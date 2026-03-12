#!/usr/bin/env python3
"""
MSFuzz-style Static Driver Analyzer using Angr
Extracts IOCTL constraints and global variable dependencies

Usage:
    python analyze_driver.py <driver.sys> -o output.json

Requirements:
    pip install angr
"""

import angr
import claripy
import json
import argparse
import sys
from collections import defaultdict
from pathlib import Path

# Windows NTSTATUS codes
STATUS_SUCCESS = 0x00000000
STATUS_INVALID_PARAMETER = 0xC000000D
STATUS_BUFFER_TOO_SMALL = 0xC0000023
STATUS_INVALID_DEVICE_REQUEST = 0xC0000010

# IRP structure offsets (x64)
IRP_IO_STATUS_OFFSET = 0x30
IRP_ASSOCIATED_IRP_OFFSET = 0x18  # SystemBuffer location

# IO_STACK_LOCATION offsets (x64)
IOSTACK_PARAMETERS_OFFSET = 0x08
IOSTACK_IOCTL_CODE_OFFSET = 0x18       # Parameters.DeviceIoControl.IoControlCode
IOSTACK_INPUT_LENGTH_OFFSET = 0x10     # Parameters.DeviceIoControl.InputBufferLength
IOSTACK_OUTPUT_LENGTH_OFFSET = 0x08    # Parameters.DeviceIoControl.OutputBufferLength


class DriverAnalyzer:
    """Analyze Windows kernel driver using symbolic execution"""
    
    def __init__(self, driver_path: str, verbose: bool = False):
        self.driver_path = driver_path
        self.verbose = verbose
        self.results = {
            "driver": Path(driver_path).name,
            "ioctls": {},
            "dependency_groups": [],
            "global_accesses": defaultdict(lambda: {"reads": [], "writes": []})
        }
        
        # Load project
        print(f"[*] Loading driver: {driver_path}")
        try:
            self.project = angr.Project(
                driver_path,
                auto_load_libs=False,
                main_opts={'base_addr': 0x140000000}  # Typical Windows driver base
            )
        except Exception as e:
            print(f"[!] Failed to load driver: {e}")
            sys.exit(1)
            
        print(f"[+] Loaded! Entry: 0x{self.project.entry:x}")
        print(f"[+] Architecture: {self.project.arch.name}")
        
    def find_dispatch_device_control(self):
        """
        Find the DispatchDeviceControl handler by looking for:
        1. DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] assignment
        2. Function that takes (DEVICE_OBJECT*, IRP*) and checks IoControlCode
        """
        print("[*] Searching for DispatchDeviceControl handler...")
        
        cfg = self.project.analyses.CFGFast()
        print(f"[+] CFG built: {len(cfg.graph.nodes())} nodes")
        
        candidates = []
        
        # Look for functions that reference IOCTL-related patterns
        for func_addr in cfg.functions:
            func = cfg.functions[func_addr]
            
            # Skip tiny functions
            if func.size < 50:
                continue
                
            # Check for switch/case patterns (common in IOCTL handlers)
            # Look for many compare instructions
            try:
                blocks = list(func.blocks)
                if len(blocks) > 5:  # Complex function
                    candidates.append((func_addr, func.size, len(blocks)))
            except:
                continue
        
        # Sort by complexity (more blocks = likely IOCTL handler)
        candidates.sort(key=lambda x: x[2], reverse=True)
        
        if candidates:
            print(f"[+] Found {len(candidates)} candidate handlers")
            for addr, size, blocks in candidates[:5]:
                print(f"    0x{addr:x}: {size} bytes, {blocks} blocks")
            return candidates[0][0]  # Return most complex
        
        return None
    
    def setup_symbolic_irp(self, state):
        """Create symbolic IRP and IO_STACK_LOCATION structures"""
        
        # Symbolic IOCTL parameters
        ioctl_code = claripy.BVS("IoControlCode", 32)
        input_length = claripy.BVS("InputBufferLength", 32)
        output_length = claripy.BVS("OutputBufferLength", 32)
        
        # Constrain IOCTL to valid Windows IOCTL format
        # Device type 0x22 (FILE_DEVICE_UNKNOWN) is most common for custom drivers
        # Also allow 0xF53 (FILE_DEVICE_AVIO - used by ahcache)
        # Format: 0x22XXXX or 0xF53XXXX
        device_type = claripy.Extract(31, 16, ioctl_code)
        state.solver.add(claripy.Or(
            device_type == 0x22,    # FILE_DEVICE_UNKNOWN 
            device_type == 0xF53,   # FILE_DEVICE_AVIO (ahcache)
            device_type == 0x32,    # FILE_DEVICE_ACPI
            device_type == 0x07,    # FILE_DEVICE_DISK
            device_type == 0x12,    # FILE_DEVICE_NETWORK
            device_type >= 0x8000   # Custom device types
        ))
        
        # Constrain buffer lengths to reasonable values
        state.solver.add(input_length <= 0x10000)
        state.solver.add(output_length <= 0x10000)
        
        # Create symbolic input buffer (64 bytes of symbolic data)
        input_buffer = claripy.BVS("InputBuffer", 64 * 8)
        
        # Allocate fake IRP structure in memory
        irp_addr = 0x7FFE0000
        iostack_addr = 0x7FFE1000
        buffer_addr = 0x7FFE2000
        
        # Store input buffer
        state.memory.store(buffer_addr, input_buffer)
        
        # Setup IO_STACK_LOCATION
        state.memory.store(
            iostack_addr + IOSTACK_IOCTL_CODE_OFFSET,
            ioctl_code,
            endness='Iend_LE'
        )
        state.memory.store(
            iostack_addr + IOSTACK_INPUT_LENGTH_OFFSET,
            input_length,
            endness='Iend_LE'
        )
        state.memory.store(
            iostack_addr + IOSTACK_OUTPUT_LENGTH_OFFSET,
            output_length,
            endness='Iend_LE'
        )
        
        # Setup IRP SystemBuffer pointer
        state.memory.store(
            irp_addr + IRP_ASSOCIATED_IRP_OFFSET,
            claripy.BVV(buffer_addr, 64),
            endness='Iend_LE'
        )
        
        # Return symbolic variables for constraint extraction
        return {
            'irp_addr': irp_addr,
            'iostack_addr': iostack_addr,
            'buffer_addr': buffer_addr,
            'ioctl_code': ioctl_code,
            'input_length': input_length,
            'output_length': output_length,
            'input_buffer': input_buffer
        }
    
    def analyze_ioctl_handler(self, handler_addr: int, timeout: int = 300):
        """
        Symbolically execute IOCTL handler to extract constraints
        """
        print(f"[*] Analyzing handler at 0x{handler_addr:x}")
        
        # Create initial state
        state = self.project.factory.blank_state(addr=handler_addr)
        
        # Setup symbolic IRP
        symbols = self.setup_symbolic_irp(state)
        
        # Set RCX = DeviceObject (don't care), RDX = IRP
        state.regs.rcx = 0xDEAD0000  # Fake DeviceObject
        state.regs.rdx = symbols['irp_addr']
        
        # Track global memory accesses
        global_reads = defaultdict(list)
        global_writes = defaultdict(list)
        
        # Create simulation manager
        simgr = self.project.factory.simulation_manager(state)
        
        # Step through with exploration
        print("[*] Starting symbolic execution...")
        
        discovered_ioctls = {}
        
        try:
            # Use DFS exploration
            simgr.run(n=1000)  # Limit steps
            
            print(f"[+] Explored {len(simgr.deadended)} paths")
            
            # Analyze each terminal state
            for final_state in simgr.deadended:
                try:
                    # Try to solve for concrete IOCTL code
                    if final_state.solver.satisfiable():
                        ioctl_val = final_state.solver.eval(symbols['ioctl_code'])
                        input_min = final_state.solver.min(symbols['input_length'])
                        input_max = final_state.solver.max(symbols['input_length'])
                        output_min = final_state.solver.min(symbols['output_length'])
                        
                        ioctl_hex = f"0x{ioctl_val:08X}"
                        
                        if ioctl_hex not in discovered_ioctls:
                            discovered_ioctls[ioctl_hex] = {
                                "min_input_size": input_min,
                                "max_input_size": min(input_max, 0x10000),
                                "min_output_size": output_min,
                                "constraints": [],
                                "reads_globals": [],
                                "writes_globals": []
                            }
                        else:
                            # Update with tighter constraints
                            existing = discovered_ioctls[ioctl_hex]
                            existing["min_input_size"] = max(existing["min_input_size"], input_min)
                            
                except Exception as e:
                    if self.verbose:
                        print(f"    [!] State analysis error: {e}")
                    continue
                    
        except Exception as e:
            print(f"[!] Symbolic execution error: {e}")
        
        return discovered_ioctls
    
    def is_valid_ioctl(self, val: int) -> bool:
        """
        Validate if a value looks like a real Windows IOCTL code.
        
        IOCTL format: CTL_CODE(DeviceType, Function, Method, Access)
        Bits 31-16: Device Type (0x0001-0x7FFF user, 0x8000+ MS reserved)
        Bits 15-14: Access (0=ANY, 1=READ, 2=WRITE, 3=READ|WRITE)
        Bits 13-2:  Function code (0-0xFFF)
        Bits 1-0:   Method (0-3: BUFFERED, IN_DIRECT, OUT_DIRECT, NEITHER)
        
        IMPORTANT: Values >= 0x80000000 are NTSTATUS codes, NOT IOCTLs!
        """
        if val < 0 or val > 0xFFFFFFFF:
            return False
        
        # CRITICAL: Filter out NTSTATUS codes!
        # 0x80000000+ = NTSTATUS warnings/informational
        # 0xC0000000+ = NTSTATUS errors
        # These are NOT IOCTLs!
        if val >= 0x80000000:
            return False
            
        device_type = (val >> 16) & 0xFFFF
        access = (val >> 14) & 0x3
        function = (val >> 2) & 0xFFF
        method = val & 0x3
        
        # Common device types for Windows drivers (must be < 0x8000)
        VALID_DEVICE_TYPES = {
            0x01,  # FILE_DEVICE_BEEP
            0x02,  # FILE_DEVICE_CD_ROM
            0x03,  # FILE_DEVICE_CD_ROM_FILE_SYSTEM
            0x04,  # FILE_DEVICE_CONTROLLER
            0x05,  # FILE_DEVICE_DATALINK
            0x06,  # FILE_DEVICE_DFS
            0x07,  # FILE_DEVICE_DISK
            0x08,  # FILE_DEVICE_DISK_FILE_SYSTEM
            0x09,  # FILE_DEVICE_FILE_SYSTEM
            0x0A,  # FILE_DEVICE_INPORT_PORT
            0x0B,  # FILE_DEVICE_KEYBOARD
            0x0C,  # FILE_DEVICE_MAILSLOT
            0x0D,  # FILE_DEVICE_MIDI_IN
            0x0E,  # FILE_DEVICE_MIDI_OUT
            0x0F,  # FILE_DEVICE_MOUSE
            0x10,  # FILE_DEVICE_MULTI_UNC_PROVIDER
            0x11,  # FILE_DEVICE_NAMED_PIPE
            0x12,  # FILE_DEVICE_NETWORK
            0x13,  # FILE_DEVICE_NETWORK_BROWSER
            0x14,  # FILE_DEVICE_NETWORK_FILE_SYSTEM
            0x15,  # FILE_DEVICE_NULL
            0x16,  # FILE_DEVICE_PARALLEL_PORT
            0x17,  # FILE_DEVICE_PHYSICAL_NETCARD
            0x18,  # FILE_DEVICE_PRINTER
            0x19,  # FILE_DEVICE_SCANNER
            0x1A,  # FILE_DEVICE_SERIAL_MOUSE_PORT
            0x1B,  # FILE_DEVICE_SERIAL_PORT
            0x1C,  # FILE_DEVICE_SCREEN
            0x1D,  # FILE_DEVICE_SOUND
            0x1E,  # FILE_DEVICE_STREAMS
            0x1F,  # FILE_DEVICE_TAPE
            0x20,  # FILE_DEVICE_TAPE_FILE_SYSTEM
            0x21,  # FILE_DEVICE_TRANSPORT
            0x22,  # FILE_DEVICE_UNKNOWN (most common for custom drivers!)
            0x23,  # FILE_DEVICE_VIDEO
            0x24,  # FILE_DEVICE_VIRTUAL_DISK
            0x25,  # FILE_DEVICE_WAVE_IN
            0x26,  # FILE_DEVICE_WAVE_OUT
            0x27,  # FILE_DEVICE_8042_PORT
            0x28,  # FILE_DEVICE_NETWORK_REDIRECTOR
            0x29,  # FILE_DEVICE_BATTERY
            0x2A,  # FILE_DEVICE_BUS_EXTENDER
            0x2B,  # FILE_DEVICE_MODEM
            0x2C,  # FILE_DEVICE_VDM
            0x2D,  # FILE_DEVICE_MASS_STORAGE
            0x2E,  # FILE_DEVICE_SMB
            0x2F,  # FILE_DEVICE_KS
            0x30,  # FILE_DEVICE_CHANGER
            0x31,  # FILE_DEVICE_SMARTCARD
            0x32,  # FILE_DEVICE_ACPI
            0x33,  # FILE_DEVICE_DVD
            0x34,  # FILE_DEVICE_FULLSCREEN_VIDEO
            0x35,  # FILE_DEVICE_DFS_FILE_SYSTEM
            0x36,  # FILE_DEVICE_DFS_VOLUME
            0x37,  # FILE_DEVICE_SERENUM
            0x38,  # FILE_DEVICE_TERMSRV
            0x39,  # FILE_DEVICE_KSEC
            0x3A,  # FILE_DEVICE_FIPS
            0x3B,  # FILE_DEVICE_INFINIBAND
            0x3C,  # FILE_DEVICE_VMBUS
            0x3D,  # FILE_DEVICE_CRYPT_PROVIDER
            0x3E,  # FILE_DEVICE_WPD
            0x3F,  # FILE_DEVICE_BLUETOOTH
            0x40,  # FILE_DEVICE_MT_COMPOSITE
            0x41,  # FILE_DEVICE_MT_TRANSPORT
            0x42,  # FILE_DEVICE_BIOMETRIC
            0x43,  # FILE_DEVICE_PMI
            0x44,  # FILE_DEVICE_EHSTOR
            0x45,  # FILE_DEVICE_DEVAPI
            0x46,  # FILE_DEVICE_GPIO
            0x47,  # FILE_DEVICE_USBEX
            0x50,  # FILE_DEVICE_CONSOLE
            0x51,  # FILE_DEVICE_NFP
            0x52,  # FILE_DEVICE_SYSENV
            0x53,  # FILE_DEVICE_VIRTUAL_BLOCK
            0x54,  # FILE_DEVICE_POINT_OF_SERVICE
            0x55,  # FILE_DEVICE_STORAGE_REPLICATION
            0x56,  # FILE_DEVICE_TRUST_ENV
            0x57,  # FILE_DEVICE_UCM
            0x58,  # FILE_DEVICE_UCMTCPCI
            0x59,  # FILE_DEVICE_PERSISTENT_MEMORY
            0x5A,  # FILE_DEVICE_NVDIMM
            0x5B,  # FILE_DEVICE_HOLOGRAPHIC
            0x5C,  # FILE_DEVICE_SDFXHCI
        }
        
        # Check if device type is in known valid set
        if device_type not in VALID_DEVICE_TYPES:
            return False
        
        # Function code 0xFFF is often just a mask, filter it out
        if function == 0xFFF:
            return False
        
        # Filter function codes that are suspiciously high (likely false positives)
        # Most real IOCTLs have function codes < 256 (0x100)
        # Very few legitimate drivers use function codes > 512
        if function > 0x200:
            return False
        
        # Additional sanity check: very small values with uncommon device types
        # are usually just coincidental matches with structure offsets
        if device_type <= 0x10 and function == 0 and method == 0:
            # 0x00010000, 0x00020000, etc are likely just round numbers, not IOCTLs
            return False
            
        return True
    
    def find_ioctls_heuristic(self):
        """
        Heuristically find IOCTLs by looking for compare instructions
        with values that match valid IOCTL structure
        """
        print("[*] Searching for IOCTL codes heuristically...")
        
        ioctls = set()
        
        # Disassemble and look for CMP instructions with IOCTL-like values
        cfg = self.project.analyses.CFGFast()
        
        for func_addr in cfg.functions:
            func = cfg.functions[func_addr]
            try:
                for block in func.blocks:
                    for insn in block.capstone.insns:
                        # Look for CMP, TEST, MOV with immediate values
                        if insn.mnemonic in ['cmp', 'test', 'mov', 'sub']:
                            for op in insn.operands:
                                if op.type == 2:  # Immediate
                                    val = op.imm
                                    # Validate against proper IOCTL structure
                                    if self.is_valid_ioctl(val):
                                        ioctls.add(val)
            except:
                continue
        
        if ioctls:
            print(f"[+] Found {len(ioctls)} valid IOCTL codes")
            for ioctl in sorted(ioctls):
                device_type = (ioctl >> 16) & 0xFFFF
                access = (ioctl >> 14) & 0x3
                function = (ioctl >> 2) & 0xFFF
                method = ioctl & 0x3
                ACCESS_NAMES = {0: "ANY", 1: "READ", 2: "WRITE", 3: "RW"}
                METHOD_NAMES = {0: "BUFFERED", 1: "IN_DIRECT", 2: "OUT_DIRECT", 3: "NEITHER"}
                print(f"    0x{ioctl:08X}  DevType=0x{device_type:X} Func={function} Access={ACCESS_NAMES[access]} Method={METHOD_NAMES[method]}")
        else:
            print("[!] No valid IOCTLs found via heuristic - will try symbolic execution")
            
        return list(ioctls)
    
    def analyze(self):
        """Run full analysis"""
        
        # Method 1: Find IOCTL codes heuristically
        found_ioctls = self.find_ioctls_heuristic()
        
        # Store results
        for ioctl in found_ioctls:
            ioctl_hex = f"0x{ioctl:08X}"
            self.results["ioctls"][ioctl_hex] = {
                "min_input_size": 0,
                "max_input_size": 4096,
                "min_output_size": 0,
                "constraints": [],
                "reads_globals": [],
                "writes_globals": [],
                "discovered_by": "heuristic"
            }
        
        # Method 2: Try to find and analyze dispatch handler (may fail on complex drivers)
        handler = self.find_dispatch_device_control()
        if handler:
            try:
                symbolic_results = self.analyze_ioctl_handler(handler, timeout=120)
                
                # Merge with heuristic results
                for ioctl_hex, data in symbolic_results.items():
                    if ioctl_hex in self.results["ioctls"]:
                        self.results["ioctls"][ioctl_hex].update(data)
                        self.results["ioctls"][ioctl_hex]["discovered_by"] = "symbolic"
                    else:
                        data["discovered_by"] = "symbolic"
                        self.results["ioctls"][ioctl_hex] = data
                        
            except Exception as e:
                print(f"[!] Symbolic analysis failed: {e}")
                print("[*] Continuing with heuristic results only")
        
        # Build dependency groups based on shared globals
        self._build_dependency_groups()
        
        return self.results
    
    def _build_dependency_groups(self):
        """Group IOCTLs that share global variables"""
        
        # Find IOCTLs that share globals
        global_to_ioctls = defaultdict(set)
        
        for ioctl, data in self.results["ioctls"].items():
            for g in data.get("reads_globals", []):
                global_to_ioctls[g].add(ioctl)
            for g in data.get("writes_globals", []):
                global_to_ioctls[g].add(ioctl)
        
        # Create groups
        groups = []
        for global_addr, ioctls in global_to_ioctls.items():
            if len(ioctls) > 1:
                groups.append({
                    "shared_global": global_addr,
                    "ioctls": list(ioctls)
                })
        
        self.results["dependency_groups"] = groups
    
    def save_results(self, output_path: str):
        """Save analysis results to JSON"""
        with open(output_path, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"[+] Results saved to: {output_path}")


def main():
    parser = argparse.ArgumentParser(description="MSFuzz-style Windows Driver Analyzer")
    parser.add_argument("driver", help="Path to driver .sys file")
    parser.add_argument("-o", "--output", default="analysis.json", help="Output JSON file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    if not Path(args.driver).exists():
        print(f"[!] Driver not found: {args.driver}")
        sys.exit(1)
    
    analyzer = DriverAnalyzer(args.driver, verbose=args.verbose)
    results = analyzer.analyze()
    analyzer.save_results(args.output)
    
    # Print summary
    print("\n" + "="*60)
    print("ANALYSIS SUMMARY")
    print("="*60)
    print(f"Driver: {results['driver']}")
    print(f"IOCTLs found: {len(results['ioctls'])}")
    print(f"Dependency groups: {len(results['dependency_groups'])}")
    
    if results['ioctls']:
        print("\nIOCTL Details:")
        for ioctl, data in sorted(results['ioctls'].items()):
            print(f"  {ioctl}:")
            print(f"    Input size: {data['min_input_size']} - {data.get('max_input_size', '?')}")
            if data.get('constraints'):
                print(f"    Constraints: {data['constraints']}")


if __name__ == "__main__":
    main()
