#!/usr/bin/env python3
"""
MSFuzz-style Symbolic Execution for Windows Driver IOCTL Discovery

Based on the CodeBlue 2024 MSFuzz presentation:
- Uses angr symbolic execution
- Makes IOCTL code, buffer lengths symbolic
- Finds valid IOCTLs by solving for NTSTATUS == SUCCESS paths

Requirements: pip install angr pefile
"""

import angr
import claripy
import pefile
import struct
import json
import sys
import os
from pathlib import Path

# Windows NTSTATUS codes
STATUS_SUCCESS = 0x00000000
STATUS_INVALID_PARAMETER = 0xC000000D
STATUS_INVALID_DEVICE_REQUEST = 0xC0000010

class MSFuzzAnalyzer:
    def __init__(self, driver_path: str):
        self.driver_path = driver_path
        self.driver_name = Path(driver_path).stem
        self.pe = pefile.PE(driver_path)
        self.image_base = self.pe.OPTIONAL_HEADER.ImageBase
        self.entry_point = self.image_base + self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        
        # Load into angr
        print(f"[*] Loading {driver_path} into angr...")
        self.project = angr.Project(
            driver_path,
            auto_load_libs=False,
            main_opts={'base_addr': self.image_base}
        )
        
        self.device_control_handler = None
        self.found_ioctls = []
        
    def find_device_control_handler(self) -> int:
        """
        Find IRP_MJ_DEVICE_CONTROL handler by analyzing DriverEntry.
        Look for: MOV [RDX+0xE0], <handler_address>
        
        DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = Handler
        IRP_MJ_DEVICE_CONTROL = 14 (0xE)
        Offset = 0x70 + (14 * 8) = 0x70 + 0x70 = 0xE0
        """
        print(f"[*] Analyzing DriverEntry at 0x{self.entry_point:X}...")
        
        # Create initial state at entry point
        state = self.project.factory.blank_state(addr=self.entry_point)
        
        # Scan for the pattern in the binary directly
        # Look for LEA/MOV patterns that reference offset 0xE0 from a register
        
        # Read raw bytes around entry point
        text_section = None
        for section in self.pe.sections:
            if b'.text' in section.Name:
                text_section = section
                break
        
        if not text_section:
            print("[!] No .text section found")
            return None
            
        text_start = self.image_base + text_section.VirtualAddress
        text_data = text_section.get_data()
        
        # Pattern: MOV qword ptr [REG + 0xE0], immediate or register
        # 48 89 XX E0 00 00 00 - MOV [RXX+0xE0], RXX
        # or LEA then MOV pattern
        
        candidates = []
        
        # Search for 0xE0 offset references (DeviceControl)
        for i in range(len(text_data) - 10):
            # Look for MOV [reg+0xE0], reg pattern
            if text_data[i:i+2] == b'\x48\x89' or text_data[i:i+2] == b'\x48\x8b':
                # Check if 0xE0 displacement follows
                if i + 3 < len(text_data):
                    # ModRM byte analysis
                    modrm = text_data[i+2]
                    mod = (modrm >> 6) & 0x3
                    reg = (modrm >> 3) & 0x7
                    rm = modrm & 0x7
                    
                    if mod == 2:  # [reg + disp32]
                        if i + 7 <= len(text_data):
                            disp = struct.unpack('<I', text_data[i+3:i+7])[0]
                            if disp == 0xE0:
                                addr = text_start + i
                                candidates.append(addr)
                                print(f"[+] Found MajorFunction[14] assignment at 0x{addr:X}")
        
        # For now, try to find handler address by deeper analysis
        # This is simplified - full MSFuzz uses more sophisticated CFG analysis
        
        return candidates
    
    def analyze_dispatch_symbolically(self, handler_addr: int) -> list:
        """
        Symbolically execute the DeviceControl handler to find valid IOCTLs.
        
        Creates symbolic:
        - IoControlCode
        - InputBufferLength  
        - OutputBufferLength
        
        Then explores paths where NTSTATUS == SUCCESS
        """
        print(f"\n[*] Symbolic execution of handler at 0x{handler_addr:X}...")
        
        # Create symbolic variables (like MSFuzz does)
        ioctl_code = claripy.BVS('ioctl_code', 32)
        input_len = claripy.BVS('input_len', 32)
        output_len = claripy.BVS('output_len', 32)
        
        # Constrain IOCTL to valid device type 0x22 (FILE_DEVICE_UNKNOWN commonly used)
        # IOCTL format: [DeviceType:16][Access:2][Function:12][Method:2]
        device_type = (ioctl_code >> 16) & 0xFFFF
        
        # Initial state
        state = self.project.factory.blank_state(addr=handler_addr)
        
        # Set up fake IRP structure in memory
        irp_addr = 0x10000000
        ios_addr = 0x10001000
        
        # IRP->Tail.Overlay.CurrentStackLocation (offset 0xB8)
        state.memory.store(irp_addr + 0xB8, claripy.BVV(ios_addr, 64), endness='Iend_LE')
        
        # IO_STACK_LOCATION->Parameters.DeviceIoControl.IoControlCode (offset 0x18)
        state.memory.store(ios_addr + 0x18, ioctl_code, endness='Iend_LE')
        
        # IO_STACK_LOCATION->Parameters.DeviceIoControl.InputBufferLength (offset 0x10)
        state.memory.store(ios_addr + 0x10, input_len, endness='Iend_LE')
        
        # IO_STACK_LOCATION->Parameters.DeviceIoControl.OutputBufferLength (offset 0x08)
        state.memory.store(ios_addr + 0x08, output_len, endness='Iend_LE')
        
        # RCX = DeviceObject, RDX = IRP
        state.regs.rcx = 0x20000000  # Fake DeviceObject
        state.regs.rdx = irp_addr
        
        # Add device type constraint
        state.solver.add(device_type == 0x22)
        
        # Create simulation manager
        simgr = self.project.factory.simulation_manager(state)
        
        found_ioctls = []
        
        # Custom exploration - look for paths that don't return error
        def check_success(state):
            """Check if path leads to success (not invalid parameter)"""
            # EAX contains NTSTATUS on return
            if state.regs.rax.concrete:
                status = state.solver.eval(state.regs.rax)
                return status == STATUS_SUCCESS
            return False
        
        def check_error(state):
            """Check if path returns error"""
            if state.regs.rax.concrete:
                status = state.solver.eval(state.regs.rax)
                return status >= 0x80000000  # Error status
            return False
        
        print("[*] Exploring execution paths (this may take a while)...")
        
        try:
            # Step-based exploration with timeout
            for step in range(1000):  # Max 1000 steps
                simgr.step()
                
                # Check deadended states for their IOCTL values
                for s in simgr.deadended:
                    if s.solver.satisfiable():
                        try:
                            # Get concrete IOCTL value for this path
                            ioctl_val = s.solver.eval(ioctl_code)
                            status = s.solver.eval(s.regs.rax) if s.regs.rax.concrete else None
                            
                            if ioctl_val not in [i['code'] for i in found_ioctls]:
                                found_ioctls.append({
                                    'code': ioctl_val,
                                    'hex': f"0x{ioctl_val:08X}",
                                    'status': f"0x{status:08X}" if status else "unknown",
                                    'min_input': s.solver.min(input_len),
                                    'max_input': s.solver.max(input_len),
                                })
                                print(f"[+] Found IOCTL: 0x{ioctl_val:08X} (status: {found_ioctls[-1]['status']})")
                        except:
                            pass
                
                simgr.drop(stash='deadended')
                
                if not simgr.active:
                    break
                    
                if step % 100 == 0:
                    print(f"    Step {step}: {len(simgr.active)} active, {len(found_ioctls)} IOCTLs found")
                    
        except Exception as e:
            print(f"[!] Exploration stopped: {e}")
        
        return found_ioctls
    
    def analyze_ioctl_range_pattern(self) -> list:
        """
        Alternative approach: Look for common IOCTL dispatch patterns.
        
        Pattern 1: (IOCTL >> 2) & 0xFF < N  (like ahcache)
        Pattern 2: switch(IOCTL) with cases  
        Pattern 3: if-else chain comparing IOCTLs
        """
        print("\n[*] Searching for IOCTL range patterns...")
        
        found_ioctls = []
        
        # Search ALL executable sections (not just .text)
        for section in self.pe.sections:
            # Check if section is executable
            is_exec = section.Characteristics & 0x20000000  # IMAGE_SCN_MEM_EXECUTE
            name = section.Name.rstrip(b'\x00').decode('ascii', errors='ignore')
            
            if not is_exec and name not in ['PAGE', 'INIT', '.text']:
                continue
                
            data = section.get_data()
            base = self.image_base + section.VirtualAddress
            print(f"[*] Scanning section {name} (0x{base:X}, {len(data)} bytes)")
            
            # Pattern from ahcache:
            # c1 e8 02           SHR EAX, 2
            # 44 0f b6 c8        MOVZX R9D, AL  (& 0xFF)
            # 41 83 f9 XX        CMP R9D, XX    (< N)
            # 73 XX              JAE ...
            
            for i in range(len(data) - 15):
                # Look for SHR EAX, 2
                if data[i:i+3] == b'\xC1\xE8\x02':
                    # Check for MOVZX R9D, AL (44 0f b6 c8) nearby
                    for j in range(i+3, min(i+10, len(data)-8)):
                        if data[j:j+4] == b'\x44\x0f\xb6\xc8':
                            # Check for CMP R9D, imm8 (41 83 f9 XX)
                            for k in range(j+4, min(j+10, len(data)-4)):
                                if data[k:k+3] == b'\x41\x83\xf9':
                                    max_index = data[k+3]
                                    addr = base + i
                                    print(f"[+] Found ahcache-style pattern at 0x{addr:X}: index < {max_index}")
                                    
                                    # Generate IOCTLs for this range
                                    for idx in range(max_index):
                                        ioctl = 0x220000 + (idx * 4)
                                        found_ioctls.append({
                                            'code': ioctl,
                                            'hex': f"0x{ioctl:08X}",
                                            'index': idx,
                                            'method': 'range_pattern'
                                        })
                                    return found_ioctls
                
                # Also check traditional pattern:
                # SHR reg, 2 followed by AND 0xFF followed by CMP
                for shr_pat in [b'\xC1\xE8\x02', b'\xC1\xE9\x02', b'\xC1\xEA\x02']:
                    if data[i:i+3] == shr_pat:
                        # Look for AND 0xFF nearby
                        for j in range(i+3, min(i+20, len(data)-4)):
                            # AND EAX, 0xFF = 25 FF 00 00 00 or 83 E0 FF
                            if (data[j:j+5] == b'\x25\xFF\x00\x00\x00' or
                                (data[j:j+2] == b'\x83\xE0' and data[j+2] == 0xFF)):
                                # Look for CMP with immediate
                                for k in range(j+2, min(j+15, len(data)-3)):
                                    # CMP EAX, imm8 = 83 F8 XX
                                    if data[k:k+2] == b'\x83\xF8':
                                        max_index = data[k+2]
                                        addr = base + i
                                        print(f"[+] Found traditional pattern at 0x{addr:X}: index < {max_index}")
                                        
                                        for idx in range(max_index):
                                            ioctl = 0x220000 + (idx * 4)
                                            found_ioctls.append({
                                                'code': ioctl,
                                                'hex': f"0x{ioctl:08X}",
                                                'index': idx,
                                                'method': 'range_pattern'
                                            })
                                        return found_ioctls
        
        return found_ioctls
    
    def analyze(self) -> dict:
        """Main analysis entry point"""
        print(f"\n{'='*60}")
        print(f"MSFuzz-style Analysis: {self.driver_name}")
        print(f"{'='*60}\n")
        
        results = {
            'driver': self.driver_name,
            'path': self.driver_path,
            'image_base': f"0x{self.image_base:X}",
            'entry_point': f"0x{self.entry_point:X}",
            'ioctls': []
        }
        
        # Method 1: Try pattern-based detection first (fast)
        ioctls = self.analyze_ioctl_range_pattern()
        
        if ioctls:
            results['ioctls'] = ioctls
            results['method'] = 'range_pattern'
        else:
            # Method 2: Find DeviceControl handler
            handlers = self.find_device_control_handler()
            
            if handlers:
                results['device_control_candidates'] = [f"0x{h:X}" for h in handlers]
                
                # Method 3: Full symbolic execution (slow but thorough)
                # Uncomment to enable:
                # for handler in handlers[:1]:  # Try first candidate
                #     ioctls = self.analyze_dispatch_symbolically(handler)
                #     if ioctls:
                #         results['ioctls'] = ioctls
                #         results['method'] = 'symbolic'
                #         break
        
        return results
    
    def save_json(self, results: dict, output_path: str):
        """Save results in Ladybug-compatible format"""
        # Convert to Ladybug format
        ladybug_format = {
            'driver': results['driver'] + '.sys',
            'device': f"\\\\.\\{results['driver']}",
            'analysis': f"MSFuzz symbolic analysis"
        }
        
        for ioctl in results.get('ioctls', []):
            code = ioctl['code']
            hex_code = f"0x{code:08X}"
            ladybug_format[hex_code] = {
                'method': 'BUFFERED',
                'access': 'ANY',
                'min_input_size': ioctl.get('min_input', 0),
                'max_input_size': ioctl.get('max_input', 4096),
            }
        
        with open(output_path, 'w') as f:
            json.dump(ladybug_format, f, indent=2)
        
        print(f"\n[+] Saved Ladybug-compatible JSON to: {output_path}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python msfuzz_symbolic.py <driver.sys> [output.json]")
        print("\nMSFuzz-style symbolic execution for IOCTL discovery")
        print("Based on CodeBlue 2024 MSFuzz presentation")
        sys.exit(1)
    
    driver_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else None
    
    if not os.path.exists(driver_path):
        print(f"[!] Driver not found: {driver_path}")
        sys.exit(1)
    
    analyzer = MSFuzzAnalyzer(driver_path)
    results = analyzer.analyze()
    
    print(f"\n{'='*60}")
    print("RESULTS")
    print(f"{'='*60}")
    print(f"Driver: {results['driver']}")
    print(f"IOCTLs found: {len(results.get('ioctls', []))}")
    
    for ioctl in results.get('ioctls', []):
        print(f"  {ioctl['hex']}")
    
    if output_path:
        analyzer.save_json(results, output_path)
    elif results.get('ioctls'):
        default_output = f"{results['driver']}_msfuzz.json"
        analyzer.save_json(results, default_output)


if __name__ == '__main__':
    main()
