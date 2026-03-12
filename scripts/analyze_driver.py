#@author Ladybug Fuzzer
#@category Analysis
#@keybinding
#@menupath
#@toolbar
"""
Ghidra Script: Extract IOCTL info for Ladybug fuzzer
Run: analyzeHeadless.bat C:\ghidra_projects Analysis -import driver.sys -postScript analyze_driver.py

Outputs JSON with:
- All IOCTL codes found
- Dispatch handler location
- Dangerous function calls (memcpy, ProbeForRead, etc.)
- Buffer size hints
- Vulnerability indicators
"""

import json
import re
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.symbol import SymbolType
from ghidra.program.model.listing import CodeUnit

# Output directory - save next to this script
import os as _os
OUTPUT_DIR = _os.path.dirname(_os.path.abspath(getSourceFile().getAbsolutePath()))

class DriverAnalyzer:
    def __init__(self):
        self.decompiler = DecompInterface()
        self.decompiler.openProgram(currentProgram)
        self.results = {
            'driver_name': currentProgram.getName(),
            'driver_path': currentProgram.getExecutablePath(),
            'architecture': str(currentProgram.getLanguage().getProcessor()),
            'ioctls': [],
            'dispatch_handler': None,
            'dangerous_functions': [],
            'vulnerability_indicators': [],
            'recommended_sizes': []
        }
        
        # Dangerous Windows kernel functions
        self.dangerous_funcs = [
            'memcpy', 'memmove', 'RtlCopyMemory', 'RtlMoveMemory',
            'strcpy', 'strncpy', 'wcscpy', 'wcsncpy',
            'sprintf', 'swprintf', 'vsprintf',
            'ProbeForRead', 'ProbeForWrite',  # Can indicate user buffer handling
            'MmMapLockedPages', 'MmMapLockedPagesSpecifyCache',  # Memory mapping
            'ExAllocatePool', 'ExAllocatePoolWithTag',  # Pool allocations
            'IoAllocateMdl', 'MmBuildMdlForNonPagedPool',
            'ZwCreateFile', 'ZwOpenFile', 'ZwReadFile', 'ZwWriteFile',
        ]
        
        # IOCTL code patterns
        self.ioctl_patterns = [
            r'0x[0-9a-fA-F]{5,8}',  # Hex constants
            r'case\s+(0x[0-9a-fA-F]+)',  # Switch cases
        ]

    def find_driver_entry(self):
        """Find DriverEntry function"""
        for symbol in currentProgram.getSymbolTable().getAllSymbols(True):
            name = symbol.getName().lower()
            if 'driverentry' in name or 'gsdriverentry' in name:
                return symbol.getAddress()
        
        # Try to find by export
        for func in currentProgram.getFunctionManager().getFunctions(True):
            if 'driverentry' in func.getName().lower():
                return func.getEntryPoint()
        
        return None

    def find_dispatch_handler(self):
        """Find IRP_MJ_DEVICE_CONTROL handler by analyzing DriverEntry"""
        driver_entry = self.find_driver_entry()
        if not driver_entry:
            print("[!] DriverEntry not found")
            return None
        
        print("[+] Found DriverEntry at: " + str(driver_entry))
        
        # Decompile DriverEntry
        func = getFunctionAt(driver_entry)
        if not func:
            return None
            
        results = self.decompiler.decompileFunction(func, 60, monitor)
        if not results.decompileCompleted():
            return None
        
        decomp = results.getDecompiledFunction().getC()
        
        # Look for MajorFunction[0xe] assignment (IRP_MJ_DEVICE_CONTROL = 14 = 0xe)
        # Pattern: DriverObject->MajorFunction[0xe] = handler
        # Or: *(DriverObject + 0x70 + 0xe*8) = handler (x64)
        
        # Save decompiled DriverEntry for manual review
        self.results['driver_entry_decomp'] = decomp
        
        # Try to find dispatch handlers by looking for functions with IRP handling patterns
        for f in currentProgram.getFunctionManager().getFunctions(True):
            f_results = self.decompiler.decompileFunction(f, 30, monitor)
            if f_results and f_results.decompileCompleted():
                f_decomp = f_results.getDecompiledFunction().getC()
                
                # Look for IOCTL handling patterns
                if ('IoControlCode' in f_decomp or 
                    'DeviceIoControl' in f_decomp or
                    'IRP_MJ_DEVICE_CONTROL' in f_decomp or
                    'switch' in f_decomp and '0x22' in f_decomp):  # Device type 0x22
                    
                    # Extract IOCTLs from this function
                    ioctls = self.extract_ioctls_from_code(f_decomp, f.getName())
                    if ioctls:
                        self.results['dispatch_handler'] = {
                            'name': f.getName(),
                            'address': str(f.getEntryPoint()),
                            'decompiled': f_decomp
                        }
                        return f
        
        return None

    def extract_ioctls_from_code(self, code, func_name):
        """Extract IOCTL codes from decompiled code"""
        ioctls = []
        
        # Find all hex constants that look like IOCTLs
        # IOCTL structure: device_type(16) | access(2) | function(12) | method(2)
        # Common device types: 0x22 (FILE_DEVICE_UNKNOWN), 0x12 (NETWORK)
        
        hex_pattern = r'0x[0-9a-fA-F]{5,8}'
        matches = re.findall(hex_pattern, code)
        
        for match in matches:
            try:
                val = int(match, 16)
                # Check if it looks like a valid IOCTL
                device_type = (val >> 16) & 0xFFFF
                method = val & 0x3
                function = (val >> 2) & 0xFFF
                access = (val >> 14) & 0x3
                
                # Valid device types for third-party drivers
                valid_device_types = [0x22, 0x12, 0x27, 0x29, 0x2D, 0x34, 0x38, 0x39, 0x8000]
                
                if device_type in valid_device_types and function < 0x1000:
                    ioctl_info = {
                        'code': match,
                        'code_int': val,
                        'device_type': hex(device_type),
                        'function': hex(function),
                        'method': ['BUFFERED', 'IN_DIRECT', 'OUT_DIRECT', 'NEITHER'][method],
                        'access': ['ANY', 'READ', 'WRITE', 'READ|WRITE'][access],
                        'found_in': func_name
                    }
                    
                    # Check for dangerous - METHOD_NEITHER is risky
                    if method == 3:
                        ioctl_info['warning'] = 'METHOD_NEITHER - user pointers passed directly!'
                        self.results['vulnerability_indicators'].append({
                            'type': 'METHOD_NEITHER',
                            'ioctl': match,
                            'risk': 'HIGH'
                        })
                    
                    # Avoid duplicates
                    if not any(i['code'] == match for i in ioctls):
                        ioctls.append(ioctl_info)
            except:
                pass
        
        return ioctls

    def analyze_function_calls(self):
        """Find dangerous function calls in dispatch handler"""
        if not self.results['dispatch_handler']:
            return
        
        handler_addr = toAddr(self.results['dispatch_handler']['address'])
        func = getFunctionAt(handler_addr)
        if not func:
            return
        
        # Get all called functions
        for called in func.getCalledFunctions(monitor):
            name = called.getName()
            for dangerous in self.dangerous_funcs:
                if dangerous.lower() in name.lower():
                    self.results['dangerous_functions'].append({
                        'function': name,
                        'called_from': func.getName(),
                        'address': str(called.getEntryPoint())
                    })
                    
                    # Add vulnerability indicator
                    if 'memcpy' in name.lower() or 'copy' in name.lower():
                        self.results['vulnerability_indicators'].append({
                            'type': 'MEMORY_COPY',
                            'function': name,
                            'risk': 'MEDIUM',
                            'note': 'Potential buffer overflow if size not validated'
                        })

    def extract_buffer_sizes(self):
        """Try to extract expected buffer sizes from decompiled code"""
        if not self.results['dispatch_handler']:
            return
        
        decomp = self.results['dispatch_handler'].get('decompiled', '')
        
        # Look for size comparisons
        size_patterns = [
            r'InputBufferLength\s*[<>=!]+\s*(\d+)',
            r'OutputBufferLength\s*[<>=!]+\s*(\d+)',
            r'sizeof\s*\(\s*\w+\s*\)\s*[<>=]+\s*(\d+)',
            r'if\s*\(\s*\w+\s*<\s*(\d+)\s*\)',
            r'if\s*\(\s*(\d+)\s*>\s*\w+\s*\)',
        ]
        
        sizes = set()
        for pattern in size_patterns:
            matches = re.findall(pattern, decomp)
            for m in matches:
                try:
                    size = int(m)
                    if 4 <= size <= 65536:  # Reasonable buffer sizes
                        sizes.add(size)
                except:
                    pass
        
        self.results['recommended_sizes'] = sorted(list(sizes))

    def analyze_all_functions(self):
        """Scan all functions for IOCTL codes and dangerous patterns"""
        print("[*] Analyzing all functions...")
        
        for func in currentProgram.getFunctionManager().getFunctions(True):
            results = self.decompiler.decompileFunction(func, 30, monitor)
            if not results or not results.decompileCompleted():
                continue
            
            decomp = results.getDecompiledFunction().getC()
            
            # Extract IOCTLs
            ioctls = self.extract_ioctls_from_code(decomp, func.getName())
            for ioctl in ioctls:
                if not any(i['code'] == ioctl['code'] for i in self.results['ioctls']):
                    self.results['ioctls'].append(ioctl)

    def run(self):
        """Main analysis"""
        print("=" * 60)
        print("  LADYBUG DRIVER ANALYZER")
        print("  Target: " + currentProgram.getName())
        print("=" * 60)
        
        # Find dispatch handler
        print("[*] Looking for dispatch handler...")
        self.find_dispatch_handler()
        
        # Analyze dangerous calls
        print("[*] Analyzing dangerous function calls...")
        self.analyze_function_calls()
        
        # Extract buffer sizes
        print("[*] Extracting buffer size hints...")
        self.extract_buffer_sizes()
        
        # Scan all functions for IOCTLs
        print("[*] Scanning all functions for IOCTLs...")
        self.analyze_all_functions()
        
        # Sort IOCTLs by code
        self.results['ioctls'] = sorted(self.results['ioctls'], key=lambda x: x['code_int'])
        
        # Remove large decompiled code from output (save separately)
        if self.results['dispatch_handler']:
            del self.results['dispatch_handler']['decompiled']
        if 'driver_entry_decomp' in self.results:
            del self.results['driver_entry_decomp']
        
        return self.results

    def save_results(self):
        """Save to JSON file in Ladybug-compatible format"""
        driver_name = currentProgram.getName().replace('.sys', '').replace('.SYS', '')
        output_file = OUTPUT_DIR + "\\" + driver_name + '_ghidra_analysis.json'
        
        # Convert to Ladybug format
        ladybug_format = {
            'driver': self.results['driver_name'],
            'driver_path': self.results['driver_path'],
            'architecture': self.results['architecture'],
            'dispatch_handler': self.results['dispatch_handler'],
            'vulnerability_indicators': self.results['vulnerability_indicators'],
            'dangerous_functions': self.results['dangerous_functions'],
            'recommended_sizes': self.results['recommended_sizes'],
        }
        
        # Convert IOCTLs to the format Ladybug expects
        for ioctl in self.results['ioctls']:
            code_hex = ioctl['code']  # Already a hex string like "0x22200C"
            ladybug_format[code_hex] = {
                'code': ioctl['code_int'],
                'min_input_size': 0,  # Unknown from static analysis
                'max_input_size': 4096,
                'min_output_size': 0,
                'method': ioctl['method'],
                'access': ioctl['access'],
                'address': ioctl.get('handler_address', '0x0'),
                'function': ioctl.get('found_in', 'unknown'),
                'device_type': ioctl.get('device_type', '0x22'),
                'warning': ioctl.get('warning', None),
                'priority': self.calculate_priority(ioctl)
            }
        
        with open(output_file, 'w') as f:
            json.dump(ladybug_format, f, indent=2)
        
        print("\n" + "=" * 60)
        print("  ANALYSIS COMPLETE")
        print("=" * 60)
        print("[+] Found {} IOCTLs".format(len(self.results['ioctls'])))
        print("[+] Found {} dangerous functions".format(len(self.results['dangerous_functions'])))
        print("[+] Found {} vulnerability indicators".format(len(self.results['vulnerability_indicators'])))
        print("[+] Saved to: " + output_file)
        
        # Print summary
        if self.results['ioctls']:
            print("\n[+] IOCTLs found (sorted by priority):")
            sorted_ioctls = sorted(self.results['ioctls'], 
                                   key=lambda x: self.calculate_priority(x), 
                                   reverse=True)
            for ioctl in sorted_ioctls[:20]:  # First 20
                priority = self.calculate_priority(ioctl)
                warning = " ⚠️ " + ioctl.get('warning', '') if 'warning' in ioctl else ''
                stars = "★" * min(5, priority // 20)
                print("    {} [{}] {} P:{} {}{}".format(
                    ioctl['code'], 
                    ioctl['method'],
                    ioctl['found_in'],
                    priority,
                    stars,
                    warning
                ))
            if len(self.results['ioctls']) > 20:
                print("    ... and {} more".format(len(self.results['ioctls']) - 20))
        
        # Print usage instructions
        print("\n" + "=" * 60)
        print("  USAGE WITH LADYBUG")
        print("=" * 60)
        print("  ladybug --device \\\\.\\{} --analysis {} --ultimate".format(
            driver_name, output_file))
        print("")

    def calculate_priority(self, ioctl):
        """Calculate fuzzing priority (higher = more interesting)"""
        priority = 50  # Base priority
        
        # METHOD_NEITHER is very interesting (direct user pointers)
        if ioctl.get('method') == 'NEITHER':
            priority += 40
        
        # Check if this IOCTL has dangerous functions
        for danger in self.results['dangerous_functions']:
            if danger.get('called_from') == ioctl.get('found_in'):
                priority += 20
                break
        
        # Check vulnerability indicators
        for vuln in self.results['vulnerability_indicators']:
            if vuln.get('ioctl') == ioctl.get('code'):
                if vuln.get('risk') == 'HIGH':
                    priority += 30
                elif vuln.get('risk') == 'MEDIUM':
                    priority += 15
        
        return priority

# Run analysis
analyzer = DriverAnalyzer()
analyzer.run()
analyzer.save_results()
