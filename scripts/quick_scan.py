#!/usr/bin/env python3
"""
Quick driver scanner - extracts IOCTL codes from driver.sys without Ghidra
Uses pattern matching on raw bytes (works on most drivers)

Usage: python quick_scan.py driver.sys
Output: driver_analysis.json (compatible with Ladybug --analysis)
"""

import sys
import struct
import json
import re
from pathlib import Path

class QuickDriverScanner:
    def __init__(self, driver_path):
        self.driver_path = Path(driver_path)
        self.data = self.driver_path.read_bytes()
        self.results = {
            'driver': self.driver_path.name,
            'driver_path': str(self.driver_path.absolute()),
            'architecture': self.detect_arch(),
            'ioctls': [],
            'method_neither_count': 0,
            'dangerous_patterns': []
        }
    
    def detect_arch(self):
        """Detect if driver is x86 or x64"""
        if len(self.data) < 0x40:
            return 'unknown'
        
        # Check PE header
        if self.data[:2] != b'MZ':
            return 'unknown'
        
        pe_offset = struct.unpack('<I', self.data[0x3C:0x40])[0]
        if pe_offset + 4 > len(self.data):
            return 'unknown'
        
        if self.data[pe_offset:pe_offset+4] != b'PE\x00\x00':
            return 'unknown'
        
        machine = struct.unpack('<H', self.data[pe_offset+4:pe_offset+6])[0]
        return 'x64' if machine == 0x8664 else 'x86' if machine == 0x14c else 'unknown'
    
    def scan_for_ioctls(self):
        """Scan binary for IOCTL codes"""
        print(f"[*] Scanning {self.driver_path.name} ({len(self.data)} bytes)...")
        
        found = set()
        
        # Pattern 1: Look for 4-byte values that look like IOCTLs
        # IOCTL format: DeviceType(16) | Access(2) | Function(12) | Method(2)
        for i in range(0, len(self.data) - 4, 4):
            val = struct.unpack('<I', self.data[i:i+4])[0]
            if self.is_valid_ioctl(val):
                found.add(val)
        
        # Pattern 2: Look for immediate moves (mov eax, 0x222xxx)
        # x86: B8 XX XX XX XX (mov eax, imm32)
        for i in range(len(self.data) - 5):
            if self.data[i] == 0xB8:  # mov eax
                val = struct.unpack('<I', self.data[i+1:i+5])[0]
                if self.is_valid_ioctl(val):
                    found.add(val)
        
        # Pattern 3: Compare instructions (cmp eax, 0x222xxx)
        # x86: 3D XX XX XX XX (cmp eax, imm32)
        for i in range(len(self.data) - 5):
            if self.data[i] == 0x3D:  # cmp eax
                val = struct.unpack('<I', self.data[i+1:i+5])[0]
                if self.is_valid_ioctl(val):
                    found.add(val)
        
        # Pattern 4: Look for switch table patterns
        # Often: sub eax, base_ioctl; cmp eax, count; ja default
        
        # Convert to list and sort
        for ioctl in sorted(found):
            self.add_ioctl(ioctl)
        
        print(f"[+] Found {len(self.results['ioctls'])} potential IOCTLs")
    
    def is_valid_ioctl(self, val):
        """Check if value looks like a valid IOCTL"""
        if val == 0 or val == 0xFFFFFFFF:
            return False
        
        device_type = (val >> 16) & 0xFFFF
        method = val & 0x3
        function = (val >> 2) & 0xFFF
        access = (val >> 14) & 0x3
        
        # Valid device types for third-party drivers
        valid_device_types = [
            0x0012,  # FILE_DEVICE_NETWORK
            0x0022,  # FILE_DEVICE_UNKNOWN (most common!)
            0x0027,  # FILE_DEVICE_DISK_FILE_SYSTEM
            0x0029,  # FILE_DEVICE_NETWORK_FILE_SYSTEM
            0x002D,  # FILE_DEVICE_KS
            0x0034,  # FILE_DEVICE_KSEC
            0x0038,  # FILE_DEVICE_CRYPT_PROVIDER
            0x0039,  # FILE_DEVICE_WPD
            0x003E,  # FILE_DEVICE_BIOMETRIC
            0x8000,  # Custom high device type
        ]
        
        # Check device type
        if device_type not in valid_device_types:
            return False
        
        # Function code should be reasonable (not all 1s or 0s)
        if function == 0 or function == 0xFFF:
            return False
        
        return True
    
    def add_ioctl(self, code):
        """Add IOCTL with parsed details"""
        device_type = (code >> 16) & 0xFFFF
        method = code & 0x3
        function = (code >> 2) & 0xFFF
        access = (code >> 14) & 0x3
        
        method_names = ['BUFFERED', 'IN_DIRECT', 'OUT_DIRECT', 'NEITHER']
        access_names = ['ANY', 'READ', 'WRITE', 'READ|WRITE']
        
        ioctl_info = {
            'code': f'0x{code:08X}',
            'code_int': code,
            'device_type': f'0x{device_type:04X}',
            'function': f'0x{function:03X}',
            'method': method_names[method],
            'access': access_names[access],
            'priority': 50
        }
        
        # METHOD_NEITHER is high priority (dangerous!)
        if method == 3:
            ioctl_info['warning'] = 'METHOD_NEITHER - user pointers passed directly!'
            ioctl_info['priority'] = 90
            self.results['method_neither_count'] += 1
        
        self.results['ioctls'].append(ioctl_info)
    
    def scan_dangerous_patterns(self):
        """Scan for dangerous code patterns"""
        patterns = {
            b'memcpy': 'MEMORY_COPY',
            b'memmove': 'MEMORY_COPY',
            b'strcpy': 'STRING_COPY',
            b'sprintf': 'FORMAT_STRING',
            b'ProbeForRead': 'USER_BUFFER',
            b'ProbeForWrite': 'USER_BUFFER',
            b'MmMapLockedPages': 'MEMORY_MAP',
            b'ExAllocatePool': 'POOL_ALLOC',
        }
        
        for pattern, danger_type in patterns.items():
            if pattern in self.data:
                self.results['dangerous_patterns'].append({
                    'pattern': pattern.decode('utf-8', errors='ignore'),
                    'type': danger_type,
                    'count': self.data.count(pattern)
                })
    
    def save_results(self):
        """Save to Ladybug-compatible JSON"""
        # Save to current directory, not next to driver (avoids permission issues)
        output_file = Path.cwd() / (self.driver_path.stem + '_analysis.json')
        
        # Convert to Ladybug format
        ladybug_format = {
            'driver': self.results['driver'],
            'driver_path': self.results['driver_path'],
            'architecture': self.results['architecture'],
            'dangerous_patterns': self.results['dangerous_patterns'],
        }
        
        # Add each IOCTL
        for ioctl in self.results['ioctls']:
            ladybug_format[ioctl['code']] = {
                'code': ioctl['code_int'],
                'min_input_size': 0,
                'max_input_size': 4096,
                'min_output_size': 0,
                'method': ioctl['method'],
                'access': ioctl['access'],
                'address': '0x0',
                'device_type': ioctl['device_type'],
                'warning': ioctl.get('warning'),
                'priority': ioctl['priority']
            }
        
        with open(output_file, 'w') as f:
            json.dump(ladybug_format, f, indent=2)
        
        return output_file
    
    def print_summary(self):
        """Print nice summary"""
        print()
        print("╔══════════════════════════════════════════════════════════════════════════════╗")
        print("║                     🔬 QUICK DRIVER ANALYSIS                                 ║")
        print("╠══════════════════════════════════════════════════════════════════════════════╣")
        print(f"║  Driver:       {self.results['driver']:<60}║")
        print(f"║  Architecture: {self.results['architecture']:<60}║")
        print(f"║  IOCTLs Found: {len(self.results['ioctls']):<60}║")
        print(f"║  METHOD_NEITHER (dangerous): {self.results['method_neither_count']:<46}║")
        print("╚══════════════════════════════════════════════════════════════════════════════╝")
        
        if self.results['ioctls']:
            print()
            print("┌──────────────────────────────────────────────────────────────────────────────┐")
            print("│                          DISCOVERED IOCTLs                                   │")
            print("├──────────────────────────────────────────────────────────────────────────────┤")
            
            # Sort by priority
            sorted_ioctls = sorted(self.results['ioctls'], 
                                   key=lambda x: x['priority'], 
                                   reverse=True)
            
            for ioctl in sorted_ioctls[:20]:
                stars = "★" * (ioctl['priority'] // 20)
                warning = " ⚠️" if 'warning' in ioctl else ""
                print(f"│  {ioctl['code']}  [{ioctl['method']:12}]  P:{ioctl['priority']:3}  {stars:5}{warning:3}        │")
            
            if len(self.results['ioctls']) > 20:
                print(f"│  ... and {len(self.results['ioctls']) - 20} more                                                        │")
            
            print("└──────────────────────────────────────────────────────────────────────────────┘")
        
        if self.results['dangerous_patterns']:
            print()
            print("┌──────────────────────────────────────────────────────────────────────────────┐")
            print("│                       ⚠️  DANGEROUS PATTERNS                                 │")
            print("├──────────────────────────────────────────────────────────────────────────────┤")
            for p in self.results['dangerous_patterns']:
                print(f"│  {p['pattern']:20} ({p['type']:15}) x{p['count']:<5}                         │")
            print("└──────────────────────────────────────────────────────────────────────────────┘")


def main():
    if len(sys.argv) < 2:
        print("Usage: python quick_scan.py driver.sys")
        print()
        print("Quick IOCTL scanner - extracts potential IOCTL codes from driver binary")
        print("Output: driver.analysis.json (compatible with ladybug --analysis)")
        sys.exit(1)
    
    driver_path = sys.argv[1]
    if not Path(driver_path).exists():
        print(f"[-] File not found: {driver_path}")
        sys.exit(1)
    
    scanner = QuickDriverScanner(driver_path)
    scanner.scan_for_ioctls()
    scanner.scan_dangerous_patterns()
    output_file = scanner.save_results()
    scanner.print_summary()
    
    print()
    print("┌──────────────────────────────────────────────────────────────────────────────┐")
    print("│                          💾 SAVED & USAGE                                    │")
    print("├──────────────────────────────────────────────────────────────────────────────┤")
    print(f"│  Saved to: {str(output_file):<64}│")
    print("│                                                                              │")
    print("│  Use with Ladybug:                                                           │")
    print(f"│    ladybug --device \\\\.\\DRIVER --analysis {output_file.name:<32}│")
    print("│                                                                              │")
    print("│  Or fuzz directly:                                                           │")
    print("│    ladybug --device \\\\.\\DRIVER --ultimate --iterations 1000000              │")
    print("└──────────────────────────────────────────────────────────────────────────────┘")


if __name__ == '__main__':
    main()
