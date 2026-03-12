#!/usr/bin/env python3
"""
Quick IOCTL Scanner - Fast heuristic analysis without full symbolic execution
Works without Angr for quick results.

Usage:
    python quick_scan.py <driver.sys> -o output.json
"""

import struct
import json
import argparse
import re
from pathlib import Path
from collections import defaultdict

# PE parsing
class PEParser:
    def __init__(self, data: bytes):
        self.data = data
        self.parse_headers()
        
    def parse_headers(self):
        # DOS header
        if self.data[:2] != b'MZ':
            raise ValueError("Not a valid PE file")
        
        # PE offset at 0x3C
        pe_offset = struct.unpack_from('<I', self.data, 0x3C)[0]
        
        if self.data[pe_offset:pe_offset+4] != b'PE\x00\x00':
            raise ValueError("Invalid PE signature")
        
        # COFF header
        coff_offset = pe_offset + 4
        self.machine = struct.unpack_from('<H', self.data, coff_offset)[0]
        self.num_sections = struct.unpack_from('<H', self.data, coff_offset + 2)[0]
        self.opt_header_size = struct.unpack_from('<H', self.data, coff_offset + 16)[0]
        
        # Optional header
        opt_offset = coff_offset + 20
        magic = struct.unpack_from('<H', self.data, opt_offset)[0]
        self.is_64bit = (magic == 0x20b)
        
        if self.is_64bit:
            self.image_base = struct.unpack_from('<Q', self.data, opt_offset + 24)[0]
        else:
            self.image_base = struct.unpack_from('<I', self.data, opt_offset + 28)[0]
        
        # Section headers
        section_offset = opt_offset + self.opt_header_size
        self.sections = []
        for i in range(self.num_sections):
            sec_data = self.data[section_offset + i*40 : section_offset + (i+1)*40]
            name = sec_data[:8].rstrip(b'\x00').decode('ascii', errors='ignore')
            virt_size = struct.unpack_from('<I', sec_data, 8)[0]
            virt_addr = struct.unpack_from('<I', sec_data, 12)[0]
            raw_size = struct.unpack_from('<I', sec_data, 16)[0]
            raw_addr = struct.unpack_from('<I', sec_data, 20)[0]
            self.sections.append({
                'name': name,
                'virt_addr': virt_addr,
                'virt_size': virt_size,
                'raw_addr': raw_addr,
                'raw_size': raw_size
            })
    
    def get_code_sections(self):
        """Get executable sections (.text, PAGE, etc.)"""
        code_sections = []
        for sec in self.sections:
            if sec['name'] in ['.text', 'PAGE', 'INIT', '.code']:
                code_sections.append(sec)
        return code_sections if code_sections else self.sections  # Fallback to all


def find_ioctl_codes(data: bytes, pe: PEParser) -> dict:
    """
    Find IOCTL codes by scanning for typical patterns:
    - CMP reg, imm32 (0x81 0xF? or 0x3D)
    - MOV reg, imm32 (0xB8+)
    - SUB reg, imm32 (0x81 0xE?)
    """
    ioctls = {}
    
    for section in pe.get_code_sections():
        start = section['raw_addr']
        end = start + section['raw_size']
        code = data[start:end]
        
        # Pattern 1: CMP EAX, imm32 (3D xx xx xx xx)
        for match in re.finditer(b'\x3D(....)', code):
            val = struct.unpack('<I', match.group(1))[0]
            if is_valid_ioctl(val):
                addr = pe.image_base + section['virt_addr'] + match.start()
                ioctls[val] = {'addr': addr, 'pattern': 'cmp eax'}
        
        # Pattern 2: CMP r32, imm32 (81 F8-FF xx xx xx xx)
        for match in re.finditer(b'\x81[\xF8-\xFF](....)', code):
            val = struct.unpack('<I', match.group(1))[0]
            if is_valid_ioctl(val):
                addr = pe.image_base + section['virt_addr'] + match.start()
                ioctls[val] = {'addr': addr, 'pattern': 'cmp r32'}
        
        # Pattern 3: MOV r32, imm32 (B8-BF xx xx xx xx)
        for match in re.finditer(b'[\xB8-\xBF](....)', code):
            val = struct.unpack('<I', match.group(1))[0]
            if is_valid_ioctl(val):
                addr = pe.image_base + section['virt_addr'] + match.start()
                if val not in ioctls:  # Don't overwrite CMP hits
                    ioctls[val] = {'addr': addr, 'pattern': 'mov r32'}
        
        # Pattern 4: SUB EAX, imm32 (2D xx xx xx xx) - switch jump tables
        for match in re.finditer(b'\x2D(....)', code):
            val = struct.unpack('<I', match.group(1))[0]
            if is_valid_ioctl(val):
                addr = pe.image_base + section['virt_addr'] + match.start()
                if val not in ioctls:
                    ioctls[val] = {'addr': addr, 'pattern': 'sub eax'}
    
    return ioctls


def is_valid_ioctl(val: int) -> bool:
    """
    Check if value looks like a valid IOCTL code.
    IOCTL format: ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method)
    """
    if val < 0x00010000 or val > 0x00FFFFFF:
        return False
    
    device_type = (val >> 16) & 0xFFFF
    access = (val >> 14) & 0x3
    function = (val >> 2) & 0xFFF
    method = val & 0x3
    
    # Valid device types are typically < 0x8000 (vendor defined start at 0x8000)
    if device_type >= 0x8000:
        return False
    
    # Function number shouldn't be huge
    if function > 0x800:
        return False
    
    return True


def decode_ioctl(code: int) -> dict:
    """Decode IOCTL code into components"""
    return {
        'device_type': (code >> 16) & 0xFFFF,
        'access': (code >> 14) & 0x3,
        'function': (code >> 2) & 0xFFF,
        'method': code & 0x3,
        'access_str': ['ANY', 'READ', 'WRITE', 'READ|WRITE'][(code >> 14) & 0x3],
        'method_str': ['BUFFERED', 'IN_DIRECT', 'OUT_DIRECT', 'NEITHER'][code & 0x3]
    }


def find_size_checks(data: bytes, pe: PEParser, ioctl_addrs: dict) -> dict:
    """
    Look for size validation patterns near IOCTL handlers.
    Common patterns:
    - CMP [reg+offset], imm  (compare InputBufferLength)
    - JB/JBE (jump if below - size too small)
    """
    size_constraints = defaultdict(lambda: {'min_size': 0, 'checks': []})
    
    for section in pe.get_code_sections():
        start = section['raw_addr']
        end = start + section['raw_size']
        code = data[start:end]
        
        # Look for CMP r32, small_imm followed by JB/JBE
        # Pattern: 83 F8-FF xx (cmp r32, imm8)
        for match in re.finditer(b'\x83[\xF8-\xFF](.)\x72', code):  # 72 = JB
            size_val = match.group(1)[0]
            if 4 <= size_val <= 0x1000:  # Reasonable buffer size
                addr = pe.image_base + section['virt_addr'] + match.start()
                # Find which IOCTL this might belong to
                for ioctl, info in ioctl_addrs.items():
                    if abs(info['addr'] - addr) < 0x200:  # Within ~512 bytes
                        size_constraints[ioctl]['min_size'] = max(
                            size_constraints[ioctl]['min_size'], 
                            size_val
                        )
                        size_constraints[ioctl]['checks'].append({
                            'addr': addr,
                            'size': size_val
                        })
        
        # Look for CMP with larger imm32
        for match in re.finditer(b'\x3D(....)\x72', code):  # cmp eax, imm32; jb
            size_val = struct.unpack('<I', match.group(1))[0]
            if 4 <= size_val <= 0x10000:
                addr = pe.image_base + section['virt_addr'] + match.start()
                for ioctl, info in ioctl_addrs.items():
                    if abs(info['addr'] - addr) < 0x200:
                        size_constraints[ioctl]['min_size'] = max(
                            size_constraints[ioctl]['min_size'],
                            size_val
                        )
    
    return dict(size_constraints)


def analyze_driver(driver_path: str) -> dict:
    """Main analysis function"""
    
    print(f"[*] Analyzing: {driver_path}")
    
    with open(driver_path, 'rb') as f:
        data = f.read()
    
    pe = PEParser(data)
    print(f"[+] PE loaded: {'x64' if pe.is_64bit else 'x86'}")
    print(f"[+] Image base: 0x{pe.image_base:X}")
    print(f"[+] Sections: {[s['name'] for s in pe.sections]}")
    
    # Find IOCTL codes
    ioctl_codes = find_ioctl_codes(data, pe)
    print(f"[+] Found {len(ioctl_codes)} IOCTL codes")
    
    # Find size constraints
    size_constraints = find_size_checks(data, pe, ioctl_codes)
    
    # Build results
    results = {
        "driver": Path(driver_path).name,
        "architecture": "x64" if pe.is_64bit else "x86",
        "image_base": f"0x{pe.image_base:X}",
        "ioctls": {}
    }
    
    for code, info in sorted(ioctl_codes.items()):
        decoded = decode_ioctl(code)
        ioctl_hex = f"0x{code:08X}"
        
        results["ioctls"][ioctl_hex] = {
            "address": f"0x{info['addr']:X}",
            "device_type": decoded['device_type'],
            "function": decoded['function'],
            "method": decoded['method_str'],
            "access": decoded['access_str'],
            "min_input_size": size_constraints.get(code, {}).get('min_size', 0),
            "pattern": info['pattern']
        }
    
    return results


def main():
    parser = argparse.ArgumentParser(description="Quick IOCTL Scanner for Windows Drivers")
    parser.add_argument("driver", help="Path to driver .sys file")
    parser.add_argument("-o", "--output", default="scan_result.json", help="Output JSON file")
    
    args = parser.parse_args()
    
    if not Path(args.driver).exists():
        print(f"[!] File not found: {args.driver}")
        return 1
    
    try:
        results = analyze_driver(args.driver)
        
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\n[+] Results saved to: {args.output}")
        print("\n" + "="*60)
        print("IOCTL SUMMARY")
        print("="*60)
        
        for ioctl, info in results["ioctls"].items():
            print(f"\n{ioctl}:")
            print(f"  Address:    {info['address']}")
            print(f"  Method:     {info['method']}")
            print(f"  Access:     {info['access']}")
            print(f"  Min Input:  {info['min_input_size']} bytes")
        
        return 0
        
    except Exception as e:
        print(f"[!] Analysis failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit(main())
