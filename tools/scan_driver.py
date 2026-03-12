#!/usr/bin/env python3
"""
Universal Windows Driver IOCTL Scanner
Extracts IOCTLs from any driver and optionally includes global common IOCTLs

Usage:
    python scan_driver.py <driver.sys> -o output.json
    python scan_driver.py <driver.sys> -o output.json --global
    python scan_driver.py <driver.sys> -o output.json --device \\.\MyDevice
    python scan_driver.py --scan-all -o all_drivers.json

Examples:
    python scan_driver.py C:\Windows\System32\drivers\ahcache.sys -o ahcache.json
    python scan_driver.py C:\Windows\System32\drivers\ndis.sys -o ndis.json --global
    python scan_driver.py --scan-all -o global_ioctls.json --min-drivers 5
"""

import struct
import os
import json
import argparse
from pathlib import Path
from collections import defaultdict


# Windows IOCTL format:
# Bits 31-16: Device Type
# Bits 15-14: Access (0=ANY, 1=READ, 2=WRITE, 3=RW)
# Bits 13-2:  Function code
# Bits 1-0:   Method (0=BUFFERED, 1=IN_DIRECT, 2=OUT_DIRECT, 3=NEITHER)

METHODS = ['BUFFERED', 'IN_DIRECT', 'OUT_DIRECT', 'NEITHER']
ACCESS = ['ANY', 'READ', 'WRITE', 'RW']

# Valid device types (< 0x8000, values >= 0x8000 are NTSTATUS codes!)
VALID_DEVICE_TYPES = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
    0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14,
    0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
    0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32,
    0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C,
    0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46,
    0x47, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
    0x59, 0x5A, 0x5B, 0x5C,
}


def parse_ioctl(val):
    """Parse IOCTL value into components"""
    device_type = (val >> 16) & 0xFFFF
    access = (val >> 14) & 0x3
    function = (val >> 2) & 0xFFF
    method = val & 0x3
    return device_type, function, method, access


def is_valid_ioctl(val):
    """Check if value looks like a real IOCTL"""
    if val >= 0x80000000:  # NTSTATUS codes
        return False
    
    device_type, function, method, access = parse_ioctl(val)
    
    # Only device type 0x22 (FILE_DEVICE_UNKNOWN) for custom drivers
    # This is what 99% of custom drivers use
    if device_type != 0x22:
        return False
    
    # Custom IOCTLs use function codes >= 0x800
    if function < 0x800 or function > 0xFFF:
        return False
    
    return True


def scan_driver(driver_path, min_function=0x800):
    """Scan a driver file for IOCTL codes"""
    ioctls = set()
    
    with open(driver_path, 'rb') as f:
        data = f.read()
    
    # Scan for 4-byte values that look like IOCTLs
    for i in range(len(data) - 4):
        val = struct.unpack('<I', data[i:i+4])[0]
        
        if not is_valid_ioctl(val):
            continue
        
        device_type, function, method, access = parse_ioctl(val)
        
        # Filter by minimum function code (0x800+ for custom IOCTLs)
        if function >= min_function:
            ioctls.add(val)
    
    return ioctls


def scan_all_drivers(driver_dir=r'C:\Windows\System32\drivers', min_function=0x800):
    """Scan all drivers and return IOCTL -> set of drivers mapping"""
    all_ioctls = defaultdict(set)
    
    print(f'[*] Scanning drivers in {driver_dir}...')
    
    count = 0
    for fname in os.listdir(driver_dir):
        if fname.lower().endswith('.sys'):
            fpath = os.path.join(driver_dir, fname)
            try:
                ioctls = scan_driver(fpath, min_function)
                for ioctl in ioctls:
                    all_ioctls[ioctl].add(fname)
                count += 1
            except Exception as e:
                pass  # Skip unreadable drivers
    
    print(f'[+] Scanned {count} drivers')
    return all_ioctls


def build_ioctl_dict(ioctls, source="static"):
    """Convert set of IOCTLs to dictionary format"""
    result = {}
    
    for val in sorted(ioctls):
        device_type, function, method, access = parse_ioctl(val)
        hex_val = f'0x{val:08X}'
        
        result[hex_val] = {
            'min_input_size': 0,
            'max_input_size': 4096,
            'min_output_size': 0,
            'method': METHODS[method],
            'access': ACCESS[access],
            'function': function,
            'device_type': device_type,
            'source': source
        }
    
    return result


def main():
    parser = argparse.ArgumentParser(
        description='Universal Windows Driver IOCTL Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Scan single driver:
    python scan_driver.py C:\\Windows\\System32\\drivers\\ahcache.sys -o ahcache.json
    
  Scan driver + include global common IOCTLs:
    python scan_driver.py C:\\Windows\\System32\\drivers\\ahcache.sys -o ahcache.json --global
    
  Scan all drivers and find common IOCTLs:
    python scan_driver.py --scan-all -o global.json --min-drivers 10
    
  Specify device path for output JSON:
    python scan_driver.py ahcache.sys -o out.json --device \\\\.\\ahcache
        """
    )
    
    parser.add_argument('driver', nargs='?', help='Path to driver .sys file')
    parser.add_argument('-o', '--output', required=True, help='Output JSON file')
    parser.add_argument('--device', help='Device path (e.g., \\\\.\\ahcache)')
    parser.add_argument('--global', dest='include_global', action='store_true',
                        help='Include global common IOCTLs from all drivers')
    parser.add_argument('--scan-all', action='store_true',
                        help='Scan all drivers in System32\\drivers')
    parser.add_argument('--min-drivers', type=int, default=10,
                        help='Minimum driver count for global IOCTLs (default: 10)')
    parser.add_argument('--min-function', type=int, default=0x800,
                        help='Minimum function code to include (default: 0x800)')
    parser.add_argument('--all-functions', action='store_true',
                        help='Include all function codes (not just >= 0x800)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Verbose output')
    
    args = parser.parse_args()
    
    min_func = 0 if args.all_functions else args.min_function
    
    all_ioctls = {}
    driver_name = "GLOBAL"
    device_path = args.device or r'\\.\DEVICE'
    
    # Mode 1: Scan all drivers for global IOCTLs
    if args.scan_all:
        print('[*] Mode: Scan all drivers for common IOCTLs')
        global_map = scan_all_drivers(min_function=min_func)
        
        # Filter by minimum driver count
        common = {k: v for k, v in global_map.items() if len(v) >= args.min_drivers}
        print(f'[+] Found {len(common)} IOCTLs used by {args.min_drivers}+ drivers')
        
        # Build result
        for ioctl, drivers in sorted(common.items(), key=lambda x: len(x[1]), reverse=True):
            device_type, function, method, access = parse_ioctl(ioctl)
            hex_val = f'0x{ioctl:08X}'
            
            all_ioctls[hex_val] = {
                'min_input_size': 0,
                'max_input_size': 4096,
                'min_output_size': 0,
                'method': METHODS[method],
                'access': ACCESS[access],
                'function': function,
                'device_type': device_type,
                'driver_count': len(drivers),
                'sample_drivers': list(drivers)[:5]
            }
        
        # Show top IOCTLs
        print('\n[+] Top 15 most common IOCTLs:')
        top = sorted(common.items(), key=lambda x: len(x[1]), reverse=True)[:15]
        for ioctl, drivers in top:
            device_type, function, method, access = parse_ioctl(ioctl)
            print(f'    0x{ioctl:08X}  Dev=0x{device_type:02X} Func=0x{function:03X} '
                  f'{METHODS[method]:12} -> {len(drivers)} drivers')
    
    # Mode 2: Scan specific driver
    elif args.driver:
        if not os.path.exists(args.driver):
            print(f'[!] Driver not found: {args.driver}')
            return
        
        driver_name = Path(args.driver).name
        print(f'[*] Scanning driver: {driver_name}')
        
        # Scan the specific driver
        driver_ioctls = scan_driver(args.driver, min_func)
        print(f'[+] Found {len(driver_ioctls)} IOCTLs in {driver_name}')
        
        all_ioctls = build_ioctl_dict(driver_ioctls, source="driver")
        
        # Show found IOCTLs
        if args.verbose or len(driver_ioctls) <= 50:
            print('\n[+] IOCTLs found:')
            for ioctl in sorted(driver_ioctls):
                device_type, function, method, access = parse_ioctl(ioctl)
                print(f'    0x{ioctl:08X}  Dev=0x{device_type:02X} Func=0x{function:03X} '
                      f'{METHODS[method]:12} {ACCESS[access]}')
        
        # Optionally include global IOCTLs
        if args.include_global:
            print('\n[*] Adding global common IOCTLs...')
            global_map = scan_all_drivers(min_function=min_func)
            common = {k: v for k, v in global_map.items() if len(v) >= args.min_drivers}
            
            added = 0
            for ioctl, drivers in common.items():
                hex_val = f'0x{ioctl:08X}'
                if hex_val not in all_ioctls:
                    device_type, function, method, access = parse_ioctl(ioctl)
                    all_ioctls[hex_val] = {
                        'min_input_size': 0,
                        'max_input_size': 4096,
                        'min_output_size': 0,
                        'method': METHODS[method],
                        'access': ACCESS[access],
                        'function': function,
                        'device_type': device_type,
                        'driver_count': len(drivers),
                        'source': 'global'
                    }
                    added += 1
            
            print(f'[+] Added {added} global IOCTLs (total: {len(all_ioctls)})')
        
        # Try to guess device path from driver name
        if not args.device:
            base = Path(args.driver).stem  # Remove .sys
            device_path = f'\\\\.\\{base}'
    
    else:
        parser.print_help()
        return
    
    # Build output JSON
    output = {
        'driver': driver_name,
        'device_path': device_path,
        'ioctl_count': len(all_ioctls),
        'ioctls': all_ioctls
    }
    
    # Save to file
    with open(args.output, 'w') as f:
        json.dump(output, f, indent=2)
    
    print(f'\n[+] Saved {len(all_ioctls)} IOCTLs to {args.output}')
    print(f'[+] Device path: {device_path}')
    print(f'\n[*] Usage with Ladybug:')
    print(f'    ladybug.exe --device "{device_path}" --analysis {args.output} --target <ip>:9999')


if __name__ == '__main__':
    main()
