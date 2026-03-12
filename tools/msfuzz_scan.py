#!/usr/bin/env python3
"""
MSFuzz-style Driver Scanner
Scans a driver and shows global popularity of each IOCTL (how many drivers share it)

Usage:
    python msfuzz_scan.py <driver.sys> -o output.json
    python msfuzz_scan.py C:\Windows\System32\drivers\ahcache.sys -o ahcache.json

This finds IOCTLs in YOUR driver, then checks how many OTHER drivers also have each one.
IOCTLs shared by many drivers = higher chance of finding bugs that affect the ecosystem!
"""

import struct
import os
import json
import argparse
from pathlib import Path
from collections import defaultdict
import sys

# IOCTL format
METHODS = ['BUFFERED', 'IN_DIRECT', 'OUT_DIRECT', 'NEITHER']
ACCESS = ['ANY', 'READ', 'WRITE', 'RW']

def parse_ioctl(val):
    """Parse IOCTL into components"""
    device_type = (val >> 16) & 0xFFFF
    access = (val >> 14) & 0x3
    function = (val >> 2) & 0xFFF
    method = val & 0x3
    return device_type, function, method, access


def is_valid_ioctl(val):
    """Strict validation - only device type 0x22 with custom function codes"""
    if val >= 0x80000000:  # NTSTATUS
        return False
    
    device_type, function, method, access = parse_ioctl(val)
    
    # Only FILE_DEVICE_UNKNOWN (0x22) - most custom drivers use this
    if device_type != 0x22:
        return False
    
    # Custom IOCTLs use function >= 0x800
    if function < 0x800 or function > 0xFFF:
        return False
    
    return True


def scan_driver_file(filepath):
    """Scan a single driver for IOCTLs"""
    ioctls = set()
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
        
        for i in range(len(data) - 4):
            val = struct.unpack('<I', data[i:i+4])[0]
            if is_valid_ioctl(val):
                ioctls.add(val)
    except:
        pass
    return ioctls


def build_global_ioctl_map(driver_dir=r'C:\Windows\System32\drivers'):
    """Scan ALL drivers and build IOCTL -> driver list mapping"""
    print(f'[*] Building global IOCTL database from {driver_dir}...')
    
    global_map = defaultdict(set)  # ioctl -> set of driver names
    
    count = 0
    drivers = [f for f in os.listdir(driver_dir) if f.lower().endswith('.sys')]
    total = len(drivers)
    
    for i, fname in enumerate(drivers):
        fpath = os.path.join(driver_dir, fname)
        ioctls = scan_driver_file(fpath)
        for ioctl in ioctls:
            global_map[ioctl].add(fname)
        count += 1
        
        # Progress indicator
        if (i + 1) % 50 == 0:
            print(f'    Scanned {i+1}/{total} drivers...')
    
    print(f'[+] Scanned {count} drivers, found {len(global_map)} unique IOCTLs')
    return global_map


def main():
    parser = argparse.ArgumentParser(
        description='MSFuzz-style Driver Scanner - finds IOCTLs and their global popularity',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python msfuzz_scan.py C:\\Windows\\System32\\drivers\\ahcache.sys -o ahcache.json
    python msfuzz_scan.py ndis.sys -o ndis.json --min-global 5
        """
    )
    
    parser.add_argument('driver', help='Path to driver .sys file')
    parser.add_argument('-o', '--output', required=True, help='Output JSON file')
    parser.add_argument('--device', help='Device path (e.g., \\\\.\\ahcache)')
    parser.add_argument('--min-global', type=int, default=1, 
                        help='Only include IOCTLs found in at least N drivers (default: 1)')
    parser.add_argument('--drivers-dir', default=r'C:\Windows\System32\drivers',
                        help='Directory to scan for global IOCTL database')
    
    args = parser.parse_args()
    
    # Resolve driver path
    driver_path = args.driver
    if not os.path.exists(driver_path):
        # Try System32\drivers
        alt_path = os.path.join(r'C:\Windows\System32\drivers', args.driver)
        if os.path.exists(alt_path):
            driver_path = alt_path
        else:
            print(f'[!] Driver not found: {args.driver}')
            sys.exit(1)
    
    driver_name = Path(driver_path).name
    print(f'[*] Target driver: {driver_name}')
    print(f'[*] Full path: {driver_path}')
    
    # Step 1: Scan target driver
    print(f'\n[*] Step 1: Scanning {driver_name} for IOCTLs...')
    target_ioctls = scan_driver_file(driver_path)
    print(f'[+] Found {len(target_ioctls)} IOCTLs in {driver_name}')
    
    if not target_ioctls:
        print('[!] No IOCTLs found in target driver!')
        sys.exit(1)
    
    # Step 2: Build global database
    print(f'\n[*] Step 2: Building global IOCTL database...')
    global_map = build_global_ioctl_map(args.drivers_dir)
    
    # Step 3: For each IOCTL in target, find global popularity
    print(f'\n[*] Step 3: Analyzing global popularity of {driver_name} IOCTLs...')
    
    results = []
    for ioctl in sorted(target_ioctls):
        device_type, function, method, access = parse_ioctl(ioctl)
        
        # How many drivers have this IOCTL?
        drivers_with_ioctl = global_map.get(ioctl, set())
        global_count = len(drivers_with_ioctl)
        
        # Get sample of other drivers (exclude target)
        other_drivers = [d for d in drivers_with_ioctl if d.lower() != driver_name.lower()]
        
        results.append({
            'ioctl': f'0x{ioctl:08X}',
            'ioctl_int': ioctl,
            'device_type': device_type,
            'function': function,
            'method': METHODS[method],
            'access': ACCESS[access],
            'global_count': global_count,
            'other_drivers': other_drivers[:10],  # Sample of up to 10 other drivers
            'is_unique': global_count == 1,
            'is_global': global_count >= 10
        })
    
    # Sort by global count (most popular first)
    results.sort(key=lambda x: x['global_count'], reverse=True)
    
    # Filter by min-global
    if args.min_global > 1:
        results = [r for r in results if r['global_count'] >= args.min_global]
        print(f'[+] After filtering (min {args.min_global} drivers): {len(results)} IOCTLs')
    
    # Display results
    print(f'\n{"="*80}')
    print(f' IOCTLs in {driver_name} with Global Popularity')
    print(f'{"="*80}')
    print(f'{"IOCTL":<14} {"Method":<12} {"Access":<8} {"Global":<8} {"Other Drivers"}')
    print(f'{"-"*14} {"-"*12} {"-"*8} {"-"*8} {"-"*30}')
    
    for r in results:
        other = ', '.join(r['other_drivers'][:3])
        if len(r['other_drivers']) > 3:
            other += f' +{len(r["other_drivers"])-3} more'
        
        marker = '🔥' if r['global_count'] >= 50 else ('⭐' if r['global_count'] >= 10 else '')
        print(f'{r["ioctl"]:<14} {r["method"]:<12} {r["access"]:<8} {r["global_count"]:<8} {other} {marker}')
    
    # Summary
    print(f'\n{"="*80}')
    unique_count = sum(1 for r in results if r['is_unique'])
    global_count = sum(1 for r in results if r['is_global'])
    print(f'[+] Summary:')
    print(f'    Total IOCTLs: {len(results)}')
    print(f'    Unique to {driver_name}: {unique_count}')
    print(f'    Global (10+ drivers): {global_count} 🔥')
    
    # Build output JSON
    device_path = args.device or f'\\\\.\\{Path(driver_path).stem}'
    
    ioctls_dict = {}
    for r in results:
        ioctls_dict[r['ioctl']] = {
            'min_input_size': 0,
            'max_input_size': 4096,
            'min_output_size': 0,
            'method': r['method'],
            'access': r['access'],
            'function': r['function'],
            'device_type': r['device_type'],
            'global_count': r['global_count'],
            'is_global': r['is_global'],
            'other_drivers': r['other_drivers']
        }
    
    output = {
        'driver': driver_name,
        'device_path': device_path,
        'ioctl_count': len(results),
        'global_ioctls': global_count,
        'unique_ioctls': unique_count,
        'ioctls': ioctls_dict
    }
    
    # Save
    with open(args.output, 'w') as f:
        json.dump(output, f, indent=2)
    
    print(f'\n[+] Saved to {args.output}')
    print(f'\n[*] Usage with Ladybug:')
    print(f'    ladybug.exe --device "{device_path}" --analysis {args.output} --target <ip>:9999')


if __name__ == '__main__':
    main()
