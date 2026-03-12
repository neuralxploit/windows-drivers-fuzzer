#!/usr/bin/env python3
"""
LADYBUG IOCTL Converter & Analyzer
Converts Ghidra output to Ladybug format and sorts by risk level

Usage:
    python convert_ioctls.py ahcache
    python convert_ioctls.py afd
    python convert_ioctls.py tcpip
    python convert_ioctls.py C:\path\to\driver_ghidra_v2.json
"""

import json
import sys
import os
from pathlib import Path

# Paths
SCRIPT_DIR = Path(__file__).parent
OUTPUT_DIR = SCRIPT_DIR.parent.parent / "vm_fuzzing"

def decode_ioctl(code):
    """Decode IOCTL code into components"""
    device_type = (code >> 16) & 0xFFFF
    function = (code >> 2) & 0xFFF
    method = code & 3
    access = (code >> 14) & 3
    
    method_str = ['BUFFERED', 'IN_DIRECT', 'OUT_DIRECT', 'NEITHER'][method]
    access_str = ['ANY', 'READ', 'WRITE', 'READ|WRITE'][access]
    
    return {
        'device_type': device_type,
        'function': function,
        'method': method,
        'method_str': method_str,
        'access': access,
        'access_str': access_str
    }

def get_risk_score(method, refs):
    """Calculate risk score for sorting (higher = more interesting)"""
    # NEITHER = highest risk (direct user pointers)
    # IN/OUT_DIRECT = medium risk (MDL-based)
    # BUFFERED = lowest risk (kernel copies)
    method_scores = {3: 1000, 2: 500, 1: 500, 0: 100}
    return method_scores.get(method, 0) + refs

def analyze_and_convert(input_path, driver_name=None):
    """Load Ghidra JSON, analyze, sort by risk, and save for Ladybug"""
    
    # Make sure input_path is a Path object with full path
    if not isinstance(input_path, Path):
        input_path = Path(input_path)
    
    # Resolve to absolute path
    input_path = input_path.resolve()
    
    # Load input
    print(f"[*] Loading: {input_path}")
    
    if not input_path.exists():
        print(f"[!] ERROR: File not found: {input_path}")
        sys.exit(1)
    
    with open(input_path, 'r') as f:
        data = json.load(f)
    
    # Extract driver name from filename if not provided
    if not driver_name:
        driver_name = Path(input_path).stem.replace('_ghidra_v2', '').replace('_analysis', '')
    
    # Filter IOCTLs
    ioctls = []
    for key, value in data.items():
        if not key.startswith('0x'):
            continue
        
        code = int(key, 16)
        decoded = decode_ioctl(code)
        refs = len(value.get('sources', [])) if isinstance(value, dict) else 0
        
        ioctls.append({
            'hex': key,
            'code': code,
            **decoded,
            'refs': refs,
            'risk_score': get_risk_score(decoded['method'], refs),
            'sources': value.get('sources', []) if isinstance(value, dict) else []
        })
    
    if not ioctls:
        print(f"[!] No IOCTLs found in {input_path}")
        return None
    
    # Sort by risk (highest first)
    ioctls.sort(key=lambda x: -x['risk_score'])
    
    # Print analysis
    print(f"\n{'='*60}")
    print(f"  📊 {driver_name.upper()}.SYS IOCTL ANALYSIS")
    print(f"{'='*60}\n")
    
    # Stats
    neither = sum(1 for i in ioctls if i['method'] == 3)
    direct = sum(1 for i in ioctls if i['method'] in [1, 2])
    buffered = sum(1 for i in ioctls if i['method'] == 0)
    
    print(f"  Total IOCTLs:     {len(ioctls)}")
    print(f"  🔥 NEITHER:       {neither} (HIGH RISK - direct pointers)")
    print(f"  ⚠️  DIRECT:        {direct} (MEDIUM RISK - MDL-based)")
    print(f"  ✓  BUFFERED:      {buffered} (LOW RISK - kernel copies)")
    
    # Top targets
    print(f"\n{'─'*60}")
    print(f"  🎯 TOP 20 TARGETS (sorted by risk)")
    print(f"{'─'*60}")
    print(f"  {'IOCTL':<14} {'Method':<12} {'Access':<8} {'Func':<6} {'Refs':<4} Risk")
    print(f"  {'-'*54}")
    
    for i in ioctls[:20]:
        risk_icon = '🔥' if i['method'] == 3 else '⚠️' if i['method'] in [1,2] else '  '
        print(f"  {i['hex']:<14} {i['method_str']:<12} {i['access_str']:<8} {i['function']:<6} {i['refs']:<4} {risk_icon}")
    
    if len(ioctls) > 20:
        print(f"  ... and {len(ioctls) - 20} more")
    
    # Create Ladybug format output
    output = {
        'driver': f'{driver_name}.sys',
        'device': f'\\\\.\\{driver_name}',
        'total_ioctls': len(ioctls),
        'high_risk': neither,
        'medium_risk': direct,
        'low_risk': buffered
    }
    
    # Add IOCTLs sorted by risk
    for i in ioctls:
        output[i['hex']] = {
            'min_input_size': 0,
            'max_input_size': 4096,
            'min_output_size': 0,
            'method': i['method_str'],
            'access': i['access_str'],
            'address': 0,
            'risk_score': i['risk_score'],
            'sources': i['sources']
        }
    
    # Save output
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    output_path = OUTPUT_DIR / f"{driver_name}_analysis.json"
    
    with open(output_path, 'w') as f:
        json.dump(output, f, indent=2)
    
    print(f"\n{'='*60}")
    print(f"  ✅ SAVED: {output_path}")
    print(f"{'='*60}")
    
    # Also save a "high risk only" version
    high_risk_ioctls = [i for i in ioctls if i['method'] >= 1]  # NEITHER + DIRECT
    if high_risk_ioctls:
        high_risk_output = {
            'driver': f'{driver_name}.sys',
            'device': f'\\\\.\\{driver_name}',
            'total_ioctls': len(high_risk_ioctls),
            'filter': 'HIGH_RISK_ONLY (NEITHER + DIRECT methods)'
        }
        for i in high_risk_ioctls:
            high_risk_output[i['hex']] = {
                'min_input_size': 0,
                'max_input_size': 4096,
                'min_output_size': 0,
                'method': i['method_str'],
                'access': i['access_str'],
                'address': 0,
                'risk_score': i['risk_score']
            }
        
        high_risk_path = OUTPUT_DIR / f"{driver_name}_high_risk.json"
        with open(high_risk_path, 'w') as f:
            json.dump(high_risk_output, f, indent=2)
        print(f"  ✅ SAVED: {high_risk_path} ({len(high_risk_ioctls)} IOCTLs)")
    
    print(f"\n  📋 Usage:")
    print(f"     .\\ladybug.exe --device \"\\\\.\\{driver_name}\" --analysis {driver_name}_analysis.json")
    print(f"     .\\ladybug.exe --device \"\\\\.\\{driver_name}\" --analysis {driver_name}_high_risk.json  # risky only")
    
    return output_path

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        print("\nAvailable Ghidra outputs:")
        for f in SCRIPT_DIR.glob("*_ghidra_v2.json"):
            print(f"  - {f.stem.replace('_ghidra_v2', '')}")
        sys.exit(1)
    
    arg = sys.argv[1]
    
    # Check if it's a full path to a JSON file (not a directory!)
    if os.path.isfile(arg):
        input_path = Path(arg)
        driver_name = input_path.stem.replace('_ghidra_v2', '').replace('_analysis', '')
    else:
        # Assume it's a driver name, look for ghidra output in SCRIPT_DIR
        driver_name = arg.replace('.sys', '')
        input_path = SCRIPT_DIR / f"{driver_name}_ghidra_v2.json"
        
        if not input_path.exists():
            # Try without _ghidra_v2 suffix
            input_path = SCRIPT_DIR / f"{driver_name}.json"
        
        if not input_path.exists():
            print(f"[!] Not found: {input_path}")
            print(f"[*] Run Ghidra first:")
            print(f'    .\\analyze_driver.ps1 C:\\Windows\\System32\\drivers\\{driver_name}.sys')
            sys.exit(1)
    
    analyze_and_convert(input_path, driver_name)

if __name__ == '__main__':
    main()
