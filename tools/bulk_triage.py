#!/usr/bin/env python3
"""
Bulk Crash Triage Tool
Analyzes all crashes and ranks by exploitability
"""

import os
import sys
from pathlib import Path

# IOCTL method extraction
def get_method(ioctl):
    return ioctl & 0x3

METHOD_NAMES = {
    0: "METHOD_BUFFERED",
    1: "METHOD_IN_DIRECT", 
    2: "METHOD_OUT_DIRECT",
    3: "METHOD_NEITHER"  # MOST DANGEROUS!
}

def analyze_crash(crash_dir):
    """Analyze a single crash directory"""
    info_file = crash_dir / "info.txt"
    input_file = crash_dir / "input.bin"
    
    if not info_file.exists():
        return None
    
    result = {
        "dir": crash_dir.name,
        "ioctl": 0,
        "size": 0,
        "method": 0,
        "method_name": "",
        "score": 0,
        "reasons": []
    }
    
    # Parse info.txt
    with open(info_file, "r") as f:
        for line in f:
            if line.startswith("IOCTL:"):
                result["ioctl"] = int(line.split(":")[1].strip(), 16)
            elif line.startswith("Size:"):
                result["size"] = int(line.split(":")[1].strip())
    
    # Get method
    result["method"] = get_method(result["ioctl"])
    result["method_name"] = METHOD_NAMES.get(result["method"], "UNKNOWN")
    
    # Read input data
    input_data = b""
    if input_file.exists():
        with open(input_file, "rb") as f:
            input_data = f.read()
    
    # SCORING SYSTEM
    score = 0
    reasons = []
    
    # METHOD_NEITHER is most exploitable (direct user buffer access)
    if result["method"] == 3:
        score += 50
        reasons.append("METHOD_NEITHER (direct buffer access)")
    
    # Small inputs that crash = likely null deref or bounds issue
    if result["size"] == 0:
        score += 30
        reasons.append("Zero-size input (null deref?)")
    elif result["size"] < 50:
        score += 20
        reasons.append("Small input (bounds check issue?)")
    
    # Check for controlled patterns in input
    if b"\x41\x41\x41\x41" in input_data:
        score += 15
        reasons.append("Contains 0x41414141 pattern")
    
    # Check for potential pointer-sized values
    if len(input_data) >= 8:
        # Look for values that could be addresses
        for i in range(0, len(input_data) - 7, 8):
            val = int.from_bytes(input_data[i:i+8], 'little')
            if 0xFFFF800000000000 <= val <= 0xFFFFFFFFFFFFFFFF:
                score += 25
                reasons.append(f"Contains kernel-range address at offset {i}")
                break
            if 0x00007FF000000000 <= val <= 0x00007FFFFFFFFFFF:
                score += 20
                reasons.append(f"Contains user-range address at offset {i}")
                break
    
    # Specific IOCTL patterns that are often vulnerable
    device_type = (result["ioctl"] >> 16) & 0xFFFF
    function = (result["ioctl"] >> 2) & 0xFFF
    
    # High function codes often = less tested
    if function > 0x800:
        score += 10
        reasons.append(f"High function code: 0x{function:X}")
    
    # Device type 0x8000+ = third party driver
    if device_type >= 0x8000:
        score += 5
        reasons.append("Third-party device type")
    
    result["score"] = score
    result["reasons"] = reasons
    
    return result

def main():
    if len(sys.argv) > 1:
        crashes_dir = Path(sys.argv[1])
    else:
        crashes_dir = Path("./crashes")
    
    if not crashes_dir.exists():
        print(f"[!] Crashes directory not found: {crashes_dir}")
        sys.exit(1)
    
    print("=" * 70)
    print("  BULK CRASH TRIAGE - Exploitability Analysis")
    print("=" * 70)
    print()
    
    crashes = []
    
    # Analyze all crashes
    for crash_dir in crashes_dir.iterdir():
        if crash_dir.is_dir() and crash_dir.name.startswith("crash_"):
            result = analyze_crash(crash_dir)
            if result:
                crashes.append(result)
    
    # Sort by score (highest first)
    crashes.sort(key=lambda x: x["score"], reverse=True)
    
    print(f"[+] Analyzed {len(crashes)} crashes\n")
    
    # Group by priority
    critical = [c for c in crashes if c["score"] >= 50]
    high = [c for c in crashes if 30 <= c["score"] < 50]
    medium = [c for c in crashes if 10 <= c["score"] < 30]
    low = [c for c in crashes if c["score"] < 10]
    
    # Stats by method
    methods = {}
    for c in crashes:
        m = c["method_name"]
        methods[m] = methods.get(m, 0) + 1
    
    print("=" * 70)
    print("  STATISTICS")
    print("=" * 70)
    print(f"  Total crashes:     {len(crashes)}")
    print(f"  🔴 CRITICAL (50+): {len(critical)}")
    print(f"  🟠 HIGH (30-49):   {len(high)}")
    print(f"  🟡 MEDIUM (10-29): {len(medium)}")
    print(f"  🟢 LOW (<10):      {len(low)}")
    print()
    print("  By IOCTL Method:")
    for m, count in sorted(methods.items(), key=lambda x: -x[1]):
        marker = "⚠️ " if "NEITHER" in m else "  "
        print(f"    {marker}{m}: {count}")
    print()
    
    # Show critical crashes
    if critical:
        print("=" * 70)
        print("  🔴 CRITICAL PRIORITY - Investigate First!")
        print("=" * 70)
        for c in critical[:20]:  # Top 20
            print(f"\n  [{c['score']}] {c['dir']}")
            print(f"      IOCTL: 0x{c['ioctl']:08X} | Size: {c['size']} | {c['method_name']}")
            for r in c["reasons"]:
                print(f"      ✓ {r}")
    
    # Show high priority
    if high:
        print("\n" + "=" * 70)
        print("  🟠 HIGH PRIORITY")
        print("=" * 70)
        for c in high[:10]:
            print(f"\n  [{c['score']}] {c['dir']}")
            print(f"      IOCTL: 0x{c['ioctl']:08X} | Size: {c['size']} | {c['method_name']}")
    
    # Generate report file
    report_file = crashes_dir / "TRIAGE_REPORT.txt"
    with open(report_file, "w") as f:
        f.write("CRASH TRIAGE REPORT\n")
        f.write("=" * 70 + "\n\n")
        f.write(f"Total crashes: {len(crashes)}\n")
        f.write(f"Critical: {len(critical)}\n")
        f.write(f"High: {len(high)}\n")
        f.write(f"Medium: {len(medium)}\n")
        f.write(f"Low: {len(low)}\n\n")
        
        f.write("CRITICAL CRASHES (Score 50+):\n")
        f.write("-" * 70 + "\n")
        for c in critical:
            f.write(f"\n[{c['score']}] {c['dir']}\n")
            f.write(f"    IOCTL: 0x{c['ioctl']:08X}\n")
            f.write(f"    Size: {c['size']}\n")
            f.write(f"    Method: {c['method_name']}\n")
            f.write(f"    Reasons:\n")
            for r in c["reasons"]:
                f.write(f"      - {r}\n")
        
        f.write("\n\nALL CRASHES (sorted by score):\n")
        f.write("-" * 70 + "\n")
        for c in crashes:
            f.write(f"[{c['score']:3}] 0x{c['ioctl']:08X} | {c['size']:5} bytes | {c['method_name']}\n")
    
    print(f"\n[+] Report saved to: {report_file}")
    
    # Quick command to test top crash
    if critical:
        top = critical[0]
        poc_file = crashes_dir / top["dir"] / "poc.py"
        if poc_file.exists():
            print(f"\n[!] Test the top crash:")
            print(f"    python {poc_file}")

if __name__ == "__main__":
    main()
