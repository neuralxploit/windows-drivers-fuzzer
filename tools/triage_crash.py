#!/usr/bin/env python3
"""
Crash Triage Tool - Analyze crashes for exploitability

Usage: python triage_crash.py <crash_folder>
"""

import os
import sys
import ctypes
from ctypes import wintypes
import struct
import time

kernel32 = ctypes.windll.kernel32
ntdll = ctypes.windll.ntdll

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x80

def open_driver(device_path):
    handle = kernel32.CreateFileW(
        device_path,
        GENERIC_READ | GENERIC_WRITE,
        0,
        None,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        None
    )
    return handle

def send_ioctl(handle, ioctl_code, in_buffer, out_size=0x1000):
    in_buf = ctypes.create_string_buffer(bytes(in_buffer), len(in_buffer))
    out_buf = ctypes.create_string_buffer(out_size)
    bytes_returned = wintypes.DWORD()
    
    result = kernel32.DeviceIoControl(
        handle,
        ioctl_code,
        in_buf,
        len(in_buffer),
        out_buf,
        out_size,
        ctypes.byref(bytes_returned),
        None
    )
    
    error = kernel32.GetLastError()
    return result, error, out_buf.raw[:bytes_returned.value] if result else None, bytes_returned.value

def analyze_crash(crash_dir):
    """Analyze a crash folder for exploitability indicators"""
    
    print(f"\n{'='*60}")
    print(f"CRASH TRIAGE: {crash_dir}")
    print(f"{'='*60}\n")
    
    # Read crash info
    info_path = os.path.join(crash_dir, "info.txt")
    input_path = os.path.join(crash_dir, "input.bin")
    
    if not os.path.exists(info_path):
        print("[!] No info.txt found")
        return
    
    with open(info_path, 'r') as f:
        info = f.read()
    print(f"[*] Crash Info:\n{info}")
    
    # Parse IOCTL
    ioctl = None
    for line in info.split('\n'):
        if line.startswith('IOCTL:'):
            ioctl = int(line.split(':')[1].strip(), 16)
            break
    
    if not ioctl:
        print("[!] Could not parse IOCTL code")
        return
    
    # Read input
    with open(input_path, 'rb') as f:
        original_input = f.read()
    
    print(f"[*] IOCTL: 0x{ioctl:08X}")
    print(f"[*] Input size: {len(original_input)} bytes")
    print(f"[*] Input preview: {original_input[:64].hex()}")
    
    # Decode IOCTL structure
    device_type = (ioctl >> 16) & 0xFFFF
    access = (ioctl >> 14) & 0x3
    function = (ioctl >> 2) & 0xFFF
    method = ioctl & 0x3
    
    methods = ["BUFFERED", "IN_DIRECT", "OUT_DIRECT", "NEITHER"]
    accesses = ["ANY", "READ", "WRITE", "READ|WRITE"]
    
    print(f"\n[*] IOCTL Structure:")
    print(f"    Device Type: 0x{device_type:04X}")
    print(f"    Function:    0x{function:03X} ({function})")
    print(f"    Method:      {methods[method]}")
    print(f"    Access:      {accesses[access]}")
    
    # METHOD_NEITHER is most dangerous!
    if method == 3:
        print(f"\n[!] ⚠️  METHOD_NEITHER - Direct user buffer access!")
        print(f"[!] HIGH exploitation potential - driver trusts user pointers!")
    
    # Open driver
    device = r"\\.\ahcache"
    print(f"\n[*] Opening {device}...")
    handle = open_driver(device)
    
    if handle == -1:
        print(f"[!] Failed to open driver")
        return
    
    print(f"[+] Handle: 0x{handle:X}")
    
    # === TEST 1: Minimum crash size ===
    print(f"\n{'='*40}")
    print("[TEST 1] Finding minimum crash size...")
    print(f"{'='*40}")
    
    min_size = len(original_input)
    for size in [0, 1, 4, 8, 16, 32, 64, 128, 256, 512, 1024]:
        if size > len(original_input):
            break
        test_input = original_input[:size]
        result, error, output, ret_size = send_ioctl(handle, ioctl, test_input)
        status = "SUCCESS" if result else f"ERROR 0x{error:08X}"
        print(f"    Size {size:4d}: {status}")
        
        # Reopen handle if needed
        handle = open_driver(device)
        if handle == -1:
            print(f"    [!] Driver handle died at size {size}!")
            min_size = size
            break
    
    print(f"[*] Minimum crash size: ~{min_size} bytes")
    
    # === TEST 2: Check for info leak ===
    print(f"\n{'='*40}")
    print("[TEST 2] Checking for information leak...")
    print(f"{'='*40}")
    
    handle = open_driver(device)
    if handle != -1:
        # Send with large output buffer
        result, error, output, ret_size = send_ioctl(handle, ioctl, original_input, out_size=0x10000)
        
        if result and ret_size > 0:
            print(f"[+] Got {ret_size} bytes of output!")
            print(f"    Preview: {output[:128].hex() if output else 'None'}")
            
            # Check for kernel pointers (0xFFFF...)
            if output:
                for i in range(0, len(output) - 8, 8):
                    val = struct.unpack('<Q', output[i:i+8])[0]
                    if 0xFFFF800000000000 <= val <= 0xFFFFFFFFFFFFFFFF:
                        print(f"[!] 🔥 POTENTIAL KERNEL POINTER at offset {i}: 0x{val:016X}")
                    elif 0x00007FF000000000 <= val <= 0x00007FFFFFFFFFFF:
                        print(f"[!] User pointer at offset {i}: 0x{val:016X}")
        else:
            print(f"[-] No output data (error: 0x{error:08X})")
    
    # === TEST 3: Controlled values ===
    print(f"\n{'='*40}")
    print("[TEST 3] Testing controlled crash values...")
    print(f"{'='*40}")
    
    # Test if first bytes control crash
    test_patterns = [
        (b"\x41" * len(original_input), "All 0x41 (A)"),
        (b"\x00" * len(original_input), "All 0x00"),
        (b"\xFF" * len(original_input), "All 0xFF"),
        (struct.pack('<Q', 0x4141414141414141) * (len(original_input)//8 + 1), "QWORD 0x41..."),
    ]
    
    for pattern, desc in test_patterns:
        pattern = pattern[:len(original_input)]
        handle = open_driver(device)
        if handle == -1:
            print(f"    {desc}: Handle dead, might have crashed kernel!")
            time.sleep(1)
            continue
        
        result, error, output, ret_size = send_ioctl(handle, ioctl, pattern)
        status = "SUCCESS" if result else f"ERROR 0x{error:08X}"
        print(f"    {desc}: {status}")
        kernel32.CloseHandle(handle)
    
    # === TEST 4: Size-based overflow test ===
    print(f"\n{'='*40}")
    print("[TEST 4] Buffer overflow detection...")
    print(f"{'='*40}")
    
    overflow_sizes = [
        len(original_input),
        len(original_input) * 2,
        0x1000,
        0x2000,
        0x10000,
    ]
    
    for size in overflow_sizes:
        handle = open_driver(device)
        if handle == -1:
            time.sleep(1)
            handle = open_driver(device)
        if handle == -1:
            print(f"    [!] Can't reopen driver!")
            break
            
        test_input = b"\x41" * size
        result, error, output, ret_size = send_ioctl(handle, ioctl, test_input)
        status = "SUCCESS" if result else f"ERROR 0x{error:08X}"
        print(f"    Size 0x{size:X} ({size}): {status}")
        kernel32.CloseHandle(handle)
    
    # === SUMMARY ===
    print(f"\n{'='*60}")
    print("EXPLOITABILITY ASSESSMENT")
    print(f"{'='*60}")
    
    print("""
[*] To determine if exploitable:

1. Run in VM with kernel debugger:
   - bcdedit /debug on
   - bcdedit /dbgsettings serial debugport:1 baudrate:115200
   - Connect WinDbg from host
   
2. Run poc.py and check:
   - Did it BSOD? → Kernel bug!
   - What was the crash address?
   - Can you control RIP/crash location?
   
3. Check C:\\Windows\\Minidump\\ for .dmp files

4. In WinDbg analyze with:
   - !analyze -v
   - !exploitable (MSEC extension)
   - r (check registers for controlled values like 0x41414141)
   
[*] High-value indicators:
   - METHOD_NEITHER = direct pointer access
   - Controlled crash address (0x41414141)
   - Kernel pointer leak in output
   - Write-what-where primitive
   - Use-after-free pattern
""")
    
    kernel32.CloseHandle(handle)

def main():
    if len(sys.argv) < 2:
        # Find all crash folders
        crash_base = r".\crashes"
        if os.path.exists(crash_base):
            crashes = [d for d in os.listdir(crash_base) if d.startswith("crash_")]
            print(f"[*] Found {len(crashes)} crash folders")
            print("[*] Usage: python triage_crash.py <crash_folder>")
            print("[*] Or: python triage_crash.py all")
            print(f"\n[*] Crashes:")
            for c in sorted(crashes)[:20]:
                print(f"    {c}")
            if len(crashes) > 20:
                print(f"    ... and {len(crashes)-20} more")
        return
    
    target = sys.argv[1]
    
    if target == "all":
        crash_base = r".\crashes"
        crashes = [d for d in os.listdir(crash_base) if d.startswith("crash_")]
        for crash in sorted(crashes):
            try:
                analyze_crash(os.path.join(crash_base, crash))
            except Exception as e:
                print(f"[!] Error analyzing {crash}: {e}")
            input("\n[Press Enter for next crash...]")
    else:
        if os.path.isdir(target):
            analyze_crash(target)
        else:
            analyze_crash(os.path.join(r".\crashes", target))

if __name__ == "__main__":
    main()
