# Ladybug - Windows Kernel Driver Fuzzer

A coverage-guided Windows kernel driver fuzzer written in Rust. Ladybug can fuzz drivers locally or remotely via a TCP executor agent running inside a VM -- so your host machine stays safe while the VM takes the BSODs.

## How It Works

```
  HOST MACHINE                          VM (Target)
┌──────────────────┐     TCP/9999     ┌──────────────────┐
│   ladybug.exe    │ ───────────────► │   executor.exe   │
│                  │                  │                  │
│ - Mutation engine│  sends IOCTLs   │ - Opens driver   │
│ - Corpus manager │ ◄─────────────── │ - Executes IOCTL │
│ - Crash tracking │  returns result  │ - SEH handling   │
│ - Coverage logic │                  │                  │
│                  │  connection drop  │                  │
│ - Detects BSOD  │ ◄── = VM crashed │                  │
└──────────────────┘                  └──────────────────┘
```

**ladybug.exe** runs on your host machine. It handles all the fuzzing logic: mutation, corpus management, coverage tracking, and crash detection.

**executor.exe** runs inside the VM where the target driver is loaded. It listens on a TCP port, receives IOCTL commands from ladybug, and executes them against the driver. If the driver crashes the VM, ladybug detects the connection drop and saves the crashing input.

This two-agent setup lets you fuzz kernel drivers without risking your host. When the VM BSODs, ladybug just waits for it to reboot and reconnects.

## Pre-Fuzzing: Automated Driver Analysis with Ghidra

Before fuzzing, you need to know which IOCTLs the driver handles. Ladybug includes a Ghidra-based pipeline that automatically decompiles any `.sys` driver and extracts every IOCTL handler.

```
  driver.sys
      │
      ▼
┌─────────────────────────────────────────┐
│  analyze_driver.ps1                     │
│                                         │
│  1. Ghidra headless decompiles driver   │
│  2. Java script finds IRP_MJ_DEVICE_   │
│     CONTROL handler (param + 0xe0)      │
│  3. Extracts all IOCTL codes + methods  │
│  4. Detects dangerous APIs (MmMapIo,    │
│     MSR read/write, ProbeForWrite...)   │
│  5. Python sorts by risk level          │
│                                         │
│  METHOD_NEITHER = HIGH RISK (raw ptrs)  │
│  METHOD_DIRECT  = MEDIUM RISK (MDL)     │
│  METHOD_BUFFERED = LOW RISK (copies)    │
└─────────────────────────────────────────┘
      │
      ▼
  driver_analysis.json    ← feed to ladybug
  driver_high_risk.json   ← high-risk IOCTLs only
```

**One command does everything:**
```powershell
.\scripts\analyze_driver.ps1 C:\path\to\driver.sys
```

This runs Ghidra headless with a custom Java script (`analyze_ioctls_v2.java`) that:
- Finds the `IRP_MJ_DEVICE_CONTROL` dispatch handler by decompiling and matching the `param + 0xe0` pattern
- Walks the call graph 2 levels deep to find IOCTLs in sub-handlers
- Reads IOCTL dispatch tables from data sections
- Detects dangerous kernel APIs (`MmMapIoSpace`, `__writemsr`, `ZwMapViewOfSection`, etc.)
- Outputs a JSON with every IOCTL, its transfer method, device type, and source function

Then `convert_ioctls.py` sorts them by risk and outputs files ready for ladybug:

```powershell
# Fuzz all discovered IOCTLs (sorted by risk, high-risk first)
.\ladybug.exe --device "\\.\TargetDriver" --analysis driver_analysis.json

# Fuzz only high-risk IOCTLs (METHOD_NEITHER + METHOD_DIRECT)
.\ladybug.exe --device "\\.\TargetDriver" --analysis driver_high_risk.json
```

**Requirements:** [Ghidra](https://ghidra-sre.org/) installed. Edit the `$GhidraPath` variable in `analyze_driver.ps1` to point to your Ghidra installation.

## Features

- **Response-Based Coverage**: Tracks unique responses and error codes to detect new code paths
- **AFL-style Mutation Engine**: 15 mutation strategies including havoc mode
- **Corpus Management**: Power scheduling, auto-culling, persistent storage
- **IOCTL Discovery**: Auto-probe and deep-scan for implemented IOCTL handlers
- **Driver Enumeration**: Scan for accessible kernel drivers
- **Crash Detection**: Catches access violations, stack overflows, BSOD via connection drops
- **TCP Two-Agent Fuzzing**: Fuzz drivers in a VM from the safety of your host machine
- **Multiple Modes**: Stateful/UAF fuzzing, CLFS fuzzing, Win32k syscall fuzzing, GDI race fuzzing
- **RL-Guided Fuzzing**: Reinforcement learning to optimize mutation strategies
- **Driver Hunter**: Scan for vulnerable 3rd-party drivers
- **Ghidra Integration**: Automated driver decompilation and IOCTL extraction with risk-based prioritization
- **Crash Triage Tools**: Post-fuzzing crash analysis and exploitability ranking

## Building

Requires Rust 1.70+ and Windows SDK.

```powershell
cargo build --release
```

Binaries:
- `target\release\ladybug.exe` -- the fuzzer (runs on host)
- `target\release\executor.exe` -- the TCP agent (runs in VM)

## Usage

### Remote Fuzzing via VM (Recommended)

**Step 1: Copy `executor.exe` into the VM and run it**
```powershell
# Inside the VM, targeting a specific driver
.\executor.exe --port 9999 --device "\\.\TargetDriver"
```

**Step 2: Run `ladybug.exe` on the host, pointing at the VM**
```powershell
# Connect to executor in VM and start fuzzing
.\ladybug.exe --device "\\.\TargetDriver" --target 192.168.1.100:9999 --ioctl 0x220000
```

Ladybug will:
1. Connect to the executor via TCP
2. Send mutated IOCTL inputs
3. Track responses for coverage
4. Detect crashes (connection drop = VM crashed / BSOD)
5. Save crashing inputs to `crashes/` directory

### Local Fuzzing (Single Machine)

> Warning: Only do this in a VM you don't care about.

```powershell
# Discover available drivers
.\ladybug.exe --discover

# Probe a driver for valid IOCTLs
.\ladybug.exe --device "\\.\VBoxGuest" --probe

# Deep scan ALL possible IOCTLs (takes 5-10 min)
.\ladybug.exe --device "\\.\TargetDriver" --deepscan

# Fuzz a specific IOCTL
.\ladybug.exe --device "\\.\TargetDriver" --ioctl 0x220000

# Fuzz an IOCTL range
.\ladybug.exe --device "\\.\TargetDriver" --ioctl-start 0x220000 --ioctl-end 0x2200FF

# With corpus directory
.\ladybug.exe --device "\\.\TargetDriver" --ioctl 0x220000 --corpus .\seeds\
```

### Special Modes

```powershell
# Stateful/UAF fuzzing
.\ladybug.exe --device "\\.\TargetDriver" --ioctl 0x220000 --stateful

# ULTIMATE mode (all techniques combined)
.\ladybug.exe --device "\\.\TargetDriver" --ioctl 0x220000 --ultimate

# CLFS.sys file-based fuzzing (CVE-2025-29824 style)
.\ladybug.exe --clfs

# Win32k.sys syscall fuzzing
.\ladybug.exe --win32k

# GDI/USER object race fuzzer
.\ladybug.exe --gdi-race

# Scan for vulnerable 3rd-party drivers
.\ladybug.exe --scan
```

## Command Line Options

| Option | Description |
|--------|-------------|
| `--device`, `-d` | Target device path (e.g., `\\.\DriverName`) |
| `--target` | TCP target for remote fuzzing (e.g., `192.168.1.100:9999`) |
| `--ioctl`, `-i` | Single IOCTL code to fuzz (hex) |
| `--ioctl-start` | Start of IOCTL range to fuzz |
| `--ioctl-end` | End of IOCTL range to fuzz |
| `--discover` | Enumerate available drivers |
| `--probe` | Probe device for implemented IOCTLs |
| `--deepscan` | Scan ALL possible IOCTLs (thorough but slow) |
| `--corpus` | Directory for seed/corpus files |
| `--output`, `-o` | Output directory for crashes (default: `.\crashes`) |
| `--iterations`, `-n` | Max iterations (0 = unlimited) |
| `--stateful` | Stateful/UAF fuzzing mode |
| `--ultimate` | All techniques combined |
| `--clfs` | CLFS.sys file fuzzer |
| `--win32k` | Win32k syscall fuzzer |
| `--gdi-race` | GDI/USER object race fuzzer |
| `--scan` | Scan for vulnerable 3rd-party drivers |
| `--analysis` | Load pre-analysis JSON from static analysis tools |
| `--verbose`, `-v` | Verbose output |

## Coverage Strategy

Since true kernel code coverage requires Intel PT or kernel instrumentation, this fuzzer uses **response-based pseudo-coverage**:

1. **Error Code Tracking**: Different error codes suggest different code paths
2. **Response Hashing**: Unique response patterns indicate new handlers/branches
3. **Corpus Evolution**: Inputs that produce new responses are saved and prioritized

## Output

Crashes are saved to the output directory with:
- `crash_ioctl_XXXXXXXX_err_XXXXXXXX_hash.bin` - Raw input that triggered the crash
- `crash_ioctl_XXXXXXXX_err_XXXXXXXX_hash.json` - Metadata (IOCTL, error code, timestamp)

## Project Structure

```
src/
├── main.rs              - CLI, main fuzzing loop, TCP mode
├── driver.rs            - Windows driver I/O, discovery, IOCTL handling
├── mutator.rs           - AFL-style mutation engine (15 strategies)
├── coverage.rs          - Response-based coverage tracking
├── corpus.rs            - Seed/corpus management with power scheduling
├── tcp_client.rs        - TCP client for remote executor communication
├── stateful.rs          - Stateful/UAF fuzzing
├── learner.rs           - RL-guided mutation learning
├── clfs_fuzzer.rs       - CLFS.sys file-based fuzzer
├── win32k_fuzzer.rs     - Win32k syscall fuzzer
├── gdi_race_fuzzer.rs   - GDI/USER object race fuzzer
├── driver_hunter.rs     - 3rd-party driver scanner
└── bin/
    └── executor.rs      - TCP executor agent (runs in VM)

scripts/
├── analyze_driver.ps1   - All-in-one: Ghidra decompile + IOCTL extraction + risk sorting
├── analyze_ioctls_v2.java - Ghidra script: finds dispatch handler, extracts IOCTLs from decompiled code
├── convert_ioctls.py    - Converts Ghidra output to Ladybug format, sorts by risk level
└── quick_scan.py        - Fast heuristic IOCTL scanner (no Ghidra needed)

tools/
├── triage_crash.py      - Analyze individual crashes for exploitability
├── bulk_triage.py       - Bulk triage all crashes, rank by exploitability
├── stress_poc.py        - Test crash reproducibility with repeated calls
├── scan_driver.py       - Universal IOCTL scanner from driver binaries
└── angr_analyzer/
    ├── quick_scan.py    - Fast heuristic analysis without symbolic execution
    └── analyze_driver.py - Deep analysis with Angr symbolic execution
```

## Safety Warning

**Run this fuzzer against drivers in a VM only!**

Fuzzing kernel drivers can cause BSOD, corrupt system state, damage filesystems, and render a system unbootable. Always use a disposable VM with snapshots.

## License

For educational and authorized security research purposes only.
