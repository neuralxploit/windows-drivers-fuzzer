# WinDriver Fuzzer (Rust Edition)

A high-performance, coverage-guided Windows kernel driver fuzzer written in Rust.

## Features

- **Response-Based Coverage**: Tracks unique responses and error codes to detect new code paths
- **AFL-style Mutation Engine**: 15 mutation strategies including havoc mode
- **Corpus Management**: Power scheduling, auto-culling, persistent storage
- **IOCTL Discovery**: Auto-probe for implemented IOCTL handlers
- **Driver Enumeration**: Scan for accessible kernel drivers
- **Crash Detection**: Catches interesting errors (access violations, stack overflows, etc.)
- **Fast**: Native Rust performance with zero-copy I/O where possible

## Building

Requires Rust 1.70+ and Windows SDK.

```powershell
# Build release version
cargo build --release

# The binary will be at target\release\windriver_fuzzer.exe
```

## Usage

### Discover Available Drivers
```powershell
.\windriver_fuzzer.exe --discover
```

### Probe for Valid IOCTLs
```powershell
.\windriver_fuzzer.exe --device "\\.\VBoxGuest" --probe
```

### Fuzz a Specific IOCTL
```powershell
.\windriver_fuzzer.exe --device "\\.\TargetDriver" --ioctl 0x220000
```

### Fuzz an IOCTL Range
```powershell
.\windriver_fuzzer.exe --device "\\.\TargetDriver" --ioctl-start 0x220000 --ioctl-end 0x2200FF
```

### With Corpus Directory
```powershell
.\windriver_fuzzer.exe --device "\\.\TargetDriver" --ioctl 0x220000 --corpus .\seeds\
```

## Command Line Options

| Option | Description |
|--------|-------------|
| `--device`, `-d` | Target device path (e.g., `\\.\DriverName`) |
| `--ioctl`, `-i` | Single IOCTL code to fuzz (hex) |
| `--ioctl-start` | Start of IOCTL range to fuzz |
| `--ioctl-end` | End of IOCTL range to fuzz |
| `--discover` | Enumerate available drivers |
| `--probe` | Probe device for implemented IOCTLs |
| `--corpus` | Directory for seed/corpus files |
| `--output`, `-o` | Output directory for crashes (default: `.\crashes`) |
| `--iterations`, `-n` | Max iterations (0 = unlimited) |
| `--verbose`, `-v` | Verbose output |

## Coverage Strategy

Since true kernel code coverage requires Intel PT or kernel instrumentation (like WinAFL/DynamoRIO), this fuzzer uses **response-based pseudo-coverage**:

1. **Error Code Tracking**: Different error codes suggest different code paths were taken
2. **Response Hashing**: Unique response patterns indicate new handlers/branches
3. **Corpus Evolution**: Inputs that produce new responses are saved and prioritized

This approach can find bugs in:
- Input validation code
- Different IOCTL handlers  
- Edge cases in size/format handling
- State machine transitions

For true coverage-guided kernel fuzzing, consider:
- [WinAFL](https://github.com/googleprojectzero/winafl) with DynamoRIO
- [kAFL](https://github.com/IntelLabs/kAFL) with Intel PT

## Output

Crashes are saved to the output directory with:
- `crash_ioctl_XXXXXXXX_err_XXXXXXXX_hash.bin` - Raw input that triggered the crash
- `crash_ioctl_XXXXXXXX_err_XXXXXXXX_hash.json` - Metadata (IOCTL, error code, timestamp)

## Architecture

```
src/
├── main.rs       - CLI and main fuzzing loop
├── driver.rs     - Windows driver I/O, discovery, IOCTL handling
├── mutator.rs    - AFL-style mutation engine (15 strategies)
├── coverage.rs   - Response-based coverage tracking
└── corpus.rs     - Seed/corpus management with power scheduling
```

## Safety Warning

⚠️ **Run this fuzzer in a VM only!** 

Fuzzing kernel drivers can:
- Cause Blue Screen of Death (BSOD)
- Corrupt system state
- Damage filesystems
- Render the system unbootable

Always use a disposable virtual machine with snapshots.

## License

For educational and authorized security research purposes only.
