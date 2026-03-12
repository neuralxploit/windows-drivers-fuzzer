# Angr Driver Analyzer

MSFuzz-style static analysis for Windows kernel drivers.

## What it does

1. **Finds IOCTL codes** - Scans binary for compare instructions with IOCTL-like values
2. **Extracts constraints** - Uses symbolic execution to find buffer size requirements
3. **Tracks global variables** - Identifies which IOCTLs read/write shared state
4. **Groups dependencies** - Links IOCTLs that must be called in sequence

## Installation

```bash
pip install angr
```

## Usage

```bash
# Analyze a driver
python analyze_driver.py C:\Windows\System32\drivers\ahcache.sys -o ahcache.json

# Verbose mode
python analyze_driver.py driver.sys -v -o output.json
```

## Output Format

```json
{
  "driver": "ahcache.sys",
  "ioctls": {
    "0x0001001F": {
      "min_input_size": 256,
      "max_input_size": 4096,
      "min_output_size": 0,
      "constraints": ["InputBufferLength >= 0x100"],
      "reads_globals": [],
      "writes_globals": ["0x1A000"]
    },
    "0x00010023": {
      "min_input_size": 0,
      "reads_globals": ["0x1A000"],
      "writes_globals": [],
      "depends_on": ["0x0001001F"]
    }
  },
  "dependency_groups": [
    {
      "shared_global": "0x1A000",
      "ioctls": ["0x0001001F", "0x00010023"]
    }
  ]
}
```

## Integration with Ladybug

Ladybug can read this JSON to:
- Skip IOCTLs with insufficient buffer sizes
- Prioritize sequences within dependency groups
- Generate valid inputs faster (no trial-and-error learning)

```bash
# Run Ladybug with pre-analyzed driver
ladybug.exe fuzz --device \\.\ahcache --analysis ahcache.json
```

## Limitations

- Symbolic execution may fail on complex drivers (path explosion)
- Some IOCTLs only reachable after specific system state
- Global variable tracking is best-effort (may miss pointer indirection)

## How MSFuzz Uses This

From the CodeBlue talk:
1. They set IRP fields as symbolic variables
2. Explore paths until NTSTATUS return
3. Use Z3 to solve "what input reaches STATUS_SUCCESS"
4. Track read/write to globals for stateful bug finding
