# Syzkaller-Style Fuzzing: Quick Start Guide

## Overview

The Nilix kernel now includes a complete syzkaller-style coverage-guided fuzzing infrastructure. This guide provides quick-start instructions for running fuzzing campaigns.

## Prerequisites

- Linux host (Ubuntu 22.04+ recommended)
- QEMU 7.0+ with x86_64 system emulation
- OVMF UEFI firmware
- musl-gcc for static linking
- Rust stable toolchain

## Quick Start

### 1. Build Everything

```bash
# Build KCOV-enabled kernel
make build-kcov

# Build guest executor (runs in QEMU)
make build-syz-executor

# Build host fuzzer (runs on Linux host)
make build-syz-fuzzer
```

### 2. Run Smoke Test (60 seconds)

```bash
make test-syz
```

This runs a 60-second smoke test to verify the infrastructure is working.

### 3. Run Full Fuzzing Campaign

```bash
# Default: 1 hour, 4 workers
make run-syz-fuzz

# Custom duration and workers
make run-syz-fuzz DURATION=7200 WORKERS=8
```

### 4. Check Results

```bash
# Corpus entries (interesting programs)
ls -lh userspace/nilix-syz-fuzzer/syz-corpus/

# Crashes found
ls -lh userspace/nilix-syz-fuzzer/syz-crashes/

# View crash details
cat userspace/nilix-syz-fuzzer/syz-crashes/crash-*.bin | hexdump -C
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Host (Linux)                           │
│                                                              │
│  ┌──────────────────────────────────────────────┐          │
│  │  nilix-syz-fuzzer (Rust)                     │          │
│  │  • Mutation engine                           │          │
│  │  • Corpus management                         │          │
│  │  • Coverage tracking                         │          │
│  └────────────┬─────────────────────────────────┘          │
│               │                                             │
│               │ Serialized programs                         │
│               ▼                                             │
│  ┌──────────────────────────────────────────────┐          │
│  │  QEMU (qemu-system-x86_64)                   │          │
│  │  • Launches Nilix kernel                     │          │
│  │  • Timeout enforcement                       │          │
│  │  • Crash detection                           │          │
│  │                                               │          │
│  │   ┌──────────────────────────────────────┐  │          │
│  │   │  Nilix Kernel (KCOV enabled)         │  │          │
│  │   │  • KCOV syscalls (520-524)           │  │          │
│  │   │  • Coverage bitmap                    │  │          │
│  │   │                                        │  │          │
│  │   │   ┌──────────────────────────────┐   │  │          │
│  │   │   │ nilix_syz_executor.elf       │   │  │          │
│  │   │   │ • Deserialize programs       │   │  │          │
│  │   │   │ • Execute syscalls           │   │  │          │
│  │   │   │ • Collect coverage           │   │  │          │
│  │   │   └──────────────────────────────┘   │  │          │
│  │   └──────────────────────────────────────┘  │          │
│  └──────────────────────────────────────────────┘          │
│               │                                             │
│               │ Coverage bitmap + crash reports             │
│               ▼                                             │
│  ┌──────────────────────────────────────────────┐          │
│  │  Corpus / Crash Storage                      │          │
│  │  • syz-corpus/prog-*.bin                     │          │
│  │  • syz-crashes/crash-*.bin                   │          │
│  └──────────────────────────────────────────────┘          │
└─────────────────────────────────────────────────────────────┘
```

## Program Format

Programs are serialized in binary format:

```
Header:
  magic:          0x4E494C58 ("NILX")
  version:        1
  syscall_count:  N

For each syscall:
  syscall_number: u64
  arg_count:      u64
  
  For each argument:
    type:   u8 (0=immediate, 1=buffer, 2=null)
    length: u64
    data:   variable
```

Example JSON representation:
```json
{
  "syscalls": [
    {
      "number": 39,
      "args": []
    },
    {
      "number": 1,
      "args": [
        {"Immediate": 1},
        {"Buffer": [72, 101, 108, 108, 111]},
        {"Immediate": 5}
      ]
    }
  ]
}
```

## Mutation Strategies

The fuzzer employs five mutation strategies:

1. **Insert Syscall** - Add new syscall at random position
2. **Delete Syscall** - Remove syscall from program
3. **Modify Argument** - Mutate values with interesting substitutions
4. **Duplicate Syscall** - Clone syscall with same arguments
5. **Reorder Syscalls** - Swap two syscalls

Each strategy is selected with equal probability (20%).

## Interesting Values

The mutator uses these interesting values for argument generation:

- Boundary: `0`, `1`, `0xFFFFFFFFFFFFFFFF`
- 32-bit: `0x7FFFFFFF`, `0x80000000`, `0xFFFFFFFF`
- Page-related: `4096`, `8192`, `16384`
- Random: 30% of the time

## Corpus Management

- **Energy-based scheduling**: Recent discoveries get 10× energy
- **Decay**: Energy decays by 1% per iteration for old seeds
- **Persistence**: All corpus entries saved to disk
- **Restore**: Corpus automatically loaded on restart

## Coverage Tracking

- **Edge-based coverage**: Tracks control-flow edges in kernel
- **Bitmap size**: 32,768 bytes (262,144 bits)
- **Deduplication**: Only new edges trigger corpus addition
- **Granularity**: Per-basic-block transitions

## Crash Classification

The fuzzer detects and classifies these failure modes:

- **kernel_panic**: Explicit kernel panic
- **page_fault**: Memory access violation
- **triple_fault**: CPU enters triple-fault state
- **boot_failure**: Kernel fails to boot in <5 seconds
- **timeout**: Program exceeds 30-second limit
- **hang**: No progress detected
- **executor_failure**: Guest executor reports error

## CI Integration

Fuzzing runs automatically on GitHub Actions:

- **Schedule**: Weekly on Sundays at 2 AM UTC
- **Duration**: 1 hour (configurable)
- **Workers**: 4 parallel instances (configurable)
- **Corpus caching**: Preserved between runs
- **Artifact upload**: Crashes and corpus snapshots

Trigger manually:
```bash
gh workflow run syzkaller-fuzz.yml -f duration=7200 -f workers=8
```

## Performance Expectations

- **Executions per second**: 5-10 (QEMU boot overhead dominates)
- **Coverage growth**: 50-200 new edges per hour (early phase)
- **Crash yield**: 0-5 per 1M executions (decreases over time)
- **Memory**: 512 MB per QEMU + 100 MB host overhead
- **Disk**: 10-50 MB corpus after 24 hours

## Troubleshooting

### Fuzzer fails to start

```bash
# Check OVMF firmware path
ls -lh $(find /usr/share/OVMF -name "OVMF_CODE*.fd")

# Verify QEMU is available
which qemu-system-x86_64

# Test kernel boots
make run-kcov
```

### No coverage growth

- Corpus may have saturated current syscall space
- Add more syscalls to grammar (see `docs/fuzzing/syscall-descriptions.syz`)
- Increase mutation aggressiveness
- Check KCOV is enabled in kernel (`make build-kcov`)

### High crash rate

- Check if crashes are reproducible
- Verify crash classification is correct
- Review kernel logs in crash reports
- May indicate real kernel bugs (good!)

### Slow execution

- QEMU boot overhead is expected (5-10 exec/sec is normal)
- Parallel workers help but don't scale linearly
- Consider increasing program timeout if crashes are false positives

## Advanced Usage

### Custom Mutation Probability

Edit `userspace/nilix-syz-fuzzer/src/mutator.rs`:
```rust
let strategy = self.rng.gen_range(0..5);
match strategy {
    0 => self.mutate_insert_syscall(&mut program)?,   // 20%
    1 => self.mutate_delete_syscall(&mut program)?,   // 20%
    2 => self.mutate_modify_argument(&mut program)?,  // 20%
    3 => self.mutate_duplicate_syscall(&mut program)?,// 20%
    4 => self.mutate_reorder_syscalls(&mut program)?, // 20%
    _ => {}
}
```

### Add New Syscalls

Edit `userspace/nilix-syz-fuzzer/src/mutator.rs` in `generate_random_syscall()`:
```rust
let syscalls = [
    (1, 3),    // read: fd, buf, count
    (2, 3),    // write: fd, buf, count
    (3, 3),    // open: path, flags, mode
    // Add your syscall here:
    (YOUR_NUMBER, ARG_COUNT),
];
```

### Corpus Seed Injection

Add custom seeds to corpus:
```bash
# Create seed program
echo '{"syscalls":[{"number":39,"args":[]}]}' > seed.json

# Convert to binary (implement converter or use fuzzer)
# Then copy to corpus directory
cp seed.bin userspace/nilix-syz-fuzzer/syz-corpus/prog-seed.bin
```

## References

- **Phase 7 Implementation**: `docs/fuzzing/phase7-implementation.md`
- **Syzkaller Integration**: `docs/fuzzing/syzkaller-integration.md`
- **Syscall Grammar**: `docs/fuzzing/syscall-descriptions.syz`
- **KCOV Documentation**: `docs/fuzzing/README.md`
- **Source Code**: `userspace/nilix-syz-fuzzer/`

## Support

For issues or questions:
1. Check `docs/fuzzing/phase7-implementation.md` for detailed architecture
2. Review CI workflow logs for examples
3. Enable verbose logging in fuzzer for debugging

---

**Status**: Phase 7.1-7.4 Complete (2026-08-04)  
**Next**: Phase 7.5 (Monitoring and Tuning) - Ongoing
