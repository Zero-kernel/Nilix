# QEMU-based AFL++ Fuzzing for Nilix Kernel

This directory contains AFL++ fuzzing infrastructure for full-kernel state validation.

## Overview

Unlike libFuzzer (which requires `host_harness` feature gates and isolated subsystems), AFL++ with QEMU mode fuzzes the **actual kernel binary** with full state:

- Real boot sequence
- Real memory management
- Real process/syscall state
- Real cross-subsystem interactions

## Architecture

```
AFL++ Controller
    │
    ├─> QEMU (instrumented)
    │   └─> Nilix Kernel (ELF binary)
    │       └─> syscall interface
    │
    └─> Corpus Management
        ├─> Seeds (valid syscall sequences)
        └─> Crashes/Hangs
```

## Prerequisites

```bash
# Install AFL++
sudo apt-get install afl++

# Or build from source for latest features
git clone https://github.com/AFLplusplus/AFLplusplus
cd AFLplusplus
make
sudo make install

# Verify installation
afl-fuzz -h
afl-qemu-trace -h
```

## Kernel Build Configuration

AFL++ requires instrumentation. Two approaches:

### Approach 1: QEMU Mode (No Kernel Modification)
- Uses QEMU's TCG to instrument at runtime
- Slower but requires zero kernel changes
- **Recommended for initial setup**

### Approach 2: Source Instrumentation (Faster)
- Compile kernel with AFL++ instrumentation
- Requires `afl-clang-fast` / `afl-rustc`
- 2-5x faster than QEMU mode

## Usage

### 1. Build Kernel for Fuzzing

```bash
# Standard kernel build (for QEMU mode)
cd /home/dev/workspace/project/rsproject/Zero-os
make build

# Or: AFL++-instrumented kernel (faster)
make fuzz-kernel
```

### 2. Run AFL++ Fuzzer

```bash
# Single instance
./scripts/afl_fuzz.sh \
    --kernel target/x86_64-unknown-none/release/kernel \
    --timeout 5000 \
    --memory 2G \
    --input fuzz/afl_seeds \
    --output fuzz/afl_findings

# Parallel fuzzing (recommended)
./scripts/afl_parallel.sh \
    --instances 4 \
    --kernel target/x86_64-unknown-none/release/kernel
```

### 3. Monitor Progress

```bash
afl-whatsup fuzz/afl_findings
```

### 4. Triage Crashes

```bash
./scripts/afl_triage.sh fuzz/afl_findings/default/crashes
```

## Seed Corpus

AFL++ needs valid syscall sequences as seeds:

```
fuzz/afl_seeds/
├── 01_simple_read       # open + read + close
├── 02_fork_exec         # fork + exec + wait
├── 03_mmap_munmap       # mmap + write + munmap
├── 04_signal_delivery   # kill + sigaction
└── 05_multithreaded     # clone + futex
```

Seeds are **binary syscall traces**, not random bytes.

## Performance Tuning

```bash
# Core affinity (one fuzzer per core)
./scripts/afl_parallel.sh --instances $(nproc) --pin-cores

# Persistent mode (if kernel supports)
export AFL_QEMU_PERSISTENT_ADDR=0x...
export AFL_QEMU_PERSISTENT_CNT=1000

# Faster mutations
export AFL_FAST_CAL=1
export AFL_SKIP_CPUFREQ=1
```

## Expected Results

| Metric | QEMU Mode | Instrumented Mode |
|--------|-----------|-------------------|
| Exec/sec | 50-200 | 500-2000 |
| Startup time | ~5s | ~1s |
| Coverage granularity | Basic block | Edge |

## Comparison with libFuzzer

| Aspect | libFuzzer | AFL++ QEMU |
|--------|-----------|------------|
| **Speed** | 100k-700k exec/s | 50-2000 exec/s |
| **State** | Isolated functions | Full kernel |
| **Coverage** | Feature gates hit stubs | Real code paths |
| **Setup** | Easy | Complex |
| **Crashes** | Function-level | System-level |

## Limitations

1. **Performance**: QEMU mode is 10-100x slower than libFuzzer
2. **Setup complexity**: Requires QEMU configuration and syscall trace format
3. **Crash reproduction**: Harder to debug than isolated function crashes
4. **CI integration**: Long runtime (hours/days) unsuitable for per-commit checks

## When to Use

- **Use AFL++ QEMU** when:
  - Testing cross-subsystem interactions
  - Validating stateful kernel behavior
  - Finding concurrency bugs
  - Testing boot/init sequences

- **Use libFuzzer** when:
  - Fuzzing parsers (ELF, network packets, VFS paths)
  - Validating individual algorithms
  - Quick pre-commit checks

## CI Integration

See `.github/workflows/afl_fuzz.yml` for weekly AFL++ runs.

Daily libFuzzer runs remain in `.github/workflows/fuzz.yml`.
