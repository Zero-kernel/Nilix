# Nilix Kernel Fuzz Testing Framework

Comprehensive fuzzing suite for the Nilix kernel covering all major subsystems.

## Overview

This fuzzing framework uses `cargo-fuzz` (libFuzzer) to test kernel components for:
- Memory safety violations
- Logic errors
- Race conditions
- Input validation bugs
- Edge cases missed by unit tests

## Fuzz Targets

### 1. `fuzz_syscall` - System Call Fuzzing
Tests syscall entry points with focus on R173/R174 fixes:
- **CLOEXEC operations** (fcntl, pipe2) - R173-05/06
- **Positioned I/O** (pread64, pwrite64) - R173-07
- **Signal operations** (rt_sigaction, rt_sigprocmask) - R174
- **Clone operations** - R174-A2
- **Futex operations** - R172-08

### 1b. `fuzz_syscall_qemu` - QEMU syscall execution

**Verification status (2026-09-10):** development paused. The real adapter and host
regressions are implemented; the current guest smoke reaches BEGIN then fails
`result_open` with `EINVAL`. Successful guest coverage is not yet qualified. See the
[handoff](../docs/review/fixes/ksa-2026-09-06-handoff-2026-09-10.md) before continuing.

Uses the production `nilix-syz-fuzzer` executor and its 20-syscall allowlist, including
process identity, read-only filesystem queries, time and bounded output buffers.
Each accepted input boots `esp-syz/kernel.elf` with 512 MiB guest RAM, a fresh ESP
and a private 128 MiB Ext3 transport. Authenticated BEGIN/PASS and result data bind
coverage to the submitted input. Missing prerequisites, process errors, crashes,
timeouts and hangs fail the invocation. Invalid byte encodings are rejected before
execution. Guest KCOV is returned; libFuzzer mutation guidance still uses host
instrumentation. There is no measured executions-per-second claim.

Build with `make build-syz-kcov` and enable `qemu-executor`. Guest startup has a
90-second bound; use `-timeout=120` or larger for libFuzzer. Optional
`NILIX_FUZZ_KERNEL`, `NILIX_FUZZ_QEMU`, `OVMF_PATH` and `NILIX_FUZZ_ARTIFACTS`
override the image, emulator, firmware and retained-evidence directory. Artifact
retention is intended for finite validation runs because it keeps each guest disk.

### 2. `fuzz_vfs_path` - VFS Path Operations
Tests filesystem operations:
- **Path traversal** attacks (../, multiple slashes)
- **Rename operations** - R172-14/15 (self-deadlock, ancestor TOCTOU)
- **rmdir/unlink type gates** - R172 FOLLOW-ON
- **Special paths** (/proc, /sys, /dev)

### 3. `fuzz_signal_delivery` - Signal Handling
Tests signal delivery mechanisms:
- **IRQ-safe delivery** - R173-01
- **Signal frame construction** and SROP defense
- **Concurrent signal delivery**
- **Signal during syscall** (EINTR) - M0-5

### 4. `fuzz_memory_ops` - Memory Management
Tests memory operations:
- **mmap/munmap** with various flags
- **mprotect** - R168-1 (double uncharge)
- **brk** operations - R174-B4 (VA-reservation TOCTOU)
- **Stack guard page** - M0-7
- **Demand-grow** - M0-7 SLICE 4/5/6

### 5. `fuzz_ipc_message` - IPC Operations
Tests inter-process communication:
- Message size limits
- Concurrent send/receive
- EINTR precision - M0-5 SLICE 1b-1b

### 6. `fuzz_scheduler` - Scheduler Operations
Tests scheduling:
- Priority operations
- CPU affinity
- Context switch - R172-03 (steal-before-save)
- sched_yield reproducer - R172-01

### 7. `fuzz_network_packet` - Network Stack
Tests packet handling:
- Malformed TCP/UDP/ICMP packets
- Protocol violations
- Buffer overflows

### 8. `fuzz_cgroup_ops` - Control Groups
Tests cgroup operations:
- Memory limits and accounting - R171/R174
- Process attachment - R149-4
- Delete operations (mem_pinned gate)

### 9. `fuzz_elf_loader` - ELF Loading
Tests ELF file parsing:
- **Crafted program headers** - R172-02 (OOB-slice panic DoS)
- Overlapping segments
- Invalid offsets

### 10. `fuzz_futex_ops` - Futex Operations
Tests futex synchronization:
- WAIT/WAKE operations
- Priority inheritance (PI) locks - R172-18
- Bucket TOCTOU - R172-08
- EINTR precision - M0-5 SLICE 1b-1b

## Installation

```bash
# Install cargo-fuzz
cargo install cargo-fuzz

# Ensure nightly toolchain (already pinned in rust-toolchain.toml)
rustup install nightly
```

## Usage

### Run a specific fuzz target

```bash
cd fuzz

# Run syscall fuzzer (host-based, fast)
cargo +nightly fuzz run fuzz_syscall

# Run QEMU-based syscall fuzzer (real kernel execution)
cargo +nightly fuzz run fuzz_syscall_qemu --features qemu-executor -- -timeout=120

# Run with specific timeout and iterations
cargo +nightly fuzz run fuzz_syscall -- -max_total_time=300 -runs=1000000

# Run with custom dictionary
cargo +nightly fuzz run fuzz_syscall -- -dict=dictionaries/syscall.dict
```

### QEMU Fuzzer Quick Start

```bash
# Prerequisites: Build KCOV kernel and executor
make build-fuzz-qemu-deps

# Finite smoke: two valid seeds, real launch/guest evidence, retained artifacts
make fuzz-qemu-smoke

# Campaign run (1 hour)
make fuzz-qemu-campaign

# Overnight soak (8 hours)
make fuzz-qemu-overnight
```

### Run all fuzz targets (parallel)

```bash
./run_all_fuzz.sh
```

### Check coverage

```bash
# Generate coverage report
cargo +nightly fuzz coverage fuzz_syscall

# View coverage in HTML
cargo +nightly fuzz cov fuzz_syscall -- --html

# Open coverage report
open fuzz/coverage/fuzz_syscall/index.html
```

### Minimize corpus

```bash
# Minimize test cases that trigger bugs
cargo +nightly fuzz cmin fuzz_syscall
```

### Triage crashes

```bash
# Reproduce a crash
cargo +nightly fuzz run fuzz_syscall fuzz/artifacts/fuzz_syscall/crash-<hash>

# Get stack trace
RUST_BACKTRACE=1 cargo +nightly fuzz run fuzz_syscall fuzz/artifacts/fuzz_syscall/crash-<hash>
```

## Continuous Fuzzing

### Local continuous fuzzing

```bash
# Run indefinitely until crash found
cargo +nightly fuzz run fuzz_syscall -- -max_total_time=0
```

### Integration with CI

The checked-in [Fuzzing workflow](../.github/workflows/fuzz.yml) runs the 11
targets on its daily schedule or through `workflow_dispatch`. The dispatch input
sets a validated per-target timeout (1–1200 seconds). Required tool, feature and
QEMU smoke checks run in the main `CI` workflow; this scheduled workflow owns
only the longer private campaigns and fail-closed result manifests.

**What actually runs kernel code:** `fuzz_elf_loader`, `fuzz_network_packet`,
and `fuzz_vfs_path` link and drive the real kernel parsers
(`kernel_core::validate_elf_image`, `net::parse_*`, `vfs::normalize_path` /
`split_path`) — the pure, host-safe validation layers. This is possible because
`mm`'s `#[global_allocator]` is compiled out under its `host_harness` feature
(see `fuzz/Cargo.toml` and the `ALLOCATOR` static in `kernel/mm/memory.rs`), so
the crate graph links against std's allocator. The remaining seven targets model
hardware/stateful subsystems that are not host-callable without a mock harness,
so they still exercise self-contained input-validation logic.

## Best Practices

1. **Start with quick runs** (1-5 minutes) to catch obvious bugs
2. **Increase timeout** for deeper fuzzing (hours to days)
3. **Use corpus seeds** from unit tests to guide fuzzing
4. **Merge corpora** from multiple runs to improve coverage
5. **Regularly minimize corpus** to reduce redundancy
6. **Monitor RSS usage** to prevent OOM

## Target-Specific Notes

### fuzz_syscall
- Focuses on R173/R174 audit fixes
- Tests argument validation and error paths
- High-priority for regression prevention

### fuzz_vfs_path
- Tests path normalization and race conditions
- Critical for security (path traversal attacks)

### fuzz_signal_delivery
- Tests IRQ-safe signal delivery (R173-01 fix)
- SROP defense validation

### fuzz_memory_ops
- Tests cgroup charge accounting
- Stack guard page and demand-grow

### fuzz_elf_loader
- Tests R172-02 OOB-slice panic fix
- Critical for preventing DoS via crafted binaries

## Performance Tips

- Use `-jobs=N` for parallel fuzzing (N = CPU cores)
- Set `-rss_limit_mb=` to prevent memory exhaustion
- Use `-max_len=` to limit input size
- Enable AddressSanitizer: `RUSTFLAGS="-Zsanitizer=address"`
- Enable UndefinedBehaviorSanitizer: `RUSTFLAGS="-Zsanitizer=undefined"`

## Debugging

```bash
# Enable debug output
RUST_LOG=debug cargo +nightly fuzz run fuzz_syscall

# Run with ASan for better crash reports
RUSTFLAGS="-Zsanitizer=address" cargo +nightly fuzz run fuzz_syscall

# Generate flamegraph
cargo +nightly fuzz run fuzz_syscall -- -print_pcs=1 -print_funcs=1
```

## Contributing

When adding new fuzz targets:
1. Add target to `Cargo.toml` `[[bin]]` section
2. Create `fuzz_targets/fuzz_<name>.rs`
3. Document what the target tests in this README
4. Add example usage to `run_all_fuzz.sh`

## References

- [libFuzzer Documentation](https://llvm.org/docs/LibFuzzer.html)
- [cargo-fuzz Book](https://rust-fuzz.github.io/book/cargo-fuzz.html)
- [Rust Fuzz Project](https://github.com/rust-fuzz)
