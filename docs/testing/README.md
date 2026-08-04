# Testing Infrastructure Summary

This document provides a high-level overview of the Nilix testing infrastructure.

**Last verified:** 2026-07-30 — `make fmt-check`, `make clippy`, `make lint`, `make build`,
`make test`, `make boot-check` and `make musl-check` all passed remotely; the runtime gate reported
**31 passed / 39 deferred / 0 failed**, with 0 panic and 0 NX faults.

> **Hosted sub-crate tests are now a fail-closed CI gate.** `make test-hosted-subcrates` runs
> **169 tests under Rust's default parallel scheduler**: audit 15, MM 19, block 9, seccomp 14,
> net 110, and the two RF186 capability lifecycle regressions. `mm/host_harness` removes the
> kernel allocator/LAPIC assumptions for those approved suites. Exact summary oracles reject
> command failure, count drift, ignored/measured drift, or an accidental zero-test filter.
> IPC, kernel_core, and kernel test code receive hosted compile checks. Full capability and
> privileged kernel suites remain QEMU-only because interrupt/MMIO execution is invalid in an
> ordinary hosted process; the boot/runtime gates below remain authoritative for those paths.

## Test Categories

### 1. Boot Tests ✅
- **boot-check.sh** - Boot health validation (userspace reached, no NX violations)
- **musl-check.sh** - Musl libc conformance gate
- Tests: Boot sequence, KASLR, early initialization

### 2. Self Tests ✅
- **50+ structural self-tests** in `kernel/src/integration_test.rs`
- Tests: API contracts, invariants, edge cases
- Examples: COW refcount, PT ledger, RCU callbacks, heap admission

### 3. Runtime Tests ✅
- **40+ functional tests** in `kernel/src/runtime_tests.rs`
- Tests: Memory, capabilities, seccomp, network, scheduler, process lifecycle
- Gate: `make test` (exit 0 = pass, 1 = fail, 2 = not run)

### 4. SMP Tests ✅
- **smp_test.sh** - 2-core validation
- **smp_test_4core.sh** - 4-core validation
- **extended_smp_test.sh** - 8/16-core validation ⚡ NEW
- Tests: Multi-CPU init, IPI, TLB shootdown, lock contention

### 5. QEMU Stability Soak Tests ⚡ ENHANCED (2026-08-04)
- **stress_test.sh** - Sustained Ring-3 workload stability validation under varied VM profiles
- **Basic stress runner** (`stress_runner.c`) - 635 lines, 5 workload phases
  - Memory (mmap/munmap validation)
  - CPU (computational kernel)
  - Process (fork/wait lifecycle)
  - File I/O (ramfs + ext3)
  - Combined concurrent workload + sustained heartbeat loop
- **Advanced stress runner** (`stress_runner_advanced.c`) - 541 lines, security-focused
  - Permission boundary validation (null ptr, invalid fd, kernel addresses, overflow sizes)
  - Concurrency stress (parallel syscall hammering, race detection)
  - Resource exhaustion (fd limits, memory pressure)
  - Signal resilience (SIGUSR1 during syscall execution)
  - Failure injection (double close, unmapped munmap, invalid operations)
- Profiles: constrained memory (192M), multi-vCPU (4 cores), SMP, block I/O, single-vCPU, extended combined
- Duration: 60-300 seconds per test with mandatory heartbeat freshness checks
- Gate: `make stress-test` or `make stress-test-extended`

### 6. Performance Tests ⚡ NEW
- **perf_regression_test.sh** - Performance regression gate
- Tests: Syscall latency, context switch, page fault, allocation speed
- Status: Framework in place, benchmarks pending
- Gate: `make test-perf`

### 7. Security Tests ⚡ ENHANCED
- **kernel/security/tests.rs** - Security mitigation validation
- Tests: W^X, RNG, kptr, Spectre V1/V2, SMAP, SMEP ⚡ 4 NEW
- Integrated into runtime test suite
- Gate: `make test` includes security subsystem

### 8. Melting Tests ⚡ NEW
- **melting_test.sh** - Sustained maximum load (real hardware only)
- Tests: 10+ minute thermal stress, memory pressure, I/O continuous
- Status: Framework in place, requires bare metal infrastructure
- Gate: `make test-melting`

### 9. Fuzzing 🚧 ENHANCED (2026-08-04)
- Host cargo-fuzz parser/model targets plus a deterministic KCOV QEMU guest E2E
- Guest gate validates KCOV enable/disable/reset/dump, bitmap counts, sequence differentiation,
  repeat stability, and fail-closed panic/NX/timeout handling
- **NEW:** Syzkaller-style syscall descriptions (`.syz` format) — 600+ lines defining 40+ syscalls
  with resource types, flag combinations, interesting values, and coverage hints
- **NEW:** Host-driven fuzzing architecture specification (see `docs/fuzzing/syzkaller-integration.md`)
  - Grammar-aware mutation engine
  - Coverage-guided corpus evolution
  - virtio-serial guest executor transport
  - HMAC-based crash deduplication
- **Status:** Deterministic E2E operational; full host-driven mutation loop Phase 7.1-7.5 not started
- Host-driven guest mutation, corpus feedback, and crash replay remain in progress

## Quick Reference

```bash
# Essential gates (run on every commit)
make boot-check        # Boot health
make test              # Runtime + security tests
make lint              # Code quality

# SMP validation
make test-smp          # 2-core
make test-smp-4core    # 4-core
make test-smp-extended # 8/16-core ⚡ NEW

# Stability soak and performance ⚡ NEW
make stress-test       # 60s QEMU stability profiles
make test-perf         # Performance regression gate

# Comprehensive (run on PR)
make test-comprehensive # All gates in sequence

# Quick smoke test
make test-quick        # Boot + runtime only
```

## Test Matrix

| Category | Tests | Duration | When to Run |
|----------|-------|----------|-------------|
| Boot | 3 | ~1 min | Every commit |
| Self | 50+ | ~2 min | Every commit (integrated) |
| Runtime | 40+ | ~35s | Every commit |
| SMP | 2/4/8/16-core | ~5 min | PR |
| Stress | 6 scenarios | 6-30 min | PR / Nightly |
| Performance | 6 benchmarks | ~2 min | PR / Nightly |
| Security | 9 tests | ~1 min | Every commit (integrated) |
| Melting | 5 scenarios | 30+ min | Release / Real HW |
| Fuzzing | Cargo-fuzz + deterministic QEMU KCOV E2E | Scheduled / per change | CI |

## Coverage Summary

✅ **Fully Operational:**
- Boot health validation
- Structural self-tests (50+)
- Functional runtime tests (40+)
- SMP validation (2/4/8/16-core)
- Stress testing suite
- Security mitigation tests (9 tests)
- Deterministic QEMU KCOV lifecycle and syscall-sequence regression

⚠️ **Framework in Place (Implementation Pending):**
- Performance benchmarks (needs dedicated benchmark code)
- Melting tests (needs bare metal infrastructure)

## What Each Category Catches

| Test Type | Catches |
|-----------|---------|
| **Boot** | Early panics, NX violations, init failures |
| **Self** | API contract violations, invariant breaches |
| **Runtime** | Functional bugs, integration issues |
| **SMP** | Race conditions, deadlocks, scheduler issues |
| **Stress** | Memory leaks, resource exhaustion, stability |
| **Performance** | Regressions, performance cliffs |
| **Security** | Missing mitigations, policy violations |
| **Melting** | Thermal issues, long-term leaks |
| **Fuzzing** | Edge cases, input validation bugs |

## CI/CD Integration Recommendations

### Fast Feedback (Every Commit)
```bash
make boot-check
make test
make lint
```
**Duration:** ~5 minutes

### Pull Request Gate
```bash
make test-comprehensive
```
**Duration:** ~20 minutes

### Nightly Extended
```bash
make stress-test-extended
make test-smp-extended
make test-perf
```
**Duration:** ~45 minutes

### Release Gate (Manual)
```bash
make test-comprehensive
make stress-test-extended
MELT_DURATION=1800 make test-melting  # Real hardware
```
**Duration:** ~60 minutes + melting

## Documentation

- **EXTENDED_TEST_SUITE.md** - Detailed documentation for new test infrastructure
- **Memory files** - Session context (uncommitted worktree, R180 status, skill loop)
- **Script comments** - Inline documentation in each test script

## Recent Additions (2026-08-04)

1. ⚡ **Advanced security stress runner** (`stress_runner_advanced.c`) - 541 lines
   - Permission boundary validation (null pointers, invalid fds, kernel addresses, overflows)
   - Concurrency stress testing (race conditions, parallel syscall execution)
   - Resource exhaustion validation (fd limits, memory pressure)
   - Signal resilience testing (SIGUSR1 delivery during syscalls)
   - Systematic failure injection (double close, unmapped munmap, invalid operations)

2. ⚡ **Syzkaller-style syscall descriptions** (`docs/fuzzing/syscall-descriptions.syz`) - 600+ lines
   - Complete grammar for 40+ Nilix syscalls
   - Resource dependency tracking (fd, pid, addr)
   - Flag combination seeds and interesting value hints
   - Multi-syscall sequence templates (file lifecycle, memory lifecycle, signal handling)
   - Edge case test patterns (null pointers, invalid flags, size overflows)
   - Coverage hints for mutation guidance

3. ⚡ **Host-driven fuzzing architecture** (`docs/fuzzing/syzkaller-integration.md`)
   - Complete Phase 7 specification for coverage-guided fuzzing
   - Grammar-aware mutation engine design
   - QEMU guest executor with virtio-serial transport
   - Coverage extraction and corpus management
   - Integration with existing HMAC-based crash triaging

### Previous Additions (2026-07-21)

1. ⚡ **QEMU stability soak suite** (`stress_test.sh`) - 6 VM configuration profiles
2. ⚡ **Performance gate** (`perf_regression_test.sh`) - Framework for regression detection
3. ⚡ **Security tests** - Added Spectre V1/V2, SMAP, SMEP validation
4. ⚡ **Melting tests** (`melting_test.sh`) - Framework for sustained load testing
5. ⚡ **Extended SMP** (`extended_smp_test.sh`) - 8/16-core validation
6. ⚡ **Comprehensive gates** - New Makefile targets for full validation

## Next Steps

1. **Implement Phase 7.1-7.5 host-driven fuzzing** (syzkaller-style mutation loop)
   - Build QEMU executor with virtio-serial transport
   - Implement grammar-aware mutation engine
   - Wire up coverage-guided corpus evolution
   - Integrate with GitHub Actions CI

2. Implement dedicated performance benchmark userspace programs
3. Set up bare metal boot infrastructure for melting tests
4. Add historical performance tracking
5. Integrate real hardware test machines into CI pipeline

---

**Status:** Stress testing enhanced, fuzzing architecture specified (host-driven loop not yet implemented)  
**Last Updated:** 2026-08-04
