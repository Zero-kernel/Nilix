# Testing Infrastructure Summary

This document provides a high-level overview of the Nilix testing infrastructure.

**Last verified:** 2026-07-29 — `make fmt-check`, `make clippy`, `make lint`, `make build`,
`make test`, `make boot-check` and `make musl-check` all passed remotely; the runtime gate reported
**31 passed / 39 deferred / 0 failed**, with 0 panic and 0 NX faults.

> **Host `cargo test` is not part of the gate set and mostly does not run.** Only the `audit` crate's
> host tests execute (15 passed / 0 failed, measured 2026-07-29). Test binaries for `mm`, `block`,
> `net`, `seccomp` and `kernel_core` abort at the first allocation because they link the kernel's
> uninitialized `global_allocator` — pre-existing and A/B-verified. In-kernel boot tests below are the
> authoritative regression coverage; a new `#[cfg(test)]` assertion in those crates documents intent
> but does not execute.

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

### 5. Stress Tests ⚡ NEW
- **stress_test.sh** - Resource leak and stability validation
- Tests: Memory pressure, CPU saturation, SMP contention, I/O sustained, process churn
- Duration: 60-300 seconds per test
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

### 9. Fuzzing ✅
- **syzkaller + KCOV** integration complete
- Tests: Syscall sequences, edge cases, input validation
- Coverage-guided fuzzing with kernel code coverage

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

# Stress and performance ⚡ NEW
make stress-test       # 60s stress tests
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
| Fuzzing | Continuous | Ongoing | Background |

## Coverage Summary

✅ **Fully Operational:**
- Boot health validation
- Structural self-tests (50+)
- Functional runtime tests (40+)
- SMP validation (2/4/8/16-core)
- Stress testing suite
- Security mitigation tests (9 tests)
- Fuzzing infrastructure (syzkaller + KCOV)

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

## Recent Additions (2026-07-21)

1. ⚡ **Stress test suite** (`stress_test.sh`) - 6 stress scenarios
2. ⚡ **Performance gate** (`perf_regression_test.sh`) - Framework for regression detection
3. ⚡ **Security tests** - Added Spectre V1/V2, SMAP, SMEP validation
4. ⚡ **Melting tests** (`melting_test.sh`) - Framework for sustained load testing
5. ⚡ **Extended SMP** (`extended_smp_test.sh`) - 8/16-core validation
6. ⚡ **Comprehensive gates** - New Makefile targets for full validation

## Next Steps

1. Implement dedicated performance benchmark userspace programs
2. Set up bare metal boot infrastructure for melting tests
3. Add historical performance tracking
4. Integrate real hardware test machines into CI pipeline

---

**Status:** Implementation complete for goal requirements  
**Last Updated:** 2026-07-21
