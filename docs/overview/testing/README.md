# Test Documentation

This directory contains test coverage analysis, expansion plans, and implementation documentation for the Zero-OS kernel test suite.

## Test Coverage

- **[test-coverage-summary.md](test-coverage-summary.md)** - Current test coverage across all kernel subsystems
- **[test-coverage-expansion-plan.md](test-coverage-expansion-plan.md)** - Plan for expanding test coverage to critical paths

## Test Implementation

- **[test-implementations-ready.md](test-implementations-ready.md)** - Tests ready for implementation
- **[test-implementation-complete.md](test-implementation-complete.md)** - Completed test implementations
- **[test-implementation-summary.md](test-implementation-summary.md)** - Summary of test implementation work

## Test Suite Overview

**Last verified:** 2026-07-30 — remote `make build`, `make lint`, and `make test` passed;
the runtime gate reported **31 passed / 39 deferred / 0 failed**, with 0 panic and 0 NX faults.

The Zero-OS kernel maintains a comprehensive test suite covering:

### Unit Tests
- Subsystem-level `#[cfg(test)]` tests per crate, with a host-safe allowlist enforced by CI
- Primitive testing (sync, allocator, data structures)
- Edge case validation
- Error path coverage

> **Hosted unit-test gate (measured 2026-07-30).** `make test-hosted-subcrates` runs 169
> default-parallel tests: audit 15, MM 19, block 9, seccomp 14, net 110, and two focused
> RF186 capability lifecycle tests. Every suite has an exact passed/failed/ignored/measured/filtered
> oracle. IPC, kernel_core, and kernel `--tests` code is compile-checked on the Linux host.
> The allowlist is deliberate: the complete capability suite retains an older privileged-interrupt
> hosted SIGSEGV, and full kernel/kernel_core execution requires boot allocator, IRQ, and MMIO state.
> Those paths remain covered by the in-kernel runtime, boot, and musl gates rather than being
> weakened or silently skipped in a hosted process.

### Integration Tests
- Full kernel boot tests
- Default runtime/self-test gate (`make test`)
- Targeted multi-core SMP gates (2/4/8/16-core)
- Cross-subsystem interaction tests

### Regression Tests
- Known bug reproduction tests
- Security vulnerability regression tests
- Fix verification tests
- Edge case regression coverage

## Test Categories

### Memory Safety Tests
- Use-after-free detection
- Double-free prevention
- Memory leak detection
- Buffer overflow protection
- Uninitialized memory access

### Concurrency Tests
- Data race detection
- Deadlock detection
- TOCTOU race prevention
- Lock ordering validation
- SMP stress tests

### Resource Management Tests
- Quota enforcement
- Resource exhaustion handling
- Reference counting validation
- Cleanup path testing

### Architecture Compliance Tests
- IRQ safety verification
- FPU state management
- TLB coherency
- Lock hierarchy enforcement
- ABI layout validation

## Running Tests

### Build and Lint
```bash
make build    # Build all crates
make lint     # Run repository-specific safety/fallibility/ABI gates
make clippy   # Run Rust clippy across build units
```

### Unit Tests
```bash
cd kernel
cargo test              # Run all unit tests
cargo test --lib        # Library tests only
cargo test <test_name>  # Specific test
```

### Integration Tests
```bash
make boot-check         # Boot test with success markers
make test               # Runtime/self-test gate with parsed summary
make test-smp           # Targeted 2-core SMP gate
make test-smp-4core     # Targeted 4-core SMP gate
make test-smp-extended  # 8/16-core extended validation
```

### Boot Check
```bash
make boot-check
# Gate parses user-mode/idle success and rejects panic or NX-fault signatures.
```

## Test Success Criteria

All changes must pass:
- ✅ `make build` - Exit code 0
- ✅ `make lint` - Structural source, VFS fallibility, and ABI-layout gates pass
- ✅ `make test` - Parseable summary with 0 failed, 0 panic, and 0 NX faults
- ✅ Boot check - Serial success markers present
- ✅ Targeted SMP tests when required by the affected subsystem

## Coverage Goals

### Current Status
- **Core subsystems**: 80%+ coverage
- **Critical paths**: 90%+ coverage
- **Error paths**: 60%+ coverage
- **Edge cases**: 40%+ coverage

### Target Status (1.0-Preview)
- **Core subsystems**: 90%+ coverage
- **Critical paths**: 95%+ coverage
- **Error paths**: 80%+ coverage
- **Edge cases**: 70%+ coverage

See [test-coverage-expansion-plan.md](test-coverage-expansion-plan.md) for the roadmap to reach these targets.

## Test Infrastructure

### Test Harness
- QEMU-based virtualization
- Serial output capture
- Success marker detection
- Timeout handling
- Core dump analysis

### Test Utilities
- Mock implementations
- Test fixtures
- Assertion helpers
- Coverage instrumentation

### CI Integration
- GitHub Actions workflows
- Pre-push hooks (fmt + clippy)
- Automated test runs
- Coverage reporting

See [.github/workflows/](../../../.github/workflows/) for CI configuration.

## Writing Tests

### Unit Test Template
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_functionality() {
        // Setup
        let input = setup_test_data();
        
        // Execute
        let result = function_under_test(input);
        
        // Verify
        assert_eq!(result, expected_output);
    }

    #[test]
    #[should_panic(expected = "invalid argument")]
    fn test_error_handling() {
        function_under_test(invalid_input);
    }
}
```

### Integration Test Template
```rust
// tests/integration_test.rs
#[test]
fn test_cross_subsystem_interaction() {
    // Initialize subsystems
    subsystem_a::init();
    subsystem_b::init();
    
    // Test interaction
    let result = subsystem_a::call_subsystem_b();
    
    // Verify
    assert!(result.is_ok());
}
```

## Test Coverage Tools

### Coverage Generation
```bash
cargo tarpaulin --out Html  # Generate HTML coverage report
```

### Coverage Analysis
- Line coverage: Lines executed during tests
- Branch coverage: Decision branches taken
- Function coverage: Functions called during tests
- Path coverage: Unique execution paths

## Regression Test Policy

All security findings must have regression tests:
1. **Reproduce**: Create test that reproduces the bug
2. **Fix**: Implement the fix
3. **Verify**: Confirm test now passes
4. **Commit**: Include test with the fix

This prevents regressions and validates the fix.

## Related Documentation

- **[../../review/audits/](../../review/audits/)** - Security audits that drive test requirements
- **[../../review/fixes/](../../review/fixes/)** - Fixes that require regression tests
- **[../06-security/safety/](../06-security/safety/)** - IRQ safety testing requirements
- **[../reports/](../reports/)** - Test implementation status reports

## Test Metrics

Track and report:
- Test count (unit + integration)
- Coverage percentage
- Test execution time
- Flaky test rate
- Bug escape rate (bugs not caught by tests)

See [test-implementation-summary.md](test-implementation-summary.md) for current metrics.
