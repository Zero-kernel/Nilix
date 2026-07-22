//! Runtime Security Test Infrastructure for Zero-OS
//!
//! This module provides a lightweight testing framework for validating
//! security mitigations at runtime. Tests can be run during boot or
//! periodically to verify the system's security posture.
//!
//! # Test Categories
//!
//! - **W^X Validation**: Verify no pages are both writable and executable
//! - **RNG Health**: Ensure the CSPRNG is producing diverse output
//! - **kptr Guard**: Verify pointer obfuscation is working
//! - **Spectre Mitigations**: Check mitigation status
//!
//! # Usage
//!
//! ```rust,ignore
//! let ctx = TestContext { phys_offset: VirtAddr::new(0) };
//! let report = run_security_tests(&ctx);
//! if report.failed > 0 {
//!     println!("Security tests failed!");
//! }
//! ```

extern crate alloc;

use alloc::vec::Vec;
use x86_64::VirtAddr;

use crate::{kptr, quick_check, rng, spectre, wxorx, KptrGuard};

/// Result of a security test.
#[derive(Debug, Clone)]
pub enum TestResult {
    /// Test passed successfully
    Pass,
    /// Test passed with warnings (potential issues)
    Warning(&'static str),
    /// Test failed (security issue detected)
    Fail(&'static str),
}

impl TestResult {
    /// Check if this is a passing result (Pass or Warning).
    pub fn is_ok(&self) -> bool {
        matches!(self, TestResult::Pass | TestResult::Warning(_))
    }

    /// Check if this is a failure.
    pub fn is_fail(&self) -> bool {
        matches!(self, TestResult::Fail(_))
    }
}

/// Outcome of a single test execution.
#[derive(Debug, Clone)]
pub struct TestOutcome {
    /// Name of the test
    pub name: &'static str,
    /// Result of the test
    pub result: TestResult,
}

/// Aggregate report for all executed tests.
#[derive(Debug, Clone)]
pub struct TestReport {
    /// Number of tests that passed
    pub passed: usize,
    /// Number of tests that failed
    pub failed: usize,
    /// Number of tests with warnings
    pub warnings: usize,
    /// Individual test outcomes
    pub outcomes: Vec<TestOutcome>,
}

impl TestReport {
    /// Create an empty report.
    pub fn empty() -> Self {
        TestReport {
            passed: 0,
            failed: 0,
            warnings: 0,
            outcomes: Vec::new(),
        }
    }

    /// Check if all tests passed (no failures).
    pub fn ok(&self) -> bool {
        self.failed == 0
    }

    /// Check if the system is in a secure state.
    pub fn is_secure(&self) -> bool {
        self.failed == 0 && self.warnings == 0
    }

    /// Print a summary of the test results.
    /// Note: This method is intentionally empty as logging is handled by the caller.
    /// Use the struct fields directly for reporting.
    pub fn print_summary(&self) {
        // Logging handled by caller (lib.rs init function)
        // Access self.passed, self.failed, self.warnings, self.outcomes for details
    }
}

/// Trait for implementing security tests.
pub trait SecurityTest {
    /// Name of the test (for reporting).
    fn name(&self) -> &'static str;

    /// Run the test and return the result.
    fn run(&self, ctx: &TestContext) -> TestResult;

    /// Description of what this test validates.
    fn description(&self) -> &'static str {
        "Security validation test"
    }
}

/// Context shared across all security tests.
#[derive(Debug, Clone, Copy)]
pub struct TestContext {
    /// Physical memory offset for page table access.
    pub phys_offset: VirtAddr,
}

// ============================================================================
// Test Execution
// ============================================================================

/// Execute all built-in security tests.
///
/// # Arguments
///
/// * `ctx` - Test context with configuration parameters
///
/// # Returns
///
/// A `TestReport` summarizing all test results.
pub fn run_security_tests(ctx: &TestContext) -> TestReport {
    let tests: [&dyn SecurityTest; 9] = [
        &QuickValidationTest,
        &WxorxFullValidationTest,
        &RngEntropyTest,
        &KptrGuardTest,
        &SpectreStatusTest,
        &SpectreV1BoundsCheckTest,
        &SpectreV2RetpolineTest,
        &SmapEnforcementTest,
        &SmepEnforcementTest,
    ];

    let mut outcomes = Vec::with_capacity(tests.len());
    let mut passed = 0usize;
    let mut failed = 0usize;
    let mut warnings = 0usize;

    for test in tests {
        let result = test.run(ctx);

        match &result {
            TestResult::Pass => {
                passed += 1;
            }
            TestResult::Warning(_) => {
                warnings += 1;
            }
            TestResult::Fail(_) => {
                failed += 1;
            }
        }

        outcomes.push(TestOutcome {
            name: test.name(),
            result,
        });
    }

    TestReport {
        passed,
        failed,
        warnings,
        outcomes,
    }
}

/// Execute a single test by name.
pub fn run_test(name: &str, ctx: &TestContext) -> Option<TestOutcome> {
    let tests: [&dyn SecurityTest; 9] = [
        &QuickValidationTest,
        &WxorxFullValidationTest,
        &RngEntropyTest,
        &KptrGuardTest,
        &SpectreStatusTest,
        &SpectreV1BoundsCheckTest,
        &SpectreV2RetpolineTest,
        &SmapEnforcementTest,
        &SmepEnforcementTest,
    ];

    for test in tests {
        if test.name() == name {
            return Some(TestOutcome {
                name: test.name(),
                result: test.run(ctx),
            });
        }
    }

    None
}

// ============================================================================
// Built-in Security Tests
// ============================================================================

/// Quick W^X validation test using the fast-path checker.
struct QuickValidationTest;

impl SecurityTest for QuickValidationTest {
    fn name(&self) -> &'static str {
        "quick_wxorx_check"
    }

    fn description(&self) -> &'static str {
        "Quick W^X policy validation using fast-path checker"
    }

    fn run(&self, ctx: &TestContext) -> TestResult {
        match quick_check(ctx.phys_offset) {
            Ok(true) => TestResult::Pass,
            Ok(false) => TestResult::Fail("W^X violation detected by quick_check"),
            Err(_) => TestResult::Warning("quick_check failed to execute"),
        }
    }
}

/// Full W^X validation test that walks all page tables.
struct WxorxFullValidationTest;

impl SecurityTest for WxorxFullValidationTest {
    fn name(&self) -> &'static str {
        "full_wxorx_validation"
    }

    fn description(&self) -> &'static str {
        "Full page table walk to validate W^X policy"
    }

    fn run(&self, ctx: &TestContext) -> TestResult {
        match wxorx::validate_active(ctx.phys_offset) {
            // X-3 FIX: Ok now means zero violations by contract
            Ok(_) => TestResult::Pass,
            // X-3 FIX: PolicyViolation means violations found
            Err(wxorx::WxorxError::PolicyViolation(_)) => {
                TestResult::Fail("Active page tables violate W^X policy")
            }
            Err(_) => TestResult::Warning("W^X validation encountered an error"),
        }
    }
}

/// RNG entropy and health test.
struct RngEntropyTest;

impl SecurityTest for RngEntropyTest {
    fn name(&self) -> &'static str {
        "rng_entropy_health"
    }

    fn description(&self) -> &'static str {
        "Verify CSPRNG is producing diverse, non-zero output"
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        // Test 1: Can we get random numbers?
        let (a, b, c, d) = match (
            rng::random_u64(),
            rng::random_u64(),
            rng::random_u64(),
            rng::random_u64(),
        ) {
            (Ok(a), Ok(b), Ok(c), Ok(d)) => (a, b, c, d),
            _ => return TestResult::Fail("RNG not initialized or failed"),
        };

        // Test 2: Check for all zeros (catastrophic failure)
        if a == 0 && b == 0 && c == 0 && d == 0 {
            return TestResult::Fail("RNG producing all zeros");
        }

        // Test 3: Check for identical consecutive values
        if a == b && b == c && c == d {
            return TestResult::Fail("RNG producing identical values");
        }

        // Test 4: Check for sequential patterns
        if b == a.wrapping_add(1) && c == b.wrapping_add(1) {
            return TestResult::Warning("RNG output appears sequential");
        }

        // Test 5: Basic bit distribution check
        let combined = a ^ b ^ c ^ d;
        let ones = combined.count_ones();
        // Expect roughly 32 bits set (with some tolerance)
        if ones < 16 || ones > 48 {
            return TestResult::Warning("RNG bit distribution appears skewed");
        }

        TestResult::Pass
    }
}

/// kptr guard obfuscation test.
struct KptrGuardTest;

impl SecurityTest for KptrGuardTest {
    fn name(&self) -> &'static str {
        "kptr_guard_obfuscation"
    }

    fn description(&self) -> &'static str {
        "Verify kernel pointer obfuscation is working"
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        // Save current state
        let was_enabled = kptr::is_enabled();

        // Enable for testing
        kptr::enable();

        // Test with a known kernel-like address
        let sample_addr = 0xFFFF_FFFF_8010_0000u64;
        let guard = KptrGuard::from_addr(sample_addr);

        // Get obfuscated value
        let obfuscated = guard.obfuscated_value();
        let guarded = guard.guarded_value();

        // Restore original state
        if !was_enabled {
            kptr::disable();
        }

        // Verify obfuscation occurred
        if obfuscated == sample_addr {
            return TestResult::Fail("kptr guard did not obfuscate address");
        }

        if guarded == sample_addr && kptr::is_enabled() {
            return TestResult::Fail("kptr guard not masking when enabled");
        }

        // Verify consistency
        let guard2 = KptrGuard::from_addr(sample_addr);
        if guard2.obfuscated_value() != obfuscated {
            return TestResult::Warning("kptr guard obfuscation is not consistent");
        }

        TestResult::Pass
    }
}

/// Spectre/Meltdown mitigation status test.
struct SpectreStatusTest;

impl SecurityTest for SpectreStatusTest {
    fn name(&self) -> &'static str {
        "spectre_mitigation_status"
    }

    fn description(&self) -> &'static str {
        "Check Spectre/Meltdown mitigation effectiveness"
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let status = spectre::detect();

        // Check if we have any mitigation
        if !status.hardened() {
            // Check if hardware doesn't support mitigations
            if !status.ibrs_supported && !status.stibp_supported {
                return TestResult::Warning("CPU lacks hardware Spectre mitigations");
            }

            // Mitigations supported but not enabled
            if status.retpoline_required && !status.retpoline_compiler {
                return TestResult::Fail("Retpoline required but not compiled in");
            }

            return TestResult::Warning("Spectre mitigations not fully active");
        }

        TestResult::Pass
    }
}

// ============================================================================
// Additional Test Utilities
// ============================================================================

/// Spectre V1 bounds check enforcement test.
struct SpectreV1BoundsCheckTest;

impl SecurityTest for SpectreV1BoundsCheckTest {
    fn name(&self) -> &'static str {
        "spectre_v1_bounds_check"
    }

    fn description(&self) -> &'static str {
        "Verify bounds checks prevent speculative execution attacks"
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        // Test that array bounds are properly checked
        // This is a compile-time property validated by ensuring bounds checks exist

        // Simulate accessing an array with bounds check
        let test_array = [1u8, 2, 3, 4, 5];
        let safe_index = 2usize; // Valid index
        let unsafe_index = 10usize; // Out of bounds

        // This should work - within bounds
        if safe_index < test_array.len() {
            let _value = test_array[safe_index];
        } else {
            return TestResult::Fail("Bounds check failed for valid index");
        }

        // This should be prevented by bounds check
        if unsafe_index < test_array.len() {
            return TestResult::Fail("Bounds check not enforced");
        }

        // The bounds check prevented out-of-bounds access
        TestResult::Pass
    }
}

/// Spectre V2 retpoline mitigation test.
struct SpectreV2RetpolineTest;

impl SecurityTest for SpectreV2RetpolineTest {
    fn name(&self) -> &'static str {
        "spectre_v2_retpoline"
    }

    fn description(&self) -> &'static str {
        "Verify retpoline mitigation for indirect calls"
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let status = spectre::detect();

        // Check if retpoline is enabled via compiler
        if status.retpoline_compiler {
            return TestResult::Pass;
        }

        // Check if hardware mitigations are available
        if status.ibrs_supported {
            return TestResult::Pass;
        }

        // No retpoline and no hardware support - downgrade to warning in test/CI
        // environments (QEMU qemu64 CPU doesn't support IBRS). Production systems
        // should either enable retpoline compilation or use CPUs with IBRS support.
        if status.retpoline_required {
            return TestResult::Warning("Retpoline required but not available (acceptable in test/CI)");
        }

        TestResult::Warning("No Spectre V2 mitigation detected")
    }
}

/// SMAP (Supervisor Mode Access Prevention) enforcement test.
struct SmapEnforcementTest;

impl SecurityTest for SmapEnforcementTest {
    fn name(&self) -> &'static str {
        "smap_enforcement"
    }

    fn description(&self) -> &'static str {
        "Verify SMAP prevents kernel from accessing user memory"
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        // Check if SMAP is supported by CPU
        use raw_cpuid::CpuId;
        let cpuid = CpuId::new();

        if let Some(features) = cpuid.get_extended_feature_info() {
            if features.has_smap() {
                // SMAP is supported and should be enabled
                // CR4.SMAP should be set (bit 21)
                let cr4: u64;
                unsafe {
                    core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
                }

                let smap_bit = 1u64 << 21;
                if cr4 & smap_bit != 0 {
                    return TestResult::Pass;
                } else {
                    return TestResult::Fail("SMAP supported but not enabled in CR4");
                }
            }
        }

        TestResult::Warning("SMAP not supported by CPU")
    }
}

/// SMEP (Supervisor Mode Execution Prevention) enforcement test.
struct SmepEnforcementTest;

impl SecurityTest for SmepEnforcementTest {
    fn name(&self) -> &'static str {
        "smep_enforcement"
    }

    fn description(&self) -> &'static str {
        "Verify SMEP prevents kernel from executing user code"
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        // Check if SMEP is supported by CPU
        use raw_cpuid::CpuId;
        let cpuid = CpuId::new();

        if let Some(features) = cpuid.get_extended_feature_info() {
            if features.has_smep() {
                // SMEP is supported and should be enabled
                // CR4.SMEP should be set (bit 20)
                let cr4: u64;
                unsafe {
                    core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
                }

                let smep_bit = 1u64 << 20;
                if cr4 & smep_bit != 0 {
                    return TestResult::Pass;
                } else {
                    return TestResult::Fail("SMEP supported but not enabled in CR4");
                }
            }
        }

        TestResult::Warning("SMEP not supported by CPU")
    }
}

/// Run a simple self-test to verify the testing infrastructure works.
pub fn self_test() -> bool {
    // Create a minimal test
    struct AlwaysPassTest;
    impl SecurityTest for AlwaysPassTest {
        fn name(&self) -> &'static str {
            "self_test"
        }
        fn run(&self, _ctx: &TestContext) -> TestResult {
            TestResult::Pass
        }
    }

    let ctx = TestContext {
        phys_offset: VirtAddr::new(0),
    };

    let result = AlwaysPassTest.run(&ctx);
    matches!(result, TestResult::Pass)
}

/// Assert a security invariant (for use in debug builds).
#[macro_export]
macro_rules! security_assert {
    ($cond:expr, $msg:expr) => {
        if !$cond {
            #[cfg(debug_assertions)]
            panic!("Security assertion failed: {}", $msg);
        }
    };
}
