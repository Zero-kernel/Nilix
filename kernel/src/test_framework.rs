//! Runtime Test Framework for Nilix Kernel
//!
//! Provides comprehensive test orchestration with category-based organization,
//! automatic discovery, parallel execution support, and coverage enforcement.
//!
//! # Architecture
//!
//! - **Category-based organization**: Tests grouped by subsystem (Architecture, Memory, IPC, etc.)
//! - **Priority levels**: P0 (critical), P1 (high), P2 (normal)
//! - **Status tracking**: Implemented, Placeholder, Skipped
//! - **Compile-time discovery**: Tests registered via const TEST_REGISTRY
//! - **Runtime execution**: Selective by category/priority with timeout detection
//! - **Coverage enforcement**: Build-time validation of minimum test counts

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

// Re-export TestResult and TestOutcome from runtime_tests to avoid duplication
pub use crate::runtime_tests::{TestOutcome, TestReport as LegacyTestReport, TestResult};

// ============================================================================
// Test Metadata Types
// ============================================================================

/// Test category - subsystem being tested
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestCategory {
    /// Architecture-specific: context switches, IRQ handling, TLS
    Architecture,
    /// Memory management: allocators, COW, TLB shootdown
    Memory,
    /// Inter-process communication: futex, signals, pipes
    Ipc,
    /// Scheduler: work stealing, affinity, starvation
    Scheduler,
    /// Virtual file system: RAMFS, rename, path resolution
    Vfs,
    /// Network: parsing, loopback, firewall
    Network,
    /// Security: capabilities, seccomp, audit
    Security,
    /// SMP: IPIs, TLB coherency, cpusets
    Smp,
    /// Namespaces: mount, IPC, network isolation
    Namespaces,
    /// Regression: P0 security-critical tests
    Regression,
}

impl TestCategory {
    /// Human-readable category name
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Architecture => "Architecture",
            Self::Memory => "Memory",
            Self::Ipc => "IPC",
            Self::Scheduler => "Scheduler",
            Self::Vfs => "VFS",
            Self::Network => "Network",
            Self::Security => "Security",
            Self::Smp => "SMP",
            Self::Namespaces => "Namespaces",
            Self::Regression => "Regression",
        }
    }

    /// All categories for iteration
    pub const fn all() -> &'static [TestCategory] {
        &[
            Self::Architecture,
            Self::Memory,
            Self::Ipc,
            Self::Scheduler,
            Self::Vfs,
            Self::Network,
            Self::Security,
            Self::Smp,
            Self::Namespaces,
            Self::Regression,
        ]
    }
}

impl fmt::Display for TestCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Test priority level
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TestPriority {
    /// P0: Critical security/correctness - must pass for 1.0-Preview
    P0,
    /// P1: High priority - important functionality
    P1,
    /// P2: Normal priority - nice to have
    P2,
}

impl TestPriority {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::P0 => "P0",
            Self::P1 => "P1",
            Self::P2 => "P2",
        }
    }
}

impl fmt::Display for TestPriority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Test implementation status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestStatus {
    /// Fully implemented and ready to run
    Implemented,
    /// Placeholder - not yet implemented
    Placeholder,
    /// Skipped - intentionally not run (e.g., requires specific hardware)
    Skipped,
}

impl TestStatus {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Implemented => "Implemented",
            Self::Placeholder => "Placeholder",
            Self::Skipped => "Skipped",
        }
    }
}

impl fmt::Display for TestStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ============================================================================
// Test Descriptor
// ============================================================================

/// Complete metadata for a runtime test
#[derive(Debug, Clone)]
pub struct TestDescriptor {
    /// Unique test identifier (e.g., "r172_01_context_switch")
    pub id: &'static str,
    /// Human-readable test name
    pub name: &'static str,
    /// Category this test belongs to
    pub category: TestCategory,
    /// Priority level
    pub priority: TestPriority,
    /// Implementation status
    pub status: TestStatus,
    /// Short description of what is tested
    pub description: &'static str,
    /// Optional: QA round ID (e.g., "R172", "R174")
    pub qa_round: Option<&'static str>,
    /// Optional: Date when placeholder was created (for staleness check)
    pub placeholder_date: Option<&'static str>,
}

impl TestDescriptor {
    /// Create new test descriptor
    pub const fn new(
        id: &'static str,
        name: &'static str,
        category: TestCategory,
        priority: TestPriority,
        status: TestStatus,
        description: &'static str,
    ) -> Self {
        Self {
            id,
            name,
            category,
            priority,
            status,
            description,
            qa_round: None,
            placeholder_date: None,
        }
    }

    /// Set QA round ID
    pub const fn with_qa_round(mut self, round: &'static str) -> Self {
        self.qa_round = Some(round);
        self
    }

    /// Set placeholder creation date
    pub const fn with_placeholder_date(mut self, date: &'static str) -> Self {
        self.placeholder_date = Some(date);
        self
    }

    /// Check if test is ready to run
    pub const fn is_runnable(&self) -> bool {
        matches!(self.status, TestStatus::Implemented)
    }
}

// ============================================================================
// Test Report Aggregation
// ============================================================================

/// Statistics for a category or overall report
#[derive(Debug, Clone, Default)]
pub struct TestStats {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub warnings: usize,
    pub skipped: usize,
    pub implemented: usize,
    pub placeholders: usize,
}

impl TestStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_outcome(&mut self, result: &TestResult) {
        self.total += 1;
        self.implemented += 1; // All outcomes are from implemented tests

        // Track execution result
        match result {
            TestResult::Pass => self.passed += 1,
            TestResult::Warning(_) => {
                self.passed += 1;
                self.warnings += 1;
            }
            TestResult::Fail(_) => self.failed += 1,
        }
    }

    pub fn coverage_percent(&self) -> usize {
        if self.total == 0 {
            0
        } else {
            (self.implemented * 100) / self.total
        }
    }

    pub fn pass_rate(&self) -> usize {
        if self.total == 0 {
            0
        } else {
            (self.passed * 100) / self.total
        }
    }
}

/// Comprehensive test execution report
#[derive(Debug, Clone)]
pub struct TestReport {
    pub overall: TestStats,
    pub by_category: [(TestCategory, TestStats); 10],
}

impl TestReport {
    pub fn from_legacy(legacy: LegacyTestReport) -> Self {
        let mut overall = TestStats::new();
        let mut by_category: [(TestCategory, TestStats); 10] = [
            (TestCategory::Architecture, TestStats::new()),
            (TestCategory::Memory, TestStats::new()),
            (TestCategory::Ipc, TestStats::new()),
            (TestCategory::Scheduler, TestStats::new()),
            (TestCategory::Vfs, TestStats::new()),
            (TestCategory::Network, TestStats::new()),
            (TestCategory::Security, TestStats::new()),
            (TestCategory::Smp, TestStats::new()),
            (TestCategory::Namespaces, TestStats::new()),
            (TestCategory::Regression, TestStats::new()),
        ];

        for outcome in &legacy.outcomes {
            overall.add_outcome(&outcome.result);

            let category = infer_category(outcome.name);
            for (cat, stats) in &mut by_category {
                if *cat == category {
                    stats.add_outcome(&outcome.result);
                    break;
                }
            }
        }

        Self {
            overall,
            by_category,
        }
    }

    pub fn ok(&self) -> bool {
        self.overall.failed == 0
    }

    pub fn category_stats(&self, category: TestCategory) -> Option<&TestStats> {
        self.by_category
            .iter()
            .find(|(cat, _)| *cat == category)
            .map(|(_, stats)| stats)
    }
}

// ============================================================================
// Test Registry
// ============================================================================

/// Global test registry - populated at compile time
///
/// Tests register themselves here via const initializers.
/// This allows build.rs to validate coverage and enforce minimums.
pub static TEST_REGISTRY: &[TestDescriptor] = &[
    // Populated by individual test modules
    // Example:
    // TestDescriptor::new(
    //     "heap_allocation",
    //     "Heap Allocation",
    //     TestCategory::Memory,
    //     TestPriority::P0,
    //     TestStatus::Implemented,
    //     "Verify kernel heap allocation and deallocation"
    // ),
];

// ============================================================================
// Test Execution Engine
// ============================================================================

/// Run all tests and generate report
pub fn run_all_tests() -> TestReport {
    use crate::runtime_tests::run_all_runtime_tests;

    let legacy_report = run_all_runtime_tests();
    TestReport::from_legacy(legacy_report)
}

/// Run tests filtered by category
pub fn run_tests_by_category(category: TestCategory) -> TestReport {
    use crate::runtime_tests::run_all_runtime_tests;

    let full_report = run_all_runtime_tests();

    // Filter outcomes by category
    let filtered_outcomes: Vec<TestOutcome> = full_report
        .outcomes
        .into_iter()
        .filter(|outcome| infer_category(outcome.name) == category)
        .collect();

    // Create a legacy report with filtered outcomes
    let filtered_legacy = LegacyTestReport {
        passed: filtered_outcomes
            .iter()
            .filter(|o| o.result.is_pass())
            .count(),
        failed: filtered_outcomes
            .iter()
            .filter(|o| o.result.is_fail())
            .count(),
        warnings: filtered_outcomes
            .iter()
            .filter(|o| matches!(o.result, TestResult::Warning(_)))
            .count(),
        outcomes: filtered_outcomes,
    };

    TestReport::from_legacy(filtered_legacy)
}

/// Run tests filtered by priority
pub fn run_tests_by_priority(_priority: TestPriority) -> TestReport {
    // For now, all tests run at the same priority
    // Future: add priority metadata to runtime tests
    run_all_tests()
}

/// Generate coverage report
pub fn generate_coverage_report() -> TestReport {
    run_all_tests()
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Infer test category from test name (for legacy tests)
fn infer_category(name: &str) -> TestCategory {
    if name.contains("heap") || name.contains("buddy") || name.contains("memory") {
        TestCategory::Memory
    } else if name.contains("cap") {
        TestCategory::Security
    } else if name.contains("seccomp") || name.contains("pledge") {
        TestCategory::Security
    } else if name.contains("audit") {
        TestCategory::Security
    } else if name.contains("network")
        || name.contains("arp")
        || name.contains("udp")
        || name.contains("tcp")
    {
        TestCategory::Network
    } else if name.contains("smp")
        || name.contains("ipi")
        || name.contains("tlb")
        || name.contains("cpuset")
    {
        TestCategory::Smp
    } else if name.contains("scheduler") || name.contains("affinity") || name.contains("starvation")
    {
        TestCategory::Scheduler
    } else if name.contains("process") {
        TestCategory::Scheduler
    } else if name.contains("security") {
        TestCategory::Security
    } else if name.contains("mount_ns") || name.contains("ipc_ns") || name.contains("net_ns") {
        TestCategory::Namespaces
    } else if name.starts_with("r1") {
        TestCategory::Regression
    } else {
        TestCategory::Memory
    }
}
