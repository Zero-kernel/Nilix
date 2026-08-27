//! Compile and exercise the formerly-unwired Phase-7 crash triage module.
//!
//! Keeping this module in a host integration target prevents API drift from
//! being hidden by the guest-only `mod.rs` scaffold (U57-4).

#![allow(dead_code)]

extern crate alloc;

#[path = "../crash_triage.rs"]
mod crash_triage;

#[path = "../mod.rs"]
mod legacy_scaffold;

use crash_triage::{CrashInput, CrashTriageSystem, TriageResult};

#[test]
fn crash_triage_preserves_inputs_without_a_verified_oracle() {
    let mut triage = CrashTriageSystem::new();
    let result = triage.process_crash(CrashInput {
        input: vec![1, 2, 3],
        output: "PANIC: integration".to_string(),
        exit_code: 1,
    });
    match result {
        TriageResult::NewCrash { reproducer, .. } => assert_eq!(reproducer, vec![1, 2, 3]),
        TriageResult::Duplicate { .. } => panic!("first crash was unexpectedly a duplicate"),
    }
}

#[test]
fn historical_module_path_exposes_only_the_repaired_api() {
    let mut triage = legacy_scaffold::crash_triage::CrashTriageSystem::new();
    let result = triage.process_crash(legacy_scaffold::crash_triage::CrashInput {
        input: vec![7],
        output: "PANIC: legacy-path".to_string(),
        exit_code: 1,
    });
    assert!(matches!(
        result,
        legacy_scaffold::crash_triage::TriageResult::NewCrash { .. }
    ));
}
