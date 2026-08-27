//! Compatibility module for the historical guest-fuzzer layout.
//!
//! The old file re-exported Phase 5/6/7 scaffolds whose signatures no longer
//! matched the live executor, corpus, and mutator.  Keeping those declarations
//! here made an accidental `mod mod;` inclusion fail at compile time.  The
//! maintained host-testable API now lives in `src/lib.rs`; expose only the
//! repaired crash-triage implementation from this compatibility path.

extern crate alloc;

#[path = "crash_triage.rs"]
pub mod crash_triage;
