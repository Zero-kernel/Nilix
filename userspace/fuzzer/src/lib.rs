//! Shared, host-testable pieces of the Nilix fuzzing pipeline.
//!
//! The guest Phase-3 executor remains a standalone binary, but the crash
//! triage implementation is intentionally exported here so its byte-oriented
//! API is compiled in every normal Cargo build.  This prevents the old
//! Phase-7 scaffold from drifting against the live corpus/executor types
//! (U57-4).

extern crate alloc;

#[path = "../crash_triage.rs"]
pub mod crash_triage;
