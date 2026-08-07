//! Host-test registration for the legacy no-std KCOV executor.
//!
//! `main.rs` is an intentionally standalone guest entry point, so Cargo does
//! not discover its modules by itself.  Include the production modules here
//! rather than duplicating their pure decoding and validation logic: this
//! makes executor.rs's `#[cfg(test)]` regressions part of Cargo's
//! `--all-targets` test surface without making host tests invoke raw KCOV
//! syscalls.

// This target intentionally executes only the embedded pure-logic tests; the
// guest-only syscall wrappers are compiled as coverage, but are not called.
#![allow(dead_code)]

#[path = "../corpus.rs"]
mod corpus;

#[path = "../executor.rs"]
mod executor;
