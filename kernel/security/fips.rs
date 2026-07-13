//! R140-6 FIX: FIPS Mode State for the Security Crate
//!
//! Stores the canonical FIPS mode flag so that cryptographic primitives in the
//! `security` crate (e.g., `rng::fill_random`) can enforce FIPS policy without
//! introducing a circular dependency on the `compliance` crate.
//!
//! The `compliance` crate sets the state via `set_fips_state()` after running
//! self-tests.  Consumers in both `security` and `compliance` read the state via
//! `fips_state()`.

use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

/// FIPS mode states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FipsState {
    /// FIPS mode not enabled.
    Disabled = 0,
    /// FIPS mode enabled (sticky until reboot).
    Enabled = 1,
    /// FIPS mode enable failed (e.g., self-test failure) or state corrupted.
    Failed = 2,
}

/// Global FIPS mode flag (sticky once enabled).
static FIPS_MODE: AtomicU8 = AtomicU8::new(FipsState::Disabled as u8);

/// RF178-22 FIX: One atomic linearizes admission against transition closure.
/// The high bit closes admission; the remaining bits count active operations.
static NON_FIPS_GATE: AtomicUsize = AtomicUsize::new(0);
const GATE_CLOSED: usize = 1usize << (usize::BITS - 1);
const GATE_ACTIVE_MASK: usize = GATE_CLOSED - 1;

/// Get the current FIPS state.
///
/// R94-3 FIX: Fail-closed on corruption — unknown/corrupted atomic values
/// return `Failed` instead of `Disabled`.
#[inline]
pub fn fips_state() -> FipsState {
    match FIPS_MODE.load(Ordering::Acquire) {
        0 => FipsState::Disabled,
        1 => FipsState::Enabled,
        2 => FipsState::Failed,
        _ => FipsState::Failed,
    }
}

pub(crate) struct NonFipsOperationGuard;

impl Drop for NonFipsOperationGuard {
    fn drop(&mut self) {
        let previous = NON_FIPS_GATE.fetch_sub(1, Ordering::Release);
        debug_assert!(
            previous & GATE_ACTIVE_MASK != 0,
            "non-FIPS operation counter underflow"
        );
    }
}

/// Enter a non-approved primitive only while FIPS is stably Disabled.
pub(crate) fn begin_non_fips_operation() -> Result<NonFipsOperationGuard, FipsState> {
    let state = fips_state();
    if state != FipsState::Disabled {
        return Err(state);
    }

    let mut gate = NON_FIPS_GATE.load(Ordering::Acquire);
    loop {
        if gate & GATE_CLOSED != 0 {
            return Err(fips_state());
        }
        if gate & GATE_ACTIVE_MASK == GATE_ACTIVE_MASK {
            return Err(FipsState::Failed);
        }
        match NON_FIPS_GATE.compare_exchange_weak(
            gate,
            gate + 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => break,
            Err(observed) => gate = observed,
        }
    }

    Ok(NonFipsOperationGuard)
}

/// Set the global FIPS state.
///
/// Called by the `compliance` subsystem after running self-tests.
///
/// Enforces monotonic transitions: once Enabled or Failed, the state cannot
/// be reverted to Disabled (Codex review: prevents accidental/malicious downgrade).
///
/// R141-6 FIX: Uses compare_exchange instead of separate load+store to
/// eliminate a theoretical race where two concurrent callers both read
/// Disabled and store different values. In practice, the compliance crate's
/// FIPS_ENABLING spinlock serializes callers, but CAS is defense-in-depth.
///
/// Reject no-op Disabled→Disabled transitions (caller should only call this
/// with Enabled or Failed).
#[inline]
pub fn set_fips_state(state: FipsState) {
    let desired = state as u8;
    // Refuse Disabled → Disabled (no-op that could mask a bug).
    if desired == FipsState::Disabled as u8 {
        return;
    }
    // Closing admission and incrementing the active count use the same atomic.
    // Therefore either an operation is counted before closure (and waited for),
    // or it observes the closed bit and cannot start.
    let mut gate = NON_FIPS_GATE.load(Ordering::Acquire);
    loop {
        if fips_state() != FipsState::Disabled {
            return;
        }
        if gate & GATE_CLOSED != 0 {
            while fips_state() == FipsState::Disabled {
                core::hint::spin_loop();
            }
            return;
        }
        match NON_FIPS_GATE.compare_exchange_weak(
            gate,
            gate | GATE_CLOSED,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => break,
            Err(observed) => gate = observed,
        }
    }

    while NON_FIPS_GATE.load(Ordering::Acquire) & GATE_ACTIVE_MASK != 0 {
        core::hint::spin_loop();
    }

    // The gate remains closed permanently because FIPS state is sticky.
    let _ = FIPS_MODE.compare_exchange(
        FipsState::Disabled as u8,
        desired,
        Ordering::AcqRel,
        Ordering::Acquire,
    );
}
