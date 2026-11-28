//! Seccomp/Pledge Syscall Filtering for Zero-OS
//!
//! This module provides two complementary syscall filtering mechanisms:
//!
//! 1. **Seccomp BPF**: Linux-style flexible filtering with a BPF-like VM
//! 2. **Pledge**: OpenBSD-style promise-based sandboxing
//!
//! # Architecture
//!
//! ```text
//! +------------------+     +-------------------+
//! | Syscall Entry    | --> | Seccomp Evaluate  |
//! | (syscall.rs)     |     | (filter stack)    |
//! +------------------+     +-------------------+
//!                                  |
//!                          +-------+-------+
//!                          |               |
//!                          v               v
//!                     Allow           Kill/Errno/Log
//!                          |               |
//!                          v               v
//!                    LSM Hooks       Audit + Action
//! ```
//!
//! # Usage
//!
//! ```rust,ignore
//! // In syscall dispatcher, before executing:
//! let verdict = seccomp::evaluate_current(syscall_nr, &args);
//! match verdict.action {
//!     SeccompAction::Allow => { /* proceed */ }
//!     SeccompAction::Kill => { terminate_with_sigsys(); }
//!     SeccompAction::Errno(e) => { return -e as isize; }
//!     SeccompAction::Log => { audit_log(); /* proceed */ }
//!     SeccompAction::Trap => { deliver_sigsys(); }
//! }
//! ```
//!
//! # Fork/Exec Semantics
//!
//! - **Fork**: Child inherits parent's filter stack (shared via Arc)
//! - **Exec**: Filters persist; pledge exec_promises take effect
//! - **no_new_privs**: Once set, cannot be cleared; prevents privilege escalation

#![no_std]
#![allow(clippy::manual_range_contains)]
#![allow(dead_code)]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::derivable_impls)]
#![allow(clippy::unnecessary_cast)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::result_unit_err)]
#![allow(clippy::doc_lazy_continuation)]
#![feature(allocator_api)]

extern crate alloc;

extern crate drivers;
#[macro_use]
extern crate klog;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::RwLock;

// Audit integration for violation logging
use audit::{emit_seccomp_violation, AuditSeccompAction, AuditSubject};

pub mod syscall_table;
pub mod types;

pub use syscall_table::{
    DispatchStatus, DispatchedSyscall, PledgePolicy, SyscallSpec, SYSCALL_TABLE,
};
pub use types::{
    FastAllowSet, PledgePromises, PledgeState, SeccompAction, SeccompError, SeccompFilter,
    SeccompFlags, SeccompInsn, SeccompState, SeccompVerdict, MAX_INSNS,
};

// ============================================================================
// R29-2 FIX: Callback-based process integration
// R65-14 FIX: Fail-closed after initialization
// ============================================================================

/// Callback type for evaluating seccomp filters on current process.
pub type SeccompEvaluator = fn(u64, &[u64; 6]) -> SeccompVerdict;
/// Callback type for checking if current process has seccomp enabled.
pub type SeccompEnabledCheck = fn() -> bool;

/// Registered evaluator callback (set by kernel_core during init).
static CURRENT_EVALUATOR: RwLock<Option<SeccompEvaluator>> = RwLock::new(None);
/// Registered enabled-check callback (set by kernel_core during init).
static CURRENT_ENABLED_CHECK: RwLock<Option<SeccompEnabledCheck>> = RwLock::new(None);

/// R65-14 FIX: Track whether seccomp has been properly initialized.
///
/// Before initialization: allow all syscalls (needed for kernel boot)
/// After initialization: fail-closed if evaluator is missing (bug/attack)
static SECCOMP_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Register callbacks for current-process seccomp evaluation.
///
/// This function is called from kernel_core::init() to bridge the dependency
/// gap between seccomp and kernel_core modules.
///
/// # Arguments
///
/// * `evaluator` - Function to evaluate seccomp filters for current process
/// * `enabled_check` - Function to check if current process has seccomp enabled
///
/// # R65-14 FIX
///
/// Sets SECCOMP_INITIALIZED to true after registering callbacks.
/// After this point, if the evaluator is somehow unset, syscalls will be
/// denied rather than allowed (fail-closed behavior).
pub fn register_current_hooks(evaluator: SeccompEvaluator, enabled_check: SeccompEnabledCheck) {
    *CURRENT_EVALUATOR.write() = Some(evaluator);
    *CURRENT_ENABLED_CHECK.write() = Some(enabled_check);
    // R65-14 FIX: Mark seccomp as initialized - fail-closed after this point
    SECCOMP_INITIALIZED.store(true, Ordering::SeqCst);
    klog!(
        Info,
        "  Seccomp hooks registered for current-process evaluation (fail-closed mode active)"
    );
}

// ============================================================================
// Strict Mode Syscall Whitelist (generated from syscall_table::SYSCALL_TABLE)
// ============================================================================

/// Syscalls allowed in SECCOMP_MODE_STRICT, derived at compile time from
/// `syscall_table::SYSCALL_TABLE` (`strict_allowed == true`).
const STRICT_ALLOWED: &[u64] = &syscall_table::STRICT_ALLOWED;

const WORST_CASE_STRICT_INSNS: usize = 2 + 2 * syscall_table::STRICT_ALLOWED_COUNT;

const fn build_strict_program() -> [SeccompInsn; WORST_CASE_STRICT_INSNS] {
    let mut prog = [SeccompInsn::Ret(SeccompAction::Kill); WORST_CASE_STRICT_INSNS];
    prog[0] = SeccompInsn::LdSyscallNr;
    let mut i = 0usize;
    while i < syscall_table::STRICT_ALLOWED_COUNT {
        prog[1 + 2 * i] = SeccompInsn::JmpEq(syscall_table::STRICT_ALLOWED[i], 0, 1);
        prog[2 + 2 * i] = SeccompInsn::Ret(SeccompAction::Allow);
        i += 1;
    }
    prog[WORST_CASE_STRICT_INSNS - 1] = SeccompInsn::Ret(SeccompAction::Kill);
    prog
}

const STRICT_PROGRAM: [SeccompInsn; WORST_CASE_STRICT_INSNS] = build_strict_program();

/// R169-12 / N2.0b: Conservative worst-case instruction count for a generated
/// pledge filter — `1` (LdSyscallNr) + `2` per allowed syscall + `1` (Ret Kill).
/// `PLEDGE_UNION_COUNT` is derived at compile time from `SYSCALL_TABLE` and
/// bounded by `MAX_PLEDGE_SYSCALLS` so any table expansion that would overrun
/// `MAX_TRUSTED_INSNS` is a build error.
const MAX_PLEDGE_SYSCALLS: usize = 64;
const _: () = assert!(syscall_table::PLEDGE_UNION_COUNT <= MAX_PLEDGE_SYSCALLS);
const WORST_CASE_PLEDGE_INSNS: usize = 2 + 2 * MAX_PLEDGE_SYSCALLS;
const _: () = assert!(WORST_CASE_PLEDGE_INSNS <= types::MAX_TRUSTED_INSNS);

/// R170-I1: parallel bound for the strict-mode trusted generator.
const _: () = assert!(WORST_CASE_STRICT_INSNS <= types::MAX_TRUSTED_INSNS);
const _: () = assert!(STRICT_PROGRAM.len() == WORST_CASE_STRICT_INSNS);

/// R169-12: Minimal fail-closed filter — a single `Ret(Kill)` with a `Kill`
/// default action (deny everything). Used as the panic-free fallback for the
/// trusted generators if a generated program ever exceeds `MAX_TRUSTED_INSNS`
/// (a future-regression backstop; the const-assert above keeps the current
/// vocabulary within bounds). A 1-instruction `[Ret(Kill)]` program is trivially
/// valid (non-empty, has a terminator, no jumps), so this construction cannot
/// itself fail. Deny-all is the safe direction.
fn deny_all_filter() -> SeccompFilter {
    let prog = [SeccompInsn::Ret(SeccompAction::Kill)];
    SeccompFilter::new_trusted_from_slice(&prog, SeccompAction::Kill, SeccompFlags::empty())
        .expect("minimal [Ret(Kill)] filter is always valid")
}

/// RF180-18 FIX: fallible strict-filter construction for user installation.
pub fn try_strict_filter() -> Result<SeccompFilter, SeccompError> {
    SeccompFilter::new_trusted_from_slice(
        &STRICT_PROGRAM,
        SeccompAction::Kill,
        SeccompFlags::empty(),
    )
}

/// Allocation-free strict-filter identity for PR_GET_SECCOMP.
pub fn strict_filter_id() -> u64 {
    SeccompFilter::program_id(&STRICT_PROGRAM)
}

/// Create a filter for strict mode.
pub fn strict_filter() -> SeccompFilter {
    // R169-12 FIX: trusted generator — validate against MAX_TRUSTED_INSNS and
    // FAIL CLOSED (deny-all [Ret(Kill)]) rather than panic if a future
    // STRICT_ALLOWED expansion ever overruns the bound.
    try_strict_filter().unwrap_or_else(|_| deny_all_filter())
}

// ============================================================================
// Pledge Filter Generation
// ============================================================================

/// N2.0b: the deduped, sorted set of syscall numbers a pledge promise set allows,
/// generated directly from `syscall_table::SYSCALL_TABLE`.
///
/// `SYSCALL_TABLE` is strictly sorted with unique syscall numbers, so collecting
/// matching rows produces the canonical sorted, deduplicated BPF allowlist with
/// zero duplication against `promise_allows_syscall()` or `syscall_dispatcher()`.
pub fn pledge_syscall_list(promises: PledgePromises) -> Vec<u64> {
    let mut allowed_syscalls: Vec<u64> = Vec::new();
    for spec in syscall_table::SYSCALL_TABLE {
        if spec.pledge.allows_nr(promises) {
            allowed_syscalls.push(spec.nr);
        }
    }
    allowed_syscalls
}

/// M0-6: the full pledge syscall union across ALL promises — the set the
/// divergence-prevention parity self-test asserts is dispatched-or-exempt.
pub fn pledge_full_syscall_union() -> Vec<u64> {
    pledge_syscall_list(PledgePromises::all())
}

/// Generate a seccomp filter from pledge promises.
///
/// This compiles the promise set into a BPF-like filter that can be
/// evaluated by the same code path as user-provided filters. The whitelisted
/// numbers are exactly `pledge_syscall_list(promises)` (single source of truth).
pub fn pledge_to_filter(promises: PledgePromises) -> SeccompFilter {
    use types::*;
    // M0-6: same sorted+deduped list the union/parity test sees -> the compiled
    // BPF program is byte-identical to the pre-refactor generator.
    let allowed_syscalls = pledge_syscall_list(promises);
    let mut prog = Vec::new();

    // Build filter program
    prog.push(SeccompInsn::LdSyscallNr);

    for &nr in &allowed_syscalls {
        prog.push(SeccompInsn::JmpEq(nr, 0, 1));
        prog.push(SeccompInsn::Ret(SeccompAction::Allow));
    }

    // Default: kill
    prog.push(SeccompInsn::Ret(SeccompAction::Kill));

    // R169-12 FIX: trusted generator — validate the (compile-time-bounded)
    // program against MAX_TRUSTED_INSNS and FAIL CLOSED (deny-all [Ret(Kill)])
    // rather than panic. The worst case is const-asserted (WORST_CASE_PLEDGE_INSNS)
    // to fit MAX_TRUSTED_INSNS, so the fallback is a future-regression backstop.
    SeccompFilter::new_trusted(prog, SeccompAction::Kill, SeccompFlags::empty())
        .unwrap_or_else(|_| deny_all_filter())
}

// ============================================================================
// Current Process Integration
// ============================================================================

/// Evaluate seccomp filters for the current process.
///
/// This is the main entry point called from syscall dispatcher.
///
/// # R29-2 FIX
///
/// Previously this function always returned Allow, completely bypassing
/// seccomp filters. Now it delegates to the registered callback from
/// kernel_core which evaluates the actual process's SeccompState.
///
/// # R65-14 FIX: Fail-Closed After Initialization
///
/// The behavior depends on the initialization state:
///
/// 1. **Before initialization** (early boot): Returns Allow.
///    The kernel itself needs to make syscalls during boot.
///
/// 2. **After initialization, evaluator present**: Delegates to evaluator.
///    Normal operation path.
///
/// 3. **After initialization, evaluator missing**: Returns Kill (fail-closed).
///    This indicates a bug or attack where the evaluator was cleared.
///    Failing closed prevents a security bypass.
#[inline]
pub fn evaluate_current(syscall_nr: u64, args: &[u64; 6]) -> SeccompVerdict {
    // Use registered callback if available
    if let Some(evaluator) = *CURRENT_EVALUATOR.read() {
        return evaluator(syscall_nr, args);
    }

    // R65-14 FIX: Fail-closed after initialization
    // If seccomp is initialized but evaluator is None, something is wrong
    // (bug or attack that cleared the callback). Fail-closed to prevent bypass.
    if SECCOMP_INITIALIZED.load(Ordering::SeqCst) {
        // Log this critical error - evaluator should never be None after init
        // Using Kill action with filter_id 0 to indicate internal error
        return SeccompVerdict {
            action: SeccompAction::Kill,
            filter_id: 0,
        };
    }

    // Pre-initialization: allow (needed for kernel boot)
    SeccompVerdict::allow()
}

/// Check if current process has seccomp enabled.
///
/// # R29-2 FIX
///
/// Previously this always returned false. Now it delegates to the
/// registered callback from kernel_core.
#[inline]
pub fn is_enabled() -> bool {
    // Use registered callback if available
    if let Some(check) = *CURRENT_ENABLED_CHECK.read() {
        return check();
    }
    // Fallback: no callback registered yet
    false
}

/// Convert SeccompAction to AuditSeccompAction.
#[inline]
fn action_to_audit(action: &SeccompAction) -> AuditSeccompAction {
    match action {
        SeccompAction::Allow => AuditSeccompAction::Allow,
        SeccompAction::Log => AuditSeccompAction::Log,
        SeccompAction::Errno(_) => AuditSeccompAction::Errno,
        SeccompAction::Trap => AuditSeccompAction::Trap,
        SeccompAction::Kill => AuditSeccompAction::Kill,
    }
}

/// Notify of a seccomp violation (for audit logging).
///
/// This function should be called when a seccomp filter returns a non-Allow
/// verdict. It emits an audit event with details about the blocked syscall.
///
/// # Arguments
///
/// * `pid` - Process ID of the caller
/// * `uid` - User ID of the caller
/// * `gid` - Group ID of the caller
/// * `syscall_nr` - System call number that was blocked
/// * `verdict` - The verdict returned by the filter
/// * `timestamp` - Event timestamp (from kernel_core::time::get_ticks())
///
/// # Note
///
/// This function is best-effort and ignores audit emission errors to avoid
/// affecting the main code path.
pub fn notify_violation(
    pid: u32,
    uid: u32,
    gid: u32,
    syscall_nr: u64,
    verdict: &SeccompVerdict,
    timestamp: u64,
) {
    let subject = AuditSubject::new(pid, uid, gid, None);
    let audit_action = action_to_audit(&verdict.action);

    // Extract errno from action if applicable
    let errno = match verdict.action {
        SeccompAction::Errno(e) => e as i32,
        SeccompAction::Kill => 9,  // SIGKILL-like
        SeccompAction::Trap => 31, // SIGSYS
        _ => 0,
    };

    let _ = emit_seccomp_violation(
        subject,
        syscall_nr,
        verdict.filter_id,
        audit_action,
        errno,
        timestamp,
    );
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize the seccomp subsystem.
pub fn init() {
    klog_always!("  Seccomp/Pledge subsystem initialized");
}

// ============================================================================
// In-kernel self-test (boot suite)
// ============================================================================

/// R171-CG2x1 self-test: the per-process seccomp filter chain MUST be bounded by
/// `MAX_FILTER_INSNS_TOTAL`. Installing filters in a loop must REJECT (Err → the
/// caller maps it to ENOMEM) before the chain grows without bound, and the
/// cumulative instruction count must stay within the cap.
///
/// Runs from the kernel boot suite (NOT `#[cfg(test)]`, which does not compile
/// under the no_std cross-build). Any failure panics → caught by `make test`.
///
/// The companion R171-CG1x2 seal (private `SeccompFilter` fields) is a COMPILE-TIME
/// property — an out-of-crate struct literal that bypasses `validate_program` no
/// longer compiles — so it needs no runtime check here.
pub fn run_seccomp_cap_self_test() {
    use types::{SeccompState, MAX_FILTER_INSNS_TOTAL};

    let mut state = SeccompState::new();
    let per = strict_filter().prog_len().max(1);
    let max_installs = MAX_FILTER_INSNS_TOTAL / per;

    let mut installed = 0usize;
    let mut rejected = false;
    // Try a few past the theoretical cap; the cap MUST reject before then.
    for _ in 0..(max_installs + 4) {
        if state.add_filter(strict_filter()).is_err() {
            rejected = true;
            break;
        }
        installed += 1;
    }

    assert!(
        rejected,
        "seccomp chain cap must reject before unbounded growth"
    );
    assert!(installed >= 1, "a below-cap install must succeed");
    assert!(
        installed <= max_installs,
        "must not exceed the total-insn cap"
    );

    let total: usize = state.filters().iter().map(|f| f.prog_len()).sum();
    assert!(
        total <= MAX_FILTER_INSNS_TOTAL,
        "chain total instructions must stay within the cap"
    );
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;
    use alloc::vec;

    use super::*;

    #[test]
    fn stdio_admits_the_durability_family_in_every_list() {
        let list = pledge_syscall_list(PledgePromises::STDIO);
        for nr in [74u64, 75, 162, 277] {
            assert!(list.contains(&nr), "pledge list omits {nr}");
            assert!(
                types::promise_allows_syscall_probe(PledgePromises::STDIO, nr),
                "promise check omits {nr}"
            );
            assert!(!types::promise_allows_syscall_probe(
                PledgePromises::RPATH,
                nr
            ));
        }
    }

    #[test]
    fn test_strict_filter() {
        let filter = strict_filter();

        // Read should be allowed
        let args = [0u64; 6];
        assert_eq!(filter.evaluate(0, &args), SeccompAction::Allow);

        // Write should be allowed
        assert_eq!(filter.evaluate(1, &args), SeccompAction::Allow);

        // rt_sigreturn should be allowed (R144-3 FIX)
        assert_eq!(filter.evaluate(15, &args), SeccompAction::Allow);

        // Exit should be allowed
        assert_eq!(filter.evaluate(60, &args), SeccompAction::Allow);

        // Other syscalls should be killed
        assert_eq!(filter.evaluate(2, &args), SeccompAction::Kill); // open
        assert_eq!(filter.evaluate(57, &args), SeccompAction::Kill); // fork
    }

    #[test]
    fn test_pledge_stdio() {
        let filter = pledge_to_filter(PledgePromises::STDIO);
        let args = [0u64; 6];

        // STDIO syscalls should be allowed
        assert_eq!(filter.evaluate(0, &args), SeccompAction::Allow); // read
        assert_eq!(filter.evaluate(1, &args), SeccompAction::Allow); // write
        assert_eq!(filter.evaluate(3, &args), SeccompAction::Allow); // close

        // Non-STDIO syscalls should be killed
        assert_eq!(filter.evaluate(57, &args), SeccompAction::Kill); // fork
    }

    #[test]
    fn test_promise_parsing() {
        let promises = PledgePromises::parse("stdio rpath").unwrap();
        assert!(promises.contains(PledgePromises::STDIO));
        assert!(promises.contains(PledgePromises::RPATH));
        assert!(!promises.contains(PledgePromises::WPATH));

        // Invalid promise should fail
        assert!(PledgePromises::parse("stdio invalid").is_err());
    }

    #[test]
    fn test_seccomp_state() {
        let mut state = SeccompState::new();
        assert!(!state.has_filters());

        // Add a strict filter
        state
            .add_filter(strict_filter())
            .expect("strict filter admission");
        assert!(state.has_filters());

        // Evaluate
        let args = [0u64; 6];
        assert_eq!(state.evaluate(0, &args).action, SeccompAction::Allow);
        assert_eq!(state.evaluate(57, &args).action, SeccompAction::Kill);
    }

    #[test]
    fn rf180_28_filter_arc_charge_follows_the_complete_control_block_lifetime() {
        let mut original = SeccompState::new();
        original
            .add_filter(strict_filter())
            .expect("strict filter admission");
        let retained = Arc::clone(&original.filters()[0]);
        let allocator = *Arc::allocator(&retained);
        let expected_charge = allocator.charge_bytes_for_test();
        assert!(expected_charge >= core::mem::size_of::<SeccompFilter>());

        let cloned = original.try_clone().expect("fallible seccomp clone");
        assert!(Arc::ptr_eq(&original.filters()[0], &cloned.filters()[0]));
        assert_eq!(Arc::strong_count(&cloned.filters()[0]), 3);

        let weak = Arc::downgrade(&retained);

        drop(original);
        drop(cloned);
        assert_eq!(Arc::strong_count(&retained), 1);
        assert_eq!(
            allocator.charge_bytes_for_test(),
            expected_charge,
            "the allocation charge must survive the state that installed it"
        );

        drop(retained);
        assert!(weak.upgrade().is_none());
        assert_eq!(
            allocator.charge_bytes_for_test(),
            expected_charge,
            "a weak handle still retains the Arc control block"
        );
        drop(weak);
        assert_eq!(
            allocator.charge_bytes_for_test(),
            0,
            "the final weak drop must release the allocation charge"
        );
    }

    #[test]
    fn test_filter_validation() {
        // Empty program should fail
        assert!(SeccompFilter::new(vec![], SeccompAction::Allow, SeccompFlags::empty()).is_err());

        // Program without terminator should fail
        let prog = vec![SeccompInsn::LdSyscallNr];
        assert!(SeccompFilter::new(prog, SeccompAction::Allow, SeccompFlags::empty()).is_err());

        // Valid program should succeed
        let prog = vec![SeccompInsn::Ret(SeccompAction::Allow)];
        assert!(SeccompFilter::new(prog, SeccompAction::Allow, SeccompFlags::empty()).is_ok());
    }

    #[test]
    fn test_pledge_rpath_blocks_write_and_create() {
        let state = PledgeState::new(PledgePromises::RPATH);
        let mut args = [0u64; 6];

        // O_RDONLY should be allowed with rpath
        args[1] = 0; // flags
        assert!(state.allows(2, &args)); // SYS_OPEN

        // O_WRONLY should be denied without wpath/cpath
        args[1] = 1; // O_WRONLY
        assert!(!state.allows(2, &args));

        // O_CREAT should be denied without cpath/tmppath
        args[1] = 0o100; // O_CREAT
        assert!(!state.allows(2, &args));
    }

    #[test]
    fn test_pledge_prot_exec_requires_promise() {
        const PROT_EXEC: u64 = 0x4;
        let vm_only = PledgeState::new(PledgePromises::VM);
        let vm_with_exec = PledgeState::new(PledgePromises::VM | PledgePromises::PROT_EXEC);

        // mprotect with PROT_EXEC should be denied without prot_exec promise
        let args = [0u64, 0, PROT_EXEC, 0, 0, 0];
        assert!(!vm_only.allows(10, &args)); // SYS_MPROTECT
        assert!(vm_with_exec.allows(10, &args));
    }

    /// R180-2: overlapping JmpEq on the same nr — first Kill must win; fast bit clear.
    #[test]
    fn r180_2_overlapping_jmpeq_must_not_fast_allow() {
        let x = 42u64;
        let prog = vec![
            SeccompInsn::LdSyscallNr,
            SeccompInsn::JmpEq(x, 0, 1),
            SeccompInsn::Ret(SeccompAction::Kill),
            SeccompInsn::JmpEq(x, 0, 1),
            SeccompInsn::Ret(SeccompAction::Allow),
            SeccompInsn::Ret(SeccompAction::Kill),
        ];
        let f = SeccompFilter::new(prog, SeccompAction::Kill, SeccompFlags::empty()).unwrap();
        let args = [0u64; 6];
        assert_eq!(f.evaluate(x, &args), SeccompAction::Kill);
        assert!(!f.fast_allows(x));
    }

    /// R180-2: first-match Allow still fast-paths.
    #[test]
    fn r180_2_first_allow_wins_fast_path() {
        let x = 7u64;
        let prog = vec![
            SeccompInsn::LdSyscallNr,
            SeccompInsn::JmpEq(x, 0, 1),
            SeccompInsn::Ret(SeccompAction::Allow),
            SeccompInsn::JmpEq(x, 0, 1),
            SeccompInsn::Ret(SeccompAction::Kill),
            SeccompInsn::Ret(SeccompAction::Kill),
        ];
        let f = SeccompFilter::new(prog, SeccompAction::Kill, SeccompFlags::empty()).unwrap();
        assert_eq!(f.evaluate(x, &[0; 6]), SeccompAction::Allow);
        assert!(f.fast_allows(x));
    }

    /// R180-2: any LdArg disables the entire fast_allow set (fail-closed).
    #[test]
    fn r180_2_ldarg_disables_fast_allow() {
        let prog = vec![
            SeccompInsn::LdArg(0),
            SeccompInsn::JmpEq(0, 0, 1),
            SeccompInsn::Ret(SeccompAction::Allow),
            SeccompInsn::Ret(SeccompAction::Kill),
        ];
        let f = SeccompFilter::new(prog, SeccompAction::Kill, SeccompFlags::empty()).unwrap();
        assert_eq!(f.evaluate(0, &[0; 6]), SeccompAction::Allow);
        assert_eq!(f.evaluate(0, &[1, 0, 0, 0, 0, 0]), SeccompAction::Kill);
        for n in 0u64..512 {
            assert!(!f.fast_allows(n), "LdArg must suppress all fast bits");
        }
    }

    /// R180-2: Log is not Allow — must not set the bit (side effects / severity).
    #[test]
    fn r180_2_log_is_not_fast_allow() {
        let prog = vec![
            SeccompInsn::LdSyscallNr,
            SeccompInsn::JmpEq(0, 0, 1),
            SeccompInsn::Ret(SeccompAction::Log),
            SeccompInsn::Ret(SeccompAction::Kill),
        ];
        let f = SeccompFilter::new(prog, SeccompAction::Kill, SeccompFlags::empty()).unwrap();
        assert_eq!(f.evaluate(0, &[0; 6]), SeccompAction::Log);
        assert!(!f.fast_allows(0));
    }

    /// R180-2: pledge/strict generators still receive fast bits (efficiency).
    #[test]
    fn r180_2_strict_and_pledge_keep_fast_path() {
        let strict = strict_filter();
        for nr in [0u64, 1, 15, 60, 231] {
            assert_eq!(strict.evaluate(nr, &[0; 6]), SeccompAction::Allow);
            assert!(strict.fast_allows(nr));
        }
        assert!(!strict.fast_allows(2));
        assert_eq!(strict.evaluate(2, &[0; 6]), SeccompAction::Kill);

        let stdio = pledge_to_filter(PledgePromises::STDIO);
        for nr in [0u64, 1, 3, 60, 231] {
            assert_eq!(stdio.evaluate(nr, &[0; 6]), SeccompAction::Allow);
            assert!(stdio.fast_allows(nr));
        }
        assert!(!stdio.fast_allows(57));
        assert_eq!(stdio.evaluate(57, &[0; 6]), SeccompAction::Kill);
    }
}
