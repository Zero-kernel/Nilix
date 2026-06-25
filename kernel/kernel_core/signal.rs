//! Signal handling for Zero-OS
//!
//! Provides POSIX-like signal support including:
//! - Signal definitions (SIGKILL, SIGTERM, SIGSTOP, etc.)
//! - Pending signals bitmap per process
//! - Default signal actions
//! - Signal delivery mechanism

use crate::process::{self, ProcessId, ProcessState};
use crate::syscall::SyscallError;
use spin::Mutex;

/// Maximum signal number supported (1-64)
const MAX_SIGNAL: u8 = 64;

// ============================================================================
// 调度器集成回调
// ============================================================================

/// 恢复被暂停进程的回调类型
type ResumeCallback = fn(ProcessId) -> bool;

/// 全局恢复回调（由调度器注册）
static RESUME_CALLBACK: Mutex<Option<ResumeCallback>> = Mutex::new(None);

/// 注册恢复回调
///
/// 由调度器在初始化时调用，注册 resume_stopped 函数
pub fn register_resume_callback(callback: ResumeCallback) {
    *RESUME_CALLBACK.lock() = Some(callback);
}

/// 获取恢复回调
fn get_resume_callback() -> Option<ResumeCallback> {
    *RESUME_CALLBACK.lock()
}

/// M0-5 sub-slice 1b: cross-CPU reschedule-kick callback type. A bare `Blocked -> Ready`
/// flip makes the target SELECTABLE on the CPU that owns its ready queue, but that CPU may
/// be idle (in HLT) with no pending reschedule — and unlike the kill-wake (which TERMINATES
/// a stranded task via the deferred-kill cascade), the signal-wake needs the task to actually
/// RUN to deliver. So after a wake we ask the scheduler to broadcast a reschedule IPI so the
/// queue-owning CPU re-selects the now-Ready task promptly instead of at the next timer tick.
type KickCallback = fn();

/// 全局重调度 kick 回调（由调度器注册）。
static KICK_CALLBACK: Mutex<Option<KickCallback>> = Mutex::new(None);

/// 注册重调度 kick 回调（调度器初始化时调用，注册广播 reschedule-IPI 的函数）。
pub fn register_kick_callback(callback: KickCallback) {
    *KICK_CALLBACK.lock() = Some(callback);
}

fn get_kick_callback() -> Option<KickCallback> {
    *KICK_CALLBACK.lock()
}

/// R171-S-R170-5-01 FIX (SLICE 3): Kernel-internal un-stop hook used by the
/// namespace init-death cascade's `force_remote_kill`. A SIGKILL must un-stop a
/// job-control-stopped victim so the scheduler will dispatch it and it can reach a
/// safe point to consume its pending kill — otherwise a `Stopped` member of a
/// shutting-down namespace would survive the cascade (a live leak). No-op if the
/// scheduler has not registered a resume callback.
pub fn kernel_resume_stopped(pid: ProcessId) {
    if let Some(resume) = get_resume_callback() {
        resume(pid);
    }
}

/// Signal identifier (1-64, 0 is invalid)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signal(u8);

impl Signal {
    // Standard POSIX signals
    pub const SIGHUP: Signal = Signal(1); // Hangup
    pub const SIGINT: Signal = Signal(2); // Interrupt (Ctrl+C)
    pub const SIGQUIT: Signal = Signal(3); // Quit (Ctrl+\)
    pub const SIGILL: Signal = Signal(4); // Illegal instruction
    pub const SIGTRAP: Signal = Signal(5); // Trace/breakpoint trap
    pub const SIGABRT: Signal = Signal(6); // Abort
    pub const SIGBUS: Signal = Signal(7); // Bus error
    pub const SIGFPE: Signal = Signal(8); // Floating-point exception
    pub const SIGKILL: Signal = Signal(9); // Kill (cannot be caught/ignored)
    pub const SIGUSR1: Signal = Signal(10); // User-defined signal 1
    pub const SIGSEGV: Signal = Signal(11); // Segmentation fault
    pub const SIGUSR2: Signal = Signal(12); // User-defined signal 2
    pub const SIGPIPE: Signal = Signal(13); // Broken pipe
    pub const SIGALRM: Signal = Signal(14); // Alarm clock
    pub const SIGTERM: Signal = Signal(15); // Termination
    pub const SIGCHLD: Signal = Signal(17); // Child status changed
    pub const SIGCONT: Signal = Signal(18); // Continue if stopped
    pub const SIGSTOP: Signal = Signal(19); // Stop (cannot be caught/ignored)
    pub const SIGTSTP: Signal = Signal(20); // Stop typed at terminal
    pub const SIGTTIN: Signal = Signal(21); // Background read from tty
    pub const SIGTTOU: Signal = Signal(22); // Background write to tty

    /// Create signal from raw signal number
    pub fn from_raw(raw: i32) -> Result<Self, SignalError> {
        if raw <= 0 || raw > MAX_SIGNAL as i32 {
            return Err(SignalError::InvalidSignal);
        }
        Ok(Signal(raw as u8))
    }

    /// Create signal from 1-based index
    pub fn from_index(idx: u8) -> Option<Self> {
        if idx == 0 || idx > MAX_SIGNAL {
            None
        } else {
            Some(Signal(idx))
        }
    }

    /// Get raw signal number
    #[inline]
    pub fn as_u8(self) -> u8 {
        self.0
    }

    /// Get signal number as i32 (for syscall compatibility)
    #[inline]
    pub fn as_i32(self) -> i32 {
        self.0 as i32
    }

    /// Get bit mask for this signal in pending signals bitmap
    #[inline]
    pub fn bit(self) -> u64 {
        1u64 << (self.0 - 1)
    }

    /// Check if this is a stop signal (SIGSTOP, SIGTSTP, SIGTTIN, SIGTTOU)
    #[inline]
    pub fn is_stop(self) -> bool {
        matches!(self.0, 19 | 20 | 21 | 22)
    }

    /// Check if this is SIGCONT
    #[inline]
    pub fn is_continue(self) -> bool {
        self == Signal::SIGCONT
    }

    /// Check if this signal cannot be caught or ignored (SIGKILL, SIGSTOP)
    #[inline]
    pub fn is_uncatchable(self) -> bool {
        self == Signal::SIGKILL || self == Signal::SIGSTOP
    }
}

/// Pending signals bitmap (supports signals 1-64)
#[derive(Debug, Clone, Copy)]
pub struct PendingSignals {
    bits: u64,
}

impl PendingSignals {
    /// Create empty pending signals set
    pub const fn new() -> Self {
        Self { bits: 0 }
    }

    /// Set a signal as pending
    #[inline]
    pub fn set(&mut self, signal: Signal) {
        self.bits |= signal.bit();
    }

    /// Clear a pending signal
    #[inline]
    pub fn clear(&mut self, signal: Signal) {
        self.bits &= !signal.bit();
    }

    /// Check if a specific signal is pending
    #[inline]
    pub fn is_pending(&self, signal: Signal) -> bool {
        (self.bits & signal.bit()) != 0
    }

    /// Check if any signal is pending
    #[inline]
    pub fn has_pending(&self) -> bool {
        self.bits != 0
    }

    /// Take the next pending signal (lowest numbered first)
    pub fn take_next(&mut self) -> Option<Signal> {
        // R172-P6-F1: delegate the lowest-bit pick to the shared `select_lowest_deliverable`
        // so this third copy of trailing_zeros/from_index cannot re-fork (currently has no
        // callers — class-hardening insurance), then pop exactly the selected bit.
        let sig = select_lowest_deliverable(self.bits)?;
        self.bits &= !sig.bit();
        Some(sig)
    }

    /// Get raw bits (for debugging)
    #[inline]
    pub fn bits(&self) -> u64 {
        self.bits
    }

    /// Clear all pending signals
    #[inline]
    pub fn clear_all(&mut self) {
        self.bits = 0;
    }
}

impl Default for PendingSignals {
    fn default() -> Self {
        Self::new()
    }
}

/// Default signal action
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalAction {
    /// Ignore the signal
    Ignore,
    /// Terminate the process
    Terminate,
    /// Stop the process
    Stop,
    /// Continue if stopped
    Continue,
}

// ============================================================================
// M0 item 5 (sub-slice 1a): user signal-handler dispositions
// ============================================================================

/// `sa_handler` sentinel: take the default action.
pub const SIG_DFL: u64 = 0;
/// `sa_handler` sentinel: ignore the signal.
pub const SIG_IGN: u64 = 1;

// `sa_flags` bits (Linux x86-64 ABI). Only SA_RESTORER is load-bearing in slice 1a
// (required); the rest are stored faithfully but several are inert (documented M0
// divergences): SA_RESTART (no syscall restart — interrupted syscalls return EINTR),
// SA_SIGINFO (siginfo is minimally synthesized), SA_ONSTACK (no sigaltstack yet).
pub const SA_NOCLDSTOP: u64 = 0x0000_0001;
pub const SA_NOCLDWAIT: u64 = 0x0000_0002;
pub const SA_SIGINFO: u64 = 0x0000_0004;
pub const SA_RESTORER: u64 = 0x0400_0000;
pub const SA_ONSTACK: u64 = 0x0800_0000;
pub const SA_RESTART: u64 = 0x1000_0000;
pub const SA_NODEFER: u64 = 0x4000_0000;
pub const SA_RESETHAND: u64 = 0x8000_0000;

/// The set of `sa_flags` bits this kernel recognizes (others are rejected at install
/// so an unknown flag can never silently change behavior).
pub const SA_SUPPORTED_FLAGS: u64 = SA_NOCLDSTOP
    | SA_NOCLDWAIT
    | SA_SIGINFO
    | SA_RESTORER
    | SA_ONSTACK
    | SA_RESTART
    | SA_NODEFER
    | SA_RESETHAND;

/// Per-signal disposition. `#[repr(C)]` with the Linux `kernel_sigaction` field
/// order (handler, flags, restorer, mask) so a future shared-table / userspace
/// `struct sigaction` copy stays layout-aligned. 32 bytes, `Copy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct SigAction {
    /// `sa_handler` / `sa_sigaction`: SIG_DFL, SIG_IGN, or a user handler VA.
    pub handler: u64,
    /// `sa_flags`.
    pub flags: u64,
    /// `sa_restorer`: the userspace trampoline that issues `rt_sigreturn(15)`.
    /// REQUIRED (SA_RESTORER) for a real handler in slice 1a.
    pub restorer: u64,
    /// `sa_mask`: additional signals blocked for the duration of the handler.
    pub mask: u64,
}

impl SigAction {
    pub const fn default_action() -> Self {
        Self {
            handler: SIG_DFL,
            flags: 0,
            restorer: 0,
            mask: 0,
        }
    }
    /// True when a real user handler is installed (not SIG_DFL / SIG_IGN).
    #[inline]
    pub fn is_handler(&self) -> bool {
        self.handler != SIG_DFL && self.handler != SIG_IGN
    }
}

/// Number of entries in the per-task sigaction table (signals 1..=64).
pub const NSIG: usize = 64;

/// A born-clean sigaction table (every signal → SIG_DFL).
#[inline]
pub fn default_sigactions() -> [SigAction; NSIG] {
    [SigAction::default_action(); NSIG]
}

/// The mask of signals that can NEVER be blocked or caught (SIGKILL, SIGSTOP).
#[inline]
pub fn uncatchable_mask() -> u64 {
    Signal::SIGKILL.bit() | Signal::SIGSTOP.bit()
}

/// R172-P6-F1: the SINGLE lowest-deliverable-bit selector — pure / total / lock-free. Takes
/// the ALREADY-MASKED deliverable set, so the uncatchable-mask choice lives at the call site
/// as an explicit, deliberate decision (NOT an accidental omission): `signal_is_deliverable`
/// / `should_abort_pending_block` pass `pending & !blocked & !uncatchable_mask()` (a lone
/// pending SIGKILL/SIGSTOP must take the kill / stop leg, never the handler-EINTR leg), while
/// `maybe_deliver_signal` Phase-1 passes the UNMASKED `pending & !blocked` (it must still
/// select a lone uncatchable so its `Default` arm terminates / stops). Both, plus
/// `PendingSignals::take_next`, share THIS `trailing_zeros` / `from_index` / None-guard, so
/// the wake-gate selector and the delivery selector can NEVER drift apart (the lost-wakeup /
/// wrong-signal divergence the finding pinned). `from_index` already None-guards
/// `bit + 1 > MAX_SIGNAL`, so a spurious high bit is dropped, never panicked.
pub fn select_lowest_deliverable(deliverable: u64) -> Option<Signal> {
    if deliverable == 0 {
        return None;
    }
    let bit = deliverable.trailing_zeros() as u8; // signal = bit + 1, lowest first
    Signal::from_index(bit + 1)
}

/// The effective disposition of a signal under a sigaction table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// Run a user handler (slice 1a: only delivered at the syscall-return safe point).
    Handler { handler: u64, flags: u64, mask: u64 },
    /// Take the kernel default action.
    Default(SignalAction),
    /// Explicitly ignored (SIG_IGN).
    Ignored,
}

/// Resolve a signal's disposition from a sigaction table. SIGKILL/SIGSTOP ALWAYS
/// resolve to their default (uncatchable) regardless of the table — the table can
/// never hold a handler for them (rt_sigaction rejects that), but this is a
/// defense-in-depth re-check so an uncatchable signal can never be handler-dispatched.
pub fn resolve_disposition(sigactions: &[SigAction; NSIG], signal: Signal) -> Disposition {
    if signal.is_uncatchable() {
        return Disposition::Default(default_action(signal));
    }
    let sa = sigactions[(signal.as_u8() - 1) as usize];
    if sa.is_handler() {
        Disposition::Handler {
            handler: sa.handler,
            flags: sa.flags,
            mask: sa.mask,
        }
    } else if sa.handler == SIG_IGN {
        Disposition::Ignored
    } else {
        Disposition::Default(default_action(signal))
    }
}

/// `how` argument values for `rt_sigprocmask` (Linux ABI).
pub const SIG_BLOCK: i32 = 0;
pub const SIG_UNBLOCK: i32 = 1;
pub const SIG_SETMASK: i32 = 2;

/// Pure read-modify-write of the per-task blocked mask. SIGKILL/SIGSTOP are ALWAYS
/// force-cleared from the result so they can never be blocked (POSIX). Factored out
/// for self-testing.
pub fn apply_sigprocmask(old: u64, how: i32, set: u64) -> u64 {
    let next = match how {
        SIG_BLOCK => old | set,
        SIG_UNBLOCK => old & !set,
        SIG_SETMASK => set,
        _ => old, // unreachable: callers validate `how` first.
    };
    next & !uncatchable_mask()
}

/// Monotonic global hint: set once ANY process installs a real signal handler. The
/// per-syscall-return delivery hook reads this LOCK-FREE and skips ALL work while it
/// is false — and the musl/native-hello gate path never installs a handler, so its
/// hot path stays a single relaxed atomic load. Monotonic (never reset) so it needs
/// no fork/exec/exit bookkeeping; the only cost is that after the first handler
/// install in a boot, every syscall return takes the (uncontended) process lock to
/// scan for a deliverable signal — acceptable, and never on the no-handler gate.
static ANY_HANDLER_INSTALLED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Record that a real handler was installed (called from `rt_sigaction`).
#[inline]
pub fn note_handler_installed() {
    ANY_HANDLER_INSTALLED.store(true, core::sync::atomic::Ordering::Relaxed);
}

/// Lock-free fast-path gate for the syscall-return delivery hook.
#[inline]
pub fn any_handler_installed() -> bool {
    ANY_HANDLER_INSTALLED.load(core::sync::atomic::Ordering::Relaxed)
}

/// M0-5 sub-slice 1b: pure predicate — is a HANDLER signal deliverable to a task with this
/// (pending, blocked, in_handler, sigactions) snapshot? HANDLER-ONLY by design:
/// * A no-handler catchable signal (e.g. Default(Terminate)) to a blocked task is ALREADY
///   wake+terminated by the KILL leg (send_signal sets terminate_code -> request_process_exit
///   flips Blocked->Ready + sets pending_kill -> wait_should_abort fires), so Handler-only is
///   both correct AND complete — NOT a gap.
/// * `in_handler` => false: never EINTR-wake (or deliver) while a handler frame is live
///   (mirrors maybe_deliver_signal's serialize-defer; anti-spurious-EINTR, LOAD-BEARING).
/// * `& !uncatchable_mask()`: send_signal sets the pending bit for SIGKILL too and SIGKILL is
///   force-stripped from `blocked`, so a SIGKILL bit IS in `pending & !blocked` — it MUST be
///   masked out here so it takes the kill leg, never the signal-EINTR leg.
/// Resolves the LOWEST deliverable bit's disposition (bit-for-bit congruent with
/// maybe_deliver_signal Phase-1) so the send-side wake and the wait-site epilogue agree.
fn signal_is_deliverable(
    pending: u64,
    blocked: u64,
    in_handler: bool,
    sigactions: &[SigAction; NSIG],
) -> bool {
    if in_handler {
        return false;
    }
    // Site A (R172-P6-F1): mask uncatchables BEFORE the shared pick — a lone pending
    // SIGKILL/SIGSTOP must NOT be reported deliverable here (it takes the kill / stop leg,
    // never the handler-EINTR leg). The bit-pick is the SAME primitive Site B uses.
    let sig = match select_lowest_deliverable(pending & !blocked & !uncatchable_mask()) {
        Some(s) => s,
        None => return false,
    };
    matches!(
        resolve_disposition(sigactions, sig),
        Disposition::Handler { .. }
    )
}

/// M0-5 sub-slice 1b: does `pid` have a deliverable HANDLER signal pending? Called by the
/// blocking wait sites to decide an EINTR-wake. Lock-free fast-path FIRST (no proc lock on
/// the no-handler musl/native boot — a single relaxed load), then ONE proc-lock snapshot.
pub fn has_deliverable_signal(pid: ProcessId) -> bool {
    if !any_handler_installed() {
        return false;
    }
    let arc = match process::get_process(pid) {
        Some(a) => a,
        None => return false,
    };
    let proc = arc.lock();
    signal_is_deliverable(
        proc.pending_signals.bits(),
        proc.blocked,
        proc.in_signal_handler,
        &proc.sigactions,
    )
}

/// M0-5 sub-slice 1b: should a task ABOUT to publish Blocked bail instead? True if a kill is
/// pending OR a deliverable handler signal exists. Called UNDER the proc lock at the
/// Blocked-commit point (where the wakers also take the lock) to close the lost-wakeup window
/// between a top-of-wait bail and publishing Blocked — a window in which the bare
/// state-flip wake (which fires only on state==Blocked) would otherwise be missed, stranding
/// the task indefinitely (signals, unlike kills, have no deferred-kill-cascade backstop).
/// Takes `&Process` so the caller can re-use its already-held guard (no re-lock / deadlock).
pub fn should_abort_pending_block(proc: &crate::process::Process) -> bool {
    proc.pending_kill
        .load(core::sync::atomic::Ordering::Acquire)
        || signal_is_deliverable(
            proc.pending_signals.bits(),
            proc.blocked,
            proc.in_signal_handler,
            &proc.sigactions,
        )
}

/// Signal-related errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalError {
    /// Invalid signal number
    InvalidSignal,
    /// Target process does not exist
    NoSuchProcess,
    /// Permission denied
    PermissionDenied,
}

impl From<SignalError> for SyscallError {
    fn from(err: SignalError) -> Self {
        match err {
            SignalError::InvalidSignal => SyscallError::EINVAL,
            SignalError::NoSuchProcess => SyscallError::ESRCH,
            SignalError::PermissionDenied => SyscallError::EPERM,
        }
    }
}

/// Calculate exit code for signal termination (128 + signal number)
// R171-S-R170-5-01 FIX (SLICE 3): exposed `pub(crate)` so the namespace
// init-death cascade can compute SIGKILL's exit code without re-deriving the
// `128 + signum` convention (avoids a drifting magic number).
#[inline]
pub(crate) fn signal_exit_code(signal: Signal) -> i32 {
    128 + signal.as_u8() as i32
}

/// Get default action for a signal
///
/// SIGKILL and SIGSTOP always execute their default action.
pub fn default_action(signal: Signal) -> SignalAction {
    if signal.is_continue() {
        SignalAction::Continue
    } else if signal.is_stop() {
        SignalAction::Stop
    } else if signal == Signal::SIGCHLD {
        SignalAction::Ignore
    } else {
        SignalAction::Terminate
    }
}

/// Send a signal to a process (user-facing, enforces POSIX permission checks).
///
/// Executes the default action immediately for SIGKILL/SIGSTOP.
/// Other signals are queued for later delivery.
///
/// # Arguments
///
/// * `pid` - Target process ID
/// * `signal` - Signal to send
///
/// # Returns
///
/// The action taken on success, or error
///
/// # Permission Model (Z-9 fix: POSIX-compliant UID/EUID checks)
///
/// POSIX permission rules for kill():
/// - Root (euid == 0) can signal any process
/// - Process can signal itself
/// - sender.uid == target.uid
/// - sender.euid == target.uid
/// - PID 1 (init) is additionally protected: only self can signal
pub fn send_signal(pid: ProcessId, signal: Signal) -> Result<SignalAction, SignalError> {
    send_signal_inner(pid, signal, true)
}

/// R115-2 FIX: Kernel-authoritative signal delivery — bypasses POSIX permission checks.
///
/// Only callable from kernel-internal paths that require unconditional authority:
/// - PID namespace init-death cascade (must SIGKILL all members regardless of UID)
/// - OOM killer
/// - Seccomp enforcement
///
/// MUST NOT be exposed to user-facing syscalls.
pub fn send_signal_kernel(pid: ProcessId, signal: Signal) -> Result<SignalAction, SignalError> {
    send_signal_inner(pid, signal, false)
}

/// Inner implementation shared by user-facing and kernel-internal signal paths.
///
/// When `enforce_permissions` is true, POSIX UID/EUID checks are applied.
/// When false, the signal is delivered unconditionally (kernel authority).
fn send_signal_inner(
    pid: ProcessId,
    signal: Signal,
    enforce_permissions: bool,
) -> Result<SignalAction, SignalError> {
    // 注意：我们需要调用调度器的 resume_stopped，它在 sched crate 中
    // 由于循环依赖的限制，我们通过回调机制实现

    // R65-26 FIX: Get target process Arc ONCE and hold it throughout the operation.
    // This prevents TOCTOU where PID is reused between permission check and signal delivery.
    // Previously, we fetched the process twice: once for permission check, once for signal.
    let process_arc = process::get_process(pid).ok_or(SignalError::NoSuchProcess)?;

    // 【安全修复 Z-9】POSIX 权限检查（深度防御）
    // 使用 UID/EUID 而非仅父子关系
    // R115-2 FIX: Only enforce permission checks on user-facing paths.
    // Kernel-internal paths (namespace cascade, OOM killer) use send_signal_kernel()
    // which sets enforce_permissions=false to bypass these checks.
    if enforce_permissions {
        if let Some(sender_pid) = process::current_pid() {
            // PID 1 (init) 保护：只有 init 自己可以向自己发信号
            if pid == 1 && sender_pid != 1 {
                return Err(SignalError::PermissionDenied);
            }

            // 非自己的进程需要进行 POSIX 权限检查
            if sender_pid != pid {
                // 获取发送者凭证
                let sender_creds =
                    process::current_credentials().ok_or(SignalError::NoSuchProcess)?;

                // R65-26 FIX: Read target UID from the same Arc we'll use for signal delivery
                // This closes the TOCTOU window where PID could be reused between check and delivery
                let target_uid = process_arc.lock().credentials.read().uid;

                // POSIX 权限检查：
                // 1. Host root (host-mapped euid == 0) 可以发信号给任何进程
                // 2. sender.uid == target.uid
                // 3. sender.euid == target.uid
                // R134-7 FIX: Use host-mapped root check for defense-in-depth.
                // sys_kill already performs namespace-aware check, but this
                // hardens the inner function against future callers.
                let has_permission = crate::current_is_host_root()
                    || sender_creds.uid == target_uid
                    || sender_creds.euid == target_uid;

                if !has_permission {
                    return Err(SignalError::PermissionDenied);
                }
            }
        }
    }

    // process_arc already obtained above (R65-26 FIX)
    let action = default_action(signal);
    let mut needs_reschedule = false;
    let mut terminate_code: Option<i32> = None;
    let mut needs_resume = false;
    // M0-5 sub-slice 1b: set when the EINTR-wake flips a blocked target Ready, so we
    // broadcast a reschedule kick AFTER releasing the proc lock.
    let mut needs_kick = false;

    {
        let mut proc = process_arc.lock();

        // Cannot send signals to zombie or terminated processes
        if matches!(proc.state, ProcessState::Zombie | ProcessState::Terminated) {
            return Err(SignalError::NoSuchProcess);
        }

        // Queue the signal (always — delivery/clear decisions follow).
        proc.pending_signals.set(signal);

        // POSIX job-control mutual exclusion (Codex review): generating SIGCONT
        // DISCARDS any pending stop signals, and generating a stop signal discards a
        // pending SIGCONT — they are opposite job-control transitions. Without this,
        // a stop bit left pending (a stop is applied at send time but its bit is not
        // cleared) could be re-applied at a later syscall-return safe point once the
        // delivery scan is active, spuriously re-stopping a resumed task.
        if signal.is_continue() {
            proc.pending_signals.clear(Signal::SIGSTOP);
            proc.pending_signals.clear(Signal::SIGTSTP);
            proc.pending_signals.clear(Signal::SIGTTIN);
            proc.pending_signals.clear(Signal::SIGTTOU);
        } else if signal.is_stop() {
            proc.pending_signals.clear(Signal::SIGCONT);
        }

        // M0 item 5 (sub-slice 1a): resolve the disposition.
        //
        // `resolve_disposition` special-cases SIGKILL/SIGSTOP to their (uncatchable)
        // DEFAULT before any table consult, so a fatal kill is never diverted to a
        // handler and the kill leg stays mask-independent — SIGKILL is unblockable by
        // construction. A catchable signal WITH a user handler is SET-PENDING-ONLY
        // here and delivered at the target's next syscall-return safe point
        // (sub-slice 1a does NOT wake a blocked-in-syscall target — that is 1b); its
        // default action is NOT executed at send time.
        match resolve_disposition(&proc.sigactions, signal) {
            Disposition::Handler { .. } => {
                // Leave the signal pending for safe-point delivery. SIGCONT is the one
                // job-control case that must still take effect even when caught: a
                // caught SIGCONT MUST un-stop a stopped target so it can reach a safe
                // point and run its handler (otherwise it would be stranded stopped
                // forever). Resume, but DO NOT clear the pending bit — the handler
                // needs it.
                if signal.is_continue() && (proc.stopped || proc.state == ProcessState::Stopped) {
                    needs_resume = true;
                }
                // M0-5 sub-slice 1b: EINTR-wake a target BLOCKED in a syscall so it unwinds
                // to its syscall-return tail and returns EINTR (the handler then delivers at
                // its NEXT syscall entry — 1a re-establishes the per-CPU frame there). Routed
                // through the SAME pure predicate the wait-site epilogues use (so the wake and
                // the epilogue agree on the lowest deliverable bit — no socket lost-wakeup).
                // Guarded `== Blocked && !stopped`: a job-control-stopped+blocked task must
                // keep its Blocked wait-state (un-stop is SIGCONT's resume_stopped path, not
                // this). Bare state flip — the PCB stays in the scheduler; select_next re-picks
                // it on `== Ready`. Idempotent vs a racing data-wake (the `== Blocked` guard).
                let should_wake = signal_is_deliverable(
                    proc.pending_signals.bits(),
                    proc.blocked,
                    proc.in_signal_handler,
                    &proc.sigactions,
                );
                if should_wake && proc.state == ProcessState::Blocked && !proc.stopped {
                    proc.state = ProcessState::Ready;
                    needs_kick = true;
                }
            }
            Disposition::Ignored => {
                // Explicitly ignored — drop it.
                proc.pending_signals.clear(signal);
            }
            Disposition::Default(default) => match default {
                SignalAction::Terminate => {
                    terminate_code = Some(signal_exit_code(signal));
                }
                SignalAction::Stop => {
                    // R98-1 FIX: Job-control stop is orthogonal to scheduler state.
                    // Do NOT overwrite Blocked/Sleeping, or we lose the wait condition
                    // and break wait queue invariants (H-34 lost wakeup fix).
                    let was_running = proc.state == ProcessState::Running;
                    proc.stopped = true;
                    if was_running && process::current_pid() == Some(pid) {
                        needs_reschedule = true;
                    }
                }
                SignalAction::Continue => {
                    // R98-1 FIX: Handle SIGCONT via the scheduler resume callback.
                    // Check (but do not clear) `stopped`; resume_stopped() clears it
                    // atomically. Check BOTH the orthogonal flag and the legacy state.
                    if proc.stopped || proc.state == ProcessState::Stopped {
                        needs_resume = true;
                    }
                    proc.pending_signals.clear(signal);
                }
                SignalAction::Ignore => {
                    proc.pending_signals.clear(signal);
                }
            },
        }
    } // Release process lock before calling scheduler functions

    // H.0.7 FIX: Cross-CPU-safe fatal signal termination.
    //
    // send_signal_inner() may target a process running on another CPU (e.g. via
    // sys_kill() or namespace cascade). Calling terminate_process() directly on a
    // remote PID is the same cross-CPU UAF class as R115-1.
    //
    // - Self-termination (same CPU): terminate immediately, never return.
    // - Remote termination (different CPU): defer via request_process_exit();
    //   the target self-terminates at its next syscall return safe point.
    if let Some(code) = terminate_code {
        if process::current_pid() == Some(pid) {
            // Self: terminate directly (safe — we are on the target's CPU).
            // Drop the Arc before entering the no-return path to avoid a
            // permanent refcount leak (Codex review feedback).
            drop(process_arc);
            // R117-1 FIX: Use centralized terminate_self_and_halt() which
            // disables interrupts and switches to boot CR3 before halting.
            process::terminate_self_and_halt(pid, code);
        } else {
            // Remote: post a pending-kill flag; target checks at syscall return.
            let _ = process::request_process_exit(pid, code);
        }
    }

    // Resume stopped process - calls into scheduler to add to ready queue
    if needs_resume {
        // 通过回调调用调度器的 resume_stopped 函数
        if let Some(resume_fn) = get_resume_callback() {
            resume_fn(pid);
        }
    }

    // Trigger reschedule if needed
    if needs_reschedule {
        crate::scheduler_hook::force_reschedule();
    }

    // M0-5 sub-slice 1b: the EINTR-wake flipped a blocked target Ready on (typically) another
    // CPU. Broadcast a reschedule IPI so the queue-owning CPU re-selects it promptly rather
    // than only at its next timer tick. No-op until the scheduler registers the callback.
    if needs_kick {
        if let Some(kick) = get_kick_callback() {
            kick();
        }
    }

    Ok(action)
}

/// Check if process has any pending signals
pub fn has_pending_signals(pid: ProcessId) -> bool {
    if let Some(process_arc) = process::get_process(pid) {
        let proc = process_arc.lock();
        proc.pending_signals.has_pending()
    } else {
        false
    }
}

/// M0 item 5 (sub-slice 1a): pure self-test of the signal data model — the mask
/// read-modify-write (with SIGKILL/SIGSTOP force-strip) and the disposition resolver
/// (handler vs default vs ignored, plus the uncatchable defense-in-depth). Pure; any
/// failure panics (surfaced by the serial Test Summary). Registered in
/// `kernel/src/integration_test.rs`.
pub fn run_signal_self_test() {
    let kill_stop = uncatchable_mask();
    assert_eq!(
        kill_stop,
        (1u64 << 8) | (1u64 << 18),
        "uncatchable == SIGKILL|SIGSTOP"
    );

    // R172-21 (NO_FIX regression guard): SA_RESTART MUST remain ACCEPTED at install (it is a
    // documented M0 no-op, NOT EINVAL-rejected). glibc signal() installs handlers with
    // SA_RESTART by default and musl's pthread_cancel sets SA_RESTART|SA_SIGINFO and ignores
    // the rt_sigaction return value; removing SA_RESTART from SA_SUPPORTED_FLAGS would make
    // the unknown-flag reject fail EVERY libc handler install — strictly worse than the
    // honest no-op. This pins the invariant so a future refactor cannot "fix" R172-21 the
    // harmful way. (A real restart needs ERESTARTSYS + orig_rax + a restartability table +
    // zero-progress detection — out of M0 scope; see the doc at the SA_RESTART definition.)
    assert!(
        SA_SUPPORTED_FLAGS & SA_RESTART != 0,
        "R172-21: SA_RESTART must stay ACCEPTED (not EINVAL-rejected) — glibc/musl set it by default"
    );

    // apply_sigprocmask: BLOCK adds, always strips SIGKILL/SIGSTOP.
    let m = apply_sigprocmask(0, SIG_BLOCK, Signal::SIGUSR1.bit() | kill_stop);
    assert_eq!(
        m,
        Signal::SIGUSR1.bit(),
        "BLOCK adds; SIGKILL/SIGSTOP stripped"
    );
    // SETMASK replaces, strips uncatchable.
    let m = apply_sigprocmask(0xFFFF_FFFF, SIG_SETMASK, kill_stop | Signal::SIGTERM.bit());
    assert_eq!(
        m,
        Signal::SIGTERM.bit(),
        "SETMASK replaces; uncatchable stripped"
    );
    // UNBLOCK clears only the requested bit.
    let base = Signal::SIGUSR1.bit() | Signal::SIGUSR2.bit();
    let m = apply_sigprocmask(base, SIG_UNBLOCK, Signal::SIGUSR1.bit());
    assert_eq!(
        m,
        Signal::SIGUSR2.bit(),
        "UNBLOCK clears the requested bit only"
    );

    // resolve_disposition: default table => Default; handler => Handler; SIG_IGN =>
    // Ignored; SIGKILL/SIGSTOP => ALWAYS Default even with a (forbidden) handler.
    let mut table = default_sigactions();
    let u1 = (Signal::SIGUSR1.as_u8() - 1) as usize;
    let u2 = (Signal::SIGUSR2.as_u8() - 1) as usize;
    assert!(matches!(
        resolve_disposition(&table, Signal::SIGUSR1),
        Disposition::Default(SignalAction::Terminate)
    ));
    table[u1] = SigAction {
        handler: 0x40_0000,
        flags: SA_RESTORER,
        restorer: 0x40_1000,
        mask: 0,
    };
    assert!(matches!(
        resolve_disposition(&table, Signal::SIGUSR1),
        Disposition::Handler { .. }
    ));
    table[u2] = SigAction {
        handler: SIG_IGN,
        flags: 0,
        restorer: 0,
        mask: 0,
    };
    assert!(matches!(
        resolve_disposition(&table, Signal::SIGUSR2),
        Disposition::Ignored
    ));
    // Defense-in-depth: even a handler-looking SIGKILL entry resolves to Default.
    let k = (Signal::SIGKILL.as_u8() - 1) as usize;
    table[k] = SigAction {
        handler: 0x40_0000,
        flags: SA_RESTORER,
        restorer: 0x40_1000,
        mask: 0,
    };
    assert!(
        matches!(
            resolve_disposition(&table, Signal::SIGKILL),
            Disposition::Default(_)
        ),
        "SIGKILL is never handler-dispatched"
    );
    // default_sigactions is born clean.
    assert!(
        default_sigactions().iter().all(|s| !s.is_handler()),
        "default table is all SIG_DFL"
    );

    // M0-5 sub-slice 1b: signal_is_deliverable decision table. `table` has SIGUSR1=Handler,
    // SIGUSR2=SIG_IGN; `clean` is all-SIG_DFL. These rows are the build-time guard that the
    // EINTR-wake predicate stays Handler-only, uncatchable-masked, mask/in-handler-aware, and
    // lowest-bit-resolving (congruent with maybe_deliver_signal Phase-1).
    let clean = default_sigactions();
    let usr1 = Signal::SIGUSR1.bit();
    // (a) in_handler => defer (anti-spurious-EINTR).
    assert!(
        !signal_is_deliverable(usr1, 0, true, &table),
        "in_handler => defer"
    );
    // (b) nothing pending => false.
    assert!(
        !signal_is_deliverable(0, 0, false, &table),
        "no pending => false"
    );
    // (c) lowest deliverable Handler bit => true.
    assert!(
        signal_is_deliverable(usr1, 0, false, &table),
        "handler pending => true"
    );
    // (d) SIG_IGN => false.
    assert!(
        !signal_is_deliverable(Signal::SIGUSR2.bit(), 0, false, &table),
        "SIG_IGN => false"
    );
    // (e) Default(Terminate) SIGTERM => false (Handler-only scope; the KILL leg handles it).
    assert!(
        !signal_is_deliverable(Signal::SIGTERM.bit(), 0, false, &clean),
        "Default(Terminate) => false"
    );
    // (f) Default(Stop) SIGTSTP => false.
    assert!(
        !signal_is_deliverable(Signal::SIGTSTP.bit(), 0, false, &clean),
        "Default(Stop) => false"
    );
    // (g) Default(Continue) SIGCONT => false.
    assert!(
        !signal_is_deliverable(Signal::SIGCONT.bit(), 0, false, &clean),
        "Default(Continue) => false"
    );
    // (h) handler signal pending but BLOCKED => false.
    assert!(
        !signal_is_deliverable(usr1, usr1, false, &table),
        "blocked handler => false"
    );
    // (i) lowest-bit precedence: a LOWER default-terminate bit (SIGHUP=1) + a HIGHER handler
    //     bit (SIGUSR1) resolves the LOW bit (not Handler) => false. Proves the send-side wake
    //     and the wait-site epilogue agree on the lowest deliverable bit (no socket lost-wakeup).
    assert!(
        !signal_is_deliverable((1u64 << 0) | usr1, 0, false, &table),
        "lowest-bit precedence: low default bit wins => false"
    );
    // (j) a SIGKILL bit IS in pending&!blocked (send_signal sets it; SIGKILL is unblockable),
    //     but the uncatchable mask-out keeps it off the signal-EINTR leg.
    assert!(
        !signal_is_deliverable(Signal::SIGKILL.bit(), 0, false, &table),
        "SIGKILL masked out of the deliverable set"
    );

    // R172-P6-F1: pin the SHARED selector AND the intentional Site-A vs Site-B mask
    // divergence so a future re-fork fails the suite (the green musl boot can't catch it —
    // no-handler boot never runs either selector).
    // (k) empty set => None.
    assert!(
        select_lowest_deliverable(0).is_none(),
        "empty deliverable => None"
    );
    // (l) DIVERGENCE WITNESS — Site B's UNMASKED input: the production selector picks
    //     SIGKILL (the lowest bit), so maybe_deliver_signal routes it into the Default /
    //     terminate arm. This is the EXACT bit Site A masks out.
    assert_eq!(
        select_lowest_deliverable(Signal::SIGKILL.bit() | usr1),
        Some(Signal::SIGKILL),
        "Site-B (unmasked) selector picks the lone-lowest SIGKILL for the Default arm"
    );
    // (m) Site A's MASKED input: the predicate selector picks SIGUSR1, never SIGKILL —
    //     (l)+(m) together pin the intentional divergence (same primitive, deliberate masks).
    assert_eq!(
        select_lowest_deliverable((Signal::SIGKILL.bit() | usr1) & !uncatchable_mask()),
        Some(Signal::SIGUSR1),
        "Site-A (masked) selector skips SIGKILL and picks the catchable handler bit"
    );
    // (n) lowest-of-multiple catchable bits.
    assert_eq!(
        select_lowest_deliverable(Signal::SIGUSR2.bit() | usr1),
        Some(Signal::SIGUSR1),
        "lowest catchable bit wins"
    );
}

/// Get signal name for debugging
pub fn signal_name(signal: Signal) -> &'static str {
    match signal.as_u8() {
        1 => "SIGHUP",
        2 => "SIGINT",
        3 => "SIGQUIT",
        4 => "SIGILL",
        5 => "SIGTRAP",
        6 => "SIGABRT",
        7 => "SIGBUS",
        8 => "SIGFPE",
        9 => "SIGKILL",
        10 => "SIGUSR1",
        11 => "SIGSEGV",
        12 => "SIGUSR2",
        13 => "SIGPIPE",
        14 => "SIGALRM",
        15 => "SIGTERM",
        17 => "SIGCHLD",
        18 => "SIGCONT",
        19 => "SIGSTOP",
        20 => "SIGTSTP",
        21 => "SIGTTIN",
        22 => "SIGTTOU",
        _ => "SIG???",
    }
}
