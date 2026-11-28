//! Signal handling for Zero-OS
//!
//! Provides POSIX-like signal support including:
//! - Signal definitions (SIGKILL, SIGTERM, SIGSTOP, etc.)
//! - Pending signals bitmap per process
//! - Default signal actions
//! - Signal delivery mechanism

use crate::process::{self, ProcessArc, ProcessId, ProcessState};
use crate::syscall::SyscallError;
use crate::user_namespace::UserNamespace;
use alloc::sync::Arc;
use cap::CapRights;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::{Mutex, Once};

/// Maximum signal number supported (1-64)
const MAX_SIGNAL: u8 = 64;

// ============================================================================
// 调度器集成回调
// ============================================================================

/// RF178-36: Resume is identity-bound from authorization through scheduler
/// mutation. A reusable PID is never sufficient authority after the target PCB
/// lock has been released.
type ResumeCallback = fn(ProcessArc, ProcessId, u64) -> bool;

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
static KICK_CALLBACK: Once<KickCallback> = Once::new();

/// 注册重调度 kick 回调（调度器初始化时调用，注册广播 reschedule-IPI 的函数）。
pub fn register_kick_callback(callback: KickCallback) {
    KICK_CALLBACK.call_once(|| callback);
}

fn get_kick_callback() -> Option<KickCallback> {
    KICK_CALLBACK.get().copied()
}

/// RF178-35: lock-free post-publication wake used after every PCB/table guard
/// has been released. Returns false only before scheduler initialization.
pub(crate) fn kernel_kick_reschedule() -> bool {
    let Some(kick) = get_kick_callback() else {
        return false;
    };
    kick();
    true
}

/// C3 repair 3 (#90): the targeted form of [`kernel_kick_reschedule`] for a
/// wake that notifies. It sets `need_resched` here and on every CPU whose
/// queue the wake published for, and sends each of the others one IPI
/// (`wait_kick::kick_published`), instead of an IPI to every CPU. Called
/// after every PCB/table guard has been released, as the broadcast was.
pub(crate) fn kernel_kick_published() -> bool {
    crate::wait_kick::kick_published().is_some()
}

/// Resume one exact task identity after its caller has released the PCB lock.
/// The callback mutates the supplied resident PCB in place; it never re-resolves
/// `expected_pid`. A successful Ready transition is followed by a cross-CPU kick.
pub fn kernel_resume_stopped(
    proc_arc: ProcessArc,
    expected_pid: ProcessId,
    expected_generation: u64,
) -> bool {
    let resumed = get_resume_callback()
        .map(|resume| resume(proc_arc, expected_pid, expected_generation))
        .unwrap_or(false);
    if resumed {
        kernel_kick_published();
    }
    resumed
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

    /// First real-time signal number (Linux x86_64 `SIGRTMIN`).
    pub const SIGRTMIN: u8 = 32;
    /// Last real-time signal number (Linux x86_64 `SIGRTMAX`).
    pub const SIGRTMAX: u8 = 64;

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
    pub const fn as_u8(self) -> u8 {
        self.0
    }

    /// Get signal number as i32 (for syscall compatibility)
    #[inline]
    pub const fn as_i32(self) -> i32 {
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

    /// Check if this is a POSIX real-time queued signal (32..=64).
    #[inline]
    pub fn is_realtime(self) -> bool {
        self.0 >= Self::SIGRTMIN
    }
}

// ============================================================================
// N2.6a: Real-time signal metadata (`SigInfo`), bounded FIFO queue, and
// alternate signal stack (`SigAltStack`)
// ============================================================================

/// Linux x86_64 `siginfo_t.si_code` values (`uapi/asm-generic/siginfo.h`).
pub const SI_USER: i32 = 0;
pub const SI_QUEUE: i32 = -1;
pub const SI_TIMER: i32 = -2;
pub const SI_TKILL: i32 = -6;
pub const SI_KERNEL: i32 = 0x80;

/// Linux x86_64 `stack_t.ss_flags` values (`uapi/asm-generic/signal.h`).
pub const SS_ONSTACK: u32 = 1;
pub const SS_DISABLE: u32 = 2;
pub const SS_AUTODISARM: u32 = 1 << 31;
/// Minimum alternate signal stack size (Linux x86_64 `MINSIGSTKSZ`).
pub const MINSIGSTKSZ: usize = 2048;

/// Bounded per-task and per-group real-time signal queue capacity
/// (matches POSIX `_POSIX_SIGQUEUE_MAX = 32`, zero heap allocation on delivery).
pub const MAX_QUEUED_RT_SIGNALS: usize = 32;

/// Compact kernel representation of a signal's `siginfo_t` payload.
/// `signo == 0` marks an empty slot in [`RtSigQueue`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SigInfo {
    pub signo: i32,
    pub errno: i32,
    pub code: i32,
    pub pid: i32,
    pub uid: u32,
    pub value: u64,
}

impl SigInfo {
    /// Empty sentinel slot.
    pub const EMPTY: Self = Self {
        signo: 0,
        errno: 0,
        code: 0,
        pid: 0,
        uid: 0,
        value: 0,
    };

    /// Minimal `SI_USER` metadata for a signal with no explicitly queued payload.
    #[inline]
    pub const fn default_for(signal: Signal) -> Self {
        Self {
            signo: signal.0 as i32,
            errno: 0,
            code: SI_USER,
            pid: 0,
            uid: 0,
            value: 0,
        }
    }

    /// Minimal `SI_USER` metadata for a raw signal number.
    #[inline]
    pub const fn default_for_raw(signum: u32) -> Self {
        Self {
            signo: signum as i32,
            errno: 0,
            code: SI_USER,
            pid: 0,
            uid: 0,
            value: 0,
        }
    }

    /// Construct metadata for a `kill`/`tkill`/`tgkill` or kernel-originated signal.
    #[inline]
    pub const fn from_sender(signal: Signal, code: i32, pid: i32, uid: u32) -> Self {
        Self {
            signo: signal.0 as i32,
            errno: 0,
            code,
            pid,
            uid,
            value: 0,
        }
    }

    /// Serialize into a 128-byte Linux x86_64 `siginfo_t` wire buffer.
    /// Zero-fills the entire buffer so no kernel stack residue can leak.
    pub fn write_wire_bytes(&self, out: &mut [u8; 128]) {
        out.fill(0);
        out[0..4].copy_from_slice(&self.signo.to_ne_bytes());
        out[4..8].copy_from_slice(&self.errno.to_ne_bytes());
        out[8..12].copy_from_slice(&self.code.to_ne_bytes());
        // Bytes 12..16: 4-byte alignment pad before `_sifields` on x86_64.
        out[16..20].copy_from_slice(&self.pid.to_ne_bytes());
        out[20..24].copy_from_slice(&self.uid.to_ne_bytes());
        out[24..32].copy_from_slice(&self.value.to_ne_bytes());
    }

    /// Parse a user-supplied 128-byte `siginfo_t` wire buffer for
    /// `rt_sigqueueinfo` / `rt_tgsigqueueinfo`, overriding `si_signo` with `sig`.
    pub fn from_wire_bytes(sig: i32, bytes: &[u8; 128]) -> Self {
        let rd_i32 =
            |o: usize| i32::from_ne_bytes([bytes[o], bytes[o + 1], bytes[o + 2], bytes[o + 3]]);
        let rd_u32 =
            |o: usize| u32::from_ne_bytes([bytes[o], bytes[o + 1], bytes[o + 2], bytes[o + 3]]);
        let rd_u64 = |o: usize| {
            u64::from_ne_bytes([
                bytes[o],
                bytes[o + 1],
                bytes[o + 2],
                bytes[o + 3],
                bytes[o + 4],
                bytes[o + 5],
                bytes[o + 6],
                bytes[o + 7],
            ])
        };
        Self {
            signo: sig,
            errno: rd_i32(4),
            code: rd_i32(8),
            pid: rd_i32(16),
            uid: rd_u32(20),
            value: rd_u64(24),
        }
    }
}

const RT_SIGQUEUE_OVERFLOW_CAP: usize = MAX_QUEUED_RT_SIGNALS - 1;

/// Lazy overflow storage for queued signals beyond the 1 inline slot.
/// Allocated fallibly via `Box::try_new` only when a process actually queues
/// 2..=32 simultaneous signals, keeping `Process` and `ThreadGroup` compact.
#[derive(Debug, Clone)]
struct RtSigQueueOverflow {
    entries: [SigInfo; RT_SIGQUEUE_OVERFLOW_CAP],
    len: usize,
}

impl RtSigQueueOverflow {
    const fn new() -> Self {
        Self {
            entries: [SigInfo::EMPTY; RT_SIGQUEUE_OVERFLOW_CAP],
            len: 0,
        }
    }
}

/// Compact bounded FIFO queue of pending signal payloads (40 bytes inline).
///
/// Stores the first pending payload inline (zero heap allocation for normal
/// single-signal delivery and IRQ claims) and lazily allocates a bounded
/// fallible overflow slab (`Box::try_new`) only when 2..=[`MAX_QUEUED_RT_SIGNALS`]
/// signals are simultaneously queued.
#[derive(Debug)]
pub struct RtSigQueue {
    first: SigInfo,
    overflow: Option<alloc::boxed::Box<RtSigQueueOverflow>>,
}

const _: () = assert!(
    core::mem::size_of::<RtSigQueue>() <= 48,
    "RtSigQueue must stay compact inside Process/ThreadGroup to preserve PCB heap admission budgets"
);

impl RtSigQueue {
    pub const fn new() -> Self {
        Self {
            first: SigInfo::EMPTY,
            overflow: None,
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        if self.first.signo == 0 {
            0
        } else {
            1 + self.overflow.as_ref().map_or(0, |o| o.len)
        }
    }

    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.first.signo == 0
    }

    /// Append `info` in FIFO order. Returns `Err(())` if the bounded queue is
    /// full or if fallible overflow allocation fails (OOM).
    pub fn push(&mut self, info: SigInfo) -> Result<(), ()> {
        if self.first.signo == 0 {
            self.first = info;
            return Ok(());
        }
        if self.overflow.is_none() {
            let slab = alloc::boxed::Box::try_new(RtSigQueueOverflow::new()).map_err(|_| ())?;
            self.overflow = Some(slab);
        }
        let ov = self.overflow.as_mut().unwrap();
        if ov.len >= RT_SIGQUEUE_OVERFLOW_CAP {
            return Err(());
        }
        ov.entries[ov.len] = info;
        ov.len += 1;
        Ok(())
    }

    /// Append `info` in FIFO order without allocating (IRQ-safe: uses the inline
    /// slot or an already-allocated overflow slab, returning `Err(())` otherwise).
    pub fn push_no_alloc(&mut self, info: SigInfo) -> Result<(), ()> {
        if self.first.signo == 0 {
            self.first = info;
            return Ok(());
        }
        let Some(ov) = self.overflow.as_mut() else {
            return Err(());
        };
        if ov.len >= RT_SIGQUEUE_OVERFLOW_CAP {
            return Err(());
        }
        ov.entries[ov.len] = info;
        ov.len += 1;
        Ok(())
    }

    /// Return the oldest queued payload for `signal` without removing it.
    pub fn peek(&self, signal: Signal) -> Option<SigInfo> {
        let target = signal.as_i32();
        if self.first.signo == 0 {
            return None;
        }
        if self.first.signo == target {
            return Some(self.first);
        }
        self.overflow
            .as_ref()?
            .entries
            .iter()
            .take(self.overflow.as_ref()?.len)
            .copied()
            .find(|e| e.signo == target)
    }

    /// Remove and return the oldest queued payload for `signal`, preserving FIFO
    /// order of all remaining entries.
    pub fn pop(&mut self, signal: Signal) -> Option<SigInfo> {
        let target = signal.as_i32();
        if self.first.signo == 0 {
            return None;
        }
        if self.first.signo == target {
            let item = self.first;
            if let Some(ov) = self.overflow.as_mut() {
                if ov.len > 0 {
                    self.first = ov.entries[0];
                    let mut i = 0usize;
                    while i + 1 < ov.len {
                        ov.entries[i] = ov.entries[i + 1];
                        i += 1;
                    }
                    ov.len -= 1;
                    ov.entries[ov.len] = SigInfo::EMPTY;
                    return Some(item);
                }
            }
            self.first = SigInfo::EMPTY;
            return Some(item);
        }
        let ov = self.overflow.as_mut()?;
        let pos = ov.entries[..ov.len]
            .iter()
            .position(|e| e.signo == target)?;
        let item = ov.entries[pos];
        let mut i = pos;
        while i + 1 < ov.len {
            ov.entries[i] = ov.entries[i + 1];
            i += 1;
        }
        ov.len -= 1;
        ov.entries[ov.len] = SigInfo::EMPTY;
        Some(item)
    }

    /// True if at least one entry for `signal` remains queued.
    pub fn has_signal(&self, signal: Signal) -> bool {
        let target = signal.as_i32();
        if self.first.signo == 0 {
            return false;
        }
        if self.first.signo == target {
            return true;
        }
        self.overflow
            .as_ref()
            .is_some_and(|ov| ov.entries[..ov.len].iter().any(|e| e.signo == target))
    }

    /// Remove all queued entries for `signal`.
    pub fn remove_all(&mut self, signal: Signal) {
        let target = signal.as_i32();
        if self.first.signo == 0 {
            return;
        }
        if let Some(ov) = self.overflow.as_mut() {
            let mut write = 0usize;
            for read in 0..ov.len {
                if ov.entries[read].signo != target {
                    ov.entries[write] = ov.entries[read];
                    write += 1;
                }
            }
            for i in write..ov.len {
                ov.entries[i] = SigInfo::EMPTY;
            }
            ov.len = write;
        }
        if self.first.signo == target {
            if let Some(ov) = self.overflow.as_mut() {
                if ov.len > 0 {
                    self.first = ov.entries[0];
                    let mut i = 0usize;
                    while i + 1 < ov.len {
                        ov.entries[i] = ov.entries[i + 1];
                        i += 1;
                    }
                    ov.len -= 1;
                    ov.entries[ov.len] = SigInfo::EMPTY;
                } else {
                    self.first = SigInfo::EMPTY;
                }
            } else {
                self.first = SigInfo::EMPTY;
            }
        }
        if self.overflow.as_ref().is_some_and(|ov| ov.len == 0) {
            self.overflow = None;
        }
    }

    /// Move every entry whose signal bit is set in `mask` into `dst` (best-effort
    /// if `dst` is full, preserving bitmap visibility via returned mask).
    pub fn drain_mask_into(&mut self, mask: u64, dst: &mut RtSigQueue) {
        if mask == 0 || self.first.signo == 0 {
            return;
        }
        let matches_mask =
            |entry: SigInfo| Signal::from_raw(entry.signo).is_ok_and(|s| (mask & s.bit()) != 0);
        let first_matched = matches_mask(self.first);
        if first_matched {
            let _ = dst.push(self.first);
            self.first = SigInfo::EMPTY;
        }
        if let Some(ov) = self.overflow.as_mut() {
            let mut write = 0usize;
            for read in 0..ov.len {
                let entry = ov.entries[read];
                if matches_mask(entry) {
                    let _ = dst.push(entry);
                } else if self.first.signo == 0 {
                    self.first = entry;
                } else {
                    ov.entries[write] = entry;
                    write += 1;
                }
            }
            for i in write..ov.len {
                ov.entries[i] = SigInfo::EMPTY;
            }
            ov.len = write;
        }
        if self.overflow.as_ref().is_some_and(|ov| ov.len == 0) {
            self.overflow = None;
        }
    }

    pub fn clear(&mut self) {
        self.first = SigInfo::EMPTY;
        self.overflow = None;
    }
}

impl Default for RtSigQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-task alternate signal stack configuration (`sigaltstack(2)`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SigAltStack {
    pub sp: u64,
    pub size: u64,
    /// `SS_DISABLE` when disabled, `0` (or `SS_AUTODISARM`) when enabled.
    pub flags: u32,
}

impl SigAltStack {
    pub const fn disabled() -> Self {
        Self {
            sp: 0,
            size: 0,
            flags: SS_DISABLE,
        }
    }

    #[inline]
    pub const fn is_enabled(self) -> bool {
        (self.flags & SS_DISABLE) == 0 && self.size >= MINSIGSTKSZ as u64 && self.sp != 0
    }

    /// True if `rsp` currently lies inside the active alternate signal stack.
    /// Matches Linux `on_sig_stack(sp)`: `sp > ss_sp && sp - ss_sp <= ss_size`.
    #[inline]
    pub const fn on_stack(self, rsp: u64) -> bool {
        self.is_enabled() && rsp > self.sp && rsp.saturating_sub(self.sp) <= self.size
    }

    /// Exclusive top VA of the alternate signal stack (`sp + size`).
    #[inline]
    pub const fn top(self) -> Option<u64> {
        if self.is_enabled() {
            self.sp.checked_add(self.size)
        } else {
            None
        }
    }

    /// Format `(ss_sp, ss_flags, ss_size)` for `old_ss` or `ucontext.uc_stack`.
    #[inline]
    pub const fn as_stack_t_fields(self, current_rsp: u64) -> (u64, u32, u64) {
        if !self.is_enabled() {
            (0, SS_DISABLE, 0)
        } else if self.on_stack(current_rsp) {
            (self.sp, SS_ONSTACK, self.size)
        } else {
            (self.sp, 0, self.size)
        }
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

    /// GAP-5 exec step 2: take over another task's set (`bits` comes from
    /// that task's own `PendingSignals`).
    #[inline]
    pub(crate) fn replace_bits(&mut self, bits: u64) {
        self.bits = bits;
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

/// GAP-5 slice 1: the signal-disposition table as an explicit shared handle.
///
/// `fork` gives the child a private table whose contents are copied from the
/// parent; `clone(CLONE_SIGHAND)` shares the parent's `Arc`. Only dispositions
/// are shared: blocked masks, pending sets, handler scratch state, robust lists
/// and clear-tid stay per task in `Process`.
///
/// Lock contract: `actions` is a LEAF lock ordered after the owning PCB lock
/// (PCB -> SignalTable); nothing is acquired while it is held. Process context
/// uses `lock()`; IRQ-return delivery uses only `try_lock()` and defers on
/// contention, so the lock needs no IRQ masking (an IRQ that interrupts a
/// same-CPU holder fails its try-lock instead of spinning).
#[derive(Debug)]
pub struct SignalTable {
    actions: Mutex<[SigAction; NSIG]>,
    /// Bumped on every disposition mutation (rt_sigaction, exec reset,
    /// SA_RESETHAND). Diagnostic/revalidation aid; not a lock.
    generation: AtomicU64,
}

impl SignalTable {
    pub const fn new() -> Self {
        Self {
            actions: Mutex::new([SigAction::default_action(); NSIG]),
            generation: AtomicU64::new(0),
        }
    }

    /// Issue #109 §3.1: Out-of-line fallible heap constructor so the 2 KiB
    /// `[SigAction; NSIG]` staging buffer does not inflate `Process::try_new_pcb`'s
    /// stack frame.
    #[inline(never)]
    pub fn try_new_arc() -> Result<alloc::sync::Arc<Self>, alloc::alloc::AllocError> {
        alloc::sync::Arc::try_new(Self::new())
    }

    /// Process-context lock. Callers may hold their own PCB lock.
    #[inline]
    pub fn lock(&self) -> spin::MutexGuard<'_, [SigAction; NSIG]> {
        self.actions.lock()
    }

    /// IRQ-context lock attempt. `None` means defer to a later safe point.
    #[inline]
    pub fn try_lock(&self) -> Option<spin::MutexGuard<'_, [SigAction; NSIG]>> {
        self.actions.try_lock()
    }

    /// IRQ-context snapshot. `None` means defer to a later safe point.
    #[inline]
    pub fn try_snapshot(&self) -> Option<[SigAction; NSIG]> {
        self.actions.try_lock().map(|actions| *actions)
    }

    #[inline]
    pub fn get(&self, index: usize) -> SigAction {
        self.lock()[index]
    }

    /// Install `action` at `index`, returning the previous disposition.
    pub fn replace(&self, index: usize, action: SigAction) -> SigAction {
        let mut actions = self.lock();
        let old = core::mem::replace(&mut actions[index], action);
        self.note_mutation();
        old
    }

    /// SA_RESETHAND commit: reset `index` to SIG_DFL only if it still holds
    /// `expected`, so a sibling's concurrent rt_sigaction is never overwritten.
    /// Returns whether the reset happened.
    pub fn reset_if_unchanged(&self, index: usize, expected: SigAction) -> bool {
        let mut actions = self.lock();
        if actions[index] != expected {
            return false;
        }
        actions[index] = SigAction::default_action();
        drop(actions);
        self.note_mutation();
        true
    }

    /// Copy another table's dispositions into this private table (fork).
    pub fn copy_from(&self, source: &SignalTable) {
        if core::ptr::eq(self, source) {
            return;
        }
        let snapshot = *source.lock();
        *self.lock() = snapshot;
        self.note_mutation();
    }

    /// Overwrite this table with a previously captured snapshot.
    pub fn store_all(&self, snapshot: &[SigAction; NSIG]) {
        *self.lock() = *snapshot;
        self.note_mutation();
    }

    #[inline]
    pub fn note_mutation(&self) {
        // Diagnostic mutation counter, never an identity. lint-fetch-add: allow
        self.generation.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Relaxed)
    }
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

/// Monotonic hint for handler-frame preparation only. Default-signal delivery
/// and temporary-mask restoration must never be skipped based on this hint.
static ANY_HANDLER_INSTALLED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Record that a real handler was installed (called from `rt_sigaction`).
#[inline]
pub fn note_handler_installed() {
    ANY_HANDLER_INSTALLED.store(true, core::sync::atomic::Ordering::Relaxed);
}

/// Lock-free hint for handler-frame preparation only.
#[inline]
pub fn any_handler_installed() -> bool {
    ANY_HANDLER_INSTALLED.load(core::sync::atomic::Ordering::Relaxed)
}

#[derive(Clone, Copy)]
pub(crate) enum DeliveryMode {
    HandlerOnly,
    AnyActionable,
}

/// Select real work without allowing an inert low bit to starve another signal.
/// Callers supply a coherent PCB-locked snapshot. Handler recursion is deferred;
/// an unblocked default terminate/stop remains actionable during a handler.
pub(crate) fn select_for_delivery(
    pending: u64,
    blocked: u64,
    in_handler: bool,
    sigactions: &[SigAction; NSIG],
    mode: DeliveryMode,
) -> Option<Signal> {
    let mut candidates = pending & !(blocked & !uncatchable_mask());
    while let Some(signal) = select_lowest_deliverable(candidates) {
        candidates &= !signal.bit();
        match resolve_disposition(sigactions, signal) {
            Disposition::Handler { .. } if !in_handler => return Some(signal),
            Disposition::Default(SignalAction::Terminate | SignalAction::Stop)
                if matches!(mode, DeliveryMode::AnyActionable) =>
            {
                return Some(signal)
            }
            _ => {}
        }
    }
    None
}

/// Revalidate a previously selected default at the PCB-locked commit point.
/// A concurrent SIGCONT can have cancelled a pending stop since selection.
pub(crate) fn pending_default_action(
    pending: u64,
    blocked: u64,
    sigactions: &[SigAction; NSIG],
    signal: Signal,
) -> Option<SignalAction> {
    if pending & signal.bit() == 0 || blocked & signal.bit() & !uncatchable_mask() != 0 {
        return None;
    }
    match resolve_disposition(sigactions, signal) {
        Disposition::Default(action) => Some(action),
        _ => None,
    }
}

pub(crate) fn discard_inert_pending(proc: &mut process::Process) {
    let mut candidates = proc.pending_bits() & !proc.blocked;
    while let Some(signal) = select_lowest_deliverable(candidates) {
        candidates &= !signal.bit();
        if matches!(
            resolve_disposition(&proc.sigactions.lock(), signal),
            Disposition::Ignored
                | Disposition::Default(SignalAction::Ignore | SignalAction::Continue)
        ) {
            proc.discard_pending(signal);
        }
    }
}

#[cfg(test)]
mod delivery_tests {
    use super::*;

    #[test]
    fn audit_20261031_pid_ancestry_alone_is_not_signal_authority() {
        assert!(!namespace_init_authorized(
            false, false, true, false, false, false, false
        ));
        assert!(!namespace_init_authorized(
            false, false, true, true, false, false, false
        ));
        assert!(namespace_init_authorized(
            false, false, true, true, true, false, false
        ));
        assert!(namespace_init_authorized(
            false, false, true, false, false, true, false
        ));
    }

    #[cfg(feature = "host_harness")]
    #[test]
    fn namespace_init_uses_owning_namespace_not_root_visibility() {
        use crate::pid_namespace::{
            assign_pid_chain, detach_pid_chain, PidNamespace, ROOT_PID_NAMESPACE,
        };
        let root = ROOT_PID_NAMESPACE.clone();
        let target = PidNamespace::new_child(root.clone()).unwrap();
        let sibling = PidNamespace::new_child(root.clone()).unwrap();
        let descendant = PidNamespace::new_child(target.clone()).unwrap();
        let cases = [
            (target.clone(), true, false),
            (sibling, false, false),
            (descendant, false, false),
            (root.clone(), false, true),
        ];
        for (index, (owning, same, ancestor)) in cases.into_iter().enumerate() {
            let pid = 24000 + index;
            let chain = assign_pid_chain(owning, pid).unwrap();
            assert!(Arc::ptr_eq(&chain[0].ns, &root));
            let relationship = pid_namespace_signal_relationship(&chain, &target);
            assert_eq!(relationship, (same, ancestor));
            assert_eq!(
                namespace_init_authorized(
                    false,
                    relationship.0,
                    relationship.1,
                    false,
                    false,
                    false,
                    ancestor
                ),
                ancestor
            );
            assert!(!pid_namespace_signal_relationship(&chain, &root).1);
            detach_pid_chain(&chain, pid);
        }
        assert_eq!(
            pid_namespace_signal_relationship(&[], &target),
            (false, false)
        );
        assert!(!namespace_init_authorized(
            false, false, false, false, false, false, false
        ));
        // Self and explicitly delegated ancestor-user supervision remain valid.
        assert!(namespace_init_authorized(
            true, true, false, false, false, false, false
        ));
        assert!(namespace_init_authorized(
            false, true, false, true, true, false, false
        ));
        assert!(!namespace_init_authorized(
            false, true, false, false, true, false, false
        ));
    }

    #[test]
    fn blocked_defaults_wait_until_unmask_without_any_handler() {
        let actions = default_sigactions();
        for sig in [Signal::SIGTERM, Signal::SIGTSTP] {
            assert_eq!(
                select_for_delivery(
                    sig.bit(),
                    sig.bit(),
                    false,
                    &actions,
                    DeliveryMode::AnyActionable
                ),
                None
            );
            assert_eq!(
                select_for_delivery(sig.bit(), 0, false, &actions, DeliveryMode::AnyActionable),
                Some(sig)
            );
        }
        assert_eq!(
            apply_sigprocmask(0, SIG_BLOCK, u64::MAX) & uncatchable_mask(),
            0
        );
    }

    #[test]
    fn ignored_and_default_bits_do_not_starve_irq_handlers() {
        let mut actions = default_sigactions();
        actions[0].handler = SIG_IGN;
        actions[(Signal::SIGUSR1.as_u8() - 1) as usize].handler = 0x400000;
        let pending = Signal::SIGHUP.bit() | Signal::SIGUSR1.bit() | Signal::SIGKILL.bit();
        assert_eq!(
            select_for_delivery(pending, 0, false, &actions, DeliveryMode::HandlerOnly),
            Some(Signal::SIGUSR1)
        );
    }

    #[test]
    fn live_handler_defers_caught_signal_but_not_unblocked_default() {
        let mut actions = default_sigactions();
        actions[(Signal::SIGUSR1.as_u8() - 1) as usize].handler = 0x400000;
        let pending = Signal::SIGUSR1.bit() | Signal::SIGTERM.bit();
        assert_eq!(
            select_for_delivery(pending, 0, true, &actions, DeliveryMode::AnyActionable),
            Some(Signal::SIGTERM)
        );
        assert_eq!(
            select_for_delivery(
                pending,
                Signal::SIGTERM.bit(),
                true,
                &actions,
                DeliveryMode::AnyActionable
            ),
            None
        );
    }

    #[test]
    fn cancelled_or_remasked_stop_is_rejected_at_commit() {
        let actions = default_sigactions();
        let stop = Signal::SIGTSTP;
        assert_eq!(
            pending_default_action(stop.bit(), 0, &actions, stop),
            Some(SignalAction::Stop)
        );
        assert_eq!(pending_default_action(0, 0, &actions, stop), None);
        assert_eq!(
            pending_default_action(stop.bit(), stop.bit(), &actions, stop),
            None
        );
    }
}

/// A blocked syscall must unwind for caught signals or catchable default
/// terminate/stop actions. Uncatchables retain their dedicated kill/stop path.
/// An inert low bit cannot hide later actionable work.
fn signal_is_deliverable(
    pending: u64,
    blocked: u64,
    in_handler: bool,
    sigactions: &[SigAction; NSIG],
) -> bool {
    select_for_delivery(
        pending & !uncatchable_mask(),
        blocked,
        in_handler,
        sigactions,
        DeliveryMode::AnyActionable,
    )
    .is_some()
}

/// Does this task have an actionable catchable signal that should unwind a
/// blocking syscall? Includes defaults and caught handlers; snapshots the PCB.
///
/// # Lock Contract (R177-D4)
///
/// **Use this variant when the Process lock is NOT held by the caller.**
///
/// This function internally acquires the Process lock via `get_process(pid).lock()`.
/// If called while already holding the Process lock for `pid`, it will **deadlock** (same-thread
/// re-entry of a non-reentrant lock).
///
/// **When you already hold `&Process` or `&mut Process`:** Use [`has_deliverable_signal_locked`]
/// instead to avoid the re-lock. Common scenarios:
/// - ppoll/pselect6 sigmask restore (syscall.rs:18623) — already holds proc guard for sigmask stash
/// - should_abort_pending_block callsites — already inside the Blocked-commit critical section
/// - Signal delivery epilogues — guard held to update in_signal_handler / blocked / pending
///
/// See [`has_deliverable_signal_locked`] for the lock-free variant when the guard is already held.
///
/// GAP-5 G7 (review D3): this is the wait-abort check, so group signals count
/// only for the member chosen for them (`wait_pending_bits`); the others would
/// return a spurious EINTR for a signal another member takes.
pub fn has_deliverable_signal(pid: ProcessId) -> bool {
    let arc = match process::get_process(pid) {
        Some(a) => a,
        None => return false,
    };
    let proc = arc.lock();
    let actions = proc.sigactions.lock();
    signal_is_deliverable(
        proc.wait_pending_bits(),
        proc.blocked,
        proc.in_signal_handler,
        &actions,
    )
}

/// Check actionable catchable signals through an already-held PCB guard.
/// Only the `SignalTable` leaf lock is taken. Defaults remain actionable during a handler;
/// caught signals follow the existing no-nested-handler-frame policy.
///
/// # Lock Contract (R177-D4)
///
/// **Use this variant when the Process lock IS already held by the caller.**
///
/// This function does NOT acquire the Process lock — it reads signal state directly from the
/// provided `&Process` guard. Its only acquisition is the `SignalTable` leaf lock (GAP-5), taken
/// briefly for the disposition snapshot; the order is always PCB -> SignalTable. The caller MUST
/// hold the Process lock for the task being checked, and that lock MUST cover the entire read of
/// `pending_signals`, `blocked` and `in_signal_handler` to ensure a consistent snapshot.
///
/// **When you do NOT hold `&Process`:** Use [`has_deliverable_signal`] instead, which acquires
/// the lock internally. Calling this function without holding the lock is a **data race** (reads
/// mutable Process fields without synchronization).
///
/// # Example (from ppoll sigmask restore, syscall.rs:18623)
///
/// ```ignore
/// let mut proc = process_arc.lock();  // Acquire Process lock
/// if has_deliverable_signal_locked(&proc) {  // No re-lock — reads from held guard
///     // ... EINTR path
/// }
/// ```
///
/// See [`has_deliverable_signal`] for the self-locking variant when no guard is held.
pub fn has_deliverable_signal_locked(proc: &crate::process::Process) -> bool {
    signal_is_deliverable(
        proc.pending_bits(),
        proc.blocked,
        proc.in_signal_handler,
        &proc.sigactions.lock(),
    )
}

/// M0-5 sub-slice 1b: should a task ABOUT to publish Blocked bail instead? True if a kill is
/// pending OR a deliverable handler signal exists. Called UNDER the proc lock at the
/// Blocked-commit point (where the wakers also take the lock) to close the lost-wakeup window
/// between a top-of-wait bail and publishing Blocked — a window in which the bare
/// state-flip wake (which fires only on state==Blocked) would otherwise be missed, stranding
/// the task indefinitely (signals, unlike kills, have no deferred-kill-cascade backstop).
/// Takes `&Process` so the caller can re-use its already-held guard (no re-lock / deadlock).
///
/// GAP-5 exec step 2 (review F1): it also reports an exec handed to this
/// leader, matching `wait_should_abort`. A publish that lands between a wait's
/// loop-top check and this commit-time check does not wake a running leader,
/// so without it the leader could commit `Blocked` and hold up the exec.
pub fn should_abort_pending_block(proc: &crate::process::Process) -> bool {
    proc.pending_kill
        .load(core::sync::atomic::Ordering::Acquire)
        || proc.exec_handoff.is_some()
        || signal_is_deliverable(
            proc.wait_pending_bits(),
            proc.blocked,
            proc.in_signal_handler,
            &proc.sigactions.lock(),
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
    /// A credential writer has closed reader admission; caller may retry.
    CredentialBusy,
    /// Bounded real-time signal queue is full (`EAGAIN`).
    QueueFull,
}

impl From<SignalError> for SyscallError {
    fn from(err: SignalError) -> Self {
        match err {
            SignalError::InvalidSignal => SyscallError::EINVAL,
            SignalError::NoSuchProcess => SyscallError::ESRCH,
            SignalError::PermissionDenied => SyscallError::EPERM,
            SignalError::CredentialBusy => SyscallError::EAGAIN,
            SignalError::QueueFull => SyscallError::EAGAIN,
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
    // GAP-5 slice 4 G7: kill() is process-directed; a thread group picks the
    // member that will take it. Single-task processes are unaffected.
    send_process_signal(pid, signal, true, None, false)
}

/// N2.6a: process-directed `rt_sigqueueinfo(2)` with explicit `SigInfo` payload.
/// Fails with `SignalError::QueueFull` (`EAGAIN`) if the bounded RT queue is full.
pub fn send_signal_queueinfo(
    pid: ProcessId,
    signal: Signal,
    info: SigInfo,
) -> Result<SignalAction, SignalError> {
    send_process_signal(pid, signal, true, Some(info), true)
}

/// GAP-5 G7 (review D3): the member is chosen without its lock, so it can
/// exit before the signal is queued. Choose again rather than report ESRCH for
/// a live process (a chosen member that is gone makes the next choice skip it).
fn send_process_signal(
    pid: ProcessId,
    signal: Signal,
    enforce_permissions: bool,
    info: Option<SigInfo>,
    fail_on_queue_full: bool,
) -> Result<SignalAction, SignalError> {
    const ATTEMPTS: usize = 4;
    let mut last = Err(SignalError::NoSuchProcess);
    for _ in 0..ATTEMPTS {
        let target = process::select_process_directed_target(pid, signal.bit());
        last = send_signal_inner(
            target,
            signal,
            enforce_permissions,
            SignalScope::Process,
            info,
            fail_on_queue_full,
        );
        if last != Err(SignalError::NoSuchProcess) || target == pid {
            return last;
        }
    }
    last
}

/// GAP-5 slice 4 G7: thread-directed delivery (`tkill`, `tgkill`) to exactly
/// `tid`, with the same POSIX permission checks as `send_signal`. Fatal and
/// job-control defaults still act on the whole group.
pub fn send_signal_thread(tid: ProcessId, signal: Signal) -> Result<SignalAction, SignalError> {
    send_signal_inner(tid, signal, true, SignalScope::Thread, None, false)
}

/// N2.6a: thread-directed `rt_tgsigqueueinfo(2)` with explicit `SigInfo` payload.
/// Fails with `SignalError::QueueFull` (`EAGAIN`) if the bounded RT queue is full.
pub fn send_signal_tgsigqueueinfo(
    tid: ProcessId,
    signal: Signal,
    info: SigInfo,
) -> Result<SignalAction, SignalError> {
    send_signal_inner(tid, signal, true, SignalScope::Thread, Some(info), true)
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
    send_process_signal(pid, signal, false, None, false)
}

/// N2.6b: Kernel-authoritative process-directed signal with explicit `SigInfo`
/// (e.g. `ITIMER_REAL` / POSIX `timer_create(SIGEV_SIGNAL)` with `SI_TIMER`).
pub fn send_signal_kernel_with_info(
    pid: ProcessId,
    signal: Signal,
    info: SigInfo,
) -> Result<SignalAction, SignalError> {
    send_process_signal(pid, signal, false, Some(info), false)
}

/// N2.6b: Kernel-authoritative thread-directed signal with explicit `SigInfo`
/// (e.g. POSIX `timer_create(SIGEV_THREAD_ID)` with `SI_TIMER`).
pub fn send_signal_kernel_thread_with_info(
    tid: ProcessId,
    signal: Signal,
    info: SigInfo,
) -> Result<SignalAction, SignalError> {
    send_signal_inner(tid, signal, false, SignalScope::Thread, Some(info), false)
}

/// GAP-5 G7: where a generated signal is queued.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SignalScope {
    /// Process-directed: the thread group's shared set; any member may take it.
    Process,
    /// Thread-directed (`tkill`, `tgkill`): the target task's own set.
    Thread,
}

// R188-U09-3 FIX: User-authorized signal paths require an authenticated current
// task.  Keep the conversion in a pure helper so the fail-closed contract is
// regression-tested without manufacturing a live process-table entry.
#[inline]
fn require_signal_sender_pid(current: Option<ProcessId>) -> Result<ProcessId, SignalError> {
    current.ok_or(SignalError::NoSuchProcess)
}

/// Check whether `sender`'s user namespace is a strict ancestor of `target`'s.
/// User namespace depth is bounded by `MAX_USER_NS_LEVEL`; the bound also makes
/// this helper robust against a corrupted parent cycle.
pub(crate) fn user_namespace_is_strict_ancestor(
    sender: &Arc<UserNamespace>,
    target: &Arc<UserNamespace>,
) -> bool {
    let mut cursor = target.parent();
    for _ in 0..=crate::user_namespace::MAX_USER_NS_LEVEL {
        let Some(namespace) = cursor else {
            break;
        };
        if Arc::ptr_eq(sender, &namespace) {
            return true;
        }
        cursor = namespace.parent();
    }
    false
}

/// Visibility in an ancestor namespace is not supervisor authority: every
/// PID chain contains the root. Only the sender's owning (leaf) namespace may
/// be compared with the target's strict ancestors. An absent identity denies.
pub(crate) fn pid_namespace_signal_relationship(
    sender_chain: &[crate::pid_namespace::PidNamespaceMembership],
    target: &crate::pid_namespace::PidNamespaceArc,
) -> (bool, bool) {
    let Some(sender) = sender_chain.last() else {
        return (false, false);
    };
    let same = Arc::ptr_eq(&sender.ns, target);
    let mut cursor = target.parent();
    for _ in 0..=crate::pid_namespace::MAX_PID_NS_LEVEL {
        let Some(namespace) = cursor else {
            break;
        };
        if Arc::ptr_eq(&sender.ns, &namespace) {
            return (same, true);
        }
        cursor = namespace.parent();
    }
    (same, false)
}

/// Pure authorization decision for the namespace-init gate.  Keeping the
/// policy separate from the process/namespace snapshots makes the dangerous
/// cases executable in the hosted unit-test suite without manufacturing live
/// scheduler tasks.
#[inline]
pub(crate) fn namespace_init_authorized(
    self_signal: bool,
    same_pid_namespace: bool,
    ancestor_pid_namespace: bool,
    ancestor_user_namespace: bool,
    has_admin: bool,
    is_host_root: bool,
    has_dac_permission: bool,
) -> bool {
    if self_signal || (ancestor_pid_namespace && (has_dac_permission || is_host_root)) {
        return true;
    }
    // PID ancestry permits supervision only after normal host-mapped DAC.
    // Other callers need an explicit ADMIN
    // capability in a strict ancestor user namespace; equal user namespaces
    // never satisfy this path.
    let user_supervisor = (has_admin || is_host_root) && ancestor_user_namespace;
    if same_pid_namespace && !user_supervisor {
        return false;
    }
    user_supervisor
}

/// Compare mapped identities without turning two unmapped UIDs into a match.
fn mapped_signal_dac(
    sender_uid: Option<u32>,
    sender_euid: Option<u32>,
    target_uid: Option<u32>,
) -> bool {
    sender_euid == Some(0)
        || target_uid
            .is_some_and(|target| sender_uid == Some(target) || sender_euid == Some(target))
}

/// Shared by syscall preflight and delivery. Snapshot each PCB separately so
/// self-signals cannot recursively acquire the same lock. The delivery caller
/// retains the exact target Arc through authorization and queueing.
pub(crate) fn user_signal_dac_allowed(target: &ProcessArc) -> Result<bool, SignalError> {
    let sender_pid = require_signal_sender_pid(process::current_pid())?;
    let sender = process::get_process(sender_pid).ok_or(SignalError::NoSuchProcess)?;
    let (sender_ns, sender_tgid, uid, euid) = {
        let proc = sender.lock();
        let creds = proc
            .try_credentials_read()
            .ok_or(SignalError::CredentialBusy)?;
        (Arc::clone(&proc.user_ns), proc.tgid, creds.uid, creds.euid)
    };
    let (target_ns, target_tgid, target_uid) = {
        let proc = target.lock();
        let creds = proc
            .try_credentials_read()
            .ok_or(SignalError::CredentialBusy)?;
        (Arc::clone(&proc.user_ns), proc.tgid, creds.uid)
    };
    // Threads in one group share identity and may signal themselves even
    // before their user namespace has a UID mapping. This is self authority,
    // never a match between two unknown principals in different groups.
    if sender_tgid == target_tgid {
        return Ok(true);
    }
    Ok(mapped_signal_dac(
        sender_ns.map_uid_from_ns(uid),
        sender_ns.map_uid_from_ns(euid),
        target_ns.map_uid_from_ns(target_uid),
    ))
}

#[cfg(test)]
#[test]
fn audit_20261031_signal_dac_requires_mapped_identity() {
    assert!(!mapped_signal_dac(None, None, None));
    assert!(!mapped_signal_dac(Some(1000), Some(1000), Some(2000)));
    assert!(mapped_signal_dac(Some(1000), Some(1000), Some(1000)));
    assert!(mapped_signal_dac(Some(1000), Some(2000), Some(2000)));
    assert!(mapped_signal_dac(Some(0), Some(0), None));
}

/// Inner implementation shared by user-facing and kernel-internal signal paths.
///
/// When `enforce_permissions` is true, POSIX UID/EUID checks are applied.
/// A missing current task is an authorization failure (`NoSuchProcess`).
/// When false, the signal is delivered unconditionally (kernel authority).
fn send_signal_inner(
    pid: ProcessId,
    signal: Signal,
    enforce_permissions: bool,
    scope: SignalScope,
    explicit_info: Option<SigInfo>,
    fail_on_queue_full: bool,
) -> Result<SignalAction, SignalError> {
    // 注意：我们需要调用调度器的 resume_stopped，它在 sched crate 中
    // 由于循环依赖的限制，我们通过回调机制实现

    // R65-26 FIX: Get target process Arc ONCE and hold it throughout the operation.
    // This prevents TOCTOU where PID is reused between permission check and signal delivery.
    // Previously, we fetched the process twice: once for permission check, once for signal.
    let process_arc = process::get_process(pid).ok_or(SignalError::NoSuchProcess)?;

    // Synthesize `SigInfo` when the caller did not supply an explicit one (e.g.
    // `kill`, `tkill`, `tgkill`, or kernel-originated signal).
    let mut synthesized_sender: Option<(i32, u32)> = None;

    // 【安全修复 Z-9】POSIX 权限检查（深度防御）
    // 使用 UID/EUID 而非仅父子关系
    // R115-2 FIX: Only enforce permission checks on user-facing paths.
    // Kernel-internal paths (namespace cascade, OOM killer) use send_signal_kernel()
    // which sets enforce_permissions=false to bypass these checks.
    if enforce_permissions {
        // R188-U09-3 FIX: a user-facing signal operation must have an
        // authenticated current task.  The old `if let Some(...)` shape made
        // the entire DAC check disappear when `current_pid()` was `None`,
        // turning an impossible/malformed execution context into fail-open
        // signal authority.  Kernel-internal callers use `send_signal_kernel`
        // and intentionally bypass this branch.
        let sender_pid = require_signal_sender_pid(process::current_pid())?;
        if explicit_info.is_none() {
            if let Some(sender_arc) = process::get_process(sender_pid) {
                let s = sender_arc.lock();
                let uid = s.try_credentials_read().map_or(0, |c| c.uid);
                let visible_pid = s.ns_tgid.max(s.tgid);
                synthesized_sender = Some((visible_pid as i32, uid));
            }
        }
        let has_dac_permission = user_signal_dac_allowed(&process_arc)?;
        let mut namespace_init_supervisor = false;
        // GAP-5 (review D1): init is a process; name the target's and the
        // sender's thread groups, not the selected task.
        let target_tgid = process_arc.lock().tgid;
        let sender_tgid = process::get_process(sender_pid)
            .ok_or(SignalError::NoSuchProcess)?
            .lock()
            .tgid;

        // R188-U02-2: namespace init is a namespace-wide failure boundary.
        // Re-check this relationship at the single delivery choke point so a
        // same-namespace task cannot turn matching DAC credentials into a
        // SIGKILL/SIGSTOP cascade. Ancestor PID namespaces still require DAC;
        // an ADMIN-capable ancestor user namespace is accepted as a
        // defense-in-depth escape for a task that stayed in the same PID ns.
        if sender_tgid != target_tgid {
            let sender_arc = process::get_process(sender_pid).ok_or(SignalError::NoSuchProcess)?;
            let (target_user_ns, target_init_ns) = {
                let target = process_arc.lock();
                let init_ns = target
                    .pid_ns_chain
                    .iter()
                    .rev()
                    .find(|membership| membership.pid == 1 || membership.ns.is_init(target_tgid))
                    .map(|membership| Arc::clone(&membership.ns));
                (Arc::clone(&target.user_ns), init_ns)
            };

            if let Some(init_ns) = target_init_ns {
                let (sender_user_ns, same_pid_namespace, ancestor_pid_namespace) = {
                    let sender = sender_arc.lock();
                    let (same, ancestor) =
                        pid_namespace_signal_relationship(&sender.pid_ns_chain, &init_ns);
                    (Arc::clone(&sender.user_ns), same, ancestor)
                };
                let sender_has_admin = process::current_has_cap_rights(CapRights::ADMIN);
                let sender_is_host_root = process::current_is_host_root();
                let allowed = namespace_init_authorized(
                    false,
                    same_pid_namespace,
                    ancestor_pid_namespace,
                    user_namespace_is_strict_ancestor(&sender_user_ns, &target_user_ns),
                    sender_has_admin,
                    sender_is_host_root,
                    has_dac_permission,
                );
                if !allowed {
                    return Err(SignalError::PermissionDenied);
                }
                namespace_init_supervisor = true;
            }
        }

        // PID 1 (init) 保护：只有 init 自己可以向自己发信号
        if target_tgid == 1 && sender_tgid != 1 {
            return Err(SignalError::PermissionDenied);
        }

        if sender_pid != pid && !namespace_init_supervisor && !has_dac_permission {
            return Err(SignalError::PermissionDenied);
        }
    }

    // process_arc already obtained above (R65-26 FIX)
    let action = default_action(signal);
    let mut needs_reschedule = false;
    let mut terminate_code: Option<i32> = None;
    let mut fatal_post = process::FatalExitPost::None;
    let target_generation;
    // M0-5 sub-slice 1b: set when the EINTR-wake flips a blocked target Ready, so we
    // broadcast a reschedule kick AFTER releasing the proc lock.
    let mut needs_kick = false;
    // GAP-5 slice 4 G7: a stop applied here (false) or a SIGCONT (true) is
    // carried to the rest of the thread group after the lock is released.
    let mut group_job_control: Option<bool> = None;
    // N2.5: notify parent of job-control stop (Some(true)) or continue (Some(false)).
    let mut job_control_notify_stopped: Option<bool> = None;
    // GAP-5 G7 (review D3): a process-directed signal the selected member
    // cannot take now is offered to another member after the lock is released.
    let mut retarget_group: Option<Arc<process::ThreadGroup>> = None;

    {
        let mut proc = process_arc.lock();

        // RF178-36: bind every post-lock action to the same task identity that
        // passed authorization. The Arc pins the object; the generation rejects
        // stale or malformed callers without consulting PROCESS_TABLE again.
        if proc.pid != pid {
            return Err(SignalError::NoSuchProcess);
        }
        target_generation = proc.generation;

        // Cannot send signals to zombie or terminated processes
        if matches!(proc.state, ProcessState::Zombie | ProcessState::Terminated) {
            return Err(SignalError::NoSuchProcess);
        }

        // Queue the signal (always — delivery/clear decisions follow).
        // GAP-5 G7 + N2.6a: process-directed signals go to the group's shared
        // set/queue, so they survive the exit of the member chosen to be woken.
        let siginfo = match explicit_info {
            Some(mut si) => {
                si.signo = signal.as_i32();
                Some(si)
            }
            None => {
                if enforce_permissions {
                    let (spid, suid) = synthesized_sender.unwrap_or((0, 0));
                    let code = match scope {
                        SignalScope::Process => SI_USER,
                        SignalScope::Thread => SI_TKILL,
                    };
                    Some(SigInfo::from_sender(signal, code, spid, suid))
                } else {
                    Some(SigInfo::from_sender(signal, SI_KERNEL, 0, 0))
                }
            }
        };
        match scope {
            SignalScope::Process => {
                proc.thread_group
                    .queue_shared_info(signal, siginfo, fail_on_queue_full)?;
                // This member was chosen for it: its waits now abort for it
                // (unless it cannot take it; see the retarget below).
                proc.shared_chosen |= signal.bit();
            }
            SignalScope::Thread => {
                if let Some(si) = siginfo {
                    if signal.is_realtime() {
                        if proc.rt_sigqueue.push(si).is_err() && fail_on_queue_full {
                            return Err(SignalError::QueueFull);
                        }
                    } else if !proc.pending_signals.is_pending(signal)
                        && !proc.rt_sigqueue.has_signal(signal)
                    {
                        let _ = proc.rt_sigqueue.push(si);
                    }
                }
                proc.pending_signals.set(signal);
                // A thread-directed instance is this task's own, not a
                // claimed group signal to hand back.
                proc.group_claimed &= !signal.bit();
            }
        }

        // POSIX job-control mutual exclusion (Codex review): generating SIGCONT
        // DISCARDS any pending stop signals, and generating a stop signal discards a
        // pending SIGCONT — they are opposite job-control transitions. Without this,
        // a stop bit left pending (a stop is applied at send time but its bit is not
        // cleared) could be re-applied at a later syscall-return safe point once the
        // delivery scan is active, spuriously re-stopping a resumed task.
        if signal.is_continue() {
            proc.discard_pending(Signal::SIGSTOP);
            proc.discard_pending(Signal::SIGTSTP);
            proc.discard_pending(Signal::SIGTTIN);
            proc.discard_pending(Signal::SIGTTOU);
        } else if signal.is_stop() {
            proc.discard_pending(Signal::SIGCONT);
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
        // GAP-5: resolve under a short table hold; the arms below re-lock it.
        let disposition = resolve_disposition(&proc.sigactions.lock(), signal);
        match disposition {
            Disposition::Handler { .. } => {
                // Leave the signal pending for safe-point delivery. SIGCONT is the one
                // job-control case that must still take effect even when caught: a
                // caught SIGCONT MUST un-stop a stopped target so it can reach a safe
                // point and run its handler (otherwise it would be stranded stopped
                // forever). Resume, but DO NOT clear the pending bit — the handler
                // needs it.
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
                    proc.pending_bits(),
                    proc.blocked,
                    proc.in_signal_handler,
                    &proc.sigactions.lock(),
                );
                if should_wake && proc.state == ProcessState::Blocked && !proc.stopped {
                    proc.enter_ready_at(crate::get_ticks());
                    needs_kick = true;
                }
            }
            Disposition::Ignored => {
                // Explicitly ignored — drop it.
                proc.discard_pending(signal);
            }
            Disposition::Default(_)
                if proc.blocked & signal.bit() != 0 && uncatchable_mask() & signal.bit() == 0 =>
            {
                // Delivery is deferred. SIGCONT's generation-time resume is
                // committed below regardless of its mask or disposition.
            }
            Disposition::Default(default) => match default {
                SignalAction::Terminate => {
                    let code = signal_exit_code(signal);
                    terminate_code = Some(code);
                    // RF178-35 FIX: publication, runnable normalization, and
                    // unstop are one PCB-locked transaction. The IPI is emitted
                    // only after this guard is released.
                    fatal_post =
                        process::request_process_exit_locked(&mut proc, code, crate::get_ticks());
                    // GAP-5 slice 4 G2: a fatal default action is process-wide;
                    // this task's teardown ends the rest of its group.
                    proc.group_fatal = true;
                }
                SignalAction::Stop => {
                    // R98-1 FIX: Job-control stop is orthogonal to scheduler state.
                    // Do NOT overwrite Blocked/Sleeping, or we lose the wait condition
                    // and break wait queue invariants (H-34 lost wakeup fix).
                    // RF178-35 FIX: a lock-serialized fatal publication wins over
                    // a later stop and cannot be stranded again.
                    if process::try_mark_job_control_stopped_locked(&mut proc) {
                        proc.thread_group.record_stop_event(signal.as_u8());
                        group_job_control = Some(false);
                        job_control_notify_stopped = Some(true);
                        if process::current_pid() == Some(pid) {
                            needs_reschedule = true;
                        }
                    }
                    proc.discard_pending(signal);
                }
                SignalAction::Continue => {
                    // Generation-time resume is committed below under this guard.
                    proc.discard_pending(signal);
                }
                SignalAction::Ignore => {
                    proc.discard_pending(signal);
                }
            },
        }
        if signal.is_continue() {
            let was_stopped = proc.stopped || proc.state == ProcessState::Stopped;
            needs_kick |= process::resume_job_control_locked(&mut proc, pid, target_generation);
            if was_stopped {
                proc.thread_group.record_continue_event();
                job_control_notify_stopped = Some(false);
            }
            group_job_control = Some(true);
        }
        // GAP-5 G7 (review D3): the selection read this member's mask without
        // its lock held, and a member inside a handler cannot take a caught
        // signal; if the queued signal is still waiting and this member cannot
        // take it now, another member is chosen.
        if matches!(scope, SignalScope::Process)
            && proc.thread_group.shared_pending() & signal.bit() != 0
            && (proc.blocked & signal.bit() != 0
                || (proc.in_signal_handler && matches!(disposition, Disposition::Handler { .. })))
        {
            proc.shared_chosen &= !signal.bit();
            retarget_group = Some(Arc::clone(&proc.thread_group));
        }
    } // Release process lock before calling scheduler functions

    if let Some(group) = retarget_group {
        if process::retarget_shared_signals(pid, &group) {
            // C3 repair 3 audit fix (F3): retarget_shared_signals already
            // drained `published[this]` and kicked all CPUs published so far.
            needs_kick = false;
        }
    }

    // GAP-5 slice 4 G7: stop or continue the other members before a self-stop
    // below parks this task. No lock is held here.
    if let Some(resume) = group_job_control {
        needs_kick |= process::propagate_group_job_control(pid, resume);
    }

    // N2.5: notify parent of WUNTRACED / WCONTINUED transition (respects SA_NOCLDSTOP).
    if let Some(stopped) = job_control_notify_stopped {
        process::notify_parent_of_job_control_event(pid, stopped);
    }

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
            process::terminate_group_self_and_halt(pid, code);
        } else {
            // The exact authorized PCB was already posted under its guard.
            let _ = process::finish_process_exit_request(fatal_post);
            if fatal_post.kicks() {
                needs_kick = false;
            }
        }
    }

    // M0-5 sub-slice 1b: the EINTR-wake flipped a blocked target Ready on (typically) another
    // CPU. Kick the queue-owning CPU so it re-selects it promptly rather than only at its next
    // timer tick (C3 repair 3: that CPU only, no longer every CPU). No-op until the scheduler
    // registers its kick.
    if needs_kick {
        kernel_kick_published();
    }

    // A single scheduler attempt can return without a switch. In particular,
    // a just-woken syscall may be Ready+on_cpu; it must not bypass self-stop.
    drop(process_arc);
    if needs_reschedule {
        process::wait_for_job_control_resume(pid, target_generation);
    }

    Ok(action)
}

/// Check if process has any pending signals
pub fn has_pending_signals(pid: ProcessId) -> bool {
    if let Some(process_arc) = process::get_process(pid) {
        let proc = process_arc.lock();
        proc.pending_bits() != 0
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
    // R188-U09-3: a missing current task must not bypass user-facing signal
    // authorization; kernel-internal callers use the separate privileged API.
    assert_eq!(
        require_signal_sender_pid(None),
        Err(SignalError::NoSuchProcess),
        "R188-U09-3: missing sender identity must fail closed"
    );
    assert_eq!(
        require_signal_sender_pid(Some(7)),
        Ok(7),
        "R188-U09-3: present sender identity must pass the precondition"
    );

    // R188-U02-2: namespace-init authorization is fail-closed for a
    // same-namespace peer, while self, ancestor-PID, and explicitly delegated
    // ancestor-user authority retain the intended supervisor paths.
    assert!(!namespace_init_authorized(
        false, true, false, false, false, false, false
    ));
    assert!(namespace_init_authorized(
        true, true, false, false, false, false, false
    ));
    assert!(namespace_init_authorized(
        false, false, true, false, false, false, true
    ));
    assert!(!namespace_init_authorized(
        false, false, false, false, false, false, false
    ));
    assert!(namespace_init_authorized(
        false, true, false, true, true, false, false
    ));
    assert!(namespace_init_authorized(
        false, true, false, true, false, true, false
    ));
    assert!(!namespace_init_authorized(
        false, true, false, false, true, false, false
    ));

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

    // The production wait predicate includes unblocked catchable defaults,
    // excludes uncatchables, and applies the non-nested handler-frame policy.
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
    // (e) An unblocked default SIGTERM needs safe-point processing.
    assert!(
        signal_is_deliverable(Signal::SIGTERM.bit(), 0, false, &clean),
        "Default(Terminate) requires safe-point delivery"
    );
    // (f) An unblocked default SIGTSTP needs safe-point processing.
    assert!(
        signal_is_deliverable(Signal::SIGTSTP.bit(), 0, false, &clean),
        "Default(Stop) requires safe-point delivery"
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
    // (i) A lower default-terminate bit is also actionable.
    assert!(
        signal_is_deliverable((1u64 << 0) | usr1, 0, false, &table),
        "lowest default bit remains actionable"
    );
    // (j) a SIGKILL bit IS in pending&!blocked (send_signal sets it; SIGKILL is unblockable),
    //     but the uncatchable mask-out keeps it off the signal-EINTR leg.
    assert!(
        !signal_is_deliverable(Signal::SIGKILL.bit(), 0, false, &table),
        "SIGKILL masked out of the deliverable set"
    );

    // The bit primitive and explicit uncatchable filtering remain shared.
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
