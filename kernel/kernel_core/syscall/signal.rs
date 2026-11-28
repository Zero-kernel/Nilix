//! Syscall family module: `signal` (split from monolithic `syscall.rs`, N2.0a).

use super::*;

/// sys_kill - 发送信号给进程
///
/// # Arguments
///
/// * `pid` - 目标进程 ID (namespace-local PID as seen by caller)
/// * `sig` - 信号编号（1-64）
///
/// # Returns
///
/// 成功返回 0，失败返回错误码
///
/// # Permission Model (Z-9 fix: POSIX-compliant UID/EUID checks)
///
/// POSIX permission rules for kill():
/// - Root (euid == 0) 可以发信号给任何进程
/// - 进程可以向自己发送任意信号
/// - sender.uid == target.uid
/// - sender.euid == target.uid
/// - PID 1 (init) 受保护，只有自己能向自己发信号
///
/// F.1 PID Namespace: The pid parameter is interpreted as a namespace-local PID.
/// It is translated to a global PID using the caller's owning namespace.
/// GAP-5 slice 4 G7: how a kill-family syscall addresses its target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum KillTarget {
    /// kill(2): process-directed; a thread group picks the receiving member.
    Process,
    /// tkill(2): exactly the named thread.
    Thread,
    /// tgkill(2): exactly the named thread, which must belong to this
    /// thread group (namespace-local id).
    ThreadInGroup(ProcessId),
}

pub(super) fn sys_kill(pid: ProcessId, sig: i32) -> SyscallResult {
    kill_common(pid, sig, KillTarget::Process)
}

/// tkill(2). musl's raise() uses it with the caller's own tid.
pub(super) fn sys_tkill(tid: i32, sig: i32) -> SyscallResult {
    if tid <= 0 {
        return Err(SyscallError::EINVAL);
    }
    kill_common(tid as ProcessId, sig, KillTarget::Thread)
}

/// tgkill(2).
pub(super) fn sys_tgkill(tgid: i32, tid: i32, sig: i32) -> SyscallResult {
    if tgid <= 0 || tid <= 0 {
        return Err(SyscallError::EINVAL);
    }
    kill_common(
        tid as ProcessId,
        sig,
        KillTarget::ThreadInGroup(tgid as ProcessId),
    )
}

/// Shared authorization and delivery for kill, tkill and tgkill. Every check
/// below (namespace translation, init protection, POSIX/user-namespace
/// permission, LSM) applies to all three; only the final delivery differs.
pub(super) fn kill_common(pid: ProcessId, sig: i32, mode: KillTarget) -> SyscallResult {
    use crate::signal::{send_signal, send_signal_thread, signal_name, Signal};

    let self_global_pid = current_pid().ok_or(SyscallError::ESRCH)?;

    // F.1: Translate namespace-local PID to global PID
    let owning_ns = {
        let self_proc = get_process(self_global_pid).ok_or(SyscallError::ESRCH)?;
        let proc = self_proc.lock();
        crate::pid_namespace::owning_namespace(&proc.pid_ns_chain)
    };
    let to_global = |local: ProcessId| -> Result<ProcessId, SyscallError> {
        match &owning_ns {
            // Translate using caller's namespace
            Some(ns) => {
                crate::pid_namespace::resolve_pid_in_namespace(ns, local).ok_or(SyscallError::ESRCH)
            }
            // No namespace (root or early boot) - use PID directly
            None => Ok(local),
        }
    };
    let target_global_pid = to_global(pid)?;

    // GAP-5 slice 4 G7: tgkill names the group too; a tid outside it is ESRCH
    // (it may have been recycled into another process).
    if let KillTarget::ThreadInGroup(tgid) = mode {
        let global_tgid = to_global(tgid)?;
        let target = get_process(target_global_pid).ok_or(SyscallError::ESRCH)?;
        if target.lock().tgid != global_tgid {
            return Err(SyscallError::ESRCH);
        }
    }
    // Release `owning_ns` before signal delivery so a fatal self-signal does
    // not pin the namespace Arc on the abandoned syscall stack.
    drop(owning_ns);

    // 【安全修复 Z-9】POSIX 权限检查（防御深度）
    // send_signal 也会进行相同检查，这里提前拒绝以提供更清晰的错误

    // PID 1 保护：只有 init 自己能向自己发信号
    // Note: This checks the target's global PID, so namespace PID 1 is protected
    // within that namespace, but global PID 1 is specially protected.
    // R188-U02-2: fast-fail a same-PID-namespace attempt to signal a
    // namespace init.  The authoritative, pinned-Arc check remains in
    // `send_signal`; this probe only avoids doing the DAC/LSM work for the
    // common container-local SIGKILL case.
    //
    // GAP-5 (review D1): init is a process, so both checks name the target's
    // thread group. Checked per task, any non-leader thread of an init could
    // be signalled (and a fatal default ends the whole group).
    let self_tgid = get_process(self_global_pid)
        .ok_or(SyscallError::ESRCH)?
        .lock()
        .tgid;
    let target_tgid = get_process(target_global_pid)
        .ok_or(SyscallError::ESRCH)?
        .lock()
        .tgid;
    let has_dac_permission = {
        let signal_target = get_process(target_global_pid).ok_or(SyscallError::ESRCH)?;
        crate::signal::user_signal_dac_allowed(&signal_target)?
    };
    let mut namespace_init_supervisor = false;
    if self_tgid != target_tgid {
        let target = get_process(target_global_pid).ok_or(SyscallError::ESRCH)?;
        let (target_init_ns, target_user_ns) = {
            let target_proc = target.lock();
            (
                target_proc
                    .pid_ns_chain
                    .iter()
                    .rev()
                    .find(|membership| membership.pid == 1 || membership.ns.is_init(target_tgid))
                    .map(|membership| membership.ns.clone()),
                target_proc.user_ns.clone(),
            )
        };
        if let Some(init_ns) = target_init_ns {
            let sender = get_process(self_global_pid).ok_or(SyscallError::ESRCH)?;
            let (same_namespace, ancestor_namespace, sender_user_ns) = {
                let sender_proc = sender.lock();
                let (same, ancestor) = crate::signal::pid_namespace_signal_relationship(
                    &sender_proc.pid_ns_chain,
                    &init_ns,
                );
                (same, ancestor, sender_proc.user_ns.clone())
            };
            namespace_init_supervisor = crate::signal::namespace_init_authorized(
                false,
                same_namespace,
                ancestor_namespace,
                crate::signal::user_namespace_is_strict_ancestor(&sender_user_ns, &target_user_ns),
                crate::process::current_has_cap_rights(cap::CapRights::ADMIN),
                crate::current_is_host_root(),
                has_dac_permission,
            );
            if !namespace_init_supervisor {
                return Err(SyscallError::EPERM);
            }
        }
    }

    if target_tgid == 1 && self_tgid != 1 {
        return Err(SyscallError::EPERM);
    }

    if self_global_pid != target_global_pid && !namespace_init_supervisor && !has_dac_permission {
        return Err(SyscallError::EPERM);
    }

    // R161-2 FIX + R162-1-1 FIX: Invoke LSM hook_signal_send BEFORE sig==0
    // check so MAC policy can deny process existence probes across security
    // domains (matching Linux SELinux/AppArmor behavior).
    // R192-5 / TD-LSM-1 FIX: a missing subject fails closed, never skips.
    let task_ctx = lsm_current_process_ctx().ok_or(SyscallError::EPERM)?;
    let sig_ctx = lsm::SignalCtx {
        target_pid: target_global_pid,
        sig,
        cap: None,
    };
    if let Err(err) = lsm::hook_signal_send(&task_ctx, &sig_ctx) {
        return Err(lsm_error_to_syscall(err));
    }

    // R161-I6 FIX: POSIX kill(pid, 0) — permission check without delivery.
    // Signal 0 is used to test if a process exists and the caller has permission.
    // Placed after LSM check so MAC policy can deny existence probes.
    if sig == 0 {
        return Ok(0);
    }

    // 验证信号编号
    let signal = Signal::from_raw(sig)?;

    // 发送信号 (using global PID)
    let _action = match mode {
        KillTarget::Process => send_signal(target_global_pid, signal)?,
        KillTarget::Thread | KillTarget::ThreadInGroup(_) => {
            send_signal_thread(target_global_pid, signal)?
        }
    };

    // R101-2 FIX: Gate signal dispatch debug print behind debug_assertions.
    // R111-4 FIX: Remove target_global_pid from output to preserve PID namespace
    // isolation even in debug builds.
    kprintln!(
        "sys_kill: sent {} to PID {} (action: {:?})",
        signal_name(signal),
        pid,
        _action
    );

    Ok(0)
}

// ============================================================================
// 信号掩码 (Signal mask) — Linux x86_64 ABI
// ============================================================================

/// `how` argument values for rt_sigprocmask (Linux ABI).
pub(super) const SIG_BLOCK: i32 = 0;
pub(super) const SIG_UNBLOCK: i32 = 1;
pub(super) const SIG_SETMASK: i32 = 2;

/// The kernel `sigset_t` is a fixed 64-bit mask on x86_64 (`_NSIG / 8 == 8`).
/// rt_sigprocmask requires the caller's `sigsetsize` to equal this exactly.
pub(super) const LINUX_KERNEL_SIGSET_SIZE: usize = core::mem::size_of::<u64>();

/// Pure validator for rt_sigprocmask arguments, factored out for self-testing.
///
/// Linux semantics: `sigsetsize` is checked unconditionally; `how` is validated
/// ONLY when a new mask is supplied (`set != NULL`). A NULL `set` is a pure
/// query of the old mask and ignores `how` entirely (so even a bogus `how` is
/// accepted there) — matching `kernel/signal.c` where `how` is only consulted
/// inside the `if (nset)` branch.
pub(super) fn validate_rt_sigprocmask_args(
    how: i32,
    set_is_null: bool,
    sigsetsize: usize,
) -> Result<(), SyscallError> {
    if sigsetsize != LINUX_KERNEL_SIGSET_SIZE {
        return Err(SyscallError::EINVAL);
    }
    if !set_is_null {
        match how {
            SIG_BLOCK | SIG_UNBLOCK | SIG_SETMASK => {}
            _ => return Err(SyscallError::EINVAL),
        }
    }
    Ok(())
}

/// sys_rt_sigprocmask - examine/change the per-task blocked-signal mask (syscall 14).
///
/// REAL since M0 item 5 (no longer an M0 stub): the per-task `blocked` mask is load-bearing.
/// Signal delivery masks against it — `maybe_deliver_signal` selects from `pending & !blocked`,
/// and `signal_is_deliverable` (the shared EINTR-wake / wait-epilogue predicate) gates on
/// `pending & !blocked & !uncatchable_mask()`. Semantics: validates `how`/`sigsetsize`,
/// fault-reads `set` and preflights `oldset` BEFORE mutating, then under the proc lock applies
/// SIG_BLOCK (old|set) / SIG_UNBLOCK (old & !set) / SIG_SETMASK (set) and copies the PREVIOUS
/// mask to `oldset`. SIGKILL/SIGSTOP are force-stripped, so they can never be blocked (POSIX).
/// A born-clean process starts `blocked == 0`, so musl's startup query still observes an
/// all-zero `oldset`.
pub(super) fn sys_rt_sigprocmask(
    how: i32,
    set: *const u8,
    oldset: *mut u8,
    sigsetsize: usize,
) -> SyscallResult {
    // M0 item 5 (sub-slice 1a): upgraded from the M0-2 zeroed stub to a REAL per-task
    // blocked mask. SIGKILL/SIGSTOP are force-stripped from any stored mask (POSIX:
    // they can never be blocked). A born-clean process starts with blocked == 0, so
    // the musl crt's startup mask query still observes an all-zero oldset.
    validate_rt_sigprocmask_args(how, set.is_null(), sigsetsize)?;
    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let proc_arc = get_process(pid).ok_or(SyscallError::ESRCH)?;

    // Read the new mask (if any) BEFORE mutating (fault-before-mutation).
    let new_set: Option<u64> = if !set.is_null() {
        let mut b = [0u8; LINUX_KERNEL_SIGSET_SIZE];
        copy_from_user(&mut b, set)?;
        Some(u64::from_ne_bytes(b))
    } else {
        None
    };
    // Preflight the oldset buffer writable before mutating, so a faulting oldset can
    // never surface AFTER the mask was already installed.
    if !oldset.is_null() {
        verify_user_memory(oldset as *const u8, LINUX_KERNEL_SIGSET_SIZE, true)?;
    }

    // Apply under the lock; capture the previous mask for oldset.
    let (old, retarget) = {
        let mut proc = proc_arc.lock();
        let old = proc.blocked;
        if let Some(s) = new_set {
            proc.blocked = crate::signal::apply_sigprocmask(old, how, s);
        }
        // GAP-5 G7 (review D3): group signals this task now blocks are left
        // to another member, which is woken if it waits.
        let retarget = (new_set.is_some() && proc.recalc_shared_signals(true))
            .then(|| Arc::clone(&proc.thread_group));
        (old, retarget)
    };
    if let Some(group) = retarget {
        crate::process::retarget_shared_signals(pid, &group);
    }

    if !oldset.is_null() {
        copy_to_user(oldset, &old.to_ne_bytes())?;
    }
    Ok(0)
}

/// sys_rt_sigaction - install / query a per-task signal disposition (syscall 13).
///
/// M0 item 5 (sub-slice 1a). Rejects SIGKILL/SIGSTOP, unknown `sa_flags`, and a real
/// handler without SA_RESTORER or with a non-canonical / high-half handler/restorer
/// VA (validated AT INSTALL, mirroring the SYSRET checks). `sa_mask` is stripped of
/// SIGKILL/SIGSTOP. Installs the action then copies out the previous one (Linux
/// window, documented). Refreshes the lock-free `has_handlers` delivery hint.
pub(super) fn sys_rt_sigaction(
    signum: i32,
    act: *const u8,
    oldact: *mut u8,
    sigsetsize: usize,
) -> SyscallResult {
    use crate::signal::{SigAction, Signal, SA_RESTORER, SA_SUPPORTED_FLAGS, SIG_DFL, SIG_IGN};
    if sigsetsize != LINUX_KERNEL_SIGSET_SIZE {
        return Err(SyscallError::EINVAL);
    }
    let sig = Signal::from_raw(signum).map_err(|_| SyscallError::EINVAL)?;
    // SIGKILL/SIGSTOP dispositions cannot be changed (POSIX).
    if sig.is_uncatchable() {
        return Err(SyscallError::EINVAL);
    }
    let idx = (sig.as_u8() - 1) as usize;
    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let proc_arc = get_process(pid).ok_or(SyscallError::ESRCH)?;

    const SIGACTION_BYTES: usize = 32;
    // Parse + validate the new action BEFORE any mutation.
    let new_act: Option<SigAction> = if !act.is_null() {
        let mut b = [0u8; SIGACTION_BYTES];
        copy_from_user(&mut b, act)?;
        let rd = |o: usize| -> u64 {
            let mut a = [0u8; 8];
            a.copy_from_slice(&b[o..o + 8]);
            u64::from_ne_bytes(a)
        };
        let handler = rd(0);
        let flags = rd(8);
        let restorer = rd(16);
        let mask = rd(24);
        // Reject unknown flags so an unrecognized bit can never silently change behavior.
        if flags & !SA_SUPPORTED_FLAGS != 0 {
            return Err(SyscallError::EINVAL);
        }
        if handler != SIG_DFL && handler != SIG_IGN {
            // A real handler REQUIRES SA_RESTORER (x86-64 Linux) and canonical low-half
            // handler + restorer VAs.
            if flags & SA_RESTORER == 0 {
                return Err(SyscallError::EINVAL);
            }
            if !crate::signal_frame::is_canonical_user_addr(handler) {
                return Err(SyscallError::EINVAL);
            }
            if restorer == 0 || !crate::signal_frame::is_canonical_user_addr(restorer) {
                return Err(SyscallError::EINVAL);
            }
        }
        // SIGKILL/SIGSTOP can never be auto-blocked via sa_mask.
        let mask = mask & !crate::signal::uncatchable_mask();
        Some(SigAction {
            handler,
            flags,
            restorer,
            mask,
        })
    } else {
        None
    };

    if !oldact.is_null() {
        verify_user_memory(oldact as *const u8, SIGACTION_BYTES, true)?;
    }

    // Install + capture the old disposition. If a real handler is installed, trip the
    // monotonic global delivery hint so the syscall-return hook starts scanning.
    let old = {
        // GAP-5: the table may be shared by a CLONE_SIGHAND group; the table
        // lock (PCB -> SignalTable leaf) makes read-old/write-new atomic.
        let proc = proc_arc.lock();
        let old = match new_act {
            Some(na) => proc.sigactions.replace(idx, na),
            None => proc.sigactions.get(idx),
        };
        if let Some(na) = new_act {
            if na.is_handler() {
                crate::signal::note_handler_installed();
            }
        }
        old
    };

    if !oldact.is_null() {
        let mut b = [0u8; SIGACTION_BYTES];
        b[0..8].copy_from_slice(&old.handler.to_ne_bytes());
        b[8..16].copy_from_slice(&old.flags.to_ne_bytes());
        b[16..24].copy_from_slice(&old.restorer.to_ne_bytes());
        b[24..32].copy_from_slice(&old.mask.to_ne_bytes());
        copy_to_user(oldact, &b)?;
    }
    Ok(0)
}

/// sys_rt_sigreturn - restore the interrupted context after a handler returns (15).
///
/// M0 item 5 (sub-slice 1a). SROP-DEFENDED: validates the restored RIP/RSP (canonical,
/// low-half), sanitizes RFLAGS, IGNORES the user CS/SS (SYSRET reloads the fixed user
/// selectors), re-derives the fpstate at a FIXED offset (never trusting the in-frame
/// pointer) and masks MXCSR so the exit-path `fxrstor64` cannot #GP. Restores the
/// pre-handler blocked mask from the PCB (never from `uc_sigmask`). ANY failure
/// terminates with SIGSEGV (139) — a forged context never resumes.
pub(super) fn sys_rt_sigreturn() -> SyscallResult {
    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let proc_arc = get_process(pid).ok_or(SyscallError::ESRCH)?;

    // Gate: must be inside a live handler frame. A forged rt_sigreturn is fatal.
    if !proc_arc.lock().in_signal_handler {
        crate::process::terminate_group_self_and_halt(pid, 139);
    }

    // The ucontext VA == the user RSP at rt_sigreturn entry. Also read the live CPU
    // MXCSR mask from the kernel's own fxsave area (FXSAVE offset 28). None => no live
    // frame (should not happen for a non-blocking syscall at its own return) => fatal.
    let (uc_va, cpu_mxcsr_mask) = match with_current_syscall_frame_mut(pid, |frame, fx| {
        let mut m = [0u8; 4];
        m.copy_from_slice(&fx[28..32]);
        (frame.rsp, u32::from_ne_bytes(m))
    }) {
        Some(v) => v,
        None => crate::process::terminate_group_self_and_halt(pid, 139),
    };

    // One bulk copy of the sigcontext from the user stack; SROP-validate it.
    let mc_va = uc_va
        .checked_add(crate::signal_frame::SIGRETURN_MCONTEXT_FROM_UC)
        .unwrap_or(0);
    let mut mc = [0u8; crate::signal_frame::MCONTEXT_SIZE];
    if copy_from_user(&mut mc, mc_va as *const u8).is_err() {
        crate::process::terminate_group_self_and_halt(pid, 139);
    }
    let restored = match crate::signal_frame::parse_and_validate_mcontext(&mc) {
        Ok(r) => r,
        Err(()) => crate::process::terminate_group_self_and_halt(pid, 139),
    };

    // One bulk copy of the fpstate from the FIXED offset; mask MXCSR.
    let fp_va = uc_va
        .checked_add(crate::signal_frame::SIGRETURN_FPSTATE_FROM_UC)
        .unwrap_or(0);
    let mut fxbuf = [0u8; 512];
    if copy_from_user(&mut fxbuf, fp_va as *const u8).is_err() {
        crate::process::terminate_group_self_and_halt(pid, 139);
    }
    crate::signal_frame::sanitize_inbound_fxsave(&mut fxbuf, cpu_mxcsr_mask);

    // Restore the interrupted register state into the live frame + the sanitized
    // fpstate into the exit-path FXSAVE area.
    let committed = with_current_syscall_frame_mut(pid, |frame, fx| {
        frame.rax = restored.rax;
        frame.rbx = restored.rbx;
        frame.rcx = restored.rip; // SYSRET reads RCX as the user RIP.
        frame.rdx = restored.rdx;
        frame.rsi = restored.rsi;
        frame.rdi = restored.rdi;
        frame.rbp = restored.rbp;
        frame.rsp = restored.rsp;
        frame.r8 = restored.r8;
        frame.r9 = restored.r9;
        frame.r10 = restored.r10;
        frame.r11 = restored.rflags; // SYSRET reads R11 as RFLAGS (already sanitized).
        frame.r12 = restored.r12;
        frame.r13 = restored.r13;
        frame.r14 = restored.r14;
        frame.r15 = restored.r15;
        fx.copy_from_slice(&fxbuf[..]);
    });
    if committed.is_none() {
        crate::process::terminate_group_self_and_halt(pid, 139);
    }

    // Restore the pre-handler blocked mask + clear the handler-live state.
    {
        let mut proc = proc_arc.lock();
        proc.blocked = proc.saved_blocked & !crate::signal::uncatchable_mask();
        proc.saved_blocked = 0;
        proc.in_signal_handler = false;
    }

    // Return the interrupted syscall's saved RAX (the exit asm does NOT reload RAX
    // from the frame — the dispatcher return value becomes RAX).
    Ok(restored.rax as usize)
}

/// Apply a DEFAULT-disposition signal at the syscall-return safe point (the current
/// task IS `pid`). Reached from `maybe_deliver_signal` when a pending bit's CURRENT
/// disposition is SIG_DFL — e.g. a handler-disposition signal was queued, then reset
/// to default by `rt_sigaction`/`exec` before the safe point drained it. Mirrors
/// `send_signal_inner`'s send-time default executor.
pub(super) fn apply_default_at_safepoint(pid: ProcessId, sig: crate::signal::Signal) {
    use crate::signal::{pending_default_action, signal_exit_code, SignalAction};
    let Some(arc) = get_process(pid) else { return };
    let mut stop = false;
    let mut exit_code = None;
    let generation;
    {
        let mut proc = arc.lock();
        generation = proc.generation;
        let Some(action) = pending_default_action(
            proc.pending_bits(),
            proc.blocked,
            &proc.sigactions.lock(),
            sig,
        ) else {
            return;
        };
        // GAP-5 G7: consume one instance, own set first, else the group's.
        if !proc.claim_pending(sig) {
            return;
        }
        proc.consume_own_pending(sig);
        match action {
            SignalAction::Terminate => {
                // Self-termination immediately follows after releasing all PCB owners.
                let _ = crate::process::request_process_exit_locked(
                    &mut proc,
                    signal_exit_code(sig),
                    crate::get_ticks(),
                );
                exit_code = Some(
                    proc.pending_exit_code
                        .load(core::sync::atomic::Ordering::Acquire),
                );
            }
            SignalAction::Stop => {
                stop = crate::process::try_mark_job_control_stopped_locked(&mut proc);
            }
            SignalAction::Continue | SignalAction::Ignore => {}
        }
    }
    drop(arc);
    if let Some(code) = exit_code {
        crate::process::terminate_group_self_and_halt(pid, code);
    }
    if stop {
        // GAP-5 G7 (review D2): a stop stops the whole group, as at send time.
        let _ = crate::process::propagate_group_job_control(pid, false);
        crate::process::wait_for_job_control_resume(pid, generation);
    }
}

/// M0 item 5 (sub-slice 1a): deliver ONE pending handler signal at the syscall-return
/// safe point. `result` is the about-to-be-returned syscall value — saved into the
/// sigframe so `rt_sigreturn` restores the interrupted context's RAX (the EINTR /
/// partial-op short-count contract). May not return (fatal SIGSEGV / racing SIGKILL).
///
/// Sub-slice 1a delivers only when the mutable frame accessor yields a live frame
/// (a non-blocking syscall return); a syscall that blocked-and-resumed has a zeroed
/// `frame_ptr`, so delivery is SAFELY DEFERRED to the task's next non-blocking return
/// (waking a blocked-in-syscall target is 1b). No blocked-waiter wake here.
/// R172-X-F1 / EXEC-SIGNAL-SAFEPOINT-CONJUNCTION leg (b): on exec, every installed user
/// handler resets to SIG_DFL (SIG_IGN is PRESERVED, per POSIX); the blocked mask and pending
/// set are untouched. The SOLE handler-reset path, so a self-test exercising THIS fn is a
/// true witness of the production reset (dev-v29: not a constant mirror).
pub(crate) fn reset_sigactions_for_exec(
    sigactions: &mut [crate::signal::SigAction; crate::signal::NSIG],
) {
    for sa in sigactions.iter_mut() {
        if sa.is_handler() {
            *sa = crate::signal::SigAction::default_action();
        }
    }
}

/// R172-X-F1: pin EXEC-SIGNAL-SAFEPOINT-CONJUNCTION leg (b) by exercising the PRODUCTION
/// `reset_sigactions_for_exec`. The runtime `exec_in_progress` tripwire in
/// `maybe_deliver_signal` (legs a/c enforcement) needs a live process to lock, so it is
/// covered by the boot / SMP exec paths, not this pure test.
pub fn run_exec_signal_safepoint_self_test() {
    use crate::signal::{SigAction, NSIG, SIG_IGN};
    let mut t: [SigAction; NSIG] = [SigAction::default_action(); NSIG];
    t[0].handler = 0x4000_1000; // a real user handler at index 0
    t[1].handler = SIG_IGN; // SIG_IGN at index 1
    reset_sigactions_for_exec(&mut t);
    assert!(
        !t[0].is_handler(),
        "leg-b: exec must reset a real handler to SIG_DFL"
    );
    assert_eq!(t[1].handler, SIG_IGN, "leg-b: exec must PRESERVE SIG_IGN");
    assert!(
        t.iter().all(|s| !s.is_handler()),
        "leg-b: no real handler survives exec"
    );
}

/// RF178-34 FIX: classify the architectural main stack without taking a lock.
/// The window is deliberately half-open; an RSP exactly at `USER_STACK_TOP`
/// does not acquire main-stack growth authority.
#[inline]
pub(super) fn main_sigframe_stack(rsp: u64) -> Option<crate::signal_frame::SigframeStack> {
    let (start, end) = crate::elf_loader::user_stack_window();
    if (start as u64) <= rsp && rsp < end as u64 {
        Some(crate::signal_frame::SigframeStack::Main {
            floor: crate::elf_loader::user_stack_usable_floor(),
        })
    } else {
        None
    }
}

/// RF178-34 FIX: allocation-free, fail-closed VMA provenance lookup shared by
/// syscall-return and IRQ-return signal delivery.
///
/// The greatest base `<= rsp` is the only candidate. This is load-bearing at
/// adjacent mappings: a mapping beginning exactly at RSP wins over a lower VMA
/// whose exclusive top is RSP. If that upper candidate is invalid, we do not
/// fall back and grant the lower mapping authority over the frame write.
pub(super) fn locate_sigframe_vma<M>(rsp: u64, regions: &M) -> crate::signal_frame::SigframeStack
where
    M: MmapRegions,
{
    use crate::signal_frame::SigframeStack;

    let Ok(rsp_key) = usize::try_from(rsp) else {
        return SigframeStack::Unlocatable;
    };
    let Some((&base, &entry)) = regions.range(..=rsp_key).next_back() else {
        return SigframeStack::Unlocatable;
    };
    let len = entry.len();
    let Some(end) = base.checked_add(len) else {
        return SigframeStack::Unlocatable;
    };
    if len == 0
        || entry.is_prot_none()
        || entry.has_transient()
        || !entry.prot_write()
        || rsp_key < base
        || rsp_key > end
    {
        return SigframeStack::Unlocatable;
    }

    // `rsp == end` is the exact-top case: [frame_base, rsp) remains inside the
    // candidate. `rsp == base` is accepted as provenance too, but the layout
    // floor then rejects the downward frame rather than borrowing a lower VMA.
    SigframeStack::Mmap { floor: base as u64 }
}

/// Trait for mmap_regions operations (supports both FallibleOrderedMap and AdmittedMap)
pub(super) trait MmapRegions {
    fn range(
        &self,
        range: impl core::ops::RangeBounds<usize>,
    ) -> impl DoubleEndedIterator<Item = (&usize, &MmapEntry)>;
}

impl MmapRegions for crate::fallible_map::FallibleOrderedMap<usize, MmapEntry> {
    fn range(
        &self,
        range: impl core::ops::RangeBounds<usize>,
    ) -> impl DoubleEndedIterator<Item = (&usize, &MmapEntry)> {
        self.range(range)
    }
}

impl MmapRegions for mm::AdmittedMap<usize, MmapEntry> {
    fn range(
        &self,
        range: impl core::ops::RangeBounds<usize>,
    ) -> impl DoubleEndedIterator<Item = (&usize, &MmapEntry)> {
        self.range(range)
    }
}

/// Pure RF178-34 regression coverage for the shared VMA locator and the
/// half-open main-stack classifier. Map construction may allocate; the
/// production locator itself only performs a binary range lookup.
pub fn run_sigframe_stack_locator_self_test() {
    use crate::fallible_map::FallibleOrderedMap;
    use crate::signal_frame::SigframeStack;

    let (main_start, main_end) = crate::elf_loader::user_stack_window();
    let main_floor = crate::elf_loader::user_stack_usable_floor();
    assert_eq!(
        main_sigframe_stack(main_start as u64),
        Some(SigframeStack::Main { floor: main_floor })
    );
    assert_eq!(
        main_sigframe_stack(main_end as u64 - 1),
        Some(SigframeStack::Main { floor: main_floor })
    );
    assert_eq!(
        main_sigframe_stack(main_end as u64),
        None,
        "the main-stack window must remain half-open"
    );

    let write = MMAP_REGION_FLAG_PROT_READ | MMAP_REGION_FLAG_PROT_WRITE;
    let mut regions: FallibleOrderedMap<usize, MmapEntry> = FallibleOrderedMap::new();
    regions
        .try_insert(0x1000, MmapEntry::from_len_flags(0x1000, write))
        .expect("insert lower VMA");
    assert_eq!(
        locate_sigframe_vma(0x1800, &regions),
        SigframeStack::Mmap { floor: 0x1000 },
        "an RSP inside a writable VMA must use its base"
    );
    assert_eq!(
        locate_sigframe_vma(0x2000, &regions),
        SigframeStack::Mmap { floor: 0x1000 },
        "an exact-top RSP must use the VMA below it"
    );

    regions
        .try_insert(0x2000, MmapEntry::from_len_flags(0x1000, write))
        .expect("insert adjacent upper VMA");
    assert_eq!(
        locate_sigframe_vma(0x2000, &regions),
        SigframeStack::Mmap { floor: 0x2000 },
        "at adjacency, the upper base==RSP mapping must win"
    );
    regions
        .try_insert(
            0x2000,
            MmapEntry::from_len_flags(0x1000, MMAP_REGION_FLAG_PROT_READ),
        )
        .expect("replace upper VMA as read-only");
    assert_eq!(
        locate_sigframe_vma(0x2000, &regions),
        SigframeStack::Unlocatable,
        "an invalid upper adjacency candidate must not fall back to the lower VMA"
    );

    let invalid = [
        MmapEntry::from_len_flags(0, write),
        MmapEntry::prot_none(0x1000),
        MmapEntry::from_len_flags(0x1000, write | MMAP_REGION_FLAG_PENDING_MAP),
        MmapEntry::from_len_flags(0x1000, MMAP_REGION_FLAG_PROT_READ),
    ];
    for entry in invalid {
        let mut one = FallibleOrderedMap::new();
        one.try_insert(0x4000usize, entry)
            .expect("insert invalid locator fixture");
        assert_eq!(
            locate_sigframe_vma(0x4000, &one),
            SigframeStack::Unlocatable,
            "zero-length, PROT_NONE, transient, and non-writable VMAs must fail closed"
        );
    }

    let overflow_base = usize::MAX & !(PAGE_SIZE - 1);
    let mut overflow = FallibleOrderedMap::new();
    overflow
        .try_insert(overflow_base, MmapEntry::from_len_flags(PAGE_SIZE, write))
        .expect("insert overflowing locator fixture");
    assert_eq!(
        locate_sigframe_vma(overflow_base as u64, &overflow),
        SigframeStack::Unlocatable,
        "base+len overflow must fail closed"
    );
}

#[inline]
pub(super) fn restore_poll_blocked_locked(proc: &mut crate::process::Process) {
    if let Some(old) = proc.poll_restore_blocked.take() {
        proc.blocked = old & !crate::signal::uncatchable_mask();
    }
}

pub(super) enum SignalTailStep {
    /// Fast path or early exit: `poll_restore_blocked` already restored under lock.
    Done,
    /// Posted fatal exit consumed at safe point; terminate with this exit code.
    Exit(i32),
    /// Pending exec handoff must run before signal delivery.
    ExecHandoff,
    /// Pending kill discovered after retargeting shared signals.
    PendingKill,
    /// Default signal action must run outside the PCB lock, then restore poll mask.
    Default(crate::signal::Signal),
    /// Handler frame delivery (Phase 2/3) outside the PCB lock.
    Handler {
        sig: crate::signal::Signal,
        handler: u64,
        restorer: u64,
        sa_mask: u64,
        sa_flags: u64,
        old_blocked: u64,
        delivered_action: crate::signal::SigAction,
    },
}

/// Phase 1 of signal delivery + `poll_restore_blocked` restore, starting from
/// an already-acquired PCB lock (from `finish_syscall_tail`).
pub(super) fn maybe_deliver_signal_phase1<'a>(
    pid: ProcessId,
    proc_arc: &'a crate::process::ProcessArc,
    mut proc: crate::owner_lock::OwnerCpuMutexGuard<'a, crate::process::Process>,
) -> SignalTailStep {
    // R172-X-F1: EXEC-SIGNAL-SAFEPOINT-CONJUNCTION (leg enforcement, the single delivery
    // choke point). Delivery here writes a sigframe against the INTERRUPTED user RSP
    // (ctx.rsp). After an exec that just swapped CR3 to the new image, that RSP is valid
    // ONLY because exec (a) refused a shared / multithreaded AS [EBUSY tgid/share_count,
    // EAGAIN migration] and (b) reset every handler + cleared the frame binding under the
    // commit lock [reset_sigactions_for_exec] BEFORE control could reach this safe point
    // [exec clears exec_in_progress via ExecInProgressGuard at scope exit, AFTER the
    // commit and BEFORE the unified syscall-return safe point], and (c) never blocks
    // mid-exec. On the legitimate post-exec path this guard is a TAUTOLOGY (never fires);
    // it fires ONLY if a future edit re-exposes this safe point while an exec is genuinely
    // mid-flight — exactly the sigframe-against-stale-RSP-on-the-new-AS corruption class it
    // pins. Fail CLOSED in release (DROP the delivery, leave the pending bit set for a
    // later post-exec attempt) rather than execute the corrupting copy_to_user. Cost: one
    // bool read on the held PCB lock before signal processing.
    if proc.exec_in_progress {
        klog_force!(
            "FATAL-INVARIANT: maybe_deliver_signal reached with exec_in_progress set \
             (pid={}) — EXEC-SIGNAL-SAFEPOINT-CONJUNCTION violated; a sigframe write would \
             target a stale pre-exec RSP on the new AS",
            pid
        );
        debug_assert!(
            !proc.exec_in_progress,
            "EXEC-SIGNAL-SAFEPOINT-CONJUNCTION: signal delivery in the live exec window"
        );
        restore_poll_blocked_locked(&mut proc);
        return SignalTailStep::Done;
    }
    // GAP-5 G7 (review D3): a mask change since the last return (sigreturn,
    // a handler's mask, a ppoll mask) may block group signals this task was
    // chosen for; another member takes them over.
    if proc.recalc_shared_signals(false) {
        let group = Arc::clone(&proc.thread_group);
        drop(proc);
        crate::process::retarget_shared_signals(pid, &group);
        proc = proc_arc.lock();
    }
    // GAP-5 G7 (review D3): a task with a posted fatal exit never takes a
    // group signal; a live member gets it. Checked unconditionally (including
    // after ExecHandoff where `run_exec_handoff` ran unlocked).
    if proc.pending_kill.load(AtomicOrdering::Acquire) {
        return SignalTailStep::PendingKill;
    }
    // Fast path: when neither per-task nor shared signals are pending,
    // skip `discard_inert_pending`, `proc.sigactions.lock()`, and the 2 KiB
    // `[SigAction; 64]` stack copy, and restore any ppoll/pselect6 temporary
    // sigmask right under this same held PCB lock.
    if proc.pending_bits() == 0 {
        restore_poll_blocked_locked(&mut proc);
        return SignalTailStep::Done;
    }
    crate::signal::discard_inert_pending(&mut proc);
    // GAP-5: one coherent snapshot of the (possibly shared) table for the
    // whole Phase-1 decision.
    let actions = *proc.sigactions.lock();
    let sig = match crate::signal::select_for_delivery(
        proc.pending_bits(),
        proc.blocked,
        proc.in_signal_handler,
        &actions,
        crate::signal::DeliveryMode::AnyActionable,
    ) {
        Some(signal) => signal,
        None => {
            restore_poll_blocked_locked(&mut proc);
            return SignalTailStep::Done;
        }
    };
    // GAP-5 G7: a group-wide signal moves into this task's own set before
    // the frame is built and committed, so no other member delivers it too.
    if !proc.claim_pending(sig) {
        restore_poll_blocked_locked(&mut proc);
        return SignalTailStep::Done;
    }
    match crate::signal::resolve_disposition(&actions, sig) {
        crate::signal::Disposition::Handler {
            handler,
            flags,
            mask,
        } => {
            // M0 item 5 (1b-2): if THIS syscall blocked-and-resumed, `switch_context`
            // zeroed the per-CPU `frame_ptr`, so the mutable accessor used by Phase 2/3
            // below would fail-closed and DEFER this handler to the next syscall (the
            // 1b-1 gap). Republish the binding snapshotted at entry — owner-re-validated
            // by the accessor — so delivery lands at the SAME return as the EINTR wake.
            // ONE republish (still under this Phase-1 lock) covers BOTH the Phase-2
            // snapshot and the Phase-3 commit because nothing between here and the commit
            // reschedules or re-zeroes the slot: `copy_to_user` does not block/switch
            // (its SMAP windows only briefly re-enable IRQs, and a fault is ex-table
            // fixed-up to EFAULT), and kernel-mode is not timer-preempted. INVARIANT FOR
            // FUTURE EDITS: if kernel-mode preemption OR a blocking usercopy path is ever
            // added, republish again immediately before the Phase-3 commit below.
            if is_valid_frame_binding(proc.saved_frame_ptr, proc.saved_frame_owner, pid) {
                publish_syscall_frame_binding(proc.saved_frame_ptr, proc.saved_frame_owner);
            }
            // R172-P6-F1: recompute the sigaction index from the selected signal (the
            // former `bit` local was folded into select_lowest_deliverable).
            let delivered_action = actions[(sig.as_u8() - 1) as usize];
            let restorer = delivered_action.restorer;
            SignalTailStep::Handler {
                sig,
                handler,
                restorer,
                sa_mask: mask,
                sa_flags: flags,
                old_blocked: proc.blocked,
                delivered_action,
            }
        }
        crate::signal::Disposition::Ignored => {
            // (race: reset to SIG_IGN after queueing.) Drop the bit and stop.
            proc.consume_own_pending(sig);
            restore_poll_blocked_locked(&mut proc);
            SignalTailStep::Done
        }
        crate::signal::Disposition::Default(_) => {
            // (race: reset to SIG_DFL after queueing.) Re-resolve at delivery and
            // apply the default — NEVER build a frame with a handler of 0.
            SignalTailStep::Default(sig)
        }
    }
}

/// Complete any unlocked Phase 2/3 signal delivery or pending-kill/default step
/// returned by [`maybe_deliver_signal_phase1`].
#[cold]
pub(super) fn finish_signal_tail_step(
    pid: ProcessId,
    result: i64,
    proc_arc: crate::process::ProcessArc,
    step: SignalTailStep,
) {
    let (sig, handler, restorer, sa_mask, sa_flags, old_blocked, delivered_action) = match step {
        SignalTailStep::Done | SignalTailStep::ExecHandoff => return,
        SignalTailStep::Exit(exit_code) => {
            drop(proc_arc);
            terminate_self_and_halt(pid, exit_code);
        }
        SignalTailStep::PendingKill => {
            // The PCB reference must not outlive the abandoned stack.
            drop(proc_arc);
            if let Some(code) = crate::process::take_pending_process_exit(pid) {
                terminate_self_and_halt(pid, code);
            }
            poll_restore_sigmask_tail(pid);
            return;
        }
        SignalTailStep::Default(sig) => {
            drop(proc_arc);
            apply_default_at_safepoint(pid, sig); // may not return
            poll_restore_sigmask_tail(pid);
            return;
        }
        SignalTailStep::Handler {
            sig,
            handler,
            restorer,
            sa_mask,
            sa_flags,
            old_blocked,
            delivered_action,
        } => (
            sig,
            handler,
            restorer,
            sa_mask,
            sa_flags,
            old_blocked,
            delivered_action,
        ),
    };

    // Phase 2 (NO lock held — faultable copy_to_user; heap-free in-place staging,
    // D1RES-R1): snapshot the interrupted context + FXSAVE, build the sigframe, copy
    // it to the user stack.
    let snap = with_current_syscall_frame_mut(pid, |frame, fx| {
        // The SYSCALL path saved user RIP into RCX and user RFLAGS into R11.
        let ctx = crate::signal_frame::SavedUserContext {
            rax: result as u64,
            rbx: frame.rbx,
            rcx: frame.rcx,
            rdx: frame.rdx,
            rsi: frame.rsi,
            rdi: frame.rdi,
            rbp: frame.rbp,
            rsp: frame.rsp,
            r8: frame.r8,
            r9: frame.r9,
            r10: frame.r10,
            r11: frame.r11,
            r12: frame.r12,
            r13: frame.r13,
            r14: frame.r14,
            r15: frame.r15,
            rip: frame.rcx,    // user RIP
            rflags: frame.r11, // user RFLAGS
        };
        let mut fxcopy = [0u8; 512];
        fxcopy.copy_from_slice(&fx[..]);
        (ctx, fxcopy)
    });
    // None => stale frame_ptr (this syscall blocked-and-resumed) => DEFER delivery to
    // the next non-blocking return; pending bit and blocked mask untouched.
    let (ctx, mut fxcopy) = match snap {
        Some(s) => s,
        None => {
            restore_poll_blocked_locked(&mut proc_arc.lock());
            return;
        }
    };
    crate::signal_frame::sanitize_fxsave_for_export(&mut fxcopy);

    // RF178-34 FIX: carry stack provenance through layout and backing. This
    // prevents a low mmap-backed thread stack from entering main-stack growth.
    let stack = match main_sigframe_stack(ctx.rsp) {
        Some(main) => main,
        None => {
            let proc = proc_arc.lock();
            let mm = proc.mm.lock();
            locate_sigframe_vma(ctx.rsp, &mm.mmap_regions)
        }
    };
    let layout =
        match crate::signal_frame::compute_sigframe_layout(ctx.rsp, stack.layout_floor(ctx.rsp)) {
            Ok(l) => l,
            // No room for the frame on the user stack: fatal SIGSEGV (Linux force_sigsegv).
            // GAP-5 review: no PCB reference may outlive the abandoned stack.
            Err(_) => {
                drop(proc_arc);
                crate::process::terminate_group_self_and_halt(pid, 139)
            }
        };
    // D1RES-R1: heap-free staging — assembled in place into a kernel-stack buffer
    // (assemble_sigframe zero-fills it; the zero fill is load-bearing). Removes the
    // former fallible heap alloc + its OOM-kill-on-delivery leg from this path.
    let mut buf = [0u8; crate::signal_frame::SIGFRAME_SIZE];
    if crate::signal_frame::assemble_sigframe(
        &layout,
        &ctx,
        &fxcopy,
        sig.as_u8() as u32,
        handler,
        restorer,
        &mut buf,
    )
    .is_err()
    {
        // Corrupt layout (len mismatch) — same fatal disposition as a failed layout.
        drop(proc_arc);
        crate::process::terminate_group_self_and_halt(pid, 139);
    }
    // M0-7 SLICE 5: PRE-GROW the user stack to back the sigframe write
    // (Ring-0 writer #1 of 3). The sigframe writes to [frame_base, rsp), which may
    // land in the lazy region. Pre-grow ensures the pages are mapped BEFORE the
    // copy_to_user. If pre-grow fails (OOM / over-limit), kill with SIGSEGV.
    if stack.needs_main_stack_backing(
        layout.frame_base,
        crate::elf_loader::user_stack_mapped_floor(),
    ) {
        if ensure_stack_backed(pid, layout.frame_base as usize).is_err() {
            drop(proc_arc);
            crate::process::terminate_group_self_and_halt(pid, 139);
        }
    }
    // A copy_to_user fault (unmapped / over-grown stack) is fatal SIGSEGV — NEVER
    // EFAULT back into the interrupted context, and NEVER a catchable SIGSEGV here
    // (that would recurse). The pending bit is still set; we do not return.
    if copy_to_user(layout.frame_base as *mut u8, &buf).is_err() {
        drop(proc_arc);
        crate::process::terminate_group_self_and_halt(pid, 139);
    }

    // Phase 3: COMMIT — redirect the live frame to the handler. Only AFTER this
    // succeeds do we mutate the PCB (clear pending, raise the blocked mask, mark
    // in-handler), so a failed frame mutation leaves pending/blocked untouched.
    let committed = with_current_syscall_frame_mut(pid, |frame, _fx| {
        frame.rcx = handler; // user RIP (SYSRET reads RCX)
        frame.rsp = layout.frame_base; // handler entry RSP (%16 == 8)
        frame.rdi = sig.as_u8() as u64; // arg0 = signum
        frame.rsi = layout.siginfo_va; // arg1 = &siginfo
        frame.rdx = layout.uc_va; // arg2 = &ucontext
                                  // Handler-entry RFLAGS: sanitize the interrupted flags (clear DF/TF/IOPL,
                                  // force IF). The ORIGINAL flags are saved into the sigframe's mcontext.EFLAGS.
        frame.r11 = crate::signal_frame::sanitize_user_rflags(ctx.rflags);
    });
    if committed.is_none() {
        // The frame vanished between build and commit (must not happen at the tail):
        // the sigframe bytes are on the user stack but control flow is unchanged, so
        // there is no delivery; the pending bit stays set for a later attempt.
        restore_poll_blocked_locked(&mut proc_arc.lock());
        return;
    }

    let retarget = {
        let mut proc = proc_arc.lock();
        proc.consume_own_pending(sig);
        // M0-6 poll/select: if a ppoll/pselect6 left its ORIGINAL mask stashed
        // (temp mask still live so THIS signal became deliverable), that original
        // mask — not the live temp mask (`old_blocked`) — is what rt_sigreturn must
        // restore. Consume the stash so the dispatcher-tail restore is a no-op.
        // Behavior-identical (`old_blocked`) when no stash is pending.
        let restore_base = proc.poll_restore_blocked.take().unwrap_or(old_blocked);
        proc.saved_blocked = restore_base;
        let mut newmask = old_blocked | sa_mask;
        if sa_flags & crate::signal::SA_NODEFER == 0 {
            newmask |= sig.bit();
        }
        proc.blocked = newmask & !crate::signal::uncatchable_mask();
        // INVARIANT FOR FUTURE EDITS (M0-7 SLICE 3b FIX B): The IRQ-return delivery
        // hook in arch/interrupts.rs (timer_interrupt_body) relies on this entire
        // Phase 2/3 signal-frame build completing at Ring-0 with no SYSRET-to-user
        // before in_signal_handler is set. If any blocking/rescheduling operation is
        // added between Phase 2 start and this commit, the IRQ hook would need an
        // additional interlock (e.g. an atomic flag) to prevent double-delivery.
        proc.in_signal_handler = true;
        // SA_RESETHAND (Codex review): a one-shot handler resets to SIG_DFL after
        // this single delivery; the next occurrence takes the default action.
        // GAP-5: reset only the disposition this delivery used; a sibling's
        // rt_sigaction installed during the unlocked Phase 2 must survive.
        if sa_flags & crate::signal::SA_RESETHAND != 0 {
            proc.sigactions
                .reset_if_unchanged((sig.as_u8() - 1) as usize, delivered_action);
        }
        // GAP-5 G7 (review D3): the handler's mask may block group signals
        // this task was chosen for; another member takes them over.
        proc.recalc_shared_signals(false)
            .then(|| Arc::clone(&proc.thread_group))
    };
    if let Some(group) = retarget {
        crate::process::retarget_shared_signals(pid, &group);
    }

    // smp-toctou: a SIGKILL could have raced in during the interrupt-enabled build
    // window. Re-check the pending-kill flag AFTER commit — SIGKILL still wins.
    drop(proc_arc);
    if let Some(code) = crate::process::take_pending_process_exit(pid) {
        terminate_self_and_halt(pid, code);
    }
}

// ────────────────────────────────────────────────────────────────────────────────
// M0-7 SLICE 3b: IRQ-context preemptive signal delivery
// ────────────────────────────────────────────────────────────────────────────────

/// Resolve stack provenance on IRQ return without blocking. Lock contention is
/// unlocatable/fail-closed; the shared locator performs no allocation.
pub(super) fn resolve_sigframe_stack_irq(
    rsp: u64,
    proc: &crate::process::Process,
) -> crate::signal_frame::SigframeStack {
    if let Some(main) = main_sigframe_stack(rsp) {
        return main;
    }
    match proc.mm.try_lock() {
        Some(mm) => locate_sigframe_vma(rsp, &mm.mmap_regions),
        None => crate::signal_frame::SigframeStack::Unlocatable,
    }
}

/// M0-7 SLICE 3b: FPU state helpers for IRQ signal delivery.
pub fn default_fxsave_area() -> [u8; 512] {
    let mut area = [0u8; 512];
    // FCW (bytes 0..2) = 0x037F (x87 default control word)
    area[0] = 0x7F;
    area[1] = 0x03;
    // MXCSR (bytes 24..28) = 0x1F80 (SSE default)
    area[24] = 0x80;
    area[25] = 0x1F;
    // All XMM registers and x87 stack = zero (already zeroed by [0u8; 512])
    area
}

pub fn sanitize_fxsave_for_export(area: &mut [u8; 512]) {
    // Zero the reserved tail (bytes 416..512) to prevent kernel info leak.
    for i in 416..512 {
        area[i] = 0;
    }
}

// R188-U09-1 FIX: Keep the IRQ-return handler-entry flags on the same sanitizer
// as the syscall-return path.  The second predicate is intentionally separate
// defense-in-depth: if a future edit weakens `sanitize_user_rflags`, the IRQ
// path fails closed instead of redirecting Ring 3 with TF/DF still set.
#[inline]
pub(super) fn sanitize_irq_handler_rflags(raw: u64) -> Option<u64> {
    let sanitized = crate::signal_frame::sanitize_user_rflags(raw);
    crate::signal_frame::is_safe_handler_entry_rflags(sanitized).then_some(sanitized)
}

/// R188-U09-1 regression guard for the IRQ-return signal-entry contract.
///
/// This pure test exercises the exact helper used by the timer-IRQ redirect,
/// rather than only testing the lower-level sanitizer.  A dirty interrupted
/// context must enter the handler with IF set and IOPL/TF/DF cleared; an unsafe
/// post-sanitization value must be rejected by the fail-closed predicate.
pub fn run_irq_signal_delivery_self_test() {
    const CF: u64 = 1u64 << 0;
    const TF: u64 = 1u64 << 8;
    const DF: u64 = 1u64 << 10;
    const IF: u64 = 1u64 << 9;
    const IOPL: u64 = 3u64 << 12;

    let dirty = CF | TF | DF | IOPL;
    let clean = sanitize_irq_handler_rflags(dirty)
        .expect("R188-U09-1: shared IRQ handler RFLAGS sanitizer rejected clean output");
    assert_eq!(clean, crate::signal_frame::sanitize_user_rflags(dirty));
    assert_eq!(clean & IF, IF, "R188-U09-1: handler entry must force IF");
    assert_eq!(
        clean & (TF | DF | IOPL),
        0,
        "R188-U09-1: handler entry must clear TF/DF/IOPL"
    );
    assert_eq!(
        clean & CF,
        CF,
        "R188-U09-1: ordinary user flags stay intact"
    );
    assert!(
        crate::signal_frame::is_safe_handler_entry_rflags(clean),
        "R188-U09-1: sanitized IRQ handler flags must pass the safety predicate"
    );
    assert!(
        !crate::signal_frame::is_safe_handler_entry_rflags(IF | TF | DF),
        "R188-U09-1: TF/DF in a redirect target must fail closed"
    );
    assert!(
        !crate::signal_frame::is_safe_handler_entry_rflags(0),
        "R188-U09-1: a redirect target without IF must fail closed"
    );
    assert!(
        !crate::signal_frame::is_safe_handler_entry_rflags(IF | IOPL),
        "R188-U09-1: privileged IOPL bits must fail closed"
    );
}

/// M0-7 SLICE 3b: Attempt to deliver a handler signal on IRQ return to Ring-3.
///
/// This is the IRQ-context sibling of `maybe_deliver_signal`. It uses an
/// all-try_lock call graph (FIX A) to avoid cross-CPU deadlock, and defers
/// on any contention or error.
///
/// Returns:
/// - `Some((handler_rip, handler_rsp, new_rflags))` if delivery succeeded
///   (the caller redirects the interrupted context to the handler entry)
/// - `None` if delivery was deferred (the caller proceeds with the original return)
pub fn try_deliver_signal_on_irq_return(
    pid: u64,
    interrupted_rip: u64,
    interrupted_rsp: u64,
    interrupted_rflags: u64,
    interrupted_rax: u64,
    interrupted_rbx: u64,
    interrupted_rcx: u64,
    interrupted_rdx: u64,
    interrupted_rsi: u64,
    interrupted_rdi: u64,
    interrupted_rbp: u64,
    interrupted_r8: u64,
    interrupted_r9: u64,
    interrupted_r10: u64,
    interrupted_r11: u64,
    interrupted_r12: u64,
    interrupted_r13: u64,
    interrupted_r14: u64,
    interrupted_r15: u64,
    fpu_state: &[u8; 512],
) -> Option<(u64, u64, u64)> {
    // FIX A: try_get_process instead of blocking get_process.
    let proc_arc = match crate::process::try_get_process(pid as usize) {
        Some(Some(arc)) => arc,
        Some(None) => return None, // Process exists but is being cleaned up
        None => {
            // PROCESS_TABLE lock contended — defer.
            crate::request_resched_from_irq();
            return None;
        }
    };

    // FIX A: try_lock instead of blocking .lock().
    let mut proc_guard = match proc_arc.try_lock() {
        Some(g) => g,
        None => {
            // Process lock contended — defer.
            crate::request_resched_from_irq();
            return None;
        }
    };

    // R188-U09-2 FIX: snapshot only the state needed for frame construction,
    // perform the non-faulting stack classification while the PCB/MM lock order
    // is established, then release the PCB lock before frame assembly and
    // faultable usercopy.  Holding a spin::Mutex guard over copy_to_user lets a
    // page fault/SMAP window retain a non-IRQ-safe lock and can deadlock a
    // nested exception or another CPU's signal/exit path.
    //
    // The generation, disposition, blocked mask, and pending bit are checked
    // again at commit below.  A concurrent state change therefore causes a
    // fail-closed defer; it can never redirect a stale handler or overwrite a
    // newer signal mask.
    let (sig, sa, old_blocked, generation, stack, mm) = {
        // RF178-35 FIX: fatal exit dominates handler delivery. This closes the
        // race after the timer's initial pending-exit transaction.
        if proc_guard
            .pending_kill
            .load(core::sync::atomic::Ordering::Acquire)
        {
            return None;
        }
        if proc_guard.pid as u64 != pid {
            return None; // Stale table/PCB identity — fail closed.
        }
        if matches!(
            proc_guard.state,
            ProcessState::Zombie | ProcessState::Terminated
        ) {
            return None; // Lifecycle teardown wins over signal-frame construction.
        }
        if proc_guard.in_signal_handler {
            return None; // Already in a handler — no nested delivery.
        }
        if proc_guard.exec_in_progress {
            return None; // Exec in flight — defer.
        }

        // GAP-5: IRQ context never spins on the (possibly shared) disposition
        // table; a sibling holding it in process context defers delivery.
        let Some(actions) = proc_guard.sigactions.try_snapshot() else {
            crate::request_resched_from_irq();
            return None;
        };
        let sig = match crate::signal::select_for_delivery(
            proc_guard.pending_bits() & !crate::signal::uncatchable_mask(),
            proc_guard.blocked,
            proc_guard.in_signal_handler,
            &actions,
            crate::signal::DeliveryMode::HandlerOnly,
        ) {
            Some(signal) => signal,
            None => return None,
        };
        let index = (sig.as_u8() - 1) as usize;
        let sa = actions[index];

        // The IRQ hook is a handler-only fast path.  Default/ignored signals
        // stay on the normal safe-point path, where their default action or
        // pending-bit cleanup is applied with the full syscall context.
        if !sa.is_handler() {
            return None;
        }
        // GAP-5 G7: take a group-wide signal into this task's own set before
        // the frame is built; another member that already took it delivers it.
        if !proc_guard.claim_pending(sig) {
            return None;
        }

        let stack = resolve_sigframe_stack_irq(interrupted_rsp, &proc_guard);
        let mm = Arc::clone(&proc_guard.mm);
        (
            sig,
            sa,
            proc_guard.blocked,
            proc_guard.generation,
            stack,
            mm,
        )
    };
    drop(proc_guard);
    let handler = sa.handler;
    let sa_flags = sa.flags;
    let sa_mask = sa.mask;
    let restorer = sa.restorer;

    // Construct SavedUserContext from the interrupted GPRs/ISF.
    // rax = interrupted user RAX (NOT a syscall result).
    let interrupted_ctx = crate::signal_frame::SavedUserContext {
        rax: interrupted_rax,
        rbx: interrupted_rbx,
        rcx: interrupted_rcx,
        rdx: interrupted_rdx,
        rsi: interrupted_rsi,
        rdi: interrupted_rdi,
        rbp: interrupted_rbp,
        rsp: interrupted_rsp,
        r8: interrupted_r8,
        r9: interrupted_r9,
        r10: interrupted_r10,
        r11: interrupted_r11,
        r12: interrupted_r12,
        r13: interrupted_r13,
        r14: interrupted_r14,
        r15: interrupted_r15,
        rip: interrupted_rip,
        rflags: interrupted_rflags,
    };

    // R188-U09-1 FIX: Both signal-entry paths use the canonical sanitizer.  Keep
    // the safety check before any user-visible state mutation so a future
    // sanitizer regression defers this attempt rather than committing a bad
    // handler frame.
    let new_rflags = match sanitize_irq_handler_rflags(interrupted_rflags) {
        Some(flags) => flags,
        None => {
            crate::request_resched_from_irq();
            return None;
        }
    };

    // Compute the layout.
    let layout = match crate::signal_frame::compute_sigframe_layout(
        interrupted_rsp,
        stack.layout_floor(interrupted_rsp),
    ) {
        Ok(l) => l,
        Err(_) => return None, // Layout computation failed — defer.
    };

    // Build the signal frame.
    // D1RES-R1: heap-free in-place staging — also removes the former fallible heap
    // alloc performed while HOLDING the proc_arc try_lock guard (FIX A graph),
    // restoring the no-alloc-under-spinlock rule on this path.
    let mut frame_bytes = [0u8; crate::signal_frame::SIGFRAME_SIZE];
    if crate::signal_frame::assemble_sigframe(
        &layout,
        &interrupted_ctx,
        fpu_state,
        sig.as_u8() as u32,
        handler,
        restorer,
        &mut frame_bytes,
    )
    .is_err()
    {
        return None; // Corrupt layout — defer (disposition unchanged).
    }

    let frame_base = layout.frame_base;

    // M0-7 SLICE 5: PRE-GROW the user stack to back the IRQ sigframe write
    // (Ring-0 writer #3 of 3). If frame_base is in the lazy region, grow it first.
    // Use try_lock variant since we're in IRQ context.
    if stack.needs_main_stack_backing(frame_base, crate::elf_loader::user_stack_mapped_floor()) {
        // Try to grow the stack to cover the frame
        let target_floor = (frame_base as usize) & !(PAGE_SIZE - 1);

        // Check if we need to grow (R173-01 FIX: try_lock for IRQ safety).
        // `mm` is the Arc snapshot taken before the PCB guard was released;
        // no Process lock is held while probing it.
        let need_grow = {
            let mm = match mm.try_lock() {
                Some(mm) => mm,
                None => return None, // mm lock contended - defer signal delivery
            };
            target_floor < mm.stack_floor_committed
        };

        if need_grow {
            // Can't call try_grow_user_stack from IRQ context with locks held
            // Defer the signal delivery — it will retry on next tick
            return None;
        }
    }

    // R188-U09-2 FIX: Write the frame to user memory only after the PCB guard
    // has been dropped above. `copy_to_user_addr` is faultable and its SMAP
    // guard owns the IRQ-state window; never move it back under `proc_arc.lock`.
    // Err → DEFER (NOT terminate).
    if crate::usercopy::copy_to_user_addr(
        crate::usercopy::UserAddr::new(frame_base as usize),
        &frame_bytes,
    )
    .is_err()
    {
        return None; // Fault on write — defer.
    }

    // Commit the delivery under a fresh lock.  The frame was built and copied
    // with no PCB guard held, so this lock is a short metadata transaction only.
    // FIX A: Use try_lock to avoid deadlock if another CPU holds the Process lock.
    let mut proc = match proc_arc.try_lock() {
        Some(g) => g,
        None => {
            // Commit contended — defer entire delivery.
            // The signal frame was written to user memory, but we haven't committed
            // the delivery state yet. On the next timer tick, we'll retry delivery
            // of the same signal (idempotent: same signal → same frame at same RSP).
            // The user-visible frame write is safe: if the process doesn't enter the
            // handler this tick, it will on the next tick when we successfully commit.
            crate::request_resched_from_irq();
            return None;
        }
    };
    let index = (sig.as_u8() - 1) as usize;
    let stack_still_matches = resolve_sigframe_stack_irq(interrupted_rsp, &proc) == stack;
    // GAP-5: hold the table (try-locked; IRQ context) across the recheck and
    // the SA_RESETHAND commit so a sibling's rt_sigaction cannot interleave.
    let sigactions = Arc::clone(&proc.sigactions);
    let Some(mut actions) = sigactions.try_lock() else {
        drop(proc);
        crate::request_resched_from_irq();
        return None;
    };
    let snapshot_still_valid = proc.pid as u64 == pid
        && proc.generation == generation
        && !matches!(proc.state, ProcessState::Zombie | ProcessState::Terminated)
        && !proc
            .pending_kill
            .load(core::sync::atomic::Ordering::Acquire)
        && !proc.in_signal_handler
        && !proc.exec_in_progress
        && proc.pending_signals.is_pending(sig)
        && proc.blocked == old_blocked
        && actions[index] == sa
        && stack_still_matches;
    if !snapshot_still_valid {
        drop(actions);
        // R188-U09-2 FIX: The usercopy completed against a snapshot that is no
        // longer authoritative.  Never redirect with stale signal metadata;
        // leave the pending state untouched and retry at a later IRQ/safe point.
        drop(proc);
        crate::request_resched_from_irq();
        return None;
    }
    // The mask raised below may block group signals this task was chosen
    // for; its next syscall return hands them on (`recalc_shared_signals`),
    // since the IRQ path cannot take PROCESS_TABLE.
    proc.consume_own_pending(sig);
    proc.saved_blocked = old_blocked;
    let mut newmask = old_blocked | sa_mask;
    if sa_flags & crate::signal::SA_NODEFER == 0 {
        newmask |= sig.bit();
    }
    proc.blocked = newmask & !crate::signal::uncatchable_mask();
    proc.in_signal_handler = true;
    if sa_flags & crate::signal::SA_RESETHAND != 0 {
        actions[index] = crate::signal::SigAction::default_action();
        drop(actions);
        sigactions.note_mutation();
    } else {
        drop(actions);
    }
    drop(proc);
    // The PCB still owns a reference, so this is never the final drop.
    drop(sigactions);

    // Return the redirect target: (handler RIP, frame_base RSP, sanitized RFLAGS).
    Some((handler, frame_base, new_rflags))
}
