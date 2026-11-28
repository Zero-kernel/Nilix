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
    kill_common(pid, sig, KillTarget::Process, None)
}

/// tkill(2). musl's raise() uses it with the caller's own tid.
pub(super) fn sys_tkill(tid: i32, sig: i32) -> SyscallResult {
    if tid <= 0 {
        return Err(SyscallError::EINVAL);
    }
    kill_common(tid as ProcessId, sig, KillTarget::Thread, None)
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
        None,
    )
}

/// rt_sigqueueinfo(2) — queue a signal + siginfo_t payload to a thread group (129).
pub(super) fn sys_rt_sigqueueinfo(tgid: i32, sig: i32, uinfo: *const u8) -> SyscallResult {
    if uinfo.is_null() {
        return Err(SyscallError::EFAULT);
    }
    let mut raw = [0u8; 128];
    copy_from_user(&mut raw, uinfo)?;
    if tgid <= 0 {
        return Err(SyscallError::EINVAL);
    }
    let info = crate::signal::SigInfo::from_wire_bytes(sig, &raw);
    kill_common(tgid as ProcessId, sig, KillTarget::Process, Some(info))
}

/// rt_tgsigqueueinfo(2) — queue a signal + siginfo_t payload to a specific thread (297).
pub(super) fn sys_rt_tgsigqueueinfo(
    tgid: i32,
    tid: i32,
    sig: i32,
    uinfo: *const u8,
) -> SyscallResult {
    if uinfo.is_null() {
        return Err(SyscallError::EFAULT);
    }
    let mut raw = [0u8; 128];
    copy_from_user(&mut raw, uinfo)?;
    if tgid <= 0 || tid <= 0 {
        return Err(SyscallError::EINVAL);
    }
    let info = crate::signal::SigInfo::from_wire_bytes(sig, &raw);
    kill_common(
        tid as ProcessId,
        sig,
        KillTarget::ThreadInGroup(tgid as ProcessId),
        Some(info),
    )
}

/// Shared authorization and delivery for kill, tkill, tgkill, rt_sigqueueinfo,
/// and rt_tgsigqueueinfo. Every check below (namespace translation, init
/// protection, POSIX/user-namespace permission, LSM) applies uniformly.
pub(super) fn kill_common(
    pid: ProcessId,
    sig: i32,
    mode: KillTarget,
    explicit_info: Option<crate::signal::SigInfo>,
) -> SyscallResult {
    use crate::signal::{
        send_signal, send_signal_queueinfo, send_signal_tgsigqueueinfo, send_signal_thread,
        signal_name, Signal,
    };

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

    // Linux rt_sigqueueinfo(2) / rt_tgsigqueueinfo(2) anti-spoofing rule:
    // a caller may not send si_code >= 0 or SI_TKILL to another process.
    if let Some(info) = explicit_info {
        if self_tgid != target_tgid && (info.code >= 0 || info.code == crate::signal::SI_TKILL) {
            return Err(SyscallError::EPERM);
        }
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
    let _action = match (mode, explicit_info) {
        (KillTarget::Process, None) => send_signal(target_global_pid, signal)?,
        (KillTarget::Process, Some(info)) => {
            send_signal_queueinfo(target_global_pid, signal, info)?
        }
        (KillTarget::Thread | KillTarget::ThreadInGroup(_), None) => {
            send_signal_thread(target_global_pid, signal)?
        }
        (KillTarget::Thread | KillTarget::ThreadInGroup(_), Some(info)) => {
            send_signal_tgsigqueueinfo(target_global_pid, signal, info)?
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

// ============================================================================
// N2.6a: Extended POSIX / Linux RT signal syscalls
// (`rt_sigpending`, `rt_sigsuspend`, `rt_sigtimedwait`, `sigaltstack`, `SA_RESTART`)
// ============================================================================

/// sys_rt_sigpending - examine pending signals for the calling thread/process (127).
pub(super) fn sys_rt_sigpending(set: *mut u8, sigsetsize: usize) -> SyscallResult {
    if sigsetsize != LINUX_KERNEL_SIGSET_SIZE {
        return Err(SyscallError::EINVAL);
    }
    if set.is_null() {
        return Err(SyscallError::EFAULT);
    }
    verify_user_memory(set as *const u8, LINUX_KERNEL_SIGSET_SIZE, true)?;

    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let proc_arc = get_process(pid).ok_or(SyscallError::ESRCH)?;
    let pending = proc_arc.lock().pending_bits();
    copy_to_user(set, &pending.to_ne_bytes())?;
    Ok(0)
}

/// sys_rt_sigsuspend - atomically replace the signal mask and wait for a signal (130).
///
/// Reuses the `poll_restore_blocked` (TIF_RESTORE_SIGMASK) contract: the temporary
/// mask stays active across the syscall-return safe point so the interrupting
/// handler is delivered under it while `saved_blocked` records the caller's
/// original mask (restored by `rt_sigreturn`). Always returns `EINTR` and is
/// never restarted by `SA_RESTART`.
pub(super) fn sys_rt_sigsuspend(unewset: *const u8, sigsetsize: usize) -> SyscallResult {
    if sigsetsize != LINUX_KERNEL_SIGSET_SIZE {
        return Err(SyscallError::EINVAL);
    }
    if unewset.is_null() {
        return Err(SyscallError::EFAULT);
    }
    let mut b = [0u8; LINUX_KERNEL_SIGSET_SIZE];
    copy_from_user(&mut b, unewset)?;
    let temp_mask = u64::from_ne_bytes(b);

    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let proc_arc = get_process(pid).ok_or(SyscallError::ESRCH)?;

    let (old_mask, retarget) = {
        let mut p = proc_arc.lock();
        let old = p.blocked;
        p.blocked = crate::signal::apply_sigprocmask(old, SIG_SETMASK, temp_mask);
        let retarget = p
            .recalc_shared_signals(true)
            .then(|| Arc::clone(&p.thread_group));
        (old, retarget)
    };
    if let Some(group) = retarget {
        crate::process::retarget_shared_signals(pid, &group);
    }

    loop {
        if wait_should_abort(pid) || crate::signal::has_deliverable_signal(pid) {
            break;
        }
        crate::reschedule_if_needed();
        debug_assert!(
            x86_64::instructions::interrupts::are_enabled(),
            "rt_sigsuspend wait loop must hlt with IRQs enabled"
        );
        unsafe {
            core::arch::asm!("hlt", options(nomem, nostack, preserves_flags));
        }
    }

    let retarget_after = {
        let mut p = proc_arc.lock();
        if crate::signal::has_deliverable_signal_locked(&p) {
            p.poll_restore_blocked = Some(old_mask);
            None
        } else {
            p.blocked = old_mask & !crate::signal::uncatchable_mask();
            p.recalc_shared_signals(false)
                .then(|| Arc::clone(&p.thread_group))
        }
    };
    if let Some(group) = retarget_after {
        crate::process::retarget_shared_signals(pid, &group);
    }

    Err(SyscallError::EINTR)
}

/// sys_rt_sigtimedwait - synchronously wait for and consume a queued signal (128).
///
/// Consumes any pending signal matching `*uthese` (even if blocked), writes its
/// 128-byte `siginfo_t` to `uinfo` when non-null, and returns the signal number.
/// Never restarted by `SA_RESTART`.
pub(super) fn sys_rt_sigtimedwait(
    uthese: *const u8,
    uinfo: *mut u8,
    uts: *const u8,
    sigsetsize: usize,
) -> SyscallResult {
    if sigsetsize != LINUX_KERNEL_SIGSET_SIZE {
        return Err(SyscallError::EINVAL);
    }
    if uthese.is_null() {
        return Err(SyscallError::EFAULT);
    }
    let mut mask_bytes = [0u8; LINUX_KERNEL_SIGSET_SIZE];
    copy_from_user(&mut mask_bytes, uthese)?;
    // Linux do_sigtimedwait strips SIGKILL and SIGSTOP from the wait set.
    let these = u64::from_ne_bytes(mask_bytes) & !crate::signal::uncatchable_mask();

    if !uinfo.is_null() {
        verify_user_memory(uinfo as *const u8, 128, true)?;
    }

    const NS_PER_MS: u64 = 1_000_000;
    let timeout_ms: Option<u64> = if !uts.is_null() {
        let mut ts = TimeSpec::default();
        // lint-repr-c-copy: allow (no-padding: TimeSpec {i64,i64} = 16 bytes; user→kernel)
        let ts_bytes = unsafe {
            core::slice::from_raw_parts_mut(
                &mut ts as *mut TimeSpec as *mut u8,
                core::mem::size_of::<TimeSpec>(),
            )
        };
        crate::usercopy::copy_from_user_safe(ts_bytes, uts).map_err(|_| SyscallError::EFAULT)?;
        if ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= 1_000_000_000 {
            return Err(SyscallError::EINVAL);
        }
        let total_ns = (ts.tv_sec as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(ts.tv_nsec as u64);
        let ms = if total_ns == 0 {
            0
        } else {
            (total_ns / NS_PER_MS)
                .saturating_add(if total_ns % NS_PER_MS != 0 { 1 } else { 0 })
                .max(1)
        };
        Some(ms)
    } else {
        None
    };

    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let proc_arc = get_process(pid).ok_or(SyscallError::ESRCH)?;
    let start = crate::time::get_ticks();

    loop {
        let outcome = {
            let mut proc = proc_arc.lock();
            if let Some((sig, info)) = proc.take_pending_for_sigwait(these) {
                Ok(Some((sig, info)))
            } else {
                let actions = proc.sigactions.lock();
                let other_deliverable = crate::signal::select_for_delivery(
                    proc.wait_pending_bits() & !these & !crate::signal::uncatchable_mask(),
                    proc.blocked,
                    proc.in_signal_handler,
                    &actions,
                    crate::signal::DeliveryMode::AnyActionable,
                )
                .is_some();
                if other_deliverable {
                    Err(SyscallError::EINTR)
                } else {
                    Ok(None)
                }
            }
        };

        match outcome {
            Ok(Some((sig, info))) => {
                if !uinfo.is_null() {
                    let mut wire = [0u8; 128];
                    info.write_wire_bytes(&mut wire);
                    copy_to_user(uinfo, &wire)?;
                }
                return Ok(sig.as_u8() as usize);
            }
            Err(e) => return Err(e),
            Ok(None) => {}
        }

        if wait_should_abort(pid) {
            return Err(SyscallError::EINTR);
        }

        match timeout_ms {
            Some(0) => return Err(SyscallError::EAGAIN),
            Some(t) if crate::time::get_ticks().saturating_sub(start) >= t => {
                return Err(SyscallError::EAGAIN);
            }
            _ => {}
        }

        crate::reschedule_if_needed();
        debug_assert!(
            x86_64::instructions::interrupts::are_enabled(),
            "rt_sigtimedwait wait loop must hlt with IRQs enabled"
        );
        unsafe {
            core::arch::asm!("hlt", options(nomem, nostack, preserves_flags));
        }
    }
}

/// Pure validator/updater for `sigaltstack(2)` (unit-testable without a live PCB).
pub(super) fn apply_sigaltstack_update(
    current: crate::signal::SigAltStack,
    user_rsp: u64,
    new_req: Option<StackT>,
) -> Result<(crate::signal::SigAltStack, StackT), SyscallError> {
    use crate::signal::{SigAltStack, MINSIGSTKSZ, SS_DISABLE};

    let on_stack = current.on_stack(user_rsp);
    let (old_sp, old_flags, old_size) = current.as_stack_t_fields(user_rsp);
    let old_stack = StackT {
        ss_sp: old_sp,
        ss_flags: old_flags as i32,
        _pad: 0,
        ss_size: old_size as usize,
    };

    let next = match new_req {
        None => current,
        Some(req) => {
            if on_stack {
                return Err(SyscallError::EPERM);
            }
            if req.ss_flags != 0 && req.ss_flags != SS_DISABLE as i32 {
                return Err(SyscallError::EINVAL);
            }
            if req.ss_flags == SS_DISABLE as i32 {
                SigAltStack::disabled()
            } else {
                if req.ss_size < MINSIGSTKSZ {
                    return Err(SyscallError::ENOMEM);
                }
                let end = req
                    .ss_sp
                    .checked_add(req.ss_size as u64)
                    .ok_or(SyscallError::EINVAL)?;
                if req.ss_sp == 0
                    || !crate::signal_frame::is_canonical_user_addr(req.ss_sp)
                    || !crate::signal_frame::is_canonical_user_addr(end - 1)
                {
                    return Err(SyscallError::EINVAL);
                }
                SigAltStack {
                    sp: req.ss_sp,
                    size: req.ss_size as u64,
                    flags: 0,
                }
            }
        }
    };

    Ok((next, old_stack))
}

/// sys_sigaltstack - set and/or get alternate signal stack context (131).
pub(super) fn sys_sigaltstack(ss: *const u8, old_ss: *mut u8) -> SyscallResult {
    let new_req: Option<StackT> = if !ss.is_null() {
        let mut req = StackT::default();
        // lint-repr-c-copy: allow (StackT is 24-byte #[repr(C)] with explicit _pad; user→kernel)
        let bytes = unsafe {
            core::slice::from_raw_parts_mut(
                &mut req as *mut StackT as *mut u8,
                core::mem::size_of::<StackT>(),
            )
        };
        copy_from_user(bytes, ss)?;
        Some(req)
    } else {
        None
    };

    if !old_ss.is_null() {
        verify_user_memory(old_ss as *const u8, core::mem::size_of::<StackT>(), true)?;
    }

    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let proc_arc = get_process(pid).ok_or(SyscallError::ESRCH)?;
    let user_rsp = with_current_syscall_frame(|f| f.rsp).unwrap_or(0);

    let old_stack = {
        let mut proc = proc_arc.lock();
        let (next, old_stack) = apply_sigaltstack_update(proc.sigaltstack, user_rsp, new_req)?;
        proc.sigaltstack = next;
        old_stack
    };

    if !old_ss.is_null() {
        // lint-repr-c-copy: allow (StackT is 24-byte #[repr(C)] with explicit _pad; kernel→user)
        let bytes = unsafe {
            core::slice::from_raw_parts(
                &old_stack as *const StackT as *const u8,
                core::mem::size_of::<StackT>(),
            )
        };
        copy_to_user(old_ss, bytes)?;
    }
    Ok(0)
}

/// Pure Linux `signal(7)` restartability predicate for `SA_RESTART`.
///
/// Only blocking I/O, wait, socket accept/send/recv, and timeout-less
/// `FUTEX_WAIT`/`FUTEX_WAIT_BITSET` restart when returning `EINTR` into an
/// `SA_RESTART` handler. Time-bounded waits (`nanosleep`, `poll`, `ppoll`,
/// `select`, `pselect6`, `rt_sigsuspend`, `rt_sigtimedwait`) and `connect`
/// NEVER restart.
#[inline]
pub(super) fn is_restartable_syscall(syscall_num: u64, args: &[u64; 6]) -> bool {
    use seccomp::syscall_table as st;
    match syscall_num {
        st::SYS_READ
        | st::SYS_WRITE
        | st::SYS_READV
        | st::SYS_WRITEV
        | st::SYS_WAIT4
        | st::SYS_WAITID
        | st::SYS_ACCEPT
        | st::SYS_ACCEPT4
        | st::SYS_SENDTO
        | st::SYS_RECVFROM
        | st::SYS_SENDMSG
        | st::SYS_RECVMSG => true,
        st::SYS_FUTEX => {
            let op = (args[1] as u32) & 0x7f;
            let timeout_ptr = args[3];
            // FUTEX_WAIT (0) or FUTEX_WAIT_BITSET (9) with NULL timeout only.
            (op == 0 || op == 9) && timeout_ptr == 0
        }
        _ => false,
    }
}

/// Choose the target stack top, red-zone policy, and `SigframeStack` provenance
/// for signal delivery, honoring `SA_ONSTACK` + `sigaltstack(2)`.
#[inline]
pub(super) fn choose_altstack_target(
    interrupted_rsp: u64,
    sa_flags: u64,
    altstack: crate::signal::SigAltStack,
) -> Option<(u64, bool, crate::signal_frame::SigframeStack)> {
    if (sa_flags & crate::signal::SA_ONSTACK) == 0 || !altstack.is_enabled() {
        return None;
    }
    let on_main = main_sigframe_stack(altstack.sp).is_some();
    let stack = crate::signal_frame::SigframeStack::AltStack {
        floor: altstack.sp,
        on_main_stack: on_main,
    };
    if altstack.on_stack(interrupted_rsp) {
        // Already running on the alternate signal stack: continue downward from
        // the current RSP within the same altstack bounds (keep red zone).
        Some((interrupted_rsp, true, stack))
    } else {
        // Switch onto the top of the alternate signal stack (no red zone above top).
        altstack.top().map(|top| (top, false, stack))
    }
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
        siginfo: crate::signal::SigInfo,
        altstack: crate::signal::SigAltStack,
        handler: u64,
        restorer: u64,
        sa_mask: u64,
        sa_flags: u64,
        old_blocked: u64,
        uc_sigmask: u64,
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
            let siginfo = proc.peek_own_siginfo(sig);
            let altstack = proc.sigaltstack;
            let uc_sigmask = proc.poll_restore_blocked.unwrap_or(proc.blocked);
            SignalTailStep::Handler {
                sig,
                siginfo,
                altstack,
                handler,
                restorer,
                sa_mask: mask,
                sa_flags: flags,
                old_blocked: proc.blocked,
                uc_sigmask,
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
    restart_nr: Option<u64>,
    proc_arc: crate::process::ProcessArc,
    step: SignalTailStep,
) {
    let (
        sig,
        siginfo,
        altstack,
        handler,
        restorer,
        sa_mask,
        sa_flags,
        old_blocked,
        uc_sigmask,
        delivered_action,
    ) = match step {
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
            siginfo,
            altstack,
            handler,
            restorer,
            sa_mask,
            sa_flags,
            old_blocked,
            uc_sigmask,
            delivered_action,
        } => (
            sig,
            siginfo,
            altstack,
            handler,
            restorer,
            sa_mask,
            sa_flags,
            old_blocked,
            uc_sigmask,
            delivered_action,
        ),
    };

    // Phase 2 (NO lock held — faultable copy_to_user; heap-free in-place staging,
    // D1RES-R1): snapshot the interrupted context + FXSAVE, build the sigframe, copy
    // it to the user stack.
    let snap = with_current_syscall_frame_mut(pid, |frame, fx| {
        // N2.6a SA_RESTART: if a restartable syscall returned EINTR and this
        // handler has SA_RESTART set, rewind RIP by the 2-byte `syscall` (0f 05)
        // instruction and save the original syscall number into RAX so
        // `rt_sigreturn` transparently re-executes the syscall with intact args.
        let should_restart = restart_nr
            .filter(|_| (sa_flags & crate::signal::SA_RESTART) != 0)
            .filter(|_| {
                frame.rcx >= 2 && crate::signal_frame::is_canonical_user_addr(frame.rcx - 2)
            });
        let (saved_rax, saved_rip) = match should_restart {
            Some(nr) => (nr, frame.rcx - 2),
            None => (result as u64, frame.rcx),
        };
        // The SYSCALL path saved user RIP into RCX and user RFLAGS into R11.
        let ctx = crate::signal_frame::SavedUserContext {
            rax: saved_rax,
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
            rip: saved_rip,    // user RIP (or rewound `syscall` for SA_RESTART)
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

    // N2.6a SA_ONSTACK + RF178-34 FIX: honor sigaltstack when SA_ONSTACK is set;
    // otherwise carry normal stack provenance through layout and backing.
    let (target_rsp, skip_red_zone, stack) =
        if let Some(alt) = choose_altstack_target(ctx.rsp, sa_flags, altstack) {
            alt
        } else {
            let s = match main_sigframe_stack(ctx.rsp) {
                Some(main) => main,
                None => {
                    let proc = proc_arc.lock();
                    let mm = proc.mm.lock();
                    locate_sigframe_vma(ctx.rsp, &mm.mmap_regions)
                }
            };
            (ctx.rsp, true, s)
        };
    let layout = match crate::signal_frame::compute_sigframe_layout_with_redzone(
        target_rsp,
        stack.layout_floor(target_rsp),
        skip_red_zone,
    ) {
        Ok(l) => l,
        // No room for the frame on the user stack: fatal SIGSEGV (Linux force_sigsegv).
        // GAP-5 review: no PCB reference may outlive the abandoned stack.
        Err(_) => {
            drop(proc_arc);
            crate::process::terminate_group_self_and_halt(pid, 139)
        }
    };
    // D1RES-R1: heap-free staging — assembled in place into a kernel-stack buffer
    // (assemble_sigframe_full zero-fills it; the zero fill is load-bearing).
    let mut buf = [0u8; crate::signal_frame::SIGFRAME_SIZE];
    if crate::signal_frame::assemble_sigframe_full(
        &layout,
        &ctx,
        &fxcopy,
        &siginfo,
        altstack.as_stack_t_fields(ctx.rsp),
        uc_sigmask,
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
    let (sig, siginfo, altstack, sa, old_blocked, generation, target_rsp, skip_red_zone, stack, mm) = {
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
        // GAP-5 G7 + N2.6a: IRQ-safe non-blocking claim of a group-wide signal.
        if !proc_guard.try_claim_pending_irq(sig) {
            return None;
        }
        let siginfo = proc_guard.peek_own_siginfo(sig);
        let altstack = proc_guard.sigaltstack;
        let (target_rsp, skip_red_zone, stack) =
            if let Some(alt) = choose_altstack_target(interrupted_rsp, sa.flags, altstack) {
                alt
            } else {
                (
                    interrupted_rsp,
                    true,
                    resolve_sigframe_stack_irq(interrupted_rsp, &proc_guard),
                )
            };
        let mm = Arc::clone(&proc_guard.mm);
        (
            sig,
            siginfo,
            altstack,
            sa,
            proc_guard.blocked,
            proc_guard.generation,
            target_rsp,
            skip_red_zone,
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

    // Compute the layout (honoring SA_ONSTACK + sigaltstack when active).
    let layout = match crate::signal_frame::compute_sigframe_layout_with_redzone(
        target_rsp,
        stack.layout_floor(target_rsp),
        skip_red_zone,
    ) {
        Ok(l) => l,
        Err(_) => return None, // Layout computation failed — defer.
    };

    // Build the signal frame.
    // D1RES-R1: heap-free in-place staging — also removes the former fallible heap
    // alloc performed while HOLDING the proc_arc try_lock guard (FIX A graph),
    // restoring the no-alloc-under-spinlock rule on this path.
    let mut frame_bytes = [0u8; crate::signal_frame::SIGFRAME_SIZE];
    if crate::signal_frame::assemble_sigframe_full(
        &layout,
        &interrupted_ctx,
        fpu_state,
        &siginfo,
        altstack.as_stack_t_fields(interrupted_rsp),
        old_blocked,
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
    let stack_still_matches = if let Some((_, _, alt_s)) =
        choose_altstack_target(interrupted_rsp, sa_flags, proc.sigaltstack)
    {
        proc.sigaltstack == altstack && alt_s == stack
    } else {
        proc.sigaltstack == altstack && resolve_sigframe_stack_irq(interrupted_rsp, &proc) == stack
    };
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

#[cfg(test)]
mod n2_6a_signal_tests {
    use super::*;
    use crate::signal::{
        RtSigQueue, SigAltStack, SigInfo, Signal, MAX_QUEUED_RT_SIGNALS, MINSIGSTKSZ, SA_ONSTACK,
        SI_QUEUE, SI_USER, SS_DISABLE, SS_ONSTACK,
    };

    #[test]
    fn n2_6a_rt_sigqueue_fifo_and_bounded_capacity() {
        let sig34 = Signal::from_raw(34).unwrap();
        let sig35 = Signal::from_raw(35).unwrap();
        assert!(sig34.is_realtime());
        assert!(!Signal::SIGUSR1.is_realtime());

        let mut q = RtSigQueue::new();
        for i in 0..MAX_QUEUED_RT_SIGNALS {
            let sig = if i % 2 == 0 { sig34 } else { sig35 };
            let info = SigInfo {
                signo: sig.as_i32(),
                errno: 0,
                code: SI_QUEUE,
                pid: 42,
                uid: 1000,
                value: i as u64,
            };
            assert!(q.push(info).is_ok(), "slot {i} must fit");
        }
        // Bounded capacity: next push fails with Err(()) -> EAGAIN.
        assert!(q.push(SigInfo::default_for(sig34)).is_err());

        // Popping sig34 drains all even values in strict FIFO order without
        // disturbing sig35 entries.
        for expected in (0..MAX_QUEUED_RT_SIGNALS).step_by(2) {
            assert_eq!(q.peek(sig34).map(|s| s.value), Some(expected as u64));
            let popped = q.pop(sig34).expect("sig34 entry");
            assert_eq!(popped.value, expected as u64);
            assert_eq!(popped.code, SI_QUEUE);
        }
        assert!(!q.has_signal(sig34));
        assert!(q.has_signal(sig35));

        // remove_all clears all remaining sig35 entries.
        q.remove_all(sig35);
        assert!(q.is_empty());
    }

    #[test]
    fn n2_6a_siginfo_wire_roundtrip_and_zero_padding() {
        let info = SigInfo {
            signo: 36,
            errno: 7,
            code: SI_QUEUE,
            pid: 1234,
            uid: 5678,
            value: 0xDEAD_BEEF_CAFE_BABE,
        };
        let mut wire = [0xA5u8; 128];
        info.write_wire_bytes(&mut wire);
        assert_eq!(&wire[12..16], &[0, 0, 0, 0], "x86_64 pad0 must be zero");
        assert!(wire[32..].iter().all(|&b| b == 0), "tail must be zero");

        let parsed = SigInfo::from_wire_bytes(36, &wire);
        assert_eq!(parsed, info);
        // signo argument overrides wire si_signo (Linux rt_sigqueueinfo contract).
        let overridden = SigInfo::from_wire_bytes(40, &wire);
        assert_eq!(overridden.signo, 40);
        assert_eq!(overridden.value, info.value);
    }

    #[test]
    fn n2_6a_sigaltstack_validation_and_on_stack_eperm() {
        let mut cur = SigAltStack::disabled();
        let main_rsp = 0x7FFF_0000u64;

        // Query disabled state.
        let (next, old) = apply_sigaltstack_update(cur, main_rsp, None).unwrap();
        assert_eq!(next, cur);
        assert_eq!(old.ss_flags, SS_DISABLE as i32);
        assert_eq!(old.ss_sp, 0);
        assert_eq!(old.ss_size, 0);

        // Reject too-small stack (< MINSIGSTKSZ) with ENOMEM.
        assert_eq!(
            apply_sigaltstack_update(
                cur,
                main_rsp,
                Some(StackT {
                    ss_sp: 0x20_0000,
                    ss_flags: 0,
                    _pad: 0,
                    ss_size: MINSIGSTKSZ - 1,
                })
            ),
            Err(SyscallError::ENOMEM)
        );

        // Reject SS_ONSTACK as an input flag with EINVAL.
        assert_eq!(
            apply_sigaltstack_update(
                cur,
                main_rsp,
                Some(StackT {
                    ss_sp: 0x20_0000,
                    ss_flags: SS_ONSTACK as i32,
                    _pad: 0,
                    ss_size: MINSIGSTKSZ,
                })
            ),
            Err(SyscallError::EINVAL)
        );

        // Reject kernel/non-canonical address with EINVAL.
        assert_eq!(
            apply_sigaltstack_update(
                cur,
                main_rsp,
                Some(StackT {
                    ss_sp: 0xFFFF_8000_0000_0000,
                    ss_flags: 0,
                    _pad: 0,
                    ss_size: MINSIGSTKSZ,
                })
            ),
            Err(SyscallError::EINVAL)
        );

        // Install valid alternate stack.
        let (installed, _) = apply_sigaltstack_update(
            cur,
            main_rsp,
            Some(StackT {
                ss_sp: 0x30_0000,
                ss_flags: 0,
                _pad: 0,
                ss_size: MINSIGSTKSZ * 2,
            }),
        )
        .unwrap();
        cur = installed;
        assert!(cur.is_enabled());
        assert!(!cur.on_stack(main_rsp));

        // While executing inside the altstack, query reports SS_ONSTACK and
        // any modification fails with EPERM.
        let alt_rsp = 0x30_0000 + MINSIGSTKSZ as u64;
        assert!(cur.on_stack(alt_rsp));
        let (_, queried) = apply_sigaltstack_update(cur, alt_rsp, None).unwrap();
        assert_eq!(queried.ss_flags, SS_ONSTACK as i32);
        assert_eq!(queried.ss_sp, 0x30_0000);
        assert_eq!(
            apply_sigaltstack_update(
                cur,
                alt_rsp,
                Some(StackT {
                    ss_sp: 0,
                    ss_flags: SS_DISABLE as i32,
                    _pad: 0,
                    ss_size: 0,
                })
            ),
            Err(SyscallError::EPERM)
        );

        // Off-stack disable succeeds and returns prior active stack.
        let (disabled, prev) = apply_sigaltstack_update(
            cur,
            main_rsp,
            Some(StackT {
                ss_sp: 0,
                ss_flags: SS_DISABLE as i32,
                _pad: 0,
                ss_size: 0,
            }),
        )
        .unwrap();
        assert!(!disabled.is_enabled());
        assert_eq!(prev.ss_sp, 0x30_0000);
        assert_eq!(prev.ss_flags, 0);
    }

    #[test]
    fn n2_6a_sa_onstack_layout_and_sigframe_full_fields() {
        let alt = SigAltStack {
            sp: 0x50_0000,
            size: MINSIGSTKSZ as u64,
            flags: 0,
        };
        let main_rsp = 0x7FFF_1000u64;

        // Without SA_ONSTACK, altstack is not selected.
        assert!(choose_altstack_target(main_rsp, 0, alt).is_none());

        // With SA_ONSTACK from main stack, switches to altstack top without red zone.
        let (target_rsp, skip_rz, stack) =
            choose_altstack_target(main_rsp, SA_ONSTACK, alt).expect("altstack selected");
        assert_eq!(target_rsp, 0x50_0000 + MINSIGSTKSZ as u64);
        assert!(!skip_rz);
        assert_eq!(stack.layout_floor(target_rsp), 0x50_0000);

        let layout = crate::signal_frame::compute_sigframe_layout_with_redzone(
            target_rsp,
            stack.layout_floor(target_rsp),
            skip_rz,
        )
        .expect("MINSIGSTKSZ altstack must fit full sigframe");
        assert_eq!(layout.frame_base & 0xF, 8);
        assert!(layout.frame_base >= alt.sp);
        assert!(layout.frame_base + crate::signal_frame::SIGFRAME_SIZE as u64 <= target_rsp);

        // Already running on altstack keeps current RSP and red zone.
        let nested_rsp = alt.sp + 1600;
        let (nested_top, nested_rz, _) =
            choose_altstack_target(nested_rsp, SA_ONSTACK, alt).expect("nested altstack");
        assert_eq!(nested_top, nested_rsp);
        assert!(nested_rz);

        // Full sigframe assembly writes siginfo + uc_stack + uc_sigmask accurately.
        let mut ctx = crate::signal_frame::SavedUserContext::default();
        ctx.rip = 0x40_1000;
        ctx.rsp = main_rsp;
        ctx.rflags = 0x202;
        let fx = [0u8; crate::signal_frame::FXSAVE_SIZE];
        let info = SigInfo {
            signo: 35,
            errno: 0,
            code: SI_QUEUE,
            pid: 77,
            uid: 1000,
            value: 0x1122_3344_5566_7788,
        };
        let mut buf = [0u8; crate::signal_frame::SIGFRAME_SIZE];
        crate::signal_frame::assemble_sigframe_full(
            &layout,
            &ctx,
            &fx,
            &info,
            alt.as_stack_t_fields(main_rsp),
            0x0000_0000_0000_0200,
            0x40_2000,
            0x40_3000,
            &mut buf,
        )
        .expect("assemble full sigframe");
        // uc_stack at uc+16 (frame+24): ss_sp, ss_flags, ss_size
        assert_eq!(
            u64::from_ne_bytes(buf[24..32].try_into().unwrap()),
            0x50_0000
        );
        assert_eq!(u32::from_ne_bytes(buf[32..36].try_into().unwrap()), 0);
        assert_eq!(
            u64::from_ne_bytes(buf[40..48].try_into().unwrap()),
            MINSIGSTKSZ as u64
        );
        // uc_sigmask at frame+304
        assert_eq!(
            u64::from_ne_bytes(buf[304..312].try_into().unwrap()),
            0x0200
        );
        // siginfo at frame+312
        assert_eq!(i32::from_ne_bytes(buf[312..316].try_into().unwrap()), 35);
        assert_eq!(
            i32::from_ne_bytes(buf[320..324].try_into().unwrap()),
            SI_QUEUE
        );
        assert_eq!(i32::from_ne_bytes(buf[328..332].try_into().unwrap()), 77);
        assert_eq!(u32::from_ne_bytes(buf[332..336].try_into().unwrap()), 1000);
        assert_eq!(
            u64::from_ne_bytes(buf[336..344].try_into().unwrap()),
            0x1122_3344_5566_7788
        );
    }

    #[test]
    fn n2_6a_sa_restart_syscall_classification() {
        use seccomp::syscall_table as st;
        let z = [0u64; 6];
        for nr in [
            st::SYS_READ,
            st::SYS_WRITE,
            st::SYS_READV,
            st::SYS_WRITEV,
            st::SYS_WAIT4,
            st::SYS_WAITID,
            st::SYS_ACCEPT,
            st::SYS_ACCEPT4,
            st::SYS_SENDTO,
            st::SYS_RECVFROM,
            st::SYS_SENDMSG,
            st::SYS_RECVMSG,
        ] {
            assert!(
                is_restartable_syscall(nr, &z),
                "syscall {nr} must be restartable under SA_RESTART"
            );
        }
        // FUTEX_WAIT / FUTEX_WAIT_BITSET with NULL timeout are restartable; with
        // non-null timeout or FUTEX_WAKE are not.
        assert!(is_restartable_syscall(st::SYS_FUTEX, &[0, 0, 0, 0, 0, 0]));
        assert!(is_restartable_syscall(st::SYS_FUTEX, &[0, 128, 0, 0, 0, 0])); // PRIVATE|WAIT
        assert!(is_restartable_syscall(st::SYS_FUTEX, &[0, 9, 0, 0, 0, 0]));
        assert!(!is_restartable_syscall(
            st::SYS_FUTEX,
            &[0, 0, 0, 0x1000, 0, 0]
        ));
        assert!(!is_restartable_syscall(st::SYS_FUTEX, &[0, 1, 0, 0, 0, 0])); // WAKE

        // Never-restartable syscalls per Linux signal(7).
        for nr in [
            st::SYS_NANOSLEEP,
            st::SYS_POLL,
            st::SYS_PPOLL,
            st::SYS_SELECT,
            st::SYS_PSELECT6,
            st::SYS_RT_SIGSUSPEND,
            st::SYS_RT_SIGTIMEDWAIT,
            st::SYS_CONNECT,
        ] {
            assert!(
                !is_restartable_syscall(nr, &z),
                "syscall {nr} must NEVER restart under SA_RESTART"
            );
        }
    }

    #[test]
    fn n2_6a_process_group_rt_queue_and_sigwait_fifo() {
        let proc_arc = Arc::new(crate::owner_lock::OwnerCpuMutex::new(
            crate::process::Process::new(901, 1, alloc::string::String::from("rt-test"), 10),
        ));
        let sig34 = Signal::from_raw(34).unwrap();
        let sigusr1 = Signal::SIGUSR1;

        {
            let p = proc_arc.lock();
            for val in [100u64, 200, 300] {
                p.thread_group
                    .queue_shared_info(
                        sig34,
                        Some(SigInfo {
                            signo: 34,
                            errno: 0,
                            code: SI_QUEUE,
                            pid: 11,
                            uid: 0,
                            value: val,
                        }),
                        true,
                    )
                    .expect("queue rt signal");
            }
            // Standard signal coalesces to first payload.
            p.thread_group
                .queue_shared_info(
                    sigusr1,
                    Some(SigInfo::from_sender(sigusr1, SI_USER, 11, 0)),
                    false,
                )
                .unwrap();
            p.thread_group
                .queue_shared_info(
                    sigusr1,
                    Some(SigInfo::from_sender(sigusr1, SI_USER, 99, 0)),
                    false,
                )
                .unwrap();
        }

        // Dequeue all 3 RT instances in FIFO order via take_pending_for_sigwait.
        let mut p = proc_arc.lock();
        let (s1, i1) = p.take_pending_for_sigwait(sig34.bit()).expect("1st rt");
        assert_eq!((s1, i1.value), (sig34, 100));
        assert_ne!(
            p.pending_bits() & sig34.bit(),
            0,
            "2 instances still remain"
        );

        let (s2, i2) = p.take_pending_for_sigwait(sig34.bit()).expect("2nd rt");
        assert_eq!((s2, i2.value), (sig34, 200));
        assert_ne!(
            p.pending_bits() & sig34.bit(),
            0,
            "1 instance still remains"
        );

        let (s3, i3) = p.take_pending_for_sigwait(sig34.bit()).expect("3rd rt");
        assert_eq!((s3, i3.value), (sig34, 300));
        assert_eq!(p.pending_bits() & sig34.bit(), 0, "queue drained");
        assert!(p.take_pending_for_sigwait(sig34.bit()).is_none());

        // Standard signal delivers once with first sender pid (11).
        let (su, iu) = p.take_pending_for_sigwait(sigusr1.bit()).expect("usr1");
        assert_eq!((su, iu.pid), (sigusr1, 11));
        assert!(p.take_pending_for_sigwait(sigusr1.bit()).is_none());
    }
}
