//! Syscall family module: `seccomp` (split from monolithic `syscall.rs`, N2.0a).

use super::*;

// ============================================================================
// Seccomp/Prctl 系统调用
// ============================================================================

// R26-3: Helper functions to manage seccomp installation state
//
// These functions set/clear the `seccomp_installing` flag to prevent TOCTOU
// race conditions between seccomp filter installation and thread creation.
// The flag must be manually cleared after installation completes or on error.

/// Convert seccomp error to syscall error
pub(super) fn seccomp_error_to_syscall(err: seccomp::SeccompError) -> SyscallError {
    match err {
        seccomp::SeccompError::Fault => SyscallError::EFAULT,
        seccomp::SeccompError::NotPermitted => SyscallError::EPERM,
        seccomp::SeccompError::ProgramTooLong => SyscallError::E2BIG,
        seccomp::SeccompError::OutOfMemory => SyscallError::ENOMEM,
        _ => SyscallError::EINVAL,
    }
}

/// Decode user-space action code to SeccompAction
pub(super) fn decode_user_action(
    code: u32,
    aux: u64,
) -> Result<seccomp::SeccompAction, SyscallError> {
    match code {
        SECCOMP_USER_ACTION_ALLOW => Ok(seccomp::SeccompAction::Allow),
        SECCOMP_USER_ACTION_LOG => Ok(seccomp::SeccompAction::Log),
        SECCOMP_USER_ACTION_ERRNO => {
            if aux > i32::MAX as u64 {
                return Err(SyscallError::EINVAL);
            }
            Ok(seccomp::SeccompAction::Errno(aux as i32))
        }
        SECCOMP_USER_ACTION_TRAP => Ok(seccomp::SeccompAction::Trap),
        SECCOMP_USER_ACTION_KILL => Ok(seccomp::SeccompAction::Kill),
        _ => Err(SyscallError::EINVAL),
    }
}

/// Convert u64 to u8 with bounds check
#[inline]
pub(super) fn to_u8_checked(val: u64) -> Result<u8, SyscallError> {
    if val > u8::MAX as u64 {
        return Err(SyscallError::EINVAL);
    }
    Ok(val as u8)
}

// R186-15 FIX: Validate shift amounts at translation time to prevent
// arithmetic overflow in overflow-checked kernel builds. Shr(64..=255)
// would panic in debug/checked builds when executing `acc >>= shift` with
// a 64-bit accumulator. The semantic constraint is 0..=63, not just u8 range.
/// Convert u64 to shift amount (0..=63) with semantic validation
#[inline]
pub(super) fn to_shift_amount_checked(val: u64) -> Result<u8, SyscallError> {
    if val > 63 {
        return Err(SyscallError::EINVAL);
    }
    Ok(val as u8)
}

/// Translate user-space instruction to kernel SeccompInsn
pub(super) fn translate_user_insn(
    insn: &UserSeccompInsn,
) -> Result<seccomp::SeccompInsn, SyscallError> {
    match insn.op {
        SECCOMP_USER_OP_LD_NR => Ok(seccomp::SeccompInsn::LdSyscallNr),
        SECCOMP_USER_OP_LD_ARG => {
            let idx = to_u8_checked(insn.arg0)?;
            if idx >= 6 {
                return Err(SyscallError::EINVAL);
            }
            Ok(seccomp::SeccompInsn::LdArg(idx))
        }
        SECCOMP_USER_OP_LD_CONST => Ok(seccomp::SeccompInsn::LdConst(insn.arg0)),
        SECCOMP_USER_OP_AND => Ok(seccomp::SeccompInsn::And(insn.arg0)),
        SECCOMP_USER_OP_OR => Ok(seccomp::SeccompInsn::Or(insn.arg0)),
        SECCOMP_USER_OP_SHR => Ok(seccomp::SeccompInsn::Shr(to_shift_amount_checked(
            insn.arg0,
        )?)),
        SECCOMP_USER_OP_JMP_EQ => Ok(seccomp::SeccompInsn::JmpEq(
            insn.arg0,
            to_u8_checked(insn.arg1)?,
            to_u8_checked(insn.arg2)?,
        )),
        SECCOMP_USER_OP_JMP_NE => Ok(seccomp::SeccompInsn::JmpNe(
            insn.arg0,
            to_u8_checked(insn.arg1)?,
            to_u8_checked(insn.arg2)?,
        )),
        SECCOMP_USER_OP_JMP_LT => Ok(seccomp::SeccompInsn::JmpLt(
            insn.arg0,
            to_u8_checked(insn.arg1)?,
            to_u8_checked(insn.arg2)?,
        )),
        SECCOMP_USER_OP_JMP_LE => Ok(seccomp::SeccompInsn::JmpLe(
            insn.arg0,
            to_u8_checked(insn.arg1)?,
            to_u8_checked(insn.arg2)?,
        )),
        SECCOMP_USER_OP_JMP_GT => Ok(seccomp::SeccompInsn::JmpGt(
            insn.arg0,
            to_u8_checked(insn.arg1)?,
            to_u8_checked(insn.arg2)?,
        )),
        SECCOMP_USER_OP_JMP_GE => Ok(seccomp::SeccompInsn::JmpGe(
            insn.arg0,
            to_u8_checked(insn.arg1)?,
            to_u8_checked(insn.arg2)?,
        )),
        SECCOMP_USER_OP_JMP => Ok(seccomp::SeccompInsn::Jmp(to_u8_checked(insn.arg0)?)),
        SECCOMP_USER_OP_RET => {
            let action = decode_user_action(insn.arg0 as u32, insn.arg1)?;
            Ok(seccomp::SeccompInsn::Ret(action))
        }
        _ => Err(SyscallError::EINVAL),
    }
}

/// Load and validate a seccomp filter from userspace
pub(super) fn load_user_seccomp_filter(
    flags: u32,
    args: u64,
) -> Result<seccomp::SeccompFilter, SyscallError> {
    // Validate flags - reject TSYNC since we don't implement thread synchronization
    // Silently accepting TSYNC would leave sibling threads unsandboxed (security gap)
    if flags & seccomp::SeccompFlags::TSYNC.bits() != 0 {
        kprintln!("[sys_seccomp] TSYNC not implemented, rejecting");
        return Err(SyscallError::EINVAL);
    }

    // R28-8 Fix: Reject NEW_THREADS flag since we don't implement per-new-thread filtering
    // Accepting this flag would make callers believe new threads are sandboxed when they're not.
    if flags & seccomp::SeccompFlags::NEW_THREADS.bits() != 0 {
        kprintln!("[sys_seccomp] NEW_THREADS not implemented, rejecting");
        return Err(SyscallError::EINVAL);
    }

    let filter_flags = seccomp::SeccompFlags::from_bits(flags).ok_or(SyscallError::EINVAL)?;

    // Read program header from userspace
    let mut prog = UserSeccompProg::default();
    // lint-repr-c-copy: allow (no-padding: UserSeccompProg {u32,u32,u64} = 16 bytes; user→kernel)
    let prog_bytes = unsafe {
        core::slice::from_raw_parts_mut(
            &mut prog as *mut _ as *mut u8,
            mem::size_of::<UserSeccompProg>(),
        )
    };
    copy_from_user(prog_bytes, args as *const u8)?;

    // Validate program length
    let len = prog.len as usize;
    if len == 0 || len > seccomp::MAX_INSNS {
        return Err(SyscallError::EINVAL);
    }

    // Validate filter pointer
    let insn_ptr = prog.filter as *const UserSeccompInsn;
    if insn_ptr.is_null() {
        return Err(SyscallError::EFAULT);
    }

    // Calculate total size and validate
    let insn_size = mem::size_of::<UserSeccompInsn>();
    let total = insn_size.checked_mul(len).ok_or(SyscallError::EFAULT)?;
    validate_user_ptr(insn_ptr as *const u8, total)?;

    // R158-3 FIX: Fallible allocation — user-controlled len can exhaust kernel heap.
    // RF180-18 FIX: bounded stack staging leaves retained allocation to the
    // admitted SeccompFilter constructor.
    let mut raw_insns = [UserSeccompInsn::default(); seccomp::MAX_INSNS];
    let raw_bytes =
        unsafe { core::slice::from_raw_parts_mut(raw_insns.as_mut_ptr() as *mut u8, total) };
    copy_from_user(raw_bytes, insn_ptr as *const u8)?;

    // Decode default action
    let default_action = decode_user_action(prog.default_action, 0)?;

    // R158-3 FIX: Fallible allocation for translated program.
    let mut program = [seccomp::SeccompInsn::Ret(seccomp::SeccompAction::Kill); seccomp::MAX_INSNS];
    for (slot, insn) in program[..len].iter_mut().zip(raw_insns[..len].iter()) {
        *slot = translate_user_insn(insn)?;
    }

    // Create and validate filter
    seccomp::SeccompFilter::new_from_slice(&program[..len], default_action, filter_flags)
        .map_err(seccomp_error_to_syscall)
}

/// Get current seccomp mode for PR_GET_SECCOMP
// R159-I3 FIX: Cache strict_filter ID to avoid heap allocation on every
// PR_GET_SECCOMP call. Computed once on first use.
pub(super) fn current_seccomp_mode(state: &seccomp::SeccompState) -> usize {
    if state.filter_count() == 0 {
        return SECCOMP_MODE_DISABLED;
    }

    let strict_id = seccomp::strict_filter_id();
    if state.single_filter_id() == Some(strict_id) {
        return SECCOMP_MODE_STRICT;
    }

    SECCOMP_MODE_FILTER
}

/// sys_seccomp - Install seccomp filter or strict mode
///
/// # Arguments
/// * `op` - Operation (SECCOMP_SET_MODE_STRICT or SECCOMP_SET_MODE_FILTER)
/// * `flags` - Filter flags (SeccompFlags bits)
/// * `args` - For FILTER mode, pointer to UserSeccompProg
///
/// # Security
/// - Filters can only be added, never removed (one-way sandboxing)
/// - Installing a filter automatically sets no_new_privs
/// - Filters are inherited across fork/clone
pub(super) fn sys_seccomp(op: u32, flags: u32, args: u64) -> SyscallResult {
    match op {
        SECCOMP_SET_MODE_STRICT => {
            // Strict mode requires no flags or args
            if flags != 0 || args != 0 {
                return Err(SyscallError::EINVAL);
            }

            let pid = current_pid().ok_or(SyscallError::ESRCH)?;
            let proc_arc = get_process(pid).ok_or(SyscallError::ESRCH)?;

            // R142-8 FIX: Reject STRICT mode in multi-threaded processes or when
            // CLONE_VM siblings exist. Without this, only the calling thread is
            // sandboxed while other threads sharing the address space retain full
            // syscall access — defeating the purpose of strict sandboxing.
            //
            // Lock ordering: read tgid/memory_space under process lock, drop it,
            // then call thread_group_size/non_thread_group_vm_share_count (which
            // acquire PROCESS_TABLE lock). PROCESS_TABLE → Process ordering preserved.
            let (tgid, memory_space) = {
                let proc = proc_arc.lock();
                // R26-3 FIX: Check if another thread is already installing
                if proc.seccomp_installing {
                    return Err(SyscallError::EBUSY);
                }
                (proc.tgid, proc.memory_space)
            }; // Process lock dropped

            let thread_count = crate::process::thread_group_size(tgid);
            if thread_count > 1 {
                klog!(
                    Warn,
                    "[sys_seccomp] PID={} STRICT mode REJECTED: threads={} (multi-threaded)",
                    pid,
                    thread_count
                );
                return Err(SyscallError::EPERM);
            }

            let pure_vm_siblings =
                crate::process::non_thread_group_vm_share_count(memory_space, tgid);
            if pure_vm_siblings > 0 {
                klog!(
                    Warn,
                    "[sys_seccomp] PID={} STRICT mode REJECTED: {} CLONE_VM siblings",
                    pid,
                    pure_vm_siblings
                );
                return Err(SyscallError::EPERM);
            }

            let filter = seccomp::try_strict_filter().map_err(seccomp_error_to_syscall)?;
            let mut proc = proc_arc.lock();

            // R26-3 FIX: Re-check after reacquiring lock (race window between
            // the initial check above and the re-acquire here).
            if proc.seccomp_installing {
                return Err(SyscallError::EBUSY);
            }

            // D2-ARC: fail-closed isolation recount UNDER the held Process::inner.
            // The R142-8 preflight ran lock-dropped and the re-check above verified
            // ONLY seccomp_installing (fail-open for the isolation predicate). STRICT
            // sandboxes the WHOLE address space, so re-verify via the registry txn
            // using proc.tgid/proc.memory_space re-read under THIS lock (authoritative,
            // not the stale preflight tuple). DEFENSE-IN-DEPTH (R181-3 uniformity):
            // the 0-sibling preflight admits only the caller (mid-syscall), so no live
            // actor can clone into the space — this is not a confirmed exploit fix, it
            // removes the implicit non-local liveness assumption.
            match crate::process::try_seccomp_isolation_recount_holding(
                pid,
                proc.tgid,
                proc.memory_space,
            ) {
                Some((threads, vm_siblings)) if threads <= 1 && vm_siblings == 0 => {}
                // Predicate failure → EPERM (matches this arm's preflight rejections).
                Some(_) => return Err(SyscallError::EPERM),
                // Table/PCB contention → EBUSY (transient; matches the installing vocab).
                None => return Err(SyscallError::EBUSY),
            }

            if proc.seccomp_generation == u64::MAX {
                return Err(SyscallError::EOVERFLOW);
            }

            // R26-3 FIX: Mark installation in progress
            proc.seccomp_installing = true;

            // R171-CG2x1 FIX: failure-atomic install — run the now-cap-fallible
            // add_filter FIRST; commit the sticky no_new_privs only on success so
            // a reject leaves no seccomp state drift.
            // R159-6 FIX: Fallible add_filter.
            if proc.seccomp_state.add_filter(filter).is_err() {
                proc.seccomp_installing = false;
                return Err(SyscallError::ENOMEM);
            }

            // Installing any filter sets no_new_privs (sticky, one-way)
            proc.seccomp_state.no_new_privs = true;
            // Issue #109 §4.1: publish active seccomp flag (Release) AFTER the
            // filter is installed and BEFORE releasing the PCB lock.
            proc.sync_seccomp_or_pledge_flag();

            // RF180-1: publish the new committed filter revision before the
            // installing flag is cleared.
            proc.seccomp_generation += 1;

            // R26-3 FIX: Mark installation complete
            proc.seccomp_installing = false;

            klog!(Info, "[sys_seccomp] PID={} installed STRICT mode", pid);
            Ok(0)
        }
        SECCOMP_SET_MODE_FILTER => {
            // Load and validate the filter from userspace
            let filter = load_user_seccomp_filter(flags, args)?;

            let pid = current_pid().ok_or(SyscallError::ESRCH)?;
            let proc_arc = get_process(pid).ok_or(SyscallError::ESRCH)?;

            // R142-8 FIX: Read tgid/memory_space under process lock, then drop
            // before calling thread_group_size/non_thread_group_vm_share_count
            // (which acquire PROCESS_TABLE lock). Holding process lock while
            // calling those helpers is a latent self-deadlock: the helpers
            // iterate PROCESS_TABLE and lock each Process entry, including
            // the caller's own entry → spin forever.
            let (tgid, memory_space) = {
                let proc = proc_arc.lock();
                // R26-3 FIX: Check if another thread is already installing
                if proc.seccomp_installing {
                    return Err(SyscallError::EBUSY);
                }
                (proc.tgid, proc.memory_space)
            }; // Process lock dropped

            // R25-6 FIX: Reject seccomp in multi-threaded processes without TSYNC
            // R37-1 FIX (Codex review): Correctly distinguish CLONE_THREAD vs pure CLONE_VM siblings.
            // - CLONE_THREAD siblings (same tgid) can be synchronized with TSYNC
            // - Pure CLONE_VM siblings (different tgid) cannot be synchronized with TSYNC
            let thread_count = crate::process::thread_group_size(tgid);
            let pure_vm_siblings =
                crate::process::non_thread_group_vm_share_count(memory_space, tgid);
            let tsync_requested = flags & seccomp::SeccompFlags::TSYNC.bits() != 0;

            // Reject if multi-threaded without TSYNC (partial sandboxing)
            if thread_count > 1 && !tsync_requested {
                klog!(
                    Warn,
                    "[sys_seccomp] PID={} REJECTED: threads={} without TSYNC",
                    pid,
                    thread_count
                );
                return Err(SyscallError::EPERM);
            }

            // R37-1 FIX: If pure CLONE_VM siblings exist, reject regardless of TSYNC.
            // TSYNC only synchronizes CLONE_THREAD siblings (same tgid), not CLONE_VM processes.
            if pure_vm_siblings > 0 {
                klog!(Warn,
                    "[sys_seccomp] PID={} REJECTED: {} CLONE_VM siblings (different tgid) present; \
                    seccomp cannot secure shared address space",
                    pid, pure_vm_siblings
                );
                return Err(SyscallError::EBUSY);
            }

            let mut proc = proc_arc.lock();

            // R26-3 FIX: Re-check after reacquiring lock
            if proc.seccomp_installing {
                return Err(SyscallError::EBUSY);
            }

            // D2-ARC: fail-closed isolation recount UNDER the held Process::inner.
            // Unlike STRICT, the TSYNC case has a REAL residual: with threads>1
            // admitted, a live sibling on another CPU can clone(CLONE_VM w/o
            // CLONE_THREAD) in the R142-8 lock-drop window. This recount NARROWS that
            // window (it catches pure-VM siblings that published before the recount,
            // which the relock missed) but does NOT close the TOCTOU: the caller's
            // held lock never blocks a sibling clone, the clone gate checks only the
            // cloning task's own seccomp_installing, and post-install an unfiltered
            // TSYNC sibling can still clone a pure-VM task (TSYNC does not fan the
            // filter out). R37-1 TSYNC residual stays OPEN (clone-side space-member
            // gate). Defense-in-depth. Errno mirrors the preflight ORDER: threads-
            // without-TSYNC → EPERM (R25-6) before vm_siblings → EBUSY (R37-1);
            // contention → EBUSY.
            match crate::process::try_seccomp_isolation_recount_holding(
                pid,
                proc.tgid,
                proc.memory_space,
            ) {
                Some((threads, vm_siblings)) => {
                    if threads > 1 && !tsync_requested {
                        return Err(SyscallError::EPERM);
                    }
                    if vm_siblings > 0 {
                        return Err(SyscallError::EBUSY);
                    }
                }
                None => return Err(SyscallError::EBUSY),
            }

            if proc.seccomp_generation == u64::MAX {
                return Err(SyscallError::EOVERFLOW);
            }

            // R26-3 FIX: Mark installation in progress
            proc.seccomp_installing = true;

            // R171-CG2x1 FIX: make the install failure-atomic. Capture the LOG
            // intent, run the now-cap-fallible add_filter FIRST, and commit the
            // sticky no_new_privs / log_violations state ONLY on success — so a
            // chain-cap reject (ENOMEM) leaves no observable seccomp state drift
            // (previously log_violations/no_new_privs were flipped before the
            // fallible add_filter, persisting on a now attacker-reachable reject).
            let wants_log = filter.flags().contains(seccomp::SeccompFlags::LOG);
            // R159-6 FIX: Fallible add_filter.
            if proc.seccomp_state.add_filter(filter).is_err() {
                proc.seccomp_installing = false;
                return Err(SyscallError::ENOMEM);
            }

            // Installing a filter sets no_new_privs (sticky, one-way).
            proc.seccomp_state.no_new_privs = true;
            if wants_log {
                proc.seccomp_state.log_violations = true;
            }
            // Issue #109 §4.1: publish active seccomp flag (Release) AFTER the
            // filter is installed and BEFORE releasing the PCB lock.
            proc.sync_seccomp_or_pledge_flag();

            // RF180-1: publish the new committed filter revision before the
            // installing flag is cleared.
            proc.seccomp_generation += 1;

            // R26-3 FIX: Mark installation complete
            proc.seccomp_installing = false;

            klog!(
                Info,
                "[sys_seccomp] PID={} installed FILTER mode (total filters: {})",
                pid,
                proc.seccomp_state.filter_count()
            );
            Ok(0)
        }
        _ => Err(SyscallError::EINVAL),
    }
}

/// sys_prctl - Process control operations
///
/// Implements seccomp and no_new_privs related prctl operations:
/// - PR_SET_NO_NEW_PRIVS: Set the sticky no_new_privs flag
/// - PR_GET_NO_NEW_PRIVS: Check if no_new_privs is set
/// - PR_GET_SECCOMP: Get current seccomp mode
/// - PR_SET_SECCOMP: Set seccomp mode (alternative to sys_seccomp)
///
/// # Arguments
/// * `option` - prctl operation code
/// * `arg2-arg5` - Operation-specific arguments
pub(super) fn sys_prctl(
    option: i32,
    arg2: u64,
    arg3: u64,
    _arg4: u64,
    _arg5: u64,
) -> SyscallResult {
    // R165-16 FIX: Invoke the dedicated task-level LSM hook for prctl. It was
    // defined (lsm::hook_task_prctl) but never called from this syscall, so an
    // LSM policy could not mediate security-relevant prctl options (NO_NEW_PRIVS,
    // SET_SECCOMP, …). Evaluate up front, before any state change; deny -> EPERM.
    // R131-1 FIX pattern: build the ctx from the locked proc and drop it before
    // calling the hook to avoid Process-mutex re-entrancy.
    {
        let pid = current_pid().ok_or(SyscallError::ESRCH)?;
        let proc_arc = get_process(pid).ok_or(SyscallError::ESRCH)?;
        let ctx = {
            let proc = proc_arc.lock();
            lsm_process_ctx_from(&proc)?
        };
        if lsm::hook_task_prctl(&ctx, option, arg2).is_err() {
            return Err(SyscallError::EPERM);
        }
    }
    match option {
        #[cfg(feature = "syscall_test")]
        crate::fork::cow_test::PR_COW_TEST => {
            let pid = current_pid().ok_or(SyscallError::ESRCH)?;
            let process = get_process(pid).ok_or(SyscallError::ESRCH)?;
            let root = process.lock().memory_space;
            crate::fork::cow_test::command(arg2, arg3, pid, root)
                .map(|value| value as usize)
                .map_err(|()| SyscallError::EINVAL)
        }
        #[cfg(feature = "syscall_test")]
        crate::fork::shared_fault_test::PR_SHARED_FAULT_TEST => {
            let pid = current_pid().ok_or(SyscallError::ESRCH)?;
            let process = get_process(pid).ok_or(SyscallError::ESRCH)?;
            let (root, generation) = {
                let proc = process.lock();
                (proc.memory_space, proc.generation)
            };
            let result = if arg2 == 10 {
                let proc = process.lock();
                let mm = proc.mm.lock();
                let region = mm
                    .shared_regions
                    .get(&(arg3 as usize))
                    .ok_or(SyscallError::EINVAL)?;
                crate::fork::shared_release_test::arm(region, pid, generation, root)
            } else if (11..=16).contains(&arg2) {
                crate::fork::shared_release_test::command(arg2, arg3, _arg4, pid, generation, root)
            } else {
                crate::fork::shared_fault_test::command(arg2, arg3, _arg4, pid, root)
            };
            result
                .map(|value| value as usize)
                .map_err(|()| SyscallError::EINVAL)
        }
        // ST-K2-P2(a): the dedicated reentry probe image only.
        #[cfg(feature = "shared_fault_reentry_probe")]
        crate::shared_fault_reentry_probe::PR_SHARED_FAULT_REENTRY_PROBE => {
            crate::shared_fault_reentry_probe::run(arg2, arg3)
        }
        // TD-LSM-1: the guest oracle marks its own pid for one LSM arm.
        #[cfg(feature = "syscall_test")]
        lsm::syscall_test::PR_SYSCALL_TEST_LSM_MARK => {
            let pid = current_pid().ok_or(SyscallError::ESRCH)?;
            lsm::syscall_test::mark(arg2, pid).map_err(|()| SyscallError::EINVAL)?;
            Ok(0)
        }
        PR_SET_NO_NEW_PRIVS => {
            // arg2 must be 1 to set, 0 is invalid (can't unset)
            if arg2 != 1 {
                return Err(SyscallError::EINVAL);
            }

            let pid = current_pid().ok_or(SyscallError::ESRCH)?;
            let proc_arc = get_process(pid).ok_or(SyscallError::ESRCH)?;
            let mut proc = proc_arc.lock();
            proc.seccomp_state.no_new_privs = true;

            klog!(Info, "[sys_prctl] PID={} set NO_NEW_PRIVS", pid);
            Ok(0)
        }
        PR_GET_NO_NEW_PRIVS => {
            let pid = current_pid().ok_or(SyscallError::ESRCH)?;
            let proc_arc = get_process(pid).ok_or(SyscallError::ESRCH)?;
            let proc = proc_arc.lock();
            Ok(proc.seccomp_state.no_new_privs as usize)
        }
        PR_GET_SECCOMP => {
            let pid = current_pid().ok_or(SyscallError::ESRCH)?;
            let proc_arc = get_process(pid).ok_or(SyscallError::ESRCH)?;
            let proc = proc_arc.lock();
            Ok(current_seccomp_mode(&proc.seccomp_state))
        }
        PR_SET_SECCOMP => {
            // prctl(PR_SET_SECCOMP, mode, filter_ptr, 0, 0)
            // Extra args (arg4/arg5) must be zero
            if _arg4 != 0 || _arg5 != 0 {
                return Err(SyscallError::EINVAL);
            }

            // Delegate to sys_seccomp based on mode
            // Note: prctl doesn't support flags, so we always pass 0
            let mode = arg2 as u32;
            match mode {
                SECCOMP_SET_MODE_STRICT => {
                    // Strict mode requires arg3=0
                    if arg3 != 0 {
                        return Err(SyscallError::EINVAL);
                    }
                    sys_seccomp(SECCOMP_SET_MODE_STRICT, 0, 0)
                }
                SECCOMP_SET_MODE_FILTER => {
                    // arg3 is pointer to filter prog
                    // prctl interface doesn't support flags (use sys_seccomp directly for flags)
                    sys_seccomp(SECCOMP_SET_MODE_FILTER, 0, arg3)
                }
                _ => Err(SyscallError::EINVAL),
            }
        }
        _ => {
            // Other prctl options not implemented
            Err(SyscallError::EINVAL)
        }
    }
}

// ============================================================================
// 架构相关系统调用
// ============================================================================

/// arch_prctl 操作码
pub(super) const ARCH_SET_GS: i32 = 0x1001;
pub(super) const ARCH_SET_FS: i32 = 0x1002;
pub(super) const ARCH_GET_FS: i32 = 0x1003;
pub(super) const ARCH_GET_GS: i32 = 0x1004;

/// 检查地址是否为 canonical 形式（x86_64）
///
/// 在 x86_64 中，虚拟地址必须是 48 位有效，高 16 位必须等于第 47 位的符号扩展。
/// 即：地址的高 17 位要么全为 0，要么全为 1。
#[inline]
pub(super) fn is_canonical(addr: u64) -> bool {
    // 有效用户空间：0x0000_0000_0000_0000 - 0x0000_7FFF_FFFF_FFFF
    // 有效内核空间：0xFFFF_8000_0000_0000 - 0xFFFF_FFFF_FFFF_FFFF
    // 非 canonical 区域：0x0000_8000_0000_0000 - 0xFFFF_7FFF_FFFF_FFFF
    let sign_extended = ((addr as i64) >> 47) as u64;
    sign_extended == 0 || sign_extended == 0x1FFFF
}

/// R190-5 FIX: validate a user FS/GS base for `arch_prctl(ARCH_SET_FS/GS)`.
///
/// Canonical form alone admitted the kernel half: an unprivileged caller could
/// load a kernel address into FS/GS base, gaining a fault-versus-no-fault probe
/// of kernel mappings and, were CR4.FSGSBASE ever enabled, a kernel pointer
/// readable by `rdfsbase`. Like Linux `do_arch_prctl_64` (`>= TASK_SIZE_MAX`),
/// every base outside the user half fails with EPERM. Non-canonical values are
/// all at or above `USER_SPACE_TOP`, so they fail here too.
#[inline]
pub(super) fn validate_user_segment_base(addr: u64) -> Result<(), SyscallError> {
    if addr >= USER_SPACE_TOP as u64 {
        Err(SyscallError::EPERM)
    } else {
        Ok(())
    }
}

/// sys_arch_prctl - 设置/获取架构相关的线程状态
///
/// 主要用于 TLS (Thread Local Storage) 支持，设置 FS/GS segment base。
///
/// # Arguments
///
/// * `code` - 操作码 (ARCH_SET_FS, ARCH_GET_FS, ARCH_SET_GS, ARCH_GET_GS)
/// * `addr` - SET: 要设置的 base 地址；GET: 存储结果的用户空间指针
///
/// # Returns
///
/// 成功返回 0，失败返回错误码
pub(super) fn sys_arch_prctl(code: i32, addr: u64) -> SyscallResult {
    use x86_64::registers::model_specific::Msr;

    // MSR 寄存器常量
    const MSR_FS_BASE: u32 = 0xC000_0100;
    // R100-1 FIX: 系统调用入口已执行 SWAPGS，此时：
    //   IA32_GS_BASE (0xC0000101) = 内核 per-CPU 指针（不可触碰）
    //   IA32_KERNEL_GS_BASE (0xC0000102) = 用户态 GS 基址
    // 因此 ARCH_SET_GS / ARCH_GET_GS 必须操作 0xC0000102
    const MSR_KERNEL_GS_BASE: u32 = 0xC000_0102;

    // 获取当前进程
    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let process = get_process(pid).ok_or(SyscallError::ESRCH)?;

    match code {
        ARCH_SET_FS => {
            validate_user_segment_base(addr)?;

            // R102-10 FIX: Gate TLS base address log behind debug_assertions.
            // Leaks userspace TLS base which aids exploitation.
            kprintln!("[arch_prctl] PID={} ARCH_SET_FS addr=0x{:x}", pid, addr);

            // 更新进程 PCB 中的 fs_base
            let gs_base = {
                let mut proc = process.lock();
                proc.fs_base = addr;
                proc.gs_base
            };

            // R172-04 W3: commit live MSR + keep staged/committed coherent atomically.
            if !stage_pending_tls_bases(addr, gs_base) {
                unsafe {
                    let mut msr = Msr::new(MSR_FS_BASE);
                    msr.write(addr);
                }
            }

            Ok(0)
        }

        ARCH_GET_FS => {
            // 验证用户空间指针
            if addr == 0 || addr >= USER_SPACE_TOP as u64 {
                return Err(SyscallError::EFAULT);
            }

            // 从 PCB 获取 fs_base
            let fs_base = {
                let proc = process.lock();
                proc.fs_base
            };

            // 写回用户空间
            let result = copy_to_user(addr as *mut u8, &fs_base.to_ne_bytes());
            if result.is_err() {
                return Err(SyscallError::EFAULT);
            }

            Ok(0)
        }

        ARCH_SET_GS => {
            validate_user_segment_base(addr)?;

            // 更新进程 PCB 中的 gs_base
            let fs_base = {
                let mut proc = process.lock();
                proc.gs_base = addr;
                proc.fs_base
            };

            // R172-04 W3: commit live MSR + keep staged/committed coherent atomically.
            if !stage_pending_tls_bases(fs_base, addr) {
                unsafe {
                    let mut msr = Msr::new(MSR_KERNEL_GS_BASE);
                    msr.write(addr);
                }
            }

            Ok(0)
        }

        ARCH_GET_GS => {
            // 验证用户空间指针
            if addr == 0 || addr >= USER_SPACE_TOP as u64 {
                return Err(SyscallError::EFAULT);
            }

            // R100-1 FIX: 直接从 IA32_KERNEL_GS_BASE 读取用户态 GS 基址。
            // 用户态可能通过 wrgsbase 指令修改了 GS，PCB 中的缓存值可能过期。
            let gs_base = unsafe { Msr::new(MSR_KERNEL_GS_BASE).read() };

            // 同步到 PCB 以保持一致性
            {
                let mut proc = process.lock();
                proc.gs_base = gs_base;
            }

            // 写回用户空间
            let result = copy_to_user(addr as *mut u8, &gs_base.to_ne_bytes());
            if result.is_err() {
                return Err(SyscallError::EFAULT);
            }

            Ok(0)
        }

        _ => Err(SyscallError::EINVAL),
    }
}

#[cfg(test)]
mod r190_5_segment_base_tests {
    use super::*;

    #[test]
    fn segment_base_must_stay_in_user_half() {
        assert_eq!(validate_user_segment_base(0), Ok(()));
        assert_eq!(validate_user_segment_base(0x7fff_ffff_f000), Ok(()));
        assert_eq!(
            validate_user_segment_base((USER_SPACE_TOP - 1) as u64),
            Ok(())
        );
        for kernel_or_noncanonical in [
            USER_SPACE_TOP as u64,
            0x0000_8000_0000_1000,
            0xffff_8000_0000_0000,
            0xffff_ffff_8000_0000,
            u64::MAX,
        ] {
            assert_eq!(
                validate_user_segment_base(kernel_or_noncanonical),
                Err(SyscallError::EPERM),
                "base {:#x} must be rejected",
                kernel_or_noncanonical
            );
        }
    }
}
