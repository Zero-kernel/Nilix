//! Syscall family module: `proc` (split from monolithic `syscall.rs`, N2.0a).

use super::*;

// ============================================================================
// 进程管理系统调用
// ============================================================================

/// sys_exit - 终止当前进程
pub(super) fn sys_exit(exit_code: i32) -> SyscallResult {
    #[cfg(feature = "kcov")]
    {
        coverage::trace_pc(1090); // sys_exit entry
    }

    if let Some(pid) = current_pid() {
        // R115-1 FIX: Removed duplicate hook_task_exit() call.
        // terminate_process() is the sole call site for the LSM exit hook,
        // preventing double-fire in audit logs.
        // R104-2 FIX: Keep PID 1 completion oracles and abnormal exits always
        // logged; downgrade routine non-init clean exits to Debug to eliminate
        // IRQ-masked global serial spinlock contention on thread-churn bursts.
        if crate::process::should_klog_process_exit_always(pid, exit_code) {
            klog_always!("Process {} exited with code {}", pid, exit_code);
        } else {
            klog!(Debug, "Process {} exited with code {}", pid, exit_code);
        }

        // R117-1 FIX: Use centralized terminate_self_and_halt() which disables
        // interrupts and switches to boot CR3 before halting.
        terminate_self_and_halt(pid, exit_code);
    } else {
        Err(SyscallError::ESRCH)
    }
}

/// sys_exit_group - 终止进程组
///
/// R101-9 FIX: Properly terminates all threads sharing the same tgid.
///
/// R115-1 FIX: Cross-CPU safe termination. Sibling threads that may be running
/// on other CPUs are NOT terminated directly (which would cause UAF on their
/// kernel stack, FPU state, and cgroup accounting). Instead, a pending-kill
/// flag is set and the sibling self-terminates at the next syscall return.
/// The calling thread terminates itself directly (same-CPU, always safe).
pub(super) fn sys_exit_group(exit_code: i32) -> SyscallResult {
    if let Some(pid) = current_pid() {
        // Determine our thread group ID and publish the group-exiting flag.
        let (tgid, group_exit_token) = {
            let proc_arc = get_process(pid).ok_or(SyscallError::ESRCH)?;
            let proc = proc_arc.lock();
            // R153-3 FIX: Publish thread-group "exiting" flag before marking
            // siblings. This prevents concurrent sys_clone(CLONE_THREAD) from
            // slipping in between this point and the atomic marking scan below.
            proc.thread_group
                .exiting
                .store(true, core::sync::atomic::Ordering::Release);
            (proc.tgid, Arc::clone(&proc.thread_group))
        };

        // R152-10 FIX: Atomically mark all siblings under PROCESS_TABLE lock.
        // This prevents a concurrent sys_clone(CLONE_THREAD) from creating a
        // new thread that escapes the exit_group scan. The old snapshot-then-mark
        // pattern had a TOCTOU window where new threads could be created between
        // the snapshot and the marking loop.
        let marked = crate::process::request_exit_group_atomic(pid, &group_exit_token, exit_code);

        // R115-1 FIX: Removed duplicate hook_task_exit() call.
        // terminate_process() is the sole call site for the LSM exit hook.
        // Now terminate ourselves directly (same CPU, always safe).
        kprintln!(
            "Process {} (tgid={}) exit_group with code {} ({} sibling task(s) marked for exit)",
            pid,
            tgid,
            exit_code,
            marked
        );

        // The no-return tail does not run stack-local destructors.
        drop(group_exit_token);

        // R117-1 FIX: Use centralized terminate_self_and_halt().
        terminate_self_and_halt(pid, exit_code);
    } else {
        Err(SyscallError::ESRCH)
    }
}

/// sys_fork - 创建子进程
///
/// R101-10 FIX: Warns (debug) when fork is called from a multi-threaded process.
/// POSIX specifies that fork() in a multi-threaded process only duplicates the
/// calling thread, but shared resources (mutexes, file locks) may be in
/// inconsistent states in the child.
pub(super) fn sys_fork(entry_proc: Option<&ProcessArc>) -> SyscallResult {
    #[cfg(feature = "kcov")]
    {
        coverage::trace_pc(1070); // sys_fork entry
    }

    // R101-10 FIX: Warn (debug builds only) when fork is called from a
    // multi-threaded process. Uses the O(1) thread_group member count instead
    // of snapshotting PROCESS_TABLE and locking every foreign PCB.
    #[cfg(debug_assertions)]
    {
        let parent_pid = current_pid().ok_or(SyscallError::ESRCH)?;
        let parent_arc = match entry_proc {
            Some(arc) => arc.clone(),
            None => get_process(parent_pid).ok_or(SyscallError::ESRCH)?,
        };
        let sibling_count = {
            let parent = parent_arc.lock();
            if parent.pid == parent.tgid {
                parent.thread_group.members().saturating_sub(1)
            } else {
                0
            }
        };
        if sibling_count > 0 {
            kprintln!(
                "WARNING: fork() called from multi-threaded process (pid={}, {} active threads). \
                 Child may deadlock on inherited locked mutexes.",
                parent_pid,
                sibling_count
            );
        }
    }

    // 调用真正的 fork 实现（包含 COW 支持），复用 syscall 入口已持有的父进程 Arc
    let fork_res = match entry_proc {
        Some(parent_arc) => crate::fork::sys_fork_with_parent(parent_arc.clone()),
        None => crate::fork::sys_fork(),
    };
    match fork_res {
        Ok((_child_pid, parent_view_pid)) => {
            // R180-19: LSM authorization and namespace-local PID translation
            // were completed during fork PREPARE, before parent PTE commit.  The
            // low-level transaction has already published the runnable child;
            // this syscall tail has no lookup or failure branch.
            Ok(parent_view_pid)
        }
        Err(e) => {
            // F.2: Map ForkError to appropriate syscall error
            use crate::fork::ForkError;
            match e {
                ForkError::CgroupPidsLimitExceeded
                | ForkError::CgroupFilesLimitExceeded
                | ForkError::MmapTransientState
                | ForkError::CredentialBusy
                | ForkError::SchedulerAdmissionFailed => Err(SyscallError::EAGAIN),
                ForkError::SecurityDenied => Err(SyscallError::EPERM),
                ForkError::NamespaceTranslationFailed => Err(SyscallError::EFAULT),
                // ST-K3 FIX (F1): unusable parent user frame — fail closed.
                ForkError::InvalidUserFrame => Err(SyscallError::EFAULT),
                _ => Err(SyscallError::ENOMEM),
            }
        }
    }
}

// ============================================================================
// Clone Flags (Linux x86_64 ABI)
// ============================================================================

/// 共享虚拟内存空间
pub(super) const CLONE_VM: u64 = 0x0000_0100;
/// 共享文件系统信息
pub(super) const CLONE_FS: u64 = 0x0000_0200;
/// 共享文件描述符表
pub(super) const CLONE_FILES: u64 = 0x0000_0400;
/// 共享信号处理器
pub(super) const CLONE_SIGHAND: u64 = 0x0000_0800;
/// 加入同一线程组
pub(super) const CLONE_THREAD: u64 = 0x0001_0000;
/// Share System V semaphore undo state. This kernel has no SysV semaphores,
/// so there is no undo list to share; accepted for musl's pthread_create.
pub(super) const CLONE_SYSVSEM: u64 = 0x0004_0000;
/// Legacy flag, ignored by Linux since 2.6; musl still passes it.
pub(super) const CLONE_DETACHED: u64 = 0x0040_0000;
/// 设置 TLS
pub(super) const CLONE_SETTLS: u64 = 0x0008_0000;
/// 在父进程写入子 TID
pub(super) const CLONE_PARENT_SETTID: u64 = 0x0010_0000;
/// 子进程退出时清除 TID 并唤醒 futex
pub(super) const CLONE_CHILD_CLEARTID: u64 = 0x0020_0000;
/// 在子进程写入 TID
pub(super) const CLONE_CHILD_SETTID: u64 = 0x0100_0000;
/// F.1: Create a new PID namespace for the child
pub(super) const CLONE_NEWPID: u64 = 0x2000_0000;
/// F.1: Create a new mount namespace for the child
pub(super) const CLONE_NEWNS: u64 = 0x0002_0000;
/// F.1: Create a new IPC namespace for the child
pub(super) const CLONE_NEWIPC: u64 = crate::CLONE_NEWIPC;
/// F.1: Create a new network namespace for the child
pub(super) const CLONE_NEWNET: u64 = crate::CLONE_NEWNET;
/// F.1: Create a new user namespace for the child
/// NOTE: Unlike other namespaces, CLONE_NEWUSER does NOT require CAP_SYS_ADMIN or root.
/// This is intentional to enable unprivileged container creation.
pub(super) const CLONE_NEWUSER: u64 = crate::CLONE_NEWUSER;

// R186-2 FIX: Bitmask of flags incompatible with non-CLONE_VM fork path.
// Fork creates an independent child with COW address space, inherited namespaces,
// and independent fd_table/TLS/TID state. It CANNOT honor isolation flags
// (CLONE_NEW*), sharing flags (CLONE_FS/FILES/SIGHAND), or pointer-setup flags
// (CLONE_SETTLS/PARENT_SETTID/CHILD_SETTID/CHILD_CLEARTID) that require operating
// on the child after creation. A non-null alternate stack is likewise unsupported
// on the fork delegation path. Reject every such semantic before sys_fork rather
// than returning success after silently discarding part of the caller's request.
pub(super) const NON_VM_INCOMPATIBLE: u64 = CLONE_NEWNS
    | CLONE_NEWIPC
    | CLONE_NEWNET
    | CLONE_NEWUSER
    | CLONE_NEWPID
    | CLONE_SETTLS
    | CLONE_CHILD_SETTID
    | CLONE_CHILD_CLEARTID
    | CLONE_PARENT_SETTID
    | CLONE_FS
    | CLONE_FILES
    | CLONE_SIGHAND
    | CLONE_THREAD;

/// GAP-5 slice 4 step 7: thread groups (CLONE_SIGHAND|CLONE_THREAD, which
/// sys_clone requires to come with CLONE_VM) plus CLONE_FS and, inside a thread
/// group only, CLONE_FILES sharing. Enabled by default on 2026-10-20 once every
/// known thread-group gap was closed (design: gap-5-slice4-thread-group-design.md).
pub(super) const SUPPORTED_CLONE_FLAGS: u64 = BASE_CLONE_FLAGS
    | CLONE_SIGHAND
    | CLONE_THREAD
    | CLONE_FS
    | CLONE_FILES
    | CLONE_SYSVSEM
    | CLONE_DETACHED;

pub(super) const BASE_CLONE_FLAGS: u64 = CLONE_VM
    | CLONE_SETTLS
    | CLONE_PARENT_SETTID
    | CLONE_CHILD_CLEARTID
    | CLONE_CHILD_SETTID
    | CLONE_NEWPID
    | CLONE_NEWNS
    | CLONE_NEWIPC
    | CLONE_NEWNET
    | CLONE_NEWUSER;

#[inline]
pub(super) fn clone_flags_supported(flags: u64) -> bool {
    flags & !SUPPORTED_CLONE_FLAGS == 0
}

#[cfg(test)]
mod rf186_clone_contract_tests {
    use super::*;

    #[test]
    fn thread_sharing_flags_are_supported_and_others_fail_closed() {
        assert!(clone_flags_supported(
            CLONE_VM | CLONE_SIGHAND | CLONE_THREAD | CLONE_FS | CLONE_FILES
        ));
        assert!(clone_flags_supported(CLONE_VM | CLONE_SETTLS));
        // CLONE_PTRACE, CLONE_VFORK and CLONE_PARENT stay outside the set.
        for flag in [0x0000_2000, 0x0000_4000, 0x0000_8000] {
            assert!(!clone_flags_supported(CLONE_VM | flag));
        }
    }
}

/// sys_clone - 创建线程/轻量级进程
///
/// 根据 flags 创建新的执行上下文，支持共享地址空间（线程）或独立地址空间（进程）。
///
/// # Arguments (Linux x86_64 ABI)
///
/// * `flags` - clone 标志位组合
/// * `stack` - 子进程/线程的用户栈指针（可为 NULL 使用父栈）
/// * `parent_tid` - CLONE_PARENT_SETTID 时写入子 TID 的地址
/// * `child_tid` - CLONE_CHILD_SETTID/CLONE_CHILD_CLEARTID 时使用的地址
/// * `tls` - CLONE_SETTLS 时设置的 TLS base 地址
///
/// # Returns
///
/// * 父进程：返回子进程/线程的 TID
/// * 子进程/线程：返回 0（通过设置 context.rax = 0）
pub(super) fn sys_clone(
    flags: u64,
    stack: *mut u8,
    parent_tid: *mut i32,
    child_tid: *mut i32,
    tls: u64,
) -> SyscallResult {
    // R101-2 FIX: Gate clone debug prints behind debug_assertions to prevent
    // leaking user stack/instruction pointers and TLS base addresses.
    kprintln!(
        "[sys_clone] entry: flags=0x{:x}, stack=0x{:x}, tls=0x{:x}",
        flags,
        stack as u64,
        tls
    );

    let parent_pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let parent_arc = get_process(parent_pid).ok_or(SyscallError::ESRCH)?;

    // 支持的 flags
    // RF186 review-fix: CLONE_FS/FILES/SIGHAND are not accepted until their
    // state is carried by true shared ownership objects. The former VM path
    // deep-copied descriptor and signal tables and copied umask while returning
    // success, silently violating the caller's isolation contract. CLONE_THREAD
    // necessarily depends on CLONE_SIGHAND (and real pthread callers also use
    // FILES/FS), so advertising it while those semantics are absent is equally
    // unsafe. Plain CLONE_VM remains supported with explicitly independent
    // non-VM state.
    let supported_flags = SUPPORTED_CLONE_FLAGS;

    // 检查不支持的 flags
    // 返回 EINVAL 而不是 ENOSYS，因为这是参数验证失败而非功能未实现
    if !clone_flags_supported(flags) {
        // R104-2 FIX: Gate diagnostic println behind debug_assertions.
        kprintln!(
            "sys_clone: unsupported flags 0x{:x}",
            flags & !supported_flags
        );
        return Err(SyscallError::EINVAL);
    }

    // GAP-5 slice 3: a shared fd table must come with the shared capability
    // table its descriptors' cap ids refer to, which only CLONE_THREAD gives.
    if flags & CLONE_FILES != 0 && flags & CLONE_THREAD == 0 {
        return Err(SyscallError::EINVAL);
    }
    let share_files = flags & CLONE_FILES != 0;

    // CLONE_THREAD 要求必须同时设置 CLONE_VM 和 CLONE_SIGHAND
    if flags & CLONE_THREAD != 0 {
        if flags & CLONE_VM == 0 || flags & CLONE_SIGHAND == 0 {
            return Err(SyscallError::EINVAL);
        }
        // R37-7 FIX: CLONE_THREAD requires a separate stack for the new thread.
        // Sharing the parent's stack leads to data races and corruption.
        if stack.is_null() {
            kprintln!(
                "[sys_clone] CLONE_THREAD rejected: NULL stack would share parent's user stack"
            );
            return Err(SyscallError::EINVAL);
        }

        // R153-3 FIX: Reject CLONE_THREAD if the thread group is exiting (or,
        // GAP-5 leader exec, draining for exec: `closed()`).
        // The shared thread_group.exiting flag is set by exit_group() BEFORE
        // the per-thread pending_kill scan, closing the TOCTOU window where
        // the caller hasn't been marked yet. Also check pending_kill as a
        // fallback for single-thread exit paths.
        {
            let parent = parent_arc.lock();
            if parent.thread_group.closed()
                || parent
                    .pending_kill
                    .load(core::sync::atomic::Ordering::Acquire)
            {
                return Err(SyscallError::EINVAL);
            }
            // GAP-5 slice 4 G6: a thread lives in its group's PID namespace.
            // After unshare(CLONE_NEWPID), pid_ns_for_children names a new
            // namespace that cannot translate the group's tgid (Linux: EINVAL).
            let same_ns = crate::pid_namespace::owning_namespace(&parent.pid_ns_chain)
                .is_some_and(|ns| Arc::ptr_eq(&ns, &parent.pid_ns_for_children));
            if !same_ns {
                return Err(SyscallError::EINVAL);
            }
        }
    }

    // F.1: CLONE_NEWPID cannot be combined with CLONE_THREAD
    // Creating a thread in a new PID namespace makes no sense - threads share PID space
    if flags & CLONE_NEWPID != 0 && flags & CLONE_THREAD != 0 {
        kprintln!("[sys_clone] CLONE_NEWPID cannot be combined with CLONE_THREAD");
        return Err(SyscallError::EINVAL);
    }

    // R161-16 FIX: When CLONE_NEWUSER is present alongside other namespace flags,
    // skip privilege checks for those flags. Linux processes CLONE_NEWUSER first,
    // granting capabilities within the new user namespace. We match this behavior
    // by deferring the check — the new user namespace grants CAP_SYS_ADMIN within it.
    let creating_user_ns = flags & CLONE_NEWUSER != 0;

    // R156-2 FIX: CLONE_NEWPID requires CAP_SYS_ADMIN or root, matching
    // the gates on CLONE_NEWNS/NEWIPC/NEWNET. Previously ungated, allowing
    // unprivileged PID namespace creation and quota exhaustion.
    if flags & CLONE_NEWPID != 0 && !creating_user_ns {
        let has_cap_admin = current_has_cap_rights(cap::CapRights::ADMIN);
        let is_root = crate::current_is_host_root();
        if !is_root && !has_cap_admin {
            kprintln!("[sys_clone] CLONE_NEWPID denied: requires CAP_SYS_ADMIN or root");
            return Err(SyscallError::EPERM);
        }
    }

    // F.1: CLONE_NEWNS cannot be combined with CLONE_THREAD
    // Mount namespace is per-process; threads must share the same mount namespace
    if flags & CLONE_NEWNS != 0 && flags & CLONE_THREAD != 0 {
        kprintln!("[sys_clone] CLONE_NEWNS cannot be combined with CLONE_THREAD");
        return Err(SyscallError::EINVAL);
    }

    // F.1 Security: CLONE_NEWNS requires CAP_SYS_ADMIN (CapRights::ADMIN) or root
    if flags & CLONE_NEWNS != 0 && !creating_user_ns {
        let has_cap_admin = current_has_cap_rights(cap::CapRights::ADMIN);
        // R93-3 FIX: Fail-closed - missing credentials denies access (was unwrap_or(true))
        // R143-2 FIX: Use current_is_host_root() instead of namespace-local euid==0
        // for consistency with sys_setns and cgroup governance gates.
        let is_root = crate::current_is_host_root();
        if !is_root && !has_cap_admin {
            kprintln!("[sys_clone] CLONE_NEWNS denied: requires CAP_SYS_ADMIN or root");
            return Err(SyscallError::EPERM);
        }
    }

    // F.1: CLONE_NEWIPC cannot be combined with CLONE_THREAD
    // IPC namespace is per-process; threads must share the same IPC namespace
    if flags & CLONE_NEWIPC != 0 && flags & CLONE_THREAD != 0 {
        kprintln!("[sys_clone] CLONE_NEWIPC cannot be combined with CLONE_THREAD");
        return Err(SyscallError::EINVAL);
    }

    // F.1 Security: CLONE_NEWIPC requires CAP_SYS_ADMIN or root
    if flags & CLONE_NEWIPC != 0 && !creating_user_ns {
        let has_cap_admin = current_has_cap_rights(cap::CapRights::ADMIN);
        // R93-3 FIX: Fail-closed - missing credentials denies access (was unwrap_or(true))
        // R143-2 FIX: Use current_is_host_root() for consistency with sys_setns.
        let is_root = crate::current_is_host_root();
        if !is_root && !has_cap_admin {
            kprintln!("[sys_clone] CLONE_NEWIPC denied: requires CAP_SYS_ADMIN or root");
            return Err(SyscallError::EPERM);
        }
    }

    // F.1: CLONE_NEWNET cannot be combined with CLONE_THREAD
    // Network namespace is per-process; threads must share the same network namespace
    if flags & CLONE_NEWNET != 0 && flags & CLONE_THREAD != 0 {
        kprintln!("[sys_clone] CLONE_NEWNET cannot be combined with CLONE_THREAD");
        return Err(SyscallError::EINVAL);
    }

    // F.1 Security: CLONE_NEWNET requires CAP_NET_ADMIN (CapRights::ADMIN) or root
    if flags & CLONE_NEWNET != 0 && !creating_user_ns {
        let has_cap_admin = current_has_cap_rights(cap::CapRights::ADMIN);
        // R93-3 FIX: Fail-closed - missing credentials denies access (was unwrap_or(true))
        // R143-2 FIX: Use current_is_host_root() for consistency with sys_setns.
        let is_root = crate::current_is_host_root();
        if !is_root && !has_cap_admin {
            kprintln!("[sys_clone] CLONE_NEWNET denied: requires CAP_NET_ADMIN or root");
            return Err(SyscallError::EPERM);
        }
    }

    // F.1: CLONE_NEWUSER cannot be combined with CLONE_THREAD
    // User namespace is per-process; threads must share the same user namespace
    if flags & CLONE_NEWUSER != 0 && flags & CLONE_THREAD != 0 {
        kprintln!("[sys_clone] CLONE_NEWUSER cannot be combined with CLONE_THREAD");
        return Err(SyscallError::EINVAL);
    }

    // F.1 Security: CLONE_NEWUSER does NOT require CAP_SYS_ADMIN or root.
    // This is intentional - user namespaces enable unprivileged container creation.
    // The only restriction is the system-wide namespace count limit.
    // Namespace depth is enforced by user_namespace::new_child().

    // 验证 parent_tid 指针
    if flags & CLONE_PARENT_SETTID != 0 {
        if parent_tid.is_null() {
            return Err(SyscallError::EINVAL);
        }
        validate_user_ptr_mut(parent_tid as *mut u8, mem::size_of::<i32>())?;
        verify_user_memory(parent_tid as *const u8, mem::size_of::<i32>(), true)?;
    }

    // 验证 child_tid 指针
    if flags & (CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID) != 0 {
        if child_tid.is_null() {
            return Err(SyscallError::EINVAL);
        }
        validate_user_ptr_mut(child_tid as *mut u8, mem::size_of::<i32>())?;
        verify_user_memory(child_tid as *const u8, mem::size_of::<i32>(), true)?;
    }

    // 验证栈指针（如果提供）
    if !stack.is_null() {
        validate_user_ptr(stack as *const u8, 1)?;
    }

    // 从 MSR 读取当前 FS_BASE（TLS 基址）
    // musl 可能通过 wrfsbase 指令直接设置 FS base，绕过 arch_prctl
    // 因此 PCB 中的 fs_base 可能是 0，需要从硬件同步
    let current_fs_base = {
        use x86_64::registers::model_specific::Msr;
        const MSR_FS_BASE: u32 = 0xC000_0100;
        unsafe { Msr::new(MSR_FS_BASE).read() }
    };

    // 从父进程收集必要信息
    let (
        parent_space,
        parent_user_memory_space, // H.3 KPTI: user CR3 root for CLONE_VM sharing
        parent_tgid,
        parent_thread_group, // R153-3 FIX / GAP-5 G1: shared thread-group state
        parent_exec_in_progress, // P1-D: mid-exec gate for CLONE_VM (authoritative recheck below)
        parent_name,
        parent_priority,
        parent_cgroup_id, // R123-2 FIX: for cgroup attachment after create_process
        parent_cpuset_id, // R123-2 FIX: for cpuset inheritance
        parent_allowed_cpus, // R123-2 FIX: for cpuset CPU mask inheritance
        _parent_context,
        parent_user_stack,
        parent_fs_base,
        parent_gs_base,
        parent_credentials_arc, // R39-3 FIX: 共享凭证 Arc
        parent_fs,              // GAP-5 slice 2: root/cwd/umask handle (shared or copied below)
        parent_rlimits,         // M0-6: inherit rlimits on the CLONE_VM/THREAD manual path
        parent_sigactions,      // GAP-5: parent's disposition handle (shared or copied below)
        parent_blocked,         // M0 item 5: inherit blocked mask
        parent_seccomp_state,
        parent_seccomp_generation,
        parent_pledge_state,
        parent_seccomp_installing,
        parent_pid_ns_for_children,   // F.1: PID namespace for children
        parent_mount_ns,              // F.1: Mount namespace
        parent_mount_ns_for_children, // F.1: Mount namespace for children
        parent_ipc_ns,                // F.1: IPC namespace
        parent_ipc_ns_for_children,   // F.1: IPC namespace for children
        parent_net_ns,                // F.1: Network namespace
        parent_net_ns_for_children,   // F.1: Network namespace for children
        parent_user_ns,               // F.1: User namespace
        parent_user_ns_for_children,  // F.1: User namespace for children
        parent_fd_table_snapshot,     // R133-5 FIX: fd_table snapshot under parent lock
        parent_cloexec_snapshot,      // R169-L1 FIX: cloexec_fds snapshot under parent lock
        parent_cap_table_clone,       // R133-5 FIX: cap_table clone under parent lock
        parent_files_table,           // GAP-5 slice 3: shared under CLONE_FILES
    ) = {
        let mut parent = parent_arc.lock();
        // 始终从 MSR 同步 fs_base 到 PCB
        // 这确保即使进程通过 wrfsbase 指令修改了 TLS（绕过 arch_prctl），
        // 子进程也能继承正确的 TLS 基址
        if current_fs_base != 0 {
            parent.fs_base = current_fs_base;
        }

        // R133-5 FIX: Snapshot fd_table and cap_table under the parent lock
        // to avoid child→parent lock order inversion later. Previously,
        // the child lock block re-acquired parent.lock() for CLONE_FILES
        // and cap_table cloning, violating the parent→child lock order
        // used in enforce_lsm_task_fork().
        // R158-7 FIX (LOW): Fallible fd_table snapshot (bounded by MAX_FD).
        // GAP-5 slice 3: both snapshots come from one fd-table critical section.
        let parent_files = parent.files.lock();
        let fd_snapshot: Vec<(i32, crate::process::FileDescriptor)> = {
            let mut snap = Vec::new();
            // GAP-5 slice 3: a shared table needs no copy.
            let source_len = if share_files {
                0
            } else {
                parent_files.fd_table.len()
            };
            if snap.try_reserve_exact(source_len).is_err() {
                drop(parent_files);
                drop(parent);
                return Err(SyscallError::ENOMEM);
            }
            let mut clone_failed = false;
            for (&fd, desc) in parent_files.fd_table.iter().take(source_len) {
                let cloned = match desc.try_clone_box() {
                    Ok(cloned) => cloned,
                    Err(()) => {
                        clone_failed = true;
                        break;
                    }
                };
                snap.push((fd, cloned));
            }
            if clone_failed {
                // Socket/FileOps destructors may acquire foreign locks; never
                // drop already-cloned descriptors under the parent PCB lock.
                drop(parent_files);
                drop(parent);
                drop(snap);
                return Err(SyscallError::ENOMEM);
            }
            snap
        };

        // R169-L1 FIX: Snapshot cloexec_fds under the parent lock too (fallibly,
        // matching fd_snapshot), so a CLONE_FILES child inherits the parent's
        // close-on-exec marks instead of silently losing them (a latent CLOEXEC
        // bypass that diverges from fork.rs). Reading parent.files.cloexec_fds at the
        // child-setup site would re-acquire the parent lock = R133-5 child->parent
        // inversion; the bounded set is rebuilt into the child OUTSIDE the lock.
        let cloexec_snapshot: Vec<i32> = {
            let mut snap = Vec::new();
            let source_len = if share_files {
                0
            } else {
                parent_files.cloexec_fds.len()
            };
            if snap.try_reserve_exact(source_len).is_err() {
                drop(parent_files);
                drop(parent);
                drop(fd_snapshot);
                return Err(SyscallError::ENOMEM);
            }
            snap.extend(parent_files.cloexec_fds.iter().copied().take(source_len));
            snap
        };
        drop(parent_files);

        let cap_clone = if flags & CLONE_THREAD != 0 {
            // Thread: share parent's cap_table (via Arc)
            parent.share_capability_table()
        } else {
            // R25-8 FIX: Non-thread cases must inherit and filter CLOFORK entries
            // R161-4 FIX: Fallible clone + Arc wrapping, sealed in Process.
            match parent.try_clone_capability_table_for_fork(None) {
                Ok(cloned) => cloned,
                Err(_) => {
                    drop(parent);
                    drop(fd_snapshot);
                    drop(cloexec_snapshot);
                    return Err(SyscallError::ENOMEM);
                }
            }
        };

        // D3-ARC-MM-SHARED / P1-D: do NOT Arc::clone(parent.mm) here for later
        // publication. The early snapshot is only used for the CLONE_VM decision
        // surface; the authoritative mm Arc is re-cloned under a re-validated
        // parent lock immediately before installing child.memory_space (below).
        // An early clone alone was insufficient: exec_from_bytes mutates the
        // same MmState Arc in place after its share_count gate, so a sibling
        // that attached to a mid-exec AS would observe rewritten bookkeeping
        // and/or a freed CR3.
        //
        // P1-D FIX: snapshot exec_in_progress so CLONE_VM can fail-closed
        // before create_process when the parent is mid-exec (mutual exclusion
        // with the exec share_count→load_elf→commit window).
        let parent_exec_in_progress = parent.exec_in_progress;

        (
            parent.memory_space,
            parent.user_memory_space, // H.3 KPTI
            parent.tgid,
            parent.thread_group.clone(), // R153-3 FIX / GAP-5 G1
            parent_exec_in_progress,     // P1-D: mid-exec gate for CLONE_VM
            crate::process::ProcessNameSnapshot::from_parts(
                &parent.name,
                if flags & CLONE_THREAD != 0 {
                    "-thread"
                } else {
                    "-clone"
                },
            ),
            parent.priority,
            parent.cgroup_id,    // R123-2 FIX
            parent.cpuset_id,    // R123-2 FIX
            parent.allowed_cpus, // R123-2 FIX
            parent.context,
            parent.user_stack,
            parent.fs_base,
            parent.gs_base,
            parent.shared_credentials(),    // R39-3 FIX: 获取凭证 Arc
            Arc::clone(&parent.fs),         // GAP-5: handle; shared under CLONE_FS
            parent.rlimits, // M0-6: [RLimit; N] is Copy — snapshot under parent lock
            Arc::clone(&parent.sigactions), // GAP-5: handle; shared under CLONE_SIGHAND
            parent.blocked, // M0 item 5: u64 mask
            parent
                .seccomp_state
                .try_clone()
                .map_err(|_| SyscallError::ENOMEM)?,
            parent.seccomp_generation,
            parent.pledge_state.clone(),
            parent.seccomp_installing,
            parent.pid_ns_for_children.clone(), // F.1: PID namespace
            parent.mount_ns.clone(),            // F.1: Mount namespace
            parent.mount_ns_for_children.clone(), // F.1: Mount namespace for children
            parent.ipc_ns.clone(),              // F.1: IPC namespace
            parent.ipc_ns_for_children.clone(), // F.1: IPC namespace for children
            parent.net_ns.clone(),              // F.1: Network namespace
            parent.net_ns_for_children.clone(), // F.1: Network namespace for children
            parent.user_ns.clone(),             // F.1: User namespace
            parent.user_ns_for_children.clone(), // F.1: User namespace for children
            fd_snapshot,                        // R133-5 FIX: fd_table snapshot
            cloexec_snapshot,                   // R169-L1 FIX: cloexec_fds snapshot
            cap_clone,                          // R133-5 FIX: cap_table clone
            Arc::clone(&parent.files),          // GAP-5 slice 3: fd table handle
        )
    };

    // R186-2 FIX: Fail-closed validation for non-CLONE_VM + incompatible flags.
    // Fork (non-CLONE_VM path below at line 4618) creates an independent child with
    // inherited namespaces and cannot honor isolation/sharing/pointer-setup flags.
    // Reject the combination here (after capability checks and namespace snapshots
    // have passed, before any child creation) to prevent silent semantic bypass.
    // This makes the isolation bypass structurally impossible by blocking delegation
    // to sys_fork when incompatible flags are present.
    if flags & CLONE_VM == 0 && (flags & NON_VM_INCOMPATIBLE != 0 || !stack.is_null()) {
        return Err(SyscallError::EINVAL);
    }

    // 决定使用的地址空间
    let (child_space, is_shared_space) = if flags & CLONE_VM != 0 {
        // CLONE_VM: 共享父进程的地址空间
        //
        // P1-D FIX: fail-closed if the parent is mid-exec. exec_from_bytes
        // rewrites the live MmState Arc in place after its share_count gate
        // (with Process lock dropped for load_elf). Attaching a sibling to
        // that mid-exec AS yields stale-mm bookkeeping and can free the old
        // CR3 while the child still maps it. Early reject avoids create_process
        // work; the install site re-checks under the parent lock.
        if parent_exec_in_progress {
            return Err(SyscallError::EBUSY);
        }
        (parent_space, true)
    } else {
        // 不共享地址空间：使用 COW fork
        match crate::fork::sys_fork() {
            Ok((_child_pid, parent_view_pid)) => {
                // R180-19: policy and PID translation were prepared before COW
                // commit, and fork::sys_fork already published the child.
                return Ok(parent_view_pid);
            }
            Err(e) => {
                // R122-1 FIX: Map MmapTransientState to EAGAIN (retriable)
                // to keep behavior consistent with the sys_fork() path.
                use crate::fork::ForkError;
                return Err(match e {
                    ForkError::CgroupPidsLimitExceeded
                    | ForkError::CgroupFilesLimitExceeded
                    | ForkError::MmapTransientState
                    | ForkError::CredentialBusy
                    | ForkError::SchedulerAdmissionFailed => SyscallError::EAGAIN,
                    ForkError::SecurityDenied => SyscallError::EPERM,
                    ForkError::NamespaceTranslationFailed => SyscallError::EFAULT,
                    _ => SyscallError::ENOMEM,
                });
            }
        }
    };

    // R160-14 FIX: Truncate child name to prevent unbounded growth from
    // deeply nested clone chains. The old infallible format!() could
    // accumulate ~230KB names and panic under OOM.
    // RF180-17 FIX: parent_name is already a bounded stack snapshot; String
    // allocation happens only inside the admitted PCB constructor.
    let child_name = parent_name;

    // F.1: Handle CLONE_NEWNS - create new mount namespace
    let (new_mount_ns, mut new_mount_table_guard) = if flags & CLONE_NEWNS != 0 {
        match crate::mount_namespace::clone_namespace(parent_mount_ns.clone()) {
            Ok(ns) => {
                // R74-2 FIX: Eagerly materialize mount namespace tables.
                //
                // Without eager materialization, the child namespace's mount table
                // is created lazily on first VFS access. This creates a race where
                // mounts added to the parent AFTER clone() but BEFORE the child's
                // first VFS access would leak into the child, bypassing namespace
                // isolation.
                //
                // Fix: Materialize both parent and child mount tables NOW to
                // snapshot the parent's mount state at clone time.
                materialize_namespace(&parent_mount_ns).map_err(|_| SyscallError::ENOMEM)?;
                materialize_namespace(&ns).map_err(|_| SyscallError::ENOMEM)?;
                // R180-22 FIX: the VFS mount-table registry is a second
                // publication surface.  Own the exact new namespace table
                // until the child is scheduler-visible; every intervening
                // clone error removes it by globally-unique namespace ID.
                let guard = PreparedMountTableGuard {
                    ns: Arc::clone(&ns),
                    armed: true,
                };

                (Some(ns), Some(guard))
            }
            Err(crate::mount_namespace::MountNsError::MaxDepthExceeded) => {
                klog!(
                    Error,
                    "[sys_clone] Failed to create mount namespace: max depth exceeded"
                );
                return Err(SyscallError::EAGAIN);
            }
            Err(e) => {
                klog!(
                    Error,
                    "[sys_clone] Failed to create mount namespace: {:?}",
                    e
                );
                return Err(SyscallError::ENOMEM);
            }
        }
    } else {
        (None, None)
    };

    // F.1: Handle CLONE_NEWIPC - create new IPC namespace
    let new_ipc_ns = if flags & CLONE_NEWIPC != 0 {
        match crate::ipc_namespace::clone_ipc_namespace(parent_ipc_ns_for_children.clone()) {
            Ok(ns) => {
                // R186-12 FIX: Audit emission moved to post-commit (after scheduler_permit.commit()).
                // Namespace creation succeeds here, but the audit SUCCESS record must reflect
                // the final committed state, not the prepare phase. Early emission causes audit
                // truth violation: a namespace that rolls back on later error still emitted SUCCESS.
                klog!(
                    Info,
                    "[sys_clone] Created new IPC namespace: id={}, level={}",
                    ns.id().raw(),
                    ns.level()
                );

                Some(ns)
            }
            Err(crate::ipc_namespace::IpcNsError::MaxDepthExceeded) => {
                klog!(
                    Error,
                    "[sys_clone] Failed to create IPC namespace: max depth exceeded"
                );
                return Err(SyscallError::EAGAIN);
            }
            // R76-2 FIX: Map MaxNamespaces to EAGAIN (retriable resource limit)
            Err(crate::ipc_namespace::IpcNsError::MaxNamespaces) => {
                klog!(
                    Error,
                    "[sys_clone] Failed to create IPC namespace: max namespaces exceeded"
                );
                return Err(SyscallError::EAGAIN);
            }
            Err(e) => {
                klog!(Error, "[sys_clone] Failed to create IPC namespace: {:?}", e);
                return Err(SyscallError::ENOMEM);
            }
        }
    } else {
        None
    };

    // F.1: Handle CLONE_NEWNET - create new network namespace
    let new_net_ns = if flags & CLONE_NEWNET != 0 {
        match crate::net_namespace::clone_net_namespace(parent_net_ns_for_children.clone()) {
            Ok(ns) => {
                // R186-12 FIX: Audit emission moved to post-commit (after scheduler_permit.commit()).
                // Namespace creation succeeds here, but the audit SUCCESS record must reflect
                // the final committed state, not the prepare phase. Early emission causes audit
                // truth violation: a namespace that rolls back on later error still emitted SUCCESS.
                klog!(
                    Info,
                    "[sys_clone] Created new network namespace: id={}, level={}, has_loopback={}",
                    ns.id().raw(),
                    ns.level(),
                    ns.has_loopback()
                );

                Some(ns)
            }
            Err(crate::net_namespace::NetNsError::MaxDepthExceeded) => {
                klog!(
                    Error,
                    "[sys_clone] Failed to create network namespace: max depth exceeded"
                );
                return Err(SyscallError::EAGAIN);
            }
            // R76-2 FIX: Map MaxNamespaces to EAGAIN (retriable resource limit)
            Err(crate::net_namespace::NetNsError::MaxNamespaces) => {
                klog!(
                    Error,
                    "[sys_clone] Failed to create network namespace: max namespaces exceeded"
                );
                return Err(SyscallError::EAGAIN);
            }
            Err(e) => {
                klog!(
                    Error,
                    "[sys_clone] Failed to create network namespace: {:?}",
                    e
                );
                return Err(SyscallError::ENOMEM);
            }
        }
    } else {
        None
    };

    // F.1: Handle CLONE_NEWUSER - create new user namespace
    let new_user_ns = if flags & CLONE_NEWUSER != 0 {
        match crate::user_namespace::clone_user_namespace(parent_user_ns_for_children.clone()) {
            Ok(ns) => {
                // R186-12 FIX: Audit emission moved to post-commit (after scheduler_permit.commit()).
                // Namespace creation succeeds here, but the audit SUCCESS record must reflect
                // the final committed state, not the prepare phase. Early emission causes audit
                // truth violation: a namespace that rolls back on later error still emitted SUCCESS.
                klog!(
                    Info,
                    "[sys_clone] Created new user namespace: id={}, level={}",
                    ns.id().raw(),
                    ns.level()
                );

                Some(ns)
            }
            Err(crate::user_namespace::UserNsError::MaxDepthExceeded) => {
                klog!(
                    Error,
                    "[sys_clone] Failed to create user namespace: max depth exceeded"
                );
                return Err(SyscallError::EAGAIN);
            }
            Err(crate::user_namespace::UserNsError::MaxNamespaces) => {
                klog!(
                    Error,
                    "[sys_clone] Failed to create user namespace: max namespaces exceeded"
                );
                return Err(SyscallError::EAGAIN);
            }
            Err(e) => {
                klog!(
                    Error,
                    "[sys_clone] Failed to create user namespace: {:?}",
                    e
                );
                return Err(SyscallError::ENOMEM);
            }
        }
    } else {
        None
    };

    // F.1: Handle CLONE_NEWPID - create child in new PID namespace
    let (child_pid, new_pid_ns) = if flags & CLONE_NEWPID != 0 {
        // Create a new child PID namespace
        let new_ns =
            crate::pid_namespace::PidNamespace::new_child(Arc::clone(&parent_pid_ns_for_children))
                .map_err(|e| {
                    // R104-2 FIX: Gate diagnostic println behind debug_assertions.
                    kprintln!("[sys_clone] Failed to create PID namespace: {:?}", e);
                    match e {
                        crate::pid_namespace::PidNamespaceError::MaxDepthExceeded => {
                            SyscallError::EAGAIN
                        }
                        // R76-2 FIX: Map MaxNamespaces to EAGAIN (retriable resource limit)
                        crate::pid_namespace::PidNamespaceError::MaxNamespaces => {
                            SyscallError::EAGAIN
                        }
                        _ => SyscallError::ENOMEM,
                    }
                })?;
        // R104-2 FIX: Gate diagnostic println behind debug_assertions.
        kprintln!(
            "[sys_clone] Created new PID namespace: id={}, level={}",
            new_ns.id().raw(),
            new_ns.level()
        );
        // Create process in the new namespace
        let child_pid = create_process_in_namespace(
            child_name,
            parent_pid,
            parent_priority,
            Arc::clone(&new_ns),
        )
        .map_err(|_| SyscallError::ENOMEM)?;
        (child_pid, Some(new_ns))
    } else {
        // Regular process creation - inherits parent's pid_ns_for_children
        (
            create_process(child_name, parent_pid, parent_priority)
                .map_err(|_| SyscallError::ENOMEM)?,
            None,
        )
    };

    let child_arc = get_process(child_pid).ok_or(SyscallError::ESRCH)?;

    // R180-1 FIX (INV-ARC-01): NEVER re-enter PROCESS_TABLE via get_process while
    // holding a published child's PCB lock — live scanners take PROCESS_TABLE then
    // each PCB (process.rs thread-group / table walks). Child → table is ABBA.
    //
    // All parent rechecks that need the table (live seccomp_installing, abort
    // retain on parent.children) run with the child lock DROPPED, then the child
    // is re-locked. parent_arc is already held as Arc so parent.lock() alone is
    // fine (does not touch PROCESS_TABLE).

    // Pre-child-lock: revalidate parent seccomp / group-exit flags without any
    // child PCB held. Snapshot can race create_process; live recheck closes that.
    let live_seccomp_installing = {
        let parent = parent_arc.lock();
        parent.seccomp_installing
    };
    // GAP-5 leader exec: a group draining for exec is closed like an exiting one.
    let live_group_exiting = parent_thread_group.closed();

    if (is_shared_space && (parent_seccomp_installing || live_seccomp_installing))
        || ((flags & CLONE_THREAD) != 0 && (parent_seccomp_installing || live_seccomp_installing))
    {
        // Never scheduled — drop Arc then cleanup (no child lock held).
        drop(child_arc);
        if let Some(parent) = get_process(parent_pid) {
            parent.lock().children.retain(|&p| p != child_pid);
        }
        cleanup_unscheduled_process(child_pid);
        kprintln!(
            "sys_clone: rejecting CLONE_VM/CLONE_THREAD during seccomp installation (pid={})",
            parent_pid
        );
        return Err(SyscallError::EBUSY);
    }
    if (flags & CLONE_THREAD) != 0 && live_group_exiting {
        drop(child_arc);
        if let Some(parent) = get_process(parent_pid) {
            parent.lock().children.retain(|&p| p != child_pid);
        }
        cleanup_unscheduled_process(child_pid);
        return Err(SyscallError::EINTR);
    }

    // RF180-15 FIX: CLONE_THREAD identity publication linearizes under
    // PROCESS_TABLE with unshare(CLONE_NEWNS). Revalidate the exact namespace
    // sources before tgid becomes visible: clone-first makes unshare observe a
    // second member; unshare-first makes this stale clone abort.
    if flags & CLONE_THREAD != 0 {
        let stale_source = {
            let table = crate::process::PROCESS_TABLE.lock();
            let parent_in_table = table
                .get(parent_pid)
                .and_then(Option::as_ref)
                .is_some_and(|entry| Arc::ptr_eq(entry, &parent_arc));
            let child_in_table = table
                .get(child_pid)
                .and_then(Option::as_ref)
                .is_some_and(|entry| Arc::ptr_eq(entry, &child_arc));
            if !parent_in_table || !child_in_table {
                true
            } else {
                let parent = parent_arc.lock();
                let stale = !Arc::ptr_eq(&parent.mount_ns, &parent_mount_ns)
                    || !Arc::ptr_eq(&parent.pid_ns_for_children, &parent_pid_ns_for_children)
                    || parent.tgid != parent_tgid
                    || parent.seccomp_installing
                    || parent_thread_group.closed();
                if !stale {
                    // GAP-5 slice 4 G5: cache the group's namespace-local id;
                    // the leader's own mapping disappears when it exits.
                    let ns_tgid = if parent.ns_tgid != 0 {
                        parent.ns_tgid
                    } else {
                        crate::pid_namespace::pid_in_owning_namespace(&parent.pid_ns_chain)
                            .unwrap_or(0)
                    };
                    let mut child = child_arc.lock();
                    child.tgid = parent_tgid;
                    child.ns_tgid = ns_tgid;
                    child.is_thread = true;
                    let displaced = core::mem::replace(
                        &mut child.thread_group,
                        Arc::clone(&parent_thread_group),
                    );
                    let freed = crate::process::drop_displaced(displaced);
                    child.release_displaced_charge(freed);
                    // GAP-5 slice 4 G1: PROCESS_TABLE is held here.
                    parent_thread_group.join_locked();
                }
                stale
            }
        };
        if stale_source {
            parent_arc.lock().children.retain(|&p| p != child_pid);
            cleanup_unscheduled_process(child_pid);
            return Err(SyscallError::EAGAIN);
        }
    }

    let prepared_private_credentials = if flags & CLONE_THREAD == 0 {
        let prepared = (|| {
            let parent = parent_credentials_arc
                .try_read()
                .ok_or(SyscallError::EAGAIN)?;
            let supplementary_groups = mm::AdmittedVec::try_copy_from_slice(
                mm::HeapClass::CoreProcess,
                &parent.supplementary_groups,
            )
            .map_err(|_| SyscallError::ENOMEM)?;
            let credentials = crate::process::Credentials {
                uid: parent.uid,
                gid: parent.gid,
                euid: parent.euid,
                egid: parent.egid,
                supplementary_groups,
            };
            let reservation = mm::try_reserve_heap(
                mm::HeapClass::CoreProcess,
                mm::arc_charge_bytes::<crate::process::SharedCredentials>()
                    .map_err(|_| SyscallError::ENOMEM)?,
            )
            .map_err(|_| SyscallError::ENOMEM)?;
            let credentials = Arc::try_new(crate::process::SharedCredentials::new(credentials))
                .map_err(|_| SyscallError::ENOMEM)?;
            Ok::<_, SyscallError>(Some((credentials, reservation)))
        })();
        match prepared {
            Ok(prepared) => prepared,
            Err(error) => {
                parent_arc.lock().children.retain(|&p| p != child_pid);
                cleanup_unscheduled_process(child_pid);
                return Err(error);
            }
        }
    } else {
        None
    };

    {
        let mut child = child_arc.lock();

        // 设置线程标识
        child.tid = child_pid; // tid == pid (Linux 语义)
        if flags & CLONE_THREAD != 0 {
            // R26-3 / R163-13 / R180-1: live seccomp and group-exit were re-checked
            // ABOVE without holding the child PCB (canonical PROCESS_TABLE → PCB
            // order). Under the child lock we only publish thread-group identity.
            // Identity and shared exit token were published under PROCESS_TABLE
            // above; never republish them outside the linearization lock.

            // R153-3: re-check the shared atomic (no table re-entry) after tgid
            // publish — still race-free vs exit_group's set-before-scan protocol.
            if parent_thread_group.closed() {
                child.state = ProcessState::Terminated;
                drop(child);
                drop(child_arc);
                // Child lock released before get_process (R180-1).
                if let Some(parent) = get_process(parent_pid) {
                    parent.lock().children.retain(|&p| p != child_pid);
                }
                cleanup_unscheduled_process(child_pid);
                return Err(SyscallError::EINTR);
            }
        } else {
            child.tgid = child_pid; // 新线程组
            child.is_thread = false;
        }

        // 设置地址空间
        //
        // P1-D FIX: for CLONE_VM, re-validate the parent under its Process lock
        // BEFORE publishing child.memory_space / child.mm. The early snapshot of
        // parent_space alone is not enough: exec_from_bytes can pass its
        // share_count gate, arm exec_in_progress, drop the Process lock for
        // load_elf, then commit a NEW CR3 while rewriting the same MmState Arc
        // in place. Without this recheck a concurrent clone would install the
        // OLD CR3 + OLD (now rewritten) mm Arc into the child → stale-mm and
        // potential UAF when exec frees the old AS.
        //
        // Lock order: Process-parent → Process-child is inverted if we lock
        // parent while holding child. Drop child first, re-lock parent, then
        // re-lock child (parent→child is the canonical order used by
        // enforce_lsm_task_fork). create_process has not scheduled the child,
        // so no concurrent child-side lock contention exists.
        //
        // Rebind `child` on both arms so the rest of this block always holds a
        // live MutexGuard (the is_shared_space arm moves the original guard).
        let mut child = if is_shared_space {
            // Drop child lock before taking parent (avoid child→parent inversion).
            drop(child);

            // P1-D: hold parent for the entire validate→publish window so
            // exec cannot arm/commit between Arc::clone and child.memory_space
            // publication. Order: parent → child (canonical).
            let parent = parent_arc.lock();
            // GAP-5 leader exec: a non-thread CLONE_VM child of a group whose
            // leader is draining it for exec would keep the old address space
            // shared. Checked under the child lock that publishes the space:
            // the drain claims its flag before it scans PCBs for such sharers,
            // so either that scan sees this child or this check sees the claim.
            let mut child = child_arc.lock();
            if parent.exec_in_progress
                || (flags & CLONE_THREAD == 0 && parent.thread_group.exec_draining())
                || parent.memory_space != parent_space
                || parent.user_memory_space != parent_user_memory_space
                || parent.memory_space == 0
            {
                drop(child);
                drop(parent);
                // Parent mid-exec or AS changed since snapshot — abort the
                // never-scheduled child. memory_space is still 0 (default), so
                // cleanup will not free any shared CR3.
                drop(child_arc);
                if let Some(p) = get_process(parent_pid) {
                    p.lock().children.retain(|&p| p != child_pid);
                }
                cleanup_unscheduled_process(child_pid);
                kprintln!(
                    "sys_clone: rejecting CLONE_VM — parent mid-exec or address space changed (parent={})",
                    parent_pid
                );
                return Err(SyscallError::EBUSY);
            }
            // Fresh Arc::clone under the held parent lock.
            let live_mm = Arc::clone(&parent.mm);
            child.memory_space = parent_space;
            child.user_memory_space = parent_user_memory_space;
            let displaced_mm = core::mem::replace(&mut child.mm, live_mm);
            let freed = crate::process::drop_displaced(displaced_mm);
            child.release_displaced_charge(freed);
            // Parent still held until here → share_count now sees the child;
            // concurrent exec's recheck/arm will EBUSY.
            drop(parent);
            child
        } else {
            child.memory_space = child_space;
            child
        };

        // 从当前 syscall 帧构建子进程上下文
        // 使用 syscall 帧而非 parent.context，因为后者是上次调度时的状态
        // R102-6 FIX: Use closure-based API to prevent syscall frame reference escape.
        let frame_applied = with_current_syscall_frame(|frame| {
            // R101-2 FIX: Gate SyscallFrame debug print behind debug_assertions
            kprintln!(
                "[sys_clone] SyscallFrame: rcx(rip)=0x{:x}, rsp=0x{:x}, r9=0x{:x}",
                frame.rcx,
                frame.rsp,
                frame.r9
            );

            // 从 syscall 帧复制寄存器状态
            child.context.rax = 0; // 子进程 clone 返回值 = 0
            child.context.rbx = frame.rbx;
            child.context.rcx = frame.rcx; // 用户 RIP (SYSCALL 保存)
            child.context.rdx = frame.rdx;
            child.context.rsi = frame.rsi;
            child.context.rdi = frame.rdi;
            child.context.rbp = frame.rbp;
            child.context.r8 = frame.r8;
            child.context.r9 = frame.r9;
            child.context.r10 = frame.r10;
            child.context.r11 = frame.r11; // 用户 RFLAGS
            child.context.r12 = frame.r12;
            child.context.r13 = frame.r13;
            child.context.r14 = frame.r14;
            child.context.r15 = frame.r15;
            // RIP = RCX (syscall 保存的用户返回地址)
            child.context.rip = frame.rcx;
            // RFLAGS = R11 (syscall 保存的用户 RFLAGS)
            child.context.rflags = frame.r11;
            // 用户态段选择子
            child.context.cs = 0x23; // USER_CODE_SELECTOR
            child.context.ss = 0x1b; // USER_DATA_SELECTOR

            // 设置栈指针
            if !stack.is_null() {
                let sp = stack as u64;
                child.context.rsp = sp;
                child.context.rbp = sp; // 子线程清空 frame pointer
                child.user_stack = Some(VirtAddr::new(sp));
            } else {
                child.context.rsp = frame.rsp;
                child.user_stack = parent_user_stack;
            }
        });

        // R103-1 FIX (fail-closed): If the syscall frame is unavailable (cleared by
        // a preemptive context switch racing switch_context's gs:[frame_ptr]=0 reset),
        // we MUST NOT fall back to `parent.context`.  That snapshot may contain ring-0
        // CS/SS, a stale kernel RSP, or state from a different scheduling epoch — any
        // of which would crash or escalate privilege once the child is scheduled.
        //
        // Instead, terminate the child and return EBUSY so the caller can retry.
        if frame_applied.is_none() {
            kprintln!(
                "sys_clone: ABORT - syscall frame not available, refusing stale context (pid={})",
                child_pid
            );
            child.state = ProcessState::Terminated;
            child.memory_space = 0; // Do not free shared address space
            drop(child);
            // H.0.9 FIX: Child was never scheduled — use cleanup_unscheduled_process
            // to avoid cgroup/cpuset/IPC detach on never-joined subsystems.
            if let Some(parent) = get_process(parent_pid) {
                parent.lock().children.retain(|&p| p != child_pid);
            }
            cleanup_unscheduled_process(child_pid);
            return Err(SyscallError::EBUSY);
        }

        // R102-10 FIX: Gate register/address dump behind debug_assertions.
        // Leaks child RIP/RSP which defeats userspace ASLR.
        kprintln!(
            "[sys_clone] Child {} ctx: rax=0x{:x}, rip=0x{:x}, rsp=0x{:x}, r9=0x{:x}, rcx=0x{:x}",
            child_pid,
            child.context.rax,
            child.context.rip,
            child.context.rsp,
            child.context.r9,
            child.context.rcx
        );

        // 设置 TLS
        // R24-2 fix: 验证 TLS 基址是 canonical 且在用户空间范围内
        // 避免非法地址导致后续 WRMSR 时 #GP 内核崩溃
        if flags & CLONE_SETTLS != 0 {
            if !is_canonical(tls) || tls >= USER_SPACE_TOP as u64 {
                // 非法 TLS 地址：先释放child锁再清理，避免死锁
                // 标记进程为终止状态并清零共享地址空间引用
                child.state = ProcessState::Terminated;
                child.memory_space = 0; // 不释放共享地址空间
                drop(child);
                // H.0.9 FIX: Child was never scheduled — use cleanup_unscheduled_process
                // to avoid cgroup/cpuset/IPC detach on never-joined subsystems.
                if let Some(parent) = get_process(parent_pid) {
                    parent.lock().children.retain(|&p| p != child_pid);
                }
                cleanup_unscheduled_process(child_pid);
                return Err(SyscallError::EINVAL);
            }
            child.fs_base = tls;
        } else {
            child.fs_base = parent_fs_base;
        }
        child.gs_base = parent_gs_base;

        // R101-2 FIX: Gate TLS debug print behind debug_assertions
        kprintln!(
            "[sys_clone] TLS: msr_fs=0x{:x}, parent_fs=0x{:x}, child_fs=0x{:x}",
            current_fs_base,
            parent_fs_base,
            child.fs_base
        );

        // 设置 tid 指针
        if flags & CLONE_CHILD_SETTID != 0 {
            child.set_child_tid = child_tid as u64;
        }
        if flags & CLONE_CHILD_CLEARTID != 0 {
            child.clear_child_tid = child_tid as u64;
        }

        // Credential identity stays prepared until scheduler admission below
        // establishes Provisioning; the LSM check uses that same prepared Arc.
        // GAP-5 slice 2: CLONE_FS shares the root/cwd/umask handle; otherwise the
        // child's own admitted handle receives a copy. The displaced private
        // handle is dropped with `displaced_sigactions`, after the child guard.
        let displaced_fs = if flags & CLONE_FS != 0 {
            Some(core::mem::replace(&mut child.fs, Arc::clone(&parent_fs)))
        } else {
            child.fs.copy_from(&parent_fs);
            None
        };
        // M0-6: inherit rlimits on the CLONE_VM/THREAD manual-construction path
        // (the non-CLONE_VM path goes through fork_inner, which copies them too).
        // Per-task copy = the documented M0 divergence from thread-group sharing.
        child.rlimits = parent_rlimits;

        // GAP-5 slice 1: CLONE_SIGHAND shares the parent's disposition table;
        // otherwise the child's own (already admitted) table receives a copy.
        // Only dispositions are shared: the blocked mask is copied per task and
        // `saved_blocked` / `in_signal_handler` stay born-clean. The displaced
        // private table is held in `displaced_sigactions` and dropped right
        // after the child guard below (no final Arc drop under a PCB lock).
        let displaced_sigactions = if flags & CLONE_SIGHAND != 0 {
            Some(core::mem::replace(
                &mut child.sigactions,
                Arc::clone(&parent_sigactions),
            ))
        } else {
            child.sigactions.copy_from(&parent_sigactions);
            None
        };
        child.blocked = parent_blocked;
        // N2.6a: Linux clone(2) disables sigaltstack when CLONE_VM is set
        // (without CLONE_VFORK), which matches born-clean `SigAltStack::disabled()`.
        child.sigaltstack = crate::signal::SigAltStack::disabled();

        // RF180-1 FIX: publish the snapshotted sandbox state only while holding
        // parent -> child in canonical order and only if the committed seccomp
        // revision is unchanged.  The old post-create boolean sample missed an
        // install that completed between the initial snapshot and that sample:
        // `seccomp_installing` was false again while the child still received
        // the stale pre-install filter stack.
        drop(child);
        // GAP-5 (review D4): return the displaced tables' charge to the child.
        let freed = displaced_sigactions.map_or(0, crate::process::drop_displaced)
            + displaced_fs.map_or(0, crate::process::drop_displaced);
        if freed != 0 {
            child_arc.lock().release_displaced_charge(freed);
        }
        let parent = parent_arc.lock();
        if parent.seccomp_installing || parent.seccomp_generation != parent_seccomp_generation {
            drop(parent);
            let mut child = child_arc.lock();
            child.state = ProcessState::Terminated;
            // This manual clone path shares the parent's address space.  The
            // unscheduled-child cleanup must not free either shared CR3.
            child.memory_space = 0;
            child.user_memory_space = 0;
            drop(child);
            drop(child_arc);
            if let Some(parent) = get_process(parent_pid) {
                parent.lock().children.retain(|&p| p != child_pid);
            }
            cleanup_unscheduled_process(child_pid);
            return Err(SyscallError::EBUSY);
        }
        let mut child = child_arc.lock();
        child.seccomp_state = parent_seccomp_state;
        child.pledge_state = parent_pledge_state;
        child.sync_seccomp_or_pledge_flag();
        // Keep the parent locked until both assignments are visible.  A new
        // installation therefore cannot commit in the snapshot->publish gap.
        drop(parent);

        // GAP-5 slice 3 step 3: CLONE_FILES (inside a thread group) shares the
        // creator's table; the owner count makes the last exit close it. The
        // child's own table being displaced is empty and was never published,
        // so dropping it (at the end of this block) runs no descriptor drop.
        let displaced_files = if share_files {
            parent_files_table.lock().add_owner();
            Some(core::mem::replace(
                &mut child.files,
                Arc::clone(&parent_files_table),
            ))
        } else {
            None
        };
        drop(parent_files_table);
        // GAP-5 (review D4): the empty displaced table is freed here.
        if let Some(displaced) = displaced_files {
            let freed = crate::process::drop_displaced(displaced);
            child.release_displaced_charge(freed);
        }

        // R133-5 FIX: Use pre-captured fd_table snapshot instead of re-acquiring
        // parent lock (which would create child→parent lock order inversion).
        if !share_files {
            // R180-7/R180-19: admit both retained containers before consuming
            // any descriptor clone. Publication below is allocation-free; on
            // refusal the snapshots are dropped only after the PCB lock.
            let child_files = Arc::clone(&child.files);
            let mut child_files = child_files.lock();
            let storage_ready = child_files
                .fd_table
                .ensure_capacity_for(parent_fd_table_snapshot.len())
                .and_then(|()| {
                    child_files
                        .cloexec_fds
                        .ensure_capacity_for(parent_cloexec_snapshot.len())
                })
                .is_ok();
            if !storage_ready {
                drop(child_files);
                child.state = ProcessState::Terminated;
                child.memory_space = 0;
                child.user_memory_space = 0;
                drop(child);
                drop(parent_fd_table_snapshot);
                drop(parent_cloexec_snapshot);
                if let Some(parent) = get_process(parent_pid) {
                    parent.lock().children.retain(|&p| p != child_pid);
                }
                cleanup_unscheduled_process(child_pid);
                return Err(SyscallError::ENOMEM);
            }
            for (fd, desc) in parent_fd_table_snapshot {
                if child_files
                    .fd_table
                    .insert_unique_reserved(fd, desc)
                    .is_err()
                {
                    panic!("prepared CLONE_FILES descriptor slot disappeared");
                }
            }
            // R169-L1 FIX: Inherit the close-on-exec marks captured under the
            // parent lock. The rebuild is bounded by MAX_FD and runs OUTSIDE the
            // parent lock, so the infallible BTreeSet insert cannot panic while a
            // foreign lock is held. Matches fork.rs, closing the CLOEXEC-bypass
            // parity gap (VD-03) where a CLONE_FILES child silently lost CLOEXEC.
            for fd in parent_cloexec_snapshot {
                if child_files.cloexec_fds.insert_reserved(fd).is_err() {
                    panic!("prepared CLONE_FILES CLOEXEC slot disappeared");
                }
            }
        }

        // R133-5 FIX: Use pre-captured cap_table clone instead of re-acquiring
        // parent lock. See snapshot above (under parent lock block).
        child.install_capability_table(parent_cap_table_clone);

        // U.S3-A3 FIX: pay the per-fd cap refcounts for the CLONE_THREAD case.
        // A thread SHARES the parent's cap_table (Arc), while its fd_table is a
        // DEEP COPY (snapshot loop above) — so every cap-bearing fd installed
        // in the child adds one real reference to a SHARED CapEntry and must
        // bump it (+1 each), exactly like dup. The non-thread CLONE_FILES case
        // must NOT bump: try_clone_for_fork gave the child its OWN table with
        // refcounts VERBATIM-copied (U.S3-A1), already equal to the child's
        // 1:1 fd copy count. Failure (InvalidCapId) = a sibling revoked the
        // cap between snapshot and install; the child fd is then a documented
        // dead handle (its close decrement is a no-op) — accepted race class.
        // Balanced at thread exit by free_process_resources' per-fd decrement
        // (U.S3-B), and on clone-abort by cleanup_unscheduled_process → the
        // same teardown path.
        // A shared table installs no copies, so it adds no references.
        if flags & CLONE_THREAD != 0 && !share_files {
            let child_files = Arc::clone(&child.files);
            for desc in child_files.lock().fd_table.values() {
                if let Some(cid) = desc.cap_id() {
                    child.capability_increment_refcount(cid);
                }
            }
        }

        // F.1 Mount Namespace: Assign mount namespace to child
        //
        // CLONE_NEWNS: Use the new mount namespace created earlier
        // Without CLONE_NEWNS: Inherit parent's mount_ns_for_children
        let child_mount_ns = new_mount_ns
            .clone()
            .unwrap_or_else(|| parent_mount_ns_for_children.clone());
        child.mount_ns = child_mount_ns.clone();
        child.mount_ns_for_children = child_mount_ns;

        // F.1 IPC Namespace: Assign IPC namespace to child
        //
        // CLONE_NEWIPC: Use the new IPC namespace created earlier
        // Without CLONE_NEWIPC: Inherit parent's ipc_ns_for_children
        let child_ipc_ns = new_ipc_ns
            .clone()
            .unwrap_or_else(|| parent_ipc_ns_for_children.clone());
        child.ipc_ns = child_ipc_ns.clone();
        child.ipc_ns_for_children = child_ipc_ns;

        // F.1 Network Namespace: Assign network namespace to child
        //
        // CLONE_NEWNET: Use the new network namespace created earlier
        // Without CLONE_NEWNET: Inherit parent's net_ns_for_children
        let child_net_ns = new_net_ns
            .clone()
            .unwrap_or_else(|| parent_net_ns_for_children.clone());
        child.net_ns = child_net_ns.clone();
        child.net_ns_for_children = child_net_ns;

        // F.1 User Namespace: Assign user namespace to child
        //
        // CLONE_NEWUSER: Use the new user namespace created earlier
        // Without CLONE_NEWUSER: Inherit parent's user_ns_for_children
        //
        // Note: User namespace does not require root/CAP_SYS_ADMIN, enabling
        // unprivileged container creation. UID/GID mappings can be set later
        // via /proc/[pid]/uid_map and /proc/[pid]/gid_map.
        let child_user_ns = new_user_ns
            .clone()
            .unwrap_or_else(|| parent_user_ns_for_children.clone());
        child.user_ns = child_user_ns.clone();
        child.user_ns_for_children = child_user_ns;

        // 设置进程状态为就绪
        child.enter_ready_at(crate::get_ticks());
    }

    // D3-ARC-MM-SHARED: reconcile_clone_vm_mmap_regions is no longer needed.
    // CLONE_VM children share the same Arc<Mutex<MmState>> as the parent,
    // so all updates are automatically visible to all siblings.

    // F.1 PID Namespace: Translate child's global PID to parent's namespace view
    //
    // Linux semantics: clone() returns the child's PID as seen from the parent's
    // namespace. This is the same PID the parent will use for kill(), waitpid(), etc.
    //
    // For processes in the root namespace, this is the same as the global PID.
    // For processes in child namespaces, the parent sees a different PID.
    //
    // R94-6 FIX: Translation failure returns EFAULT instead of leaking global PID.
    // H.0.9 FIX: Translation failure must clean up the unscheduled child.
    let parent_view_pid = {
        let parent = parent_arc.lock();
        let owning_ns = crate::pid_namespace::owning_namespace(&parent.pid_ns_chain);
        if let Some(ns) = owning_ns {
            crate::pid_namespace::pid_in_namespace(&ns, child_pid)
        } else {
            // No namespace chain (shouldn't happen), fall back to global PID
            Some(child_pid)
        }
    };
    let parent_view_pid = match parent_view_pid {
        Some(pid) => pid,
        None => {
            // Child was created via create_process() and never scheduled.
            if let Some(parent) = get_process(parent_pid) {
                parent.lock().children.retain(|&p| p != child_pid);
            }
            cleanup_unscheduled_process(child_pid);
            return Err(SyscallError::EFAULT);
        }
    };

    // F.1 PID Namespace: Get child's own namespace-local PID for CLONE_CHILD_SETTID
    //
    // CLONE_CHILD_SETTID writes the TID the child sees for itself.
    // This is the child's PID in its owning namespace (the deepest namespace).
    // With CLONE_NEWPID, the child's owning namespace is a new child namespace,
    // where it is PID 1 (the init process of that namespace).
    // R94-6 FIX: Translation failure returns EFAULT instead of leaking global PID.
    // H.0.9 FIX: Translation failure must clean up the unscheduled child.
    let child_view_pid = {
        let child = child_arc.lock();
        crate::pid_namespace::pid_in_owning_namespace(&child.pid_ns_chain)
    };
    let child_view_pid = match child_view_pid {
        Some(pid) => pid,
        None => {
            // Child was created via create_process() and never scheduled.
            if let Some(parent) = get_process(parent_pid) {
                parent.lock().children.retain(|&p| p != child_pid);
            }
            cleanup_unscheduled_process(child_pid);
            return Err(SyscallError::EFAULT);
        }
    };

    // R104-3 FIX: Move LSM check BEFORE user memory writes to prevent observable
    // side effects when policy denies the clone. Previously, copy_to_user wrote the
    // child TID to user memory before the LSM gate, creating a side channel. Also,
    // copy_to_user failure (EFAULT) returned immediately without cleaning up the
    // fully-constructed child process, leaking PID/kernel-stack/address-space.
    //
    // LSM hook: check if policy allows this fork/clone
    // Must be BEFORE user memory writes and scheduler notification
    // Keep the prepared (Arc, reservation) owner intact across every fallible
    // step. Tuple fields drop in order: the allocation must be released before
    // its temporary credit on error. A separately bound reservation would drop
    // before the earlier Arc local. Installation consumes only this Arc clone.
    let child_credentials = prepared_private_credentials
        .as_ref()
        .map(|(credentials, _reservation)| Arc::clone(credentials))
        .unwrap_or_else(|| Arc::clone(&parent_credentials_arc));
    enforce_lsm_task_fork(parent_pid, child_pid, &child_credentials)?;

    // R123-2 FIX: Propagate cgroup + cpuset membership for sys_clone tasks.
    //
    // create_process() initializes cgroup_id=0 (root). Without explicit
    // attachment, CLONE_THREAD tasks bypass pids.max, memory.max, and cpu.max
    // — a container escape via resource exhaustion. The fork path (fork.rs:73-148)
    // handles this correctly; this brings sys_clone to parity.
    //
    // Must be AFTER enforce_lsm_task_fork() because that helper uses
    // cleanup_unscheduled_process() which skips cgroup/cpuset teardown.
    // We attach here so rollback paths below can detach symmetrically.
    //
    // R149-4 FIX: For CLONE_VM, the early parent_cgroup_id snapshot (captured
    // under parent lock at line ~2802) may be stale — cgroup migration could
    // have changed the parent's cgroup_id between snapshot and here.  By this
    // point, child.memory_space is set (line ~3195), making share_count > 1,
    // which blocks further migration via R148-5.  Re-read the parent's
    // cgroup_id now to get the stable, post-migration value.
    let parent_cgroup_id = if is_shared_space {
        get_process(parent_pid)
            .map(|p| p.lock().cgroup_id)
            .unwrap_or(parent_cgroup_id)
    } else {
        parent_cgroup_id
    };
    if !crate::cgroup::check_fork_allowed(parent_cgroup_id) {
        if let Some(parent) = get_process(parent_pid) {
            parent.lock().children.retain(|&p| p != child_pid);
        }
        cleanup_unscheduled_process(child_pid);
        return Err(SyscallError::EAGAIN);
    }

    {
        let mut child = child_arc.lock();
        child.set_cgroup_id(parent_cgroup_id);
        child.cpuset_id = parent_cpuset_id;
        child.allowed_cpus = parent_allowed_cpus;
    }

    if let Some(cgroup) = crate::cgroup::lookup_cgroup(parent_cgroup_id) {
        if cgroup.attach_task(child_pid as u64).is_err() {
            if let Some(parent) = get_process(parent_pid) {
                parent.lock().children.retain(|&p| p != child_pid);
            }
            cleanup_unscheduled_process(child_pid);
            return Err(SyscallError::EAGAIN);
        }
    }

    // R180-19: reserve scheduler storage before user-visible TID writes and
    // before the final FD charge. The child remains Provisioning in the queue;
    // all later failures cancel the exact slot before tearing the PCB down.
    let scheduler_permit = match crate::process::prepare_clone_scheduler_add_process(
        Arc::clone(&child_arc),
        child_credentials,
    ) {
        Ok(permit) => permit,
        Err(_) => {
            if let Some(cg) = crate::cgroup::lookup_cgroup(parent_cgroup_id) {
                let _ = cg.detach_task(child_pid as u64);
            }
            if let Some(parent) = get_process(parent_pid) {
                parent.lock().children.retain(|&p| p != child_pid);
            }
            cleanup_unscheduled_process(child_pid);
            return Err(SyscallError::EAGAIN);
        }
    };
    // The PCB's admitted fixed charge now owns the installed credential Arc;
    // its temporary preparation reservation can be returned after installation.
    drop(prepared_private_credentials);

    // E.5 Cpuset: update task count after successful cgroup attach.
    crate::process::notify_cpuset_task_joined(parent_cpuset_id);

    // R174-A2: FD charge moved AFTER all error paths (see line 4644+ below).
    // This prevents double-uncharge when copy_to_user fails.

    // 写入 parent_tid (F.1: use parent's view of child's PID)
    if flags & CLONE_PARENT_SETTID != 0 {
        if let Err(e) = store_user_tid(parent_tid, parent_view_pid) {
            drop(scheduler_permit);
            // R104-3 FIX: Clean up child process on copy_to_user failure to prevent
            // PID / kernel-stack / address-space leak.
            // R123-2 FIX: Child is now attached to cgroup + cpuset; roll back
            // those subsystems before cleanup_unscheduled_process().
            if let Some(cg) = crate::cgroup::lookup_cgroup(parent_cgroup_id) {
                let _ = cg.detach_task(child_pid as u64);
            }
            crate::process::notify_cpuset_task_left(parent_cpuset_id);
            if let Some(parent) = get_process(parent_pid) {
                parent.lock().children.retain(|&p| p != child_pid);
            }
            cleanup_unscheduled_process(child_pid);
            return Err(e);
        }
    }

    // 写入 child_tid（在共享地址空间中，子进程会看到此值）
    // F.1: use child's own namespace-local PID (not parent's view)
    //
    // With CLONE_NEWPID, parent sees child as e.g. PID 5, but child sees itself as PID 1.
    // The child uses this value for futex operations, robust_list, etc., so it must match
    // what gettid() returns to the child.
    if flags & CLONE_CHILD_SETTID != 0 {
        if let Err(e) = store_user_tid(child_tid, child_view_pid) {
            drop(scheduler_permit);
            // R104-3 FIX: Clean up child process on copy_to_user failure.
            // R123-2 FIX: Child is now attached to cgroup + cpuset; roll back
            // those subsystems before cleanup_unscheduled_process().
            if let Some(cg) = crate::cgroup::lookup_cgroup(parent_cgroup_id) {
                let _ = cg.detach_task(child_pid as u64);
            }
            crate::process::notify_cpuset_task_left(parent_cpuset_id);
            if let Some(parent) = get_process(parent_pid) {
                parent.lock().children.retain(|&p| p != child_pid);
            }
            cleanup_unscheduled_process(child_pid);
            return Err(e);
        }
    }

    // R174-A2 FIX: Charge FDs AFTER all error paths (moved from line 4577-4600).
    //
    // RATIONALE: The FD charge is the LAST resource acquisition that can fail.
    // All prior error paths (LSM denial, cgroup attach failure, copy_to_user
    // failure) must NOT see a charged fds_charged_count, otherwise
    // cleanup_unscheduled_process double-uncharges:
    //   1. cleanup calls free_process_resources (process.rs:5119-5121)
    //   2. free_process_resources uncharges fds_charged_count
    //   3. BUT the parent still holds the FD references (child fd_table was
    //      deep-copied at line 4390-4400, parent never lost those FDs)
    //   4. When parent exits, it uncharges the SAME FDs again → double-uncharge
    //      → fds_current underflow → delete-gate bypass
    //
    // By charging HERE (after copy_to_user), we guarantee:
    // 1. All error paths before this point uncharge 0 FDs (idempotent)
    // 2. After this point, only ONE error path remains (FD charge failure itself)
    // 3. The charge/uncharge lifecycle is symmetric
    //
    // INVARIANT (FD-CHARGE-LAST):
    //   fds_charged_count is set ONLY after all error paths that call
    //   cleanup_unscheduled_process(). This ensures error-path uncharge is
    //   idempotent (uncharges 0 when nothing was charged).
    //
    // J2-7: per-cgroup FD budget — batch-charge the child's copied fds. Only
    // CLONE_FILES populates the child fd_table (deep copy); otherwise it is empty
    // (count 0, a no-op). Charge to the child's now-attached cgroup.
    // GAP-5 slice 3: a shared table is already charged to its owner cgroup.
    let child_fd_count = if share_files {
        0
    } else {
        let child = child_arc.lock();
        let count = child.files.lock().fd_table.len() as u64;
        count
    };
    if child_fd_count > 0 {
        // NOTE: This is the ONLY remaining error path after copy_to_user.
        // On failure, we must manually rollback cgroup/cpuset/cleanup.
        if crate::cgroup::try_charge_fds(parent_cgroup_id, child_fd_count).is_err() {
            drop(scheduler_permit);
            if let Some(cg) = crate::cgroup::lookup_cgroup(parent_cgroup_id) {
                let _ = cg.detach_task(child_pid as u64);
            }
            crate::process::notify_cpuset_task_left(parent_cpuset_id);
            if let Some(parent) = get_process(parent_pid) {
                parent.lock().children.retain(|&p| p != child_pid);
            }
            cleanup_unscheduled_process(child_pid);
            return Err(SyscallError::EAGAIN);
        }
        child_arc.lock().files.lock().fds_charged_count = child_fd_count;
    }

    // GAP-5 slice 4 G1: a thread is not its creator's child. No rollback path
    // remains (cleanup_unscheduled_process reads `ppid == 0` as "joined a
    // cpuset", so this must follow the last one), and the child is not yet
    // runnable. `ppid == 0` keeps it out of SIGCHLD, parent wakes and wait*;
    // getppid reads the group leader instead.
    if flags & CLONE_THREAD != 0 {
        parent_arc.lock().children.retain(|&p| p != child_pid);
        child_arc.lock().ppid = 0;
    }

    // Allocation-free publication of the already-reserved queue entry.
    scheduler_permit.commit();
    if let Some(guard) = new_mount_table_guard.as_mut() {
        guard.commit();
    }

    // R186-12/RF186-8: Post-commit audit emission for every namespace type.
    // Audit SUCCESS records must only be emitted after the child is committed to the scheduler.
    // Early emission (pre-commit) creates audit truth violations: if a later error causes rollback,
    // the audit log claims SUCCESS for a namespace that was never finalized.
    // This mirrors the mount namespace audit pattern (RF180-16).

    if let Some(ref new_ipc_ns) = new_ipc_ns {
        let parent_id = new_ipc_ns.parent().map(|p| p.id().raw()).unwrap_or(0);
        let _ = audit::emit(
            AuditKind::Process,
            AuditOutcome::Success,
            get_audit_subject(),
            AuditObject::Namespace {
                ns_id: new_ipc_ns.id().raw(),
                ns_type: CLONE_NEWIPC as u32,
                parent_id,
            },
            &[56, flags, CLONE_NEWIPC],
            0,
            crate::time::current_timestamp_ms(),
        );
    }

    if let Some(ref new_net_ns) = new_net_ns {
        let parent_id = new_net_ns.parent().map(|p| p.id().raw()).unwrap_or(0);
        let _ = audit::emit(
            AuditKind::Process,
            AuditOutcome::Success,
            get_audit_subject(),
            AuditObject::Namespace {
                ns_id: new_net_ns.id().raw(),
                ns_type: CLONE_NEWNET as u32,
                parent_id,
            },
            &[56, flags, CLONE_NEWNET],
            0,
            crate::time::current_timestamp_ms(),
        );
    }

    if let Some(ref new_user_ns) = new_user_ns {
        let parent_id = new_user_ns.parent().map(|p| p.id().raw()).unwrap_or(0);
        let _ = audit::emit(
            AuditKind::Process,
            AuditOutcome::Success,
            get_audit_subject(),
            AuditObject::Namespace {
                ns_id: new_user_ns.id().raw(),
                ns_type: CLONE_NEWUSER as u32,
                parent_id,
            },
            &[56, flags, CLONE_NEWUSER],
            0,
            crate::time::current_timestamp_ms(),
        );
    }

    if let Some(ref new_pid_ns) = new_pid_ns {
        let parent_id = new_pid_ns
            .parent()
            .map(|parent| parent.id().raw())
            .unwrap_or(0);
        let _ = audit::emit(
            AuditKind::Process,
            AuditOutcome::Success,
            get_audit_subject(),
            AuditObject::Namespace {
                ns_id: new_pid_ns.id().raw(),
                ns_type: CLONE_NEWPID as u32,
                parent_id,
            },
            &[56, flags, CLONE_NEWPID],
            0,
            crate::time::current_timestamp_ms(),
        );
    }

    // RF180-16: audit SUCCESS belongs to COMMIT, never PREPARE. Every clone
    // failure above leaves the guard armed, rolls the VFS table back, and emits
    // no success record for a namespace that was never published.
    if let Some(ns) = new_mount_ns.as_ref() {
        klog!(
            Info,
            "[sys_clone] Created new mount namespace: id={}, level={} (eagerly materialized)",
            ns.id().raw(),
            ns.level()
        );
        let parent_id = ns.parent().map(|p| p.id().raw()).unwrap_or(0);
        let _ = audit::emit(
            AuditKind::Process,
            AuditOutcome::Success,
            get_audit_subject(),
            AuditObject::Namespace {
                ns_id: ns.id().raw(),
                ns_type: CLONE_NEWNS as u32,
                parent_id,
            },
            &[56, flags, CLONE_NEWNS],
            0,
            crate::time::current_timestamp_ms(),
        );
    }

    // R101-2 FIX: Gate clone completion debug print behind debug_assertions.
    // Leaks global child PID and clone flags.
    kprintln!(
        "sys_clone: parent={}, child={} (parent_view={}, child_view={}), flags=0x{:x}, is_thread={}",
        parent_pid,
        child_pid,
        parent_view_pid,
        child_view_pid,
        flags,
        flags & CLONE_THREAD != 0
    );

    // F.1: Return namespace-local PID to parent (Linux semantics)
    Ok(parent_view_pid)
}

/// sys_wait - 等待子进程
///
/// 阻塞当前进程直到一个子进程终止，然后收割该僵尸进程并返回其 PID 和退出码。
///
/// # Arguments
///
/// * `status` - 指向用户态 i32 的指针，用于存储子进程的退出码。可为 NULL。
///
/// # Returns
///
/// * 成功：返回已终止子进程的 PID
/// * ECHILD：当前进程没有子进程
/// * EFAULT：status 指针无效
/// sys_wait4 - Linux-ABI wait4(pid, wstatus, options, rusage)
///
/// ST-K3 FIX (wait4 ABI): formerly `sys_wait(status)` with any-child-only
/// semantics and the RAW exit code written to *status. Now:
/// - `pid_sel > 0`  → reap only that child (ECHILD if it is not a child);
/// - `pid_sel == -1` → reap any child (the historical behavior);
/// - `pid_sel == 0` / `< -1` (process-group selectors) → EINVAL, fail-closed:
///   the PCB tracks no process groups (D2-ABI census row);
/// - `WNOHANG` → returns 0 instead of blocking when nothing is reapable;
///   `WUNTRACED`/`WCONTINUED` are accepted and ignored (no job-control stop
///   reporting), unknown option bits → EINVAL;
/// - *wstatus gets the Linux encoding for a normal exit: (code & 0xff) << 8
///   (WIFEXITED true, WEXITSTATUS = code). Signal deaths surface as this
///   kernel's unified 128+sig exit code, i.e. as an "exited" status — the
///   single-exit-code model predates signaled-death wstatus encoding.
pub(super) fn sys_wait4(
    pid_sel: i64,
    status: *mut i32,
    options: i32,
    entry_proc: Option<ProcessArc>,
) -> SyscallResult {
    if options & !(WNOHANG | WUNTRACED | WCONTINUED) != 0 {
        return Err(SyscallError::EINVAL);
    }
    if pid_sel == 0 || pid_sel < -1 {
        return Err(SyscallError::EINVAL);
    }
    let target = if pid_sel > 0 {
        WaitTarget::Pid(pid_sel as ProcessId)
    } else {
        WaitTarget::Any
    };

    // The wstatus store is the core's `publish` step: it runs at the point the
    // old inline code wrote it — after a reapable zombie is chosen, before the
    // child is unlinked and cleaned up — so an EFAULT leaves the zombie
    // reapable and restores the parent to Ready.
    let publish = |outcome: &WaitOutcome| -> Result<(), SyscallError> {
        if status.is_null() {
            return Ok(());
        }
        let wstatus: i32 = (outcome.exit_code & 0xff) << 8;
        copy_to_user(status as *mut u8, &wstatus.to_ne_bytes())
    };

    match wait_reap_core_with_parent(target, options & WNOHANG != 0, false, publish, entry_proc)? {
        Some(outcome) => Ok(outcome.view_pid),
        // WNOHANG with nothing reapable.
        None => Ok(0),
    }
}

pub(super) const WNOHANG: i32 = 0x1;
pub(super) const WUNTRACED: i32 = 0x2;
pub(super) const WCONTINUED: i32 = 0x8;

/// Which children a wait call will accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WaitTarget {
    /// Any child (`wait4(-1, ..)`, `waitid(P_ALL, ..)`).
    Any,
    /// Exactly this child, named in the caller's PID namespace.
    Pid(ProcessId),
}

/// A reaped child, described both globally and as the caller sees it.
pub(super) struct WaitOutcome {
    pub(super) global_pid: ProcessId,
    pub(super) view_pid: ProcessId,
    pub(super) exit_code: i32,
}

/// Resolve the wake filter before publishing Blocked. A PID selector must
/// never temporarily admit sibling exits. Use the child's retained identity:
/// live namespace maps may already have been detached by exit.
///
/// No parent PCB guard is held while looking up or locking a child. The caller
/// MUST scan for reapable children after this returns: an exit during identity
/// resolution either precedes that scan or sees the published wait and wakes it.
/// False leaves the caller runnable so stale/incomplete child-list recovery can
/// run without ever falling back to an any-child wait for an unresolved PID.
pub(super) fn prepare_child_wait(
    parent: &crate::process::ProcessArc,
    pid: ProcessId,
    target: WaitTarget,
    children: &[ProcessId],
    namespace: &crate::pid_namespace::PidNamespaceArc,
    lookup: impl FnMut(ProcessId) -> Option<crate::process::ProcessArc>,
) -> Result<bool, SyscallError> {
    prepare_child_wait_checked(parent, pid, target, children, namespace, None, lookup)
}

pub(super) fn prepare_child_wait_checked(
    parent: &crate::process::ProcessArc,
    pid: ProcessId,
    target: WaitTarget,
    children: &[ProcessId],
    namespace: &crate::pid_namespace::PidNamespaceArc,
    expected_child_events: Option<u64>,
    mut lookup: impl FnMut(ProcessId) -> Option<crate::process::ProcessArc>,
) -> Result<bool, SyscallError> {
    let wake_pid = match target {
        WaitTarget::Any => Some(0),
        WaitTarget::Pid(want) => children.iter().find_map(|&global| {
            let child = lookup(global)?;
            let child = child.lock();
            (child.ppid == pid && child.wait_pid_in_namespace(namespace) == Some(want))
                .then_some(global)
        }),
    };
    let mut proc = parent.lock();
    // Signal/kill publishers take this same lock. Recheck immediately before
    // committing Blocked so an interrupt racing with identity resolution wins.
    if crate::signal::should_abort_pending_block(&proc) {
        proc.enter_ready_at(crate::get_ticks());
        proc.waiting_child = None;
        return Err(SyscallError::EINTR);
    }
    // If an already-reapable zombie was adopted (or a child exited) after
    // `children` was snapshotted, decline to publish Blocked on the stale
    // snapshot so the wait loop re-snapshots `proc.children` before halting.
    let stale_snapshot =
        expected_child_events.is_some_and(|seen| proc.thread_group.child_events() != seen);
    if let Some(global) = wake_pid.filter(|_| !stale_snapshot) {
        proc.enter_blocked_at(crate::get_ticks());
        proc.waiting_child = Some(global);
        Ok(true)
    } else {
        proc.enter_ready_at(crate::get_ticks());
        proc.waiting_child = None;
        Ok(false)
    }
}

#[cfg(all(test, feature = "host_harness", not(target_os = "none")))]
mod selective_wait_tests {
    extern crate std;

    use super::*;
    use crate::pid_namespace::{PidNamespace, PidNamespaceArc, PidNamespaceMembership};
    use crate::process::{Process, ProcessArc, ProcessNameSnapshot, ThreadGroup};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) enum GroupWaitPhase {
        Scanned,
        Checked,
        Blocked,
    }

    std::thread_local! {
        // Only the waiter under test sees these hooks. Parallel hosted tests
        // and the production kernel never acquire a test callback or barrier.
        static GROUP_WAIT_HOOK: std::cell::RefCell<Option<std::boxed::Box<dyn FnMut(GroupWaitPhase)>>> =
            const { std::cell::RefCell::new(None) };
    }

    pub(super) fn group_wait_phase(phase: GroupWaitPhase) {
        GROUP_WAIT_HOOK.with_borrow_mut(|hook| {
            if let Some(hook) = hook {
                hook(phase);
            }
        });
    }

    struct GroupWaitHook;

    impl Drop for GroupWaitHook {
        fn drop(&mut self) {
            GROUP_WAIT_HOOK.with_borrow_mut(|hook| *hook = None);
        }
    }

    const HANDOFF_TIMEOUT: Duration = Duration::from_secs(10);

    fn pause_group_wait(
        phase: GroupWaitPhase,
        reached: &mpsc::Sender<GroupWaitPhase>,
        resume: &mpsc::Receiver<()>,
    ) {
        reached.send(phase).unwrap();
        resume
            .recv_timeout(HANDOFF_TIMEOUT)
            .expect("group wait interleaving did not finish");
    }

    fn fixture(pid: usize, ppid: usize, view_pid: usize, ns: &PidNamespaceArc) -> ProcessArc {
        mm::publish_heap_budgets();
        let process = Process::try_new_pcb(
            pid,
            ppid,
            ProcessNameSnapshot::from_parts("selective-wait", ""),
            120,
        )
        .unwrap();
        {
            let mut proc = process.lock();
            proc.pid_ns_chain.try_reserve(1).unwrap();
            proc.pid_ns_chain
                .push_reserved(PidNamespaceMembership {
                    ns: ns.clone(),
                    pid: view_pid,
                })
                .unwrap();
        }
        process
    }

    fn namespace() -> PidNamespaceArc {
        mm::publish_heap_budgets();
        PidNamespace::new_child(crate::pid_namespace::ROOT_PID_NAMESPACE.clone()).unwrap()
    }

    static GROUP_FIXTURE_SERIAL: spin::Mutex<()> = spin::Mutex::new(());

    /// Run the actual group scan/block loop and group notifier on published
    /// PCBs, without installing a scheduler callback or physical stacks. The
    /// caller is a non-leader waiting for another thread's children. WNOWAIT
    /// keeps synthetic zombies out of physical-resource teardown.
    struct GroupFixture {
        owner: ProcessArc,
        caller: ProcessArc,
        sibling: ProcessArc,
        target: ProcessArc,
        outsider: ProcessArc,
        group: Arc<ThreadGroup>,
        base: ProcessId,
        _serial: spin::MutexGuard<'static, ()>,
    }

    impl GroupFixture {
        fn new() -> Self {
            let serial = GROUP_FIXTURE_SERIAL.lock();
            let ns = namespace();
            let base = {
                let table = crate::process::PROCESS_TABLE.lock();
                // Separate from the child-creation fixtures' 768..1024 slots.
                (2048..4096)
                    .step_by(5)
                    .find(|base| {
                        (*base..*base + 5).all(|pid| table.get(pid).is_none_or(Option::is_none))
                    })
                    .expect("unused group-wait fixture slots")
            };
            let owner = fixture(base, 0, 1, &ns);
            let caller = fixture(base + 1, 0, 2, &ns);
            let sibling = fixture(base + 2, base, 3, &ns);
            let target = fixture(base + 3, base, 4, &ns);
            let outsider = fixture(base + 4, 0, 5, &ns);
            let group = owner.lock().thread_group.clone();
            {
                let mut proc = caller.lock();
                proc.thread_group = group.clone();
                proc.tgid = base;
                proc.ns_tgid = 1;
            }
            {
                let mut proc = owner.lock();
                proc.children.try_reserve_exact(2).unwrap();
                proc.children.push_reserved(base + 2).unwrap();
                proc.children.push_reserved(base + 3).unwrap();
            }
            // Matching PID alone must not wake a task outside the parent group.
            {
                let mut proc = outsider.lock();
                proc.enter_blocked_at(0);
                proc.waiting_child = Some(base + 3);
            }
            {
                let mut table = crate::process::PROCESS_TABLE.lock();
                if table.len() < base + 5 {
                    let missing = base + 5 - table.len();
                    table.try_reserve_exact(missing).unwrap();
                    while table.len() < base + 5 {
                        table.push_reserved(None).unwrap();
                    }
                }
                for (offset, proc) in [&owner, &caller, &sibling, &target, &outsider]
                    .into_iter()
                    .enumerate()
                {
                    assert!(table[base + offset].is_none());
                    table[base + offset] = Some(proc.clone());
                }
                group.join_locked();
            }
            Self {
                owner,
                caller,
                sibling,
                target,
                outsider,
                group,
                base,
                _serial: serial,
            }
        }

        fn wait(
            &self,
            hook: impl FnMut(GroupWaitPhase) + 'static,
        ) -> Result<Option<WaitOutcome>, SyscallError> {
            GROUP_WAIT_HOOK.with_borrow_mut(|slot| {
                assert!(slot.is_none());
                *slot = Some(std::boxed::Box::new(hook));
            });
            let _hook = GroupWaitHook;
            assert_eq!(self.group.members(), 2);
            wait_reap_group(
                WaitTarget::Pid(4),
                false,
                true,
                |_| Ok(()),
                self.base + 1,
                &self.caller,
                &self.group,
            )
        }

        fn exit(&self, child: &ProcessArc, code: i32) -> bool {
            let pid = {
                let mut proc = child.lock();
                proc.state = ProcessState::Zombie;
                proc.exit_code = Some(code);
                proc.teardown_done
                    .store(true, core::sync::atomic::Ordering::Release);
                proc.pid
            };
            crate::process::wake_group_child_waiters(&self.group, pid)
        }

        fn assert_target(&self, result: Result<Option<WaitOutcome>, SyscallError>) {
            let outcome = result.unwrap().expect("target must be reported");
            assert_eq!(
                (outcome.global_pid, outcome.view_pid, outcome.exit_code),
                (self.base + 3, 4, 22)
            );
            let caller = self.caller.lock();
            assert_eq!(caller.state, ProcessState::Ready);
            assert_eq!(caller.waiting_child, None);
            assert_eq!(self.target.lock().state, ProcessState::Zombie);
            assert_eq!(self.outsider.lock().state, ProcessState::Blocked);
        }
    }

    impl Drop for GroupFixture {
        fn drop(&mut self) {
            let mut table = crate::process::PROCESS_TABLE.lock();
            for (offset, proc) in [
                &self.owner,
                &self.caller,
                &self.sibling,
                &self.target,
                &self.outsider,
            ]
            .into_iter()
            .enumerate()
            {
                let slot = &mut table[self.base + offset];
                if slot.as_ref().is_some_and(|entry| Arc::ptr_eq(entry, proc)) {
                    *slot = None;
                }
            }
            // Fixture fields retain the PCBs until after the table is unlocked.
        }
    }

    #[test]
    fn group_pid_wait_sibling_exit_does_not_wake_another_threads_waiter() {
        let fixture = GroupFixture::new();
        let (reached, phases) = mpsc::channel();
        let (resume, proceed) = mpsc::channel();
        std::thread::scope(|threads| {
            let waiter = threads.spawn(|| {
                fixture.wait(move |phase| {
                    if phase == GroupWaitPhase::Blocked {
                        pause_group_wait(phase, &reached, &proceed);
                    }
                })
            });
            assert_eq!(
                phases.recv_timeout(HANDOFF_TIMEOUT).unwrap(),
                GroupWaitPhase::Blocked
            );
            assert_eq!(fixture.caller.lock().state, ProcessState::Blocked);
            assert!(!fixture.exit(&fixture.sibling, 11));
            assert_eq!(fixture.caller.lock().state, ProcessState::Blocked);
            assert_eq!(fixture.caller.lock().waiting_child, Some(fixture.base + 3));
            assert!(fixture.exit(&fixture.target, 22));
            assert_eq!(fixture.caller.lock().state, ProcessState::Ready);
            resume.send(()).unwrap();
            fixture.assert_target(waiter.join().unwrap());
            assert_eq!(fixture.sibling.lock().state, ProcessState::Zombie);
        });
    }

    #[test]
    fn group_pid_wait_exit_after_scan_prevents_stale_block_publication() {
        let fixture = GroupFixture::new();
        let (reached, phases) = mpsc::channel();
        let (resume, proceed) = mpsc::channel();
        std::thread::scope(|threads| {
            let waiter = threads.spawn(|| {
                let mut first_scan = true;
                fixture.wait(move |phase| {
                    assert_ne!(phase, GroupWaitPhase::Blocked, "lost child event");
                    if phase == GroupWaitPhase::Scanned && first_scan {
                        first_scan = false;
                        pause_group_wait(phase, &reached, &proceed);
                    }
                })
            });
            assert_eq!(
                phases.recv_timeout(HANDOFF_TIMEOUT).unwrap(),
                GroupWaitPhase::Scanned
            );
            assert_eq!(fixture.group.child_events(), 0);
            assert!(!fixture.exit(&fixture.target, 22));
            assert_eq!(fixture.group.child_events(), 1);
            resume.send(()).unwrap();
            fixture.assert_target(waiter.join().unwrap());
        });
    }

    #[test]
    fn group_pid_wait_exit_after_event_check_wakes_the_published_wait() {
        let fixture = GroupFixture::new();
        let (reached, phases) = mpsc::channel();
        let (resume, proceed) = mpsc::channel();
        std::thread::scope(|threads| {
            let waiter = threads.spawn(|| {
                fixture.wait(move |phase| {
                    if phase != GroupWaitPhase::Scanned {
                        pause_group_wait(phase, &reached, &proceed);
                    }
                })
            });
            assert_eq!(
                phases.recv_timeout(HANDOFF_TIMEOUT).unwrap(),
                GroupWaitPhase::Checked
            );
            // The waiter still holds its PCB lock after reading child_events.
            // The notifier publishes the event, then must wait for that lock.
            assert!(fixture.caller.try_lock().is_none());
            let notifier = threads.spawn(|| fixture.exit(&fixture.target, 22));
            let deadline = Instant::now() + HANDOFF_TIMEOUT;
            while fixture.group.child_events() == 0 {
                assert!(Instant::now() < deadline, "child event was not published");
                std::thread::yield_now();
            }
            assert!(!notifier.is_finished());
            resume.send(()).unwrap();
            assert_eq!(
                phases.recv_timeout(HANDOFF_TIMEOUT).unwrap(),
                GroupWaitPhase::Blocked
            );
            assert!(notifier.join().unwrap(), "target exit must wake the waiter");
            assert_eq!(fixture.caller.lock().state, ProcessState::Ready);
            assert_eq!(fixture.caller.lock().waiting_child, None);
            resume.send(()).unwrap();
            fixture.assert_target(waiter.join().unwrap());
        });
    }

    #[test]
    fn selective_wait_sibling_exit_cannot_wake_between_publication_and_scan() {
        let ns = namespace();
        let parent = fixture(100, 1, 1, &ns);
        let fast = fixture(200, 100, 2, &ns);
        let slow = fixture(300, 100, 3, &ns);
        assert!(
            prepare_child_wait(&parent, 100, WaitTarget::Pid(3), &[200, 300], &ns, |pid| {
                assert!(
                    parent.try_lock().is_some(),
                    "parent/child locks must not nest"
                );
                Some(if pid == 200 {
                    fast.clone()
                } else {
                    slow.clone()
                })
            })
            .unwrap()
        );
        // Force the exact old race: a sibling exit arrives after publication,
        // before the first reapability scan. Exercise the production waker
        // shared by notification and the final switch-out handoff.
        let mut proc = parent.lock();
        assert!(!proc.wake_for_child_exit(200, 1));
        assert_eq!(proc.state, ProcessState::Blocked);
        assert_eq!(proc.waiting_child, Some(300));
        assert!(proc.wake_for_child_exit(300, 2));
        assert_eq!(proc.state, ProcessState::Ready);
        assert_eq!(proc.waiting_child, None);
        assert!(!proc.wake_for_child_exit(300, 3));
    }

    #[test]
    fn selective_wait_target_exit_during_resolution_is_visible_to_the_rescan() {
        let ns = namespace();
        let parent = fixture(100, 1, 1, &ns);
        let child = fixture(200, 100, 2, &ns);
        assert!(
            prepare_child_wait(&parent, 100, WaitTarget::Pid(2), &[200], &ns, |_| {
                // Exit before publication cannot wake a runnable parent. Its
                // zombie remains visible to the required post-publication scan.
                child.lock().state = ProcessState::Zombie;
                assert!(!parent.lock().wake_for_child_exit(200, 1));
                Some(child.clone())
            })
            .unwrap()
        );
        assert_eq!(child.lock().state, ProcessState::Zombie);
        assert_eq!(child.lock().wait_pid_in_namespace(&ns), Some(2));
        assert_eq!(parent.lock().waiting_child, Some(200));
        // Teardown/switch-out completing after publication still wakes it.
        assert!(parent.lock().wake_for_child_exit(200, 2));
    }

    #[test]
    fn selective_wait_missing_or_reparented_target_never_arms_any_child() {
        let ns = namespace();
        let parent = fixture(100, 1, 1, &ns);
        let stranger = fixture(200, 999, 2, &ns);
        // A scheduler may have declined the preceding switch; clear that old
        // wait when the identity is no longer a child of this parent.
        {
            let mut proc = parent.lock();
            proc.enter_blocked_at(0);
            proc.waiting_child = Some(200);
        }
        assert!(
            !prepare_child_wait(&parent, 100, WaitTarget::Pid(2), &[200, 300], &ns, |pid| {
                (pid == 200).then(|| stranger.clone())
            })
            .unwrap()
        );
        let mut proc = parent.lock();
        assert_eq!(proc.state, ProcessState::Ready);
        assert_eq!(proc.waiting_child, None);
        assert!(!proc.wake_for_child_exit(300, 1));
    }

    #[test]
    fn selective_wait_kill_during_resolution_prevents_blocking() {
        let ns = namespace();
        let parent = fixture(100, 1, 1, &ns);
        let child = fixture(200, 100, 2, &ns);
        assert_eq!(
            prepare_child_wait(&parent, 100, WaitTarget::Pid(2), &[200], &ns, |_| {
                parent
                    .lock()
                    .pending_kill
                    .store(true, core::sync::atomic::Ordering::Release);
                Some(child.clone())
            }),
            Err(SyscallError::EINTR)
        );
        assert_eq!(parent.lock().state, ProcessState::Ready);
        assert_eq!(parent.lock().waiting_child, None);
    }

    #[test]
    fn selective_wait_any_child_keeps_its_broad_wake_contract() {
        let ns = namespace();
        let parent = fixture(100, 1, 1, &ns);
        assert!(
            prepare_child_wait(&parent, 100, WaitTarget::Any, &[200], &ns, |_| {
                panic!("any-child wait needs no PID translation")
            })
            .unwrap()
        );
        let mut proc = parent.lock();
        assert_eq!(proc.waiting_child, Some(0));
        assert!(proc.wake_for_child_exit(200, 1));
        assert_eq!(proc.waiting_child, None);
    }
}

/// Shared blocking reap loop behind `wait4(2)` and `waitid(2)`.
///
/// This is the lost-wakeup-critical path: `Blocked` + `waiting_child` are
/// published BEFORE the child scan so a child exiting in the gap still wakes
/// the parent, and every exit edge must restore `Ready` and clear
/// `waiting_child`. Both callers share it so those invariants have one home.
///
/// `publish` runs once a reapable zombie is selected and before it is unlinked;
/// returning `Err` aborts the reap with the child still reapable.
///
/// `nowait` implements `WNOWAIT`: the child is reported but left as a reapable
/// zombie (not unlinked, not cleaned up), so a later wait sees it again.
///
/// Returns `Ok(None)` only when `nohang` is set and nothing is reapable yet.
pub(super) fn wait_reap_core<W>(
    target: WaitTarget,
    nohang: bool,
    nowait: bool,
    publish: W,
) -> Result<Option<WaitOutcome>, SyscallError>
where
    W: FnMut(&WaitOutcome) -> Result<(), SyscallError>,
{
    wait_reap_core_with_parent(target, nohang, nowait, publish, None)
}

pub(super) fn wait_reap_core_with_parent<W>(
    target: WaitTarget,
    nohang: bool,
    nowait: bool,
    mut publish: W,
    entry_proc: Option<ProcessArc>,
) -> Result<Option<WaitOutcome>, SyscallError>
where
    W: FnMut(&WaitOutcome) -> Result<(), SyscallError>,
{
    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let parent = entry_proc
        .or_else(|| get_process(pid))
        .ok_or(SyscallError::ESRCH)?;
    let mut resumed_from_block = false;

    // GAP-5 G8: a thread of a multi-threaded process waits for the children of
    // every thread in its group. Also check for the O(1) direct already-zombie
    // reap fast path (single-threaded root-namespace `waitpid(child_pid)`):
    // avoids heap Vec snapshot, sibling PCB scans, and Ready->Blocked->Ready
    // transitions when the requested child is already a reapable zombie.
    enum FastWaitCheck {
        MultiThread(Arc<crate::process::ThreadGroup>),
        DirectCandidate(ProcessId, crate::pid_namespace::PidNamespaceArc),
        AbortEintr,
        SlowPath,
    }
    let fast_check = {
        let proc = parent.lock();
        if proc.thread_group.members() > 1 {
            FastWaitCheck::MultiThread(Arc::clone(&proc.thread_group))
        } else if crate::signal::should_abort_pending_block(&proc) {
            FastWaitCheck::AbortEintr
        } else if let WaitTarget::Pid(want) = target {
            let ns = crate::pid_namespace::owning_namespace(&proc.pid_ns_chain)
                .unwrap_or_else(|| crate::pid_namespace::ROOT_PID_NAMESPACE.clone());
            if Arc::ptr_eq(&ns, &crate::pid_namespace::ROOT_PID_NAMESPACE)
                && proc.children.contains(&want)
            {
                FastWaitCheck::DirectCandidate(want, ns)
            } else {
                FastWaitCheck::SlowPath
            }
        } else {
            FastWaitCheck::SlowPath
        }
    };
    match fast_check {
        FastWaitCheck::MultiThread(group) => {
            return wait_reap_group(target, nohang, nowait, publish, pid, &parent, &group);
        }
        FastWaitCheck::AbortEintr => {
            return Err(SyscallError::EINTR);
        }
        FastWaitCheck::DirectCandidate(want, parent_namespace) => {
            let direct_zombie = get_process(want).and_then(|child_proc| {
                let child = child_proc.lock();
                if child.ppid == pid
                    && child.wait_pid_in_namespace(&parent_namespace) == Some(want)
                    && child.state == ProcessState::Zombie
                    && child
                        .teardown_done
                        .load(core::sync::atomic::Ordering::Acquire)
                    && !child.on_cpu.load(core::sync::atomic::Ordering::Acquire)
                    && !child
                        .switch_reap_pending
                        .load(core::sync::atomic::Ordering::Acquire)
                    && child.tgid == want
                    && child.thread_group.members() == 1
                {
                    Some(WaitOutcome {
                        global_pid: want,
                        view_pid: want,
                        exit_code: child.exit_code.unwrap_or(0),
                    })
                } else {
                    None
                }
            });
            if let Some(outcome) = direct_zombie {
                if nowait || crate::process::claim_wait_reap(want) {
                    if let Err(e) = publish(&outcome) {
                        if !nowait {
                            crate::process::release_wait_reap(want);
                        }
                        return Err(e);
                    }
                    if nowait {
                        return Ok(Some(outcome));
                    }
                    {
                        let mut proc = parent.lock();
                        proc.children.retain(|&c| c != want);
                    }
                    cleanup_zombie(want);
                    return Ok(Some(outcome));
                }
            }
        }
        FastWaitCheck::SlowPath => {}
    }

    loop {
        // C3 repair 3 (#90): this CPU's wait sequence before the pass, for the
        // halt at the end of it.
        let snapshot = crate::wait_kick::snapshot();
        // R171-F3 FIX: a pending kill interrupts wait() with EINTR instead of
        // re-blocking on children. Restore Ready + clear the waiting_child marker
        // so the scheduler/teardown sees a runnable task (not a stuck Blocked one).
        if wait_should_abort(pid) {
            let mut proc = parent.lock();
            proc.enter_ready_at(crate::get_ticks());
            proc.waiting_child = None;
            return Err(SyscallError::EINTR);
        }
        // M0-5 sub-slice 1b: same EINTR cleanup for a deliverable handler signal — restore
        // Ready AND clear the waiting_child marker (the load-bearing cleanup; dropping it
        // strands a confused parent). SEPARATE from the kill gate (kill-first).
        if crate::signal::has_deliverable_signal(pid) {
            let mut proc = parent.lock();
            proc.enter_ready_at(crate::get_ticks());
            proc.waiting_child = None;
            return Err(SyscallError::EINTR);
        }
        // GAP-5 slice 4 G1: reap exited non-leader threads before the scan. A
        // group is reportable only once its last thread is reaped, and on a
        // busy-waiting single CPU this loop may be the only process context left
        // to run the drain (it already calls cleanup_zombie, so the context is
        // the same). The same holds for a child killed at a timer interrupt: it
        // stays non-runnable until the deferred IRQ-kill drain ends it. The
        // Blocked recheck below still runs before the scan, so a SIGCHLD with a
        // handler that this drain posts ends the wait with EINTR (pre-existing;
        // Linux scans first and reports the child).
        crate::process::run_blocked_wait_drains();
        // Snapshot the children and owning PID namespace in ONE parent lock.
        // For `WaitTarget::Pid(want)` in the root PID namespace where `want`
        // is already listed in `proc.children`, avoid heap-allocating the full
        // sibling list and avoid locking unrelated sibling PCBs during
        // `prepare_child_wait` and the reapability scan.
        enum WaitChildList {
            Single([ProcessId; 1]),
            Many(Vec<ProcessId>),
        }
        impl WaitChildList {
            #[inline]
            fn as_slice(&self) -> &[ProcessId] {
                match self {
                    Self::Single(one) => one,
                    Self::Many(many) => many.as_slice(),
                }
            }
        }
        let (child_list, parent_namespace, events_before_snapshot) = {
            let mut proc = parent.lock();
            let events_before = proc.thread_group.child_events();
            if proc.children.is_empty() {
                if !proc.children_incomplete {
                    // ST-K3 FIX (W-1 Blocked-leak class): on iteration >= 2 a
                    // PREVIOUS iteration published Blocked and
                    // `force_reschedule` can return WITHOUT switching
                    // (`reschedule_now` bails on drain/finish_pending_prev
                    // try_lock contention or !preemptible), so this bail-out
                    // can run with Blocked still live. Restoring is idempotent
                    // and unconditionally safe on iteration 1.
                    proc.enter_ready_at(crate::get_ticks());
                    proc.waiting_child = None;
                    return Err(SyscallError::ECHILD);
                }
                // R158-4 Phase 2: children_incomplete is set — do PROCESS_TABLE fallback scan.
                let parent_ns = crate::pid_namespace::owning_namespace(&proc.pid_ns_chain)
                    .unwrap_or_else(|| crate::pid_namespace::ROOT_PID_NAMESPACE.clone());
                drop(proc);
                let mut found = Vec::new();
                // R180-14 FIX: track whether a matching child was seen but skipped
                // because try_reserve failed. Clearing children_incomplete on an
                // empty `found` when that happens permanently loses the recovery
                // path (ECHILD despite live orphans → unreapable zombies / PID pin).
                let mut reserve_failed = false;
                // RF180-9 FIX: keep the table locked from the orphan scan through
                // any `children_incomplete` clear. Reparenting publishes children
                // under this same lock, so dropping it after the empty proof let a
                // child arrive before the flag clear and permanently lose the
                // fallback-scan marker. No PCB is held on entry; the clear below
                // follows the canonical PROCESS_TABLE -> parent PCB order.
                let table = crate::process::PROCESS_TABLE.lock();
                for (idx, slot) in table.iter().enumerate() {
                    if let Some(proc_arc) = slot {
                        let p = proc_arc.lock();
                        if p.ppid == pid && idx != pid {
                            if found.try_reserve(1).is_ok() {
                                found.push(idx);
                            } else {
                                reserve_failed = true;
                                // Keep scanning so we know whether any match
                                // exists even if we cannot snapshot it.
                            }
                        }
                    }
                }
                if found.is_empty() {
                    if reserve_failed {
                        // Live children may exist; surface ENOMEM and leave the
                        // incomplete flag set so a later wait rescans.
                        // ST-K3 FIX (W-1): restore Ready — a prior iteration may
                        // have left Blocked published (PROCESS_TABLE -> parent
                        // PCB is the canonical order; the table is held here).
                        let mut proc = parent.lock();
                        proc.enter_ready_at(crate::get_ticks());
                        proc.waiting_child = None;
                        return Err(SyscallError::ENOMEM);
                    }
                    // Complete allocation-free scan proved no orphans. The table
                    // remains held until this clear commits, closing the lost-clear
                    // race with concurrent reparenting.
                    let mut proc = parent.lock();
                    proc.children_incomplete = false;
                    // ST-K3 FIX (W-1): this path MUTATES children_incomplete, so
                    // leaving Blocked set would strand the task with the rescan
                    // marker already cleared.
                    proc.enter_ready_at(crate::get_ticks());
                    proc.waiting_child = None;
                    return Err(SyscallError::ECHILD);
                }
                // R180-14 (iteration-2): any reserve failure means the snapshot is
                // incomplete. Do NOT publish Blocked on a partial list — that can
                // strand the waiter if the only zombies were among the skipped
                // matches. Fail closed with ENOMEM; flag stays set for rescan.
                if reserve_failed {
                    // ST-K3 FIX (W-1): same restore — see above.
                    let mut proc = parent.lock();
                    proc.enter_ready_at(crate::get_ticks());
                    proc.waiting_child = None;
                    return Err(SyscallError::ENOMEM);
                }
                drop(table);
                (WaitChildList::Many(found), parent_ns, events_before)
            } else {
                let parent_ns = crate::pid_namespace::owning_namespace(&proc.pid_ns_chain)
                    .unwrap_or_else(|| crate::pid_namespace::ROOT_PID_NAMESPACE.clone());
                if let WaitTarget::Pid(want) = target {
                    if Arc::ptr_eq(&parent_ns, &crate::pid_namespace::ROOT_PID_NAMESPACE)
                        && proc.children.contains(&want)
                    {
                        (WaitChildList::Single([want]), parent_ns, events_before)
                    } else {
                        let mut snapshot = Vec::new();
                        if snapshot.try_reserve_exact(proc.children.len()).is_err() {
                            proc.enter_ready_at(crate::get_ticks());
                            proc.waiting_child = None;
                            return Err(SyscallError::ENOMEM);
                        }
                        snapshot.extend_from_slice(&proc.children);
                        (WaitChildList::Many(snapshot), parent_ns, events_before)
                    }
                } else {
                    // Normal fast path: snapshot first; prepare_child_wait will
                    // recheck signals under the PCB lock before publishing Blocked.
                    let mut snapshot = Vec::new();
                    if snapshot.try_reserve_exact(proc.children.len()).is_err() {
                        // ST-K3 FIX (W-1): the "nothing is committed yet" rationale
                        // holds only on iteration 1; on a re-loop a prior iteration's
                        // Blocked is still published. Restore before failing.
                        proc.enter_ready_at(crate::get_ticks());
                        proc.waiting_child = None;
                        return Err(SyscallError::ENOMEM);
                    }
                    snapshot.extend_from_slice(&proc.children);
                    (WaitChildList::Many(snapshot), parent_ns, events_before)
                }
            }
        };

        let prepared = prepare_child_wait_checked(
            &parent,
            pid,
            target,
            child_list.as_slice(),
            &parent_namespace,
            Some(events_before_snapshot),
            get_process,
        )?;
        let mut selected_exists = false;
        // A selected zombie whose teardown/switch-out is still in flight: the
        // wake was genuine, only early (wake_reaper_after_switch follows).
        let mut selected_zombie_pending = false;
        let mut zombie_child: Option<(ProcessId, i32, ProcessId)> = None;
        let mut stale_pids: vec::Vec<ProcessId> = vec::Vec::new();

        for child_pid in child_list.as_slice().iter() {
            match get_process(*child_pid) {
                Some(child_proc) => {
                    let child = child_proc.lock();
                    // GAP-5 G8 (review D2): an entry whose child now has another
                    // parent (or whose pid was reused) is stale.
                    if child.ppid != pid {
                        if stale_pids.try_reserve(1).is_ok() {
                            stale_pids.push(*child_pid);
                        }
                        continue;
                    }
                    let Some(view_pid) = child.wait_pid_in_namespace(&parent_namespace) else {
                        continue;
                    };
                    if let WaitTarget::Pid(want) = target {
                        if view_pid != want {
                            continue;
                        }
                    }

                    selected_exists = true;
                    // R169-9: only reap a Zombie whose teardown has been published
                    // (teardown_done) — never before its cgroup/ns/futex teardown ran.
                    // GAP-5 slice 4 G1: wait reaps only group leaders (non-leader
                    // threads are auto-reaped), and a zombie leader only once it
                    // is the last member. A lone zombie leader cannot gain
                    // members, so this stays true through cleanup_zombie.
                    if child.state == ProcessState::Zombie
                        && child
                            .teardown_done
                            .load(core::sync::atomic::Ordering::Acquire)
                        && !child.on_cpu.load(core::sync::atomic::Ordering::Acquire)
                        && !child
                            .switch_reap_pending
                            .load(core::sync::atomic::Ordering::Acquire)
                        && child.tgid == *child_pid
                        && child.thread_group.members() == 1
                    {
                        zombie_child = Some((*child_pid, child.exit_code.unwrap_or(0), view_pid));
                        break;
                    }
                    if child.state == ProcessState::Zombie {
                        selected_zombie_pending = true;
                    }
                }
                None => {
                    // 子进程已被清理但仍在父进程列表中，标记为过期
                    // R157-6 FIX: Fallible push — skip stale entry on OOM
                    // (it will be cleaned up on the next wait call).
                    if stale_pids.try_reserve(1).is_ok() {
                        stale_pids.push(*child_pid);
                    }
                }
            }
        }

        if let Some((child_pid, exit_code, parent_view_pid)) = zombie_child {
            let outcome = WaitOutcome {
                global_pid: child_pid,
                view_pid: parent_view_pid,
                exit_code,
            };

            // GAP-5 G8: the group may have gained a thread that waits too; one
            // waiter claims the zombie. A loser rescans once the winner's reap
            // has removed the child.
            if !nowait && !crate::process::claim_wait_reap(child_pid) {
                {
                    let mut proc = parent.lock();
                    proc.enter_ready_at(crate::get_ticks());
                    proc.waiting_child = None;
                }
                crate::force_reschedule();
                continue;
            }

            // Report to the caller before committing the reap. A failure here
            // must restore Ready and leave the zombie reapable, matching Linux
            // EFAULT semantics for a bad status/siginfo pointer.
            if let Err(e) = publish(&outcome) {
                if !nowait {
                    crate::process::release_wait_reap(child_pid);
                }
                let mut proc = parent.lock();
                proc.enter_ready_at(crate::get_ticks());
                proc.waiting_child = None;
                return Err(e);
            }

            if nowait {
                // WNOWAIT: leave the child linked and un-cleaned so a later
                // wait can reap it. Only the parent's own wait state is undone.
                let mut proc = parent.lock();
                proc.waiting_child = None;
                proc.enter_ready_at(crate::get_ticks());
                return Ok(Some(outcome));
            }

            {
                let mut proc = parent.lock();
                proc.children.retain(|&c| c != child_pid);
                proc.waiting_child = None;
                proc.enter_ready_at(crate::get_ticks());
            }

            // 清理僵尸进程资源
            cleanup_zombie(child_pid);

            kprintln!(
                "sys_wait: reaped child {} (ns_pid={}) with exit code {}",
                child_pid,
                parent_view_pid,
                exit_code
            );
            // F.1: Return namespace-local PID to parent (Linux semantics)
            return Ok(Some(outcome));
        }

        // 清理过期的子进程 PID
        if !stale_pids.is_empty() {
            let mut proc = parent.lock();
            if proc.prune_stale_wait_children(&stale_pids) {
                proc.enter_ready_at(crate::get_ticks());
                proc.waiting_child = None;
                drop(proc);
                continue; // Recover fallibly unlisted children from PROCESS_TABLE.
            }
        }
        if !selected_exists {
            let mut proc = parent.lock();
            proc.enter_ready_at(crate::get_ticks());
            proc.waiting_child = None;
            return Err(SyscallError::ECHILD);
        }

        // ST-K3 FIX (wait4 ABI): WNOHANG — nothing reapable right now, so
        // undo the published Blocked state and report "nothing yet" instead of
        // blocking. wait4 maps this to 0; waitid to a zeroed siginfo.
        if nohang {
            let mut proc = parent.lock();
            proc.enter_ready_at(crate::get_ticks());
            proc.waiting_child = None;
            return Ok(None);
        }

        if !prepared {
            // A child may have been adopted between identity resolution and
            // this scan. Resolve it again before sleeping; no broad filter.
            continue;
        }
        // A real resume with no reportable target is an over-wake. Preserve
        // this oracle; an in-flight target zombie is only an early valid wake.
        if resumed_from_block && !selected_zombie_pending {
            crate::process::note_wait_over_wake();
        }

        // 没有找到僵尸子进程，让出 CPU 等待被唤醒
        // 状态已在循环开始时设为 Blocked，子进程退出时会将其设为 Ready
        crate::force_reschedule();
        // A reschedule that bailed (contention / non-preemptible) returns with
        // Blocked still published: that spin is not a wake, so don't count it.
        resumed_from_block = parent.lock().state != ProcessState::Blocked;
        if !resumed_from_block {
            // C3 repair 3 (#90): nothing woke this task and nothing else can
            // run here; halt until an interrupt instead of polling. A child's
            // exit after the snapshot moves it or kicks this CPU.
            crate::wait_kick::halt_blocked_wait(snapshot);
            resumed_from_block = parent.lock().state != ProcessState::Blocked;
        }

        // 被唤醒后继续循环，检查是否有僵尸子进程
        // 如果是被子进程退出唤醒的，循环会找到 zombie 并返回
        // 如果是误唤醒，循环会重新设置 Blocked 状态并继续等待
    }
}

/// GAP-5 G8: `wait_reap_core` for a caller whose thread group has more than one
/// member. Children of every member are candidates (a full table scan, which
/// also needs no `children_incomplete` fallback). One waiter claims a zombie
/// before reporting it (`claim_wait_reap`).
///
/// Sleeping (review D3; it polled once per tick before): the caller counts
/// itself as a group child waiter, reads the group's child-report count before
/// its scan and re-reads it under its PCB lock before it publishes `Blocked`.
/// A report bumps the count first and then wakes every sleeping member
/// (`wake_group_child_waiters`), so a report either lands before the re-read
/// (the caller rescans) or finds the caller `Blocked`. A candidate that is a
/// zombie still finishing its exit, or one another waiter claimed, makes the
/// caller poll instead, since those transitions send no report.
pub(super) fn wait_reap_group<W>(
    target: WaitTarget,
    nohang: bool,
    nowait: bool,
    mut publish: W,
    pid: ProcessId,
    caller: &crate::process::ProcessArc,
    group: &Arc<crate::process::ThreadGroup>,
) -> Result<Option<WaitOutcome>, SyscallError>
where
    W: FnMut(&WaitOutcome) -> Result<(), SyscallError>,
{
    struct ChildWaiter<'a>(&'a crate::process::ThreadGroup);
    impl Drop for ChildWaiter<'_> {
        fn drop(&mut self) {
            self.0.note_child_waiter(false);
        }
    }

    let parent_namespace = {
        let proc = caller.lock();
        crate::pid_namespace::owning_namespace(&proc.pid_ns_chain)
            .unwrap_or_else(|| crate::pid_namespace::ROOT_PID_NAMESPACE.clone())
    };
    group.note_child_waiter(true);
    let _waiter = ChildWaiter(group);
    loop {
        // C3 repair 3 (#90): this CPU's wait sequence before the pass.
        let snapshot = crate::wait_kick::snapshot();
        if wait_should_abort(pid) || crate::signal::has_deliverable_signal(pid) {
            return Err(SyscallError::EINTR);
        }
        // After the signal checks, so the scan reports a child this pass ends.
        crate::process::run_blocked_wait_drains();
        let events = group.child_events();

        let mut members: Vec<ProcessId> = Vec::new();
        members
            .try_reserve_exact(group.members().saturating_add(1))
            .map_err(|_| SyscallError::ENOMEM)?;
        let mut selected_exists = false;
        let mut wake_pid = 0;
        let mut grew = false;
        // A candidate that becomes reapable without a report: poll for it.
        let mut transient = false;
        // (child, exit code, view pid)
        let mut found: Option<(ProcessId, i32, ProcessId)> = None;
        'scan: {
            let table = crate::process::PROCESS_TABLE.lock();
            for (slot_pid, slot) in table.iter().enumerate() {
                let Some(arc) = slot else { continue };
                if Arc::ptr_eq(&arc.lock().thread_group, group) {
                    if members.len() == members.capacity() {
                        // The group grew since the reserve; size again.
                        grew = true;
                        break 'scan;
                    }
                    members.push(slot_pid);
                }
            }
            for (child_pid, slot) in table.iter().enumerate() {
                let Some(arc) = slot else { continue };
                let child = arc.lock();
                if !members.contains(&child.ppid) || members.contains(&child_pid) {
                    continue;
                }
                let Some(view_pid) = child.wait_pid_in_namespace(&parent_namespace) else {
                    continue;
                };
                if let WaitTarget::Pid(want) = target {
                    if view_pid != want {
                        continue;
                    }
                    wake_pid = child_pid;
                }
                selected_exists = true;
                // A zombie leader whose group is empty is reported once its
                // teardown is published and it has switched out for good.
                let reportable = child.state == ProcessState::Zombie
                    && child.tgid == child_pid
                    && child.thread_group.members() == 1;
                let reapable = reportable
                    && child
                        .teardown_done
                        .load(core::sync::atomic::Ordering::Acquire)
                    && !child.on_cpu.load(core::sync::atomic::Ordering::Acquire)
                    && !child
                        .switch_reap_pending
                        .load(core::sync::atomic::Ordering::Acquire);
                if !reapable {
                    transient |= reportable;
                    continue;
                }
                if !nowait
                    && child
                        .wait_claimed
                        .compare_exchange(
                            false,
                            true,
                            core::sync::atomic::Ordering::AcqRel,
                            core::sync::atomic::Ordering::Acquire,
                        )
                        .is_err()
                {
                    transient = true;
                    continue;
                }
                found = Some((child_pid, child.exit_code.unwrap_or(0), view_pid));
                break;
            }
        }
        if grew {
            continue;
        }

        #[cfg(all(test, feature = "host_harness", not(target_os = "none")))]
        selective_wait_tests::group_wait_phase(selective_wait_tests::GroupWaitPhase::Scanned);

        if let Some((child_pid, exit_code, view_pid)) = found {
            let outcome = WaitOutcome {
                global_pid: child_pid,
                view_pid,
                exit_code,
            };
            if let Err(e) = publish(&outcome) {
                if !nowait {
                    crate::process::release_wait_reap(child_pid);
                }
                return Err(e);
            }
            if nowait {
                return Ok(Some(outcome));
            }
            // GAP-5 G8 (review D2): the child may have been reparented since
            // the scan (its parent thread exited). Unlink it from its current
            // parent; reparenting runs under the same table lock.
            {
                let table = crate::process::PROCESS_TABLE.lock();
                let parent_pid = table
                    .get(child_pid)
                    .and_then(Option::as_ref)
                    .map(|child| child.lock().ppid);
                if let Some(parent) = parent_pid.and_then(|p| table.get(p).and_then(Option::as_ref))
                {
                    parent.lock().children.retain(|&c| c != child_pid);
                }
            }
            cleanup_zombie(child_pid);
            return Ok(Some(outcome));
        }
        if !selected_exists {
            return Err(SyscallError::ECHILD);
        }
        if nohang {
            return Ok(None);
        }
        if transient {
            yield_and_halt();
            continue;
        }
        {
            let mut proc = caller.lock();
            if crate::signal::should_abort_pending_block(&proc) {
                return Err(SyscallError::EINTR);
            }
            if group.child_events() != events {
                continue;
            }
            // The hosted interleaving pauses here with the caller PCB locked.
            #[cfg(all(test, feature = "host_harness", not(target_os = "none")))]
            selective_wait_tests::group_wait_phase(selective_wait_tests::GroupWaitPhase::Checked);

            proc.enter_blocked_at(crate::get_ticks());
            proc.waiting_child = Some(wake_pid);
        }
        #[cfg(all(test, feature = "host_harness", not(target_os = "none")))]
        selective_wait_tests::group_wait_phase(selective_wait_tests::GroupWaitPhase::Blocked);

        crate::force_reschedule();
        // C3 repair 3 (#90): still Blocked, so nothing woke it and nothing else
        // runs here. Halt while still Blocked, so that a report wakes and kicks
        // this CPU, and only then make the task Ready for the next pass.
        if caller.lock().state == ProcessState::Blocked {
            crate::wait_kick::halt_blocked_wait(snapshot);
        }
        // Ready again, whether woken or not switched out at all.
        let mut proc = caller.lock();
        if proc.state == ProcessState::Blocked {
            proc.enter_ready_at(crate::get_ticks());
        }
        proc.waiting_child = None;
    }
}

/// Issue #109 §4.1: Read-only `getpid` fast path reusing the namespace ID
/// already resolved under the single syscall-entry PCB lock.
#[inline]
pub(super) fn sys_getpid_fast(fast_ns_id: Option<Result<usize, ()>>) -> SyscallResult {
    match fast_ns_id {
        Some(Ok(ns_pid)) => {
            #[cfg(feature = "kcov")]
            {
                coverage::trace_pc(1110);
                coverage::trace_pc(1111);
                coverage::trace_pc(1112);
            }
            Ok(ns_pid)
        }
        Some(Err(())) => {
            #[cfg(feature = "kcov")]
            {
                coverage::trace_pc(1110);
                coverage::trace_pc(1111);
            }
            Err(SyscallError::EFAULT)
        }
        None => sys_getpid(),
    }
}

/// sys_getpid - 获取当前进程ID
///
/// F.1 PID Namespace: Returns the PID as seen from the process's owning namespace,
/// not the global (kernel internal) PID. For processes in the root namespace,
/// these are the same.
pub(super) fn sys_getpid() -> SyscallResult {
    #[cfg(feature = "kcov")]
    coverage::trace_pc(1110); // sys_getpid entry

    let global_pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let proc_arc = get_process(global_pid).ok_or(SyscallError::ESRCH)?;

    #[cfg(feature = "kcov")]
    coverage::trace_pc(1111); // sys_getpid process resolved

    let ns_pid = {
        let proc = proc_arc.lock();
        if proc.tgid != proc.pid {
            // GAP-5 slice 4 G5: a thread reports its group's id, cached at
            // creation in the shared namespace (0 = translation failed).
            if proc.ns_tgid == 0 {
                return Err(SyscallError::EFAULT);
            }
            proc.ns_tgid
        } else {
            // F.1: Return the PID from the owning (leaf) namespace
            // The last entry in pid_ns_chain is the owning namespace
            // R94-6 FIX: Translation failure returns EFAULT instead of leaking global PID.
            crate::pid_namespace::pid_in_owning_namespace(&proc.pid_ns_chain)
                .ok_or(SyscallError::EFAULT)?
        }
    };

    #[cfg(feature = "kcov")]
    coverage::trace_pc(1112); // sys_getpid namespace translation succeeded

    Ok(ns_pid)
}

/// sys_getppid - 获取父进程ID
///
/// F.1 PID Namespace: Returns the parent's PID as seen from the current process's
/// owning namespace. If the parent is not visible in the namespace (e.g., parent
/// is in an ancestor namespace), returns 0 (orphan/adopted by namespace init).
pub(super) fn sys_getppid() -> SyscallResult {
    let global_pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let proc_arc = get_process(global_pid).ok_or(SyscallError::ESRCH)?;

    #[cfg(feature = "kcov")]
    coverage::trace_pc(1120); // sys_getppid process resolved

    let proc = proc_arc.lock();
    let own_ppid = proc.ppid;
    let tgid = proc.tgid;
    let is_group_member = tgid != proc.pid;

    // F.1: Get owning namespace for translation
    let owning_ns = crate::pid_namespace::owning_namespace(&proc.pid_ns_chain);
    drop(proc); // Release lock before looking up parent

    // GAP-5 slice 4 G5: a thread's parent is its group leader's parent, read
    // from the leader so a later reparent of the group is visible to every
    // thread. G1 keeps the leader PCB until the group is empty; if it is
    // already gone the thread falls back to its own recorded parent.
    let parent_global_pid = if is_group_member {
        get_process(tgid).map_or(own_ppid, |leader| leader.lock().ppid)
    } else {
        own_ppid
    };

    // If parent_pid is 0, the process has no parent (init)
    if parent_global_pid == 0 {
        #[cfg(feature = "kcov")]
        coverage::trace_pc(1121); // sys_getppid init/no-parent path
        return Ok(0);
    }

    // GAP-5 G8: a parent that is a non-leader thread (it forked this task, or
    // took it over from an exiting sibling) is reported as its process, as
    // Linux reports real_parent->tgid. The group's cached id in its own
    // namespace covers a leader whose mapping is already gone.
    let (parent_global_pid, parent_group) = match get_process(parent_global_pid) {
        Some(parent) => {
            let parent = parent.lock();
            if parent.tgid != parent.pid {
                let parent_ns = crate::pid_namespace::owning_namespace(&parent.pid_ns_chain);
                (parent.tgid, Some((parent.ns_tgid, parent_ns)))
            } else {
                (parent_global_pid, None)
            }
        }
        None => (parent_global_pid, None),
    };

    // Try to translate parent's global PID to namespace-local PID
    if let Some(ns) = owning_ns {
        // Look up parent's PID in our namespace
        if let Some(ns_ppid) = ns.lookup_ns_pid(parent_global_pid) {
            #[cfg(feature = "kcov")]
            coverage::trace_pc(1122); // sys_getppid parent visible
            return Ok(ns_ppid);
        }
        if let Some((ns_tgid, Some(parent_ns))) = parent_group {
            if ns_tgid != 0 && Arc::ptr_eq(&parent_ns, &ns) {
                return Ok(ns_tgid);
            }
        }
        // Parent not visible in our namespace - return 0 (orphan semantics)
        // This happens when parent is in an ancestor namespace
        #[cfg(feature = "kcov")]
        coverage::trace_pc(1123); // sys_getppid orphaned namespace path
        Ok(0)
    } else {
        // No namespace chain - return global PID (root namespace)
        #[cfg(feature = "kcov")]
        coverage::trace_pc(1124); // sys_getppid root namespace path
        Ok(parent_global_pid)
    }
}

/// Issue #109 §4.1: Read-only `gettid` fast path reusing the namespace TID
/// already resolved under the single syscall-entry PCB lock.
#[inline]
pub(super) fn sys_gettid_fast(fast_ns_id: Option<Result<usize, ()>>) -> SyscallResult {
    match fast_ns_id {
        Some(Ok(ns_tid)) => Ok(ns_tid),
        Some(Err(())) => Err(SyscallError::EFAULT),
        None => sys_gettid(),
    }
}

/// sys_gettid - 获取当前线程ID
///
/// 返回当前线程的 TID。对于主线程，TID == PID == TGID。
/// 对于子线程，TID 是线程的唯一标识，TGID 是所属进程组。
///
/// F.1 PID Namespace: Returns the TID as seen from the thread's owning namespace.
pub(super) fn sys_gettid() -> SyscallResult {
    let global_pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let process = get_process(global_pid).ok_or(SyscallError::ESRCH)?;
    let proc = process.lock();

    // F.1: Return the TID from the owning namespace (TID == namespace-local PID)
    // R94-6 FIX: Translation failure returns EFAULT instead of leaking global TID.
    let ns_tid = crate::pid_namespace::pid_in_owning_namespace(&proc.pid_ns_chain)
        .ok_or(SyscallError::EFAULT)?;
    Ok(ns_tid)
}

/// sys_set_tid_address - 设置 clear_child_tid 指针
///
/// musl libc 在启动时调用此函数来注册 TID 清理指针。
/// 当线程退出时，内核应将 0 写入此地址并执行 futex_wake。
///
/// # Arguments
///
/// * `tidptr` - 指向用户空间 i32 的指针，可为 NULL
///
/// # Returns
///
/// 返回调用进程的 TID（当前等于 PID）
///
/// F.1 PID Namespace: Returns the namespace-local TID.
pub(super) fn sys_set_tid_address(tidptr: *mut i32) -> SyscallResult {
    let global_pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let process = get_process(global_pid).ok_or(SyscallError::ESRCH)?;

    // 验证用户指针（如果非空）
    if !tidptr.is_null() {
        validate_user_ptr_mut(tidptr as *mut u8, mem::size_of::<i32>())?;
        verify_user_memory(tidptr as *const u8, mem::size_of::<i32>(), true)?;
    }

    // 保存指针到进程控制块
    let ns_tid = {
        let mut proc = process.lock();
        proc.clear_child_tid = tidptr as u64;
        // F.1: Return the TID from the owning namespace
        // R94-6 FIX: Translation failure returns EFAULT instead of leaking global TID.
        crate::pid_namespace::pid_in_owning_namespace(&proc.pid_ns_chain)
            .ok_or(SyscallError::EFAULT)?
    };

    // 返回当前 TID (namespace-local)
    Ok(ns_tid)
}

/// sys_get_robust_list - GAP-5 G8: report a task's robust-list registration.
///
/// `pid` 0 names the caller. Another task must belong to the caller's thread
/// group, or the caller must hold ADMIN or be host root (a conservative stand-in
/// for Linux's ptrace-read check) and pass the LSM ptrace-access hook. `pid` is
/// namespace-local. Writes the length (24 when registered, else 0) to `len_ptr`
/// and the head address to `head_ptr`.
pub(super) fn sys_get_robust_list(
    pid: i32,
    head_ptr: *mut u64,
    len_ptr: *mut u64,
) -> SyscallResult {
    if pid < 0 {
        return Err(SyscallError::ESRCH);
    }
    let caller = current_pid().ok_or(SyscallError::ESRCH)?;
    let (caller_group, caller_ns) = {
        let proc_arc = get_process(caller).ok_or(SyscallError::ESRCH)?;
        let proc = proc_arc.lock();
        (
            Arc::clone(&proc.thread_group),
            crate::pid_namespace::owning_namespace(&proc.pid_ns_chain),
        )
    };
    let target = if pid == 0 {
        caller
    } else if let Some(ns) = caller_ns {
        crate::pid_namespace::resolve_pid_in_namespace(&ns, pid as ProcessId)
            .ok_or(SyscallError::ESRCH)?
    } else {
        pid as ProcessId
    };
    let (head, len, foreign_target) = {
        let target_arc = get_process(target).ok_or(SyscallError::ESRCH)?;
        let t = target_arc.lock();
        if matches!(t.state, ProcessState::Zombie | ProcessState::Terminated) {
            return Err(SyscallError::ESRCH);
        }
        // R191-3: the hook's object, a snapshot of the target's current
        // credentials taken under its PCB lock; none for a group member,
        // which Linux's ptrace_may_access admits before the LSM check. A busy
        // credential lock (EAGAIN) is reported only after the DAC check.
        let foreign_target = if Arc::ptr_eq(&t.thread_group, &caller_group) {
            None
        } else {
            Some(lsm_process_ctx_from(&t))
        };
        (
            t.robust_list_head,
            // Linux always reports sizeof(struct robust_list_head), 24.
            24u64,
            foreign_target,
        )
    };
    if let Some(target_ctx) = foreign_target {
        if !current_has_cap_rights(cap::CapRights::ADMIN) && !crate::current_is_host_root() {
            return Err(SyscallError::EPERM);
        }
        let target_ctx = target_ctx?;
        // R191-3 FIX (D4-SEC-1): a cross-group read is a ptrace-read access,
        // mediated by the LSM after the DAC check, as Linux's
        // `ptrace_may_access` calls `security_ptrace_access_check`. Fail
        // closed when the subject cannot be described. No PCB lock is held.
        let tracer_ctx = lsm_current_process_ctx().ok_or(SyscallError::EPERM)?;
        lsm::hook_ptrace(&tracer_ctx, &target_ctx, lsm::ptrace_op::READ)
            .map_err(lsm_error_to_syscall)?;
    }
    if head_ptr.is_null() || len_ptr.is_null() {
        return Err(SyscallError::EFAULT);
    }
    crate::usercopy::copy_to_user_safe(len_ptr as *mut u8, &len.to_ne_bytes())
        .map_err(|_| SyscallError::EFAULT)?;
    crate::usercopy::copy_to_user_safe(head_ptr as *mut u8, &head.to_ne_bytes())
        .map_err(|_| SyscallError::EFAULT)?;
    Ok(0)
}

/// sys_set_robust_list - 注册 robust_list 头指针
///
/// robust_list 用于跟踪进程持有的 robust futex，以便在进程异常退出时
/// 内核能够自动释放这些锁，防止死锁。
///
/// # Arguments
///
/// * `head` - 指向 robust_list_head 结构的用户空间指针
/// * `len` - robust_list_head 结构的大小（必须为 24）
///
/// # Returns
///
/// 成功返回 0
pub(super) fn sys_set_robust_list(head: *const u8, len: usize) -> SyscallResult {
    /// Linux robust_list_head 结构大小
    /// struct robust_list_head {
    ///     struct robust_list *list;         // 8 bytes
    ///     long futex_offset;                // 8 bytes
    ///     struct robust_list *list_op_pending; // 8 bytes
    /// }
    const ROBUST_LIST_HEAD_SIZE: usize = 24;

    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let process = get_process(pid).ok_or(SyscallError::ESRCH)?;

    // 允许 NULL 指针（用于清除）
    if head.is_null() {
        let mut proc = process.lock();
        proc.robust_list_head = 0;
        proc.robust_list_len = 0;
        return Ok(0);
    }

    // Linux 要求 len 必须等于 sizeof(struct robust_list_head) == 24
    if len != ROBUST_LIST_HEAD_SIZE {
        return Err(SyscallError::EINVAL);
    }

    // 验证用户内存
    validate_user_ptr(head, len)?;
    verify_user_memory(head, len, false)?;

    // 保存到进程控制块
    let mut proc = process.lock();
    proc.robust_list_head = head as u64;
    proc.robust_list_len = len;

    Ok(0)
}

// ============================================================================
// 用户/组ID系统调用
// ============================================================================

/// sys_getuid - 获取真实用户ID
pub(super) fn sys_getuid() -> SyscallResult {
    #[cfg(feature = "kcov")]
    {
        coverage::trace_pc(1100); // sys_getuid entry
    }
    let creds = crate::process::current_credentials().ok_or(SyscallError::EPERM)?;
    Ok(creds.uid as usize)
}

/// sys_geteuid - 获取有效用户ID
pub(super) fn sys_geteuid() -> SyscallResult {
    #[cfg(feature = "kcov")]
    {
        coverage::trace_pc(1101); // sys_geteuid entry
    }
    let creds = crate::process::current_credentials().ok_or(SyscallError::EPERM)?;
    Ok(creds.euid as usize)
}

/// sys_getgid - 获取真实组ID
pub(super) fn sys_getgid() -> SyscallResult {
    #[cfg(feature = "kcov")]
    {
        coverage::trace_pc(1102); // sys_getgid entry
    }
    let creds = crate::process::current_credentials().ok_or(SyscallError::EPERM)?;
    Ok(creds.gid as usize)
}

/// sys_getegid - 获取有效组ID
pub(super) fn sys_getegid() -> SyscallResult {
    #[cfg(feature = "kcov")]
    {
        coverage::trace_pc(1103); // sys_getegid entry
    }
    let creds = crate::process::current_credentials().ok_or(SyscallError::EPERM)?;
    Ok(creds.egid as usize)
}

/// `waitid(2)` idtype: wait for any child.
pub(super) const P_ALL: i32 = 0;
/// `waitid(2)` idtype: wait for one child by PID.
pub(super) const P_PID: i32 = 1;
/// `waitid(2)` idtype: wait for any child in a process group.
pub(super) const P_PGID: i32 = 2;

/// `waitid(2)` option: report children that have exited.
pub(super) const WEXITED: i32 = 0x4;
/// `waitid(2)` option: report without reaping — the child stays reapable.
pub(super) const WNOWAIT: i32 = 0x0100_0000;

/// `si_code` for a child that exited normally.
pub(super) const CLD_EXITED: i32 = 1;

/// Byte offsets into the x86_64 `siginfo_t` fields `waitid` fills.
/// Layout: si_signo(0) si_errno(4) si_code(8) __pad(12) then the _sigchld
/// union at 16: si_pid(16) si_uid(20) si_status(24).
pub(super) const SI_OFF_SIGNO: usize = 0;
pub(super) const SI_OFF_ERRNO: usize = 4;
pub(super) const SI_OFF_CODE: usize = 8;
pub(super) const SI_OFF_PID: usize = 16;
pub(super) const SI_OFF_UID: usize = 20;
pub(super) const SI_OFF_STATUS: usize = 24;
/// Size of `siginfo_t` on x86_64. The whole struct is written so no stale user
/// bytes remain visible in the padding or the unused union tail.
pub(super) const SIGINFO_SIZE: usize = 128;

/// waitid(2) - wait for a child process to change state
///
/// Shares the blocking reap loop with [`sys_wait4`] via [`wait_reap_core`], so
/// the lost-wakeup and `Blocked`-restore invariants have a single home. The
/// differences from `wait4` are the reporting format and `WNOWAIT`:
/// - the result is a `siginfo_t` at `infop` rather than a packed wstatus, and
///   the return value is 0 on success (the PID travels in `si_pid`);
/// - `WNOWAIT` reports the child but leaves it reapable for a later wait;
/// - `WEXITED` is required. `WSTOPPED`/`WCONTINUED` are rejected with EINVAL
///   rather than silently ignored as `wait4` does: this kernel records no
///   parent-visible stop/continue event, so accepting them would promise
///   notifications that can never arrive and hang the caller. `wait4` keeps
///   ignoring them only for backward compatibility.
/// - `P_PGID` is refused (EINVAL, fail-closed) on the same grounds `wait4`
///   refuses its process-group selectors: no process-group wait tracking.
///
/// A zeroed `siginfo_t` plus a 0 return is the `WNOHANG`-nothing-ready answer,
/// matching Linux: callers distinguish it by `si_pid == 0`.
/// Pure `waitid(2)` argument contract: the whole fail-closed decision with no
/// process state touched, so the hosted oracle can execute the production path
/// rather than a copy of it.
pub(super) fn waitid_validate_args(
    idtype: i32,
    id: i32,
    options: i32,
) -> Result<WaitTarget, SyscallError> {
    const KNOWN: i32 = WNOHANG | WUNTRACED | WEXITED | WCONTINUED | WNOWAIT;
    if options & !KNOWN != 0 {
        return Err(SyscallError::EINVAL);
    }
    // No stop/continue event ledger exists, so these can never be satisfied.
    if options & (WUNTRACED | WCONTINUED) != 0 {
        return Err(SyscallError::EINVAL);
    }
    if options & WEXITED == 0 {
        return Err(SyscallError::EINVAL);
    }

    match idtype {
        P_ALL => Ok(WaitTarget::Any),
        P_PID => {
            if id <= 0 {
                return Err(SyscallError::EINVAL);
            }
            Ok(WaitTarget::Pid(id as ProcessId))
        }
        P_PGID => Err(SyscallError::EINVAL),
        _ => Err(SyscallError::EINVAL),
    }
}

/// Pure `siginfo_t` encoder for `waitid`. Always returns the full 128 bytes so
/// no stale user bytes survive in the padding or the unused union tail; `pid == 0`
/// is the `WNOHANG`-nothing-ready shape and stays fully zeroed.
pub(super) fn waitid_encode_siginfo(
    pid: ProcessId,
    uid: u32,
    code: i32,
    status: i32,
) -> [u8; SIGINFO_SIZE] {
    let mut buf = [0u8; SIGINFO_SIZE];
    if pid != 0 {
        buf[SI_OFF_SIGNO..SI_OFF_SIGNO + 4]
            .copy_from_slice(&crate::signal::Signal::SIGCHLD.as_i32().to_ne_bytes());
        buf[SI_OFF_ERRNO..SI_OFF_ERRNO + 4].copy_from_slice(&0i32.to_ne_bytes());
        buf[SI_OFF_CODE..SI_OFF_CODE + 4].copy_from_slice(&code.to_ne_bytes());
        buf[SI_OFF_PID..SI_OFF_PID + 4].copy_from_slice(&(pid as i32).to_ne_bytes());
        buf[SI_OFF_UID..SI_OFF_UID + 4].copy_from_slice(&uid.to_ne_bytes());
        buf[SI_OFF_STATUS..SI_OFF_STATUS + 4].copy_from_slice(&status.to_ne_bytes());
    }
    buf
}

pub(super) fn sys_waitid(
    idtype: i32,
    id: i32,
    infop: *mut u8,
    options: i32,
) -> Result<usize, SyscallError> {
    let target = waitid_validate_args(idtype, id, options)?;

    let write_siginfo = |pid: ProcessId, uid: u32, code: i32, status: i32| {
        copy_to_user(infop, &waitid_encode_siginfo(pid, uid, code, status))
    };

    // Resolved while the zombie is still selected but before it is unlinked:
    // after cleanup_zombie the PCB is gone and si_uid would be unrecoverable.
    let publish = |outcome: &WaitOutcome| -> Result<(), SyscallError> {
        if infop.is_null() {
            // Linux accepts a NULL infop and reports only via the return value.
            return Ok(());
        }
        // try_read (not read): a blocking credential read here would be taken
        // while the wait path already holds process state, so a contended
        // writer could deadlock. uid 0 on contention is the fail-soft answer.
        let uid = get_process(outcome.global_pid)
            .map(|p| p.lock().shared_credentials())
            .and_then(|creds| creds.try_read().map(|c| c.uid))
            .unwrap_or(0);
        // si_status carries the raw exit code, NOT the packed wstatus: with
        // si_code == CLD_EXITED, userspace reads it directly as the exit status.
        write_siginfo(outcome.view_pid, uid, CLD_EXITED, outcome.exit_code & 0xff)
    };

    match wait_reap_core(
        target,
        options & WNOHANG != 0,
        options & WNOWAIT != 0,
        publish,
    )? {
        Some(_) => Ok(0),
        None => {
            // WNOHANG, nothing ready: zeroed siginfo so si_pid == 0.
            if !infop.is_null() {
                write_siginfo(0, 0, 0, 0)?;
            }
            Ok(0)
        }
    }
}

/// ST-K3-WAITID hosted oracle: executes the production `waitid(2)` argument
/// contract and `siginfo_t` encoder on the host target. The reap/unlink,
/// blocking and WNOWAIT-then-reap legs need live process state and a user
/// address space, so they run only in the guest runtime gate.
#[cfg(all(test, feature = "host_harness", not(target_os = "none")))]
mod st_k3_waitid_oracle_tests {
    use super::*;

    #[test]
    fn waitid_selectors_resolve_or_fail_closed() {
        assert!(matches!(
            waitid_validate_args(P_ALL, 0, WEXITED),
            Ok(WaitTarget::Any)
        ));
        assert!(matches!(
            waitid_validate_args(P_PID, 7, WEXITED),
            Ok(WaitTarget::Pid(7))
        ));
        // P_PGID has no process-group wait tracking behind it: refused, never
        // silently widened to "any child".
        assert_eq!(
            waitid_validate_args(P_PGID, 7, WEXITED),
            Err(SyscallError::EINVAL)
        );
        for bad_id in [0, -1] {
            assert_eq!(
                waitid_validate_args(P_PID, bad_id, WEXITED),
                Err(SyscallError::EINVAL)
            );
        }
        assert_eq!(
            waitid_validate_args(99, 1, WEXITED),
            Err(SyscallError::EINVAL)
        );
    }

    #[test]
    fn waitid_options_are_validated_before_any_state_change() {
        // WEXITED is mandatory: a wait that can report nothing is a caller bug.
        assert_eq!(waitid_validate_args(P_ALL, 0, 0), Err(SyscallError::EINVAL));
        assert_eq!(
            waitid_validate_args(P_ALL, 0, WNOHANG),
            Err(SyscallError::EINVAL)
        );
        // Unsatisfiable rather than ignored: no stop/continue ledger exists, so
        // honouring these would promise a notification that can never arrive.
        for unsupported in [WUNTRACED, WCONTINUED] {
            assert_eq!(
                waitid_validate_args(P_ALL, 0, WEXITED | unsupported),
                Err(SyscallError::EINVAL)
            );
        }
        // Unknown bits are rejected, so future flags cannot be silently dropped.
        assert_eq!(
            waitid_validate_args(P_ALL, 0, WEXITED | 1 << 20),
            Err(SyscallError::EINVAL)
        );
        assert!(waitid_validate_args(P_ALL, 0, WEXITED | WNOHANG | WNOWAIT).is_ok());
    }

    #[test]
    fn waitid_siginfo_encodes_the_x86_64_layout() {
        let buf = waitid_encode_siginfo(4321, 1000, CLD_EXITED, 42);
        assert_eq!(buf.len(), SIGINFO_SIZE);

        let field = |off: usize| i32::from_ne_bytes(buf[off..off + 4].try_into().unwrap());
        assert_eq!(field(SI_OFF_SIGNO), crate::signal::Signal::SIGCHLD.as_i32());
        assert_eq!(field(SI_OFF_ERRNO), 0);
        assert_eq!(field(SI_OFF_CODE), CLD_EXITED);
        assert_eq!(field(SI_OFF_PID), 4321);
        assert_eq!(field(SI_OFF_UID), 1000);
        assert_eq!(field(SI_OFF_STATUS), 42);

        // The union tail past si_status must stay zero: user memory is
        // overwritten in full, so no stale bytes leak back to the caller.
        assert!(buf[SI_OFF_STATUS + 4..].iter().all(|&b| b == 0));
    }

    #[test]
    fn waitid_nothing_ready_is_a_fully_zeroed_siginfo() {
        // The WNOHANG-nothing-ready answer. Callers distinguish it by si_pid == 0,
        // so every other field must be zero too.
        let buf = waitid_encode_siginfo(0, 1000, CLD_EXITED, 42);
        assert!(buf.iter().all(|&b| b == 0));
    }
}
