//! 系统调用接口
//!
//! 实现类POSIX系统调用，提供用户程序与内核交互的接口
//!
//! # Audit Integration
//!
//! All syscalls are audited with entry and exit events for security monitoring.
//! Events include: syscall number, arguments, result, and process context.

use crate::cgroup;
use crate::fork::{cow_flag, cow_readonly_flag, PAGE_REF_COUNT};
use crate::process::{
    cleanup_unscheduled_process, cleanup_zombie, create_process, create_process_in_namespace,
    current_has_cap_rights, current_net_ns_id, current_pid, get_process, terminate_self_and_halt,
    try_get_process, wait_should_abort, FileDescriptor, ProcessArc, ProcessId, ProcessState,
};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::mem;
use cpu_local::{current_cpu, current_cpu_id};
use x86_64::structures::paging::PageTableFlags;
use x86_64::VirtAddr;

// Audit integration for syscall security monitoring
use audit::{AuditKind, AuditObject, AuditOutcome, AuditSubject};

// Seccomp/Pledge syscall filtering
extern crate seccomp;

// LSM hook infrastructure
extern crate lsm;

// Network socket layer
extern crate net;

// Capability system
extern crate cap;

// Security RNG for cryptographically secure random number generation
use security::rng;

// G.1 Observability: Per-CPU counter integration
use trace::counters::{increment_counter, TraceCounter};

// G.3 Compliance: Hardening profiles and FIPS mode
extern crate compliance;
extern crate livepatch;

/// 最大参数数量（防止恶意用户传递过多参数）
const MAX_ARG_COUNT: usize = 256;

mod abi;
mod cgroups;
mod exec;
mod fs;
mod futex;
mod helpers;
mod memory;
mod ns;
mod poll;
mod proc;
mod sandbox;
mod signal;
mod socket;
mod sys;
mod time;

#[allow(unused_imports)]
use abi::*;
#[allow(unused_imports)]
use cgroups::*;
#[allow(unused_imports)]
use exec::*;
#[allow(unused_imports)]
use fs::*;
#[allow(unused_imports)]
use futex::*;
#[allow(unused_imports)]
use helpers::*;
#[allow(unused_imports)]
use memory::*;
#[allow(unused_imports)]
use ns::*;
#[allow(unused_imports)]
use poll::*;
#[allow(unused_imports)]
use proc::*;
#[allow(unused_imports)]
use sandbox::*;
#[allow(unused_imports)]
use signal::*;
#[allow(unused_imports)]
use socket::*;
#[allow(unused_imports)]
use sys::*;
#[allow(unused_imports)]
use time::*;

pub(crate) use abi::SocketFile;
pub use abi::{run_linux_wire_abi_self_test, LINUX_DIRENT64_NAME_OFFSET};
pub use cgroups::CgroupStatsBuf;
pub use exec::run_exec_disambiguation_self_test;
pub use futex::{FutexRequest, FutexWakeOp, FutexWakeOpCmp, FutexWakeOpKind};
#[cfg(feature = "open_fault_probe")]
pub use helpers::OpenFaultProbe;
pub use helpers::{
    cap_error_to_syscall, drain_deferred_stdin_wakes, init_blocking_waiter_registries,
    lsm_error_to_syscall, lsm_process_ctx_from, lsm_process_ctx_from_credentials,
    prepare_process_cap_allocation_authorized, register_fd_close_callback,
    register_fd_read_callback, register_fd_write_callback, register_futex_callback,
    register_get_frame_binding_callback, register_mount_ns_materialize_callback,
    register_mount_ns_materialize_rollback_callback, register_pipe_callback,
    register_set_frame_binding_callback, register_set_frame_owner_callback,
    register_stage_pending_tls_bases_callback, register_syscall_frame_callback,
    register_syscall_frame_mut_callback, register_vfs_create_callback,
    register_vfs_durability_callbacks, register_vfs_lseek_callback, register_vfs_open_callback,
    register_vfs_open_with_resolve_callback, register_vfs_pread_callback,
    register_vfs_pwrite_callback, register_vfs_read_file_callback, register_vfs_readdir_callback,
    register_vfs_readlink_callback, register_vfs_rename_callback, register_vfs_stat_callback,
    register_vfs_stat_nofollow_callback, register_vfs_symlink_callback,
    register_vfs_truncate_callback, register_vfs_unlink_callback,
    run_authorized_cap_grant_audit_self_test, run_fd_publication_transaction_self_test,
    run_fileops_cap_id_self_test, run_fork_reconcile_refcount_self_test,
    run_saved_frame_binding_self_test, run_transient_io_admission_self_test,
    set_syscall_frame_owner, test_is_mount_ns_callback_registered, wake_stdin_waiters,
    with_current_syscall_frame, with_current_syscall_frame_mut, AuthorizedCapGrant,
    AuthorizedCapReservation, DirEntry, FdCloseCallback, FdReadCallback, FdWriteCallback, FileType,
    FutexCallback, GetFrameBindingCallback, GetSyscallFrameCallback, GetSyscallFrameMutCallback,
    MountNsMaterializeCallback, MountNsMaterializeRollbackCallback, PipeCreateCallback,
    PreparedVfsOpen, SetFrameBindingCallback, SetFrameOwnerCallback, StagePendingTlsBasesCallback,
    SyscallFrame, VfsCreateCallback, VfsDirCopyout, VfsLseekCallback, VfsOpenCallback,
    VfsOpenWithResolveCallback, VfsPreadCallback, VfsPwriteCallback, VfsReadFileCallback,
    VfsReaddirCallback, VfsReadlinkCallback, VfsRenameCallback, VfsStat, VfsStatCallback,
    VfsStatNofollowCallback, VfsSymlinkCallback, VfsTruncateCallback, VfsUnlinkCallback,
};
pub(crate) use helpers::{stage_pending_tls_bases, WAITER_REGISTRY_MAX_ENTRIES};
#[cfg(feature = "syscall_test")]
pub use memory::{arm_populate_fault_probe, POPULATE_FAULT_PROBE_PAGES};
pub(crate) use memory::{
    copy_to_user, debug_validate_mmap_entry, decide_mremap_placement, mmap_region_len,
    mremap_byte_delta, mremap_tail_len, mremap_uncharged_reserve, EagerPopulator, FailedPopulate,
    MremapPlacement, RecordingFrameAllocator, MMAP_REGION_FLAG_MASK, MMAP_REGION_FLAG_PROT_NONE,
    MMAP_REGION_FLAG_SHARED, MMAP_REGION_FLAG_TRANSIENT_MASK,
};
pub use memory::{
    mmap_flags_to_perms, run_cow_mprotect_self_test, run_mmap_flags_self_test,
    run_mremap_flags_self_test, run_mremap_geometry_self_test,
    run_recording_frame_allocator_split_self_test, run_stack_window_exclusion_self_test,
    try_demand_grow_user_stack, try_grow_user_stack, MmapEntry, MMAP_REGION_FLAG_PROT_EXEC,
    MMAP_REGION_FLAG_PROT_READ, MMAP_REGION_FLAG_PROT_WRITE,
};
pub use poll::run_poll_socket_arm_self_test;
pub(crate) use signal::reset_sigactions_for_exec;
pub use signal::{
    default_fxsave_area, run_exec_signal_safepoint_self_test, run_irq_signal_delivery_self_test,
    run_sigframe_stack_locator_self_test, sanitize_fxsave_for_export,
    try_deliver_signal_on_irq_return,
};
pub use socket::{
    check_socket_timeouts, drain_socket_waiter_cleanup, register_cgroup_port_hooks,
    register_netns_device_hooks, register_socket_hooks, run_socket_waiter_deferred_free_self_test,
    KernelSocketWaitHooks,
};
pub use sys::ComplianceStatusBuf;
pub use time::run_startup_abi_self_test;

/// R130-1 FIX: Maximum number of mmap regions per process.
///
/// Bounds the per-process `mmap_regions` BTreeMap to prevent unbounded kernel
/// heap growth from unprivileged syscalls (e.g., millions of PROT_NONE mmaps).
///
/// R180-9 FIX: derive from general residual (~32 B/region incl. tree slack),
/// hard-capped at 4096. Linux default 65536 cannot fit in our 1 MiB heap residual.
///
/// R165-14: `pub(crate)` so fork.rs can re-assert the bound before cloning the
/// parent's region map into the child (see fork::fork_inner).
pub(crate) const MAX_MAP_COUNT: usize = {
    let residual = mm::general_residual_bytes();
    let by_bytes = residual / 32;
    if by_bytes < 64 {
        64
    } else if by_bytes > 4096 {
        4096
    } else {
        by_bytes
    }
};

/// 系统调用号定义（参考Linux系统调用表）
#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallNumber {
    // 进程管理
    Exit = 60,           // 退出进程
    ExitGroup = 231,     // 退出进程组
    Fork = 57,           // 创建子进程
    Exec = 59,           // 执行程序
    Wait = 61,           // 等待子进程
    GetPid = 39,         // 获取进程ID
    GetTid = 186,        // 获取线程ID
    GetPPid = 110,       // 获取父进程ID
    SetTidAddress = 218, // 设置 clear_child_tid
    SetRobustList = 273, // 设置 robust_list
    GetRobustList = 274, // GAP-5 G8: 读取 robust_list
    Kill = 62,           // 发送信号

    // 文件I/O
    Read = 0,   // 读取文件
    Write = 1,  // 写入文件
    Open = 2,   // 打开文件
    Close = 3,  // 关闭文件
    Stat = 4,   // 获取文件状态
    Fstat = 5,  // 获取文件描述符状态
    Lseek = 8,  // 移动文件指针
    Ioctl = 16, // I/O 控制

    // 内存管理
    Brk = 12,      // 改变数据段大小
    Mmap = 9,      // 内存映射
    Munmap = 11,   // 取消内存映射
    Mprotect = 10, // 设置内存保护

    // 进程间通信
    Pipe = 22, // 创建管道
    Dup = 32,  // 复制文件描述符
    Dup2 = 33, // 复制文件描述符到指定位置

    // 时间相关
    Time = 201,  // 获取时间
    Sleep = 35,  // 睡眠
    Futex = 202, // 快速用户空间互斥锁

    // 其他
    Yield = 24,      // 主动让出CPU
    GetCwd = 79,     // 获取当前工作目录
    Chdir = 80,      // 改变当前工作目录
    GetRandom = 318, // 获取随机字节
}

/// 系统调用错误码
#[repr(i64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallError {
    Success = 0,        // 成功
    EPERM = -1,         // 操作不允许
    ENOENT = -2,        // 文件或目录不存在
    ESRCH = -3,         // 进程不存在
    EINTR = -4,         // 系统调用被中断
    EIO = -5,           // I/O错误
    ENXIO = -6,         // 设备不存在
    E2BIG = -7,         // 参数列表过长
    ENOEXEC = -8,       // 执行格式错误
    EBADF = -9,         // 文件描述符错误
    ECHILD = -10,       // 没有子进程
    EAGAIN = -11,       // 资源暂时不可用
    ENOMEM = -12,       // 内存不足
    EACCES = -13,       // 权限不足
    EFAULT = -14,       // 地址错误
    EBUSY = -16,        // 设备或资源忙
    EEXIST = -17,       // 文件已存在
    EXDEV = -18,        // 跨设备链接 (cross-device link)
    ENOTDIR = -20,      // 不是目录
    EISDIR = -21,       // 是目录
    EINVAL = -22,       // 无效参数
    ENFILE = -23,       // 系统打开文件过多
    EMFILE = -24,       // 进程打开文件过多
    ENOTTY = -25,       // 不是终端设备
    ESPIPE = -29,       // Illegal seek (不支持seek操作，如管道/socket)
    EPIPE = -32,        // 管道破裂
    ERANGE = -34,       // 结果超出范围
    ENOSYS = -38,       // 功能未实现
    ENOTEMPTY = -39,    // 目录非空
    ELOOP = -40,        // 符号链接过多或禁止符号链接
    ENOSPC = -28,       // 设备无空间 (no space left on device)
    EROFS = -30,        // 只读文件系统 (read-only filesystem)
    ENAMETOOLONG = -36, // 文件名过长 (filename too long)
    // Socket-related errors (Linux ABI)
    ENOTSOCK = -88,        // 套接字操作目标不是套接字
    EDESTADDRREQ = -89,    // 需要目标地址
    EMSGSIZE = -90,        // 消息太长
    EPROTOTYPE = -91,      // 协议类型错误
    ENOPROTOOPT = -92,     // 协议选项不可用
    EPROTONOSUPPORT = -93, // 协议不支持
    EAFNOSUPPORT = -97,    // 地址族不支持
    EADDRINUSE = -98,      // 地址已被使用
    EADDRNOTAVAIL = -99,   // 无法分配请求的地址
    ENETDOWN = -100,       // 网络不可用
    ENETUNREACH = -101,    // D3 NETNS-ROUTING: 网络不可达 (unroutable destination)
    EHOSTUNREACH = -113,   // D3 PENDING-FRAME v2: 主机不可达 (on-link neighbor unresolved)
    ECONNREFUSED = -111,   // 连接被拒绝
    EISCONN = -106,        // 套接字已连接
    ENOTCONN = -107,       // 传输端点未连接
    ETIMEDOUT = -110,      // R39-6 FIX: 操作超时
    EALREADY = -114,       // 操作已经在进行
    EINPROGRESS = -115,    // 操作正在进行
    EOPNOTSUPP = -95,      // 操作不支持
    ECONNABORTED = -103,   // R51-1: 连接被中止 (accept on closed listener)
    ENOBUFS = -105,        // No network buffer space available
    // E.4 PI: Robust futex error
    EOWNERDEAD = -130, // E.4 PI: Robust futex - 锁持有者已退出
    EDEADLK = -35,     // GAP-5 PI parity: FUTEX_LOCK_PI on a lock the caller owns
    // R104-4: Arithmetic overflow (POSIX value 75)
    EOVERFLOW = -75, // 值溢出 (value too large for data type)
}

impl SyscallError {
    pub fn as_i64(self) -> i64 {
        self as i64
    }
}

/// 系统调用结果类型
pub type SyscallResult = Result<usize, SyscallError>;

/// 初始化系统调用处理器
pub fn init() {
    klog_always!("Syscall handler initialized");
    klog_always!("  Supported syscalls: exit, fork, getpid, read, write, yield");
}

/// 系统调用分发器
///
/// 根据系统调用号和参数执行相应的系统调用
///
/// # Audit Trail
///
/// All syscalls emit an audit event after completion with:
/// - Syscall number and up to 6 arguments
/// - Success/Error outcome
/// - Process context (pid, uid, gid)
///
/// 在返回前检查 NEED_RESCHED 标志，如果需要则执行调度。
/// 这是 NEED_RESCHED 的主要消费点，确保时间片到期后能在返回用户态前触发调度。
pub fn syscall_dispatcher(
    syscall_num: u64,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
) -> i64 {
    // Capture timestamp at syscall entry
    let timestamp = crate::time::get_ticks();

    // G.1: Count every syscall entry (per-CPU, lock-free, IRQ-safe)
    increment_counter(TraceCounter::SyscallEntry, 1);

    // R154-I1 FIX: Early-exit if this thread is marked for death by exit_group().
    // Without this, a pending_kill thread can execute one full syscall before the
    // flag is consumed at the normal syscall-return check point.
    // We use take_pending_process_exit() (which atomically clears the flag) and
    // terminate_self_and_halt() so the thread actually dies rather than looping
    // on EINTR indefinitely.
    let args = [arg0, arg1, arg2, arg3, arg4, arg5];
    let mut exec_handoff = false;
    let mut entry_pid: Option<ProcessId> = None;
    let mut entry_tgid: ProcessId = 0;
    let mut entry_creds: Option<crate::process::CredentialIds> = None;
    let mut fast_ns_id: Option<Result<usize, ()>> = None;
    let mut entry_proc: Option<ProcessArc> = None;

    // Issue #109 §4.1: Consolidate syscall_entry_safe_point + atomic-gated
    // seccomp/pledge evaluation + LSM (tgid, credentials) snapshot + read-only
    // getpid/gettid namespace ID resolution into ONE PROCESS_TABLE + PCB lock.
    let verdict = if let Some(pid) = crate::process::current_pid() {
        entry_pid = Some(pid);
        // M0 item 5: record this task as the owner of the current syscall frame, so
        // the MUTABLE frame accessor used by signal-handler delivery at the return
        // tail can reject a stale cross-task `frame_ptr` (defense-in-depth + the
        // invariant the future preemptive-IRQ slice relies on). Exec and raw-image
        // spawn also need this binding to redirect SYSRET into the replacement
        // image, even when no signal handler exists. A handler for THIS task is always
        // installed by a PRIOR rt_sigaction syscall (so the hint is already set at a
        // later syscall's entry); a cross-process install that trips the hint mid-
        // syscall is harmless (this task has no handler in its own table, so no frame
        // is ever built and the unset owner is never consulted).
        set_syscall_frame_owner(pid);
        // M0 item 5 (1b-2): SNAPSHOT the live syscall-frame binding into the PCB so
        // a blocked-and-resumed return tail can republish it (`switch_context` zeroes
        // the per-CPU `frame_ptr` on a block, which would otherwise fail-close the
        // delivery accessor and defer the handler to the NEXT syscall). The exec
        // front-ends can also block while loading, so capture their binding here.
        // The binding is owner==pid here (set_syscall_frame_owner just ran); an
        // invalid pair is stored as cleared (defensive — the syscall ASM always sets
        // `frame_ptr` before this dispatcher runs).
        //
        // GAP-5 exec step 2: the same PCB lock consumes a posted fatal exit first
        // (R154-I1: such a thread must not run one more syscall) and reports an exec
        // handed to this group leader. A member of a multi-member group always
        // snapshots: a non-leader's exec may run on this frame at syscall return.
        let (frame_ptr, owner) = current_syscall_frame_binding();
        let binding = is_valid_frame_binding(frame_ptr, owner, pid).then_some((frame_ptr, owner));
        let want_snapshot =
            matches!(syscall_num, 59 | 517) || crate::signal::any_handler_installed();
        match crate::process::syscall_entry_prepare(pid, syscall_num, &args, binding, want_snapshot)
        {
            crate::process::SyscallEntryState::Exit(exit_code) => {
                increment_counter(TraceCounter::SyscallExit, 1);
                terminate_self_and_halt(pid, exit_code);
            }
            crate::process::SyscallEntryState::MissingProcess => {
                // Fail-closed: matches standalone evaluate_seccomp when PCB is absent.
                seccomp::SeccompVerdict::kill(0)
            }
            crate::process::SyscallEntryState::Ready {
                proc_arc,
                exec_handoff: handoff,
                verdict,
                tgid,
                creds,
                fast_ns_id: ns_id,
            } => {
                entry_proc = Some(proc_arc);
                exec_handoff = handoff;
                entry_tgid = tgid;
                entry_creds = creds;
                fast_ns_id = ns_id;
                verdict
            }
        }
    } else {
        seccomp::SeccompVerdict::kill(0)
    };

    match verdict.action {
        seccomp::SeccompAction::Kill => {
            increment_counter(TraceCounter::SyscallDenied, 1);
            // R25-4 + R39-2 FIX: Kill process with SIGSYS semantics and NEVER return
            //
            // SECURITY: After terminating the process, we must not return to userspace.
            // The process state is now invalid (PCB cleaned up, memory potentially freed).
            // Returning would cause UAF and complete seccomp bypass.
            let pid = match entry_pid {
                Some(pid) => pid,
                None => {
                    // No current PID is an internal invariant failure.  Do
                    // not enter an unbounded spin with interrupts enabled;
                    // panic routes through the kernel's safe halt path.
                    panic!("seccomp Kill without a current process");
                }
            };

            if let Some(creds) = entry_creds {
                seccomp::notify_violation(
                    pid as u32,
                    creds.uid,
                    creds.gid,
                    syscall_num,
                    &verdict,
                    timestamp,
                );
            }

            // Release cached ProcessArc before abandoning the syscall stack so
            // reaping can reclaim the PCB allocation and its admission slot.
            drop(entry_proc);
            // R117-1 FIX: Use centralized terminate_self_and_halt() which disables
            // interrupts and switches to boot CR3 before halting, preventing timer
            // IRQ UAF on the zombie's stack/CR3.
            crate::process::terminate_group_self_and_halt(pid, 128 + 31);
        }
        seccomp::SeccompAction::Trap => {
            increment_counter(TraceCounter::SyscallDenied, 1);
            // R25-4 + R39-2 FIX: Trap treated as fatal until SIGSYS delivery exists
            //
            // SECURITY: Same rationale as Kill - process is terminated, never return.
            let pid = match entry_pid {
                Some(pid) => pid,
                None => {
                    panic!("seccomp Trap without a current process");
                }
            };

            if let Some(creds) = entry_creds {
                seccomp::notify_violation(
                    pid as u32,
                    creds.uid,
                    creds.gid,
                    syscall_num,
                    &verdict,
                    timestamp,
                );
            }

            // Release cached ProcessArc before abandoning the syscall stack.
            drop(entry_proc);
            // R117-1 FIX: Use centralized terminate_self_and_halt().
            crate::process::terminate_group_self_and_halt(pid, 128 + 31);
        }
        seccomp::SeccompAction::Errno(e) => {
            increment_counter(TraceCounter::SyscallDenied, 1);
            // Return the error code - audit the violation
            if let Some(creds) = entry_creds {
                if let Some(pid) = entry_pid {
                    seccomp::notify_violation(
                        pid as u32,
                        creds.uid,
                        creds.gid,
                        syscall_num,
                        &verdict,
                        timestamp,
                    );
                }
            }
            increment_counter(TraceCounter::SyscallExit, 1);
            return -(e as i64);
        }
        seccomp::SeccompAction::Log => {
            // Log the violation but continue
            if let Some(creds) = entry_creds {
                if let Some(pid) = entry_pid {
                    seccomp::notify_violation(
                        pid as u32,
                        creds.uid,
                        creds.gid,
                        syscall_num,
                        &verdict,
                        timestamp,
                    );
                }
            }
            // Fall through to dispatch
        }
        seccomp::SeccompAction::Allow => {
            // Continue to dispatch
        }
    }

    // LSM hook: check syscall entry with security policy
    // Build context from the single-lock entry snapshot; on missing credentials,
    // fail closed with EPERM (R184-U01-1 / R192-5 / TD-LSM-1).
    let lsm_creds = entry_creds.map(|c| lsm::Credentials {
        uid: c.uid,
        gid: c.gid,
        euid: c.euid,
        egid: c.egid,
    });
    let lsm_ctx = lsm::SyscallCtx::from_snapshot(
        entry_pid.unwrap_or(0),
        entry_tgid,
        entry_pid.and(lsm_creds),
        syscall_num,
        &args,
    );
    // R192-5 / TD-LSM-1 FIX: the R142-4 `debug_assert!(lsm_ctx.is_some())` that
    // stood here called a missing context a kernel bug, but `from_current`
    // returns None whenever a sibling thread holds the shared credentials for
    // writing (`try_read`), so a debug kernel panicked on a legitimate race.
    // The R184 arm below is the contract: fail closed, never panic.
    let lsm_ctx = match lsm_ctx {
        Some(ctx) => ctx,
        None => {
            // R184-U01-1 FIX: a missing security context is an internal
            // consistency failure, never an implicit allow.  `from_current`
            // may legitimately fail while another CPU updates credentials;
            // dispatching in that window would bypass every MAC hook.  Fail
            // closed.
            increment_counter(TraceCounter::SyscallDenied, 1);
            let subject = get_audit_subject();
            let _ = audit::emit_lsm_denial(
                subject,
                AuditObject::None,
                "syscall_context",
                audit::AuditLsmReason::Internal,
                SyscallError::EPERM as i32,
                timestamp,
            );
            increment_counter(TraceCounter::SyscallExit, 1);
            return SyscallError::EPERM.as_i64();
        }
    };
    // GAP-5 exec step 2: the handed-over exec runs its own LSM exec hook.
    let enter_verdict = if exec_handoff {
        Ok(())
    } else {
        lsm::hook_syscall_enter(&lsm_ctx)
    };
    if let Err(err) = enter_verdict {
        increment_counter(TraceCounter::SyscallDenied, 1);
        // LSM denied the syscall - call exit hook and return error
        let errno = lsm_error_to_syscall(err);
        let ret = errno.as_i64();
        let _ = lsm::hook_syscall_exit(&lsm_ctx, ret as isize);
        increment_counter(TraceCounter::SyscallExit, 1);
        return ret;
    }

    // GAP-5 exec step 2: the exec a non-leader handed to this leader replaces
    // the call. Release `entry_proc` first because `run_exec_handoff()` can
    // terminate fatally without unwinding this frame.
    if exec_handoff {
        drop(entry_proc);
        let result = run_exec_handoff();
        return finish_syscall(syscall_num, &args, timestamp, &lsm_ctx, result, false, None);
    }

    // Release cached ProcessArc before any syscall whose handler may terminate
    // fatally without unwinding (`rt_sigreturn`, `execve`, `exit`, `kill`,
    // `tkill`, `exit_group`, `tgkill`, `spawn_image`) so the dying task's PCB
    // strong count never stays pinned on the abandoned syscall stack.
    if matches!(syscall_num, 15 | 59 | 60 | 62 | 200 | 231 | 234 | 517) {
        entry_proc = None;
    }

    let result = match syscall_num {
        // 进程管理
        56 => sys_clone(
            arg0,
            arg1 as *mut u8,
            arg2 as *mut i32,
            arg3 as *mut i32,
            arg4,
        ),
        60 => sys_exit(arg0 as i32),
        231 => sys_exit_group(arg0 as i32),
        // M2-1 SLICE-2 INVARIANT (vfork / syscall 58 scope boundary):
        // There is intentionally NO `58 =>` arm here. vfork is in the default
        // seccomp allowlist (`pledge_syscall_list` / `promise_allows_syscall`
        // under PledgePromises::PROC) but has no dispatch, so syscall 58 falls
        // through to the `_ => Err(ENOSYS)` default arm below. It is listed as
        // `UndispatchedKind::NoArm` in INTENTIONAL_UNDISPATCHED, and the hosted
        // R190-11 parity test fails if an arm appears. vfork is therefore ENOSYS and
        // CHARGE-NEUTRAL today: it creates no process and no address space, so
        // it can never pin/charge cgroup memory and cannot strand a mem_pinned
        // residual (no path exists). If a FUTURE slice wires vfork to real Linux
        // semantics (child borrows the parent's MmState until exec/exit), the
        // handler MUST route memory accounting through exactly ONE of:
        //   (a) fork_inner / sys_fork  -> independent MmState, so the aggregated
        //       fork charge at fork.rs:240 (try_charge_memory(parent_cgroup_id,
        //       fork_charge_bytes)) applies and telescopes via the child's exit
        //       uncharge; OR
        //   (b) the CLONE_VM shared-MmState path (see line ~3151:
        //       `if flags & CLONE_VM != 0 { (parent_space, true) }`) which shares
        //       the parent AS and performs NO independent fork charge.
        // A vfork handler MUST NOT introduce a THIRD, uncharged AS-creating path:
        // a shared-MmState process that independently fork-charges would double
        // the charge (the FA-09 over-count / permanent-undeletability direction),
        // and an independent-MmState process that skips the fork charge would
        // strand the child's exit uncharge into a saturating under-count.
        57 => sys_fork(entry_proc.as_ref()),
        // M0-4: execve is now REAL path-based exec(pathname, argv, envp).
        // arg0 is a pathname pointer (NOT a raw ELF image) — the confused-deputy
        // is gone. Native raw-image spawn moved to sys_spawn_image (517).
        59 => sys_execve(
            arg0 as *const u8,        // pathname
            arg1 as *const *const u8, // argv
            arg2 as *const *const u8, // envp
        ),
        // ST-K3 FIX (wait4 ABI): Linux wait4(pid, wstatus, options, rusage) —
        // the pid SELECTOR is arg0 and the status pointer is arg1. The old
        // dispatch passed arg0 (the PID) as the status pointer, so musl's
        // waitpid(pid, &status, 0) hit copy_to_user(pid) = EFAULT on the first
        // Ring-3 parent that ever reaped a real child (stress-v2 memory
        // profile, stage=cgroup_child_wait errno=14). rusage (arg3) is
        // accepted and ignored — Linux permits NULL.
        61 => sys_wait4(
            arg0 as i64,
            arg1 as *mut i32,
            arg2 as i32,
            entry_proc.clone(),
        ),
        39 => sys_getpid_fast(fast_ns_id),
        186 => sys_gettid_fast(fast_ns_id),
        110 => sys_getppid(),
        102 => sys_getuid(),
        107 => sys_geteuid(),
        104 => sys_getgid(),
        108 => sys_getegid(),
        218 => sys_set_tid_address(arg0 as *mut i32),
        273 => sys_set_robust_list(arg0 as *const u8, arg1 as usize),
        274 => sys_get_robust_list(arg0 as i32, arg1 as *mut u64, arg2 as *mut u64),
        62 => sys_kill(arg0 as ProcessId, arg1 as i32),
        // GAP-5 slice 4 G7: thread-directed signals.
        200 => sys_tkill(arg0 as i32, arg1 as i32),
        234 => sys_tgkill(arg0 as i32, arg1 as i32, arg2 as i32),
        // M0 item 5: signal-handler delivery (sub-slice 1a).
        13 => sys_rt_sigaction(
            arg0 as i32,
            arg1 as *const u8,
            arg2 as *mut u8,
            arg3 as usize,
        ),
        14 => sys_rt_sigprocmask(
            arg0 as i32,
            arg1 as *const u8,
            arg2 as *mut u8,
            arg3 as usize,
        ),
        15 => sys_rt_sigreturn(),
        // F.1: Namespace unshare
        272 => sys_unshare(arg0 as u64),
        // F.1: setns for mount namespace
        308 => sys_setns(arg0 as i32, arg1 as i32),

        // 文件I/O
        0 => sys_read(
            arg0 as i32,
            arg1 as *mut u8,
            arg2 as usize,
            entry_proc.as_ref(),
        ),
        1 => sys_write(
            arg0 as i32,
            arg1 as *const u8,
            arg2 as usize,
            entry_proc.as_ref(),
        ),
        17 => sys_pread64(arg0 as i32, arg1 as *mut u8, arg2 as usize, arg3 as i64),
        18 => sys_pwrite64(arg0 as i32, arg1 as *const u8, arg2 as usize, arg3 as i64),
        2 => sys_open(arg0 as *const u8, arg1 as i32, arg2 as u32),
        257 => sys_openat(arg0 as i32, arg1 as *const u8, arg2 as i32, arg3 as u32),
        437 => sys_openat2(
            arg0 as i32,
            arg1 as *const u8,
            arg2 as *const OpenHow,
            arg3 as usize,
        ),
        3 => sys_close(arg0 as i32, entry_proc.as_ref()),
        4 => sys_stat(arg0 as *const u8, arg1 as *mut VfsStat),
        5 => sys_fstat(arg0 as i32, arg1 as *mut VfsStat),
        6 => sys_lstat(arg0 as *const u8, arg1 as *mut VfsStat),
        262 => sys_fstatat(
            arg0 as i32,
            arg1 as *const u8,
            arg2 as *mut VfsStat,
            arg3 as i32,
        ),
        // M0-6: statx - modern extended stat interface
        332 => sys_statx(
            arg0 as i32,
            arg1 as *const u8,
            arg2 as i32,
            arg3 as u32,
            arg4 as *mut u8,
        ),
        8 => sys_lseek(arg0 as i32, arg1 as i64, arg2 as i32),
        16 => sys_ioctl(arg0 as i32, arg1, arg2),
        19 => sys_readv(arg0 as i32, arg1 as *const Iovec, arg2 as usize),
        20 => sys_writev(arg0 as i32, arg1 as *const Iovec, arg2 as usize),
        22 => sys_pipe(arg0 as *mut i32, entry_proc.as_ref()),
        32 => sys_dup(arg0 as i32),
        33 => sys_dup2(arg0 as i32, arg1 as i32),
        72 => sys_fcntl(arg0 as i32, arg1 as i32, arg2),
        292 => sys_dup3(arg0 as i32, arg1 as i32, arg2 as i32),
        77 => sys_ftruncate(arg0 as i32, arg1 as i64),
        74 => sys_fsync(arg0 as i32),
        75 => sys_fdatasync(arg0 as i32),
        162 => sys_sync(),
        277 => sys_sync_file_range(arg0 as i32, arg1 as i64, arg2 as i64, arg3 as u32),
        217 => sys_getdents64(arg0 as i32, arg1 as *mut u8, arg2 as usize),
        293 => sys_pipe2(arg0 as *mut i32, arg1 as i32, entry_proc.as_ref()),

        // 文件系统操作
        21 => sys_access(arg0 as *const u8, arg1 as i32),
        79 => sys_getcwd(arg0 as *mut u8, arg1 as usize),
        80 => sys_chdir(arg0 as *const u8),
        83 => sys_mkdir(arg0 as *const u8, arg1 as u32),
        84 => sys_rmdir(arg0 as *const u8),
        86 => sys_link(arg0 as *const u8, arg1 as *const u8),
        87 => sys_unlink(arg0 as *const u8),
        // M0-6 slice 3: symlink/readlink - DEFERRED per plan
        // Blocked on ramfs lacking Symlink NodeKind + /proc/self contradictory inode
        88 => sys_symlink(arg0 as *const u8, arg1 as *const u8),
        89 => sys_readlink(arg0 as *const u8, arg1 as *mut u8, arg2 as usize),
        // M0-6 slice 2: rename family. 82 is pledge-promised (WPATH); 264/316 dispatch as
        // plain unpledged arms (no seccomp constant -> default-denied for a pledged process).
        82 => sys_rename(arg0 as *const u8, arg1 as *const u8),
        264 => sys_renameat(
            arg0 as i32,
            arg1 as *const u8,
            arg2 as i32,
            arg3 as *const u8,
        ),
        316 => sys_renameat2(
            arg0 as i32,
            arg1 as *const u8,
            arg2 as i32,
            arg3 as *const u8,
            arg4 as u32,
        ),
        90 => sys_chmod(arg0 as *const u8, arg1 as u32),
        91 => sys_fchmod(arg0 as i32, arg1 as u32),
        95 => sys_umask(arg0 as u32),
        155 => sys_pivot_root(arg0 as *const u8, arg1 as *const u8),
        161 => sys_chroot(arg0 as *const u8),

        // M0-6: POSIX resource limits (closes the RLIMIT allowed-but-ENOSYS seam).
        // prlimit64 arg order: (pid, resource, NEW=arg2, OLD=arg3) — keep new=arg2/old=arg3.
        97 => sys_getrlimit(arg0 as u32, arg1 as *mut u8),
        160 => sys_setrlimit(arg0 as u32, arg1 as *const u8),
        302 => sys_prlimit64(
            arg0 as ProcessId,
            arg1 as u32,
            arg2 as *const u8,
            arg3 as *mut u8,
        ),

        // 内存管理
        12 => sys_brk(arg0 as usize),
        9 => sys_mmap(
            arg0 as usize,
            arg1 as usize,
            arg2 as i32,
            arg3 as i32,
            arg4 as i32,
            arg5 as i64,
        ),
        10 => sys_mprotect(arg0 as usize, arg1 as usize, arg2 as i32),
        11 => sys_munmap(arg0 as usize, arg1 as usize),

        // 架构相关
        158 => sys_arch_prctl(arg0 as i32, arg1 as u64),

        // Futex
        // R39-6 FIX: 传递第4个参数用于超时
        202 => sys_futex(
            arg0 as usize,
            arg1 as i32,
            arg2 as u32,
            arg3 as usize,
            arg4 as usize,
            arg5 as u32,
        ),

        // 安全/沙箱 (Seccomp/Prctl)
        157 => sys_prctl(arg0 as i32, arg1, arg2, arg3, arg4),
        317 => sys_seccomp(arg0 as u32, arg1 as u32, arg2),

        // 时间相关
        35 => sys_nanosleep(arg0 as *const TimeSpec, arg1 as *mut TimeSpec),
        96 => sys_gettimeofday(arg0 as *mut TimeVal, arg1 as usize),
        228 => sys_clock_gettime(arg0 as i32, arg1 as *mut TimeSpec),

        // 系统信息
        63 => sys_uname(arg0 as *mut UtsName),

        // 其他
        24 => sys_yield(),
        318 => sys_getrandom(arg0 as *mut u8, arg1 as usize, arg2 as u32),

        // CPU Affinity (E.5 SMP Scheduler - syscalls 203/204)
        203 => sys_sched_setaffinity(arg0 as i32, arg1 as usize, arg2 as *const u8),
        204 => sys_sched_getaffinity(arg0 as i32, arg1 as usize, arg2 as *mut u8),

        // 套接字 (Socket syscalls - Linux x86_64 ABI)
        41 => sys_socket(arg0 as i32, arg1 as i32, arg2 as i32),
        42 => sys_connect(arg0 as i32, arg1 as *const SockAddrIn, arg2 as u32),
        43 => sys_accept(arg0 as i32, arg1 as *mut SockAddrIn, arg2 as *mut u32),
        288 => sys_accept4(
            arg0 as i32,
            arg1 as *mut SockAddrIn,
            arg2 as *mut u32,
            arg3 as i32,
        ),
        44 => sys_sendto(
            arg0 as i32,
            arg1 as *const u8,
            arg2 as usize,
            arg3 as i32,
            arg4 as *const SockAddrIn,
            arg5 as u32,
        ),
        45 => sys_recvfrom(
            arg0 as i32,
            arg1 as *mut u8,
            arg2 as usize,
            arg3 as i32,
            arg4 as *mut SockAddrIn,
            arg5 as *mut u32,
        ),
        46 => sys_sendmsg(arg0 as i32, arg1 as *const MsgHdr, arg2 as i32),
        47 => sys_recvmsg(arg0 as i32, arg1 as *mut MsgHdr, arg2 as i32),
        48 => sys_shutdown(arg0 as i32, arg1 as i32),
        49 => sys_bind(arg0 as i32, arg1 as *const SockAddrIn, arg2 as u32),
        50 => sys_listen(arg0 as i32, arg1 as i32),
        51 => sys_getsockname(arg0 as i32, arg1 as *mut SockAddrIn, arg2 as *mut u32),
        52 => sys_getpeername(arg0 as i32, arg1 as *mut SockAddrIn, arg2 as *mut u32),
        54 => sys_setsockopt(
            arg0 as i32,
            arg1 as i32,
            arg2 as i32,
            arg3 as *const u8,
            arg4 as u32,
        ),
        55 => sys_getsockopt(
            arg0 as i32,
            arg1 as i32,
            arg2 as i32,
            arg3 as *mut u8,
            arg4 as *mut u32,
        ),

        // F.2 Cgroup v2 syscalls (Zero-OS specific, 500-504, 513, 516)
        500 => sys_cgroup_create(arg0 as u64, arg1 as u32),
        501 => sys_cgroup_destroy(arg0 as u64),
        502 => sys_cgroup_attach(arg0 as u64),
        503 => sys_cgroup_set_limit(arg0 as u64, arg1 as u32, arg2),
        // 504 is the FROZEN v1 stats ABI (2-arg, writes the 104-byte v1 prefix, returns 0).
        504 => sys_cgroup_get_stats(arg0 as u64, arg1 as *mut CgroupStatsBuf),
        513 => sys_cgroup_delegate(arg0 as u64, arg1 as u64),
        // J.2: v2 stats with statx-style size negotiation (writes min(buf_len, sizeof)).
        516 => sys_cgroup_get_stats2(arg0 as u64, arg1 as *mut CgroupStatsBuf, arg2 as usize),

        // M0-4: Zero-OS-private (517) raw in-memory-image spawn — the pre-M0-4
        // execve(image, image_len, argv, envp) behavior, relocated off 59 so that
        // execve(59) can be real path-based. arg0 is ALWAYS an image pointer here.
        517 => sys_spawn_image(
            arg0 as *const u8,
            arg1 as usize,
            arg2 as *const *const u8,
            arg3 as *const *const u8,
        ),

        // D3 NETNS-DATAPLANE-CONFIG: Move network device between namespaces
        518 => sys_move_net_device(arg0 as u32, arg1 as i32),

        // G.3 Compliance syscalls (Zero-OS specific, 505-508)
        505 => sys_compliance_status(arg0 as *mut ComplianceStatusBuf),
        506 => sys_fips_enable(),
        507 => sys_compliance_query_algo(arg0 as u32),
        508 => sys_audit_export(arg0 as *mut u8, arg1 as usize, arg2 as u64, arg3 as usize),

        // G.2 Live Patching syscalls (Zero-OS specific, 509-512, 514-515)
        509 => sys_kpatch_load(arg0 as usize, arg1 as usize),
        510 => sys_kpatch_enable(arg0 as u64),
        511 => sys_kpatch_disable(arg0 as u64),
        // R104-5 FIX: Wire kpatch_unload to complete the livepatch syscall family
        512 => sys_kpatch_unload(arg0 as u64),
        // P1-4: Batch enable/disable with topological dependency ordering
        514 => sys_kpatch_enable_all(),
        515 => sys_kpatch_disable_all(),

        // KCOV (Kernel Code Coverage) syscalls (Zero-OS specific, 520-524)
        // Used for coverage-guided fuzzing infrastructure
        520 => sys_kcov_init(arg0 as usize),
        521 => sys_kcov_enable(),
        522 => sys_kcov_disable(),
        523 => sys_kcov_dump(arg0 as usize, arg1 as usize),
        524 => sys_kcov_reset(),

        // M0-6 poll/select: I/O multiplexing (poll/select/pselect6/ppoll).
        // ppoll/pselect6 timeout args are *mut: raw-Linux writes remaining time
        // back (glibc hides this in a local; man ppoll/pselect6 NOTES).
        7 => sys_poll(arg0, arg1, arg2),
        23 => sys_select(
            arg0 as i32,
            arg1 as *mut u8,
            arg2 as *mut u8,
            arg3 as *mut u8,
            arg4 as *mut u8,
        ),
        270 => sys_pselect6(
            arg0 as i32,
            arg1 as *mut u8,
            arg2 as *mut u8,
            arg3 as *mut u8,
            arg4 as *mut u8,
            arg5,
        ),
        271 => sys_ppoll(arg0, arg1, arg2 as *mut u8, arg3, arg4),

        // Memory management
        25 => sys_mremap(
            arg0 as u64,
            arg1 as usize,
            arg2 as usize,
            arg3 as i32,
            arg4 as u64,
        ),

        // File ownership (dispatch-or-stub per plan)
        92 => sys_chown(arg0 as *const u8, arg1 as u32, arg2 as u32),
        93 => sys_fchown(arg0 as i32, arg1 as u32, arg2 as u32),
        94 => sys_lchown(arg0 as *const u8, arg1 as u32, arg2 as u32),

        // Process wait
        247 => sys_waitid(arg0 as i32, arg1 as i32, arg2 as *mut u8, arg3 as i32),

        _ => Err(SyscallError::ENOSYS),
    };

    finish_syscall(
        syscall_num,
        &args,
        timestamp,
        &lsm_ctx,
        result,
        true,
        entry_proc,
    )
}

/// The syscall return path shared by every dispatched call: audit, the LSM
/// exit hook, the return safe point, signal delivery and rescheduling.
/// `dispatched` is false for a call skipped for a handed-over exec: its enter
/// hook did not run, and the exec audits itself (as `execve`).
fn finish_syscall(
    syscall_num: u64,
    args: &[u64; 6],
    timestamp: u64,
    lsm_ctx: &lsm::SyscallCtx,
    result: SyscallResult,
    dispatched: bool,
    entry_proc: Option<ProcessArc>,
) -> i64 {
    if dispatched {
        audit_syscall_exit(syscall_num, args, timestamp, lsm_ctx, &result);
    }
    let voluntary_yield = dispatched && syscall_num == 24 && result.is_ok();
    finish_syscall_tail(result, voluntary_yield, entry_proc)
}

/// Audit record and LSM exit hook for a dispatched call.
fn audit_syscall_exit(
    syscall_num: u64,
    args: &[u64; 6],
    timestamp: u64,
    lsm_ctx: &lsm::SyscallCtx,
    result: &SyscallResult,
) {
    // Issue #109 §4.1: Gate syscall audit emission behind an Acquire check on
    // AUDIT_ENABLED && AUDIT_INITIALIZED, and reuse the subject identity
    // already captured in `lsm_ctx` instead of re-locking PROCESS_TABLE + PCB.
    if audit::is_active() {
        // Emit audit event for syscall completion
        // Note: This is after the syscall so we capture the outcome
        let (outcome, errno) = match result {
            Ok(_) => (AuditOutcome::Success, 0),
            Err(e) => (AuditOutcome::Error, e.as_i64() as i32),
        };
        let subject = AuditSubject::new(lsm_ctx.pid as u32, lsm_ctx.euid, lsm_ctx.egid, None);

        // Emit audit event (ignore errors - audit should never block syscalls)
        // Include all 6 arguments for syscalls like mmap that use all of them
        let _ = audit::emit(
            AuditKind::Syscall,
            outcome,
            subject,
            AuditObject::None,
            &[
                syscall_num,
                args[0],
                args[1],
                args[2],
                args[3],
                args[4],
                args[5],
            ],
            errno,
            timestamp,
        );
    }

    // LSM hook: notify security policy of syscall exit
    let ret = match result {
        Ok(val) => *val as isize,
        Err(e) => e.as_i64() as isize,
    };
    let _ = lsm::hook_syscall_exit(lsm_ctx, ret);
}

/// Return safe point, signal delivery and rescheduling for every syscall.
fn finish_syscall_tail(
    mut result: SyscallResult,
    mut voluntary_yield: bool,
    entry_proc: Option<ProcessArc>,
) -> i64 {
    // Compute the syscall's return value (→ RAX). Captured here because signal
    // delivery saves it into the sigframe (so `rt_sigreturn` restores the
    // interrupted context's RAX — the EINTR / partial-op short-count contract: the
    // FINAL `result` is used verbatim, never recomputed).
    let mut ret_val: i64 = match &result {
        Ok(val) => *val as i64,
        Err(err) => err.as_i64(),
    };

    // R115-1 FIX: Honor cross-CPU exit requests at syscall return.
    //
    // exit_group() may request sibling threads to exit while they are running on
    // other CPUs. Those threads cannot be terminated remotely (UAF risk), so they
    // check the pending-kill flag here — the earliest safe point where the thread
    // is guaranteed to not be in the middle of a kernel operation.
    //
    // GAP-5 exec step 2: the same gate runs an exec handed to this leader while
    // it was in this call (its wait returned EINTR for it). The exec's result
    // replaces the call's.
    //
    // Issue #109 §4.1: Consolidate syscall_return_safe_point + maybe_deliver_signal
    // + poll_restore_sigmask_tail into ONE PCB lock, reusing `entry_proc` from
    // syscall entry so normal syscalls never re-acquire `PROCESS_TABLE`.
    if let Some(pid) = current_pid() {
        if let Some(proc_arc) = entry_proc.or_else(|| get_process(pid)) {
            let phase1 = {
                let mut proc = proc_arc.lock();
                let frame_bound = proc.saved_frame_ptr != 0 && proc.saved_frame_owner == pid as u64;
                match crate::process::syscall_safe_point_locked(&mut proc, frame_bound) {
                    crate::process::SyscallSafePoint::Exit(exit_code) => {
                        SignalTailStep::Exit(exit_code)
                    }
                    crate::process::SyscallSafePoint::ExecHandoff => SignalTailStep::ExecHandoff,
                    crate::process::SyscallSafePoint::Continue => {
                        maybe_deliver_signal_phase1(pid, &proc_arc, proc)
                    }
                }
            };
            match phase1 {
                SignalTailStep::Done => {
                    drop(proc_arc);
                }
                SignalTailStep::Exit(exit_code) => {
                    drop(proc_arc);
                    // R117-1 FIX: Use centralized terminate_self_and_halt().
                    terminate_self_and_halt(pid, exit_code);
                }
                SignalTailStep::ExecHandoff => {
                    drop(proc_arc);
                    voluntary_yield = false;
                    result = run_exec_handoff();
                    ret_val = match &result {
                        Ok(val) => *val as i64,
                        Err(err) => err.as_i64(),
                    };
                    if let Some(handoff_arc) = get_process(pid) {
                        let step = {
                            let handoff_proc = handoff_arc.lock();
                            maybe_deliver_signal_phase1(pid, &handoff_arc, handoff_proc)
                        };
                        finish_signal_tail_step(pid, ret_val, handoff_arc, step);
                    }
                }
                other => finish_signal_tail_step(pid, ret_val, proc_arc, other),
            }
        }
    } else {
        drop(entry_proc);
    }

    // 在返回用户态前检查是否需要调度
    // 这是定时器中断设置的 NEED_RESCHED 标志的主要消费点。
    // For `sched_yield()` (syscall 24), perform ONE combined deferred-work drain
    // + voluntary local yield here so U10-3 deferred work always runs BEFORE
    // switching away (even if the task is stopped before returning) without
    // duplicating the drain or reschedule across `sys_yield()` and this tail.
    if voluntary_yield {
        crate::scheduler_hook::drain_and_yield_reschedule();
    } else {
        crate::reschedule_if_needed();
    }

    // G.1: Count successful syscall exit (after all processing complete)
    increment_counter(TraceCounter::SyscallExit, 1);

    ret_val
}

// ============================================================================
// M0-6: seccomp pledge <-> dispatch DIVERGENCE-PREVENTION (the class fix)
// ============================================================================

/// Pledge-promised syscalls that HAVE a functional dispatcher arm (a handler
/// that is not a fixed ENOSYS stub; deliberate non-ENOSYS errnos such as
/// chmod's EOPNOTSUPP or link's EPERM count as dispatched). With
/// INTENTIONAL_UNDISPATCHED this must PARTITION the pledge union, so a
/// newly-promised-but-undispatched syscall (allowed-but-ENOSYS) fails the
/// parity self-test at `make test`.
///
/// R190-11 FIX: this list and INTENTIONAL_UNDISPATCHED were hand-verified and
/// had drifted. mremap, link, symlink and readlink were dispatched while still
/// listed as undispatched. The hosted `r190_11_dispatch_parity_tests` now parse
/// the real `syscall_dispatcher` match and fail on any disagreement.
const DISPATCHED_PROMISED: &[u64] = &[
    0, 1, 2, 3, 4, 5, 6, 8, // read write open close stat fstat lstat lseek
    7, 23, 270, 271, // poll select pselect6 ppoll (M0-6 poll/select STDIO wiring)
    9, 10, 11, 12, 25, // mmap mprotect munmap brk mremap (VM promise)
    24, 39, // sched_yield getpid
    56, 57, 59, 60, 61, 62,  // clone fork execve exit wait4 kill
    247, // waitid (ST-K3, dispatched 2026-09-25)
    74, 75, 162, 277, // fsync fdatasync sync sync_file_range (ST-K4)
    82, 83, 84, 87, // rename mkdir rmdir unlink  (82 = M0-6 slice 2)
    86, 88, 89, // link (fixed EPERM, R173-09) symlink readlink
    90, 91, // chmod fchmod (fixed EOPNOTSUPP, R72)
    97, 160, 302, // getrlimit setrlimit prlimit64  (M0-6 NEW)
    102, 104, 107, 108, 110, // getuid getgid geteuid getegid getppid
    202, 217, 218, // futex getdents64 set_tid_address
    228, 231, 257, 318, // clock_gettime exit_group openat getrandom
];

/// How an intentionally undispatched pledge syscall reaches ENOSYS.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum UndispatchedKind {
    /// No dispatcher arm: the number falls to the `_ => ENOSYS` default.
    NoArm,
    /// A dispatcher arm whose handler is a fixed ENOSYS stub.
    EnosysStub,
}

/// Pledge-promised syscalls deliberately NOT dispatched (ENOSYS), each with a
/// reason. Bounded by MAX_EXEMPT, which every future M0-6 slice MUST lower — so
/// this list can never permanently hide divergence.
const INTENTIONAL_UNDISPATCHED: &[(u64, UndispatchedKind, &str)] = &[
    (
        58,
        UndispatchedKind::NoArm,
        "vfork: deliberate ENOSYS-by-invariant (sys_clone documents the fallback)",
    ),
    (
        92,
        UndispatchedKind::EnosysStub,
        "chown: FATTR, ENOSYS stub arm (M0-6 later slice)",
    ),
    (
        93,
        UndispatchedKind::EnosysStub,
        "fchown: FATTR (post-const-fix), ENOSYS stub arm (M0-6 later slice)",
    ),
];
const MAX_EXEMPT: usize = 3;

/// R172-P6-F3: syscall numbers that are PRIVATE / native dispatch arms (reachable by direct
/// syscall number) but MUST NEVER appear in the pledge union — there is no seccomp constant
/// for them and they are not pledge-grantable. The parity test fences ALL of them (not just
/// 517): a future engineer who grants e.g. WPATH and naively adds renameat(264)/renameat2(316)
/// to the pledge union would otherwise hit the MISLEADING "must be dispatched XOR exempt"
/// failure (they are dispatched but NOT in DISPATCHED_PROMISED), which invites "fixing" it by
/// adding them to DISPATCHED_PROMISED — a fail-open seccomp escape (a private arm reachable
/// from a pledged sandbox). To LEGITIMATELY pledge one: remove it here, add it IDENTICALLY to
/// pledge_to_filter (seccomp/lib.rs) AND promise_allows_syscall (seccomp/types.rs) per R150-3,
/// AND add it to DISPATCHED_PROMISED — never silence the XOR assert by editing
/// DISPATCHED_PROMISED alone. Members: 517 spawn_image (Zero-OS-private native), 264 renameat
/// / 316 renameat2 (siblings of pledged 82 rename), 437 openat2 (sibling of pledged 257
/// openat), 262 newfstatat (sibling of pledged 4/5/6 stat-family).
const PRIVATE_NEVER_PLEDGED: &[u64] = &[262, 264, 316, 437, 517];

fn rlimit_is_exempt(nr: u64) -> bool {
    INTENTIONAL_UNDISPATCHED.iter().any(|&(n, _, _)| n == nr)
}

/// M0-6: the divergence-prevention parity self-test. Asserts the pledge allowlist
/// is PARTITIONED into dispatched XOR intentionally-exempt, fences the FastAllowSet
/// boundary, and confirms 517 is private. A future promise that grants an
/// un-dispatched syscall (allowed-but-ENOSYS) then fails `make test`.
pub fn run_pledge_dispatch_parity_self_test() {
    assert!(
        INTENTIONAL_UNDISPATCHED.len() <= MAX_EXEMPT,
        "M0-6: exemption set exceeded MAX_EXEMPT (a slice must LOWER it)"
    );
    let union = seccomp::pledge_full_syscall_union();
    for &nr in &union {
        assert!(
            nr < 512,
            "M0-6: pledge union member {} >= 512 (FastAllowSet boundary)",
            nr
        );
        let disp = DISPATCHED_PROMISED.contains(&nr);
        let ex = rlimit_is_exempt(nr);
        assert!(
            disp ^ ex,
            "M0-6 allowed-but-ENOSYS: pledge syscall {} must be dispatched XOR exempt (disp={}, exempt={})",
            nr, disp, ex
        );
    }
    for &nr in DISPATCHED_PROMISED {
        assert!(
            union.contains(&nr),
            "M0-6: DISPATCHED_PROMISED {} is not pledge-promised (stale)",
            nr
        );
    }
    for &(nr, _, _) in INTENTIONAL_UNDISPATCHED {
        assert!(
            union.contains(&nr),
            "M0-6: exemption {} is not pledge-promised (stale)",
            nr
        );
    }
    // R172-P6-F3: fence EVERY private/native arm out of the pledge union (the both-directions
    // form), not just 517 — so the misleading-XOR fail-open trap is closed for the whole
    // class (rename/openat/stat siblings), not just one number.
    for &nr in PRIVATE_NEVER_PLEDGED {
        assert!(
            !union.contains(&nr),
            "R172-P6-F3 fail-open seccomp escape: private/native syscall {} must NEVER be pledge-able",
            nr
        );
    }
    // Disjointness seal (the second direction): a private arm must NOT also be in
    // DISPATCHED_PROMISED. If a misled engineer adds e.g. 264 to DISPATCHED_PROMISED to
    // silence the XOR assert, THIS fires instead with a clear contradiction message,
    // converting the misleading invitation into an explicit stop sign.
    for &nr in PRIVATE_NEVER_PLEDGED {
        assert!(
            !DISPATCHED_PROMISED.contains(&nr),
            "R172-P6-F3 contradiction: {} is in BOTH PRIVATE_NEVER_PLEDGED and DISPATCHED_PROMISED",
            nr
        );
    }
}

/// M0-6: machine-check BPF<->semantic agreement (R150-3) + promise non-vacuity.
/// Every BPF-whitelisted syscall must also pass the authoritative semantic gate,
/// and every list-bearing promise must contribute >=1 syscall (catches a vacuous
/// promise like the empty UNIX/INET/DNS/PTRACE bits — tracked for a later slice).
pub fn run_pledge_semantic_parity_self_test() {
    use seccomp::types::PledgePromises;
    let all = PledgePromises::all();
    for nr in seccomp::pledge_syscall_list(all) {
        assert!(
            seccomp::types::promise_allows_syscall_probe(all, nr),
            "M0-6 R150-3 drift: BPF whitelists syscall {} but the semantic gate denies it",
            nr
        );
    }
    const LIST_BEARING: &[PledgePromises] = &[
        PledgePromises::STDIO,
        PledgePromises::RPATH,
        PledgePromises::WPATH,
        PledgePromises::CPATH,
        PledgePromises::TMPPATH,
        PledgePromises::PROC,
        PledgePromises::EXEC,
        PledgePromises::THREAD,
        PledgePromises::TIME,
        PledgePromises::SENDSIG,
        PledgePromises::FATTR,
        PledgePromises::RLIMIT,
        PledgePromises::VM,
    ];
    let base = seccomp::pledge_syscall_list(PledgePromises::empty()).len();
    for &bit in LIST_BEARING {
        assert!(
            seccomp::pledge_syscall_list(bit).len() > base,
            "M0-6: list-bearing promise contributes no syscalls (vacuous)"
        );
    }
}

/// R190-11 FIX: bind the hand-written pledge partition to the real dispatch
/// table. The boot parity self-test only compared lists with each other, so
/// it stayed green while six of seven "undispatched" entries had live arms.
#[cfg(test)]
mod r190_11_dispatch_parity_tests {
    use super::*;
    use alloc::string::String;
    use alloc::vec::Vec;

    /// `(number, handler)` for every `N => handler(...)` arm of the
    /// `syscall_dispatcher` match, parsed from this file. Any other arm form
    /// in the match (or-patterns, named constants, guards, blocks) fails the
    /// parse, so a new arm cannot hide from the checks below.
    fn dispatcher_arms() -> Vec<(u64, String)> {
        let source = include_str!("mod.rs");
        let start = source
            .find("    let result = match syscall_num {")
            .expect("syscall_dispatcher match not found");
        let body = &source[start + "    let result = match syscall_num {".len()..];
        let end = body
            .find("        _ => Err(SyscallError::ENOSYS),")
            .expect("syscall_dispatcher default arm not found");
        let mut arms = Vec::new();
        for line in body[..end].lines() {
            let line = line.trim_start();
            if line.starts_with("//") || !line.contains("=>") {
                continue;
            }
            let (number, rest) = line
                .split_once(" => ")
                .unwrap_or_else(|| panic!("unparsable dispatcher arm: {line}"));
            let number = number
                .parse::<u64>()
                .unwrap_or_else(|_| panic!("dispatcher arm must be one integer literal: {line}"));
            let handler = rest
                .split(|c: char| c == '(' || c.is_whitespace())
                .next()
                .unwrap_or_default();
            assert!(
                handler.starts_with("sys_"),
                "dispatcher arm must call a sys_ handler: {line}"
            );
            arms.push((number, String::from(handler)));
        }
        arms
    }

    /// R191-3: whether the body of `fn handler` in the syscall modules calls
    /// `lsm::hook(` on a line that is not a `//` comment. A top-level item's
    /// body ends at the first line that is just its closing brace. A text
    /// match: a call in dead code still counts (review's job, as in the
    /// census).
    fn handler_calls(handler: &str, hook: &str) -> bool {
        const SOURCES: &[&str] = &[
            include_str!("mod.rs"),
            include_str!("proc.rs"),
            include_str!("exec.rs"),
            include_str!("signal.rs"),
            include_str!("ns.rs"),
            include_str!("fs.rs"),
            include_str!("poll.rs"),
            include_str!("memory.rs"),
            include_str!("socket.rs"),
            include_str!("sandbox.rs"),
            include_str!("futex.rs"),
            include_str!("time.rs"),
            include_str!("cgroups.rs"),
            include_str!("sys.rs"),
        ];
        let sig_priv = alloc::format!("\nfn {}(", handler);
        let sig_pub_super = alloc::format!("\npub(super) fn {}(", handler);
        let mut found_body = None;
        for source in SOURCES {
            if let Some(start) = source.find(&sig_pub_super) {
                found_body = Some(&source[start + sig_pub_super.len()..]);
                break;
            }
            if let Some(start) = source.find(&sig_priv) {
                found_body = Some(&source[start + sig_priv.len()..]);
                break;
            }
        }
        let Some(body) = found_body else {
            panic!("handler {} not found as a top-level fn", handler);
        };
        let end = body.find("\n}").expect("handler body not closed");
        let call = alloc::format!("lsm::{}(", hook);
        body[..end]
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .any(|line| line.contains(&call))
    }

    /// Call a known fixed-errno stub handler with inert arguments and return
    /// `(result, pinned errno)`. None of these touches process state or user
    /// memory. The errno is pinned: a stub that gains a real body returns
    /// something else for these inputs (EBADF for fd -1, EFAULT for pointer 1),
    /// which fails the checks below.
    fn probe_fixed_errno_stub(handler: &str) -> Option<(SyscallResult, SyscallError)> {
        let inert = 1 as *const u8;
        match handler {
            "sys_chmod" => Some((sys_chmod(inert, 0), SyscallError::EOPNOTSUPP)),
            "sys_fchmod" => Some((sys_fchmod(-1, 0), SyscallError::EOPNOTSUPP)),
            "sys_chown" => Some((sys_chown(inert, 0, 0), SyscallError::ENOSYS)),
            "sys_fchown" => Some((sys_fchown(-1, 0, 0), SyscallError::ENOSYS)),
            "sys_lchown" => Some((sys_lchown(inert, 0, 0), SyscallError::ENOSYS)),
            "sys_link" => Some((sys_link(inert, inert), SyscallError::EPERM)),
            _ => None,
        }
    }

    #[test]
    fn pledge_partition_matches_dispatch_table() {
        let arms = dispatcher_arms();
        assert!(
            arms.len() > 100,
            "dispatcher parse found only {} arms",
            arms.len()
        );
        let handler_of = |nr: u64| {
            arms.iter()
                .find(|(number, _)| *number == nr)
                .map(|(_, handler)| handler.as_str())
        };
        for (index, (nr, _)) in arms.iter().enumerate() {
            assert!(
                !arms[..index].iter().any(|(other, _)| other == nr),
                "duplicate dispatcher arm {}",
                nr
            );
        }

        for &nr in DISPATCHED_PROMISED {
            let handler = handler_of(nr)
                .unwrap_or_else(|| panic!("DISPATCHED_PROMISED {} has no dispatcher arm", nr));
            if let Some((result, pinned)) = probe_fixed_errno_stub(handler) {
                assert_eq!(result, Err(pinned), "{} stub errno drifted", handler);
                assert_ne!(
                    pinned,
                    SyscallError::ENOSYS,
                    "DISPATCHED_PROMISED {} is an ENOSYS stub ({})",
                    nr,
                    handler
                );
            }
        }
        for &(nr, kind, _) in INTENTIONAL_UNDISPATCHED {
            match (kind, handler_of(nr)) {
                (UndispatchedKind::NoArm, None) => {}
                (UndispatchedKind::NoArm, Some(handler)) => {
                    panic!(
                        "exemption {} claims no arm but dispatches to {}",
                        nr, handler
                    )
                }
                (UndispatchedKind::EnosysStub, None) => {
                    panic!("exemption {} claims a stub arm but has none", nr)
                }
                (UndispatchedKind::EnosysStub, Some(handler)) => {
                    let (result, _) = probe_fixed_errno_stub(handler).unwrap_or_else(|| {
                        panic!("exemption {}: no stub probe for {}", nr, handler)
                    });
                    assert_eq!(
                        result,
                        Err(SyscallError::ENOSYS),
                        "{} must be ENOSYS",
                        handler
                    );
                }
            }
        }
        for &nr in PRIVATE_NEVER_PLEDGED {
            assert!(
                handler_of(nr).is_some(),
                "private syscall {} lost its arm",
                nr
            );
        }

        // R190-1: a syscall that would expose a feature-absent LSM hook family
        // has no arm, or only a fixed-errno stub. Wiring it for real requires
        // removing the census entry, which then requires a hook caller.
        let fence_absent = |nr: u64, hook: &str| {
            if let Some(handler) = handler_of(nr) {
                let (result, pinned) = probe_fixed_errno_stub(handler).unwrap_or_else(|| {
                    panic!(
                        "syscall {} ({}) reaches feature-absent {}: wire the hook \
                             and drop the FEATURE_ABSENT_HOOKS entry",
                        nr, handler, hook
                    )
                });
                assert_eq!(
                    result,
                    Err(pinned),
                    "{} is no longer its fixed-errno stub but {} is still \
                     feature-absent: wire the hook and drop the entry",
                    handler,
                    hook
                );
            }
        };
        for entry in lsm::FEATURE_ABSENT_HOOKS {
            for &nr in entry.syscalls {
                fence_absent(nr, entry.hook);
            }
        }

        // R192-7 FIX: pin the partially wired families independently of the
        // table that drives the loop below, so deleting or narrowing an entry
        // fails here instead of silently lifting its fence (the census pins the
        // same family from the source text).
        let pinned: &[(&str, &[u64], &[u64])] =
            &[("hook_ptrace", &[274], &[101, 310, 311, 312, 438])];
        assert_eq!(
            lsm::PARTIALLY_WIRED_HOOKS.len(),
            pinned.len(),
            "PARTIALLY_WIRED_HOOKS changed: update the R192-7 pin deliberately"
        );
        for &(hook, wired, absent) in pinned {
            let entry = lsm::PARTIALLY_WIRED_HOOKS
                .iter()
                .find(|entry| entry.hook == hook)
                .unwrap_or_else(|| panic!("{} left PARTIALLY_WIRED_HOOKS", hook));
            assert_eq!(entry.wired, wired, "{} wired set changed", hook);
            assert_eq!(entry.absent, absent, "{} fenced set changed", hook);
        }

        // R191-3: a partially wired family. Its wired syscalls' handlers call
        // the hook; its other syscalls are fenced as above.
        for entry in lsm::PARTIALLY_WIRED_HOOKS {
            assert!(
                !lsm::FEATURE_ABSENT_HOOKS
                    .iter()
                    .any(|absent| absent.hook == entry.hook),
                "{} is both partially wired and feature-absent",
                entry.hook
            );
            assert!(
                !entry.wired.is_empty(),
                "{} lists no wired syscall",
                entry.hook
            );
            for &nr in entry.wired {
                let handler = handler_of(nr).unwrap_or_else(|| {
                    panic!("{} wired syscall {} has no dispatcher arm", entry.hook, nr)
                });
                assert!(
                    handler_calls(handler, entry.hook),
                    "{} (syscall {}) does not call {}",
                    handler,
                    nr,
                    entry.hook
                );
            }
            for &nr in entry.absent {
                assert!(
                    !entry.wired.contains(&nr),
                    "{} lists syscall {} as wired and absent",
                    entry.hook,
                    nr
                );
                fence_absent(nr, entry.hook);
            }
        }

        // The boot self-test itself must also hold on the corrected lists.
        run_pledge_dispatch_parity_self_test();
    }
}

/// M0-6: rlimit data-model + validator self-test (pure).
pub fn run_rlimit_self_test() {
    use crate::process::{default_rlimits, RLimit, RLIMIT_NOFILE, RLIMIT_STACK, RLIM_INFINITY};
    let d = default_rlimits();
    assert_eq!(d[RLIMIT_NOFILE].rlim_cur, crate::process::MAX_FD as u64);
    assert_eq!(d[0].rlim_cur, RLIM_INFINITY); // CPU index = infinity
                                              // M0-7: STACK soft limit reports the ACTUAL writable stack = reserved window minus
                                              // the permanently-unmapped low guard page (must NOT overstate the mapped extent).
    assert_eq!(
        d[RLIMIT_STACK].rlim_cur,
        (crate::elf_loader::USER_STACK_SIZE - crate::elf_loader::USER_STACK_GUARD_SIZE) as u64
    );
    // R172-X-F2: pin the limit to the single-sourced geometry helper so this test and the
    // stack-window geometry test agree (a guard-size change moves both together).
    assert_eq!(
        d[RLIMIT_STACK].rlim_cur,
        crate::elf_loader::USER_STACK_TOP - crate::elf_loader::user_stack_usable_floor()
    );
    assert_eq!(d[RLIMIT_STACK].rlim_max, RLIM_INFINITY);
    let old = RLimit {
        rlim_cur: 100,
        rlim_max: 200,
    };
    assert!(validate_rlimit_change(
        old,
        RLimit {
            rlim_cur: 10,
            rlim_max: 5
        },
        false
    )
    .is_err()); // cur>max
    assert!(validate_rlimit_change(
        old,
        RLimit {
            rlim_cur: 100,
            rlim_max: 300
        },
        false
    )
    .is_err()); // raise w/o root
    assert!(validate_rlimit_change(
        old,
        RLimit {
            rlim_cur: 100,
            rlim_max: 300
        },
        true
    )
    .is_ok()); // raise w/ root
    assert!(validate_rlimit_change(
        old,
        RLimit {
            rlim_cur: 50,
            rlim_max: 150
        },
        false
    )
    .is_ok()); // lower
}

// ============================================================================
// Syscall Statistics
// ============================================================================

/// 系统调用统计
pub struct SyscallStats {
    pub total_calls: u64,
    pub exit_calls: u64,
    pub fork_calls: u64,
    pub read_calls: u64,
    pub write_calls: u64,
    pub failed_calls: u64,
}

impl SyscallStats {
    pub fn new() -> Self {
        SyscallStats {
            total_calls: 0,
            exit_calls: 0,
            fork_calls: 0,
            read_calls: 0,
            write_calls: 0,
            failed_calls: 0,
        }
    }

    pub fn print(&self) {
        klog!(Info, "=== Syscall Statistics ===");
        klog!(Info, "Total calls:  {}", self.total_calls);
        klog!(Info, "Exit calls:   {}", self.exit_calls);
        klog!(Info, "Fork calls:   {}", self.fork_calls);
        klog!(Info, "Read calls:   {}", self.read_calls);
        klog!(Info, "Write calls:  {}", self.write_calls);
        klog!(Info, "Failed calls: {}", self.failed_calls);
    }
}
