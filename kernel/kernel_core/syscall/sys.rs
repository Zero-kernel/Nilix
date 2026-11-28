//! Syscall family module: `sys` (split from monolithic `syscall.rs`, N2.0a).

use super::*;

// ============================================================================
// M0-6: POSIX resource limits (getrlimit/setrlimit/prlimit64)
// ============================================================================

/// M0-6: validate a proposed rlimit change (pure, unit-testable).
/// `cur > max` => EINVAL; RAISING the hard limit requires host-root (Linux
/// CAP_SYS_RESOURCE). All limits are ADVISORY (stored+reported, not enforced).
pub(super) fn validate_rlimit_change(
    old: crate::process::RLimit,
    nv: crate::process::RLimit,
    is_host_root: bool,
) -> Result<crate::process::RLimit, SyscallError> {
    if nv.rlim_cur > nv.rlim_max {
        return Err(SyscallError::EINVAL);
    }
    if nv.rlim_max > old.rlim_max && !is_host_root {
        return Err(SyscallError::EPERM);
    }
    Ok(nv)
}

/// getrlimit(resource, *rlimit) — read the current task's limit.
pub(super) fn sys_getrlimit(resource: u32, rlim_ptr: *mut u8) -> SyscallResult {
    if resource as usize >= crate::process::RLIMIT_NLIMITS {
        return Err(SyscallError::EINVAL);
    }
    if rlim_ptr.is_null() {
        return Err(SyscallError::EFAULT);
    }
    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let p = get_process(pid).ok_or(SyscallError::ESRCH)?;
    let rl = { p.lock().rlimits[resource as usize] };
    let mut buf = [0u8; 16];
    buf[0..8].copy_from_slice(&rl.rlim_cur.to_le_bytes());
    buf[8..16].copy_from_slice(&rl.rlim_max.to_le_bytes());
    copy_to_user(rlim_ptr, &buf)?;
    Ok(0)
}

/// setrlimit(resource, *rlimit) — self-only; routes through prlimit64.
pub(super) fn sys_setrlimit(resource: u32, rlim_ptr: *const u8) -> SyscallResult {
    sys_prlimit64(0, resource, rlim_ptr, core::ptr::null_mut())
}

/// prlimit64(pid, resource, *new, *old) — the modern interface musl/glibc route
/// get/setrlimit through. SELF-ONLY (never locks a foreign PCB).
pub(super) fn sys_prlimit64(
    pid: ProcessId,
    resource: u32,
    new_ptr: *const u8,
    old_ptr: *mut u8,
) -> SyscallResult {
    if resource as usize >= crate::process::RLIMIT_NLIMITS {
        return Err(SyscallError::EINVAL);
    }
    let self_pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let self_proc = get_process(self_pid).ok_or(SyscallError::ESRCH)?;

    // SELF-ONLY: accept pid==0 (self) or pid == the caller's NAMESPACE-visible pid
    // (what getpid() returns — Codex Fix: raw current_pid() would wrongly EPERM a
    // legitimate prlimit64(getpid(), ...)). A foreign pid => EPERM; never lock another PCB.
    if pid != 0 {
        let ns_pid = {
            let proc = self_proc.lock();
            crate::pid_namespace::pid_in_owning_namespace(&proc.pid_ns_chain)
                .ok_or(SyscallError::EFAULT)?
        };
        if pid != ns_pid {
            return Err(SyscallError::EPERM);
        }
    }

    // Pre-validate the OLD-out destination up front: a genuine mapped+writable
    // preflight (validate_user_ptr_mut is bounds-only; verify_user_memory(.., true)
    // is the real check, mirroring sys_pipe/sys_clone) so the install runs only
    // after the destination is known-writable. This minimizes the Linux-like
    // post-install copy-out EFAULT window (it cannot fully eliminate it — Linux has
    // the same install-then-copyout window — but it is now a real preflight).
    if !old_ptr.is_null() {
        validate_user_ptr_mut(old_ptr, 16)?;
        verify_user_memory(old_ptr as *const u8, 16, true)?;
    }

    // Read NEW before the lock (copy_from_user can fault — BEFORE any mutation).
    let nv = if !new_ptr.is_null() {
        let mut b = [0u8; 16];
        copy_from_user(&mut b, new_ptr)?;
        let mut cur = [0u8; 8];
        cur.copy_from_slice(&b[0..8]);
        let mut max = [0u8; 8];
        max.copy_from_slice(&b[8..16]);
        Some(crate::process::RLimit {
            rlim_cur: u64::from_le_bytes(cur),
            rlim_max: u64::from_le_bytes(max),
        })
    } else {
        None
    };

    // Codex Fix: snapshot privilege BEFORE the PCB lock — current_is_host_root()
    // re-locks PROCESS_TABLE + the Process, so calling it under the lock deadlocks.
    let is_root = crate::process::current_is_host_root();

    let idx = resource as usize;
    let old = {
        let mut proc = self_proc.lock();
        let old = proc.rlimits[idx];
        if let Some(n) = nv {
            let stored = validate_rlimit_change(old, n, is_root)?;
            proc.rlimits[idx] = stored;
        }
        old
    };

    if !old_ptr.is_null() {
        let mut buf = [0u8; 16];
        buf[0..8].copy_from_slice(&old.rlim_cur.to_le_bytes());
        buf[8..16].copy_from_slice(&old.rlim_max.to_le_bytes());
        copy_to_user(old_ptr, &buf)?;
    }
    Ok(0)
}

// ============================================================================
// 其他系统调用
// ============================================================================

/// U10-3: a voluntary process-context yield in a kernel retry/wait loop is
/// also a safe deferred-work progress point, and MUST force a reschedule even
/// when `need_resched` is clear. IRQ-return scheduling remains deliberately
/// nonblocking.
#[inline]
pub(super) fn yield_with_deferred_work() {
    if crate::scheduler_hook::process_deferred_work_ready() {
        crate::scheduler_hook::drain_and_force_reschedule();
    } else {
        crate::force_reschedule();
    }
}

/// sys_yield - 主动让出CPU
pub(super) fn sys_yield() -> SyscallResult {
    // The combined U10-3 deferred-work drain and `ReschedOrigin::VoluntaryYield`
    // dispatch run once in `finish_syscall_tail()` right before returning to
    // user mode. This avoids pre-locking `PROCESS_TABLE` + PCB to flip
    // `Running -> Ready` (`prepare_switch()` already marks `old` Ready on an
    // actual switch) and eliminates the duplicate drain/reschedule while still
    // guaranteeing deferred work drains before any context switch away.
    Ok(0)
}

// ============================================================================
// CPU Affinity Syscalls (E.5 SMP Scheduler)
// ============================================================================

/// Debug macro for scheduler-related syscalls (defined early for use in functions below)
macro_rules! sched_affinity_debug {
    ($($arg:tt)*) => {
        #[cfg(feature = "sched_debug")]
        {
            kprintln!($($arg)*);
        }
    };
}

/// Check whether the calling task may SET another task's CPU affinity.
///
/// Per Linux semantics, sched_setaffinity requires:
/// - Target is self (always allowed)
/// - OR caller has CAP_SYS_NICE (using ADMIN as closest equivalent)
/// - OR caller is root (euid == 0)
///
/// # Returns
/// - Ok(true) if allowed
/// - Ok(false) if not allowed (caller should return EPERM)
/// - Err if process lookup fails
#[inline]
pub(super) fn can_set_affinity(target_pid: ProcessId) -> Result<bool, SyscallError> {
    let caller = current_pid().ok_or(SyscallError::ESRCH)?;
    if caller == target_pid {
        return Ok(true);
    }

    // Check for CAP_SYS_NICE (using ADMIN capability as closest match)
    let has_cap = current_has_cap_rights(cap::CapRights::ADMIN);
    if has_cap {
        return Ok(true);
    }

    // R134-4 FIX: Use host-mapped root check instead of namespace euid==0.
    // Namespace root must not be able to modify CPU affinity of host processes.
    if crate::current_is_host_root() {
        return Ok(true);
    }

    Ok(false)
}

/// Check whether the calling task may GET another task's CPU affinity.
///
/// Per Linux semantics, sched_getaffinity is permissive (no EPERM for
/// cross-UID reads). However, PID namespace isolation MUST be enforced:
/// a container process must not be able to probe host processes by global PID.
///
/// R141-4 FIX: Added PID namespace visibility check. Processes not visible
/// from the caller's namespace are treated as ESRCH.
#[inline]
pub(super) fn can_get_affinity(target_pid: ProcessId) -> Result<bool, SyscallError> {
    let target_arc = get_process(target_pid).ok_or(SyscallError::ESRCH)?;

    // R141-4 FIX: Enforce PID namespace visibility.
    let caller_pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let caller_ns = {
        let proc_arc = get_process(caller_pid).ok_or(SyscallError::ESRCH)?;
        let proc = proc_arc.lock();
        crate::pid_namespace::owning_namespace(&proc.pid_ns_chain)
    };
    if let Some(ns) = caller_ns {
        let visible = {
            let proc = target_arc.lock();
            crate::pid_namespace::is_visible_in_namespace(&ns, &proc.pid_ns_chain)
        };
        if !visible {
            return Err(SyscallError::ESRCH);
        }
    }

    Ok(true)
}

/// Get the authoritative mask of usable online CPUs.
///
/// This returns a bitmask where bit N is set if CPU N is available.
/// Used for normalizing affinity masks and for returning "all CPUs"
/// when allowed_cpus == 0.
#[inline]
pub(super) fn usable_cpu_mask() -> u64 {
    // RF178-24: capacity is not topology. Returning capacity bits allowed
    // affinity to target registered-but-offline CPUs and misrepresented holes.
    cpu_local::online_cpu_mask()
}

/// Normalize affinity mask: mask off offline CPU IDs and reject empty masks.
///
/// # Returns
/// - Ok(mask) - Normalized mask with only valid CPU bits set
/// - Err(EINVAL) - If the normalized mask is empty (no valid CPUs)
#[inline]
pub(super) fn normalize_affinity_mask(mask: u64) -> Result<u64, SyscallError> {
    let normalized = mask & usable_cpu_mask();
    if normalized == 0 {
        return Err(SyscallError::EINVAL);
    }
    Ok(normalized)
}

/// sys_sched_setaffinity - Set CPU affinity mask for a process
///
/// # Arguments
/// * `pid` - Target process ID (0 = calling process)
/// * `cpusetsize` - Size of the CPU mask in bytes (must be >= 8)
/// * `mask` - User pointer to the affinity mask (u64 bitmask, bit N = CPU N)
///
/// # Returns
/// * `Ok(0)` - Success
/// * `Err(ESRCH)` - No process with the given PID
/// * `Err(EPERM)` - Caller lacks permission to modify target's affinity
/// * `Err(EINVAL)` - Invalid cpusetsize or empty mask after normalization
/// * `Err(EFAULT)` - Invalid user pointer
///
/// # E.5 Implementation Notes
/// If the target process is currently running on a CPU not in the new mask,
/// a reschedule is triggered to migrate it to an allowed CPU.
pub(super) fn sys_sched_setaffinity(pid: i32, cpusetsize: usize, mask: *const u8) -> SyscallResult {
    use core::mem::size_of;

    // Validate parameters
    if mask.is_null() {
        return Err(SyscallError::EFAULT);
    }
    if cpusetsize < size_of::<u64>() {
        return Err(SyscallError::EINVAL);
    }

    // R141-4 FIX: Resolve target PID through namespace translation.
    // The user-provided pid is namespace-local; translate to global.
    let caller_pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let target_pid = if pid == 0 {
        caller_pid
    } else {
        let caller_ns = {
            let proc_arc = get_process(caller_pid).ok_or(SyscallError::ESRCH)?;
            let proc = proc_arc.lock();
            crate::pid_namespace::owning_namespace(&proc.pid_ns_chain)
        };
        if let Some(ns) = caller_ns {
            crate::pid_namespace::resolve_pid_in_namespace(&ns, pid as ProcessId)
                .ok_or(SyscallError::ESRCH)?
        } else {
            pid as ProcessId
        }
    };

    // Permission check (uses can_set_affinity which requires privilege for other processes)
    if !can_set_affinity(target_pid)? {
        return Err(SyscallError::EPERM);
    }

    // Copy mask from userspace
    // P1-6 FIX: Removed redundant outer UserAccessGuard — copy_from_user_safe
    // creates its own guard internally.
    let mut mask_bytes = [0u8; 8];
    crate::usercopy::copy_from_user_safe(&mut mask_bytes, mask)
        .map_err(|_| SyscallError::EFAULT)?;
    let new_mask = normalize_affinity_mask(u64::from_ne_bytes(mask_bytes))?;

    // Update PCB and get info needed for reschedule decision
    let proc_arc = get_process(target_pid).ok_or(SyscallError::ESRCH)?;
    let mut proc = proc_arc.lock();
    let old_mask = proc.allowed_cpus;
    proc.allowed_cpus = new_mask;
    if old_mask != new_mask {
        // C3 (#90): a CPU that the old mask excluded has ruled this task out
        // and may now have to steal it. Publish under the PCB lock, after
        // the mask is written.
        crate::process::note_publication(target_pid);
    }
    let is_on_cpu = proc.on_cpu.load(core::sync::atomic::Ordering::Acquire);
    drop(proc);

    // If the caller changed its own affinity and current CPU is now disallowed,
    // trigger immediate reschedule so this CPU switches off (handing off to
    // idle if no local peer exists) and pushes the task to an allowed CPU.
    if target_pid == caller_pid && is_on_cpu {
        let cpu_id = current_cpu_id();
        // new_mask is never 0 here (normalize_affinity_mask rejects it)
        let cpu_still_allowed = cpu_id < 64 && (new_mask & (1u64 << cpu_id)) != 0;
        if !cpu_still_allowed {
            current_cpu().set_need_resched();
        }
    } else if target_pid != caller_pid && old_mask != new_mask {
        // GAP-6: another task may be running, or queued, on a CPU it may no
        // longer use. Kick every CPU so that CPU re-selects now (its pick skips
        // the disallowed task) and an allowed CPU steals it, rather than both
        // waiting for the next tick. Only a privileged caller reaches here.
        let _ = crate::signal::kernel_kick_reschedule();
    }

    // Log if mask changed (for debugging)
    if old_mask != new_mask {
        sched_affinity_debug!(
            "[AFFINITY] pid={} mask changed: 0x{:016x} -> 0x{:016x}",
            target_pid,
            old_mask,
            new_mask
        );
    }

    Ok(0)
}

/// sys_sched_getaffinity - Get CPU affinity mask for a process
///
/// # Arguments
/// * `pid` - Target process ID (0 = calling process)
/// * `cpusetsize` - Size of the CPU mask buffer in bytes (must be >= 8)
/// * `mask` - User pointer to receive the affinity mask
///
/// # Returns
/// * `Ok(8)` - Success, returns number of bytes written
/// * `Err(ESRCH)` - No process with the given PID
/// * `Err(EINVAL)` - Invalid cpusetsize
/// * `Err(EFAULT)` - Invalid user pointer
///
/// # Notes
/// - If allowed_cpus == 0 in the PCB, this means "no restriction" (all CPUs).
///   In that case, we return a mask with all usable CPUs set.
/// - The returned mask is always normalized to the system's CPU count.
/// - Linux is permissive about reading affinity (no EPERM for other processes).
pub(super) fn sys_sched_getaffinity(pid: i32, cpusetsize: usize, mask: *mut u8) -> SyscallResult {
    use core::mem::size_of;

    // Validate parameters
    if mask.is_null() {
        return Err(SyscallError::EFAULT);
    }
    if cpusetsize < size_of::<u64>() {
        return Err(SyscallError::EINVAL);
    }

    // R141-4 FIX: Resolve target PID through namespace translation.
    let caller_pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let target_pid = if pid == 0 {
        caller_pid
    } else {
        let caller_ns = {
            let proc_arc = get_process(caller_pid).ok_or(SyscallError::ESRCH)?;
            let proc = proc_arc.lock();
            crate::pid_namespace::owning_namespace(&proc.pid_ns_chain)
        };
        if let Some(ns) = caller_ns {
            crate::pid_namespace::resolve_pid_in_namespace(&ns, pid as ProcessId)
                .ok_or(SyscallError::ESRCH)?
        } else {
            pid as ProcessId
        }
    };

    // Permission check (permissive - just verify process exists + namespace visibility)
    can_get_affinity(target_pid)?;

    // Get the affinity mask from PCB
    let proc_arc = get_process(target_pid).ok_or(SyscallError::ESRCH)?;
    let proc = proc_arc.lock();
    let mut affinity = proc.allowed_cpus;
    drop(proc);

    // Normalize the mask to the system's usable CPUs
    let usable = usable_cpu_mask();

    // If allowed_cpus == 0, it means "all CPUs allowed"
    // Return a mask with all usable CPUs set
    if affinity == 0 {
        affinity = usable;
    } else {
        // Normalize: mask off every currently offline CPU ID.
        affinity &= usable;
    }

    // Copy mask to userspace
    // P1-6 FIX: Removed redundant outer UserAccessGuard — copy_to_user_safe
    // creates its own guard internally.
    let mask_bytes = affinity.to_ne_bytes();
    crate::usercopy::copy_to_user_safe(mask, &mask_bytes).map_err(|_| SyscallError::EFAULT)?;

    // Return number of bytes written (Linux returns the cpumask size)
    Ok(size_of::<u64>())
}

/// sys_getrandom - 获取随机字节
///
/// 为 musl libc 提供随机数生成支持。
/// 使用 RDRAND 指令（如果 CPU 支持）混合时间戳生成随机数。
///
/// # Arguments
/// * `buf` - 用户空间缓冲区指针
/// * `len` - 请求的字节数
/// * `flags` - 标志位 (GRND_NONBLOCK=0x1, GRND_RANDOM=0x2)
///
/// # Returns
/// 成功返回写入的字节数，失败返回错误码
pub(super) fn sys_getrandom(buf: *mut u8, len: usize, flags: u32) -> SyscallResult {
    /// GRND_NONBLOCK - 非阻塞模式
    const GRND_NONBLOCK: u32 = 0x1;
    /// GRND_RANDOM - 使用 /dev/random 语义（当前忽略）
    const GRND_RANDOM: u32 = 0x2;

    // 验证 flags 有效性
    if flags & !(GRND_NONBLOCK | GRND_RANDOM) != 0 {
        return Err(SyscallError::EINVAL);
    }

    // 处理边界情况
    let count = match len {
        0 => return Ok(0),
        c if c > MAX_RW_SIZE => return Err(SyscallError::E2BIG),
        c => c,
    };

    // R163-I1 FIX: Removed redundant validate_user_ptr_mut — verify_user_memory
    // already calls validate_user_ptr internally.
    verify_user_memory(buf as *const u8, count, true)?;

    // R40-1 FIX: 使用 CSPRNG (ChaCha20) 生成随机数据
    //
    // 之前的实现使用时间戳混合 RDRAND，在启动早期可能是可预测的。
    // 现在使用 security::rng 模块的 ChaCha20 CSPRNG，它：
    // - 由 RDRAND/RDSEED 播种
    // - 定期重新播种
    // - 提供密码学安全的随机数
    // R180-10 defense in depth: getrandom shares the 1 MiB syscall staging
    // contract, so concurrent requests must participate in aggregate admission.
    let mut tmp = try_admitted_zeroed_io_buffer(count)?;
    match rng::fill_random(&mut tmp) {
        Ok(()) => {}
        // R140-6 FIX: FIPS state failed/corrupted — deny all crypto.
        Err(rng::RngError::FipsBlocked) => return Err(SyscallError::EPERM),
        Err(rng::RngError::NotInitialized) => {
            // 懒初始化 CSPRNG；非阻塞模式遵循 Linux 语义返回 EAGAIN
            if flags & GRND_NONBLOCK != 0 {
                return Err(SyscallError::EAGAIN);
            }
            // 尝试初始化 CSPRNG
            rng::init_global().map_err(|_| SyscallError::EAGAIN)?;
            rng::fill_random(&mut tmp).map_err(|_| SyscallError::EIO)?
        }
        Err(_) if flags & GRND_NONBLOCK != 0 => return Err(SyscallError::EAGAIN),
        Err(_) => return Err(SyscallError::EIO),
    }

    // 复制到用户空间
    copy_to_user(buf, &tmp)?;

    Ok(count)
}

// ============================================================================
// 系统信息系统调用
// ============================================================================

/// sys_uname - 获取系统信息
pub(super) fn sys_uname(buf: *mut UtsName) -> SyscallResult {
    #[cfg(feature = "kcov")]
    coverage::trace_pc(1300); // uname entry (including invalid output pointers)
    if buf.is_null() {
        #[cfg(feature = "kcov")]
        coverage::trace_pc(1301); // null destination rejection
        return Err(SyscallError::EFAULT);
    }

    fn fill_field(target: &mut [u8; 65], src: &str) {
        let bytes = src.as_bytes();
        let len = bytes.len().min(64);
        target[..len].copy_from_slice(&bytes[..len]);
        target[len] = 0;
    }

    let mut uts = UtsName::default();
    fill_field(&mut uts.sysname, "Zero-OS");
    fill_field(&mut uts.nodename, "zero-node");
    fill_field(&mut uts.release, "0.6.5");
    fill_field(&mut uts.version, "Security Foundation Phase A");
    fill_field(&mut uts.machine, "x86_64");
    // D2-ABI-STAT-LAYOUT: Linux default for an unset NIS domain name.
    fill_field(&mut uts.domainname, "(none)");

    // lint-repr-c-copy: allow (no-padding: UtsName {[u8;65]×6} = 390 bytes, alignment=1)
    let uts_bytes = unsafe {
        core::slice::from_raw_parts(
            &uts as *const UtsName as *const u8,
            core::mem::size_of::<UtsName>(),
        )
    };
    crate::usercopy::copy_to_user_safe(buf as *mut u8, uts_bytes)
        .map_err(|_| SyscallError::EFAULT)?;

    #[cfg(feature = "kcov")]
    coverage::trace_pc(1302); // complete UTS copyout

    Ok(0)
}

// ============================================================================
// G.3 Compliance Syscalls
// ============================================================================

/// Buffer for returning compliance status to userspace.
///
/// Must match the layout expected by userspace compliance tools.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ComplianceStatusBuf {
    /// Hardening profile: 0=Secure, 1=Balanced, 2=Performance
    pub profile: u8,
    /// Whether the profile is locked (cannot be changed until reboot)
    pub profile_locked: u8,
    /// FIPS state: 0=Disabled, 1=Enabled, 2=Failed
    pub fips_state: u8,
    /// Padding for alignment
    _padding: [u8; 5],
}

// H.0.1-3: Compile-time ABI size assertion (8 bytes, alignment 1, no implicit padding).
const _: [(); 8] = [(); core::mem::size_of::<ComplianceStatusBuf>()];

/// H.0.1-3: Copy ComplianceStatusBuf to userspace via a zeroed byte buffer.
/// All fields are u8 (alignment 1, no implicit gaps), but explicit _padding
/// is guaranteed zero by the zeroed buffer pattern for defense-in-depth.
#[inline]
pub(super) fn copy_compliance_status_to_user(
    user_dst: *mut ComplianceStatusBuf,
    status: &ComplianceStatusBuf,
) -> Result<(), SyscallError> {
    let mut buf = [0u8; mem::size_of::<ComplianceStatusBuf>()];
    buf[mem::offset_of!(ComplianceStatusBuf, profile)] = status.profile;
    buf[mem::offset_of!(ComplianceStatusBuf, profile_locked)] = status.profile_locked;
    buf[mem::offset_of!(ComplianceStatusBuf, fips_state)] = status.fips_state;
    // `_padding` intentionally left as zeroes in the buffer.
    copy_to_user(user_dst as *mut u8, &buf)
}

/// sys_compliance_status - Get current compliance status
///
/// # Arguments
/// * `buf` - Pointer to ComplianceStatusBuf in userspace
///
/// # Returns
/// * On success: 0
/// * On error: Negative errno (EFAULT if pointer invalid)
pub(super) fn sys_compliance_status(buf: *mut ComplianceStatusBuf) -> Result<usize, SyscallError> {
    // Validate user pointer
    if buf.is_null() {
        return Err(SyscallError::EFAULT);
    }
    let buf_addr = buf as usize;
    if buf_addr < crate::usercopy::MMAP_MIN_ADDR || buf_addr >= USER_SPACE_TOP {
        return Err(SyscallError::EFAULT);
    }

    // Get compliance status from the compliance module
    let status = compliance::status();

    let result = ComplianceStatusBuf {
        profile: status.profile as u8,
        profile_locked: if status.profile_locked { 1 } else { 0 },
        fips_state: status.fips_state as u8,
        _padding: [0; 5],
    };

    // H.0.1-3: Copy via zeroed byte buffer so padding bytes are guaranteed zero.
    copy_compliance_status_to_user(buf, &result)?;

    Ok(0)
}

/// sys_fips_enable - Enable FIPS mode (sticky until reboot)
///
/// Requires CAP_SYS_ADMIN capability. Once enabled, FIPS mode cannot be
/// disabled until the next reboot.
///
/// # Returns
/// * On success: 0
/// * On error: Negative errno
///   - EPERM: Not privileged (requires CAP_SYS_ADMIN)
///   - EALREADY: FIPS mode already enabled
///   - EIO: FIPS self-test failed
pub(super) fn sys_fips_enable() -> Result<usize, SyscallError> {
    // Check privilege: require root or CAP_ADMIN capability
    // R133-1 FIX: Use host-mapped root check for host-global FIPS gate.
    let _creds = crate::current_credentials().ok_or(SyscallError::ESRCH)?;
    if !crate::current_is_host_root() {
        // Check for CAP_ADMIN capability (system administration rights)
        if !current_has_cap_rights(cap::CapRights::ADMIN) {
            return Err(SyscallError::EPERM);
        }
    }

    // Attempt to enable FIPS mode
    match compliance::enable_fips_mode() {
        Ok(()) => Ok(0),
        Err(compliance::FipsError::AlreadyEnabled) => Err(SyscallError::EALREADY),
        Err(compliance::FipsError::EnableFailed) => Err(SyscallError::EIO), // R93-1 FIX
        Err(compliance::FipsError::SelfTestFailed) => Err(SyscallError::EIO),
        Err(compliance::FipsError::Busy) => Err(SyscallError::EBUSY),
        Err(_) => Err(SyscallError::EPERM),
    }
}

/// sys_compliance_query_algo - Check if a cryptographic algorithm is permitted
///
/// # Arguments
/// * `algo_id` - Algorithm identifier (matches compliance::CryptoAlgorithm repr)
///
/// # Returns
/// * 1: Algorithm is permitted under current policy
/// * 0: Algorithm is not permitted (blocked by FIPS)
/// * Negative errno on error
pub(super) fn sys_compliance_query_algo(algo_id: u32) -> Result<usize, SyscallError> {
    // Convert algo_id to CryptoAlgorithm
    let algo = match algo_id {
        0 => compliance::CryptoAlgorithm::Sha256,
        1 => compliance::CryptoAlgorithm::Sha384,
        2 => compliance::CryptoAlgorithm::Sha512,
        3 => compliance::CryptoAlgorithm::Blake2b,
        4 => compliance::CryptoAlgorithm::HmacSha256,
        5 => compliance::CryptoAlgorithm::EcdsaP256,
        6 => compliance::CryptoAlgorithm::EcdsaP384,
        7 => compliance::CryptoAlgorithm::Ed25519,
        8 => compliance::CryptoAlgorithm::Aes128Gcm,
        9 => compliance::CryptoAlgorithm::Aes256Gcm,
        10 => compliance::CryptoAlgorithm::ChaCha20,
        11 => compliance::CryptoAlgorithm::ChaCha20Poly1305,
        _ => return Err(SyscallError::EINVAL),
    };

    if compliance::is_algorithm_permitted(algo) {
        Ok(1)
    } else {
        Ok(0)
    }
}

// ============================================================================
// Audit Export — G.fin.2 (cursor-based, non-draining)
// ============================================================================

/// Token-bucket rate limiter for `sys_audit_export`.
///
/// Prevents audit export from becoming a DoS vector: each exported event
/// consumes one token. Tokens refill at a fixed rate per timer tick.
///
/// - Capacity (burst): 1000 records
/// - Refill: 10 records per tick
pub(super) struct AuditExportTokenBucket {
    tokens: u64,
    last_tick: u64,
}

impl AuditExportTokenBucket {
    const CAPACITY: u64 = 1000;
    const REFILL_PER_TICK: u64 = 10;

    const fn new() -> Self {
        Self {
            tokens: Self::CAPACITY,
            last_tick: 0,
        }
    }

    fn refill(&mut self, now_tick: u64) {
        if self.last_tick == 0 {
            self.last_tick = now_tick;
            return;
        }
        // Monotonic time expected; if time goes backwards, skip refill (fail-closed).
        if now_tick <= self.last_tick {
            self.last_tick = now_tick;
            return;
        }
        let elapsed = now_tick - self.last_tick;
        let added = elapsed.saturating_mul(Self::REFILL_PER_TICK);
        self.tokens = core::cmp::min(Self::CAPACITY, self.tokens.saturating_add(added));
        self.last_tick = now_tick;
    }

    fn take(&mut self, now_tick: u64, want: u64) -> u64 {
        self.refill(now_tick);
        let grant = core::cmp::min(self.tokens, want);
        self.tokens -= grant;
        grant
    }

    fn refund(&mut self, n: u64) {
        self.tokens = core::cmp::min(Self::CAPACITY, self.tokens.saturating_add(n));
    }
}

pub(super) static AUDIT_EXPORT_LIMITER: spin::Mutex<AuditExportTokenBucket> =
    spin::Mutex::new(AuditExportTokenBucket::new());

/// sys_audit_export — Export audit events to userspace buffer (cursor-based, non-draining)
///
/// Requires CAP_AUDIT_READ capability or root privilege.
///
/// # Arguments
/// * `buf`        — Pointer to destination buffer in userspace
/// * `buf_len`    — Size of the buffer in bytes
/// * `cursor`     — Starting event ID (inclusive); pass 0 to start from the oldest
/// * `max_events` — Maximum number of records to export
///
/// # ABI
///
/// The buffer is filled with:
/// - [`audit::AuditExportHeader`] (96 bytes): magic `"ZAUD"`, version 3, record_count, next cursor,
///   tail_hash, dropped_since_cursor, ring_usage, backpressure_high_water_bps, batch_first_prev_hash
/// - [`audit::AuditExportRecord`] array (128 bytes each): fixed-size per-event records
///
/// The header's `cursor` field is the next cursor to use (`last_id + 1`).
///
/// # Returns
/// * On success: number of events exported (≥ 0)
/// * On error: Negative errno
///   - EPERM: Not privileged
///   - EFAULT: Invalid pointer
///   - ENOSPC: Buffer too small for header + ≥1 record
///   - EINVAL: `max_events == 0`
///   - EAGAIN: Rate limited
pub(super) fn sys_audit_export(
    buf: *mut u8,
    buf_len: usize,
    cursor: u64,
    max_events: usize,
) -> Result<usize, SyscallError> {
    use crate::usercopy::copy_to_user_safe;

    // Check privilege: require root or CAP_AUDIT_READ.
    // R133-1 FIX: Use host-mapped root check for host-global audit gate.
    let creds = crate::current_credentials().ok_or(SyscallError::ESRCH)?;
    let caller_is_root = crate::current_is_host_root();
    if !caller_is_root {
        if !current_has_cap_rights(cap::CapRights::AUDIT_READ) {
            return Err(SyscallError::EPERM);
        }
    }

    if buf.is_null() {
        return Err(SyscallError::EFAULT);
    }
    if max_events == 0 {
        return Err(SyscallError::EINVAL);
    }

    let buf_addr = buf as usize;
    // R107-6 FIX: Validate both buffer start AND end against user-space boundaries.
    // Without end-of-buffer check, a malicious caller could pass buf near USER_SPACE_TOP
    // with a large buf_len, causing wrapping_add to produce kernel-space addresses.
    if buf_addr < crate::usercopy::MMAP_MIN_ADDR || buf_addr >= USER_SPACE_TOP {
        return Err(SyscallError::EFAULT);
    }
    if buf_len > USER_SPACE_TOP - buf_addr {
        return Err(SyscallError::EFAULT);
    }

    const HEADER_SIZE: usize = audit::AuditExportHeader::SIZE;
    const RECORD_SIZE: usize = audit::AuditExportRecord::SIZE;

    // Require space for at least the header + one record.
    if buf_len < HEADER_SIZE + RECORD_SIZE {
        return Err(SyscallError::ENOSPC);
    }

    // How many records physically fit in the buffer?
    let max_fit = (buf_len - HEADER_SIZE) / RECORD_SIZE;
    let requested = core::cmp::min(max_events, core::cmp::min(max_fit, u16::MAX as usize));
    if requested == 0 {
        return Err(SyscallError::ENOSPC);
    }

    // Token-bucket rate limiting: reserve up to `requested` event exports.
    let now_tick = crate::time::get_ticks();
    let reserved = {
        let mut limiter = AUDIT_EXPORT_LIMITER.lock();
        limiter.take(now_tick, requested as u64)
    };
    if reserved == 0 {
        return Err(SyscallError::EAGAIN);
    }

    // Perform the non-draining export.
    let batch = match audit::export(cursor, reserved as usize) {
        Ok(b) => b,
        Err(audit::AuditError::AccessDenied) => {
            AUDIT_EXPORT_LIMITER.lock().refund(reserved);
            return Err(SyscallError::EPERM);
        }
        Err(audit::AuditError::Uninitialized) => {
            AUDIT_EXPORT_LIMITER.lock().refund(reserved);
            return Err(SyscallError::ENOSYS);
        }
        Err(_) => {
            AUDIT_EXPORT_LIMITER.lock().refund(reserved);
            return Err(SyscallError::EIO);
        }
    };

    let exported = batch.events.len();
    let record_count = core::cmp::min(exported, u16::MAX as usize) as u16;

    // Write header.
    let header = audit::AuditExportHeader::new(
        record_count,
        batch.next_cursor,
        batch.tail_hash,
        batch.ring_usage,
        batch.dropped_since_cursor,
        batch.batch_first_prev_hash,
    );
    let header_bytes = header.to_bytes();
    if copy_to_user_safe(buf, &header_bytes).is_err() {
        AUDIT_EXPORT_LIMITER.lock().refund(reserved);
        return Err(SyscallError::EFAULT);
    }

    // Write records. Non-root callers get redacted syscall args.
    let redact_syscall_args = !caller_is_root;
    for (i, event) in batch.events.iter().enumerate() {
        let record = audit::AuditExportRecord::from_event(event, redact_syscall_args);
        let record_bytes = record.to_bytes();

        let offset = HEADER_SIZE + i * RECORD_SIZE;
        // R107-6 FIX: Use checked_add for defense-in-depth. The upfront buf_len boundary
        // check guarantees this cannot overflow, but checked_add makes the intent explicit.
        let dst_addr = match (buf as usize).checked_add(offset) {
            Some(addr) => addr,
            None => {
                AUDIT_EXPORT_LIMITER.lock().refund(reserved);
                return Err(SyscallError::EFAULT);
            }
        };
        let dst = dst_addr as *mut u8;
        if copy_to_user_safe(dst, &record_bytes).is_err() {
            AUDIT_EXPORT_LIMITER.lock().refund(reserved);
            return Err(SyscallError::EFAULT);
        }
    }

    // Refund any unused tokens (reserved > exported if ring had fewer events).
    let unused = reserved.saturating_sub(exported as u64);
    if unused > 0 {
        AUDIT_EXPORT_LIMITER.lock().refund(unused);
    }

    Ok(exported)
}

// ============================================================================
// G.2 Live Patching syscalls (509-511)
// ============================================================================

/// sys_kpatch_load (509): Load a patch image from userspace.
///
/// Arguments:
/// - user_ptr: Pointer to patch image buffer in userspace
/// - len: Length of patch image in bytes
///
/// Returns:
/// - Positive patch_id on success (as usize)
/// - Negative errno on failure (EPERM, EFAULT, E2BIG, EINVAL, EACCES, etc.)
pub(super) fn sys_kpatch_load(user_ptr: usize, len: usize) -> Result<usize, SyscallError> {
    // Delegate to livepatch crate which handles privilege check via KernelOps
    let result = livepatch::sys_kpatch_load(user_ptr, len);
    if result < 0 {
        // Convert livepatch errno to SyscallError
        match result {
            -1 => Err(SyscallError::EPERM),
            -2 => Err(SyscallError::ENOENT),
            -7 => Err(SyscallError::E2BIG),
            -12 => Err(SyscallError::ENOMEM),
            -13 => Err(SyscallError::EACCES),
            -14 => Err(SyscallError::EFAULT),
            -16 => Err(SyscallError::EBUSY),
            -17 => Err(SyscallError::EEXIST),
            -22 => Err(SyscallError::EINVAL),
            -38 => Err(SyscallError::ENOSYS),
            _ => Err(SyscallError::EINVAL),
        }
    } else {
        Ok(result as usize)
    }
}

/// sys_kpatch_enable (510): Enable a previously loaded patch.
///
/// Arguments:
/// - patch_id: Patch identifier returned by sys_kpatch_load
///
/// Returns:
/// - 0 on success
/// - Negative errno on failure
pub(super) fn sys_kpatch_enable(patch_id: u64) -> Result<usize, SyscallError> {
    let result = livepatch::sys_kpatch_enable(patch_id);
    if result < 0 {
        match result {
            -1 => Err(SyscallError::EPERM),
            -2 => Err(SyscallError::ENOENT),
            -16 => Err(SyscallError::EBUSY),
            -22 => Err(SyscallError::EINVAL),
            -38 => Err(SyscallError::ENOSYS),
            _ => Err(SyscallError::EINVAL),
        }
    } else {
        Ok(0)
    }
}

/// sys_kpatch_disable (511): Disable (rollback) a previously enabled patch.
///
/// Arguments:
/// - patch_id: Patch identifier returned by sys_kpatch_load
///
/// Returns:
/// - 0 on success
/// - Negative errno on failure
pub(super) fn sys_kpatch_disable(patch_id: u64) -> Result<usize, SyscallError> {
    let result = livepatch::sys_kpatch_disable(patch_id);
    if result < 0 {
        match result {
            -1 => Err(SyscallError::EPERM),
            -2 => Err(SyscallError::ENOENT),
            -16 => Err(SyscallError::EBUSY),
            -22 => Err(SyscallError::EINVAL),
            -38 => Err(SyscallError::ENOSYS),
            _ => Err(SyscallError::EINVAL),
        }
    } else {
        Ok(0)
    }
}

/// sys_kpatch_unload — Unload a disabled livepatch module and free its memory.
///
/// R104-5 FIX: This wrapper was missing from the syscall layer, leaving
/// syscall 512 dispatching to the default ENOSYS path.
///
/// # Arguments
/// * `patch_id` - The patch identifier returned by `sys_kpatch_load`.
///
/// # Errors
/// - `EPERM`   — caller lacks privileges
/// - `ENOENT`  — no patch with the given id
/// - `EBUSY`   — patch is still enabled
/// - `EINVAL`  — invalid patch_id or internal error
/// - `ENOSYS`  — livepatch subsystem not available
pub(super) fn sys_kpatch_unload(patch_id: u64) -> Result<usize, SyscallError> {
    let result = livepatch::sys_kpatch_unload(patch_id);
    if result < 0 {
        match result {
            -1 => Err(SyscallError::EPERM),
            -2 => Err(SyscallError::ENOENT),
            -16 => Err(SyscallError::EBUSY),
            -22 => Err(SyscallError::EINVAL),
            -38 => Err(SyscallError::ENOSYS),
            _ => Err(SyscallError::EINVAL),
        }
    } else {
        Ok(0)
    }
}

/// P1-4: sys_kpatch_enable_all (514) — Enable all loaded patches in topological
/// dependency order.
///
/// Patches already in `Enabled` state are skipped. On failure, all patches
/// enabled by this batch are rolled back (disabled) in reverse order.
///
/// # Arguments
///
/// Takes no arguments (operates on all loaded patches).
///
/// # Errors
///
/// - `EPERM`   — caller lacks privileges
/// - `ENOENT`  — a dependency UID is not loaded, or a patch disappeared
/// - `EBUSY`   — a patch is in a transitional state
/// - `EINVAL`  — dependency cycle detected
/// - `ENOSYS`  — livepatch subsystem not available
pub(super) fn sys_kpatch_enable_all() -> Result<usize, SyscallError> {
    let result = livepatch::sys_kpatch_enable_all();
    if result < 0 {
        match result {
            -1 => Err(SyscallError::EPERM),
            -2 => Err(SyscallError::ENOENT),
            -16 => Err(SyscallError::EBUSY),
            -22 => Err(SyscallError::EINVAL),
            -38 => Err(SyscallError::ENOSYS),
            _ => Err(SyscallError::EINVAL),
        }
    } else {
        Ok(0)
    }
}

/// P1-4: sys_kpatch_disable_all (515) — Disable all enabled patches in reverse
/// topological dependency order.
///
/// Patches not in `Enabled` state are skipped. On failure, all patches
/// disabled by this batch are re-enabled in reverse order.
///
/// # Arguments
///
/// Takes no arguments (operates on all enabled patches).
///
/// # Errors
///
/// - `EPERM`   — caller lacks privileges
/// - `ENOENT`  — a patch disappeared during iteration
/// - `EBUSY`   — a patch is in a transitional state
/// - `EINVAL`  — dependency cycle detected
/// - `ENOSYS`  — livepatch subsystem not available
pub(super) fn sys_kpatch_disable_all() -> Result<usize, SyscallError> {
    let result = livepatch::sys_kpatch_disable_all();
    if result < 0 {
        match result {
            -1 => Err(SyscallError::EPERM),
            -2 => Err(SyscallError::ENOENT),
            -16 => Err(SyscallError::EBUSY),
            -22 => Err(SyscallError::EINVAL),
            -38 => Err(SyscallError::ENOSYS),
            _ => Err(SyscallError::EINVAL),
        }
    } else {
        Ok(0)
    }
}

// ============================================================================
// KCOV (Kernel Code Coverage) Syscalls - Fuzzing Infrastructure
// ============================================================================

/// Return whether a caller may access the KCOV control and export surface.
///
/// KCOV exposes kernel control-flow observations and consumes a bounded kernel
/// allocation.  It is therefore a host-global debugging surface: namespace-root
/// credentials cannot authorize it.  The R187 authority-policy repair makes the
/// surface explicitly host-root-only until a reviewed, identity-bound grant
/// protocol exists.  Keeping the policy narrow is safer than treating an
/// unissuable capability bit as if it were a usable delegation mechanism.
#[cfg(feature = "kcov")]
#[inline]
pub(super) fn kcov_access_allowed(is_host_root: bool, _has_reserved_kcov_right: bool) -> bool {
    is_host_root
}

/// RF187-1 FIX: KCOV is deliberately host-root-only until a production
/// identity-bound issuance protocol is reviewed and implemented.  Every
/// operation, including state-only operations, shares this single fail-closed
/// gate so no direct or future caller can allocate, enable, reset, or export
/// coverage without host-global authority.
#[cfg(feature = "kcov")]
#[inline]
pub(super) fn require_kcov_access() -> Result<(), SyscallError> {
    if kcov_access_allowed(crate::current_is_host_root(), false) {
        Ok(())
    } else {
        Err(SyscallError::EPERM)
    }
}

/// Initialize KCOV for current task
///
/// Allocates a coverage buffer and prepares the task for coverage collection.
/// Must be called before sys_kcov_enable.
///
/// # Arguments
/// - `buf_size`: Size of coverage buffer in bytes (must be <= 4096)
///
/// # Returns
/// - Success: 0
/// - Error: EINVAL (invalid size), ENOMEM (allocation failed), EEXIST (already initialized)
#[cfg(feature = "kcov")]
pub(super) fn sys_kcov_init(buf_size: usize) -> Result<usize, SyscallError> {
    require_kcov_access()?;

    if buf_size == 0 || buf_size > coverage::KCOV_BUFFER_SIZE {
        return Err(SyscallError::EINVAL);
    }

    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let proc_arc = get_process(pid).ok_or(SyscallError::ESRCH)?;

    // Cheap duplicate precheck. Allocation remains outside the PCB lock.
    {
        let proc = proc_arc.lock();
        if proc.task_kcov_initialized() {
            return Err(SyscallError::EEXIST);
        }
    }

    let candidate = match crate::process::TaskKcovState::try_new(buf_size) {
        Ok(candidate) => candidate,
        Err(coverage::CoverageAllocError::InvalidSize) => return Err(SyscallError::EINVAL),
        Err(coverage::CoverageAllocError::AllocationFailed) => return Err(SyscallError::ENOMEM),
    };

    // Recheck under the PCB lock before the one-time publication. A rejected
    // candidate is returned to this scope and dropped only after unlocking.
    let installed = {
        let mut proc = proc_arc.lock();
        proc.install_task_kcov(candidate)
    };
    let token = match installed {
        Ok(token) => token,
        Err(rejected) => {
            drop(rejected);
            return Err(SyscallError::EEXIST);
        }
    };

    crate::process::publish_current_kcov_token(token);
    Ok(0)
}

#[cfg(not(feature = "kcov"))]
pub(super) fn sys_kcov_init(_buf_size: usize) -> Result<usize, SyscallError> {
    Err(SyscallError::ENOSYS)
}

/// Enable coverage collection for current task
#[cfg(feature = "kcov")]
pub(super) fn sys_kcov_enable() -> Result<usize, SyscallError> {
    require_kcov_access()?;

    crate::process::try_with_current_kcov(coverage::CoverageBuffer::enable)
        .map_err(kcov_access_error)?;
    Ok(0)
}

#[cfg(not(feature = "kcov"))]
pub(super) fn sys_kcov_enable() -> Result<usize, SyscallError> {
    Err(SyscallError::ENOSYS)
}

/// Disable coverage collection for current task
#[cfg(feature = "kcov")]
pub(super) fn sys_kcov_disable() -> Result<usize, SyscallError> {
    require_kcov_access()?;

    crate::process::try_with_current_kcov(coverage::CoverageBuffer::disable)
        .map_err(kcov_access_error)?;
    Ok(0)
}

#[cfg(not(feature = "kcov"))]
pub(super) fn sys_kcov_disable() -> Result<usize, SyscallError> {
    Err(SyscallError::ENOSYS)
}

/// Dump coverage data to userspace
#[cfg(feature = "kcov")]
pub(super) fn sys_kcov_dump(user_buf: usize, len: usize) -> Result<usize, SyscallError> {
    require_kcov_access()?;

    if user_buf == 0 {
        return Err(SyscallError::EINVAL);
    }

    if len > coverage::KCOV_BUFFER_SIZE {
        return Err(SyscallError::EINVAL);
    }

    let configured_len = crate::process::try_with_current_kcov(|buffer| buffer.bitmap_len())
        .map_err(kcov_access_error)?;
    if len != configured_len {
        return Err(SyscallError::EINVAL);
    }

    // Reject malformed user ranges before consuming transient heap admission.
    validate_user_ptr(user_buf as *const u8, len)?;
    let mut kernel_buf = try_admitted_zeroed_buffer(mm::HeapClass::Coverage, len)?;

    // Snapshot only while owning the KCOV mutex. Allocation and usercopy stay
    // outside it so faults and allocator paths cannot recurse into the lock.
    let edge_count = crate::process::try_with_current_kcov(|buffer| {
        // R187-3 FIX: exact-copy is an independent invariant check.  It
        // rejects both a shortened and an oversized staging slice before any
        // bytes move, so refactors cannot silently turn this snapshot partial.
        buffer
            .copy_to_slice_exact(&mut kernel_buf)
            .map_err(|_| SyscallError::EIO)?;
        Ok::<usize, SyscallError>(buffer.edge_count())
    })
    .map_err(kcov_access_error)??;

    // Copy to userspace via SMAP-compliant path
    crate::usercopy::copy_to_user_safe(user_buf as *mut u8, &kernel_buf)
        .map_err(|_| SyscallError::EFAULT)?;

    Ok(edge_count)
}

#[cfg(not(feature = "kcov"))]
pub(super) fn sys_kcov_dump(_user_buf: usize, _len: usize) -> Result<usize, SyscallError> {
    Err(SyscallError::ENOSYS)
}

/// Reset coverage data
#[cfg(feature = "kcov")]
pub(super) fn sys_kcov_reset() -> Result<usize, SyscallError> {
    require_kcov_access()?;

    crate::process::try_with_current_kcov(coverage::CoverageBuffer::reset)
        .map_err(kcov_access_error)?;
    Ok(0)
}

#[cfg(not(feature = "kcov"))]
pub(super) fn sys_kcov_reset() -> Result<usize, SyscallError> {
    Err(SyscallError::ENOSYS)
}

#[cfg(feature = "kcov")]
#[inline]
pub(super) fn kcov_access_error(error: crate::process::KcovAccessError) -> SyscallError {
    match error {
        crate::process::KcovAccessError::NotInitialized => SyscallError::EINVAL,
        crate::process::KcovAccessError::Contended
        | crate::process::KcovAccessError::InterruptContext
        | crate::process::KcovAccessError::CpuUnavailable => SyscallError::EBUSY,
    }
}

#[cfg(all(test, feature = "kcov"))]
mod r187_kcov_authorization_tests {
    use super::*;

    #[test]
    fn only_host_root_can_authorize_kcov() {
        assert!(!kcov_access_allowed(false, false));
        assert!(!kcov_access_allowed(false, true));
        assert!(kcov_access_allowed(true, false));
        assert!(kcov_access_allowed(true, true));
    }
}
