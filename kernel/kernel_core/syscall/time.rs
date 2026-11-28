//! Syscall family module: `time` (split from monolithic `syscall.rs`, N2.0a).

use super::*;

// ============================================================================
// 时间系统调用
// ============================================================================

/// sys_nanosleep - 高精度睡眠
///
/// 当前使用忙等待实现，未来应使用定时器。
pub(super) fn sys_nanosleep(req: *const TimeSpec, rem: *mut TimeSpec) -> SyscallResult {
    if req.is_null() {
        return Err(SyscallError::EFAULT);
    }

    let mut ts = TimeSpec::default();
    // lint-repr-c-copy: allow (no-padding: TimeSpec {i64,i64} = 16 bytes; user→kernel)
    let ts_bytes = unsafe {
        core::slice::from_raw_parts_mut(
            &mut ts as *mut TimeSpec as *mut u8,
            core::mem::size_of::<TimeSpec>(),
        )
    };
    crate::usercopy::copy_from_user_safe(ts_bytes, req as *const u8)
        .map_err(|_| SyscallError::EFAULT)?;

    if ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= 1_000_000_000 {
        return Err(SyscallError::EINVAL);
    }

    // 计算睡眠时间(毫秒)
    // R172-20 FIX: round UP to >= 1ms for any nonzero request. The old truncating
    // sec*1000 + nsec/1_000_000 made a sub-ms sleep a no-op (usleep -> userspace busy-spin)
    // and under-slept non-whole-ms requests, violating POSIX "sleep at LEAST the requested
    // time". Compute total ns (checked), then ceil-divide to ms.
    const NS_PER_MS: u64 = 1_000_000;
    let total_ns = (ts.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.tv_nsec as u64);
    let total_ms = if total_ns == 0 {
        0
    } else {
        // ceil(total_ns / NS_PER_MS), always >= 1 for any nonzero request.
        (total_ns / NS_PER_MS)
            .saturating_add(if total_ns % NS_PER_MS != 0 { 1 } else { 0 })
            .max(1)
    };

    // R42-3 FIX: Yield CPU during sleep to prevent busy-wait DoS (HLT to next timer tick).
    let start = crate::time::get_ticks();
    let mut interrupted = false;
    while crate::time::get_ticks().saturating_sub(start) < total_ms {
        // R172-10 FIX: honor a pending kill + deliverable handler signal EACH iteration. The
        // old loop never checked, so a Running task in nanosleep ignored SIGKILL / OOM-kill /
        // ns-init-death cascade AND any handler signal for the entire sleep window
        // (uninterruptible, defeating the deferred-kill model that only fires at the RPL==3
        // safe point this loop never reached). Break to EINTR so the task unwinds to that safe
        // point (kill honored there; handler delivered on syscall return).
        if let Some(pid) = current_pid() {
            if wait_should_abort(pid) || crate::signal::has_deliverable_signal(pid) {
                interrupted = true;
                break;
            }
        }
        // Allow other processes to run
        crate::reschedule_if_needed();
        // Halt until next timer interrupt (reduces CPU usage)
        unsafe {
            core::arch::asm!("hlt", options(nomem, nostack, preserves_flags));
        }
    }

    // R172-10/20 FIX: report the REMAINING time on EINTR (POSIX), 0 on normal completion.
    if !rem.is_null() {
        let remaining_ms = if interrupted {
            total_ms.saturating_sub(crate::time::get_ticks().saturating_sub(start))
        } else {
            0
        };
        let rem_ts = TimeSpec {
            tv_sec: (remaining_ms / 1000) as i64,
            tv_nsec: ((remaining_ms % 1000).saturating_mul(NS_PER_MS)) as i64,
        };
        // lint-repr-c-copy: allow (no-padding: TimeSpec {i64,i64} = 16 bytes; kernel→user)
        let rem_bytes = unsafe {
            core::slice::from_raw_parts(
                &rem_ts as *const TimeSpec as *const u8,
                core::mem::size_of::<TimeSpec>(),
            )
        };
        crate::usercopy::copy_to_user_safe(rem as *mut u8, rem_bytes)
            .map_err(|_| SyscallError::EFAULT)?;
    }

    if interrupted {
        return Err(SyscallError::EINTR);
    }
    Ok(0)
}

// ============================================================================
// 时间辅助 (shared timespec/timeval construction + startup clock support)
// ============================================================================

/// CLOCK_* ids that the single millisecond tick can satisfy today (Linux ABI).
pub(super) const CLOCK_REALTIME: i32 = 0;
pub(super) const CLOCK_MONOTONIC: i32 = 1;
pub(super) const CLOCK_MONOTONIC_RAW: i32 = 4;
pub(super) const CLOCK_REALTIME_COARSE: i32 = 5;
pub(super) const CLOCK_MONOTONIC_COARSE: i32 = 6;
pub(super) const CLOCK_BOOTTIME: i32 = 7;

/// Build a `struct timespec` from a millisecond count (sec + nanosecond remainder).
pub(super) fn timespec_from_ms(ms: u64) -> TimeSpec {
    TimeSpec {
        tv_sec: (ms / 1000) as i64,
        tv_nsec: ((ms % 1000) * 1_000_000) as i64,
    }
}

/// Build a `struct timeval` from a millisecond count (sec + microsecond remainder).
pub(super) fn timeval_from_ms(ms: u64) -> TimeVal {
    TimeVal {
        tv_sec: (ms / 1000) as i64,
        tv_usec: ((ms % 1000) * 1000) as i64,
    }
}

/// Whether `clock_gettime` can satisfy `clockid` from the current time source.
///
/// Zero-OS exposes a SINGLE monotonic millisecond tick (`current_timestamp_ms`),
/// so REALTIME currently aliases uptime exactly as `sys_gettimeofday` already
/// does, and the whole MONOTONIC family resolves to that same source. CPU-time
/// clocks (PROCESS/THREAD_CPUTIME_ID = 2/3) and unknown/negative/dynamic ids
/// return EINVAL until a real epoch wall-clock + per-task CPU accounting land
/// (Phase U). The realtime-vs-monotonic split is intentionally NOT branched on
/// today (both arms would be identical); that divergence seam is documented here
/// so the future epoch source only has to add an offset, not re-classify.
pub(super) fn startup_clockid_supported(clockid: i32) -> bool {
    matches!(
        clockid,
        CLOCK_REALTIME
            | CLOCK_MONOTONIC
            | CLOCK_MONOTONIC_RAW
            | CLOCK_REALTIME_COARSE
            | CLOCK_MONOTONIC_COARSE
            | CLOCK_BOOTTIME
    )
}

/// sys_clock_gettime - high-resolution clock query (syscall 228).
///
/// musl's crt faults without this. Fills a `struct timespec` from the kernel
/// millisecond tick for every supported clock id (see `startup_clockid_supported`).
pub(super) fn sys_clock_gettime(clockid: i32, tp: *mut TimeSpec) -> SyscallResult {
    if tp.is_null() {
        return Err(SyscallError::EFAULT);
    }
    if !startup_clockid_supported(clockid) {
        return Err(SyscallError::EINVAL);
    }

    let timespec = timespec_from_ms(crate::time::current_timestamp_ms());

    // lint-repr-c-copy: allow (no-padding: TimeSpec {i64,i64} = 16 bytes)
    let tp_bytes = unsafe {
        core::slice::from_raw_parts(
            &timespec as *const TimeSpec as *const u8,
            core::mem::size_of::<TimeSpec>(),
        )
    };
    crate::usercopy::copy_to_user_safe(tp as *mut u8, tp_bytes)
        .map_err(|_| SyscallError::EFAULT)?;

    Ok(0)
}

/// M0 #2 self-test for the pure startup-ABI helpers — the wires a green
/// build/boot can't catch (clock-id accept/reject set, ms→timespec/timeval
/// boundary arithmetic, and the rt_sigprocmask Linux-semantics validator
/// including the NULL-`set` how-skip). Panics on failure (caught by `make test`
/// / `make boot-check`).
pub fn run_startup_abi_self_test() {
    // --- clock-id acceptance set ---
    for id in [
        CLOCK_REALTIME,
        CLOCK_MONOTONIC,
        CLOCK_MONOTONIC_RAW,
        CLOCK_REALTIME_COARSE,
        CLOCK_MONOTONIC_COARSE,
        CLOCK_BOOTTIME,
    ] {
        assert!(
            startup_clockid_supported(id),
            "clockid {} must be supported",
            id
        );
    }
    // CPU-time clocks (2/3) + unknown/negative/extreme ids are rejected.
    for id in [2_i32, 3, 8, 9, 11, -1, i32::MAX, i32::MIN] {
        assert!(
            !startup_clockid_supported(id),
            "clockid {} must be rejected",
            id
        );
    }

    // --- ms -> timespec / timeval boundary arithmetic ---
    // (ms, expected_sec, expected_nsec)
    let cases = [
        (0u64, 0i64, 0i64),
        (1, 0, 1_000_000),
        (999, 0, 999_000_000),
        (1000, 1, 0),
        (1500, 1, 500_000_000),
        (3_600_000, 3600, 0),
    ];
    for (ms, sec, nsec) in cases {
        let ts = timespec_from_ms(ms);
        assert_eq!(ts.tv_sec, sec, "timespec sec for ms={}", ms);
        assert_eq!(ts.tv_nsec, nsec, "timespec nsec for ms={}", ms);
        assert!(
            ts.tv_nsec >= 0 && ts.tv_nsec < 1_000_000_000,
            "timespec nsec out of range for ms={}",
            ms
        );
        let tv = timeval_from_ms(ms);
        assert_eq!(tv.tv_sec, sec, "timeval sec for ms={}", ms);
        assert_eq!(tv.tv_usec, nsec / 1000, "timeval usec for ms={}", ms);
        assert!(
            tv.tv_usec >= 0 && tv.tv_usec < 1_000_000,
            "timeval usec out of range for ms={}",
            ms
        );
    }

    // --- rt_sigprocmask argument validator (Linux semantics) ---
    // Valid how + correct size, with a real `set`.
    assert!(validate_rt_sigprocmask_args(SIG_BLOCK, false, LINUX_KERNEL_SIGSET_SIZE).is_ok());
    assert!(validate_rt_sigprocmask_args(SIG_UNBLOCK, false, LINUX_KERNEL_SIGSET_SIZE).is_ok());
    assert!(validate_rt_sigprocmask_args(SIG_SETMASK, false, LINUX_KERNEL_SIGSET_SIZE).is_ok());
    // Wrong sigsetsize always fails, regardless of set/how.
    assert_eq!(
        validate_rt_sigprocmask_args(SIG_BLOCK, false, 0),
        Err(SyscallError::EINVAL)
    );
    assert_eq!(
        validate_rt_sigprocmask_args(SIG_BLOCK, false, 16),
        Err(SyscallError::EINVAL)
    );
    assert_eq!(
        validate_rt_sigprocmask_args(SIG_BLOCK, true, 4),
        Err(SyscallError::EINVAL)
    );
    // Non-NULL set + invalid how => EINVAL.
    assert_eq!(
        validate_rt_sigprocmask_args(-1, false, LINUX_KERNEL_SIGSET_SIZE),
        Err(SyscallError::EINVAL)
    );
    assert_eq!(
        validate_rt_sigprocmask_args(3, false, LINUX_KERNEL_SIGSET_SIZE),
        Err(SyscallError::EINVAL)
    );
    // NULL set is a pure query: `how` is ignored, so even a bogus how is OK.
    assert!(validate_rt_sigprocmask_args(-1, true, LINUX_KERNEL_SIGSET_SIZE).is_ok());
    assert!(validate_rt_sigprocmask_args(999, true, LINUX_KERNEL_SIGSET_SIZE).is_ok());

    // --- readv segment selection (the single segment readv services) ---
    let z = core::ptr::null::<u8>();
    // All-empty (incl. the iovcnt==0 case) selects nothing => readv returns 0.
    assert_eq!(first_nonempty_iovec(&[]), None);
    assert_eq!(
        first_nonempty_iovec(&[Iovec {
            iov_base: z,
            iov_len: 0
        }]),
        None
    );
    assert_eq!(
        first_nonempty_iovec(&[
            Iovec {
                iov_base: z,
                iov_len: 0
            },
            Iovec {
                iov_base: z,
                iov_len: 0
            },
        ]),
        None
    );
    // First non-empty wins; leading zero-length segments are skipped.
    assert_eq!(
        first_nonempty_iovec(&[Iovec {
            iov_base: z,
            iov_len: 5
        }]),
        Some(0)
    );
    assert_eq!(
        first_nonempty_iovec(&[
            Iovec {
                iov_base: z,
                iov_len: 0
            },
            Iovec {
                iov_base: z,
                iov_len: 3
            },
        ]),
        Some(1)
    );
    assert_eq!(
        first_nonempty_iovec(&[
            Iovec {
                iov_base: z,
                iov_len: 0
            },
            Iovec {
                iov_base: z,
                iov_len: 0
            },
            Iovec {
                iov_base: z,
                iov_len: 7
            },
            Iovec {
                iov_base: z,
                iov_len: 1
            },
        ]),
        Some(2)
    );
}

/// sys_gettimeofday - 获取当前时间
pub(super) fn sys_gettimeofday(tv: *mut TimeVal, _tz: usize) -> SyscallResult {
    if tv.is_null() {
        return Err(SyscallError::EFAULT);
    }

    let timeval = timeval_from_ms(crate::time::current_timestamp_ms());

    // lint-repr-c-copy: allow (no-padding: TimeVal {i64,i64} = 16 bytes)
    let tv_bytes = unsafe {
        core::slice::from_raw_parts(
            &timeval as *const TimeVal as *const u8,
            core::mem::size_of::<TimeVal>(),
        )
    };
    crate::usercopy::copy_to_user_safe(tv as *mut u8, tv_bytes)
        .map_err(|_| SyscallError::EFAULT)?;

    Ok(0)
}
