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

/// Build a `struct timespec` from nanoseconds.
#[inline]
pub(super) fn timespec_from_ns(ns: u64) -> TimeSpec {
    TimeSpec {
        tv_sec: (ns / 1_000_000_000) as i64,
        tv_nsec: (ns % 1_000_000_000) as i64,
    }
}

/// Build a `struct timeval` from nanoseconds.
#[inline]
pub(super) fn timeval_from_ns(ns: u64) -> TimeVal {
    TimeVal {
        tv_sec: (ns / 1_000_000_000) as i64,
        tv_usec: ((ns % 1_000_000_000) / 1_000) as i64,
    }
}

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

/// Convert a validated Linux `TimeSpec` into nanoseconds.
#[inline]
pub(super) fn timespec_to_ns(ts: &TimeSpec) -> Result<u64, SyscallError> {
    if ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= 1_000_000_000 {
        return Err(SyscallError::EINVAL);
    }
    Ok((ts.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.tv_nsec as u64))
}

/// Convert a validated Linux `TimeVal` pair `(sec, usec)` into nanoseconds.
#[inline]
pub(super) fn timeval_pair_to_ns(sec: i64, usec: i64) -> Result<u64, SyscallError> {
    if sec < 0 || usec < 0 || usec >= 1_000_000 {
        return Err(SyscallError::EINVAL);
    }
    Ok((sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add((usec as u64).saturating_mul(1_000)))
}

/// N2.6b: Read the nanosecond timestamp for a supported `CLOCK_*` id.
#[inline]
pub(super) fn read_clock_ns(clockid: i32) -> Result<u64, SyscallError> {
    match clockid {
        CLOCK_REALTIME | CLOCK_REALTIME_COARSE => Ok(crate::time::realtime_ns()),
        CLOCK_MONOTONIC | CLOCK_MONOTONIC_RAW | CLOCK_MONOTONIC_COARSE | CLOCK_BOOTTIME => {
            Ok(crate::time::monotonic_ns())
        }
        _ => Err(SyscallError::EINVAL),
    }
}

/// N2.6b: Map a `clockid` accepted by `timer_create` / `clock_nanosleep` to `TimerClock`.
#[inline]
pub(super) fn clockid_to_timer_clock(
    clockid: i32,
) -> Result<crate::time::TimerClock, SyscallError> {
    match clockid {
        CLOCK_REALTIME => Ok(crate::time::TimerClock::Realtime),
        CLOCK_MONOTONIC => Ok(crate::time::TimerClock::Monotonic),
        CLOCK_BOOTTIME => Ok(crate::time::TimerClock::Boottime),
        _ => Err(SyscallError::EINVAL),
    }
}

/// Whether `clock_gettime` / `clock_getres` can satisfy `clockid`.
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
/// N2.6b: `CLOCK_REALTIME` / `CLOCK_REALTIME_COARSE` return wall-clock Unix
/// epoch nanoseconds (seeded from CMOS RTC at boot); monotonic/boottime clocks
/// return nanosecond monotonic uptime (HPET 64-bit counter with 1 kHz fallback).
pub(super) fn sys_clock_gettime(clockid: i32, tp: *mut TimeSpec) -> SyscallResult {
    if tp.is_null() {
        return Err(SyscallError::EFAULT);
    }
    let ns = read_clock_ns(clockid)?;
    let timespec = timespec_from_ns(ns);

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

/// sys_clock_getres - query clock resolution (syscall 229, N2.6b).
///
/// Linux/POSIX: a NULL `res` pointer is valid and checks `clockid` only.
pub(super) fn sys_clock_getres(clockid: i32, res: *mut TimeSpec) -> SyscallResult {
    if !startup_clockid_supported(clockid) {
        return Err(SyscallError::EINVAL);
    }
    if res.is_null() {
        return Ok(0);
    }
    let coarse = matches!(clockid, CLOCK_REALTIME_COARSE | CLOCK_MONOTONIC_COARSE);
    let res_ts = timespec_from_ns(crate::time::clock_resolution_ns(coarse));
    // lint-repr-c-copy: allow (no-padding: TimeSpec {i64,i64} = 16 bytes)
    let bytes = unsafe {
        core::slice::from_raw_parts(
            &res_ts as *const TimeSpec as *const u8,
            core::mem::size_of::<TimeSpec>(),
        )
    };
    crate::usercopy::copy_to_user_safe(res as *mut u8, bytes).map_err(|_| SyscallError::EFAULT)?;
    Ok(0)
}

/// Linux `TIMER_ABSTIME` flag for `clock_nanosleep(2)` and `timer_settime(2)`.
pub(super) const TIMER_ABSTIME: i32 = 1;

/// sys_clock_nanosleep - high-resolution sleep with selectable clock and
/// optional `TIMER_ABSTIME` (syscall 230, N2.6b).
pub(super) fn sys_clock_nanosleep(
    clockid: i32,
    flags: i32,
    req: *const TimeSpec,
    rem: *mut TimeSpec,
) -> SyscallResult {
    if req.is_null() {
        return Err(SyscallError::EFAULT);
    }
    if (flags & !TIMER_ABSTIME) != 0 {
        return Err(SyscallError::EINVAL);
    }
    let clock = clockid_to_timer_clock(clockid)?;
    let abstime = (flags & TIMER_ABSTIME) != 0;

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
    let req_ns = timespec_to_ns(&ts)?;

    let now_mono = crate::time::monotonic_ns();
    let deadline_mono = if abstime {
        match clock {
            crate::time::TimerClock::Realtime => {
                req_ns.saturating_sub(crate::time::wall_clock_offset_ns())
            }
            crate::time::TimerClock::Monotonic | crate::time::TimerClock::Boottime => req_ns,
        }
    } else {
        now_mono.saturating_add(req_ns)
    };

    let mut interrupted = false;
    while crate::time::monotonic_ns() < deadline_mono {
        if let Some(pid) = current_pid() {
            if wait_should_abort(pid) || crate::signal::has_deliverable_signal(pid) {
                interrupted = true;
                break;
            }
        }
        crate::reschedule_if_needed();
        debug_assert!(
            x86_64::instructions::interrupts::are_enabled(),
            "clock_nanosleep loop must hlt with IRQs enabled"
        );
        unsafe {
            core::arch::asm!("hlt", options(nomem, nostack, preserves_flags));
        }
    }

    // POSIX: `rem` is written ONLY on relative-sleep EINTR (never for TIMER_ABSTIME).
    if interrupted && !abstime && !rem.is_null() {
        let remaining_ns = deadline_mono.saturating_sub(crate::time::monotonic_ns());
        let rem_ts = timespec_from_ns(remaining_ns);
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
        Err(SyscallError::EINTR)
    } else {
        Ok(0)
    }
}

// ============================================================================
// N2.6b: Interval Timers (`alarm`, `getitimer`, `setitimer`) & POSIX Timers
// ============================================================================

pub(super) const ITIMER_REAL: i32 = 0;
pub(super) const ITIMER_VIRTUAL: i32 = 1;
pub(super) const ITIMER_PROF: i32 = 2;

pub(super) const SIGEV_SIGNAL: i32 = 0;
pub(super) const SIGEV_NONE: i32 = 1;
pub(super) const SIGEV_THREAD_ID: i32 = 4;

fn current_tgid() -> Result<ProcessId, SyscallError> {
    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let proc_arc = get_process(pid).ok_or(SyscallError::ESRCH)?;
    let tgid = proc_arc.lock().tgid;
    Ok(tgid)
}

#[inline]
pub(super) fn itimerval_from_ns(interval_ns: u64, value_ns: u64) -> ITimerVal {
    let iv = timeval_from_ns(interval_ns);
    let val = timeval_from_ns(value_ns);
    ITimerVal {
        it_interval_sec: iv.tv_sec,
        it_interval_usec: iv.tv_usec,
        it_value_sec: val.tv_sec,
        it_value_usec: val.tv_usec,
    }
}

#[inline]
pub(super) fn itimerspec_from_ns(interval_ns: u64, value_ns: u64) -> ITimerSpec {
    let iv = timespec_from_ns(interval_ns);
    let val = timespec_from_ns(value_ns);
    ITimerSpec {
        it_interval_sec: iv.tv_sec,
        it_interval_nsec: iv.tv_nsec,
        it_value_sec: val.tv_sec,
        it_value_nsec: val.tv_nsec,
    }
}

/// Convert previous remaining `ITIMER_REAL` nanoseconds to POSIX `alarm(2)` return seconds.
/// Returns 0 if disarmed, otherwise rounds up to at least 1 second (POSIX).
#[inline]
pub(super) fn alarm_remaining_secs(remaining_ns: u64) -> usize {
    if remaining_ns == 0 {
        0
    } else {
        let secs = remaining_ns / 1_000_000_000;
        let rem = remaining_ns % 1_000_000_000;
        let rounded = if rem >= 500_000_000 { secs + 1 } else { secs };
        rounded.max(1) as usize
    }
}

/// sys_alarm - set a one-shot `SIGALRM` delivery timer in seconds (syscall 37, N2.6b).
pub(super) fn sys_alarm(seconds: u32) -> SyscallResult {
    let tgid = current_tgid()?;
    let value_ns = (seconds as u64).saturating_mul(1_000_000_000);
    let (_prev_iv, prev_rem) = crate::time::set_real_itimer(tgid, 0, value_ns)?;
    Ok(alarm_remaining_secs(prev_rem))
}

/// sys_getitimer - query an interval timer (syscall 36, N2.6b).
pub(super) fn sys_getitimer(which: i32, curr_value: *mut ITimerVal) -> SyscallResult {
    if curr_value.is_null() {
        return Err(SyscallError::EFAULT);
    }
    let (iv_ns, rem_ns) = match which {
        ITIMER_REAL => {
            let tgid = current_tgid()?;
            crate::time::get_real_itimer(tgid)
        }
        ITIMER_VIRTUAL | ITIMER_PROF => (0, 0),
        _ => return Err(SyscallError::EINVAL),
    };
    let out = itimerval_from_ns(iv_ns, rem_ns);
    // lint-repr-c-copy: allow (ITimerVal is 32B #[repr(C)] no padding; kernel→user)
    let bytes = unsafe {
        core::slice::from_raw_parts(
            &out as *const ITimerVal as *const u8,
            core::mem::size_of::<ITimerVal>(),
        )
    };
    copy_to_user(curr_value as *mut u8, bytes)?;
    Ok(0)
}

/// sys_setitimer - arm/disarm an interval timer (syscall 38, N2.6b).
pub(super) fn sys_setitimer(
    which: i32,
    new_value: *const ITimerVal,
    old_value: *mut ITimerVal,
) -> SyscallResult {
    if !matches!(which, ITIMER_REAL | ITIMER_VIRTUAL | ITIMER_PROF) {
        return Err(SyscallError::EINVAL);
    }
    if new_value.is_null() {
        return Err(SyscallError::EFAULT);
    }
    let mut req = ITimerVal::default();
    // lint-repr-c-copy: allow (ITimerVal is 32B #[repr(C)] no padding; user→kernel)
    let req_bytes = unsafe {
        core::slice::from_raw_parts_mut(
            &mut req as *mut ITimerVal as *mut u8,
            core::mem::size_of::<ITimerVal>(),
        )
    };
    copy_from_user(req_bytes, new_value as *const u8)?;
    let interval_ns = timeval_pair_to_ns(req.it_interval_sec, req.it_interval_usec)?;
    let value_ns = timeval_pair_to_ns(req.it_value_sec, req.it_value_usec)?;

    if !old_value.is_null() {
        verify_user_memory(
            old_value as *const u8,
            core::mem::size_of::<ITimerVal>(),
            true,
        )?;
    }

    let (prev_iv, prev_rem) = match which {
        ITIMER_REAL => {
            let tgid = current_tgid()?;
            crate::time::set_real_itimer(tgid, interval_ns, value_ns)?
        }
        ITIMER_VIRTUAL | ITIMER_PROF => {
            if value_ns != 0 || interval_ns != 0 {
                return Err(SyscallError::EOPNOTSUPP);
            }
            (0, 0)
        }
        _ => return Err(SyscallError::EINVAL),
    };

    if !old_value.is_null() {
        let out = itimerval_from_ns(prev_iv, prev_rem);
        // lint-repr-c-copy: allow (ITimerVal is 32B #[repr(C)] no padding; kernel→user)
        let bytes = unsafe {
            core::slice::from_raw_parts(
                &out as *const ITimerVal as *const u8,
                core::mem::size_of::<ITimerVal>(),
            )
        };
        copy_to_user(old_value as *mut u8, bytes)?;
    }
    Ok(0)
}

/// sys_timer_create - create a POSIX per-process timer (syscall 222, N2.6b).
pub(super) fn sys_timer_create(
    clockid: i32,
    sevp: *const SigEvent,
    timerid_out: *mut i32,
) -> SyscallResult {
    if timerid_out.is_null() {
        return Err(SyscallError::EFAULT);
    }
    let clock = clockid_to_timer_clock(clockid)?;
    verify_user_memory(timerid_out as *const u8, core::mem::size_of::<i32>(), true)?;

    let pid = current_pid().ok_or(SyscallError::ESRCH)?;
    let (tgid, owning_ns) = {
        let proc_arc = get_process(pid).ok_or(SyscallError::ESRCH)?;
        let proc = proc_arc.lock();
        (
            proc.tgid,
            crate::pid_namespace::owning_namespace(&proc.pid_ns_chain),
        )
    };

    let notify = if sevp.is_null() {
        None
    } else {
        let mut ev = SigEvent::default();
        // lint-repr-c-copy: allow (SigEvent is 64B #[repr(C)] with explicit _pad; user→kernel)
        let ev_bytes = unsafe {
            core::slice::from_raw_parts_mut(
                &mut ev as *mut SigEvent as *mut u8,
                core::mem::size_of::<SigEvent>(),
            )
        };
        copy_from_user(ev_bytes, sevp as *const u8)?;
        match ev.sigev_notify {
            SIGEV_NONE => Some(crate::time::PosixTimerNotify::None),
            SIGEV_SIGNAL => {
                let sig = crate::signal::Signal::from_raw(ev.sigev_signo)
                    .map_err(|_| SyscallError::EINVAL)?;
                Some(crate::time::PosixTimerNotify::Signal {
                    sig,
                    sival: ev.sigev_value,
                })
            }
            SIGEV_THREAD_ID => {
                if ev.sigev_notify_tid <= 0 {
                    return Err(SyscallError::EINVAL);
                }
                let sig = crate::signal::Signal::from_raw(ev.sigev_signo)
                    .map_err(|_| SyscallError::EINVAL)?;
                let target_tid = match &owning_ns {
                    Some(ns) => crate::pid_namespace::resolve_pid_in_namespace(
                        ns,
                        ev.sigev_notify_tid as ProcessId,
                    )
                    .ok_or(SyscallError::EINVAL)?,
                    None => ev.sigev_notify_tid as ProcessId,
                };
                let target_arc = get_process(target_tid).ok_or(SyscallError::EINVAL)?;
                if target_arc.lock().tgid != tgid {
                    return Err(SyscallError::EINVAL);
                }
                Some(crate::time::PosixTimerNotify::ThreadSignal {
                    tid: target_tid,
                    sig,
                    sival: ev.sigev_value,
                })
            }
            _ => return Err(SyscallError::EINVAL),
        }
    };

    let id = crate::time::create_posix_timer(tgid, clock, notify)?;
    if copy_to_user(timerid_out as *mut u8, &id.to_ne_bytes()).is_err() {
        let _ = crate::time::delete_posix_timer(tgid, id);
        return Err(SyscallError::EFAULT);
    }
    Ok(0)
}

/// sys_timer_settime - arm/disarm a POSIX per-process timer (syscall 223, N2.6b).
pub(super) fn sys_timer_settime(
    timerid: i32,
    flags: i32,
    new_value: *const ITimerSpec,
    old_value: *mut ITimerSpec,
) -> SyscallResult {
    if (flags & !TIMER_ABSTIME) != 0 {
        return Err(SyscallError::EINVAL);
    }
    if new_value.is_null() {
        return Err(SyscallError::EFAULT);
    }
    let mut req = ITimerSpec::default();
    // lint-repr-c-copy: allow (ITimerSpec is 32B #[repr(C)] no padding; user→kernel)
    let req_bytes = unsafe {
        core::slice::from_raw_parts_mut(
            &mut req as *mut ITimerSpec as *mut u8,
            core::mem::size_of::<ITimerSpec>(),
        )
    };
    copy_from_user(req_bytes, new_value as *const u8)?;
    let interval_ns = timespec_to_ns(&TimeSpec {
        tv_sec: req.it_interval_sec,
        tv_nsec: req.it_interval_nsec,
    })?;
    let value_ns = timespec_to_ns(&TimeSpec {
        tv_sec: req.it_value_sec,
        tv_nsec: req.it_value_nsec,
    })?;

    if !old_value.is_null() {
        verify_user_memory(
            old_value as *const u8,
            core::mem::size_of::<ITimerSpec>(),
            true,
        )?;
    }

    let tgid = current_tgid()?;
    let (prev_iv, prev_rem) = crate::time::settime_posix_timer(
        tgid,
        timerid,
        (flags & TIMER_ABSTIME) != 0,
        interval_ns,
        value_ns,
    )?;

    if !old_value.is_null() {
        let out = itimerspec_from_ns(prev_iv, prev_rem);
        // lint-repr-c-copy: allow (ITimerSpec is 32B #[repr(C)] no padding; kernel→user)
        let bytes = unsafe {
            core::slice::from_raw_parts(
                &out as *const ITimerSpec as *const u8,
                core::mem::size_of::<ITimerSpec>(),
            )
        };
        copy_to_user(old_value as *mut u8, bytes)?;
    }
    Ok(0)
}

/// sys_timer_gettime - fetch remaining time of a POSIX timer (syscall 224, N2.6b).
pub(super) fn sys_timer_gettime(timerid: i32, curr_value: *mut ITimerSpec) -> SyscallResult {
    if curr_value.is_null() {
        return Err(SyscallError::EFAULT);
    }
    let tgid = current_tgid()?;
    let (iv_ns, rem_ns) = crate::time::gettime_posix_timer(tgid, timerid)?;
    let out = itimerspec_from_ns(iv_ns, rem_ns);
    // lint-repr-c-copy: allow (ITimerSpec is 32B #[repr(C)] no padding; kernel→user)
    let bytes = unsafe {
        core::slice::from_raw_parts(
            &out as *const ITimerSpec as *const u8,
            core::mem::size_of::<ITimerSpec>(),
        )
    };
    copy_to_user(curr_value as *mut u8, bytes)?;
    Ok(0)
}

/// sys_timer_getoverrun - get overrun count for a POSIX timer (syscall 225, N2.6b).
pub(super) fn sys_timer_getoverrun(timerid: i32) -> SyscallResult {
    let tgid = current_tgid()?;
    let overrun = crate::time::getoverrun_posix_timer(tgid, timerid)?;
    Ok(overrun as usize)
}

/// sys_timer_delete - delete a POSIX per-process timer (syscall 226, N2.6b).
pub(super) fn sys_timer_delete(timerid: i32) -> SyscallResult {
    let tgid = current_tgid()?;
    crate::time::delete_posix_timer(tgid, timerid)?;
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

/// sys_gettimeofday - 获取当前墙钟时间 (N2.6b: CMOS RTC epoch + ns monotonic)
pub(super) fn sys_gettimeofday(tv: *mut TimeVal, _tz: usize) -> SyscallResult {
    if tv.is_null() {
        return Err(SyscallError::EFAULT);
    }

    let timeval = timeval_from_ns(crate::time::realtime_ns());

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

#[cfg(test)]
mod n2_6b_timer_tests {
    use super::*;
    use crate::time::{
        advance_expired_timer, cleanup_all_timers_for_process, cleanup_posix_timers_for_exec,
        compute_timer_deadline_ns, create_posix_timer, delete_posix_timer, get_real_itimer,
        getoverrun_posix_timer, gettime_posix_timer, set_real_itimer, settime_posix_timer,
        PosixTimerNotify, TimerClock, MAX_POSIX_TIMERS_PER_PROCESS,
    };

    #[test]
    fn n2_6b_nanosecond_conversions_and_alarm_rounding() {
        let ts = timespec_from_ns(1_795_838_400_123_456_789);
        assert_eq!(ts.tv_sec, 1_795_838_400);
        assert_eq!(ts.tv_nsec, 123_456_789);
        assert_eq!(timespec_to_ns(&ts), Ok(1_795_838_400_123_456_789));

        let tv = timeval_from_ns(1_795_838_400_123_456_789);
        assert_eq!(tv.tv_sec, 1_795_838_400);
        assert_eq!(tv.tv_usec, 123_456);
        assert_eq!(timeval_pair_to_ns(1, 500_000), Ok(1_500_000_000));
        assert_eq!(timeval_pair_to_ns(-1, 0), Err(SyscallError::EINVAL));
        assert_eq!(timeval_pair_to_ns(0, 1_000_000), Err(SyscallError::EINVAL));
        assert_eq!(
            timespec_to_ns(&TimeSpec {
                tv_sec: 0,
                tv_nsec: 1_000_000_000
            }),
            Err(SyscallError::EINVAL)
        );

        // POSIX alarm(2) rounding: 0 stays 0; nonzero sub-second rounds up to 1.
        assert_eq!(alarm_remaining_secs(0), 0);
        assert_eq!(alarm_remaining_secs(1), 1);
        assert_eq!(alarm_remaining_secs(499_999_999), 1);
        assert_eq!(alarm_remaining_secs(1_499_999_999), 1);
        assert_eq!(alarm_remaining_secs(1_500_000_000), 2);
    }

    #[test]
    fn n2_6b_clock_resolution_and_abstime_deadline_math() {
        assert_eq!(crate::time::clock_resolution_ns(true), 1_000_000);
        assert!(crate::time::clock_resolution_ns(false) >= 1);
        assert_eq!(
            clockid_to_timer_clock(CLOCK_REALTIME),
            Ok(TimerClock::Realtime)
        );
        assert_eq!(
            clockid_to_timer_clock(CLOCK_MONOTONIC),
            Ok(TimerClock::Monotonic)
        );
        assert_eq!(
            clockid_to_timer_clock(CLOCK_BOOTTIME),
            Ok(TimerClock::Boottime)
        );
        assert_eq!(clockid_to_timer_clock(99), Err(SyscallError::EINVAL));

        // Relative vs absolute deadline conversion on monotonic and realtime clocks.
        let mono = 10_000_000_000u64;
        let offset = 1_700_000_000_000_000_000u64;
        assert_eq!(
            compute_timer_deadline_ns(0, false, TimerClock::Monotonic, mono, offset),
            None
        );
        assert_eq!(
            compute_timer_deadline_ns(500_000_000, false, TimerClock::Monotonic, mono, offset),
            Some(mono + 500_000_000)
        );
        assert_eq!(
            compute_timer_deadline_ns(
                offset + mono + 250_000_000,
                true,
                TimerClock::Realtime,
                mono,
                offset
            ),
            Some(mono + 250_000_000)
        );
    }

    #[test]
    fn n2_6b_real_itimer_and_overrun_advancement() {
        let tgid = 910_001usize;
        cleanup_all_timers_for_process(tgid);
        assert_eq!(get_real_itimer(tgid), (0, 0));

        // Arm periodic ITIMER_REAL: 500ms initial, 200ms interval.
        let prev = set_real_itimer(tgid, 200_000_000, 500_000_000).unwrap();
        assert_eq!(prev, (0, 0));
        let (iv, rem) = get_real_itimer(tgid);
        assert_eq!(iv, 200_000_000);
        assert!(rem > 0 && rem <= 500_000_000);

        // Disarming returns previous interval + remaining and clears entry.
        let (old_iv, old_rem) = set_real_itimer(tgid, 0, 0).unwrap();
        assert_eq!(old_iv, 200_000_000);
        assert!(old_rem > 0);
        assert_eq!(get_real_itimer(tgid), (0, 0));

        // Overrun math: one-shot disarms with overrun 0; periodic computes missed intervals.
        assert_eq!(advance_expired_timer(1_000, 0, 5_000), (None, 0));
        assert_eq!(advance_expired_timer(1_000, 100, 1_050), (Some(1_100), 0));
        assert_eq!(advance_expired_timer(1_000, 100, 1_350), (Some(1_400), 3));
    }

    #[test]
    fn n2_6b_posix_timers_quota_lifecycle_and_exec_cleanup() {
        let tgid = 910_002usize;
        cleanup_all_timers_for_process(tgid);

        // Arm ITIMER_REAL alongside POSIX timers to verify exec preserves ITIMER_REAL
        // while deleting POSIX timers (POSIX.1-2008).
        set_real_itimer(tgid, 0, 5_000_000_000).unwrap();

        let mut ids = [0i32; MAX_POSIX_TIMERS_PER_PROCESS];
        for slot in ids.iter_mut() {
            *slot = create_posix_timer(
                tgid,
                TimerClock::Monotonic,
                Some(PosixTimerNotify::Signal {
                    sig: crate::signal::Signal::from_raw(34).unwrap(),
                    sival: 0x1234,
                }),
            )
            .expect("within per-process quota");
        }
        // Per-process cap enforced with EAGAIN.
        assert_eq!(
            create_posix_timer(tgid, TimerClock::Monotonic, None),
            Err(SyscallError::EAGAIN)
        );

        // Arm, query, check overrun, and delete one timer.
        let tid0 = ids[0];
        let old = settime_posix_timer(tgid, tid0, false, 100_000_000, 1_000_000_000).unwrap();
        assert_eq!(old, (0, 0));
        let (iv, rem) = gettime_posix_timer(tgid, tid0).unwrap();
        assert_eq!(iv, 100_000_000);
        assert!(rem > 0 && rem <= 1_000_000_000);
        assert_eq!(getoverrun_posix_timer(tgid, tid0), Ok(0));
        assert!(delete_posix_timer(tgid, tid0).is_ok());
        assert_eq!(gettime_posix_timer(tgid, tid0), Err(SyscallError::EINVAL));

        // Exec cleanup deletes all remaining POSIX timers, keeps ITIMER_REAL.
        cleanup_posix_timers_for_exec(tgid);
        assert_eq!(gettime_posix_timer(tgid, ids[1]), Err(SyscallError::EINVAL));
        assert!(get_real_itimer(tgid).1 > 0);

        // Process exit cleanup removes ITIMER_REAL too.
        cleanup_all_timers_for_process(tgid);
        assert_eq!(get_real_itimer(tgid), (0, 0));
    }
}
