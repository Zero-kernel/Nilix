// Executor for coverage-guided fuzzing
// Phase 4: Executes syscall sequences and collects coverage via KCOV

// `main.rs` owns the crate-level `#![no_std]` contract. Keeping this as a
// normal module lets the host regression harness exercise the real decoder
// and validation code without invoking raw KCOV syscalls.

extern crate alloc;
use alloc::vec::Vec;

use super::corpus::Syscall;

// Syscall numbers for KCOV interface
const SYS_KCOV_INIT: usize = 520;
const SYS_KCOV_ENABLE: usize = 521;
const SYS_KCOV_DISABLE: usize = 522;
const SYS_KCOV_DUMP: usize = 523;
const SYS_KCOV_RESET: usize = 524;
const SYS_CLOCK_GETTIME: usize = 228;
const SYS_EXIT_GROUP: usize = 231;
const CLOCK_MONOTONIC: usize = 1;

// The kernel currently maps both transient recorder contention and persistent
// context/topology rejection to EBUSY. Bound retries so neither case can spin
// forever while still giving ordinary contention a chance to clear.
const SYSCALL_EBUSY: isize = -16;
const KCOV_CONTROL_MAX_ATTEMPTS: usize = 4;

const KCOV_BUFFER_SIZE: usize = 4096;
const KCOV_SLOT_COUNT: usize = KCOV_BUFFER_SIZE * 8;

#[repr(C)]
#[derive(Clone, Copy)]
struct TimeSpec {
    tv_sec: i64,
    tv_nsec: i64,
}

/// Execution result
pub struct ExecutionResult {
    /// Occupied KCOV bitmap-slot identifiers, not original source edge IDs.
    ///
    /// KCOV maps instrumentation IDs modulo its bitmap capacity, so distinct
    /// source edges can alias the same slot.
    pub occupied_slots: Vec<u32>,

    /// Execution time in microseconds
    pub exec_time_us: u64,

    /// Whether execution succeeded
    pub success: bool,
}

pub struct Executor {
    /// Raw KCOV bitmap. The kernel requires a dump destination exactly equal
    /// to the configured size, and every set bit represents one occupied slot.
    coverage_buf: [u8; KCOV_BUFFER_SIZE],

    /// KCOV initialized
    initialized: bool,
}

impl Executor {
    pub fn new() -> Self {
        Self {
            coverage_buf: [0u8; KCOV_BUFFER_SIZE],
            initialized: false,
        }
    }

    /// Initialize KCOV
    pub fn init(&mut self) -> bool {
        if self.initialized {
            return true;
        }

        let result = syscall1(SYS_KCOV_INIT, KCOV_BUFFER_SIZE);
        self.initialized = result == 0;
        self.initialized
    }

    /// Execute syscall sequence and collect coverage
    pub fn execute(&mut self, sequence: &[Syscall]) -> ExecutionResult {
        if !self.initialized && !self.init() {
            return failed_execution();
        }

        // R187-5 FIX: Query time only while coverage is disabled. Using
        // CLOCK_MONOTONIC avoids exposing the raw hardware TSC, and keeping
        // the clock syscalls outside the collection window prevents them from
        // contaminating the fuzzed program's KCOV bitmap.
        let start = monotonic_time_us();

        // Enable coverage collection. Any control failure invalidates this
        // execution instead of returning a misleading empty bitmap.
        if syscall0(SYS_KCOV_ENABLE) != 0 {
            return failed_execution();
        }

        // Execute sequence
        for syscall in sequence {
            self.execute_syscall(syscall);
        }

        // Disable before sampling time so clock_gettime itself is never part
        // of the coverage result. This does not return until disable succeeds:
        // reset clears data but deliberately cannot deactivate KCOV.
        complete_kcov_control_or_terminate(SYS_KCOV_DISABLE);
        let end = monotonic_time_us();

        // Dump coverage data
        let occupied_slot_count = syscall3(
            SYS_KCOV_DUMP,
            self.coverage_buf.as_mut_ptr() as usize,
            self.coverage_buf.len(),
            0,
        );

        // Reset only after a confirmed disable. Completion before returning
        // establishes the next iteration's clean, disabled-bitmap invariant.
        complete_kcov_control_or_terminate(SYS_KCOV_RESET);

        // Convert the bitmap into canonical slot IDs. The kernel's return
        // value must equal the bitmap popcount; reject mismatches and signed
        // errno values (which appear as large usize values) fail-closed.
        let Some(occupied_slots) = coverage_slots(&self.coverage_buf, occupied_slot_count) else {
            return failed_execution();
        };

        let exec_time_us = match (start, end) {
            (Some(start), Some(end)) => end.saturating_sub(start),
            // Timing is advisory to corpus scheduling. A clock failure must
            // not turn into a raw-counter fallback or invalidate valid KCOV.
            _ => 0,
        };

        ExecutionResult {
            occupied_slots,
            exec_time_us,
            success: true,
        }
    }

    /// Execute single syscall
    fn execute_syscall(&self, syscall: &Syscall) {
        let args = &syscall.args;

        // Execute syscall with up to 6 arguments
        syscall6(
            syscall.number,
            args[0] as usize,
            args[1] as usize,
            args[2] as usize,
            args[3] as usize,
            args[4] as usize,
            args[5] as usize,
        );

        // Ignore errors - fuzzer continues regardless
    }
}

// Syscall wrappers

fn syscall0(n: usize) -> usize {
    let ret: usize;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") n,
            lateout("rax") ret,
            lateout("rcx") _,
            lateout("r11") _,
        );
    }
    ret
}

fn syscall1(n: usize, arg1: usize) -> usize {
    let ret: usize;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") n,
            in("rdi") arg1,
            lateout("rax") ret,
            lateout("rcx") _,
            lateout("r11") _,
        );
    }
    ret
}

fn syscall2(n: usize, arg1: usize, arg2: usize) -> usize {
    let ret: usize;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") n,
            in("rdi") arg1,
            in("rsi") arg2,
            lateout("rax") ret,
            lateout("rcx") _,
            lateout("r11") _,
        );
    }
    ret
}

fn syscall3(n: usize, arg1: usize, arg2: usize, arg3: usize) -> usize {
    let ret: usize;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") n,
            in("rdi") arg1,
            in("rsi") arg2,
            in("rdx") arg3,
            lateout("rax") ret,
            lateout("rcx") _,
            lateout("r11") _,
        );
    }
    ret
}

fn syscall6(
    n: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
    arg5: usize,
    arg6: usize,
) -> usize {
    let ret: usize;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") n,
            in("rdi") arg1,
            in("rsi") arg2,
            in("rdx") arg3,
            in("r10") arg4,
            in("r8") arg5,
            in("r9") arg6,
            lateout("rax") ret,
            lateout("rcx") _,
            lateout("r11") _,
        );
    }
    ret
}

fn failed_execution() -> ExecutionResult {
    ExecutionResult {
        occupied_slots: Vec::new(),
        exec_time_us: 0,
        success: false,
    }
}

/// Complete a KCOV control transition or contain the process.
///
/// RF187-3 FIX: KCOV control uses a try-lock, so a direct `EBUSY` may be
/// transient and receives a bounded retry window. The kernel also uses EBUSY
/// for context/topology rejection, so persistent EBUSY must terminate instead
/// of spinning forever. Returning after any failed disable/reset would let
/// ordinary fuzzer code execute without a proven KCOV state. `exit_group` is
/// the fail-closed containment path; if it unexpectedly returns, no further
/// syscalls execute.
fn complete_kcov_control_or_terminate(syscall_number: usize) {
    if try_complete_kcov_control(|| syscall0(syscall_number)).is_err() {
        terminate_after_kcov_control_failure();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KcovControlFailure {
    NonRetryable(usize),
    BusyExhausted,
}

fn try_complete_kcov_control(mut invoke: impl FnMut() -> usize) -> Result<(), KcovControlFailure> {
    for attempt in 0..KCOV_CONTROL_MAX_ATTEMPTS {
        let result = invoke();
        if result == 0 {
            return Ok(());
        }
        if !is_kcov_control_retryable(result) {
            return Err(KcovControlFailure::NonRetryable(result));
        }
        if attempt + 1 < KCOV_CONTROL_MAX_ATTEMPTS {
            core::hint::spin_loop();
        }
    }

    Err(KcovControlFailure::BusyExhausted)
}

#[inline]
fn is_kcov_control_retryable(result: usize) -> bool {
    result as isize == SYSCALL_EBUSY
}

#[inline(never)]
fn terminate_after_kcov_control_failure() -> ! {
    let _ = syscall1(SYS_EXIT_GROUP, 1);
    loop {
        core::hint::spin_loop();
    }
}

/// Read the kernel-provided monotonic clock in microseconds.
///
/// This intentionally avoids the user-readable TSC: it does not reveal a raw
/// cycle counter, is portable across frequency changes, and follows the
/// kernel's `clock_gettime(CLOCK_MONOTONIC)` ABI.
fn monotonic_time_us() -> Option<u64> {
    let mut time = TimeSpec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if syscall2(
        SYS_CLOCK_GETTIME,
        CLOCK_MONOTONIC,
        &mut time as *mut TimeSpec as usize,
    ) != 0
    {
        return None;
    }
    timespec_to_us(time)
}

fn timespec_to_us(time: TimeSpec) -> Option<u64> {
    if time.tv_sec < 0 || !(0..1_000_000_000).contains(&time.tv_nsec) {
        return None;
    }
    (time.tv_sec as u64)
        .checked_mul(1_000_000)?
        .checked_add(time.tv_nsec as u64 / 1_000)
}

/// Decode set KCOV bits into stable bitmap-slot IDs.
fn coverage_slots(bitmap: &[u8], reported_slot_count: usize) -> Option<Vec<u32>> {
    if reported_slot_count > KCOV_SLOT_COUNT || bitmap.len() != KCOV_BUFFER_SIZE {
        return None;
    }

    let mut slots = Vec::new();
    slots.try_reserve_exact(reported_slot_count).ok()?;
    for (byte_index, byte) in bitmap.iter().copied().enumerate() {
        for bit_index in 0..8u32 {
            if byte & (1u8 << bit_index) != 0 {
                slots.push((byte_index as u32) * 8 + bit_index);
            }
        }
    }

    if slots.len() == reported_slot_count {
        Some(slots)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kcov_bitmap_decodes_slots_and_rejects_bad_counts() {
        let mut bitmap = [0u8; KCOV_BUFFER_SIZE];
        bitmap[0] = 0b0000_1001;
        bitmap[3] = 0b1000_0000;
        assert_eq!(coverage_slots(&bitmap, 3), Some(alloc::vec![0, 3, 31]));
        assert_eq!(coverage_slots(&bitmap, 2), None);
        assert_eq!(coverage_slots(&bitmap, KCOV_SLOT_COUNT + 1), None);
    }

    #[test]
    fn timespec_conversion_rejects_invalid_or_overflowing_values() {
        assert_eq!(
            timespec_to_us(TimeSpec {
                tv_sec: 2,
                tv_nsec: 345_678_000,
            }),
            Some(2_345_678)
        );
        assert_eq!(
            timespec_to_us(TimeSpec {
                tv_sec: -1,
                tv_nsec: 0,
            }),
            None
        );
        assert_eq!(
            timespec_to_us(TimeSpec {
                tv_sec: 0,
                tv_nsec: 1_000_000_000,
            }),
            None
        );
    }

    #[test]
    fn kcov_control_retries_transient_contention_until_success() {
        assert!(is_kcov_control_retryable(SYSCALL_EBUSY as usize));
        assert!(!is_kcov_control_retryable(0));
        assert!(!is_kcov_control_retryable((-1isize) as usize));

        let mut results = [SYSCALL_EBUSY as usize, SYSCALL_EBUSY as usize, 0].into_iter();
        let mut attempts = 0;
        assert_eq!(
            try_complete_kcov_control(|| {
                attempts += 1;
                results.next().expect("bounded test result")
            }),
            Ok(())
        );
        assert_eq!(attempts, 3);
    }

    #[test]
    fn kcov_control_stops_on_non_retryable_error() {
        let fatal = (-1isize) as usize;
        let mut attempts = 0;
        assert_eq!(
            try_complete_kcov_control(|| {
                attempts += 1;
                fatal
            }),
            Err(KcovControlFailure::NonRetryable(fatal))
        );
        assert_eq!(attempts, 1);
    }

    #[test]
    fn kcov_control_exhausts_persistent_busy() {
        let mut attempts = 0;
        assert_eq!(
            try_complete_kcov_control(|| {
                attempts += 1;
                SYSCALL_EBUSY as usize
            }),
            Err(KcovControlFailure::BusyExhausted)
        );
        assert_eq!(attempts, KCOV_CONTROL_MAX_ATTEMPTS);
    }
}
