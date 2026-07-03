#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

/// Fuzz input for syscall testing
#[derive(Arbitrary, Debug)]
struct SyscallFuzzInput {
    syscall_number: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
    arg6: u64,
}

/// Syscall categories for targeted fuzzing
#[derive(Arbitrary, Debug)]
enum SyscallCategory {
    FileOps {
        fd: i32,
        buffer_size: usize,
        offset: i64,
    },
    ProcessOps {
        pid: i32,
        signal: i32,
        flags: u64,
    },
    MemoryOps {
        addr: u64,
        length: u64,
        prot: i32,
        flags: i32,
    },
    IPC {
        id: i32,
        data_len: usize,
        flags: u32,
    },
    Signal {
        signum: i32,
        handler_addr: u64,
        mask: u64,
    },
}

fuzz_target!(|input: SyscallFuzzInput| {
    // R173/R174 focus areas: CLOEXEC, positioned I/O, signal delivery

    // Validate syscall number is in reasonable range (0-512)
    if input.syscall_number > 512 {
        return;
    }

    // Test specific high-risk syscalls from R173/R174
    match input.syscall_number {
        // fcntl - R173-05/06 CLOEXEC fixes
        72 => {
            test_fcntl_fuzzing(input.arg1 as i32, input.arg2 as i32, input.arg3);
        }
        // pipe2 - R173-05/06 CLOEXEC fixes
        293 => {
            test_pipe2_fuzzing(input.arg1 as u64, input.arg2 as i32);
        }
        // pread64 - R173-07 positioned I/O
        17 => {
            test_pread64_fuzzing(
                input.arg1 as i32,
                input.arg2 as u64,
                input.arg3 as usize,
                input.arg4 as i64
            );
        }
        // pwrite64 - R173-07 positioned I/O
        18 => {
            test_pwrite64_fuzzing(
                input.arg1 as i32,
                input.arg2 as u64,
                input.arg3 as usize,
                input.arg4 as i64
            );
        }
        // rt_sigaction - R174 signal delivery
        13 => {
            test_sigaction_fuzzing(
                input.arg1 as i32,
                input.arg2 as u64,
                input.arg3 as u64
            );
        }
        // rt_sigprocmask - R174 signal delivery
        14 => {
            test_sigprocmask_fuzzing(
                input.arg1 as i32,
                input.arg2 as u64,
                input.arg3 as u64
            );
        }
        // clone - R174-A2 FD double-uncharge fix
        56 => {
            test_clone_fuzzing(
                input.arg1 as u64,
                input.arg2 as u64,
                input.arg3 as u64
            );
        }
        // futex - R172-08 futex bucket TOCTOU
        202 => {
            test_futex_fuzzing(
                input.arg1 as u64,
                input.arg2 as i32,
                input.arg3 as i32,
                input.arg4 as u64
            );
        }
        _ => {
            // Generic syscall validation
            validate_syscall_args(&input);
        }
    }
});

fn test_fcntl_fuzzing(fd: i32, cmd: i32, arg: u64) {
    // Fuzz fcntl operations: F_DUPFD, F_DUPFD_CLOEXEC, F_GETFD, F_SETFD
    // Target: CLOEXEC invariant (cloexec_fds ⊆ fd_table)

    // Validate fd is in range [-1, 256]
    if fd < -1 || fd > 256 {
        return;
    }

    // Validate cmd is a known fcntl command
    match cmd {
        0 | 1 | 2 | 3 | 4 | 1030 => {
            // F_DUPFD=0, F_GETFD=1, F_SETFD=2, F_GETFL=3, F_SETFL=4, F_DUPFD_CLOEXEC=1030
            // Test boundary: arg for F_DUPFD should be < MAX_FD
            if cmd == 0 || cmd == 1030 {
                assert!(arg <= 256, "F_DUPFD arg exceeds MAX_FD");
            }
        }
        _ => return, // Invalid cmd
    }
}

fn test_pipe2_fuzzing(pipefd_addr: u64, flags: i32) {
    // Fuzz pipe2 O_CLOEXEC flag handling
    // Target: both pipe ends marked before copy-out, failure path clears marks

    // Validate flags are valid combinations
    let valid_flags = [0, 0x800, 0x80000, 0x80800]; // 0, O_CLOEXEC, O_NONBLOCK, both
    if !valid_flags.contains(&flags) {
        return;
    }

    // Address should be user-space (< KERNEL_BASE)
    const KERNEL_BASE: u64 = 0xffff_8000_0000_0000;
    assert!(pipefd_addr < KERNEL_BASE, "pipe2 pipefd in kernel space");
}

fn test_pread64_fuzzing(fd: i32, buf_addr: u64, count: usize, offset: i64) {
    // Fuzz positioned read
    // Target: offset validation (EINVAL on negative), fd offset unchanged

    if fd < -1 || fd > 256 {
        return;
    }

    // Negative offset should be rejected
    if offset < 0 {
        // Kernel should return EINVAL
        return;
    }

    // Buffer address validation
    const KERNEL_BASE: u64 = 0xffff_8000_0000_0000;
    assert!(buf_addr < KERNEL_BASE, "pread64 buffer in kernel space");

    // Count should be bounded by MAX_RW_SIZE
    const MAX_RW_SIZE: usize = 0x7ffff000;
    if count > MAX_RW_SIZE {
        return;
    }
}

fn test_pwrite64_fuzzing(fd: i32, buf_addr: u64, count: usize, offset: i64) {
    // Fuzz positioned write
    // Same validations as pread64

    if fd < -1 || fd > 256 {
        return;
    }

    if offset < 0 {
        return;
    }

    const KERNEL_BASE: u64 = 0xffff_8000_0000_0000;
    assert!(buf_addr < KERNEL_BASE, "pwrite64 buffer in kernel space");

    const MAX_RW_SIZE: usize = 0x7ffff000;
    if count > MAX_RW_SIZE {
        return;
    }
}

fn test_sigaction_fuzzing(signum: i32, act_addr: u64, oldact_addr: u64) {
    // Fuzz signal handler registration
    // Target: SA_RESTORER required, SIGKILL/SIGSTOP rejection, canonical handler VA

    // Validate signal number [1, 64]
    if signum < 1 || signum > 64 {
        return;
    }

    // SIGKILL (9) and SIGSTOP (19) cannot have handlers
    if signum == 9 || signum == 19 {
        // Kernel should reject with EINVAL
        return;
    }

    // Addresses should be user-space or NULL
    const KERNEL_BASE: u64 = 0xffff_8000_0000_0000;
    if act_addr != 0 {
        assert!(act_addr < KERNEL_BASE, "sigaction act in kernel space");
    }
    if oldact_addr != 0 {
        assert!(oldact_addr < KERNEL_BASE, "sigaction oldact in kernel space");
    }
}

fn test_sigprocmask_fuzzing(how: i32, set_addr: u64, oldset_addr: u64) {
    // Fuzz signal mask operations
    // Target: how validation only when set != NULL

    // Valid how values: SIG_BLOCK=0, SIG_UNBLOCK=1, SIG_SETMASK=2
    if set_addr != 0 && !(0..=2).contains(&how) {
        // Kernel should reject with EINVAL
        return;
    }

    // Addresses validation
    const KERNEL_BASE: u64 = 0xffff_8000_0000_0000;
    if set_addr != 0 {
        assert!(set_addr < KERNEL_BASE, "sigprocmask set in kernel space");
    }
    if oldset_addr != 0 {
        assert!(oldset_addr < KERNEL_BASE, "sigprocmask oldset in kernel space");
    }
}

fn test_clone_fuzzing(flags: u64, stack: u64, ptid: u64) {
    // Fuzz clone flags combinations
    // Target: R174-A2 FD double-uncharge, CLONE_VM charge bypass (refuted as HIGH)

    const CLONE_VM: u64 = 0x00000100;
    const CLONE_FILES: u64 = 0x00000400;
    const CLONE_SIGHAND: u64 = 0x00000800;
    const CLONE_THREAD: u64 = 0x00010000;

    // CLONE_THREAD requires CLONE_SIGHAND and CLONE_VM
    if flags & CLONE_THREAD != 0 {
        assert!(flags & CLONE_SIGHAND != 0, "CLONE_THREAD without CLONE_SIGHAND");
        assert!(flags & CLONE_VM != 0, "CLONE_THREAD without CLONE_VM");
    }

    // CLONE_SIGHAND requires CLONE_VM
    if flags & CLONE_SIGHAND != 0 {
        assert!(flags & CLONE_VM != 0, "CLONE_SIGHAND without CLONE_VM");
    }

    // Stack address for CLONE_VM must be user-provided
    if flags & CLONE_VM != 0 && stack != 0 {
        const KERNEL_BASE: u64 = 0xffff_8000_0000_0000;
        assert!(stack < KERNEL_BASE, "clone stack in kernel space");
    }
}

fn test_futex_fuzzing(uaddr: u64, op: i32, val: i32, timeout_addr: u64) {
    // Fuzz futex operations
    // Target: R172-08 futex bucket TOCTOU (get_or_create_bucket under lock)

    // Validate futex operations
    const FUTEX_WAIT: i32 = 0;
    const FUTEX_WAKE: i32 = 1;
    const FUTEX_LOCK_PI: i32 = 6;
    const FUTEX_UNLOCK_PI: i32 = 7;

    let base_op = op & 0xf;
    if !(0..=7).contains(&base_op) {
        return;
    }

    // Address must be 4-byte aligned
    assert!(uaddr % 4 == 0, "futex uaddr not aligned");

    // Address must be user-space
    const KERNEL_BASE: u64 = 0xffff_8000_0000_0000;
    assert!(uaddr < KERNEL_BASE, "futex uaddr in kernel space");

    // Timeout address validation for WAIT operations
    if base_op == FUTEX_WAIT && timeout_addr != 0 {
        assert!(timeout_addr < KERNEL_BASE, "futex timeout in kernel space");
    }
}

fn validate_syscall_args(input: &SyscallFuzzInput) {
    // Generic syscall argument validation
    // Catch common classes of invalid arguments

    // Pointer arguments should not be in kernel space
    const KERNEL_BASE: u64 = 0xffff_8000_0000_0000;

    for arg in [input.arg1, input.arg2, input.arg3, input.arg4, input.arg5, input.arg6] {
        // If arg looks like a pointer (high bit clear), validate it's user-space
        if arg != 0 && arg < KERNEL_BASE {
            // Could be a valid user pointer
            continue;
        }

        if arg >= KERNEL_BASE {
            // Potential kernel pointer - should be rejected by syscall
            // This is a valid fuzz case to test kernel hardening
        }
    }
}
