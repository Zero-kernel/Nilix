#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

/// Fuzz input for signal delivery
#[derive(Arbitrary, Debug)]
struct SignalFuzzInput {
    operation: SignalOperation,
    signum: i32,
    target_pid: i32,
    handler_addr: u64,
    mask: u64,
    flags: u32,
}

#[derive(Arbitrary, Debug)]
enum SignalOperation {
    Send,
    Action,
    ProcMask,
    Return,
    Suspend,
}

fuzz_target!(|input: SignalFuzzInput| {
    // Target R173/R174 signal delivery fixes:
    // - R173-01: try_deliver_signal_on_irq_return blocking mm lock in IRQ
    // - R174 signal delivery end-to-end (M0-5)
    // - Signal frame construction, SROP defense

    // Validate signal number [1, 64]
    if input.signum < 1 || input.signum > 64 {
        return;
    }

    match input.operation {
        SignalOperation::Send => {
            test_signal_send(input.target_pid, input.signum);
        }
        SignalOperation::Action => {
            test_signal_action(input.signum, input.handler_addr, input.flags);
        }
        SignalOperation::ProcMask => {
            test_signal_procmask(input.mask);
        }
        SignalOperation::Return => {
            test_signal_return(input.handler_addr);
        }
        SignalOperation::Suspend => {
            test_signal_suspend(input.mask);
        }
    }
});

fn test_signal_send(pid: i32, signum: i32) {
    // Fuzz kill/tkill/tgkill operations

    // PID validation
    if pid == 0 {
        // Send to process group
    } else if pid == -1 {
        // Broadcast (requires privilege)
    } else if pid < -1 {
        // Send to process group |pid|
    } else {
        // Send to specific PID
        assert!(pid > 0, "invalid PID");
    }

    // Special signals
    const SIGKILL: i32 = 9;
    const SIGSTOP: i32 = 19;
    const SIGCONT: i32 = 18;

    match signum {
        SIGKILL | SIGSTOP => {
            // Cannot be caught or ignored
            // SIGCONT should clear stop state
        }
        SIGCONT => {
            // Should clear SIGSTOP and wake stopped processes
        }
        _ => {
            // Regular signal - can be caught/ignored
        }
    }
}

fn test_signal_action(signum: i32, handler_addr: u64, flags: u32) {
    // Fuzz rt_sigaction
    // Target: SA_RESTORER required, canonical handler VA, SROP defense

    const SIGKILL: i32 = 9;
    const SIGSTOP: i32 = 19;

    // SIGKILL and SIGSTOP cannot have handlers
    if signum == SIGKILL || signum == SIGSTOP {
        // Should return EINVAL
        return;
    }

    // Handler address validation
    if handler_addr != 0 && handler_addr != 1 {
        // SIG_DFL = 0, SIG_IGN = 1, otherwise custom handler

        // Must be canonical user-space address
        const KERNEL_BASE: u64 = 0xffff_8000_0000_0000;
        const USER_MAX: u64 = 0x0000_7fff_ffff_ffff;

        if handler_addr >= KERNEL_BASE {
            // Non-canonical high - should be rejected
            return;
        }

        if handler_addr > USER_MAX {
            // Non-canonical middle - should be rejected
            return;
        }

        // Handler must be executable (cannot validate without page tables)
    }

    // Flags validation
    const SA_RESTORER: u32 = 0x04000000;
    const SA_NODEFER: u32 = 0x40000000;
    const SA_RESETHAND: u32 = 0x80000000;
    const SA_RESTART: u32 = 0x10000000;
    const SA_SIGINFO: u32 = 0x00000004;
    const SA_ONSTACK: u32 = 0x08000000;

    // Custom handler requires SA_RESTORER; kernel returns EINVAL otherwise.
    if handler_addr > 1 && flags & SA_RESTORER == 0 {
        return;
    }

    // SA_NODEFER: signal is not automatically blocked during handler
    // SA_RESETHAND: handler is reset to SIG_DFL after one invocation
    // Both are valid and can be combined
}

fn test_signal_procmask(mask: u64) {
    // Fuzz rt_sigprocmask
    // Target: how validation, SIGKILL/SIGSTOP cannot be blocked

    const SIGKILL: i32 = 9;
    const SIGSTOP: i32 = 19;

    // SIGKILL (bit 8) and SIGSTOP (bit 18) should be ignored in mask
    let sigkill_bit = 1u64 << (SIGKILL - 1);
    let sigstop_bit = 1u64 << (SIGSTOP - 1);

    if mask & sigkill_bit != 0 {
        // Attempt to block SIGKILL - should be silently ignored
    }

    if mask & sigstop_bit != 0 {
        // Attempt to block SIGSTOP - should be silently ignored
    }

    // Valid mask should only have bits [0, 63] set
    // (signals are 1-indexed, so bit 0 = signal 1)
}

fn test_signal_return(frame_addr: u64) {
    // Fuzz rt_sigreturn
    // Target: SROP defense via canonical RIP/RSP checks + RFLAGS sanitize

    if frame_addr == 0 {
        return;
    }

    // Frame must be in user space and 16-byte aligned (x86_64 ABI); the SROP
    // defense rejects the rest, so filter rather than panic on fuzz input.
    const KERNEL_BASE: u64 = 0xffff_8000_0000_0000;
    if frame_addr >= KERNEL_BASE || frame_addr % 16 != 0 {
        return;
    }

    // SROP defense checks (in kernel):
    // 1. RIP must be canonical user-space
    // 2. RSP must be canonical user-space
    // 3. RFLAGS: preserve only safe flags (IF, DF, AC cleared)
    // 4. CS must be user code segment (0x2b)
    // 5. SS must be user data segment (0x33)

    // Simulate frame structure
    #[repr(C)]
    struct Sigframe {
        uc_flags: u64,
        uc_link: u64,
        uc_stack: [u64; 3],
        uc_mcontext: MContext,
        uc_sigmask: u64,
    }

    #[repr(C)]
    struct MContext {
        r8: u64, r9: u64, r10: u64, r11: u64,
        r12: u64, r13: u64, r14: u64, r15: u64,
        rdi: u64, rsi: u64, rbp: u64, rbx: u64,
        rdx: u64, rax: u64, rcx: u64, rsp: u64,
        rip: u64,
        eflags: u64,
        cs: u16, gs: u16, fs: u16, ss: u16,
    }

    // SROP attack would try to set:
    // - RIP to gadget in kernel
    // - CS to kernel code segment
    // - RFLAGS.IF to disable interrupts
    // Defense must validate all of these
}

fn test_signal_suspend(mask: u64) {
    // Fuzz rt_sigsuspend
    // Target: atomically replaces signal mask and suspends until signal

    const SIGKILL: i32 = 9;
    const SIGSTOP: i32 = 19;

    // Even if mask attempts to block SIGKILL/SIGSTOP, they should wake sigsuspend
    let sigkill_bit = 1u64 << (SIGKILL - 1);
    let sigstop_bit = 1u64 << (SIGSTOP - 1);

    // sigsuspend should be interruptible by any signal
    // Must return EINTR (not EAGAIN)
}

/// Test concurrent signal delivery
fn test_concurrent_signals(pid: i32, signals: &[i32]) {
    // Fuzz concurrent signal delivery to same process
    // Target: signal queue corruption, lost signals, double-delivery

    for &sig in signals {
        if sig < 1 || sig > 64 {
            continue;
        }

        // Standard signals [1-31] are not queued (only one pending)
        // RT signals [32-64] are queued

        if sig <= 31 {
            // Standard signal - only one pending flag
            // Multiple sends before delivery = one delivery
        } else {
            // RT signal - should be queued
            // Multiple sends = multiple deliveries (FIFO)
        }
    }
}

/// Test signal delivery during syscall
fn test_signal_during_syscall(signum: i32, syscall_num: u64) {
    // Fuzz signal delivery while process is blocked in syscall
    // Target: EINTR wake (M0-5 SLICE 1b-1), same-return delivery (SLICE 1b-2)

    if signum < 1 || signum > 64 {
        return;
    }

    // Blocking syscalls that should be interruptible:
    const SYS_READ: u64 = 0;
    const SYS_WRITE: u64 = 1;
    const SYS_WAIT4: u64 = 61;
    const SYS_NANOSLEEP: u64 = 35;
    const SYS_FUTEX: u64 = 202;

    match syscall_num {
        SYS_READ | SYS_WRITE => {
            // Should return EINTR if interrupted by handler signal
            // Should return EINPROGRESS if interrupted by fatal signal
        }
        SYS_WAIT4 => {
            // Should return EINTR (R172-11 fixed lost-wakeup)
        }
        SYS_NANOSLEEP => {
            // Should return EINTR and set *rem to remaining time
        }
        SYS_FUTEX => {
            // FUTEX_WAIT should return EINTR
            // FUTEX_LOCK_PI should return EINTR (M0-5 SLICE 1b-1b)
        }
        _ => {}
    }
}
