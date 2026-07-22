//! Fuzzing executor - runs syscall sequences with KCOV coverage collection
//!
//! This program generates random syscall sequences, executes them, and collects
//! coverage data for syzkaller-style fuzzing.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use core::panic::PanicInfo;
use syscall_gen::{
    ArgValue, BrkGenerator, CloseGenerator, ExitGenerator, ForkGenerator, GeneratedSyscall,
    MmapGenerator, MunmapGenerator, OpenGenerator, ReadGenerator, Rng, SyscallGenerator,
    WriteGenerator,
};

// Syscall numbers for KCOV interface
const SYS_KCOV_INIT: usize = 520;
const SYS_KCOV_ENABLE: usize = 521;
const SYS_KCOV_DISABLE: usize = 522;
const SYS_KCOV_DUMP: usize = 523;
const SYS_KCOV_RESET: usize = 524;

// Other syscalls
const SYS_WRITE: usize = 1;
const SYS_EXIT: usize = 60;
const SYS_GETPID: usize = 39;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // Initialize KCOV
    let result = syscall1(SYS_KCOV_INIT, 4096);
    if result != 0 {
        write_str("KCOV init failed\n");
        exit(1);
    }

    // Initialize RNG with a seed (in real fuzzer, this comes from fuzzer input)
    let seed = syscall0(SYS_GETPID) as u64;
    let mut rng = Rng::new(seed);

    // Coverage buffer for results
    let mut coverage_buf = [0u32; 1024];

    // Run 10 iterations
    for iteration in 0..10 {
        write_str("\n[ITER ");
        write_num(iteration);
        write_str("] Generating syscall sequence...\n");

        // Generate random syscall sequence (2-5 syscalls)
        let sequence_len = rng.range(2, 5);
        let mut sequence = Vec::new();

        for _ in 0..sequence_len {
            let syscall_choice = rng.range(0, 9);
            let generated = match syscall_choice {
                0 => ReadGenerator.generate(&mut rng),
                1 => WriteGenerator.generate(&mut rng),
                2 => OpenGenerator.generate(&mut rng),
                3 => CloseGenerator.generate(&mut rng),
                4 => BrkGenerator.generate(&mut rng),
                5 => MmapGenerator.generate(&mut rng),
                6 => MunmapGenerator.generate(&mut rng),
                7 => ForkGenerator.generate(&mut rng),
                8 => BrkGenerator.generate(&mut rng), // Duplicate brk for weight
                _ => OpenGenerator.generate(&mut rng),
            };
            sequence.push(generated);
        }

        // Enable coverage collection
        syscall0(SYS_KCOV_ENABLE);

        // Execute the sequence
        write_str("  Executing: ");
        for syscall in &sequence {
            write_str(syscall.name);
            write_str(" ");

            // Execute syscall (simplified - real executor needs proper argument handling)
            let _ = execute_syscall(syscall);
        }
        write_str("\n");

        // Disable coverage
        syscall0(SYS_KCOV_DISABLE);

        // Dump coverage
        let edge_count = syscall3(
            SYS_KCOV_DUMP,
            coverage_buf.as_mut_ptr() as usize,
            coverage_buf.len() * 4,
            0,
        );

        write_str("  Coverage: ");
        write_num(edge_count);
        write_str(" edges\n");

        // Reset for next iteration
        syscall0(SYS_KCOV_RESET);
    }

    write_str("\n=== Fuzzing Complete ===\n");
    exit(0);
}

/// Execute a single syscall (simplified implementation)
fn execute_syscall(syscall: &GeneratedSyscall) -> isize {
    match syscall.args.len() {
        0 => syscall0(syscall.number) as isize,
        1 => {
            let arg0 = extract_arg_usize(&syscall.args[0]);
            syscall1(syscall.number, arg0) as isize
        }
        2 => {
            let arg0 = extract_arg_usize(&syscall.args[0]);
            let arg1 = extract_arg_usize(&syscall.args[1]);
            syscall2(syscall.number, arg0, arg1) as isize
        }
        3 => {
            let arg0 = extract_arg_usize(&syscall.args[0]);
            let arg1 = extract_arg_usize(&syscall.args[1]);
            let arg2 = extract_arg_usize(&syscall.args[2]);
            syscall3(syscall.number, arg0, arg1, arg2) as isize
        }
        _ => -1,
    }
}

/// Extract usize value from ArgValue (simplified)
fn extract_arg_usize(arg: &ArgValue) -> usize {
    match arg {
        ArgValue::I32(v) => *v as usize,
        ArgValue::U32(v) => *v as usize,
        ArgValue::Usize(v) => *v,
        ArgValue::I64(v) => *v as usize,
        ArgValue::Ptr(v) => *v,
        ArgValue::String(vec) => vec.as_ptr() as usize,
        ArgValue::StringArray(vec) => vec.as_ptr() as usize,
    }
}

// Helper: Write string to stdout
fn write_str(s: &str) {
    syscall3(SYS_WRITE, 1, s.as_ptr() as usize, s.len());
}

// Helper: Write number as decimal
fn write_num(mut n: usize) {
    if n == 0 {
        write_str("0");
        return;
    }

    let mut buf = [0u8; 20];
    let mut i = 0;

    while n > 0 {
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }

    // Reverse
    for j in 0..i / 2 {
        buf.swap(j, i - 1 - j);
    }

    let s = core::str::from_utf8(&buf[..i]).unwrap_or("?");
    write_str(s);
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

fn exit(code: i32) -> ! {
    syscall1(SYS_EXIT, code as usize);
    loop {}
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_str("PANIC\n");
    exit(1);
}
