// Phase 3: Random Syscall Sequence Generator
// Generates 2-5 syscall chains using the TOML-based grammar

#![no_std]
#![no_main]

extern crate alloc;
use alloc::vec::Vec;
use core::panic::PanicInfo;

// Syscall numbers from grammar
const SYS_READ: usize = 0;
const SYS_WRITE: usize = 1;
const SYS_OPEN: usize = 2;
const SYS_CLOSE: usize = 3;
const SYS_BRK: usize = 12;
const SYS_MMAP: usize = 9;
const SYS_MUNMAP: usize = 11;
const SYS_FORK: usize = 57;
const SYS_EXECVE: usize = 59;
const SYS_EXIT: usize = 60;

// KCOV syscalls
const SYS_KCOV_INIT: usize = 520;
const SYS_KCOV_ENABLE: usize = 521;
const SYS_KCOV_DISABLE: usize = 522;
const SYS_KCOV_DUMP: usize = 523;
const SYS_KCOV_RESET: usize = 524;

// Memory protection flags
const PROT_READ: i32 = 1;
const PROT_WRITE: i32 = 2;
const PROT_EXEC: i32 = 4;
const PROT_NONE: i32 = 0;

// Memory mapping flags
const MAP_PRIVATE: i32 = 2;
const MAP_ANONYMOUS: i32 = 0x20;

// Open flags
const O_RDONLY: i32 = 0;
const O_WRONLY: i32 = 1;
const O_RDWR: i32 = 2;
const O_CREAT: i32 = 0x40;

// Simple PRNG state
static mut PRNG_STATE: u32 = 0x12345678;

fn rand() -> u32 {
    unsafe {
        PRNG_STATE = PRNG_STATE.wrapping_mul(1664525).wrapping_add(1013904223);
        PRNG_STATE
    }
}

fn rand_range(min: u32, max: u32) -> u32 {
    if max <= min {
        return min;
    }
    min + (rand() % (max - min + 1))
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    write_str("=== Phase 3: Random Syscall Sequence Generator ===\n\n");

    // Initialize KCOV
    if syscall1(SYS_KCOV_INIT, 4096) != 0 {
        write_str("KCOV init failed\n");
        exit(1);
    }
    write_str("[KCOV] Initialized\n");

    // Run 5 randomized test sequences
    let iterations = 5;
    let mut total_edges = 0;

    for iter in 1..=iterations {
        write_str("\n--- Iteration ");
        write_num(iter);
        write_str(" ---\n");

        // Enable coverage collection
        syscall0(SYS_KCOV_ENABLE);

        // Generate random sequence (2-5 syscalls)
        let sequence_len = rand_range(2, 5);
        write_str("Sequence length: ");
        write_num(sequence_len as usize);
        write_str("\n");

        for step in 1..=sequence_len {
            write_str("  Step ");
            write_num(step as usize);
            write_str(": ");

            // Pick random syscall from safe set
            let syscall_choice = rand() % 10;

            match syscall_choice {
                0 => {
                    write_str("read(0, buf, 16)\n");
                    let mut buf = [0u8; 16];
                    // Non-blocking read from stdin
                    let _ = syscall3(SYS_READ, 0, buf.as_mut_ptr() as usize, 16);
                }
                1 => {
                    write_str("write(1, \"test\", 4)\n");
                    let msg = b"test";
                    syscall3(SYS_WRITE, 1, msg.as_ptr() as usize, 4);
                }
                2 => {
                    write_str("open(\"/test\", O_RDONLY, 0)\n");
                    let path = b"/test\0";
                    let _ = syscall3(SYS_OPEN, path.as_ptr() as usize, O_RDONLY as usize, 0);
                }
                3 => {
                    write_str("brk(0) - query\n");
                    let _ = syscall1(SYS_BRK, 0);
                }
                4 => {
                    write_str("mmap(0, 4096, PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)\n");
                    let _ = syscall6(
                        SYS_MMAP,
                        0,
                        4096,
                        PROT_READ as usize,
                        (MAP_PRIVATE | MAP_ANONYMOUS) as usize,
                        (-1isize) as usize,
                        0
                    );
                }
                5 => {
                    write_str("getpid()\n");
                    let _ = syscall0(39); // sys_getpid
                }
                6 => {
                    write_str("getppid()\n");
                    let _ = syscall0(110); // sys_getppid
                }
                7 => {
                    write_str("getuid()\n");
                    let _ = syscall0(102); // sys_getuid
                }
                8 => {
                    write_str("geteuid()\n");
                    let _ = syscall0(107); // sys_geteuid
                }
                9 => {
                    write_str("getgid()\n");
                    let _ = syscall0(104); // sys_getgid
                }
                _ => {
                    write_str("getegid()\n");
                    let _ = syscall0(108); // sys_getegid
                }
            }
        }

        // Disable coverage collection
        syscall0(SYS_KCOV_DISABLE);

        // Dump coverage
        let mut coverage_buf = [0u32; 256];
        let edge_count = syscall3(
            SYS_KCOV_DUMP,
            coverage_buf.as_mut_ptr() as usize,
            coverage_buf.len() * 4,
            0
        );

        write_str("  Coverage: ");
        write_num(edge_count);
        write_str(" unique edges\n");

        total_edges += edge_count;

        // Show first 5 edge IDs
        if edge_count > 0 {
            write_str("  Edge IDs: ");
            let max_display = if edge_count < 5 { edge_count } else { 5 };
            for i in 0..max_display {
                if i > 0 {
                    write_str(", ");
                }
                write_num(coverage_buf[i] as usize);
            }
            if edge_count > 5 {
                write_str(", ...");
            }
            write_str("\n");
        }

        // Reset for next iteration
        syscall0(SYS_KCOV_RESET);
    }

    // Summary
    write_str("\n=== Summary ===\n");
    write_str("Total iterations: ");
    write_num(iterations);
    write_str("\n");
    write_str("Total edges collected: ");
    write_num(total_edges);
    write_str("\n");
    write_str("Average edges per iteration: ");
    write_num(total_edges / iterations);
    write_str("\n");

    write_str("\n✓ Phase 3 random sequence generation complete\n");

    exit(0);
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
    for j in 0..i/2 {
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

fn syscall6(n: usize, arg1: usize, arg2: usize, arg3: usize, arg4: usize, arg5: usize, arg6: usize) -> usize {
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

fn exit(code: i32) -> ! {
    syscall1(SYS_EXIT, code as usize);
    loop {}
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_str("\nPANIC\n");
    exit(1);
}
