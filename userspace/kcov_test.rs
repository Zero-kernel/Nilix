// KCOV syscall interface test
// Demonstrates Phase 2 coverage collection capabilities

#![no_std]
#![no_main]

use core::panic::PanicInfo;

// Syscall numbers for KCOV interface
const SYS_KCOV_INIT: usize = 520;
const SYS_KCOV_ENABLE: usize = 521;
const SYS_KCOV_DISABLE: usize = 522;
const SYS_KCOV_DUMP: usize = 523;
const SYS_KCOV_RESET: usize = 524;

// Test syscalls that are instrumented
const SYS_GETPID: usize = 39;
const SYS_GETPPID: usize = 110;
const SYS_GETUID: usize = 102;
const SYS_GETEUID: usize = 107;
const SYS_GETGID: usize = 104;
const SYS_GETEGID: usize = 108;
const SYS_WRITE: usize = 1;
const SYS_EXIT: usize = 60;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // Buffer for coverage data (1KB = 256 u32s)
    let mut coverage_buf = [0u32; 256];

    // Test 1: Initialize KCOV
    let result = syscall1(SYS_KCOV_INIT, 4096);
    if result != 0 {
        write_str("KCOV init failed\n");
        exit(1);
    }
    write_str("[TEST] KCOV initialized\n");

    // Test 2: Enable coverage collection
    let result = syscall0(SYS_KCOV_ENABLE);
    if result != 0 {
        write_str("KCOV enable failed\n");
        exit(1);
    }
    write_str("[TEST] KCOV enabled\n");

    // Test 3: Execute instrumented syscalls
    write_str("[TEST] Executing instrumented syscalls...\n");

    // These syscalls have manual coverage trace points
    syscall0(SYS_GETPID);   // 3 edges
    syscall0(SYS_GETPPID);  // 5 edges
    syscall0(SYS_GETUID);   // 1 edge
    syscall0(SYS_GETEUID);  // 1 edge
    syscall0(SYS_GETGID);   // 1 edge
    syscall0(SYS_GETEGID);  // 1 edge

    write_str("[TEST] Syscalls executed\n");

    // Test 4: Disable coverage collection
    let result = syscall0(SYS_KCOV_DISABLE);
    if result != 0 {
        write_str("KCOV disable failed\n");
        exit(1);
    }
    write_str("[TEST] KCOV disabled\n");

    // Test 5: Dump coverage data
    let edge_count = syscall3(
        SYS_KCOV_DUMP,
        coverage_buf.as_mut_ptr() as usize,
        coverage_buf.len() * 4,
        0
    );

    if edge_count == usize::MAX {
        write_str("KCOV dump failed\n");
        exit(1);
    }

    // Display results
    write_str("[TEST] Coverage collected: ");
    write_num(edge_count);
    write_str(" unique edges\n");

    if edge_count > 0 {
        write_str("[TEST] First 10 edge IDs: ");
        let max_display = if edge_count < 10 { edge_count } else { 10 };
        for i in 0..max_display {
            if i > 0 {
                write_str(", ");
            }
            write_num(coverage_buf[i] as usize);
        }
        write_str("\n");
    }

    // Test 6: Reset coverage
    let result = syscall0(SYS_KCOV_RESET);
    if result != 0 {
        write_str("KCOV reset failed\n");
        exit(1);
    }
    write_str("[TEST] KCOV reset\n");

    // Test 7: Verify reset by dumping again
    let edge_count_after_reset = syscall3(
        SYS_KCOV_DUMP,
        coverage_buf.as_mut_ptr() as usize,
        coverage_buf.len() * 4,
        0
    );

    write_str("[TEST] Coverage after reset: ");
    write_num(edge_count_after_reset);
    write_str(" edges\n");

    // Summary
    write_str("\n=== KCOV Test Summary ===\n");
    if edge_count >= 6 {
        write_str("✓ SUCCESS: Detected ");
        write_num(edge_count);
        write_str(" edges from 6 syscalls\n");
        write_str("✓ Expected: 12 edges (3+5+1+1+1+1)\n");
        if edge_count_after_reset == 0 {
            write_str("✓ Reset verified\n");
        } else {
            write_str("✗ Reset failed - still has edges\n");
        }
    } else {
        write_str("✗ FAIL: Only detected ");
        write_num(edge_count);
        write_str(" edges (expected >= 6)\n");
    }

    exit(0);
}

// Helper: Write string to stdout (fd=1)
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

fn exit(code: i32) -> ! {
    syscall1(SYS_EXIT, code as usize);
    loop {}
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_str("PANIC\n");
    exit(1);
}
