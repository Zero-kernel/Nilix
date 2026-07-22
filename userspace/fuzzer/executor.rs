// Executor for coverage-guided fuzzing
// Phase 4: Executes syscall sequences and collects coverage via KCOV

#![no_std]

extern crate alloc;
use alloc::vec::Vec;

use super::corpus::Syscall;

// Syscall numbers for KCOV interface
const SYS_KCOV_INIT: usize = 520;
const SYS_KCOV_ENABLE: usize = 521;
const SYS_KCOV_DISABLE: usize = 522;
const SYS_KCOV_DUMP: usize = 523;
const SYS_KCOV_RESET: usize = 524;

/// Execution result
pub struct ExecutionResult {
    /// Coverage edges hit
    pub edges: Vec<u32>,

    /// Execution time in microseconds
    pub exec_time_us: u64,

    /// Whether execution succeeded
    pub success: bool,
}

pub struct Executor {
    /// Coverage buffer
    coverage_buf: [u32; 256],

    /// KCOV initialized
    initialized: bool,
}

impl Executor {
    pub fn new() -> Self {
        Self {
            coverage_buf: [0u32; 256],
            initialized: false,
        }
    }

    /// Initialize KCOV
    pub fn init(&mut self) -> bool {
        if self.initialized {
            return true;
        }

        let result = syscall1(SYS_KCOV_INIT, 4096);
        self.initialized = result == 0;
        self.initialized
    }

    /// Execute syscall sequence and collect coverage
    pub fn execute(&mut self, sequence: &[Syscall]) -> ExecutionResult {
        if !self.initialized {
            if !self.init() {
                return ExecutionResult {
                    edges: Vec::new(),
                    exec_time_us: 0,
                    success: false,
                };
            }
        }

        // Enable coverage collection
        syscall0(SYS_KCOV_ENABLE);

        // Execute sequence
        let start = read_tsc();
        for syscall in sequence {
            self.execute_syscall(syscall);
        }
        let end = read_tsc();

        // Disable coverage
        syscall0(SYS_KCOV_DISABLE);

        // Dump coverage data
        let edge_count = syscall3(
            SYS_KCOV_DUMP,
            self.coverage_buf.as_mut_ptr() as usize,
            self.coverage_buf.len() * 4,
            0,
        );

        // Reset for next iteration
        syscall0(SYS_KCOV_RESET);

        // Convert edge count to vector
        let edges = if edge_count <= self.coverage_buf.len() {
            self.coverage_buf[..edge_count].to_vec()
        } else {
            Vec::new()
        };

        // Approximate microseconds from TSC cycles
        let exec_time_us = (end - start) / 2000;  // Assume ~2GHz CPU

        ExecutionResult {
            edges,
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

/// Read timestamp counter (TSC)
fn read_tsc() -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        core::arch::asm!(
            "rdtsc",
            lateout("eax") lo,
            lateout("edx") hi,
            options(nomem, nostack),
        );
    }
    ((hi as u64) << 32) | (lo as u64)
}
