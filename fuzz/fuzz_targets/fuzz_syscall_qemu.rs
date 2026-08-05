#![no_main]

//! QEMU-based syscall fuzzer - executes syscalls against the real KCOV-enabled kernel
//!
//! This target launches QEMU for each fuzzing iteration and extracts real kernel coverage.
//! It is MUCH slower than the mock-based fuzz_syscall target but finds real kernel bugs.
//!
//! Usage:
//!   cargo fuzz run fuzz_syscall_qemu -- -max_total_time=3600
//!
//! Prerequisites:
//!   - KCOV kernel built: make build-kcov
//!   - e2fsprogs installed: mke2fs, debugfs, e2fsck
//!   - QEMU installed: qemu-system-x86_64
//!   - OVMF firmware available

use libfuzzer_sys::fuzz_target;
use std::sync::Mutex;

// Lazy-initialized executor to avoid rebuilding on every iteration
static EXECUTOR: Mutex<Option<QemuFuzzerState>> = Mutex::new(None);

struct QemuFuzzerState {
    executor: nilix_syz_qemu::QemuExecutor,
    stats: FuzzStats,
}

struct FuzzStats {
    iterations: u64,
    successes: u64,
    crashes: u64,
    timeouts: u64,
    parse_failures: u64,
}

fuzz_target!(|data: &[u8]| {
    // Initialize executor on first run
    let mut guard = EXECUTOR.lock().unwrap();
    if guard.is_none() {
        match init_executor() {
            Ok(state) => {
                eprintln!("[+] QEMU executor initialized");
                *guard = Some(state);
            }
            Err(e) => {
                eprintln!("[!] Failed to initialize executor: {:#}", e);
                return;
            }
        }
    }

    let state = guard.as_mut().unwrap();
    state.stats.iterations += 1;

    // Parse libfuzzer input into SyscallProgram
    let program = match parse_fuzzer_input(data) {
        Ok(prog) => prog,
        Err(_) => {
            state.stats.parse_failures += 1;
            return;
        }
    };

    // Execute in QEMU and extract coverage
    match state.executor.execute(&program) {
        Ok(result) => match result {
            nilix_syz_qemu::ExecutionResult::Success(coverage) => {
                state.stats.successes += 1;
                // Note: Coverage feedback from QEMU is captured in the bitmap
                // but libfuzzer's guidance comes from compile-time instrumentation
                // of the parser code (parse_fuzzer_input). This is a limitation
                // of the current approach - future work should use custom mutators
                // or the libfuzzer custom mutator API to incorporate KCOV feedback.
                let _ = coverage; // Acknowledge we receive it but don't use it yet
            }
            nilix_syz_qemu::ExecutionResult::Crash(info) => {
                state.stats.crashes += 1;
                eprintln!("[!] CRASH: {}", info.classification);
                eprintln!("Serial log (last 1KB):");
                eprintln!("{}", truncate_log(&info.serial_log, 1024));
                panic!("Kernel crash detected: {}", info.classification);
            }
            nilix_syz_qemu::ExecutionResult::Timeout => {
                state.stats.timeouts += 1;
            }
            nilix_syz_qemu::ExecutionResult::Hang => {
                state.stats.timeouts += 1;
            }
        },
        Err(e) => {
            eprintln!("[!] Execution error: {:#}", e);
        }
    }

    // Report stats every 100 iterations
    if state.stats.iterations % 100 == 0 {
        eprintln!(
            "[*] Iterations: {}, Successes: {}, Crashes: {}, Timeouts: {}, Parse failures: {}",
            state.stats.iterations,
            state.stats.successes,
            state.stats.crashes,
            state.stats.timeouts,
            state.stats.parse_failures
        );
    }
});

fn init_executor() -> anyhow::Result<QemuFuzzerState> {
    use anyhow::Context;
    use std::path::PathBuf;

    // Locate KCOV kernel (relative to project root, one level up from fuzz/)
    let kernel_path = PathBuf::from("../esp-kcov/kernel.elf");
    if !kernel_path.exists() {
        anyhow::bail!(
            "KCOV kernel not found at {}. Run: make build-kcov",
            kernel_path.display()
        );
    }

    // Initialize executor with short timeout for fuzzing
    let qemu_path = PathBuf::from("qemu-system-x86_64");
    let executor = nilix_syz_qemu::QemuExecutor::new(
        &qemu_path,
        &kernel_path,
        None, // Auto-detect OVMF
        10,   // 10-second timeout per program
        16,   // 16 MiB disk
        nilix_syz_qemu::Ext3Tools::default(),
    )
    .context("Failed to create QEMU executor")?;

    Ok(QemuFuzzerState {
        executor,
        stats: FuzzStats {
            iterations: 0,
            successes: 0,
            crashes: 0,
            timeouts: 0,
            parse_failures: 0,
        },
    })
}

fn parse_fuzzer_input(data: &[u8]) -> anyhow::Result<nilix_syz_qemu::SyscallProgram> {
    use anyhow::Context;

    // Minimum: 1 byte for syscall count
    if data.is_empty() {
        anyhow::bail!("Input too short");
    }

    let syscall_count = (data[0] as usize).min(10); // Limit to 10 syscalls for speed
    if syscall_count == 0 {
        anyhow::bail!("Zero syscalls");
    }

    let mut offset = 1;
    let mut program = nilix_syz_qemu::SyscallProgram::new();

    for _ in 0..syscall_count {
        if offset + 8 > data.len() {
            break;
        }

        // Parse syscall number (1 byte) + arg count (1 byte)
        let syscall_num = u32::from(data[offset]);
        let arg_count = (data[offset + 1] as usize).min(6);
        offset += 2;

        // Map libfuzzer syscall numbers to safe allowlisted syscalls
        let safe_syscall = map_to_safe_syscall(syscall_num);

        let mut args = Vec::new();
        for _ in 0..arg_count {
            if offset + 8 > data.len() {
                break;
            }

            let arg_type = data[offset] % 4; // 4 argument types
            offset += 1;

            let arg = match arg_type {
                0 => {
                    // Immediate value
                    if offset + 8 > data.len() {
                        break;
                    }
                    let val = u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
                    offset += 8;
                    nilix_syz_qemu::Argument::Immediate(val)
                }
                1 => {
                    // Null
                    nilix_syz_qemu::Argument::Null
                }
                2 => {
                    // Buffer (read-only input)
                    let len = ((data.get(offset).copied().unwrap_or(0) as usize) + 1).min(256);
                    offset += 1;
                    let buf_data: Vec<u8> = data
                        .get(offset..offset + len)
                        .unwrap_or(&[0u8; 1])
                        .to_vec();
                    offset += len.min(data.len() - offset);
                    nilix_syz_qemu::Argument::Buffer(buf_data)
                }
                3 => {
                    // Output buffer
                    let capacity = ((data.get(offset).copied().unwrap_or(0) as u32) + 1).min(256);
                    offset += 1;
                    nilix_syz_qemu::Argument::Output { capacity }
                }
                _ => nilix_syz_qemu::Argument::Null,
            };

            args.push(arg);
        }

        let syscall = nilix_syz_qemu::Syscall {
            number: safe_syscall,
            args,
        };

        // Validate and add syscall
        if program.add_syscall(syscall).is_err() {
            break;
        }
    }

    program.validate().context("Invalid program")?;
    Ok(program)
}

fn map_to_safe_syscall(raw: u32) -> u32 {
    // Map arbitrary input to expanded syscall allowlist covering:
    // - Process/user info (original safe syscalls)
    // - File I/O operations (read-only and controlled write operations)
    // - Memory management (mmap, munmap, mprotect, brk)
    // - IPC operations (pipe, select, poll)

    let safe_syscalls = [
        // === File I/O (9 syscalls) ===
        0,   // read - read from file descriptor
        1,   // write - write to file descriptor
        2,   // open - open files
        3,   // close - close file descriptor
        4,   // stat - file status
        5,   // fstat - file status by fd
        6,   // lstat - file status (no symlink follow)
        8,   // lseek - reposition read/write offset
        17,  // pread64 - positioned read
        18,  // pwrite64 - positioned write

        // === Memory Management (4 syscalls) ===
        9,   // mmap - map memory
        10,  // mprotect - change memory protection
        11,  // munmap - unmap memory
        12,  // brk - change data segment size

        // === IPC Operations (4 syscalls) ===
        22,  // pipe - create pipe
        23,  // select - I/O multiplexing
        7,   // poll - wait for events on file descriptors
        53,  // socketpair - create connected socket pair

        // === Process/User Info (19 syscalls - original safe set) ===
        21,  // access - check file accessibility
        24,  // sched_yield - yield CPU
        39,  // getpid - get process ID
        63,  // uname - system information
        79,  // getcwd - get current working directory
        96,  // gettimeofday - get time of day
        97,  // getrlimit - get resource limits
        98,  // getrusage - get resource usage
        102, // getuid - get user ID
        104, // getgid - get group ID
        107, // geteuid - get effective user ID
        108, // getegid - get effective group ID
        110, // getppid - get parent process ID
        111, // getpgrp - get process group ID
        121, // getpgid - get process group ID by PID
        124, // getsid - get session ID
        186, // gettid - get thread ID
        204, // sched_getaffinity - get CPU affinity mask
        228, // clock_gettime - get high-resolution time
        318, // getrandom - get random bytes

        // === Time Operations (2 syscalls) ===
        35,  // nanosleep - high-resolution sleep
        37,  // alarm - set alarm clock
    ];

    safe_syscalls[raw as usize % safe_syscalls.len()]
}

fn truncate_log(log: &str, max_bytes: usize) -> &str {
    if log.len() <= max_bytes {
        log
    } else {
        &log[log.len() - max_bytes..]
    }
}

// Re-export types from the qemu_executor module
mod nilix_syz_qemu {
    pub use nilix_fuzz::qemu_executor::{
        Argument, ExecutionResult, Ext3Tools, QemuExecutor, Syscall, SyscallProgram,
    };
}
