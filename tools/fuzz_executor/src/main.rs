//! Nilix Fuzzing Executor - Phase 2
//!
//! Simple executor that runs sequences of syscalls and measures coverage.
//!
//! # Architecture
//!
//! 1. Parent process reads syscall sequences
//! 2. Forks child process for isolation
//! 3. Child initializes KCOV and executes syscalls
//! 4. Parent collects coverage and crash status
//! 5. Results reported: OK/CRASH/TIMEOUT + edge count

use anyhow::{Context, Result};
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{fork, ForkResult, Pid};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::time::{Duration, Instant};

// Syscall numbers for KCOV
const SYS_KCOV_INIT: i64 = 520;
const SYS_KCOV_ENABLE: i64 = 521;
const SYS_KCOV_DISABLE: i64 = 522;
const SYS_KCOV_DUMP: i64 = 523;
const SYS_KCOV_RESET: i64 = 524;

// KCOV buffer size
const KCOV_BUFFER_SIZE: usize = 4096;

/// Represents a single syscall with arguments
#[derive(Debug, Clone)]
struct SyscallSpec {
    num: i64,
    args: [u64; 6],
}

impl SyscallSpec {
    /// Parse from a line: "syscall_num arg0 arg1 arg2 arg3 arg4 arg5"
    fn parse(line: &str) -> Result<Self> {
        let parts: Vec<&str> = line.split_whitespace().collect();

        if parts.is_empty() {
            anyhow::bail!("Empty line");
        }

        let num = if parts[0].starts_with("0x") {
            i64::from_str_radix(&parts[0][2..], 16).context("Failed to parse syscall number")?
        } else {
            parts[0]
                .parse::<i64>()
                .context("Failed to parse syscall number")?
        };

        let mut args = [0u64; 6];
        for (i, part) in parts.iter().skip(1).take(6).enumerate() {
            args[i] = if part.starts_with("0x") {
                u64::from_str_radix(&part[2..], 16).context(format!("Failed to parse arg{}", i))?
            } else {
                part.parse::<u64>()
                    .context(format!("Failed to parse arg{}", i))?
            };
        }

        Ok(SyscallSpec { num, args })
    }

    /// Execute this syscall
    unsafe fn execute(&self) -> i64 {
        syscall(
            self.num,
            self.args[0],
            self.args[1],
            self.args[2],
            self.args[3],
            self.args[4],
            self.args[5],
        )
    }
}

/// Outcome of executing a syscall sequence
#[derive(Debug)]
enum ExecutionResult {
    /// Completed successfully
    Ok { edge_count: usize, duration_us: u64 },
    /// Process crashed
    Crash { signal: Signal, duration_us: u64 },
    /// Exceeded timeout
    Timeout { duration_us: u64 },
    /// KCOV initialization failed
    KcovFailed { error: String },
}

/// Raw syscall wrapper
unsafe fn syscall(num: i64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> i64 {
    let ret: i64;
    std::arch::asm!(
        "syscall",
        in("rax") num,
        in("rdi") a0,
        in("rsi") a1,
        in("rdx") a2,
        in("r10") a3,
        in("r8") a4,
        in("r9") a5,
        lateout("rax") ret,
        options(nostack)
    );
    ret
}

/// Execute a sequence of syscalls in a child process
fn execute_sequence(sequence: &[SyscallSpec], timeout_ms: u64) -> Result<ExecutionResult> {
    let start = Instant::now();

    match unsafe { fork() }? {
        ForkResult::Parent { child } => {
            // Parent: wait for child with timeout
            let timeout = Duration::from_millis(timeout_ms);
            let deadline = start + timeout;

            loop {
                // Non-blocking wait
                match waitpid(child, Some(nix::sys::wait::WaitPidFlag::WNOHANG)) {
                    Ok(WaitStatus::Exited(_, code)) => {
                        let duration_us = start.elapsed().as_micros() as u64;

                        // Exit code is edge count (or negative errno)
                        if code >= 0 {
                            return Ok(ExecutionResult::Ok {
                                edge_count: code as usize,
                                duration_us,
                            });
                        } else {
                            return Ok(ExecutionResult::KcovFailed {
                                error: format!("Child exited with code {}", code),
                            });
                        }
                    }
                    Ok(WaitStatus::Signaled(_, signal, _)) => {
                        let duration_us = start.elapsed().as_micros() as u64;
                        return Ok(ExecutionResult::Crash {
                            signal,
                            duration_us,
                        });
                    }
                    Ok(WaitStatus::StillAlive) => {
                        // Check timeout
                        if Instant::now() >= deadline {
                            // Kill child
                            let _ = nix::sys::signal::kill(child, Signal::SIGKILL);
                            let _ = waitpid(child, None);

                            let duration_us = start.elapsed().as_micros() as u64;
                            return Ok(ExecutionResult::Timeout { duration_us });
                        }

                        // Sleep briefly
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Ok(_) => {
                        // Other status (stopped, continued)
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(e) => {
                        return Err(anyhow::anyhow!("waitpid failed: {}", e));
                    }
                }
            }
        }
        ForkResult::Child => {
            // Child: execute sequence
            unsafe {
                let exit_code = execute_sequence_child(sequence);
                libc::_exit(exit_code);
            }
        }
    }
}

/// Execute sequence in child (does not return)
unsafe fn execute_sequence_child(sequence: &[SyscallSpec]) -> i32 {
    // Step 1: Initialize KCOV
    let ret = syscall(SYS_KCOV_INIT, KCOV_BUFFER_SIZE as u64, 0, 0, 0, 0, 0);
    if ret < 0 {
        eprintln!("[CHILD] kcov_init failed: {}", ret);
        return -1;
    }

    // Step 2: Enable coverage
    let ret = syscall(SYS_KCOV_ENABLE, 0, 0, 0, 0, 0, 0);
    if ret < 0 {
        eprintln!("[CHILD] kcov_enable failed: {}", ret);
        return -2;
    }

    // Step 3: Execute all syscalls in sequence
    for (i, spec) in sequence.iter().enumerate() {
        let ret = spec.execute();
        // We don't check return values - fuzzing explores all paths
        // Even failing syscalls are interesting for coverage
        let _ = ret;
        let _ = i; // Suppress unused warning
    }

    // Step 4: Disable coverage
    let ret = syscall(SYS_KCOV_DISABLE, 0, 0, 0, 0, 0, 0);
    if ret < 0 {
        eprintln!("[CHILD] kcov_disable failed: {}", ret);
        return -3;
    }

    // Step 5: Dump coverage
    let mut coverage_buf = vec![0u8; KCOV_BUFFER_SIZE];
    let edge_count = syscall(
        SYS_KCOV_DUMP,
        coverage_buf.as_ptr() as u64,
        KCOV_BUFFER_SIZE as u64,
        0,
        0,
        0,
        0,
    );

    if edge_count < 0 {
        eprintln!("[CHILD] kcov_dump failed: {}", edge_count);
        return -4;
    }

    // Exit with edge count as exit code
    edge_count as i32
}

/// Load syscall sequence from file
fn load_sequence(path: &PathBuf) -> Result<Vec<SyscallSpec>> {
    let file = File::open(path).context(format!("Failed to open {}", path.display()))?;

    let reader = BufReader::new(file);
    let mut sequence = Vec::new();

    for (line_num, line) in reader.lines().enumerate() {
        let line = line?;
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        match SyscallSpec::parse(line) {
            Ok(spec) => sequence.push(spec),
            Err(e) => {
                eprintln!(
                    "Warning: Failed to parse line {}: {} (error: {})",
                    line_num + 1,
                    line,
                    e
                );
                // Continue parsing, don't fail on parse errors
            }
        }
    }

    if sequence.is_empty() {
        anyhow::bail!("No valid syscalls found in {}", path.display());
    }

    Ok(sequence)
}

/// Print execution result
fn print_result(path: &PathBuf, result: &ExecutionResult) {
    match result {
        ExecutionResult::Ok {
            edge_count,
            duration_us,
        } => {
            println!(
                "[OK] {} - {} edges in {}μs",
                path.display(),
                edge_count,
                duration_us
            );
        }
        ExecutionResult::Crash {
            signal,
            duration_us,
        } => {
            println!(
                "[CRASH] {} - signal {:?} after {}μs",
                path.display(),
                signal,
                duration_us
            );
        }
        ExecutionResult::Timeout { duration_us } => {
            println!(
                "[TIMEOUT] {} - exceeded limit at {}μs",
                path.display(),
                duration_us
            );
        }
        ExecutionResult::KcovFailed { error } => {
            println!("[KCOV_FAIL] {} - {}", path.display(), error);
        }
    }
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <sequence.txt> [timeout_ms]", args[0]);
        eprintln!();
        eprintln!("Examples:");
        eprintln!("  {} sequences/test1.txt", args[0]);
        eprintln!("  {} sequences/test1.txt 5000", args[0]);
        std::process::exit(1);
    }

    let sequence_path = PathBuf::from(&args[1]);
    let timeout_ms = if args.len() >= 3 {
        args[2].parse::<u64>().context("Invalid timeout value")?
    } else {
        5000 // Default 5 second timeout
    };

    println!("=== Nilix Fuzzing Executor - Phase 2 ===");
    println!("Sequence: {}", sequence_path.display());
    println!("Timeout: {}ms", timeout_ms);
    println!();

    // Load sequence
    let sequence = load_sequence(&sequence_path)?;
    println!("Loaded {} syscalls", sequence.len());

    // Execute
    let result = execute_sequence(&sequence, timeout_ms)?;
    print_result(&sequence_path, &result);

    Ok(())
}
