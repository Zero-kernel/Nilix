//! Bridge to the standalone nilix-syz-fuzzer binary
//!
//! This module provides a lightweight interface to execute syscall programs
//! via the existing syzkaller-style fuzzer without duplicating 2000+ lines of code.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

#[cfg(feature = "qemu-executor")]
use anyhow::{bail, Context, Result};

#[cfg(feature = "qemu-executor")]
pub struct SyzBridge {
    fuzzer_bin: PathBuf,
    kernel_path: PathBuf,
    work_dir: PathBuf,
    timeout: Duration,
}

#[cfg(feature = "qemu-executor")]
impl SyzBridge {
    pub fn new(kernel_path: &Path, timeout_secs: u64) -> Result<Self> {
        let fuzzer_bin = PathBuf::from("userspace/nilix-syz-fuzzer/target/x86_64-unknown-linux-gnu/release/nilix-syz-fuzzer");

        if !fuzzer_bin.exists() {
            bail!(
                "Syzkaller fuzzer binary not found at {}. Build it with: make build-syz-fuzzer",
                fuzzer_bin.display()
            );
        }

        if !kernel_path.exists() {
            bail!("KCOV kernel not found at {}", kernel_path.display());
        }

        let work_dir = tempfile::Builder::new()
            .prefix("cargo-fuzz-syz-")
            .tempdir()
            .context("Failed to create work directory")?
            .into_path();

        Ok(Self {
            fuzzer_bin,
            kernel_path: kernel_path.to_path_buf(),
            work_dir,
            timeout: Duration::from_secs(timeout_secs),
        })
    }

    /// Execute a single syscall program and return coverage
    pub fn execute_program(&self, program_json: &str) -> Result<ExecutionResult> {
        // Write program to temp file
        let program_file = self.work_dir.join("program.json");
        std::fs::write(&program_file, program_json)
            .context("Failed to write program file")?;

        // Invoke fuzzer binary in single-shot mode
        let output = Command::new(&self.fuzzer_bin)
            .arg("--kernel")
            .arg(&self.kernel_path)
            .arg("--program")
            .arg(&program_file)
            .arg("--timeout")
            .arg(self.timeout.as_secs().to_string())
            .arg("--single-shot")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .context("Failed to execute syzkaller fuzzer")?;

        // Parse result from stdout
        self.parse_result(&output)
    }

    fn parse_result(&self, output: &std::process::Output) -> Result<ExecutionResult> {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        // Look for result markers in stdout
        if stdout.contains("RESULT: SUCCESS") {
            // Extract coverage hex string
            if let Some(cov_line) = stdout.lines().find(|line| line.starts_with("COVERAGE: ")) {
                let hex_str = cov_line.strip_prefix("COVERAGE: ").unwrap_or("");
                let coverage = hex::decode(hex_str)
                    .context("Invalid coverage hex string")?;
                return Ok(ExecutionResult::Success(coverage));
            }
            bail!("Success result but no coverage data");
        } else if stdout.contains("RESULT: CRASH") {
            let classification = stdout
                .lines()
                .find(|line| line.starts_with("CRASH: "))
                .map(|line| line.strip_prefix("CRASH: ").unwrap_or("unknown"))
                .unwrap_or("unknown")
                .to_string();

            return Ok(ExecutionResult::Crash(CrashInfo {
                classification,
                serial_log: stderr.to_string(),
                qemu_stderr: String::new(),
            }));
        } else if stdout.contains("RESULT: TIMEOUT") {
            return Ok(ExecutionResult::Timeout);
        } else if stdout.contains("RESULT: HANG") {
            return Ok(ExecutionResult::Hang);
        }

        bail!("Unknown execution result: {}", stdout);
    }
}

#[cfg(feature = "qemu-executor")]
#[derive(Debug)]
pub enum ExecutionResult {
    Success(Vec<u8>),
    Crash(CrashInfo),
    Timeout,
    Hang,
}

#[cfg(feature = "qemu-executor")]
#[derive(Debug)]
pub struct CrashInfo {
    pub classification: String,
    pub serial_log: String,
    pub qemu_stderr: String,
}

// Stub implementation when feature is disabled
#[cfg(not(feature = "qemu-executor"))]
pub struct SyzBridge;

#[cfg(not(feature = "qemu-executor"))]
impl SyzBridge {
    pub fn new(_kernel_path: &Path, _timeout_secs: u64) -> Result<Self, ()> {
        Err(())
    }

    pub fn execute_program(&self, _program_json: &str) -> Result<ExecutionResult, ()> {
        Err(())
    }
}

#[cfg(not(feature = "qemu-executor"))]
pub enum ExecutionResult {
    Success(Vec<u8>),
    Crash(CrashInfo),
    Timeout,
    Hang,
}

#[cfg(not(feature = "qemu-executor"))]
pub struct CrashInfo {
    pub classification: String,
    pub serial_log: String,
}

#[cfg(all(test, feature = "qemu-executor"))]
mod tests {
    use super::*;

    #[test]
    fn bridge_requires_prebuilt_fuzzer() {
        let kernel = PathBuf::from("esp-kcov/kernel.elf");
        if kernel.exists() {
            let bridge = SyzBridge::new(&kernel, 5);
            assert!(
                bridge.is_ok() || bridge.unwrap_err().to_string().contains("not found")
            );
        }
    }
}
