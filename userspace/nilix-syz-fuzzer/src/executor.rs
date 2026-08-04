use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;

use crate::program::SyscallProgram;

#[derive(Debug)]
pub enum ExecutionResult {
    Success(Vec<u8>),  // Coverage bitmap
    Crash(CrashInfo),
    Timeout,
    Hang,
}

#[derive(Debug)]
pub struct CrashInfo {
    pub classification: String,
    pub serial_log: String,
}

pub struct QemuExecutor {
    qemu_path: PathBuf,
    kernel_path: PathBuf,
    ovmf_path: Option<PathBuf>,
    timeout: Duration,
}

impl QemuExecutor {
    pub fn new(
        qemu_path: &Path,
        kernel_path: &Path,
        ovmf_path: Option<&Path>,
        timeout_secs: u64,
    ) -> Result<Self> {
        Ok(Self {
            qemu_path: qemu_path.to_path_buf(),
            kernel_path: kernel_path.to_path_buf(),
            ovmf_path: ovmf_path.map(|p| p.to_path_buf()),
            timeout: Duration::from_secs(timeout_secs),
        })
    }

    pub fn execute(&self, program: &SyscallProgram) -> Result<ExecutionResult> {
        // Create temporary directory for this execution
        let temp_dir = tempfile::tempdir()?;
        let input_file = temp_dir.path().join("program.bin");
        let serial_file = temp_dir.path().join("serial.log");
        let output_file = temp_dir.path().join("coverage.bin");

        // Serialize program to input file
        program.save_to_file(&input_file)?;

        // Determine OVMF path
        let ovmf = if let Some(ref path) = self.ovmf_path {
            path.clone()
        } else {
            self.find_ovmf()?
        };

        // Build QEMU command
        let esp_dir = self.kernel_path.parent()
            .context("Kernel path has no parent")?;

        let mut cmd = Command::new(&self.qemu_path);
        cmd.arg("-bios").arg(&ovmf)
            .arg("-drive").arg(format!("format=raw,file=fat:rw:{}", esp_dir.display()))
            .arg("-m").arg("512M")
            .arg("-smp").arg("1")
            .arg("-cpu").arg("qemu64,+smep,+smap,+umip,+rdrand")
            .arg("-serial").arg(format!("file:{}", serial_file.display()))
            .arg("-display").arg("none")
            .arg("-no-reboot")
            .arg("-no-shutdown")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        // Launch QEMU
        let mut child = cmd.spawn()
            .context("Failed to spawn QEMU")?;

        let pid = Pid::from_raw(child.id() as i32);

        // Wait with timeout
        let start = std::time::Instant::now();
        let result = loop {
            if let Some(_status) = child.try_wait()? {
                // Process exited
                let elapsed = start.elapsed();

                if elapsed < self.timeout {
                    // Early exit - likely a crash
                    let serial_log = std::fs::read_to_string(&serial_file)
                        .unwrap_or_default();

                    if self.is_crash(&serial_log) {
                        break ExecutionResult::Crash(CrashInfo {
                            classification: self.classify_crash(&serial_log),
                            serial_log,
                        });
                    } else if elapsed < Duration::from_secs(5) {
                        // Too fast - likely failed to boot
                        break ExecutionResult::Crash(CrashInfo {
                            classification: "boot_failure".to_string(),
                            serial_log,
                        });
                    } else {
                        // Normal completion - read coverage
                        if let Ok(coverage) = self.read_coverage(&output_file) {
                            break ExecutionResult::Success(coverage);
                        } else {
                            break ExecutionResult::Crash(CrashInfo {
                                classification: "no_coverage".to_string(),
                                serial_log,
                            });
                        }
                    }
                } else {
                    // Timeout reached
                    break ExecutionResult::Timeout;
                }
            }

            if start.elapsed() > self.timeout {
                // Kill QEMU
                let _ = kill(pid, Signal::SIGTERM);
                std::thread::sleep(Duration::from_millis(100));
                let _ = kill(pid, Signal::SIGKILL);
                let _ = child.wait();
                break ExecutionResult::Timeout;
            }

            std::thread::sleep(Duration::from_millis(100));
        };

        Ok(result)
    }

    fn find_ovmf(&self) -> Result<PathBuf> {
        let candidates = [
            "/usr/share/qemu/OVMF.fd",
            "/usr/share/ovmf/OVMF.fd",
            "/usr/share/OVMF/OVMF_CODE.fd",
        ];

        for path in &candidates {
            if Path::new(path).exists() {
                return Ok(PathBuf::from(path));
            }
        }

        // Try find command
        if let Ok(output) = Command::new("find")
            .args(&["/usr/share/OVMF", "-type", "f", "-name", "OVMF_CODE*.fd"])
            .output()
        {
            if let Ok(stdout) = String::from_utf8(output.stdout) {
                if let Some(line) = stdout.lines().next() {
                    if !line.is_empty() {
                        return Ok(PathBuf::from(line));
                    }
                }
            }
        }

        anyhow::bail!("OVMF firmware not found")
    }

    fn is_crash(&self, serial_log: &str) -> bool {
        serial_log.contains("KERNEL PANIC") ||
        serial_log.contains("kernel panicked") ||
        serial_log.contains("NILIX_SYZ_EXECUTOR_FAIL")
    }

    fn classify_crash(&self, serial_log: &str) -> String {
        if serial_log.contains("KERNEL PANIC") {
            "kernel_panic".to_string()
        } else if serial_log.contains("page fault") {
            "page_fault".to_string()
        } else if serial_log.contains("triple fault") {
            "triple_fault".to_string()
        } else if serial_log.contains("NILIX_SYZ_EXECUTOR_FAIL") {
            "executor_failure".to_string()
        } else {
            "unknown_crash".to_string()
        }
    }

    fn read_coverage(&self, path: &Path) -> Result<Vec<u8>> {
        if !path.exists() {
            // For now, return dummy coverage since guest executor isn't built yet
            return Ok(vec![0; 4096]);
        }
        Ok(std::fs::read(path)?)
    }
}
