//! QEMU executor wrapper for cargo-fuzz integration
//!
//! This module re-exports the nilix-syz-fuzzer components and provides
//! a simplified interface for cargo-fuzz targets.

#[cfg(feature = "qemu-executor")]
pub use self::real::*;

#[cfg(not(feature = "qemu-executor"))]
pub use self::stub::*;

#[cfg(feature = "qemu-executor")]
mod real {
    // Re-export types from the standalone syzkaller fuzzer crate
    // These would normally come from userspace/nilix-syz-fuzzer
    // For now, we inline the minimal necessary types

    pub use anyhow::Result;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::time::Duration;

    #[derive(Clone, Debug)]
    pub struct QemuExecutor {
        qemu_path: PathBuf,
        kernel_path: PathBuf,
        timeout: Duration,
    }

    impl QemuExecutor {
        pub fn new(
            qemu_path: &Path,
            kernel_path: &Path,
            _ovmf_path: Option<&Path>,
            timeout_secs: u64,
            _disk_mib: u64,
            _tools: Ext3Tools,
        ) -> Result<Self> {
            Ok(Self {
                qemu_path: qemu_path.to_path_buf(),
                kernel_path: kernel_path.to_path_buf(),
                timeout: Duration::from_secs(timeout_secs),
            })
        }

        pub fn execute(&self, _program: &SyscallProgram) -> Result<ExecutionResult> {
            // TODO: Implement actual QEMU execution
            // For now, return a stub result
            Ok(ExecutionResult::Success(vec![1, 2, 3]))
        }
    }

    #[derive(Debug)]
    pub enum ExecutionResult {
        Success(Vec<u8>),
        Crash(CrashInfo),
        Timeout,
        Hang,
    }

    #[derive(Debug)]
    pub struct CrashInfo {
        pub classification: String,
        pub serial_log: String,
        pub qemu_stderr: String,
    }

    #[derive(Clone, Debug)]
    pub struct SyscallProgram {
        pub syscalls: Vec<Syscall>,
    }

    impl SyscallProgram {
        pub fn new() -> Self {
            Self { syscalls: Vec::new() }
        }

        pub fn add_syscall(&mut self, syscall: Syscall) -> Result<()> {
            if self.syscalls.len() >= 100 {
                anyhow::bail!("Too many syscalls");
            }
            self.syscalls.push(syscall);
            Ok(())
        }

        pub fn validate(&self) -> Result<()> {
            if self.syscalls.is_empty() {
                anyhow::bail!("Empty program");
            }
            Ok(())
        }
    }

    #[derive(Clone, Debug)]
    pub struct Syscall {
        pub number: u32,
        pub args: Vec<Argument>,
    }

    #[derive(Clone, Debug)]
    pub enum Argument {
        Immediate(u64),
        Null,
        Buffer(Vec<u8>),
        Output { capacity: u32 },
        InOut { data: Vec<u8>, capacity: u32 },
    }

    #[derive(Clone, Debug)]
    pub struct Ext3Tools;

    impl Default for Ext3Tools {
        fn default() -> Self {
            Self
        }
    }
}

#[cfg(not(feature = "qemu-executor"))]
mod stub {
    //! Stub implementation when qemu-executor feature is disabled

    use std::path::Path;

    pub struct QemuExecutor;

    impl QemuExecutor {
        pub fn new(
            _qemu_path: &Path,
            _kernel_path: &Path,
            _ovmf_path: Option<&Path>,
            _timeout_secs: u64,
            _disk_mib: u64,
            _tools: Ext3Tools,
        ) -> Result<Self, ()> {
            Err(())
        }

        pub fn execute(&self, _program: &SyscallProgram) -> Result<ExecutionResult, ()> {
            Err(())
        }
    }

    pub enum ExecutionResult {
        Success(Vec<u8>),
        Crash(CrashInfo),
        Timeout,
        Hang,
    }

    pub struct CrashInfo {
        pub classification: String,
        pub serial_log: String,
    }

    pub struct SyscallProgram;

    impl SyscallProgram {
        pub fn new() -> Self {
            Self
        }

        pub fn add_syscall(&mut self, _syscall: Syscall) -> Result<(), ()> {
            Ok(())
        }

        pub fn validate(&self) -> Result<(), ()> {
            Ok(())
        }
    }

    pub struct Syscall {
        pub number: u32,
        pub args: Vec<Argument>,
    }

    pub enum Argument {
        Immediate(u64),
        Null,
        Buffer(Vec<u8>),
        Output { capacity: u32 },
    }

    pub struct Ext3Tools;

    impl Default for Ext3Tools {
        fn default() -> Self {
            Self
        }
    }
}
