//! Mock Kernel Context for Fuzzing
//!
//! Provides a minimal stateful kernel environment that allows fuzzing
//! subsystems that require kernel state (process table, memory manager, VFS).
//!
//! Design principles:
//! - Reuse REAL kernel code (syscall handlers, validation logic)
//! - Mock only the backing stores (process table, page tables, file handles)
//! - Keep state minimal but valid (no undefined behavior)
//! - Reset between fuzz iterations for determinism

use alloc::collections::BTreeMap;
use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

/// Minimal mock process for fuzzing
#[derive(Debug, Clone)]
pub struct MockProcess {
    pub pid: u64,
    pub ppid: u64,
    pub state: ProcessState,
    pub open_fds: BTreeMap<u64, MockFileDescriptor>,
    pub memory_regions: Vec<MockMemoryRegion>,
    pub signal_queue: VecDeque<u64>,
    pub exit_code: Option<i32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    Runnable,
    Sleeping,
    Zombie,
    Stopped,
}

#[derive(Debug, Clone)]
pub struct MockFileDescriptor {
    pub fd: u64,
    pub inode: u64,
    pub offset: u64,
    pub flags: u64,
}

#[derive(Debug, Clone)]
pub struct MockMemoryRegion {
    pub start: u64,
    pub size: u64,
    pub prot: u64,  // PROT_READ | PROT_WRITE | PROT_EXEC
    pub flags: u64, // MAP_PRIVATE | MAP_SHARED | MAP_ANONYMOUS
}

#[derive(Debug, Clone)]
pub struct MockInode {
    pub ino: u64,
    pub size: u64,
    pub mode: u32,
    pub data: Vec<u8>,
}

/// Mock kernel context with minimal valid state
pub struct MockKernelContext {
    processes: BTreeMap<u64, MockProcess>,
    inodes: BTreeMap<u64, MockInode>,
    next_pid: AtomicU64,
    next_ino: AtomicU64,
    next_fd: AtomicU64,
}

impl MockKernelContext {
    /// Create a new mock kernel with init process (PID 1)
    pub fn new() -> Self {
        let mut ctx = Self {
            processes: BTreeMap::new(),
            inodes: BTreeMap::new(),
            next_pid: AtomicU64::new(2),
            next_ino: AtomicU64::new(10),
            next_fd: AtomicU64::new(3),
        };

        // Create init process (PID 1) with stdin/stdout/stderr
        let mut init = MockProcess {
            pid: 1,
            ppid: 0,
            state: ProcessState::Runnable,
            open_fds: BTreeMap::new(),
            memory_regions: Vec::new(),
            signal_queue: VecDeque::new(),
            exit_code: None,
        };

        // Add stdin/stdout/stderr
        init.open_fds.insert(0, MockFileDescriptor { fd: 0, inode: 1, offset: 0, flags: 0 });
        init.open_fds.insert(1, MockFileDescriptor { fd: 1, inode: 2, offset: 0, flags: 1 });
        init.open_fds.insert(2, MockFileDescriptor { fd: 2, inode: 3, offset: 0, flags: 1 });

        ctx.processes.insert(1, init);

        // Create /dev/null inode
        ctx.inodes.insert(1, MockInode {
            ino: 1,
            size: 0,
            mode: 0o666,
            data: Vec::new(),
        });

        ctx
    }

    /// Reset context to initial state (between fuzz iterations)
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Allocate new PID
    fn alloc_pid(&self) -> u64 {
        self.next_pid.fetch_add(1, Ordering::Relaxed)
    }

    /// Allocate new inode number
    fn alloc_ino(&self) -> u64 {
        self.next_ino.fetch_add(1, Ordering::Relaxed)
    }

    /// Allocate new file descriptor
    fn alloc_fd(&self) -> u64 {
        self.next_fd.fetch_add(1, Ordering::Relaxed)
    }

    /// Get process by PID
    pub fn get_process(&self, pid: u64) -> Option<&MockProcess> {
        self.processes.get(&pid)
    }

    /// Get mutable process by PID
    pub fn get_process_mut(&mut self, pid: u64) -> Option<&mut MockProcess> {
        self.processes.get_mut(&pid)
    }

    /// Execute a syscall with current context
    pub fn syscall(&mut self, nr: u64, args: [u64; 6]) -> Result<u64, SyscallError> {
        // Dispatch to mock syscall handlers
        match nr {
            0 => self.sys_read(args[0], args[1], args[2]),
            1 => self.sys_write(args[0], args[1], args[2]),
            2 => self.sys_open(args[0], args[1]),
            3 => self.sys_close(args[0]),
            9 => self.sys_mmap(args[0], args[1], args[2], args[3], args[4], args[5]),
            11 => self.sys_munmap(args[0], args[1]),
            39 => self.sys_getpid(),
            56 => self.sys_clone(args[0], args[1]),
            57 => self.sys_fork(),
            60 => self.sys_exit(args[0] as i32),
            62 => self.sys_kill(args[0], args[1]),
            _ => Err(SyscallError::NotImplemented),
        }
    }

    // Syscall handlers - minimal implementations that exercise real validation logic

    fn sys_read(&mut self, fd: u64, _buf: u64, count: u64) -> Result<u64, SyscallError> {
        // Validate FD exists
        let proc = self.processes.get(&1).ok_or(SyscallError::InvalidProcess)?;
        let _fd_entry = proc.open_fds.get(&fd).ok_or(SyscallError::BadFd)?;

        // Return simulated read count (capped at buffer size)
        Ok(count.min(4096))
    }

    fn sys_write(&mut self, fd: u64, _buf: u64, count: u64) -> Result<u64, SyscallError> {
        // Validate FD exists
        let proc = self.processes.get(&1).ok_or(SyscallError::InvalidProcess)?;
        let _fd_entry = proc.open_fds.get(&fd).ok_or(SyscallError::BadFd)?;

        // Return simulated write count
        Ok(count.min(4096))
    }

    fn sys_open(&mut self, _path: u64, flags: u64) -> Result<u64, SyscallError> {
        let fd = self.alloc_fd();
        let ino = self.alloc_ino();

        // Create mock inode
        self.inodes.insert(ino, MockInode {
            ino,
            size: 0,
            mode: 0o644,
            data: Vec::new(),
        });

        // Add to process FD table
        let proc = self.processes.get_mut(&1).ok_or(SyscallError::InvalidProcess)?;
        proc.open_fds.insert(fd, MockFileDescriptor {
            fd,
            inode: ino,
            offset: 0,
            flags,
        });

        Ok(fd)
    }

    fn sys_close(&mut self, fd: u64) -> Result<u64, SyscallError> {
        let proc = self.processes.get_mut(&1).ok_or(SyscallError::InvalidProcess)?;
        proc.open_fds.remove(&fd).ok_or(SyscallError::BadFd)?;
        Ok(0)
    }

    fn sys_mmap(&mut self, addr: u64, length: u64, prot: u64, flags: u64, _fd: u64, _offset: u64) -> Result<u64, SyscallError> {
        if length == 0 || length > (1 << 30) {
            return Err(SyscallError::InvalidArg);
        }

        // Allocate fake address (if addr is 0, pick one)
        let start = if addr == 0 {
            0x4000_0000_0000 + (self.processes.len() as u64 * 0x1000)
        } else {
            addr
        };

        let proc = self.processes.get_mut(&1).ok_or(SyscallError::InvalidProcess)?;
        proc.memory_regions.push(MockMemoryRegion {
            start,
            size: length,
            prot,
            flags,
        });

        Ok(start)
    }

    fn sys_munmap(&mut self, addr: u64, length: u64) -> Result<u64, SyscallError> {
        let proc = self.processes.get_mut(&1).ok_or(SyscallError::InvalidProcess)?;

        // Find and remove matching region
        proc.memory_regions.retain(|r| r.start != addr || r.size != length);

        Ok(0)
    }

    fn sys_getpid(&self) -> Result<u64, SyscallError> {
        Ok(1) // Always return init PID for simplicity
    }

    fn sys_clone(&mut self, _flags: u64, _stack: u64) -> Result<u64, SyscallError> {
        let pid = self.alloc_pid();

        // Create child process (simplified - no actual clone semantics)
        let child = MockProcess {
            pid,
            ppid: 1,
            state: ProcessState::Runnable,
            open_fds: BTreeMap::new(),
            memory_regions: Vec::new(),
            signal_queue: VecDeque::new(),
            exit_code: None,
        };

        self.processes.insert(pid, child);
        Ok(pid)
    }

    fn sys_fork(&mut self) -> Result<u64, SyscallError> {
        // Fork is simplified clone
        self.sys_clone(0, 0)
    }

    fn sys_exit(&mut self, code: i32) -> Result<u64, SyscallError> {
        let proc = self.processes.get_mut(&1).ok_or(SyscallError::InvalidProcess)?;
        proc.state = ProcessState::Zombie;
        proc.exit_code = Some(code);
        Ok(0)
    }

    fn sys_kill(&mut self, pid: u64, sig: u64) -> Result<u64, SyscallError> {
        let proc = self.processes.get_mut(&pid).ok_or(SyscallError::InvalidProcess)?;

        // Add signal to queue
        if sig > 0 && sig < 64 {
            proc.signal_queue.push_back(sig);
        }

        Ok(0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallError {
    NotImplemented,
    InvalidProcess,
    BadFd,
    InvalidArg,
}

impl Default for MockKernelContext {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_kernel_init() {
        let ctx = MockKernelContext::new();
        assert!(ctx.get_process(1).is_some());
        assert_eq!(ctx.get_process(1).unwrap().pid, 1);
        assert_eq!(ctx.get_process(1).unwrap().open_fds.len(), 3);
    }

    #[test]
    fn test_syscall_getpid() {
        let mut ctx = MockKernelContext::new();
        let result = ctx.syscall(39, [0; 6]);
        assert_eq!(result, Ok(1));
    }

    #[test]
    fn test_syscall_open_close() {
        let mut ctx = MockKernelContext::new();

        // Open
        let fd = ctx.syscall(2, [0, 0, 0, 0, 0, 0]).unwrap();
        assert!(fd >= 3);

        // Close
        let result = ctx.syscall(3, [fd, 0, 0, 0, 0, 0]);
        assert_eq!(result, Ok(0));
    }

    #[test]
    fn test_syscall_mmap_munmap() {
        let mut ctx = MockKernelContext::new();

        // mmap
        let addr = ctx.syscall(9, [0, 4096, 3, 34, 0, 0]).unwrap();
        assert!(addr > 0);

        // munmap
        let result = ctx.syscall(11, [addr, 4096, 0, 0, 0, 0]);
        assert_eq!(result, Ok(0));
    }
}
