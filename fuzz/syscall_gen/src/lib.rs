//! Syscall argument generator for fuzzing
//!
//! Generates valid syscall arguments based on TOML descriptions

#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use alloc::string::String;

/// Syscall argument types
#[derive(Debug, Clone)]
pub enum ArgValue {
    I32(i32),
    U32(u32),
    Usize(usize),
    I64(i64),
    Ptr(usize),
    String(Vec<u8>),
    StringArray(Vec<Vec<u8>>),
}

/// A generated syscall with arguments
#[derive(Debug, Clone)]
pub struct GeneratedSyscall {
    pub number: usize,
    pub name: &'static str,
    pub args: Vec<ArgValue>,
}

/// Random number generator state (simple LCG)
pub struct Rng {
    state: u64,
}

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Generate next random u64
    pub fn next_u64(&mut self) -> u64 {
        // Linear congruential generator (simple but sufficient for fuzzing)
        self.state = self.state.wrapping_mul(6364136223846793005).wrapping_add(1);
        self.state
    }

    /// Generate random u32
    pub fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }

    /// Generate random usize
    pub fn next_usize(&mut self) -> usize {
        self.next_u64() as usize
    }

    /// Generate random value in range [min, max]
    pub fn range(&mut self, min: usize, max: usize) -> usize {
        if max <= min {
            return min;
        }
        let range = max - min + 1;
        min + (self.next_usize() % range)
    }

    /// Generate random i32 in range [min, max]
    pub fn range_i32(&mut self, min: i32, max: i32) -> i32 {
        if max <= min {
            return min;
        }
        let range = (max - min + 1) as u32;
        min + (self.next_u32() % range) as i32
    }

    /// Generate random boolean
    pub fn bool(&mut self) -> bool {
        (self.next_u32() & 1) == 1
    }
}

/// Syscall generator trait
pub trait SyscallGenerator {
    fn generate(&mut self, rng: &mut Rng) -> GeneratedSyscall;
}

/// Generate a syscall: read
pub struct ReadGenerator;

impl SyscallGenerator for ReadGenerator {
    fn generate(&mut self, rng: &mut Rng) -> GeneratedSyscall {
        let fd = rng.range_i32(0, 10);  // Focus on low fds (0=stdin, 1=stdout, 2=stderr)
        let buf_size = rng.range(1, 4096);

        GeneratedSyscall {
            number: 0,
            name: "read",
            args: alloc::vec![
                ArgValue::I32(fd),
                ArgValue::Ptr(0),  // Will be allocated by executor
                ArgValue::Usize(buf_size),
            ],
        }
    }
}

/// Generate a syscall: write
pub struct WriteGenerator;

impl SyscallGenerator for WriteGenerator {
    fn generate(&mut self, rng: &mut Rng) -> GeneratedSyscall {
        let fd = rng.range_i32(0, 10);
        let buf_size = rng.range(1, 4096);

        // Generate random buffer content
        let mut buf = Vec::new();
        for _ in 0..buf_size.min(256) {
            buf.push(rng.next_u32() as u8);
        }

        GeneratedSyscall {
            number: 1,
            name: "write",
            args: alloc::vec![
                ArgValue::I32(fd),
                ArgValue::String(buf),
                ArgValue::Usize(buf_size),
            ],
        }
    }
}

/// Generate a syscall: open
pub struct OpenGenerator;

impl SyscallGenerator for OpenGenerator {
    fn generate(&mut self, rng: &mut Rng) -> GeneratedSyscall {
        // Common file paths for testing
        let paths = [
            b"/dev/null\0",
            b"/tmp/test\0",
            b"/proc/self/maps\0",
            b".\0",
            b"..\0",
        ];

        let path_idx = rng.range(0, paths.len() - 1);
        let path = paths[path_idx].to_vec();

        // Generate flags: O_RDONLY=0, O_WRONLY=1, O_RDWR=2, O_CREAT=0x40, O_TRUNC=0x200
        let access_mode = rng.range_i32(0, 2);
        let mut flags = access_mode;

        if rng.bool() {
            flags |= 0x40;  // O_CREAT
        }
        if rng.bool() {
            flags |= 0x200; // O_TRUNC
        }

        let mode = 0o644u32;  // rw-r--r--

        GeneratedSyscall {
            number: 2,
            name: "open",
            args: alloc::vec![
                ArgValue::String(path),
                ArgValue::I32(flags),
                ArgValue::U32(mode),
            ],
        }
    }
}

/// Generate a syscall: close
pub struct CloseGenerator;

impl SyscallGenerator for CloseGenerator {
    fn generate(&mut self, rng: &mut Rng) -> GeneratedSyscall {
        let fd = rng.range_i32(0, 20);

        GeneratedSyscall {
            number: 3,
            name: "close",
            args: alloc::vec![ArgValue::I32(fd)],
        }
    }
}

/// Generate a syscall: brk
pub struct BrkGenerator;

impl SyscallGenerator for BrkGenerator {
    fn generate(&mut self, rng: &mut Rng) -> GeneratedSyscall {
        // Generate either 0 (query) or a page-aligned address
        let addr = if rng.bool() {
            0
        } else {
            let page = rng.range(1, 1024);
            page * 4096
        };

        GeneratedSyscall {
            number: 12,
            name: "brk",
            args: alloc::vec![ArgValue::Usize(addr)],
        }
    }
}

/// Generate a syscall: mmap
pub struct MmapGenerator;

impl SyscallGenerator for MmapGenerator {
    fn generate(&mut self, rng: &mut Rng) -> GeneratedSyscall {
        let addr = 0usize;  // Let kernel choose
        let length = rng.range(1, 64) * 4096;  // 4KB to 256KB

        // PROT flags: PROT_READ=1, PROT_WRITE=2, PROT_EXEC=4
        let mut prot = 0i32;
        if rng.bool() { prot |= 1; }  // PROT_READ
        if rng.bool() { prot |= 2; }  // PROT_WRITE

        // MAP flags: MAP_PRIVATE=0x02, MAP_ANONYMOUS=0x20
        let flags = 0x02 | 0x20;  // MAP_PRIVATE | MAP_ANONYMOUS
        let fd = -1i32;
        let offset = 0i64;

        GeneratedSyscall {
            number: 9,
            name: "mmap",
            args: alloc::vec![
                ArgValue::Usize(addr),
                ArgValue::Usize(length),
                ArgValue::I32(prot),
                ArgValue::I32(flags),
                ArgValue::I32(fd),
                ArgValue::I64(offset),
            ],
        }
    }
}

/// Generate a syscall: munmap
pub struct MunmapGenerator;

impl SyscallGenerator for MunmapGenerator {
    fn generate(&mut self, rng: &mut Rng) -> GeneratedSyscall {
        // Generate a plausible user-space address
        let page = rng.range(1, 1024);
        let addr = 0x400000 + page * 4096;
        let length = rng.range(1, 16) * 4096;

        GeneratedSyscall {
            number: 11,
            name: "munmap",
            args: alloc::vec![
                ArgValue::Usize(addr),
                ArgValue::Usize(length),
            ],
        }
    }
}

/// Generate a syscall: fork
pub struct ForkGenerator;

impl SyscallGenerator for ForkGenerator {
    fn generate(&mut self, _rng: &mut Rng) -> GeneratedSyscall {
        GeneratedSyscall {
            number: 57,
            name: "fork",
            args: alloc::vec![],
        }
    }
}

/// Generate a syscall: exit
pub struct ExitGenerator;

impl SyscallGenerator for ExitGenerator {
    fn generate(&mut self, rng: &mut Rng) -> GeneratedSyscall {
        let status = rng.range_i32(0, 255);

        GeneratedSyscall {
            number: 60,
            name: "exit",
            args: alloc::vec![ArgValue::I32(status)],
        }
    }
}
