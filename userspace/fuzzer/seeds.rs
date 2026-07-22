// Seed corpus for coverage-guided fuzzing
// Phase 4: Hand-crafted test cases to bootstrap fuzzer

#![no_std]

extern crate alloc;
use alloc::vec::Vec;
use alloc::vec;

use super::corpus::Syscall;

/// Get seed corpus
pub fn get_seeds() -> Vec<Vec<Syscall>> {
    vec![
        seed_simple_io(),
        seed_query_syscalls(),
        seed_memory_operations(),
        seed_file_operations(),
        seed_mixed_sequence(),
    ]
}

/// Seed 1: Simple I/O operations
fn seed_simple_io() -> Vec<Syscall> {
    vec![
        // write(1, "hello", 5)
        Syscall::new(1, [1, 0x2000, 5, 0, 0, 0]),
        // read(0, buf, 16)
        Syscall::new(0, [0, 0x3000, 16, 0, 0, 0]),
    ]
}

/// Seed 2: Query syscalls
fn seed_query_syscalls() -> Vec<Syscall> {
    vec![
        // getpid()
        Syscall::new(39, [0, 0, 0, 0, 0, 0]),
        // getuid()
        Syscall::new(102, [0, 0, 0, 0, 0, 0]),
        // getgid()
        Syscall::new(104, [0, 0, 0, 0, 0, 0]),
    ]
}

/// Seed 3: Memory operations
fn seed_memory_operations() -> Vec<Syscall> {
    vec![
        // brk(0) - query
        Syscall::new(12, [0, 0, 0, 0, 0, 0]),
        // mmap(0, 4096, PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
        Syscall::new(9, [0, 4096, 1, 0x22, u64::MAX, 0]),
    ]
}

/// Seed 4: File operations
fn seed_file_operations() -> Vec<Syscall> {
    vec![
        // open("/test", O_RDONLY, 0)
        Syscall::new(2, [0x4000, 0, 0, 0, 0, 0]),
        // close(3) - assume fd=3 from open
        Syscall::new(3, [3, 0, 0, 0, 0, 0]),
    ]
}

/// Seed 5: Mixed sequence
fn seed_mixed_sequence() -> Vec<Syscall> {
    vec![
        // getpid()
        Syscall::new(39, [0, 0, 0, 0, 0, 0]),
        // write(1, "test", 4)
        Syscall::new(1, [1, 0x5000, 4, 0, 0, 0]),
        // brk(0)
        Syscall::new(12, [0, 0, 0, 0, 0, 0]),
        // getuid()
        Syscall::new(102, [0, 0, 0, 0, 0, 0]),
    ]
}
