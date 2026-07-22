// Mutator engine for coverage-guided fuzzing
// Phase 4: Implements multiple mutation strategies

#![no_std]

extern crate alloc;
use alloc::vec::Vec;

use super::corpus::Syscall;

/// Interesting values for substitution
const INTERESTING_VALUES: &[u64] = &[
    0,
    1,
    u64::MAX,
    0x7fffffff,          // i32::MAX
    0x80000000,          // i32::MIN as u32
    0xffffffff,          // u32::MAX
    0x100000000,         // u32::MAX + 1
    4096,                // Page size
    8192,
    16384,
    65536,
    0x7fff,              // i16::MAX
    0x8000,              // i16::MIN as u16
    0xff,                // u8::MAX
    0x100,               // u8::MAX + 1
];

/// Mutation strategy
#[derive(Clone, Copy, Debug)]
pub enum MutationStrategy {
    BitFlip,
    Arithmetic,
    InterestingValue,
    InsertSyscall,
    DeleteSyscall,
    DuplicateSyscall,
    ReorderSyscalls,
}

pub struct Mutator {
    seed: u64,
}

impl Mutator {
    pub fn new(seed: u64) -> Self {
        Self { seed }
    }

    /// Mutate a syscall sequence
    pub fn mutate(&mut self, sequence: &[Syscall]) -> Vec<Syscall> {
        let mut mutated = sequence.to_vec();

        if mutated.is_empty() {
            // Generate random syscall if empty
            mutated.push(self.generate_random_syscall());
            return mutated;
        }

        // Apply 1-3 mutations
        let num_mutations = (self.rand() % 3) + 1;

        for _ in 0..num_mutations {
            let strategy = self.select_strategy();

            match strategy {
                MutationStrategy::BitFlip => self.mutate_bit_flip(&mut mutated),
                MutationStrategy::Arithmetic => self.mutate_arithmetic(&mut mutated),
                MutationStrategy::InterestingValue => self.mutate_interesting_value(&mut mutated),
                MutationStrategy::InsertSyscall => self.mutate_insert_syscall(&mut mutated),
                MutationStrategy::DeleteSyscall => self.mutate_delete_syscall(&mut mutated),
                MutationStrategy::DuplicateSyscall => self.mutate_duplicate_syscall(&mut mutated),
                MutationStrategy::ReorderSyscalls => self.mutate_reorder(&mut mutated),
            }
        }

        mutated
    }

    /// Select mutation strategy (weighted)
    fn select_strategy(&mut self) -> MutationStrategy {
        let choice = self.rand() % 100;

        match choice {
            0..=19 => MutationStrategy::BitFlip,           // 20%
            20..=39 => MutationStrategy::Arithmetic,       // 20%
            40..=59 => MutationStrategy::InterestingValue, // 20%
            60..=74 => MutationStrategy::InsertSyscall,    // 15%
            75..=84 => MutationStrategy::DeleteSyscall,    // 10%
            85..=94 => MutationStrategy::DuplicateSyscall, // 10%
            95..=99 => MutationStrategy::ReorderSyscalls,  // 5%
            _ => MutationStrategy::BitFlip,
        }
    }

    /// Bit flip mutation: flip random bit in random argument
    fn mutate_bit_flip(&mut self, sequence: &mut [Syscall]) {
        if sequence.is_empty() {
            return;
        }

        let syscall_idx = (self.rand() as usize) % sequence.len();
        let arg_idx = (self.rand() as usize) % 6;
        let bit_idx = (self.rand() as usize) % 64;

        sequence[syscall_idx].args[arg_idx] ^= 1u64 << bit_idx;
    }

    /// Arithmetic mutation: add/subtract small value
    fn mutate_arithmetic(&mut self, sequence: &mut [Syscall]) {
        if sequence.is_empty() {
            return;
        }

        let syscall_idx = (self.rand() as usize) % sequence.len();
        let arg_idx = (self.rand() as usize) % 6;
        let delta = ((self.rand() % 35) as i64) - 17;  // [-17, +17]

        sequence[syscall_idx].args[arg_idx] =
            sequence[syscall_idx].args[arg_idx].wrapping_add(delta as u64);
    }

    /// Interesting value mutation: replace with known interesting value
    fn mutate_interesting_value(&mut self, sequence: &mut [Syscall]) {
        if sequence.is_empty() {
            return;
        }

        let syscall_idx = (self.rand() as usize) % sequence.len();
        let arg_idx = (self.rand() as usize) % 6;
        let value_idx = (self.rand() as usize) % INTERESTING_VALUES.len();

        sequence[syscall_idx].args[arg_idx] = INTERESTING_VALUES[value_idx];
    }

    /// Insert syscall mutation: insert new random syscall
    fn mutate_insert_syscall(&mut self, sequence: &mut Vec<Syscall>) {
        let pos = (self.rand() as usize) % (sequence.len() + 1);
        let new_syscall = self.generate_random_syscall();
        sequence.insert(pos, new_syscall);

        // Limit sequence length to 10
        if sequence.len() > 10 {
            sequence.truncate(10);
        }
    }

    /// Delete syscall mutation: remove random syscall
    fn mutate_delete_syscall(&mut self, sequence: &mut Vec<Syscall>) {
        if sequence.len() > 1 {
            let pos = (self.rand() as usize) % sequence.len();
            sequence.remove(pos);
        }
    }

    /// Duplicate syscall mutation: duplicate existing syscall
    fn mutate_duplicate_syscall(&mut self, sequence: &mut Vec<Syscall>) {
        if sequence.is_empty() {
            return;
        }

        let src_pos = (self.rand() as usize) % sequence.len();
        let dst_pos = (self.rand() as usize) % (sequence.len() + 1);
        let syscall = sequence[src_pos].clone();
        sequence.insert(dst_pos, syscall);

        // Limit sequence length to 10
        if sequence.len() > 10 {
            sequence.truncate(10);
        }
    }

    /// Reorder mutation: swap two syscalls
    fn mutate_reorder(&mut self, sequence: &mut [Syscall]) {
        if sequence.len() < 2 {
            return;
        }

        let pos1 = (self.rand() as usize) % sequence.len();
        let pos2 = (self.rand() as usize) % sequence.len();
        sequence.swap(pos1, pos2);
    }

    /// Generate random syscall from safe subset
    fn generate_random_syscall(&mut self) -> Syscall {
        // Safe syscall pool (same as Phase 3 fuzzer)
        const SAFE_SYSCALLS: &[usize] = &[
            0,   // read
            1,   // write
            2,   // open
            12,  // brk
            9,   // mmap
            39,  // getpid
            110, // getppid
            102, // getuid
            107, // geteuid
            104, // getgid
            108, // getegid
        ];

        let syscall_num = SAFE_SYSCALLS[(self.rand() as usize) % SAFE_SYSCALLS.len()];

        // Generate arguments based on syscall
        let args = match syscall_num {
            0 => {
                // read(0, buf, 16)
                let buf = 0x1000 + (self.rand() % 0x10000);
                [0, buf, 16, 0, 0, 0]
            }
            1 => {
                // write(1, buf, len)
                let buf = 0x1000 + (self.rand() % 0x10000);
                let len = (self.rand() % 32) + 1;
                [1, buf, len, 0, 0, 0]
            }
            2 => {
                // open(path, flags, mode)
                let path = 0x2000 + (self.rand() % 0x1000);
                let flags = self.rand() % 4;  // O_RDONLY, O_WRONLY, O_RDWR
                [path, flags, 0, 0, 0, 0]
            }
            12 => {
                // brk(addr) - use 0 for query
                [0, 0, 0, 0, 0, 0]
            }
            9 => {
                // mmap(addr, len, prot, flags, fd, offset)
                let len = 4096 << ((self.rand() % 4) as usize);  // 4K, 8K, 16K, 32K
                let prot = 1;  // PROT_READ only (safe)
                let flags = 0x22;  // MAP_PRIVATE | MAP_ANONYMOUS
                [0, len, prot, flags, u64::MAX, 0]
            }
            _ => {
                // Query syscalls (no arguments)
                [0, 0, 0, 0, 0, 0]
            }
        };

        Syscall::new(syscall_num, args)
    }

    /// Simple PRNG (xorshift64)
    fn rand(&mut self) -> u64 {
        let mut x = self.seed;
        if x == 0 {
            x = 88172645463325252u64;
        }
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.seed = x;
        x
    }
}
