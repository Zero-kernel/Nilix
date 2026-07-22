// Resource-aware mutation strategies
// Mutates syscall sequences while preserving resource validity

#![allow(dead_code)]

extern crate alloc;
use alloc::vec::Vec;

use super::generator::Syscall;
use super::resources::ResourceTracker;
use super::constraints::ConstraintTable;
use super::mutator::Xorshift64;

/// Resource-aware mutator
pub struct ResourceAwareMutator {
    constraints: ConstraintTable,
    prng: Xorshift64,
}

impl ResourceAwareMutator {
    pub fn new(seed: u64) -> Self {
        Self {
            constraints: ConstraintTable::new(),
            prng: Xorshift64::new(seed),
        }
    }

    /// Mutate a syscall sequence while preserving resource validity
    pub fn mutate_preserving_resources(&mut self, sequence: &[Syscall]) -> Vec<Syscall> {
        if sequence.is_empty() {
            return Vec::new();
        }

        // Choose mutation strategy
        let strategy = (self.prng.next() % 7) as usize;

        match strategy {
            0 => self.mutate_bit_flip(sequence),
            1 => self.mutate_arithmetic(sequence),
            2 => self.mutate_interesting(sequence),
            3 => self.mutate_insert(sequence),
            4 => self.mutate_delete(sequence),
            5 => self.mutate_duplicate(sequence),
            6 => self.mutate_reorder(sequence),
            _ => sequence.to_vec(),
        }
    }

    /// Bit flip mutation with resource validation
    fn mutate_bit_flip(&mut self, sequence: &[Syscall]) -> Vec<Syscall> {
        let mut result = sequence.to_vec();
        if result.is_empty() {
            return result;
        }

        let idx = (self.prng.next() as usize) % result.len();
        let arg_idx = (self.prng.next() as usize) % 6;
        let bit_pos = (self.prng.next() as usize) % 64;

        result[idx].args[arg_idx] ^= 1 << bit_pos;

        // Validate and fix
        self.fix_sequence(&mut result);
        result
    }

    /// Arithmetic mutation with resource validation
    fn mutate_arithmetic(&mut self, sequence: &[Syscall]) -> Vec<Syscall> {
        let mut result = sequence.to_vec();
        if result.is_empty() {
            return result;
        }

        let idx = (self.prng.next() as usize) % result.len();
        let arg_idx = (self.prng.next() as usize) % 6;
        let delta = (self.prng.next() as i32 % 35) - 17;

        result[idx].args[arg_idx] = result[idx].args[arg_idx].wrapping_add(delta as usize);

        // Validate and fix
        self.fix_sequence(&mut result);
        result
    }

    /// Interesting value mutation with resource validation
    fn mutate_interesting(&mut self, sequence: &[Syscall]) -> Vec<Syscall> {
        let mut result = sequence.to_vec();
        if result.is_empty() {
            return result;
        }

        let interesting_values = [
            0, 1, usize::MAX, usize::MAX - 1,
            4096, 0x1000, 0xffff, 0x10000,
        ];

        let idx = (self.prng.next() as usize) % result.len();
        let arg_idx = (self.prng.next() as usize) % 6;
        let val_idx = (self.prng.next() as usize) % interesting_values.len();

        result[idx].args[arg_idx] = interesting_values[val_idx];

        // Validate and fix
        self.fix_sequence(&mut result);
        result
    }

    /// Insert syscall mutation
    fn mutate_insert(&mut self, sequence: &[Syscall]) -> Vec<Syscall> {
        let mut result = sequence.to_vec();

        if result.len() >= 10 {
            return result;  // Max length
        }

        let insert_pos = if result.is_empty() {
            0
        } else {
            (self.prng.next() as usize) % (result.len() + 1)
        };

        // Generate a new syscall (simple for now)
        let safe_syscalls = [39, 102, 104, 107, 108, 110];  // getpid, getuid, etc.
        let syscall_num = safe_syscalls[(self.prng.next() as usize) % safe_syscalls.len()];

        result.insert(insert_pos, Syscall {
            number: syscall_num,
            args: [0; 6],
        });

        self.fix_sequence(&mut result);
        result
    }

    /// Delete syscall mutation
    fn mutate_delete(&mut self, sequence: &[Syscall]) -> Vec<Syscall> {
        let mut result = sequence.to_vec();

        if result.len() <= 1 {
            return result;  // Keep at least one syscall
        }

        let del_pos = (self.prng.next() as usize) % result.len();
        result.remove(del_pos);

        self.fix_sequence(&mut result);
        result
    }

    /// Duplicate syscall mutation
    fn mutate_duplicate(&mut self, sequence: &[Syscall]) -> Vec<Syscall> {
        let mut result = sequence.to_vec();

        if result.is_empty() || result.len() >= 10 {
            return result;
        }

        let dup_idx = (self.prng.next() as usize) % result.len();
        let insert_pos = (self.prng.next() as usize) % (result.len() + 1);

        let dup = result[dup_idx].clone();
        result.insert(insert_pos, dup);

        self.fix_sequence(&mut result);
        result
    }

    /// Reorder syscalls mutation
    fn mutate_reorder(&mut self, sequence: &[Syscall]) -> Vec<Syscall> {
        let mut result = sequence.to_vec();

        if result.len() < 2 {
            return result;
        }

        let idx1 = (self.prng.next() as usize) % result.len();
        let idx2 = (self.prng.next() as usize) % result.len();

        result.swap(idx1, idx2);

        self.fix_sequence(&mut result);
        result
    }

    /// Fix a sequence to make it resource-valid
    fn fix_sequence(&mut self, sequence: &mut Vec<Syscall>) {
        let mut tracker = ResourceTracker::new();

        // Track resources and fix invalid references
        for i in 0..sequence.len() {
            let syscall_num = sequence[i].number;

            if let Some(constraint) = self.constraints.get(syscall_num) {
                // Check and fix argument constraints
                for arg_constraint in &constraint.arg_constraints {
                    let arg_idx = arg_constraint.arg_index;
                    if arg_idx >= 6 {
                        continue;
                    }

                    let arg_value = sequence[i].args[arg_idx];

                    match arg_constraint.constraint_type {
                        super::constraints::ArgConstraintType::MustBeFd |
                        super::constraints::ArgConstraintType::MustBeReadableFd |
                        super::constraints::ArgConstraintType::MustBeWritableFd => {
                            // Check if fd is valid
                            if !tracker.has_fd(arg_value) {
                                // Try to find a valid fd
                                if let Some(valid_fd) = tracker.get_random_fd(&mut self.prng) {
                                    sequence[i].args[arg_idx] = valid_fd;
                                } else {
                                    // No valid fd, use default
                                    sequence[i].args[arg_idx] = 3;
                                    tracker.create_fd(3, true, true);
                                }
                            }
                        }
                        super::constraints::ArgConstraintType::MustBeMappedAddress => {
                            // Check if memory is mapped
                            if !tracker.has_memory(arg_value) {
                                // Try to find valid memory
                                if let Some(valid_addr) = tracker.get_random_memory(&mut self.prng) {
                                    sequence[i].args[arg_idx] = valid_addr;
                                } else {
                                    // No valid memory, use default
                                    sequence[i].args[arg_idx] = 0x7f00_0000;
                                    tracker.create_memory(0x7f00_0000, 4096, 3);
                                }
                            }
                        }
                        _ => {
                            // Other constraints not fixed here
                        }
                    }
                }

                // Update tracker with resource changes
                self.update_tracker(&mut tracker, syscall_num, &sequence[i].args);
            }
        }
    }

    /// Update resource tracker after simulating syscall
    fn update_tracker(&mut self, tracker: &mut ResourceTracker, syscall_num: usize, args: &[usize; 6]) {
        match syscall_num {
            2 => {  // open - creates fd
                let fd = 3;  // Simulated fd
                tracker.create_fd(fd, true, true);
            }
            3 => {  // close - destroys fd
                tracker.destroy_fd(args[0]);
            }
            9 => {  // mmap - creates memory
                let addr = 0x7f00_0000;  // Simulated address
                tracker.create_memory(addr, 4096, 3);
            }
            11 => {  // munmap - destroys memory
                tracker.destroy_memory(args[0]);
            }
            57 => {  // fork - creates pid
                let pid = 1234;  // Simulated pid
                tracker.create_pid(pid);
            }
            _ => {
                // No resource changes
            }
        }
    }

    /// Validate that sequence is resource-valid
    pub fn validate(&self, sequence: &[Syscall]) -> bool {
        // Convert to format expected by validator
        let seq: Vec<(usize, Vec<usize>)> = sequence
            .iter()
            .map(|s| (s.number, s.args.to_vec()))
            .collect();

        self.constraints.validate_sequence(&seq).is_ok()
    }
}
