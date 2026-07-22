// Resource-aware syscall sequence generator
// Generates valid syscall sequences respecting resource dependencies

#![allow(dead_code)]

extern crate alloc;
use alloc::vec::Vec;
use alloc::string::String;

use super::resources::{ResourceTracker, ResourceType};
use super::constraints::{ConstraintTable, ArgConstraintType};
use super::mutator::Xorshift64;

/// Syscall representation with arguments
#[derive(Debug, Clone)]
pub struct Syscall {
    pub number: usize,
    pub args: [usize; 6],
}

/// Resource-aware syscall generator
pub struct ResourceAwareGenerator {
    tracker: ResourceTracker,
    constraints: ConstraintTable,
    prng: Xorshift64,
}

impl ResourceAwareGenerator {
    pub fn new(seed: u64) -> Self {
        Self {
            tracker: ResourceTracker::new(),
            constraints: ConstraintTable::new(),
            prng: Xorshift64::new(seed),
        }
    }

    pub fn set_iteration(&mut self, iter: usize) {
        self.tracker.set_iteration(iter);
    }

    /// Generate a valid syscall considering current resources
    pub fn generate_valid_syscall(&mut self) -> Option<Syscall> {
        // Get all syscalls that can be executed
        let executable = self.constraints.get_executable_syscalls(&self.tracker);

        if executable.is_empty() {
            // No syscalls can execute, generate a creator syscall
            return self.generate_creator_syscall();
        }

        // Randomly select an executable syscall
        let idx = (self.prng.next() as usize) % executable.len();
        let syscall_num = executable[idx];

        // Generate arguments for this syscall
        let args = self.generate_args(syscall_num);

        // Update tracker with resource changes
        self.update_tracker(syscall_num, &args);

        Some(Syscall {
            number: syscall_num,
            args,
        })
    }

    /// Generate a syscall that creates resources
    fn generate_creator_syscall(&mut self) -> Option<Syscall> {
        // Prefer creating fds (open) when no resources exist
        let syscall_num = 2;  // SYS_OPEN
        let args = self.generate_args(syscall_num);

        // Simulate fd creation
        let fd = 3;
        self.tracker.create_fd(fd, true, true);

        Some(Syscall {
            number: syscall_num,
            args,
        })
    }

    /// Generate arguments for a syscall
    fn generate_args(&mut self, syscall_num: usize) -> [usize; 6] {
        let mut args = [0usize; 6];

        let constraint = match self.constraints.get(syscall_num) {
            Some(c) => c,
            None => return args,
        };

        // Fill arguments based on constraints
        for arg_constraint in &constraint.arg_constraints {
            let idx = arg_constraint.arg_index;
            if idx >= 6 {
                continue;
            }

            args[idx] = match arg_constraint.constraint_type {
                ArgConstraintType::MustBeFd |
                ArgConstraintType::MustBeReadableFd |
                ArgConstraintType::MustBeWritableFd => {
                    // Use a valid fd from tracker
                    self.tracker.get_random_fd(&mut self.prng).unwrap_or(3)
                }
                ArgConstraintType::MustBeMappedAddress => {
                    // Use a valid mapped address
                    self.tracker.get_random_memory(&mut self.prng).unwrap_or(0x7f00_0000)
                }
                ArgConstraintType::MustBeUnmappedAddress => {
                    // Return an unmapped address
                    0x7f00_0000 + (self.prng.next() as usize % 0x1000_0000)
                }
                ArgConstraintType::MustBeValidPort => {
                    // Return a free port
                    (self.prng.next() as u16 % 60000 + 1024) as usize
                }
                ArgConstraintType::MustBeValidPid => {
                    // Use a valid pid from tracker
                    let pids = self.tracker.get_all_pids();
                    if pids.is_empty() {
                        1234
                    } else {
                        let idx = (self.prng.next() as usize) % pids.len();
                        pids[idx]
                    }
                }
                ArgConstraintType::MustBeBuffer => {
                    // Return a fake buffer address
                    0x600000
                }
                ArgConstraintType::MustBePath => {
                    // Return a fake path pointer
                    0x500000
                }
            };
        }

        // Fill remaining arguments with syscall-specific values
        match syscall_num {
            0 => {  // read(fd, buf, count)
                args[1] = 0x600000;  // buffer
                args[2] = 64;  // count
            }
            1 => {  // write(fd, buf, count)
                args[1] = 0x600000;  // buffer
                args[2] = 64;  // count
            }
            2 => {  // open(path, flags, mode)
                args[0] = 0x500000;  // path
                args[1] = 2;  // O_RDWR
                args[2] = 0o644;  // mode
            }
            9 => {  // mmap(addr, len, prot, flags, fd, offset)
                args[0] = 0;  // NULL (let kernel choose)
                args[1] = 4096;  // length
                args[2] = 3;  // PROT_READ | PROT_WRITE
                args[3] = 0x22;  // MAP_PRIVATE | MAP_ANONYMOUS
                args[4] = usize::MAX;  // -1 (no fd)
                args[5] = 0;  // offset
            }
            11 => {  // munmap(addr, len)
                args[1] = 4096;  // length
            }
            12 => {  // brk(addr)
                args[0] = self.prng.next() as usize & 0xffff_f000;
            }
            _ => {
                // Default random values for other syscalls
                for i in 0..6 {
                    if args[i] == 0 {
                        args[i] = self.prng.next() as usize % 1024;
                    }
                }
            }
        }

        args
    }

    /// Update resource tracker after syscall execution
    fn update_tracker(&mut self, syscall_num: usize, args: &[usize; 6]) {
        match syscall_num {
            2 => {  // open - creates fd
                let fd = 3;  // Simulated fd
                self.tracker.create_fd(fd, true, true);
            }
            3 => {  // close - destroys fd
                self.tracker.destroy_fd(args[0]);
            }
            9 => {  // mmap - creates memory
                let addr = 0x7f00_0000;  // Simulated address
                self.tracker.create_memory(addr, args[1], args[2] as u32);
            }
            11 => {  // munmap - destroys memory
                self.tracker.destroy_memory(args[0]);
            }
            57 => {  // fork - creates pid
                let pid = 1234;  // Simulated pid
                self.tracker.create_pid(pid);
            }
            60 => {  // exit - destroys self pid
                // Self pid destruction
            }
            _ => {
                // No resource changes
            }
        }
    }

    /// Generate cleanup sequence for all live resources
    pub fn generate_cleanup(&mut self) -> Vec<Syscall> {
        let mut cleanup = Vec::new();

        // Close all open fds
        for fd in self.tracker.get_all_fds() {
            cleanup.push(Syscall {
                number: 3,  // SYS_CLOSE
                args: [fd, 0, 0, 0, 0, 0],
            });
        }

        // Unmap all memory regions
        for addr in self.tracker.get_all_memory() {
            cleanup.push(Syscall {
                number: 11,  // SYS_MUNMAP
                args: [addr, 4096, 0, 0, 0, 0],
            });
        }

        cleanup
    }

    /// Check if there are resource leaks
    pub fn check_leaks(&self) -> Vec<ResourceLeak> {
        let mut leaks = Vec::new();

        // Check for unclosed fds
        for fd in self.tracker.get_all_fds() {
            if let Some(resource) = self.tracker.get_fd(fd) {
                leaks.push(ResourceLeak {
                    resource_type: ResourceType::FileDescriptor,
                    value: fd,
                    created_at: resource.created_at,
                });
            }
        }

        // Check for unmapped memory
        for addr in self.tracker.get_all_memory() {
            if let Some(resource) = self.tracker.get_memory(addr) {
                leaks.push(ResourceLeak {
                    resource_type: ResourceType::MemoryRegion,
                    value: addr,
                    created_at: resource.created_at,
                });
            }
        }

        leaks
    }

    /// Generate a complete valid sequence
    pub fn generate_sequence(&mut self, length: usize) -> Vec<Syscall> {
        let mut sequence = Vec::new();

        for _ in 0..length {
            if let Some(syscall) = self.generate_valid_syscall() {
                sequence.push(syscall);
            }
        }

        // Append cleanup
        let cleanup = self.generate_cleanup();
        sequence.extend(cleanup);

        sequence
    }

    /// Get current resource tracker
    pub fn tracker(&self) -> &ResourceTracker {
        &self.tracker
    }

    /// Clear tracker for new iteration
    pub fn clear_tracker(&mut self) {
        self.tracker.clear();
    }
}

/// Resource leak information
#[derive(Debug, Clone)]
pub struct ResourceLeak {
    pub resource_type: ResourceType,
    pub value: usize,
    pub created_at: usize,
}
