// Syscall dependency constraints for resource-aware fuzzing
// Defines what resources each syscall requires, creates, and destroys

#![allow(dead_code)]

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::resources::{ResourceType, ResourceTracker};

/// Dependencies that must be satisfied before executing a syscall
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dependency {
    FdMustExist,               // Syscall requires valid fd
    FdMustBeReadable,          // Syscall requires readable fd
    FdMustBeWritable,          // Syscall requires writable fd
    MemoryMustBeMapped,        // Syscall requires mapped memory
    MemoryMustBeUnmapped,      // Syscall requires unmapped memory
    PortMustBeFree,            // Syscall requires available port
    PidMustExist,              // Syscall requires valid process
}

/// Constraint specification for a syscall
#[derive(Debug, Clone)]
pub struct SyscallConstraint {
    pub name: &'static str,
    pub number: usize,
    pub creates: Vec<ResourceType>,     // Resources this syscall creates
    pub requires: Vec<Dependency>,      // Dependencies before execution
    pub destroys: Vec<ResourceType>,    // Resources this syscall destroys
    pub arg_constraints: Vec<ArgConstraint>,  // Constraints on specific arguments
}

/// Constraint on a specific syscall argument
#[derive(Debug, Clone)]
pub struct ArgConstraint {
    pub arg_index: usize,          // Which argument (0-indexed)
    pub constraint_type: ArgConstraintType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgConstraintType {
    MustBeFd,                      // Must be a valid fd
    MustBeReadableFd,              // Must be a readable fd
    MustBeWritableFd,              // Must be a writable fd
    MustBeMappedAddress,           // Must be a mapped memory address
    MustBeUnmappedAddress,         // Must be an unmapped address
    MustBeValidPort,               // Must be a free port
    MustBeValidPid,                // Must be a valid process ID
    MustBeBuffer,                  // Must be a valid buffer pointer
    MustBePath,                    // Must be a valid path string
}

impl SyscallConstraint {
    /// Check if this syscall can be executed given current resources
    pub fn can_execute(&self, tracker: &ResourceTracker) -> bool {
        for dep in &self.requires {
            match dep {
                Dependency::FdMustExist => {
                    if tracker.get_all_fds().is_empty() {
                        return false;
                    }
                }
                Dependency::FdMustBeReadable => {
                    if !tracker.get_all_fds().iter().any(|&fd| {
                        tracker.get_fd(fd).map_or(false, |r| r.is_readable())
                    }) {
                        return false;
                    }
                }
                Dependency::FdMustBeWritable => {
                    if !tracker.get_all_fds().iter().any(|&fd| {
                        tracker.get_fd(fd).map_or(false, |r| r.is_writable())
                    }) {
                        return false;
                    }
                }
                Dependency::MemoryMustBeMapped => {
                    if tracker.get_all_memory().is_empty() {
                        return false;
                    }
                }
                Dependency::MemoryMustBeUnmapped => {
                    // Always can find unmapped memory
                }
                Dependency::PortMustBeFree => {
                    // Always can find free port
                }
                Dependency::PidMustExist => {
                    if tracker.get_all_pids().is_empty() {
                        return false;
                    }
                }
            }
        }
        true
    }
}

/// Global constraint table for all syscalls
pub struct ConstraintTable {
    constraints: BTreeMap<usize, SyscallConstraint>,
}

impl ConstraintTable {
    pub fn new() -> Self {
        let mut table = Self {
            constraints: BTreeMap::new(),
        };
        table.init_constraints();
        table
    }

    /// Initialize constraints for all syscalls
    fn init_constraints(&mut self) {
        use alloc::vec;

        // SYS_READ (0)
        self.add(SyscallConstraint {
            name: "read",
            number: 0,
            creates: vec![],
            requires: vec![Dependency::FdMustExist, Dependency::FdMustBeReadable],
            destroys: vec![],
            arg_constraints: vec![
                ArgConstraint {
                    arg_index: 0,
                    constraint_type: ArgConstraintType::MustBeReadableFd,
                },
            ],
        });

        // SYS_WRITE (1)
        self.add(SyscallConstraint {
            name: "write",
            number: 1,
            creates: vec![],
            requires: vec![Dependency::FdMustExist, Dependency::FdMustBeWritable],
            destroys: vec![],
            arg_constraints: vec![
                ArgConstraint {
                    arg_index: 0,
                    constraint_type: ArgConstraintType::MustBeWritableFd,
                },
            ],
        });

        // SYS_OPEN (2)
        self.add(SyscallConstraint {
            name: "open",
            number: 2,
            creates: vec![ResourceType::FileDescriptor],
            requires: vec![],
            destroys: vec![],
            arg_constraints: vec![
                ArgConstraint {
                    arg_index: 0,
                    constraint_type: ArgConstraintType::MustBePath,
                },
            ],
        });

        // SYS_CLOSE (3)
        self.add(SyscallConstraint {
            name: "close",
            number: 3,
            creates: vec![],
            requires: vec![Dependency::FdMustExist],
            destroys: vec![ResourceType::FileDescriptor],
            arg_constraints: vec![
                ArgConstraint {
                    arg_index: 0,
                    constraint_type: ArgConstraintType::MustBeFd,
                },
            ],
        });

        // SYS_MMAP (9)
        self.add(SyscallConstraint {
            name: "mmap",
            number: 9,
            creates: vec![ResourceType::MemoryRegion],
            requires: vec![Dependency::MemoryMustBeUnmapped],
            destroys: vec![],
            arg_constraints: vec![],
        });

        // SYS_MUNMAP (11)
        self.add(SyscallConstraint {
            name: "munmap",
            number: 11,
            creates: vec![],
            requires: vec![Dependency::MemoryMustBeMapped],
            destroys: vec![ResourceType::MemoryRegion],
            arg_constraints: vec![
                ArgConstraint {
                    arg_index: 0,
                    constraint_type: ArgConstraintType::MustBeMappedAddress,
                },
            ],
        });

        // SYS_BRK (12)
        self.add(SyscallConstraint {
            name: "brk",
            number: 12,
            creates: vec![],
            requires: vec![],
            destroys: vec![],
            arg_constraints: vec![],
        });

        // SYS_FORK (57)
        self.add(SyscallConstraint {
            name: "fork",
            number: 57,
            creates: vec![ResourceType::ProcessId],
            requires: vec![],
            destroys: vec![],
            arg_constraints: vec![],
        });

        // SYS_EXECVE (59)
        self.add(SyscallConstraint {
            name: "execve",
            number: 59,
            creates: vec![],
            requires: vec![],
            destroys: vec![],
            arg_constraints: vec![
                ArgConstraint {
                    arg_index: 0,
                    constraint_type: ArgConstraintType::MustBePath,
                },
            ],
        });

        // SYS_EXIT (60)
        self.add(SyscallConstraint {
            name: "exit",
            number: 60,
            creates: vec![],
            requires: vec![],
            destroys: vec![ResourceType::ProcessId],
            arg_constraints: vec![],
        });

        // SYS_GETPID (39)
        self.add(SyscallConstraint {
            name: "getpid",
            number: 39,
            creates: vec![],
            requires: vec![],
            destroys: vec![],
            arg_constraints: vec![],
        });

        // SYS_GETPPID (110)
        self.add(SyscallConstraint {
            name: "getppid",
            number: 110,
            creates: vec![],
            requires: vec![],
            destroys: vec![],
            arg_constraints: vec![],
        });

        // SYS_GETUID (102)
        self.add(SyscallConstraint {
            name: "getuid",
            number: 102,
            creates: vec![],
            requires: vec![],
            destroys: vec![],
            arg_constraints: vec![],
        });

        // SYS_GETEUID (107)
        self.add(SyscallConstraint {
            name: "geteuid",
            number: 107,
            creates: vec![],
            requires: vec![],
            destroys: vec![],
            arg_constraints: vec![],
        });

        // SYS_GETGID (104)
        self.add(SyscallConstraint {
            name: "getgid",
            number: 104,
            creates: vec![],
            requires: vec![],
            destroys: vec![],
            arg_constraints: vec![],
        });

        // SYS_GETEGID (108)
        self.add(SyscallConstraint {
            name: "getegid",
            number: 108,
            creates: vec![],
            requires: vec![],
            destroys: vec![],
            arg_constraints: vec![],
        });
    }

    fn add(&mut self, constraint: SyscallConstraint) {
        self.constraints.insert(constraint.number, constraint);
    }

    /// Get constraint for a syscall number
    pub fn get(&self, syscall_num: usize) -> Option<&SyscallConstraint> {
        self.constraints.get(&syscall_num)
    }

    /// Get all syscalls that can be executed given current resources
    pub fn get_executable_syscalls(&self, tracker: &ResourceTracker) -> Vec<usize> {
        self.constraints
            .iter()
            .filter(|(_, constraint)| constraint.can_execute(tracker))
            .map(|(num, _)| *num)
            .collect()
    }

    /// Get all syscalls that create a specific resource type
    pub fn get_creators(&self, rtype: ResourceType) -> Vec<usize> {
        self.constraints
            .iter()
            .filter(|(_, constraint)| constraint.creates.contains(&rtype))
            .map(|(num, _)| *num)
            .collect()
    }

    /// Get all syscalls that destroy a specific resource type
    pub fn get_destroyers(&self, rtype: ResourceType) -> Vec<usize> {
        self.constraints
            .iter()
            .filter(|(_, constraint)| constraint.destroys.contains(&rtype))
            .map(|(num, _)| *num)
            .collect()
    }

    /// Check if a syscall sequence is valid
    pub fn validate_sequence(&self, syscalls: &[(usize, Vec<usize>)]) -> Result<(), ValidationError> {
        let mut tracker = ResourceTracker::new();

        for (idx, (syscall_num, args)) in syscalls.iter().enumerate() {
            let constraint = self.get(*syscall_num)
                .ok_or(ValidationError::UnknownSyscall(*syscall_num, idx))?;

            // Check dependencies
            if !constraint.can_execute(&tracker) {
                return Err(ValidationError::DependencyNotMet(
                    constraint.name,
                    idx,
                ));
            }

            // Validate arguments
            for arg_constraint in &constraint.arg_constraints {
                if arg_constraint.arg_index >= args.len() {
                    return Err(ValidationError::MissingArgument(
                        constraint.name,
                        arg_constraint.arg_index,
                        idx,
                    ));
                }

                let arg_value = args[arg_constraint.arg_index];
                match arg_constraint.constraint_type {
                    ArgConstraintType::MustBeFd |
                    ArgConstraintType::MustBeReadableFd |
                    ArgConstraintType::MustBeWritableFd => {
                        if !tracker.has_fd(arg_value) {
                            return Err(ValidationError::InvalidFd(arg_value, idx));
                        }
                        if arg_constraint.constraint_type == ArgConstraintType::MustBeReadableFd {
                            if let Some(res) = tracker.get_fd(arg_value) {
                                if !res.is_readable() {
                                    return Err(ValidationError::FdNotReadable(arg_value, idx));
                                }
                            }
                        }
                        if arg_constraint.constraint_type == ArgConstraintType::MustBeWritableFd {
                            if let Some(res) = tracker.get_fd(arg_value) {
                                if !res.is_writable() {
                                    return Err(ValidationError::FdNotWritable(arg_value, idx));
                                }
                            }
                        }
                    }
                    ArgConstraintType::MustBeMappedAddress => {
                        if !tracker.has_memory(arg_value) {
                            return Err(ValidationError::MemoryNotMapped(arg_value, idx));
                        }
                    }
                    _ => {
                        // Other constraints not validated here
                    }
                }
            }

            // Simulate resource changes
            self.simulate_execution(&mut tracker, *syscall_num, args, idx);
        }

        Ok(())
    }

    /// Simulate execution to update resource tracker
    fn simulate_execution(&self, tracker: &mut ResourceTracker, syscall_num: usize, args: &[usize], _idx: usize) {
        match syscall_num {
            2 => {  // open - creates fd
                let fd = 3;  // Assume fd=3 for simulation
                tracker.create_fd(fd, true, true);
            }
            3 => {  // close - destroys fd
                if !args.is_empty() {
                    tracker.destroy_fd(args[0]);
                }
            }
            9 => {  // mmap - creates memory
                let addr = 0x7f00_0000;  // Assume address
                tracker.create_memory(addr, 4096, 0x3);  // PROT_READ | PROT_WRITE
            }
            11 => {  // munmap - destroys memory
                if !args.is_empty() {
                    tracker.destroy_memory(args[0]);
                }
            }
            57 => {  // fork - creates pid
                let pid = 1234;  // Assume pid
                tracker.create_pid(pid);
            }
            _ => {
                // No resource changes for other syscalls
            }
        }
    }
}

/// Validation errors
#[derive(Debug)]
pub enum ValidationError {
    UnknownSyscall(usize, usize),  // syscall_num, position
    DependencyNotMet(&'static str, usize),  // syscall_name, position
    MissingArgument(&'static str, usize, usize),  // syscall_name, arg_index, position
    InvalidFd(usize, usize),  // fd, position
    FdNotReadable(usize, usize),  // fd, position
    FdNotWritable(usize, usize),  // fd, position
    MemoryNotMapped(usize, usize),  // address, position
}
