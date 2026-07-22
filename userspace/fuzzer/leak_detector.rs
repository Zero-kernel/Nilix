// Resource leak detection for fuzzing
// Detects never-closed resources, use-after-free, and double-free

#![allow(dead_code)]

extern crate alloc;
use alloc::vec::Vec;
use alloc::collections::BTreeMap;

use super::resources::{Resource, ResourceType};
use super::generator::Syscall;

/// Types of resource leaks
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeakType {
    NeverClosed,                // Resource created but never destroyed
    UsedAfterFree,             // Resource used after being destroyed
    DoubleFree,                // Resource destroyed twice
}

/// A detected resource leak
#[derive(Debug, Clone)]
pub struct ResourceLeak {
    pub resource_type: ResourceType,
    pub value: usize,               // fd number, address, port, pid
    pub leak_type: LeakType,
    pub created_at: usize,          // Iteration when created
    pub last_used: usize,           // Last time referenced
    pub destroyed_at: Option<usize>, // When destroyed (for use-after-free)
}

/// Resource operation for tracking
#[derive(Debug, Clone, Copy)]
enum ResourceOp {
    Create,
    Use,
    Destroy,
}

/// Tracks resource operations to detect leaks
pub struct LeakDetector {
    resources: BTreeMap<u32, Resource>,     // resource_id -> Resource
    operations: Vec<(usize, u32, ResourceOp)>,  // (iteration, resource_id, operation)
    iteration: usize,
}

impl LeakDetector {
    pub fn new() -> Self {
        Self {
            resources: BTreeMap::new(),
            operations: Vec::new(),
            iteration: 0,
        }
    }

    pub fn set_iteration(&mut self, iter: usize) {
        self.iteration = iter;
    }

    /// Track resource creation
    pub fn track_create(&mut self, resource: Resource) {
        let id = resource.id;
        self.resources.insert(id, resource);
        self.operations.push((self.iteration, id, ResourceOp::Create));
    }

    /// Track resource use
    pub fn track_use(&mut self, resource_id: u32) {
        self.operations.push((self.iteration, resource_id, ResourceOp::Use));
    }

    /// Track resource destruction
    pub fn track_destroy(&mut self, resource_id: u32) {
        self.operations.push((self.iteration, resource_id, ResourceOp::Destroy));
    }

    /// Detect all resource leaks in tracked operations
    pub fn detect_leaks(&self) -> Vec<ResourceLeak> {
        let mut leaks = Vec::new();

        // Build resource lifecycle map
        let mut lifecycles: BTreeMap<u32, ResourceLifecycle> = BTreeMap::new();

        for (iter, res_id, op) in &self.operations {
            let lifecycle = lifecycles.entry(*res_id).or_insert_with(|| ResourceLifecycle {
                resource_id: *res_id,
                created_at: None,
                last_used: None,
                destroyed_at: Vec::new(),
            });

            match op {
                ResourceOp::Create => {
                    lifecycle.created_at = Some(*iter);
                }
                ResourceOp::Use => {
                    lifecycle.last_used = Some(*iter);
                }
                ResourceOp::Destroy => {
                    lifecycle.destroyed_at.push(*iter);
                }
            }
        }

        // Analyze each resource lifecycle
        for (res_id, lifecycle) in &lifecycles {
            if let Some(resource) = self.resources.get(res_id) {
                // Check for never-closed resources
                if lifecycle.destroyed_at.is_empty() {
                    leaks.push(ResourceLeak {
                        resource_type: resource.rtype,
                        value: resource.value,
                        leak_type: LeakType::NeverClosed,
                        created_at: lifecycle.created_at.unwrap_or(0),
                        last_used: lifecycle.last_used.unwrap_or(lifecycle.created_at.unwrap_or(0)),
                        destroyed_at: None,
                    });
                }

                // Check for double-free
                if lifecycle.destroyed_at.len() > 1 {
                    leaks.push(ResourceLeak {
                        resource_type: resource.rtype,
                        value: resource.value,
                        leak_type: LeakType::DoubleFree,
                        created_at: lifecycle.created_at.unwrap_or(0),
                        last_used: lifecycle.last_used.unwrap_or(0),
                        destroyed_at: Some(lifecycle.destroyed_at[1]),
                    });
                }

                // Check for use-after-free
                if !lifecycle.destroyed_at.is_empty() {
                    let first_destroy = lifecycle.destroyed_at[0];
                    if let Some(last_use) = lifecycle.last_used {
                        if last_use > first_destroy {
                            leaks.push(ResourceLeak {
                                resource_type: resource.rtype,
                                value: resource.value,
                                leak_type: LeakType::UsedAfterFree,
                                created_at: lifecycle.created_at.unwrap_or(0),
                                last_used,
                                destroyed_at: Some(first_destroy),
                            });
                        }
                    }
                }
            }
        }

        leaks
    }

    /// Analyze a syscall sequence for leaks
    pub fn analyze_sequence(&mut self, sequence: &[Syscall]) -> Vec<ResourceLeak> {
        self.clear();

        // Simulate sequence and track operations
        let mut next_id = 1u32;
        let mut fd_map: BTreeMap<usize, u32> = BTreeMap::new();
        let mut mem_map: BTreeMap<usize, u32> = BTreeMap::new();

        for (iter, syscall) in sequence.iter().enumerate() {
            self.iteration = iter;

            match syscall.number {
                2 => {  // open - creates fd
                    let fd = 3;  // Simulated fd
                    let id = next_id;
                    next_id += 1;

                    let resource = Resource::new(id, ResourceType::FileDescriptor, fd, iter);
                    self.track_create(resource);
                    fd_map.insert(fd, id);
                }
                3 => {  // close - destroys fd
                    let fd = syscall.args[0];
                    if let Some(&id) = fd_map.get(&fd) {
                        self.track_destroy(id);
                        fd_map.remove(&fd);
                    }
                }
                0 | 1 => {  // read/write - uses fd
                    let fd = syscall.args[0];
                    if let Some(&id) = fd_map.get(&fd) {
                        self.track_use(id);
                    }
                }
                9 => {  // mmap - creates memory
                    let addr = 0x7f00_0000;  // Simulated address
                    let id = next_id;
                    next_id += 1;

                    let resource = Resource::new(id, ResourceType::MemoryRegion, addr, iter);
                    self.track_create(resource);
                    mem_map.insert(addr, id);
                }
                11 => {  // munmap - destroys memory
                    let addr = syscall.args[0];
                    if let Some(&id) = mem_map.get(&addr) {
                        self.track_destroy(id);
                        mem_map.remove(&addr);
                    }
                }
                _ => {
                    // Other syscalls don't affect resources we track
                }
            }
        }

        self.detect_leaks()
    }

    /// Clear all tracked data
    pub fn clear(&mut self) {
        self.resources.clear();
        self.operations.clear();
        self.iteration = 0;
    }

    /// Get statistics on tracked resources
    pub fn stats(&self) -> LeakStats {
        let mut stats = LeakStats {
            total_resources: self.resources.len(),
            total_operations: self.operations.len(),
            creates: 0,
            uses: 0,
            destroys: 0,
        };

        for (_, _, op) in &self.operations {
            match op {
                ResourceOp::Create => stats.creates += 1,
                ResourceOp::Use => stats.uses += 1,
                ResourceOp::Destroy => stats.destroys += 1,
            }
        }

        stats
    }
}

/// Resource lifecycle information
#[derive(Debug, Clone)]
struct ResourceLifecycle {
    resource_id: u32,
    created_at: Option<usize>,
    last_used: Option<usize>,
    destroyed_at: Vec<usize>,  // Can be destroyed multiple times (double-free)
}

/// Statistics on leak detection
#[derive(Debug, Clone, Copy)]
pub struct LeakStats {
    pub total_resources: usize,
    pub total_operations: usize,
    pub creates: usize,
    pub uses: usize,
    pub destroys: usize,
}
