// Resource tracking for resource-aware fuzzing
// Tracks fds, memory regions, ports, and process IDs

#![allow(dead_code)]

extern crate alloc;
use alloc::collections::BTreeMap;

/// Resource types that can be tracked
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ResourceType {
    FileDescriptor,
    MemoryRegion,
    EphemeralPort,
    ProcessId,
}

/// A tracked resource with metadata
#[derive(Debug, Clone)]
pub struct Resource {
    pub id: u32,                    // Unique resource ID (internal)
    pub rtype: ResourceType,        // Type of resource
    pub value: usize,               // Actual value (fd number, address, port, pid)
    pub created_at: usize,          // Iteration when created
    pub used_count: usize,          // How many times referenced
    pub properties: u32,            // Flags (readable, writable, etc.)
}

/// Property flags for resources
pub mod properties {
    pub const READABLE: u32 = 1 << 0;
    pub const WRITABLE: u32 = 1 << 1;
    pub const EXECUTABLE: u32 = 1 << 2;
    pub const ANONYMOUS: u32 = 1 << 3;  // For anonymous memory maps
}

impl Resource {
    pub fn new(id: u32, rtype: ResourceType, value: usize, iteration: usize) -> Self {
        Self {
            id,
            rtype,
            value,
            created_at: iteration,
            used_count: 0,
            properties: 0,
        }
    }

    pub fn with_properties(mut self, props: u32) -> Self {
        self.properties = props;
        self
    }

    pub fn is_readable(&self) -> bool {
        self.properties & properties::READABLE != 0
    }

    pub fn is_writable(&self) -> bool {
        self.properties & properties::WRITABLE != 0
    }

    pub fn mark_used(&mut self) {
        self.used_count += 1;
    }
}

/// Tracks live resources across fuzzing iterations
pub struct ResourceTracker {
    fds: BTreeMap<usize, Resource>,         // fd -> Resource
    memory: BTreeMap<usize, Resource>,      // base address -> Resource
    ports: BTreeMap<u16, Resource>,         // port number -> Resource
    pids: BTreeMap<usize, Resource>,        // pid -> Resource
    next_id: u32,                           // Next resource ID
    current_iteration: usize,               // Current fuzzing iteration
}

impl ResourceTracker {
    pub fn new() -> Self {
        Self {
            fds: BTreeMap::new(),
            memory: BTreeMap::new(),
            ports: BTreeMap::new(),
            pids: BTreeMap::new(),
            next_id: 1,
            current_iteration: 0,
        }
    }

    pub fn set_iteration(&mut self, iter: usize) {
        self.current_iteration = iter;
    }

    /// Create a new file descriptor resource
    pub fn create_fd(&mut self, fd: usize, readable: bool, writable: bool) -> u32 {
        let id = self.next_id;
        self.next_id += 1;

        let mut props = 0;
        if readable {
            props |= properties::READABLE;
        }
        if writable {
            props |= properties::WRITABLE;
        }

        let resource = Resource::new(id, ResourceType::FileDescriptor, fd, self.current_iteration)
            .with_properties(props);

        self.fds.insert(fd, resource);
        id
    }

    /// Create a new memory region resource
    pub fn create_memory(&mut self, addr: usize, size: usize, prot: u32) -> u32 {
        let id = self.next_id;
        self.next_id += 1;

        let mut props = 0;
        if prot & 0x1 != 0 {  // PROT_READ
            props |= properties::READABLE;
        }
        if prot & 0x2 != 0 {  // PROT_WRITE
            props |= properties::WRITABLE;
        }
        if prot & 0x4 != 0 {  // PROT_EXEC
            props |= properties::EXECUTABLE;
        }

        let resource = Resource::new(id, ResourceType::MemoryRegion, addr, self.current_iteration)
            .with_properties(props);

        self.memory.insert(addr, resource);
        id
    }

    /// Create a new ephemeral port resource
    pub fn create_port(&mut self, port: u16) -> u32 {
        let id = self.next_id;
        self.next_id += 1;

        let resource = Resource::new(id, ResourceType::EphemeralPort, port as usize, self.current_iteration);
        self.ports.insert(port, resource);
        id
    }

    /// Create a new process ID resource
    pub fn create_pid(&mut self, pid: usize) -> u32 {
        let id = self.next_id;
        self.next_id += 1;

        let resource = Resource::new(id, ResourceType::ProcessId, pid, self.current_iteration);
        self.pids.insert(pid, resource);
        id
    }

    /// Check if a file descriptor exists
    pub fn has_fd(&self, fd: usize) -> bool {
        self.fds.contains_key(&fd)
    }

    /// Check if memory region exists at address
    pub fn has_memory(&self, addr: usize) -> bool {
        self.memory.contains_key(&addr)
    }

    /// Check if port is bound
    pub fn has_port(&self, port: u16) -> bool {
        self.ports.contains_key(&port)
    }

    /// Check if process ID exists
    pub fn has_pid(&self, pid: usize) -> bool {
        self.pids.contains_key(&pid)
    }

    /// Get a file descriptor resource
    pub fn get_fd(&self, fd: usize) -> Option<&Resource> {
        self.fds.get(&fd)
    }

    /// Get a memory region resource
    pub fn get_memory(&self, addr: usize) -> Option<&Resource> {
        self.memory.get(&addr)
    }

    /// Get a port resource
    pub fn get_port(&self, port: u16) -> Option<&Resource> {
        self.ports.get(&port)
    }

    /// Get a process ID resource
    pub fn get_pid(&self, pid: usize) -> Option<&Resource> {
        self.pids.get(&pid)
    }

    /// Mark fd as used (increment usage count)
    pub fn use_fd(&mut self, fd: usize) {
        if let Some(resource) = self.fds.get_mut(&fd) {
            resource.mark_used();
        }
    }

    /// Mark memory as used
    pub fn use_memory(&mut self, addr: usize) {
        if let Some(resource) = self.memory.get_mut(&addr) {
            resource.mark_used();
        }
    }

    /// Mark port as used
    pub fn use_port(&mut self, port: u16) {
        if let Some(resource) = self.ports.get_mut(&port) {
            resource.mark_used();
        }
    }

    /// Mark pid as used
    pub fn use_pid(&mut self, pid: usize) {
        if let Some(resource) = self.pids.get_mut(&pid) {
            resource.mark_used();
        }
    }

    /// Destroy a file descriptor
    pub fn destroy_fd(&mut self, fd: usize) -> Option<Resource> {
        self.fds.remove(&fd)
    }

    /// Destroy a memory region
    pub fn destroy_memory(&mut self, addr: usize) -> Option<Resource> {
        self.memory.remove(&addr)
    }

    /// Destroy a port
    pub fn destroy_port(&mut self, port: u16) -> Option<Resource> {
        self.ports.remove(&port)
    }

    /// Destroy a process ID
    pub fn destroy_pid(&mut self, pid: usize) -> Option<Resource> {
        self.pids.remove(&pid)
    }

    /// Get all live file descriptors
    pub fn get_all_fds(&self) -> alloc::vec::Vec<usize> {
        self.fds.keys().copied().collect()
    }

    /// Get all live memory regions
    pub fn get_all_memory(&self) -> alloc::vec::Vec<usize> {
        self.memory.keys().copied().collect()
    }

    /// Get all live ports
    pub fn get_all_ports(&self) -> alloc::vec::Vec<u16> {
        self.ports.keys().copied().collect()
    }

    /// Get all live process IDs
    pub fn get_all_pids(&self) -> alloc::vec::Vec<usize> {
        self.pids.keys().copied().collect()
    }

    /// Get a random valid fd (if any exist)
    pub fn get_random_fd(&self, prng: &mut super::mutator::Xorshift64) -> Option<usize> {
        let fds = self.get_all_fds();
        if fds.is_empty() {
            return None;
        }
        let idx = (prng.next() as usize) % fds.len();
        Some(fds[idx])
    }

    /// Get a random valid memory address
    pub fn get_random_memory(&self, prng: &mut super::mutator::Xorshift64) -> Option<usize> {
        let addrs = self.get_all_memory();
        if addrs.is_empty() {
            return None;
        }
        let idx = (prng.next() as usize) % addrs.len();
        Some(addrs[idx])
    }

    /// Clear all resources (for new iteration)
    pub fn clear(&mut self) {
        self.fds.clear();
        self.memory.clear();
        self.ports.clear();
        self.pids.clear();
    }

    /// Count total live resources
    pub fn total_count(&self) -> usize {
        self.fds.len() + self.memory.len() + self.ports.len() + self.pids.len()
    }

    /// Get resource statistics
    pub fn stats(&self) -> ResourceStats {
        ResourceStats {
            fd_count: self.fds.len(),
            memory_count: self.memory.len(),
            port_count: self.ports.len(),
            pid_count: self.pids.len(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ResourceStats {
    pub fd_count: usize,
    pub memory_count: usize,
    pub port_count: usize,
    pub pid_count: usize,
}
