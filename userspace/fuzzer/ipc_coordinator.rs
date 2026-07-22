// Inter-process coordination for multi-process fuzzing
// Tracks fork/exec/wait patterns and shared resources

#![allow(dead_code)]

extern crate alloc;
use alloc::vec::Vec;
use alloc::collections::BTreeMap;

use super::resources::{Resource, ResourceType};

/// Process state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    Created,
    Running,
    Blocked,
    Zombie,
    Reaped,
}

/// Process information
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: usize,
    pub parent_pid: Option<usize>,
    pub state: ProcessState,
    pub resources: Vec<Resource>,
    pub shared_fds: Vec<usize>,
}

impl ProcessInfo {
    pub fn new(pid: usize, parent_pid: Option<usize>) -> Self {
        Self {
            pid,
            parent_pid,
            state: ProcessState::Created,
            resources: Vec::new(),
            shared_fds: Vec::new(),
        }
    }

    pub fn add_resource(&mut self, resource: Resource) {
        self.resources.push(resource);
    }

    pub fn remove_resource(&mut self, rtype: ResourceType, value: usize) {
        self.resources.retain(|r| !(r.rtype == rtype && r.value == value));
    }

    pub fn has_resource(&self, rtype: ResourceType, value: usize) -> bool {
        self.resources.iter().any(|r| r.rtype == rtype && r.value == value)
    }
}

/// Pipe information
#[derive(Debug, Clone)]
pub struct PipeInfo {
    pub id: usize,
    pub read_fd: usize,
    pub write_fd: usize,
    pub reader_pid: Option<usize>,
    pub writer_pid: Option<usize>,
}

impl PipeInfo {
    pub fn new(id: usize, read_fd: usize, write_fd: usize) -> Self {
        Self {
            id,
            read_fd,
            write_fd,
            reader_pid: None,
            writer_pid: None,
        }
    }
}

/// Shared memory information
#[derive(Debug, Clone)]
pub struct ShmInfo {
    pub id: usize,
    pub addr: usize,
    pub size: usize,
    pub attached_pids: Vec<usize>,
}

impl ShmInfo {
    pub fn new(id: usize, addr: usize, size: usize) -> Self {
        Self {
            id,
            addr,
            size,
            attached_pids: Vec::new(),
        }
    }

    pub fn attach(&mut self, pid: usize) {
        if !self.attached_pids.contains(&pid) {
            self.attached_pids.push(pid);
        }
    }

    pub fn detach(&mut self, pid: usize) {
        self.attached_pids.retain(|p| *p != pid);
    }
}

/// Synchronization point
#[derive(Debug, Clone)]
pub struct SyncPoint {
    pub id: usize,
    pub processes: Vec<usize>,
    pub condition: SyncCondition,
    pub reached: Vec<usize>,
}

impl SyncPoint {
    pub fn new(id: usize, processes: Vec<usize>, condition: SyncCondition) -> Self {
        Self {
            id,
            processes,
            condition,
            reached: Vec::new(),
        }
    }

    pub fn mark_reached(&mut self, pid: usize) {
        if !self.reached.contains(&pid) {
            self.reached.push(pid);
        }
    }

    pub fn is_satisfied(&self) -> bool {
        match self.condition {
            SyncCondition::AllReached => {
                self.reached.len() == self.processes.len()
            }
            SyncCondition::AnyReached => {
                !self.reached.is_empty()
            }
            SyncCondition::Timeout(_) => {
                false  // Would need timer integration
            }
        }
    }
}

/// Synchronization condition
#[derive(Debug, Clone, Copy)]
pub enum SyncCondition {
    AllReached,
    AnyReached,
    Timeout(usize),  // milliseconds
}

/// IPC coordinator
pub struct IPCCoordinator {
    pub processes: BTreeMap<usize, ProcessInfo>,
    pub pipes: BTreeMap<usize, PipeInfo>,
    pub shared_memory: BTreeMap<usize, ShmInfo>,
    pub sync_points: Vec<SyncPoint>,
    next_pipe_id: usize,
    next_shm_id: usize,
    next_sync_id: usize,
}

impl IPCCoordinator {
    pub fn new() -> Self {
        Self {
            processes: BTreeMap::new(),
            pipes: BTreeMap::new(),
            shared_memory: BTreeMap::new(),
            sync_points: Vec::new(),
            next_pipe_id: 1,
            next_shm_id: 1,
            next_sync_id: 1,
        }
    }

    /// Register a new process
    pub fn register_process(&mut self, pid: usize, parent_pid: Option<usize>) {
        let proc = ProcessInfo::new(pid, parent_pid);
        self.processes.insert(pid, proc);
    }

    /// Update process state
    pub fn update_state(&mut self, pid: usize, state: ProcessState) {
        if let Some(proc) = self.processes.get_mut(&pid) {
            proc.state = state;
        }
    }

    /// Handle fork syscall
    pub fn handle_fork(&mut self, parent_pid: usize, child_pid: usize) {
        // Register child process
        self.register_process(child_pid, Some(parent_pid));

        // Copy shared resources from parent
        if let Some(parent) = self.processes.get(&parent_pid).cloned() {
            if let Some(child) = self.processes.get_mut(&child_pid) {
                child.shared_fds = parent.shared_fds.clone();
            }
        }
    }

    /// Handle exec syscall
    pub fn handle_exec(&mut self, pid: usize) {
        if let Some(proc) = self.processes.get_mut(&pid) {
            proc.state = ProcessState::Running;
            // Close non-shared file descriptors
            proc.resources.clear();
        }
    }

    /// Handle exit syscall
    pub fn handle_exit(&mut self, pid: usize) {
        if let Some(proc) = self.processes.get_mut(&pid) {
            proc.state = ProcessState::Zombie;
        }
    }

    /// Handle wait syscall
    pub fn handle_wait(&mut self, parent_pid: usize, child_pid: usize) {
        if let Some(proc) = self.processes.get_mut(&child_pid) {
            if proc.state == ProcessState::Zombie {
                proc.state = ProcessState::Reaped;
            }
        }
    }

    /// Create a pipe
    pub fn create_pipe(&mut self, read_fd: usize, write_fd: usize) -> usize {
        let id = self.next_pipe_id;
        self.next_pipe_id += 1;

        let pipe = PipeInfo::new(id, read_fd, write_fd);
        self.pipes.insert(id, pipe);
        id
    }

    /// Assign pipe to processes
    pub fn assign_pipe_reader(&mut self, pipe_id: usize, pid: usize) {
        if let Some(pipe) = self.pipes.get_mut(&pipe_id) {
            pipe.reader_pid = Some(pid);

            // Add to process shared fds
            if let Some(proc) = self.processes.get_mut(&pid) {
                proc.shared_fds.push(pipe.read_fd);
            }
        }
    }

    pub fn assign_pipe_writer(&mut self, pipe_id: usize, pid: usize) {
        if let Some(pipe) = self.pipes.get_mut(&pipe_id) {
            pipe.writer_pid = Some(pid);

            // Add to process shared fds
            if let Some(proc) = self.processes.get_mut(&pid) {
                proc.shared_fds.push(pipe.write_fd);
            }
        }
    }

    /// Create shared memory
    pub fn create_shm(&mut self, addr: usize, size: usize) -> usize {
        let id = self.next_shm_id;
        self.next_shm_id += 1;

        let shm = ShmInfo::new(id, addr, size);
        self.shared_memory.insert(id, shm);
        id
    }

    /// Attach process to shared memory
    pub fn attach_shm(&mut self, shm_id: usize, pid: usize) {
        if let Some(shm) = self.shared_memory.get_mut(&shm_id) {
            shm.attach(pid);
        }
    }

    /// Detach process from shared memory
    pub fn detach_shm(&mut self, shm_id: usize, pid: usize) {
        if let Some(shm) = self.shared_memory.get_mut(&shm_id) {
            shm.detach(pid);
        }
    }

    /// Create synchronization point
    pub fn create_sync_point(&mut self, processes: Vec<usize>, condition: SyncCondition) -> usize {
        let id = self.next_sync_id;
        self.next_sync_id += 1;

        let sync = SyncPoint::new(id, processes, condition);
        self.sync_points.push(sync);
        id
    }

    /// Mark process as reaching sync point
    pub fn reach_sync_point(&mut self, sync_id: usize, pid: usize) {
        for sync in &mut self.sync_points {
            if sync.id == sync_id {
                sync.mark_reached(pid);
                break;
            }
        }
    }

    /// Check if sync point is satisfied
    pub fn is_sync_satisfied(&self, sync_id: usize) -> bool {
        self.sync_points.iter()
            .find(|s| s.id == sync_id)
            .map(|s| s.is_satisfied())
            .unwrap_or(false)
    }

    /// Get process count
    pub fn process_count(&self) -> usize {
        self.processes.len()
    }

    /// Get active process count
    pub fn active_process_count(&self) -> usize {
        self.processes.values()
            .filter(|p| matches!(p.state, ProcessState::Running | ProcessState::Blocked))
            .count()
    }

    /// Get zombie process count
    pub fn zombie_process_count(&self) -> usize {
        self.processes.values()
            .filter(|p| p.state == ProcessState::Zombie)
            .count()
    }

    /// Clear all state
    pub fn clear(&mut self) {
        self.processes.clear();
        self.pipes.clear();
        self.shared_memory.clear();
        self.sync_points.clear();
        self.next_pipe_id = 1;
        self.next_shm_id = 1;
        self.next_sync_id = 1;
    }

    /// Get statistics
    pub fn stats(&self) -> IPCStats {
        IPCStats {
            total_processes: self.process_count(),
            active_processes: self.active_process_count(),
            zombie_processes: self.zombie_process_count(),
            pipes: self.pipes.len(),
            shared_memory: self.shared_memory.len(),
            sync_points: self.sync_points.len(),
        }
    }
}

/// IPC statistics
#[derive(Debug, Clone, Copy)]
pub struct IPCStats {
    pub total_processes: usize,
    pub active_processes: usize,
    pub zombie_processes: usize,
    pub pipes: usize,
    pub shared_memory: usize,
    pub sync_points: usize,
}

/// Coordination pattern builder
pub struct CoordinationPatternBuilder;

impl CoordinationPatternBuilder {
    /// Build fork-exec-wait pattern
    pub fn build_fork_exec_wait() -> Vec<(usize, Vec<usize>)> {
        // Returns: [(syscall_num, args)]
        vec![
            (57, vec![0, 0, 0, 0, 0, 0]),  // fork
            (59, vec![0x2000, 0, 0, 0, 0, 0]),  // exec (child)
            (61, vec![0, 0x3000, 0, 0, 0, 0]),  // wait (parent)
        ]
    }

    /// Build pipe communication pattern
    pub fn build_pipe_communication() -> Vec<(usize, Vec<usize>)> {
        vec![
            (22, vec![0x1000, 0, 0, 0, 0, 0]),  // pipe
            (57, vec![0, 0, 0, 0, 0, 0]),        // fork
            (3, vec![4, 0, 0, 0, 0, 0]),         // close write_fd (parent)
            (0, vec![3, 0x2000, 100, 0, 0, 0]),  // read (parent)
            (3, vec![3, 0, 0, 0, 0, 0]),         // close read_fd (child)
            (1, vec![4, 0x2000, 100, 0, 0, 0]),  // write (child)
        ]
    }

    /// Build shared memory pattern
    pub fn build_shared_memory() -> Vec<(usize, Vec<usize>)> {
        vec![
            (29, vec![0, 4096, 3, 0x22, 0, 0]),  // shmget (mmap with MAP_SHARED)
            (57, vec![0, 0, 0, 0, 0, 0]),        // fork
            // Both parent and child can access shared memory
        ]
    }
}
