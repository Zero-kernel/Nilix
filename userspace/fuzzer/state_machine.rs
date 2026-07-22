// State machine framework for protocol modeling
// Tracks valid state transitions and protocol invariants

#![allow(dead_code)]

extern crate alloc;
use alloc::vec::Vec;
use alloc::string::String;
use alloc::collections::BTreeMap;

use super::generator::Syscall;
use super::resources::ResourceType;

/// State identifier
pub type StateId = u32;

/// State in a state machine
#[derive(Debug, Clone)]
pub struct State {
    pub id: StateId,
    pub name: String,
    pub entry_actions: Vec<Action>,
    pub exit_actions: Vec<Action>,
    pub invariants: Vec<Invariant>,
}

impl State {
    pub fn new(id: StateId, name: String) -> Self {
        Self {
            id,
            name,
            entry_actions: Vec::new(),
            exit_actions: Vec::new(),
            invariants: Vec::new(),
        }
    }
}

/// Actions to execute during transitions
#[derive(Debug, Clone)]
pub enum Action {
    CreateResource(ResourceType, usize),
    DestroyResource(ResourceType, usize),
    ExecuteSyscall(Syscall),
    RecordCoverage(u32),
    Log(String),
}

/// State invariants that must hold
#[derive(Debug, Clone)]
pub enum Invariant {
    ResourceExists(ResourceType, usize),
    ResourceNotExists(ResourceType, usize),
    ResourceReadable(usize),
    ResourceWritable(usize),
    Custom(String),
}

/// Guard conditions for transitions
#[derive(Debug, Clone)]
pub enum Guard {
    ResourceExists(ResourceType, usize),
    ResourceNotExists(ResourceType, usize),
    Always,
    Never,
}

impl Guard {
    pub fn evaluate(&self) -> bool {
        match self {
            Guard::Always => true,
            Guard::Never => false,
            Guard::ResourceExists(_, _) => true,  // Simplified
            Guard::ResourceNotExists(_, _) => true,  // Simplified
        }
    }
}

/// Transition between states
#[derive(Debug, Clone)]
pub struct Transition {
    pub id: u32,
    pub from: StateId,
    pub to: StateId,
    pub trigger: usize,  // syscall number
    pub guard: Option<Guard>,
    pub actions: Vec<Action>,
}

impl Transition {
    pub fn new(id: u32, from: StateId, to: StateId, trigger: usize) -> Self {
        Self {
            id,
            from,
            to,
            trigger,
            guard: None,
            actions: Vec::new(),
        }
    }

    pub fn can_fire(&self, current_state: StateId, syscall_num: usize) -> bool {
        if self.from != current_state {
            return false;
        }
        if self.trigger != syscall_num {
            return false;
        }
        if let Some(ref guard) = self.guard {
            return guard.evaluate();
        }
        true
    }
}

/// State machine for protocol modeling
pub struct StateMachine {
    pub name: String,
    pub states: BTreeMap<StateId, State>,
    pub transitions: Vec<Transition>,
    pub current_state: StateId,
    pub initial_state: StateId,
    pub final_states: Vec<StateId>,
    pub transition_history: Vec<(StateId, StateId, usize)>,
    next_transition_id: u32,
}

impl StateMachine {
    pub fn new(name: String, initial_state: StateId) -> Self {
        Self {
            name,
            states: BTreeMap::new(),
            transitions: Vec::new(),
            current_state: initial_state,
            initial_state,
            final_states: Vec::new(),
            transition_history: Vec::new(),
            next_transition_id: 1,
        }
    }

    /// Add a state to the machine
    pub fn add_state(&mut self, state: State) {
        self.states.insert(state.id, state);
    }

    /// Add a transition
    pub fn add_transition(&mut self, from: StateId, to: StateId, trigger: usize) {
        let transition = Transition::new(self.next_transition_id, from, to, trigger);
        self.next_transition_id += 1;
        self.transitions.push(transition);
    }

    /// Add a guarded transition
    pub fn add_guarded_transition(&mut self, from: StateId, to: StateId, trigger: usize, guard: Guard) {
        let mut transition = Transition::new(self.next_transition_id, from, to, trigger);
        self.next_transition_id += 1;
        transition.guard = Some(guard);
        self.transitions.push(transition);
    }

    /// Mark a state as final
    pub fn add_final_state(&mut self, state_id: StateId) {
        if !self.final_states.contains(&state_id) {
            self.final_states.push(state_id);
        }
    }

    /// Attempt to transition based on syscall
    pub fn transition(&mut self, syscall_num: usize) -> Result<StateId, TransitionError> {
        // Find applicable transition
        for transition in &self.transitions {
            if transition.can_fire(self.current_state, syscall_num) {
                let old_state = self.current_state;
                self.current_state = transition.to;
                self.transition_history.push((old_state, transition.to, syscall_num));
                return Ok(transition.to);
            }
        }

        Err(TransitionError::NoValidTransition)
    }

    /// Reset to initial state
    pub fn reset(&mut self) {
        self.current_state = self.initial_state;
        self.transition_history.clear();
    }

    /// Check if in a final state
    pub fn is_in_final_state(&self) -> bool {
        self.final_states.contains(&self.current_state)
    }

    /// Get current state name
    pub fn current_state_name(&self) -> Option<&str> {
        self.states.get(&self.current_state).map(|s| s.name.as_str())
    }

    /// Get transition coverage (unique transitions observed)
    pub fn transition_coverage(&self) -> usize {
        let mut unique_transitions = Vec::new();
        for (from, to, trigger) in &self.transition_history {
            let key = (*from, *to, *trigger);
            if !unique_transitions.contains(&key) {
                unique_transitions.push(key);
            }
        }
        unique_transitions.len()
    }

    /// Get state coverage (unique states visited)
    pub fn state_coverage(&self) -> usize {
        let mut unique_states = Vec::new();
        for (from, to, _) in &self.transition_history {
            if !unique_states.contains(from) {
                unique_states.push(*from);
            }
            if !unique_states.contains(to) {
                unique_states.push(*to);
            }
        }
        unique_states.len()
    }
}

/// Transition errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionError {
    NoValidTransition,
    GuardFailed,
    InvalidState,
}

/// Pre-defined state machines for common protocols

/// File descriptor state machine: CLOSED ↔ OPEN
pub fn create_fd_state_machine() -> StateMachine {
    let mut sm = StateMachine::new("FileDescriptor".into(), 0);

    // States
    let closed = State::new(0, "CLOSED".into());
    let open = State::new(1, "OPEN".into());

    sm.add_state(closed);
    sm.add_state(open);
    sm.add_final_state(0);  // CLOSED is a valid final state

    // Transitions
    sm.add_transition(0, 1, 2);   // CLOSED --[open]--> OPEN
    sm.add_transition(1, 1, 0);   // OPEN --[read]--> OPEN
    sm.add_transition(1, 1, 1);   // OPEN --[write]--> OPEN
    sm.add_transition(1, 0, 3);   // OPEN --[close]--> CLOSED

    sm
}

/// Memory region state machine: UNMAPPED → MAPPED → UNMAPPED
pub fn create_memory_state_machine() -> StateMachine {
    let mut sm = StateMachine::new("MemoryRegion".into(), 0);

    // States
    let unmapped = State::new(0, "UNMAPPED".into());
    let mapped = State::new(1, "MAPPED".into());
    let protected = State::new(2, "PROTECTED".into());

    sm.add_state(unmapped);
    sm.add_state(mapped);
    sm.add_state(protected);
    sm.add_final_state(0);  // UNMAPPED is final

    // Transitions
    sm.add_transition(0, 1, 9);   // UNMAPPED --[mmap]--> MAPPED
    sm.add_transition(1, 2, 10);  // MAPPED --[mprotect]--> PROTECTED
    sm.add_transition(2, 1, 10);  // PROTECTED --[mprotect]--> MAPPED
    sm.add_transition(1, 0, 11);  // MAPPED --[munmap]--> UNMAPPED
    sm.add_transition(2, 0, 11);  // PROTECTED --[munmap]--> UNMAPPED

    sm
}

/// Process lifecycle state machine: INIT → FORKED → EXEC → ZOMBIE → REAPED
pub fn create_process_state_machine() -> StateMachine {
    let mut sm = StateMachine::new("ProcessLifecycle".into(), 0);

    // States
    let init = State::new(0, "INIT".into());
    let forked = State::new(1, "FORKED".into());
    let exec = State::new(2, "EXEC".into());
    let zombie = State::new(3, "ZOMBIE".into());
    let reaped = State::new(4, "REAPED".into());

    sm.add_state(init);
    sm.add_state(forked);
    sm.add_state(exec);
    sm.add_state(zombie);
    sm.add_state(reaped);
    sm.add_final_state(4);  // REAPED is final

    // Transitions
    sm.add_transition(0, 1, 57);  // INIT --[fork]--> FORKED
    sm.add_transition(1, 2, 59);  // FORKED --[exec]--> EXEC
    sm.add_transition(2, 3, 60);  // EXEC --[exit]--> ZOMBIE
    sm.add_transition(3, 4, 61);  // ZOMBIE --[wait]--> REAPED

    sm
}

/// State machine manager
pub struct StateMachineManager {
    machines: Vec<StateMachine>,
}

impl StateMachineManager {
    pub fn new() -> Self {
        let mut manager = Self {
            machines: Vec::new(),
        };

        // Add pre-defined machines
        manager.machines.push(create_fd_state_machine());
        manager.machines.push(create_memory_state_machine());
        manager.machines.push(create_process_state_machine());

        manager
    }

    /// Get a state machine by name
    pub fn get(&self, name: &str) -> Option<&StateMachine> {
        self.machines.iter().find(|sm| sm.name == name)
    }

    /// Get a mutable state machine by name
    pub fn get_mut(&mut self, name: &str) -> Option<&mut StateMachine> {
        self.machines.iter_mut().find(|sm| sm.name == name)
    }

    /// Process syscall through all state machines
    pub fn process_syscall(&mut self, syscall_num: usize) {
        for machine in &mut self.machines {
            let _ = machine.transition(syscall_num);
        }
    }

    /// Reset all state machines
    pub fn reset_all(&mut self) {
        for machine in &mut self.machines {
            machine.reset();
        }
    }

    /// Get total transition coverage across all machines
    pub fn total_transition_coverage(&self) -> usize {
        self.machines.iter().map(|sm| sm.transition_coverage()).sum()
    }

    /// Get total state coverage across all machines
    pub fn total_state_coverage(&self) -> usize {
        self.machines.iter().map(|sm| sm.state_coverage()).sum()
    }

    /// Get statistics
    pub fn stats(&self) -> StateMachineStats {
        StateMachineStats {
            total_machines: self.machines.len(),
            total_transitions: self.total_transition_coverage(),
            total_states: self.total_state_coverage(),
        }
    }
}

/// State machine statistics
#[derive(Debug, Clone, Copy)]
pub struct StateMachineStats {
    pub total_machines: usize,
    pub total_transitions: usize,
    pub total_states: usize,
}
