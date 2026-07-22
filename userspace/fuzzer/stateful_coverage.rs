// Stateful coverage tracking
// Tracks state transitions in addition to code edges

#![allow(dead_code)]

extern crate alloc;
use alloc::collections::BTreeSet;
use alloc::collections::BTreeMap;
use alloc::string::String;

use super::state_machine::StateId;

/// State transition representation
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct StateTransition {
    pub machine_id: u32,
    pub from_state: StateId,
    pub to_state: StateId,
    pub trigger: usize,  // syscall number
}

impl StateTransition {
    pub fn new(machine_id: u32, from: StateId, to: StateId, trigger: usize) -> Self {
        Self {
            machine_id,
            from_state: from,
            to_state: to,
            trigger,
        }
    }
}

/// Transaction coverage information
#[derive(Debug, Clone)]
pub struct TransactionCoverage {
    pub transaction_id: u32,
    pub completed_steps: usize,
    pub total_steps: usize,
    pub success_rate: f32,
}

impl TransactionCoverage {
    pub fn new(transaction_id: u32, total_steps: usize) -> Self {
        Self {
            transaction_id,
            completed_steps: 0,
            total_steps,
            success_rate: 0.0,
        }
    }

    pub fn completion_percentage(&self) -> f32 {
        if self.total_steps == 0 {
            100.0
        } else {
            (self.completed_steps as f32 / self.total_steps as f32) * 100.0
        }
    }
}

/// Stateful coverage collector
pub struct StatefulCoverage {
    // Traditional edge coverage (from Phase 2)
    pub edge_coverage: BTreeSet<u32>,

    // State transition coverage (new in Phase 6)
    pub state_coverage: BTreeSet<StateTransition>,

    // Transaction coverage (new in Phase 6)
    pub transaction_coverage: BTreeMap<u32, TransactionCoverage>,

    // Coverage over time
    pub edge_timeline: Vec<usize>,
    pub state_timeline: Vec<usize>,
}

impl StatefulCoverage {
    pub fn new() -> Self {
        Self {
            edge_coverage: BTreeSet::new(),
            state_coverage: BTreeSet::new(),
            transaction_coverage: BTreeMap::new(),
            edge_timeline: Vec::new(),
            state_timeline: Vec::new(),
        }
    }

    /// Record a code edge hit
    pub fn record_edge(&mut self, edge_id: u32) {
        self.edge_coverage.insert(edge_id);
    }

    /// Record a state transition
    pub fn record_transition(&mut self, transition: StateTransition) {
        self.state_coverage.insert(transition);
    }

    /// Start tracking a transaction
    pub fn start_transaction(&mut self, transaction_id: u32, total_steps: usize) {
        let cov = TransactionCoverage::new(transaction_id, total_steps);
        self.transaction_coverage.insert(transaction_id, cov);
    }

    /// Record transaction step completion
    pub fn record_transaction_step(&mut self, transaction_id: u32) {
        if let Some(cov) = self.transaction_coverage.get_mut(&transaction_id) {
            cov.completed_steps += 1;
        }
    }

    /// Mark transaction as complete
    pub fn complete_transaction(&mut self, transaction_id: u32, success: bool) {
        if let Some(cov) = self.transaction_coverage.get_mut(&transaction_id) {
            if success {
                cov.success_rate = 1.0;
            } else {
                cov.success_rate = 0.0;
            }
        }
    }

    /// Take a snapshot of current coverage
    pub fn snapshot(&mut self) {
        self.edge_timeline.push(self.edge_coverage.len());
        self.state_timeline.push(self.state_coverage.len());
    }

    /// Get edge coverage count
    pub fn edge_count(&self) -> usize {
        self.edge_coverage.len()
    }

    /// Get state transition coverage count
    pub fn state_count(&self) -> usize {
        self.state_coverage.len()
    }

    /// Get transaction coverage count
    pub fn transaction_count(&self) -> usize {
        self.transaction_coverage.len()
    }

    /// Get average transaction completion rate
    pub fn avg_transaction_completion(&self) -> f32 {
        if self.transaction_coverage.is_empty() {
            return 0.0;
        }

        let sum: f32 = self.transaction_coverage.values()
            .map(|c| c.completion_percentage())
            .sum();

        sum / self.transaction_coverage.len() as f32
    }

    /// Get coverage growth rate
    pub fn edge_growth_rate(&self) -> f32 {
        if self.edge_timeline.len() < 2 {
            return 0.0;
        }

        let first = self.edge_timeline[0] as f32;
        let last = *self.edge_timeline.last().unwrap() as f32;

        if first == 0.0 {
            return last;
        }

        (last - first) / first * 100.0
    }

    /// Get state coverage growth rate
    pub fn state_growth_rate(&self) -> f32 {
        if self.state_timeline.len() < 2 {
            return 0.0;
        }

        let first = self.state_timeline[0] as f32;
        let last = *self.state_timeline.last().unwrap() as f32;

        if first == 0.0 {
            return last;
        }

        (last - first) / first * 100.0
    }

    /// Check if new edge was discovered
    pub fn is_new_edge(&self, edge_id: u32) -> bool {
        !self.edge_coverage.contains(&edge_id)
    }

    /// Check if new state transition was discovered
    pub fn is_new_transition(&self, transition: &StateTransition) -> bool {
        !self.state_coverage.contains(transition)
    }

    /// Merge coverage from another collector
    pub fn merge(&mut self, other: &StatefulCoverage) {
        for edge in &other.edge_coverage {
            self.edge_coverage.insert(*edge);
        }

        for transition in &other.state_coverage {
            self.state_coverage.insert(*transition);
        }

        for (id, cov) in &other.transaction_coverage {
            self.transaction_coverage.insert(*id, cov.clone());
        }
    }

    /// Clear all coverage
    pub fn clear(&mut self) {
        self.edge_coverage.clear();
        self.state_coverage.clear();
        self.transaction_coverage.clear();
        self.edge_timeline.clear();
        self.state_timeline.clear();
    }

    /// Get statistics
    pub fn stats(&self) -> CoverageStats {
        CoverageStats {
            edges: self.edge_count(),
            states: self.state_count(),
            transactions: self.transaction_count(),
            avg_transaction_completion: self.avg_transaction_completion(),
            edge_growth: self.edge_growth_rate(),
            state_growth: self.state_growth_rate(),
        }
    }
}

/// Coverage statistics
#[derive(Debug, Clone, Copy)]
pub struct CoverageStats {
    pub edges: usize,
    pub states: usize,
    pub transactions: usize,
    pub avg_transaction_completion: f32,
    pub edge_growth: f32,
    pub state_growth: f32,
}

/// Coverage comparator for prioritizing interesting inputs
pub struct CoverageComparator;

impl CoverageComparator {
    /// Compare two coverage sets and return a score
    /// Higher score = more interesting
    pub fn compare(baseline: &StatefulCoverage, candidate: &StatefulCoverage) -> f32 {
        let mut score = 0.0;

        // New edges are valuable
        let new_edges = candidate.edge_coverage.difference(&baseline.edge_coverage).count();
        score += new_edges as f32 * 10.0;

        // New state transitions are very valuable
        let new_states = candidate.state_coverage.difference(&baseline.state_coverage).count();
        score += new_states as f32 * 20.0;

        // Transaction completion is valuable
        let completion_delta = candidate.avg_transaction_completion() - baseline.avg_transaction_completion();
        score += completion_delta * 5.0;

        score
    }

    /// Check if candidate is more interesting than baseline
    pub fn is_more_interesting(baseline: &StatefulCoverage, candidate: &StatefulCoverage) -> bool {
        Self::compare(baseline, candidate) > 0.0
    }
}

/// Coverage-guided input prioritization
pub struct CoveragePrioritizer {
    baseline: StatefulCoverage,
}

impl CoveragePrioritizer {
    pub fn new() -> Self {
        Self {
            baseline: StatefulCoverage::new(),
        }
    }

    /// Update baseline with new coverage
    pub fn update_baseline(&mut self, coverage: &StatefulCoverage) {
        self.baseline.merge(coverage);
    }

    /// Calculate priority score for an input based on coverage
    pub fn calculate_priority(&self, coverage: &StatefulCoverage) -> f32 {
        CoverageComparator::compare(&self.baseline, coverage)
    }

    /// Check if input should be added to corpus
    pub fn should_add_to_corpus(&self, coverage: &StatefulCoverage) -> bool {
        CoverageComparator::is_more_interesting(&self.baseline, coverage)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_edge_coverage() {
        let mut cov = StatefulCoverage::new();
        assert_eq!(cov.edge_count(), 0);

        cov.record_edge(1);
        cov.record_edge(2);
        cov.record_edge(1);  // Duplicate

        assert_eq!(cov.edge_count(), 2);
    }

    #[test]
    fn test_state_coverage() {
        let mut cov = StatefulCoverage::new();

        let t1 = StateTransition::new(0, 0, 1, 2);  // open
        let t2 = StateTransition::new(0, 1, 0, 3);  // close

        cov.record_transition(t1);
        cov.record_transition(t2);
        cov.record_transition(t1);  // Duplicate

        assert_eq!(cov.state_count(), 2);
    }

    #[test]
    fn test_transaction_coverage() {
        let mut cov = StatefulCoverage::new();

        cov.start_transaction(1, 5);
        cov.record_transaction_step(1);
        cov.record_transaction_step(1);

        assert_eq!(cov.transaction_count(), 1);

        if let Some(tc) = cov.transaction_coverage.get(&1) {
            assert_eq!(tc.completed_steps, 2);
            assert_eq!(tc.total_steps, 5);
            assert_eq!(tc.completion_percentage(), 40.0);
        }
    }
}
