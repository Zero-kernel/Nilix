// Input minimization using delta debugging
// Reduces failing inputs to minimal crashing examples

#![allow(dead_code)]

extern crate alloc;
use alloc::vec::Vec;

use super::generator::Syscall;

/// Condition that defines a "failure"
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailCondition {
    Crash,
    Hang(usize),  // timeout in ms
    AssertionFailure,
    ResourceLeak,
    Custom(u32),  // user-defined error code
}

/// Reduction strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReductionStrategy {
    RemoveSyscalls,      // Remove individual syscalls
    RemoveBlocks,        // Remove contiguous blocks
    SimplifyArgs,        // Simplify arguments to 0/1/MAX
    DeltaDebug,          // Hierarchical binary search
}

/// Test function type: returns true if input still fails
pub type TestFn = fn(&[Syscall]) -> bool;

/// Input minimizer
pub struct Minimizer {
    pub original_input: Vec<Syscall>,
    pub failing_condition: FailCondition,
    pub current_best: Vec<Syscall>,
    pub strategy: ReductionStrategy,
    pub iterations: usize,
    pub max_iterations: usize,
}

impl Minimizer {
    /// Create a new minimizer
    pub fn new(input: Vec<Syscall>, condition: FailCondition) -> Self {
        Self {
            current_best: input.clone(),
            original_input: input,
            failing_condition: condition,
            strategy: ReductionStrategy::DeltaDebug,
            iterations: 0,
            max_iterations: 1000,
        }
    }

    /// Set reduction strategy
    pub fn with_strategy(mut self, strategy: ReductionStrategy) -> Self {
        self.strategy = strategy;
        self
    }

    /// Set max iterations
    pub fn with_max_iterations(mut self, max: usize) -> Self {
        self.max_iterations = max;
        self
    }

    /// Minimize the input
    pub fn minimize(&mut self, test_fn: TestFn) -> Vec<Syscall> {
        match self.strategy {
            ReductionStrategy::RemoveSyscalls => self.minimize_remove_syscalls(test_fn),
            ReductionStrategy::RemoveBlocks => self.minimize_remove_blocks(test_fn),
            ReductionStrategy::SimplifyArgs => self.minimize_simplify_args(test_fn),
            ReductionStrategy::DeltaDebug => self.minimize_delta_debug(test_fn),
        }
    }

    /// Strategy 1: Remove individual syscalls
    fn minimize_remove_syscalls(&mut self, test_fn: TestFn) -> Vec<Syscall> {
        let mut improved = true;

        while improved && self.iterations < self.max_iterations {
            improved = false;
            let mut i = 0;

            while i < self.current_best.len() {
                self.iterations += 1;

                // Try removing syscall at position i
                let mut candidate = self.current_best.clone();
                candidate.remove(i);

                if !candidate.is_empty() && test_fn(&candidate) {
                    // Still fails without this syscall
                    self.current_best = candidate;
                    improved = true;
                    // Don't increment i, check same position again
                } else {
                    // Need this syscall, move to next
                    i += 1;
                }
            }
        }

        self.current_best.clone()
    }

    /// Strategy 2: Remove contiguous blocks
    fn minimize_remove_blocks(&mut self, test_fn: TestFn) -> Vec<Syscall> {
        let mut block_size = self.current_best.len() / 2;

        while block_size > 0 && self.iterations < self.max_iterations {
            let mut improved = false;
            let mut i = 0;

            while i + block_size <= self.current_best.len() {
                self.iterations += 1;

                // Try removing block [i..i+block_size)
                let mut candidate = self.current_best.clone();
                candidate.drain(i..i + block_size);

                if !candidate.is_empty() && test_fn(&candidate) {
                    // Still fails without this block
                    self.current_best = candidate;
                    improved = true;
                    // Don't increment i, check same position again
                } else {
                    // Need this block, move to next
                    i += 1;
                }
            }

            if !improved {
                block_size /= 2;
            }
        }

        self.current_best.clone()
    }

    /// Strategy 3: Simplify arguments
    fn minimize_simplify_args(&mut self, test_fn: TestFn) -> Vec<Syscall> {
        for i in 0..self.current_best.len() {
            if self.iterations >= self.max_iterations {
                break;
            }

            for arg_idx in 0..6 {
                self.iterations += 1;

                let original_arg = self.current_best[i].args[arg_idx];

                // Try simplifying to 0
                if original_arg != 0 {
                    let mut candidate = self.current_best.clone();
                    candidate[i].args[arg_idx] = 0;

                    if test_fn(&candidate) {
                        self.current_best = candidate;
                        continue;
                    }
                }

                // Try simplifying to 1
                if original_arg != 1 {
                    let mut candidate = self.current_best.clone();
                    candidate[i].args[arg_idx] = 1;

                    if test_fn(&candidate) {
                        self.current_best = candidate;
                        continue;
                    }
                }

                // Try simplifying to small value
                if original_arg > 10 {
                    let mut candidate = self.current_best.clone();
                    candidate[i].args[arg_idx] = 10;

                    if test_fn(&candidate) {
                        self.current_best = candidate;
                    }
                }
            }
        }

        self.current_best.clone()
    }

    /// Strategy 4: Delta debugging (hierarchical)
    fn minimize_delta_debug(&mut self, test_fn: TestFn) -> Vec<Syscall> {
        self.current_best = self.ddmin(&self.current_best, test_fn);
        self.current_best.clone()
    }

    /// Delta debugging recursive implementation
    fn ddmin(&mut self, input: &[Syscall], test_fn: TestFn) -> Vec<Syscall> {
        let n = input.len();

        if n <= 1 || self.iterations >= self.max_iterations {
            return input.to_vec();
        }

        // Try removing first half
        self.iterations += 1;
        let first_half = &input[0..n/2];
        if !first_half.is_empty() && test_fn(first_half) {
            return self.ddmin(first_half, test_fn);
        }

        // Try removing second half
        self.iterations += 1;
        let second_half = &input[n/2..];
        if !second_half.is_empty() && test_fn(second_half) {
            return self.ddmin(second_half, test_fn);
        }

        // Try removing each element individually
        for i in 0..n {
            if self.iterations >= self.max_iterations {
                break;
            }

            self.iterations += 1;
            let mut candidate = input.to_vec();
            candidate.remove(i);

            if !candidate.is_empty() && test_fn(&candidate) {
                return self.ddmin(&candidate, test_fn);
            }
        }

        // No further reduction possible
        input.to_vec()
    }

    /// Get reduction percentage
    pub fn reduction_percentage(&self) -> f32 {
        let original_len = self.original_input.len() as f32;
        let current_len = self.current_best.len() as f32;

        if original_len == 0.0 {
            return 0.0;
        }

        ((original_len - current_len) / original_len) * 100.0
    }

    /// Get minimization statistics
    pub fn stats(&self) -> MinimizationStats {
        MinimizationStats {
            original_size: self.original_input.len(),
            minimized_size: self.current_best.len(),
            reduction_percentage: self.reduction_percentage(),
            iterations: self.iterations,
        }
    }
}

/// Minimization statistics
#[derive(Debug, Clone, Copy)]
pub struct MinimizationStats {
    pub original_size: usize,
    pub minimized_size: usize,
    pub reduction_percentage: f32,
    pub iterations: usize,
}

/// Multi-strategy minimizer
pub struct MultiStrategyMinimizer {
    minimizers: Vec<Minimizer>,
}

impl MultiStrategyMinimizer {
    /// Create a new multi-strategy minimizer
    pub fn new(input: Vec<Syscall>, condition: FailCondition) -> Self {
        let strategies = vec![
            ReductionStrategy::DeltaDebug,
            ReductionStrategy::RemoveBlocks,
            ReductionStrategy::RemoveSyscalls,
            ReductionStrategy::SimplifyArgs,
        ];

        let minimizers = strategies.into_iter()
            .map(|strategy| {
                Minimizer::new(input.clone(), condition.clone())
                    .with_strategy(strategy)
                    .with_max_iterations(250)  // 250 per strategy = 1000 total
            })
            .collect();

        Self { minimizers }
    }

    /// Apply all strategies and return the best result
    pub fn minimize(&mut self, test_fn: TestFn) -> Vec<Syscall> {
        let mut best = self.minimizers[0].original_input.clone();

        for minimizer in &mut self.minimizers {
            minimizer.current_best = best.clone();
            let result = minimizer.minimize(test_fn);

            if result.len() < best.len() {
                best = result;
            }
        }

        best
    }

    /// Get statistics from all strategies
    pub fn all_stats(&self) -> Vec<(ReductionStrategy, MinimizationStats)> {
        self.minimizers.iter()
            .map(|m| (m.strategy, m.stats()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_input() -> Vec<Syscall> {
        vec![
            Syscall { number: 2, args: [0, 0, 0, 0, 0, 0] },  // open
            Syscall { number: 1, args: [3, 0, 0, 0, 0, 0] },  // write
            Syscall { number: 1, args: [3, 0, 0, 0, 0, 0] },  // write (redundant)
            Syscall { number: 3, args: [3, 0, 0, 0, 0, 0] },  // close
            Syscall { number: 39, args: [0, 0, 0, 0, 0, 0] }, // getpid (irrelevant)
        ]
    }

    fn test_fn_needs_open_write(input: &[Syscall]) -> bool {
        // Fails if has open (2) followed by write (1)
        for i in 0..input.len().saturating_sub(1) {
            if input[i].number == 2 && input[i+1].number == 1 {
                return true;
            }
        }
        false
    }

    #[test]
    fn test_remove_syscalls() {
        let input = create_test_input();
        let mut minimizer = Minimizer::new(input, FailCondition::Crash)
            .with_strategy(ReductionStrategy::RemoveSyscalls);

        let result = minimizer.minimize(test_fn_needs_open_write);

        // Should reduce to just: open, write
        assert!(result.len() <= 2);
        assert!(result[0].number == 2);  // open
        assert!(result[1].number == 1);  // write
    }

    #[test]
    fn test_delta_debug() {
        let input = create_test_input();
        let mut minimizer = Minimizer::new(input, FailCondition::Crash)
            .with_strategy(ReductionStrategy::DeltaDebug);

        let result = minimizer.minimize(test_fn_needs_open_write);

        assert!(result.len() <= 2);
    }
}
