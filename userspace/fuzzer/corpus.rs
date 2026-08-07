// Corpus management for coverage-guided fuzzing
// Phase 4: Stores test cases that increase coverage

// `main.rs` owns the crate-level `#![no_std]` contract. Keeping this as a
// normal module also lets the host regression harness compile the real types.

extern crate alloc;
use alloc::collections::BTreeSet;
use alloc::vec::Vec;

/// A single syscall with arguments
#[derive(Clone, Debug)]
pub struct Syscall {
    pub number: usize,
    pub args: [u64; 6],
}

impl Syscall {
    pub fn new(number: usize, args: [u64; 6]) -> Self {
        Self { number, args }
    }
}

/// Entry in the corpus
#[derive(Clone)]
pub struct CorpusEntry {
    /// Syscall sequence
    pub sequence: Vec<Syscall>,

    /// Coverage edges hit by this input
    pub edges: Vec<u32>,

    /// Number of unique edges
    pub unique_edges: usize,

    /// Execution time in microseconds
    pub exec_time_us: u64,

    /// Number of times selected for mutation
    pub selection_count: u32,

    /// Total descendants (mutants) generated
    pub descendant_count: u32,

    /// Number of descendants that found new coverage
    pub productive_descendants: u32,

    /// Energy (priority for selection)
    pub energy: f32,
}

impl CorpusEntry {
    pub fn new(sequence: Vec<Syscall>, edges: Vec<u32>, exec_time_us: u64) -> Self {
        let unique_edges = edges.len();
        Self {
            sequence,
            edges,
            unique_edges,
            exec_time_us,
            selection_count: 0,
            descendant_count: 0,
            productive_descendants: 0,
            energy: 1.0,
        }
    }
}

/// Corpus manager
pub struct Corpus {
    /// All test cases
    entries: Vec<CorpusEntry>,

    /// Global coverage bitmap (union of all entries)
    global_edges: BTreeSet<u32>,

    /// Maximum corpus size
    max_size: usize,
}

impl Corpus {
    pub fn new(max_size: usize) -> Self {
        Self {
            entries: Vec::new(),
            global_edges: BTreeSet::new(),
            max_size,
        }
    }

    /// Add entry if it has new coverage
    /// Returns true if added
    pub fn add(&mut self, entry: CorpusEntry) -> bool {
        let mut has_new = false;

        for &edge in &entry.edges {
            if !self.global_edges.contains(&edge) {
                self.global_edges.insert(edge);
                has_new = true;
            }
        }

        if has_new {
            self.entries.push(entry);

            // Cull oldest entries if over limit
            if self.entries.len() > self.max_size {
                // Sort by energy (descending), remove lowest
                self.entries
                    .sort_by(|a, b| b.energy.partial_cmp(&a.energy).unwrap());
                self.entries.truncate(self.max_size);
            }

            true
        } else {
            false
        }
    }

    /// Select entry based on energy (weighted random)
    pub fn select(&mut self, seed: &mut u64) -> Option<&mut CorpusEntry> {
        if self.entries.is_empty() {
            return None;
        }

        // Calculate total energy
        let total_energy: f32 = self.entries.iter().map(|e| e.energy).sum();

        if total_energy == 0.0 {
            // Fallback: uniform random
            let idx = (simple_rand(seed) % self.entries.len() as u64) as usize;
            return Some(&mut self.entries[idx]);
        }

        // Choose by index first, then take the one mutable borrow needed to
        // update the selected entry. This keeps the legacy no-std module
        // valid under the host regression harness as well as the guest build.
        let mut target = (simple_rand(seed) as f32 / u64::MAX as f32) * total_energy;
        let mut selected = None;

        for (index, entry) in self.entries.iter().enumerate() {
            target -= entry.energy;
            if target <= 0.0 {
                selected = Some(index);
                break;
            }
        }

        if let Some(index) = selected {
            let entry = &mut self.entries[index];
            entry.selection_count += 1;
            return Some(entry);
        }

        // Floating-point roundoff can leave a tiny positive remainder; retain
        // the legacy fallback while taking only one mutable borrow.
        let last_index = self.entries.len() - 1;
        Some(&mut self.entries[last_index])
    }

    /// Update energy for all entries
    pub fn update_energy(&mut self) {
        for entry in &mut self.entries {
            entry.energy = calculate_energy(entry);
        }
    }

    /// Get global coverage set
    pub fn get_coverage(&self) -> &BTreeSet<u32> {
        &self.global_edges
    }

    /// Get total unique edges discovered
    pub fn total_edges(&self) -> usize {
        self.global_edges.len()
    }

    /// Get corpus size
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if corpus is empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get entry at index
    pub fn get(&self, index: usize) -> Option<&CorpusEntry> {
        self.entries.get(index)
    }
}

/// Calculate energy for an entry
fn calculate_energy(entry: &CorpusEntry) -> f32 {
    let mut energy = 1.0;

    // Boost: fewer selections = more energy
    energy *= 1.0 / (1.0 + (entry.selection_count as f32).sqrt());

    // Boost: more unique edges = more energy
    energy *= entry.unique_edges as f32 / 10.0;

    // Boost: higher productivity = more energy
    let productivity = if entry.descendant_count > 0 {
        entry.productive_descendants as f32 / entry.descendant_count as f32
    } else {
        1.0 // New entries get full boost
    };
    energy *= productivity;

    // Penalty: longer execution = less energy
    energy /= (entry.exec_time_us as f32 / 1000.0).max(1.0);

    energy.max(0.01) // Minimum energy to keep entries in play
}

/// Simple PRNG (xorshift64)
fn simple_rand(seed: &mut u64) -> u64 {
    let mut x = *seed;
    if x == 0 {
        x = 88172645463325252u64;
    }
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *seed = x;
    x
}

/// Check if edges contain new coverage
pub fn has_new_coverage(edges: &[u32], global_edges: &BTreeSet<u32>) -> (bool, Vec<u32>) {
    let mut new_edges = Vec::new();

    for &edge in edges {
        if !global_edges.contains(&edge) {
            new_edges.push(edge);
        }
    }

    (!new_edges.is_empty(), new_edges)
}
