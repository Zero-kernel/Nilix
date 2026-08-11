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

    /// Occupied KCOV bitmap slots hit by this input
    pub occupied_slots: Vec<u32>,

    /// Number of occupied bitmap slots
    pub occupied_slot_count: usize,

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
    pub fn new(sequence: Vec<Syscall>, occupied_slots: Vec<u32>, exec_time_us: u64) -> Self {
        let occupied_slot_count = occupied_slots.len();
        Self {
            sequence,
            occupied_slots,
            occupied_slot_count,
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

    /// Union of occupied KCOV bitmap slots across all entries
    global_slots: BTreeSet<u32>,

    /// Maximum corpus size
    max_size: usize,
}

impl Corpus {
    pub fn new(max_size: usize) -> Self {
        Self {
            entries: Vec::new(),
            global_slots: BTreeSet::new(),
            max_size,
        }
    }

    /// Add an entry if it occupies a previously unseen bitmap slot.
    /// Returns true if added
    pub fn add(&mut self, entry: CorpusEntry) -> bool {
        let mut has_new = false;

        for &slot in &entry.occupied_slots {
            if !self.global_slots.contains(&slot) {
                self.global_slots.insert(slot);
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

    /// Select an entry based on energy (weighted random) and return its index.
    ///
    /// Returning an index, rather than a live mutable borrow, lets callers
    /// inspect global corpus state before reacquiring the selected entry.
    pub fn select(&mut self, seed: &mut u64) -> Option<usize> {
        if self.entries.is_empty() {
            return None;
        }

        // Calculate total energy
        let total_energy: f32 = self.entries.iter().map(|e| e.energy).sum();

        if total_energy == 0.0 {
            // Fallback: uniform random
            let idx = (simple_rand(seed) % self.entries.len() as u64) as usize;
            self.entries[idx].selection_count += 1;
            return Some(idx);
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
            self.entries[index].selection_count += 1;
            return Some(index);
        }

        // Floating-point roundoff can leave a tiny positive remainder; retain
        // the legacy fallback while taking only one mutable borrow.
        let last_index = self.entries.len() - 1;
        self.entries[last_index].selection_count += 1;
        Some(last_index)
    }

    /// Update energy for all entries
    pub fn update_energy(&mut self) {
        for entry in &mut self.entries {
            entry.energy = calculate_energy(entry);
        }
    }

    /// Get the global set of occupied bitmap slots.
    pub fn get_occupied_slots(&self) -> &BTreeSet<u32> {
        &self.global_slots
    }

    /// Get the number of distinct occupied bitmap slots discovered.
    pub fn total_occupied_slots(&self) -> usize {
        self.global_slots.len()
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

    /// Get a mutable corpus entry by a previously selected stable index.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut CorpusEntry> {
        self.entries.get_mut(index)
    }
}

/// Calculate energy for an entry
fn calculate_energy(entry: &CorpusEntry) -> f32 {
    let mut energy = 1.0;

    // Boost: fewer selections = more energy
    energy *= 1.0 / (1.0 + (entry.selection_count as f32).sqrt());

    // Boost: more occupied slots = more energy
    energy *= entry.occupied_slot_count as f32 / 10.0;

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

/// Check whether a bitmap snapshot contains previously unoccupied slots.
pub fn has_new_coverage(occupied_slots: &[u32], global_slots: &BTreeSet<u32>) -> (bool, Vec<u32>) {
    let mut new_slots = Vec::new();

    for &slot in occupied_slots {
        if !global_slots.contains(&slot) {
            new_slots.push(slot);
        }
    }

    (!new_slots.is_empty(), new_slots)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corpus_tracks_occupied_slots_without_source_edge_claims() {
        let mut corpus = Corpus::new(4);
        let first = CorpusEntry::new(Vec::new(), alloc::vec![0, 3, 31], 1);
        assert!(corpus.add(first));
        assert_eq!(corpus.total_occupied_slots(), 3);

        let duplicate = CorpusEntry::new(Vec::new(), alloc::vec![3, 31], 1);
        assert!(!corpus.add(duplicate));

        let mut seed = 1;
        let selected = corpus.select(&mut seed).expect("populated corpus");
        assert_eq!(corpus.get_occupied_slots().len(), 3);
        let selected_entry = corpus.get_mut(selected).expect("stable selected index");
        selected_entry.productive_descendants += 1;
        assert_eq!(selected_entry.selection_count, 1);

        let (has_new, new_slots) = has_new_coverage(&[3, 7, 31], corpus.get_occupied_slots());
        assert!(has_new);
        assert_eq!(new_slots, alloc::vec![7]);
    }
}
