use std::collections::HashSet;

/// Tracks KCOV bitmap positions that have been occupied across executions.
///
/// KCOV hashes control-flow observations into a finite bitmap. A set bit is an
/// occupied slot, not a globally unique control-flow observation: distinct
/// observations can collide, and the tracker deliberately preserves that lossy
/// contract.
pub struct CoverageTracker {
    seen_slots: HashSet<usize>,
}

impl CoverageTracker {
    pub fn new() -> Self {
        Self {
            seen_slots: HashSet::new(),
        }
    }

    pub fn is_new(&self, coverage: &[u8]) -> bool {
        for (idx, &byte) in coverage.iter().enumerate() {
            if byte != 0 {
                for bit in 0..8 {
                    if byte & (1 << bit) != 0 {
                        let slot = idx * 8 + bit;
                        if !self.seen_slots.contains(&slot) {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    pub fn update(&mut self, coverage: &[u8]) {
        for (idx, &byte) in coverage.iter().enumerate() {
            if byte != 0 {
                for bit in 0..8 {
                    if byte & (1 << bit) != 0 {
                        let slot = idx * 8 + bit;
                        self.seen_slots.insert(slot);
                    }
                }
            }
        }
    }

    pub fn total_occupied_slots(&self) -> usize {
        self.seen_slots.len()
    }
}

impl Default for CoverageTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::CoverageTracker;

    #[test]
    fn bitmap_collisions_are_one_occupied_slot() {
        let mut tracker = CoverageTracker::new();
        let mut first = [0u8; 2];
        first[0] = 1 << 3;
        assert!(tracker.is_new(&first));
        tracker.update(&first);
        assert_eq!(tracker.total_occupied_slots(), 1);

        // Distinct observations that hash to the same bitmap bit are
        // indistinguishable here and must not inflate the global count.
        let colliding = [1u8 << 3, 0];
        assert!(!tracker.is_new(&colliding));
        tracker.update(&colliding);
        assert_eq!(tracker.total_occupied_slots(), 1);

        let distinct = [1u8 << 3, 1u8 << 1];
        assert!(tracker.is_new(&distinct));
        tracker.update(&distinct);
        assert_eq!(tracker.total_occupied_slots(), 2);
    }
}
