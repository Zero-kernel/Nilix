use std::collections::HashSet;

pub struct CoverageTracker {
    seen_edges: HashSet<usize>,
}

impl CoverageTracker {
    pub fn new() -> Self {
        Self {
            seen_edges: HashSet::new(),
        }
    }

    pub fn is_new(&self, coverage: &[u8]) -> bool {
        for (idx, &byte) in coverage.iter().enumerate() {
            if byte != 0 {
                for bit in 0..8 {
                    if byte & (1 << bit) != 0 {
                        let edge = idx * 8 + bit;
                        if !self.seen_edges.contains(&edge) {
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
                        let edge = idx * 8 + bit;
                        self.seen_edges.insert(edge);
                    }
                }
            }
        }
    }

    pub fn total_edges(&self) -> usize {
        self.seen_edges.len()
    }
}

impl Default for CoverageTracker {
    fn default() -> Self {
        Self::new()
    }
}
