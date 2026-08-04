use anyhow::Result;
use std::fs;
use std::path::{Path, PathBuf};
use rand::Rng;

use crate::program::SyscallProgram;
use crate::stats::FuzzStats;

pub struct Corpus {
    dir: PathBuf,
    entries: Vec<CorpusEntry>,
}

struct CorpusEntry {
    id: usize,
    program: SyscallProgram,
    coverage: Vec<u8>,
    energy: f64,
}

impl Corpus {
    pub fn new(dir: &Path) -> Result<Self> {
        fs::create_dir_all(dir)?;

        let mut corpus = Self {
            dir: dir.to_path_buf(),
            entries: Vec::new(),
        };

        // Load existing corpus entries
        corpus.load_from_disk()?;

        Ok(corpus)
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn add(&mut self, program: SyscallProgram, coverage: Vec<u8>) -> Result<()> {
        let id = self.entries.len();

        // Save to disk
        let program_path = self.dir.join(format!("prog-{}.bin", id));
        let json_path = self.dir.join(format!("prog-{}.json", id));

        program.save_to_file(&program_path)?;
        fs::write(json_path, program.to_json()?)?;

        // Add to memory
        self.entries.push(CorpusEntry {
            id,
            program,
            coverage,
            energy: 1.0,
        });

        Ok(())
    }

    pub fn select_seed(&mut self, _stats: &FuzzStats) -> Result<SyscallProgram> {
        if self.entries.is_empty() {
            anyhow::bail!("Corpus is empty");
        }

        // Energy-based selection: prioritize recent discoveries
        let mut rng = rand::thread_rng();

        // Boost energy for recently added entries
        let len = self.entries.len();
        for (idx, entry) in self.entries.iter_mut().enumerate() {
            if idx + 10 >= len {
                entry.energy = 10.0;
            } else {
                entry.energy *= 0.99;
            }
        }

        // Weighted random selection
        let total_energy: f64 = self.entries.iter().map(|e| e.energy).sum();
        let mut threshold = rng.gen::<f64>() * total_energy;

        for entry in &self.entries {
            threshold -= entry.energy;
            if threshold <= 0.0 {
                return Ok(entry.program.clone());
            }
        }

        // Fallback: return last entry
        Ok(self.entries.last().unwrap().program.clone())
    }

    fn load_from_disk(&mut self) -> Result<()> {
        if !self.dir.exists() {
            return Ok(());
        }

        let mut loaded = 0;
        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().and_then(|s| s.to_str()) == Some("bin") {
                if let Ok(program) = SyscallProgram::load_from_file(&path) {
                    // Create dummy coverage for loaded entries
                    self.entries.push(CorpusEntry {
                        id: self.entries.len(),
                        program,
                        coverage: vec![0; 4096],
                        energy: 1.0,
                    });
                    loaded += 1;
                }
            }
        }

        if loaded > 0 {
            println!("Loaded {} corpus entries from disk", loaded);
        }

        Ok(())
    }
}
