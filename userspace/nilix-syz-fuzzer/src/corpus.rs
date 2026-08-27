use anyhow::{bail, Context, Result};
use rand::Rng;
use std::fs;
use std::path::{Path, PathBuf};

use crate::program::SyscallProgram;
use crate::stats::FuzzStats;

pub struct Corpus {
    dir: PathBuf,
    entries: Vec<CorpusEntry>,
    /// Monotonic on-disk identifier allocator.  It is independent of
    /// `entries.len()` because files can be deleted or imported with gaps.
    next_id: usize,
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
            next_id: 0,
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
        let id = self.next_id;
        self.next_id = self
            .next_id
            .checked_add(1)
            .context("corpus entry identifier space exhausted")?;

        // Save to disk
        let program_path = self.dir.join(format!("prog-{}.bin", id));
        let json_path = self.dir.join(format!("prog-{}.json", id));

        program
            .save_to_file(&program_path)
            .with_context(|| format!("failed to persist corpus entry {id}"))?;
        // Publish the canonical metadata companion only after the program file
        // succeeds.  The same atomic writer is used for both files so a
        // failed companion write cannot leave an apparently complete but
        // unverifiable entry on disk.
        if let Err(error) = program.save_to_file(&json_path) {
            let _ = fs::remove_file(&program_path);
            return Err(error).with_context(|| format!("failed to persist corpus metadata {id}"));
        }

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

        let mut disk_entries = Vec::new();
        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?;
            let path = entry.path();

            let file_type = entry.file_type()?;
            if !file_type.is_file() || file_type.is_symlink() {
                bail!("corpus contains a non-regular entry: {}", path.display());
            }

            let Some(extension) = path.extension().and_then(|s| s.to_str()) else {
                bail!(
                    "corpus contains an entry without a recognized extension: {}",
                    path.display()
                );
            };
            if extension != "bin" && extension != "json" {
                bail!("corpus contains an unexpected file: {}", path.display());
            }

            let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
                bail!(
                    "corpus entry filename is not valid UTF-8: {}",
                    path.display()
                );
            };
            let Some(id_text) = stem.strip_prefix("prog-") else {
                bail!(
                    "corpus entry has a non-canonical filename: {}",
                    path.display()
                );
            };
            let id = id_text.parse::<usize>().with_context(|| {
                format!("invalid corpus entry identifier in {}", path.display())
            })?;
            if id_text != id.to_string() {
                bail!(
                    "corpus entry identifier is not canonical: {}",
                    path.display()
                );
            }
            disk_entries.push((id, extension.to_string(), path));
        }

        disk_entries.sort_by_key(|(id, _, _)| *id);
        let bin_ids: std::collections::HashSet<usize> = disk_entries
            .iter()
            .filter_map(|(id, extension, _)| (extension == "bin").then_some(*id))
            .collect();
        for (id, extension, path) in &disk_entries {
            if extension == "json" && !bin_ids.contains(id) {
                bail!(
                    "corpus metadata has no corresponding binary entry: {}",
                    path.display()
                );
            }
        }
        let mut loaded = 0usize;
        let mut previous_id = None;
        for (id, extension, path) in disk_entries {
            if extension != "bin" {
                continue;
            }
            if previous_id == Some(id) {
                bail!("corpus contains duplicate files for entry {id}");
            }
            previous_id = Some(id);

            let program = SyscallProgram::load_from_file(&path)
                .with_context(|| format!("corrupt or invalid corpus entry {}", path.display()))?;
            let metadata_path = self.dir.join(format!("prog-{id}.json"));
            let metadata_type = match fs::symlink_metadata(&metadata_path) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    bail!("corpus entry {id} is missing its metadata companion")
                }
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!(
                            "failed to inspect corpus metadata {}",
                            metadata_path.display()
                        )
                    })
                }
            };
            if !metadata_type.file_type().is_file() || metadata_type.file_type().is_symlink() {
                bail!("corpus entry {id} is missing its metadata companion");
            }
            let metadata = fs::read_to_string(&metadata_path).with_context(|| {
                format!("failed to read corpus metadata {}", metadata_path.display())
            })?;
            let metadata_program: SyscallProgram = serde_json::from_str(&metadata)
                .with_context(|| format!("corrupt corpus metadata {}", metadata_path.display()))?;
            metadata_program
                .validate()
                .with_context(|| format!("invalid corpus metadata {}", metadata_path.display()))?;
            if metadata_program != program {
                bail!("corpus metadata disagrees with binary entry {id}");
            }

            // Create dummy coverage for loaded entries.  Coverage is rebuilt by
            // fresh executions; the persisted program remains authoritative.
            self.entries.push(CorpusEntry {
                id,
                program,
                coverage: vec![0; 4096],
                energy: 1.0,
            });
            loaded += 1;
            self.next_id = id
                .checked_add(1)
                .context("corpus entry identifier space exhausted")?;
        }

        if loaded > 0 {
            println!("Loaded {} corpus entries from disk", loaded);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::{Syscall, SYS_GETPID};

    fn sample_program() -> SyscallProgram {
        SyscallProgram {
            syscalls: vec![Syscall {
                number: SYS_GETPID,
                args: vec![],
            }],
        }
    }

    #[test]
    fn allocates_ids_above_existing_gaps_instead_of_entries_len() {
        let directory = tempfile::tempdir().unwrap();
        let first = sample_program();
        let first_bin = directory.path().join("prog-0.bin");
        first.save_to_file(&first_bin).unwrap();
        std::fs::write(
            directory.path().join("prog-0.json"),
            first.to_json().unwrap(),
        )
        .unwrap();

        let third = sample_program();
        let third_bin = directory.path().join("prog-2.bin");
        third.save_to_file(&third_bin).unwrap();
        std::fs::write(
            directory.path().join("prog-2.json"),
            third.to_json().unwrap(),
        )
        .unwrap();

        let mut corpus = Corpus::new(directory.path()).unwrap();
        corpus.add(sample_program(), vec![0; 4096]).unwrap();
        assert!(directory.path().join("prog-3.bin").is_file());
        assert!(directory.path().join("prog-3.json").is_file());
    }

    #[test]
    fn rejects_corrupt_entries_instead_of_silently_dropping_them() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("prog-0.bin"), b"not-json").unwrap();
        let error = match Corpus::new(directory.path()) {
            Ok(_) => panic!("corrupt corpus unexpectedly loaded"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("corrupt or invalid corpus entry"));
    }

    #[test]
    fn rejects_orphan_metadata_files() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("prog-4.json"), "{}").unwrap();
        let error = match Corpus::new(directory.path()) {
            Ok(_) => panic!("orphan metadata unexpectedly loaded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("no corresponding binary"));
    }

    #[test]
    fn rejects_binary_entries_without_metadata_companions() {
        let directory = tempfile::tempdir().unwrap();
        sample_program()
            .save_to_file(&directory.path().join("prog-0.bin"))
            .unwrap();
        let error = match Corpus::new(directory.path()) {
            Ok(_) => panic!("entry without metadata unexpectedly loaded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("missing its metadata companion"));
    }
}
