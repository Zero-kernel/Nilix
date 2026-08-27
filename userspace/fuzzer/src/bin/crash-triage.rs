//! Convert private cargo-fuzz findings into public-safe candidate identifiers.
//!
//! Raw libFuzzer inputs and logs may be security reproducers.  This tool reads
//! them only inside the ephemeral CI runner and emits a strict two-field report
//! containing a keyed, opaque identifier.  It never copies payload bytes,
//! messages, paths, hashes, stack traces, or previews into its output directory.

use clap::Parser;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashSet;
use std::error::Error;
use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const ARTIFACT_DIR_PREFIX: &str = "cargo-fuzz-crashes-";
const CANDIDATE_SCHEMA: &str = "nilix-fuzz-candidate-v1";
const FINGERPRINT_KEY_ENV: &str = "NILIX_FUZZ_FINGERPRINT_KEY";
const MIN_KEY_BYTES: usize = 32;
const ALLOWED_TARGETS: &[&str] = &[
    "fuzz_syscall",
    "fuzz_vfs_path",
    "fuzz_signal_delivery",
    "fuzz_memory_ops",
    "fuzz_ipc_message",
    "fuzz_scheduler",
    "fuzz_network_packet",
    "fuzz_cgroup_ops",
    "fuzz_elf_loader",
    "fuzz_futex_ops",
];

type HmacSha256 = Hmac<Sha256>;
type TriageResult<T> = Result<T, Box<dyn Error>>;

#[derive(Parser, Debug)]
#[clap(
    author,
    version,
    about = "Create public-safe IDs for private cargo-fuzz findings"
)]
struct Args {
    /// Root containing direct cargo-fuzz-crashes-<target> directories
    #[clap(long)]
    crash_dir: PathBuf,

    /// Empty directory that will receive metadata-only candidate reports
    #[clap(long)]
    output_dir: PathBuf,

    /// Finding count observed by the producer (required cross-check)
    #[clap(long)]
    expected_findings: usize,

    /// Deduplicate identical inputs within the same target and finding kind
    #[clap(long)]
    dedup: bool,
}

#[derive(Debug, Clone)]
struct Candidate {
    file_path: PathBuf,
    candidate_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Summary {
    accepted_findings: usize,
    unique_candidates: usize,
}

fn main() {
    let result = (|| -> TriageResult<()> {
        let args = Args::parse();
        let key = std::env::var(FINGERPRINT_KEY_ENV).map_err(|_| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("required environment variable {FINGERPRINT_KEY_ENV} is missing"),
            )
        })?;
        validate_key(key.as_bytes())?;
        run(args, key.as_bytes()).map(|_| ())
    })();

    if let Err(error) = result {
        eprintln!("candidate triage failed: {error}");
        std::process::exit(1);
    }
}

fn run(args: Args, key: &[u8]) -> TriageResult<Summary> {
    validate_key(key)?;
    ensure_input_directory(&args.crash_dir)?;
    ensure_empty_output_directory(&args.output_dir)?;

    let candidates = collect_candidates(&args.crash_dir, key)?;
    if candidates.len() != args.expected_findings {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "producer/triage finding-count mismatch: expected {}, accepted {}",
                args.expected_findings,
                candidates.len()
            ),
        )
        .into());
    }

    let accepted_findings = candidates.len();
    let final_candidates = if args.dedup {
        deduplicate_candidates(&candidates)
    } else {
        candidates
    };

    for (index, candidate) in final_candidates.iter().enumerate() {
        write_candidate_report(&args.output_dir, index + 1, &candidate.candidate_id)?;
    }

    let summary = Summary {
        accepted_findings,
        unique_candidates: final_candidates.len(),
    };
    println!("[TRIAGE] Accepted findings: {}", summary.accepted_findings);
    println!("[TRIAGE] Unique candidates: {}", summary.unique_candidates);
    Ok(summary)
}

fn validate_key(key: &[u8]) -> TriageResult<()> {
    if key.len() < MIN_KEY_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("fingerprint key must contain at least {MIN_KEY_BYTES} bytes"),
        )
        .into());
    }
    Ok(())
}

fn ensure_input_directory(path: &Path) -> TriageResult<()> {
    let metadata = fs::metadata(path).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("cannot access finding input directory: {error}"),
        )
    })?;
    if !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "finding input path is not a directory",
        )
        .into());
    }
    Ok(())
}

fn ensure_empty_output_directory(path: &Path) -> TriageResult<()> {
    match fs::metadata(path) {
        Ok(metadata) if !metadata.is_dir() => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "candidate output path is not a directory",
            )
            .into());
        }
        Ok(_) => {
            if fs::read_dir(path)?.next().transpose()?.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "candidate output directory must be empty",
                )
                .into());
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(path)?;
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn collect_candidates(root: &Path, key: &[u8]) -> TriageResult<Vec<Candidate>> {
    let mut artifact_dirs = fs::read_dir(root)?.collect::<Result<Vec<_>, _>>()?;
    artifact_dirs.sort_by_key(|entry| entry.file_name());
    let mut candidates = Vec::new();

    for artifact_dir in artifact_dirs {
        if !artifact_dir.file_type()?.is_dir() {
            return Err(invalid_layout(
                "finding root contains a non-directory entry",
            ));
        }

        let directory_name = artifact_dir
            .file_name()
            .into_string()
            .map_err(|_| invalid_layout("artifact directory name is not UTF-8"))?;
        let target = directory_name
            .strip_prefix(ARTIFACT_DIR_PREFIX)
            .ok_or_else(|| invalid_layout("unexpected artifact directory name"))?;
        if !ALLOWED_TARGETS.contains(&target) {
            return Err(invalid_layout("artifact directory names an unknown target"));
        }

        let mut entries = fs::read_dir(artifact_dir.path())?.collect::<Result<Vec<_>, _>>()?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            if !entry.file_type()?.is_file() {
                return Err(invalid_layout(
                    "artifact directory contains a non-file entry",
                ));
            }
            let kind = artifact_kind(&entry.file_name())
                .ok_or_else(|| invalid_layout("artifact has an unsupported filename"))?;
            let payload = fs::read(entry.path())?;
            let candidate_id = keyed_candidate_id(key, target, kind, &payload)?;
            candidates.push(Candidate {
                file_path: entry.path(),
                candidate_id,
            });
        }
    }

    candidates.sort_by(|left, right| left.file_path.cmp(&right.file_path));
    Ok(candidates)
}

fn invalid_layout(message: &'static str) -> Box<dyn Error> {
    io::Error::new(io::ErrorKind::InvalidData, message).into()
}

fn artifact_kind(filename: &OsStr) -> Option<&'static str> {
    let filename = filename.to_str()?;
    if filename.starts_with("crash-") {
        Some("crash")
    } else if filename.starts_with("timeout-") {
        Some("timeout")
    } else if filename.starts_with("oom-") {
        Some("oom")
    } else if filename.starts_with("leak-") {
        Some("leak")
    } else {
        None
    }
}

fn keyed_candidate_id(
    key: &[u8],
    target: &str,
    kind: &str,
    payload: &[u8],
) -> TriageResult<String> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid fingerprint key"))?;
    update_hmac_field(&mut mac, b"schema", CANDIDATE_SCHEMA.as_bytes());
    update_hmac_field(&mut mac, b"target", target.as_bytes());
    update_hmac_field(&mut mac, b"kind", kind.as_bytes());
    update_hmac_field(&mut mac, b"payload", payload);
    let bytes = mac.finalize().into_bytes();
    let mut id = String::with_capacity(12 + bytes.len() * 2);
    id.push_str("hmac-sha256:");
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut id, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(id)
}

fn update_hmac_field(mac: &mut HmacSha256, name: &[u8], value: &[u8]) {
    mac.update(&(name.len() as u64).to_be_bytes());
    mac.update(name);
    mac.update(&(value.len() as u64).to_be_bytes());
    mac.update(value);
}

fn deduplicate_candidates(candidates: &[Candidate]) -> Vec<Candidate> {
    let mut ids = HashSet::new();
    candidates
        .iter()
        .filter(|candidate| ids.insert(candidate.candidate_id.clone()))
        .cloned()
        .collect()
}

fn write_candidate_report(output_dir: &Path, index: usize, candidate_id: &str) -> TriageResult<()> {
    let final_path = output_dir.join(format!("candidate-{index:03}.txt"));
    let temporary_path = output_dir.join(format!(".candidate-{index:03}.tmp"));
    let report = format!("Schema: {CANDIDATE_SCHEMA}\nCandidate-ID: {candidate_id}\n");
    fs::write(&temporary_path, report)?;
    fs::rename(&temporary_path, &final_path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest as _;
    use std::sync::atomic::{AtomicU64, Ordering};

    const TEST_KEY: &[u8] = b"0123456789abcdef0123456789abcdef";
    const OTHER_KEY: &[u8] = b"fedcba9876543210fedcba9876543210";
    static NEXT_TEMP_DIR: AtomicU64 = AtomicU64::new(0);

    struct TestDir(PathBuf);

    impl TestDir {
        fn new(name: &str) -> Self {
            let sequence = NEXT_TEMP_DIR.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "nilix-candidate-triage-{name}-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir_all(&path).expect("create test directory");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn write_artifact(root: &Path, target: &str, filename: &str, payload: &[u8]) {
        let directory = root.join(format!("{ARTIFACT_DIR_PREFIX}{target}"));
        fs::create_dir_all(&directory).expect("create artifact directory");
        fs::write(directory.join(filename), payload).expect("write artifact");
    }

    fn args(root: &Path, expected_findings: usize) -> Args {
        Args {
            crash_dir: root.join("input"),
            output_dir: root.join("output"),
            expected_findings,
            dedup: true,
        }
    }

    fn assert_keyed_id_shape(candidate_id: &str) {
        let digest = candidate_id
            .strip_prefix("hmac-sha256:")
            .expect("candidate ID uses the keyed SHA-256 prefix");
        assert_eq!(digest.len(), 64);
        assert!(digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
    }

    #[test]
    fn validates_fingerprint_key_length_boundaries() {
        assert!(validate_key(&[]).is_err());
        assert!(validate_key(&[0; MIN_KEY_BYTES - 1]).is_err());
        assert!(validate_key(&[0; MIN_KEY_BYTES]).is_ok());
    }

    #[test]
    fn rejects_legacy_continuous_simulator_layout() {
        let temp = TestDir::new("synthetic");
        let input = temp.path().join("input");
        let directory = input.join("continuous-crashes-worker-1");
        fs::create_dir_all(&directory).unwrap();
        fs::write(
            directory.join("crash-000001.txt"),
            b"Crash #1 at iteration 10000\n",
        )
        .unwrap();

        let error = run(args(temp.path(), 1), TEST_KEY).unwrap_err();
        assert!(error.to_string().contains("unexpected artifact directory"));
        assert!(!temp.path().join("output/candidate-001.txt").exists());
    }

    #[test]
    fn emits_only_allowlisted_opaque_metadata_for_low_entropy_payload() {
        let temp = TestDir::new("opaque");
        let input = temp.path().join("input");
        fs::create_dir_all(&input).unwrap();
        let payload = b"tiny-secret-reproducer";
        write_artifact(&input, "fuzz_elf_loader", "crash-a", payload);

        let summary = run(args(temp.path(), 1), TEST_KEY).unwrap();
        assert_eq!(
            summary,
            Summary {
                accepted_findings: 1,
                unique_candidates: 1
            }
        );

        let output = temp.path().join("output");
        let names = fs::read_dir(&output)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(names, vec!["candidate-001.txt"]);

        let report = fs::read_to_string(output.join("candidate-001.txt")).unwrap();
        let lines = report.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], format!("Schema: {CANDIDATE_SCHEMA}"));
        assert!(lines[1].starts_with("Candidate-ID: hmac-sha256:"));
        assert_eq!(lines[1].len(), "Candidate-ID: hmac-sha256:".len() + 64);
        let candidate_id = lines[1]
            .strip_prefix("Candidate-ID: ")
            .expect("candidate ID field");
        assert_keyed_id_shape(candidate_id);
        let raw_sha = Sha256::digest(payload)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let input_path = input.display().to_string();
        for forbidden in [
            "Payload",
            "payload",
            "Preview",
            "Message",
            "Original",
            "SHA-256",
            "Raw-SHA-256",
            "Base64",
            "base64",
            "Path",
            "path",
            "File",
            "file",
            "Type",
            "type",
            "Length",
            "length",
            "Stack",
            "stack",
            "tiny-secret-reproducer",
            "dGlueS1zZWNyZXQtcmVwcm9kdWNlcg==",
            "fuzz_elf_loader",
            "crash",
            "crash-a",
            raw_sha.as_str(),
            input_path.as_str(),
        ] {
            assert!(!report.contains(forbidden), "leaked field: {forbidden}");
        }
    }

    #[test]
    fn candidate_ids_are_keyed_stable_and_target_scoped() {
        let payload = [0xff, 0x00, 0x80, b'A'];
        let first = keyed_candidate_id(TEST_KEY, "fuzz_syscall", "crash", &payload).unwrap();
        let repeated = keyed_candidate_id(TEST_KEY, "fuzz_syscall", "crash", &payload).unwrap();
        let other_target =
            keyed_candidate_id(TEST_KEY, "fuzz_memory_ops", "crash", &payload).unwrap();
        let other_key = keyed_candidate_id(OTHER_KEY, "fuzz_syscall", "crash", &payload).unwrap();
        let other_payload =
            keyed_candidate_id(TEST_KEY, "fuzz_syscall", "crash", &[0xff, 0x00, 0x80, b'B'])
                .unwrap();
        assert_eq!(first, repeated);
        assert_ne!(first, other_target);
        assert_ne!(first, other_key);
        assert_ne!(first, other_payload);
        assert_keyed_id_shape(&first);
    }

    #[test]
    fn accepts_all_finding_kinds_and_keys_kind_into_id() {
        let temp = TestDir::new("all-kinds");
        let input = temp.path().join("input");
        fs::create_dir_all(&input).unwrap();
        let findings = [
            ("crash-a", "crash"),
            ("timeout-a", "timeout"),
            ("oom-a", "oom"),
            ("leak-a", "leak"),
        ];
        let mut ids = HashSet::new();
        for (filename, kind) in findings {
            write_artifact(&input, "fuzz_vfs_path", filename, b"same-payload");
            assert_eq!(artifact_kind(OsStr::new(filename)), Some(kind));
            let id = keyed_candidate_id(TEST_KEY, "fuzz_vfs_path", kind, b"same-payload").unwrap();
            assert_keyed_id_shape(&id);
            assert!(ids.insert(id));
        }
        assert_eq!(ids.len(), findings.len());

        let summary = run(args(temp.path(), findings.len()), TEST_KEY).unwrap();
        assert_eq!(summary.accepted_findings, findings.len());
        assert_eq!(summary.unique_candidates, findings.len());
    }

    #[test]
    fn deduplicates_identical_inputs_and_accepts_leak_findings() {
        let temp = TestDir::new("dedup-leak");
        let input = temp.path().join("input");
        fs::create_dir_all(&input).unwrap();
        write_artifact(&input, "fuzz_network_packet", "leak-a", b"secret");
        write_artifact(&input, "fuzz_network_packet", "leak-b", b"secret");

        let summary = run(args(temp.path(), 2), TEST_KEY).unwrap();
        assert_eq!(summary.accepted_findings, 2);
        assert_eq!(summary.unique_candidates, 1);
    }

    #[test]
    fn rejects_missing_inputs_unknown_files_and_count_mismatches() {
        let missing = TestDir::new("missing");
        assert!(run(args(missing.path(), 0), TEST_KEY).is_err());

        let unknown = TestDir::new("unknown");
        let input = unknown.path().join("input");
        fs::create_dir_all(&input).unwrap();
        write_artifact(&input, "fuzz_vfs_path", "notes.txt", b"not a finding");
        assert!(run(args(unknown.path(), 1), TEST_KEY).is_err());

        let mismatch = TestDir::new("mismatch");
        let input = mismatch.path().join("input");
        fs::create_dir_all(&input).unwrap();
        write_artifact(&input, "fuzz_vfs_path", "timeout-a", b"private");
        assert!(run(args(mismatch.path(), 2), TEST_KEY).is_err());
    }

    #[test]
    fn rejects_unknown_targets_and_nested_directories() {
        let unknown = TestDir::new("unknown-target");
        let input = unknown.path().join("input");
        fs::create_dir_all(&input).unwrap();
        write_artifact(&input, "fuzz_not_allowlisted", "crash-a", b"private");
        let error = run(args(unknown.path(), 1), TEST_KEY).unwrap_err();
        assert!(error.to_string().contains("unknown target"));

        let nested = TestDir::new("nested-entry");
        let input = nested.path().join("input");
        let artifact = input.join(format!("{ARTIFACT_DIR_PREFIX}fuzz_vfs_path"));
        fs::create_dir_all(artifact.join("nested")).unwrap();
        let error = run(args(nested.path(), 0), TEST_KEY).unwrap_err();
        assert!(error.to_string().contains("non-file entry"));
    }

    #[test]
    fn rejects_input_root_that_is_a_regular_file() {
        let temp = TestDir::new("input-file");
        fs::write(temp.path().join("input"), b"not a directory").unwrap();
        let error = run(args(temp.path(), 0), TEST_KEY).unwrap_err();
        assert!(error.to_string().contains("not a directory"));
    }

    #[test]
    fn rejects_non_empty_output_without_overwriting_it() {
        let temp = TestDir::new("output-nonempty");
        fs::create_dir_all(temp.path().join("input")).unwrap();
        let output = temp.path().join("output");
        fs::create_dir_all(&output).unwrap();
        let sentinel = output.join("sentinel.txt");
        fs::write(&sentinel, b"keep-me").unwrap();

        let error = run(args(temp.path(), 0), TEST_KEY).unwrap_err();
        assert!(error.to_string().contains("must be empty"));
        assert_eq!(fs::read(&sentinel).unwrap(), b"keep-me");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_artifact_entries() {
        use std::os::unix::fs::symlink;

        let temp = TestDir::new("symlink-entry");
        let input = temp.path().join("input");
        let artifact = input.join(format!("{ARTIFACT_DIR_PREFIX}fuzz_vfs_path"));
        fs::create_dir_all(&artifact).unwrap();
        let outside_file = temp.path().join("outside-finding");
        fs::write(&outside_file, b"private").unwrap();
        symlink(&outside_file, artifact.join("crash-link")).unwrap();

        let error = run(args(temp.path(), 0), TEST_KEY).unwrap_err();
        assert!(error.to_string().contains("non-file entry"));
    }
}
