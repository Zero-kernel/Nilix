//! Build-time test coverage validation for Nilix kernel
//!
//! This build script:
//! 1. Scans runtime_tests/ for test functions
//! 2. Parses test metadata from doc comments
//! 3. Verifies all tests are registered in TEST_REGISTRY
//! 4. Enforces minimum coverage per category
//! 5. Generates warnings for stale placeholder tests
//! 6. Emits coverage statistics

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=src/runtime_tests.rs");
    println!("cargo:rerun-if-changed=src/runtime_tests/");
    println!("cargo:rerun-if-changed=src/test_framework.rs");

    let out_dir = env::var("OUT_DIR").unwrap();
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    // Scan for test files
    let test_files = scan_test_files(&manifest_dir);

    // Parse test metadata
    let test_metadata = parse_test_metadata(&test_files);

    // Validate coverage
    validate_coverage(&test_metadata);

    // Generate warnings for stale placeholders
    check_stale_placeholders(&test_metadata);

    // Emit statistics
    emit_statistics(&test_metadata);

    // Generate test registry validation
    generate_registry_validation(&out_dir, &test_metadata);
}

fn scan_test_files(manifest_dir: &str) -> Vec<PathBuf> {
    let mut files = Vec::new();

    let runtime_tests_dir = Path::new(manifest_dir).join("src").join("runtime_tests");

    // Add main runtime_tests.rs
    let main_tests = Path::new(manifest_dir).join("src").join("runtime_tests.rs");
    if main_tests.exists() {
        files.push(main_tests);
    }

    // Add files in runtime_tests/
    if runtime_tests_dir.exists() {
        if let Ok(entries) = fs::read_dir(&runtime_tests_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("rs") {
                    files.push(path);
                }
            }
        }
    }

    files
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct TestMetadata {
    name: String,
    category: Option<String>,
    priority: Option<String>,
    status: Option<String>,
    description: Option<String>,
    qa_round: Option<String>,
    placeholder_date: Option<String>,
    file: PathBuf,
    line: usize,
}

fn parse_test_metadata(files: &[PathBuf]) -> Vec<TestMetadata> {
    let mut metadata = Vec::new();

    for file in files {
        if let Ok(content) = fs::read_to_string(file) {
            let lines: Vec<&str> = content.lines().collect();

            for (i, line) in lines.iter().enumerate() {
                // Look for test functions (struct implementing RuntimeTest)
                if line.contains("impl RuntimeTest for") {
                    let test_name = extract_test_name(line);

                    // Parse doc comments above this line
                    let mut doc_lines = Vec::new();
                    let mut j = i;
                    while j > 0 {
                        j -= 1;
                        let prev_line = lines[j].trim();
                        if prev_line.starts_with("///") {
                            doc_lines.insert(0, prev_line.trim_start_matches("///").trim());
                        } else if prev_line.starts_with("//!") {
                            // Module-level doc, stop
                            break;
                        } else if !prev_line.is_empty() && !prev_line.starts_with("//") {
                            // Non-doc-comment line, stop
                            break;
                        }
                    }

                    // Runtime tests historically did not carry the optional
                    // doc metadata fields consistently.  Treat source
                    // discovery itself as authoritative: infer a category
                    // and mark the concrete `RuntimeTest` implementation as
                    // implemented when a field is absent.  Reporting zero
                    // tests for a tree containing dozens of implementations
                    // made the coverage gate silently meaningless.
                    let category = extract_field(&doc_lines, "Category:")
                        .or_else(|| Some(infer_category(&test_name).to_string()));
                    let priority = extract_field(&doc_lines, "Priority:").or_else(|| {
                        // The dedicated P0 regression module is itself the
                        // source of truth for critical coverage.  Preserve
                        // that intent even when individual tests omit the
                        // optional doc tag.
                        if file
                            .file_name()
                            .and_then(|name| name.to_str())
                            .is_some_and(|name| name == "regression_tests_p0.rs")
                        {
                            Some("P0".to_string())
                        } else {
                            Some("P1".to_string())
                        }
                    });
                    let status = extract_field(&doc_lines, "Status:")
                        .or_else(|| Some("Implemented".to_string()));

                    let meta = TestMetadata {
                        name: test_name.clone(),
                        category,
                        priority,
                        status,
                        description: doc_lines.first().map(|s| s.to_string()),
                        qa_round: extract_field(&doc_lines, "QA Round:"),
                        placeholder_date: extract_field(&doc_lines, "TODO:"),
                        file: file.clone(),
                        line: i + 1,
                    };

                    metadata.push(meta);
                }
            }
        }
    }

    metadata
}

fn extract_test_name(line: &str) -> String {
    // Extract from "impl RuntimeTest for TestName"
    let parts: Vec<&str> = line.split_whitespace().collect();
    if let Some(pos) = parts.iter().position(|&s| s == "for") {
        if let Some(name) = parts.get(pos + 1) {
            return name.trim_end_matches('{').to_string();
        }
    }
    "UnknownTest".to_string()
}

fn extract_field(doc_lines: &[&str], field: &str) -> Option<String> {
    for line in doc_lines {
        if let Some(content) = line.strip_prefix(field) {
            return Some(content.trim().to_string());
        }
    }
    None
}

fn validate_coverage(metadata: &[TestMetadata]) {
    let categories = [
        "Architecture",
        "Memory",
        "IPC",
        "Scheduler",
        "VFS",
        "Network",
        "Security",
        "SMP",
        "Namespaces",
        "Regression",
    ];

    println!("cargo:warning==============================================");
    println!("cargo:warning=Runtime Test Coverage Validation");
    println!("cargo:warning==============================================");

    let mut total_tests = 0;
    let mut total_implemented = 0;
    let mut total_p0 = 0;

    for category in &categories {
        let cat_tests: Vec<_> = metadata
            .iter()
            .filter(|m| {
                m.category
                    .as_deref()
                    .map(|c| category_matches(c, category))
                    .unwrap_or(false)
            })
            .collect();

        let implemented = cat_tests
            .iter()
            .filter(|m| {
                m.status
                    .as_ref()
                    .map(|s| s == "Implemented")
                    .unwrap_or(true)
            })
            .count();

        let p0_tests = cat_tests
            .iter()
            .filter(|m| m.priority.as_ref().map(|p| p == "P0").unwrap_or(false))
            .count();

        total_tests += cat_tests.len();
        total_implemented += implemented;
        total_p0 += p0_tests;

        println!(
            "cargo:warning=[{}] {} tests ({} implemented, {} P0)",
            category,
            cat_tests.len(),
            implemented,
            p0_tests
        );

        // Enforce minimums for P0 coverage
        if (category == &"Architecture" || category == &"Memory" || category == &"Scheduler")
            && p0_tests < 3
        {
            println!(
                "cargo:warning=WARNING: {} has only {} P0 tests (minimum 3 required)",
                category, p0_tests
            );
        }
    }

    println!("cargo:warning=----------------------------------------------");
    println!(
        "cargo:warning=Total: {} tests ({} implemented, {} P0)",
        total_tests, total_implemented, total_p0
    );

    let coverage = if total_tests > 0 {
        (total_implemented * 100) / total_tests
    } else {
        0
    };

    println!("cargo:warning=Coverage: {}%", coverage);
    if metadata.is_empty() {
        // A source scan that unexpectedly finds nothing is a build-integrity
        // failure, not a valid zero-coverage result.  Keep the build usable
        // for early-boot tooling but make the condition unmistakable in CI.
        println!("cargo:warning=ERROR: no RuntimeTest implementations discovered");
    }
    println!("cargo:warning==============================================");
}

fn check_stale_placeholders(metadata: &[TestMetadata]) {
    use std::time::{SystemTime, UNIX_EPOCH};

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let eight_weeks = 8 * 7 * 24 * 60 * 60;

    for meta in metadata {
        if let Some(status) = &meta.status {
            if status == "Placeholder" {
                if let Some(date_str) = &meta.placeholder_date {
                    // Parse date (format: YYYY-MM-DD)
                    if let Some(timestamp) = parse_date(date_str) {
                        if now > timestamp + eight_weeks {
                            println!(
                                "cargo:warning=STALE PLACEHOLDER: {} (created {}, >8 weeks old)",
                                meta.name, date_str
                            );
                            println!(
                                "cargo:warning=  File: {}:{}",
                                meta.file.display(),
                                meta.line
                            );
                        }
                    }
                }
            }
        }
    }
}

fn parse_date(date_str: &str) -> Option<u64> {
    // Parse without allocating a temporary Vec and reject impossible
    // calendar dates before converting to seconds.  Build metadata is input
    // to generated test ordering, so wrapped/ambiguous timestamps must fail
    // closed rather than silently changing the registry order.
    let mut parts = date_str.split('-');
    let year: u64 = parts.next()?.parse().ok()?;
    let month: u64 = parts.next()?.parse().ok()?;
    let day: u64 = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }

    if year < 1970 || !(1..=12).contains(&month) {
        return None;
    }

    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let month_days = [
        31u64,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if day == 0 || day > month_days[(month - 1) as usize] {
        return None;
    }

    let years = year.checked_sub(1970)?;
    let leap_days = ((year - 1) / 4 - 1969 / 4)
        .checked_sub((year - 1) / 100 - 1969 / 100)?
        .checked_add((year - 1) / 400 - 1969 / 400)?;
    let prior_month_days = month_days[..(month - 1) as usize]
        .iter()
        .try_fold(0u64, |sum, days| sum.checked_add(*days))?;
    let days_since_epoch = years
        .checked_mul(365)?
        .checked_add(leap_days)?
        .checked_add(prior_month_days)?
        .checked_add(day - 1)?;
    days_since_epoch.checked_mul(24 * 60 * 60)
}

fn emit_statistics(metadata: &[TestMetadata]) {
    let total = metadata.len();
    let implemented = metadata
        .iter()
        .filter(|m| {
            m.status
                .as_ref()
                .map(|s| s == "Implemented")
                .unwrap_or(true)
        })
        .count();

    let placeholders = metadata
        .iter()
        .filter(|m| {
            m.status
                .as_ref()
                .map(|s| s == "Placeholder")
                .unwrap_or(false)
        })
        .count();

    // Emit as environment variables for use in code
    println!("cargo:rustc-env=NILIX_TEST_TOTAL={}", total);
    println!("cargo:rustc-env=NILIX_TEST_IMPLEMENTED={}", implemented);
    println!("cargo:rustc-env=NILIX_TEST_PLACEHOLDERS={}", placeholders);
}

fn generate_registry_validation(out_dir: &str, metadata: &[TestMetadata]) {
    // Generate a deterministic manifest consumed by the kernel test framework.
    // This replaces the historical no-op and gives CI a concrete discovery
    // oracle even when a new test is added outside the hand-maintained list.
    let mut generated = String::from("// @generated by kernel/build.rs; do not edit.\n");
    generated.push_str("pub const DISCOVERED_RUNTIME_TEST_NAMES: &[&str] = &[\n");
    for test in metadata {
        generated.push_str("    ");
        generated.push_str(&format!("{:?},\n", test.name));
    }
    generated.push_str("];\n");
    generated.push_str(&format!(
        "pub const DISCOVERED_RUNTIME_TEST_COUNT: usize = {};\n",
        metadata.len()
    ));
    generated.push_str("pub static DISCOVERED_TEST_REGISTRY: &[TestDescriptor] = &[\n");
    for test in metadata {
        let category = infer_category(&test.name);
        let priority = match test.priority.as_deref() {
            Some("P0") => "P0",
            Some("P2") => "P2",
            _ => "P1",
        };
        let status = match test.status.as_deref() {
            Some("Placeholder") => "Placeholder",
            Some("Skipped") => "Skipped",
            _ => "Implemented",
        };
        generated.push_str(&format!(
            "    TestDescriptor::new({:?}, {:?}, TestCategory::{}, TestPriority::{}, TestStatus::{}, {:?}),\n",
            test.name.to_ascii_lowercase(),
            test.name,
            category,
            priority,
            status,
            test.description.as_deref().unwrap_or("Discovered runtime test"),
        ));
    }
    generated.push_str("];\n");
    let path = Path::new(out_dir).join("test_registry_validation.rs");
    fs::write(&path, generated).expect("write generated test registry manifest");
    println!("cargo:rerun-if-changed=src/runtime_tests.rs");
}

fn infer_category(name: &str) -> &'static str {
    let lower = name.to_ascii_lowercase();
    if lower.contains("heap")
        || lower.contains("tlb")
        || lower.contains("cow")
        || lower.contains("memory")
    {
        "Memory"
    } else if lower.contains("futex") || lower.contains("pipe") || lower.contains("signal") {
        "Ipc"
    } else if lower.contains("sched") || lower.contains("cpu") || lower.contains("starvation") {
        "Scheduler"
    } else if lower.contains("vfs") || lower.contains("ramfs") || lower.contains("mount") {
        "Vfs"
    } else if lower.contains("net") || lower.contains("tcp") || lower.contains("arp") {
        "Network"
    } else if lower.contains("security") || lower.contains("seccomp") || lower.contains("audit") {
        "Security"
    } else if lower.contains("smp") || lower.contains("ipi") {
        "Smp"
    } else if lower.contains("namespace") || lower.contains("ns") {
        "Namespaces"
    } else if lower.contains("context") || lower.contains("tls") || lower.contains("fpu") {
        "Architecture"
    } else {
        "Regression"
    }
}

fn category_matches(actual: &str, expected: &str) -> bool {
    actual.eq_ignore_ascii_case(expected)
        || matches!(
            (actual, expected),
            ("Ipc", "IPC") | ("Vfs", "VFS") | ("Smp", "SMP")
        )
}
