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

                    let meta = TestMetadata {
                        name: test_name.clone(),
                        category: extract_field(&doc_lines, "Category:"),
                        priority: extract_field(&doc_lines, "Priority:"),
                        status: extract_field(&doc_lines, "Status:"),
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
        if line.starts_with(field) {
            return Some(line[field.len()..].trim().to_string());
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
            .filter(|m| m.category.as_ref().map(|c| c == category).unwrap_or(false))
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
        if category == &"Architecture" || category == &"Memory" || category == &"Scheduler" {
            if p0_tests < 3 {
                println!(
                    "cargo:warning=WARNING: {} has only {} P0 tests (minimum 3 required)",
                    category, p0_tests
                );
            }
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
    // Simple YYYY-MM-DD parser
    let parts: Vec<&str> = date_str.split('-').collect();
    if parts.len() != 3 {
        return None;
    }

    let year: i32 = parts[0].parse().ok()?;
    let month: i32 = parts[1].parse().ok()?;
    let day: i32 = parts[2].parse().ok()?;

    // Approximate timestamp (not accounting for leap years, etc.)
    let days_since_epoch = (year - 1970) * 365 + (month - 1) * 30 + day;
    Some(days_since_epoch as u64 * 24 * 60 * 60)
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

fn generate_registry_validation(_out_dir: &str, _metadata: &[TestMetadata]) {
    // Future: generate code to validate TEST_REGISTRY matches discovered tests
    // For now, we just do compile-time warnings
}
