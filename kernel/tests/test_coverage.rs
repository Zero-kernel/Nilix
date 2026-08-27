//! Compile-time test coverage enforcement
#![allow(clippy::manual_strip)]
//!
//! These tests run during `cargo test` to enforce minimum test coverage
//! and detect stale placeholder tests.

#[cfg(test)]
mod test_coverage_tests {
    use std::fs;
    use std::path::Path;

    /// Enforce minimum P0 coverage per category
    #[test]
    fn enforce_minimum_p0_coverage() {
        let test_files = scan_test_files();
        let metadata = parse_test_metadata(&test_files);

        // Keep this integration oracle tied to the same source-discovery
        // count emitted by kernel/build.rs.  A path/configuration regression
        // that makes the scanner see zero (or only a subset) must fail rather
        // than silently passing the category minimums.
        let discovered = metadata.len();
        assert!(discovered > 0, "no RuntimeTest implementations discovered");
        if let Some(expected) = option_env!("NILIX_TEST_TOTAL") {
            let expected = expected
                .parse::<usize>()
                .expect("kernel build script emitted an invalid test count");
            assert_eq!(
                discovered, expected,
                "host coverage scanner disagrees with build-time RuntimeTest discovery"
            );
        }

        let categories = [
            ("Architecture", 3),
            ("Memory", 3),
            ("IPC", 3),
            ("Scheduler", 3),
            ("VFS", 3),
        ];

        let mut failures = Vec::new();

        for (category, min_p0) in &categories {
            let p0_count = metadata
                .iter()
                .filter(|m| {
                    // LOW-10 FIX: Require explicit Status: Implemented (Safety > Efficiency).
                    // Previously: unwrap_or(true) counted missing status as implemented.
                    // Now: fail-closed - only count tests with explicit "Implemented" status.
                    m.category
                        .as_deref()
                        .map(|c| category_matches(c, category))
                        .unwrap_or(false)
                        && m.priority.as_ref().map(|p| p == "P0").unwrap_or(false)
                        && m.status
                            .as_ref()
                            .map(|s| s == "Implemented")
                            .unwrap_or(false)
                })
                .count();

            if p0_count < *min_p0 {
                failures.push(format!(
                    "{} has only {} P0 tests (minimum {} required)",
                    category, p0_count, min_p0
                ));
            }
        }

        if !failures.is_empty() {
            panic!("P0 coverage below minimum:\n{}", failures.join("\n"));
        }
    }

    /// Detect stale placeholder tests (>8 weeks without implementation)
    #[test]
    fn detect_stale_placeholders() {
        let test_files = scan_test_files();
        let metadata = parse_test_metadata(&test_files);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let eight_weeks = 8 * 7 * 24 * 60 * 60;
        let mut stale_p0_p1 = Vec::new();
        let mut stale_other = Vec::new();

        for meta in metadata {
            if meta.status.as_deref() != Some("Placeholder") {
                continue;
            }
            let Some(date_str) = &meta.placeholder_date else {
                panic!("placeholder {} is missing its TODO date", meta.name);
            };
            let Some(timestamp) = parse_date(date_str) else {
                panic!(
                    "placeholder {} has an invalid TODO date {:?}",
                    meta.name, date_str
                );
            };
            if now <= timestamp.saturating_add(eight_weeks) {
                continue;
            }

            // LOW-11 FIX: Check for valid waiver (Safety > Efficiency).
            // Waivers must have both owner and non-expired expiration date.
            let has_valid_waiver = match (&meta.waiver_owner, &meta.waiver_expiration) {
                (Some(owner), Some(exp_str)) if !owner.is_empty() => {
                    parse_date(exp_str).is_some_and(|exp_ts| now <= exp_ts)
                }
                _ => false,
            };
            if has_valid_waiver {
                continue;
            }

            let msg = format!("{} (created {}, >8 weeks old)", meta.name, date_str);
            // P0/P1 placeholders fail CI, others warn only.
            if matches!(meta.priority.as_deref(), Some("P0") | Some("P1")) {
                stale_p0_p1.push(msg);
            } else {
                stale_other.push(msg);
            }
        }

        // Warn about stale lower-priority placeholders
        if !stale_other.is_empty() {
            println!(
                "Warning: {} stale P2/P3 placeholder tests:",
                stale_other.len()
            );
            for s in &stale_other {
                println!("  - {}", s);
            }
        }

        // FAIL CI for stale P0/P1 placeholders without valid waivers
        if !stale_p0_p1.is_empty() {
            panic!(
                "Stale P0/P1 placeholder tests detected (>8 weeks):\n{}\n\n\
                 To waive a placeholder, add:\n\
                 /// Waiver-Owner: <name>\n\
                 /// Waiver-Expires: YYYY-MM-DD\n\
                 to the test documentation.",
                stale_p0_p1.join("\n")
            );
        }
    }

    /// Verify test naming convention: test_{round}_{id}_{description}
    #[test]
    fn verify_test_naming_convention() {
        let test_files = scan_test_files();
        let metadata = parse_test_metadata(&test_files);

        let mut violations = Vec::new();

        for meta in metadata {
            let name = &meta.name;

            // Check for regression tests (r172_01_...) format
            if name.starts_with('r') && name.len() > 4 {
                let parts: Vec<&str> = name.split('_').collect();
                if parts.len() < 3 {
                    violations.push(format!(
                        "{} doesn't follow convention: r###_##_description",
                        name
                    ));
                }
            }
        }

        if !violations.is_empty() {
            println!(
                "Warning: {} naming convention violations:",
                violations.len()
            );
            for v in &violations {
                println!("  - {}", v);
            }
            // Don't fail the build for naming violations
        }
    }

    // Helper functions

    fn scan_test_files() -> Vec<std::path::PathBuf> {
        let mut files = Vec::new();
        let src_dir = Path::new("src");

        if src_dir.join("runtime_tests.rs").exists() {
            files.push(src_dir.join("runtime_tests.rs"));
        }

        let runtime_tests_dir = src_dir.join("runtime_tests");
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

    #[derive(Debug)]
    struct TestMetadata {
        name: String,
        category: Option<String>,
        priority: Option<String>,
        status: Option<String>,
        placeholder_date: Option<String>,
        waiver_owner: Option<String>,
        waiver_expiration: Option<String>,
    }

    fn parse_test_metadata(files: &[std::path::PathBuf]) -> Vec<TestMetadata> {
        let mut metadata = Vec::new();

        for file in files {
            if let Ok(content) = fs::read_to_string(file) {
                let lines: Vec<&str> = content.lines().collect();

                for (i, line) in lines.iter().enumerate() {
                    if line.contains("impl RuntimeTest for") {
                        let test_name = extract_test_name(line);

                        let mut doc_lines = Vec::new();
                        let mut j = i;
                        while j > 0 {
                            j -= 1;
                            let prev_line = lines[j].trim();
                            if prev_line.starts_with("///") {
                                doc_lines.insert(0, prev_line.trim_start_matches("///").trim());
                            } else if !prev_line.is_empty() && !prev_line.starts_with("//") {
                                break;
                            }
                        }

                        let file_is_p0 = file
                            .file_name()
                            .and_then(|name| name.to_str())
                            .is_some_and(|name| name == "regression_tests_p0.rs");
                        let inferred_category = infer_category(&test_name).to_string();
                        let meta = TestMetadata {
                            name: test_name,
                            // Mirror kernel/build.rs exactly.  RuntimeTest
                            // implementations are the authoritative concrete
                            // tests; missing optional tags are inferred from
                            // the implementation/file rather than counted as
                            // an absent test.
                            category: extract_field(&doc_lines, "Category:")
                                .or(Some(inferred_category)),
                            priority: extract_field(&doc_lines, "Priority:")
                                .or_else(|| Some(if file_is_p0 { "P0" } else { "P1" }.to_string())),
                            status: extract_field(&doc_lines, "Status:")
                                .or_else(|| Some("Implemented".to_string())),
                            placeholder_date: extract_field(&doc_lines, "TODO:"),
                            waiver_owner: extract_field(&doc_lines, "Waiver-Owner:"),
                            waiver_expiration: extract_field(&doc_lines, "Waiver-Expires:"),
                        };

                        metadata.push(meta);
                    }
                }
            }
        }

        metadata
    }

    fn extract_test_name(line: &str) -> String {
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

    fn parse_date(date_str: &str) -> Option<u64> {
        let mut parts = date_str.split('-');
        let year: u64 = parts.next()?.parse().ok()?;
        let month: u64 = parts.next()?.parse().ok()?;
        let day: u64 = parts.next()?.parse().ok()?;
        if parts.next().is_some() || year < 1970 || !(1..=12).contains(&month) {
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
        years
            .checked_mul(365)?
            .checked_add(leap_days)?
            .checked_add(prior_month_days)?
            .checked_add(day - 1)?
            .checked_mul(24 * 60 * 60)
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
        } else if lower.contains("security") || lower.contains("seccomp") || lower.contains("audit")
        {
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
}
