//! Compile-time test coverage enforcement
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
                    m.category.as_ref().map(|c| c == category).unwrap_or(false)
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
            if let Some(status) = &meta.status {
                if status == "Placeholder" {
                    if let Some(date_str) = &meta.placeholder_date {
                        if let Some(timestamp) = parse_date(date_str) {
                            if now > timestamp + eight_weeks {
                                // LOW-11 FIX: Check for valid waiver (Safety > Efficiency).
                                // Waivers must have both owner and non-expired expiration date.
                                let has_valid_waiver = match (&meta.waiver_owner, &meta.waiver_expiration) {
                                    (Some(owner), Some(exp_str)) if !owner.is_empty() => {
                                        if let Some(exp_ts) = parse_date(exp_str) {
                                            now <= exp_ts
                                        } else {
                                            false
                                        }
                                    }
                                    _ => false,
                                };

                                if has_valid_waiver {
                                    // Waiver is valid - skip this test
                                    continue;
                                }

                                let msg = format!(
                                    "{} (created {}, >8 weeks old)",
                                    meta.name, date_str
                                );

                                // P0/P1 placeholders fail CI, others warn only
                                if let Some(priority) = &meta.priority {
                                    if priority == "P0" || priority == "P1" {
                                        stale_p0_p1.push(msg);
                                    } else {
                                        stale_other.push(msg);
                                    }
                                } else {
                                    stale_other.push(msg);
                                }
                            }
                        }
                    }
                }
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

                        let meta = TestMetadata {
                            name: test_name,
                            category: extract_field(&doc_lines, "Category:"),
                            priority: extract_field(&doc_lines, "Priority:"),
                            status: extract_field(&doc_lines, "Status:"),
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
        let parts: Vec<&str> = date_str.split('-').collect();
        if parts.len() != 3 {
            return None;
        }

        let year: i32 = parts[0].parse().ok()?;
        let month: i32 = parts[1].parse().ok()?;
        let day: i32 = parts[2].parse().ok()?;

        let days_since_epoch = (year - 1970) * 365 + (month - 1) * 30 + day;
        Some(days_since_epoch as u64 * 24 * 60 * 60)
    }
}
