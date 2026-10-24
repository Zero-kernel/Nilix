//! R190-1 LSM hook coverage census (INV-SEC-02 / INV-SEC-03).
//!
//! Every `pub fn hook_*` in `lsm/lib.rs` must either have a production
//! caller outside `kernel/lsm` or be listed in `lsm::FEATURE_ABSENT_HOOKS`
//! with the boundary that keeps its feature unreachable. A listed hook must
//! not be referenced from production code at all, and guarded private APIs
//! (capability delegation, IPC endpoints) may only be called from files that
//! name their hook. The syscall numbers of each listed family are checked
//! against the dispatcher by kernel-core `r190_11_dispatch_parity_tests`.
//! Limits: one call site counts as wired (per-emitter coverage is review's
//! job), and calls through function pointers are not seen.
//! R192 adds two source pins: the families in `lsm::PARTIALLY_WIRED_HOOKS`
//! keep every fenced syscall listed (R192-7), and no production subject
//! lookup skips its hook when the subject is `None` (R192-5).
//! Pure std source analysis, run from the `kernel/` directory by the hosted
//! gate (`scripts/tools/hosted_subcrate_tests.sh`).

#[cfg(test)]
mod lsm_hook_census_tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    /// Upper bound on dormant hook families. Lower it whenever a family is
    /// wired; never raise it to admit a new unwired hook. 15 since R191-3
    /// wired `hook_ptrace` (get_robust_list; the rest of the family is in
    /// `lsm::PARTIALLY_WIRED_HOOKS`).
    const MAX_FEATURE_ABSENT: usize = 15;

    fn kernel_root() -> PathBuf {
        for candidate in [".", "kernel"] {
            let root = Path::new(candidate);
            if root.join("lsm/lib.rs").is_file() {
                return root.to_path_buf();
            }
        }
        panic!("run from the repository root or kernel/: lsm/lib.rs not found");
    }

    /// Replace comments and string/char literal contents with spaces,
    /// keeping newlines and code. Raw strings `r"..."`/`r#"..."#` included.
    fn code_only(source: &str) -> String {
        let bytes = source.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        let blank = |b: u8| if b == b'\n' { b'\n' } else { b' ' };
        while i < bytes.len() {
            let b = bytes[i];
            let next = bytes.get(i + 1).copied();
            if b == b'/' && next == Some(b'/') {
                while i < bytes.len() && bytes[i] != b'\n' {
                    out.push(b' ');
                    i += 1;
                }
            } else if b == b'/' && next == Some(b'*') {
                let mut depth = 0usize;
                while i < bytes.len() {
                    if bytes[i] == b'/' && bytes.get(i + 1) == Some(&b'*') {
                        depth += 1;
                        out.extend_from_slice(b"  ");
                        i += 2;
                    } else if bytes[i] == b'*' && bytes.get(i + 1) == Some(&b'/') {
                        depth -= 1;
                        out.extend_from_slice(b"  ");
                        i += 2;
                        if depth == 0 {
                            break;
                        }
                    } else {
                        out.push(blank(bytes[i]));
                        i += 1;
                    }
                }
            } else if b == b'r'
                && (next == Some(b'"') || next == Some(b'#'))
                && (i == 0 || !(bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_'))
            {
                let mut j = i + 1;
                let mut hashes = 0;
                while bytes.get(j) == Some(&b'#') {
                    hashes += 1;
                    j += 1;
                }
                if bytes.get(j) != Some(&b'"') {
                    out.push(b);
                    i += 1;
                    continue;
                }
                out.resize(out.len() + (j + 1 - i), b' ');
                i = j + 1;
                loop {
                    if i >= bytes.len() {
                        break;
                    }
                    if bytes[i] == b'"'
                        && bytes.len() >= i + 1 + hashes
                        && bytes[i + 1..i + 1 + hashes].iter().all(|&h| h == b'#')
                    {
                        out.resize(out.len() + 1 + hashes, b' ');
                        i += 1 + hashes;
                        break;
                    }
                    out.push(blank(bytes[i]));
                    i += 1;
                }
            } else if b == b'"' {
                out.push(b' ');
                i += 1;
                while i < bytes.len() && bytes[i] != b'"' {
                    if bytes[i] == b'\\' {
                        out.push(b' ');
                        i += 1;
                    }
                    if i < bytes.len() {
                        out.push(blank(bytes[i]));
                        i += 1;
                    }
                }
                out.push(b' ');
                i += 1;
            } else if b == b'\'' {
                // Char literal ('x', '中', '\n', '\u{..}') versus lifetime ('a).
                let is_char = match next {
                    Some(b'\\') => true,
                    Some(lead) => {
                        let width = match lead {
                            0x00..=0x7f => 1,
                            0xc0..=0xdf => 2,
                            0xe0..=0xef => 3,
                            _ => 4,
                        };
                        bytes.get(i + 1 + width) == Some(&b'\'')
                    }
                    None => false,
                };
                if is_char {
                    out.push(b' ');
                    i += 1;
                    while i < bytes.len() && bytes[i] != b'\'' {
                        if bytes[i] == b'\\' {
                            out.push(b' ');
                            i += 1;
                        }
                        if i < bytes.len() {
                            out.push(b' ');
                            i += 1;
                        }
                    }
                    out.push(b' ');
                    i += 1;
                } else {
                    out.push(b);
                    i += 1;
                }
            } else {
                out.push(b);
                i += 1;
            }
        }
        out.truncate(bytes.len());
        String::from_utf8(out).expect("blanking keeps UTF-8 structure")
    }

    /// Which test-only items to blank.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Strip {
        /// Every `#[cfg]` whose predicate mentions `test`, including
        /// `any(test, ..)` and `not(test)`. Conservative for "is this hook
        /// wired": such code never counts as a production caller.
        Broad,
        /// Only items that exist solely under test (`#[test]`,
        /// `#[cfg(test)]`, `#[cfg(all(.., test, ..))]`). Conservative for
        /// "is a dormant hook or guarded API used": `not(test)` and
        /// `any(test, feature)` code ships.
        Exact,
    }

    /// Blank every item guarded by a test attribute selected by `strip`
    /// (the item's braced body, or up to `;` for a bodiless item). Input is
    /// `code_only`.
    fn strip_test_items(code: &str, strip: Strip) -> String {
        let mut bytes = code.as_bytes().to_vec();
        let mut search = 0;
        while let Some(found) = find_test_attribute(&bytes, search, strip) {
            let (attr_start, attr_end) = found;
            let mut i = attr_end;
            let mut body_end = None;
            // `;` ends a bodiless item only outside (), [] (e.g. `[u8; 4]`).
            let mut nesting = 0usize;
            while i < bytes.len() {
                match bytes[i] {
                    b'(' | b'[' => {
                        nesting += 1;
                        i += 1;
                    }
                    b')' | b']' => {
                        nesting = nesting.saturating_sub(1);
                        i += 1;
                    }
                    b';' if nesting == 0 => {
                        body_end = Some(i + 1);
                        break;
                    }
                    b'{' => {
                        let mut depth = 0usize;
                        let mut j = i;
                        while j < bytes.len() {
                            match bytes[j] {
                                b'{' => depth += 1,
                                b'}' => {
                                    depth -= 1;
                                    if depth == 0 {
                                        break;
                                    }
                                }
                                _ => {}
                            }
                            j += 1;
                        }
                        body_end = Some((j + 1).min(bytes.len()));
                        break;
                    }
                    _ => i += 1,
                }
            }
            let end = body_end.unwrap_or(bytes.len());
            for byte in &mut bytes[attr_start..end] {
                if *byte != b'\n' {
                    *byte = b' ';
                }
            }
            search = end;
        }
        String::from_utf8(bytes).expect("blanking keeps UTF-8 structure")
    }

    /// Next test attribute selected by `strip` at or after `from`.
    fn find_test_attribute(bytes: &[u8], from: usize, strip: Strip) -> Option<(usize, usize)> {
        let text = std::str::from_utf8(&bytes[from..]).ok()?;
        let mut offset = 0;
        while let Some(rel) = text[offset..].find("#[") {
            let start = offset + rel;
            let end = text[start..].find(']').map(|e| start + e + 1)?;
            let inner: String = text[start + 2..end - 1]
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect();
            let mentions_test = inner
                .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .any(|token| token == "test");
            let selected = match strip {
                Strip::Broad => inner.starts_with("cfg(") && mentions_test,
                Strip::Exact => {
                    inner == "cfg(test)"
                        || (inner.starts_with("cfg(all(")
                            && mentions_test
                            && !inner.contains("not(")
                            && !inner.contains("any("))
                }
            };
            if inner == "test" || selected {
                return Some((from + start, from + end));
            }
            offset = end;
        }
        None
    }

    fn is_ident_byte(b: u8) -> bool {
        b.is_ascii_alphanumeric() || b == b'_'
    }

    /// Whole-identifier occurrences of `name` that are not its own `fn`
    /// definition, as `(start, end)` byte ranges.
    fn references(code: &str, name: &str) -> Vec<(usize, usize)> {
        let bytes = code.as_bytes();
        let mut out = Vec::new();
        let mut offset = 0;
        while let Some(rel) = code[offset..].find(name) {
            let start = offset + rel;
            let end = start + name.len();
            offset = end;
            if start > 0 && is_ident_byte(bytes[start - 1]) {
                continue;
            }
            if bytes.get(end).copied().is_some_and(is_ident_byte) {
                continue;
            }
            if code[..start].trim_end().ends_with("fn")
                && !code[..start]
                    .trim_end()
                    .trim_end_matches("fn")
                    .ends_with(|c: char| c.is_ascii_alphanumeric() || c == '_')
            {
                continue;
            }
            out.push((start, end));
        }
        out
    }

    /// Blank plain `pub use ...;` re-exports. A crate facade re-exporting an
    /// API under its own name is not a caller. A renaming re-export
    /// (`pub use api as alias`) stays visible, because callers of the alias
    /// would otherwise hide the API name. Private `use` imports stay visible.
    fn strip_pub_use(code: &str) -> String {
        let mut bytes = code.as_bytes().to_vec();
        let mut offset = 0;
        while let Some(rel) = code[offset..].find("pub use ") {
            let start = offset + rel;
            let end = code[start..]
                .find(';')
                .map_or(code.len(), |e| start + e + 1);
            let renames = code[start..end]
                .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .any(|token| token == "as");
            if !renames {
                for byte in &mut bytes[start..end] {
                    if *byte != b'\n' {
                        *byte = b' ';
                    }
                }
            }
            offset = end;
        }
        String::from_utf8(bytes).expect("blanking keeps UTF-8 structure")
    }

    /// Count `name(` call sites (whole identifier, not the definition).
    fn count_calls(code: &str, name: &str) -> usize {
        let bytes = code.as_bytes();
        let mut count = 0;
        for (_, end) in references(code, name) {
            let mut k = end;
            while bytes
                .get(k)
                .copied()
                .is_some_and(|b| b.is_ascii_whitespace())
            {
                k += 1;
            }
            if bytes.get(k) == Some(&b'(') {
                count += 1;
            }
        }
        count
    }

    /// One production source in both stripping modes.
    struct Source {
        path: PathBuf,
        /// Test-ish items blanked broadly (for "is this hook wired").
        broad: String,
        /// Only test-only items blanked (for dormant-hook and guarded-API use).
        exact: String,
    }

    /// Production sources: every `.rs` under the kernel root except the LSM
    /// crate itself, test directories and test-only files.
    fn production_sources(root: &Path) -> Vec<Source> {
        let mut out = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            for entry in fs::read_dir(&dir).expect("read kernel source dir") {
                let path = entry.expect("dir entry").path();
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if path.is_dir() {
                    // `tests`, `runtime_tests` and friends hold test-only code.
                    let skip = name.starts_with('.')
                        || name == "target"
                        || name.contains("test")
                        || (dir == root && name == "lsm");
                    if !skip {
                        stack.push(path);
                    }
                } else if name.ends_with(".rs") && !name.contains("test") {
                    let code = code_only(&fs::read_to_string(&path).expect("read source"));
                    out.push(Source {
                        broad: strip_test_items(&code, Strip::Broad),
                        exact: strip_test_items(&code, Strip::Exact),
                        path,
                    });
                }
            }
        }
        out
    }

    fn hook_names(lsm_lib: &str) -> Vec<String> {
        code_only(lsm_lib)
            .lines()
            .filter_map(|line| {
                let rest = line.trim_start().strip_prefix("pub fn hook_")?;
                let ident: String = rest
                    .chars()
                    .take_while(|&c| is_ident_byte(c as u8))
                    .collect();
                Some(format!("hook_{ident}"))
            })
            .collect()
    }

    fn feature_absent(lsm_lib: &str) -> Vec<String> {
        let start = lsm_lib
            .find("pub const FEATURE_ABSENT_HOOKS")
            .expect("FEATURE_ABSENT_HOOKS table missing");
        let body = &lsm_lib[start..];
        let end = body
            .find("];")
            .expect("FEATURE_ABSENT_HOOKS table not closed");
        // Every `"hook_..."` string literal in the table is an entry name.
        // Independent of layout: rustfmt splits long tuples across lines.
        body[..end]
            .split("\"hook_")
            .skip(1)
            .filter_map(|rest| Some(format!("hook_{}", &rest[..rest.find('"')?])))
            .collect()
    }

    #[test]
    fn every_lsm_hook_is_wired_or_declared_feature_absent() {
        let root = kernel_root();
        let lsm_lib = fs::read_to_string(root.join("lsm/lib.rs")).expect("read lsm/lib.rs");
        let hooks = hook_names(&lsm_lib);
        assert!(
            hooks.len() >= 50,
            "hook scan found only {} hooks",
            hooks.len()
        );
        let absent = feature_absent(&lsm_lib);
        assert!(
            absent.len() <= MAX_FEATURE_ABSENT,
            "FEATURE_ABSENT_HOOKS grew to {} (max {}): wire the hook instead",
            absent.len(),
            MAX_FEATURE_ABSENT
        );

        let sources = production_sources(&root);
        assert!(
            sources.len() > 100,
            "scanned only {} source files",
            sources.len()
        );
        let mut failures = Vec::new();
        for (index, name) in absent.iter().enumerate() {
            if !hooks.contains(name) {
                failures.push(format!("{name}: listed feature-absent but not defined"));
            }
            if absent[..index].contains(name) {
                failures.push(format!("{name}: listed feature-absent twice"));
            }
        }
        for hook in &hooks {
            if absent.contains(hook) {
                // Any production reference (call, import, fn pointer) to a
                // dormant hook means its feature is being wired.
                let referrers: Vec<_> = sources
                    .iter()
                    .filter(|source| !references(&source.exact, hook).is_empty())
                    .map(|source| source.path.display().to_string())
                    .collect();
                if !referrers.is_empty() {
                    failures.push(format!(
                        "{hook}: listed feature-absent but referenced from {}",
                        referrers.join(", ")
                    ));
                }
            } else if !sources
                .iter()
                .any(|source| count_calls(&source.broad, hook) > 0)
            {
                failures.push(format!(
                    "{hook}: no production caller and not in FEATURE_ABSENT_HOOKS"
                ));
            }
        }
        assert!(
            failures.is_empty(),
            "LSM hook census failed:\n  {}",
            failures.join("\n  ")
        );
    }

    /// R192-7: every syscall of each partially wired hook family. The
    /// kernel-core dispatcher test fences what `lsm::PARTIALLY_WIRED_HOOKS`
    /// lists; this pins the list itself, so deleting or narrowing an entry
    /// fails here instead of silently lifting the fence. Moving a syscall from
    /// `absent` to `wired` keeps it listed.
    const PARTIALLY_WIRED_FAMILIES: &[(&str, &[u64])] =
        &[("hook_ptrace", &[101, 274, 310, 311, 312, 438])];

    /// `(hook, wired and absent syscalls)` of each `PARTIALLY_WIRED_HOOKS` entry.
    fn partially_wired(lsm_lib: &str) -> Vec<(String, Vec<u64>)> {
        let start = lsm_lib
            .find("pub const PARTIALLY_WIRED_HOOKS")
            .expect("PARTIALLY_WIRED_HOOKS table missing");
        let body = &lsm_lib[start..];
        let end = body
            .find("}];")
            .expect("PARTIALLY_WIRED_HOOKS table not closed");
        body[..end]
            .split("hook: \"")
            .skip(1)
            .map(|entry| {
                let name = entry[..entry.find('"').expect("hook name")].to_string();
                let mut syscalls = Vec::new();
                for field in ["wired: &[", "absent: &["] {
                    let list = &entry[entry.find(field).expect(field) + field.len()..];
                    for number in list[..list.find(']').expect("list end")].split(',') {
                        let number = number.trim();
                        if !number.is_empty() {
                            syscalls.push(number.parse().expect("syscall number"));
                        }
                    }
                }
                syscalls.sort_unstable();
                (name, syscalls)
            })
            .collect()
    }

    #[test]
    fn partially_wired_families_stay_listed() {
        let root = kernel_root();
        let lsm_lib = fs::read_to_string(root.join("lsm/lib.rs")).expect("read lsm/lib.rs");
        let table = partially_wired(&lsm_lib);
        assert_eq!(
            table.len(),
            PARTIALLY_WIRED_FAMILIES.len(),
            "PARTIALLY_WIRED_HOOKS has {:?}; update the R192-7 pin deliberately",
            table
        );
        for &(hook, syscalls) in PARTIALLY_WIRED_FAMILIES {
            let listed = table
                .iter()
                .find(|(name, _)| name == hook)
                .unwrap_or_else(|| panic!("{hook} left PARTIALLY_WIRED_HOOKS: its fence is gone"));
            assert_eq!(
                listed.1, syscalls,
                "{hook}: a fenced syscall left PARTIALLY_WIRED_HOOKS"
            );
        }
        let sample = "pub const PARTIALLY_WIRED_HOOKS: &[PartiallyWiredHook] = &[\r\n    \
                      PartiallyWiredHook {\r\n        hook: \"hook_x\",\r\n        \
                      wired: &[3],\r\n        absent: &[2, 1],\r\n        reason: \"r\",\r\n    \
                      }];\r\n";
        assert_eq!(
            partially_wired(sample),
            [("hook_x".to_string(), vec![1, 2, 3])]
        );
    }

    /// R192-5: the LSM subject lookups and whether a bare `?` already fails
    /// closed (they return `Result`). A `None` or `Err` from them means the
    /// task's credentials are being written or its PCB is gone, never "no
    /// policy applies". Limits (review): the scan sees these spellings only, so
    /// a type alias, a wrapper that turns the error into `Ok`, or a `?` inside
    /// a discarded closure is not seen; a fail-closed `let .. else { return
    /// Err(..) }` or `match .. { Err(e) => return Err(e), .. }` is flagged and
    /// must be written with `.ok_or(..)?` or `?`.
    const SUBJECT_LOOKUPS: &[(&str, bool)] = &[
        ("ProcessCtx::from_current()", false),
        ("Self::from_current()", false),
        ("ProcessCtx::current_task()", false),
        ("SyscallCtx::from_current(", false),
        ("SocketLabel::from_current(", false),
        ("lsm_current_process_ctx()", false),
        ("lsm_process_ctx_from(", true),
    ];

    /// Reviewed lookups that handle the missing subject themselves:
    /// `(file suffix, text in the 200 bytes before the call, text the 3000
    /// bytes after it must contain (whitespace-insensitive), why)`. Each entry
    /// must match exactly once, so a moved, deleted or weakened site fails.
    const SUBJECT_LOOKUP_SITES: &[(&str, &str, &str, &str)] = &[
        (
            "kernel_core/syscall.rs",
            "fn lsm_current_process_ctx() -> Option<lsm::ProcessCtx> {",
            "",
            "the wrapper; its callers are scanned",
        ),
        (
            "kernel_core/syscall.rs",
            "let lsm_ctx = lsm::",
            "increment_counter(TraceCounter::SyscallExit, 1); \
             return SyscallError::EPERM.as_i64(); } };",
            "syscall entry: the None arm returns EPERM (R184-U01-1)",
        ),
        (
            "kernel_core/syscall.rs",
            "let foreign_target = if Arc::ptr_eq(&t.thread_group, &caller_group) {",
            "let target_ctx = target_ctx?;",
            "get_robust_list target snapshot; propagated after the DAC check (R191-3)",
        ),
        (
            "net/src/socket.rs",
            "pub fn from_current(secmark: u64) -> Option<Self> {",
            "",
            "the SocketLabel wrapper; its callers are scanned",
        ),
        (
            "sched/cpuset.rs",
            "pub fn authorize() -> Result<Self, CpusetError> {",
            "None => Err(CpusetError::PermissionDenied),",
            "None fails closed unless there is no current task (kernel context)",
        ),
        (
            "lsm/lib.rs",
            "pub fn current_task() -> Result<Option<Self>, MissingSubject> {",
            ".map(Some).ok_or(MissingSubject)",
            "the current_task wrapper; its callers are scanned",
        ),
    ];

    /// The end of the parenthesized group opening at `open`, if balanced.
    fn group_end(code: &str, open: usize) -> Option<usize> {
        let mut depth = 0usize;
        for (index, c) in code[open..].char_indices() {
            match c {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(open + index + 1);
                    }
                }
                _ => {}
            }
        }
        None
    }

    /// Whether the lookup ending at `after` fails closed right there: it is
    /// immediately converted to an error and propagated,
    /// `.ok_or(..)?`, `.ok_or_else(..)?` or `.map_err(..)?`, or (for a lookup
    /// returning `Result`) propagated with a bare `?`.
    fn fails_closed_at(code: &str, after: usize, bare_question: bool) -> bool {
        let rest = code[after..].trim_start();
        if bare_question && rest.starts_with('?') {
            return true;
        }
        let rest_at = code.len() - rest.len();
        for method in [".ok_or(", ".ok_or_else(", ".map_err("] {
            if rest.starts_with(method) {
                let open = rest_at + method.len() - 1;
                return group_end(code, open)
                    .is_some_and(|end| code[end..].trim_start().starts_with('?'));
            }
        }
        false
    }

    fn char_floor(code: &str, mut index: usize) -> usize {
        while !code.is_char_boundary(index) {
            index -= 1;
        }
        index
    }

    /// A lookup in `code` that does not fail closed where it is made.
    struct OpenLookup {
        call: String,
        /// The 200 bytes before the call.
        before: String,
        /// The 3000 bytes after it, whitespace collapsed.
        after: String,
    }

    fn collapse(text: &str) -> String {
        text.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    fn fail_open_lookups(code: &str) -> Vec<OpenLookup> {
        let mut found = Vec::new();
        for &(lookup, bare_question) in SUBJECT_LOOKUPS {
            let mut from = 0;
            while let Some(offset) = code[from..].find(lookup) {
                let at = from + offset;
                let mut after = at + lookup.len();
                if lookup.ends_with('(') {
                    after = group_end(code, after - 1).unwrap_or(after);
                }
                // A definition (`fn lsm_current_process_ctx()`) is no call.
                let definition = code[..at].trim_end().ends_with("fn");
                if !definition && !fails_closed_at(code, after, bare_question) {
                    let head = char_floor(code, at.saturating_sub(200));
                    let tail = char_floor(code, (after + 3000).min(code.len()));
                    found.push(OpenLookup {
                        call: code[at..after].split_whitespace().collect(),
                        before: code[head..at].to_string(),
                        after: collapse(&code[after..tail]),
                    });
                }
                from = after.max(at + 1);
            }
        }
        found
    }

    #[test]
    fn lsm_subject_lookups_fail_closed() {
        let open = [
            "if let Some(ctx) =\n lsm::ProcessCtx::from_current() { hook(); }",
            "let t = ProcessCtx::from_current(); if let Some(t) = t { hook(); }",
            "let t = ProcessCtx::current_task().unwrap_or(None);",
            "let Some(t) = ProcessCtx::from_current() else { return Ok(()) };",
            "match lsm_current_process_ctx() { None => return Ok(()), Some(c) => hook(c) }",
            "ProcessCtx::from_current().map_or(Ok(()), |c| hook(c))?;",
            "let c = lsm_current_process_ctx().ok_or(E).unwrap_or_default();",
            "let s = SocketLabel::from_current(mark);",
            "let c = SyscallCtx::from_current(nr, &args);",
            "if let Some(c) = Self::from_current() { hook(c); }",
            "if let Ok(c) = lsm_process_ctx_from(&proc) { hook(&c); }",
            "let c = lsm_process_ctx_from(&proc).ok();",
        ];
        for probe in open {
            assert_eq!(fail_open_lookups(probe).len(), 1, "missed: {probe}");
        }
        let closed = [
            "let c = lsm_current_process_ctx().ok_or(SyscallError::EPERM)?;",
            "let t = lsm::ProcessCtx::current_task().map_err(|_| E::EACCES)?;",
            "let c = ProcessCtx::from_current()\n .ok_or_else(|| err(f(1)))?\n .uid;",
            "let c = SyscallCtx::from_current(nr, &args).ok_or(E)?;",
            "let c = lsm_process_ctx_from(&proc.lock())?;",
            "fn lsm_current_process_ctx() -> Option<X> { None }",
            "pub fn lsm_process_ctx_from(p: &P) -> Result<X, E> { todo!() }",
        ];
        for probe in closed {
            assert!(fail_open_lookups(probe).is_empty(), "flagged: {probe}");
        }

        let root = kernel_root();
        let mut sources = production_sources(&root);
        sources.extend(lsm_crate_sources(&root));
        let mut failures = Vec::new();
        let mut site_uses = vec![0usize; SUBJECT_LOOKUP_SITES.len()];
        for source in &sources {
            for open in fail_open_lookups(&source.exact) {
                let site = SUBJECT_LOOKUP_SITES
                    .iter()
                    .position(|(file, marker, _, _)| {
                        source.path.ends_with(file) && open.before.contains(marker)
                    });
                match site {
                    Some(index) => {
                        site_uses[index] += 1;
                        let required = collapse(SUBJECT_LOOKUP_SITES[index].2);
                        if !open.after.contains(&required) {
                            failures.push(format!(
                                "{}: reviewed {} no longer has `{required}` after it",
                                source.path.display(),
                                open.call
                            ));
                        }
                    }
                    None => failures.push(format!("{}: {}", source.path.display(), open.call)),
                }
            }
        }
        for (uses, (file, marker, _, _)) in site_uses.iter().zip(SUBJECT_LOOKUP_SITES) {
            if *uses != 1 {
                failures.push(format!(
                    "{file}: reviewed site `{marker}` matched {uses} times"
                ));
            }
        }
        assert!(
            failures.is_empty(),
            "LSM subject lookups must fail closed where they are made (`.ok_or(..)?`, \
             `.ok_or_else(..)?`, `.map_err(..)?`) or be a reviewed site:\n  {}",
            failures.join("\n  ")
        );
    }

    /// The LSM crate's own sources: policy code there must fail closed too
    /// (`ProcessCtx::current_task` is a reviewed site).
    fn lsm_crate_sources(root: &Path) -> Vec<Source> {
        let mut out = Vec::new();
        for entry in fs::read_dir(root.join("lsm")).expect("read lsm dir") {
            let path = entry.expect("dir entry").path();
            if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                let code = code_only(&fs::read_to_string(&path).expect("read source"));
                out.push(Source {
                    broad: strip_test_items(&code, Strip::Broad),
                    exact: strip_test_items(&code, Strip::Exact),
                    path,
                });
            }
        }
        out
    }

    /// `(API call, token the calling file must contain, defining file)`.
    /// The private APIs behind a dormant or op-specific hook: a production
    /// caller elsewhere must mediate through the named hook.
    const GUARDED_APIS: &[(&str, &str, &str)] = &[
        ("delegate", "cap_op::DELEGATE", "cap/lib.rs"),
        ("send_message", "hook_ipc_send", "ipc/ipc.rs"),
        ("send_message_notify", "hook_ipc_send", "ipc/ipc.rs"),
        ("receive_message", "hook_ipc_recv", "ipc/ipc.rs"),
        ("receive_message_blocking", "hook_ipc_recv", "ipc/ipc.rs"),
        (
            "receive_message_with_retries",
            "hook_ipc_recv",
            "ipc/ipc.rs",
        ),
    ];

    #[test]
    fn guarded_api_callers_name_their_hook() {
        let root = kernel_root();
        let mut failures = Vec::new();
        for source in production_sources(&root) {
            let uses = strip_pub_use(&source.exact);
            for &(api, hook, home) in GUARDED_APIS {
                if source.path.ends_with(home) {
                    continue;
                }
                // Any reference counts (calls, `use .. as`, fn pointers). The
                // hook requirement is file-granular (a documented limit).
                if !references(&uses, api).is_empty() && !source.exact.contains(hook) {
                    failures.push(format!(
                        "{}: uses {api} without {hook}",
                        source.path.display()
                    ));
                }
            }
        }
        assert!(
            failures.is_empty(),
            "guarded API callers without their LSM hook:\n  {}",
            failures.join("\n  ")
        );
    }

    #[test]
    fn scanner_ignores_comments_strings_and_test_items() {
        let source = r##"
            // lsm::hook_alpha(ctx);
            /* lsm::hook_alpha(ctx); /* nested */ */
            const S: &str = "lsm::hook_alpha(ctx)";
            const R: &str = r#"hook_alpha("x")"#;
            const C: char = '(';
            fn live<'a>(x: &'a u8) { lsm::hook_beta (x); hook_beta_extra(x); }
            #[cfg(test)]
            mod tests { fn t() { lsm::hook_gamma(ctx); } }
            #[test]
            fn unit() { lsm::hook_gamma(ctx); }
            #[cfg(test)]
            fn helper(buf: &[u8; 4]) { lsm::hook_gamma(buf); }
            #[cfg(any(test, feature = "probe"))]
            fn probe() { lsm::hook_gamma(ctx); }
            const W: char = '\u{4e2d}';
            const U: char = '中';
            use lsm::hook_delta;
            pub fn hook_epsilon(task: &u8) {}
            let pointer = lsm::hook_zeta;
            #[cfg(not(test))]
            fn shipped() { lsm::hook_eta(ctx); }
            #[cfg(all(feature = "x", test))]
            fn test_only() { lsm::hook_theta(ctx); }
            use ipc::receive_message as rm;
            pub use ipc::{send_message, grant_access};
            pub use ipc::receive_message_blocking as recv;
        "##;
        let code = strip_test_items(&code_only(source), Strip::Broad);
        let exact = strip_test_items(&code_only(source), Strip::Exact);
        assert_eq!(count_calls(&code, "hook_alpha"), 0);
        assert_eq!(count_calls(&code, "hook_beta"), 1);
        assert_eq!(count_calls(&code, "hook_gamma"), 0);
        assert_eq!(count_calls(&code, "hook_delta"), 0);
        assert_eq!(
            references(&code, "hook_delta").len(),
            1,
            "imports are references"
        );
        assert_eq!(
            count_calls(&code, "hook_epsilon"),
            0,
            "a definition is not a call"
        );
        assert!(references(&code, "hook_epsilon").is_empty());
        assert_eq!(
            references(&code, "hook_zeta").len(),
            1,
            "fn pointers are references"
        );
        assert_eq!(count_calls(&code, "hook_eta"), 0, "broad strips not(test)");
        assert_eq!(
            references(&exact, "hook_eta").len(),
            1,
            "not(test) code ships"
        );
        assert_eq!(
            references(&exact, "hook_gamma").len(),
            1,
            "any(test, feature) ships"
        );
        assert!(
            references(&exact, "hook_theta").is_empty(),
            "all(.., test) is test-only"
        );
        assert_eq!(
            references(&exact, "receive_message").len(),
            1,
            "aliased imports"
        );
        assert!(references(&strip_pub_use(&exact), "send_message").is_empty());
        assert_eq!(
            references(&strip_pub_use(&exact), "receive_message_blocking").len(),
            1,
            "renaming re-exports stay visible"
        );
        assert_eq!(
            references(&strip_pub_use(&exact), "receive_message").len(),
            1
        );
        assert_eq!(code.len(), source.len());
        assert_eq!(exact.len(), source.len());

        // The table parser must not depend on the entry layout.
        let table = "pub const FEATURE_ABSENT_HOOKS: &[FeatureAbsentHook] = &[\r\n    \
                     FeatureAbsentHook {\r\n        hook: \"hook_split\",\r\n        \
                     syscalls: &[1, 2],\r\n        reason: \"long reason\",\r\n    },\r\n    \
                     FeatureAbsentHook { hook: \"hook_inline\", syscalls: &[], reason: \"x\" },\r\n\
                     ];\r\n";
        assert_eq!(feature_absent(table), ["hook_split", "hook_inline"]);
    }
}
