// D2-ERR-VFS-FALLIBILITY lint self-test — POSITIVE fixture.
//
// NOT COMPILED. Every candidate pattern appears here, but each is covered by one
// suppression path, so `scripts/lint_fallible.sh` must yield ZERO hits. If any line
// here is flagged, a suppression rule regressed.

// --- 1. same-line / N-lines-above annotations ---
fn same_line_annotation() {
    let mut v = make();
    v.push(x); // lint-fallible: BOUNDED(fixed 4 entries)
}

fn annotation_one_line_above() {
    let mut v = make();
    // lint-fallible: BOUNDED(fixed count)
    v.push(x);
}

fn annotation_three_lines_above() {
    // lint-fallible: PREALLOCATED(caller reserved capacity)
    let mut v = make();
    let _tmp = 0;
    v.push(x);
}

// --- 2. fn-level annotation blesses the whole body ---
// lint-fallible-fn: BOUNDED(fixed set of static names)
fn fn_level_annotated() {
    let mut v = make();
    v.push("cpu");
    v.push("memory");
    v.push("pids");
}

// --- 3. fn-scope guard (order-insensitive) ---
fn guard_before_push() {
    let mut v = make();
    v.try_reserve(1).ok();
    v.push(x);
}

fn guard_after_resize() {
    let mut v = make();
    v.resize(n, 0);
    v.try_reserve(extra).ok();
}

// --- 4. test exclusion (attribute WITHOUT 'test' in the fn name) ---
#[test]
fn attribute_gated_alloc() {
    let a = Arc::new(thing);
}

// --- 5. test exclusion (fn name contains 'test') ---
fn ramfs_self_test() {
    let owned = var.to_string();
}

// --- 6. literal-source forms are bounded by construction ---
fn literal_forms() {
    let a = "/".to_string();
    let b = "x".to_owned();
    let c = String::from("max\n");
}

// --- 7. comment / doc / trailing-comment mentions are not code ---
fn comment_mentions() {
    // this helper would v.push(x) if it were not pre-sized
    /// doc: Arc::new(y) is deliberately avoided
    let n = 5; // never actually calls v.push(x) here
}

// --- 8. non-matching fallible forms must NOT trip the candidate set ---
fn fallible_forms() {
    let mut v = make();
    v.try_reserve(1).ok();
    v.try_reserve_exact(2).ok();
    m.try_insert(k, val).ok();
    let a = Arc::try_new(thing);
}
