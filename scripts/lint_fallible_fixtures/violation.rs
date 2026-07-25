// D2-ERR-VFS-FALLIBILITY lint self-test — NEGATIVE fixture.
//
// NOT COMPILED (lives outside any cargo workspace member). `scripts/lint_fallible.sh`
// must flag EXACTLY 22 lines here. The count is pinned in the Makefile
// `lint-fallible-selftest` target: if you add/remove a candidate alternation or a
// suppression-bypass case, update BOTH this fixture and that pinned count together.
// A drop in the count means a regex alternation regressed; a rise means a new
// candidate slipped in unpinned.

fn f1_push() {
    let mut v: Vec<u8> = make();
    v.push(x);                       // HIT 1: .push(
}

fn f2_push_str() {
    let mut s = make();
    s.push_str(other);               // HIT 2: .push_str(
}

fn f3_extend() {
    let mut v = make();
    v.extend(iter);                  // HIT 3: .extend(
}

fn f4_extend_from_slice() {
    let mut v = make();
    v.extend_from_slice(sl);         // HIT 4: .extend_from_slice(
}

fn f5_append() {
    let mut v = make();
    v.append(&mut other);            // HIT 5: .append(
}

fn f6_resize() {
    let mut v = make();
    v.resize(n, 0);                  // HIT 6: .resize(
}

fn f7_insert() {
    let mut m = make();
    m.insert(key, value);            // HIT 7: .insert(
}

fn f8_to_vec() {
    let owned = slice.to_vec();      // HIT 8: .to_vec(
}

fn f9_to_string() {
    let owned = var.to_string();     // HIT 9: .to_string( (non-literal receiver)
}

fn f10_to_owned() {
    let owned = var.to_owned();      // HIT 10: .to_owned( (non-literal receiver)
}

fn f11_string_from() {
    let owned = String::from(var);   // HIT 11: String::from( (non-literal arg)
}

fn f12_collect() {
    let out = iter.collect();        // HIT 12: .collect(
}

fn f13_join() {
    let joined = parts.join(sep);    // HIT 13: .join(
}

fn f14_with_capacity() {
    let v = Vec::with_capacity(n);   // HIT 14: with_capacity(
}

fn f15_bare_reserve() {
    let mut v = make();
    v.reserve(n);                    // HIT 15: .reserve( (bare, not try_reserve)
}

fn f16_vec_macro() {
    let v = vec![a, b, c];           // HIT 16: vec![
}

fn f17_box_new() {
    let b = Box::new(thing);         // HIT 17: Box::new(
}

fn f18_rc_new() {
    let r = Rc::new(thing);          // HIT 18: Rc::new(
}

fn f19_arc_new() {
    let a = Arc::new(thing);         // HIT 19: Arc::new(
}

fn f20_empty_reason_annotation() {
    let mut v = make();
    // lint-fallible: BOUNDED()
    v.push(x);                       // HIT 20: annotation reason is empty -> NOT suppressed
}

// fn-boundary reset: guarded_a holds the guard (its push is SUPPRESSED); unguarded_b
// does NOT inherit it (its push is a HIT). Proves the guard is fn-scoped.
fn guarded_a() {
    let mut v = make();
    v.try_reserve(1).ok();           // guard -> the push below is suppressed
    v.push(x);                       // suppressed (same fn as the guard)
}

fn unguarded_b() {
    let mut v = make();
    v.push(y);                       // HIT 21: guard did NOT cross the fn boundary
}

// Anchored test-name exemption: 'test' must be a whole `_`-delimited word. A
// production fn whose name merely CONTAINS the substring "test" (latest_, attest_,
// contest_) is NOT a test and must NOT be exempted.
fn latest_snapshot() {
    let mut v = make();
    v.push(z);                       // HIT 22: "latest" contains "test" but is not a test fn
}
