#![cfg(feature = "kcov")]

#[test]
fn exported_record_edge_macro_expands_in_a_dependent_crate() {
    coverage::record_edge!();
}
