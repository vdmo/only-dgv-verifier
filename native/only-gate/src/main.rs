//! only-gate v0.2.0 — Real verification engine for DGV compliance testing.
//!
//! Thin binary wrapper around the only_gate library crate.
//! All check functions live in lib.rs and are shared with dgv-verifier.

fn main() {
    let (check, params) = only_gate::parse_args();
    let result = only_gate::run_check(&check, &params);
    println!("{}", result);
}
