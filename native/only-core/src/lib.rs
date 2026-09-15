#![no_std]
extern crate alloc;
// ONLY Core: Arithmetic invariants and equilibrium primitives
// Invariants:
// - Residual r = Σ s_i v_i; equilibrium holds when |r| ≤ τ
// - Sign vector generated via Prouhet–Thue–Morse for deterministic balance patterns
// - Constructors produce fields satisfying first-order equilibrium by solving the last element

use serde::{Deserialize, Serialize};
use alloc::string::String;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum Sign {
    Plus = 1,
    Minus = -1,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GateDecision {
    /// The action is cryptographically verified and authorized.
    PERMIT,
    /// The action violates mathematical or policy constraints and is hard-blocked.
    DENY(String),
    /// The action exceeds autonomous thresholds and requires Human-in-the-Loop.
    ESCALATE(String),
    /// The engine is corrupted, unreachable, or in an invalid state.
    SILENCE,
    /// The system maintains multiple admissible interpretations without committing.
    /// Used for sustained ambiguity holding (TC-056) and persistent state across turns (TC-060).
    HOLD(String),
}

/// The Prouhet-Thue-Morse Generator (The Universal Grammar)
pub fn generate_signs(n: usize) -> core::iter::Map<core::ops::Range<usize>, fn(usize) -> Sign> {
    (0..n).map(|i| {
        if i.count_ones() % 2 == 0 {
            Sign::Plus
        } else {
            Sign::Minus
        }
    })
}

/// The Foundational 1st-Order Equilibrium Check
pub fn check_equilibrium(signs: &[Sign], values: &[f64], tolerance: f64) -> bool {
    let residual = compute_residual(signs, values);
    residual.abs() < tolerance
}

/// Computes the raw equilibrium residual: Σ s_i * v_i
pub fn compute_residual(signs: &[Sign], values: &[f64]) -> f64 {
    signs
        .iter()
        .zip(values.iter())
        .map(|(s, v)| (*s as i8 as f64) * *v)
        .sum()
}

/// Equilibrium check that returns both pass/fail and residual
pub fn check_equilibrium_with_residual(
    signs: &[Sign],
    values: &[f64],
    tolerance: f64,
) -> (bool, f64) {
    let residual = compute_residual(signs, values);
    (residual.abs() < tolerance, residual)
}

/// Constructs a balanced field in-place using a constant base value for first n-1 elements
/// and solving the last element to achieve Σ s_i * v_i = 0.
/// Returns Err(()) when input lengths mismatch or n < 2.
pub fn make_balanced_field_in_place(
    signs: &[Sign],
    values: &mut [f64],
    base_value: f64,
) -> Result<(), ()> {
    let n = signs.len();
    if n != values.len() || n < 2 {
        return Err(());
    }
    for i in 0..(n - 1) {
        values[i] = base_value;
    }
    let mut sum: f64 = 0.0;
    for i in 0..(n - 1) {
        let s = signs[i] as i8 as f64;
        sum += s * values[i];
    }
    let last_sign = signs[n - 1] as i8 as f64;
    values[n - 1] = -sum / last_sign;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;
    use alloc::vec;

    #[test]
    fn residual_zero_for_balanced_two() {
        let signs: [Sign; 2] = [Sign::Plus, Sign::Minus];
        let values: [f64; 2] = [3.0, 3.0];
        let r = compute_residual(&signs, &values);
        assert!(r.abs() < 1e-12);
        assert!(check_equilibrium(&signs, &values, 1e-12));
        let (pass, residual) = check_equilibrium_with_residual(&signs, &values, 1e-12);
        assert!(pass);
        assert!(residual.abs() < 1e-12);
    }

    #[test]
    fn residual_detects_imbalance() {
        let signs: [Sign; 4] = [Sign::Plus, Sign::Minus, Sign::Minus, Sign::Plus];
        let values: [f64; 4] = [1.0, 1.0, 1.5, 1.0];
        let r = compute_residual(&signs, &values);
        assert!(r.abs() > 0.0);
        assert!(!check_equilibrium(&signs, &values, 1e-12));
    }

    #[test]
    fn construct_balanced_field_in_place() {
        let n = 6;
        // Generate Thue-Morse signs into a fixed array
        let mut signs = [Sign::Plus; 6];
        for (i, s) in generate_signs(n).enumerate() {
            signs[i] = s;
        }
        let mut values = [0.0f64; 6];
        make_balanced_field_in_place(&signs, &mut values, 2.0).unwrap();
        assert!(check_equilibrium(&signs, &values, 1e-12));
    }

    #[test]
    fn residual_stability_over_multiple_sizes() {
        // Simple deterministic sweep to approximate property test behavior
        for n in 2..9 {
            // Build signs
            let mut signs = vec![Sign::Plus; n];
            for (i, s) in generate_signs(n).enumerate() {
                signs[i] = s;
            }
            // Sweep base values
            for k in 1..5 {
                let base = k as f64;
                let mut values = vec![0.0f64; n];
                make_balanced_field_in_place(&signs, &mut values, base).unwrap();
                let r = compute_residual(&signs, &values);
                assert!(r.abs() < 1e-10);
                assert!(check_equilibrium(&signs, &values, 1e-10));
            }
        }
    }
}
