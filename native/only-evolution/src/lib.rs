#![no_std]
//! ONLY Evolution: Healing solvers and multi-missing strategies
//! Invariants:
//! - Single-missing solve restores first-order equilibrium via v_target = -sum / s_target
//! - Multi-missing strategies require additional constraints (equal mids, ratio ends/mids, affine ends)
//! - Diagnostics include residual post-solve and solvability status

use only_core::Sign;

#[inline]
fn sqrt(x: f64) -> f64 {
    libm::sqrt(x)
}

#[derive(Debug, PartialEq)]
pub enum MultiSolveStatus {
    Solved,
    Unsolvable,
    InvalidConstraints,
}

pub struct MultiSolveResult {
    pub status: MultiSolveStatus,
    pub values: Option<(f64, f64)>,
    pub residual: f64,
}

/// The Evolution Engine (The Healer)
/// Given n-1 elements and their signs, solve for the missing i-th element
/// to restore 1st-order equilibrium (Sum s_j * v_j = 0)
pub fn solve_for_equilibrium(
    signs: &[Sign],
    known_values: &[(usize, f64)],
    target_idx: usize,
) -> f64 {
    let mut sum: f64 = 0.0;

    // Accumulate all other known (s_j * v_j)
    for (idx, val) in known_values {
        if *idx != target_idx {
            let s = signs[*idx] as i8 as f64;
            sum += s * val;
        }
    }

    // 0 = s_target * v_target + sum
    // v_target = -sum / s_target
    let target_sign = signs[target_idx] as i8 as f64;
    -sum / target_sign
}

/// Solver that also returns the post-insert residual and checks tolerance externally
pub fn solve_with_residual(
    signs: &[Sign],
    known_values: &[(usize, f64)],
    target_idx: usize,
) -> (f64, f64) {
    let v_target = solve_for_equilibrium(signs, known_values, target_idx);
    let mut residual: f64 = 0.0;
    for (idx, val) in known_values {
        let s = signs[*idx] as i8 as f64;
        residual += s * *val;
    }
    let s_target = signs[target_idx] as i8 as f64;
    residual += s_target * v_target;
    (v_target, residual)
}

pub fn solve_two_unknowns_with_moment(
    signs: &[Sign],
    known_values: &[(usize, f64)],
    unknown_indices: (usize, usize),
    moment_data: f64,
) -> MultiSolveResult {
    if signs.len() != 4 {
        return MultiSolveResult {
            status: MultiSolveStatus::InvalidConstraints,
            values: None,
            residual: 0.0,
        };
    }
    let (a, b) = unknown_indices;
    let p = signs[0] as i8;
    let m1 = signs[1] as i8;
    let m2 = signs[2] as i8;
    let p2 = signs[3] as i8;
    if !(p == 1 && m1 == -1 && m2 == -1 && p2 == 1) {
        return MultiSolveResult {
            status: MultiSolveStatus::InvalidConstraints,
            values: None,
            residual: 0.0,
        };
    }
    let mut vals = [0.0f64; 4];
    for (idx, val) in known_values {
        vals[*idx] = *val;
    }
    let _sum_known = (signs[0] as i8 as f64) * vals[0]
        + (signs[1] as i8 as f64) * vals[1]
        + (signs[2] as i8 as f64) * vals[2]
        + (signs[3] as i8 as f64) * vals[3];

    if a == 0 && b == 3 {
        let y2 = vals[1];
        let y3 = vals[2];
        if (y2 - y3).abs() < 1e-12 {
            let y = y2;
            let x = sqrt(moment_data / 2.0 + y * y);
            let residual = (signs[0] as i8 as f64) * (x)
                + (signs[1] as i8 as f64) * y
                + (signs[2] as i8 as f64) * y
                + (signs[3] as i8 as f64) * (x);
            return MultiSolveResult {
                status: MultiSolveStatus::Solved,
                values: Some((x, x)),
                residual,
            };
        }
    }
    MultiSolveResult {
        status: MultiSolveStatus::Unsolvable,
        values: None,
        residual: 0.0,
    }
}

pub fn solve_two_unknowns_ratio_ends(
    signs: &[Sign],
    known_values: &[(usize, f64)],
    unknown_indices: (usize, usize),
    moment_data: f64,
    ratio_r: f64,
) -> MultiSolveResult {
    if signs.len() != 4 || !ratio_r.is_finite() || ratio_r <= 0.0 {
        return MultiSolveResult {
            status: MultiSolveStatus::InvalidConstraints,
            values: None,
            residual: 0.0,
        };
    }
    let (u0, u3) = unknown_indices;
    if !(u0 == 0 && u3 == 3) {
        return MultiSolveResult {
            status: MultiSolveStatus::InvalidConstraints,
            values: None,
            residual: 0.0,
        };
    }

    let mut vals = [0.0f64; 4];
    for (idx, val) in known_values {
        vals[*idx] = *val;
    }
    if (vals[1] - vals[2]).abs() > 1e-12 {
        return MultiSolveResult {
            status: MultiSolveStatus::Unsolvable,
            values: None,
            residual: 0.0,
        };
    }
    let y = vals[1];
    let v3_eq = 2.0 * y / (ratio_r + 1.0);
    let v3_m = sqrt((moment_data + 2.0 * y * y) / (1.0 + ratio_r * ratio_r));
    if (v3_eq - v3_m).abs() > 1e-9 {
        return MultiSolveResult {
            status: MultiSolveStatus::Unsolvable,
            values: None,
            residual: 0.0,
        };
    }
    let v3 = v3_eq;
    let v0 = ratio_r * v3;
    let residual = (signs[0] as i8 as f64) * v0
        + (signs[1] as i8 as f64) * y
        + (signs[2] as i8 as f64) * y
        + (signs[3] as i8 as f64) * v3;
    MultiSolveResult {
        status: MultiSolveStatus::Solved,
        values: Some((v0, v3)),
        residual,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;
    use alloc::vec;
    use alloc::vec::Vec;
    use only_core::{check_equilibrium, generate_signs, Sign};

    #[test]
    fn test_self_healing() {
        let n = 8;
        let signs: Vec<Sign> = generate_signs(n).collect();
        let mut values = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 0.0];
        let known = (0..7).map(|i| (i, values[i])).collect::<Vec<_>>();
        let healed_val = solve_for_equilibrium(&signs, &known, 7);
        values[7] = healed_val;
        assert!(check_equilibrium(&signs, &values, 1e-10));
    }

    #[test]
    fn test_multi_missing_solved() {
        let signs: Vec<Sign> = generate_signs(4).collect();
        let y = 1.0;
        let known = vec![(1, y), (2, y)];
        let res = solve_two_unknowns_with_moment(&signs, &known, (0, 3), 0.0);
        assert_eq!(res.status, MultiSolveStatus::Solved);
        assert!(res.residual.abs() < 1e-9);
    }
}
