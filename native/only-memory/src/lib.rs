#![cfg_attr(not(test), no_std)]
//! ONLY Memory: Ghost storage via moment invariants
//! Invariants:
//! - First-order equilibrium: Σ s_i v_i = 0 (provider view)
//! - Second-order moment encodes payload: Σ s_i v_i^2 = data (user view)
//! - Encoders validate sign patterns and parameters; reveal reconstructs payload under equilibrium

use only_core::Sign;

#[inline]
fn sqrt(x: f64) -> f64 {
    libm::sqrt(x)
}

pub mod string_encoder;
/// Ghost Memory Encoder
/// Encodes a value (the "ghost") into a field of n integers such that:
/// 1. 1st-Order Equilibrium: Sum s_i * v_i = 0 (Provider View: "Empty")
/// 2. 2nd-Order Moment: Sum s_i * v_i^2 = Data (User View: "Hidden Value")
pub struct GhostMemory;

pub trait StorageAdapter {
    fn write(&self, key: u64, values: &[f64]) -> Result<(), ()>;
    fn read(&self, key: u64, out: &mut [f64]) -> Result<(), ()>;
}

#[derive(Debug, PartialEq)]
pub enum EncodeError {
    InvalidLength,
    InvalidSignsPattern,
    NonFiniteY,
}

impl GhostMemory {
    /// Encodes a single data value into a 2-element PIR field
    /// (Minimal viable ghost storage: n=2)
    pub fn encode_2(signs: &[Sign], data: f64) -> Result<[f64; 2], ()> {
        // We solve for v0, v1 such that:
        // s0*v0 + s1*v1 = 0
        // s0*v0^2 + s1*v1^2 = data

        // Note: For s0=1, s1=-1 (standard Thue-Morse for n=2):
        // v0 - v1 = 0  => v0 = v1
        // v0^2 - v1^2 = data => 0 = data (impossible for data != 0)

        // Therefore, we need n >= 4 for multi-moment balance.
        let _ = signs;
        let _ = data;
        Err(())
    }

    /// Encodes data into a 4-element PIR field (n=4)
    /// Rigorous solution using substitution v = [a+b, a+c, a-c, a-b]
    /// 1. Satisfies Sum s_i v_i = (a+b) - (a+c) - (a-c) + (a-b) = 0
    /// 2. Satisfies Sum s_i v_i^2 = (a+b)^2 - (a+c)^2 - (a-c)^2 + (a-b)^2 = 2b^2 - 2c^2
    pub fn encode_4(_signs: &[Sign], data: f64) -> [f64; 4] {
        let a = 100.0;
        let c = 1.0;
        let b = sqrt(data / 2.0 + c * c);
        [a + b, a + c, a - c, a - b]
    }

    pub fn try_encode_4(signs: &[Sign], data: f64) -> Result<[f64; 4], ()> {
        if signs.len() != 4 {
            return Err(());
        }
        let p = signs[0] as i8;
        let m1 = signs[1] as i8;
        let m2 = signs[2] as i8;
        let p2 = signs[3] as i8;
        if p != 1 || m1 != -1 || m2 != -1 || p2 != 1 {
            return Err(());
        }
        let y = 1.0;
        let x = sqrt(data / 2.0 + 1.0);
        Ok([x, y, -y, -x])
    }

    pub fn try_encode_4_with_y(signs: &[Sign], data: f64, y: f64) -> Result<[f64; 4], ()> {
        if signs.len() != 4 {
            return Err(());
        }
        let p = signs[0] as i8;
        let m1 = signs[1] as i8;
        let m2 = signs[2] as i8;
        let p2 = signs[3] as i8;
        if p != 1 || m1 != -1 || m2 != -1 || p2 != 1 {
            return Err(());
        }
        let x = sqrt(data / 2.0 + y * y);
        Ok([x, y, -y, -x])
    }

    pub fn encode_4_alt(_signs: &[Sign], data: f64) -> [f64; 4] {
        let a = 10.0;
        let c = 0.5;
        let b = sqrt(data / 2.0 + c * c);
        [a + b, a + c, a - c, a - b]
    }

    pub fn try_encode_4_alt(signs: &[Sign], data: f64) -> Result<[f64; 4], ()> {
        if signs.len() != 4 {
            return Err(());
        }
        let p = signs[0] as i8;
        let m1 = signs[1] as i8;
        let m2 = signs[2] as i8;
        let p2 = signs[3] as i8;
        if p != 1 || m1 != -1 || m2 != -1 || p2 != 1 {
            return Err(());
        }
        Ok(Self::encode_4_alt(signs, data))
    }

    pub fn encode_4_params(_signs: &[Sign], data: f64, a: f64, c: f64) -> [f64; 4] {
        let b = sqrt(data / 2.0 + c * c);
        [a + b, a + c, a - c, a - b]
    }

    pub fn try_encode_4_params(
        signs: &[Sign],
        data: f64,
        a: f64,
        c: f64,
    ) -> Result<[f64; 4], EncodeError> {
        if signs.len() != 4 {
            return Err(EncodeError::InvalidLength);
        }
        if !a.is_finite() || !c.is_finite() {
            return Err(EncodeError::NonFiniteY);
        }
        if c <= 0.0 {
            return Err(EncodeError::NonFiniteY);
        }
        let p = signs[0] as i8;
        let m1 = signs[1] as i8;
        let m2 = signs[2] as i8;
        let p2 = signs[3] as i8;
        if !(p == 1 && m1 == -1 && m2 == -1 && p2 == 1) {
            return Err(EncodeError::InvalidSignsPattern);
        }
        let field = Self::encode_4_params(signs, data, a, c);
        Ok(field)
    }

    pub fn try_encode_4_with_y_reason(
        signs: &[Sign],
        data: f64,
        y: f64,
    ) -> Result<[f64; 4], EncodeError> {
        if signs.len() != 4 {
            return Err(EncodeError::InvalidLength);
        }
        if !y.is_finite() {
            return Err(EncodeError::NonFiniteY);
        }
        let p = signs[0] as i8;
        let m1 = signs[1] as i8;
        let m2 = signs[2] as i8;
        let p2 = signs[3] as i8;
        if !(p == 1 && m1 == -1 && m2 == -1 && p2 == 1) {
            return Err(EncodeError::InvalidSignsPattern);
        }
        let x = sqrt(data / 2.0 + y * y);
        Ok([x, y, -y, -x])
    }
    /// Decodes (Reveals) the ghost data from a 4-element field
    pub fn reveal_4(signs: &[Sign], values: &[f64]) -> f64 {
        let mut sum: f64 = 0.0;
        for i in 0..4 {
            let s = signs[i] as i8 as f64;
            sum += s * values[i] * values[i]; // sum s_i * v_i^2
        }
        sum
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use only_core::{check_equilibrium, generate_signs};
    use only_evolution::solve_for_equilibrium;

    #[test]
    fn test_ghost_revealing() {
        let signs: Vec<Sign> = generate_signs(4).collect();
        let secret_data = 42.0;

        let field = GhostMemory::try_encode_4(&signs, secret_data).unwrap();

        // 1. Provider sees a balanced field (Empty)
        assert!(check_equilibrium(&signs, &field, 1e-10));

        // 2. User reveals the ghost data
        let revealed = GhostMemory::reveal_4(&signs, &field);
        assert!((revealed - secret_data).abs() < 1e-10);
    }

    #[test]
    fn test_roundtrip_corruption_matrix() {
        let signs: Vec<Sign> = generate_signs(4).collect();
        for secret in [1.0, 10.0, 64.0, 256.0] {
            let mut field = GhostMemory::try_encode_4(&signs, secret).unwrap();
            assert!(check_equilibrium(&signs, &field, 1e-12));
            for idx in 0..4 {
                let mut corrupted = field;
                corrupted[idx] = 0.0;
                let known = (0..4)
                    .filter(|&i| i != idx)
                    .map(|i| (i, corrupted[i]))
                    .collect::<Vec<_>>();
                let healed = solve_for_equilibrium(&signs, &known, idx);
                corrupted[idx] = healed;
                for tol in [1e-8, 1e-10, 1e-12] {
                    assert!(check_equilibrium(&signs, &corrupted, tol));
                }
                let revealed = GhostMemory::reveal_4(&signs, &corrupted);
                assert!((revealed - secret).abs() < 1e-8);
            }
        }
    }

    #[test]
    fn test_encode_error_reasons() {
        let mut bad_signs = [Sign::Plus; 4];
        bad_signs[1] = Sign::Plus;
        let e = GhostMemory::try_encode_4_with_y_reason(&bad_signs, 10.0, 1.0)
            .err()
            .unwrap();
        assert_eq!(e, EncodeError::InvalidSignsPattern);
        let signs: Vec<Sign> = generate_signs(4).collect();
        let e2 = GhostMemory::try_encode_4_with_y_reason(&signs, 10.0, f64::NAN)
            .err()
            .unwrap();
        assert_eq!(e2, EncodeError::NonFiniteY);
    }

    #[test]
    fn test_encode_params() {
        let signs: Vec<Sign> = generate_signs(4).collect();
        let field = GhostMemory::try_encode_4_params(&signs, 42.0, 50.0, 1.0).unwrap();
        assert!(check_equilibrium(&signs, &field, 1e-12));
        let revealed = GhostMemory::reveal_4(&signs, &field);
        assert!((revealed - 42.0).abs() < 1e-10);
    }

    #[test]
    fn test_encode_alt_and_params_variants() {
        let signs: Vec<Sign> = generate_signs(4).collect();
        let secret = 84.0;
        let field_alt = GhostMemory::try_encode_4_alt(&signs, secret).unwrap();
        assert!(check_equilibrium(&signs, &field_alt, 1e-12));
        let rev_alt = GhostMemory::reveal_4(&signs, &field_alt);
        assert!((rev_alt - secret).abs() < 1e-10);

        let field_params = GhostMemory::try_encode_4_params(&signs, secret, 20.0, 0.5).unwrap();
        assert!(check_equilibrium(&signs, &field_params, 1e-12));
        let rev_params = GhostMemory::reveal_4(&signs, &field_params);
        assert!((rev_params - secret).abs() < 1e-10);
    }
}
