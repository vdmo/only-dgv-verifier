//! PIR structural watermark for trusted capture (Phase 3).

use only_core::{check_equilibrium, compute_residual, generate_signs, Sign};
use serde::{Deserialize, Serialize};

pub const DEFAULT_WATERMARK_LEN: usize = 64;
pub const DEFAULT_TOLERANCE: f64 = 1.0;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PirWatermarkSummary {
    pub applicable: bool,
    pub verified: bool,
    #[serde(default)]
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub residual: Option<f64>,
    #[serde(default = "default_watermark_len_field")]
    pub watermark_len: usize,
}

fn default_watermark_len_field() -> usize {
    DEFAULT_WATERMARK_LEN
}

impl Default for PirWatermarkSummary {
    fn default() -> Self {
        Self {
            applicable: false,
            verified: false,
            status: "not_applicable".to_string(),
            residual: None,
            watermark_len: DEFAULT_WATERMARK_LEN,
        }
    }
}

fn signs(len: usize) -> Vec<Sign> {
    generate_signs(len).collect()
}

fn values_from_bytes(bytes: &[u8], len: usize) -> Vec<f64> {
    bytes.iter().take(len).map(|&b| b as f64).collect()
}

/// Embed equilibrium watermark into first `watermark_len` bytes (trusted capture only).
pub fn embed_pir_watermark(bytes: &mut [u8], watermark_len: usize) -> Result<(), &'static str> {
    if bytes.len() < watermark_len || watermark_len < 2 {
        return Err("buffer too small for watermark");
    }
    let s = signs(watermark_len);
    let mut sum = 0.0;
    for i in 0..watermark_len - 1 {
        sum += bytes[i] as f64 * s[i] as i8 as f64;
    }
    let last = s[watermark_len - 1] as i8 as f64;
    bytes[watermark_len - 1] = (-sum / last).clamp(0.0, 255.0) as u8;
    Ok(())
}

/// Verify structural watermark residual.
pub fn verify_pir_watermark(bytes: &[u8], watermark_len: usize, tolerance: f64) -> PirWatermarkSummary {
    if bytes.len() < watermark_len {
        return PirWatermarkSummary {
            applicable: true,
            verified: false,
            status: "buffer_too_short".to_string(),
            watermark_len,
            ..Default::default()
        };
    }
    let s = signs(watermark_len);
    let vals = values_from_bytes(bytes, watermark_len);
    let residual = compute_residual(&s, &vals).abs();
    let verified = check_equilibrium(&s, &vals, tolerance);
    PirWatermarkSummary {
        applicable: true,
        verified,
        status: if verified {
            "verified".to_string()
        } else {
            "dissonance_detected".to_string()
        },
        residual: Some(residual),
        watermark_len,
    }
}

pub fn summary_for_untrusted_upload() -> PirWatermarkSummary {
    PirWatermarkSummary {
        applicable: false,
        verified: false,
        status: "not_applicable_on_arbitrary_upload".to_string(),
        watermark_len: DEFAULT_WATERMARK_LEN,
        residual: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embed_then_verify() {
        let mut buf = vec![120u8; 128];
        embed_pir_watermark(&mut buf, 64).unwrap();
        let s = verify_pir_watermark(&buf, 64, 1.0);
        assert!(s.verified, "residual={:?}", s.residual);
    }

    #[test]
    fn tamper_breaks_verify() {
        let mut buf = vec![120u8; 128];
        embed_pir_watermark(&mut buf, 64).unwrap();
        buf[0] = buf[0].wrapping_add(10);
        let s = verify_pir_watermark(&buf, 64, 1.0);
        assert!(!s.verified);
    }
}
