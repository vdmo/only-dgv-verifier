//! PDF manifest embedding + platform signature envelope (PAdES pilot — HMAC, not X.509).

use crate::document_manifest::DocumentManifest;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io;

type HmacSha256 = Hmac<Sha256>;

pub const PADES_PILOT_ALG: &str = "HMAC-SHA256-platform-pilot-v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PadesEnvelope {
    pub algorithm: String,
    pub signed_at_unix_ms: u128,
    pub content_sha256: String,
    pub manifest_fingerprint: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedPdfBundle {
    pub pdf_bytes: Vec<u8>,
    pub manifest: DocumentManifest,
    pub pades: PadesEnvelope,
}

fn canonical_signing_input(content_sha256: &str, manifest_fingerprint: &str, signed_at: u128) -> String {
    format!("{content_sha256}.{manifest_fingerprint}.{signed_at}.{PADES_PILOT_ALG}")
}

pub fn sign_platform_envelope(
    secret: &[u8],
    content_sha256: &str,
    manifest_fingerprint: &str,
    signed_at_unix_ms: u128,
) -> PadesEnvelope {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC key");
    mac.update(
        canonical_signing_input(content_sha256, manifest_fingerprint, signed_at_unix_ms).as_bytes(),
    );
    PadesEnvelope {
        algorithm: PADES_PILOT_ALG.to_string(),
        signed_at_unix_ms,
        content_sha256: content_sha256.to_string(),
        manifest_fingerprint: manifest_fingerprint.to_string(),
        signature_hex: hex::encode(mac.finalize().into_bytes()),
    }
}

pub fn verify_platform_envelope(secret: &[u8], env: &PadesEnvelope) -> bool {
    let expected = sign_platform_envelope(
        secret,
        &env.content_sha256,
        &env.manifest_fingerprint,
        env.signed_at_unix_ms,
    );
    env.signature_hex == expected.signature_hex
}

/// Embed manifest + PAdES pilot block before %%EOF in a PDF byte stream.
pub fn embed_manifest_in_pdf(pdf: &[u8], manifest: &DocumentManifest, pades: &PadesEnvelope) -> io::Result<Vec<u8>> {
    let manifest_json = serde_json::to_string(manifest)?;
    let pades_json = serde_json::to_string(pades)?;
    let block = format!(
        "\n% OnlyOS-DocumentManifest\n% {}\n% OnlyOS-PadesPilot\n% {}\n",
        manifest_json.replace('\n', " "),
        pades_json.replace('\n', " ")
    );

    if let Some(pos) = pdf.windows(5).rposition(|w| w == b"%%EOF") {
        let mut out = Vec::with_capacity(pdf.len() + block.len());
        out.extend_from_slice(&pdf[..pos]);
        out.extend_from_slice(block.as_bytes());
        out.extend_from_slice(&pdf[pos..]);
        Ok(out)
    } else {
        let mut out = pdf.to_vec();
        out.extend_from_slice(block.as_bytes());
        Ok(out)
    }
}

pub fn sign_pdf_with_manifest(
    secret: &[u8],
    pdf_bytes: Vec<u8>,
    mut manifest: DocumentManifest,
    signed_at_unix_ms: u128,
) -> io::Result<SignedPdfBundle> {
    let pades = sign_platform_envelope(
        secret,
        &manifest.content_sha256,
        &manifest.manifest_fingerprint,
        signed_at_unix_ms,
    );
    let signed_pdf = embed_manifest_in_pdf(&pdf_bytes, &manifest, &pades)?;
    manifest.content_sha256 = hex::encode(Sha256::digest(&signed_pdf));
    manifest.manifest_fingerprint = crate::document_manifest::manifest_fingerprint(&manifest);
    Ok(SignedPdfBundle {
        pdf_bytes: signed_pdf,
        manifest,
        pades,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::document_manifest::{DocumentManifestBuilder, DocumentProvenanceClass};

    #[test]
    fn sign_and_verify_envelope() {
        let env = sign_platform_envelope(b"secret", "abc", "def", 123);
        assert!(verify_platform_envelope(b"secret", &env));
        assert!(!verify_platform_envelope(b"wrong", &env));
    }

    #[test]
    fn embed_in_pdf() {
        let pdf = b"%PDF-1.4\nhello\n%%EOF".to_vec();
        let (m, _) = DocumentManifestBuilder::new(
            "application/pdf",
            "test",
            DocumentProvenanceClass::PlatformGeneratedPdf,
        )
        .content_bytes(pdf.clone())
        .build()
        .unwrap();
        let pades = sign_platform_envelope(b"k", &m.content_sha256, &m.manifest_fingerprint, 1);
        let out = embed_manifest_in_pdf(&pdf, &m, &pades).unwrap();
        assert!(out.windows(5).any(|w| w == b"%%EOF"));
        assert!(String::from_utf8_lossy(&out).contains("OnlyOS-DocumentManifest"));
    }
}
