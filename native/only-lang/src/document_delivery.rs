//! Document delivery adapter (pilot — file outbox; swap for SMTP/MCOL later).

use crate::document_manifest::{content_sha256_hex, read_content_blob, store_content_blob};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryReceipt {
    pub delivery_receipt_id: String,
    pub channel: String,
    pub recipient_hash: String,
    pub content_sha256: String,
    pub delivered: bool,
    pub outbox_path: Option<String>,
    pub delivered_at_unix_ms: u128,
    pub message: String,
}

fn recipient_hash(recipient: &str) -> String {
    hex::encode(Sha256::digest(recipient.trim().to_ascii_lowercase().as_bytes()))
}

fn outbox_dir(base: &Path) -> std::path::PathBuf {
    crate::document_manifest::documents_root(base).join("outbox")
}

/// Pilot delivery: write `.eml` stub to outbox (replace with SMTP/SendGrid in production).
pub fn deliver_letter(
    base: &Path,
    content_sha256: &str,
    recipient: &str,
    delivered_at_unix_ms: u128,
) -> Result<DeliveryReceipt, String> {
    if recipient.trim().is_empty() {
        return Err("recipient required".into());
    }
    let bytes = read_content_blob(base, content_sha256)
        .map_err(|e| format!("content blob missing: {e}"))?;
    let computed = content_sha256_hex(&bytes);
    if !computed.eq_ignore_ascii_case(content_sha256) {
        return Err("blob integrity mismatch".into());
    }

    let receipt_id = format!(
        "dlv_{}_{}",
        &content_sha256[..content_sha256.len().min(12)],
        delivered_at_unix_ms
    );
    std::fs::create_dir_all(outbox_dir(base)).map_err(|e| e.to_string())?;
    let path = outbox_dir(base).join(format!("{receipt_id}.eml"));
    let body = format!(
        "To: {recipient}\r\nSubject: Letter Before Action (OnlyOS pilot)\r\nContent-Type: application/pdf\r\nX-OnlyOS-Content-Sha256: {content_sha256}\r\n\r\n[Pilot outbox — PDF bytes in blobs/{content_sha256}]\r\n"
    );
    std::fs::write(&path, body).map_err(|e| e.to_string())?;

    Ok(DeliveryReceipt {
        delivery_receipt_id: receipt_id,
        channel: "email_outbox_pilot".to_string(),
        recipient_hash: recipient_hash(recipient),
        content_sha256: content_sha256.to_string(),
        delivered: true,
        outbox_path: Some(path.to_string_lossy().to_string()),
        delivered_at_unix_ms,
        message: "Delivered to pilot outbox — wire SMTP for production".to_string(),
    })
}

pub fn store_registered_blob(base: &Path, content_sha256: &str, bytes: &[u8]) -> Result<(), String> {
    store_content_blob(base, content_sha256, bytes)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::document_manifest::{
        register_document, DocumentManifestBuilder, DocumentProvenanceClass,
    };

    #[test]
    fn deliver_from_blob() {
        let dir = std::env::temp_dir().join("only_doc_deliver_test");
        let _ = std::fs::remove_dir_all(&dir);
        let pdf = b"%PDF-1.4 pilot letter".to_vec();
        let (m, _) = DocumentManifestBuilder::new(
            "application/pdf",
            "platform",
            DocumentProvenanceClass::PlatformGeneratedLetter,
        )
        .content_bytes(pdf.clone())
        .governance("hash_x", "ALLOW", "run_1")
        .build()
        .unwrap();
        store_content_blob(&dir, &m.content_sha256, &pdf).unwrap();
        register_document(&dir, m.clone(), 1, true).unwrap();
        let receipt = deliver_letter(&dir, &m.content_sha256, "defendant@example.com", 99).unwrap();
        assert!(receipt.delivered);
        assert!(receipt.outbox_path.is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
