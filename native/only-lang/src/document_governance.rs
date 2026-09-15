//! Governance gates for document tools (P1).

use crate::document_manifest::lookup_by_sha256;
use crate::document_manifest::{blob_path_for, read_content_blob};
use serde_json::Value;
use std::path::Path;

pub fn gate_document_send(base: &Path, params: &Value, gate_decision_hash: &str) -> Result<(), String> {
    let recipient = params
        .get("recipient")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if recipient.trim().is_empty() {
        return Err("missing recipient".into());
    }
    let content_sha256 = params
        .get("content_sha256")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing content_sha256".to_string())?;
    let manifest_fp = params
        .get("manifest_fingerprint")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing manifest_fingerprint".to_string())?;
    let decision_hash = params
        .get("decision_hash")
        .and_then(|v| v.as_str())
        .unwrap_or(gate_decision_hash);

    let registered = lookup_by_sha256(base, content_sha256)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "document not registered".to_string())?;

    if !registered.manifest_fingerprint.eq_ignore_ascii_case(manifest_fp) {
        return Err("manifest_fingerprint mismatch".into());
    }

    if let Some(reg_dh) = &registered.decision_hash {
        if !reg_dh.eq_ignore_ascii_case(decision_hash) {
            return Err("decision_hash mismatch vs registered manifest".into());
        }
    }

    if registered.gate_state.as_deref() != Some("ALLOW") {
        return Err(format!(
            "registered gate_state={:?}, expected ALLOW",
            registered.gate_state
        ));
    }

    if read_content_blob(base, content_sha256).is_err() {
        return Err(format!(
            "content blob missing at {}",
            blob_path_for(base, content_sha256).display()
        ));
    }

    Ok(())
}

pub fn gate_document_ingest(params: &Value) -> Result<(), String> {
    if params.get("content_sha256").and_then(|v| v.as_str()).is_none()
        && params.get("content_base64").and_then(|v| v.as_str()).is_none()
    {
        return Err("missing content_sha256 or content_base64".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::document_manifest::{
        register_document, store_content_blob, DocumentManifestBuilder, DocumentProvenanceClass,
    };
    use serde_json::json;

    #[test]
    fn send_gate_passes_when_registered() {
        let dir = std::env::temp_dir().join("only_doc_gate_test");
        let _ = std::fs::remove_dir_all(&dir);
        let (m, _) = DocumentManifestBuilder::new(
            "application/pdf",
            "platform",
            DocumentProvenanceClass::PlatformGeneratedLetter,
        )
        .content_bytes(b"%PDF-1.4".to_vec())
        .governance("hash_abc", "ALLOW", "run_1")
        .build()
        .unwrap();
        store_content_blob(&dir, &m.content_sha256, b"%PDF-1.4").unwrap();
        register_document(&dir, m.clone(), 1, true).unwrap();
        let params = json!({
            "content_sha256": m.content_sha256,
            "manifest_fingerprint": m.manifest_fingerprint,
            "decision_hash": "hash_abc",
            "recipient": "defendant@example.com"
        });
        assert!(gate_document_send(&dir, &params, "hash_abc").is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
