//! Execute document marketplace tools (generate + send).

use crate::claims::{
    generate_letter, qualify, render_letter_pdf_bytes, ClaimFacts,
};
use crate::document_delivery::deliver_letter;
use crate::document_governance::gate_document_send;
use crate::document_manifest::{
    bind_governance, register_document_with_blob, DocumentManifestBuilder, DocumentProvenanceClass,
};
use serde_json::{json, Value};
use std::path::Path;

pub fn is_document_tool(tool: &str) -> bool {
    tool.starts_with("document.") || tool.starts_with("claims.")
}

pub fn execute_document_generate(
    base: &Path,
    params: &Value,
    registered_at: u128,
) -> Result<Value, String> {
    let case_id = params
        .get("case_id")
        .and_then(|v| v.as_str())
        .unwrap_or("case_unknown");
    let facts: ClaimFacts = if let Some(f) = params.get("facts") {
        serde_json::from_value(f.clone()).map_err(|e| format!("invalid facts: {e}"))?
    } else {
        serde_json::from_value(params.clone()).map_err(|e| format!("invalid ClaimFacts: {e}"))?
    };

    let q = qualify(&facts);
    if !q.eligible {
        return Err(format!("claim ineligible: {:?}", q.track));
    }

    let draft = generate_letter(case_id, &facts, q.track);
    let pdf_bytes = render_letter_pdf_bytes(&draft);
    let mut builder = DocumentManifestBuilder::new(
        "application/pdf",
        "claims_platform",
        DocumentProvenanceClass::PlatformGeneratedLetter,
    )
    .content_bytes(pdf_bytes.clone())
    .template_id(&draft.template_id)
    .facts_json(&draft.facts_json);

    if let (Some(dh), Some(gs), Some(rid)) = (
        params.get("decision_hash").and_then(|v| v.as_str()),
        params.get("gate_state").and_then(|v| v.as_str()),
        params.get("governance_run_id").and_then(|v| v.as_str()),
    ) {
        builder = builder.governance(dh, gs, rid);
    }

    let (manifest, _) = builder.build().map_err(|e| e.to_string())?;
    let registered = register_document_with_blob(base, manifest, &pdf_bytes, registered_at, true)
        .map_err(|e| e.to_string())?;

    Ok(json!({
        "generated": true,
        "qualification": q,
        "template_id": draft.template_id,
        "content_sha256": registered.content_sha256,
        "manifest_fingerprint": registered.manifest_fingerprint,
        "ai_generated": true
    }))
}

pub fn execute_document_send(
    base: &Path,
    params: &Value,
    gate_decision_hash: &str,
    gate_run_id: &str,
    delivered_at: u128,
) -> Result<Value, String> {
    let content_sha256 = params
        .get("content_sha256")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing content_sha256".to_string())?;
    let recipient = params
        .get("recipient")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing recipient".to_string())?;

    bind_governance(base, content_sha256, gate_decision_hash, "ALLOW", gate_run_id)
        .map_err(|e| e.to_string())?;
    gate_document_send(base, params, gate_decision_hash)?;

    let receipt = deliver_letter(base, content_sha256, recipient, delivered_at)?;
    Ok(json!({
        "delivered": receipt.delivered,
        "delivery_receipt_id": receipt.delivery_receipt_id,
        "channel": receipt.channel,
        "recipient_hash": receipt.recipient_hash,
        "content_sha256": receipt.content_sha256,
        "outbox_path": receipt.outbox_path,
        "message": receipt.message
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::document_manifest::lookup_by_sha256;

    fn sample_facts() -> Value {
        json!({
            "case_id": "CLM-001",
            "claim_amount_gbp": 400.0,
            "limitation_ok": true,
            "jurisdiction": "eng_wales",
            "dispute_type": "deposit",
            "has_contract": true,
            "has_payment_proof": true,
            "defendant_named": true,
            "gate_state": "ALLOW",
            "decision_hash": "hash_gen",
            "governance_run_id": "run_gen"
        })
    }

    #[test]
    fn generate_then_send_loop() {
        let dir = std::env::temp_dir().join("only_doc_exec_test");
        let _ = std::fs::remove_dir_all(&dir);
        let gen = execute_document_generate(&dir, &sample_facts(), 1).unwrap();
        let sha = gen.get("content_sha256").and_then(|v| v.as_str()).unwrap();
        let fp = gen
            .get("manifest_fingerprint")
            .and_then(|v| v.as_str())
            .unwrap();
        let send_params = json!({
            "content_sha256": sha,
            "manifest_fingerprint": fp,
            "decision_hash": "hash_send",
            "recipient": "defendant@example.com"
        });
        let out = execute_document_send(&dir, &send_params, "hash_send", "run_send", 2).unwrap();
        assert_eq!(out.get("delivered").and_then(|v| v.as_bool()), Some(true));
        assert!(lookup_by_sha256(&dir, sha).unwrap().is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
