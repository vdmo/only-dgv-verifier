//! End-to-end pilot rehearsal (library path — no HTTP server required).

use only_lang::document_execute::{execute_document_generate, execute_document_send};
use only_lang::document_manifest::verify_document;
use serde_json::json;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    println!("=== OnlyOS design-partner pilot E2E (library) ===\n");

    let facts = json!({
        "case_id": "CLM-PILOT-001",
        "claim_amount_gbp": 450.0,
        "limitation_ok": true,
        "jurisdiction": "eng_wales",
        "dispute_type": "deposit",
        "has_contract": true,
        "has_payment_proof": true,
        "defendant_named": true,
        "gate_state": "ALLOW",
        "decision_hash": "hash_generate_pilot",
        "governance_run_id": "run_generate_pilot"
    });

    let gen = execute_document_generate(&base, &facts, 1)?;
    let sha = gen["content_sha256"].as_str().unwrap();
    let fp = gen["manifest_fingerprint"].as_str().unwrap();
    println!("1. Generate + register");
    println!("   content_sha256:      {sha}");
    println!("   manifest_fingerprint: {fp}");

    let send_params = json!({
        "content_sha256": sha,
        "manifest_fingerprint": fp,
        "decision_hash": "hash_send_pilot",
        "recipient": "defendant@design-partner.example"
    });
    let send = execute_document_send(&base, &send_params, "hash_send_pilot", "run_send_pilot", 2)?;
    println!("\n2. Governed send");
    println!("   delivered:           {}", send["delivered"]);
    println!("   delivery_receipt_id: {}", send["delivery_receipt_id"]);
    println!("   outbox:              {}", send["outbox_path"]);

    let blob = only_lang::document_manifest::read_content_blob(&base, sha)?;
    let verify = verify_document(&base, sha, Some(&blob), None);
    println!("\n3. Verify");
    println!("   integrity:  {}", verify.integrity);
    println!("   registered: {}", verify.registered);
    println!("   ok:         {}", verify.ok);

    println!("\nPilot E2E complete. For HTTP rehearsal: .\\scripts\\run_pilot_demo.ps1");
    Ok(())
}
