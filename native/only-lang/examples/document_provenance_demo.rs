//! Document provenance demo: register PDF bytes, write sidecar, verify integrity.

use only_lang::document_manifest::{
    register_document, verify_document, write_sidecar, DocumentManifestBuilder,
    DocumentProvenanceClass,
};
use only_lang::evidence_pack::now_unix_ms;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    let facts = r#"{"case_id":"CLM-10492","amount":800,"template":"LBA_deposit_v3"}"#;
    let pdf_bytes = b"%PDF-1.4\n% Demo letter before action\n";

    let (manifest, _) = DocumentManifestBuilder::new(
        "application/pdf",
        "claims_platform",
        DocumentProvenanceClass::PlatformGeneratedLetter,
    )
    .content_bytes(pdf_bytes.to_vec())
    .template_id("LBA_deposit_v3")
    .facts_json(facts)
    .governance("faebaa4f5ed38aa0", "ALLOW", "run_demo_governance")
    .build()?;

    let sidecar = write_sidecar(&base, &manifest)?;
    let registered =
        register_document(&base, manifest.clone(), now_unix_ms(), false)?;

    println!("=== Document provenance demo ===\n");
    println!("content_sha256:     {}", registered.content_sha256);
    println!("manifest_fingerprint: {}", registered.manifest_fingerprint);
    println!("sidecar:            {}", sidecar.display());
    println!("provenance_class:   {}", registered.provenance_class);
    println!("ai_generated:       {}", registered.ai_generated);
    println!("c2pa.status:        {}", registered.c2pa.status);
    println!("pir_watermark:      {}", registered.pir_watermark.status);

    let ok = verify_document(&base, &registered.content_sha256, Some(pdf_bytes), None);
    println!("\nVerify (match): integrity={} registered={}", ok.integrity, ok.registered);

    let bad = verify_document(&base, &registered.content_sha256, Some(b"tampered"), None);
    println!(
        "Verify (tampered): integrity={} ok={}",
        bad.integrity, bad.ok
    );

    println!("\nAPI (with only_control_api running):");
    println!("  POST http://127.0.0.1:8091/api/document/register");
    println!("  GET  http://127.0.0.1:8091/api/document/verify/{}", registered.content_sha256);

    Ok(())
}
