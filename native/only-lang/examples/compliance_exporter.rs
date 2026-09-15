use only_lang::evidence_store::ManifestEvidenceStore;
use std::env;
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: cargo run --example compliance_exporter <request_id> [output_path]");
        std::process::exit(1);
    }

    let request_id = &args[1];
    
    // Find base directory: search for manifest.json in standard workspace paths
    let base_path = if Path::new("only-lang/evidence/manifest.json").exists() {
        Path::new("only-lang")
    } else if Path::new("evidence/manifest.json").exists() {
        Path::new(".")
    } else {
        Path::new(".")
    };
    
    let store = ManifestEvidenceStore::new(base_path);

    println!("[Compliance Exporter] Exporting compliance package for Request ID: {}", request_id);

    match store.create_compliance_package(request_id) {
        Ok(zip_bytes) => {
            let default_name = format!("compliance_package_{}.zip", request_id);
            let out_name = args.get(2).unwrap_or(&default_name);
            std::fs::write(out_name, &zip_bytes)?;
            println!("[Success] Signed compliance package written to: {}", out_name);
            
            // Re-read compliance manifest from zip to display details
            use std::io::Read;
            let cursor = std::io::Cursor::new(zip_bytes);
            let mut archive = zip::ZipArchive::new(cursor)?;
            let mut manifest_file = archive.by_name("compliance_manifest.json")?;
            let mut manifest_content = String::new();
            manifest_file.read_to_string(&mut manifest_content)?;
            
            let val: serde_json::Value = serde_json::from_str(&manifest_content)?;
            println!("\n=== COMPLIANCE PACKAGE MANIFEST ===");
            println!("Request ID:         {}", val.get("request_id").and_then(|v| v.as_str()).unwrap_or(""));
            println!("Export Timestamp:   {}", val.get("exported_unix_ms").and_then(|v| v.as_u64()).unwrap_or(0));
            println!("Overall Gate State: {}", val.get("overall_gate_state").and_then(|v| v.as_str()).unwrap_or(""));
            println!("Policy Version:     {}", val.get("policy_version").and_then(|v| v.as_str()).unwrap_or(""));
            println!("Signature (SHA256): {}", val.get("signature").and_then(|v| v.as_str()).unwrap_or(""));
            
            if let Some(frameworks) = val.get("regulatory_frameworks").and_then(|v| v.as_array()) {
                let fw_strs: Vec<&str> = frameworks.iter().filter_map(|v| v.as_str()).collect();
                println!("Frameworks:         {:?}", fw_strs);
            }
            
            println!("Files Included:");
            if let Some(files) = val.get("files").and_then(|v| v.as_array()) {
                for f in files {
                    println!(
                        "  - {} ({} bytes, sha256: {})",
                        f.get("filename").and_then(|v| v.as_str()).unwrap_or(""),
                        f.get("size_bytes").and_then(|v| v.as_u64()).unwrap_or(0),
                        f.get("sha256").and_then(|v| v.as_str()).unwrap_or("")
                    );
                }
            }
            println!("===================================");
        }
        Err(e) => {
            eprintln!("[Error] Failed to create compliance package: {}", e);
            std::process::exit(1);
        }
    }

    Ok(())
}
