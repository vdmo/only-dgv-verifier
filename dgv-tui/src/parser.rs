use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestCase {
    pub id: String,
    pub input: serde_json::Value,
    pub expected: serde_json::Value,
    pub mandatory: bool,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestCard {
    pub id: String,
    /// "only-gate" routes to the real gate engine; absent/None uses dgv-verifier.
    pub executor: Option<String>,
    pub svrnos_layer: String,
    pub ger_mapping: String,
    pub claim_name: String,
    pub claim_definition: String,
    pub scope: String,
    pub test_type: String,
    pub test_cases: Vec<TestCase>,
    pub metrics: Vec<String>,
    pub pass_threshold: serde_json::Value,
    pub version: String,
    pub expiry: String,
    pub latency_threshold_ms: Option<f64>,
    pub replay_protection_required: Option<bool>,
    pub excluded_scope: Option<String>,
    pub evidence: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceCaseResult {
    pub case_id: String,
    pub passed: bool,
    pub runs_count: Option<u32>,
    pub runs_identical: Option<bool>,
    pub output_sample: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidencePackage {
    pub test_card_id: String,
    pub claim_name: String,
    pub svrnos_layer: String,
    pub ger_mapping: String,
    pub verified_timestamp: String,
    pub status: String, // e.g. "passed", "failed"
    pub results: Vec<EvidenceCaseResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certification {
    pub claim_id: String,
    pub claim_name: String,
    pub test_card_id: String,
    pub badge_status: String,
    pub verification_timestamp: String,
    pub expiry: String,
    pub evidence_package: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertifiedSystem {
    pub system_name: String,
    pub system_version: String,
    pub certifications: Vec<Certification>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimsRegistry {
    pub certified_systems: Vec<CertifiedSystem>,
}

pub fn load_test_cards(dir: &Path) -> Result<Vec<TestCard>, Box<dyn std::error::Error>> {
    let mut cards = Vec::new();
    if !dir.is_dir() {
        return Ok(cards);
    }
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() && path.extension().map_or(false, |ext| ext == "json") {
            let content = fs::read_to_string(&path)?;
            if let Ok(card) = serde_json::from_str::<TestCard>(&content) {
                cards.push(card);
            }
        }
    }
    // Sort cards by ID (e.g. TC-001, TC-002)
    cards.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(cards)
}

pub fn load_claims_registry(
    file_path: &Path,
) -> Result<ClaimsRegistry, Box<dyn std::error::Error>> {
    let content = fs::read_to_string(file_path)?;
    let registry = serde_json::from_str::<ClaimsRegistry>(&content)?;
    Ok(registry)
}

pub fn load_evidence_package(
    file_path: &Path,
) -> Result<EvidencePackage, Box<dyn std::error::Error>> {
    let content = fs::read_to_string(file_path)?;
    let evidence = serde_json::from_str::<EvidencePackage>(&content)?;
    Ok(evidence)
}

pub fn scan_evidence_dir(dir: &Path) -> HashMap<String, EvidencePackage> {
    let mut evidence_map = HashMap::new();
    if !dir.is_dir() {
        return evidence_map;
    }
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() && path.extension().map_or(false, |ext| ext == "json") {
                if let Ok(content) = fs::read_to_string(&path) {
                    if let Ok(evidence) = serde_json::from_str::<EvidencePackage>(&content) {
                        evidence_map.insert(evidence.test_card_id.clone(), evidence);
                    }
                }
            }
        }
    }
    evidence_map
}
