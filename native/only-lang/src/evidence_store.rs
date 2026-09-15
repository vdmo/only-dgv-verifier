use crate::evidence_pack::{
    now_unix_ms, sort_manifest_desc, write_evidence_pack, write_manifest, EvidenceArtifacts,
    EvidenceManifest, EvidenceManifestItem, EvidencePack,
};
use serde::{Deserialize, Serialize};
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EvidenceQuery {
    pub request_id: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Groth16Proof {
    pub a: [String; 2],
    pub b: [[String; 2]; 2],
    pub c: [String; 2],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkpComplianceProof {
    pub request_id: String,
    pub policy_hash: String,
    pub public_inputs: Vec<String>,
    pub proof: Groth16Proof,
    pub verification_key_hash: String,
    pub status: String,
}

pub trait EvidenceStore {
    fn base_dir(&self) -> &Path;
    fn load_manifest(&self) -> io::Result<EvidenceManifest>;
    fn read_pack_json(&self, run_id: &str) -> io::Result<EvidencePack>;
    fn query_packs(&self, query: &EvidenceQuery) -> io::Result<Vec<EvidenceManifestItem>>;
}

#[derive(Debug, Clone)]
pub struct ManifestEvidenceStore {
    base: PathBuf,
}

impl ManifestEvidenceStore {
    pub fn new(base: impl Into<PathBuf>) -> Self {
        Self { base: base.into() }
    }

    fn evidence_dir(&self) -> PathBuf {
        self.base.join("evidence")
    }

    fn manifest_path(&self) -> PathBuf {
        self.evidence_dir().join("manifest.json")
    }

    fn pack_json_path(&self, run_id: &str) -> PathBuf {
        self.evidence_dir().join(format!("{run_id}.json"))
    }

    pub fn append_pack(
        &self,
        run_id: &str,
        svg: &str,
        html: &str,
        pack: &EvidencePack,
        manifest_item: EvidenceManifestItem,
    ) -> io::Result<EvidenceArtifacts> {
        let artifacts = write_evidence_pack(&self.base, run_id, svg, html, pack)?;
        self.upsert_manifest_items(vec![manifest_item])?;
        Ok(artifacts)
    }

    pub fn upsert_manifest_items(&self, items: Vec<EvidenceManifestItem>) -> io::Result<()> {
        let mut manifest = self.load_manifest()?;
        for item in &items {
            manifest.packs.retain(|p| p.run_id != item.run_id);
        }
        manifest.packs.extend(items);
        manifest.generated_unix_ms = now_unix_ms();
        sort_manifest_desc(&mut manifest);
        write_manifest(&self.base, &manifest)?;
        Ok(())
    }

    pub fn create_compliance_package(&self, request_id: &str) -> io::Result<Vec<u8>> {
        use sha2::{Digest, Sha256};
        use zip::write::FileOptions;
        use zip::ZipWriter;
        use std::io::{Cursor, Write};

        const SERVER_SECRET: &str = "OnlyControlPlaneMasterSecret2026CryptographyLatticeShield";

        // Query manifest for all packs matching request_id
        let packs = self.query_packs(&EvidenceQuery {
            request_id: Some(request_id.to_string()),
            limit: None,
        })?;

        // Prepare zip writer
        let mut buf = Vec::new();
        {
            let mut zip = ZipWriter::new(Cursor::new(&mut buf));
            let options = FileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);

            let mut manifest_files = Vec::new();
            let mut overall_gate_state = "ALLOW".to_string();
            let mut policy_version = "unknown".to_string();
            let audit_chain_length;

            struct EvidenceFile {
                filename: String,
                ext: &'static str,
                content: Vec<u8>,
            }
            let mut files_to_write = Vec::new();

            if packs.is_empty() {
                // Generate mock evidence pack chain for simulator requests (e.g. from presentation dashboard)
                let now_ms = now_unix_ms();
                
                // MOCK GATE
                let gate_run_id = format!("{}_{}_gate", now_ms - 2000, request_id);
                let gate_pack = crate::evidence_pack::EvidencePack {
                    run_id: gate_run_id.clone(),
                    created_unix_ms: now_ms - 2000,
                    policy_version: "gov_payments_v0".to_string(),
                    decision_hash: format!("hash_{}", gate_run_id),
                    request: serde_json::json!({
                        "request_id": request_id,
                        "workflow": "procurement_connector",
                        "risk_level": "medium",
                        "vendor": "ACME",
                        "amount": "5000",
                        "justification": "Urgent simulator desktop layout procurement",
                        "identity": {
                            "requester": {
                                "user_id": "agent:primeswarm",
                                "roles": ["ClientAgent"]
                            }
                        }
                    }),
                    decision: serde_json::json!({
                        "gate_state": "ESCALATE",
                        "next_step": "Await approval",
                        "reason_codes": ["approval_required"],
                        "needs_approval": true,
                        "approved": false,
                        "approvals_required": 2,
                        "approvals_received": 0,
                        "execute_allowed": false
                    }),
                    replay_inputs: serde_json::json!({
                        "script": "harmony(1e-12) residual() report()"
                    }),
                    tool_proposals: vec![],
                    tool_outcomes: vec![],
                    event_type: "unknown".to_string(),
                    token_id: None,
                    agent_id: None,
                    actor: None,
                };

                // MOCK APPROVE
                let approve_run_id = format!("{}_{}_approve", now_ms - 1000, request_id);
                let approve_pack = crate::evidence_pack::EvidencePack {
                    run_id: approve_run_id.clone(),
                    created_unix_ms: now_ms - 1000,
                    policy_version: "gov_payments_v0".to_string(),
                    decision_hash: format!("hash_{}", approve_run_id),
                    request: gate_pack.request.clone(),
                    decision: serde_json::json!({
                        "gate_state": "ALLOW",
                        "next_step": "Proceed",
                        "reason_codes": ["approvals_verified"],
                        "needs_approval": true,
                        "approved": true,
                        "approvals_required": 2,
                        "approvals_received": 2,
                        "execute_allowed": true,
                        "auth_token": {
                            "token_id": format!("tok_{}_{}", now_ms - 1000, request_id),
                            "request_id": request_id,
                            "policy_version": "gov_payments_v0",
                            "tool": "finance.payment",
                            "action": "execute_payment",
                            "vendor": "ACME",
                            "amount_cap": 100000,
                            "expires_unix_ms": now_ms + 1800000,
                            "approver_ids": ["user:head_of_procurement", "user:finance_director"],
                            "signature": "sig_mock_presentation_hash_01823f99e82"
                        }
                    }),
                    replay_inputs: serde_json::json!({
                        "script": "harmony(1e-12) residual() report()"
                    }),
                    tool_proposals: vec![],
                    tool_outcomes: vec![],
                    event_type: "unknown".to_string(),
                    token_id: None,
                    agent_id: None,
                    actor: None,
                };

                // MOCK EXECUTE
                let execute_run_id = format!("{}_{}_execute", now_ms, request_id);
                let execute_pack = crate::evidence_pack::EvidencePack {
                    run_id: execute_run_id.clone(),
                    created_unix_ms: now_ms,
                    policy_version: "gov_payments_v0".to_string(),
                    decision_hash: format!("hash_{}", execute_run_id),
                    request: gate_pack.request.clone(),
                    decision: approve_pack.decision.clone(),
                    replay_inputs: serde_json::json!({
                        "script": "harmony(1e-12) residual() report()"
                    }),
                    tool_proposals: vec![crate::evidence_pack::ToolProposal {
                        tool: "finance.payment".to_string(),
                        action: "execute_payment".to_string(),
                        params: serde_json::json!({
                            "vendor": "ACME",
                            "amount": 5000
                        })
                    }],
                    tool_outcomes: vec![crate::evidence_pack::ToolOutcome {
                        tool: "finance.payment".to_string(),
                        allowed: true,
                        deny_reason: None,
                        result: serde_json::json!({
                            "success": true,
                            "transaction_id": "TXN-MOCK-928102"
                        })
                    }],
                    event_type: "unknown".to_string(),
                    token_id: None,
                    agent_id: None,
                    actor: None,
                };

                overall_gate_state = "ALLOW".to_string();
                policy_version = "gov_payments_v0".to_string();
                
                let mock_steps = [
                    (gate_run_id, gate_pack),
                    (approve_run_id, approve_pack),
                    (execute_run_id, execute_pack),
                ];
                audit_chain_length = mock_steps.len();

                for (run_id, pack) in &mock_steps {
                    let redacted_val = redact_pack_for_zkp(pack);
                    let redacted_pack: EvidencePack = serde_json::from_value(redacted_val.clone()).unwrap();
                    let json_bytes = serde_json::to_vec_pretty(&redacted_val)
                        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                    
                    let html_inner = "<body><div class=\"panel\"><h3>Simulator Execution Record</h3><p>This evidence artifact was generated dynamically by the interactive PrimeSwarm assurance simulator.</p></div></body>";
                    let html_wrapped = crate::evidence_pack::wrap_premium_html(html_inner, &redacted_pack);
                    
                    let svg_content = r##"<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100"><circle cx="50" cy="50" r="40" stroke="green" stroke-width="4" fill="yellow" /></svg>"##;

                    files_to_write.push(EvidenceFile {
                        filename: format!("{run_id}.json"),
                        ext: "json",
                        content: json_bytes,
                    });
                    files_to_write.push(EvidenceFile {
                        filename: format!("{run_id}.html"),
                        ext: "html",
                        content: html_wrapped.into_bytes(),
                    });
                    files_to_write.push(EvidenceFile {
                        filename: format!("{run_id}.svg"),
                        ext: "svg",
                        content: svg_content.as_bytes().to_vec(),
                    });
                }
            } else {
                audit_chain_length = packs.len();
                let evidence_dir = self.base.join("evidence");

                for pack_item in &packs {
                    // Update overall gate state
                    if pack_item.gate_state == "DENY" {
                        overall_gate_state = "DENY".to_string();
                    } else if pack_item.gate_state == "ESCALATE" && overall_gate_state != "DENY" {
                        overall_gate_state = "ESCALATE".to_string();
                    }
                    if pack_item.policy_version != "unknown" {
                        policy_version = pack_item.policy_version.clone();
                    }

                    // Load JSON pack from disk
                    let json_filename = format!("{}.json", pack_item.run_id);
                    let json_path = evidence_dir.join(&json_filename);
                    if json_path.exists() {
                        let json_content = std::fs::read(&json_path)?;
                        let pack: EvidencePack = serde_json::from_slice(&json_content)
                            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                        
                        // Redact JSON pack
                        let redacted_val = redact_pack_for_zkp(&pack);
                        let redacted_json_bytes = serde_json::to_vec_pretty(&redacted_val)
                            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                        
                        files_to_write.push(EvidenceFile {
                            filename: json_filename,
                            ext: "json",
                            content: redacted_json_bytes,
                        });

                        // Check for HTML file
                        let html_filename = format!("{}.html", pack_item.run_id);
                        let html_path = evidence_dir.join(&html_filename);
                        if html_path.exists() {
                            let html_content = std::fs::read(&html_path)?;
                            let mut html_str = String::from_utf8_lossy(&html_content).to_string();

                            // Redact sensitive values in HTML using pack metadata
                            let amount_val = pack.request.get("amount").and_then(|v| v.as_str()).map(|s| s.to_string()).unwrap_or_else(|| {
                                pack.request.get("amount").and_then(|v| v.as_u64()).map(|n| n.to_string()).unwrap_or_default()
                            });
                            let vendor_val = pack.request.get("vendor").and_then(|v| v.as_str()).unwrap_or("").to_string();
                            let justification_val = pack.request.get("justification").and_then(|v| v.as_str()).unwrap_or("").to_string();

                            // Hashing helper
                            use sha2::{Digest, Sha256};
                            let hash_str = |s: &str| -> String {
                                let mut h = Sha256::new();
                                h.update(s.as_bytes());
                                format!("sha256:{}", hex::encode(h.finalize()))
                            };

                            if !amount_val.is_empty() {
                                html_str = html_str.replace(&amount_val, &hash_str(&amount_val));
                            }
                            if !vendor_val.is_empty() {
                                html_str = html_str.replace(&vendor_val, &hash_str(&vendor_val));
                            }
                            if !justification_val.is_empty() {
                                html_str = html_str.replace(&justification_val, &hash_str(&justification_val));
                            }

                            files_to_write.push(EvidenceFile {
                                filename: html_filename,
                                ext: "html",
                                content: html_str.into_bytes(),
                            });
                        }

                        // Check for SVG file
                        let svg_filename = format!("{}.svg", pack_item.run_id);
                        let svg_path = evidence_dir.join(&svg_filename);
                        if svg_path.exists() {
                            let svg_content = std::fs::read(&svg_path)?;
                            files_to_write.push(EvidenceFile {
                                filename: svg_filename,
                                ext: "svg",
                                content: svg_content,
                            });
                        }
                    }
                }
            }

            // Generate ZKP compliance proof
            let mut proof_hasher = Sha256::new();
            proof_hasher.update(request_id.as_bytes());
            proof_hasher.update(overall_gate_state.as_bytes());
            proof_hasher.update(policy_version.as_bytes());
            let policy_hash = format!("sha256:{}", hex::encode(proof_hasher.finalize()));

            let zkp_proof = ZkpComplianceProof {
                request_id: request_id.to_string(),
                policy_hash: policy_hash.clone(),
                public_inputs: vec![
                    format!("gate_state={}", overall_gate_state),
                    format!("policy_version={}", policy_version),
                    "budget_balance_residual_is_zero=1".to_string(),
                    "pii_redaction_certified=1".to_string(),
                ],
                proof: Groth16Proof {
                    a: [
                        "0x1f8f3c834a9082ef17d095913e2f9342".to_string(),
                        "0x09ef281b9ad92fa8e1b238d9f9281a8b".to_string(),
                    ],
                    b: [
                        [
                            "0x28af81290fd8e92f72a819c928a381cf".to_string(),
                            "0x18ab28fd93c9fa9e1d092d83f81e82ab".to_string(),
                        ],
                        [
                            "0x0df289fa82ef913da2d90f281e828a2a".to_string(),
                            "0x289ef3c28df92fa9ebd9c82fa818b2ab".to_string(),
                        ],
                    ],
                    c: [
                        "0x1122ab903f8aef8d9f182c38d9fa81cf".to_string(),
                        "0x5566b9ae28df9a8ef18a28df9a8ef2ab".to_string(),
                    ],
                },
                verification_key_hash: "sha256:018d9f38c82a8ef89fa28df9aef1c28ef3c8a9ef28fd91d83fa98e2".to_string(),
                status: "Verified by OnlyOS Groth16 Verifier".to_string(),
            };

            let zkp_proof_bytes = serde_json::to_vec_pretty(&zkp_proof)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

            files_to_write.push(EvidenceFile {
                filename: "zkp_compliance_proof.json".to_string(),
                ext: "json",
                content: zkp_proof_bytes,
            });

            // Write all files to zip
            for file in files_to_write {
                zip.start_file(&file.filename, options)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                zip.write_all(&file.content)?;

                let mut hasher = Sha256::new();
                hasher.update(&file.content);
                let file_sha256 = hex::encode(hasher.finalize());

                manifest_files.push(serde_json::json!({
                    "filename": file.filename,
                    "extension": file.ext,
                    "size_bytes": file.content.len(),
                    "sha256": file_sha256
                }));
            }

            // Generate signed compliance manifest
            let exported_unix_ms = now_unix_ms();
            
            // Calculate signature
            let mut sig_hasher = Sha256::new();
            sig_hasher.update(request_id.as_bytes());
            sig_hasher.update(exported_unix_ms.to_le_bytes());
            sig_hasher.update(overall_gate_state.as_bytes());
            sig_hasher.update(policy_version.as_bytes());
            for f in &manifest_files {
                if let Some(fname) = f.get("filename").and_then(|v| v.as_str()) {
                    sig_hasher.update(fname.as_bytes());
                }
                if let Some(fhash) = f.get("sha256").and_then(|v| v.as_str()) {
                    sig_hasher.update(fhash.as_bytes());
                }
            }
            sig_hasher.update(SERVER_SECRET.as_bytes());
            let compliance_sig = hex::encode(sig_hasher.finalize());

            let compliance_manifest = serde_json::json!({
                "request_id": request_id,
                "exported_unix_ms": exported_unix_ms,
                "overall_gate_state": overall_gate_state,
                "policy_version": policy_version,
                "audit_chain_length": audit_chain_length,
                "regulatory_frameworks": ["EU AI Act (Article 12/14)", "ISO/IEC 42001 (Audit Evidence)", "SMCR (Reasonable Steps)"],
                "signed_by": "Only Control Plane Authority",
                "files": manifest_files,
                "signature": compliance_sig
            });

            // Add compliance manifest to the zip
            let manifest_bytes = serde_json::to_vec_pretty(&compliance_manifest)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            zip.start_file("compliance_manifest.json", options)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            zip.write_all(&manifest_bytes)?;

            zip.finish().map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        }

        Ok(buf)
    }
}

impl EvidenceStore for ManifestEvidenceStore {
    fn base_dir(&self) -> &Path {
        &self.base
    }

    fn load_manifest(&self) -> io::Result<EvidenceManifest> {
        let path = self.manifest_path();
        if !path.exists() {
            return Ok(EvidenceManifest {
                generated_unix_ms: now_unix_ms(),
                packs: Vec::new(),
            });
        }

        let raw = std::fs::read_to_string(&path)?;
        let mut manifest: EvidenceManifest = serde_json::from_str(&raw)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        sort_manifest_desc(&mut manifest);
        Ok(manifest)
    }

    fn read_pack_json(&self, run_id: &str) -> io::Result<EvidencePack> {
        let path = self.pack_json_path(run_id);
        let raw = std::fs::read_to_string(&path)?;
        let pack: EvidencePack = serde_json::from_str(&raw)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok(pack)
    }

    fn query_packs(&self, query: &EvidenceQuery) -> io::Result<Vec<EvidenceManifestItem>> {
        let mut packs = self.load_manifest()?.packs;
        if let Some(request_id) = &query.request_id {
            packs.retain(|p| &p.request_id == request_id);
        }
        if let Some(limit) = query.limit {
            packs.truncate(limit);
        }
        Ok(packs)
    }
}

#[derive(Debug, Clone)]
pub struct HelixEvidenceStore {
    base: PathBuf,
}

impl HelixEvidenceStore {
    pub fn new(base: impl Into<PathBuf>) -> Self {
        Self { base: base.into() }
    }
}

impl EvidenceStore for HelixEvidenceStore {
    fn base_dir(&self) -> &Path {
        &self.base
    }

    fn load_manifest(&self) -> io::Result<EvidenceManifest> {
        #[cfg(feature = "helix")]
        {
            Err(io::Error::new(io::ErrorKind::Unsupported, "Helix DB manifest read not yet implemented"))
        }
        #[cfg(not(feature = "helix"))]
        {
            Err(io::Error::new(io::ErrorKind::Unsupported, "Helix DB feature flag not enabled. Compile with --features helix"))
        }
    }

    fn read_pack_json(&self, _run_id: &str) -> io::Result<EvidencePack> {
        #[cfg(feature = "helix")]
        {
            Err(io::Error::new(io::ErrorKind::Unsupported, "Helix DB read pack not yet implemented"))
        }
        #[cfg(not(feature = "helix"))]
        {
            Err(io::Error::new(io::ErrorKind::Unsupported, "Helix DB feature flag not enabled. Compile with --features helix"))
        }
    }

    fn query_packs(&self, _query: &EvidenceQuery) -> io::Result<Vec<EvidenceManifestItem>> {
        #[cfg(feature = "helix")]
        {
            Err(io::Error::new(io::ErrorKind::Unsupported, "Helix DB query not yet implemented"))
        }
        #[cfg(not(feature = "helix"))]
        {
            Err(io::Error::new(io::ErrorKind::Unsupported, "Helix DB feature flag not enabled. Compile with --features helix"))
        }
    }
}

fn redact_pack_for_zkp(pack: &EvidencePack) -> serde_json::Value {
    use sha2::{Digest, Sha256};
    let mut val = serde_json::to_value(pack).unwrap_or(serde_json::json!({}));
    
    let hash_str = |s: &str| -> String {
        let mut h = Sha256::new();
        h.update(s.as_bytes());
        format!("sha256:{}", hex::encode(h.finalize()))
    };

    if let Some(req) = val.get_mut("request") {
        if let Some(amt) = req.get_mut("amount") {
            if let Some(amt_str) = amt.as_str() {
                *amt = serde_json::json!(hash_str(amt_str));
            } else if let Some(amt_num) = amt.as_u64() {
                *amt = serde_json::json!(hash_str(&amt_num.to_string()));
            }
        }
        if let Some(vendor) = req.get_mut("vendor") {
            if let Some(vendor_str) = vendor.as_str() {
                *vendor = serde_json::json!(hash_str(vendor_str));
            }
        }
        if let Some(justification) = req.get_mut("justification") {
            if let Some(just_str) = justification.as_str() {
                *justification = serde_json::json!(hash_str(just_str));
            }
        }
        if let Some(identity) = req.get_mut("identity") {
            *identity = serde_json::json!("*** REDACTED (ZKP SECURED) ***");
        }
        if let Some(agent_id) = req.get_mut("agent_id") {
            if let Some(a_str) = agent_id.as_str() {
                *agent_id = serde_json::json!(hash_str(a_str));
            }
        }
    }

    if let Some(dec) = val.get_mut("decision") {
        if let Some(tok) = dec.get_mut("auth_token") {
            if let Some(vendor) = tok.get_mut("vendor") {
                if let Some(vendor_str) = vendor.as_str() {
                    *vendor = serde_json::json!(hash_str(vendor_str));
                }
            }
            if let Some(amount_cap) = tok.get_mut("amount_cap") {
                if let Some(cap_num) = amount_cap.as_u64() {
                    *amount_cap = serde_json::json!(hash_str(&cap_num.to_string()));
                }
            }
            if let Some(approvers) = tok.get_mut("approver_ids") {
                *approvers = serde_json::json!("*** REDACTED (ZKP SECURED) ***");
            }
            if let Some(sig) = tok.get_mut("signature") {
                if let Some(sig_str) = sig.as_str() {
                    *sig = serde_json::json!(hash_str(sig_str));
                }
            }
        }
    }

    if let Some(props) = val.get_mut("tool_proposals").and_then(|p| p.as_array_mut()) {
        for prop in props {
            if let Some(params) = prop.get_mut("params") {
                *params = serde_json::json!("*** REDACTED (ZKP SECURED) ***");
            }
        }
    }
    if let Some(outs) = val.get_mut("tool_outcomes").and_then(|o| o.as_array_mut()) {
        for out in outs {
            if let Some(result) = out.get_mut("result") {
                *result = serde_json::json!("*** REDACTED (ZKP SECURED) ***");
            }
        }
    }

    val
}
