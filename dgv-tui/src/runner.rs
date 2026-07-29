use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::parser::{EvidenceCaseResult, EvidencePackage, TestCard, TestCase};

fn evaluate_expected(run_res: &Value, expected: &Value) -> bool {
    if let Some(obj) = expected.as_object() {
        for (key, val) in obj {
            if run_res.get(key) != Some(val) {
                return false;
            }
        }
    }
    true
}

pub struct TestRunner {
    binary_path: PathBuf,
    gate_binary_path: Option<PathBuf>,
    evidence_dir: PathBuf,
}

impl TestRunner {
    pub fn new(project_root: &Path) -> Result<Self, String> {
        let binary_name = if cfg!(windows) {
            "dgv-verifier.exe"
        } else {
            "dgv-verifier"
        };
        let binary_path = project_root.join("target").join("debug").join(binary_name);

        let evidence_dir = project_root
            .join("only-engine")
            .join("dgv")
            .join("evidence");
        if !evidence_dir.exists() {
            let _ = fs::create_dir_all(&evidence_dir);
        }

        if !binary_path.exists() {
            // Attempt to build
            println!(
                "Binary not found at {}. Building with cargo...",
                binary_path.display()
            );
            let build_status = Command::new("cargo")
                .args(["build", "-p", "dgv-verifier"])
                .current_dir(project_root)
                .env("CARGO_INCREMENTAL", "0")
                .status();

            match build_status {
                Ok(status) if status.success() => {
                    if !binary_path.exists() {
                        return Err(format!(
                            "Cargo build succeeded but binary still missing at {}",
                            binary_path.display()
                        ));
                    }
                }
                _ => return Err("Failed to compile dgv-verifier binary via cargo".to_string()),
            }
        }

        // Locate the only-gate real verification engine (optional — dgv-verifier tests still work without it)
        let gate_binary_name = if cfg!(windows) {
            "only-gate.exe"
        } else {
            "only-gate"
        };
        let gate_path = project_root
            .join("target")
            .join("debug")
            .join(gate_binary_name);
        let gate_binary_path = if gate_path.exists() {
            Some(gate_path)
        } else {
            None
        };

        Ok(Self {
            binary_path,
            gate_binary_path,
            evidence_dir,
        })
    }

    fn run_test_case(
        &self,
        script: &str,
        payload: &str,
        extra_args: &[&str],
    ) -> Result<Value, String> {
        // Create temp file
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temp_file_name = format!("dgv_temp_script_{}.txt", timestamp);
        let temp_path = std::env::temp_dir().join(temp_file_name);

        fs::write(&temp_path, script).map_err(|e| format!("Failed to write temp script: {}", e))?;

        let mut cmd = Command::new(&self.binary_path);
        cmd.arg(format!("--script={}", temp_path.display()))
            .arg(format!("--payload={}", payload))
            .arg("--emit=json")
            .arg("--log-level=2");

        for &arg in extra_args {
            cmd.arg(arg);
        }

        let output = cmd.output().map_err(|e| {
            let _ = fs::remove_file(&temp_path);
            format!("Failed to execute dgv-verifier: {}", e)
        })?;

        let _ = fs::remove_file(&temp_path);

        if !output.status.success() {
            // Some checks expect failure, so let's parse stdout anyway if present
            let stdout_str = String::from_utf8_lossy(&output.stdout);
            if let Some(parsed) = self.parse_json_from_stdout(&stdout_str) {
                return Ok(parsed);
            }
            return Err(format!(
                "dgv-verifier failed with exit code: {:?}",
                output.status.code()
            ));
        }

        let stdout_str = String::from_utf8_lossy(&output.stdout);
        self.parse_json_from_stdout(&stdout_str).ok_or_else(|| {
            format!(
                "Could not find JSON output in dgv-verifier stdout:\n{}",
                stdout_str
            )
        })
    }

    /// Run only-gate with the case input fields as --key=value CLI arguments.
    fn run_gate_check(&self, input: &Value) -> Result<Value, String> {
        let gate_path = self.gate_binary_path.as_ref().ok_or_else(|| {
            "only-gate binary not found — build with: cargo build -p only-gate".to_string()
        })?;

        let mut cmd = Command::new(gate_path);
        cmd.arg("--emit=json");

        if let Some(obj) = input.as_object() {
            for (key, val) in obj {
                // Convert JSON key underscores to hyphens for the CLI flag name
                let arg_key = key.replace('_', "-");
                let arg_val = match val {
                    Value::String(s) => s.clone(),
                    Value::Bool(b) => b.to_string(),
                    Value::Number(n) => n.to_string(),
                    _ => continue, // skip arrays/objects
                };
                cmd.arg(format!("--{}={}", arg_key, arg_val));
            }
        }

        let output = cmd
            .output()
            .map_err(|e| format!("Failed to run only-gate: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        self.parse_json_from_stdout(&stdout)
            .ok_or_else(|| format!("No JSON from only-gate stdout: {}", stdout))
    }

    fn parse_json_from_stdout(&self, stdout: &str) -> Option<Value> {
        for line in stdout.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('{') && trimmed.ends_with('}') {
                let sanitized = trimmed.replace("NaN", "null").replace("Infinity", "null");
                if let Ok(parsed) = serde_json::from_str(&sanitized) {
                    return Some(parsed);
                }
            }
        }
        None
    }

    pub async fn run_card(&self, card: &TestCard) -> Result<EvidencePackage, String> {
        let mut evidence_cases = Vec::new();
        let mut card_passed = true;

        for case in &card.test_cases {
            // ── only-gate routing ──────────────────────────────────────────────
            // Cards with executor="only-gate" are handled by the real gate engine.
            // Input fields become --key=value CLI args; expected fields are checked
            // generically. Early-continue skips the dgv-verifier match block below.
            if card.executor.as_deref() == Some("only-gate") {
                let res = self.run_gate_check(&case.input)?;
                let passed = evaluate_expected(&res, &case.expected);
                let is_mandatory = case.mandatory;
                evidence_cases.push(EvidenceCaseResult {
                    case_id: case.id.clone(),
                    passed,
                    runs_count: None,
                    runs_identical: None,
                    output_sample: Some(res),
                });
                if !passed && is_mandatory {
                    card_passed = false;
                }
                continue;
            }

            let script = case
                .input
                .get("script")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let payload_string = match case.input.get("payload") {
                Some(serde_json::Value::String(s)) => s.clone(),
                Some(serde_json::Value::Number(n)) => n.to_string(),
                Some(serde_json::Value::Bool(b)) => b.to_string(),
                Some(other) => other.to_string(),
                None => "".to_string(),
            };
            let payload = &payload_string;

            let card_id = card.id.as_str();

            // Match dgv_runner.py execution paradigms
            let (passed, output_sample) = match card_id {
                "DGV-TC-001" | "DGV-TC-008" => {
                    let mut runs = Vec::new();
                    for _ in 0..5 {
                        let res = self.run_test_case(script, payload, &[])?;
                        runs.push(res);
                        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
                    }

                    let first_run = &runs[0];
                    let mut runs_identical = true;
                    for r in &runs[1..] {
                        if r.get("pass") != first_run.get("pass")
                            || r.get("residual_final") != first_run.get("residual_final")
                            || r.get("indices_healed") != first_run.get("indices_healed")
                        {
                            runs_identical = false;
                            break;
                        }
                    }

                    let mut case_passed = runs_identical
                        && first_run
                            .get("pass")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);

                    if case_passed {
                        if let Some(thresholds) = card.pass_threshold.as_object() {
                            if let Some(max_res_val) =
                                thresholds.get("max_residual").and_then(|v| v.as_f64())
                            {
                                if let Some(res_final_str) =
                                    first_run.get("residual_final").and_then(|v| v.as_str())
                                {
                                    if let Ok(res_final_val) = res_final_str.parse::<f64>() {
                                        if res_final_val > max_res_val {
                                            case_passed = false;
                                        }
                                    }
                                }
                            }
                        }
                    }

                    (case_passed, first_run.clone())
                }
                "DGV-TC-002" | "DGV-TC-004" | "DGV-TC-005" => {
                    let res = self.run_test_case(script, payload, &[])?;
                    let passed = !res.get("pass").and_then(|v| v.as_bool()).unwrap_or(true);
                    (passed, res)
                }
                "DGV-TC-003" => {
                    let res = self.run_test_case(script, payload, &[])?;
                    let mut passed = res.get("pass").and_then(|v| v.as_bool()).unwrap_or(false);
                    if passed {
                        if let Some(thresholds) = card.pass_threshold.as_object() {
                            if let Some(max_res_val) =
                                thresholds.get("max_residual").and_then(|v| v.as_f64())
                            {
                                if let Some(res_final_str) =
                                    res.get("residual_final").and_then(|v| v.as_str())
                                {
                                    if let Ok(res_final_val) = res_final_str.parse::<f64>() {
                                        if res_final_val > max_res_val {
                                            passed = false;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    (passed, res)
                }
                "DGV-TC-006" => {
                    let res = self.run_test_case(script, payload, &[])?;
                    let passed = res.get("pass").and_then(|v| v.as_bool()).unwrap_or(false)
                        && res
                            .get("indices_healed")
                            .and_then(|v| v.as_array())
                            .map_or(false, |a| !a.is_empty());
                    (passed, res)
                }
                "DGV-TC-007" => {
                    let res = self.run_test_case(script, payload, &[])?;
                    let passed = res.get("revealed").is_some();
                    (passed, res)
                }
                "DGV-TC-009" => {
                    let res = self.run_test_case(script, payload, &["--simulate-replay-token"])?;
                    let passed = !res.get("pass").and_then(|v| v.as_bool()).unwrap_or(true)
                        && res.get("rejection_reason").and_then(|v| v.as_str())
                            == Some("token_replay_attack_detected");
                    (passed, res)
                }
                "DGV-TC-010" => {
                    let res =
                        self.run_test_case(script, payload, &["--simulate-latency-ms=100"])?;
                    let passed = !res.get("pass").and_then(|v| v.as_bool()).unwrap_or(true)
                        && res.get("rejection_reason").and_then(|v| v.as_str())
                            == Some("fail_closed_latency_timeout_exceeded");
                    (passed, res)
                }
                "DGV-TC-011" => {
                    let res = self.run_test_case(script, payload, &["--simulate-explain"])?;
                    let passed = res.get("pass").and_then(|v| v.as_bool()).unwrap_or(false)
                        && res.get("explanation_trace").is_some();
                    (passed, res)
                }
                "DGV-TC-012" => {
                    let res =
                        self.run_test_case(script, payload, &["--simulate-prompt-injection"])?;
                    let passed = !res.get("pass").and_then(|v| v.as_bool()).unwrap_or(true)
                        && res.get("rejection_reason").and_then(|v| v.as_str())
                            == Some("adversarial_prompt_injection_detected");
                    (passed, res)
                }
                "DGV-TC-013" => {
                    let res = self.run_test_case(script, payload, &["--simulate-bias-check"])?;
                    let ratio = res
                        .get("disparate_impact_ratio")
                        .and_then(|v| v.as_f64())
                        .unwrap_or(0.0);
                    let passed = res.get("pass").and_then(|v| v.as_bool()).unwrap_or(false)
                        && (0.80 <= ratio && ratio <= 1.25);
                    (passed, res)
                }
                "DGV-TC-014" => {
                    let res = self.run_test_case(script, payload, &["--simulate-provenance"])?;
                    let passed = res.get("pass").and_then(|v| v.as_bool()).unwrap_or(false)
                        && res
                            .get("provenance_verified")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                    (passed, res)
                }
                "DGV-TC-015" => {
                    let res =
                        self.run_test_case(script, payload, &["--simulate-heartbeat-failure"])?;
                    let passed = !res.get("pass").and_then(|v| v.as_bool()).unwrap_or(true)
                        && res.get("rejection_reason").and_then(|v| v.as_str())
                            == Some("governance_heartbeat_timeout_failure");
                    (passed, res)
                }
                "DGV-TC-016" => {
                    let res =
                        self.run_test_case(script, payload, &["--simulate-codon-delegation"])?;
                    let passed = !res.get("pass").and_then(|v| v.as_bool()).unwrap_or(true)
                        && res.get("rejection_reason").and_then(|v| v.as_str())
                            == Some("invalid_codon_delegation_lineage");
                    (passed, res)
                }
                "DGV-TC-017" => {
                    let res =
                        self.run_test_case(script, payload, &["--simulate-rlwe-signature"])?;
                    let passed = !res.get("pass").and_then(|v| v.as_bool()).unwrap_or(true)
                        && res.get("rejection_reason").and_then(|v| v.as_str())
                            == Some("invalid_rlwe_enclave_signature");
                    (passed, res)
                }
                "DGV-TC-018" => {
                    let res =
                        self.run_test_case(script, payload, &["--simulate-spectral-drift"])?;
                    let passed = !res.get("pass").and_then(|v| v.as_bool()).unwrap_or(true)
                        && res.get("rejection_reason").and_then(|v| v.as_str())
                            == Some("phi_lattice_drift_limit_exceeded");
                    (passed, res)
                }
                "DGV-TC-019" => {
                    let res =
                        self.run_test_case(script, payload, &["--simulate-non-expansive-repair"])?;
                    let passed = res.get("pass").and_then(|v| v.as_bool()).unwrap_or(false)
                        && res
                            .get("is_contraction")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                    (passed, res)
                }
                "DGV-TC-020" => {
                    let res =
                        self.run_test_case(script, payload, &["--simulate-transitive-revocation"])?;
                    let passed = !res.get("pass").and_then(|v| v.as_bool()).unwrap_or(true)
                        && res.get("rejection_reason").and_then(|v| v.as_str())
                            == Some("parent_authority_revoked");
                    (passed, res)
                }
                "DGV-TC-021" => {
                    let res =
                        self.run_test_case(script, payload, &["--simulate-multisig-escape"])?;
                    let passed = !res.get("pass").and_then(|v| v.as_bool()).unwrap_or(true)
                        && res.get("rejection_reason").and_then(|v| v.as_str())
                            == Some("insufficient_consensus_signatures");
                    (passed, res)
                }
                "DGV-TC-022" => {
                    let res = self.run_test_case(script, payload, &["--simulate-double-spend"])?;
                    let passed = !res.get("pass").and_then(|v| v.as_bool()).unwrap_or(true)
                        && res.get("rejection_reason").and_then(|v| v.as_str())
                            == Some("token_double_spend_detected");
                    (passed, res)
                }
                "DGV-TC-023" => {
                    let res =
                        self.run_test_case(script, payload, &["--simulate-coherence-escalation"])?;
                    let passed = res.get("pass").and_then(|v| v.as_bool()).unwrap_or(false)
                        && res.get("gate_status").and_then(|v| v.as_str()) == Some("ESCALATE");
                    (passed, res)
                }
                "DGV-TC-024" => {
                    let res = self.run_test_case(script, payload, &["--simulate-legal-hold"])?;
                    let passed = !res.get("pass").and_then(|v| v.as_bool()).unwrap_or(true)
                        && res.get("rejection_reason").and_then(|v| v.as_str())
                            == Some("data_disposition_blocked_by_active_legal_hold");
                    (passed, res)
                }
                "DGV-TC-025" => {
                    let res = self.run_test_case(script, payload, &["--simulate-dpia-gate"])?;
                    let passed = !res.get("pass").and_then(|v| v.as_bool()).unwrap_or(true)
                        && res.get("rejection_reason").and_then(|v| v.as_str())
                            == Some("high_risk_processing_lacks_completed_dpia");
                    (passed, res)
                }
                "DGV-TC-026" => {
                    let res =
                        self.run_test_case(script, payload, &["--simulate-security-linkage"])?;
                    let passed = res.get("pass").and_then(|v| v.as_bool()).unwrap_or(false)
                        && res.get("encryption_enforced").and_then(|v| v.as_str())
                            == Some("AES-256");
                    (passed, res)
                }
                "DGV-TC-027" => {
                    let res =
                        self.run_test_case(script, payload, &["--simulate-weight-mismatch"])?;
                    let passed = !res.get("pass").and_then(|v| v.as_bool()).unwrap_or(true)
                        && res.get("rejection_reason").and_then(|v| v.as_str())
                            == Some("model_weight_hash_mismatch");
                    (passed, res)
                }
                "DGV-TC-028" => {
                    let res =
                        self.run_test_case(script, payload, &["--simulate-unregistered-ai-id"])?;
                    let passed = !res.get("pass").and_then(|v| v.as_bool()).unwrap_or(true)
                        && res.get("rejection_reason").and_then(|v| v.as_str())
                            == Some("ai_id_not_found_in_registry");
                    (passed, res)
                }
                "DGV-TC-029" => {
                    let res =
                        self.run_test_case(script, payload, &["--simulate-drift-exceeded"])?;
                    let passed = !res.get("pass").and_then(|v| v.as_bool()).unwrap_or(true)
                        && res.get("rejection_reason").and_then(|v| v.as_str())
                            == Some("structural_drift_exceeds_threshold");
                    (passed, res)
                }
                "DGV-TC-031" | "DGV-TC-032" | "DGV-TC-033" | "DGV-TC-034" | "DGV-TC-035" => {
                    // Per-case extra_args are embedded in the test-card JSON; evaluate all
                    // expected fields generically so the runner stays in sync with the card schema.
                    let extra_args: Vec<String> = case
                        .input
                        .get("extra_args")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                .collect()
                        })
                        .unwrap_or_default();
                    let extra_refs: Vec<&str> = extra_args.iter().map(|s| s.as_str()).collect();
                    let res = self.run_test_case(script, payload, &extra_refs)?;
                    let passed = evaluate_expected(&res, &case.expected);
                    (passed, res)
                }
                _ => {
                    // Fallback default validation
                    let res = self.run_test_case(script, payload, &[])?;
                    let passed = res.get("pass").and_then(|v| v.as_bool()).unwrap_or(false);
                    (passed, res)
                }
            };

            evidence_cases.push(EvidenceCaseResult {
                case_id: case.id.clone(),
                passed,
                runs_count: if card_id == "DGV-TC-001" || card_id == "DGV-TC-008" {
                    Some(5)
                } else {
                    None
                },
                runs_identical: if card_id == "DGV-TC-001" || card_id == "DGV-TC-008" {
                    Some(passed)
                } else {
                    None
                },
                output_sample: Some(output_sample),
            });

            if !passed {
                card_passed = false;
            }
        }

        // Generate and save evidence package
        let formatted_time = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let evidence_pack = EvidencePackage {
            test_card_id: card.id.clone(),
            claim_name: card.claim_name.clone(),
            svrnos_layer: card.svrnos_layer.clone(),
            ger_mapping: card.ger_mapping.clone(),
            verified_timestamp: formatted_time,
            status: if card_passed {
                "passed".to_string()
            } else {
                "failed".to_string()
            },
            results: evidence_cases,
        };

        let filename = format!("{}_evidence.json", card.id.to_lowercase().replace("-", "_"));
        let filepath = self.evidence_dir.join(filename);
        let evidence_json = serde_json::to_string_pretty(&evidence_pack)
            .map_err(|e| format!("Failed to serialize evidence: {}", e))?;
        fs::write(&filepath, evidence_json)
            .map_err(|e| format!("Failed to save evidence to {}: {}", filepath.display(), e))?;

        if card_passed {
            Ok(evidence_pack)
        } else {
            Err(format!("Card {} failed verification.", card.id))
        }
    }
}
