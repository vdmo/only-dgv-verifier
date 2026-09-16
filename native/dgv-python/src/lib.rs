//! DGV Python bindings — in-process evaluation without HTTP server.
//!
//! Exposes the core gate functionality as a Python module. Use this when
//! you want to embed the gate directly in your Python application rather
//! than running it as a separate HTTP service.
//!
//! Build:
//!   cd native/dgv-python && cargo build --release
//!   # Or use maturin for a proper Python package
//!
//! Usage:
//!   import dgv_python
//!
//!   gate = dgv_python.Gate("sqlite://./gate.db")
//!   decision = gate.govern({
//!       "agent_id": "my-agent",
//!       "workflow": "loan_approval",
//!       "tool": "send_email",
//!       "action": "send",
//!       "params": {"to": "client@example.com"},
//!       "justification": "user requested",
//!       "risk_level": "1000",
//!   })
//!   print(decision["gate_state"])  # "ALLOW" or "DENY"
//!
//!   if decision["allowed"]:
//!       result = gate.execute(decision["token_id"], "my-agent", "send_email", "send", {"to": "client@example.com"})
//!       print(result["allowed"])

use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::sync::Arc;
use tokio::runtime::Runtime;

use dgv_storage::{DecisionRecord, PolicyRecord, PostgresStorage, RevocationRecord, SqliteStorage, Storage, TokenRecord};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use only_core::{generate_signs, Sign};
use only_memory::GhostMemory;
use sha2::{Digest, Sha256};

fn now_unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

fn sha256_hex(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    hex::encode(h.finalize())
}

fn compute_decision_hash(request_id: &str, gate_state: &str, reason_codes: &[String], tool: &str, action: &str, params: &serde_json::Value) -> String {
    let mut h = Sha256::new();
    h.update(request_id.as_bytes());
    h.update(gate_state.as_bytes());
    h.update(reason_codes.join(",").as_bytes());
    h.update(tool.as_bytes());
    h.update(action.as_bytes());
    h.update(params.to_string().as_bytes());
    hex::encode(h.finalize())
}

fn compute_params_hash(params: &serde_json::Value) -> String {
    sha256_hex(&params.to_string())
}

/// In-process DGV gate — no HTTP server needed.
#[pyclass]
struct Gate {
    storage: Arc<dyn Storage>,
    rt: Runtime,
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

#[pymethods]
impl Gate {
    /// Create a new gate with the given storage backend.
    ///
    /// storage_backend: "sqlite" or "postgres"
    /// database_url: "sqlite://./gate.db" or "postgres://user:pass@host/db"
    #[new]
    fn new(storage_backend: &str, database_url: &str) -> PyResult<Self> {
        let rt = Runtime::new().map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;

        let storage: Arc<dyn Storage> = rt.block_on(async {
            match storage_backend {
                "postgres" => PostgresStorage::new(database_url).await.map(|s| Arc::new(s) as Arc<dyn Storage>),
                _ => SqliteStorage::new(database_url).await.map(|s| Arc::new(s) as Arc<dyn Storage>),
            }
        }).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("storage init failed: {}", e)))?;

        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let verifying_key = signing_key.verifying_key();

        Ok(Self {
            storage,
            rt,
            signing_key,
            verifying_key,
        })
    }

    /// Evaluate a proposal. Returns a dict with gate_state, decision_hash, signature, etc.
    fn govern(&self, proposal: &Bound<'_, PyDict>) -> PyResult<PyObject> {
        // Extract fields individually — HashMap<String, Value> doesn't implement FromPyObjectBound
        let get_str = |key: &str| -> String {
            proposal.get_item(key)
                .ok()
                .flatten()
                .and_then(|v| v.extract::<String>().ok())
                .unwrap_or_default()
        };

        let get_value = |key: &str| -> serde_json::Value {
            proposal.get_item(key)
                .ok()
                .flatten()
                .and_then(|v| {
                    // Serialize through Python's json.dumps to get proper JSON
                    let json_mod = v.py().import_bound("json").ok()?;
                    let json_str: String = json_mod.call_method1("dumps", (&v,)).ok()?.extract().ok()?;
                    serde_json::from_str(&json_str).ok()
                })
                .unwrap_or(serde_json::json!({}))
        };

        let request_id = get_str("request_id");
        let agent_id = get_str("agent_id");
        let workflow = get_str("workflow");
        let tool = get_str("tool");
        let action = get_str("action");
        let _justification = get_str("justification");
        let risk_level = get_str("risk_level").parse::<f64>().unwrap_or(1000.0);
        let params = get_value("params");
        let _identity = get_value("identity");

        let run_id = format!("run_{}", now_unix_ms());
        let now = now_unix_ms();

        // Check revocation
        let revocation = self.rt.block_on(self.storage.check_revocation(&agent_id))
            .ok().flatten();

        let (gate_state, reason_codes, pass) = if let Some(rev) = revocation {
            ("DENY".to_string(), vec![format!("authority_revoked: {}", rev.reason)], false)
        } else {
            // Load policy from storage
            let policy = self.rt.block_on(self.storage.get_active_policy(&tool, &action))
                .ok().flatten();

            let script = policy.map(|p| p.script).unwrap_or_else(|| {
                format!(
                    "harmony(1e-12)\nbind_authority(\"{}\", \"agent\", \"{}\")\nbind_objective(\"{}\", [\"{}\"])\nbind_context(\"{}\", \"{}\")\nevolve(2)\ndata({})\ncheck_authority(\"{}\")\ncheck_objective_drift(\"{}\")\ncheck_context_drift()\nbudget_limit({})\nresidual()",
                    agent_id, tool, action, action,
                    sha256_hex(&params.to_string()), sha256_hex(&tool),
                    risk_level,
                    agent_id, action, risk_level
                )
            });

            let n = 4;
            let signs: Vec<Sign> = generate_signs(n).collect();
            let mut field = GhostMemory::encode_4(&signs, risk_level);

            match only_lang::evaluate_script(&signs, &mut field, &script) {
                Ok(res) => {
                    if res.authority_revoked {
                        let reason = res.authority_revocation_reason.unwrap_or_else(|| "authority_revoked".to_string());
                        ("DENY".to_string(), vec![reason], false)
                    } else if res.pass {
                        ("ALLOW".to_string(), vec![], true)
                    } else {
                        ("DENY".to_string(), vec!["mathematical_drift_detected".to_string()], false)
                    }
                }
                Err(e) => {
                    let err_str = e.to_string().to_lowercase();
                    let is_governance = err_str.contains("authority") || err_str.contains("revocation")
                        || err_str.contains("lineage") || err_str.contains("objective")
                        || err_str.contains("context") || err_str.contains("drift")
                        || err_str.contains("bounds") || err_str.contains("bind");
                    if is_governance {
                        ("DENY".to_string(), vec![e.to_string()], false)
                    } else {
                        ("SILENCE".to_string(), vec![format!("system_error: {}", e)], false)
                    }
                }
            }
        };

        let decision_hash = compute_decision_hash(&request_id, &gate_state, &reason_codes, &tool, &action, &params);
        let signature = self.signing_key.sign(decision_hash.as_bytes());
        let signature_hex = hex::encode(signature.to_bytes());
        let verifying_key = hex::encode(self.verifying_key.to_bytes());

        let auth_token = if pass {
            let token_id = format!("tok_{}", &sha256_hex(&format!("{}{}", request_id, run_id))[..16]);
            let token_rec = TokenRecord {
                token_id: token_id.clone(),
                request_id: request_id.clone(),
                tool: tool.clone(),
                action: action.clone(),
                params_hash: compute_params_hash(&params),
                expires_unix_ms: now + 300_000,
                consumed: false,
                consumed_unix_ms: None,
                decision_hash: decision_hash.clone(),
                signature: signature_hex.clone(),
                created_unix_ms: now,
                min_approvals: 0,
                granted_to: agent_id.clone(),
                parent_token_id: None,
                delegation_depth: 0,
            };
            let _ = self.rt.block_on(self.storage.store_token(token_rec));
            Some(token_id)
        } else {
            None
        };

        // Store decision
        let dec_rec = DecisionRecord {
            run_id: run_id.clone(),
            request_id: request_id.clone(),
            decision_hash: decision_hash.clone(),
            gate_state: gate_state.clone(),
            reason_codes: serde_json::to_string(&reason_codes).unwrap_or_default(),
            replay_inputs: serde_json::json!({
                "tool": tool,
                "action": action,
                "params": params,
                "agent_id": agent_id,
                "workflow": workflow,
                "risk_level": risk_level,
            }).to_string(),
            signature: signature_hex.clone(),
            created_unix_ms: now,
        };
        let _ = self.rt.block_on(self.storage.store_decision(dec_rec));

        Python::with_gil(|py| {
            let result = PyDict::new_bound(py);
            result.set_item("gate_state", &gate_state).unwrap();
            result.set_item("reason_codes", &reason_codes).unwrap();
            result.set_item("decision_hash", &decision_hash).unwrap();
            result.set_item("signature", &signature_hex).unwrap();
            result.set_item("verifying_key", &verifying_key).unwrap();
            result.set_item("run_id", &run_id).unwrap();
            result.set_item("request_id", &request_id).unwrap();
            result.set_item("allowed", pass).unwrap();
            result.set_item("token_id", auth_token.as_deref()).unwrap();
            Ok(result.into())
        })
    }

    /// Execute with a token. Returns a dict with allowed, deny_reason, receipt.
    fn execute(&self, token_id: &str, executor_id: &str, tool: &str, action: &str, params: &Bound<'_, PyDict>) -> PyResult<PyObject> {
        let params_value = {
            // Serialize through Python's json.dumps to get proper JSON
            let json_mod = params.py().import_bound("json").map_err(|e| {
                pyo3::exceptions::PyValueError::new_err(format!("json import failed: {}", e))
            })?;
            let json_str: String = json_mod.call_method1("dumps", (params,))
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("json.dumps failed: {}", e)))?
                .extract()
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("extract failed: {}", e)))?;
            serde_json::from_str(&json_str).unwrap_or(serde_json::json!({}))
        };
        let now = now_unix_ms();
        let run_id = format!("exec_{}", now_unix_ms());

        // Look up token
        let token = match self.rt.block_on(self.storage.get_token(token_id)) {
            Ok(Some(t)) => t,
            _ => {
                return Python::with_gil(|py| {
                    let result = PyDict::new_bound(py);
                    result.set_item("allowed", false).unwrap();
                    result.set_item("deny_reason", "token_not_found").unwrap();
                    result.set_item("run_id", &run_id).unwrap();
                    Ok(result.into())
                });
            }
        };

        // Verify signature
        let sig_bytes = hex::decode(&token.signature).unwrap_or_default();
        if sig_bytes.len() != 64 {
            return Python::with_gil(|py| {
                let result = PyDict::new_bound(py);
                result.set_item("allowed", false).unwrap();
                result.set_item("deny_reason", "token_signature_invalid").unwrap();
                result.set_item("run_id", &run_id).unwrap();
                Ok(result.into())
            });
        }
        let sig = ed25519_dalek::Signature::from_slice(&sig_bytes).unwrap();
        if self.verifying_key.verify(token.decision_hash.as_bytes(), &sig).is_err() {
            return Python::with_gil(|py| {
                let result = PyDict::new_bound(py);
                result.set_item("allowed", false).unwrap();
                result.set_item("deny_reason", "token_signature_invalid").unwrap();
                result.set_item("run_id", &run_id).unwrap();
                Ok(result.into())
            });
        }

        // Check expiry
        if now > token.expires_unix_ms {
            return Python::with_gil(|py| {
                let result = PyDict::new_bound(py);
                result.set_item("allowed", false).unwrap();
                result.set_item("deny_reason", "token_expired").unwrap();
                result.set_item("run_id", &run_id).unwrap();
                Ok(result.into())
            });
        }

        // Check grantee binding — token usable only by its grantee (skip for
        // legacy rows with empty granted_to)
        if !token.granted_to.is_empty() && token.granted_to != executor_id {
            return Python::with_gil(|py| {
                let result = PyDict::new_bound(py);
                result.set_item("allowed", false).unwrap();
                result.set_item("deny_reason", "token_grantee_mismatch").unwrap();
                result.set_item("run_id", &run_id).unwrap();
                Ok(result.into())
            });
        }

        // Check tool/action match
        if token.tool != tool || token.action != action {
            return Python::with_gil(|py| {
                let result = PyDict::new_bound(py);
                result.set_item("allowed", false).unwrap();
                result.set_item("deny_reason", "token_action_mismatch").unwrap();
                result.set_item("run_id", &run_id).unwrap();
                Ok(result.into())
            });
        }

        // Check params hash
        let actual_params_hash = compute_params_hash(&params_value);
        if token.params_hash != actual_params_hash {
            return Python::with_gil(|py| {
                let result = PyDict::new_bound(py);
                result.set_item("allowed", false).unwrap();
                result.set_item("deny_reason", "token_params_mismatch").unwrap();
                result.set_item("run_id", &run_id).unwrap();
                Ok(result.into())
            });
        }

        // Check revocation (T₁)
        if let Ok(Some(rev)) = self.rt.block_on(self.storage.check_revocation(executor_id)) {
            return Python::with_gil(|py| {
                let result = PyDict::new_bound(py);
                result.set_item("allowed", false).unwrap();
                result.set_item("deny_reason", format!("authority_revoked_at_t1: {}", rev.reason)).unwrap();
                result.set_item("run_id", &run_id).unwrap();
                Ok(result.into())
            });
        }

        // Mark consumed
        if let Err(_) = self.rt.block_on(self.storage.mark_token_consumed(token_id, now)) {
            return Python::with_gil(|py| {
                let result = PyDict::new_bound(py);
                result.set_item("allowed", false).unwrap();
                result.set_item("deny_reason", "token_already_consumed").unwrap();
                result.set_item("run_id", &run_id).unwrap();
                Ok(result.into())
            });
        }

        Python::with_gil(|py| {
            let result = PyDict::new_bound(py);
            result.set_item("allowed", true).unwrap();
            result.set_item("run_id", &run_id).unwrap();
            let receipt = PyDict::new_bound(py);
            receipt.set_item("token_id", token_id).unwrap();
            receipt.set_item("executor_id", executor_id).unwrap();
            receipt.set_item("tool", tool).unwrap();
            receipt.set_item("action", action).unwrap();
            receipt.set_item("params_hash", &actual_params_hash).unwrap();
            receipt.set_item("consumed_unix_ms", now).unwrap();
            result.set_item("receipt", receipt).unwrap();
            Ok(result.into())
        })
    }

    /// Verify a decision by run_id. Returns a dict with verified, stored_hash, rederived_hash.
    fn verify(&self, run_id: &str) -> PyResult<PyObject> {
        match self.rt.block_on(self.storage.get_decision(run_id)) {
            Ok(Some(d)) => {
                let replay: serde_json::Value = serde_json::from_str(&d.replay_inputs).unwrap_or(serde_json::json!({}));
                let tool = replay.get("tool").and_then(|v| v.as_str()).unwrap_or("");
                let action = replay.get("action").and_then(|v| v.as_str()).unwrap_or("");
                let params = replay.get("params").cloned().unwrap_or(serde_json::json!({}));
                let reason_codes: Vec<String> = serde_json::from_str(&d.reason_codes).unwrap_or_default();
                let rederived = compute_decision_hash(&d.request_id, &d.gate_state, &reason_codes, tool, action, &params);
                let verified = rederived == d.decision_hash;

                Python::with_gil(|py| {
                    let result = PyDict::new_bound(py);
                    result.set_item("verified", verified).unwrap();
                    result.set_item("stored_decision_hash", &d.decision_hash).unwrap();
                    result.set_item("rederived_decision_hash", &rederived).unwrap();
                    result.set_item("gate_state", &d.gate_state).unwrap();
                    result.set_item("run_id", run_id).unwrap();
                    Ok(result.into())
                })
            }
            _ => {
                Python::with_gil(|py| {
                    let result = PyDict::new_bound(py);
                    result.set_item("verified", false).unwrap();
                    result.set_item("run_id", run_id).unwrap();
                    Ok(result.into())
                })
            }
        }
    }

    /// Revoke an actor.
    fn revoke(&self, actor_id: &str, reason: &str, revoked_by: &str) -> PyResult<bool> {
        let rec = RevocationRecord {
            actor_id: actor_id.to_string(),
            reason: reason.to_string(),
            revoked_unix_ms: now_unix_ms(),
            revoked_by: revoked_by.to_string(),
        };
        match self.rt.block_on(self.storage.store_revocation(rec)) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Check if an actor is revoked.
    fn check_revocation(&self, actor_id: &str) -> PyResult<Option<String>> {
        match self.rt.block_on(self.storage.check_revocation(actor_id)) {
            Ok(Some(r)) => Ok(Some(r.reason)),
            _ => Ok(None),
        }
    }

    /// Store a policy for a tool+action.
    fn store_policy(&self, tool: &str, action: &str, script: &str, policy_version: &str) -> PyResult<String> {
        let policy_id = format!("pol_{}", &sha256_hex(&format!("{}{}{}", tool, action, now_unix_ms()))[..16]);
        let rec = PolicyRecord {
            policy_id: policy_id.clone(),
            tool: tool.to_string(),
            action: action.to_string(),
            script: script.to_string(),
            policy_version: policy_version.to_string(),
            created_unix_ms: now_unix_ms(),
            active: true,
            signature: None,
            min_approvals: 0,
            min_justification_length: 0,
        };
        match self.rt.block_on(self.storage.store_policy(rec)) {
            Ok(()) => Ok(policy_id),
            Err(e) => Err(pyo3::exceptions::PyRuntimeError::new_err(format!("store_policy failed: {}", e))),
        }
    }

    /// Get the verifying key (hex-encoded Ed25519 public key).
    #[getter]
    fn verifying_key(&self) -> String {
        hex::encode(self.verifying_key.to_bytes())
    }
}

/// DGV Python module.
#[pymodule]
fn dgv_python(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Gate>()?;
    Ok(())
}
