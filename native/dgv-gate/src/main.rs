//! DGV Enforcement Gate — Phase 2 (persistent storage)
//!
//! A real HTTP server that intercepts agent tool calls and returns computed
//! decisions with signed receipts. State persists across restarts via
//! a pluggable Storage trait (SQLite for dev, Postgres for production).
//!
//! Endpoints:
//!   POST /govern            — evaluate a proposal, return signed decision
//!   POST /execute           — verify token, mark consumed, return receipt
//!   GET  /verify/:run_id    — re-derive decision hash, compare to stored
//!   GET  /health            — liveness probe
//!   GET  /stats             — counters
//!   POST /policies          — store a policy (tool+action -> script)
//!   GET  /policies/:tool/:action — get active policy for tool+action
//!   POST /revocations      — revoke an actor
//!   GET  /revocations      — list revocations
//!   POST /tenant/:tenant_id/policies — store tenant-specific policy

use axum::{
    extract::{Json, Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use dgv_storage::{
    DecisionRecord, PolicyRecord, PostgresStorage, RevocationRecord, SqliteStorage, Storage,
    StorageError, TokenRecord,
};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use only_core::{generate_signs, Sign};
use only_lang::evidence_pack::{AuthTokenIssued, DecisionReturned, ProposalSubmitted};
use only_memory::GhostMemory;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

// ── Helpers ─────────────────────────────────────────────────────────────────

fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

fn sha256_hex(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    hex::encode(h.finalize())
}

fn compute_decision_hash(
    request_id: &str,
    gate_state: &str,
    reason_codes: &[String],
    tool: &str,
    action: &str,
    params: &Value,
) -> String {
    let mut h = Sha256::new();
    h.update(request_id.as_bytes());
    h.update(gate_state.as_bytes());
    h.update(reason_codes.join(",").as_bytes());
    h.update(tool.as_bytes());
    h.update(action.as_bytes());
    h.update(params.to_string().as_bytes());
    hex::encode(h.finalize())
}

fn compute_params_hash(params: &Value) -> String {
    sha256_hex(&params.to_string())
}

// ── Signing keys ─────────────────────────────────────────────────────────────

struct SigningKeys {
    sk: SigningKey,
    vk: VerifyingKey,
}

impl SigningKeys {
    fn new() -> Self {
        let sk = SigningKey::generate(&mut rand::rngs::OsRng);
        let vk = sk.verifying_key();
        Self { sk, vk }
    }

    /// Load from a file, or generate new and save.
    fn load_or_create(path: &str) -> Self {
        if let Ok(hex_str) = std::fs::read_to_string(path) {
            if let Ok(bytes) = hex::decode(hex_str.trim()) {
                if bytes.len() == 32 {
                    let sk = SigningKey::from_bytes(&bytes.try_into().unwrap());
                    let vk = sk.verifying_key();
                    println!("Loaded signing key from {}", path);
                    return Self { sk, vk };
                }
            }
        }
        let keys = Self::new();
        let _ = std::fs::write(path, hex::encode(keys.sk.to_bytes()));
        println!("Generated new signing key, saved to {}", path);
        keys
    }

    fn sign_decision(&self, decision_hash: &str) -> String {
        let sig = self.sk.sign(decision_hash.as_bytes());
        hex::encode(sig.to_bytes())
    }

    fn verify_signature(&self, decision_hash: &str, signature_hex: &str) -> bool {
        let sig_bytes = match hex::decode(signature_hex) {
            Ok(b) => b,
            Err(_) => return false,
        };
        if sig_bytes.len() != 64 {
            return false;
        }
        let sig = match ed25519_dalek::Signature::from_slice(&sig_bytes) {
            Ok(s) => s,
            Err(_) => return false,
        };
        self.vk.verify(decision_hash.as_bytes(), &sig).is_ok()
    }
}

// ── App state ────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct AppState {
    storage: Arc<dyn Storage>,
    keys: Arc<SigningKeys>,
    /// In-memory counters (not persisted; reset on restart)
    counters: Arc<std::sync::Mutex<Counters>>,
    /// Rate limit configuration (requests per window per agent+tool)
    /// Wrapped in RwLock so it can be updated at runtime via PUT /config/rate-limit
    rate_limit: Arc<std::sync::RwLock<RateLimitConfig>>,
}

#[derive(Clone)]
struct RateLimitConfig {
    /// Max requests per window per agent+tool
    max_requests: i64,
    /// Window size in milliseconds
    window_ms: i64,
    /// Whether rate limiting is enabled
    enabled: bool,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_requests: 100,
            window_ms: 60_000, // 1 minute
            enabled: true,
        }
    }
}

#[derive(Default)]
struct Counters {
    decisions_made: u64,
    tokens_issued: u64,
    tokens_consumed: u64,
    denials: u64,
}

// ── Default governance script ────────────────────────────────────────────────

fn default_governance_script(agent_id: &str, tool: &str, action: &str, params: &Value, risk: f64) -> String {
    format!(
        "harmony(1e-12)\n\
         bind_authority(\"{}\", \"agent\", \"{}\")\n\
         bind_objective(\"{}\", [\"{}\"])\n\
         bind_context(\"{}\", \"{}\")\n\
         evolve(2)\n\
         data({})\n\
         check_authority(\"{}\")\n\
         check_objective_drift(\"{}\")\n\
         check_context_drift()\n\
         budget_limit({})\n\
         residual()",
        agent_id,
        tool,
        action,
        action,
        sha256_hex(&params.to_string()),
        sha256_hex(tool),
        risk,
        agent_id,
        action,
        risk,
    )
}

// ── POST /govern ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct GovernRequest {
    #[serde(flatten)]
    proposal: ProposalSubmitted,
    /// Optional tenant ID for multi-tenant isolation
    tenant_id: Option<String>,
}

#[derive(Serialize)]
struct GovernResponse {
    decision: DecisionReturned,
    evidence_pack_id: String,
    signature: String,
    verifying_key: String,
}

async fn handle_govern(
    State(app): State<AppState>,
    Json(req): Json<GovernRequest>,
) -> impl IntoResponse {
    let p = req.proposal;
    let request_id = p.request_id.clone();
    let run_id = only_lang::evidence_pack::run_id_unix_ms();
    let now = now_unix_ms();

    // 0. Rate limiting (per agent+tool)
    let rl_enabled = { app.rate_limit.read().unwrap().enabled };
    let rl_max = { app.rate_limit.read().unwrap().max_requests };
    let rl_window = { app.rate_limit.read().unwrap().window_ms };
    if rl_enabled {
        let rl_key = format!("govern:{}:{}", p.agent_id, p.tool);
        match app.storage.check_and_increment_rate(&rl_key, rl_max, rl_window).await {
            Ok(false) => {
                let decision = DecisionReturned {
                    request_id: request_id.clone(),
                    gate_state: "DENY".to_string(),
                    reason_codes: vec!["rate_limit_exceeded".to_string()],
                    approvals_required: 1,
                    approvals_received: 0,
                    auth_token: None,
                    run_id: run_id.clone(),
                    decision_hash: compute_decision_hash(&request_id, "DENY", &["rate_limit_exceeded".to_string()], &p.tool, &p.action, &p.params),
                    counterfactual: None,
                };
                let signature = app.keys.sign_decision(&decision.decision_hash);
                {
                    let mut c = app.counters.lock().unwrap();
                    c.decisions_made += 1;
                    c.denials += 1;
                }
                return (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(GovernResponse {
                        decision,
                        evidence_pack_id: run_id,
                        signature,
                        verifying_key: hex::encode(app.keys.vk.to_bytes()),
                    }),
                );
            }
            Err(e) => {
                // Storage error — fail open for rate limiting (log but continue)
                eprintln!("rate limit check failed: {}", e);
            }
            Ok(true) => {} // allowed
        }
    }

    // 1. Check revocation (from persistent storage)
    let revocation = app.storage.check_revocation(&p.agent_id).await.ok().flatten();
    let (gate_state, reason_codes, pass) = if let Some(rev) = revocation {
        (
            "DENY".to_string(),
            vec![format!("authority_revoked: {}", rev.reason)],
            false,
        )
    } else {
        // 2. Load policy from storage (tenant-specific or global)
        let policy = if let Some(ref tenant) = req.tenant_id {
            app.storage
                .get_tenant_active_policy(tenant, &p.tool, &p.action)
                .await
                .ok()
                .flatten()
        } else {
            None
        };
        let policy = policy.or_else(|| {
            // Fall back to global policy
            None
        });
        let global_policy = app
            .storage
            .get_active_policy(&p.tool, &p.action)
            .await
            .ok()
            .flatten();
        let policy = policy.or(global_policy);

        let script = policy
            .map(|p| p.script)
            .unwrap_or_else(|| default_governance_script(&p.agent_id, &p.tool, &p.action, &p.params, p.risk_level.parse::<f64>().unwrap_or(1000.0)));

        // 3. Evaluate the script
        let n = 4;
        let signs: Vec<Sign> = generate_signs(n).collect();
        let payload = p.risk_level.parse::<f64>().unwrap_or(1000.0);
        let mut field = GhostMemory::encode_4(&signs, payload);

        match only_lang::evaluate_script(&signs, &mut field, &script) {
            Ok(res) => {
                if res.authority_revoked {
                    let reason = res.authority_revocation_reason
                        .unwrap_or_else(|| "authority_revoked".to_string());
                    ("DENY".to_string(), vec![reason], false)
                } else if res.pass {
                    ("ALLOW".to_string(), vec![], true)
                } else {
                    ("DENY".to_string(), vec!["mathematical_drift_detected".to_string()], false)
                }
            }
            Err(e) => {
                let err_str = e.to_string().to_lowercase();
                let is_governance = err_str.contains("authority")
                    || err_str.contains("revocation")
                    || err_str.contains("lineage")
                    || err_str.contains("objective")
                    || err_str.contains("context")
                    || err_str.contains("drift")
                    || err_str.contains("bounds")
                    || err_str.contains("bind");
                if is_governance {
                    ("DENY".to_string(), vec![e.to_string()], false)
                } else {
                    ("SILENCE".to_string(), vec![format!("system_error: {}", e)], false)
                }
            }
        }
    };

    // 4. Compute and sign decision hash
    let decision_hash = compute_decision_hash(
        &request_id,
        &gate_state,
        &reason_codes,
        &p.tool,
        &p.action,
        &p.params,
    );
    let signature = app.keys.sign_decision(&decision_hash);
    let verifying_key = hex::encode(app.keys.vk.to_bytes());

    // 5. Issue auth token if ALLOW
    let auth_token = if pass {
        let token_id = format!("tok_{}", &sha256_hex(&format!("{}{}", request_id, run_id))[..16]);
        let token_rec = TokenRecord {
            token_id: token_id.clone(),
            request_id: request_id.clone(),
            tool: p.tool.clone(),
            action: p.action.clone(),
            params_hash: compute_params_hash(&p.params),
            expires_unix_ms: now + 300_000, // 5 minutes
            consumed: false,
            consumed_unix_ms: None,
            decision_hash: decision_hash.clone(),
            signature: signature.clone(),
            created_unix_ms: now,
        };
        let _ = app.storage.store_token(token_rec).await;
        {
            let mut c = app.counters.lock().unwrap();
            c.tokens_issued += 1;
        }
        Some(AuthTokenIssued {
            token_id,
            request_id: request_id.clone(),
            policy_version: "v1".to_string(),
            tool: p.tool.clone(),
            action: p.action.clone(),
            vendor: "dgv-gate".to_string(),
            amount_cap: p.risk_level.parse::<f64>().unwrap_or(1000.0) as u64,
            expires_unix_ms: (now + 300_000) as u64,
            approver_ids: vec![p.agent_id.clone()],
            signature: signature.clone(),
        })
    } else {
        None
    };

    // 6. Build decision
    let decision = DecisionReturned {
        request_id: request_id.clone(),
        gate_state: gate_state.clone(),
        reason_codes: reason_codes.clone(),
        approvals_required: if pass { 0 } else { 1 },
        approvals_received: if pass { 1 } else { 0 },
        auth_token,
        run_id: run_id.clone(),
        decision_hash: decision_hash.clone(),
        counterfactual: None,
    };

    // 7. Persist decision
    let replay_inputs = json!({
        "tool": p.tool,
        "action": p.action,
        "params": p.params,
        "agent_id": p.agent_id,
        "workflow": p.workflow,
        "risk_level": p.risk_level,
    });
    let dec_rec = DecisionRecord {
        run_id: run_id.clone(),
        request_id: request_id.clone(),
        decision_hash: decision_hash.clone(),
        gate_state: gate_state.clone(),
        reason_codes: serde_json::to_string(&reason_codes).unwrap_or_default(),
        replay_inputs: replay_inputs.to_string(),
        signature: signature.clone(),
        created_unix_ms: now,
    };
    let _ = app.storage.store_decision(dec_rec).await;

    {
        let mut c = app.counters.lock().unwrap();
        c.decisions_made += 1;
        if !pass {
            c.denials += 1;
        }
    }

    let response = GovernResponse {
        decision,
        evidence_pack_id: run_id,
        signature,
        verifying_key,
    };

    (StatusCode::OK, Json(response))
}

// ── POST /execute ───────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct ExecuteRequest {
    token_id: String,
    executor_id: String,
    tool: String,
    action: String,
    params: Value,
}

#[derive(Serialize)]
struct ExecuteResponse {
    allowed: bool,
    deny_reason: Option<String>,
    receipt: Value,
    run_id: String,
}

async fn handle_execute(
    State(app): State<AppState>,
    Json(req): Json<ExecuteRequest>,
) -> impl IntoResponse {
    let now = now_unix_ms();
    let run_id = only_lang::evidence_pack::run_id_unix_ms();

    // 0. Rate limiting (per executor+tool)
    let rl_enabled = { app.rate_limit.read().unwrap().enabled };
    let rl_max = { app.rate_limit.read().unwrap().max_requests };
    let rl_window = { app.rate_limit.read().unwrap().window_ms };
    if rl_enabled {
        let rl_key = format!("execute:{}:{}", req.executor_id, req.tool);
        match app.storage.check_and_increment_rate(&rl_key, rl_max, rl_window).await {
            Ok(false) => {
                return (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(ExecuteResponse {
                        allowed: false,
                        deny_reason: Some("rate_limit_exceeded".to_string()),
                        receipt: json!({"run_id": run_id, "verified": false, "rate_limited": true}),
                        run_id,
                    }),
                );
            }
            Err(e) => {
                eprintln!("rate limit check failed: {}", e);
            }
            Ok(true) => {}
        }
    }

    // 1. Look up token from persistent storage
    let token = match app.storage.get_token(&req.token_id).await {
        Ok(Some(t)) => t,
        Ok(None) => {
            return (
                StatusCode::FORBIDDEN,
                Json(ExecuteResponse {
                    allowed: false,
                    deny_reason: Some("token_not_found".to_string()),
                    receipt: json!({"run_id": run_id, "verified": false}),
                    run_id,
                }),
            );
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ExecuteResponse {
                    allowed: false,
                    deny_reason: Some(format!("storage_error: {}", e)),
                    receipt: json!({"run_id": run_id, "verified": false}),
                    run_id,
                }),
            );
        }
    };

    // 2. Verify signature
    if !app.keys.verify_signature(&token.decision_hash, &token.signature) {
        return (
            StatusCode::FORBIDDEN,
            Json(ExecuteResponse {
                allowed: false,
                deny_reason: Some("token_signature_invalid".to_string()),
                receipt: json!({"run_id": run_id, "verified": false}),
                run_id,
            }),
        );
    }

    // 3. Check expiry
    if now > token.expires_unix_ms {
        return (
            StatusCode::FORBIDDEN,
            Json(ExecuteResponse {
                allowed: false,
                deny_reason: Some("token_expired".to_string()),
                receipt: json!({"run_id": run_id, "verified": false, "expires_unix_ms": token.expires_unix_ms, "now_unix_ms": now}),
                run_id,
            }),
        );
    }

    // 4. Verify token matches this action
    if token.tool != req.tool || token.action != req.action {
        return (
            StatusCode::FORBIDDEN,
            Json(ExecuteResponse {
                allowed: false,
                deny_reason: Some("token_action_mismatch".to_string()),
                receipt: json!({
                    "run_id": run_id,
                    "verified": false,
                    "expected_tool": token.tool,
                    "expected_action": token.action,
                    "actual_tool": req.tool,
                    "actual_action": req.action,
                }),
                run_id,
            }),
        );
    }

    // 5. Verify params hash
    let actual_params_hash = compute_params_hash(&req.params);
    if token.params_hash != actual_params_hash {
        return (
            StatusCode::FORBIDDEN,
            Json(ExecuteResponse {
                allowed: false,
                deny_reason: Some("token_params_mismatch".to_string()),
                receipt: json!({
                    "run_id": run_id,
                    "verified": false,
                    "expected_params_hash": token.params_hash,
                    "actual_params_hash": actual_params_hash,
                }),
                run_id,
            }),
        );
    }

    // 6. Check revocation (T₁ authority check)
    if let Ok(Some(rev)) = app.storage.check_revocation(&req.executor_id).await {
        return (
            StatusCode::FORBIDDEN,
            Json(ExecuteResponse {
                allowed: false,
                deny_reason: Some(format!("authority_revoked_at_t1: {}", rev.reason)),
                receipt: json!({"run_id": run_id, "verified": false, "revocation": rev.reason}),
                run_id,
            }),
        );
    }

    // 7. Mark token consumed (atomic)
    if let Err(StorageError::Conflict) = app.storage.mark_token_consumed(&req.token_id, now).await {
        return (
            StatusCode::FORBIDDEN,
            Json(ExecuteResponse {
                allowed: false,
                deny_reason: Some("token_already_consumed".to_string()),
                receipt: json!({"run_id": run_id, "verified": false}),
                run_id,
            }),
        );
    }

    {
        let mut c = app.counters.lock().unwrap();
        c.tokens_consumed += 1;
    }

    // 8. Build receipt
    let receipt = json!({
        "token_id": req.token_id,
        "executor_id": req.executor_id,
        "tool": req.tool,
        "action": req.action,
        "params_hash": actual_params_hash,
        "consumed_unix_ms": now,
        "verified": true,
        "signature": token.signature,
    });

    (
        StatusCode::OK,
        Json(ExecuteResponse {
            allowed: true,
            deny_reason: None,
            receipt,
            run_id,
        }),
    )
}

// ── GET /verify/:run_id ─────────────────────────────────────────────────────

#[derive(Serialize)]
struct VerifyResponse {
    run_id: String,
    verified: bool,
    stored_decision_hash: Option<String>,
    rederived_decision_hash: Option<String>,
    gate_state: Option<String>,
    reason_codes: Option<Value>,
    created_unix_ms: Option<i64>,
}

async fn handle_verify(
    State(app): State<AppState>,
    Path(run_id): Path<String>,
) -> impl IntoResponse {
    match app.storage.get_decision(&run_id).await {
        Ok(Some(d)) => {
            let replay: Value = serde_json::from_str(&d.replay_inputs).unwrap_or(json!({}));
            let tool = replay.get("tool").and_then(|v| v.as_str()).unwrap_or("");
            let action = replay.get("action").and_then(|v| v.as_str()).unwrap_or("");
            let params = replay.get("params").cloned().unwrap_or(json!({}));
            let reason_codes: Vec<String> = serde_json::from_str(&d.reason_codes).unwrap_or_default();
            let rederived = compute_decision_hash(&d.request_id, &d.gate_state, &reason_codes, tool, action, &params);
            let verified = rederived == d.decision_hash;
            (
                StatusCode::OK,
                Json(VerifyResponse {
                    run_id,
                    verified,
                    stored_decision_hash: Some(d.decision_hash),
                    rederived_decision_hash: Some(rederived),
                    gate_state: Some(d.gate_state),
                    reason_codes: Some(json!(reason_codes)),
                    created_unix_ms: Some(d.created_unix_ms),
                }),
            )
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(VerifyResponse {
                run_id,
                verified: false,
                stored_decision_hash: None,
                rederived_decision_hash: None,
                gate_state: None,
                reason_codes: None,
                created_unix_ms: None,
            }),
        ),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(VerifyResponse {
                run_id,
                verified: false,
                stored_decision_hash: None,
                rederived_decision_hash: None,
                gate_state: None,
                reason_codes: None,
                created_unix_ms: None,
            }),
        ),
    }
}

// ── POST /policies ──────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct StorePolicyRequest {
    tool: String,
    action: String,
    script: String,
    policy_version: Option<String>,
}

#[derive(Serialize)]
struct StorePolicyResponse {
    policy_id: String,
    active: bool,
}

async fn handle_store_policy(
    State(app): State<AppState>,
    Json(req): Json<StorePolicyRequest>,
) -> impl IntoResponse {
    let policy_id = format!("pol_{}", &sha256_hex(&format!("{}{}{}", req.tool, req.action, now_unix_ms()))[..16]);
    let rec = PolicyRecord {
        policy_id: policy_id.clone(),
        tool: req.tool,
        action: req.action,
        script: req.script,
        policy_version: req.policy_version.unwrap_or_else(|| "v1".to_string()),
        created_unix_ms: now_unix_ms(),
        active: true,
    };
    match app.storage.store_policy(rec).await {
        Ok(()) => (StatusCode::OK, Json(StorePolicyResponse { policy_id, active: true })),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(StorePolicyResponse { policy_id: format!("error: {}", e), active: false })),
    }
}

// ── GET /policies/:tool/:action ────────────────────────────────────────────

async fn handle_get_policy(
    State(app): State<AppState>,
    Path((tool, action)): Path<(String, String)>,
) -> impl IntoResponse {
    match app.storage.get_active_policy(&tool, &action).await {
        Ok(Some(p)) => (StatusCode::OK, Json(serde_json::to_value(p).unwrap_or_default())),
        Ok(None) => (StatusCode::NOT_FOUND, Json(json!({"error": "no_active_policy"}))),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))),
    }
}

// ── POST /revocations ────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct RevokeRequest {
    actor_id: String,
    reason: String,
    revoked_by: String,
}

async fn handle_revoke(
    State(app): State<AppState>,
    Json(req): Json<RevokeRequest>,
) -> impl IntoResponse {
    let rec = RevocationRecord {
        actor_id: req.actor_id,
        reason: req.reason,
        revoked_unix_ms: now_unix_ms(),
        revoked_by: req.revoked_by,
    };
    match app.storage.store_revocation(rec).await {
        Ok(()) => (StatusCode::OK, Json(json!({"revoked": true}))),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))),
    }
}

// ── GET /revocations ────────────────────────────────────────────────────────

async fn list_revocations(State(app): State<AppState>) -> impl IntoResponse {
    match app.storage.list_revocations().await {
        Ok(list) => (StatusCode::OK, Json(serde_json::to_value(list).unwrap_or_default())),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))),
    }
}

// ── POST /tenant/:tenant_id/policies ────────────────────────────────────────

#[derive(Deserialize)]
struct StoreTenantPolicyRequest {
    tool: String,
    action: String,
    script: String,
    policy_version: Option<String>,
}

async fn handle_store_tenant_policy(
    State(app): State<AppState>,
    Path(tenant_id): Path<String>,
    Json(req): Json<StoreTenantPolicyRequest>,
) -> impl IntoResponse {
    let policy_id = format!("tpol_{}", &sha256_hex(&format!("{}{}{}{}", tenant_id, req.tool, req.action, now_unix_ms()))[..16]);
    let rec = PolicyRecord {
        policy_id: policy_id.clone(),
        tool: req.tool,
        action: req.action,
        script: req.script,
        policy_version: req.policy_version.unwrap_or_else(|| "v1".to_string()),
        created_unix_ms: now_unix_ms(),
        active: true,
    };
    match app.storage.store_tenant_policy(&tenant_id, rec).await {
        Ok(()) => (StatusCode::OK, Json(StorePolicyResponse { policy_id, active: true })),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(StorePolicyResponse { policy_id: format!("error: {}", e), active: false })),
    }
}

// ── GET/PUT /config/rate-limit ───────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone)]
struct RateLimitConfigResponse {
    max_requests: i64,
    window_ms: i64,
    enabled: bool,
}

async fn handle_get_rate_limit(State(app): State<AppState>) -> impl IntoResponse {
    let rl = app.rate_limit.read().unwrap();
    (
        StatusCode::OK,
        Json(RateLimitConfigResponse {
            max_requests: rl.max_requests,
            window_ms: rl.window_ms,
            enabled: rl.enabled,
        }),
    )
}

#[derive(Deserialize)]
struct UpdateRateLimitRequest {
    max_requests: Option<i64>,
    window_ms: Option<i64>,
    enabled: Option<bool>,
}

// Updates the shared rate limit config in-place via RwLock write.
async fn handle_update_rate_limit(
    State(app): State<AppState>,
    Json(req): Json<UpdateRateLimitRequest>,
) -> impl IntoResponse {
    {
        let mut rl = app.rate_limit.write().unwrap();
        if let Some(max) = req.max_requests {
            rl.max_requests = max;
        }
        if let Some(window) = req.window_ms {
            rl.window_ms = window;
        }
        if let Some(enabled) = req.enabled {
            rl.enabled = enabled;
        }
    }
    let rl = app.rate_limit.read().unwrap();
    (
        StatusCode::OK,
        Json(RateLimitConfigResponse {
            max_requests: rl.max_requests,
            window_ms: rl.window_ms,
            enabled: rl.enabled,
        }),
    )
}

// ── POST /policies/load-file ────────────────────────────────────────────────
//
// Load policies from a YAML file. The file format is:
//
// policies:
//   - tool: send_email
//     action: send
//     script: |
//       harmony(1e-12)
//       bind_authority(...)
//       residual()
//   - tool: delete_file
//     action: delete
//     script: |
//       harmony(1e-12)
//       bind_authority(...)
//       residual()
//
// tenant_policies:
//   acme-corp:
//     - tool: send_email
//       action: send
//       script: |
//         harmony(1e-12)
//         residual()

#[derive(Deserialize)]
struct LoadPolicyFileRequest {
    file_path: String,
}

#[derive(Deserialize)]
struct YamlPolicyFile {
    policies: Option<Vec<YamlPolicyEntry>>,
    tenant_policies: Option<std::collections::HashMap<String, Vec<YamlPolicyEntry>>>,
}

#[derive(Deserialize)]
struct YamlPolicyEntry {
    tool: String,
    action: String,
    script: String,
    policy_version: Option<String>,
}

async fn handle_load_policy_file(
    State(app): State<AppState>,
    Json(req): Json<LoadPolicyFileRequest>,
) -> impl IntoResponse {
    // Read the file
    let content = match std::fs::read_to_string(&req.file_path) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("failed to read file: {}", e), "loaded": 0})),
            )
        }
    };

    // Parse as YAML (we accept JSON too since YAML is a superset)
    let parsed: YamlPolicyFile = match serde_json::from_str(&content)
        .or_else(|_| serde_yaml::from_str(&content))
    {
        Ok(p) => p,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("failed to parse: {}", e), "loaded": 0})),
            )
        }
    };

    let mut loaded = 0i64;
    let mut errors: Vec<String> = Vec::new();

    // Load global policies
    if let Some(policies) = parsed.policies {
        for entry in policies {
            let policy_id = format!("pol_{}", &sha256_hex(&format!("{}{}{}{}", entry.tool, entry.action, entry.script, now_unix_ms()))[..16]);
            let rec = PolicyRecord {
                policy_id: policy_id.clone(),
                tool: entry.tool.clone(),
                action: entry.action.clone(),
                script: entry.script.clone(),
                policy_version: entry.policy_version.unwrap_or_else(|| "v1".to_string()),
                created_unix_ms: now_unix_ms(),
                active: true,
            };
            match app.storage.store_policy(rec).await {
                Ok(()) => loaded += 1,
                Err(e) => errors.push(format!("{} {}: {}", entry.tool, entry.action, e)),
            }
        }
    }

    // Load tenant policies
    if let Some(tenant_policies) = parsed.tenant_policies {
        for (tenant_id, policies) in tenant_policies {
            for entry in policies {
                let policy_id = format!("tpol_{}", &sha256_hex(&format!("{}{}{}{}{}", tenant_id, entry.tool, entry.action, entry.script, now_unix_ms()))[..16]);
                let rec = PolicyRecord {
                    policy_id: policy_id.clone(),
                    tool: entry.tool.clone(),
                    action: entry.action.clone(),
                    script: entry.script.clone(),
                    policy_version: entry.policy_version.unwrap_or_else(|| "v1".to_string()),
                    created_unix_ms: now_unix_ms(),
                    active: true,
                };
                match app.storage.store_tenant_policy(&tenant_id, rec).await {
                    Ok(()) => loaded += 1,
                    Err(e) => errors.push(format!("tenant {} {} {}: {}", tenant_id, entry.tool, entry.action, e)),
                }
            }
        }
    }

    (
        StatusCode::OK,
        Json(json!({
            "loaded": loaded,
            "errors": errors,
        })),
    )
}

// ── GET /health ─────────────────────────────────────────────────────────────

async fn handle_health(State(app): State<AppState>) -> impl IntoResponse {
    let storage_ok = app.storage.ping().await.is_ok();
    (
        StatusCode::OK,
        Json(json!({
            "status": if storage_ok { "ok" } else { "degraded" },
            "version": "0.2.0",
            "storage": if storage_ok { "connected" } else { "disconnected" },
            "verifying_key": hex::encode(app.keys.vk.to_bytes()),
        })),
    )
}

// ── GET /stats ─────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct StatsResponse {
    decisions_made: u64,
    tokens_issued: u64,
    tokens_consumed: u64,
    denials: u64,
}

async fn handle_stats(State(app): State<AppState>) -> impl IntoResponse {
    let c = app.counters.lock().unwrap();
    (
        StatusCode::OK,
        Json(StatsResponse {
            decisions_made: c.decisions_made,
            tokens_issued: c.tokens_issued,
            tokens_consumed: c.tokens_consumed,
            denials: c.denials,
        }),
    )
}

// ── Main ────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    println!("--- DGV ENFORCEMENT GATE v0.2.0 ---");
    println!("Phase 2: Persistent storage + policy loading + revocation + multi-tenant");

    // Parse storage backend from env: DGV_STORAGE=sqlite|postgres, DGV_DATABASE_URL=...
    let storage_backend = std::env::var("DGV_STORAGE").unwrap_or_else(|_| "sqlite".to_string());
    let database_url = std::env::var("DGV_DATABASE_URL").unwrap_or_else(|_| {
        if storage_backend == "postgres" {
            "postgres://localhost/dgv_gate".to_string()
        } else {
            "sqlite://dgv_gate.db".to_string()
        }
    });

    println!("Storage backend: {}", storage_backend);
    println!("Database URL: {}", database_url);

    let storage: Arc<dyn Storage> = match storage_backend.as_str() {
        "postgres" => Arc::new(
            PostgresStorage::new(&database_url)
                .await
                .expect("failed to connect to postgres"),
        ),
        _ => Arc::new(
            SqliteStorage::new(&database_url)
                .await
                .expect("failed to open sqlite"),
        ),
    };

    let key_path = std::env::var("DGV_SIGNING_KEY").unwrap_or_else(|_| "dgv_signing_key.hex".to_string());
    let keys = Arc::new(SigningKeys::load_or_create(&key_path));
    println!("Verifying key: {}", hex::encode(keys.vk.to_bytes()));

    // Rate limit configuration from env (mutable at runtime via PUT /config/rate-limit)
    let rate_limit = RateLimitConfig {
        max_requests: std::env::var("DGV_RATE_LIMIT_MAX")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(100),
        window_ms: std::env::var("DGV_RATE_LIMIT_WINDOW_MS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(60_000),
        enabled: std::env::var("DGV_RATE_LIMIT_DISABLED").is_err(),
    };
    println!(
        "Rate limit: {} requests per {}ms (enabled: {})",
        rate_limit.max_requests, rate_limit.window_ms, rate_limit.enabled
    );

    let app_state = AppState {
        storage,
        keys,
        counters: Arc::new(std::sync::Mutex::new(Counters::default())),
        rate_limit: Arc::new(std::sync::RwLock::new(rate_limit)),
    };

    let app = Router::new()
        .route("/govern", post(handle_govern))
        .route("/execute", post(handle_execute))
        .route("/verify/:run_id", get(handle_verify))
        .route("/health", get(handle_health))
        .route("/stats", get(handle_stats))
        .route("/policies", post(handle_store_policy))
        .route("/policies/load-file", post(handle_load_policy_file))
        .route("/policies/:tool/:action", get(handle_get_policy))
        .route("/revocations", post(handle_revoke).get(list_revocations))
        .route("/tenant/:tenant_id/policies", post(handle_store_tenant_policy))
        .route("/config/rate-limit", get(handle_get_rate_limit).put(handle_update_rate_limit))
        .with_state(app_state);

    let addr = std::env::var("DGV_LISTEN_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:7878".to_string());
    println!("Listening on http://{}", addr);
    println!("");
    println!("Endpoints:");
    println!("  POST /govern                        - evaluate proposal, return signed decision");
    println!("  POST /execute                       - verify token, mark consumed, return receipt");
    println!("  GET  /verify/:run_id               - re-derive decision hash, compare to stored");
    println!("  GET  /health                        - liveness probe");
    println!("  GET  /stats                         - decision/token counters");
    println!("  POST /policies                      - store a policy (tool+action -> script)");
    println!("  POST /policies/load-file            - load policies from a YAML/JSON file");
    println!("  GET  /policies/:tool/:action        - get active policy");
    println!("  POST /revocations                   - revoke an actor");
    println!("  GET  /revocations                   - list revocations");
    println!("  POST /tenant/:tenant_id/policies    - store tenant-specific policy");
    println!("  GET  /config/rate-limit             - get rate limit config");
    println!("  PUT  /config/rate-limit             - update rate limit config");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
