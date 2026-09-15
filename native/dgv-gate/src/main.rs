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
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::IntoResponse,
    routing::{delete, get, post, put},
    Router,
};
use dgv_storage::{
    A2aEnvelopeRecord, AgentKeyRecord, ApprovalRecord, DecisionRecord, PolicyRecord,
    PostgresStorage, RevocationRecord, SqliteStorage, Storage, StorageError, TokenRecord,
};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use jsonwebtoken::{decode, decode_header, DecodingKey, Validation, Algorithm};
use only_core::{generate_signs, Sign};
use only_lang::evidence_pack::{AuthTokenIssued, DecisionReturned, ProposalSubmitted};
use only_memory::GhostMemory;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tower_http::cors::{CorsLayer, Any};

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
    /// Admin API key for privileged endpoints (POST /policies, POST /revocations, etc.)
    /// If None, admin endpoints are open (dev mode only — not for production).
    admin_key: Option<String>,
    /// JWT verification config — when set, /govern and /execute require a valid JWT
    /// in the Authorization: Bearer header. The `sub` claim becomes the verified agent_id.
    jwt_config: Option<JwtConfig>,
    /// Circuit breaker state per tool — tracks failures and auto-disables tools
    /// that exceed the failure threshold.
    tool_health: Arc<std::sync::Mutex<std::collections::HashMap<String, ToolHealth>>>,
    /// Optional external semantic verifier webhook — the gate POSTs the
    /// justification + action context and expects {allowed, reason, confidence}.
    /// The gate itself performs no LLM analysis; this is a pluggable hook.
    semantic_verifier_url: Option<String>,
    /// If true, deny when the semantic verifier is unreachable (default false).
    semantic_fail_closed: bool,
}

/// Circuit breaker state for a single tool.
#[derive(Clone, Debug)]
struct ToolHealth {
    /// Consecutive failures
    consecutive_failures: u32,
    /// When the circuit was last opened (unix ms)
    opened_at_ms: Option<i64>,
    /// Whether the circuit is currently open (blocking requests)
    circuit_open: bool,
}

impl ToolHealth {
    fn new() -> Self {
        Self {
            consecutive_failures: 0,
            opened_at_ms: None,
            circuit_open: false,
        }
    }

    /// Record a failure. Opens the circuit if threshold is exceeded.
    fn record_failure(&mut self, threshold: u32) {
        self.consecutive_failures += 1;
        if self.consecutive_failures >= threshold {
            self.circuit_open = true;
            self.opened_at_ms = Some(now_unix_ms());
        }
    }

    /// Record a success. Resets the failure counter and closes the circuit.
    fn record_success(&mut self) {
        self.consecutive_failures = 0;
        self.circuit_open = false;
        self.opened_at_ms = None;
    }

    /// Check if the circuit should half-open (allow a test request through).
    fn should_half_open(&self, cooldown_ms: i64) -> bool {
        if !self.circuit_open {
            return false;
        }
        match self.opened_at_ms {
            Some(t) => now_unix_ms() - t > cooldown_ms,
            None => false,
        }
    }
}

/// JWT verification configuration
#[derive(Clone)]
struct JwtConfig {
    /// HS256 shared secret (for dev/test)
    secret: Option<String>,
    /// RS256 public key PEM (for production — verify with issuer's public key)
    public_key_pem: Option<String>,
    /// JWKS URL for fetching public keys (for key rotation)
    jwks_url: Option<String>,
    /// Expected issuer (iss claim)
    issuer: Option<String>,
    /// Expected audience (aud claim)
    audience: Option<String>,
}

/// JWT claims extracted from the Authorization header
#[derive(Debug, Deserialize)]
struct JwtClaims {
    sub: String,
    #[serde(default)]
    iss: Option<String>,
    #[serde(default)]
    aud: Option<String>,
    #[serde(default)]
    exp: Option<u64>,
    #[serde(default)]
    iat: Option<u64>,
    #[serde(default)]
    scope: Option<String>,
    /// Custom claim for agent role (e.g., "admin", "operator", "agent")
    #[serde(default)]
    #[allow(dead_code)]
    agent_role: Option<String>,
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

fn default_governance_script(agent_id: &str, tool: &str, action: &str, _params: &Value, risk: f64, context_hash: &str) -> String {
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
        context_hash, // Use provided context hash or computed one
        sha256_hex(tool),
        risk,
        agent_id,
        action,
        risk,
    )
}

// ── Admin auth middleware ────────────────────────────────────────────────────

async fn admin_auth_middleware(
    State(app): State<AppState>,
    headers: HeaderMap,
    request: axum::extract::Request,
    next: Next,
) -> impl IntoResponse {
    // If no admin key is configured, allow all (dev mode)
    let Some(ref admin_key) = app.admin_key else {
        return next.run(request).await;
    };

    // Check X-Admin-Key header
    let provided = headers
        .get("X-Admin-Key")
        .and_then(|v| v.to_str().ok());

    if provided == Some(admin_key.as_str()) {
        next.run(request).await
    } else {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "admin_auth_required",
                "hint": "provide X-Admin-Key header",
            })),
        )
            .into_response()
    }
}

// ── JWT verification ─────────────────────────────────────────────────────────

/// JWKS response format (RFC 7517)
#[derive(Debug, Deserialize)]
struct JwksResponse {
    keys: Vec<JwksKey>,
}

#[derive(Debug, Deserialize)]
struct JwksKey {
    kid: String,
    kty: String, // "RSA"
    n: String,   // base64url-encoded modulus
    e: String,   // base64url-encoded exponent
    #[serde(default)]
    alg: Option<String>,
}

/// Fetch a JWKS and find the key matching the given kid.
async fn fetch_jwks_key(jwks_url: &str, kid: &str) -> Result<DecodingKey, String> {
    let client = reqwest::Client::new();
    let resp = client.get(jwks_url).send().await
        .map_err(|e| format!("JWKS fetch failed: {}", e))?;

    let jwks: JwksResponse = resp.json().await
        .map_err(|e| format!("JWKS parse failed: {}", e))?;

    let key = jwks.keys.iter()
        .find(|k| k.kid == kid)
        .ok_or_else(|| format!("no key found for kid: {}", kid))?;

    if key.kty != "RSA" {
        return Err(format!("unsupported key type: {}", key.kty));
    }

    // Build DecodingKey from RSA components (n, e are base64url-encoded)
    DecodingKey::from_rsa_components(&key.n, &key.e)
        .map_err(|e| format!("RSA key construction failed: {}", e))
}

/// Verify a JWT from the Authorization header and extract the agent_id.
/// Supports HS256 (shared secret), RS256 (public key PEM), and JWKS (key rotation).
async fn verify_jwt(
    headers: &HeaderMap,
    config: &JwtConfig,
) -> Result<(String, JwtClaims), String> {
    let auth_header = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or("missing Authorization header")?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or("Authorization header must be 'Bearer <token>'")?;

    // Determine algorithm from JWT header
    let header = decode_header(token)
        .map_err(|e| format!("JWT header decode failed: {}", e))?;

    // Enforce the expected algorithm for the configured mode — never trust the
    // token's alg header alone (prevents HS256-with-RSA-public-key confusion).
    let expected_alg = if config.jwks_url.is_some() || config.public_key_pem.is_some() {
        Algorithm::RS256
    } else {
        Algorithm::HS256
    };
    if header.alg != expected_alg {
        return Err(format!(
            "algorithm mismatch: expected {:?}, got {:?}",
            expected_alg, header.alg
        ));
    }

    let mut validation = Validation::new(expected_alg);

    if let Some(ref iss) = config.issuer {
        validation.set_issuer(&[iss]);
    }
    if let Some(ref aud) = config.audience {
        validation.set_audience(&[aud]);
    }
    validation.validate_exp = true;

    let key = if let Some(ref jwks_url) = config.jwks_url {
        // JWKS mode — fetch the key by kid
        let kid = header.kid.ok_or("JWT missing kid header")?;
        fetch_jwks_key(jwks_url, &kid).await?
    } else if let Some(ref secret) = config.secret {
        DecodingKey::from_secret(secret.as_bytes())
    } else if let Some(ref pem) = config.public_key_pem {
        DecodingKey::from_rsa_pem(pem.as_bytes())
            .map_err(|e| format!("invalid RSA public key: {}", e))?
    } else {
        return Err("no JWT verification key configured".to_string());
    };

    let claims = decode::<JwtClaims>(token, &key, &validation)
        .map_err(|e| format!("JWT verification failed: {}", e))?;

    let agent_id = claims.claims.sub.clone();
    Ok((agent_id, claims.claims))
}

/// Extract verified agent_id from JWT if JWT auth is configured.
/// Returns Some(agent_id) if JWT is configured and valid, None if JWT not configured,
/// Err(msg) if JWT is configured but invalid.
async fn extract_agent_id(
    headers: &HeaderMap,
    jwt_config: &Option<JwtConfig>,
    request_agent_id: &str,
) -> Result<String, String> {
    match jwt_config {
        Some(config) => {
            let (agent_id, _claims) = verify_jwt(headers, config).await?;
            Ok(agent_id)
        }
        None => Ok(request_agent_id.to_string()),
    }
}

// ── Policy signing ────────────────────────────────────────────────────────────

/// Sign a policy script with the gate's signing key.
fn sign_policy(keys: &SigningKeys, script: &str) -> String {
    keys.sign_decision(script)
}

/// Verify a policy's signature against the gate's verifying key.
fn verify_policy_signature(keys: &SigningKeys, script: &str, signature: &str) -> bool {
    keys.verify_signature(script, signature)
}

// ── POST /govern ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct GovernRequest {
    #[serde(flatten)]
    proposal: ProposalSubmitted,
    /// Optional tenant ID for multi-tenant isolation
    tenant_id: Option<String>,
    /// Optional full context hash — if provided, used in bind_context instead of tool+params hash.
    /// This is a SHA-256 hash of the agent's full context (memory state, session data, etc.)
    context_hash: Option<String>,
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
    headers: HeaderMap,
    Json(req): Json<GovernRequest>,
) -> impl IntoResponse {
    let mut p = req.proposal;

    // 0. JWT verification — if configured, verify the JWT and use the verified agent_id
    if app.jwt_config.is_some() {
        match extract_agent_id(&headers, &app.jwt_config, &p.agent_id).await {
            Ok(verified_id) => {
                // Override the claimed agent_id with the verified one from JWT
                p.agent_id = verified_id;
            }
            Err(e) => {
                let run_id = only_lang::evidence_pack::run_id_unix_ms();
                let decision = DecisionReturned {
                    request_id: p.request_id.clone(),
                    gate_state: "DENY".to_string(),
                    reason_codes: vec![format!("identity_verification_failed: {}", e)],
                    approvals_required: 0,
                    approvals_received: 0,
                    auth_token: None,
                    run_id: run_id.clone(),
                    decision_hash: compute_decision_hash(&p.request_id, "DENY", &["identity_verification_failed".to_string()], &p.tool, &p.action, &p.params),
                    counterfactual: None,
                };
                let signature = app.keys.sign_decision(&decision.decision_hash);
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(GovernResponse {
                        decision,
                        evidence_pack_id: run_id,
                        signature,
                        verifying_key: hex::encode(app.keys.vk.to_bytes()),
                    }),
                );
            }
        }
    }

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

    // 0b. Circuit breaker — deny if the tool's circuit is open
    {
        let cb_threshold: u32 = std::env::var("DGV_CIRCUIT_BREAKER_THRESHOLD")
            .ok().and_then(|v| v.parse().ok()).unwrap_or(5);
        let cb_cooldown_ms: i64 = std::env::var("DGV_CIRCUIT_BREAKER_COOLDOWN_MS")
            .ok().and_then(|v| v.parse().ok()).unwrap_or(30_000);
        let cb_enabled = std::env::var("DGV_CIRCUIT_BREAKER_DISABLED")
            .map(|v| v != "1" && v != "true").unwrap_or(true);

        if cb_enabled {
            let mut health_map = app.tool_health.lock().unwrap();
            let health = health_map.entry(p.tool.clone()).or_insert_with(ToolHealth::new);
            if health.circuit_open {
                if health.should_half_open(cb_cooldown_ms) {
                    // Half-open: allow one probe request through
                    health.circuit_open = false;
                    eprintln!("circuit breaker half-open for tool: {}", p.tool);
                } else {
                    drop(health_map);
                    let decision = DecisionReturned {
                        request_id: request_id.clone(),
                        gate_state: "DENY".to_string(),
                        reason_codes: vec![format!(
                            "circuit_breaker_open: tool {} disabled after {} consecutive failures",
                            p.tool, cb_threshold
                        )],
                        approvals_required: 0,
                        approvals_received: 0,
                        auth_token: None,
                        run_id: run_id.clone(),
                        decision_hash: compute_decision_hash(&request_id, "DENY", &["circuit_breaker_open".to_string()], &p.tool, &p.action, &p.params),
                        counterfactual: None,
                    };
                    let signature = app.keys.sign_decision(&decision.decision_hash);
                    {
                        let mut c = app.counters.lock().unwrap();
                        c.decisions_made += 1;
                        c.denials += 1;
                    }
                    return (
                        StatusCode::OK,
                        Json(GovernResponse {
                            decision,
                            evidence_pack_id: run_id,
                            signature,
                            verifying_key: hex::encode(app.keys.vk.to_bytes()),
                        }),
                    );
                }
            }
        }
    }

    // 1. Check revocation (from persistent storage)
    let revocation = app.storage.check_revocation(&p.agent_id).await.ok().flatten();
    let (gate_state, reason_codes, pass, policy_min_approvals) = if let Some(rev) = revocation {
        (
            "DENY".to_string(),
            vec![format!("authority_revoked: {}", rev.reason)],
            false,
            0i64,
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

        // Verify policy signature — reject tampered policies
        if let Some(ref pol) = policy {
            if let Some(ref sig) = pol.signature {
                if !verify_policy_signature(&app.keys, &pol.script, sig) {
                    eprintln!("WARNING: policy signature invalid for {} {}", pol.tool, pol.action);
                    let decision = DecisionReturned {
                        request_id: request_id.clone(),
                        gate_state: "DENY".to_string(),
                        reason_codes: vec!["policy_signature_invalid".to_string()],
                        approvals_required: 0,
                        approvals_received: 0,
                        auth_token: None,
                        run_id: run_id.clone(),
                        decision_hash: compute_decision_hash(&request_id, "DENY", &["policy_signature_invalid".to_string()], &p.tool, &p.action, &p.params),
                        counterfactual: None,
                    };
                    let signature = app.keys.sign_decision(&decision.decision_hash);
                    {
                        let mut c = app.counters.lock().unwrap();
                        c.decisions_made += 1;
                        c.denials += 1;
                    }
                    return (
                        StatusCode::OK,
                        Json(GovernResponse {
                            decision,
                            evidence_pack_id: run_id,
                            signature,
                            verifying_key: hex::encode(app.keys.vk.to_bytes()),
                        }),
                    );
                }
            }
            // If signature is None, policy was stored before signing was implemented — allow but warn
            else {
                eprintln!("WARNING: unsigned policy for {} {}", pol.tool, pol.action);
            }
        }
        let policy_min_approvals = policy.as_ref().map(|p| p.min_approvals).unwrap_or(0);

        // Check minimum justification length (if policy requires it)
        if let Some(ref pol) = policy {
            if pol.min_justification_length > 0
                && p.justification.len() < pol.min_justification_length as usize
            {
                let decision = DecisionReturned {
                    request_id: request_id.clone(),
                    gate_state: "DENY".to_string(),
                    reason_codes: vec![format!(
                        "justification_too_short: required {} chars, got {}",
                        pol.min_justification_length,
                        p.justification.len()
                    )],
                    approvals_required: 0,
                    approvals_received: 0,
                    auth_token: None,
                    run_id: run_id.clone(),
                    decision_hash: compute_decision_hash(&request_id, "DENY", &["justification_too_short".to_string()], &p.tool, &p.action, &p.params),
                    counterfactual: None,
                };
                let signature = app.keys.sign_decision(&decision.decision_hash);
                {
                    let mut c = app.counters.lock().unwrap();
                    c.decisions_made += 1;
                    c.denials += 1;
                }
                return (
                    StatusCode::OK,
                    Json(GovernResponse {
                        decision,
                        evidence_pack_id: run_id,
                        signature,
                        verifying_key: hex::encode(app.keys.vk.to_bytes()),
                    }),
                );
            }
        }

        // Semantic justification verification — pluggable external verifier.
        // The gate performs no LLM analysis itself; if DGV_SEMANTIC_VERIFIER_URL
        // is configured, the justification + action context is POSTed to it and
        // the verdict is enforced. Fail-open by default (recorded in reason
        // codes); set DGV_SEMANTIC_FAIL_CLOSED=1 to deny on unavailability.
        let mut semantic_denial: Option<Vec<String>> = None;
        if let Some(ref url) = app.semantic_verifier_url {
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .unwrap_or_default();
            let body = json!({
                "agent_id": p.agent_id,
                "tool": p.tool,
                "action": p.action,
                "justification": p.justification,
                "params": p.params,
            });
            match client.post(url).json(&body).send().await {
                Ok(resp) => {
                    match resp.json::<serde_json::Value>().await {
                        Ok(v) => {
                            let allowed = v.get("allowed").and_then(|a| a.as_bool()).unwrap_or(false);
                            if !allowed {
                                let reason = v.get("reason").and_then(|r| r.as_str())
                                    .unwrap_or("no reason provided");
                                semantic_denial = Some(vec![format!(
                                    "semantic_verification_failed: {}", reason
                                )]);
                            }
                        }
                        Err(e) => {
                            if app.semantic_fail_closed {
                                semantic_denial = Some(vec![format!(
                                    "semantic_verifier_unparseable: {}", e
                                )]);
                            } else {
                                eprintln!("semantic verifier response unparseable (fail-open): {}", e);
                            }
                        }
                    }
                }
                Err(e) => {
                    if app.semantic_fail_closed {
                        semantic_denial = Some(vec![format!(
                            "semantic_verifier_unreachable: {}", e
                        )]);
                    } else {
                        eprintln!("semantic verifier unreachable (fail-open): {}", e);
                    }
                }
            }
        }
        if let Some(reasons) = semantic_denial {
            let decision = DecisionReturned {
                request_id: request_id.clone(),
                gate_state: "DENY".to_string(),
                reason_codes: reasons.clone(),
                approvals_required: policy_min_approvals as u32,
                approvals_received: 0,
                auth_token: None,
                run_id: run_id.clone(),
                decision_hash: compute_decision_hash(&request_id, "DENY", &reasons, &p.tool, &p.action, &p.params),
                counterfactual: None,
            };
            let signature = app.keys.sign_decision(&decision.decision_hash);
            {
                let mut c = app.counters.lock().unwrap();
                c.decisions_made += 1;
                c.denials += 1;
            }
            return (
                StatusCode::OK,
                Json(GovernResponse {
                    decision,
                    evidence_pack_id: run_id,
                    signature,
                    verifying_key: hex::encode(app.keys.vk.to_bytes()),
                }),
            );
        }

        // Use context_hash if provided (full context hashing), otherwise hash tool+params
        let context_binding = req.context_hash.as_deref()
            .map(|s| s.to_string())
            .unwrap_or_else(|| {
                sha256_hex(&format!("{}{}", p.tool, p.params))
            });

        let script = policy
            .as_ref()
            .map(|p| p.script.clone())
            .unwrap_or_else(|| default_governance_script(&p.agent_id, &p.tool, &p.action, &p.params, p.risk_level.parse::<f64>().unwrap_or(1000.0), &context_binding));

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
                    ("DENY".to_string(), vec![reason], false, policy_min_approvals)
                } else if res.pass {
                    ("ALLOW".to_string(), vec![], true, policy_min_approvals)
                } else {
                    ("DENY".to_string(), vec!["mathematical_drift_detected".to_string()], false, policy_min_approvals)
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
                    ("DENY".to_string(), vec![e.to_string()], false, policy_min_approvals)
                } else {
                    ("SILENCE".to_string(), vec![format!("system_error: {}", e)], false, policy_min_approvals)
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
            min_approvals: policy_min_approvals,
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
        approvals_required: policy_min_approvals as u32,
        approvals_received: 0,
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
    headers: HeaderMap,
    Json(req): Json<ExecuteRequest>,
) -> impl IntoResponse {
    let now = now_unix_ms();
    let run_id = only_lang::evidence_pack::run_id_unix_ms();

    // 0. JWT verification — if configured, verify the JWT
    if app.jwt_config.is_some() {
        if let Err(e) = extract_agent_id(&headers, &app.jwt_config, &req.executor_id).await {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ExecuteResponse {
                    allowed: false,
                    deny_reason: Some(format!("identity_verification_failed: {}", e)),
                    receipt: json!({"run_id": run_id, "verified": false}),
                    run_id,
                }),
            );
        }
    }

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

    // 6b. Check approvals — if the policy required min_approvals, verify count
    if token.min_approvals > 0 {
        let approval_count = app.storage.count_approvals(&req.token_id).await.unwrap_or(0);
        if approval_count < token.min_approvals {
            return (
                StatusCode::FORBIDDEN,
                Json(ExecuteResponse {
                    allowed: false,
                    deny_reason: Some(format!(
                        "insufficient_approvals: {} required, {} received",
                        token.min_approvals, approval_count
                    )),
                    receipt: json!({
                        "run_id": run_id,
                        "verified": false,
                        "approvals_required": token.min_approvals,
                        "approvals_received": approval_count,
                    }),
                    run_id,
                }),
            );
        }
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
    /// Minimum approvals required before execution (default 0)
    min_approvals: Option<i64>,
    /// Minimum justification length in characters (default 0)
    min_justification_length: Option<i64>,
}

#[derive(Serialize)]
struct StorePolicyResponse {
    policy_id: String,
    active: bool,
    signature: String,
}

async fn handle_store_policy(
    State(app): State<AppState>,
    Json(req): Json<StorePolicyRequest>,
) -> impl IntoResponse {
    let policy_id = format!("pol_{}", &sha256_hex(&format!("{}{}{}", req.tool, req.action, now_unix_ms()))[..16]);
    // Sign the policy script — prevents tampering with stored policies
    let sig = sign_policy(&app.keys, &req.script);
    let rec = PolicyRecord {
        policy_id: policy_id.clone(),
        tool: req.tool,
        action: req.action,
        script: req.script,
        policy_version: req.policy_version.unwrap_or_else(|| "v1".to_string()),
        created_unix_ms: now_unix_ms(),
        active: true,
        signature: Some(sig.clone()),
        min_approvals: req.min_approvals.unwrap_or(0),
        min_justification_length: req.min_justification_length.unwrap_or(0),
    };
    match app.storage.store_policy(rec).await {
        Ok(()) => (StatusCode::OK, Json(StorePolicyResponse { policy_id, active: true, signature: sig })),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(StorePolicyResponse { policy_id: format!("error: {}", e), active: false, signature: String::new() })),
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
    min_approvals: Option<i64>,
    min_justification_length: Option<i64>,
}

async fn handle_store_tenant_policy(
    State(app): State<AppState>,
    Path(tenant_id): Path<String>,
    Json(req): Json<StoreTenantPolicyRequest>,
) -> impl IntoResponse {
    let policy_id = format!("tpol_{}", &sha256_hex(&format!("{}{}{}{}", tenant_id, req.tool, req.action, now_unix_ms()))[..16]);
    let sig = sign_policy(&app.keys, &req.script);
    let rec = PolicyRecord {
        policy_id: policy_id.clone(),
        tool: req.tool,
        action: req.action,
        script: req.script,
        policy_version: req.policy_version.unwrap_or_else(|| "v1".to_string()),
        created_unix_ms: now_unix_ms(),
        active: true,
        signature: Some(sig.clone()),
        min_approvals: req.min_approvals.unwrap_or(0),
        min_justification_length: req.min_justification_length.unwrap_or(0),
    };
    match app.storage.store_tenant_policy(&tenant_id, rec).await {
        Ok(()) => (StatusCode::OK, Json(StorePolicyResponse { policy_id, active: true, signature: sig })),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(StorePolicyResponse { policy_id: format!("error: {}", e), active: false, signature: String::new() })),
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
            let sig = sign_policy(&app.keys, &entry.script);
            let rec = PolicyRecord {
                policy_id: policy_id.clone(),
                tool: entry.tool.clone(),
                action: entry.action.clone(),
                script: entry.script.clone(),
                policy_version: entry.policy_version.unwrap_or_else(|| "v1".to_string()),
                created_unix_ms: now_unix_ms(),
                active: true,
                signature: Some(sig),
                min_approvals: 0,
                min_justification_length: 0,
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
                let sig = sign_policy(&app.keys, &entry.script);
                let rec = PolicyRecord {
                    policy_id: policy_id.clone(),
                    tool: entry.tool.clone(),
                    action: entry.action.clone(),
                    script: entry.script.clone(),
                    policy_version: entry.policy_version.unwrap_or_else(|| "v1".to_string()),
                    created_unix_ms: now_unix_ms(),
                    active: true,
                    signature: Some(sig),
                    min_approvals: 0,
                    min_justification_length: 0,
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

// ── POST /approve/:token_id ────────────────────────────────────────────────

#[derive(Deserialize)]
struct ApproveRequest {
    approver_id: String,
}

#[derive(Serialize)]
#[allow(dead_code)]
struct ApproveResponse {
    approved: bool,
    token_id: String,
    approval_count: i64,
}

async fn handle_approve(
    State(app): State<AppState>,
    Path(token_id): Path<String>,
    headers: HeaderMap,
    Json(req): Json<ApproveRequest>,
) -> impl IntoResponse {
    // JWT verification — if configured, verify the approver's identity
    let verified_approver = if app.jwt_config.is_some() {
        match extract_agent_id(&headers, &app.jwt_config, &req.approver_id).await {
            Ok(id) => Some(id),
            Err(e) => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"error": format!("approver_identity_verification_failed: {}", e)})),
                );
            }
        }
    } else {
        None
    };
    let approver_id = verified_approver.unwrap_or_else(|| req.approver_id.clone());
    // Verify the token exists
    let token = match app.storage.get_token(&token_id).await {
        Ok(Some(t)) => t,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "token_not_found", "token_id": token_id})),
            );
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("storage_error: {}", e)})),
            );
        }
    };

    // Check token isn't consumed
    if token.consumed {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error": "token_already_consumed", "token_id": token_id})),
        );
    }

    // Sign the approval with the gate's key (approvals are gate-signed)
    let approval_sig = app.keys.sign_decision(&format!("approve:{}:{}", token_id, approver_id));

    let rec = ApprovalRecord {
        token_id: token_id.clone(),
        approver_id: approver_id.clone(),
        approved_unix_ms: now_unix_ms(),
        signature: approval_sig,
    };

    match app.storage.store_approval(rec).await {
        Ok(()) => {
            let count = app.storage.count_approvals(&token_id).await.unwrap_or(0);
            (
                StatusCode::OK,
                Json(json!({
                    "approved": true,
                    "token_id": token_id,
                    "approval_count": count,
                    "min_approvals": token.min_approvals,
                })),
            )
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("store_failed: {}", e)})),
        ),
    }
}

// ── Tool health / circuit breaker endpoints ─────────────────────────────────
//
// The gate authorizes tool calls but does not execute them — it cannot observe
// downstream failures itself. Callers report execution outcomes via
// POST /tool-health/report. After DGV_CIRCUIT_BREAKER_THRESHOLD consecutive
// failures (default 5), the circuit opens and /govern denies new proposals for
// that tool until DGV_CIRCUIT_BREAKER_COOLDOWN_MS (default 30s) elapses.

#[derive(Deserialize)]
struct ToolHealthReport {
    tool: String,
    success: bool,
    /// Optional detail — e.g. downstream error message, recorded in evidence
    detail: Option<String>,
}

async fn handle_tool_health_report(
    State(app): State<AppState>,
    Json(req): Json<ToolHealthReport>,
) -> impl IntoResponse {
    let cb_threshold: u32 = std::env::var("DGV_CIRCUIT_BREAKER_THRESHOLD")
        .ok().and_then(|v| v.parse().ok()).unwrap_or(5);

    let mut health_map = app.tool_health.lock().unwrap();
    let health = health_map.entry(req.tool.clone()).or_insert_with(ToolHealth::new);
    if req.success {
        health.record_success();
    } else {
        health.record_failure(cb_threshold);
    }
    (
        StatusCode::OK,
        Json(json!({
            "tool": req.tool,
            "circuit_open": health.circuit_open,
            "consecutive_failures": health.consecutive_failures,
        })),
    )
}

/// GET /tool-health — circuit breaker state for all tracked tools
async fn handle_tool_health(State(app): State<AppState>) -> impl IntoResponse {
    let health_map = app.tool_health.lock().unwrap();
    let tools: serde_json::Map<String, serde_json::Value> = health_map
        .iter()
        .map(|(tool, h)| {
            (tool.clone(), json!({
                "circuit_open": h.circuit_open,
                "consecutive_failures": h.consecutive_failures,
                "opened_at_ms": h.opened_at_ms,
            }))
        })
        .collect();
    (StatusCode::OK, Json(json!({ "tools": tools })))
}

/// POST /tool-health/reset/:tool — manually reset a circuit (admin)
async fn handle_tool_health_reset(
    State(app): State<AppState>,
    Path(tool): Path<String>,
) -> impl IntoResponse {
    let mut health_map = app.tool_health.lock().unwrap();
    if let Some(h) = health_map.get_mut(&tool) {
        h.record_success();
    }
    (StatusCode::OK, Json(json!({"tool": tool, "circuit_open": false})))
}

// ── Agent-to-Agent (A2A) signed envelopes ────────────────────────────────────
//
// DGV-native A2A design: agents register Ed25519 public keys (admin-provisioned),
// then exchange signed envelopes routed through the gate. The gate verifies the
// sender's signature, enforces expiry/replay/revocation, stores the envelope for
// the recipient, and returns a gate-signed delivery receipt. Payloads never
// transit the gate — only payload hashes — so the gate sees metadata, not content.
//
// Canonical signing string:
//   envelope_id|sender_id|recipient_id|payload_hash|nonce|sent_unix_ms|expires_unix_ms

#[derive(Deserialize)]
struct RegisterAgentKeyRequest {
    agent_id: String,
    /// hex-encoded Ed25519 public key (64 hex chars = 32 bytes)
    public_key_hex: String,
}

async fn handle_register_agent_key(
    State(app): State<AppState>,
    Json(req): Json<RegisterAgentKeyRequest>,
) -> impl IntoResponse {
    // Validate the public key parses as Ed25519
    let key_bytes = match hex::decode(&req.public_key_hex) {
        Ok(b) if b.len() == 32 => b,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "invalid_public_key: expected 64 hex chars (32 bytes)"})),
            );
        }
    };
    if ed25519_dalek::VerifyingKey::from_bytes(&key_bytes.try_into().unwrap()).is_err() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid_public_key: not a valid Ed25519 key"})),
        );
    }

    let rec = AgentKeyRecord {
        agent_id: req.agent_id.clone(),
        public_key_hex: req.public_key_hex.clone(),
        registered_unix_ms: now_unix_ms(),
        active: true,
    };
    match app.storage.register_agent_key(rec).await {
        Ok(()) => (
            StatusCode::OK,
            Json(json!({"registered": true, "agent_id": req.agent_id})),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("store_failed: {}", e)})),
        ),
    }
}

async fn handle_deactivate_agent_key(
    State(app): State<AppState>,
    Path(agent_id): Path<String>,
) -> impl IntoResponse {
    match app.storage.deactivate_agent_key(&agent_id).await {
        Ok(()) => (StatusCode::OK, Json(json!({"deactivated": true, "agent_id": agent_id}))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("store_failed: {}", e)})),
        ),
    }
}

/// Canonical string that the sender signs — binds all envelope fields together.
fn a2a_canonical_string(
    envelope_id: &str,
    sender_id: &str,
    recipient_id: &str,
    payload_hash: &str,
    nonce: &str,
    sent_unix_ms: i64,
    expires_unix_ms: i64,
) -> String {
    format!(
        "{}|{}|{}|{}|{}|{}|{}",
        envelope_id, sender_id, recipient_id, payload_hash, nonce, sent_unix_ms, expires_unix_ms
    )
}

#[derive(Deserialize)]
struct A2aSendRequest {
    envelope_id: String,
    sender_id: String,
    recipient_id: String,
    /// SHA-256 hex of the payload (payload itself does not transit the gate)
    payload_hash: String,
    nonce: String,
    sent_unix_ms: i64,
    expires_unix_ms: i64,
    /// Sender's Ed25519 signature (hex) over the canonical envelope string
    signature: String,
}

async fn handle_a2a_send(
    State(app): State<AppState>,
    Json(req): Json<A2aSendRequest>,
) -> impl IntoResponse {
    let now = now_unix_ms();

    // 1. Sender must have a registered, active key
    let sender_key = match app.storage.get_agent_key(&req.sender_id).await {
        Ok(Some(k)) if k.active => k,
        Ok(_) => {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "unregistered_sender", "sender_id": req.sender_id})),
            );
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("storage_error: {}", e)})),
            );
        }
    };

    // 2. Verify sender's Ed25519 signature over the canonical envelope
    let canonical = a2a_canonical_string(
        &req.envelope_id, &req.sender_id, &req.recipient_id,
        &req.payload_hash, &req.nonce, req.sent_unix_ms, req.expires_unix_ms,
    );
    let key_bytes: [u8; 32] = match hex::decode(&sender_key.public_key_hex)
        .ok().and_then(|b| b.try_into().ok()) {
        Some(b) => b,
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "stored_key_corrupt"})),
            );
        }
    };
    let vk = match ed25519_dalek::VerifyingKey::from_bytes(&key_bytes) {
        Ok(v) => v,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "stored_key_invalid"})),
            );
        }
    };
    let sig_bytes: [u8; 64] = match hex::decode(&req.signature)
        .ok().and_then(|b| b.try_into().ok()) {
        Some(b) => b,
        None => {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "invalid_signature: malformed hex"})),
            );
        }
    };
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    if vk.verify(canonical.as_bytes(), &sig).is_err() {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "invalid_signature: envelope signature verification failed"})),
        );
    }

    // 3. Expiry and clock-skew checks
    if req.expires_unix_ms <= now {
        return (
            StatusCode::GONE,
            Json(json!({"error": "envelope_expired"})),
        );
    }
    const MAX_CLOCK_SKEW_MS: i64 = 60_000;
    if req.sent_unix_ms > now + MAX_CLOCK_SKEW_MS {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "sent_timestamp_in_future"})),
        );
    }

    // 4. Sender and recipient must not be revoked
    if app.storage.check_revocation(&req.sender_id).await.ok().flatten().is_some() {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "sender_revoked", "sender_id": req.sender_id})),
        );
    }
    if app.storage.check_revocation(&req.recipient_id).await.ok().flatten().is_some() {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "recipient_revoked", "recipient_id": req.recipient_id})),
        );
    }

    // 5. Recipient must have a registered key (otherwise the envelope can't be
    //    meaningfully verified by the recipient's side of the protocol)
    match app.storage.get_agent_key(&req.recipient_id).await {
        Ok(Some(k)) if k.active => {}
        Ok(_) => {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "unregistered_recipient", "recipient_id": req.recipient_id})),
            );
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("storage_error: {}", e)})),
            );
        }
    }

    // 6. Gate-signed delivery receipt — evidence that the envelope passed checks
    let receipt_sig = app.keys.sign_decision(&format!(
        "a2a-deliver:{}:{}:{}",
        req.envelope_id, req.sender_id, req.recipient_id
    ));

    let rec = A2aEnvelopeRecord {
        envelope_id: req.envelope_id.clone(),
        sender_id: req.sender_id.clone(),
        recipient_id: req.recipient_id.clone(),
        payload_hash: req.payload_hash.clone(),
        nonce: req.nonce.clone(),
        sent_unix_ms: req.sent_unix_ms,
        expires_unix_ms: req.expires_unix_ms,
        sender_signature: req.signature.clone(),
        gate_receipt_signature: receipt_sig.clone(),
        delivered: false,
        delivered_unix_ms: None,
    };

    match app.storage.store_a2a_envelope(rec).await {
        Ok(()) => (
            StatusCode::OK,
            Json(json!({
                "accepted": true,
                "envelope_id": req.envelope_id,
                "gate_receipt": receipt_sig,
                "verifying_key": hex::encode(app.keys.vk.to_bytes()),
            })),
        ),
        // envelope_id PK or (sender_id, nonce) UNIQUE violation → replay
        Err(StorageError::Conflict) => (
            StatusCode::CONFLICT,
            Json(json!({"error": "replay_detected", "envelope_id": req.envelope_id})),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("store_failed: {}", e)})),
        ),
    }
}

/// GET /a2a/inbox/:agent_id — fetch undelivered envelopes.
/// When JWT is configured, the verified sub must equal agent_id.
async fn handle_a2a_inbox(
    State(app): State<AppState>,
    Path(agent_id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if app.jwt_config.is_some() {
        match extract_agent_id(&headers, &app.jwt_config, &agent_id).await {
            Ok(verified) if verified == agent_id => {}
            Ok(_) => {
                return (
                    StatusCode::FORBIDDEN,
                    Json(json!({"error": "inbox_access_denied: JWT sub does not match recipient"})),
                );
            }
            Err(e) => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"error": format!("identity_verification_failed: {}", e)})),
                );
            }
        }
    }

    match app.storage.get_a2a_inbox(&agent_id).await {
        Ok(envelopes) => (
            StatusCode::OK,
            Json(json!({
                "agent_id": agent_id,
                "envelopes": envelopes,
            })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("storage_error: {}", e)})),
        ),
    }
}

/// POST /a2a/ack/:envelope_id — recipient acknowledges delivery.
/// Body: {"agent_id": "..."} — must match envelope recipient (JWT-enforced if configured).
async fn handle_a2a_ack(
    State(app): State<AppState>,
    Path(envelope_id): Path<String>,
    headers: HeaderMap,
    Json(req): Json<serde_json::Value>,
) -> impl IntoResponse {
    let agent_id = req.get("agent_id").and_then(|v| v.as_str()).unwrap_or("").to_string();

    if app.jwt_config.is_some() {
        match extract_agent_id(&headers, &app.jwt_config, &agent_id).await {
            Ok(verified) if verified == agent_id => {}
            Ok(_) => {
                return (
                    StatusCode::FORBIDDEN,
                    Json(json!({"error": "ack_denied: JWT sub does not match agent_id"})),
                );
            }
            Err(e) => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"error": format!("identity_verification_failed: {}", e)})),
                );
            }
        }
    }

    match app.storage.mark_a2a_delivered(&envelope_id, now_unix_ms()).await {
        Ok(()) => (StatusCode::OK, Json(json!({"delivered": true, "envelope_id": envelope_id}))),
        Err(StorageError::Conflict) => (
            StatusCode::CONFLICT,
            Json(json!({"error": "already_delivered_or_not_found"})),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("storage_error: {}", e)})),
        ),
    }
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

    // Admin API key — if DGV_ADMIN_KEY is set, admin endpoints require X-Admin-Key header
    let admin_key = std::env::var("DGV_ADMIN_KEY").ok();
    if admin_key.is_some() {
        println!("Admin auth: enabled (X-Admin-Key required for admin endpoints)");
    } else {
        println!("Admin auth: disabled (DGV_ADMIN_KEY not set — dev mode only)");
    }

    // JWT verification — if DGV_JWT_SECRET, DGV_JWT_PUBLIC_KEY, or DGV_JWT_JWKS_URL is set,
    // /govern and /execute require a valid JWT. The sub claim becomes the agent_id.
    let jwt_config = {
        let secret = std::env::var("DGV_JWT_SECRET").ok();
        let public_key_pem = std::env::var("DGV_JWT_PUBLIC_KEY").ok();
        let jwks_url = std::env::var("DGV_JWT_JWKS_URL").ok();
        let issuer = std::env::var("DGV_JWT_ISSUER").ok();
        let audience = std::env::var("DGV_JWT_AUDIENCE").ok();

        if secret.is_some() || public_key_pem.is_some() || jwks_url.is_some() {
            let mode = if jwks_url.is_some() { "JWKS" } else if public_key_pem.is_some() { "RS256" } else { "HS256" };
            println!("JWT auth: enabled ({} mode — agents must present valid JWT)", mode);
            Some(JwtConfig {
                secret,
                public_key_pem,
                jwks_url,
                issuer,
                audience,
            })
        } else {
            println!("JWT auth: disabled (no DGV_JWT_SECRET, DGV_JWT_PUBLIC_KEY, or DGV_JWT_JWKS_URL)");
            None
        }
    };

    // Semantic verifier webhook — optional external service for justification analysis.
    // The gate performs no LLM analysis itself; this delegates to a pluggable verifier.
    let semantic_verifier_url = std::env::var("DGV_SEMANTIC_VERIFIER_URL").ok();
    let semantic_fail_closed = std::env::var("DGV_SEMANTIC_FAIL_CLOSED")
        .map(|v| v == "1" || v == "true").unwrap_or(false);
    if semantic_verifier_url.is_some() {
        println!("Semantic verifier: enabled (fail_closed={})", semantic_fail_closed);
    }

    let app_state = AppState {
        storage,
        keys,
        counters: Arc::new(std::sync::Mutex::new(Counters::default())),
        rate_limit: Arc::new(std::sync::RwLock::new(rate_limit)),
        admin_key: admin_key.clone(),
        jwt_config,
        tool_health: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        semantic_verifier_url,
        semantic_fail_closed,
    };

    // Public routes (no auth required)
    let public_routes = Router::new()
        .route("/govern", post(handle_govern))
        .route("/execute", post(handle_execute))
        .route("/verify/:run_id", get(handle_verify))
        .route("/health", get(handle_health))
        .route("/stats", get(handle_stats))
        .route("/policies/:tool/:action", get(handle_get_policy))
        .route("/revocations", get(list_revocations))
        .route("/approve/:token_id", post(handle_approve))
        .route("/tool-health/report", post(handle_tool_health_report))
        .route("/tool-health", get(handle_tool_health))
        .route("/a2a/send", post(handle_a2a_send))
        .route("/a2a/inbox/:agent_id", get(handle_a2a_inbox))
        .route("/a2a/ack/:envelope_id", post(handle_a2a_ack))
        .route("/config/rate-limit", get(handle_get_rate_limit));

    // Admin routes (require X-Admin-Key when DGV_ADMIN_KEY is set)
    let admin_routes = Router::new()
        .route("/policies", post(handle_store_policy))
        .route("/policies/load-file", post(handle_load_policy_file))
        .route("/revocations", post(handle_revoke))
        .route("/tenant/:tenant_id/policies", post(handle_store_tenant_policy))
        .route("/config/rate-limit", put(handle_update_rate_limit))
        .route("/tool-health/reset/:tool", post(handle_tool_health_reset))
        .route("/agents/keys", post(handle_register_agent_key))
        .route("/agents/keys/:agent_id", delete(handle_deactivate_agent_key))
        .route_layer(middleware::from_fn_with_state(
            app_state.clone(),
            admin_auth_middleware,
        ));

    // CORS — permissive in dev, restrictive in production via DGV_CORS_ORIGINS
    let cors_origins = std::env::var("DGV_CORS_ORIGINS")
        .unwrap_or_else(|_| "*".to_string());
    let cors = if cors_origins == "*" {
        CorsLayer::permissive()
    } else {
        let origins: Vec<axum::http::HeaderValue> = cors_origins
            .split(',')
            .filter_map(|s| s.trim().parse().ok())
            .collect();
        CorsLayer::new()
            .allow_origin(tower_http::cors::AllowOrigin::list(origins))
            .allow_methods([axum::http::Method::GET, axum::http::Method::POST, axum::http::Method::PUT])
            .allow_headers(Any)
    };
    println!("CORS: {}", if cors_origins == "*" { "permissive (*)" } else { "restricted" });

    let app = public_routes
        .merge(admin_routes)
        .with_state(app_state)
        .layer(cors);

    let addr = std::env::var("DGV_LISTEN_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:7878".to_string());
    println!("Listening on http://{}", addr);
    println!("");
    println!("Endpoints:");
    println!("  POST /govern                        - evaluate proposal, return signed decision");
    println!("  POST /execute                       - verify token, mark consumed, return receipt");
    println!("  POST /approve/:token_id             - approve a token (for multi-approval policies)");
    println!("  GET  /verify/:run_id               - re-derive decision hash, compare to stored");
    println!("  GET  /health                        - liveness probe");
    println!("  GET  /stats                         - decision/token counters");
    println!("  GET  /policies/:tool/:action        - get active policy");
    println!("  GET  /revocations                   - list revocations");
    println!("  GET  /config/rate-limit             - get rate limit config");
    println!("  ── Admin endpoints (require X-Admin-Key when DGV_ADMIN_KEY is set) ──");
    println!("  POST /policies                      - store a policy (signed)");
    println!("  POST /policies/load-file            - load policies from YAML/JSON file");
    println!("  POST /revocations                   - revoke an actor");
    println!("  POST /tenant/:tenant_id/policies    - store tenant-specific policy (signed)");
    println!("  PUT  /config/rate-limit             - update rate limit config");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
