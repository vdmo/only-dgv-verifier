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
    A2aEnvelopeRecord, AgentKeyRecord, ApprovalRecord, DecisionRecord, DelegationRecord,
    PolicyRecord, PostgresStorage, RevocationRecord, SqliteStorage, Storage, StorageError,
    TokenRecord,
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

// ── Structured logging ───────────────────────────────────────────────────────
// DGV_LOG_FORMAT=json emits one JSON object per line for log aggregation;
// anything else (default) emits human-readable text.

fn log_format_json() -> bool {
    static JSON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *JSON.get_or_init(|| {
        std::env::var("DGV_LOG_FORMAT")
            .map(|v| v.eq_ignore_ascii_case("json"))
            .unwrap_or(false)
    })
}

fn log_event(level: &str, event: &str, fields: serde_json::Value) {
    if log_format_json() {
        let mut obj = serde_json::Map::new();
        obj.insert("ts_unix_ms".into(), json!(now_unix_ms()));
        obj.insert("level".into(), json!(level));
        obj.insert("event".into(), json!(event));
        if let serde_json::Value::Object(extra) = fields {
            obj.extend(extra);
        }
        println!("{}", serde_json::Value::Object(obj));
    } else {
        let rendered = match &fields {
            serde_json::Value::Object(m) if !m.is_empty() => {
                let pairs: Vec<String> = m.iter()
                    .map(|(k, v)| format!("{}={}", k, v))
                    .collect();
                format!(" [{}]", pairs.join(" "))
            }
            _ => String::new(),
        };
        println!("[{}] {}{}", level.to_uppercase(), event, rendered);
    }
}

/// Gate startup instant for uptime reporting.
static START_UNIX_MS: std::sync::OnceLock<i64> = std::sync::OnceLock::new();

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

/// Monotonic-narrowing check for delegation: every key in `child` must exist
/// in `parent` with a recursively-narrowed-or-equal value; child arrays must
/// contain only elements present in the parent array; scalars must be equal.
/// The child can omit keys but can never add or change a value.
fn json_subset(child: &Value, parent: &Value) -> bool {
    match (child, parent) {
        (Value::Object(c), Value::Object(p)) => c
            .iter()
            .all(|(k, cv)| p.get(k).map_or(false, |pv| json_subset(cv, pv))),
        (Value::Array(c), Value::Array(p)) => {
            c.iter().all(|cv| p.iter().any(|pv| json_subset(cv, pv)))
        }
        _ => child == parent,
    }
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
    /// Partition policy — what a revocation check returning a storage *error*
    /// means. `fail_closed` (default) denies: a gate that cannot verify
    /// continuing authority must not assume it. `fail_open` restores the
    /// previous behaviour for development only.
    partition_fail_closed: bool,
    /// Peer gate base URLs that receive signed revocation broadcasts
    /// (DGV_PEERS, comma-separated). Only locally-originated revocations are
    /// broadcast — gossiped revocations are never re-gossiped, which bounds
    /// propagation and prevents message storms.
    peers: Vec<String>,
    /// Trusted Ed25519 verifying keys for inbound gossip
    /// (DGV_GOSSIP_KEYS, comma-separated hex). A gossip message that does not
    /// verify against one of these keys is rejected — a forged gossip cannot
    /// revoke anyone.
    gossip_keys: Vec<VerifyingKey>,
    /// Maximum delegation chain depth for /delegate (DGV_MAX_DELEGATION_DEPTH,
    /// default 3). A token at depth N cannot mint a child if N+1 would exceed
    /// this bound.
    max_delegation_depth: i64,
    /// Quorum peer gate base URLs for distributed quorum revocation checks (DGV_QUORUM_PEERS, comma-separated)
    quorum_peers: Vec<String>,
    /// Required quorum size (default: (1 + quorum_peers.len()) / 2 + 1)
    quorum_size: usize,
    /// Quorum network timeout in milliseconds (DGV_QUORUM_TIMEOUT_MS, default 1500ms)
    quorum_timeout_ms: u64,
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
    /// JWKS response cache — avoids fetching on every request.
    /// TTL via DGV_JWKS_CACHE_TTL_MS (default 300s). On unknown kid, one
    /// forced refetch handles key rotation faster than the TTL.
    jwks_cache: Arc<std::sync::Mutex<Option<JwksCacheEntry>>>,
}

struct JwksCacheEntry {
    keys: Vec<JwksKey>,
    fetched_unix_ms: i64,
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

#[derive(Debug, Deserialize, Clone)]
struct JwksKey {
    kid: String,
    kty: String, // "RSA"
    n: String,   // base64url-encoded modulus
    e: String,   // base64url-encoded exponent
    #[serde(default)]
    #[allow(dead_code)]
    alg: Option<String>,
}

/// Fetch the JWKS document, using the TTL cache when fresh.
async fn fetch_jwks(
    jwks_url: &str,
    cache: &Arc<std::sync::Mutex<Option<JwksCacheEntry>>>,
    force_refresh: bool,
) -> Result<Vec<JwksKey>, String> {
    let ttl_ms: i64 = std::env::var("DGV_JWKS_CACHE_TTL_MS")
        .ok().and_then(|v| v.parse().ok()).unwrap_or(300_000);

    if !force_refresh {
        let cached = cache.lock().unwrap().as_ref().and_then(|e| {
            if now_unix_ms() - e.fetched_unix_ms < ttl_ms {
                Some(e.keys.clone())
            } else {
                None
            }
        });
        if let Some(keys) = cached {
            return Ok(keys);
        }
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap_or_default();
    let resp = client.get(jwks_url).send().await
        .map_err(|e| format!("JWKS fetch failed: {}", e))?;
    let jwks: JwksResponse = resp.json().await
        .map_err(|e| format!("JWKS parse failed: {}", e))?;

    *cache.lock().unwrap() = Some(JwksCacheEntry {
        keys: jwks.keys.clone(),
        fetched_unix_ms: now_unix_ms(),
    });
    Ok(jwks.keys)
}

/// Fetch a JWKS and find the key matching the given kid.
/// Uses the TTL cache; on unknown kid with a fresh cache, forces one refetch
/// to handle key rotation without waiting for TTL expiry.
async fn fetch_jwks_key(
    jwks_url: &str,
    kid: &str,
    cache: &Arc<std::sync::Mutex<Option<JwksCacheEntry>>>,
) -> Result<DecodingKey, String> {
    let mut keys = fetch_jwks(jwks_url, cache, false).await?;

    if !keys.iter().any(|k| k.kid == kid) {
        // Unknown kid — may be a key rotation; force one refetch
        keys = fetch_jwks(jwks_url, cache, true).await?;
    }

    let key = keys.iter()
        .find(|k| k.kid == kid)
        .ok_or_else(|| format!("no key found for kid: {}", kid))?;

    if key.kty != "RSA" {
        return Err(format!("unsupported key type: {}", key.kty));
    }

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
        // JWKS mode — fetch the key by kid (TTL-cached)
        let kid = header.kid.ok_or("JWT missing kid header")?;
        fetch_jwks_key(jwks_url, &kid, &config.jwks_cache).await?
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
                log_event("warn", "rate_limit_check_failed", json!({"error": e.to_string()}));
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
                    log_event("warn", "circuit_breaker_half_open", json!({"tool": p.tool}));
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

    // 1. Check revocation (from persistent storage + quorum when configured)
    // Partition policy: a storage error is not "not revoked". fail_closed
    // denies — continuing authority cannot be verified, so it cannot be
    // assumed. fail_open keeps the old behaviour for development.
    let revocation = match check_revocation_with_quorum(&app, &p.agent_id).await {
        QuorumOutcome::Revoked(rev) => Some(rev),
        QuorumOutcome::ConfirmedClean => None,
        QuorumOutcome::PartitionFailure(e) => {
            if app.partition_fail_closed {
                Some(RevocationRecord {
                    actor_id: p.agent_id.clone(),
                    reason: format!("revocation_check_unavailable: {}", e),
                    revoked_unix_ms: now_unix_ms(),
                    revoked_by: "partition_policy".to_string(),
                })
            } else {
                log_event(
                    "warn",
                    "revocation_check_failed_fail_open",
                    json!({"agent_id": p.agent_id, "error": e}),
                );
                None
            }
        }
    };
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
                    log_event("warn", "policy_signature_invalid", json!({"tool": pol.tool, "action": pol.action}));
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
                log_event("warn", "unsigned_policy", json!({"tool": pol.tool, "action": pol.action}));
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
                                log_event("warn", "semantic_verifier_unparseable", json!({"error": e.to_string(), "mode": "fail_open"}));
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
                        log_event("warn", "semantic_verifier_unreachable", json!({"error": e.to_string(), "mode": "fail_open"}));
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
            granted_to: p.agent_id.clone(),
            parent_token_id: None,
            delegation_depth: 0,
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
                log_event("warn", "rate_limit_check_failed", json!({"error": e.to_string()}));
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

    // 3b. Grantee binding — a token is usable only by the agent it was granted
    // to (the /govern proposer, or the delegatee for delegated tokens).
    // Tokens predating this field (empty granted_to) skip the check.
    if !token.granted_to.is_empty() && token.granted_to != req.executor_id {
        return (
            StatusCode::FORBIDDEN,
            Json(ExecuteResponse {
                allowed: false,
                deny_reason: Some("token_grantee_mismatch".to_string()),
                receipt: json!({
                    "run_id": run_id,
                    "verified": false,
                    "granted_to": token.granted_to,
                    "executor_id": req.executor_id,
                }),
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

    // 6. Check revocation (T₁ authority check with quorum when configured)
    // Partition policy applies here too: a storage error at T₁ means
    // continuing authority cannot be verified.
    match check_revocation_with_quorum(&app, &req.executor_id).await {
        QuorumOutcome::Revoked(rev) => {
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
        QuorumOutcome::ConfirmedClean => {}
        QuorumOutcome::PartitionFailure(e) => {
            if app.partition_fail_closed {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(ExecuteResponse {
                        allowed: false,
                        deny_reason: Some(format!(
                            "revocation_check_unavailable_at_t1: {}",
                            e
                        )),
                        receipt: json!({"run_id": run_id, "verified": false, "partition": true}),
                        run_id,
                    }),
                );
            }
            log_event(
                "warn",
                "revocation_check_failed_fail_open_t1",
                json!({"executor_id": req.executor_id, "error": e}),
            );
        }
    }

    // 6a. Delegation chain revocation — a delegated token's authority flows
    // from its ancestors; if any ancestor's grantee (i.e. delegator) is
    // revoked, delegated authority dies with it. Bounded by depth.
    {
        let mut ancestor = token.parent_token_id.clone();
        for _ in 0..8 {
            let pid = match ancestor {
                Some(ref p) => p.clone(),
                None => break,
            };
            let ptok = match app.storage.get_token(&pid).await {
                Ok(Some(t)) => t,
                _ => break,
            };
            if !ptok.granted_to.is_empty() {
                match check_revocation_with_quorum(&app, &ptok.granted_to).await {
                    QuorumOutcome::Revoked(rev) => {
                        return (
                            StatusCode::FORBIDDEN,
                            Json(ExecuteResponse {
                                allowed: false,
                                deny_reason: Some(format!(
                                    "delegated_authority_revoked: ancestor {} revoked ({})",
                                    ptok.granted_to, rev.reason
                                )),
                                receipt: json!({"run_id": run_id, "verified": false, "revoked_ancestor": ptok.granted_to}),
                                run_id,
                            }),
                        );
                    }
                    QuorumOutcome::ConfirmedClean => {}
                    QuorumOutcome::PartitionFailure(e) => {
                        if app.partition_fail_closed {
                            return (
                                StatusCode::SERVICE_UNAVAILABLE,
                                Json(ExecuteResponse {
                                    allowed: false,
                                    deny_reason: Some(format!("ancestor_revocation_check_unavailable: {}", e)),
                                    receipt: json!({"run_id": run_id, "verified": false, "partition": true}),
                                    run_id,
                                }),
                            );
                        }
                    }
                }
            }
            ancestor = ptok.parent_token_id;
        }
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
    match app.storage.store_revocation(rec.clone()).await {
        Ok(()) => {
            broadcast_revocation(&app, &rec);
            (StatusCode::OK, Json(json!({"revoked": true, "peers": app.peers.len()})))
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))),
    }
}

// ── Revocation gossip ───────────────────────────────────────────────────────
// Signed, one-hop broadcast of locally-originated revocations to peer gates.
// This is authenticated *propagation*, not consensus: peers merge via
// idempotent upsert, and received gossip is never re-gossiped.

#[derive(Serialize, Deserialize, Clone)]
struct GossipRevocation {
    actor_id: String,
    reason: String,
    revoked_unix_ms: i64,
    revoked_by: String,
    /// Hex of the originating gate's verifying key — identifies the signer
    /// and is bound into the signature.
    origin: String,
    signature: String,
}

fn gossip_canonical(g: &GossipRevocation) -> String {
    format!(
        "dgv-revocation-v1|{}|{}|{}|{}|{}",
        g.actor_id, g.reason, g.revoked_unix_ms, g.revoked_by, g.origin
    )
}

fn broadcast_revocation(app: &AppState, rec: &RevocationRecord) {
    if app.peers.is_empty() {
        return;
    }
    let origin = hex::encode(app.keys.vk.to_bytes());
    let mut msg = GossipRevocation {
        actor_id: rec.actor_id.clone(),
        reason: rec.reason.clone(),
        revoked_unix_ms: rec.revoked_unix_ms,
        revoked_by: rec.revoked_by.clone(),
        origin: origin.clone(),
        signature: String::new(),
    };
    let sig = app.keys.sk.sign(gossip_canonical(&msg).as_bytes());
    msg.signature = hex::encode(sig.to_bytes());

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .unwrap_or_default();
    for peer in &app.peers {
        let url = format!("{}/revocations/gossip", peer);
        let body = msg.clone();
        let c = client.clone();
        tokio::spawn(async move {
            match c.post(&url).json(&body).send().await {
                Ok(r) if r.status().is_success() => {}
                Ok(r) => log_event("warn", "gossip_rejected", json!({"peer": url, "status": r.status().as_u16()})),
                Err(e) => log_event("warn", "gossip_unreachable", json!({"peer": url, "error": e.to_string()})),
            }
        });
    }
}

/// POST /revocations/gossip — receive a signed revocation from a peer gate.
/// The signature must verify against DGV_GOSSIP_KEYS; otherwise the message
/// is forged and rejected. Received gossip is merged via idempotent upsert
/// and is never re-broadcast (one-hop bound, no storms).
async fn handle_gossip_revocation(
    State(app): State<AppState>,
    Json(msg): Json<GossipRevocation>,
) -> impl IntoResponse {
    if app.gossip_keys.is_empty() {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "gossip_not_configured"})),
        );
    }
    let sig_bytes = match hex::decode(&msg.signature)
        .ok()
        .and_then(|b| <[u8; 64]>::try_from(b.as_slice()).ok())
    {
        Some(b) => b,
        None => {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "invalid_signature: malformed hex"})),
            );
        }
    };
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    let canonical = gossip_canonical(&msg);
    if !app.gossip_keys.iter().any(|vk| vk.verify(canonical.as_bytes(), &sig).is_ok()) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "invalid_signature: untrusted signer"})),
        );
    }

    // Merge with a monotonicity guard: an existing revocation with a newer
    // timestamp wins, so stale gossip cannot weaken the recorded state.
    match app.storage.check_revocation(&msg.actor_id).await {
        Ok(Some(existing)) if existing.revoked_unix_ms >= msg.revoked_unix_ms => {
            return (
                StatusCode::OK,
                Json(json!({"stored": false, "reason": "already_known_or_newer"})),
            );
        }
        Ok(_) => {}
        Err(e) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": format!("storage_error: {}", e)})),
            );
        }
    }
    // Store byte-identically to the origin's record — digests only converge
    // if every node holds the same canonical entries. The signer is already
    // established by signature verification, so no provenance rewrite is
    // needed in the record itself.
    let rec = RevocationRecord {
        actor_id: msg.actor_id,
        reason: msg.reason,
        revoked_unix_ms: msg.revoked_unix_ms,
        revoked_by: msg.revoked_by,
    };
    match app.storage.store_revocation(rec).await {
        Ok(()) => (StatusCode::OK, Json(json!({"stored": true}))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        ),
    }
}

/// GET /revocations/digest — cheap divergence detector. Sorts revocations by
/// actor_id, hashes a canonical line per entry; two nodes with identical
/// revocation state produce identical digests.
async fn handle_revocations_digest(State(app): State<AppState>) -> impl IntoResponse {
    match app.storage.list_revocations().await {
        Ok(mut list) => {
            list.sort_by(|a, b| a.actor_id.cmp(&b.actor_id));
            let canonical: String = list
                .iter()
                .map(|r| format!("{}|{}|{}|{}", r.actor_id, r.revoked_unix_ms, r.revoked_by, r.reason))
                .collect::<Vec<_>>()
                .join("\n");
            let max_ts = list.iter().map(|r| r.revoked_unix_ms).max().unwrap_or(0);
            (
                StatusCode::OK,
                Json(json!({
                    "count": list.len(),
                    "max_revoked_unix_ms": max_ts,
                    "sha256": sha256_hex(&canonical),
                })),
            )
        }
        Err(e) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": e.to_string()})),
        ),
    }
}

// ── GET /revocations ────────────────────────────────────────────────────────

async fn list_revocations(State(app): State<AppState>) -> impl IntoResponse {
    match app.storage.list_revocations().await {
        Ok(list) => (StatusCode::OK, Json(serde_json::to_value(list).unwrap_or_default())),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))),
    }
}

// ── Quorum & Merkle Anti-Entropy ─────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone, Debug)]
struct QuorumCheckRequest {
    actor_id: String,
    nonce: String,
    timestamp_ms: i64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct QuorumCheckResponse {
    actor_id: String,
    status: String,
    record: Option<RevocationRecord>,
    responder_vk: String,
    nonce: String,
    timestamp_ms: i64,
    signature: String,
}

fn quorum_canonical(
    actor_id: &str,
    status: &str,
    nonce: &str,
    timestamp_ms: i64,
    responder_vk: &str,
) -> String {
    format!(
        "dgv-quorum-v1|{}|{}|{}|{}|{}",
        actor_id, status, nonce, timestamp_ms, responder_vk
    )
}

/// POST /revocations/quorum-check — peer query for continuing authority check.
async fn handle_quorum_check(
    State(app): State<AppState>,
    Json(req): Json<QuorumCheckRequest>,
) -> impl IntoResponse {
    let now = now_unix_ms();
    if (now - req.timestamp_ms).abs() > 60_000 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "clock_skew_exceeded"})),
        );
    }

    let (status, record) = match app.storage.check_revocation(&req.actor_id).await {
        Ok(Some(rev)) => ("revoked", Some(rev)),
        Ok(None) => ("clean", None),
        Err(e) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": format!("storage_error: {}", e)})),
            );
        }
    };

    let responder_vk = hex::encode(app.keys.vk.to_bytes());
    let canonical = quorum_canonical(&req.actor_id, status, &req.nonce, now, &responder_vk);
    let sig = app.keys.sk.sign(canonical.as_bytes());

    (
        StatusCode::OK,
        Json(json!(QuorumCheckResponse {
            actor_id: req.actor_id,
            status: status.to_string(),
            record,
            responder_vk,
            nonce: req.nonce,
            timestamp_ms: now,
            signature: hex::encode(sig.to_bytes()),
        })),
    )
}

enum QuorumOutcome {
    ConfirmedClean,
    Revoked(RevocationRecord),
    PartitionFailure(String),
}

async fn check_revocation_with_quorum(
    app: &AppState,
    actor_id: &str,
) -> QuorumOutcome {
    match app.storage.check_revocation(actor_id).await {
        Ok(Some(rev)) => return QuorumOutcome::Revoked(rev),
        Ok(None) => {}
        Err(e) => {
            return QuorumOutcome::PartitionFailure(format!("local storage error: {}", e));
        }
    }

    if app.quorum_peers.is_empty() {
        return QuorumOutcome::ConfirmedClean;
    }

    let nonce = hex::encode(rand::random::<[u8; 16]>());
    let now_ms = now_unix_ms();
    let req_body = QuorumCheckRequest {
        actor_id: actor_id.to_string(),
        nonce: nonce.clone(),
        timestamp_ms: now_ms,
    };

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(app.quorum_timeout_ms))
        .build()
        .unwrap_or_default();

    let mut tasks = Vec::new();
    for peer in &app.quorum_peers {
        let url = format!("{}/revocations/quorum-check", peer);
        let c = client.clone();
        let body = req_body.clone();
        tasks.push(async move {
            c.post(&url).json(&body).send().await
        });
    }

    let results = futures::future::join_all(tasks).await;
    let mut clean_votes = 1usize;

    for res in results {
        if let Ok(resp) = res {
            if resp.status().is_success() {
                if let Ok(qc) = resp.json::<QuorumCheckResponse>().await {
                    if qc.nonce != nonce || qc.actor_id != actor_id {
                        continue;
                    }
                    if (now_unix_ms() - qc.timestamp_ms).abs() > 60_000 {
                        continue;
                    }
                    if let Ok(sig_bytes) = hex::decode(&qc.signature) {
                        if sig_bytes.len() == 64 {
                            if let Ok(sig) = ed25519_dalek::Signature::from_slice(&sig_bytes) {
                                if let Ok(vk_bytes) = hex::decode(&qc.responder_vk) {
                                    if vk_bytes.len() == 32 {
                                        if let Ok(vk) = VerifyingKey::from_bytes(&vk_bytes.try_into().unwrap_or([0u8; 32])) {
                                            let canonical = quorum_canonical(
                                                &qc.actor_id,
                                                &qc.status,
                                                &qc.nonce,
                                                qc.timestamp_ms,
                                                &qc.responder_vk,
                                            );
                                            let is_trusted = app.gossip_keys.is_empty()
                                                || app.gossip_keys.iter().any(|k| k == &vk);
                                            if is_trusted && vk.verify(canonical.as_bytes(), &sig).is_ok() {
                                                if qc.status == "revoked" {
                                                    if let Some(rec) = qc.record {
                                                        let _ = app.storage.store_revocation(rec.clone()).await;
                                                        return QuorumOutcome::Revoked(rec);
                                                    }
                                                } else if qc.status == "clean" {
                                                    clean_votes += 1;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if clean_votes >= app.quorum_size {
        QuorumOutcome::ConfirmedClean
    } else {
        QuorumOutcome::PartitionFailure(format!(
            "insufficient quorum: received {} clean votes out of {} required",
            clean_votes, app.quorum_size
        ))
    }
}

// ── Merkle Anti-Entropy ──────────────────────────────────────────────────────

fn merkle_bucket_char(actor_id: &str) -> char {
    let h = sha256_hex(actor_id);
    h.chars().next().unwrap_or('0')
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct MerkleBucketSummary {
    count: usize,
    hash: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct MerkleTreeSummary {
    count: usize,
    tree_root: String,
    buckets: std::collections::BTreeMap<String, MerkleBucketSummary>,
}

fn compute_merkle_tree(mut list: Vec<RevocationRecord>) -> MerkleTreeSummary {
    list.sort_by(|a, b| a.actor_id.cmp(&b.actor_id));
    let mut bucket_records: std::collections::BTreeMap<char, Vec<RevocationRecord>> =
        std::collections::BTreeMap::new();
    for c in "0123456789abcdef".chars() {
        bucket_records.insert(c, Vec::new());
    }
    for r in list {
        let b = merkle_bucket_char(&r.actor_id);
        bucket_records.entry(b).or_default().push(r);
    }

    let mut buckets = std::collections::BTreeMap::new();
    let mut concatenated_hashes = String::new();

    for (c, recs) in bucket_records {
        let canonical: String = recs
            .iter()
            .map(|r| {
                format!(
                    "{}|{}|{}|{}",
                    r.actor_id, r.revoked_unix_ms, r.revoked_by, r.reason
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        let h = sha256_hex(&canonical);
        concatenated_hashes.push_str(&h);
        buckets.insert(
            c.to_string(),
            MerkleBucketSummary {
                count: recs.len(),
                hash: h,
            },
        );
    }

    let tree_root = sha256_hex(&concatenated_hashes);
    let total_count = buckets.values().map(|b| b.count).sum();

    MerkleTreeSummary {
        count: total_count,
        tree_root,
        buckets,
    }
}

/// GET /revocations/merkle — returns 16-bucket prefix Merkle tree of revocations.
async fn handle_revocations_merkle(State(app): State<AppState>) -> impl IntoResponse {
    match app.storage.list_revocations().await {
        Ok(list) => {
            let tree = compute_merkle_tree(list);
            (StatusCode::OK, Json(json!(tree)))
        }
        Err(e) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": e.to_string()})),
        ),
    }
}

/// GET /revocations/bucket/:prefix — returns records in a specific 1-char prefix bucket ('0'..'f').
async fn handle_revocations_bucket(
    State(app): State<AppState>,
    Path(prefix): Path<String>,
) -> impl IntoResponse {
    let p_char = match prefix.chars().next() {
        Some(c) if c.is_ascii_hexdigit() => c.to_ascii_lowercase(),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "invalid_prefix: must be single hex char [0-9a-f]"})),
            );
        }
    };

    match app.storage.list_revocations().await {
        Ok(list) => {
            let filtered: Vec<RevocationRecord> = list
                .into_iter()
                .filter(|r| merkle_bucket_char(&r.actor_id) == p_char)
                .collect();
            (StatusCode::OK, Json(json!({
                "prefix": p_char.to_string(),
                "count": filtered.len(),
                "records": filtered,
            })))
        }
        Err(e) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": e.to_string()})),
        ),
    }
}

#[derive(Deserialize)]
struct ReconcileRequest {
    peer: String,
}

#[derive(Serialize)]
struct ReconcileResponse {
    reconciled: bool,
    divergent: bool,
    differing_buckets: Vec<String>,
    pulled_count: usize,
    pushed_count: usize,
    tree_root: String,
}

async fn reconcile_with_peer(
    app: &AppState,
    peer_url: &str,
) -> Result<ReconcileResponse, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| e.to_string())?;

    let peer_merkle_url = format!("{}/revocations/merkle", peer_url.trim_end_matches('/'));
    let resp = client.get(&peer_merkle_url).send().await.map_err(|e| format!("peer unreachable: {}", e))?;
    if !resp.status().is_success() {
        return Err(format!("peer returned HTTP {}", resp.status()));
    }
    let peer_tree = resp.json::<MerkleTreeSummary>().await.map_err(|e| format!("invalid peer response: {}", e))?;

    let local_list = app.storage.list_revocations().await.map_err(|e| e.to_string())?;
    let local_tree = compute_merkle_tree(local_list.clone());

    if local_tree.tree_root == peer_tree.tree_root {
        return Ok(ReconcileResponse {
            reconciled: true,
            divergent: false,
            differing_buckets: Vec::new(),
            pulled_count: 0,
            pushed_count: 0,
            tree_root: local_tree.tree_root,
        });
    }

    let mut differing = Vec::new();
    for c in "0123456789abcdef".chars() {
        let key = c.to_string();
        let local_hash = local_tree.buckets.get(&key).map(|b| &b.hash);
        let peer_hash = peer_tree.buckets.get(&key).map(|b| &b.hash);
        if local_hash != peer_hash {
            differing.push(key);
        }
    }

    let mut pulled_count = 0usize;
    let mut pushed_count = 0usize;

    for prefix in &differing {
        let bucket_url = format!("{}/revocations/bucket/{}", peer_url.trim_end_matches('/'), prefix);
        if let Ok(b_resp) = client.get(&bucket_url).send().await {
            if b_resp.status().is_success() {
                if let Ok(data) = b_resp.json::<serde_json::Value>().await {
                    if let Some(records) = data.get("records").and_then(|v| v.as_array()) {
                        for item in records {
                            if let Ok(rec) = serde_json::from_value::<RevocationRecord>(item.clone()) {
                                match app.storage.check_revocation(&rec.actor_id).await {
                                    Ok(Some(existing)) if existing.revoked_unix_ms >= rec.revoked_unix_ms => {}
                                    _ => {
                                        if app.storage.store_revocation(rec).await.is_ok() {
                                            pulled_count += 1;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        let p_char = prefix.chars().next().unwrap_or('0');
        for local_rec in &local_list {
            if merkle_bucket_char(&local_rec.actor_id) == p_char {
                let origin = hex::encode(app.keys.vk.to_bytes());
                let mut msg = GossipRevocation {
                    actor_id: local_rec.actor_id.clone(),
                    reason: local_rec.reason.clone(),
                    revoked_unix_ms: local_rec.revoked_unix_ms,
                    revoked_by: local_rec.revoked_by.clone(),
                    origin: origin.clone(),
                    signature: String::new(),
                };
                let sig = app.keys.sk.sign(gossip_canonical(&msg).as_bytes());
                msg.signature = hex::encode(sig.to_bytes());

                let gossip_url = format!("{}/revocations/gossip", peer_url.trim_end_matches('/'));
                if client.post(&gossip_url).json(&msg).send().await.is_ok() {
                    pushed_count += 1;
                }
            }
        }
    }

    let new_list = app.storage.list_revocations().await.map_err(|e| e.to_string())?;
    let new_tree = compute_merkle_tree(new_list);

    Ok(ReconcileResponse {
        reconciled: true,
        divergent: true,
        differing_buckets: differing,
        pulled_count,
        pushed_count,
        tree_root: new_tree.tree_root,
    })
}

/// POST /revocations/reconcile — trigger divergence reconciliation against a peer.
async fn handle_reconcile(
    State(app): State<AppState>,
    Json(req): Json<ReconcileRequest>,
) -> impl IntoResponse {
    match reconcile_with_peer(&app, &req.peer).await {
        Ok(resp) => (StatusCode::OK, Json(json!(resp))),
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({"error": e})),
        ),
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
    /// optional hex-encoded X25519 public key — enables ECDH-sealed payloads
    #[serde(default)]
    enc_public_key_hex: Option<String>,
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

    // X25519 public keys are any 32-byte value; only hex/length needs checking.
    if let Some(enc) = &req.enc_public_key_hex {
        match hex::decode(enc) {
            Ok(b) if b.len() == 32 => {}
            _ => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": "invalid_enc_public_key: expected 64 hex chars (32 bytes)"})),
                );
            }
        }
    }

    let rec = AgentKeyRecord {
        agent_id: req.agent_id.clone(),
        public_key_hex: req.public_key_hex.clone(),
        enc_public_key_hex: req.enc_public_key_hex.clone(),
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

/// GET /agents/keys/:agent_id — public key lookup so agents can fetch a
/// peer's signing + encryption keys from the trusted registry rather than
/// trusting keys delivered in-band with a message.
async fn handle_get_agent_key(
    State(app): State<AppState>,
    Path(agent_id): Path<String>,
) -> impl IntoResponse {
    match app.storage.get_agent_key(&agent_id).await {
        Ok(Some(k)) => (
            StatusCode::OK,
            Json(json!({
                "agent_id": k.agent_id,
                "public_key_hex": k.public_key_hex,
                "enc_public_key_hex": k.enc_public_key_hex,
                "registered_unix_ms": k.registered_unix_ms,
                "active": k.active,
            })),
        ),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "agent_key_not_found", "agent_id": agent_id})),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("storage_error: {}", e)})),
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

/// Canonical string the delegator signs — binds the delegation request.
fn delegate_canonical_string(
    parent_token_id: &str,
    delegator_id: &str,
    delegatee_id: &str,
    params_hash: &str,
    expires_unix_ms: i64,
) -> String {
    format!(
        "dgv-delegate-v1|{}|{}|{}|{}|{}",
        parent_token_id, delegator_id, delegatee_id, params_hash, expires_unix_ms
    )
}

#[derive(Deserialize)]
struct DelegateRequest {
    parent_token_id: String,
    /// Must equal the parent token's granted_to — proven by signature, not claim.
    delegator_id: String,
    delegatee_id: String,
    /// Narrowed params — must be a JSON subset of the parent's params
    /// (omit keys to narrow; values may never be added or changed). Absent =
    /// inherit unchanged.
    params: Option<Value>,
    /// Requested child expiry — must not exceed the parent's expiry.
    expires_unix_ms: Option<i64>,
    /// Delegator's Ed25519 signature (hex) over the canonical delegation string.
    signature: String,
}

/// POST /delegate — mint a strictly-narrower child token from a live parent
/// token. Authority can only decay: same tool+action, params ⊆ parent's,
/// expiry ≤ parent's, approvals inherited, depth bounded. Every delegation is
/// signed by the delegator's registered key and recorded as a receipt-chain
/// DelegationRecord.
async fn handle_delegate(
    State(app): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<DelegateRequest>,
) -> impl IntoResponse {
    let now = now_unix_ms();

    // 0. JWT — if configured, the verified sub must equal delegator_id
    if app.jwt_config.is_some() {
        match extract_agent_id(&headers, &app.jwt_config, &req.delegator_id).await {
            Ok(v) if v == req.delegator_id => {}
            Ok(_) => {
                return (
                    StatusCode::FORBIDDEN,
                    Json(json!({"error": "delegator_mismatch: JWT sub != delegator_id"})),
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

    // 1. Parent token must exist, be unconsumed, and unexpired
    let parent = match app.storage.get_token(&req.parent_token_id).await {
        Ok(Some(t)) => t,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "parent_token_not_found"})),
            );
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("storage_error: {}", e)})),
            );
        }
    };
    if parent.consumed {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "parent_token_consumed"})),
        );
    }
    if parent.expires_unix_ms <= now {
        return (
            StatusCode::GONE,
            Json(json!({"error": "parent_token_expired"})),
        );
    }

    // 2. Delegator must be the parent token's grantee
    if parent.granted_to.is_empty() || parent.granted_to != req.delegator_id {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "delegator_mismatch",
                "granted_to": parent.granted_to,
            })),
        );
    }

    // 3. Depth bound — authority decays with each hop
    let child_depth = parent.delegation_depth + 1;
    if child_depth > app.max_delegation_depth {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "delegation_depth_exceeded",
                "max": app.max_delegation_depth,
                "parent_depth": parent.delegation_depth,
            })),
        );
    }

    // 4. Recover the parent's raw params for the subset check
    let parent_decision = match app.storage.get_decision_by_request_id(&parent.request_id).await {
        Ok(Some(d)) => d,
        Ok(None) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "parent_params_unavailable"})),
            );
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("storage_error: {}", e)})),
            );
        }
    };
    let replay: Value = serde_json::from_str(&parent_decision.replay_inputs)
        .unwrap_or(json!({}));
    let parent_params = replay.get("params").cloned().unwrap_or(json!({}));

    // 5. Child params must be a subset of the parent's — never wider
    let child_params = req.params.clone().unwrap_or_else(|| parent_params.clone());
    if !json_subset(&child_params, &parent_params) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "params_not_narrower"})),
        );
    }
    let child_params_hash = compute_params_hash(&child_params);

    // 6. Child expiry can only tighten the parent's
    let child_expiry = req.expires_unix_ms.unwrap_or(parent.expires_unix_ms);
    if child_expiry > parent.expires_unix_ms {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "expiry_exceeds_parent",
                "parent_expires_unix_ms": parent.expires_unix_ms,
            })),
        );
    }
    if child_expiry <= now {
        return (
            StatusCode::GONE,
            Json(json!({"error": "child_expiry_in_past"})),
        );
    }

    // 7. Delegator must hold a registered, active key — verify the signature
    let delegator_key = match app.storage.get_agent_key(&req.delegator_id).await {
        Ok(Some(k)) if k.active => k,
        Ok(_) => {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "unregistered_delegator", "delegator_id": req.delegator_id})),
            );
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("storage_error: {}", e)})),
            );
        }
    };
    let canonical = delegate_canonical_string(
        &req.parent_token_id, &req.delegator_id, &req.delegatee_id,
        &child_params_hash, child_expiry,
    );
    let sig_ok = hex::decode(&delegator_key.public_key_hex)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
        .and_then(|b| ed25519_dalek::VerifyingKey::from_bytes(&b).ok())
        .zip(hex::decode(&req.signature).ok()
            .and_then(|b| <[u8; 64]>::try_from(b.as_slice()).ok())
            .map(|b| ed25519_dalek::Signature::from_bytes(&b)))
        .map_or(false, |(vk, sig)| {
            vk.verify(canonical.as_bytes(), &sig).is_ok()
        });
    if !sig_ok {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "invalid_delegation_signature"})),
        );
    }

    // 8. Revocation checks — delegator and delegatee (partition policy applies)
    for (actor, kind) in [(&req.delegator_id, "delegator"), (&req.delegatee_id, "delegatee")] {
        match check_revocation_with_quorum(&app, actor).await {
            QuorumOutcome::Revoked(_) => {
                return (
                    StatusCode::FORBIDDEN,
                    Json(json!({"error": format!("{}_revoked", kind), "actor_id": actor})),
                );
            }
            QuorumOutcome::ConfirmedClean => {}
            QuorumOutcome::PartitionFailure(e) => {
                if app.partition_fail_closed {
                    return (
                        StatusCode::SERVICE_UNAVAILABLE,
                        Json(json!({"error": "revocation_check_unavailable", "detail": e})),
                    );
                }
                log_event("warn", "delegate_revocation_check_fail_open",
                    json!({"actor": actor, "error": e}));
            }
        }
    }

    // 9. Mint the child token — same tool+action, narrowed params/expiry,
    //    approvals inherited (never reduced)
    let delegation_id = format!("dlg_{}", &sha256_hex(&format!(
        "{}{}{}", req.parent_token_id, req.delegatee_id, now))[..16]);
    let child_token_id = format!("tok_{}", &sha256_hex(&format!(
        "{}{}", delegation_id, child_params_hash))[..16]);
    let child_request_id = format!("deleg:{}", parent.request_id);
    let child_decision_hash = sha256_hex(&format!(
        "dgv-delegation-v1|{}|{}|{}|{}|{}",
        req.parent_token_id, child_token_id, parent.tool, parent.action, child_params_hash
    ));
    let child_sig = app.keys.sign_decision(&child_decision_hash);

    let child = TokenRecord {
        token_id: child_token_id.clone(),
        request_id: child_request_id.clone(),
        tool: parent.tool.clone(),
        action: parent.action.clone(),
        params_hash: child_params_hash.clone(),
        expires_unix_ms: child_expiry,
        consumed: false,
        consumed_unix_ms: None,
        decision_hash: child_decision_hash.clone(),
        signature: child_sig.clone(),
        created_unix_ms: now,
        min_approvals: parent.min_approvals,
        granted_to: req.delegatee_id.clone(),
        parent_token_id: Some(req.parent_token_id.clone()),
        delegation_depth: child_depth,
    };
    let drec = DelegationRecord {
        delegation_id: delegation_id.clone(),
        parent_token_id: req.parent_token_id.clone(),
        child_token_id: child_token_id.clone(),
        delegator_id: req.delegator_id.clone(),
        delegatee_id: req.delegatee_id.clone(),
        signature: req.signature.clone(),
        created_unix_ms: now,
    };
    if let Err(e) = app.storage.store_token(child).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("store_failed: {}", e)})),
        );
    }
    // Persist a decision record for the delegated grant — makes the child
    // token's params recoverable for further delegation and keeps the grant
    // auditable as a governance event.
    let child_run_id = only_lang::evidence_pack::run_id_unix_ms();
    let _ = app.storage.store_decision(DecisionRecord {
        run_id: child_run_id,
        request_id: child_request_id.clone(),
        decision_hash: child_decision_hash.clone(),
        gate_state: "ALLOW".to_string(),
        reason_codes: "[\"delegated\"]".to_string(),
        replay_inputs: json!({
            "tool": parent.tool,
            "action": parent.action,
            "params": child_params,
            "agent_id": req.delegatee_id,
            "workflow": "delegation",
            "delegated_from": req.parent_token_id,
        }).to_string(),
        signature: child_sig.clone(),
        created_unix_ms: now,
    }).await;
    if let Err(e) = app.storage.store_delegation(drec).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("store_failed: {}", e)})),
        );
    }
    log_event("info", "delegation_issued", json!({
        "delegation_id": delegation_id,
        "delegator": req.delegator_id,
        "delegatee": req.delegatee_id,
        "depth": child_depth,
    }));
    (
        StatusCode::OK,
        Json(json!({
            "delegated": true,
            "delegation_id": delegation_id,
            "parent_token_id": req.parent_token_id,
            "child_token_id": child_token_id,
            "delegation_depth": child_depth,
            "tool": parent.tool,
            "action": parent.action,
            "expires_unix_ms": child_expiry,
            "gate_signature": child_sig,
            "verifying_key": hex::encode(app.keys.vk.to_bytes()),
        })),
    )
}

/// GET /delegations/:token_id — walk the delegation chain upward, returning
/// the lineage root→...→this token. Audit endpoint.
async fn handle_delegation_chain(
    State(app): State<AppState>,
    Path(token_id): Path<String>,
) -> impl IntoResponse {
    let mut chain = Vec::new();
    let mut cursor = token_id.clone();
    for _ in 0..8 {
        match app.storage.get_delegation(&cursor).await {
            Ok(Some(d)) => {
                cursor = d.parent_token_id.clone();
                chain.push(d);
            }
            Ok(None) => break,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": format!("storage_error: {}", e)})),
                );
            }
        }
    }
    chain.reverse();
    (
        StatusCode::OK,
        Json(json!({"token_id": token_id, "chain": chain, "depth": chain.len()})),
    )
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
    /// Where the ciphertext lives — "relay:<relay_url>|<queue_id>" or
    /// "direct:<url>". Opaque to the gate; delivered to the recipient verbatim.
    #[serde(default)]
    transport_ref: Option<String>,
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

    // 4. Sender and recipient must not be revoked — partition policy applies:
    // a storage error is not "not revoked".
    match check_revocation_with_quorum(&app, &req.sender_id).await {
        QuorumOutcome::Revoked(_) => {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "sender_revoked", "sender_id": req.sender_id})),
            );
        }
        QuorumOutcome::ConfirmedClean => {}
        QuorumOutcome::PartitionFailure(e) => {
            if app.partition_fail_closed {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({"error": "revocation_check_unavailable", "detail": e})),
                );
            }
            log_event("warn", "a2a_sender_revocation_check_fail_open", json!({"sender_id": req.sender_id, "error": e}));
        }
    }
    match check_revocation_with_quorum(&app, &req.recipient_id).await {
        QuorumOutcome::Revoked(_) => {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "recipient_revoked", "recipient_id": req.recipient_id})),
            );
        }
        QuorumOutcome::ConfirmedClean => {}
        QuorumOutcome::PartitionFailure(e) => {
            if app.partition_fail_closed {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({"error": "revocation_check_unavailable", "detail": e})),
                );
            }
            log_event("warn", "a2a_recipient_revocation_check_fail_open", json!({"recipient_id": req.recipient_id, "error": e}));
        }
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
        transport_ref: req.transport_ref.clone(),
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

// ── GET /policies/:tool/:action/versions — policy version history ────────────

async fn handle_policy_versions(
    State(app): State<AppState>,
    Path((tool, action)): Path<(String, String)>,
) -> impl IntoResponse {
    match app.storage.list_policy_versions(&tool, &action).await {
        Ok(versions) => (
            StatusCode::OK,
            Json(json!({
                "tool": tool,
                "action": action,
                "versions": versions,
            })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("storage_error: {}", e)})),
        ),
    }
}

// ── POST /policies/:policy_id/rollback — reactivate a previous version ───────

async fn handle_policy_rollback(
    State(app): State<AppState>,
    Path(policy_id): Path<String>,
) -> impl IntoResponse {
    match app.storage.reactivate_policy(&policy_id).await {
        Ok(()) => {
            log_event("info", "policy_rollback", json!({"policy_id": policy_id}));
            (
                StatusCode::OK,
                Json(json!({"rolled_back": true, "policy_id": policy_id})),
            )
        }
        Err(StorageError::NotFound) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "policy_not_found", "policy_id": policy_id})),
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
    let uptime_ms = START_UNIX_MS.get().map(|t| now_unix_ms() - t).unwrap_or(0);
    let jwt_mode = match &app.jwt_config {
        Some(c) if c.jwks_url.is_some() => "jwks",
        Some(c) if c.public_key_pem.is_some() => "rs256",
        Some(_) => "hs256",
        None => "disabled",
    };
    (
        if storage_ok { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE },
        Json(json!({
            "status": if storage_ok { "ok" } else { "degraded" },
            "version": "0.4.0",
            "storage": if storage_ok { "connected" } else { "disconnected" },
            "uptime_ms": uptime_ms,
            "signing_key_loaded": true,
            "jwt_mode": jwt_mode,
            "admin_auth": app.admin_key.is_some(),
            "partition_policy": if app.partition_fail_closed { "fail_closed" } else { "fail_open" },
            "gossip_peers": app.peers.len(),
            "gossip_trusted_keys": app.gossip_keys.len(),
            "quorum_enabled": !app.quorum_peers.is_empty(),
            "quorum_peers": app.quorum_peers.len(),
            "quorum_size": app.quorum_size,
            "verifying_key": hex::encode(app.keys.vk.to_bytes()),
        })),
    )
}

// ── GET /metrics — Prometheus text exposition format ─────────────────────────

async fn handle_metrics(State(app): State<AppState>) -> impl IntoResponse {
    let c = app.counters.lock().unwrap();
    let health_map = app.tool_health.lock().unwrap();
    let uptime_ms = START_UNIX_MS.get().map(|t| now_unix_ms() - t).unwrap_or(0);

    let mut out = String::new();
    out.push_str("# HELP dgv_decisions_total Total governance decisions evaluated\n");
    out.push_str("# TYPE dgv_decisions_total counter\n");
    out.push_str(&format!("dgv_decisions_total {}\n", c.decisions_made));
    out.push_str("# HELP dgv_denials_total Total denied decisions\n");
    out.push_str("# TYPE dgv_denials_total counter\n");
    out.push_str(&format!("dgv_denials_total {}\n", c.denials));
    out.push_str("# HELP dgv_tokens_issued_total Total auth tokens issued\n");
    out.push_str("# TYPE dgv_tokens_issued_total counter\n");
    out.push_str(&format!("dgv_tokens_issued_total {}\n", c.tokens_issued));
    out.push_str("# HELP dgv_tokens_consumed_total Total auth tokens consumed\n");
    out.push_str("# TYPE dgv_tokens_consumed_total counter\n");
    out.push_str(&format!("dgv_tokens_consumed_total {}\n", c.tokens_consumed));
    out.push_str("# HELP dgv_uptime_ms Gate uptime in milliseconds\n");
    out.push_str("# TYPE dgv_uptime_ms gauge\n");
    out.push_str(&format!("dgv_uptime_ms {}\n", uptime_ms));
    out.push_str("# HELP dgv_circuit_open Per-tool circuit breaker state (1=open, 0=closed)\n");
    out.push_str("# TYPE dgv_circuit_open gauge\n");
    for (tool, h) in health_map.iter() {
        out.push_str(&format!(
            "dgv_circuit_open{{tool=\"{}\"}} {}\n",
            tool.replace('\\', "\\\\").replace('"', "\\\""),
            if h.circuit_open { 1 } else { 0 }
        ));
    }
    out.push_str("# HELP dgv_tool_consecutive_failures Consecutive reported failures per tool\n");
    out.push_str("# TYPE dgv_tool_consecutive_failures gauge\n");
    for (tool, h) in health_map.iter() {
        out.push_str(&format!(
            "dgv_tool_consecutive_failures{{tool=\"{}\"}} {}\n",
            tool.replace('\\', "\\\\").replace('"', "\\\""),
            h.consecutive_failures
        ));
    }

    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        out,
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
    START_UNIX_MS.set(now_unix_ms()).ok();
    println!("--- DGV ENFORCEMENT GATE v0.4.0 ---");
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

    log_event("info", "storage_config", json!({"backend": storage_backend, "url": database_url}));

    let storage: Arc<dyn Storage> = match storage_backend.as_str() {
        "postgres" => match PostgresStorage::new(&database_url).await {
            Ok(s) => Arc::new(s) as Arc<dyn Storage>,
            Err(e) => {
                // Postgres unreachable at boot: come up degraded rather than
                // crash-looping. Every storage call fails -> partition policy
                // applies -> fail_closed denies. A background task retries the
                // schema migration until Postgres returns (self-healing).
                log_event("warn", "storage_initial_connect_failed", json!({"error": e.to_string(), "behavior": "degraded_boot_fail_closed"}));
                let lazy = PostgresStorage::new_lazy(&database_url)
                    .expect("failed to build lazy postgres pool");
                let retry = Arc::new(lazy);
                let retry_task = retry.clone();
                tokio::spawn(async move {
                    loop {
                        match retry_task.migrate().await {
                            Ok(()) => {
                                log_event("info", "storage_recovered", json!({"backend": "postgres"}));
                                break;
                            }
                            Err(e) => {
                                log_event("warn", "storage_migrate_retry", json!({"error": e.to_string()}));
                                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                            }
                        }
                    }
                });
                retry as Arc<dyn Storage>
            }
        },
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

    // JWT verification — if DGV_JWT_SECRET, DGV_JWT_PUBLIC_KEY, DGV_JWT_JWKS_URL,
    // or DGV_OIDC_ISSUER is set, /govern and /execute require a valid JWT.
    // The sub claim becomes the agent_id.
    // DGV_OIDC_ISSUER triggers OIDC discovery: fetches
    //   {issuer}/.well-known/openid-configuration
    // and uses its jwks_uri + issuer for RS256 validation.
    let jwt_config = {
        let secret = std::env::var("DGV_JWT_SECRET").ok();
        let public_key_pem = std::env::var("DGV_JWT_PUBLIC_KEY").ok();
        let mut jwks_url = std::env::var("DGV_JWT_JWKS_URL").ok();
        let mut issuer = std::env::var("DGV_JWT_ISSUER").ok();
        let audience = std::env::var("DGV_JWT_AUDIENCE").ok();

        // OIDC discovery — resolve jwks_uri from the issuer's metadata document
        if let Ok(oidc_issuer) = std::env::var("DGV_OIDC_ISSUER") {
            let discovery_url = format!(
                "{}/.well-known/openid-configuration",
                oidc_issuer.trim_end_matches('/')
            );
            match reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap_or_default()
                .get(&discovery_url)
                .send()
                .await
            {
                Ok(resp) => match resp.json::<serde_json::Value>().await {
                    Ok(doc) => {
                        match doc.get("jwks_uri").and_then(|v| v.as_str()) {
                            Some(uri) => {
                                jwks_url = Some(uri.to_string());
                                // Prefer the discovered issuer for validation
                                if issuer.is_none() {
                                    issuer = doc.get("issuer")
                                        .and_then(|v| v.as_str())
                                        .map(|s| s.to_string())
                                        .or(Some(oidc_issuer.clone()));
                                }
                                log_event("info", "oidc_discovery", json!({"jwks_uri": uri}));
                            }
                            None => log_event("warn", "oidc_discovery_no_jwks_uri", json!({})),
                        }
                    }
                    Err(e) => log_event("warn", "oidc_discovery_parse_failed", json!({"error": e.to_string()})),
                },
                Err(e) => log_event("warn", "oidc_discovery_fetch_failed", json!({"error": e.to_string()})),
            }
        }

        // An explicitly configured OIDC issuer whose discovery failed must not
        // silently drop to unauthenticated mode — that turns a typo'd issuer
        // into "JWT off" with only a warn-level log. Refuse to start unless a
        // fallback mode (JWKS URL / pinned key / secret) is also set.
        if std::env::var("DGV_OIDC_ISSUER").is_ok()
            && jwks_url.is_none()
            && public_key_pem.is_none()
            && secret.is_none()
        {
            eprintln!(
                "FATAL: DGV_OIDC_ISSUER is set but discovery failed and no \
                 DGV_JWT_JWKS_URL / DGV_JWT_PUBLIC_KEY / DGV_JWT_SECRET fallback \
                 is configured. The gate would run with identity verification \
                 disabled. Fix the issuer, set a fallback, or unset DGV_OIDC_ISSUER."
            );
            std::process::exit(1);
        }

        if secret.is_some() || public_key_pem.is_some() || jwks_url.is_some() {
            let mode = if jwks_url.is_some() { "JWKS" } else if public_key_pem.is_some() { "RS256" } else { "HS256" };
            log_event("info", "jwt_auth_enabled", json!({"mode": mode}));
            Some(JwtConfig {
                secret,
                public_key_pem,
                jwks_url,
                issuer,
                audience,
                jwks_cache: Arc::new(std::sync::Mutex::new(None)),
            })
        } else {
            log_event("info", "jwt_auth_disabled", json!({}));
            None
        }
    };

    // Semantic verifier webhook — optional external service for justification analysis.
    // The gate performs no LLM analysis itself; this delegates to a pluggable verifier.
    let semantic_verifier_url = std::env::var("DGV_SEMANTIC_VERIFIER_URL").ok();
    let semantic_fail_closed = std::env::var("DGV_SEMANTIC_FAIL_CLOSED")
        .map(|v| v == "1" || v == "true").unwrap_or(false);
    if semantic_verifier_url.is_some() {
        log_event("info", "semantic_verifier_enabled", json!({"fail_closed": semantic_fail_closed}));
    }

    // Partition policy — what a revocation-check storage error means.
    // fail_closed (default): deny — unverifiable continuing authority is not authority.
    // fail_open: legacy behaviour, development only.
    let partition_fail_closed = match std::env::var("DGV_PARTITION_POLICY")
        .unwrap_or_else(|_| "fail_closed".to_string())
        .to_ascii_lowercase()
        .as_str()
    {
        "fail_closed" => true,
        "fail_open" => {
            log_event("warn", "partition_policy_fail_open", json!({"note": "revocation check failures will be treated as not-revoked — dev only"}));
            false
        }
        other => {
            eprintln!("FATAL: DGV_PARTITION_POLICY must be fail_closed or fail_open, got '{}'", other);
            std::process::exit(2);
        }
    };
    log_event("info", "partition_policy", json!({"mode": if partition_fail_closed { "fail_closed" } else { "fail_open" }}));

    // Gossip peers — comma-separated base URLs receiving signed revocation
    // broadcasts. Only locally-originated revocations are broadcast.
    let peers: Vec<String> = std::env::var("DGV_PEERS")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().trim_end_matches('/').to_string())
        .filter(|s| !s.is_empty())
        .collect();

    // Trusted Ed25519 verifying keys (hex) for inbound gossip verification.
    let gossip_keys: Vec<VerifyingKey> = std::env::var("DGV_GOSSIP_KEYS")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .filter_map(|hex_key| {
            match hex::decode(&hex_key)
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
                .and_then(|b| VerifyingKey::from_bytes(&b).ok())
            {
                Some(vk) => Some(vk),
                None => {
                    eprintln!("FATAL: DGV_GOSSIP_KEYS contains an invalid Ed25519 key: '{}'", hex_key);
                    std::process::exit(2);
                }
            }
        })
        .collect();
    if !peers.is_empty() || !gossip_keys.is_empty() {
        log_event("info", "gossip_config", json!({"peers": peers.len(), "trusted_keys": gossip_keys.len()}));
    }

    let max_delegation_depth: i64 = std::env::var("DGV_MAX_DELEGATION_DEPTH")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3);

    // Quorum peers — comma-separated base URLs participating in quorum checks
    let quorum_peers: Vec<String> = std::env::var("DGV_QUORUM_PEERS")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().trim_end_matches('/').to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let cluster_size = 1 + quorum_peers.len();
    let default_quorum = (cluster_size / 2) + 1;
    let quorum_size = std::env::var("DGV_QUORUM_SIZE")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(default_quorum);

    let quorum_timeout_ms = std::env::var("DGV_QUORUM_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(1500);

    if !quorum_peers.is_empty() {
        log_event("info", "quorum_config", json!({
            "quorum_peers": quorum_peers.len(),
            "quorum_size": quorum_size,
            "timeout_ms": quorum_timeout_ms
        }));
    }

    let anti_entropy_secs: u64 = std::env::var("DGV_ANTI_ENTROPY_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

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
        partition_fail_closed,
        peers,
        gossip_keys,
        max_delegation_depth,
        quorum_peers,
        quorum_size,
        quorum_timeout_ms,
    };

    if anti_entropy_secs > 0 && !app_state.peers.is_empty() {
        let bg_app = app_state.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(anti_entropy_secs));
            loop {
                interval.tick().await;
                for peer in &bg_app.peers {
                    match reconcile_with_peer(&bg_app, peer).await {
                        Ok(res) if res.divergent => {
                            log_event("info", "anti_entropy_reconciled", json!({
                                "peer": peer,
                                "pulled": res.pulled_count,
                                "pushed": res.pushed_count,
                                "differing_buckets": res.differing_buckets
                            }));
                        }
                        _ => {}
                    }
                }
            }
        });
        log_event("info", "anti_entropy_enabled", json!({"interval_secs": anti_entropy_secs}));
    }

    // Public routes (no auth required)
    let public_routes = Router::new()
        .route("/govern", post(handle_govern))
        .route("/execute", post(handle_execute))
        .route("/verify/:run_id", get(handle_verify))
        .route("/health", get(handle_health))
        .route("/metrics", get(handle_metrics))
        .route("/stats", get(handle_stats))
        .route("/policies/:tool/:action", get(handle_get_policy))
        .route("/revocations", get(list_revocations))
        .route("/revocations/gossip", post(handle_gossip_revocation))
        .route("/revocations/digest", get(handle_revocations_digest))
        .route("/revocations/quorum-check", post(handle_quorum_check))
        .route("/revocations/merkle", get(handle_revocations_merkle))
        .route("/revocations/bucket/:prefix", get(handle_revocations_bucket))
        .route("/revocations/reconcile", post(handle_reconcile))
        .route("/approve/:token_id", post(handle_approve))
        .route("/tool-health/report", post(handle_tool_health_report))
        .route("/tool-health", get(handle_tool_health))
        .route("/a2a/send", post(handle_a2a_send))
        .route("/a2a/inbox/:agent_id", get(handle_a2a_inbox))
        .route("/agents/keys/:agent_id", get(handle_get_agent_key))
        .route("/delegate", post(handle_delegate))
        .route("/delegations/:token_id", get(handle_delegation_chain))
        .route("/a2a/ack/:envelope_id", post(handle_a2a_ack))
        .route("/policies/:tool/:action/versions", get(handle_policy_versions))
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
        .route("/policies/:policy_id/rollback", post(handle_policy_rollback))
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
    log_event("info", "cors_config", json!({"mode": if cors_origins == "*" { "permissive" } else { "restricted" }}));

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

    log_event("info", "listening", json!({"addr": addr}));
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();
    log_event("info", "shutdown_complete", json!({}));
}

/// Drain in-flight requests on SIGTERM/SIGINT (or Ctrl+C on any platform).
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c().await.expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => { log_event("info", "shutdown_initiated", json!({"signal": "SIGINT"})); },
        _ = terminate => { log_event("info", "shutdown_initiated", json!({"signal": "SIGTERM"})); },
    }
}
