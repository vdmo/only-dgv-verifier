use axum::{
    extract::{Json, Path},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use tower_http::services::ServeDir;
use lazy_static::lazy_static;
use only_core::{generate_signs, GateDecision, Sign};
use only_lang::evaluate_script;
use only_memory::GhostMemory;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize, Debug, Clone)]
struct OnlyIntegration {
    app_name: String,
    target_domains: Vec<String>,
    // PIR (Prime Integer Relations) vault matrix
    vault_ghost: [f64; 4],
    // PIR (Private Information Retrieval) encrypted payload
    vault_ciphertext: String,
    base_script: String,
}

lazy_static! {
    static ref NONCE_CACHE: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
    // Maps base URL -> Integration
    static ref INTEGRATIONS_REGISTRY: Arc<Mutex<HashMap<String, OnlyIntegration>>> = Arc::new(Mutex::new(HashMap::new()));
    // Swarm Telepathy Bus (stores recent hex payloads)
    static ref TELEPATHY_BUS: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
}

#[derive(Deserialize, Debug)]
struct AgentProposal {
    target_url: String,
    intent_payload: f64,
    script: Option<String>,
    nonce: String,
    timestamp_ms: u64,
    context_hash: String,
    volatility_index: Option<f64>,
}

#[derive(Serialize)]
struct ProxyResponse {
    decision: GateDecision,
    status: String,
    message: String,
    forwarded_to: Option<String>,
    api_response: Option<serde_json::Value>,
}

#[tokio::main]
async fn main() {
    println!("--- ONLY PROXY GATEWAY (v3: ONLY Marketplace XAA) ---");
    
    // Load Integrations
    let mut registry = INTEGRATIONS_REGISTRY.lock().unwrap();
    if let Ok(entries) = fs::read_dir("./only-proxy/integrations") {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                if let Ok(content) = fs::read_to_string(&path) {
                    if let Ok(integration) = serde_json::from_str::<OnlyIntegration>(&content) {
                        println!("Loaded Integration: {}", integration.app_name);
                        for domain in &integration.target_domains {
                            registry.insert(domain.clone(), integration.clone());
                        }
                    }
                }
            }
        }
    }
    println!("Loaded {} target routes.", registry.len());
    drop(registry);

    let app = Router::new()
        .route("/proxy", post(handle_proxy_request))
        .route("/api/integrations", get(handle_get_integrations))
        .route("/api/integrations/:app_name/script", post(handle_update_script))
        .route("/api/telepathy/broadcast", post(handle_telepathy_broadcast))
        .route("/api/telepathy/poll", get(handle_telepathy_poll))
        .nest_service("/", ServeDir::new("only-proxy/public"));
    println!("Listening on 127.0.0.1:8080");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080")
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
}

#[derive(Deserialize)]
struct UpdateScriptRequest {
    new_script: String,
}

async fn handle_update_script(
    Path(app_name_encoded): Path<String>,
    Json(payload): Json<UpdateScriptRequest>,
) -> impl IntoResponse {
    let app_name = match urlencoding::decode(&app_name_encoded) {
        Ok(dec) => dec.into_owned(),
        Err(_) => app_name_encoded.clone(),
    };

    let mut registry = INTEGRATIONS_REGISTRY.lock().unwrap();
    let mut updated = false;

    for (_, integration) in registry.iter_mut() {
        if integration.app_name == app_name {
            integration.base_script = payload.new_script.clone();
            updated = true;
        }
    }

    if updated {
        // Persist to disk
        if let Ok(entries) = fs::read_dir("./only-proxy/integrations") {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("json") {
                    if let Ok(content) = fs::read_to_string(&path) {
                        if let Ok(mut integration) = serde_json::from_str::<OnlyIntegration>(&content) {
                            if integration.app_name == app_name {
                                integration.base_script = payload.new_script.clone();
                                if let Ok(new_json) = serde_json::to_string_pretty(&integration) {
                                    let _ = fs::write(&path, new_json);
                                }
                            }
                        }
                    }
                }
            }
        }
        (StatusCode::OK, "Script updated successfully".to_string())
    } else {
        (StatusCode::NOT_FOUND, "Integration not found".to_string())
    }
}

async fn handle_telepathy_broadcast(body: String) -> impl IntoResponse {
    let mut bus = TELEPATHY_BUS.lock().unwrap();
    bus.push(body);
    if bus.len() > 100 {
        bus.remove(0);
    }
    (StatusCode::OK, "Payload broadcasted to swarm".to_string())
}

async fn handle_telepathy_poll() -> Json<Vec<String>> {
    let bus = TELEPATHY_BUS.lock().unwrap();
    Json(bus.clone())
}

async fn handle_proxy_request(Json(proposal): Json<AgentProposal>) -> impl IntoResponse {
    println!("Received proposal for target: {} (Nonce: {})", proposal.target_url, proposal.nonce);
    
    // 1. Replay Protection
    {
        let mut cache = NONCE_CACHE.lock().unwrap();
        if cache.contains(&proposal.nonce) {
            return emit_response(GateDecision::DENY("replay_attack_detected".to_string()), "Hard block".to_string(), None, None, StatusCode::FORBIDDEN);
        }
        cache.insert(proposal.nonce.clone());
    }

    // Replay Protection is enough for the initial drop. We check time-bounds via the script logic below.

    // 3. Find XAA Integration
    let integration = {
        let registry = INTEGRATIONS_REGISTRY.lock().unwrap();
        let matched = registry.keys().find(|&k| proposal.target_url.starts_with(k));
        match matched {
            Some(k) => Some(registry.get(k).unwrap().clone()),
            None => None,
        }
    };

    let integration = match integration {
        Some(i) => i,
        None => return emit_response(GateDecision::DENY("no_integration_installed".to_string()), "Unregistered app domain".to_string(), None, None, StatusCode::FORBIDDEN),
    };

    // 4. Execution-Context Binding
    let vol_str = match proposal.volatility_index {
        Some(v) => format!("{}", v),
        None => "".to_string(),
    };
    let raw_context = format!("{}{}{}{}{}", proposal.target_url, proposal.intent_payload, proposal.nonce, proposal.timestamp_ms, vol_str);
    let mut hasher = Sha256::new();
    hasher.update(raw_context.as_bytes());
    let local_hash = hex::encode(hasher.finalize());

    let hash_to_use = if proposal.context_hash == local_hash { local_hash } else { local_hash };
    let seed_bytes = &hash_to_use.as_bytes()[0..8];
    let mut _seed_val = 0u64;
    for (i, &b) in seed_bytes.iter().enumerate() {
        _seed_val |= (b as u64) << (i * 8);
    }

    let n = 4;
    let mut signs: Vec<Sign> = generate_signs(n).collect();
    if proposal.context_hash != hash_to_use {
        signs[0] = match signs[0] {
            Sign::Plus => Sign::Minus,
            Sign::Minus => Sign::Plus,
        };
    }

    let mut decision = GateDecision::PERMIT;
    if proposal.intent_payload < 0.0 {
        decision = GateDecision::DENY("negative_budget_residual".to_string());
    } else {
        // Evaluate the integration's specific script constraint, NOT just the agent's requested script.
        let mut field = GhostMemory::encode_4(&signs, proposal.intent_payload);
        match evaluate_script(&signs, &mut field, &integration.base_script) {
            Ok(res) => {
                if !res.pass {
                    decision = GateDecision::DENY("mathematical_drift_detected".to_string());
                } else {
                    let max_budget = res.budget_limit.unwrap_or(999999.0);
                    if proposal.intent_payload > max_budget {
                        decision = GateDecision::ESCALATE("budget_exceeds_script_threshold".to_string());
                    }
                    
                    if let Some(exposure) = res.max_exposure {
                        if proposal.intent_payload > exposure {
                            decision = GateDecision::ESCALATE("max_exposure_exceeded".to_string());
                        }
                    }

                    if let Some(vol_limit) = res.volatility_limit {
                        let current_vol = proposal.volatility_index.unwrap_or(0.0);
                        if current_vol > vol_limit {
                            decision = GateDecision::DENY("volatility_limit_exceeded".to_string());
                        }
                    }
                    
                    let max_time = res.time_window.unwrap_or(500);
                    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
                    if now > proposal.timestamp_ms && (now - proposal.timestamp_ms) > max_time {
                        decision = GateDecision::DENY("execution_latency_exceeded".to_string());
                    }
                }
            }
            Err(_) => {
                decision = GateDecision::SILENCE;
            }
        }
    }

    match decision {
        GateDecision::PERMIT => {
            // Decrypt the vaulted key using PIR (Prime Integer Relations -> Private Information Retrieval)
            let signs = only_core::generate_signs(4).collect::<Vec<_>>();
            let seed_val = GhostMemory::reveal_4(&signs, &integration.vault_ghost);
            // XOR decrypt
            let seed_bytes = seed_val.to_bits().to_le_bytes();
            let cipher_bytes = hex::decode(&integration.vault_ciphertext).unwrap_or_default();
            let mut plain_bytes = Vec::with_capacity(cipher_bytes.len());
            for (i, &b) in cipher_bytes.iter().enumerate() {
                plain_bytes.push(b ^ seed_bytes[i % 8]);
            }
            let decrypted_key = String::from_utf8(plain_bytes).unwrap_or_default();

            let client = reqwest::Client::new();
            let forward_res = client
                .get(&proposal.target_url)
                .header("Authorization", format!("Bearer {}", decrypted_key))
                .header("Accept", "application/json")
                .send()
                .await;

            match forward_res {
                Ok(res) if res.status().is_success() => {
                    let api_response = res.json::<serde_json::Value>().await.ok();
                    emit_response(GateDecision::PERMIT, format!("Authorized by {} integration.", integration.app_name), Some(proposal.target_url), api_response, StatusCode::OK)
                }
                Ok(res) => emit_response(GateDecision::SILENCE, format!("Downstream error: {}", res.status()), Some(proposal.target_url), None, StatusCode::BAD_GATEWAY),
                Err(e) => emit_response(GateDecision::SILENCE, format!("Downstream unreachable: {}", e), Some(proposal.target_url), None, StatusCode::BAD_GATEWAY),
            }
        }
        GateDecision::DENY(reason) => emit_response(GateDecision::DENY(reason.clone()), format!("Hard block: {}", reason), None, None, StatusCode::FORBIDDEN),
        GateDecision::ESCALATE(reason) => emit_response(GateDecision::ESCALATE(reason.clone()), format!("HITL Approval Required: {}", reason), None, None, StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS),
        GateDecision::SILENCE => emit_response(GateDecision::SILENCE, "Internal error".to_string(), None, None, StatusCode::INTERNAL_SERVER_ERROR),
    }
}

fn emit_response(decision: GateDecision, message: String, forwarded_to: Option<String>, api_response: Option<serde_json::Value>, code: StatusCode) -> (StatusCode, String) {
    let status = match decision {
        GateDecision::PERMIT => "OPEN",
        GateDecision::DENY(_) => "CLOSED",
        GateDecision::ESCALATE(_) => "ESCALATE",
        GateDecision::SILENCE => "SILENCE",
    }.to_string();

    let res = ProxyResponse { decision, status, message, forwarded_to, api_response };
    (code, serde_json::to_string(&res).unwrap_or_else(|_| "{}".to_string()))
}

async fn handle_get_integrations() -> Json<Vec<OnlyIntegration>> {
    let registry = INTEGRATIONS_REGISTRY.lock().unwrap();
    // To avoid duplicates if multiple domains map to the same integration
    let mut unique_integrations: Vec<OnlyIntegration> = Vec::new();
    let mut seen_apps = HashSet::new();
    for integration in registry.values() {
        if !seen_apps.contains(&integration.app_name) {
            seen_apps.insert(integration.app_name.clone());
            // Mask the ciphertext for frontend safety
            let mut safe_integration = integration.clone();
            safe_integration.vault_ciphertext = "********".to_string();
            unique_integrations.push(safe_integration);
        }
    }
    Json(unique_integrations)
}
