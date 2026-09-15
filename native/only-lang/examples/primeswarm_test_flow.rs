use only_lang::evidence_pack::{
    now_unix_ms, run_id_unix_ms, write_evidence_pack, EvidenceManifestItem, EvidencePack, ToolOutcome,
    ToolProposal, ProposalSubmitted, AuthTokenIssued, DecisionReturned, ExecutionResult,
};
use only_lang::evidence_store::{EvidenceQuery, EvidenceStore, ManifestEvidenceStore};
use reqwest::Client;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

// --- SERVER CODE (Only Control Plane stub run in a background thread on port 8092) ---

#[derive(Debug, Clone, Deserialize)]
struct VendorConstraints {
    check_allowlist: bool,
    check_denylist: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct ToolMarketplaceConstraint {
    name: String,
    action: String,
    risk_class: String,
    required_approvals: u32,
    amount_cap: u64,
    vendor_constraints: VendorConstraints,
}

#[derive(Debug, Clone, Deserialize)]
struct ToolMarketplace {
    tools: Vec<ToolMarketplaceConstraint>,
}

#[derive(Debug, Clone, Deserialize)]
struct EnabledControls {
    vendor_lists: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct PolicyPack {
    policy_version: String,
    enabled_controls: EnabledControls,
    token_ttl_minutes: u64,
    approvals_required_by_risk: HashMap<String, u32>,
    vendor_allowlist: Vec<String>,
    vendor_denylist: Vec<String>,
    amount_caps_by_risk: HashMap<String, u64>,
}

fn load_policy_pack(base: &Path) -> PolicyPack {
    let path = base.join("settings").join("policy_pack.json");
    let txt = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(_) => {
            let mut approvals = HashMap::new();
            approvals.insert("low".to_string(), 0);
            approvals.insert("medium".to_string(), 1);
            approvals.insert("high".to_string(), 2);
            let mut caps = HashMap::new();
            caps.insert("low".to_string(), 1000);
            caps.insert("medium".to_string(), 10000);
            caps.insert("high".to_string(), 100000);
            return PolicyPack {
                policy_version: "gov_payments_v0".to_string(),
                enabled_controls: EnabledControls { vendor_lists: true },
                token_ttl_minutes: 30,
                approvals_required_by_risk: approvals,
                vendor_allowlist: vec!["ACME".to_string()],
                vendor_denylist: vec!["EVILCORP".to_string()],
                amount_caps_by_risk: caps,
            };
        }
    };
    serde_json::from_str::<PolicyPack>(&txt).unwrap_or_else(|_| {
        let mut approvals = HashMap::new();
        approvals.insert("low".to_string(), 0);
        approvals.insert("medium".to_string(), 1);
        approvals.insert("high".to_string(), 2);
        let mut caps = HashMap::new();
        caps.insert("low".to_string(), 1000);
        caps.insert("medium".to_string(), 10000);
        caps.insert("high".to_string(), 100000);
        PolicyPack {
            policy_version: "gov_payments_v0".to_string(),
            enabled_controls: EnabledControls { vendor_lists: true },
            token_ttl_minutes: 30,
            approvals_required_by_risk: approvals,
            vendor_allowlist: vec!["ACME".to_string()],
            vendor_denylist: vec!["EVILCORP".to_string()],
            amount_caps_by_risk: caps,
        }
    })
}

fn load_tool_marketplace(base: &Path) -> ToolMarketplace {
    let path = base.join("settings").join("tool_marketplace.json");
    let txt = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(_) => return ToolMarketplace { tools: vec![] },
    };
    serde_json::from_str::<ToolMarketplace>(&txt).unwrap_or_else(|_| ToolMarketplace { tools: vec![] })
}

fn approvals_required(policy: &PolicyPack, risk_level: &str) -> u32 {
    policy
        .approvals_required_by_risk
        .get(risk_level)
        .copied()
        .unwrap_or(1)
}

fn amount_cap(policy: &PolicyPack, risk_level: &str) -> u64 {
    policy
        .amount_caps_by_risk
        .get(risk_level)
        .copied()
        .unwrap_or(0)
}

fn vendor_gate(policy: &PolicyPack, vendor: &str) -> (String, Vec<String>) {
    if !policy.enabled_controls.vendor_lists {
        return ("ALLOW".to_string(), vec![]);
    }
    if policy.vendor_denylist.iter().any(|v| v.eq_ignore_ascii_case(vendor)) {
        return ("DENY".to_string(), vec!["vendor_denylist".to_string()]);
    }
    if !policy.vendor_allowlist.is_empty()
        && !policy.vendor_allowlist.iter().any(|v| v.eq_ignore_ascii_case(vendor))
    {
        return (
            "ESCALATE".to_string(),
            vec!["vendor_not_allowlisted".to_string()],
        );
    }
    ("ALLOW".to_string(), vec![])
}

const SERVER_SECRET: &str = "OnlyControlPlaneMasterSecret2026CryptographyLatticeShield";

fn compute_token_signature(
    token_id: &str,
    request_id: &str,
    policy_version: &str,
    tool: &str,
    action: &str,
    vendor: &str,
    amount_cap: u64,
    expires_unix_ms: u64,
) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(token_id.as_bytes());
    hasher.update(request_id.as_bytes());
    hasher.update(policy_version.as_bytes());
    hasher.update(tool.as_bytes());
    hasher.update(action.as_bytes());
    hasher.update(vendor.as_bytes());
    hasher.update(amount_cap.to_le_bytes());
    hasher.update(expires_unix_ms.to_le_bytes());
    hasher.update(SERVER_SECRET.as_bytes());
    hex::encode(hasher.finalize())
}

fn build_auth_token(
    policy: &PolicyPack,
    request_id: &str,
    tool: &str,
    action: &str,
    vendor: &str,
    risk_level: &str,
    approver_ids: Vec<String>,
) -> Value {
    let now = now_unix_ms();
    let ttl_ms: u128 = (policy.token_ttl_minutes as u128) * 60_000;
    let expires_unix_ms = now + ttl_ms;
    let token_id = format!("tok_{now}_{request_id}");
    let cap = amount_cap(policy, risk_level);

    let signature = compute_token_signature(
        &token_id,
        request_id,
        &policy.policy_version,
        tool,
        action,
        vendor,
        cap,
        expires_unix_ms as u64,
    );

    json!({
        "token_id": token_id,
        "request_id": request_id,
        "policy_version": policy.policy_version,
        "tool": tool,
        "action": action,
        "vendor": vendor,
        "amount_cap": cap,
        "expires_unix_ms": expires_unix_ms,
        "approver_ids": approver_ids,
        "signature": signature
    })
}

fn svg_simple(title: &str, ok: bool) -> String {
    let title = title
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    let status = if ok { "OK" } else { "BLOCKED" };
    let color = if ok { "#22c55e" } else { "#ef4444" };
    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="100%" height="180" viewBox="0 0 760 180" preserveAspectRatio="xMinYMin meet">
  <rect x="0" y="0" width="760" height="180" fill="#0b1020"/>
  <text x="16" y="28" fill="#e6e8ef" font-family="monospace" font-size="14">{title}</text>
  <rect x="16" y="48" width="728" height="110" fill="#0f1730" stroke="#2b365a"/>
  <text x="32" y="115" fill="{color}" font-family="monospace" font-size="34">{status}</text>
</svg>"##,
        title = title,
        status = status,
        color = color
    )
}

fn html_wrap(title: &str, svg: &str, detail: &Value) -> String {
    let title = title
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    let json_pretty = serde_json::to_string_pretty(detail).unwrap_or_else(|_| "{}".to_string());
    let json_pretty = json_pretty
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    format!(
        r##"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{title}</title>
  <style>
    :root {{ color-scheme: dark; }}
    body {{ background:#0b1020; color:#e6e8ef; font-family: monospace; margin:0; padding:16px; }}
    .box {{ background:#0f1730; border:1px solid #2b365a; padding:12px; margin:12px 0; }}
    pre {{ white-space: pre-wrap; margin:0; }}
  </style>
</head>
<body>
  <h1 style="margin:0 0 10px 0; font-size:16px;">{title}</h1>
  <div class="box">{svg}</div>
  <div class="box"><div style="color:#aab2d5;margin-bottom:6px;">Details</div><pre>{json_pretty}</pre></div>
</body>
</html>"##,
        title = title,
        svg = svg,
        json_pretty = json_pretty
    )
}

fn request_timeline(store: &ManifestEvidenceStore, request_id: &str) -> Vec<EvidenceManifestItem> {
    store
        .query_packs(&EvidenceQuery {
            request_id: Some(request_id.to_string()),
            limit: None,
        })
        .unwrap_or_default()
}

fn latest_by_stage(timeline: &[EvidenceManifestItem], stage: &str) -> Option<EvidenceManifestItem> {
    timeline.iter().find(|p| p.stage == stage).cloned()
}

fn load_pack(store: &ManifestEvidenceStore, run_id: &str) -> Option<EvidencePack> {
    store.read_pack_json(run_id).ok()
}

fn approval_ids(store: &ManifestEvidenceStore, timeline: &[EvidenceManifestItem]) -> Vec<String> {
    let mut ids = Vec::<String>::new();
    for item in timeline.iter().filter(|i| i.stage == "approve") {
        let pack = match load_pack(store, &item.run_id) {
            Some(p) => p,
            None => continue,
        };
        let approve = pack
            .decision
            .get("approve")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !approve {
            continue;
        }
        let approver_id = pack
            .decision
            .get("approver_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if approver_id.is_empty() {
            continue;
        }
        if !ids.iter().any(|x| x == &approver_id) {
            ids.push(approver_id);
        }
    }
    ids
}

fn handle_agent_proposal(base: &Path, store: &ManifestEvidenceStore, body: &[u8]) -> Value {
    let proposal: ProposalSubmitted = match serde_json::from_slice(body) {
        Ok(p) => p,
        Err(e) => return json!({"ok": false, "error": format!("invalid ProposalSubmitted: {e}")}),
    };

    let policy = load_policy_pack(base);
    let marketplace = load_tool_marketplace(base);

    let tool_config = marketplace.tools.iter().find(|t| t.name == proposal.tool && t.action == proposal.action);

    let mut reason_codes = Vec::new();
    let mut gate_state = "ALLOW".to_string();
    let mut risk_class = proposal.risk_level.clone();
    let mut required = approvals_required(&policy, &risk_class);
    let mut cap = amount_cap(&policy, &risk_class);

    let vendor = proposal.params.get("vendor").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let amount = proposal.params.get("amount").and_then(|v| v.as_u64()).or_else(|| {
        proposal.params.get("amount").and_then(|v| v.as_str()).and_then(|s| s.parse::<u64>().ok())
    }).unwrap_or(0);

    let mut dsl_passed = true;
    let mut cap_room = 0.0;
    let mut budget_remaining = 100000.0;

    match tool_config {
        None => {
            gate_state = "DENY".to_string();
            reason_codes.push("unknown_tool".to_string());
        }
        Some(tc) => {
            risk_class = tc.risk_class.clone();
            let policy_req = approvals_required(&policy, &risk_class);
            required = std::cmp::max(policy_req, tc.required_approvals);

            let policy_cap = amount_cap(&policy, &risk_class);
            cap = if tc.amount_cap > 0 {
                std::cmp::min(policy_cap, tc.amount_cap)
            } else {
                policy_cap
            };

            // Only-Lang DSL Policy Integration: Evaluate Cap Check via Evolve constraint
            use only_core::Sign::{Plus, Minus};
            use only_lang::evaluate_script;
            let signs = [Plus, Minus, Minus];
            let script = "harmony(1e-12) residual() evolve(2) residual()";
            
            if cap > 0 {
                let mut dsl_field = [cap as f64, amount as f64, 0.0];
                if let Ok(res) = evaluate_script(&signs, &mut dsl_field, script) {
                    dsl_passed = res.pass;
                    cap_room = dsl_field[2];
                    if cap_room < 0.0 {
                        gate_state = "DENY".to_string();
                        reason_codes.push("amount_cap_exceeded".to_string());
                    }
                } else {
                    gate_state = "DENY".to_string();
                    dsl_passed = false;
                    reason_codes.push("dsl_evaluation_failed".to_string());
                }
            }

            // Evaluate Budget Equation: [BudgetTotal, RequestAmount, RemainingBudget]
            let mut budget_field = [100000.0, amount as f64, 0.0];
            if let Ok(res) = evaluate_script(&signs, &mut budget_field, script) {
                dsl_passed = dsl_passed && res.pass;
                budget_remaining = budget_field[2];
                if budget_remaining < 0.0 {
                    gate_state = "DENY".to_string();
                    reason_codes.push("insufficient_budget".to_string());
                }
            } else {
                gate_state = "DENY".to_string();
                dsl_passed = false;
                reason_codes.push("budget_dsl_failed".to_string());
            }

            if tc.vendor_constraints.check_denylist {
                if policy.vendor_denylist.iter().any(|v| v.eq_ignore_ascii_case(&vendor)) {
                    gate_state = "DENY".to_string();
                    reason_codes.push("vendor_denylist".to_string());
                }
            }

            if gate_state != "DENY" && tc.vendor_constraints.check_allowlist {
                if !policy.vendor_allowlist.is_empty() && !policy.vendor_allowlist.iter().any(|v| v.eq_ignore_ascii_case(&vendor)) {
                    gate_state = "ESCALATE".to_string();
                    reason_codes.push("vendor_not_allowlisted".to_string());
                }
            }
        }
    }

    if gate_state != "DENY" && required > 0 {
        gate_state = "ESCALATE".to_string();
        reason_codes.push("approval_required".to_string());
    }

    let needs_approval = required > 0;
    let approved = gate_state == "ALLOW";

    let next_step = if gate_state == "ALLOW" {
        "Proceed".to_string()
    } else if gate_state == "DENY" {
        "Blocked".to_string()
    } else {
        "Await approval".to_string()
    };

    let run_ts = run_id_unix_ms();
    let run_id = format!("{run_ts}_{}_gate", proposal.request_id);

    let auth_token = if gate_state == "ALLOW" {
        let token_data = build_auth_token(
            &policy,
            &proposal.request_id,
            &proposal.tool,
            &proposal.action,
            &vendor,
            &risk_class,
            vec![],
        );
        let token: AuthTokenIssued = serde_json::from_value(token_data).unwrap();
        Some(token)
    } else {
        None
    };

    let decision = json!({
        "gate_state": gate_state,
        "next_step": next_step,
        "reason_codes": reason_codes,
        "needs_approval": needs_approval,
        "approved": approved,
        "approvals_required": required,
        "approvals_received": 0,
        "execute_allowed": approved,
        "auth_token": auth_token,
        "dsl_passed": dsl_passed,
        "budget_remaining": budget_remaining,
        "cap_room": cap_room
    });

    let tool_proposals = vec![ToolProposal {
        tool: proposal.tool.clone(),
        action: proposal.action.clone(),
        params: proposal.params.clone(),
    }];

    let tool_outcomes = vec![ToolOutcome {
        tool: proposal.tool.clone(),
        allowed: approved,
        deny_reason: if approved { None } else { Some(format!("blocked by gate: {:?}", reason_codes)) },
        result: json!({"executed": false}),
    }];

    let request_val = json!({
        "workflow": proposal.workflow,
        "request_id": proposal.request_id,
        "risk_level": risk_class,
        "vendor": vendor,
        "amount": amount.to_string(),
        "justification": proposal.justification,
        "identity": proposal.identity,
        "agent_id": proposal.agent_id
    });

    let pack = EvidencePack {
        run_id: run_id.clone(),
        created_unix_ms: now_unix_ms(),
        request: request_val,
        policy_version: policy.policy_version.clone(),
        decision: decision.clone(),
        decision_hash: format!("hash_{run_id}"),
        replay_inputs: proposal.llm_trace.unwrap_or(json!({
            "source": "primeswarm_proposal"
        })),
        tool_proposals,
        tool_outcomes,
        event_type: "unknown".to_string(),
        token_id: None,
        agent_id: None,
        actor: None,
    };

    let svg = svg_simple("PrimeSwarm Proposal Gate", approved);
    let html = html_wrap("PrimeSwarm Proposal Gate", &svg, &json!({ "decision": decision, "run_id": run_id }));
    let _ = write_evidence_pack(base, &run_id, &svg, &html, &pack);

    let sla_minutes: u128 = if risk_class == "high" { 15 } else { 60 };
    let sla_due_unix_ms = Some(now_unix_ms() + sla_minutes * 60_000);

    let manifest_item = EvidenceManifestItem {
        run_id: run_id.clone(),
        created_unix_ms: pack.created_unix_ms,
        request_id: proposal.request_id.clone(),
        workflow: proposal.workflow.clone(),
        stage: "gate".to_string(),
        risk_level: risk_class,
        needs_approval,
        approved,
        gate_state: gate_state.clone(),
        next_step: next_step.clone(),
        sla_due_unix_ms,
        policy_version: policy.policy_version.clone(),
        decision_hash: pack.decision_hash.clone(),
        json: format!("{run_id}.json"),
        html: format!("{run_id}.html"),
        svg: format!("{run_id}.svg"),
        event_type: "unknown".to_string(),
        token_id: None,
        agent_id: None,
        actor: None,
    };

    let _ = store.upsert_manifest_items(vec![manifest_item]);

    let counterfactual = if gate_state == "ESCALATE" {
        Some(format!("Awaiting Approval: Gating requires {} approvals. Acquire necessary authorizations to execute the task.", required))
    } else if gate_state == "DENY" {
        Some("Blocked by PrimeSwarm policy limits.".to_string())
    } else {
        None
    };

    json!(DecisionReturned {
        request_id: proposal.request_id,
        gate_state,
        reason_codes,
        approvals_required: required,
        approvals_received: 0,
        auth_token,
        run_id,
        decision_hash: pack.decision_hash,
        counterfactual,
    })
}

fn handle_agent_execution(base: &Path, store: &ManifestEvidenceStore, body: &[u8]) -> Value {
    let exec: ExecutionResult = match serde_json::from_slice(body) {
        Ok(e) => e,
        Err(err) => return json!({"ok": false, "error": format!("invalid ExecutionResult: {err}")}),
    };

    let policy = load_policy_pack(base);
    let timeline = request_timeline(store, &exec.request_id);
    let latest_gate = match latest_by_stage(&timeline, "gate") {
        Some(i) => i,
        None => return json!({"ok": false, "error": "no gate evidence for request"}),
    };
    let gate_pack = match load_pack(store, &latest_gate.run_id) {
        Some(p) => p,
        None => return json!({"ok": false, "error": "gate evidence not found"}),
    };

    let gate_state = gate_pack
        .decision
        .get("gate_state")
        .and_then(|v| v.as_str())
        .unwrap_or("ESCALATE")
        .to_string();
    if gate_state != "ALLOW" {
        return json!({"ok": false, "error": format!("cannot execute: gate_state={gate_state}")});
    }

    let token = match gate_pack.decision.get("auth_token") {
        Some(v) if v.is_object() => v.clone(),
        _ => return json!({"ok": false, "error": "missing auth_token in gate"}),
    };

    let token_signature = token.get("signature").and_then(|v| v.as_str()).unwrap_or("");
    let expected_sig = compute_token_signature(
        token.get("token_id").and_then(|v| v.as_str()).unwrap_or(""),
        token.get("request_id").and_then(|v| v.as_str()).unwrap_or(""),
        token.get("policy_version").and_then(|v| v.as_str()).unwrap_or(""),
        token.get("tool").and_then(|v| v.as_str()).unwrap_or(""),
        token.get("action").and_then(|v| v.as_str()).unwrap_or(""),
        token.get("vendor").and_then(|v| v.as_str()).unwrap_or(""),
        token.get("amount_cap").and_then(|v| v.as_u64()).unwrap_or(0),
        token.get("expires_unix_ms").and_then(|v| v.as_u64()).unwrap_or(0),
    );
    if token_signature != expected_sig {
        return json!({"ok": false, "error": "invalid cryptographic token signature"});
    }

    if token.get("token_id").and_then(|v| v.as_str()) != Some(&exec.token_id) {
        return json!({"ok": false, "error": "token mismatch"});
    }

    let expires_u64 = token
        .get("expires_unix_ms")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    if expires_u64 > 0 && (now_unix_ms() as u64) > expires_u64 {
        return json!({"ok": false, "error": "token expired"});
    }

    if token.get("tool").and_then(|v| v.as_str()) != Some(&exec.tool) {
        return json!({"ok": false, "error": "token tool mismatch"});
    }
    if token.get("action").and_then(|v| v.as_str()) != Some(&exec.action) {
        return json!({"ok": false, "error": "token action mismatch"});
    }

    let run_ts = run_id_unix_ms();
    let exec_run_id = format!("{run_ts}_{}_execute", exec.request_id);

    let decision_val = json!({
        "authorized": exec.allowed,
        "reason": exec.deny_reason.clone().unwrap_or_else(|| "allowed".to_string()),
        "executor_id": exec.executor_id,
        "token_id": exec.token_id,
        "tool": exec.tool,
        "action": exec.action,
        "params": exec.params,
        "receipt": exec.receipt
    });

    let exec_pack = EvidencePack {
        run_id: exec_run_id.clone(),
        created_unix_ms: now_unix_ms(),
        request: gate_pack.request.clone(),
        policy_version: policy.policy_version.clone(),
        decision: decision_val,
        decision_hash: format!("hash_{exec_run_id}"),
        replay_inputs: json!({"source": "primeswarm_client_execution"}),
        tool_proposals: vec![],
        tool_outcomes: vec![ToolOutcome {
            tool: exec.tool.clone(),
            allowed: exec.allowed,
            deny_reason: exec.deny_reason,
            result: exec.outcome,
        }],
        event_type: "unknown".to_string(),
        token_id: None,
        agent_id: None,
        actor: None,
    };

    let exec_svg = svg_simple("PrimeSwarm Execution Result", exec.allowed);
    let exec_html = html_wrap("PrimeSwarm Execution Result", &exec_svg, &exec_pack.decision);
    let _ = write_evidence_pack(base, &exec_run_id, &exec_svg, &exec_html, &exec_pack);

    let risk_level = gate_pack
        .request
        .get("risk_level")
        .and_then(|v| v.as_str())
        .unwrap_or("medium")
        .to_string();
    let required = approvals_required(&policy, &risk_level);

    let manifest_item = EvidenceManifestItem {
        run_id: exec_run_id.clone(),
        created_unix_ms: exec_pack.created_unix_ms,
        request_id: exec.request_id.clone(),
        workflow: gate_pack.request.get("workflow").and_then(|v| v.as_str()).unwrap_or("procurement").to_string(),
        stage: "execute".to_string(),
        risk_level,
        needs_approval: required > 0,
        approved: exec.allowed,
        gate_state: "ALLOW".to_string(),
        next_step: "Completed".to_string(),
        sla_due_unix_ms: latest_gate.sla_due_unix_ms,
        policy_version: exec_pack.policy_version.clone(),
        decision_hash: exec_pack.decision_hash.clone(),
        json: format!("{exec_run_id}.json"),
        html: format!("{exec_run_id}.html"),
        svg: format!("{exec_run_id}.svg"),
        event_type: "unknown".to_string(),
        token_id: None,
        agent_id: None,
        actor: None,
    };

    let _ = store.upsert_manifest_items(vec![manifest_item]);

    json!({
        "ok": true,
        "receipt_id": format!("receipt_{exec_run_id}"),
        "run_id": exec_run_id,
        "status": "Logged"
    })
}

fn handle_approve(base: &Path, store: &ManifestEvidenceStore, body: &[u8]) -> Value {
    let input: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return json!({"ok": false, "error": "invalid json"}),
    };

    let request_id = match input.get("request_id").and_then(|v| v.as_str()) {
        Some(v) => v.to_string(),
        None => return json!({"ok": false, "error": "missing request_id"}),
    };
    let approver_id = match input.get("approver_id").and_then(|v| v.as_str()) {
        Some(v) => v.to_string(),
        None => return json!({"ok": false, "error": "missing approver_id"}),
    };
    let approve = input.get("approve").and_then(|v| v.as_bool()).unwrap_or(false);
    let justification = input.get("justification").and_then(|v| v.as_str()).unwrap_or("").to_string();

    let policy = load_policy_pack(base);
    let timeline = request_timeline(store, &request_id);
    let latest_gate = match latest_by_stage(&timeline, "gate") {
        Some(i) => i,
        None => return json!({"ok": false, "error": "no gate evidence for request"}),
    };
    let gate_pack = match load_pack(store, &latest_gate.run_id) {
        Some(p) => p,
        None => return json!({"ok": false, "error": "gate evidence not found"}),
    };

    let risk_level = gate_pack.request.get("risk_level").and_then(|v| v.as_str()).unwrap_or("medium").to_string();
    let vendor = gate_pack.request.get("vendor").and_then(|v| v.as_str()).unwrap_or("ACME").to_string();

    let run_ts = run_id_unix_ms();
    let approve_run_id = format!("{run_ts}_{request_id}_approve");
    let approve_decision = json!({
        "stage": "approve",
        "approve": approve,
        "approver_id": approver_id,
        "justification": justification
    });

    let approve_pack = EvidencePack {
        run_id: approve_run_id.clone(),
        created_unix_ms: now_unix_ms(),
        request: gate_pack.request.clone(),
        policy_version: policy.policy_version.clone(),
        decision: approve_decision.clone(),
        decision_hash: format!("hash_{approve_run_id}"),
        replay_inputs: json!({"source":"connector_approve"}),
        tool_proposals: vec![],
        tool_outcomes: vec![],
        event_type: "unknown".to_string(),
        token_id: None,
        agent_id: None,
        actor: None,
    };

    let approve_svg = svg_simple("Approval", approve);
    let approve_html = html_wrap("Approval", &approve_svg, &approve_decision);
    let _ = write_evidence_pack(base, &approve_run_id, &approve_svg, &approve_html, &approve_pack);

    let mut items = vec![EvidenceManifestItem {
        run_id: approve_run_id.clone(),
        created_unix_ms: approve_pack.created_unix_ms,
        request_id: request_id.clone(),
        workflow: "procurement_connector".to_string(),
        stage: "approve".to_string(),
        risk_level: risk_level.clone(),
        needs_approval: true,
        approved: false,
        gate_state: "ESCALATE".to_string(),
        next_step: "Approval recorded".to_string(),
        sla_due_unix_ms: latest_gate.sla_due_unix_ms,
        policy_version: approve_pack.policy_version.clone(),
        decision_hash: approve_pack.decision_hash.clone(),
        json: format!("{approve_run_id}.json"),
        html: format!("{approve_run_id}.html"),
        svg: format!("{approve_run_id}.svg"),
        event_type: "unknown".to_string(),
        token_id: None,
        agent_id: None,
        actor: None,
    }];

    let mut timeline2 = timeline.clone();
    timeline2.push(items[0].clone());
    let approver_ids = approval_ids(store, &timeline2);
    let required = approvals_required(&policy, &risk_level);

    let (vendor_state, mut reasons) = vendor_gate(&policy, &vendor);
    if required > 0 {
        reasons.push("approval_required".to_string());
    }

    let mut gate_state = "ESCALATE".to_string();
    if vendor_state == "DENY" {
        gate_state = "DENY".to_string();
    } else if !approve {
        gate_state = "DENY".to_string();
        reasons.push("approval_denied".to_string());
    } else if vendor_state == "ALLOW" && (approver_ids.len() as u32) >= required {
        gate_state = "ALLOW".to_string();
    }

    let next_step = if gate_state == "ALLOW" {
        "Proceed".to_string()
    } else if gate_state == "DENY" {
        "Blocked".to_string()
    } else {
        "Await approval".to_string()
    };

    let tool = "finance.payment";
    let action = "execute_payment";

    let auth_token = if gate_state == "ALLOW" {
        build_auth_token(
            &policy,
            &request_id,
            tool,
            action,
            &vendor,
            &risk_level,
            approver_ids.clone(),
        )
    } else {
        Value::Null
    };

    let gate_update_run_id = format!("{run_ts}_{request_id}_gate");
    let gate_update_decision = json!({
        "gate_state": gate_state,
        "next_step": next_step,
        "reason_codes": reasons,
        "needs_approval": required > 0,
        "approved": gate_state == "ALLOW",
        "approvals_required": required,
        "approvals_received": approver_ids.len(),
        "execute_allowed": gate_state == "ALLOW",
        "auth_token": auth_token
    });

    let gate_update_pack = EvidencePack {
        run_id: gate_update_run_id.clone(),
        created_unix_ms: now_unix_ms(),
        request: gate_pack.request.clone(),
        policy_version: policy.policy_version.clone(),
        decision: gate_update_decision.clone(),
        decision_hash: format!("hash_{gate_update_run_id}"),
        replay_inputs: json!({"source":"connector_gate_update"}),
        tool_proposals: vec![ToolProposal {
            tool: tool.to_string(),
            action: action.to_string(),
            params: json!({
                "vendor": gate_pack.request.get("vendor").cloned().unwrap_or(Value::Null),
                "amount": gate_pack.request.get("amount").cloned().unwrap_or(Value::Null)
            }),
        }],
        tool_outcomes: vec![ToolOutcome {
            tool: tool.to_string(),
            allowed: false,
            deny_reason: Some("blocked: connector stub (not authorized)".to_string()),
            result: json!({"executed": false}),
        }],
        event_type: "unknown".to_string(),
        token_id: None,
        agent_id: None,
        actor: None,
    };

    let gate_ok = gate_update_decision.get("gate_state").and_then(|v| v.as_str()).unwrap_or("ESCALATE") == "ALLOW";
    let gate_svg = svg_simple("Gate update", gate_ok);
    let gate_html = html_wrap("Gate update", &gate_svg, &gate_update_decision);
    let _ = write_evidence_pack(base, &gate_update_run_id, &gate_svg, &gate_html, &gate_update_pack);

    items.push(EvidenceManifestItem {
        run_id: gate_update_run_id.clone(),
        created_unix_ms: gate_update_pack.created_unix_ms,
        request_id: request_id.clone(),
        workflow: "procurement_connector".to_string(),
        stage: "gate".to_string(),
        risk_level: risk_level.clone(),
        needs_approval: required > 0,
        approved: gate_ok,
        gate_state: gate_update_pack.decision.get("gate_state").and_then(|v| v.as_str()).unwrap_or("ESCALATE").to_string(),
        next_step: gate_update_pack.decision.get("next_step").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        sla_due_unix_ms: latest_gate.sla_due_unix_ms,
        policy_version: gate_update_pack.policy_version.clone(),
        decision_hash: gate_update_pack.decision_hash.clone(),
        json: format!("{gate_update_run_id}.json"),
        html: format!("{gate_update_run_id}.html"),
        svg: format!("{gate_update_run_id}.svg"),
        event_type: "unknown".to_string(),
        token_id: None,
        agent_id: None,
        actor: None,
    });

    let _ = store.upsert_manifest_items(items);

    json!({
        "ok": true,
        "request_id": request_id,
        "run_id": gate_update_run_id,
        "gate_state": gate_update_pack.decision.get("gate_state").cloned().unwrap_or(Value::Null),
        "auth_token": gate_update_pack.decision.get("auth_token").cloned().unwrap_or(Value::Null)
    })
}

fn handle_conn(mut stream: TcpStream, store: &ManifestEvidenceStore) -> std::io::Result<()> {
    let mut buf = [0u8; 4096];
    let n = stream.read(&mut buf)?;
    let req_str = String::from_utf8_lossy(&buf[..n]);

    let mut lines = req_str.split("\r\n");
    let req_line = lines.next().unwrap_or("");
    let mut parts = req_line.split_whitespace();
    let method = parts.next().unwrap_or("GET");
    let path_raw = parts.next().unwrap_or("/");

    let path = if let Some(q) = path_raw.find('?') {
        &path_raw[..q]
    } else {
        path_raw
    };

    let mut content_len = 0;
    for line in lines {
        if line.is_empty() { break; }
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().to_ascii_lowercase() == "content-length" {
                content_len = v.trim().parse::<usize>().unwrap_or(0);
            }
        }
    }

    let mut body = Vec::new();
    if content_len > 0 {
        if let Some(pos) = req_str.find("\r\n\r\n") {
            let rest = &buf[pos + 4..n];
            body.extend_from_slice(rest);
        }
        while body.len() < content_len {
            let mut tmp = [0u8; 1024];
            let read_bytes = stream.read(&mut tmp)?;
            if read_bytes == 0 { break; }
            body.extend_from_slice(&tmp[..read_bytes]);
        }
    }

    let response = if method == "POST" && path == "/api/agent/proposal" {
        let out = handle_agent_proposal(store.base_dir(), store, &body);
        let resp_bytes = serde_json::to_vec_pretty(&out).unwrap();
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\n\r\n",
            resp_bytes.len()
        ).into_bytes()
        .into_iter()
        .chain(resp_bytes.into_iter())
        .collect::<Vec<u8>>()
    } else if method == "POST" && path == "/api/agent/execution" {
        let out = handle_agent_execution(store.base_dir(), store, &body);
        let resp_bytes = serde_json::to_vec_pretty(&out).unwrap();
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\n\r\n",
            resp_bytes.len()
        ).into_bytes()
        .into_iter()
        .chain(resp_bytes.into_iter())
        .collect::<Vec<u8>>()
    } else if method == "POST" && path == "/api/approve" {
        let out = handle_approve(store.base_dir(), store, &body);
        let resp_bytes = serde_json::to_vec_pretty(&out).unwrap();
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\n\r\n",
            resp_bytes.len()
        ).into_bytes()
        .into_iter()
        .chain(resp_bytes.into_iter())
        .collect::<Vec<u8>>()
    } else {
        let resp_bytes = b"{\"ok\":true}".to_vec();
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\n\r\n",
            resp_bytes.len()
        ).into_bytes()
        .into_iter()
        .chain(resp_bytes.into_iter())
        .collect::<Vec<u8>>()
    };

    stream.write_all(&response)?;
    Ok(())
}

// --- CLIENT TEST FLOW SUITE ---

#[tokio::main]
async fn main() {
    println!("=== PRIMESWARM ASSURANCE CONTRACT TEST SUITE ===");

    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let store = ManifestEvidenceStore::new(base.clone());

    let server_store = store.clone();
    std::thread::spawn(move || {
        let listener = TcpListener::bind("127.0.0.1:8092").unwrap();
        println!("[Control Plane] Gating plane active on http://127.0.0.1:8092");
        for stream in listener.incoming() {
            if let Ok(stream) = stream {
                let _ = handle_conn(stream, &server_store);
            }
        }
    });

    tokio::time::sleep(Duration::from_millis(200)).await;

    let api_key = std::env::var("GEMINI_API_KEY").unwrap_or_default();
    let model = std::env::var("GEMINI_MODEL").unwrap_or_else(|_| "gemini-1.5-flash".to_string());
    
    let memo_text = if !api_key.is_empty() {
        println!("[PrimeSwarm Agent] Invoking Gemini API ({}) for autonomous proposal generation...", model);
        let url = format!(
            "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
        );
        let client = Client::new();
        let prompt = "Propose a procurement memo for paying vendor ACME the amount of 5000. Justify the request with furniture purchase details. Out plain text.";
        let req_body = json!({
            "contents": [
                {"role": "user", "parts": [{"text": prompt}]}
            ]
        });

        match client.post(url).json(&req_body).send().await {
            Ok(resp) => {
                match resp.json::<Value>().await {
                    Ok(resp_json) => {
                        let text = resp_json
                            .get("candidates")
                            .and_then(|v| v.as_array())
                            .and_then(|a| a.first())
                            .and_then(|v| v.get("content"))
                            .and_then(|v| v.get("parts"))
                            .and_then(|v| v.as_array())
                            .and_then(|a| a.first())
                            .and_then(|v| v.get("text"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        println!("[PrimeSwarm Agent] Gemini generated memo:\n{}", text);
                        text
                    }
                    Err(_) => {
                        println!("[Warning] Failed parsing Gemini JSON. Using mock justification.");
                        "Mock Memo: Urgent procurement of ACME desk chairs.".to_string()
                    }
                }
            }
            Err(_) => {
                println!("[Warning] Gemini API call failed. Using mock justification.");
                "Mock Memo: Urgent procurement of ACME desk chairs.".to_string()
            }
        }
    } else {
        println!("[Info] GEMINI_API_KEY is empty. Simulating LLM response.");
        "Desk replacement purchase order: 12 tables + chairs for design studio layout.".to_string()
    };

    let request_id = format!("REQ-PS-{}", now_unix_ms() % 10000);
    println!("[PrimeSwarm Agent] Formulating ProposalSubmitted message for request: {}", request_id);

    let proposal = ProposalSubmitted {
        request_id: request_id.clone(),
        agent_id: "primeswarm_furniture_agent".to_string(),
        workflow: "furniture_procurement_v1".to_string(),
        tool: "finance.payment".to_string(),
        action: "execute_payment".to_string(),
        params: json!({
            "vendor": "ACME",
            "amount": 5000
        }),
        justification: memo_text.clone(),
        llm_trace: Some(json!({
            "llm_provider": "gemini",
            "model": model,
            "raw_text": memo_text
        })),
        risk_level: "medium".to_string(),
        identity: json!({
            "requester": {
                "user_id": "agent:primeswarm",
                "roles": ["ClientAgent"]
            },
            "delegations": []
        }),
        ..Default::default()
    };

    let client = Client::new();
    println!("[PrimeSwarm Agent] Sending ProposalSubmitted to Control Plane...");
    let resp = client.post("http://127.0.0.1:8092/api/agent/proposal")
        .json(&proposal)
        .send()
        .await
        .unwrap();

    let decision: DecisionReturned = resp.json().await.unwrap();
    println!("[Control Plane] Gating evaluation returned:");
    println!("  -> Gate State: {:?}", decision.gate_state);
    println!("  -> Reason Codes: {:?}", decision.reason_codes);
    println!("  -> Approvals Required: {}", decision.approvals_required);
    println!("  -> Has Scoped Auth Token: {}", decision.auth_token.is_some());

    assert_eq!(decision.gate_state, "ESCALATE", "Expected ESCALATE due to approval requirements");
    assert!(decision.auth_token.is_none(), "Should not issue token without approvals");

    println!("\n[Governance Plane] Submitting required approval...");
    let approval_payload = json!({
        "request_id": request_id,
        "approver_id": "user:head_of_procurement",
        "approve": true,
        "justification": "Desks are necessary for studio space onboarding. Budget approved."
    });

    let approve_resp = client.post("http://127.0.0.1:8092/api/approve")
        .json(&approval_payload)
        .send()
        .await
        .unwrap();

    let approve_outcome: Value = approve_resp.json().await.unwrap();
    println!("[Governance Plane] Approval registered successfully.");
    
    let gate_state_updated = approve_outcome.get("gate_state").unwrap().as_str().unwrap();
    println!("  -> Updated Gate State: {}", gate_state_updated);
    assert_eq!(gate_state_updated, "ESCALATE");

    println!("\n[Governance Plane] Submitting second required approval...");
    let approval_payload2 = json!({
        "request_id": request_id,
        "approver_id": "user:finance_director",
        "approve": true,
        "justification": "Budget review verified. Approving expenditure."
    });

    let approve_resp2 = client.post("http://127.0.0.1:8092/api/approve")
        .json(&approval_payload2)
        .send()
        .await
        .unwrap();

    let approve_outcome2: Value = approve_resp2.json().await.unwrap();
    println!("[Governance Plane] Second approval registered successfully.");

    let gate_state_final = approve_outcome2.get("gate_state").unwrap().as_str().unwrap();
    println!("  -> Final Gate State: {}", gate_state_final);
    assert_eq!(gate_state_final, "ALLOW");

    let auth_token_raw = approve_outcome2.get("auth_token").unwrap();
    let auth_token: AuthTokenIssued = serde_json::from_value(auth_token_raw.clone()).unwrap();
    println!("  -> Issued Scoped Token: {}", auth_token.token_id);
    println!("  -> Scoped TTL Cap: {}", auth_token.amount_cap);

    println!("\n[PrimeSwarm Agent] Preparing tool execution wrapper (never bypasses control plane)...");
    let execution_result_payload = ExecutionResult {
        request_id: request_id.clone(),
        token_id: auth_token.token_id.clone(),
        executor_id: "user:finance_bridge_operator".to_string(),
        tool: "finance.payment".to_string(),
        action: "execute_payment".to_string(),
        params: json!({
            "vendor": "ACME",
            "amount": 5000
        }),
        allowed: true,
        deny_reason: None,
        outcome: json!({
            "success": true,
            "transaction_id": "TXN-SECURE-898231",
            "transferred_to": "ACME"
        }),
        receipt: json!({
            "evidence_signature": "ONLY_GATEWAY_SIG_0x712aefbc90",
            "block_timestamp": now_unix_ms()
        }),
        run_id: "".to_string(),
    };

    println!("[PrimeSwarm Agent] Submitting ExecutionResult to Control Plane boundary...");
    let exec_resp = client.post("http://127.0.0.1:8092/api/agent/execution")
        .json(&execution_result_payload)
        .send()
        .await
        .unwrap();

    let exec_outcome: Value = exec_resp.json().await.unwrap();
    println!("[Control Plane] Secured execution logged. Receipt:");
    println!("{}", serde_json::to_string_pretty(&exec_outcome).unwrap());

    assert_eq!(exec_outcome.get("ok").unwrap().as_bool().unwrap(), true);

    // --- TAMPER-PROOF SIMULATED ATTACK TEST ---
    println!("\n[Security Test] Simulating database tampering attack...");
    // 1. Get the gate evidence pack run_id directly from the approve outcome
    let gate_run_id = approve_outcome2.get("run_id").unwrap().as_str().unwrap().to_string();

    // 2. Load the gate pack
    let mut tampered_pack = store.read_pack_json(&gate_run_id).unwrap();
    
    // 3. Corrupt the signature inside the auth_token
    if let Some(token_val) = tampered_pack.decision.get_mut("auth_token") {
        if let Some(sig) = token_val.get_mut("signature") {
            *sig = json!("forged_signature_attacker_666");
        }
    }
    
    // 4. Write tampered pack back to disk (simulating unauthorized database write)
    let json_path = store.base_dir().join("evidence").join(format!("{}.json", gate_run_id));
    let tampered_json = serde_json::to_string_pretty(&tampered_pack).unwrap();
    std::fs::write(&json_path, tampered_json).unwrap();
    println!("[Security Test] DB write simulated: corrupted auth_token.signature.");

    // 5. Try to execute with the tampered token
    println!("[Security Test] Submitting ExecutionResult using tampered token...");
    let tampered_execution_payload = ExecutionResult {
        request_id: request_id.clone(),
        token_id: auth_token.token_id.clone(),
        executor_id: "user:finance_bridge_operator".to_string(),
        tool: "finance.payment".to_string(),
        action: "execute_payment".to_string(),
        params: json!({
            "vendor": "ACME",
            "amount": 5000
        }),
        allowed: true,
        deny_reason: None,
        outcome: json!({ "success": true }),
        receipt: json!({ "block_timestamp": now_unix_ms() }),
        run_id: "".to_string(),
    };

    let tamper_resp = client.post("http://127.0.0.1:8092/api/agent/execution")
        .json(&tampered_execution_payload)
        .send()
        .await
        .unwrap();

    let tamper_outcome: Value = tamper_resp.json().await.unwrap();
    println!("[Control Plane] Gating plane response to tampered token check:");
    println!("{}", serde_json::to_string_pretty(&tamper_outcome).unwrap());

    // Assert that execution was REJECTED due to signature verification failure
    assert_eq!(tamper_outcome.get("error").and_then(|v| v.as_str()), Some("invalid cryptographic token signature"));
    println!("[Security Test] SUCCESS: Tampered token was rejected with the correct signature error!");

    println!("\n=== SYSTEM VERIFIED SUCCESSFULLY ===");
}
