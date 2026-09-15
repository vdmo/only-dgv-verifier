use only_lang::evidence_pack::{
    now_unix_ms, run_id_unix_ms, write_evidence_pack, write_manifest, EvidenceManifest,
    EvidenceManifestItem, EvidencePack, ToolOutcome, ToolProposal,
};
use reqwest::Client;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

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

fn read_manifest(base: &Path) -> EvidenceManifest {
    let path = base.join("evidence").join("manifest.json");
    if let Ok(existing) = std::fs::read_to_string(&path) {
        if let Ok(m) = serde_json::from_str::<EvidenceManifest>(&existing) {
            return m;
        }
    }
    EvidenceManifest {
        generated_unix_ms: now_unix_ms(),
        packs: vec![],
    }
}

fn push_manifest(base: &Path, item: EvidenceManifestItem) {
    let mut m = read_manifest(base);
    m.packs.push(item);
    m.packs.sort_by_key(|p| p.created_unix_ms);
    m.packs.reverse();
    m.generated_unix_ms = now_unix_ms();
    let _ = write_manifest(base, &m);
}

fn policy_value(base: &Path) -> Value {
    let path = base.join("settings").join("policy_pack.json");
    if let Ok(txt) = std::fs::read_to_string(&path) {
        if let Ok(v) = serde_json::from_str::<Value>(&txt) {
            return v;
        }
    }
    json!({
        "policy_version": "gov_payments_v0",
        "enabled_controls": {"vendor_lists": true},
        "token_ttl_minutes": 30,
        "approvals_required_by_risk": {"low": 0, "medium": 1, "high": 2},
        "vendor_allowlist": ["ACME"],
        "vendor_denylist": ["EVILCORP"],
        "amount_caps_by_risk": {"low": 1000, "medium": 10000, "high": 100000}
    })
}

fn approvals_required(policy: &Value, risk_level: &str) -> u64 {
    policy
        .get("approvals_required_by_risk")
        .and_then(|v| v.get(risk_level))
        .and_then(|v| v.as_u64())
        .unwrap_or(1)
}

fn token_ttl_minutes(policy: &Value) -> u64 {
    policy
        .get("token_ttl_minutes")
        .and_then(|v| v.as_u64())
        .unwrap_or(30)
}

fn vendor_gate(policy: &Value, vendor: &str) -> (String, Vec<String>) {
    let enabled = policy
        .get("enabled_controls")
        .and_then(|v| v.get("vendor_lists"))
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    if !enabled {
        return ("ALLOW".to_string(), vec![]);
    }

    let deny = policy
        .get("vendor_denylist")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    if deny
        .iter()
        .any(|x| x.as_str().unwrap_or("").eq_ignore_ascii_case(vendor))
    {
        return ("DENY".to_string(), vec!["vendor_denylist".to_string()]);
    }

    let allow = policy
        .get("vendor_allowlist")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    if !allow.is_empty()
        && !allow
            .iter()
            .any(|x| x.as_str().unwrap_or("").eq_ignore_ascii_case(vendor))
    {
        return (
            "ESCALATE".to_string(),
            vec!["vendor_not_allowlisted".to_string()],
        );
    }

    ("ALLOW".to_string(), vec![])
}

fn amount_cap(policy: &Value, risk_level: &str) -> u64 {
    policy
        .get("amount_caps_by_risk")
        .and_then(|v| v.get(risk_level))
        .and_then(|v| v.as_u64())
        .unwrap_or(0)
}

#[tokio::main]
async fn main() {
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    let api_key = std::env::var("GEMINI_API_KEY").unwrap_or_default();
    if api_key.is_empty() {
        eprintln!("missing GEMINI_API_KEY");
        std::process::exit(2);
    }

    let model = std::env::var("GEMINI_MODEL").unwrap_or_else(|_| "gemini-1.5-flash".to_string());
    let request_id = std::env::var("REQUEST_ID").unwrap_or_else(|_| "REQ-LLM-0001".to_string());
    let risk_level = std::env::var("RISK_LEVEL").unwrap_or_else(|_| "high".to_string());
    let vendor = std::env::var("VENDOR").unwrap_or_else(|_| "ACME".to_string());
    let amount = std::env::var("AMOUNT").unwrap_or_else(|_| "5000".to_string());
    let requester_id =
        std::env::var("REQUESTER_ID").unwrap_or_else(|_| "user:llm_requester".to_string());

    let prompt = format!(
        "You are a procurement assistant. Propose a short payment memo and checklist for paying vendor {vendor} amount {amount}. Output plain text with a memo line and 3 bullet checks."
    );

    let url = format!(
        "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
    );

    let client = Client::new();
    let req_body = json!({
        "contents": [
            {"role": "user", "parts": [{"text": prompt}]}
        ]
    });

    let resp = client.post(url).json(&req_body).send().await;

    let resp = match resp {
        Ok(r) => r,
        Err(e) => {
            eprintln!("gemini request failed: {e}");
            std::process::exit(2);
        }
    };

    let resp_json: Value = match resp.json().await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("gemini response json failed: {e}");
            std::process::exit(2);
        }
    };

    let llm_text = resp_json
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

    let policy = policy_value(&base);
    let policy_version = policy
        .get("policy_version")
        .and_then(|v| v.as_str())
        .unwrap_or("gov_payments_v0")
        .to_string();

    let required = approvals_required(&policy, &risk_level);
    let needs_approval = required > 0;

    let (vendor_state, mut reason_codes) = vendor_gate(&policy, &vendor);
    if needs_approval {
        reason_codes.push("approval_required".to_string());
    }

    let gate_state = if vendor_state == "DENY" {
        "DENY".to_string()
    } else if !needs_approval && vendor_state == "ALLOW" {
        "ALLOW".to_string()
    } else {
        "ESCALATE".to_string()
    };

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
        let now = now_unix_ms();
        let ttl_ms: u128 = (token_ttl_minutes(&policy) as u128) * 60_000;
        json!({
            "token_id": format!("tok_{now}_{request_id}"),
            "request_id": request_id,
            "policy_version": policy_version,
            "tool": tool,
            "action": action,
            "vendor": vendor,
            "amount_cap": amount_cap(&policy, &risk_level),
            "expires_unix_ms": now + ttl_ms,
            "approver_ids": []
        })
    } else {
        Value::Null
    };

    let run_ts = run_id_unix_ms();
    let run_id = format!("{run_ts}_{request_id}_llm_gate");

    let request = json!({
        "workflow": "gov_llm_payment",
        "request_id": request_id,
        "risk_level": risk_level,
        "vendor": vendor,
        "amount": amount,
        "proposal": llm_text,
        "identity": {
            "requester": {"user_id": requester_id, "roles": ["Requester"]},
            "delegations": []
        }
    });

    let decision = json!({
        "gate_state": gate_state,
        "next_step": next_step,
        "reason_codes": reason_codes,
        "needs_approval": needs_approval,
        "approved": gate_state == "ALLOW",
        "approvals_required": required,
        "approvals_received": 0,
        "execute_allowed": gate_state == "ALLOW",
        "auth_token": auth_token
    });

    let pack = EvidencePack {
        run_id: run_id.clone(),
        created_unix_ms: now_unix_ms(),
        request,
        policy_version: policy_version.clone(),
        decision: decision.clone(),
        decision_hash: format!("hash_{run_id}"),
        replay_inputs: json!({
            "llm": {
                "provider": "gemini",
                "model": model,
                "prompt": req_body,
                "response": resp_json
            }
        }),
        tool_proposals: vec![ToolProposal {
            tool: tool.to_string(),
            action: action.to_string(),
            params: json!({"vendor": vendor, "amount": amount}),
        }],
        tool_outcomes: vec![ToolOutcome {
            tool: tool.to_string(),
            allowed: false,
            deny_reason: Some("proposal only".to_string()),
            result: json!({"executed": false}),
        }],
        event_type: "unknown".to_string(),
        token_id: None,
        agent_id: None,
        actor: None,
    };

    let ok = pack
        .decision
        .get("gate_state")
        .and_then(|v| v.as_str())
        .unwrap_or("ESCALATE")
        == "ALLOW";

    let svg = svg_simple("Gemini LLM Gate", ok);
    let html = html_wrap(
        "Gemini LLM Gate",
        &svg,
        &json!({"request": pack.request, "decision": pack.decision, "replay_inputs": pack.replay_inputs}),
    );
    let _ = write_evidence_pack(&base, &run_id, &svg, &html, &pack);

    push_manifest(
        &base,
        EvidenceManifestItem {
            run_id: run_id.clone(),
            created_unix_ms: pack.created_unix_ms,
            request_id: pack
                .request
                .get("request_id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            workflow: "gov_llm_payment".to_string(),
            stage: "gate".to_string(),
            risk_level: pack
                .request
                .get("risk_level")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string(),
            needs_approval,
            approved: ok,
            gate_state: pack
                .decision
                .get("gate_state")
                .and_then(|v| v.as_str())
                .unwrap_or("ESCALATE")
                .to_string(),
            next_step: pack
                .decision
                .get("next_step")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            sla_due_unix_ms: None,
            policy_version: policy_version,
            decision_hash: pack.decision_hash.clone(),
            json: format!("{run_id}.json"),
            html: format!("{run_id}.html"),
            svg: format!("{run_id}.svg"),
            event_type: "unknown".to_string(),
            token_id: None,
            agent_id: None,
            actor: None,
        },
    );

    println!("ok=true run_id={run_id}");
}
