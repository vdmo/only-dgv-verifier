use only_lang::evidence_pack::{
    now_unix_ms, run_id_unix_ms, sort_manifest_packs_desc, write_evidence_pack, write_manifest,
    EvidenceManifest, EvidenceManifestItem, EvidencePack, ToolOutcome, ToolProposal,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};

fn http_response(status: &str, content_type: &str, body: &str) -> Vec<u8> {
    let headers = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {len}\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Headers: content-type\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\n\r\n",
        len = body.as_bytes().len()
    );
    let mut out = Vec::with_capacity(headers.len() + body.len());
    out.extend_from_slice(headers.as_bytes());
    out.extend_from_slice(body.as_bytes());
    out
}

fn read_http_request(
    stream: &mut TcpStream,
) -> Option<(String, String, HashMap<String, String>, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        let n = stream.read(&mut tmp).ok()?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if buf.len() > 1024 * 128 {
            return None;
        }
    }

    let header_end = buf.windows(4).position(|w| w == b"\r\n\r\n")?;
    let (header_bytes, rest) = buf.split_at(header_end + 4);
    let header_str = String::from_utf8_lossy(header_bytes);
    let mut lines = header_str.split("\r\n").filter(|l| !l.is_empty());
    let request_line = lines.next()?.to_string();
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();

    let mut headers = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }

    let content_len: usize = headers
        .get("content-length")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);

    let mut body = Vec::with_capacity(content_len);
    body.extend_from_slice(rest);

    while body.len() < content_len {
        let n = stream.read(&mut tmp).ok()?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
        if body.len() > 1024 * 1024 {
            break;
        }
    }

    Some((method, path, headers, body))
}

fn normalize_path(path: &str) -> String {
    let mut p = path.to_string();
    if let Some(q) = p.find('?') {
        p.truncate(q);
    }

    if let Some(scheme) = p.find("://") {
        let after = &p[(scheme + 3)..];
        if let Some(slash) = after.find('/') {
            p = after[slash..].to_string();
        } else {
            p = "/".to_string();
        }
    }

    while p.len() > 1 && p.ends_with('/') {
        p.pop();
    }

    if p.is_empty() {
        p = "/".to_string();
    }

    p
}

fn parse_csv(text: &str) -> Vec<Value> {
    let mut rows = Vec::new();
    let mut lines = text.lines().map(|l| l.trim()).filter(|l| !l.is_empty());
    let header = match lines.next() {
        Some(h) => h,
        None => return rows,
    };

    let headers: Vec<&str> = header.split(',').map(|s| s.trim()).collect();
    for line in lines {
        let cols: Vec<&str> = line.split(',').map(|s| s.trim()).collect();
        if cols.is_empty() {
            continue;
        }
        let mut obj = serde_json::Map::new();
        for (i, key) in headers.iter().enumerate() {
            if let Some(v) = cols.get(i) {
                obj.insert((*key).to_string(), Value::String((*v).to_string()));
            }
        }
        rows.push(Value::Object(obj));
    }
    rows
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

fn default_policy_pack() -> PolicyPack {
    let mut approvals_required_by_risk = HashMap::new();
    approvals_required_by_risk.insert("low".to_string(), 0);
    approvals_required_by_risk.insert("medium".to_string(), 1);
    approvals_required_by_risk.insert("high".to_string(), 2);

    let mut amount_caps_by_risk = HashMap::new();
    amount_caps_by_risk.insert("low".to_string(), 1000);
    amount_caps_by_risk.insert("medium".to_string(), 10_000);
    amount_caps_by_risk.insert("high".to_string(), 100_000);

    PolicyPack {
        policy_version: "gov_payments_v0".to_string(),
        enabled_controls: EnabledControls { vendor_lists: true },
        token_ttl_minutes: 30,
        approvals_required_by_risk,
        vendor_allowlist: vec![
            "ACME".to_string(),
            "OMNI-MED".to_string(),
            "CITY-SUPPLY".to_string(),
        ],
        vendor_denylist: vec!["EVILCORP".to_string()],
        amount_caps_by_risk,
    }
}

fn load_policy_pack(base: &Path) -> PolicyPack {
    let path = base.join("settings").join("policy_pack.json");
    let txt = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(_) => return default_policy_pack(),
    };
    serde_json::from_str::<PolicyPack>(&txt).unwrap_or_else(|_| default_policy_pack())
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

    if policy
        .vendor_denylist
        .iter()
        .any(|v| v.eq_ignore_ascii_case(vendor))
    {
        return ("DENY".to_string(), vec!["vendor_denylist".to_string()]);
    }

    if !policy.vendor_allowlist.is_empty()
        && !policy
            .vendor_allowlist
            .iter()
            .any(|v| v.eq_ignore_ascii_case(vendor))
    {
        return (
            "ESCALATE".to_string(),
            vec!["vendor_not_allowlisted".to_string()],
        );
    }

    ("ALLOW".to_string(), vec![])
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

    json!({
        "token_id": token_id,
        "request_id": request_id,
        "policy_version": policy.policy_version,
        "tool": tool,
        "action": action,
        "vendor": vendor,
        "amount_cap": amount_cap(policy, risk_level),
        "expires_unix_ms": expires_unix_ms,
        "approver_ids": approver_ids
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

fn append_to_manifest(base: &Path, items: Vec<EvidenceManifestItem>) -> std::io::Result<PathBuf> {
    let evidence_dir = base.join("evidence");
    std::fs::create_dir_all(&evidence_dir)?;
    let path = evidence_dir.join("manifest.json");
    let mut packs = Vec::<EvidenceManifestItem>::new();
    if let Ok(existing) = std::fs::read_to_string(&path) {
        if let Ok(m) = serde_json::from_str::<EvidenceManifest>(&existing) {
            packs = m.packs;
        }
    }
    packs.extend(items);
    sort_manifest_packs_desc(&mut packs);
    let manifest = EvidenceManifest {
        generated_unix_ms: now_unix_ms(),
        packs,
    };
    write_manifest(base, &manifest)
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

fn request_timeline(base: &Path, request_id: &str) -> Vec<EvidenceManifestItem> {
    let mut items: Vec<EvidenceManifestItem> = read_manifest(base)
        .packs
        .into_iter()
        .filter(|p| p.request_id == request_id)
        .collect();
    sort_manifest_packs_desc(&mut items);
    items
}

fn latest_by_stage(timeline: &[EvidenceManifestItem], stage: &str) -> Option<EvidenceManifestItem> {
    timeline.iter().find(|p| p.stage == stage).cloned()
}

fn load_pack(base: &Path, run_id: &str) -> Option<EvidencePack> {
    let path = base.join("evidence").join(format!("{run_id}.json"));
    let txt = std::fs::read_to_string(&path).ok()?;
    serde_json::from_str::<EvidencePack>(&txt).ok()
}

fn approval_ids(base: &Path, timeline: &[EvidenceManifestItem]) -> Vec<String> {
    let mut ids = Vec::<String>::new();
    for item in timeline.iter().filter(|i| i.stage == "approve") {
        let pack = match load_pack(base, &item.run_id) {
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

fn handle_import_csv(base: &Path, body: &[u8]) -> Value {
    let policy = load_policy_pack(base);
    let csv = String::from_utf8_lossy(body).to_string();
    let rows = parse_csv(&csv);
    if rows.is_empty() {
        return json!({"ok": false, "error": "empty csv; expected header row"});
    }

    let mut created = Vec::new();
    let mut manifest_items = Vec::new();

    for row in rows {
        let request_id = row
            .get("request_id")
            .and_then(|v| v.as_str())
            .unwrap_or("REQ-CSV-0001")
            .to_string();
        let risk_level = row
            .get("risk_level")
            .and_then(|v| v.as_str())
            .unwrap_or("medium")
            .to_string();
        let vendor = row
            .get("vendor")
            .and_then(|v| v.as_str())
            .unwrap_or("ACME")
            .to_string();
        let amount_str = row
            .get("amount")
            .and_then(|v| v.as_str())
            .unwrap_or("0")
            .to_string();

        let sla_minutes: u128 = if risk_level == "high" {
            15
        } else if risk_level == "medium" {
            60
        } else {
            15
        };
        let sla_due_unix_ms = Some(now_unix_ms() + sla_minutes * 60_000);

        let approvals_required = approvals_required(&policy, &risk_level);
        let needs_approval = approvals_required > 0;
        let approvals_received = 0_u32;

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
            build_auth_token(
                &policy,
                &request_id,
                tool,
                action,
                &vendor,
                &risk_level,
                vec![],
            )
        } else {
            Value::Null
        };

        let execute_allowed = gate_state == "ALLOW";

        let run_ts = run_id_unix_ms();
        let run_id = format!("{run_ts}_{request_id}_gate");

        let identity = json!({
            "requester": {
                "user_id": row.get("requester_id").and_then(|v| v.as_str()).unwrap_or("user:anonymous"),
                "roles": [ row.get("requester_role").and_then(|v| v.as_str()).unwrap_or("Requester") ]
            },
            "delegations": [
                {
                    "from_role": "ProcurementOfficer",
                    "to_role": "ProcurementDelegate",
                    "scope": "low_risk_only"
                }
            ]
        });

        let request = json!({
            "workflow": "procurement_connector",
            "request_id": request_id,
            "risk_level": risk_level,
            "vendor": vendor,
            "amount": amount_str,
            "sla_minutes": sla_minutes,
            "identity": identity
        });

        let decision = json!({
            "gate_state": gate_state,
            "next_step": next_step,
            "reason_codes": reason_codes,
            "evidence_requirements": {"citations": false, "assumptions": false, "uncertainty": false},
            "needs_approval": needs_approval,
            "approved": execute_allowed,
            "approvals_required": approvals_required,
            "approvals_received": approvals_received,
            "execute_allowed": execute_allowed,
            "sla_due_unix_ms": sla_due_unix_ms.unwrap(),
            "restricted_tools": if risk_level == "high" { json!(["finance.payment"]) } else { json!([]) },
            "auth_token": auth_token
        });

        let tool_proposals = vec![ToolProposal {
            tool: tool.to_string(),
            action: action.to_string(),
            params: json!({"vendor": request.get("vendor").cloned().unwrap_or(Value::Null), "amount": request.get("amount").cloned().unwrap_or(Value::Null)}),
        }];
        let tool_outcomes = vec![ToolOutcome {
            tool: tool.to_string(),
            allowed: false,
            deny_reason: Some("blocked: connector stub (not authorized)".to_string()),
            result: json!({"executed": false}),
        }];

        let pack = EvidencePack {
            run_id: run_id.clone(),
            created_unix_ms: now_unix_ms(),
            request,
            policy_version: policy.policy_version.clone(),
            decision: decision.clone(),
            decision_hash: format!("hash_{run_id}"),
            replay_inputs: json!({"source":"csv_import"}),
            tool_proposals,
            tool_outcomes,
            event_type: "unknown".to_string(),
            token_id: None,
            agent_id: None,
            actor: None,
        };

        let svg = svg_simple("CSV import gate", false);
        let html = html_wrap(
            "CSV import gate",
            &svg,
            &json!({ "decision": decision, "run_id": run_id }),
        );
        let _ = write_evidence_pack(base, &run_id, &svg, &html, &pack);

        manifest_items.push(EvidenceManifestItem {
            run_id: run_id.clone(),
            created_unix_ms: pack.created_unix_ms,
            request_id: pack
                .request
                .get("request_id")
                .and_then(|v| v.as_str())
                .unwrap_or("REQ-CSV-0001")
                .to_string(),
            workflow: "procurement_connector".to_string(),
            stage: "gate".to_string(),
            risk_level: pack
                .request
                .get("risk_level")
                .and_then(|v| v.as_str())
                .unwrap_or("medium")
                .to_string(),
            needs_approval,
            approved: execute_allowed,
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
            sla_due_unix_ms,
            policy_version: pack.policy_version.clone(),
            decision_hash: pack.decision_hash.clone(),
            json: format!("{run_id}.json"),
            html: format!("{run_id}.html"),
            svg: format!("{run_id}.svg"),
            event_type: "unknown".to_string(),
            token_id: None,
            agent_id: None,
            actor: None,
        });

        created.push(run_id);
    }

    match append_to_manifest(base, manifest_items) {
        Ok(p) => json!({"ok": true, "created": created, "manifest": p.display().to_string()}),
        Err(e) => json!({"ok": false, "error": e.to_string(), "created": created}),
    }
}

fn handle_policy(base: &Path) -> Value {
    let path = base.join("settings").join("policy_pack.json");
    match std::fs::read_to_string(&path) {
        Ok(txt) => serde_json::from_str::<Value>(&txt)
            .unwrap_or_else(|_| json!({"ok": false, "error": "bad policy json"})),
        Err(e) => json!({"ok": false, "error": e.to_string()}),
    }
}

fn handle_approve(base: &Path, body: &[u8]) -> Value {
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
    let approve = input
        .get("approve")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let justification = input
        .get("justification")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let policy = load_policy_pack(base);
    let timeline = request_timeline(base, &request_id);
    let latest_gate = match latest_by_stage(&timeline, "gate") {
        Some(i) => i,
        None => return json!({"ok": false, "error": "no gate evidence for request"}),
    };
    let gate_pack = match load_pack(base, &latest_gate.run_id) {
        Some(p) => p,
        None => return json!({"ok": false, "error": "gate evidence not found"}),
    };

    let risk_level = gate_pack
        .request
        .get("risk_level")
        .and_then(|v| v.as_str())
        .unwrap_or("medium")
        .to_string();
    let vendor = gate_pack
        .request
        .get("vendor")
        .and_then(|v| v.as_str())
        .unwrap_or("ACME")
        .to_string();

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
    let _ = write_evidence_pack(
        base,
        &approve_run_id,
        &approve_svg,
        &approve_html,
        &approve_pack,
    );

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

    let mut timeline2 = request_timeline(base, &request_id);
    timeline2.push(items[0].clone());
    let approver_ids = approval_ids(base, &timeline2);
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
            params: json!({"vendor": gate_pack.request.get("vendor").cloned().unwrap_or(Value::Null), "amount": gate_pack.request.get("amount").cloned().unwrap_or(Value::Null)}),
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

    let gate_ok = gate_update_decision
        .get("gate_state")
        .and_then(|v| v.as_str())
        .unwrap_or("ESCALATE")
        == "ALLOW";
    let gate_svg = svg_simple("Gate update", gate_ok);
    let gate_html = html_wrap("Gate update", &gate_svg, &gate_update_decision);
    let _ = write_evidence_pack(
        base,
        &gate_update_run_id,
        &gate_svg,
        &gate_html,
        &gate_update_pack,
    );

    items.push(EvidenceManifestItem {
        run_id: gate_update_run_id.clone(),
        created_unix_ms: gate_update_pack.created_unix_ms,
        request_id: request_id.clone(),
        workflow: "procurement_connector".to_string(),
        stage: "gate".to_string(),
        risk_level: risk_level.clone(),
        needs_approval: required > 0,
        approved: gate_ok,
        gate_state: gate_update_pack
            .decision
            .get("gate_state")
            .and_then(|v| v.as_str())
            .unwrap_or("ESCALATE")
            .to_string(),
        next_step: gate_update_pack
            .decision
            .get("next_step")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
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

    match append_to_manifest(base, items) {
        Ok(_) => json!({
            "ok": true,
            "request_id": request_id,
            "gate_state": gate_update_pack.decision.get("gate_state").cloned().unwrap_or(Value::Null),
            "auth_token": gate_update_pack.decision.get("auth_token").cloned().unwrap_or(Value::Null)
        }),
        Err(e) => json!({"ok": false, "error": e.to_string()}),
    }
}

fn handle_execute_action(base: &Path, body: &[u8]) -> Value {
    let input: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return json!({"ok": false, "error": "invalid json"}),
    };

    if let Some(run_id) = input.get("run_id").and_then(|v| v.as_str()) {
        let tool = input
            .get("tool")
            .and_then(|v| v.as_str())
            .unwrap_or("finance.payment");

        let path = base.join("evidence").join(format!("{run_id}.json"));
        let txt = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(_) => return json!({"ok": false, "error": "evidence pack not found"}),
        };
        let pack: EvidencePack = match serde_json::from_str(&txt) {
            Ok(p) => p,
            Err(_) => return json!({"ok": false, "error": "bad evidence pack json"}),
        };

        let decision = &pack.decision;
        let execute_allowed = decision
            .get("execute_allowed")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let approved = decision
            .get("approved")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let needs_approval = decision
            .get("needs_approval")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let risk_level = pack
            .request
            .get("risk_level")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        if needs_approval && !approved {
            return json!({"ok": true, "authorized": false, "reason": "blocked: approval required"});
        }
        if !execute_allowed {
            return json!({"ok": true, "authorized": false, "reason": "blocked: execute_allowed=false"});
        }
        if risk_level == "high" && tool == "finance.payment" {
            return json!({"ok": true, "authorized": false, "reason": "blocked: high-risk tool restriction"});
        }

        return json!({"ok": true, "authorized": true, "reason": "allowed"});
    }

    let request_id = match input.get("request_id").and_then(|v| v.as_str()) {
        Some(v) => v.to_string(),
        None => return json!({"ok": false, "error": "missing request_id"}),
    };
    let token_id = match input.get("token_id").and_then(|v| v.as_str()) {
        Some(v) => v.to_string(),
        None => return json!({"ok": false, "error": "missing token_id"}),
    };
    let executor_id = input
        .get("executor_id")
        .and_then(|v| v.as_str())
        .unwrap_or("user:executor")
        .to_string();
    let tool = input
        .get("tool")
        .and_then(|v| v.as_str())
        .unwrap_or("finance.payment")
        .to_string();
    let action = input
        .get("action")
        .and_then(|v| v.as_str())
        .unwrap_or("execute_payment")
        .to_string();

    let params = input.get("params").cloned().unwrap_or(Value::Null);
    let vendor = params
        .get("vendor")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let amount_u64 = params
        .get("amount")
        .and_then(|v| v.as_u64())
        .or_else(|| {
            params
                .get("amount")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<u64>().ok())
        })
        .unwrap_or(0);

    let policy = load_policy_pack(base);
    let timeline = request_timeline(base, &request_id);
    let latest_gate = match latest_by_stage(&timeline, "gate") {
        Some(i) => i,
        None => return json!({"ok": false, "error": "no gate evidence for request"}),
    };
    let gate_pack = match load_pack(base, &latest_gate.run_id) {
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
        return json!({"ok": true, "authorized": false, "reason": format!("blocked: gate_state={gate_state}")});
    }

    let requester_id = gate_pack
        .request
        .get("identity")
        .and_then(|v| v.get("requester"))
        .and_then(|v| v.get("user_id"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if !requester_id.is_empty() && requester_id == executor_id {
        return json!({"ok": true, "authorized": false, "reason": "blocked: requester cannot execute"});
    }

    let token = match gate_pack.decision.get("auth_token") {
        Some(v) if v.is_object() => v.clone(),
        _ => {
            return json!({"ok": true, "authorized": false, "reason": "blocked: missing auth_token"})
        }
    };

    if token.get("token_id").and_then(|v| v.as_str()).unwrap_or("") != token_id {
        return json!({"ok": true, "authorized": false, "reason": "blocked: token mismatch"});
    }

    let expires_u64 = token
        .get("expires_unix_ms")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    if expires_u64 > 0 && (now_unix_ms() as u64) > expires_u64 {
        return json!({"ok": true, "authorized": false, "reason": "blocked: token expired"});
    }

    if token
        .get("request_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        != request_id
    {
        return json!({"ok": true, "authorized": false, "reason": "blocked: token request_id mismatch"});
    }
    if token.get("tool").and_then(|v| v.as_str()).unwrap_or("") != tool {
        return json!({"ok": true, "authorized": false, "reason": "blocked: token tool mismatch"});
    }
    if token.get("action").and_then(|v| v.as_str()).unwrap_or("") != action {
        return json!({"ok": true, "authorized": false, "reason": "blocked: token action mismatch"});
    }
    if token.get("vendor").and_then(|v| v.as_str()).unwrap_or("") != vendor {
        return json!({"ok": true, "authorized": false, "reason": "blocked: token vendor mismatch"});
    }

    let risk_level = gate_pack
        .request
        .get("risk_level")
        .and_then(|v| v.as_str())
        .unwrap_or("medium")
        .to_string();
    let required = approvals_required(&policy, &risk_level);
    let approver_ids = approval_ids(base, &timeline);
    if required > 0 && (approver_ids.len() as u32) < required {
        return json!({"ok": true, "authorized": false, "reason": "blocked: insufficient approvals"});
    }
    if approver_ids.iter().any(|a| a == &executor_id) {
        return json!({"ok": true, "authorized": false, "reason": "blocked: approver cannot execute"});
    }

    let (vendor_state, _) = vendor_gate(&policy, &vendor);
    if vendor_state == "DENY" {
        return json!({"ok": true, "authorized": false, "reason": "blocked: vendor denylist"});
    }
    if vendor_state == "ESCALATE" {
        return json!({"ok": true, "authorized": false, "reason": "blocked: vendor not allowlisted"});
    }

    let cap_u64 = token
        .get("amount_cap")
        .and_then(|v| v.as_u64())
        .unwrap_or(amount_cap(&policy, &risk_level));
    if cap_u64 > 0 && amount_u64 > cap_u64 {
        return json!({"ok": true, "authorized": false, "reason": "blocked: amount cap exceeded"});
    }

    let run_ts = run_id_unix_ms();
    let exec_run_id = format!("{run_ts}_{request_id}_execute");
    let exec_decision = json!({
        "authorized": true,
        "reason": "allowed",
        "executor_id": executor_id,
        "token_id": token_id,
        "tool": tool,
        "action": action,
        "params": params
    });

    let exec_pack = EvidencePack {
        run_id: exec_run_id.clone(),
        created_unix_ms: now_unix_ms(),
        request: gate_pack.request.clone(),
        policy_version: policy.policy_version.clone(),
        decision: exec_decision.clone(),
        decision_hash: format!("hash_{exec_run_id}"),
        replay_inputs: json!({"source":"connector_execute_action"}),
        tool_proposals: vec![],
        tool_outcomes: vec![ToolOutcome {
            tool: tool.to_string(),
            allowed: true,
            deny_reason: None,
            result: json!({"executed": true}),
        }],
        event_type: "unknown".to_string(),
        token_id: None,
        agent_id: None,
        actor: None,
    };

    let exec_svg = svg_simple("Execute", true);
    let exec_html = html_wrap("Execute", &exec_svg, &exec_decision);
    let _ = write_evidence_pack(base, &exec_run_id, &exec_svg, &exec_html, &exec_pack);

    let manifest_item = EvidenceManifestItem {
        run_id: exec_run_id.clone(),
        created_unix_ms: exec_pack.created_unix_ms,
        request_id,
        workflow: "procurement_connector".to_string(),
        stage: "execute".to_string(),
        risk_level,
        needs_approval: required > 0,
        approved: true,
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

    match append_to_manifest(base, vec![manifest_item]) {
        Ok(_) => {
            json!({"ok": true, "authorized": true, "reason": "allowed", "run_id": exec_run_id})
        }
        Err(e) => json!({"ok": false, "error": e.to_string()}),
    }
}

fn handle_conn(mut stream: TcpStream, base: PathBuf) {
    let req = match read_http_request(&mut stream) {
        Some(r) => r,
        None => return,
    };
    let (method, path_raw, _headers, body) = req;
    let path = normalize_path(&path_raw);

    if method == "OPTIONS" {
        let resp = http_response("204 No Content", "text/plain", "");
        let _ = stream.write_all(&resp);
        return;
    }

    let (status, content_type, body_str) = if method == "GET" && path == "/health" {
        (
            "200 OK",
            "application/json",
            json!({"ok": true}).to_string(),
        )
    } else if method == "GET" && path == "/policy" {
        (
            "200 OK",
            "application/json",
            handle_policy(&base).to_string(),
        )
    } else if method == "POST" && path == "/import_csv" {
        (
            "200 OK",
            "application/json",
            handle_import_csv(&base, &body).to_string(),
        )
    } else if method == "POST" && path == "/approve" {
        (
            "200 OK",
            "application/json",
            handle_approve(&base, &body).to_string(),
        )
    } else if method == "POST" && path == "/execute_action" {
        (
            "200 OK",
            "application/json",
            handle_execute_action(&base, &body).to_string(),
        )
    } else {
        (
            "404 Not Found",
            "application/json",
            json!({"ok": false, "error": "not found"}).to_string(),
        )
    };

    let resp = http_response(status, content_type, &body_str);
    let _ = stream.write_all(&resp);
}

fn main() {
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let listener = TcpListener::bind("127.0.0.1:8090").expect("bind 127.0.0.1:8090");
    println!("connector_server_listening=http://127.0.0.1:8090");
    for stream in listener.incoming() {
        if let Ok(stream) = stream {
            handle_conn(stream, base.clone());
        }
    }
}
