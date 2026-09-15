use only_lang::evidence_pack::{
    sort_manifest_desc, write_evidence_pack, write_manifest, EvidenceManifest,
    EvidenceManifestItem, EvidencePack, ToolOutcome, ToolProposal,
};
use serde_json::{json, Value};
use std::path::PathBuf;

fn svg_gate(title: &str, gate_state: &str) -> String {
    let (label, color) = match gate_state {
        "ALLOW" => ("ALLOW", "#19c37d"),
        "DENY" => ("DENY", "#ef4444"),
        "ESCALATE" => ("ESCALATE", "#f59e0b"),
        _ => (gate_state, "#94a3b8"),
    };

    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="100%" height="180" viewBox="0 0 760 180" preserveAspectRatio="xMinYMin meet">
  <rect x="0" y="0" width="760" height="180" rx="12" fill="#0f1730" stroke="#2b365a" />
  <text x="24" y="46" fill="#e6e8ef" font-family="monospace" font-size="22">{title}</text>
  <rect x="24" y="70" width="220" height="48" rx="10" fill="{color}" />
  <text x="40" y="103" fill="#0b1020" font-family="monospace" font-size="24">{label}</text>
  <text x="24" y="152" fill="#aab2d5" font-family="monospace" font-size="14">ONLY Lang evidence artifact</text>
</svg>"##,
        title = title,
        label = label,
        color = color
    )
}

fn html_wrap(title: &str, svg: &str, detail: &Value) -> String {
    let json_pretty = serde_json::to_string_pretty(detail).unwrap_or_else(|_| "{}".to_string());
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

fn pack(
    run_id: &str,
    created_unix_ms: u128,
    request: Value,
    policy_version: &str,
    decision: Value,
    replay_inputs: Value,
    tool_proposals: Vec<ToolProposal>,
    tool_outcomes: Vec<ToolOutcome>,
) -> EvidencePack {
    EvidencePack {
        run_id: run_id.to_string(),
        created_unix_ms,
        request,
        policy_version: policy_version.to_string(),
        decision,
        decision_hash: format!("hash_{run_id}"),
        replay_inputs,
        tool_proposals,
        tool_outcomes,
        event_type: "unknown".to_string(),
        token_id: None,
        agent_id: None,
        actor: None,
    }
}

fn read_manifest(base: &PathBuf) -> EvidenceManifest {
    let path = base.join("evidence").join("manifest.json");
    let Ok(txt) = std::fs::read_to_string(&path) else {
        return EvidenceManifest {
            generated_unix_ms: 0,
            packs: vec![],
        };
    };
    serde_json::from_str::<EvidenceManifest>(&txt).unwrap_or(EvidenceManifest {
        generated_unix_ms: 0,
        packs: vec![],
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let policy_version = "only_control_golden_v0";

    let mut new_items: Vec<EvidenceManifestItem> = Vec::new();

    let created_base: u128 = 1700000000000;

    let scenarios = vec![
        (
            "REQ-GOV-001",
            "government.procurement",
            "high",
            "ESCALATE",
            "Await approvals",
            json!({"vendor":"ACME","amount":25000,"memo":"Purchase order","identity":{"requester_id":"user:requester"}}),
            json!({"reason_codes":["approval_required"],"approvals_required":2,"approvals_received":0}),
        ),
        (
            "REQ-MED-001",
            "medical.vitals",
            "medium",
            "ESCALATE",
            "Clinician review",
            json!({"patient_id":"PAT-001","vitals":{"heart_rate":132,"glucose":220,"blood_pressure":{"systolic":162,"diastolic":98}},"identity":{"requester_id":"user:nurse"}}),
            json!({"reason_codes":["vitals_anomaly"],"anomaly_score":0.91}),
        ),
        (
            "REQ-FIN-001",
            "finance.payment",
            "low",
            "ALLOW",
            "Execute",
            json!({"vendor":"CITY-SUPPLY","amount":125,"purpose":"Recurring supplies","identity":{"requester_id":"user:analyst"}}),
            json!({"reason_codes":[],"amount_cap":1000}),
        ),
    ];

    for (idx, (request_id, workflow, risk_level, gate_state, next_step, request_payload, extra)) in
        scenarios.into_iter().enumerate()
    {
        let created_unix_ms = created_base + (idx as u128) * 1000;
        let run_id = format!("GOLDEN_{request_id}_gate");

        let decision = json!({
            "gate_state": gate_state,
            "next_step": next_step,
            "needs_approval": gate_state == "ESCALATE",
            "approved": gate_state == "ALLOW",
            "execute_allowed": gate_state == "ALLOW",
            "extra": extra
        });

        let replay_inputs = json!({
            "script": "harmony(1e-12) residual() evolve(2) residual() report()",
            "llm": {
                "provider": "gemini",
                "model": "gemini-2.0-flash",
                "prompt": "Decide if this request can proceed.",
                "response": "GATE=ESCALATE if approvals required; otherwise ALLOW.",
                "observed": false
            }
        });

        let tool_proposals = vec![ToolProposal {
            tool: workflow.to_string(),
            action: "gate".to_string(),
            params: json!({"request_id": request_id}),
        }];

        let tool_outcomes = vec![ToolOutcome {
            tool: workflow.to_string(),
            allowed: gate_state == "ALLOW",
            deny_reason: if gate_state == "DENY" {
                Some("policy_denied".to_string())
            } else {
                None
            },
            result: json!({"gate_state": gate_state}),
        }];

        let pack = pack(
            &run_id,
            created_unix_ms,
            json!({"request_id": request_id, "payload": request_payload}),
            policy_version,
            decision.clone(),
            replay_inputs,
            tool_proposals,
            tool_outcomes,
        );

        let svg = svg_gate(&format!("{request_id} gate"), gate_state);
        let html = html_wrap(
            &format!("{request_id} gate"),
            &svg,
            &json!({"request": pack.request, "decision": decision}),
        );

        write_evidence_pack(&base, &run_id, &svg, &html, &pack)?;

        new_items.push(EvidenceManifestItem {
            run_id: run_id.clone(),
            created_unix_ms,
            request_id: request_id.to_string(),
            workflow: workflow.to_string(),
            stage: "gate".to_string(),
            risk_level: risk_level.to_string(),
            needs_approval: gate_state == "ESCALATE",
            approved: gate_state == "ALLOW",
            gate_state: gate_state.to_string(),
            next_step: next_step.to_string(),
            sla_due_unix_ms: None,
            policy_version: policy_version.to_string(),
            decision_hash: pack.decision_hash.clone(),
            json: format!("{run_id}.json"),
            html: format!("{run_id}.html"),
            svg: format!("{run_id}.svg"),
            event_type: "unknown".to_string(),
            token_id: None,
            agent_id: None,
            actor: None,
        });
    }

    let mut existing = read_manifest(&base);
    let new_run_ids: std::collections::HashSet<String> =
        new_items.iter().map(|i| i.run_id.clone()).collect();
    existing.packs.retain(|p| !new_run_ids.contains(&p.run_id));
    existing.packs.extend(new_items);
    existing.generated_unix_ms = 1700000000999;
    sort_manifest_desc(&mut existing);
    write_manifest(&base, &existing)?;

    println!(
        "Wrote golden evidence packs into {}/evidence",
        base.display()
    );
    Ok(())
}
