use only_core::Sign;
use only_core::Sign::{Minus, Plus};
use only_lang::evaluate_script;
use only_lang::evidence_pack::{
    now_unix_ms, run_id_unix_ms, write_evidence_pack, write_manifest, EvidenceManifest,
    EvidenceManifestItem, EvidencePack, ToolOutcome, ToolProposal,
};
use serde_json::json;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;

fn escape_html(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

fn sign_to_i8(s: Sign) -> i8 {
    match s {
        Sign::Plus => 1,
        Sign::Minus => -1,
    }
}

fn hash_u64_hex(parts: &[String]) -> String {
    let mut h = DefaultHasher::new();
    for p in parts {
        p.hash(&mut h);
    }
    format!("{:016x}", h.finish())
}

fn svg_report(title: &str, residuals: &[f64]) -> String {
    let w: f64 = 760.0;
    let h: f64 = 240.0;
    let ml: f64 = 50.0;
    let mt: f64 = 30.0;
    let mr: f64 = 20.0;
    let mb: f64 = 40.0;

    let pw = w - ml - mr;
    let ph = h - mt - mb;

    let mut min_y = 0.0;
    let mut max_y = 0.0;
    if !residuals.is_empty() {
        min_y = residuals[0];
        max_y = residuals[0];
        for &v in residuals {
            if v < min_y {
                min_y = v;
            }
            if v > max_y {
                max_y = v;
            }
        }
    }
    if (max_y - min_y).abs() < 1e-12 {
        max_y = min_y + 1.0;
    }

    let n = residuals.len().max(1);
    let dx = if n > 1 { pw / ((n - 1) as f64) } else { 0.0 };

    let mut points = String::new();
    for (i, &v) in residuals.iter().enumerate() {
        let x = ml + (i as f64) * dx;
        let y = mt + (max_y - v) / (max_y - min_y) * ph;
        if !points.is_empty() {
            points.push(' ');
        }
        points.push_str(&format!("{:.2},{:.2}", x, y));
    }

    let title = escape_html(title);

    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="100%" height="{h}" viewBox="0 0 {w} {h}" preserveAspectRatio="xMinYMin meet">
  <rect x="0" y="0" width="{w}" height="{h}" fill="#0b1020" />
  <text x="12" y="18" fill="#e6e8ef" font-family="monospace" font-size="14">{title}</text>
  <rect x="{ml}" y="{mt}" width="{pw}" height="{ph}" fill="#0f1730" stroke="#2b365a" />
  <polyline fill="none" stroke="#61dafb" stroke-width="2" points="{points}" />
</svg>"##,
        w = w,
        h = h,
        ml = ml,
        mt = mt,
        pw = pw,
        ph = ph,
        points = points,
        title = title,
    )
}

fn html_report(
    title: &str,
    script: &str,
    signs: &[Sign],
    field_before: &[f64],
    field_after: &[f64],
    residuals: &[f64],
    indices_healed: &[usize],
    extra_summary: &str,
    svg_inline: &str,
    svg_filename: &str,
) -> String {
    let title_esc = escape_html(title);
    let script_esc = escape_html(script.trim());
    let extra_esc = escape_html(extra_summary);

    let healed = if indices_healed.is_empty() {
        "(none)".to_string()
    } else {
        indices_healed
            .iter()
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    };

    let residual_list = if residuals.is_empty() {
        "(none)".to_string()
    } else {
        residuals
            .iter()
            .map(|v| format!("{:.6}", v))
            .collect::<Vec<_>>()
            .join(", ")
    };

    let mut table_rows = String::new();
    for i in 0..signs.len().min(field_before.len()).min(field_after.len()) {
        table_rows.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{:.6}</td><td>{:.6}</td></tr>",
            i,
            sign_to_i8(signs[i]),
            field_before[i],
            field_after[i]
        ));
    }

    format!(
        r##"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{title}</title>
  <style>
    :root {{ color-scheme: dark; }}
    body {{ background: #0b1020; color: #e6e8ef; font-family: monospace; margin: 0; padding: 16px; }}
    a {{ color: #61dafb; }}
    .box {{ background: #0f1730; border: 1px solid #2b365a; padding: 12px; margin: 12px 0; }}
    table {{ width: 100%; border-collapse: collapse; }}
    td, th {{ border-bottom: 1px solid #2b365a; padding: 6px; text-align: left; }}
    th {{ color: #aab2d5; }}
    pre {{ white-space: pre-wrap; margin: 0; }}
  </style>
</head>
<body>
  <h1 style="margin:0 0 10px 0; font-size:16px;">{title}</h1>
  <div style="color:#aab2d5;">healed_indices=[{healed}]</div>

  <div class="box"><div style="color:#aab2d5; margin-bottom:6px;">Summary</div><pre>{extra}</pre></div>

  <div class="box">{svg}<div style="margin-top:8px;"><a href="{svg_filename}">Open SVG file</a></div></div>

  <div class="box"><div style="color:#aab2d5; margin-bottom:6px;">Residual history</div><pre>{residual_list}</pre></div>

  <div class="box">
    <div style="color:#aab2d5; margin-bottom:6px;">Field (before vs after)</div>
    <table>
      <thead><tr><th>index</th><th>sign</th><th>before</th><th>after</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>

  <div class="box"><div style="color:#aab2d5; margin-bottom:6px;">Script</div><pre>{script}</pre></div>
</body>
</html>"##,
        title = title_esc,
        healed = escape_html(&healed),
        extra = extra_esc,
        svg = svg_inline,
        svg_filename = escape_html(svg_filename),
        residual_list = escape_html(&residual_list),
        rows = table_rows,
        script = script_esc,
    )
}

fn write_report_card(
    base: &PathBuf,
    slug: &str,
    title: &str,
    script: &str,
    signs: &[Sign],
    field_before: &[f64],
    field_after: &[f64],
    residuals: &[f64],
    indices_healed: &[usize],
    extra_summary: &str,
) -> (String, String) {
    let out_dir = base.join("report_cards");
    std::fs::create_dir_all(&out_dir).unwrap();

    let svg_path = out_dir.join(format!("{slug}.svg"));
    let html_path = out_dir.join(format!("{slug}.html"));

    let svg = svg_report(title, residuals);
    std::fs::write(&svg_path, &svg).unwrap();

    let svg_filename = svg_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    let html = html_report(
        title,
        script,
        signs,
        field_before,
        field_after,
        residuals,
        indices_healed,
        extra_summary,
        &svg,
        &svg_filename,
    );
    std::fs::write(&html_path, html).unwrap();

    (
        svg_path.display().to_string(),
        html_path.display().to_string(),
    )
}

fn run_budget_block(
    base: &PathBuf,
    slug: &str,
    budget_total: f64,
    request_amount: f64,
) -> (f64, String) {
    let signs = [Plus, Minus, Minus];
    let script = "harmony(1e-12) residual() evolve(2) residual() report()";

    let mut field = [budget_total, request_amount, 0.0];
    let field_before = field;

    let res = evaluate_script(&signs, &mut field, script).unwrap();

    let (_, html) = write_report_card(
        base,
        slug,
        "Budget coherence",
        script,
        &signs,
        &field_before,
        &field,
        &res.residual_history,
        &res.indices_healed,
        "repair_target=remaining_budget",
    );

    (field[2], html)
}

fn run_triage_block(
    base: &PathBuf,
    slug: &str,
    amount_scaled: f64,
    vendor_risk: f64,
) -> (f64, String) {
    let signs = [Plus, Plus, Minus];
    let script = "harmony(1e-12) residual() evolve(2) residual() report()";

    let mut field = [amount_scaled, vendor_risk, 0.0];
    let field_before = field;

    let res = evaluate_script(&signs, &mut field, script).unwrap();

    let (_, html) = write_report_card(
        base,
        slug,
        "Triage score",
        script,
        &signs,
        &field_before,
        &field,
        &res.residual_history,
        &res.indices_healed,
        "repair_target=triage_score",
    );

    (field[2], html)
}

fn main() {
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let run_ts = run_id_unix_ms();

    let workflows = vec![
        ("low", "REQ-LOW-0001", 200.0, 0.10, 2.0, 15_u128),
        ("medium", "REQ-MED-0001", 1_200.0, 0.35, 1.0, 60_u128),
        ("high", "REQ-HIGH-0001", 75_000.0, 0.70, 0.8, 15_u128),
    ];

    let mut manifest_items: Vec<EvidenceManifestItem> = Vec::new();

    for (risk_level, request_id, request_amount, vendor_risk, threshold, sla_minutes) in workflows {
        let sla_due_unix_ms = Some(now_unix_ms() + sla_minutes * 60_000);
        let budget_total = 100_000.0;
        let (budget_remaining, submit_report_html) = run_budget_block(
            &base,
            &format!("pilot_{risk_level}_submit"),
            budget_total,
            request_amount,
        );

        let submit_run_id = format!("{run_ts}_{risk_level}_submit");
        let submit_svg =
            std::fs::read_to_string(PathBuf::from(&submit_report_html).with_extension("svg"))
                .unwrap();
        let submit_html = std::fs::read_to_string(&submit_report_html)
            .unwrap()
            .replace(
                &format!("href=\"pilot_{risk_level}_submit.svg\""),
                &format!("href=\"{submit_run_id}.svg\""),
            );

        let submit_policy = "submit_budget_coherence_v0".to_string();
        let submit_hash = hash_u64_hex(&vec![
            submit_policy.clone(),
            request_id.to_string(),
            format!("amount={:.2}", request_amount),
            format!("budget_remaining={:.6}", budget_remaining),
        ]);

        let submit_pack = EvidencePack {
            run_id: submit_run_id.clone(),
            created_unix_ms: now_unix_ms(),
            request: json!({
                "workflow": "procurement_pilot",
                "risk_level": risk_level,
                "request_id": request_id,
                "amount": request_amount,
                "vendor_risk": vendor_risk,
                "sla_minutes": sla_minutes,
                "identity": {
                    "requester": { "user_id": "user:alice", "roles": ["Requester"] },
                    "delegations": [
                        { "from_role": "ProcurementOfficer", "to_role": "ProcurementDelegate", "scope": "low_risk_only" }
                    ]
                }
            }),
            policy_version: submit_policy,
            decision: json!({
                "gate_state": "ALLOW",
                "next_step": "Continue",
                "reason_codes": [],
                "evidence_requirements": {"citations": false, "assumptions": false, "uncertainty": false},
                "budget_remaining": budget_remaining,
                "repaired": true
            }),
            decision_hash: submit_hash,
            replay_inputs: json!({
                "script": "harmony(1e-12) residual() evolve(2) residual() report()",
                "signs": [1, -1, -1],
                "field_before": [budget_total, request_amount, 0.0]
            }),
            tool_proposals: vec![],
            tool_outcomes: vec![],
            event_type: "unknown".to_string(),
            token_id: None,
            agent_id: None,
            actor: None,
        };
        write_evidence_pack(
            base.as_path(),
            &submit_run_id,
            &submit_svg,
            &submit_html,
            &submit_pack,
        )
        .unwrap();

        manifest_items.push(EvidenceManifestItem {
            run_id: submit_run_id.clone(),
            created_unix_ms: submit_pack.created_unix_ms,
            request_id: request_id.to_string(),
            workflow: "procurement_pilot".to_string(),
            stage: "submit".to_string(),
            risk_level: risk_level.to_string(),
            needs_approval: false,
            approved: true,
            gate_state: "ALLOW".to_string(),
            next_step: "Continue".to_string(),
            sla_due_unix_ms,
            policy_version: submit_pack.policy_version.clone(),
            decision_hash: submit_pack.decision_hash.clone(),
            json: format!("{submit_run_id}.json"),
            html: format!("{submit_run_id}.html"),
            svg: format!("{submit_run_id}.svg"),
            event_type: "unknown".to_string(),
            token_id: None,
            agent_id: None,
            actor: None,
        });

        let amount_scaled = request_amount / 1_000.0;
        let (triage_score, triage_report_html) = run_triage_block(
            &base,
            &format!("pilot_{risk_level}_triage"),
            amount_scaled,
            vendor_risk,
        );

        let triage_run_id = format!("{run_ts}_{risk_level}_triage");
        let triage_svg =
            std::fs::read_to_string(PathBuf::from(&triage_report_html).with_extension("svg"))
                .unwrap();
        let triage_html = std::fs::read_to_string(&triage_report_html)
            .unwrap()
            .replace(
                &format!("href=\"pilot_{risk_level}_triage.svg\""),
                &format!("href=\"{triage_run_id}.svg\""),
            );

        let triage_policy = "triage_scoring_v0".to_string();
        let triage_hash = hash_u64_hex(&vec![
            triage_policy.clone(),
            request_id.to_string(),
            format!("triage_score={:.6}", triage_score),
            format!("vendor_risk={:.6}", vendor_risk),
        ]);

        let triage_pack = EvidencePack {
            run_id: triage_run_id.clone(),
            created_unix_ms: now_unix_ms(),
            request: json!({
                "workflow": "procurement_pilot",
                "risk_level": risk_level,
                "request_id": request_id,
                "amount_scaled": amount_scaled,
                "vendor_risk": vendor_risk,
                "sla_minutes": sla_minutes,
                "identity": {
                    "requester": { "user_id": "user:alice", "roles": ["Requester"] },
                    "delegations": [
                        { "from_role": "ProcurementOfficer", "to_role": "ProcurementDelegate", "scope": "low_risk_only" }
                    ]
                }
            }),
            policy_version: triage_policy,
            decision: json!({
                "gate_state": "ALLOW",
                "next_step": "Continue",
                "reason_codes": [],
                "evidence_requirements": {"citations": false, "assumptions": false, "uncertainty": false},
                "triage_score": triage_score
            }),
            decision_hash: triage_hash,
            replay_inputs: json!({
                "script": "harmony(1e-12) residual() evolve(2) residual() report()",
                "signs": [1, 1, -1],
                "field_before": [amount_scaled, vendor_risk, 0.0]
            }),
            tool_proposals: vec![],
            tool_outcomes: vec![],
            event_type: "unknown".to_string(),
            token_id: None,
            agent_id: None,
            actor: None,
        };
        write_evidence_pack(
            base.as_path(),
            &triage_run_id,
            &triage_svg,
            &triage_html,
            &triage_pack,
        )
        .unwrap();

        manifest_items.push(EvidenceManifestItem {
            run_id: triage_run_id.clone(),
            created_unix_ms: triage_pack.created_unix_ms,
            request_id: request_id.to_string(),
            workflow: "procurement_pilot".to_string(),
            stage: "triage".to_string(),
            risk_level: risk_level.to_string(),
            needs_approval: false,
            approved: true,
            gate_state: "ALLOW".to_string(),
            next_step: "Continue".to_string(),
            sla_due_unix_ms,
            policy_version: triage_pack.policy_version.clone(),
            decision_hash: triage_pack.decision_hash.clone(),
            json: format!("{triage_run_id}.json"),
            html: format!("{triage_run_id}.html"),
            svg: format!("{triage_run_id}.svg"),
            event_type: "unknown".to_string(),
            token_id: None,
            agent_id: None,
            actor: None,
        });

        let needs_approval = risk_level != "low";
        let approvals_required = if risk_level == "high" {
            2
        } else if needs_approval {
            1
        } else {
            0
        };
        let approvals_received = 0_u32;
        let approved = !needs_approval;
        let execute_allowed = approved && budget_remaining >= 0.0;

        let gate_parts = vec![
            format!("risk={risk_level}"),
            request_id.to_string(),
            format!("threshold={threshold:.3}"),
            format!("triage_score={triage_score:.6}"),
            format!("needs_approval={needs_approval}"),
            format!("approved={approved}"),
            format!("execute_allowed={execute_allowed}"),
        ];
        let gate_hash = hash_u64_hex(&gate_parts);

        let gate_run_id = format!("{run_ts}_{risk_level}_gate");
        let gate_svg = svg_report("Decision gate", &[]);
        let gate_html = format!(
            r#"<!doctype html><html lang="en"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/><title>Gate</title><style>body{{background:#0b1020;color:#e6e8ef;font-family:monospace;padding:16px}}.box{{background:#0f1730;border:1px solid #2b365a;padding:12px;margin:12px 0}}</style></head><body><h1>Decision gate</h1><div class="box">request_id={request_id}<br/>risk={risk_level}<br/>triage_score={triage_score:.6}<br/>threshold={threshold:.3}<br/>needs_approval={needs_approval}<br/>approved={approved}<br/>execute_allowed={execute_allowed}</div><div class="box">{gate_svg}</div><div class="box"><a href="{gate_run_id}.svg">Open SVG file</a></div></body></html>"#
        );

        let gate_pack = EvidencePack {
            run_id: gate_run_id.clone(),
            created_unix_ms: now_unix_ms(),
            request: json!({
                "workflow": "procurement_pilot",
                "risk_level": risk_level,
                "request_id": request_id,
                "amount": request_amount,
                "vendor_risk": vendor_risk,
                "triage_score": triage_score,
                "sla_minutes": sla_minutes,
                "identity": {
                    "requester": { "user_id": "user:alice", "roles": ["Requester"] },
                    "delegations": [
                        { "from_role": "ProcurementOfficer", "to_role": "ProcurementDelegate", "scope": "low_risk_only" }
                    ]
                }
            }),
            policy_version: format!("gate(threshold={threshold:.3})"),
            decision: json!({
                "gate_state": if needs_approval && !approved { "ESCALATE" } else { "ALLOW" },
                "next_step": if needs_approval && !approved { "Await approval" } else { "Proceed" },
                "reason_codes": if needs_approval && !approved { json!(["approval_required"]) } else { json!([]) },
                "evidence_requirements": {"citations": false, "assumptions": false, "uncertainty": false},
                "needs_approval": needs_approval,
                "approved": approved,
                "approvals_required": approvals_required,
                "approvals_received": approvals_received,
                "execute_allowed": execute_allowed,
                "sla_due_unix_ms": sla_due_unix_ms.unwrap(),
                "restricted_tools": if risk_level == "high" { json!(["finance.payment"]) } else { json!([]) }
            }),
            decision_hash: gate_hash.clone(),
            replay_inputs: json!({
                "decision_parts": gate_parts
            }),
            tool_proposals: vec![],
            tool_outcomes: vec![],
            event_type: "unknown".to_string(),
            token_id: None,
            agent_id: None,
            actor: None,
        };
        write_evidence_pack(
            base.as_path(),
            &gate_run_id,
            &gate_svg,
            &gate_html,
            &gate_pack,
        )
        .unwrap();

        manifest_items.push(EvidenceManifestItem {
            run_id: gate_run_id.clone(),
            created_unix_ms: gate_pack.created_unix_ms,
            request_id: request_id.to_string(),
            workflow: "procurement_pilot".to_string(),
            stage: "gate".to_string(),
            risk_level: risk_level.to_string(),
            needs_approval,
            approved,
            gate_state: (if needs_approval && !approved {
                "ESCALATE"
            } else {
                "ALLOW"
            })
            .to_string(),
            next_step: (if needs_approval && !approved {
                "Await approval"
            } else {
                "Proceed"
            })
            .to_string(),
            sla_due_unix_ms,
            policy_version: gate_pack.policy_version.clone(),
            decision_hash: gate_pack.decision_hash.clone(),
            json: format!("{gate_run_id}.json"),
            html: format!("{gate_run_id}.html"),
            svg: format!("{gate_run_id}.svg"),
            event_type: "unknown".to_string(),
            token_id: None,
            agent_id: None,
            actor: None,
        });

        let tool_run_id = format!("{run_ts}_{risk_level}_tool");
        let tool_allowed = execute_allowed && risk_level != "high";
        let deny_reason = if tool_allowed {
            None
        } else if !execute_allowed {
            Some("blocked: not authorized".to_string())
        } else {
            Some("blocked: restricted tool in high-risk workflow".to_string())
        };

        let tool_svg = svg_report("Tool gating", &[]);
        let tool_html = format!(
            r##"<!doctype html><html lang="en"><head><meta charset="utf-8"/><title>Tool gating</title><style>body{{background:#0b1020;color:#e6e8ef;font-family:monospace;padding:16px}}.box{{background:#0f1730;border:1px solid #2b365a;padding:12px;margin:12px 0}}</style></head><body><h1>Tool gating</h1><div class="box">request_id={request_id}<br/>risk={risk_level}<br/>execute_allowed={execute_allowed}<br/>tool_allowed={tool_allowed}<br/>deny_reason={deny}</div><div class="box">{tool_svg}</div><div class="box"><a href="{tool_run_id}.svg">Open SVG file</a></div></body></html>"##,
            deny = escape_html(&deny_reason.clone().unwrap_or_else(|| "(none)".to_string()))
        );

        let tool_proposals = vec![ToolProposal {
            tool: "finance.payment".to_string(),
            action: "execute_payment".to_string(),
            params: json!({"vendor": "ACME", "amount": request_amount}),
        }];
        let tool_outcomes = vec![ToolOutcome {
            tool: "finance.payment".to_string(),
            allowed: tool_allowed,
            deny_reason: deny_reason.clone(),
            result: json!({"executed": tool_allowed}),
        }];

        let tool_pack = EvidencePack {
            run_id: tool_run_id.clone(),
            created_unix_ms: now_unix_ms(),
            request: json!({
                "workflow": "procurement_pilot",
                "risk_level": risk_level,
                "request_id": request_id,
                "tool": "finance.payment",
                "action": "execute_payment",
                "sla_minutes": sla_minutes,
                "identity": {
                    "requester": { "user_id": "user:alice", "roles": ["Requester"] },
                    "delegations": [
                        { "from_role": "ProcurementOfficer", "to_role": "ProcurementDelegate", "scope": "low_risk_only" }
                    ]
                }
            }),
            policy_version: "tool_gating_v0".to_string(),
            decision: json!({
                "gate_state": if tool_allowed { "ALLOW" } else { "DENY" },
                "next_step": if tool_allowed { "Execute" } else { "Escalate" },
                "sla_due_unix_ms": sla_due_unix_ms,
                "reason_codes": if tool_allowed { json!([]) } else if !execute_allowed { json!(["not_authorized"]) } else { json!(["restricted_tool"]) },
                "evidence_requirements": {"citations": false, "assumptions": false, "uncertainty": false},
                "execute_allowed": execute_allowed,
                "tool_allowed": tool_allowed,
                "deny_reason": deny_reason
            }),
            decision_hash: hash_u64_hex(&vec![tool_run_id.clone(), gate_hash.clone()]),
            replay_inputs: json!({
                "gate_hash": gate_hash
            }),
            tool_proposals,
            tool_outcomes,
            event_type: "unknown".to_string(),
            token_id: None,
            agent_id: None,
            actor: None,
        };
        write_evidence_pack(
            base.as_path(),
            &tool_run_id,
            &tool_svg,
            &tool_html,
            &tool_pack,
        )
        .unwrap();

        manifest_items.push(EvidenceManifestItem {
            run_id: tool_run_id.clone(),
            created_unix_ms: tool_pack.created_unix_ms,
            request_id: request_id.to_string(),
            workflow: "procurement_pilot".to_string(),
            stage: "tool".to_string(),
            risk_level: risk_level.to_string(),
            needs_approval,
            approved,
            gate_state: (if tool_allowed { "ALLOW" } else { "DENY" }).to_string(),
            next_step: (if tool_allowed { "Execute" } else { "Escalate" }).to_string(),
            sla_due_unix_ms,
            policy_version: tool_pack.policy_version.clone(),
            decision_hash: tool_pack.decision_hash.clone(),
            json: format!("{tool_run_id}.json"),
            html: format!("{tool_run_id}.html"),
            svg: format!("{tool_run_id}.svg"),
            event_type: "unknown".to_string(),
            token_id: None,
            agent_id: None,
            actor: None,
        });
    }

    let manifest = EvidenceManifest {
        generated_unix_ms: now_unix_ms(),
        packs: manifest_items,
    };
    let manifest_path = write_manifest(base.as_path(), &manifest).unwrap();

    println!("evidence_manifest={}", manifest_path.display());
}
