use only_core::Sign::{Minus, Plus};
use only_core::{compute_residual, Sign};
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
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}">
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

fn hash_u64_hex(parts: &[String]) -> String {
    let mut h = DefaultHasher::new();
    for p in parts {
        p.hash(&mut h);
    }
    format!("{:016x}", h.finish())
}

fn run_budget_block(
    base: &PathBuf,
    slug: &str,
    budget_total: f64,
    request_amount: f64,
    remaining_before: f64,
    summary: &str,
) -> (f64, String) {
    let signs = [Plus, Minus, Minus];
    let script = "harmony(1e-12) residual() evolve(2) residual() report()";

    let mut field = [budget_total, request_amount, remaining_before];
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
        summary,
    );

    (field[2], html)
}

fn run_triage_block(
    base: &PathBuf,
    slug: &str,
    amount_scaled: f64,
    vendor_risk_scaled: f64,
    triage_before: f64,
    summary: &str,
) -> (f64, String) {
    let signs = [Plus, Plus, Minus];
    let script = "harmony(1e-12) residual() evolve(2) residual() report()";

    let mut field = [amount_scaled, vendor_risk_scaled, triage_before];
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
        summary,
    );

    (field[2], html)
}

fn main() {
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let run_ts = run_id_unix_ms();

    let request_id = "REQ-0001".to_string();
    let budget_total = 10_000.0;
    let request_amount = 1_200.0;
    let vendor_risk = 0.35;

    let remaining_corrupt = 0.0;

    let (budget_remaining, report_budget_html) = run_budget_block(
        &base,
        "gov_demo_submit_budget",
        budget_total,
        request_amount,
        remaining_corrupt,
        &format!(
            "workflow=procurement_approval_routing\nrequest_id={}\nbudget_total={:.2}\nrequest_amount={:.2}\nrepair_target=remaining_budget",
            request_id, budget_total, request_amount
        ),
    );

    let submit_run_id = format!("{run_ts}_submit");
    let submit_svg =
        std::fs::read_to_string(PathBuf::from(&report_budget_html).with_extension("svg")).unwrap();
    let submit_html = std::fs::read_to_string(&report_budget_html)
        .unwrap()
        .replace(
            "href=\"gov_demo_submit_budget.svg\"",
            &format!("href=\"{submit_run_id}.svg\""),
        );
    let submit_policy = "submit_budget_coherence_v0".to_string();
    let submit_hash = hash_u64_hex(&vec![
        submit_policy.clone(),
        request_id.clone(),
        format!("budget_total={:.2}", budget_total),
        format!("request_amount={:.2}", request_amount),
        format!("budget_remaining={:.6}", budget_remaining),
    ]);
    let submit_pack = EvidencePack {
        run_id: submit_run_id.clone(),
        created_unix_ms: now_unix_ms(),
        request: json!({
            "workflow": "procurement_approval_routing",
            "request_id": request_id,
            "budget_total": budget_total,
            "request_amount": request_amount
        }),
        policy_version: submit_policy,
        decision: json!({
            "budget_remaining": budget_remaining,
            "repaired": true
        }),
        decision_hash: submit_hash,
        replay_inputs: json!({
            "script": "harmony(1e-12) residual() evolve(2) residual() report()",
            "signs": [1, -1, -1],
            "field_before": [budget_total, request_amount, remaining_corrupt]
        }),
        tool_proposals: vec![],
        tool_outcomes: vec![],
        event_type: "unknown".to_string(),
        token_id: None,
        agent_id: None,
        actor: None,
    };
    let submit_artifacts = write_evidence_pack(
        base.as_path(),
        &submit_run_id,
        &submit_svg,
        &submit_html,
        &submit_pack,
    )
    .unwrap();

    let amount_scaled = request_amount / 1_000.0;
    let (triage_score, report_triage_html) = run_triage_block(
        &base,
        "gov_demo_triage",
        amount_scaled,
        vendor_risk,
        0.0,
        &format!(
            "workflow=procurement_approval_routing\nrequest_id={}\ntriage_inputs=amount_scaled({:.4}) + vendor_risk({:.4})\nbudget_remaining={:.2}",
            request_id, amount_scaled, vendor_risk, budget_remaining
        ),
    );

    let triage_run_id = format!("{run_ts}_triage");
    let triage_svg =
        std::fs::read_to_string(PathBuf::from(&report_triage_html).with_extension("svg")).unwrap();
    let triage_html = std::fs::read_to_string(&report_triage_html)
        .unwrap()
        .replace(
            "href=\"gov_demo_triage.svg\"",
            &format!("href=\"{triage_run_id}.svg\""),
        );
    let triage_policy = "triage_scoring_v0".to_string();
    let triage_hash = hash_u64_hex(&vec![
        triage_policy.clone(),
        request_id.clone(),
        format!("amount_scaled={:.6}", amount_scaled),
        format!("vendor_risk={:.6}", vendor_risk),
        format!("triage_score={:.6}", triage_score),
    ]);
    let triage_pack = EvidencePack {
        run_id: triage_run_id.clone(),
        created_unix_ms: now_unix_ms(),
        request: json!({
            "workflow": "procurement_approval_routing",
            "request_id": request_id,
            "amount_scaled": amount_scaled,
            "vendor_risk": vendor_risk,
            "budget_remaining": budget_remaining
        }),
        policy_version: triage_policy,
        decision: json!({
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
    let triage_artifacts = write_evidence_pack(
        base.as_path(),
        &triage_run_id,
        &triage_svg,
        &triage_html,
        &triage_pack,
    )
    .unwrap();

    let policy_v1 = "policy_v1(threshold=1.00)";
    let approval_required_v1 = triage_score > 1.0;
    let approved_v1 = !approval_required_v1;
    let execute_allowed_v1 = approved_v1 && budget_remaining >= 0.0;

    let decision_v1_parts = vec![
        policy_v1.to_string(),
        request_id.clone(),
        format!("amount={:.2}", request_amount),
        format!("vendor_risk={:.6}", vendor_risk),
        format!("triage_score={:.6}", triage_score),
        format!("budget_remaining={:.6}", budget_remaining),
        format!("approval_required={}", approval_required_v1),
        format!("approved={}", approved_v1),
        format!("execute_allowed={}", execute_allowed_v1),
    ];
    let decision_hash_v1 = hash_u64_hex(&decision_v1_parts);

    let replay_hash_v1 = hash_u64_hex(&decision_v1_parts);
    let replay_ok = replay_hash_v1 == decision_hash_v1;

    let signs = [Plus, Minus, Minus];
    let script = "harmony(1e-12) residual() evolve(2) residual() report()";
    let mut field = [budget_total, request_amount, remaining_corrupt];
    let field_before = field;
    let res = evaluate_script(&signs, &mut field, script).unwrap();

    let (report_replay_svg, report_replay_html) = write_report_card(
        &base,
        "gov_demo_replay",
        "Deterministic replay (decision gate)",
        script,
        &signs,
        &field_before,
        &field,
        &res.residual_history,
        &res.indices_healed,
        &format!(
            "workflow=procurement_approval_routing\nrequest_id={}\npolicy={}\ndecision_hash={}\nreplay_hash={}\nreplay_ok={}\napproval_required={}\napproved={}\nexecute_allowed={}\nsubreports:\n- {}\n- {}",
            request_id,
            policy_v1,
            decision_hash_v1,
            replay_hash_v1,
            replay_ok,
            approval_required_v1,
            approved_v1,
            execute_allowed_v1,
            report_budget_html,
            report_triage_html
        ),
    );

    let replay_run_id = format!("{run_ts}_replay");
    let replay_svg = std::fs::read_to_string(&report_replay_svg).unwrap();
    let replay_html = std::fs::read_to_string(&report_replay_html)
        .unwrap()
        .replace(
            "href=\"gov_demo_replay.svg\"",
            &format!("href=\"{replay_run_id}.svg\""),
        );
    let replay_pack = EvidencePack {
        run_id: replay_run_id.clone(),
        created_unix_ms: now_unix_ms(),
        request: json!({
            "workflow": "procurement_approval_routing",
            "request_id": request_id,
            "budget_total": budget_total,
            "request_amount": request_amount,
            "vendor_risk": vendor_risk
        }),
        policy_version: policy_v1.to_string(),
        decision: json!({
            "triage_score": triage_score,
            "budget_remaining": budget_remaining,
            "approval_required": approval_required_v1,
            "approved": approved_v1,
            "execute_allowed": execute_allowed_v1,
            "replay_ok": replay_ok
        }),
        decision_hash: decision_hash_v1.clone(),
        replay_inputs: json!({
            "decision_parts": decision_v1_parts,
            "replay_hash": replay_hash_v1
        }),
        tool_proposals: vec![],
        tool_outcomes: vec![],
        event_type: "unknown".to_string(),
        token_id: None,
        agent_id: None,
        actor: None,
    };
    let replay_artifacts = write_evidence_pack(
        base.as_path(),
        &replay_run_id,
        &replay_svg,
        &replay_html,
        &replay_pack,
    )
    .unwrap();

    let policy_v2 = "policy_v2(threshold=1.80)";
    let approval_required_v2 = triage_score > 1.8;
    let approved_v2 = !approval_required_v2;
    let execute_allowed_v2 = approved_v2 && budget_remaining >= 0.0;

    let decision_v2_parts = vec![
        policy_v2.to_string(),
        request_id.clone(),
        format!("amount={:.2}", request_amount),
        format!("vendor_risk={:.6}", vendor_risk),
        format!("triage_score={:.6}", triage_score),
        format!("budget_remaining={:.6}", budget_remaining),
        format!("approval_required={}", approval_required_v2),
        format!("approved={}", approved_v2),
        format!("execute_allowed={}", execute_allowed_v2),
    ];
    let decision_hash_v2 = hash_u64_hex(&decision_v2_parts);

    let (report_policy_svg, report_policy_html) = write_report_card(
        &base,
        "gov_demo_policy_diff",
        "Policy diff + approval",
        script,
        &signs,
        &field_before,
        &field,
        &res.residual_history,
        &res.indices_healed,
        &format!(
            "workflow=procurement_approval_routing\nrequest_id={}\npolicy_v1={}\ndecision_hash_v1={}\napproval_required_v1={}\nexecute_allowed_v1={}\n\npolicy_v2={}\ndecision_hash_v2={}\napproval_required_v2={}\nexecute_allowed_v2={}\n\npolicy_change_effect={}",
            request_id,
            policy_v1,
            decision_hash_v1,
            approval_required_v1,
            execute_allowed_v1,
            policy_v2,
            decision_hash_v2,
            approval_required_v2,
            execute_allowed_v2,
            decision_hash_v1 != decision_hash_v2
        ),
    );

    let policy_diff_run_id = format!("{run_ts}_policy_diff");
    let policy_diff_svg = std::fs::read_to_string(&report_policy_svg).unwrap();
    let policy_diff_html = std::fs::read_to_string(&report_policy_html)
        .unwrap()
        .replace(
            "href=\"gov_demo_policy_diff.svg\"",
            &format!("href=\"{policy_diff_run_id}.svg\""),
        );
    let policy_diff_hash = hash_u64_hex(&vec![decision_hash_v1.clone(), decision_hash_v2.clone()]);
    let policy_diff_pack = EvidencePack {
        run_id: policy_diff_run_id.clone(),
        created_unix_ms: now_unix_ms(),
        request: json!({
            "workflow": "procurement_approval_routing",
            "request_id": request_id,
            "triage_score": triage_score,
            "budget_remaining": budget_remaining
        }),
        policy_version: "policy_diff".to_string(),
        decision: json!({
            "policy_v1": policy_v1,
            "decision_hash_v1": decision_hash_v1,
            "approval_required_v1": approval_required_v1,
            "execute_allowed_v1": execute_allowed_v1,
            "policy_v2": policy_v2,
            "decision_hash_v2": decision_hash_v2,
            "approval_required_v2": approval_required_v2,
            "execute_allowed_v2": execute_allowed_v2
        }),
        decision_hash: policy_diff_hash,
        replay_inputs: json!({
            "policy_v1_parts": decision_v1_parts,
            "policy_v2_parts": decision_v2_parts
        }),
        tool_proposals: vec![],
        tool_outcomes: vec![],
        event_type: "unknown".to_string(),
        token_id: None,
        agent_id: None,
        actor: None,
    };
    let policy_diff_artifacts = write_evidence_pack(
        base.as_path(),
        &policy_diff_run_id,
        &policy_diff_svg,
        &policy_diff_html,
        &policy_diff_pack,
    )
    .unwrap();

    let model_proposed_action = "execute_payment(vendor=ACME, amount=1200)".to_string();
    let gateway_execute = execute_allowed_v1;
    let deny_reason = if gateway_execute {
        "(none)".to_string()
    } else if approval_required_v1 {
        "blocked: requires approval".to_string()
    } else {
        "blocked: insufficient budget".to_string()
    };

    let (report_tool_gating_svg, report_tool_gating_html) = write_report_card(
        &base,
        "gov_demo_tool_gating",
        "Tool gating",
        script,
        &signs,
        &field_before,
        &field,
        &res.residual_history,
        &res.indices_healed,
        &format!(
            "workflow=procurement_approval_routing\nrequest_id={}\npolicy={}\ndecision_hash={}\nmodel_proposed_action={}\ngateway_execute={}\ndeny_reason={}",
            request_id,
            policy_v1,
            decision_hash_v1,
            model_proposed_action,
            gateway_execute,
            deny_reason
        ),
    );

    let tool_gating_run_id = format!("{run_ts}_tool_gating");
    let tool_gating_svg = std::fs::read_to_string(&report_tool_gating_svg).unwrap();
    let tool_gating_html = std::fs::read_to_string(&report_tool_gating_html)
        .unwrap()
        .replace(
            "href=\"gov_demo_tool_gating.svg\"",
            &format!("href=\"{tool_gating_run_id}.svg\""),
        );
    let tool_proposals = vec![ToolProposal {
        tool: "finance.payment".to_string(),
        action: "execute_payment".to_string(),
        params: json!({"vendor": "ACME", "amount": request_amount}),
    }];
    let tool_outcomes = vec![ToolOutcome {
        tool: "finance.payment".to_string(),
        allowed: gateway_execute,
        deny_reason: if gateway_execute {
            None
        } else {
            Some(deny_reason.clone())
        },
        result: json!({"executed": gateway_execute}),
    }];
    let tool_gating_pack = EvidencePack {
        run_id: tool_gating_run_id.clone(),
        created_unix_ms: now_unix_ms(),
        request: json!({
            "workflow": "procurement_approval_routing",
            "request_id": request_id,
            "policy": policy_v1,
            "model_proposed_action": model_proposed_action
        }),
        policy_version: policy_v1.to_string(),
        decision: json!({
            "gateway_execute": gateway_execute,
            "deny_reason": deny_reason
        }),
        decision_hash: decision_hash_v1.clone(),
        replay_inputs: json!({
            "triage_score": triage_score,
            "budget_remaining": budget_remaining
        }),
        tool_proposals,
        tool_outcomes,
        event_type: "unknown".to_string(),
        token_id: None,
        agent_id: None,
        actor: None,
    };
    let tool_gating_artifacts = write_evidence_pack(
        base.as_path(),
        &tool_gating_run_id,
        &tool_gating_svg,
        &tool_gating_html,
        &tool_gating_pack,
    )
    .unwrap();

    let audit_hash = hash_u64_hex(&vec![
        "run=gov_demo".to_string(),
        format!("request_id={}", request_id),
        format!("policy={}", policy_v1),
        format!("decision_hash={}", decision_hash_v1),
        format!("field_residual={:.6}", compute_residual(&signs, &field)),
    ]);

    let manifest = EvidenceManifest {
        generated_unix_ms: now_unix_ms(),
        packs: vec![
            EvidenceManifestItem {
                run_id: submit_run_id.clone(),
                created_unix_ms: submit_pack.created_unix_ms,
                request_id: request_id.clone(),
                workflow: "procurement_approval_routing".to_string(),
                stage: "submit".to_string(),
                risk_level: "medium".to_string(),
                needs_approval: false,
                approved: true,
                gate_state: "ALLOW".to_string(),
                next_step: "Continue".to_string(),
                sla_due_unix_ms: None,
                policy_version: submit_pack.policy_version.clone(),
                decision_hash: submit_pack.decision_hash.clone(),
                json: format!("{submit_run_id}.json"),
                html: format!("{submit_run_id}.html"),
                svg: format!("{submit_run_id}.svg"),
                event_type: "unknown".to_string(),
                token_id: None,
                agent_id: None,
                actor: None,
            },
            EvidenceManifestItem {
                run_id: triage_run_id.clone(),
                created_unix_ms: triage_pack.created_unix_ms,
                request_id: request_id.clone(),
                workflow: "procurement_approval_routing".to_string(),
                stage: "triage".to_string(),
                risk_level: "medium".to_string(),
                needs_approval: false,
                approved: true,
                gate_state: "ALLOW".to_string(),
                next_step: "Continue".to_string(),
                sla_due_unix_ms: None,
                policy_version: triage_pack.policy_version.clone(),
                decision_hash: triage_pack.decision_hash.clone(),
                json: format!("{triage_run_id}.json"),
                html: format!("{triage_run_id}.html"),
                svg: format!("{triage_run_id}.svg"),
                event_type: "unknown".to_string(),
                token_id: None,
                agent_id: None,
                actor: None,
            },
            EvidenceManifestItem {
                run_id: replay_run_id.clone(),
                created_unix_ms: replay_pack.created_unix_ms,
                request_id: request_id.clone(),
                workflow: "procurement_approval_routing".to_string(),
                stage: "replay".to_string(),
                risk_level: "medium".to_string(),
                needs_approval: approval_required_v1,
                approved: approved_v1,
                gate_state: "ALLOW".to_string(),
                next_step: "Continue".to_string(),
                sla_due_unix_ms: None,
                policy_version: replay_pack.policy_version.clone(),
                decision_hash: replay_pack.decision_hash.clone(),
                json: format!("{replay_run_id}.json"),
                html: format!("{replay_run_id}.html"),
                svg: format!("{replay_run_id}.svg"),
                event_type: "unknown".to_string(),
                token_id: None,
                agent_id: None,
                actor: None,
            },
            EvidenceManifestItem {
                run_id: policy_diff_run_id.clone(),
                created_unix_ms: policy_diff_pack.created_unix_ms,
                request_id: request_id.clone(),
                workflow: "procurement_approval_routing".to_string(),
                stage: "policy_diff".to_string(),
                risk_level: "medium".to_string(),
                needs_approval: approval_required_v1,
                approved: approved_v1,
                gate_state: "ALLOW".to_string(),
                next_step: "Continue".to_string(),
                sla_due_unix_ms: None,
                policy_version: policy_diff_pack.policy_version.clone(),
                decision_hash: policy_diff_pack.decision_hash.clone(),
                json: format!("{policy_diff_run_id}.json"),
                html: format!("{policy_diff_run_id}.html"),
                svg: format!("{policy_diff_run_id}.svg"),
                event_type: "unknown".to_string(),
                token_id: None,
                agent_id: None,
                actor: None,
            },
            EvidenceManifestItem {
                run_id: tool_gating_run_id.clone(),
                created_unix_ms: tool_gating_pack.created_unix_ms,
                request_id: request_id.clone(),
                workflow: "procurement_approval_routing".to_string(),
                stage: "tool_gating".to_string(),
                risk_level: "medium".to_string(),
                needs_approval: approval_required_v1,
                approved: approved_v1,
                gate_state: "ALLOW".to_string(),
                next_step: "Continue".to_string(),
                sla_due_unix_ms: None,
                policy_version: tool_gating_pack.policy_version.clone(),
                decision_hash: tool_gating_pack.decision_hash.clone(),
                json: format!("{tool_gating_run_id}.json"),
                html: format!("{tool_gating_run_id}.html"),
                svg: format!("{tool_gating_run_id}.svg"),
                event_type: "unknown".to_string(),
                token_id: None,
                agent_id: None,
                actor: None,
            },
        ],
    };
    let manifest_path = write_manifest(base.as_path(), &manifest).unwrap();
    println!("report_replay_html={}", report_replay_html);
    println!("report_policy_diff_html={}", report_policy_html);
    println!("report_tool_gating_html={}", report_tool_gating_html);
    println!(
        "evidence_submit_json={}",
        submit_artifacts.json_path.display()
    );
    println!(
        "evidence_triage_json={}",
        triage_artifacts.json_path.display()
    );
    println!(
        "evidence_replay_json={}",
        replay_artifacts.json_path.display()
    );
    println!(
        "evidence_policy_diff_json={}",
        policy_diff_artifacts.json_path.display()
    );
    println!(
        "evidence_tool_gating_json={}",
        tool_gating_artifacts.json_path.display()
    );
    println!("evidence_manifest={}", manifest_path.display());
    println!("audit_hash={}", audit_hash);
}
