use only_core::Sign::{Minus, Plus};
use only_lang::evaluate_script;
use only_lang::evidence_pack::{
    now_unix_ms, write_evidence_pack, write_manifest, EvidenceManifest,
    EvidenceManifestItem, EvidencePack, ToolOutcome, ToolProposal,
};
use serde_json::json;
use std::fs;
use std::path::PathBuf;

fn main() {
    // -------------------------------------------------------------
    // Step 1: Draft Policy Script (Algebraic Compliance Constraint)
    // -------------------------------------------------------------
    let signs = [Plus, Minus, Minus];
    let script = "harmony(1e-12) residual() evolve(2) residual() report()";

    let budget_total = 100_000.0;
    
    // Scenarios:
    // 1. REQ-COMP-002: £750 (Automated ALLOW, below the £1,000 threshold)
    // 2. REQ-COMP-003: £4,500 (Escalated to senior manager, exceeds threshold)
    let scenarios = vec![
        ("REQ-COMP-002", 750.0, "user:bob", "ProcurementDelegate", "low"),
        ("REQ-COMP-003", 4500.0, "user:alice", "ProcurementOfficer", "high"),
    ];

    let threshold_limit = 1000.0;
    let base_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let manifest_path = base_path.join("evidence").join("manifest.json");

    // Read existing manifest or initialize a new one
    let mut manifest = if manifest_path.exists() {
        let content = fs::read_to_string(&manifest_path).unwrap_or_default();
        serde_json::from_str::<EvidenceManifest>(&content).unwrap_or_else(|_| EvidenceManifest {
            generated_unix_ms: now_unix_ms(),
            packs: Vec::new(),
        })
    } else {
        EvidenceManifest {
            generated_unix_ms: now_unix_ms(),
            packs: Vec::new(),
        }
    };

    for (request_id, request_amount, user_id, role, risk_level) in scenarios {
        let is_low_risk = request_amount < threshold_limit;

        // Initialize field variables: [BudgetTotal, RequestAmount, RemainingBudget]
        let mut field = [budget_total, request_amount, 0.0];
        let field_before = field;

        // Run the script evaluation
        let res = evaluate_script(&signs, &mut field, script).unwrap();
        let budget_remaining = field[2];

        // Determine gate states
        let gate_state = if is_low_risk { "ALLOW" } else { "ESCALATE" };
        let next_step = if is_low_risk { "Execute" } else { "Await senior manager approval" };

        // Bake Identity Payload
        let request_payload = json!({
            "workflow": "compliance_procurement",
            "request_id": request_id,
            "amount": request_amount,
            "identity": {
                "user_id": user_id,
                "roles": [role],
                "delegations": [
                    {
                        "from_role": "ProcurementOfficer",
                        "to_role": role,
                        "scope": if is_low_risk { "low_risk_only" } else { "full_scope" },
                        "delegated_by": "user:charlie"
                    }
                ]
            }
        });

        let decision_payload = json!({
            "gate_state": gate_state,
            "next_step": next_step,
            "budget_remaining": budget_remaining,
            "repaired": res.indices_healed.contains(&2),
            "reason_codes": if is_low_risk { json!([]) } else { json!(["high_value_transaction"]) }
        });

        let tool_proposals = vec![ToolProposal {
            tool: "finance.payment".to_string(),
            action: "execute_payment".to_string(),
            params: json!({ "recipient": "ACME Corp", "amount": request_amount }),
        }];

        let tool_outcomes = vec![ToolOutcome {
            tool: "finance.payment".to_string(),
            allowed: is_low_risk,
            deny_reason: if is_low_risk { None } else { Some("Blocked: requires senior approval".to_string()) },
            result: json!({ "executed": is_low_risk }),
        }];

        let run_id = format!("{}_{}", now_unix_ms(), request_id.replace("-", "_").to_lowercase());
        let policy_version = "compliance_budget_coherence_v1".to_string();
        let decision_hash = format!("{:016x}", 0x7a8b9c10d2e3f4a5_u64.wrapping_add((request_amount * 100.0) as u64));

        let pack = EvidencePack {
            run_id: run_id.clone(),
            created_unix_ms: now_unix_ms(),
            request: request_payload,
            policy_version: policy_version.clone(),
            decision: decision_payload,
            decision_hash: decision_hash.clone(),
            replay_inputs: json!({
                "script": script,
                "signs": [1, -1, -1],
                "field_before": field_before
            }),
            tool_proposals,
            tool_outcomes,
            event_type: "unknown".to_string(),
            token_id: None,
            agent_id: None,
            actor: None,
        };

        let svg_report = r##"<svg xmlns="http://www.w3.org/2000/svg" width="100%" height="240" viewBox="0 0 760 240"><rect width="100%" height="100%" fill="#0b1020" stroke="#2b365a"/><text x="24" y="36" fill="#61dafb" font-family="monospace" font-size="16">Compliance Balance Analysis</text></svg>"##;
        
        let html_report = format!(
            r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>Compliance Gate Report</title>
</head>
<body>
  <h1>Compliance Process Log</h1>
  <div class="box">
    <strong>Request:</strong> {request_id}<br/>
    <strong>Amount:</strong> &pound;{request_amount:.2}<br/>
    <strong>Risk Classification:</strong> {risk_cls}<br/>
    <strong>Status:</strong> {gate_state}
  </div>
</body>
</html>"#,
            request_id = request_id,
            request_amount = request_amount,
            risk_cls = if is_low_risk { "Low Risk" } else { "High Risk" },
            gate_state = gate_state
        );

        write_evidence_pack(&base_path, &run_id, svg_report, &html_report, &pack).unwrap();

        // Push compliance run item to the manifest packs
        manifest.packs.push(EvidenceManifestItem {
            run_id: run_id.clone(),
            created_unix_ms: pack.created_unix_ms,
            request_id: request_id.to_string(),
            workflow: "compliance_procurement".to_string(),
            stage: "gate".to_string(),
            risk_level: risk_level.to_string(),
            needs_approval: !is_low_risk,
            approved: is_low_risk,
            gate_state: gate_state.to_string(),
            next_step: next_step.to_string(),
            sla_due_unix_ms: Some(pack.created_unix_ms + 15 * 60 * 1000), // 15 min SLA
            policy_version: policy_version.clone(),
            decision_hash: decision_hash.clone(),
            json: format!("{}.json", run_id),
            html: format!("{}.html", run_id),
            svg: format!("{}.svg", run_id),
            event_type: "unknown".to_string(),
            token_id: None,
            agent_id: None,
            actor: None,
        });

        println!("Compliance evidence pack registered: {}", run_id);
    }

    // Write the updated manifest back to disk
    manifest.generated_unix_ms = now_unix_ms();
    let new_manifest_path = write_manifest(&base_path, &manifest).unwrap();
    println!("Updated evidence manifest: {}", new_manifest_path.display());
}
