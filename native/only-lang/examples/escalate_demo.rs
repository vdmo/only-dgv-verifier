use only_core::generate_signs;
use only_lang::{evaluate_script_with_context, ScriptResult};
use serde_json::json;

fn main() {
    println!("=== ONLY-LANG ENTERPRISE DEMO 2: SEMANTIC MAPPING & ESCALATION ===\n");

    let signs: Vec<only_core::Sign> = generate_signs(4).collect();

    // The agent payload
    let agent_payload = json!({
        "proposed_cost": 25000.0,
        "calculated_tax": 2500.0,
        "hallucinated_remaining": -27500.0
    });

    let policy_script = r#"
        // 1. Semantic Mapping (No more magic numbers)
        alias(1, "proposed_cost")
        alias(2, "calculated_tax")
        alias(3, "hallucinated_remaining")
        
        // Magically bind all JSON keys to their matched index aliases
        bind_all()
        
        // Assert strict upper bound for cost using the semantic name
        assert_bounds(0.0, 50000.0, "proposed_cost")
        
        // 2. Conditional Escalation (Human In The Loop)
        // If the cost is over 10k, it's mathematically sound but requires VP approval
        if_greater_than("proposed_cost", 10000.0) {
            escalate("Cost exceeds $10,000 threshold. Requires VP of Finance Approval.")
        }
        
        // Track cryptographic lineage for the auditor
        link_identity("DID:ENT:PROCUREMENT_GATE_02")
        track_lineage(true)
        
        // Enforce mathematics
        require_equilibrium(1e-9)
        report_json()
    "#;

    let mut field = [10000.0, 0.0, 0.0, -10000.0];

    println!(
        "[Agent] Submitting Context: {}",
        serde_json::to_string_pretty(&agent_payload).unwrap()
    );
    println!("\n[Control Plane] Executing Semantic Policy Script...");

    let fuel_limit = 100;
    let result = evaluate_script_with_context(
        &signs,
        &mut field,
        Some(&agent_payload),
        policy_script,
        fuel_limit,
    );

    match result {
        Ok(ScriptResult {
            pass,
            report,
            escalate_reason,
            ..
        }) => {
            println!("\n[Control Plane] Script Executed Successfully.");
            if let Some(reason) = escalate_reason {
                println!("  Gate Status: 🟡 ESCALATE");
                println!("  Reason: {}", reason);
            } else {
                println!(
                    "  Gate Status: {}",
                    if pass { "🟢 ALLOW" } else { "🔴 DENY" }
                );
            }
            println!(
                "\n[TDO Cryptographic Export]\n{}",
                report.unwrap_or_default()
            );
        }
        Err(e) => {
            println!("\n🔴 [Control Plane] GATE CLOSED: FATAL VIOLATION");
            println!("   Reason: {}", e);
        }
    }
}
