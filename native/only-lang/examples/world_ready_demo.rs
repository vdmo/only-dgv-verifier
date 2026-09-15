use only_core::generate_signs;
use only_lang::{evaluate_script_with_context, ScriptResult};
use serde_json::json;

fn main() {
    println!("=== ONLY-LANG ENTERPRISE DEMO: CONTEXT BINDING & GAS LIMITS ===\n");

    // 1. The Mathematics: 4-node invariant system (e.g. Budget = Cost + Tax + Remaining)
    let signs: Vec<only_core::Sign> = generate_signs(4).collect();

    // The initial state of the world (Budget: 10,000, Cost: 0, Tax: 0, Remaining: 10,000)
    // Field array: [Budget, Cost, Tax, Remaining]
    // Signs:       [+, -, -, +]  (from generate_signs(4)) -> Budget - Cost - Tax + Remaining = 0
    let mut field = [10000.0, 0.0, 0.0, -10000.0];

    // 2. The Agent's Proposal (The JSON Context)
    // The agent wants to spend $50,000 but the budget is only $10,000.
    // It hallucinated the `remaining` balance to try and force the math to work.
    let agent_payload = json!({
        "proposed_cost": 50000.0,
        "calculated_tax": 5000.0,
        "hallucinated_remaining": -45000.0 // Agent trying to balance the equation: 10k - 50k - 5k + 45k = 0
    });

    // 3. The World-Ready Declarative Invariant Script
    // This is what the Enterprise Compliance Officer wrote.
    let policy_script = r#"
        // Bind the agent's JSON payload to the math array
        bind("proposed_cost", 1)
        bind("calculated_tax", 2)
        bind("hallucinated_remaining", 3)
        
        // Assert strict bounds: Cost cannot exceed 10,000 (Index 1)
        assert_bounds(0.0, 10000.0, 1)
        
        // Track cryptographic lineage for the auditor
        link_identity("DID:ENT:PROCUREMENT_GATE_01")
        track_lineage(true)
        
        // Enforce mathematics
        require_equilibrium(1e-9)
        report_json()
    "#;

    println!(
        "[Agent] Submitting Context: {}",
        serde_json::to_string_pretty(&agent_payload).unwrap()
    );
    println!("\n[Control Plane] Executing Invariant Policy Script...");

    // 4. Evaluate the script with a Gas Limit of 100
    let fuel_limit = 100;
    let result = evaluate_script_with_context(
        &signs,
        &mut field,
        Some(&agent_payload),
        policy_script,
        fuel_limit,
    );

    match result {
        Ok(ScriptResult { pass, report, .. }) => {
            println!("\n[Control Plane] Script Executed Successfully.");
            println!(
                "  Gate Status: {}",
                if pass { "🟢 ALLOW" } else { "🔴 DENY" }
            );
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

    println!("\n--- Test 2: The Honest Agent ---\n");

    // Let's try it again with an honest agent who obeys the bounds
    let honest_payload = json!({
        "proposed_cost": 2000.0,
        "calculated_tax": 200.0,
        "hallucinated_remaining": -7800.0 // 10000 - 2000 - 200 - 7800 = 0
    });

    // Reset the field
    let mut field2 = [10000.0, 0.0, 0.0, -10000.0];

    println!(
        "[Agent] Submitting Context: {}",
        serde_json::to_string_pretty(&honest_payload).unwrap()
    );

    let result2 = evaluate_script_with_context(
        &signs,
        &mut field2,
        Some(&honest_payload),
        policy_script,
        fuel_limit,
    );

    if let Ok(ScriptResult { pass, report, .. }) = result2 {
        println!("\n[Control Plane] Script Executed Successfully.");
        println!(
            "  Gate Status: {}",
            if pass { "🟢 ALLOW" } else { "🔴 DENY" }
        );
        println!(
            "\n[TDO Cryptographic Export]\n{}",
            report.unwrap_or_default()
        );
    }
}
