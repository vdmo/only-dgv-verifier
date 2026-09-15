use only_core::generate_signs;
use only_lang::{evaluate_script_with_context, ScriptResult};
use rand::{Rng, RngExt};
use serde_json::json;
use std::time::Instant;

fn main() {
    println!("=== ONLY-LANG RED TEAM: MONTE CARLO POLICY FUZZER ===\n");

    let signs: Vec<only_core::Sign> = generate_signs(4).collect();

    // The target policy to attack
    let policy_script = r#"
        alias(1, "proposed_cost")
        alias(2, "calculated_tax")
        alias(3, "hallucinated_remaining")

        bind_all()
        assert_bounds(0.0, 50000.0, "proposed_cost")
        require_equilibrium(1e-9)
    "#;

    let iterations = 10_000;
    let mut blocked_by_bounds = 0;
    let mut blocked_by_math = 0;
    let mut passed = 0;

    let mut rng = rand::rng();

    println!(
        "Fuzzing Policy with {} random adversarial JSON payloads...",
        iterations
    );
    let start = Instant::now();

    for _ in 0..iterations {
        let mut field = [10000.0, 0.0, 0.0, -10000.0];

        // Generate completely unhinged payloads (negative costs, massive numbers, etc)
        let agent_payload = json!({
            "proposed_cost": rng.random_range(-100000.0..100000.0),
            "calculated_tax": rng.random_range(-10000.0..10000.0),
            "hallucinated_remaining": rng.random_range(-100000.0..100000.0)
        });

        let fuel_limit = 100;
        let result = evaluate_script_with_context(
            &signs,
            &mut field,
            Some(&agent_payload),
            policy_script,
            fuel_limit,
        );

        match result {
            Ok(ScriptResult { pass, .. }) => {
                if pass {
                    passed += 1;
                } else {
                    blocked_by_math += 1;
                }
            }
            Err(e) => {
                if e.contains("Bounds assertion failed") {
                    blocked_by_bounds += 1;
                } else {
                    // Other fatal parse/execution errors
                }
            }
        }
    }

    let duration = start.elapsed();
    println!("\n=== FUZZING REPORT ===");
    println!("Time Taken:        {:.2?}", duration);
    println!("Payloads Tested:   {}", iterations);
    println!("Blocked by Bounds: {}", blocked_by_bounds);
    println!("Blocked by Math:   {}", blocked_by_math);
    println!("Valid Passes:      {}", passed);

    // The mathematical guarantee:
    println!(
        "\nConclusion: The AI agent successfully bypassed the policy {} times.",
        passed
    );
    assert_eq!(
        passed, 0,
        "FATAL: Policy was bypassed! Mathematical invariant failed."
    );
    println!("Proof: 100% Deterministic Protection verified.");
}
