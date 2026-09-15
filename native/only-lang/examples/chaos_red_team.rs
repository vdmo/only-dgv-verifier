use serde_json::Value;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let url = "http://127.0.0.1:8091/api/chaos/fuzz";

    println!("============================================================");
    println!("   ONLYOS CONTINUOUS CHAOS RED-TEAMING (CI/CD PIPELINE)      ");
    println!("============================================================");
    println!("Connecting to gating shadow container at http://127.0.0.1:8091...");

    let res = match client.post(url).send().await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error: Gating shadow container offline or unreachable: {}", e);
            std::process::exit(1);
        }
    };

    if !res.status().is_success() {
        eprintln!("Error: Fuzzing execution failed with status code: {}", res.status());
        std::process::exit(1);
    }

    let report: Value = res.json().await?;
    let summary = &report["summary"];
    let checkpoints = report["checkpoints"].as_array().ok_or("Invalid report format")?;

    println!("\n+-------------+-----------------------------------+----------+------------+");
    println!("| CHECKPOINT  | NAME                              | STATUS   | ITERATIONS |");
    println!("+-------------+-----------------------------------+----------+------------+");

    for cp in checkpoints {
        let id = cp["id"].as_str().unwrap_or("");
        let name = cp["name"].as_str().unwrap_or("");
        let status = cp["status"].as_str().unwrap_or("");
        let iter = cp["iterations"].as_u64().unwrap_or(0);
        let status_color = if status == "PASSED" { "PASSED" } else { "FAILED" };
        println!(
            "| {:<11} | {:<33} | {:<8} | {:<10} |",
            id, name, status_color, iter
        );
    }
    println!("+-------------+-----------------------------------+----------+------------+");

    let total = summary["total_checked"].as_u64().unwrap_or(0);
    let passed = summary["passed"].as_u64().unwrap_or(0);
    let failed = summary["failed"].as_u64().unwrap_or(0);
    let total_iter = summary["fuzz_iterations"].as_u64().unwrap_or(0);

    println!("\nFuzz iterations: {}", total_iter);
    println!("Passed: {}/{}", passed, total);
    println!("Failed: {}", failed);

    if failed > 0 {
        println!("\n[!] CI/CD Pipeline Status: RED-TEAM VULNERABILITY DETECTED!");
        std::process::exit(1);
    } else {
        println!("\n[+] CI/CD Pipeline Status: GREEN - ALL 15 DGV CHECKPOINTS RESILIENT!");
        std::process::exit(0);
    }
}
