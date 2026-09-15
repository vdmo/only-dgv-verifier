use only_core::{check_equilibrium, generate_signs, Sign};
use only_memory::GhostMemory;
use only_evolution::solve_for_equilibrium;
use std::time::Duration;
use tokio::time;

#[tokio::main]
async fn main() {
    println!("=== only-heal: Ghost Memory Self-Healing Daemon ===");
    
    // 1. Initialize a secret ghost memory array.
    // The secret payload data we are hiding is 42.0.
    let secret_payload = 42.0;
    let signs: Vec<Sign> = generate_signs(4).collect();
    
    println!("[INIT] Creating a new Ghost Memory array...");
    let mut memory_array = GhostMemory::try_encode_4(&signs, secret_payload)
        .expect("Failed to encode ghost memory");
        
    println!("[INIT] Original Memory Array: {:?}", memory_array);
    println!("[INIT] Expected Sign Pattern: {:?}", signs);

    loop {
        println!("\n--- Monitoring Cycle ---");
        
        // 2. Continuous Monitoring
        // Check if the 1st-order equilibrium (Sum s_i * v_i = 0) is maintained
        if check_equilibrium(&signs, &memory_array, 1e-10) {
            println!("[MONITOR] Status: OK. 1st-order equilibrium is maintained.");
            
            // Extract the 2nd-order payload just to prove it's still there
            let revealed = GhostMemory::reveal_4(&signs, &memory_array);
            println!("[MONITOR] Data Payload Extracted: {:.2}", revealed);
            
            println!("[SIMULATE] Simulating a cosmic ray / data corruption in 3 seconds...");
            time::sleep(Duration::from_secs(3)).await;
            
            // 3. Simulate Corruption (Data Loss)
            // We lose the value at index 2.
            println!("[SIMULATE] *BZZZT* Value at index 2 is lost!");
            memory_array[2] = 0.0; 
            
        } else {
            // 4. Detect Breach
            println!("[ALERT] 1st-order equilibrium broken! Array corruption detected!");
            println!("[ALERT] Current Corrupted Array: {:?}", memory_array);
            
            // 5. Mathematical Self-Healing
            println!("[HEAL] Initiating mathematical algebraic reconstruction...");
            
            // We assume index 2 is the missing/corrupted one for this simulation.
            // In a real system, the daemon would iterate to find which index heals the equilibrium.
            let missing_idx = 2;
            
            let known_elements: Vec<(usize, f64)> = (0..4)
                .filter(|&i| i != missing_idx)
                .map(|i| (i, memory_array[i]))
                .collect();
                
            let reconstructed_value = solve_for_equilibrium(&signs, &known_elements, missing_idx);
            
            println!("[HEAL] Reconstructed missing value: {:.6}", reconstructed_value);
            
            // Write the healed value back into memory
            memory_array[missing_idx] = reconstructed_value;
            println!("[HEAL] Array restored: {:?}", memory_array);
            
            // 6. Verify Payload
            let revealed = GhostMemory::reveal_4(&signs, &memory_array);
            println!("[VERIFY] Re-extracting 2nd-order payload to verify...");
            println!("[VERIFY] Data Payload Extracted: {:.2} (Expected: {:.2})", revealed, secret_payload);
            
            if (revealed - secret_payload).abs() < 1e-5 {
                println!("[SUCCESS] Ghost Memory Self-Healing Complete!");
            } else {
                println!("[ERROR] Healing failed. Payload is corrupted.");
            }
            
            println!("Resetting simulation in 5 seconds...");
            time::sleep(Duration::from_secs(5)).await;
        }
    }
}
