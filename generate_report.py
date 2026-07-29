import os
import json

# Output path in WSL mapped to Windows artifact directory
output_file = "/mnt/c/Users/vdmo-live/.gemini/antigravity/brain/a3b2ff54-7956-4817-8e67-9f57394230bd/dgv_55_test_report.md"
cards_dir = "/home/vdmo/pir/only-engine/dgv/test_cards"

def generate_report():
    with open(output_file, "w", encoding="utf-8") as out:
        out.write("# DGV Framework: 55-Point Zero-Trust Architectural Report\n\n")
        out.write("## 1. High-Level Summary\n")
        out.write("The Deterministic Governance Verification (DGV) suite comprises 55 specialized test cards. Its primary intention is to mathematically and cryptographically prove that an AI engine operates within strict, zero-trust constraints. Rather than evaluating standard software functionality, DGV evaluates **containment, governance, cryptography, and provenance**.\n\n")
        
        out.write("## 2. Technological Operation\n")
        out.write("Technologically, DGV operates using a dual-engine architecture:\n")
        out.write("- **`dgv-verifier` (The Sandbox/Synthetic Engine)**: Executes mathematical state evaluations to ensure the core logic (budgeting, residual healing) is 100% deterministic.\n")
        out.write("- **`only-gate` (The Hardware/Crypto Engine)**: Validates real-world constraints like ML-KEM-768 post-quantum key encapsulation, SHAKE-256 conformance, and GPU TEE attestation reports.\n")
        out.write("- **Python Interceptor**: Evaluates behavioral constraints (e.g., prompt injection) via API calls to live models, anchoring the evidence via SHA-256.\n\n")
        
        out.write("## 3. The 55 Test Cards Explained\n\n")

        # Load and sort test cards
        card_files = [f for f in os.listdir(cards_dir) if f.endswith(".json")]
        card_files.sort()

        for filename in card_files:
            filepath = os.path.join(cards_dir, filename)
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    card = json.load(f)
            except Exception as e:
                continue

            card_id = card.get("id", "Unknown ID")
            name = card.get("claim_name", "Unknown Name")
            definition = card.get("claim_definition", "No definition provided.")
            layer = card.get("svrnos_layer", "N/A")
            scope = card.get("scope", "N/A")
            enforcement = card.get("enforcement_layer", {}).get("enforcement_type", "simulation") if isinstance(card.get("enforcement_layer"), dict) else "simulation"
            
            out.write(f"### {card_id}: {name}\n")
            out.write(f"- **SVRNOS Layer**: {layer}\n")
            out.write(f"- **Scope**: {scope}\n")
            out.write(f"- **Enforcement Strategy**: {enforcement}\n")
            out.write(f"- **Intention/Definition**: {definition}\n")
            
            threats = card.get("threat_model_tie_in")
            if threats:
                out.write(f"- **Threat Mitigation**: {', '.join(threats)}\n")
            
            out.write("\n")

if __name__ == "__main__":
    generate_report()
    print(f"Report generated at {output_file}")
