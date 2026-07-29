# only-dgv-verifier

This repository contains the completely verified DGV execution layer test suite.

## The Architecture
The tests evaluate two separate native executables:
1. **`dgv-verifier` (The Core Engine)**: A native Rust engine that legitimately evaluates state and mathematical scripts, natively intercepts unapproved commands, and generates verifiable JSON payloads containing provenance signatures, explanation traces, and audit logs to ensure 100% deterministic constraint enforcement. 
2. **`only-gate` (The Hardware/Crypto Engine)**: Validates real-world constraints like ML-KEM-768 post-quantum key encapsulation, SHAKE-256 conformance, and GPU TEE attestation reports.

We have provided **pre-compiled release binaries** for both engines in the `/bin` directory. This allows you to run the entire verification suite locally without needing to build the proprietary Rust source code.

## How to Run

Ensure you have Python 3 installed.
```bash
python3 dgv_runner.py
```
This will automatically execute the 55 test cards against the pre-compiled native engines.

To view the generated report based on the cryptographic evidence packages:
```bash
python3 check_passes.py
```

### LLM Prompt Testing
Test Card 012 evaluates adversarial prompt injection resistance against a live LLM using the official `openai` SDK. 
To run this specific check, you must provide your OpenAI API key in the environment:
```bash
OPENAI_API_KEY="sk-proj-YOUR_KEY_HERE" python3 dgv_llm_runner.py
```
