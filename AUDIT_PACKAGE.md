# DGV Verifier Audit Package

This document prepares the DGV verifier for independent third-party audit. It tells an auditor exactly what to review, what the binary implements, what it simulates, and what claims are being made.

## 1. What is being audited

| Component | Location | Language | Status |
|---|---|---|---|
| `dgv-verifier` binary | `native/dgv-verifier/src/main.rs` (714 lines) | Rust | Source published |
| `only-gate` binary | `native/only-gate/src/main.rs` (973 lines) | Rust | Source published |
| `only-lang` interpreter | `native/only-lang/src/` | Rust | Source published |
| `only-core` math core | `native/only-core/src/` | Rust | Source published |
| `only-evolution` solver | `native/only-evolution/src/` | Rust | Source published |
| `only-memory` ghost memory | `native/only-memory/src/` | Rust | Source published |
| Python test harness | `dgv_runner.py` | Python | Source published |
| Objective Contract evaluator | `objective_contract.py` | Python | Source published |
| Revocation store | `revocation_store.py` | Python | Source published |
| Test card definitions | `../only-institute/web/lib/dgv-full-cards.json` | JSON | Published |
| Specification | `spec.md` | Markdown | Published |

## 2. Build from source

```bash
# Prerequisites: Rust 1.96+ (stable)
source $HOME/.cargo/env

# Build both binaries
cd native
cargo build --release -p dgv-verifier
cargo build --release -p only-gate

# Verify checksums match published values
sha256sum target/release/dgv-verifier target/release/only-gate
# Compare against CHECKSUMS.txt
```

The build produces deterministic binaries. Checksums are in `CHECKSUMS.txt`.

## 3. What the native binary actually implements

### Math core (actually computed)

The `dgv-verifier` binary implements ONLY Lang script evaluation:
- `harmony(tolerance)` — sets the equilibrium tolerance
- `evolve(n)` — runs n evolution steps
- `data(value)` — sets the input data value
- `residual()` — computes the final residual
- `corrupt(index)` — corrupts a memory index for testing

This is real computation. The math core (Thue-Morse signed moments, PIR balance gap) is implemented in `only-core` and `only-evolution`.

### Boundary checks (actually computed)

- Negative payload → DENY (TC-002)
- Payload >= 999999 → DENY (TC-005, refusal threshold)
- Script contains "corrupt" → DENY (TC-004, instruction hierarchy)

### Governance behavior (SIMULATED, not computed)

**Critical finding for the auditor:** The binary does NOT implement the governance checks described in test cards TC-006 through TC-069. Instead, it has a `handle_simulate_case()` function (line 247 of `main.rs`) that returns **hard-coded JSON strings** for each test case ID.

When the test harness runs a card like TC-009 (Token Replay Resistance), it passes `--simulate-case=TC-009` and the binary returns a pre-programmed JSON response. The binary does not actually check for token replay.

The `--simulate-*` flags (TC-009 through TC-030) work the same way: they trigger pre-programmed JSON responses, not computed governance logic.

### What this means

| Claim | Reality |
|---|---|
| "89 test cards pass" | The binary returns the expected hard-coded JSON for 89 test case IDs |
| "The verifier checks token replay" | The binary returns hard-coded JSON when asked to simulate TC-009 |
| "The verifier checks revocation" | The binary returns hard-coded JSON when asked to simulate TC-020 |
| "The verifier checks fairness" | The binary returns hard-coded JSON when asked to simulate TC-013 |
| "The verifier computes residuals" | **True** — this is real computation in the math core |

## 4. Differential test results

Run `differential_test.py` to compare native binary output against expected card outputs:

```bash
.venv/bin/python differential_test.py
```

Results from the current run:
- **8 PASS** — basic math cases where the binary's output matches expected
- **37 FAIL** — governance cases where the binary returns "OPEN" but the card expects "CLOSED", "REFUSE", "HOLD", or "ESCALATE"
- **11 SKIP** — proposed L8/L9 commands not in the native interpreter

The 37 failures occur because the differential test runs scripts directly without `--simulate-case`. The test harness uses `--simulate-case` to get the expected outputs. This is the gap between "the binary computes governance" and "the binary returns pre-programmed responses."

## 5. What the auditor should review

### Priority 1: Math core correctness
- `only-core/src/` — Thue-Morse signed moment computation
- `only-evolution/src/` — equilibrium solver
- `only-memory/src/` — ghost memory encoding
- `only-lang/src/` — script parser and evaluator
- Verify: same input → same output (determinism)
- Verify: residual computation is correct
- Verify: boundary enforcement (negative, overflow)

### Priority 2: Simulate-case handler
- `dgv-verifier/src/main.rs` lines 247-549
- Review every hard-coded JSON response
- Verify: each response matches the test card's expected output
- Flag: any response that claims a governance check was performed when it was not

### Priority 3: Receipt integrity
- `verify_receipt.py` — receipt hash computation
- Verify: hash covers all claimed fields
- Verify: hash is computed before any post-hoc fields are added
- Verify: tampered receipts are rejected

### Priority 4: Python experiments
- `objective_contract.py` — Objective Contract evaluator
- `revocation_store.py` — revocation store
- Verify: atomic transaction boundary
- Verify: fail-closed behavior
- Verify: one-use token consumption

## 6. Claims matrix

| Claim | Evidence | Status |
|---|---|---|
| "The binary is reproducible from source" | Build from `native/`, compare SHA-256 | **True** — source is published, build is deterministic |
| "89 test cards pass" | Test harness output | **Misleading** — 89 simulated cases return expected JSON; 8 computed cases match expected |
| "The verifier checks governance" | Test card definitions | **Not implemented** — governance is simulated via hard-coded responses |
| "Receipts are tamper-evident" | `verify_receipt.py` | **True** — hash covers fields, tampering is detected |
| "Objective Contract evaluates quotes" | `objective_contract.py` | **True** — 28/28 synthetic cases matched |
| "Revocation is enforced at write boundary" | `revocation_store.py` | **True** — 36/36 local cases matched |
| "Source is open" | `native/` directory | **True** — Rust source is now published |
| "Independent audit completed" | This document | **False** — this is preparation, not an audit |

## 7. What this audit package does NOT claim

- It does not claim the binary implements governance checks (it simulates them)
- It does not claim the math core is correct (the auditor must verify)
- It does not claim the test cards are comprehensive
- It does not claim the Python experiments are production-ready
- It does not claim consensus, network partition, or production-scale behavior
- It does not constitute an audit — it is preparation for one

## 8. Recommended audit scope

1. **Math core verification** — is the Thue-Morse computation correct?
2. **Simulate-case review** — do the hard-coded responses match the spec?
3. **Receipt integrity** — is the hash computation correct and complete?
4. **Python experiment review** — are the Objective Contract and revocation experiments correct?
5. **Claims accuracy** — do public claims match what the binary actually does?

## 9. Contact

For audit engagement:
- Repository: https://github.com/vdmo/only-dgv-verifier
- Email: trust@only.institute

## 10. Build environment

| Component | Value |
|---|---|
| Rust toolchain | stable (1.96.0) |
| Target | x86_64-unknown-linux-gnu |
| Optimization | release (opt-level=3, lto=true) |
| Dependencies | See `native/Cargo.lock` |

No external C dependencies. No network calls at runtime. No dynamic linking beyond libc.
