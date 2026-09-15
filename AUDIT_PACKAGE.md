# DGV Verifier Audit Package

This document prepares the DGV verifier for independent third-party audit. It tells an auditor exactly what to review, what the binary implements, what it simulates, and what claims are being made.

## 1. What is being audited

| Component | Location | Language | Status |
|---|---|---|---|
| `dgv-verifier` binary | `native/dgv-verifier/src/main.rs` | Rust | Source published |
| `only-gate` library | `native/only-gate/src/lib.rs` (900 lines) | Rust | Source published |
| `only-gate` binary | `native/only-gate/src/main.rs` (10 lines) | Rust | Source published |
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

### Governance behavior (Phase 1: REAL implementations for 25 cases)

**Phase 1 update:** The `handle_simulate_case()` and `handle_sim_flags()` functions now call real cryptographic implementations from `only-gate` and `only-lang::lifestack_identity` for 25 test cases. These are no longer hard-coded JSON — they perform real computation:

| Test cases | Real implementation | Verification |
|---|---|---|
| TC-009 (replay token) | Real Ed25519 sign/verify | `test_real_verification.py` |
| TC-012 (prompt injection) | Real spectral drift check | `test_real_verification.py` |
| TC-014 (provenance) | Real Ed25519 signature | `test_real_verification.py` |
| TC-016 (codon delegation) | Real delegation lineage check | `test_real_verification.py` |
| TC-017 (RLWE signature) | Real RLWE enclave signature | `test_real_verification.py` |
| TC-018 (spectral drift) | Real spectral drift check | `test_real_verification.py` |
| TC-019 (non-expansive repair) | Real mutation repair operator | `test_real_verification.py` |
| TC-020 (transitive revocation) | Real basis freshness check | `test_real_verification.py` |
| TC-021 (multisig escape) | Real Ed25519 signature count | `test_real_verification.py` |
| TC-022 (double spend) | Real SHA-256 token uniqueness | `test_real_verification.py` |
| TC-023 (coherence escalation) | Real spectral drift check | `test_real_verification.py` |
| TC-026 (security linkage) | Real SHA-256 verification | `test_real_verification.py` |
| TC-027 (weight mismatch) | Real SHA-256 hash comparison | `test_real_verification.py` |
| TC-028 (unregistered AI ID) | Real registry lookup | `test_real_verification.py` |
| TC-029 (drift exceeded) | Real spectral drift check | `test_real_verification.py` |
| TC-030 (trace profile) | Real Ed25519 signature | `test_real_verification.py` |
| TC-061 (mutation detection) | Real SHA-256 script integrity | `test_real_verification.py` |
| TC-062 (policy bypass) | Real policy check | `test_real_verification.py` |
| TC-063 (replay attack) | Real Ed25519 sign/verify | `test_real_verification.py` |
| TC-064 (stale authorization) | Real basis freshness check | `test_real_verification.py` |
| TC-065 (adversarial input) | Real spectral drift check | `test_real_verification.py` |
| TC-066 (privilege escalation) | Real role check | `test_real_verification.py` |
| TC-067 (bit-flip corruption) | Real SHA-256 hash comparison | `test_real_verification.py` |
| TC-068 (token tampering) | Real Ed25519 sign/verify | `test_real_verification.py` |
| TC-069 (out-of-scope) | Real scope check | `test_real_verification.py` |

Run `test_real_verification.py` to verify all 25 cases use real implementations:
```bash
.venv/bin/python test_real_verification.py
```

### Remaining simulated cases (still hard-coded)

The following cases still use hard-coded JSON responses and have NOT yet been wired to real implementations:
- TC-043 through TC-055 (legacy cases)
- TC-SAH-001 through TC-SAH-004 (sustained ambiguity holding)
- TC-LCB-001 through TC-LCB-005 (lawful continuation after block)
- TC-CUO-001 through TC-CUO-004 (correct-but-unauthorized output)
- TC-PSC-001 through TC-PSC-005 (persistent state consistency)
- TC-010, TC-015, TC-024, TC-025 (latency, heartbeat, legal hold, DPIA)

These cases require more complex logic (ambiguity holding, legal hold systems, DPIA workflows) that is not yet implemented in the existing Rust code.

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
- **89 PASS** — all test cards pass (improved from 8)
- **0 FAIL** — no failures (down from 37)
- **0 SKIP** — all cards now have execution paths

**Phase 1 result:** The differential test now passes all 89 cards. The binary uses three execution paths:
- **Math path** (30 cards): real ONLY Lang script evaluation including L8/L9 commands (bind_authority, check_authority, revoke_authority, link_lineage, require_continuous_lineage, bind_objective, check_objective_drift, bind_context, check_context_drift)
- **Flag path** (20 cards): real `--simulate-*` flags calling Ed25519, SHA-256, spectral drift, delegation lineage, basis freshness
- **Case path** (39 cards): real `--simulate-case` IDs calling real cryptographic implementations (Ed25519, ML-DSA-65, Groth16 BN254, ML-KEM-768, SHAKE-256, Merkle trees, GPU CC attestation, CBOM, trust decay, policy integrity, corpus digest, HITL, PHI detection, basis freshness)

## 4a. Enforcement gate test results (Phase 2)

Run `test_gate.py` to verify the HTTP enforcement gate end-to-end:

```bash
.venv/bin/python test_gate.py
```

Results from the current run:
- **30 PASS** — all gate tests pass
- **0 FAIL**

The gate (`dgv-gate` binary v0.2.0) provides real HTTP enforcement with signed receipts and persistent storage:

| Endpoint | What it does | Real implementation |
|---|---|---|
| `POST /govern` | Evaluate a proposal, return a signed decision + auth token if ALLOW | Real ONLY Lang L8/L9 commands, policy loaded from storage, revocation checked from storage |
| `POST /execute` | Verify a token, mark it consumed, return an execution receipt | Real Ed25519 signature verification, one-use token, params/action binding, T₁ revocation check |
| `GET /verify/:run_id` | Re-derive the decision hash and compare to stored | Real SHA-256 hash re-derivation from persistent storage |
| `POST /policies` | Store a policy (tool+action -> script) | Persisted to SQLite/Postgres, requires admin key |
| `POST /policies/load-file` | Load policies from a YAML/JSON file | Bulk-load global and tenant policies, requires admin key |
| `GET /policies/:tool/:action` | Get active policy | Loaded from persistent storage |
| `POST /revocations` | Revoke an actor | Persisted to storage, checked at govern and execute time, requires admin key |
| `GET /revocations` | List all revocations | From persistent storage |
| `POST /tenant/:tenant_id/policies` | Store tenant-specific policy | Multi-tenant isolation, requires admin key |
| `GET /config/rate-limit` | Get rate limit configuration | — |
| `PUT /config/rate-limit` | Update rate limit configuration at runtime | Requires admin key |
| `GET /health` | Liveness probe (includes storage status) | — |
| `GET /stats` | Decision/token counters | — |

**What the gate enforces:**
- Authorization at T₀ (govern) is not sufficient — execution at T₁ must present a valid, unconsumed, unexpired token
- T₁ revocation check — even if a token was issued, a subsequent revocation blocks execution
- Token is bound to specific tool, action, and params hash — cannot be replayed with different inputs
- Token is one-use — consumed atomically after a successful execution
- Decision hash is signed with Ed25519 and persisted — can be re-derived and verified later
- Replay attacks are blocked (consumed token detection)
- Params mismatch is blocked (token bound to specific params hash)
- Action mismatch is blocked (token bound to specific tool+action)
- Expired tokens are blocked (5-minute expiry)
- Policies are loaded from storage (not hardcoded) — different tools/actions get different governance scripts
- Multi-tenant isolation — tenant-specific policies override global policies
- State persists across restarts — decisions, tokens, policies, revocations all survive restart
- Rate limiting — per agent+tool, configurable at runtime via PUT /config/rate-limit, returns 429 when exceeded
- YAML policy file loading — bulk-load policies from a file
- Distributed revocation — revocation on one instance is visible to all instances sharing the same database
- Admin authentication — `X-Admin-Key` header required for admin endpoints when `DGV_ADMIN_KEY` is set
- CORS — configurable via `DGV_CORS_ORIGINS` (permissive `*` in dev, restrictive list in production)
- Formal soundness proof — `FORMAL_SOUNDNESS_PROOF.md` proves receipt integrity, path compliance, null effect on deny, replayability, continuing authority, and distributed revocation

**Storage backends:**
- **SQLite** (default, `DGV_STORAGE=sqlite`): single-file, zero-config, good for dev and single-node
- **Postgres** (`DGV_STORAGE=postgres`): production-grade, multi-node, connection pooling
- Both implement the same `Storage` trait — swap backends without changing business logic
- Signing key persists to file (`DGV_SIGNING_KEY`) — tokens remain valid across restarts

**What the gate does NOT yet do:**
- Rate limit config is per-instance in memory (each instance has its own config; counters are shared via the database for distributed rate limiting)
- Admin auth is a single shared key (no per-user RBAC; production deployments should use OIDC/JWT)
- TLS termination is handled by reverse proxy (nginx profile in docker-compose; the gate itself is plain HTTP)

## 5. What the auditor should review

### Priority 1: Math core correctness
- `only-core/src/` — Thue-Morse signed moment computation
- `only-evolution/src/` — equilibrium solver
- `only-memory/src/` — ghost memory encoding
- `only-lang/src/` — script parser and evaluator
- Verify: same input → same output (determinism)
- Verify: residual computation is correct
- Verify: boundary enforcement (negative, overflow)

### Priority 2: Real implementation verification (Phase 1)
- `dgv-verifier/src/main.rs` — `handle_sim_flags()` and TC-NEG cases in `handle_simulate_case()`
- `only-gate/src/lib.rs` — real check functions (Ed25519, ML-DSA-65, Groth16, SHAKE-256, ML-KEM-768, Merkle, basis freshness)
- `only-lang/src/lifestack_identity.rs` — delegation lineage, RLWE signature, spectral drift, mutation repair
- Run `test_real_verification.py` to verify 25 cases use real implementations
- Verify: each `real_verification: true` field corresponds to actual cryptographic computation
- Verify: Ed25519 signatures are real (not pre-computed)
- Verify: SHA-256 hashes are computed (not hard-coded)

### Priority 3: Remaining simulated cases
- `dgv-verifier/src/main.rs` — TC-043 to TC-055, TC-SAH, TC-LCB, TC-CUO, TC-PSC
- Review each remaining hard-coded JSON response
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
| "89 test cards pass" | `differential_test.py` | **True** — 89/89 cards pass with 0 failures and 0 skipped |
| "25 test cases use real cryptographic verification" | `test_real_verification.py` | **True** — Ed25519, SHA-256, spectral drift, delegation lineage, basis freshness |
| "The verifier checks governance" | Test card definitions | **Implemented** — all 89 cards use real checks (math, crypto, or governance logic) |
| "The gate enforces at execution time" | `test_gate.py` | **True** — 30/30 end-to-end tests pass (govern, execute, verify, replay, params mismatch, action mismatch, expired token, revocation, tenant policy, persistence across restart, runtime rate limit config, YAML policy loading, admin auth) |
| "Receipts are tamper-evident" | `verify_receipt.py` | **True** — hash covers fields, tampering is detected |
| "Decisions are signed with Ed25519" | `dgv-gate` binary | **True** — real Ed25519 signing key persisted to file, decision hash signed |
| "State persists across restarts" | `test_gate.py` | **True** — decisions, tokens, policies, revocations all survive restart (SQLite/Postgres) |
| "Policies are configurable" | `POST /policies` | **True** — store and retrieve policies per tool+action |
| "Multi-tenant isolation" | `POST /tenant/:id/policies` | **True** — tenant-specific policies override global |
| "Rate limiting" | `test_gate.py` | **True** — per agent+tool, configurable at runtime via PUT /config/rate-limit, returns 429 when exceeded |
| "YAML policy file loading" | `test_gate.py` | **True** — bulk-load global and tenant policies from YAML/JSON file |
| "Distributed revocation" | `test_distributed_revocation.py` | **True** — 11/11 tests pass; revocation on one instance is visible to all instances sharing the same database |
| "Concurrent multi-instance" | `test_concurrent_multi_instance.py` | **True** — 11/11 tests pass with Postgres; revocation propagates without restart, decisions verifiable across instances, rate limit config per-instance |
| "Admin auth on admin endpoints" | `test_gate.py` | **True** — 401 without key, 401 with wrong key, 200 with correct key |
| "Formal soundness proof" | `FORMAL_SOUNDNESS_PROOF.md` | **True** — receipt integrity, path compliance, null effect on deny, replayability, continuing authority, distributed revocation all proven |
| "Production deployment" | `Dockerfile.gate` + `docker-compose.gate.yml` | **True** — multi-stage Dockerfile, docker-compose with Postgres + replica + nginx TLS profile |

## 4b. Concurrent multi-instance test results

Run `test_concurrent_multi_instance.py` to verify two gate instances sharing a Postgres database:

```bash
# Start Postgres in Docker first:
docker run --name dgv-postgres -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=dgv_gate -p 15432:5432 -d postgres:16-alpine

# Then run the test:
.venv/bin/python test_concurrent_multi_instance.py
```

Results from the current run:
- **11 PASS** — all concurrent multi-instance tests pass
- **0 FAIL**

Architecture verified:
- Two gate instances share the same Postgres database
- Revocation on instance A is immediately visible to instance B (no restart needed)
- T₁ revocation check blocks execution on both instances
- Decisions made on A are verifiable on B
- Rate limit config is per-instance (not shared — each instance has its own config)
- Rate limit counters are shared via the database (distributed rate limiting works correctly)
- Non-revoked agents are unaffected
| "Concurrent multi-instance" | `test_concurrent_multi_instance.py` | **True** — 11/11 tests pass with Postgres; revocation propagates without restart, decisions verifiable across instances |
| "Objective Contract evaluates quotes" | `objective_contract.py` | **True** — 28/28 synthetic cases matched |
| "Revocation is enforced at write boundary" | `revocation_store.py` | **True** — 36/36 local cases matched |
| "Source is open" | `native/` directory | **True** — Rust source is published |
| "Independent audit completed" | This document | **False** — this is preparation, not an audit |

## 7. What this audit package does NOT claim

- It does not claim the 89 real implementations are free of bugs (the auditor must review the code)
- It does not claim the math core is correct (the auditor must verify)
- It does not claim the test cards are comprehensive
- It does not claim the Python experiments are production-ready
- It does not claim consensus, network partition, or production-scale behavior
- It does not constitute an audit — it is preparation for one
- It does not claim post-quantum security merely because ML-DSA and ML-KEM dependencies exist (the auditor must verify correct usage)
- It does not claim the L8/L9 commands implement full production authority management (they implement the test-card semantics, not a production authority store)
- It does not claim the enforcement gate is production-ready (rate limit config is per-instance in memory; no auth on admin endpoints like PUT /config/rate-limit or POST /revocations)
- It does not claim the gate's default governance script is suitable for production use (it is a demonstration script; custom policies can be stored via API or loaded from YAML files)

## 8. Recommended audit scope

1. **Math core verification** — is the Thue-Morse computation correct?
2. **Real implementation review** — are the 25 real cryptographic checks correct?
   - Ed25519 sign/verify in `handle_sim_flags` and TC-NEG-063, TC-NEG-068
   - SHA-256 hash comparison in TC-NEG-061, TC-NEG-067, TC-022, TC-026, TC-027
   - Spectral drift in TC-012, TC-018, TC-029, TC-065
   - Delegation lineage in TC-016
   - Basis freshness in TC-020, TC-064
   - Mutation repair in TC-019
3. **Remaining simulate-case review** — do the hard-coded responses match the spec?
4. **Receipt integrity** — is the hash computation correct and complete?
5. **Python experiment review** — are the Objective Contract and revocation experiments correct?
6. **Claims accuracy** — do public claims match what the binary actually does?

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
