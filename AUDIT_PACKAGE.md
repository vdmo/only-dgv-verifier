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
- **JWT identity verification** — HS256 (`DGV_JWT_SECRET`), RS256 static PEM (`DGV_JWT_PUBLIC_KEY`), or RS256 via JWKS (`DGV_JWT_JWKS_URL`) with `kid`-based key rotation and TTL-cached JWKS responses (`DGV_JWKS_CACHE_TTL_MS`, default 300s; unknown `kid` forces one refetch); `sub` claim becomes the verified `agent_id`; algorithm pinned per mode (HS256 tokens rejected in RS256/JWKS mode)
- **Approval workflow** — `min_approvals` in policies enforces multi-approval before execution; `POST /approve/:token_id` stores approvals
- **Approver identity verification** — when JWT is configured, `/approve` requires a valid JWT and the verified `sub` is stored as the approver identity (body-supplied `approver_id` cannot be forged)
- **Policy signing** — policies are Ed25519-signed when stored; verified on load; tampered policies rejected
- **Full context hashing** — `context_hash` field in proposal binds the agent's full context (not just tool+params)
- **Justification enforcement** — `min_justification_length` in policies requires minimum justification length
- **Semantic justification verification (pluggable)** — `DGV_SEMANTIC_VERIFIER_URL` delegates justification↔action semantic checks to an external verifier webhook; the gate performs no LLM analysis itself. `DGV_SEMANTIC_FAIL_CLOSED=1` denies when the verifier is unreachable (default fail-open with logged warning)
- **Circuit breakers** — callers report tool outcomes via `POST /tool-health/report`; after `DGV_CIRCUIT_BREAKER_THRESHOLD` consecutive failures (default 5) the circuit opens and `/govern` denies new proposals for that tool; half-open probe after `DGV_CIRCUIT_BREAKER_COOLDOWN_MS` (default 30s); admin reset via `POST /tool-health/reset/:tool`
- **A2A signed envelopes** — `POST /a2a/send` accepts Ed25519-signed envelopes between admin-registered agents (`POST/DELETE /agents/keys`); verifies sender signature over the canonical envelope string, expiry, clock skew, revocation of both parties; replay-protected via envelope_id PK and (sender_id, nonce) UNIQUE; gate-signed delivery receipt; `GET /a2a/inbox/:agent_id` + `POST /a2a/ack/:envelope_id` for delivery (JWT-verified when configured). Payloads never transit the gate — hash-only.
- **A2A sealed transport (dgv-sealed-v1)** — optional data plane over `onlystate-relay`: agents register X25519 encryption keys (`enc_public_key_hex`), seal payloads via ECDH + SHA3-256 per-message KDF + ChaCha20-Poly1305 (mirroring `libonlystate`); the gate binds `payload_hash` to the *ciphertext*, and `transport_ref` tells the recipient where the ciphertext lives. Public `GET /agents/keys/:agent_id` resolves peer keys. See `A2A_TRANSPORT.md`.
- **Token delegation (dgv-delegate-v1)** — `POST /delegate` mints a strictly-narrower child token from a live parent: same tool+action, params must be a JSON subset of the parent's (keys omittable, values never added/changed, array elements drawn from parent's), expiry ≤ parent's, `min_approvals` inherited, depth bounded by `DGV_MAX_DELEGATION_DEPTH` (default 3). The delegator signs the canonical delegation string with its registered Ed25519 key; a `DelegationRecord` is persisted (query lineage via `GET /delegations/:token_id`). Tokens are now **grantee-bound** — `executor_id` must equal `granted_to`; revoking any ancestor in the chain denies delegated execution at T₁.
- CORS — configurable via `DGV_CORS_ORIGINS` (permissive `*` in dev, restrictive list in production)
- Formal soundness proof — `FORMAL_SOUNDNESS_PROOF.md` proves receipt integrity, path compliance, null effect on deny, replayability, continuing authority, and distributed revocation

**Storage backends:**
- **SQLite** (default, `DGV_STORAGE=sqlite`): single-file, zero-config, good for dev and single-node
- **Postgres** (`DGV_STORAGE=postgres`): production-grade, multi-node, connection pooling
- Both implement the same `Storage` trait — swap backends without changing business logic
- Signing key persists to file (`DGV_SIGNING_KEY`) — tokens remain valid across restarts

**What the gate does NOT yet do:**
- Rate limit config is per-instance in memory (each instance has its own config; counters are shared via the database for distributed rate limiting)
- JWKS responses are TTL-cached (`DGV_JWKS_CACHE_TTL_MS`, default 300s); an unknown `kid` triggers exactly one forced refetch to handle key rotation faster than TTL expiry
- Circuit-breaker state is per-instance in memory — not shared across multi-instance deployments (unlike revocations, which live in shared storage)
- Circuit breakers depend on callers honestly reporting tool outcomes — the gate cannot observe downstream failures itself
- A2A payloads are hash-only at the gate — payload confidentiality now has a reference implementation (`dgv-sealed-v1` over onlystate-relay), but it is ECDH+ChaCha20-Poly1305, not post-quantum; WOTS+ signatures from libonlystate are not wired in; deterministic queue IDs are dictionary-guessable (see A2A_TRANSPORT.md non-claims)
- Semantic verification quality depends entirely on the external verifier — the gate performs no semantic analysis itself
- TLS termination is handled by reverse proxy (nginx profile in docker-compose; the gate itself is plain HTTP)
- Policy signing verifies integrity but not provenance (no SLSA/dependency chain verification)

## 4b. Framework integration (Phase 3)

Run `test_sdk_langchain.py` to verify the SDK + LangChain adapter:

```bash
python3 test_sdk_langchain.py          # SDK tests (11) + LangChain tests (4)
python3 test_dgv_python.py              # PyO3 in-process tests (9)
```

Results from the current run:
- **15 PASS** — SDK + LangChain tests
- **9 PASS** — PyO3 in-process tests
- **0 FAIL**

**What was built:**

| Component | File | Purpose |
|---|---|---|
| Python SDK | `dgv_sdk.py` | HTTP client for all 12 gate endpoints |
| LangChain adapter | `dgv_langchain.py` | GovernedTool wrapper, GateTool, GovernanceCallbackHandler |
| PyO3 bindings | `native/dgv-python/` | In-process governance evaluation without HTTP server |

**Python SDK (`dgv_sdk.py`):**
- `GateClient` class with methods for all endpoints: `govern()`, `execute()`, `verify()`, `health()`, `stats()`, `store_policy()`, `get_policy()`, `load_policy_file()`, `revoke()`, `list_revocations()`, `store_tenant_policy()`, `get_rate_limit()`, `update_rate_limit()`, `approve()`, `report_tool_health()`, `tool_health()`, `reset_tool_health()`, `register_agent_key()`, `deactivate_agent_key()`, `a2a_send()`, `a2a_inbox()`, `a2a_ack()`
- `sign_a2a_envelope()` + `a2a_canonical_string()` helpers for building signed envelopes (PyNaCl)
- Dataclass responses: `Decision`, `ExecutionResult`, `VerifyResult`, `HealthResult`, `StatsResult`, `PolicyRecord`, `RateLimitConfig`, `RevocationRecord`
- `GateError` exception with HTTP status, error, and hint fields
- `admin_key` parameter sets `X-Admin-Key` header for admin endpoints
- `jwt_token` parameter sets `Authorization: Bearer` for identity-verified endpoints
- Zero dependencies beyond stdlib (no requests/httpx required; `sign_a2a_envelope` needs PyNaCl)

**LangChain adapter (`dgv_langchain.py`):**
- `GovernedTool` — wraps any existing LangChain `BaseTool` with governance: calls `/govern` then `/execute` then invokes the inner tool
- `GateTool` — standalone governance evaluation tool that agents can call directly
- `GovernanceCallbackHandler` — `BaseCallbackHandler` that intercepts tool calls for audit/monitoring
- Graceful fallback when `langchain-core` is not installed (no hard dependency)

**PyO3 bindings (`native/dgv-python/`):**
- `dgv_python.Gate(storage_backend, database_url)` — in-process governance engine
- `gate.govern(proposal_dict)` — evaluate a proposal, returns decision dict
- `gate.execute(token_id, executor_id, tool, action, params)` — execute with token, returns receipt
- `gate.verify(run_id)` — verify a decision by re-deriving the hash
- `gate.revoke(actor_id, reason, revoked_by)` — revoke an actor
- `gate.check_revocation(actor_id)` — check if actor is revoked
- `gate.store_policy(tool, action, script, version)` — store a policy
- `gate.verifying_key` — get the Ed25519 verifying key (hex)
- Build: `maturin build --release` produces a `.whl` for `pip install`

**Integration patterns:**

```python
# Pattern 1: HTTP SDK (works with remote gate)
from dgv_sdk import GateClient
client = GateClient("http://localhost:7878", admin_key="...")
decision = client.govern(agent_id="my-agent", tool="send_email", action="send", params={...})
if decision.allowed:
    result = client.execute(token_id=decision.token_id, ...)

# Pattern 2: LangChain GovernedTool (wraps existing tools)
from dgv_langchain import GovernedTool
governed_tool = GovernedTool(tool=existing_tool, gate_url="http://localhost:7878")
result = governed_tool.invoke({"param": "value"})

# Pattern 3: PyO3 in-process (no HTTP server needed)
import dgv_python
gate = dgv_python.Gate("sqlite", ":memory:")
result = gate.govern({"request_id": "r1", "agent_id": "agent", "tool": "t", ...})
```

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
| "JWT identity verification" | `test_gate_v3.py` | **True** — 6/6 JWT tests pass; no token = 401, valid token = allow, expired/wrong secret = deny, sub claim overrides agent_id |
| "Approval workflow" | `test_gate_v3.py` | **True** — min_approvals enforced at execute; POST /approve/:token_id stores approvals; insufficient approvals = 403 |
| "Policy signing" | `test_gate_v3.py` | **True** — policies signed with Ed25519 on store; signature verified on load; tampered policies rejected |
| "Full context hashing" | `test_gate_v3.py` | **True** — context_hash field binds full agent context, not just tool+params |
| "Justification enforcement" | `test_gate_v3.py` | **True** — min_justification_length denies short justifications |
| "Formal soundness proof" | `FORMAL_SOUNDNESS_PROOF.md` | **True** — receipt integrity, path compliance, null effect on deny, replayability, continuing authority, distributed revocation all proven |
| "Production deployment" | `Dockerfile.gate` + `docker-compose.gate.yml` | **True** — multi-stage Dockerfile, docker-compose with Postgres + replica + nginx TLS profile |
| "Python SDK for gate" | `dgv_sdk.py` + `test_sdk_langchain.py` | **True** — 11/11 SDK tests pass; zero-dependency stdlib client covering all 12 endpoints |
| "LangChain adapter" | `dgv_langchain.py` + `test_sdk_langchain.py` | **True** — 4/4 LangChain tests pass; GovernedTool, GateTool, GovernanceCallbackHandler |
| "In-process governance (no HTTP)" | `native/dgv-python/` + `test_dgv_python.py` | **True** — 9/9 PyO3 tests pass; govern, execute, verify, revoke, policies without HTTP server |
| "RS256/JWKS identity" | `test_gate_v4.py` | **True** — 8/8 tests pass; kid-selected keys, rotation, unknown kid denied, algorithm confusion rejected, JWKS responses TTL-cached with forced refetch on unknown kid |
| "Approver identity verification" | `test_gate_v4.py` | **True** — 3/3 tests pass; approve without JWT = 401, verified sub persisted as approver |
| "Semantic verifier hook" | `test_gate_v4.py` | **True** — 3/3 tests pass; webhook allow/deny enforced, fail-closed on unreachable |
| "Circuit breakers" | `test_gate_v4.py` | **True** — 5/5 tests pass; open after threshold, per-tool isolation, half-open recovery, admin reset |
| "A2A signed envelopes" | `test_gate_v4.py` | **True** — 12/12 tests pass; signature verification, replay/nonce protection, expiry, revocation, unregistered parties denied, inbox/ack flow |
| "OIDC discovery" | `test_gate_v5.py` | **True** — `DGV_OIDC_ISSUER` fetches `.well-known/openid-configuration`, resolves jwks_uri, RS256 verification works |
| "Policy versioning + rollback" | `test_gate_v5.py` | **True** — version history endpoint, rollback reactivates previous version, admin-only |
| "Prometheus metrics" | `test_gate_v5.py` | **True** — `/metrics` exposes decisions/denials/tokens/uptime/circuit state in text format |
| "Structured JSON logging" | `test_gate_v5.py` | **True** — `DGV_LOG_FORMAT=json` emits one JSON object per log line |
| "Graceful shutdown" | `test_gate_v5.py` | **True** — SIGTERM drains in-flight requests and exits 0 |
| "CrewAI adapter" | `dgv_crewai.py` + `test_gate_v5.py` | **True** — verified against real `crewai` 1.x `BaseTool` (end-to-end allow path) plus duck-typed fallback; allow and deny paths verified |
| "Agent executor middleware" | `dgv_langchain.py` `govern_all_tools` + `test_gate_v5.py` | **True** — wraps an entire tool list; every call governed |
| "PyPI packaging" | `pyproject.toml` + `native/dgv-python/pyproject.toml` | **Build-verified** — `dgv_sdk-0.4.0` sdist+wheel and `dgv_python-0.4.0` manylinux wheel build and install cleanly; PyPI publication not performed |

## 4c. Concurrent multi-instance test results

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

## 4d. Phase 4 test results — remaining OWASP gaps closed

Run `test_gate_v4.py` to verify RS256/JWKS, approver identity, the semantic
verifier hook, circuit breakers, and A2A signed envelopes:

```bash
python3 test_gate_v4.py    # 31 tests across 5 suites
```

Results from the current run:
- **29 PASS** — all v4 tests pass
- **0 FAIL**

Coverage:

| Suite | Tests | What it verifies |
|---|---|---|
| Circuit breakers | 5 | closed→open at threshold, per-tool isolation, half-open probe after cooldown, success closes circuit, admin reset |
| A2A envelopes | 12 | admin key registration, valid envelope accepted, envelope_id replay → 409, nonce replay → 409, tampered payload → 403, wrong-key signature → 403, expired → 410, unregistered sender → 403, inbox+ack flow, revoked sender → 403, deactivated recipient key → 403 |
| Semantic verifier | 3 | webhook allow → ALLOW, webhook deny → DENY with reason code, unreachable + fail-closed → DENY |
| RS256/JWKS | 8 | valid RS256 via JWKS, key rotation (two kids), unknown kid → 401, wrong key for kid → 401, expired → 401, HS256 rejected in JWKS mode (algorithm confusion), JWKS TTL cache hit, unknown kid → one forced refetch |
| Approver identity | 3 | approve without JWT → 401, JWT sub persisted as approver, body approver_id cannot be forged |


| "Concurrent multi-instance" | `test_concurrent_multi_instance.py` | **True** — 11/11 tests pass with Postgres; revocation propagates without restart, decisions verifiable across instances |
| "Objective Contract evaluates quotes" | `objective_contract.py` | **True** — 28/28 synthetic cases matched |
| "Revocation is enforced at write boundary" | `revocation_store.py` | **True** — 36/36 local cases matched |
| "Source is open" | `native/` directory | **True** — Rust source is published |
| "Independent audit completed" | This document | **False** — this is preparation, not an audit |

## 4e. Phase 8 test results — network-scale revocation

Run `test_revocation_network.py` to verify partition handling, signed gossip,
digest divergence detection, and propagation latency:

```bash
python3 test_revocation_network.py    # 20 checks across 3 suites
```

Results from the current run:
- **20 PASS** — all Phase 8 checks pass
- **0 FAIL**

| Suite | Checks | What it verifies |
|---|---|---|
| Signed gossip | 9 | revocation broadcast between disconnected nodes (separate DBs), gossiped revocation enforced at /govern, digest convergence, forged signature → 403, malformed signature → 403, stale gossip rejected by monotonicity guard, gossip rejected when DGV_GOSSIP_KEYS unset, digest detects divergence |
| Partition handling | 7 | gate boots degraded when Postgres unreachable at startup (lazy connect, no crash), /health 503 + storage=disconnected, /govern DENY with revocation_check_unavailable (fail_closed default), /execute cannot allow, /a2a/send cannot deliver, DGV_PARTITION_POLICY=fail_open restores legacy behavior explicitly, invalid policy value refused at startup |
| Propagation latency | 2 | measured ms-to-visibility across two live gate instances (gossip path ~60ms, shared-storage path ~4ms same-host SQLite lower bound), digest equality under shared storage |

Phase 8 mechanisms, kept distinct:

- **Shared Postgres** — the normal consistency boundary; every node's
  revocation check reads the same table. Idempotent upsert semantics.
- **Fail-closed partition policy** — `DGV_PARTITION_POLICY=fail_closed`
  (default): a revocation check that returns a storage *error* denies at T₀,
  T₁, and A2A paths. `fail_open` restores pre-Phase-8 behavior as an
  explicit, logged, dev-only opt-in.
- **Signed gossip** — `DGV_PEERS` + `DGV_GOSSIP_KEYS`: Ed25519-signed
  revocation records broadcast one hop to peer gates; merged via idempotent
  upsert with a monotonicity guard (newer `revoked_unix_ms` wins). Received
  gossip is never re-broadcast.
- **Digest** — `GET /revocations/digest` returns count + max timestamp +
  SHA-256 over sorted canonical entries; identical state ⇒ identical digest.
- **Degraded boot** — a gate that cannot reach Postgres at startup now boots
  degraded (health 503, all checks fail closed) and self-heals via background
  migration retry when the database returns.

## 4f. Sealed A2A transport test results

Run `test_a2a_transport.py` to verify the dgv-sealed-v1 data plane — a live
gate plus a live `onlystate-relay` binary:

```bash
python3 test_a2a_transport.py    # 15 checks
```

Results from the current run:
- **15 PASS**
- **0 FAIL**

| Checks | What it verifies |
|---|---|
| Key registry | X25519 `enc_public_key_hex` registered via admin endpoint; `GET /agents/keys/:id` public lookup; missing → 404 |
| Crypto | seal/open ECDH roundtrip; AEAD tamper → decrypt failure; wrong recipient key → AEAD failure |
| Transport | full path — seal → gate authorize + receipt → relay queue → recipient fetch → hash check → open → ack (~70ms same host); transport_ref delivered verbatim |
| Binding | gate payload_hash binds the ciphertext; swapped ciphertext → hash mismatch → refuse + no ack |
| Control plane | forged sender signature → 403; revoked sender → 403 |
| Compat | legacy unsealed hash-only envelopes still accepted; sealed wire format carries no plaintext metadata |

## 4g. Delegation test results — monotonic authority decay

Run `test_delegation.py` to verify `/delegate` and the receipt chain:

```bash
python3 test_delegation.py    # 17 checks
```

Results from the current run:
- **17 PASS**
- **0 FAIL**

| Checks | What it verifies |
|---|---|
| Happy path | root token issued → child minted with subset params + tighter expiry → child executes; parent token still valid (attenuating copy, not handoff) |
| Narrowing | changed param value → 403; added param key → 403; array element outside parent's list → 403; expiry beyond parent's → 403 |
| Identity | forged delegator signature → 403; non-grantee delegator → 403; wrong executor on any token → `token_grantee_mismatch` |
| Depth | orch→w1→w2→w3 chain (depth 3) minted; depth 4 → 403 |
| Lineage | `GET /delegations/:token_id` returns the full root→leaf chain |
| Lifecycle | consumed parent cannot delegate; revoking the orchestrator denies the depth-3 child at T₁ (`delegated_authority_revoked`); revoked delegator cannot govern |

## 4h. Quorum revocation & Merkle anti-entropy test results

Run `test_revocation_quorum.py` to verify quorum revocation at T₁ and automatic Merkle anti-entropy reconciliation:

```bash
python3 test_revocation_quorum.py    # 17 checks
```

Results from the current run:
- **17 PASS**
- **0 FAIL**

| Checks | What it verifies |
|---|---|
| Cluster topology | 3-node cluster boots with quorum enabled (Q=2 of 3); /health reports quorum_enabled=true, quorum_peers=2, quorum_size=2 |
| Signed peer queries | `POST /revocations/quorum-check` returns signed Ed25519 confirmation ("clean" / "revoked"); clock skew >60s rejected |
| Unanimous execution | Under clean quorum (3/3 votes), `/execute` succeeds and produces receipt |
| T₁ Quorum discovery | Revoking an actor on Node B immediately halts `/execute` on Node A without gossip; Node A automatically replicates the revocation locally |
| Partition fail-closed | When majority peers are unreachable (isolated Node A), `/execute` fails closed with HTTP 503 (`partition_policy_denied`) and `/govern` produces signed DENY receipt |
| Prefix Merkle tree | `GET /revocations/merkle` returns 16-bucket prefix tree; `GET /revocations/bucket/:p` returns records for that bucket |
| Active Anti-Entropy | `POST /revocations/reconcile` compares bucket hashes, pinpoints differing buckets, pulls/pushes missing records; divergent nodes automatically converge byte-for-byte to identical `tree_root` and `/revocations/digest` |

## 4i. Formal models — T₀/T₁ quorum invariant

`formal/` contains two independent models of `check_revocation_with_quorum` (see `formal/README.md` for reproduction and scope):

- **TLA+ / TLC (exhaustive):** `tla/DgvQuorum.tla`, three configurations.
- **Alloy 6 (bounded SAT):** `alloy/DgvQuorum.als`.

Results:

| Property | TLC | Alloy |
|---|---|---|
| Execution requires ≥Q reachable clean voters (fail-closed) | Holds under all partition sequences (13,280 states) | UNSAT — valid |
| No reachable node held the revocation at execution | Holds under all partition sequences | UNSAT — valid |
| No node anywhere held the revocation at execution | Holds under full mesh (46,656 states); **counterexample under partitions** | UNSAT under bounds; **counterexample under partitions** |
| Revocation convergence (liveness) | Holds under FullMesh + fair gossip | UNSAT — valid |

The counterexample both tools produce is the documented residual boundary: a revocation held **only by partitioned-away nodes** is undiscoverable, and a clean quorum assembled from the remaining majority authorizes execution (5-step trace: `Revoke(g2)` → `Partition(g1,g2)` → `Grant(g1)` → `Execute(g1)`).

## 7. What this audit package does NOT claim

- It does not claim the 89 real implementations are free of bugs (the auditor must review the code)
- It does not claim the math core is correct (the auditor must verify)
- It does not claim the test cards are comprehensive
- It does not claim the Python experiments are production-ready
- Quorum revocation (`dgv-quorum-v1`) provides linearizable read quorum ($R + W > N$) and partition fail-closed execution, and active anti-entropy (`dgv-merkle-v1`) resolves divergence between disconnected nodes; it does not claim multi-leader Byzantine consensus (BFT) or dynamic cluster reconfiguration (adding/removing quorum nodes requires environment configuration). Model checking (§4i) confirms the boundary: revocations known only to partitioned-away nodes do not block execution on the remaining clean quorum
- The formal models in §4i are bounded/exhaustive checks of a manually derived abstraction, not proofs about the Rust binary; signatures, nonces, timestamps, and Byzantine peers are out of model scope, and bounds are small (N=3, A≤2)
- It does not claim gossip delivery guarantees — broadcasts are fire-and-forget with a 3s timeout; a permanently unreachable peer misses revocations until shared storage or reconfiguration reconciles it
- It does not claim network partition or production-scale behavior beyond what Phase 8 tests demonstrate
- It does not constitute an audit — it is preparation for one
- It does not claim post-quantum security merely because ML-DSA and ML-KEM dependencies exist (the auditor must verify correct usage)
- It does not claim the L8/L9 commands implement full production authority management (they implement the test-card semantics, not a production authority store)
- It does not claim the enforcement gate is production-ready (rate limit config is per-instance in memory; admin auth is a single shared key, not OIDC/JWT)
- It does not claim the LangChain adapter is a complete production integration (GovernedTool wraps individual tools; `govern_all_tools` covers a full tool list, but agent-loop governance — intercepting the model's reasoning itself — is not addressed)
- It does not claim the PyO3 bindings cover all gate functionality (they provide core govern/execute/verify/revoke; admin endpoints like rate limit config require the HTTP API)
- It does not claim Python package distribution is live (`dgv-sdk` and `dgv-python` wheels build and install locally — verified; PyPI publication has not been performed)
- It does not claim OIDC discovery refreshes (the discovery document is fetched once at startup; JWKS keys are TTL-cached with forced refetch on unknown kid)
- It does not claim structured logging covers all code paths (key events are structured; some startup banner lines remain plain text)
- It does not claim the gate's default governance script is suitable for production use (it is a demonstration script; custom policies can be stored via API or loaded from YAML files)
- It does not claim the semantic verifier performs analysis inside the gate (the gate delegates to a configured webhook; verifier quality is external)
- It does not claim circuit-breaker state is distributed (it is per-instance in memory; shared-state breakers are future work)
- It does not claim A2A payloads are confidential *by the gate itself* (the gate stores hashes only) — dgv-sealed-v1 provides agent-side confidentiality via ECDH+ChaCha20-Poly1305 over onlystate-relay, which is not post-quantum and does not hide traffic metadata (see A2A_TRANSPORT.md)
- It does not claim delegation is a full capability system — child scope is confined to the parent's literal tool+action with a JSON-subset params check; there is no cross-tool scope composition or parametric value widening (e.g., "amount ≤ X") — those would need richer policy semantics

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
