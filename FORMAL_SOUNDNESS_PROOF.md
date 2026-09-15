# Formal Soundness Proof — DGV Enforcement Gate

**Version:** 1.0
**Date:** 2025-09-16
**Scope:** The DGV enforcement gate (`dgv-gate` v0.2.0) with persistent storage (`dgv-storage`)

---

## 1. Definitions

Let:
- `P` = a proposal (tool call request) containing `(request_id, agent_id, workflow, tool, action, params, justification, risk_level)`
- `D` = a decision produced by `govern(P)` containing `(gate_state, reason_codes, decision_hash, auth_token)`
- `T` = an auth token issued on ALLOW containing `(token_id, request_id, tool, action, params_hash, expires_unix_ms, consumed, decision_hash, signature)`
- `R` = an execution receipt produced by `execute(T)` containing `(allowed, deny_reason, run_id)`
- `S` = the persistent storage backend (SQLite or Postgres)
- `K` = the Ed25519 signing key pair `(sk, vk)`
- `H(x)` = SHA-256 hash of `x`
- `σ(m)` = Ed25519 signature of message `m` under `sk`
- `V(σ, m)` = Ed25519 verification of signature `σ` on message `m` under `vk`

---

## 2. Security Model

### 2.1 Assumptions

**A1 (Cryptographic):** Ed25519 is existentially unforgeable under chosen-message attack (EUF-CMA). An adversary without `sk` cannot produce a valid signature `σ` such that `V(σ, m) = true` for any message `m` they have not seen signed.

**A2 (Hash):** SHA-256 is collision-resistant. Given `H(x)`, it is computationally infeasible to find `x' ≠ x` such that `H(x') = H(x)`.

**A3 (Storage):** The storage backend `S` provides atomic read-modify-write for token consumption and revocation checks. SQLite uses WAL mode with `BEGIN IMMEDIATE` transactions; Postgres uses row-level locking with `FOR UPDATE` or equivalent.

**A4 (Network):** The gate runs on a single logical node (or multiple nodes sharing the same `S`). Network adversaries can intercept, replay, or modify messages but cannot forge signatures or find hash collisions.

### 2.2 Threat Model

We consider an adversary who:
- Can observe all network traffic between agents and the gate
- Can replay previously observed requests
- Can modify request parameters
- Can attempt to execute with forged or stale tokens
- Cannot access `sk`, cannot break SHA-256, cannot bypass storage atomicity

---

## 3. Theorems and Proofs

### Theorem 1: Receipt Integrity

**Statement:** A receipt `R` produced by `execute(T)` cannot be forged or tampered with without detection.

**Proof:**

1. Each decision `D` contains `decision_hash = H(request_id || gate_state || reason_codes || tool || action || params)`. By A2, modifying any component produces a different hash.

2. Each ALLOW decision includes `auth_token` with `signature = σ(decision_hash)`. By A1, an adversary cannot produce a valid signature for a modified `decision_hash` without `sk`.

3. The `verify` endpoint re-derives `decision_hash` from stored `replay_inputs` and compares to the stored hash. Any tampering produces `verified = false`.

4. The execution receipt `R` contains `run_id`, `verified`, and `signature`. An adversary cannot produce a receipt with `verified = true` and a different `decision_hash` without either (a) forging the signature (impossible by A1) or (b) finding a hash collision (impossible by A2).

**∴** Receipt integrity holds. Any modification to a decision, token, or receipt is detectable via hash comparison or signature verification. ∎

---

### Theorem 2: Path Compliance

**Statement:** If `govern(P)` returns `gate_state = DENY`, the tool call does not execute.

**Proof:**

1. The `govern` handler evaluates the governance script for `P`. If the script fails any check, `gate_state = DENY` and `auth_token = None`.

2. The `execute` handler requires a valid `auth_token`. Without a token, `execute` returns `403` with `deny_reason = "token_not_found"`.

3. Even if the adversary constructs a fake token, `execute` verifies `V(token.signature, token.decision_hash)`. A forged signature fails by A1.

4. Even if the adversary replays a valid token from a previous ALLOW decision, the token is marked `consumed` atomically in `S`. A second `execute` with the same `token_id` returns `403` with `deny_reason = "token_already_consumed"` (by A3, the atomic update prevents double-consumption).

5. Even if the adversary modifies the `params` or `action` in the execute request, `execute` checks `token.params_hash == H(params)` and `token.action == action`. Mismatch returns `403`.

**∴** Path compliance holds. A DENY decision produces no executable token, and no forged or replayed token can bypass the check. ∎

---

### Theorem 3: Null Effect on Deny

**Statement:** A denied proposal produces no side effects on the target system.

**Proof:**

1. The gate's `execute` endpoint is the only path to the target system. If `execute` returns `403`, no downstream call is made.

2. The gate does not proxy or forward denied requests — it simply returns the denial to the caller.

3. The `decision` record stored in `S` is a log entry, not a command. It has no effect on the target system.

4. The only side effects of a DENY are: (a) the decision record in `S`, (b) the in-memory counter increment, (c) the HTTP response. None of these affect the target system.

**∴** Null effect on deny holds. A denied proposal produces no effect on the target system. ∎

---

### Theorem 4: Replayability

**Statement:** The same proposal `P` always produces the same `decision_hash` when the governance policy and revocation state are unchanged.

**Proof:**

1. `decision_hash = H(request_id || gate_state || reason_codes || tool || action || params)` is deterministic given the same inputs.

2. `gate_state` and `reason_codes` are deterministic functions of `P` and the policy script. The ONLY Lang interpreter is deterministic — the same script on the same inputs produces the same result.

3. The only non-deterministic inputs are: (a) the `run_id` (timestamp-based, not used in hash), (b) the `signature` (depends on `sk`, but `decision_hash` is the input to signing, not the output), (c) revocation state (explicitly modeled as a dependency).

4. If the policy script and revocation state are unchanged, `decision_hash` is invariant.

**∴** Replayability holds. The same proposal produces the same decision hash, enabling auditability and non-repudiation. ∎

---

## 4. Soundness of the Full System

### Theorem 5: Continuing Authority

**Statement:** Authorization at T₀ (govern time) is not sufficient for execution at T₁ (execute time). The system checks current authority at T₁.

**Proof:**

1. The `execute` handler checks `check_revocation(executor_id)` at T₁, not just at T₀. If the actor was revoked between T₀ and T₁, `execute` returns `403` with `deny_reason = "authority_revoked_at_t1"`.

2. The `execute` handler checks `token.expires_unix_ms` at T₁. If the token expired between T₀ and T₁, `execute` returns `403` with `deny_reason = "token_expired"`.

3. The `execute` handler checks `token.consumed` atomically at T₁. If the token was consumed between T₀ and T₁ (e.g., by another request), `execute` returns `403` with `deny_reason = "token_already_consumed"`.

**∴** Continuing authority holds. The system re-checks authority at execution time, catching revocation, expiry, and consumption that occurred between govern and execute. ∎

---

### Theorem 6: Distributed Revocation

**Statement:** Revocation on one gate instance is visible to all instances sharing the same storage backend.

**Proof:**

1. `store_revocation` writes to the shared `S` (SQLite file or Postgres database). The write is committed before the response is returned.

2. `check_revocation` reads from `S` at the time of the check. Any committed revocation is visible to all readers.

3. For Postgres, `check_revocation` uses a `SELECT` query that sees committed transactions. For SQLite with WAL mode, readers see the latest committed state.

4. The concurrent multi-instance test verifies this: revocation written by instance A is immediately visible to instance B without restart.

**∴** Distributed revocation holds. Revocation propagates to all instances sharing the same database. ∎

---

## 5. Limitations and Honest Disclosures

1. **Single-node signing key** — All instances must share the same Ed25519 signing key. A key compromise affects all instances. Production deployments should use HSM or KMS for key management.

2. **No Byzantine fault tolerance** — The system assumes honest gate instances. A malicious instance could issue forged tokens (if it has `sk`). The storage layer prevents double-spending but cannot prevent a compromised instance from issuing valid tokens.

3. **No consensus for revocation** — If two instances write conflicting revocations simultaneously, the last-write-wins. This is acceptable for most use cases but may need consensus for high-stakes scenarios.

4. **Rate limit config is per-instance** — Each instance has its own `RateLimitConfig` in memory. Counters are shared via the database (distributed rate limiting works), but the config itself is not shared.

5. **Admin endpoints have no RBAC** — `X-Admin-Key` is a single shared key, not per-user. Production deployments should use OIDC/JWT for admin auth.

6. **No proof of script correctness** — The ONLY Lang interpreter is deterministic, but we do not prove that a given script implements the intended policy. Script correctness is a separate concern (testing, auditing).

---

## 6. Conclusion

The DGV enforcement gate satisfies the four core soundness properties:

| Property | Status | Mechanism |
|---|---|---|
| Receipt integrity | ✅ Proven | SHA-256 + Ed25519 signatures |
| Path compliance | ✅ Proven | Token requirement + signature verification + atomic consumption |
| Null effect on deny | ✅ Proven | No downstream call on 403 |
| Replayability | ✅ Proven | Deterministic hash + deterministic interpreter |
| Continuing authority | ✅ Proven | T₁ revocation + expiry + consumption checks |
| Distributed revocation | ✅ Proven | Shared storage backend |

The system is sound under the stated cryptographic and storage assumptions. It does not claim Byzantine fault tolerance, consensus for revocation, or per-user admin RBAC — those are documented as limitations.
