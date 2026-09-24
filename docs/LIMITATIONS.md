# Known Limitations & Design Boundaries

> **Transparency is a feature.** This document describes what `dgv-gate` does *not* do, and where its guarantees stop, so operators can make informed architecture decisions rather than discover the boundary in production. Structure borrowed deliberately from [Microsoft's Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/LIMITATIONS.md), which does this well.

## 1. Action Governance, Not Reasoning Governance

DGV governs **what an agent does** (proposed tool calls, evaluated against policy). It does **not** govern what an agent *thinks*, *says*, or whether the content it passes to an allowed action is correct.

- ✅ DGV blocks an action if policy forbids it, or if authority was revoked between grant and spend
- ❌ DGV does **not** detect if the *content* passed to an allowed action is wrong, hallucinated, or malicious
- ❌ DGV does **not** correlate a sequence of individually-allowed actions that together form a harmful pattern (e.g. `read_customer_list` then `post_to_public_channel`, each separately permitted)

**Mitigation today:** keep policies narrow and action-specific; combine with application-level validation of tool arguments. **Not yet built:** workflow-level policies evaluating action sequences rather than single calls.

## 2. Quorum and Gossip Are Real Code, Not Yet Proven at Real Multi-Node Scale

Peer-gossip revocation broadcast, quorum-voted revocation checks, and Merkle anti-entropy reconciliation are implemented and pass local logic (see `main.rs`: `check_revocation_with_quorum`, `reconcile_with_peer`), but have **not yet** been exercised against a second, genuinely independent, network-separated host — only the single live node at `gate.only.institute` has been tested externally.

**Status:** a test plan for a second node exists and is ready to run. Until that happens, `DGV_QUORUM_PEERS`/`DGV_PEERS` should be treated as implemented-but-field-unverified, not production-proven.

## 3. Evidence Verification Only Covers `https://` References

`POST /evidence/artifacts/:id/verify` fetches and hashes a referenced artifact itself, but only for `https://` URLs.

- ✅ An `https://` `content_ref` is fetched, hashed, and its `verified` flag reflects a real comparison
- ❌ `s3://`, `file://`, or any other scheme is rejected outright (`400 unsupported_content_ref_scheme`) — the gate has no credentialed access to private buckets or filesystems, deliberately, and won't guess

**Mitigation today:** for non-`https://` evidence, verify out-of-band and register with `content_b64` (≤256KB) instead, which is hash-checked at registration time. **Not yet built:** a pluggable fetcher for authenticated/private storage backends.

## 4. The Decision Chain Proves Export Integrity, Not Operator Honesty

`GET /decisions/export` produces a hash-chained, Ed25519-signed batch that an offline verifier (`scripts/verify_decision_chain.py`) can confirm is internally consistent — no record inserted, deleted, reordered, or altered *within what was exported*.

- ✅ Tampering with an exported JSON file after the fact is detected (hash mismatch, signature mismatch, or broken chain link — verified independently, live-tested against all three failure modes)
- ✅ Every DENY the gate issues is a signed, chained record — including refusals decided *before* policy evaluation (failed identity, rate limit, open circuit breaker). These are marked `early_denial: true` in `replay_inputs`; an identity failure additionally carries `agent_id_verified: false`, because the `agent_id` is then only the caller's unverified claim.
- ⚠️ Persisting those early denials is capped (`DGV_EARLY_DENIAL_LOG_MAX_PER_MIN`, default 600 per rolling minute), because they are reachable by unauthenticated callers and each stored decision takes the chain-tail lock. Past the cap a denial is still enforced, signed in the response, and counted in `/stats` — but **not chained**. `dgv_early_denials_unpersisted_total` in `/metrics` counts exactly those, so a non-zero value means the chain is intentionally incomplete for that period.
- ✅ Run IDs are now unique within a gate process. They were millisecond timestamps, so two requests in the same millisecond collided on `decisions.run_id` and the second decision was silently not recorded even though the caller already held a signed verdict (found by a 40-way concurrent burst against Postgres: 2 of 13 issued ALLOWs had no chain record). A persist failure on the normal path is no longer swallowed: it is logged as `decision_persist_failed` and counted in `dgv_decisions_unpersisted_total`; a non-zero value means a verdict was issued that is not in the chain. Two gate instances sharing one database can still, rarely, draw the same millisecond (a per-instance suffix would close it but changes the id format).
- ✅ `/decisions/export` orders each batch by chain links, not by `created_unix_ms`. The timestamp is taken before the chain-tail lock, so under concurrency it disagrees with chain order and a correct chain looked "broken" to the offline verifier.
- ❌ Export **pagination is still by timestamp** (`after=<created_unix_ms>`, strictly greater): decisions sharing a millisecond at a page boundary can be skipped, and the offline verifier requires the first record of a file to have a null parent, so a second page verifies only if it is exported as part of one contiguous range. Export in a single request (`limit` up to 2000) when verifying. **Not yet built:** cursoring by chain sequence.
- ⚠️ Early denials issued **before** this behavior was deployed were never chained and cannot be recovered; `/stats` counters (in-memory, reset on restart) may exceed the chain for older periods.
- 🔒 `GET /decisions/export` is not public. It requires `X-Export-Key` (`DGV_EXPORT_KEY`, a read-only credential suitable for an auditor) or `X-Admin-Key`; with neither configured it returns `403 export_disabled` unless `DGV_EXPORT_PUBLIC=1` is set for development. `?redact=true` withholds `params`, `agent_id` and `workflow`: chain contiguity and signatures still verify, but the decision hash **cannot** be re-derived, and the offline verifier reports that check as `SKIPPED` rather than passed.
- ❌ The chain does **not** prove that the first record in a given export is genuinely the first decision the gate ever made. An operator with direct database access could, in principle, truncate history and reset the chain tail before exporting — the same trust boundary every append-only-log design has against its own operator

**Mitigation today:** export and archive batches regularly to an operator-independent location (append-only storage, a second organization); a gap in exported sequence numbers or timestamps is itself a signal worth investigating. **Not yet built:** external anchoring (e.g. periodic chain-tail commitment to a third-party timestamping service) that would make even operator-level history rewriting detectable.

## 5. `decision_hash` Formula Versioned 2026-09-19 — Old Decisions Don't Re-Verify

`compute_decision_hash()` was fixed to use RFC 8785 (JCS) canonical serialization instead of raw field concatenation (see the [Microsoft positioning note](../../only-institute-pir/docs/positioning/microsoft-agent-governance.md) for why). Decisions stored before this change will correctly report `verified:false` from `/verify/:run_id` and `FAIL` from the offline chain verifier under the new formula — this is expected, not a bug, and is a permanent property of that specific historical cutover.

**Mitigation:** treat the JCS fix's deploy timestamp as a version boundary when auditing older exports; there is currently no explicit `hash_version` field distinguishing pre/post-fix records — an operator must reason about it via `created_unix_ms`. **Not yet built:** an explicit versioned hash-scheme tag on each decision record.

## 6. One Static Admin Secret, Not Per-Operator Credentials

`DGV_ADMIN_KEY` is a single shared secret gating all admin endpoints (revocation, policy writes, agent-key registration). There's no per-operator identity, rotation, or scoped permission on top of it.

**Mitigation today:** treat the admin key like any other production secret — rotate it manually, restrict which hosts can reach admin routes at the network layer. **Not yet built:** OAuth2 client-credentials-style per-caller admin auth (the direction [Blue's own SECURITY.md](../../only-institute-pir/docs/positioning/blue-metaharness.md) documents moving toward for their comparable internal trust boundary).

## 7. Peer-to-Peer Wire Protocols Aren't JCS-Canonicalized

`gossip_canonical`, `quorum_canonical`, and `delegate_canonical_string` still build ad-hoc pipe-delimited strings rather than RFC 8785 canonical JSON, unlike the internal `decision_hash` (fixed in #5). Left alone deliberately: these are documented formats external peers and delegators reconstruct independently (e.g. `dgv-delegate-v1|...`), so changing the format is a breaking protocol version bump requiring a coordinated `v2`, not a quiet internal fix.

**Status:** known, accepted gap. **Not yet built:** a versioned `dgv-delegate-v2` canonical format.

## 8. SQLite Is Development/Test Only

The SQLite storage backend is not recommended for concurrent production load — Postgres is the documented production backend (`docker-compose.gate.yml`). The decision-chain locking added in this pass works correctly on both, but SQLite's single-writer lock will serialize (not corrupt) concurrent decisions under real load, which is a throughput ceiling, not a correctness bug.

## 9. No Adversarial Penetration Testing Yet

Everything verified so far against the live deployment (TLS quality, security headers, rate limiting, firewall exposure, OIDC enforcement) is **configuration and exposure verification** — confirming the gate is set up correctly — not an adversarial attempt by an independent party to actually break in. [Microsoft's AGT](https://github.com/microsoft/agent-governance-toolkit) has had exactly this kind of external red-team engagement (Periculo, 15 bypass vectors, published); DGV hasn't yet.

**Status:** not yet scoped. Worth pursuing as the deployment matures.

---

*This document should be updated whenever a genuine limitation is found or closed — see the git history of this file for what's changed and when, matching the discipline of treating gaps as a permanent, dated record rather than something to quietly fix and forget.*
