# Benchmark Report: Only Institute DGV vs. Microsoft AGT

**Comparative Execution Evaluation across Mid-Flight Revocation, Delegation Decay, and Cryptographic Evidence**

*Original benchmark date: 2026-09-16 17:36:51 UTC*
*Real-product verification: 2026-09-21 (Vector 2, human oversight) and 2026-09-22 (Vector 1 end-to-end, Vector 3 evidence).*
*Harness: `test_benchmark_agt_vs_dgv.py`*

---

## Read this first: what "AGT" means in each table below

This report mixes two different kinds of evidence. Earlier versions did not make that distinction clear, which let a model of a competitor stand in for the competitor. That is corrected here, and it changes the conclusion in more than one place — including one correction that weakens our own claim, not just Microsoft's.

| Marker | What it means | Basis |
|---|---|---|
| 🔷 **Modeled** | Measured against `MicrosoftAgtEngine`, a reimplementation we wrote from Microsoft's published architecture description, in `benchmark_agt_vs_dgv.py`. **This is not the Microsoft product.** | modeled-reference |
| 🟢 **Tested-real** | Measured by running the real, installable Microsoft package (`agent-os-kernel`, a component of AGT, version 3.7.0, from PyPI) and observing its behaviour directly. Scripts in `verification/`. | tested-real |

As of 2026-09-22, all four vectors below have real-product results. None is modeled-only any more. Where a modeled claim from the original document turned out wrong, it is corrected, not softened — including in Vector 1, where the real product does something we previously said it didn't.

---

## Executive Summary

1. **Mid-Flight Revocation — corrected, real, and the biggest change in this document.** 🟢 We built the actual scenario against the real product's HTTP execution endpoint: authorize a session, revoke it, attempt execution with the same token. **The real product refused the second request.** The original claim — that AGT "allows the write to proceed, recording the incident post-hoc" — is wrong for a properly configured deployment of the real product. We also found the endpoint refuses everything by default (503) if no bearer-token authenticator is configured at all, rather than running ungoverned. Both corrections narrow our differentiation on this specific vector; we're reporting them anyway.
2. **Authority Delegation — corrected 2026-09-21.** 🟢 The real product blocks a delegated child from adding an action its parent never declared, but accepts a child with a widened parameter, and we found no cascade-revocation mechanism. The original claim overstated the gap on actions and was accurate on parameters and cascades.
3. **Receipt Architecture — corrected 2026-09-22.** 🟢 The real product's audit logger (`FlightRecorder`) hash-chains every entry, including denials, and detects tampering precisely — we tampered with a stored denial and it correctly identified which row. The original claim that "denials are unreceipted exceptions" is wrong. What still holds: there is no cryptographic signature, so verifying the chain requires access to (and some trust in) the database file itself — not the standalone, offline-verifiable proof DGV produces.
4. **Human oversight — added 2026-09-21.** 🟢 The real product ships an escalation module with approval gates and configurable timeout behaviour. The original document said nothing about this, which read as a claim AGT lacks it. It doesn't.

**What's left standing as a real, tested difference:** DGV enforces parameter-level delegation limits and cascade revocation where the real AGT product does not (Vector 2); DGV produces standalone, offline-verifiable signed receipts where the real AGT product's evidence requires trusting the database it's stored in (Vector 3). What is **no longer** a claim we can make: that AGT lets a revoked agent's write through. Tested, it does not.

---

## Benchmark Results by Vector

### Vector 1: Mid-Flight Revocation (T₀ Proposal vs. T₁ Execution) — 🟢 tested-real, corrected 2026-09-22

**Scenario, as tested against the real product:** bootstrap a session bound to a bearer token for an agent, via `agent_os.mcp_session_auth.MCPSessionAuthenticator`, wired into the real FastAPI app (`agent_os.server.app.GovServer`) as its execute-request authenticator — the SDK's own shipped configuration for protecting `/api/v1/execute`. Call `/api/v1/execute` with that token (T₀-equivalent: this succeeds). Revoke the session. Call `/api/v1/execute` again with the same token (T₁).

| Metric | Microsoft AGT — 🟢 tested-real, 2026-09-22 | Only Institute DGV Gate (Live) |
|---|---|---|
| First execute call, valid token | `200`, action executed | ALLOW |
| Revoke session | `revoke_session(token)` | — |
| Second execute call, same (now-revoked) token | **`401 Invalid or expired execute bearer token.` — BLOCKED** | **BLOCKED (HTTP 403, fail-closed)** |
| Execute called with no authenticator configured and unauthenticated execute not explicitly enabled | **`503`, refused — fails closed by default** | N/A |

**Reproduce:** `verification/agt_real_test_vector1_execution.py`. Last run 2026-09-22:
```
T0 (valid session) execute -> 200 {'success': True, ...}
T1 (same token, after revoke_session) execute -> 401 Invalid or expired execute bearer token.
```

**This corrects the original claim directly.** The original table said AGT's execution "EXECUTED (Unauthorized write committed)" after revocation, with the write going through and only being logged after the fact. That was never measured against the real product — it came from `MicrosoftAgtEngine`, our own model, which does not implement session-token revocation checking on its execute path at all, because we didn't build it to. The real product does check, when you use the authentication mechanism it ships for exactly this purpose. We were wrong to imply otherwise before checking.

**What is still a real, narrower gap, not corrected away:** this exercises `agent-os-kernel`'s own default `StatelessKernel.execute()` with no custom policy or action handler. It doesn't test whether every AGT deployment actually configures `execute_authenticator` (the SDK warns at startup if you don't, but doesn't force it), whether a custom action handler built on top of the kernel re-checks revocation itself, or AgentMesh's separate delegation path (see Vector 2). DGV's fail-closed behaviour is not configurable off; here it depends on using the mechanism as shipped.

> *"Permission to act is not continuing authority to act."* Both DGV and — when configured — the real AGT execution path we tested check this at execution, not only at proposal. This document previously claimed only DGV did. That claim does not survive contact with the real product and is withdrawn.

---

### Vector 2: Monotonic Authority Delegation Decay — 🟢 tested-real, corrected 2026-09-21

**Scenario A (Parameter Widening):** Parent orchestrator delegates a subtask to a worker. The worker attempts to inject unauthorized parameters into the delegated token.

| Control | Microsoft AGT | Only Institute DGV Gate |
|---|---|---|
| Extra-action delegation (child requests an action the parent never declared) | 🟢 **Blocked**, tested against the real `agent-os-kernel` 3.7.0: `create_child_intent` raised `IntentScopeError` | **Blocked** (`widened_params` → HTTP 403) |
| Parameter widening (same action, looser limit) | 🟢 **Allowed**, tested against the real product: a child intent with a higher spending limit than its parent was accepted with no error | **Blocked**, strict mathematical JSON subset (A ⊆ B) |

The original version of this table said AGT's scope containment was a "pass-through snapshot" with "no subset math" at all. Real: it does check and reject an unplanned *action*. It is the *parameter* check that is missing.

**Scenario B (Ancestor Cascade Kill Switch):** An orchestrator agent delegates authority to a child worker. The orchestrator is revoked. The worker attempts to execute.

| Control | Microsoft AGT | Only Institute DGV Gate |
|---|---|---|
| Cascade / ancestor-revocation API | 🟢 Tested-real: searched the real `IntentManager`'s public interface for anything named revoke, cancel, kill or abort — found none | **Present**: revoking an orchestrator invalidates the entire subtree (tested, live gate) |

Unchanged in substance from the original claim — no cascade-revocation mechanism found — now backed by inspecting the real package.

**Reproduce:** `verification/agt_real_test.py`. Scope: `agent-os-kernel` 3.7.0's `IntentManager` and `MCPSessionAuthenticator` only, exercised by code, on one date. Does not cover AgentMesh.

---

### Vector 3: Decision Evidence & Independent Verifiability — 🟢 tested-real, corrected 2026-09-22

**Scenario, as tested against the real product:** log a successful action and a policy violation (denial) through `agent_control_plane.flight_recorder.FlightRecorder`, the real hash-chained SQLite audit logger shipped with the toolkit. Run its own `verify_integrity()`. Then tamper directly with the SQLite file — flip a denial's stored verdict to "allowed," bypassing the recorder's API, as an operator or an attacker with database access could — and run `verify_integrity()` again.

| Property | Microsoft AGT — 🟢 tested-real, 2026-09-22 | Only Institute DGV Gate (Live) |
|---|---|---|
| Evidence Format | Merkle-style hash chain (`entry_hash` linked to `previous_hash`, plus a `content_hash` over the record's fields), in SQLite | PSR-001 Ed25519 Cryptographic Receipt |
| Verification Complexity | **Confirmed $O(N)$** — `verify_integrity()` walks every row in insertion order | **$O(1)$ — constant time single signature verify** |
| Offline / third-party verification | **No** — verification requires the SQLite database file itself, and trusts that file's authenticity; nothing here is signed | **Yes — self-contained, verifiable with only the receipt and a published public key** |
| Denial Proofs | **Wrong in the original document.** A denial (`log_violation`) updates the *same* chained row its proposal (`start_trace`) created, and gets its own `content_hash`. Tampering with a denial's stored verdict is detected, and the exact tampered row identified. | **Signed Receipts for both ALLOW and DENY** |
| Tamper detection, tested | **Confirmed**: `verify_integrity()` returned `valid: True` before tampering, `valid: False, first_tampered_id: 2` after we edited the denial's stored verdict directly in the SQLite file | Deterministic re-derivation from context hash |

**Reproduce:** `verification/agt_real_test_vector3_evidence.py`. Last run 2026-09-22:
```
Logged 1 success + 1 violation (denial).
verify_integrity() before tampering: {'valid': True, 'total_entries': 2, 'message': 'Hash chain integrity verified'}
verify_integrity() after tampering:  {'valid': False, 'total_entries': 2, 'first_tampered_id': 2, 'error': 'Content hash mismatch at entry 2: field tampering detected'}
```

**What this corrects:** "Denial Proofs: None (Denials are unreceipted exceptions)" is false for the real product — denials are chained and tamper-evident exactly like approvals. **What holds up:** there is no signature. Verifying the chain means trusting whoever holds the SQLite file, or replicating it, which is a materially different property from a receipt you can carry off-site and check against a public key with nothing else. That is a real, tested difference, not a modeled one, and it is the one the original document's spirit was gesturing at even though its specific wording ("unreceipted exceptions") was wrong.

**Scope:** `agent_control_plane.flight_recorder.FlightRecorder` only. We did not check whether every action in a real deployment is actually routed through it, or whether other evidence backends exist elsewhere in the toolkit.

---

### Vector 4: Human-in-the-loop escalation — 🟢 tested-real (code inspection), 2026-09-21

Added 2026-09-21. Its absence from the original three vectors read as a claim AGT lacks human oversight, which is false.

| Property | Microsoft AGT | Only Institute DGV Gate |
|---|---|---|
| Human-approval module | 🟢 **Present**: `agent_os.escalation.EscalationManager`, with approval/deny/timeout outcomes and a configurable default-on-timeout | **Present**: HITL gate with recorded approver and decision |
| Default on timeout | Configurable (`default_on_timeout`) | Fail-closed |

Verified by reading the module's real source and docstring, not by executing an escalation flow end-to-end — a weaker form of "tested" than Vectors 1–3.

---

## Architectural Comparison Matrix

| Architectural Capability | Microsoft AGT | Only Institute DGV | Basis for the AGT column |
|---|---|---|---|
| **Continuing Authority Enforcement at Execution** | ✅ **Confirmed, when the shipped execute-authenticator is configured**: a revoked session's token is refused at `/api/v1/execute` (tested-real, 2026-09-22) | ✅ Fail-closed write barrier, always on (tested, live) | 🟢 tested-real |
| **Fail-closed when authentication isn't configured at all** | ✅ Refuses (503) rather than running ungoverned (tested-real, 2026-09-22) | ✅ Same principle, always on | 🟢 tested-real |
| **Delegated action containment** | ✅ **Blocks an undeclared action** (tested-real, 2026-09-21) | ✅ Blocks an undeclared action (tested, live) | 🟢 tested-real |
| **Delegated parameter containment** | ❌ **Accepts a widened parameter** (tested-real, 2026-09-21) | ✅ Strict recursive JSON subset validation (tested, live) | 🟢 tested-real |
| **Cascade Revocation Kill Switch** | ❌ No revoke/cancel/kill API found on the real intent manager (tested-real, 2026-09-21) | ✅ Ancestor walk at T₁ invalidates all descendants (tested, live) | 🟢 tested-real |
| **Human-approval escalation** | ✅ **Present** — `agent_os.escalation` module (tested-real, code inspection, 2026-09-21) | ✅ Present, HITL gate | 🟢 tested-real |
| **Evidence hash-chained, tamper-evident, including denials** | ✅ **Confirmed** — `FlightRecorder`, denials included (tested-real, 2026-09-22) | ✅ Confirmed, own gate (tested, live) | 🟢 tested-real |
| **Standalone, offline, third-party-verifiable evidence (no signature required)** | ❌ Requires the database file itself; no signature found (tested-real, 2026-09-22) | ✅ Ed25519-signed, self-contained (tested, live) | 🟢 tested-real |
| **Network Partition Handling** | Not tested by us in either direction | ✅ CP quorum read fails closed (tested, live) | untested for AGT |
| **Partition Healing** | Not tested by us in either direction | ✅ Automated Merkle anti-entropy (tested, live) | untested for AGT |
| **Execution Sandboxing** | ✅ Rings 0–3 privilege isolation, per Microsoft's own documentation | ❌ Delegated to container runtime | internal-analysis, not independently tested by us either way |
| **Framework Integrations** | ✅ Multiple frameworks supported, per Microsoft's own documentation | ⚠️ LangChain, CrewAI, Python, REST | internal-analysis |

---

## Conclusion & Recommendation

1. **For Sandboxing & Fleet SRE:** Microsoft AGT provides container-level process isolation and chaos testing that DGV intentionally does not build. This claim is from Microsoft's own documentation, not independently tested by us.
2. **On mid-flight revocation, the two products behave the same way when both are configured as intended.** This is a real correction, not a hedge: earlier drafts of this document claimed otherwise, and that claim was wrong. Where DGV differs is that fail-closed is not optional — there is no configuration in which it runs unauthenticated or ungoverned, where AGT's execute path can be (`allow_unauthenticated_execute`).
3. **On delegation, a real difference remains:** DGV checks parameters, not only actions, and cascades revocation through a delegation tree. AGT, tested, does neither.
4. **On evidence, a real difference remains, narrower than originally claimed:** both products produce tamper-evident records of denials, not just approvals. DGV's records are independently, offline verifiable with a signature; AGT's require access to and trust in the database that holds them.
5. **AGT has human-in-the-loop escalation.** Previously undocumented here; corrected.
6. **The Optimal Enterprise Posture:** compose both, where each is strong. Use AGT for the execution sandbox and its own approval and execution-authentication flows; place the DGV gate where its remaining tested advantages matter — delegation parameter limits, cascade revocation, and receipts a third party can verify without access to your systems — not as a blanket claim of superiority this document no longer makes.

---

## Claims register

Every comparative claim above about AGT, cross-referenced to its evidence and basis, per this document's own evidence rule (see `docs/governance-starter/07-evidence-and-logging-standard.md`, EV-12, in the sibling `dgv-deforge-editor` repository: no external claim without a traceable test or record).

| Claim | Basis | Source | Verified |
|---|---|---|---|
| Real AGT's execute path refuses a revoked session's token | tested-real | `verification/agt_real_test_vector1_execution.py` | 2026-09-22 |
| Real AGT's execute path refuses all requests by default if no authenticator is configured | tested-real | `verification/agt_real_test_vector1_execution.py` | 2026-09-22 |
| Real AGT blocks a delegated child adding an undeclared action | tested-real | `verification/agt_real_test.py` | 2026-09-21 |
| Real AGT accepts a delegated child with a widened parameter | tested-real | `verification/agt_real_test.py` | 2026-09-21 |
| Real AGT's intent manager has no revoke/cancel/kill/abort method | tested-real | `verification/agt_real_test.py` (`dir()` inspection of the public interface) | 2026-09-21 |
| Real AGT has a human-approval escalation module | tested-real (code read, not executed) | `agent_os/escalation.py` in `agent-os-kernel` 3.7.0 | 2026-09-21 |
| Real AGT's FlightRecorder hash-chains every entry, including denials, and detects tampering | tested-real | `verification/agt_real_test_vector3_evidence.py` | 2026-09-22 |
| Real AGT's evidence has no cryptographic signature; verification requires the database file | tested-real (absence confirmed by reading `flight_recorder.py` and `audit_logger.py` in full, and by the reproduction above) | `verification/agt_real_test_vector3_evidence.py`, `agent_control_plane/flight_recorder.py` | 2026-09-22 |
| AGT's sandboxing and framework-integration count | internal-analysis | Microsoft's own published documentation | Not independently verified |
| AGT's network-partition handling | — | not tested | Open question, not claimed |
| DGV's own tested behaviours (fail-closed execution check, parameter subset, cascade revocation, signed receipts, quorum, anti-entropy) | tested-real, our own gate | `native/` live gate, run 2026-09-16 | 2026-09-16 |

**Unresolved, listed rather than hidden:**
- Network partition handling for the real AGT product was never tested in either direction; the matrix now says "untested" instead of implying a result.
- The escalation-module finding is code inspection, not an executed approval flow.
- All real-product tests here exercise `agent-os-kernel`'s own SDK-provided defaults (its `StatelessKernel`, `MCPSessionAuthenticator`, `IntentManager`, `FlightRecorder`). None of this tests AgentMesh, a specific customer's deployment, or a custom policy engine built on top of the kernel that might behave differently.
- Nothing here has been reviewed by anyone at Microsoft or by an independent third party.
