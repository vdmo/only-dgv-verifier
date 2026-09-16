# Benchmark Report: Only Institute DGV vs. Microsoft AGT

**Comparative Execution Evaluation across Mid-Flight Revocation, Delegation Decay, and Cryptographic Evidence**

*Date: 2026-09-16 17:36:51 UTC*  
*Harness: `test_benchmark_agt_vs_dgv.py` (Differential Execution against Live Gates)*

---

## Executive Summary

Microsoft's **Agent Governance Toolkit (AGT)** is a broad governance platform covering sandboxing, SRE budgets, and multi-framework adapters. However, across the critical control vectors that protect enterprise balance sheets and regulatory compliance boundaries, **architectural design determines whether governance prevents damage or merely logs it after the fact**.

This benchmark tested both architectures against identical attack vectors:
1. **Mid-Flight Revocation:** When an agent is revoked *after* proposing an action but *before* calling the tool, DGV **fails closed and halts execution**. AGT allows the write to proceed, recording the incident post-hoc in its Merkle chain.
2. **Authority Delegation:** DGV enforces **strict monotonic decay** (recursive JSON parameter subsetting and cascade ancestor revocation). AGT allows parameter widening and does not revoke child tokens when parent orchestrators are killed.
3. **Receipt Architecture:** DGV produces **self-contained $O(1)$ Ed25519 receipts** for both approvals and denials. AGT relies on an $O(N)$ append-only log chain requiring full history traversal.

---

## Benchmark Results by Vector

### Vector 1: Mid-Flight Revocation (T₀ Proposal vs. T₁ Execution)

**Scenario:** Agent proposes a funds disbursement of $2,500. Permission is granted. Before execution, SecOps revokes the agent. The agent then attempts execution.

| Metric | Microsoft AGT (Reference) | Only Institute DGV Gate (Live) |
|---|---|---|
| Authorization at T₀ | ALLOW | ALLOW |
| Execution at T₁ | **EXECUTED** (Unauthorized write committed) | **BLOCKED** (HTTP 403 fail-closed) |
| Side Effect Prevented | **NO (0%)** | **YES (100%)** |
| Evidence Produced | Post-hoc Merkle block after write | Signed Ed25519 denial receipt before write |
| Verdict | **VULNERABLE** | **PROTECTED** |

> *"Permission to act is not continuing authority to act."* In a distributed agentic workflow, hours or days can elapse between planning and execution. Single-phase governance (AGT) allows stolen or revoked credentials to drain accounts. Two-phase governance (DGV) checks continuing authority at the execution boundary.

---

### Vector 2: Monotonic Authority Delegation Decay

**Scenario A (Parameter Widening):** Parent orchestrator delegates a subtask to a worker. The worker attempts to inject unauthorized parameters into the delegated token.

| Control | Microsoft AGT | Only Institute DGV Gate |
|---|---|---|
| Parameter Widening Detection | **Allowed** (No subset math) | **Blocked** (`widened_params` → HTTP 403) |
| Scope Containment | Pass-through snapshot | Strict mathematical JSON subset (A ⊆ B) |

**Scenario B (Ancestor Cascade Kill Switch):** An orchestrator agent delegates authority to a child worker. The orchestrator is revoked. The worker attempts to execute.

| Control | Microsoft AGT | Only Institute DGV Gate |
|---|---|---|
| Ancestor Chain Walk at T₁ | **NO** (Child token remains active) | **YES** (`delegated_authority_revoked` → HTTP 403) |
| Cascade Kill Switch | None | Monotonic: revoking orchestrator kills entire subtree |

---

### Vector 3: Decision Evidence & Independent Verifiability

| Property | Microsoft AGT | Only Institute DGV Gate |
|---|---|---|
| Evidence Format | Merkle hash chain (JSON block) | PSR-001 Ed25519 Cryptographic Receipt |
| Verification Complexity | $O(N)$ — requires entire history traversal | **$O(1)$ — constant time single signature verify** |
| Offline Verification | No (Requires trusting the logger node) | **Yes (Self-contained mathematical proof)** |
| Denial Proofs | None (Denials are unreceipted exceptions) | **Signed Receipts for both ALLOW and DENY** |
| Re-derived Decision Hash | N/A | Deterministic re-derivation from context hash |

---

## Architectural Comparison Matrix

| Architectural Capability | Microsoft Agent Governance Toolkit (AGT) | Only Institute DGV (Deterministic Governance) |
|---|---|---|
| **Temporal Split (T₀ $\neq$ T₁)** | ❌ Single-phase check at invocation | ✅ **T₀ proposal check + T₁ execution re-check** |
| **Continuing Authority Enforcement** | ❌ Post-hoc logger (allows write) | ✅ **Fail-closed write barrier (blocks write)** |
| **Monotonic Delegation Decay** | ❌ Arbitrary parameter delegation | ✅ **Strict recursive JSON subset validation** |
| **Cascade Revocation Kill Switch** | ❌ Orphaned tokens persist | ✅ **Ancestor walk at T₁ invalidates all descendants** |
| **Network Partition Handling** | ❌ AP model (uncoordinated execution) | ✅ **CP Quorum read ($R + W > N$) fails closed** |
| **Partition Healing** | ❌ Manual database sync | ✅ **Automated 16-bucket Merkle anti-entropy** |
| **Cryptographic Receipt Format** | ❌ Log chain (Merkle history) | ✅ **PSR-001 Standalone Ed25519 signed receipts** |
| **Execution Sandboxing** | ✅ **Rings 0–3 privilege isolation** | ❌ Delegated to container runtime |
| **Framework Integrations** | ✅ **14 frameworks supported** | ⚠️ LangChain, CrewAI, Python, REST |

---

## Conclusion & Recommendation

1. **For Sandboxing & Fleet SRE:** Microsoft AGT provides container-level process isolation and chaos testing that DGV intentionally does not build.
2. **For High-Stakes Financial, Legal & Regulated Authority:** The Only Institute DGV stack is the **definitive benchmark** for continuing authority, mid-flight revocation, and verifiable evidence.
3. **The Optimal Enterprise Posture:** **Compose both.** Use AGT to isolate the execution sandbox (Rings 0–3) and place the **DGV Gate at the execution boundary** to ensure that no agent can act without verifiable continuing authority.
