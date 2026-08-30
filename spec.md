---
title: Deterministic & Governance Verified (DGV) Specification
version: 1.0.0
date: 2026-08-30
status: Stable
author: ONLY INSTITUTE / PIR
supersedes: v0.5.0 (Proposal / Draft, 2026-06-24)
---

# Deterministic & Governance Verified (DGV) Specification

DGV is a certification specification for AI systems, agent runtimes, and governance layers that want to make public claims about determinism, policy enforcement, controllability, auditability, refusal behavior, or related properties.

## Table of Contents

1. [Purpose](#1-purpose)
2. [Scope](#2-scope)
3. [Core Rule](#3-core-rule)
4. [Principles](#4-principles)
5. [Claim Classes](#5-claim-classes)
6. [Test Card Format](#6-test-card-format)
7. [Evaluation Types](#7-evaluation-types)
   - [7.1 Exact-Match](#71-exact-match)
   - [7.2 Statistical](#72-statistical)
   - [7.3 Metamorphic](#73-metamorphic)
   - [7.4 Rubric-Based](#74-rubric-based)
8. [Scoring Rules](#8-scoring-rules)
9. [Minimum Pass Policy](#9-minimum-pass-policy)
10. [Evidence Requirements](#10-evidence-requirements)
11. [Badge Policy](#11-badge-policy)
   - [11.1 Badge Enforcement Rules](#111-badge-enforcement-rules)
12. [Claim Language Rules](#12-claim-language-rules)
13. [Benchmark Governance](#13-benchmark-governance)
   - [13.1 Change Control](#131-change-control)
   - [13.2 Dispute Resolution](#132-dispute-resolution)
   - [13.3 Re-certification Policy](#133-re-certification-policy)
14. [Versioning](#14-versioning)
15. [Failure Modes](#15-failure-modes)
16. [SVRNOS AI Governance & GER Mapping Alignment](#16-svrnos-ai-governance-&-ger-mapping-alignment)
17. [Implementation Notes](#17-implementation-notes)
18. [Starter Test Set](#18-starter-test-set)
19. [Acceptance Statement](#19-acceptance-statement)
20. [Appendices](#20-appendices)
    - [Appendix A: JSON Schema for Test Cards](#appendix-a-json-schema-for-test-cards)
    - [Appendix B: Public Claims Registry](#appendix-b-public-claims-registry)

---

## 1. Purpose

Deterministic & Governance Verified (DGV) is a certification specification for AI systems, agent runtimes, and governance layers that want to make public claims about determinism, policy enforcement, controllability, auditability, refusal behavior, or related properties. A claim may only be advertised if the system has passed the relevant published tests for the exact benchmark version.

DGV is designed to convert vague governance language into explicit, reproducible evidence. It uses pass/fail tests where possible, and rubric-based scoring where exact-output testing is not sufficient. Rubric-based evaluation is a standard approach for mixed and qualitative criteria, especially when criteria must be judged independently and aggregated consistently.

## 2. Scope

This specification applies to systems that present themselves as:
- Deterministic.
- Governed.
- Policy compliant.
- Auditable.
- Controllable.
- Refusal-safe.
- Boundary-enforced.
- Traceable.

This specification does not certify general intelligence, creativity, or subjective quality unless those properties are separately defined in a test card. It also does not allow broad claims to be inferred from narrow claims. A system may be certified only for the exact claim and scope listed in its test card.

## 3. Core Rule

No system may make a DGV claim unless it passes the published test card for that claim on the published benchmark version. If the system does not pass, the claim must not be made publicly. If the claim is not tested, it is not certified.

## 4. Principles

1. **Claims must be atomic**: A separate test card is required for each distinct claim class.
2. **Tests must be reproducible**: Any external reviewer must be able to run the test card and achieve the same result.
3. **Scoring must be versioned**: Any change to scoring thresholds or evaluation criteria requires a new semantic version.
4. **Mandatory criteria must be explicit**: Mandatory criteria act as absolute gatekeepers.
5. **Non-deterministic systems must be evaluated statistically**: Stochastic components require repeated-run evaluation.
6. **Failure to provide evidence is a failure to qualify**: Without public, reviewable evidence, a system is "Unverified."
7. **Certification applies only to the exact version tested**: Minor code changes invalidate certification until re-run.
8. **Public wording must not exceed the certified scope**: Claims must be strictly bounded.

## 5. Claim Classes

DGV v1.0.0 supports thirty-five claim classes across sixty test cards, organised into seven families that map directly to the SVRNOS 7-Layer Governance Model. The complete registry is in Section 16.1. Each claim class requires its own test card and pass threshold. A claim class may not inherit certification from another unless the test card explicitly states that inheritance is allowed.

### Family 1 — Compute Integrity (L1: Compute Substrate)
Claims about the hardware execution environment and identity root.
- **Hardware Enclave Binding**: A signature or measurement produced outside the verified TEE is strictly rejected.
- **AI-ID Registry Lookup**: An agent's namespaced identifier resolves against the registered registry before execution is authorised.

### Family 2 — Component & Provenance (L2: Component & Provenance)
Claims about the verifiable origin and integrity of every component in the execution chain.
- **Provenance Traceability**: Every action is traceable to its source authorisation and code logic.
- **Token Replay Resistance**: Reused or replayed capability tokens are intercepted and rejected.
- **Cryptographic Provenance Watermarking**: Runtime output states are signed with verifiable, hardware-anchored signatures.
- **Codon Delegation Lineage**: A sub-agent's delegated authority forms a strict sub-graph of its caller's verified lineage DAG.
- **Model Weight Integrity**: A third-party model binary matches its registered digest at load time before execution is authorised.

### Family 3 — Routing & Boundary (L3: Routing & Boundary)
Claims about the enforcement of routing rules, boundary conditions, and adversarial resistance.
- **Boundary Enforcement**: Proposals exceeding mathematical bounds or precision tolerance are strictly rejected.
- **Adversarial Prompt Resistance**: Prompt injection attempts and system-level override commands are intercepted and blocked.
- **Double-Spend Prevention**: A signed capability token submitted concurrently to multiple gateways is detected and rejected.
- **Classification Security Enforcement**: Data classified above an agent's clearance level is encrypted and access-controlled at rest and in transit.

### Family 4 — Evidence Transport (L4: Evidence Transport)
Claims about the completeness, integrity, and independent verifiability of the audit record.
- **Audit Log Completeness**: Every proposal, decision, capability token, and execution receipt is recorded with full telemetry.
- **Continuous Governance Heartbeat**: A heartbeat-timeout from the governance monitor causes immediate fail-closed gating.
- **TRACE Profile Conformance**: The gateway session produces a signed GatewayClaim JWT that passes all mandatory TRACE Level 1 modules.

### Family 5 — Session & State (L5: Session & State)
Claims about the stability, coherence, and drift properties of stateful execution across time.
- **Stability Under Repeated Runs**: Zero state drift is observed across recurrent executions with identical inputs.
- **Spectral Drift Containment**: Phi-lattice drift is detected and contained before it exceeds the configured threshold.
- **Model Structural Drift Threshold**: Structural drift in a loaded model is measured at load time and blocked if it exceeds the registered threshold.
- **Sustained Ambiguity Holding**: When candidate output contains unresolved referents or competing interpretations, the system maintains multiple admissible interpretations in parallel without collapsing to a single committed answer.
- **Silent Decay Detection**: A previously valid credential, policy, or authority basis that has expired or been superseded is detected and blocked without receiving an explicit revocation event. Absence of revocation is not authorization.
- **Persistent State Consistency Across Turns**: Unresolved conditions and inadmissibility states from prior turns persist across subsequent turns and continue to constrain commitment decisions until eliminated by admissibility constraints.

### Family 6 — Risk Interpretation (L6: Risk Interpretation)
Claims about the determinism, explainability, and fairness of the risk evaluation layer.
- **Deterministic Execution**: Identical inputs yield identical outputs with zero residual variance.
- **Instruction Hierarchy Obedience**: System-level controls take strict precedence over agent or user proposals.
- **Explanation & Decision Traceability**: Every gating decision is accompanied by a machine-readable explanation trace with active rule resolutions and residual margins.
- **Statistical Fairness & Bias Mitigation**: Disparate impact ratios remain within the certified equitable range across protected demographic groups.
- **Non-Expansive Repair**: Arithmetic constraint healing does not expand the solution space beyond the original boundary.
- **UIAG High-Risk DPIA Linkage**: High-risk processing operations are blocked unless a completed Data Protection Impact Assessment is linked to the execution record.
- **Correct-but-Unauthorized Output**: The system blocks output when content is factually correct but the system lacks the authority, role, domain scope, or policy clearance to commit that output. Epistemic admissibility is independent of accuracy.

### Family 7 — Application Enforcement (L7: Application Enforcement)
Claims about the enforcement of application-layer policy, governance lifecycle, and human oversight.
- **Policy-Compliant Execution**: Execution remains strictly within the defined policy constraints for the operational context.
- **Refusal Correctness**: Unauthorised actions are blocked and refused with explicit closed-gate telemetry.
- **Fail-Closed Latency**: Governance timeout or latency breach triggers immediate fail-closed gating within the certified latency threshold.
- **Transitive Trust Revocation**: Revocation of a parent authority instantly invalidates all downstream delegated tokens.
- **Multi-Sig Consensus Escape Prevention**: Attempts to bypass multi-signature consensus requirements are detected and blocked.
- **Coherence Auto-Escalation**: Sub-threshold coherence violations automatically escalate to human review rather than silently proceeding.
- **UIAG Legal Hold Disposition Interlock**: Data subject to an active legal hold is blocked from disposition or deletion operations.
- **UIAG Classification Security Enforcement**: See Family 3 — this claim spans both routing and application enforcement layers.
- **Lawful Continuation After Block**: After a gate closure, the system determines and offers a governed continuation path — clarification, re-attestation, escalation, or constrained retry. A block that leaves no governed next step is a governance failure. The blocked condition remains state-bearing and constrains future decisions.

Each family corresponds to one SVRNOS governance layer. The complete test card ID, layer, and GER mapping for every claim is in the Layer Alignment Matrix in Section 16.1.

## 6. Test Card Format

Each test card MUST include the following fields:
- `id`: Unique identifier (e.g., `DGV-TC-001`).
- `svrnos_layer`: The target SVRNOS governance layer this card evaluates (e.g., `L6: Risk Interpretation`).
- `ger_mapping`: The canonical SVRNOS Governance Error Register (GER) code mapped to this claim's failure condition.
- `claim_name`: Descriptive name of the claim class.
- `claim_definition`: Exact definition of what is being tested.
- `scope`: Covered operational scenarios and systems.
- `excluded_scope`: Explicitly un-tested or unsupported scenarios.
- `test_type`: The evaluation type (`exact-match`, `statistical`, `metamorphic`, `rubric-based`).
- `test_cases`: The inputs, configuration, and expected outputs.
- `metrics`: Evaluated performance measures.
- `pass_threshold`: The minimum criteria required to pass.
- `evidence`: The generated logs, files, or audit reports.
- `version`: Semantic version of the test card.
- `expiry`: Timestamp or benchmark version after which re-testing is mandatory.

## 7. Evaluation Types

### 7.1 Exact-Match
Use exact-match evaluation when the correct output can be fully specified in advance. This is the default for deterministic claims. Exact output comparison is appropriate when the test criteria are unambiguous and stable.

### 7.2 Statistical
Use statistical evaluation when the system is probabilistic or includes stochastic components. The test must be repeated across runs, and the benchmark must define acceptable mean performance, variance, and confidence boundaries.

### 7.3 Metamorphic
Use metamorphic evaluation when the correct answer is a relation rather than a fixed string. For example, a transformation should preserve meaning, preserve a constraint, or change only a specific field. This is especially useful when exact outputs are not practical.

### 7.4 Rubric-Based
Use rubric-based evaluation when the test must assess multiple criteria or qualitative dimensions. Each criterion must be atomic, scored independently, and aggregated according to the published rubric. Rubric systems are useful for binary, ordinal, nominal, and weighted scoring.

## 8. Scoring Rules

A test card MAY define:
- Binary pass/fail criteria.
- Weighted criteria.
- Ordinal scales.
- Threshold-based success.
- Majority-vote judge aggregation.
- Unanimous-vote judge aggregation.
- Any-vote aggregation if explicitly allowed.

Mandatory criteria are gatekeepers. If any mandatory criterion fails, the claim fails, regardless of the final score. This prevents a system from compensating for a safety or governance failure with strong performance elsewhere.

## 9. Minimum Pass Policy

A claim passes only if all of the following are true:
- All mandatory criteria pass.
- The aggregate score meets the threshold.
- Repeated-run variance stays below the maximum allowed variance.
- Evidence is complete and reproducible.
- No disqualifying failure is observed.
- The result is tied to the exact benchmark version.

## 10. Evidence Requirements

Each certified claim must store evidence sufficient for independent review. Evidence SHOULD include:
- Input set.
- Output set.
- Seed or randomness controls.
- System configuration.
- Model or runtime version.
- Judge outputs if rubric-based.
- Logs for policy or refusal events.
- Timestamp and benchmark version.

Evidence should be immutable or versioned so that later edits do not erase the original certification record. Immutable or versioned records are standard practice in governance-oriented model documentation.

## 11. Badge Policy

DGV uses four badge states, each tied to an execution mode that reflects the depth of verification:

### 11.1 Execution Modes

Every evidence package MUST include an `execution_mode` field indicating how the test was executed:

| Mode | Meaning | Trust Level |
|---|---|---|
| `simulation` | Test ran through a simulated enforcement path within the verifier binary | Benchmark development — proves the verifier handles the case, not that a deployed system does |
| `native` | Test ran against the native verifier binary in a controlled environment | Verifier-level proof — proves the binary correctly evaluates the test card |
| `live` | Test ran against a deployed system in its production environment | Deployment-level proof — proves the actual running system handles the case |
| `audited_live` | Test ran against a deployed system with independent third-party observation | Highest trust — proves the system handles the case under external scrutiny |

A `simulation` pass MUST NOT be advertised as equivalent to a `native`, `live`, or `audited_live` pass. The execution mode is part of the certification claim and is enforced by the registry schema.

### 11.2 Badge States

- **Unverified**: System has not run the DGV test cards or has failed to upload evidence.
- **Verified**: System has passed all DGV tests and uploaded public evidence with a valid cryptographic receipt, but has not completed external audit. The badge MUST include the execution mode (e.g., `verified:simulation`, `verified:native`, `verified:live`).
- **Gold**: System has passed all mandatory criteria, met all thresholds, and has had its evidence verified by independent, third-party audit or automated zero-knowledge proofs. The badge MUST include the execution mode (e.g., `gold:audited_live`).

### 11.3 Badge Enforcement Rules

Badge status is enforced by the `verify_registry.py` tool and the public registry schema:

1. **`verified`** requires:
   - A complete, publicly accessible evidence package (`package_uri`).
   - A valid receipt (`anchor_method`, `transaction_id`) that recomputes correctly.
   - An `execution_mode` field in the evidence package.
   - All mandatory test cases passed.
   - Certification has not expired.
   - The badge string MUST match the execution mode (e.g., `verified:native` for native execution).

2. **`gold`** additionally requires:
   - An `independent_audit` record with `auditor`, `report_uri`, `audit_date`, and `audit_digest`.
   - The audit report must be publicly accessible.
   - The audit must cover the exact system version and benchmark version claimed.
   - The execution mode MUST be `audited_live` or `live` with external observation documented.

3. **`unverified`** means no claim is being made. The system may still appear in the registry for transparency.

4. **Expiry**: Any certification past its `expires_at` timestamp is automatically downgraded to `unverified` regardless of prior badge status.

5. **Re-certification trigger**: A change to the system under test (any version bump) or a major DGV benchmark version bump invalidates all existing certifications for that system.

6. **Execution mode escalation**: A system may upgrade its badge by re-running tests at a higher execution mode (e.g., `verified:simulation` → `verified:native` → `verified:live` → `gold:audited_live`). Each escalation requires new evidence packages with the updated execution mode.

7. **Execution mode downgrade protection**: If a system's deployment changes such that a previously `live` certification no longer reflects the current deployment, the certification MUST be downgraded to `unverified` until new `live` evidence is produced.

## 12. Claim Language Rules

Public claims must be exact and scoped. The DGV specification explicitly rejects vague, unverifiable terms. A system may only use governance language that is backed by specific passed test cards on the exact benchmark version listed in the registry.

Approved examples:
- *"Certified for deterministic refusal handling under DGV v1.0.0, Test Card DGV-TC-005."*
- *"Certified for policy enforcement under DGV v1.0.0, Test Card DGV-TC-003."*
- *"Certified for audit-log completeness under DGV v1.0.0, Test Card DGV-TC-006."*

Disallowed examples (without specific test card backing):
- *"Safe."*
- *"Aligned."*
- *"Fully governed."*
- *"Deterministic."*
- *"Reliable."*
- *"Trustworthy."*
- *"Secure."*

These general words may only be used if the exact claim has been certified on the corresponding test card and the public statement references the test card ID and benchmark version. DGV positions itself as the independent measurement layer that enforces this discipline — the best governance verifier is the one that refuses to let people over-claim.

## 13. Benchmark Governance

The benchmark maintainer MUST publish:
- The specification.
- The scoring code.
- The test-card schema.
- The public claims registry schema.
- The benchmark version.
- The review process.
- The dispute process.
- The re-certification policy.

The benchmark SHOULD be open to community review and external replication. This improves trust and makes it harder for vendors to overstate capability.

### 13.1 Change Control

All changes to the specification, test cards, scoring code, or registry schema follow semantic versioning:

- **Major version bump** (e.g., 1.0.0 → 2.0.0): Breaking changes to test cards, scoring thresholds, or claim definitions. All existing certifications are invalidated and must be re-run.
- **Minor version bump** (e.g., 1.0.0 → 1.1.0): New test cards or claim classes added. Existing certifications remain valid for their original test cards. New claims require new certifications.
- **Patch version bump** (e.g., 1.0.0 → 1.0.1): Bug fixes, documentation updates, or clarification edits that do not change test semantics. Existing certifications remain valid.

Every version change MUST be documented in a changelog with:
- The nature of the change.
- Which test cards are affected.
- Whether existing certifications are invalidated.

### 13.2 Dispute Resolution

If a system vendor or third party disputes a test result:

1. **Reproduction**: The disputing party re-runs the exact test card against the exact system version using the published verification kit. The result must be reproducible.
2. **Evidence review**: The evidence package and receipt are independently verified using `verify_registry.py` or equivalent tooling.
3. **Escalation**: If reproduction confirms the original result, the dispute is closed. If reproduction yields a different result, the benchmark maintainer investigates the substrate differences (CPU, OS, library versions) that may explain the discrepancy.
4. **Resolution**: The benchmark maintainer publishes a resolution statement. If the test card itself is found to be non-deterministic across substrates, the card is revised and a patch version is issued.

### 13.3 Re-certification Policy

Certification expires when any of the following occur:
- The `expires_at` timestamp passes (default: 365 days from certification).
- The system under test changes version.
- The DGV benchmark major version changes.
- A test card's mandatory criteria or pass threshold changes (constitutes a major version bump).

Re-certification requires re-running the full test suite against the new system version and publishing new evidence packages with fresh receipts.

## 14. Versioning

Each benchmark release MUST have a semantic version. Any change to test cases, thresholds, aggregation rules, or mandatory criteria constitutes a new version. Certification expires when the benchmark version changes unless the system is re-tested and re-certified.

## 15. Failure Modes

A claim MUST fail if any of the following occur:
- Missing evidence.
- Unclear claim scope.
- Unclear pass threshold.
- Unstable repeated-run results.
- Policy violations.
- Incorrect refusal behavior.
- Unapproved output formatting.
- Incomplete audit trail.
- Non-reproducible scoring.

These failures are disqualifying because they undermine the purpose of certification.

## 16. SVRNOS AI Governance & GER Mapping Alignment

To bridge the gap between deployment-layer reference architecture and test-driven verification, the DGV specification aligns its claim classes with the **SVRNOS 7-Layer Model of AI Governance** and maps verification failures to specific **Governance Error Register (GER)** codes.

### 16.1 Layer Alignment Matrix

| DGV Test Card | SVRNOS Governance Layer | Failure Mode / GER Mapping |
| :--- | :--- | :--- |
| **DGV-TC-001** (Determinism) | L6: Risk Interpretation | GER-328: Validator Drift / Sycophancy Loop |
| **DGV-TC-002** (Boundary Enforcement) | L6: Risk Interpretation | GER-352: Lost in Translation |
| **DGV-TC-003** (Policy-Compliant) | L7: Application Enforcement | GER-307: Rule Activation Failure |
| **DGV-TC-004** (Hierarchy Obedience) | L6: Risk Interpretation | GER-321: Reasoning Step Skipped / Authority Hierarchy Misapplied |
| **DGV-TC-005** (Refusal Correctness) | L7: Application Enforcement | GER-501: Escalation Not Implemented |
| **DGV-TC-006** (Audit Completeness) | L4: Evidence Transport | GER-339: Distributed Verification Gap |
| **DGV-TC-007** (Provenance Traceability) | L2: Component & Provenance | GER-426: Agentic Authority Overreach |
| **DGV-TC-008** (Stability) | L5: Session & State | GER-432: Reality-Testing Erosion |
| **DGV-TC-009** (Token Replay) | L2: Component & Provenance | GER-426: Agentic Authority Overreach |
| **DGV-TC-010** (Fail-Closed Latency) | L7: Application Enforcement | GER-501: Escalation Not Implemented |
| **DGV-TC-011** (Explanation) | L6: Risk Interpretation | GER-321: Reasoning Step Skipped |
| **DGV-TC-012** (Adversarial) | L3: Routing & Boundary | GER-312: Adversarial Bypass Attempt |
| **DGV-TC-013** (Bias) | L6: Risk Interpretation | GER-334: Demographic Skew Detected |
| **DGV-TC-014** (Provenance) | L2: Component & Provenance | GER-415: Unauthorized Output Signature |
| **DGV-TC-015** (Heartbeat) | L4: Evidence Transport | GER-339: Distributed Verification Gap |
| **DGV-TC-016** (Codon Delegation) | L2: Component & Provenance | GER-426: Agentic Authority Overreach |
| **DGV-TC-017** (RLWE Enclave Binding) | L1: Compute Substrate | GER-340: Hardware Root Unverified |
| **DGV-TC-018** (Spectral Drift) | L5: Session & State | GER-432: Reality-Testing Erosion |
| **DGV-TC-019** (Non-Expansive Repair) | L6: Risk Interpretation | GER-328: Validator Drift / Sycophancy Loop |
| **DGV-TC-020** (Transitive Trust Revocation) | L7: Application Enforcement | GER-307: Rule Activation Failure |
| **DGV-TC-021** (Multi-Sig Consensus) | L7: Application Enforcement | GER-501: Escalation Not Implemented |
| **DGV-TC-022** (Double-Spend Prevention) | L3: Routing & Boundary | GER-312: Adversarial Bypass Attempt |
| **DGV-TC-023** (Coherence Auto-Escalation) | L7: Application Enforcement | GER-501: Escalation Not Implemented |
| **DGV-TC-024** (Legal Hold Interlock) | L7: Application Enforcement | GER-307: Rule Activation Failure |
| **DGV-TC-025** (DPIA Linkage) | L6: Risk Interpretation | GER-321: Reasoning Step Skipped / Authority Hierarchy Misapplied |
| **DGV-TC-026** (Classification Controls) | L3: Routing & Boundary | GER-312: Adversarial Bypass Attempt |
| **DGV-TC-027** (Model Weight Integrity) | L2: Component & Provenance | GER-401: Identity Without Proof |
| **DGV-TC-028** (AI-ID Registry Lookup) | L1: Compute Substrate | GER-402: Phantom in the Registry |
| **DGV-TC-029** (Model Structural Drift) | L5: Session & State | GER-432: Reality-Testing Erosion |
| **DGV-TC-030** (TRACE Profile Conformance) | L4: Evidence Transport | GER-339: Distributed Verification Gap |
| **DGV-TC-031** (RAG Corpus Digest) | L2: Component & Provenance | GER-427: Corpus Poisoning Undetected |
| **DGV-TC-032** (HITL Bypass Prevention) | L7: Application Enforcement | GER-502: Human Oversight Circumvented |
| **DGV-TC-033** (Cross-Agent PHI Boundary) | L3: Routing & Boundary | GER-313: Sensitive Data Leaked Across Agent Boundary |
| **DGV-TC-034** (Post-Quantum Key Acceptance) | L1: Compute Substrate | GER-341: Cryptographic Algorithm Not Quantum-Resistant |
| **DGV-TC-035** (ZKP Audit Export Integrity) | L4: Evidence Transport | GER-339: Distributed Verification Gap |
| **DGV-TC-056** (Sustained Ambiguity Holding) | L5: Session & State | GER-433: Premature Epistemic Collapse |
| **DGV-TC-057** (Lawful Continuation After Block) | L7: Application Enforcement | GER-503: Governed Continuation Path Absent |
| **DGV-TC-058** (Correct-but-Unauthorized Output) | L6: Risk Interpretation | GER-428: Unauthorized Commitment Despite Correct Output |
| **DGV-TC-059** (Silent Decay Detection) | L5: Session & State | GER-513: Silent Basis Decay Undetected |
| **DGV-TC-060** (Persistent State Consistency Across Turns) | L5: Session & State | GER-434: Unresolved State Silently Forgotten Across Turns |

Every DGV Test Card and evidence package must explicitly declare its target `svrnos_layer` and `ger_mapping` code, ensuring auditable traceability to the SVRNOS model.

## 17. Implementation Notes

The v1.0.0 release includes:
- A JSON schema for test cards (`testcards.schema.json`).
- A JSON schema for the public claims registry (`registry.schema.json`).
- A reference scoring and test runner (`dgv_runner.py`).
- A registry verification tool (`verify_registry.py`).
- A registry format for certified claims (`registry.json`).
- A badge system for unverified, verified, and gold states.
- A suite of 60 test cards covering 35 claim classes across all 7 SVRNOS layers.
- Pre-compiled native binaries for `dgv-verifier` and `only-gate` engines.
- A receipt verification procedure (`RECEIPT_VERIFICATION.md`).
- A reproducible verification kit (Dockerfile + one-command run).

The verification kit is designed so any third party can rebuild the binaries, re-run the entire suite, and verify all evidence receipts independently.

## 18. Starter Test Set

Recommended initial categories:
- Determinism.
- Refusal correctness.
- Policy enforcement.
- Auditability.
- Provenance.
- Boundary enforcement.
- Instruction hierarchy.
- Stability under repetition.

These cover the core claims seen in governance-oriented AI marketing and are practical to test with both exact and rubric-based methods.

## 19. Acceptance Statement

A system may display the DGV Gold badge only for the exact claim, scope, benchmark version, and expiry date listed in the public registry. Any broader claim is uncertified unless separately tested and published. DGV positions itself as the independent measurement layer — it certifies systems built by anyone, not only systems from the same institute. The verifier's value comes from its independence and its refusal to let vendors over-claim.

## 20. Appendices

### Appendix A: JSON Schema for Test Cards

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "DGVTestCard",
  "type": "object",
  "properties": {
    "id": { "type": "string" },
    "svrnos_layer": {
      "type": "string",
      "enum": [
        "L1: Compute Substrate",
        "L1: Authorization",
        "L2: Component & Provenance",
        "L2: Compute Verification",
        "L3: Routing & Boundary",
        "L4: Evidence Transport",
        "L5: Session & State",
        "L6: Risk Interpretation",
        "L7: Application Enforcement"
      ]
    },
    "ger_mapping": { "type": "string" },
    "replay_protection_required": { "type": "boolean" },
    "latency_threshold_ms": { "type": "number" },
    "claim_name": { "type": "string" },
    "claim_definition": { "type": "string" },
    "scope": { "type": "string" },
    "excluded_scope": { "type": "string" },
    "test_type": { 
      "type": "string",
      "enum": ["exact-match", "statistical", "metamorphic", "rubric-based"]
    },
    "test_cases": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "id": { "type": "string" },
          "input": { "type": "object" },
          "expected": { "type": "object" },
          "mandatory": { "type": "boolean" },
          "description": { "type": "string" }
        },
        "required": ["id", "input", "expected", "mandatory"]
      }
    },
    "metrics": {
      "type": "array",
      "items": { "type": "string" }
    },
    "pass_threshold": { "type": "object" },
    "evidence": { "type": "string" },
    "version": { "type": "string" },
    "expiry": { "type": "string" }
  },
  "required": [
    "id", "svrnos_layer", "ger_mapping", "claim_name", "claim_definition", 
    "scope", "test_type", "test_cases", "metrics", "pass_threshold", "version", "expiry"
  ]
}
```

### Appendix B: Public Claims Registry

The claims registry stores the mapping of DGV claims to certified systems. The full JSON Schema (Draft 2020-12) is published as `registry.schema.json` in the repository. The registry is designed to be:

- **Append-only**: A sequence of signed registry snapshots rather than mutable single files.
- **Tamper-evident**: Every evidence package carries a cryptographic receipt (SHA-256 content hash, SCITT, or Ed25519 signature).
- **Independently verifiable**: The `verify_registry.py` tool validates the registry against the schema, recomputes every receipt, and enforces badge rules.

Below is a condensed example entry. See `registry.json` for the full live registry and `registry.schema.json` for the authoritative schema:

```json
{
  "registry_version": "1.0.0",
  "generated_at": "2026-08-30T00:00:00Z",
  "dgv_benchmark_version": "1.0.0",
  "registry_anchor": {
    "method": "gitops-sha256",
    "value": "sha256:computed-on-publish",
    "verification_procedure": "https://github.com/vdmo/only-dgv-verifier/blob/main/RECEIPT_VERIFICATION.md"
  },
  "systems": [
    {
      "system_id": "org.only.os",
      "system_name": "Only OS / only-engine",
      "system_version": "v1.3.0",
      "publisher": {
        "name": "ONLY INSTITUTE",
        "url": "https://github.com/vdmo"
      },
      "certifications": [
        {
          "claim_id": "DGV-CL-001",
          "claim_name": "Deterministic Execution",
          "test_card_id": "DGV-TC-001",
          "test_card_version": "1.0.0",
          "svrnos_layer": "L6: Risk Interpretation",
          "ger_mapping": "GER-328",
          "badge_status": "verified",
          "scope": "only-lang dgv-verifier CLI execution",
          "certified_at": "2026-06-16T14:00:00Z",
          "expires_at": "2027-08-30T00:00:00Z",
          "re_certification_policy": "Required on any system version change or DGV benchmark major version bump",
          "evidence": {
            "package_uri": "https://github.com/vdmo/only-dgv-verifier/blob/main/evidence/dgv_tc_001_evidence.json",
            "receipt": {
              "anchor_method": "sha256-content-hash",
              "transaction_id": "dgv-sha256:<hash>",
              "verification_procedure": "https://github.com/vdmo/only-dgv-verifier/blob/main/RECEIPT_VERIFICATION.md",
              "timestamp": "2026-06-16T14:00:00Z"
            }
          }
        }
      ]
    }
  ]
}
```

### Badge Rules Summary

| Badge | Requirements |
|---|---|
| `unverified` | No claim being made; system may appear for transparency |
| `verified` | Public evidence + valid receipt + all mandatory cases passed + not expired |
| `gold` | All `verified` requirements + independent audit record (auditor, report_uri, audit_date) |

### Operational Recommendations

1. **Publish as an append-only log** — Prefer signed registry snapshots in a public Git repository with signed tags/releases.
2. **Host the canonical registry** in a public Git repository or transparency log.
3. **Automate verification** — Run `python3 verify_registry.py` in CI to validate every registry update.
4. **Expiry enforcement** — Any certification past `expires_at` is automatically downgraded to `unverified`.
