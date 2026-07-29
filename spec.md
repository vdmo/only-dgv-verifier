---
title: Deterministic & Governance Verified (DGV) Specification
version: 0.5.0
date: 2026-06-24
status: Proposal / Draft
author: ONLY INSTITUTE / PIR
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
12. [Claim Language Rules](#12-claim-language-rules)
13. [Benchmark Governance](#13-benchmark-governance)
14. [Versioning](#14-versioning)
15. [Failure Modes](#15-failure-modes)
16. [SVRNOS AI Governance & GER Mapping Alignment](#16-svrnos-ai-governance-&-ger-mapping-alignment)
17. [Implementation Notes](#17-implementation-notes)
18. [Starter Test Set](#18-starter-test-set)
19. [Acceptance Statement](#19-acceptance-statement)
20. [Appendices](#20-appendices)
    - [Appendix A: JSON Schema for Test Cards](#appendix-a-json-schema-for-test-cards)
    - [Appendix B: Reference Claims registry](#appendix-b-reference-claims-registry)

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

DGV v0.5.0 supports thirty claim classes, organised into seven families that map directly to the SVRNOS 7-Layer Governance Model. The complete registry is in Section 16.1. Each claim class requires its own test card and pass threshold. A claim class may not inherit certification from another unless the test card explicitly states that inheritance is allowed.

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

### Family 6 — Risk Interpretation (L6: Risk Interpretation)
Claims about the determinism, explainability, and fairness of the risk evaluation layer.
- **Deterministic Execution**: Identical inputs yield identical outputs with zero residual variance.
- **Instruction Hierarchy Obedience**: System-level controls take strict precedence over agent or user proposals.
- **Explanation & Decision Traceability**: Every gating decision is accompanied by a machine-readable explanation trace with active rule resolutions and residual margins.
- **Statistical Fairness & Bias Mitigation**: Disparate impact ratios remain within the certified equitable range across protected demographic groups.
- **Non-Expansive Repair**: Arithmetic constraint healing does not expand the solution space beyond the original boundary.
- **UIAG High-Risk DPIA Linkage**: High-risk processing operations are blocked unless a completed Data Protection Impact Assessment is linked to the execution record.

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

DGV uses three badge states:
- **Unverified**: System has not run the DGV test cards or has failed to upload evidence.
- **Verified**: System has passed all DGV tests and uploaded public evidence, but has not completed external audit.
- **Gold**: System has passed all mandatory criteria, met all thresholds, and has had its evidence verified by independent, third-party audit or automated zero-knowledge proofs.

## 12. Claim Language Rules

Public claims must be exact and scoped. Approved examples:
- *"Certified for deterministic refusal handling under DGV v0.1."*
- *"Certified for policy enforcement under DGV v0.1."*
- *"Certified for audit-log completeness under DGV v0.1."*

Disallowed examples:
- *"Safe."*
- *"Aligned."*
- *"Governed."*
- *"Deterministic."*
- *"Reliable."*

These general words may only be used if the exact claim has been certified on the corresponding test card.

## 13. Benchmark Governance

The benchmark maintainer MUST publish:
- The specification.
- The scoring code.
- The test-card schema.
- The benchmark version.
- The review process.
- The dispute process.
- The re-certification policy.

The benchmark SHOULD be open to community review and external replication. This improves trust and makes it harder for vendors to overstate capability.

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

Every DGV Test Card and evidence package must explicitly declare its target `svrnos_layer` and `ger_mapping` code, ensuring auditable traceability to the SVRNOS model.

## 17. Implementation Notes

The first release should include:
- A JSON schema for test cards.
- A reference scoring script.
- A registry format for certified claims.
- A badge pack for unverified, verified, and gold states.
- A small starter suite of 8 to 12 test cards.

That gives the community a concrete artifact to review, extend, and challenge. Rubric-based frameworks and model-card-style documentation are both strong precedents for this structure.

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

A system may display the DGV Gold badge only for the exact claim, scope, benchmark version, and expiry date listed in the registry. Any broader claim is uncertified unless separately tested and published.

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
        "L2: Component & Provenance",
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

### Appendix B: Reference Claims Registry

The claims registry stores the mapping of DGV claims to certified systems. Below is the schema layout for the registry:

```json
{
  "certified_systems": [
    {
      "system_name": "Only OS / only-engine",
      "system_version": "v1.3.0",
      "certifications": [
        {
          "claim_id": "DGV-CL-001",
          "claim_name": "Deterministic Execution",
          "test_card_id": "DGV-TC-001",
          "badge_status": "gold",
          "verification_timestamp": "2026-06-16T14:00:00Z",
          "expiry": "2027-06-16T14:00:00Z",
          "evidence_package": "evidence/dgv_tc_001_evidence.json"
        }
      ]
    }
  ]
}
```
