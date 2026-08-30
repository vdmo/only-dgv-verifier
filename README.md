# only-dgv-verifier

**Deterministic & Governance Verified (DGV) — v1.0.0**

**Author:** [vdmo](https://github.com/vdmo)

A certification specification and verification suite for AI systems, agent runtimes, and governance layers that want to make public claims about determinism, policy enforcement, controllability, auditability, refusal behavior, or related properties.

DGV converts vague governance language into explicit, reproducible evidence. It uses pass/fail tests where possible, and rubric-based scoring where exact-output testing is not sufficient. A claim may only be advertised if the system has passed the relevant published tests for the exact benchmark version.

---

## What's In This Repository

| Component | Description |
|---|---|
| `dgv-verifier` | Native Rust engine — evaluates state, mathematical scripts, and governance constraints. Generates verifiable JSON receipts with provenance signatures, explanation traces, and audit logs. |
| `only-gate` | Native Rust engine — validates hardware/crypto constraints: ML-KEM-768 post-quantum key encapsulation, SHAKE-256 conformance, GPU TEE attestation, basis-freshness checks. |
| `test_cards/` | 65 test cards (60 positive + 5 negative/adversarial) covering 35 claim classes across all 7 SVRNOS governance layers. |
| `evidence/` | Cryptographic evidence packages with SHA-256 content-hash receipts for every test card. Each includes an `execution_mode` field (simulation, native, live, or audited_live). |
| `dgv_runner.py` | Test runner — executes all cards against the native engines and generates evidence with execution mode metadata. |
| `verify_registry.py` | Registry verifier — validates the public claims registry, recomputes receipts, enforces badge rules, checks cross-consistency. |
| `registry.json` | Public claims registry — append-only record of certified systems and their claims with execution-mode-qualified badges. |
| `registry.schema.json` | JSON Schema (Draft 2020-12) for the public claims registry, including execution_mode and audit metadata. |
| `spec.md` | The DGV Specification v1.0.0 — stable standard with change control, dispute resolution, badge enforcement, and execution mode separation. |
| `TRUST_ROOT.md` | Trust model documentation — explains binary-only distribution rationale, NDA-gated source review paths, and the full trust chain. |
| `BUILD_PROVENANCE.md` | Build chain documentation — toolchain, dependencies, checksums, SLSA provenance level. |
| `CHECKSUMS.txt` | SHA-256 checksums for verifier binaries. |
| `RECEIPT_VERIFICATION.md` | Procedure for independently verifying evidence receipts. |

---

## Quick Start

### Prerequisites

- Python 3.8+
- Pre-compiled binaries are included in `/bin` (no build required)

### Run the Full Suite

```bash
python3 dgv_runner.py
```

This executes all 60 test cards against the native engines and generates fresh evidence packages in `/evidence/`.

### Check Results

```bash
python3 check_passes.py
```

### Verify the Public Registry

```bash
pip install jsonschema
python3 verify_registry.py
```

This validates `registry.json` against the schema, recomputes every SHA-256 receipt, and enforces badge rules.

### Run a Single Card

```bash
python3 dgv_runner.py --card DGV-TC-001
python3 dgv_runner.py --case DGV-TC-001-01
```

### Dry Run (List Cards Without Executing)

```bash
python3 dgv_runner.py --dry-run
```

---

## Docker (One-Command Verification)

```bash
docker build -t dgv-verifier .
docker run --rm dgv-verifier
```

This runs the full 60-card suite in a reproducible container and prints the pass/fail summary. See `Dockerfile` for substrate details.

---

## Architecture

```
  Test Cards (60 JSON files)
      │
      ▼
  dgv_runner.py (Python harness)
      │
      ├──▶ dgv-verifier (Rust) ──▶ JSON receipts
      │    Core engine: equilibrium math, scripts, governance
      │
      └──▶ only-gate (Rust) ────▶ JSON receipts
           Hardware/crypto: PQ keys, TEE attestation, freshness
      │
      ▼
  Evidence Packages (JSON + SHA-256 receipts)
      │
      ▼
  registry.json (Public Claims Registry)
      │
      ▼
  verify_registry.py (Independent verification)
```

### Two-Engine Design

1. **`dgv-verifier`** — The core engine. Evaluates mathematical scripts via `only-lang`, checks arithmetic equilibrium (Σ sᵢvᵢ = 0), intercepts unapproved commands, and generates verifiable JSON payloads with provenance signatures, explanation traces, and audit logs.

2. **`only-gate`** — The hardware/crypto engine. Validates real-world constraints: ML-KEM-768 post-quantum key encapsulation, SHAKE-256 conformance, GPU TEE attestation reports, and basis-freshness checks for silent decay detection.

Pre-compiled release binaries for both engines are in `/bin`. This allows running the entire verification suite without building the Rust source code.

---

## The 65 Test Cards

The suite covers 35 claim classes organized into 7 families mapped to the SVRNOS 7-Layer Governance Model, plus 5 negative/adversarial test cards that prove the verifier correctly detects and rejects violations:

| Family | SVRNOS Layer | Cards | Key Claims |
|---|---|---|---|
| Compute Integrity | L1: Compute Substrate | TC-017, 028, 034 | Hardware enclave binding, AI-ID registry, PQ key acceptance |
| Component & Provenance | L2: Component & Provenance | TC-007, 009, 014, 016, 027, 031 | Provenance, token replay, watermarking, delegation, weight integrity, RAG corpus |
| Routing & Boundary | L3: Routing & Boundary | TC-012, 022, 026, 033 | Adversarial resistance, double-spend, classification, PHI boundary |
| Evidence Transport | L4: Evidence Transport | TC-006, 015, 030, 035 | Audit completeness, heartbeat, TRACE conformance, ZKP export |
| Session & State | L5: Session & State | TC-008, 018, 029, 056, 059, 060 | Stability, spectral drift, model drift, sustained ambiguity, silent decay, persistent state |
| Risk Interpretation | L6: Risk Interpretation | TC-001, 002, 004, 011, 013, 019, 025, 058 | Determinism, boundary, hierarchy, explanation, bias, repair, DPIA, correct-but-unauthorized |
| Application Enforcement | L7: Application Enforcement | TC-003, 005, 010, 020, 021, 023, 024, 032, 057 | Policy, refusal, latency, revocation, multi-sig, escalation, legal hold, HITL, lawful continuation |
| **Negative Tests** | Multiple | **TC-061, 062, 063, 064, 065** | Non-determinism detection, policy bypass detection, provenance forgery detection, receipt tampering detection, adversarial input rejection |

See `spec.md` Section 16.1 for the complete Layer Alignment Matrix with GER mappings.

---

## Badge System

Badges now include execution mode to prevent confusion between simulated, native, live, and audited verification:

| Badge | Meaning | Requirements |
|---|---|---|
| **Unverified** | No claim being made | System may appear in registry for transparency |
| **Verified:simulation** | Simulated enforcement pass | All mandatory cases passed in simulation mode + valid receipt |
| **Verified:native** | Verifier binary pass | All mandatory cases passed against native binary + valid receipt |
| **Verified:live** | Deployed system pass | All mandatory cases passed against production system + valid receipt |
| **Gold:audited_live** | Independently audited | All verified requirements + independent audit record with NDA-gated source review |

A `simulation` pass cannot be advertised as equivalent to a `native` or `live` pass. Badge rules are enforced by `verify_registry.py`. Any certification past its `expires_at` timestamp is automatically downgraded to `unverified`.

---

## Trust Model

The verifier engines are distributed as precompiled binaries. The source code is not public due to IP protection (PIR algorithms, patent-pending work). Trust is established through:

1. **Deterministic execution** — same input always produces same output
2. **Binary provenance** — SHA-256 checksums, build documentation (see `BUILD_PROVENANCE.md`)
3. **Execution mode transparency** — every evidence package states how the test was run
4. **NDA-gated source review** — third parties can review source under NDA and issue attestations

For the full trust model, including NDA review paths (Attestation Review and Sandbox Review), see [`TRUST_ROOT.md`](TRUST_ROOT.md).

For NDA-gated review requests: **trust@only.institute**

---

## Claim Language Rules

DGV explicitly rejects vague terms. A system may only use governance language backed by specific passed test cards.

**Approved:**
- *"Certified for deterministic refusal handling under DGV v1.0.0, Test Card DGV-TC-005."*

**Disallowed (without specific test card backing):**
- *"Safe."* / *"Aligned."* / *"Fully governed."* / *"Deterministic."* / *"Trustworthy."*

See `spec.md` Section 12 for the full rules.

---

## Regulatory Mappings

DGV test cards map to real-world regulatory frameworks:

| Framework | Relevant Test Cards | Mapping |
|---|---|---|
| **EU AI Act** (high-risk requirements) | TC-024, 025, 032 | Legal hold interlock, DPIA linkage, human oversight |
| **NIST AI RMF** (risk management) | TC-001, 003, 005, 011 | Determinism, policy compliance, refusal, explainability |
| **TRACE Profile** | TC-030 | GatewayClaim JWT conformance with mandatory modules |
| **ISO 42001** (AI management) | TC-006, 007, 014 | Audit completeness, provenance, cryptographic watermarking |
| **21 CFR Part 11** (GxP) | TC-006, 014, 030 | Audit trails, electronic signatures, traceability |
| **GDPR** | TC-024, 025, 033 | Legal hold, DPIA, cross-agent PHI boundary |

See `spec.md` Section 16 for the complete SVRNOS/GER alignment matrix.

---

## CI/CD Integration

### GitHub Actions

```yaml
name: DGV Verification
on: [push, pull_request]
jobs:
  dgv:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.10'
      - run: pip install jsonschema
      - run: python3 dgv_runner.py
      - run: python3 verify_registry.py
      - uses: actions/upload-artifact@v4
        with:
          name: dgv-evidence
          path: evidence/
```

### Pre-Commit Hook

```bash
#!/bin/bash
python3 dgv_runner.py --card DGV-TC-001 && python3 dgv_runner.py --card DGV-TC-005
```

---

## Independent Verification

Any third party can verify the results:

1. **Reproduce**: Clone this repo and run `python3 dgv_runner.py` — the same 60 cards must pass.
2. **Verify receipts**: Run `python3 verify_registry.py` — every SHA-256 receipt must recompute correctly.
3. **Check the spec**: Read `spec.md` to understand what each claim means and what passing requires.
4. **Inspect evidence**: Each file in `evidence/` contains the full test input, output, and cryptographic receipt.

See `RECEIPT_VERIFICATION.md` for the detailed receipt verification procedure.

---

## LLM Prompt Testing

Test Card 012 evaluates adversarial prompt injection resistance against a live LLM using the official `openai` SDK.

```bash
OPENAI_API_KEY="sk-proj-YOUR_KEY_HERE" python3 dgv_llm_runner.py
```

---

## Repository Structure

```
only-dgv-verifier/
├── bin/                    # Pre-compiled native binaries
│   ├── dgv-verifier
│   └── only-gate
├── test_cards/             # 60 JSON test cards
├── evidence/               # Cryptographic evidence packages
├── registry.json           # Public claims registry
├── registry.schema.json    # Registry JSON Schema (Draft 2020-12)
├── verify_registry.py      # Registry verification tool
├── dgv_runner.py           # Test runner
├── dgv_llm_runner.py       # LLM prompt injection test runner
├── check_passes.py         # Results summary
├── spec.md                 # DGV Specification v1.0.0
├── RECEIPT_VERIFICATION.md # Receipt verification procedure
├── testcards.schema.json   # Test card JSON Schema
├── Dockerfile              # Reproducible verification container
├── requirements.txt        # Python dependencies
└── release/                # Release packaging
```

---

## Author

This project was authored by vdmo.

---

## Versioning

This repository follows the DGV benchmark version (currently v1.0.0). See `spec.md` Section 13.1 for the change control policy and Section 14 for versioning rules.

---

## License

See repository for license details.
