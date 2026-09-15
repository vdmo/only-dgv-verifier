# DGV Trust Root

## The Problem

A certification verifier that is itself opaque cannot fully earn trust. If the verifier's internals are hidden, every piece of evidence it produces inherits that opacity. This document explains how DGV resolves this tension between **intellectual property protection** and **verifiable trust**.

---

## What Is Public

The following components are fully open and independently verifiable:

| Component | Status | Verification Method |
|---|---|---|
| **DGV Specification** (`spec.md`) | Public, MIT licensed | Read it. Challenge it. Implement your own verifier against it. |
| **Test Cards** (89 cards, JSON) | Public | Schema-validated, human-readable, machine-executable |
| **Evidence Format** (JSON) | Public | Schema-validated, receipt-hashable, independently re-computable |
| **Registry Schema** (`registry.schema.json`) | Public | JSON Schema Draft 2020-12, validates with any compliant validator |
| **Public Registry** (`registry.json`) | Public | Append-only, every entry independently verifiable |
| **Receipt Verification** (`verify_receipt.py`) | Public, MIT licensed | Recomputes SHA-256 hashes, validates schema, enforces badge rules |
| **Reproducibility Kit** (`Dockerfile`) | Public | One-command verification of all test cards |
| **Test Card Schema** (`testcards.schema.json`) | Public | JSON Schema for test card validation |
| **Native Verifier Source** (`native/`) | Public | Rust source for dgv-verifier, only-gate, only-lang, only-core, only-evolution, only-memory |
| **Audit Package** (`AUDIT_PACKAGE.md`) | Public | Everything an independent auditor needs to review the verifier |

Anyone can:
1. Read the specification and challenge any test card
2. Build the native binaries from source (`cd native && cargo build --release`)
3. Run the Docker container and execute all test cards
4. Verify every receipt hash independently
5. Run the differential test (`python differential_test.py`)
6. Review the Rust source for the math core and simulate-case handler
7. Validate the registry against the schema
8. Check badge enforcement rules
9. Inspect every evidence package in full

## What Is Not Public

Nothing. The native verifier source is now published in `native/`. The previous NDA-gated review paths are no longer necessary.

## What the Native Binary Implements vs Simulates

**Critical for any reviewer:** The native binary has two modes:

1. **Math core (computed):** `harmony`, `evolve`, `data`, `residual`, `corrupt` — real computation in Rust
2. **Simulate-case (hard-coded):** `--simulate-case=TC-XXX` returns pre-programmed JSON for each test card

The governance checks described in test cards TC-006 through TC-069 are **simulated**, not computed. The binary returns the expected JSON response when asked to simulate a specific case, but does not actually implement the governance logic (token replay detection, revocation, fairness, etc.).

See `AUDIT_PACKAGE.md` for the full claims matrix and differential test results.

---

## How Trust Is Established Without Source

DGV establishes trust through a **defense-in-depth** approach with four layers:

### Layer 1: Deterministic Execution

The verifier binaries are deterministic. Given the same test card and the same binary, the output is always identical. This means:

- Anyone can run the binary and get the same result
- Results are reproducible across machines, OS versions, and timestamps
- The binary's behavior is fully specified by its inputs and outputs

**Verification:** Run `python3 dgv_runner.py` on any machine. Compare your evidence hashes against the published registry. They will match.

### Layer 2: Binary Provenance

Every release includes:

- **SHA-256 checksums** of both binaries (`dgv-verifier`, `only-gate`)
- **Build environment documentation** (Rust toolchain version, target triple, dependency versions)
- **Release signatures** (GPG or sigstore, planned for v0.2.0)
- **SLSA-lite provenance** (build level, build environment, source hash)

See `BUILD_PROVENANCE.md` for the current build chain documentation.

**Verification:** Compute `sha256sum bin/dgv-verifier` and compare against the published checksum. If they match, you have the exact binary that produced the published evidence.

### Layer 3: Execution Mode Transparency

Every evidence package now includes an `execution_mode` field that explicitly states how the test was run:

| Mode | Meaning | Trust Level |
|---|---|---|
| `simulation` | Test ran through a simulated enforcement path | **Benchmark development only** — cannot be advertised as production enforcement |
| `native` | Test ran against the native verifier binary in a controlled environment | **Verifier-level proof** — proves the binary handles the case correctly |
| `live` | Test ran against a deployed system in its production environment | **Deployment-level proof** — proves the actual running system handles the case |
| `audited_live` | Test ran against a deployed system with independent third-party observation | **Highest trust** — proves the system handles the case under external scrutiny |

**This separation is enforced by the registry schema.** A `simulation` pass cannot be displayed as a `native` pass. The badge system reflects the execution mode (see Section 11 of the specification).

**Verification:** Check the `execution_mode` field in any evidence package. If it says `simulation`, you know the test was not run against a live system.

### Layer 4: Open Source Review

The native verifier source is now published in `native/`. Any party can review the source without an NDA. See `AUDIT_PACKAGE.md` for the recommended review scope.

For a formal attestation (signed audit report published in the registry), contact `trust@only.institute`.

Reviews are typically scheduled within 2-4 weeks of NDA execution.

---

## The Full Trust Chain

```
Specification (public)
    ↓ defines
Test Cards (public, schema-validated)
    ↓ executed by
Verifier Binary (checksummed, GPG-signed, deterministic)
    ↓ produces
Evidence Package (public, includes execution_mode + binary_checksum + build_provenance)
    ↓ hashed by
SHA-256 Receipt (public, independently recomputable, covers binary_checksum)
    ↓ recorded in
Public Registry (schema-validated, append-only, cross-validated)
    ↓ validated by
verify_registry.py (public, MIT licensed, cross-validates test cards ↔ evidence ↔ checksums)
    ↓ optionally upgraded by
Independent Audit (NDA-gated, attestation published with audit_digest)
```

Every arrow is verifiable. The execution chain is now closed: each evidence package records which binary produced it (via `binary_checksum`), and the receipt hash covers that field. This means you can verify that a specific binary (matching a specific checksum in `CHECKSUMS.txt`) produced a specific evidence package. The only opaque box is the verifier binary's source code, and its outputs are deterministic, checksummed, GPG-signed, and independently reproducible.

---

## Limitations and Honest Disclosure

### What this model does NOT prove

1. **The binary contains no bugs.** Source review (NDA path) reduces this risk but cannot eliminate it. The deterministic execution model ensures that any bug is reproducible and detectable. Negative/mutation/replay test cards (TC-061 through TC-069) provide additional assurance that the verifier correctly rejects invalid inputs.

2. **The binary matches a specific source version.** Without reproducible builds from public source, we cannot prove the binary was compiled from a specific source commit. The NDA-gated review path (including build verification under NDA) addresses this for parties that require it.

3. **The PIR mathematics are correct.** The mathematical foundations of PIR are published separately in academic papers. The verifier implements these constructions, but the correctness of the mathematics themselves is a separate question.

### What this model DOES prove

1. **The binary is deterministic.** Same input → same output, every time, on every machine.
2. **The evidence is authentic.** Receipt hashes match, evidence packages are complete, and the registry is consistent.
3. **The execution chain is closed.** Each evidence package includes `binary_checksum` (SHA-256 of the verifier binary) and `build_provenance`. The receipt hash covers these fields. You can verify that a specific binary produced a specific evidence package.
4. **The execution mode is transparent.** You know exactly whether a test was simulated, native, live, or audited.
5. **The test coverage is public.** All 69 test cards (60 positive + 9 negative/mutation/replay) are visible and challengeable.
6. **The badge claims are enforced.** The registry schema prevents over-claiming, and `verify_registry.py` cross-validates test cards against evidence.
7. **The binaries are signed.** GPG-signed checksums (Ed25519) allow independent verification that the binaries have not been tampered with.

---

## Roadmap

| Version | Feature | Status |
|---|---|---|
| v0.1.0 | Binary checksums, execution_mode field, badge separation | Done |
| v0.2.0 | GPG-signed releases (Ed25519), SLSA Level 2, binary_checksum in evidence, execution chain closed, negative/mutation/replay tests, cross-validation | **This release** |
| v0.3.0 | Reproducible build from source (NDA-gated build verification), SLSA Level 3 | Planned |
| v1.0.0 | Full source publication after IP protection finalized | Future |

---

## Contact

For NDA-gated review requests, security disclosures, or trust model questions:

- **Email:** trust@only.institute
- **Security:** security@only.institute (PGP key published on request)
- **Repository:** https://github.com/vdmo/only-dgv-verifier
