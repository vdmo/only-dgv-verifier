# only-dgv-verifier

**Deterministic & Governance Verified (DGV)** — a specification, a test-card suite, and a reference authorization gate for AI agents.

Author: [vdmo](https://github.com/vdmo)

DGV turns vague governance claims ("deterministic", "revocable", "auditable") into specific, reproducible checks. A system may only advertise a claim if it passed the published test card for that claim, at that benchmark version, in a stated execution mode.

The design rule throughout: **an untrusted proposer (an AI agent) plus a deterministic checker.** The checker's decisions are signed, hash-chained, and replayable. Where a property is machine-checked, this repo says so; where it is only tested, it says that too.

---

## What is here

| Part | Location | What it is |
|---|---|---|
| Specification | `spec.md`, `TRUST_ROOT.md`, `BUILD_PROVENANCE.md` | The DGV spec, trust model, and build provenance. |
| Test cards | `test_cards/` | 89 cards (`DGV-TC-001` to `089`) across claim families, plus negative, mutation and replay cards. |
| Runner and evidence | `dgv_runner.py`, `evidence/`, `check_passes.py` | Runs the cards against the native engines and writes receipts with SHA-256 hashes. |
| Registry | `registry.json`, `verify_registry.py` | Public claims registry with badge rules, recomputed and checked by the verifier. |
| Verifier binaries | `bin/` | Pre-compiled `dgv-verifier` and `only-gate`; checksums are GPG-signed (`CHECKSUMS.txt.sig`). |
| **dgv-gate** | `native/dgv-gate` | Rust authorization gate: signed decisions, tokens, revocation with quorum, delegation, A2A envelopes. Source is in this repo. |
| Cores | `native/only-quorum-core`, `native/only-delegation-core` | Small `no_std`, integer-only decision functions extracted from the gate so they can be proved. |
| Formal work | `formal/tla`, `formal/alloy`, `formal/lean` | TLA+/Alloy models and Lean 4 proofs. See `formal/lean/README.md`. |
| Gate test suites | `test_gate*.py`, `test_delegation*.py`, `test_revocation*.py`, `test_*quorum*.py`, ... | End-to-end tests that start real gate processes. |
| Local experiments | `docs/EXPERIMENTS.md` | Objective-contract and revocation experiments (synthetic, local). |

---

## Quick start

Python 3.10+ and the pre-built binaries in `bin/` are enough to run the card suite.

```bash
python3 dgv_runner.py --dry-run     # list cards
python3 dgv_runner.py               # run all cards, write evidence/
python3 check_passes.py             # summarize results
pip install jsonschema
python3 verify_registry.py          # validate registry, recompute receipts
```

One card or case:

```bash
python3 dgv_runner.py --card DGV-TC-001
python3 dgv_runner.py --case DGV-TC-001-01
```

Reproducible container:

```bash
docker build -t dgv-verifier .
docker run --rm dgv-verifier
```

### Building and testing the Rust gate

Requires a Rust toolchain; Postgres is needed only for the concurrent multi-instance test.

```bash
cd native
cargo test -p only-quorum-core -p only-delegation-core -p dgv-gate
cargo build --release -p dgv-gate
```

The gate's end-to-end suites are Python scripts at the repo root (for example `python3 test_delegation_adversarial.py`, `python3 test_revocation_quorum.py`). They start gate processes on local ports. Some older scripts hard-code the author's checkout path and need it adjusted. A workspace-wide `cargo test` can fail on the optional `dgv-python` crate if your Python is newer than PyO3 supports; test the packages above directly.

---

## What is proved, and what is only tested

This section is the honest status of the strongest claims.

**Machine-checked in Lean 4 (via Charon and Aeneas, standard axioms only, no `sorry`):**
- The real Rust quorum `decide` function, for any number of votes and any quorum size: exact output, and "a confirmed-clean answer implies no vote was revoked."
- A refinement from that function to the TLA+ `QuorumSaysClean` / `QuorumSaysRevoked` predicates for any node set, and the TLA+ safety invariants over all reachable states for any cluster size.
- The delegation depth and expiry rules for all i64 inputs: no overflow, depth never exceeds the maximum, a child's expiry never exceeds its parent's, and chains cannot grow past the bound.

**Modelled, not proved about the Rust:** delegation scope narrowing (`json_subset`) is a hand-written Lean model proved reflexive and transitive. A differential test compares the gate's real function against a transcription of the model on random inputs. That is agreement on tested inputs, not a proof.

**Tested only:** signatures, nonces, freshness and key checks, storage atomicity, networking, gossip liveness, receipts, and everything in the card suite.

**Not covered:** Ed25519 and SHA-256 security (assumed), partitions where a revocation sits only on unreachable nodes (the `NoRevAnywhereAtExec` property fails there by design, and the gate fails closed or defers instead), and properties with no formal model in the repo. The full list is in `formal/lean/README.md`.

A passing card or a proof about one function does not make a whole system safe. Claims should be quoted narrowly, as in the claim rules below.

---

## Test cards and badges

Cards are grouped by claim family (compute integrity, provenance, routing and boundary, evidence transport, session and state, risk interpretation, application enforcement) with additional negative, mutation, replay, delegation, revocation and receipt cards. Each card defines inputs, expected outputs and the evidence required. `spec.md` Section 16 holds the layer alignment matrix.

Badges carry the execution mode so simulated, native, live and audited passes are never confused:

| Badge | Meaning |
|---|---|
| Unverified | No claim is being made. |
| Verified:simulation | All mandatory cases passed in simulation, with a valid receipt. |
| Verified:native | Passed against the native verifier binary. |
| Verified:live | Passed against a deployed system. |
| Gold:audited_live | Verified, plus an independent audit record with NDA-gated source review. |

`verify_registry.py` enforces the badge rules, and expired certifications are downgraded automatically.

### Claim language

Approved: *"Certified for deterministic refusal handling under DGV v1.0.0, Test Card DGV-TC-005."*
Not allowed without a specific passing card: "safe", "aligned", "fully governed", "deterministic", "trustworthy". See `spec.md` Section 12.

---

## Trust model

`dgv-verifier` and `only-gate` are distributed as pre-compiled binaries; their source is not public. Trust rests on deterministic execution, signed checksums and build provenance (`BUILD_PROVENANCE.md`), a `binary_checksum` recorded in every evidence package, execution-mode labels, and optional NDA-gated source review. Details are in [`TRUST_ROOT.md`](TRUST_ROOT.md). NDA review requests: trust@only.institute.

The `dgv-gate` source is in `native/` of this repository (see `native/LICENSE` for terms) and is the code the Lean work extracts from.

---

## Independent verification

1. Run `python3 dgv_runner.py`; the cards must pass.
2. Run `python3 verify_registry.py`; every receipt must recompute.
3. Follow `RECEIPT_VERIFICATION.md` to check a receipt by hand, or use `verify_receipt.py` and `scripts/verify_decision_chain.py` for gate decision chains. Decision hashes use RFC 8785 canonical JSON; integers above 2^53 are encoded exactly (tagged) so distinct values never share a hash, and shared vectors are in `scripts/decision_hash_vectors.json`.
4. To check the proofs, see `formal/lean/README.md`. The Lean project currently needs a local Aeneas checkout (`formal/lean/lakefile.lean` has an absolute path to adjust).

---

## Other documents

`A2A_TRANSPORT.md`, `AUDIT_PACKAGE.md`, `DEPLOYMENT.md`, `FORMAL_SOUNDNESS_PROOF.md`, `OWASP_AGENTIC_TOP10.md`, `REPRODUCIBILITY.md`, `BENCHMARK_AGT_VS_DGV.md`, `openapi.yaml`, and `docs/LIMITATIONS.md`.

## Versioning and license

Follows the DGV benchmark version (currently v1.0.0); see `spec.md` Sections 13 and 14. License: see the repository.
