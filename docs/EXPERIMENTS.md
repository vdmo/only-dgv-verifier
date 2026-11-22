# Local experiments

Moved from the top-level README. Run all commands from the repository root.

## Objective Contract experiment (local, synthetic)

This experiment implements deterministic checks for `prepare_quote`, not general intent understanding or a live CRM gate. It does not implement the proposed ONLY Lang authority commands. Website cards TC-070 through TC-089 are specifications, not evidence that those interpreter features or reproducible builds passed.

Run from this directory with Python 3.10+ in a virtual environment; the experiment uses only the standard library:

```bash
python3 -m venv .venv
.venv/bin/python -m unittest -v test_objective_contract
.venv/bin/python dgv_runner.py --objective-experiment
.venv/bin/python dgv_runner.py --objective-experiment --output evidence/my_objective_run.json
```

`--output` creates a new file and refuses to overwrite existing evidence. The checked-in `evidence/objective_contract_experiment.json` contains deterministic fixtures, expected outcomes, all predicate results, complete replay inputs and hashes. The unit suite compares the saved report against a fresh run. These cases are separate from the numbered native DGV suite.

To evaluate an independently prepared host request and replay its receipt:

```bash
.venv/bin/python dgv_runner.py --objective-request request.json --output receipt.json
.venv/bin/python verify_receipt.py --objective-receipt receipt.json --objective-request request.json
```

The request has exactly four keys: `contract`, `proposal`, `context`, `now_ms`. `objective_experiment.base_request()` is the synthetic reference fixture; `objective_contract.py` defines the exact accepted fields. The host must obtain the contract review, reviewers, actor, policy version, revocation state, ledger, approvals and time independently of the proposing agent. Do not expose the entire request as an untrusted agent API payload. No credentials or identities are authenticated by this prototype; reviewer IDs in the fixtures are synthetic assertions.

The contract fixes the customer, permitted services, currency, total budget, aggregate approval threshold, freshness windows, expiry and unresolved requirements. All money is non-negative integer minor units; there is no currency conversion. `source_instruction` is retained for human review, not interpreted by a model. The contract hash binds that review to every contract field. Above the aggregate threshold, transaction approval must bind both the contract hash and exact proposal hash. Any unknown field or unsupported schema is rejected, not silently ignored.

A violated constraint returns `DENY`; missing or stale evidence, changed policy and declared ambiguity return `ESCALATE`. A known violation takes precedence over escalation. Neither result authorizes execution. `ALLOW` means the synthetic inputs satisfy this evaluator, not that a CRM action occurred. No tool callback or CRM write is performed.

Receipts use the distinct `DGV-OBJECTIVE-EXPERIMENT-1` profile, not PSR-001 conformance. Canonicalization is compact sorted-key JSON, ASCII strings, safe integers (absolute value at most 2^53-1), booleans and null. Arrays retain order; duplicate keys, non-ASCII strings and floating-point values are rejected. This restricted profile is not advertised as a general RFC 8785 implementation. SHA-256 covers every receipt field except `receipt_hash`; hashes of contract, proposal, context and decision are also checked by re-derivation. A hash is not a digital signature.

Replay without an independent request returns `UNVERIFIABLE` even if the content hash and decision match. Matching an independent request returns `VERIFIED_AGAINST_SUPPLIED_CONTEXT`, never a fresh execution authorization. If an attacker replaces both the receipt and the supposedly independent request, hashes cannot establish truth; protect the external reference. The verifier does not fetch URLs or run scripts from receipts.

Live deployment still requires authenticated evidence adapters, a complete authoritative ledger, atomic check-and-reserve/write, revocation freshness guarantees, permission boundaries and independent review. A stale or incomplete ledger cannot establish aggregate safety. Historical receipts are not retroactively invalidated by a later revocation. No continuous lineage or general semantic alignment is claimed.

## Revocation propagation experiment (two local gates, one SQLite authority)

This experiment tests whether a revoked actor can still execute after revocation commits, using two local gate processes against one temporary SQLite authority store. It does **not** test network partitions, replicated consensus, or production-scale propagation latency. No CRM writes or external tool calls are performed.

The key design choice: authority check, token consumption, and the synthetic destination write all happen inside one SQLite `BEGIN IMMEDIATE` transaction. A gate cannot authorize a write using a stale cached authority, because the check and the write commit together or fail together.

Run from this directory with the virtual environment:

```bash
.venv/bin/python dgv_runner.py --revocation-experiment
.venv/bin/python dgv_runner.py --revocation-experiment --race-trials 50 --output evidence/my_revocation_run.json
.venv/bin/python -m unittest -v test_revocation
```

`--output` creates a new file and refuses to overwrite. The checked-in `evidence/revocation_experiment.json` contains 36 cases (12 sequential + 24 simultaneous revoke/write races), all predicate results, the full committed history snapshot, measurements and a report hash. The unit suite compares the saved report against a fresh run and checks tampering.

To verify a saved report against an independently retained checkpoint:

```bash
.venv/bin/python verify_receipt.py --revocation-report evidence/revocation_experiment.json --expected-hash <report_hash>
```

Without `--expected-hash`, verification returns `UNVERIFIABLE` — the report hash alone cannot establish that the report was not wholesale replaced.

### What the experiment demonstrated

| Case | Result |
|---|---|
| Stale cached authority after committed revocation | **DENY** — execution check ordered after revocation commit |
| Old token after re-grant | **DENY** — token version is stale |
| Fresh token after re-grant | **ALLOW** — new version-bound token |
| Token replay on other gate | **DENY** — one-use across gates |
| Duplicate action with new token | **DENY** — action ID already committed |
| Write committed before revocation | **ALLOW** — revocation is not retroactive |
| Store timeout (locked database) | **DENY** — no cached-permission fallback |
| Store recovery after timeout | **ALLOW** — failed attempt did not consume token |
| Payload or destination substitution | **DENY** — token binding mismatch |
| Concurrent token use (two gates) | Exactly one ALLOW, one DENY |
| 24 simultaneous revoke/write races | All correctly ordered by transaction commit |

All 24 race trials resolved as `revoke_before_check` — SQLite's `BEGIN IMMEDIATE` lock serializes concurrent transactions, so revocation always commits before the execution check can start. There is no stale-cache window when authority checks and writes share the same transaction.

### What this does not prove

- **No network partition:** the "unavailable store" case is a SQLite lock timeout, not a real network outage. Production requires fail-closed behavior when the authority service is unreachable.
- **No replication or consensus:** one SQLite database, one writer at a time. Multi-region deployment needs consensus (Raft, Paxos, or a managed service) to maintain the same guarantee.
- **No authenticated identities:** trusted local processes have direct database access. Production requires authenticated service roles and protected destination writes.
- **No external exactly-once:** commit errors are unconfirmed — reconcile by action ID before retrying.
- **No production SLA:** latency samples describe this run only.
- **No signature:** the report hash is not a digital signature. An independent trusted checkpoint is needed to detect wholesale replacement.
