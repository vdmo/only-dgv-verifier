# DGV Evidence Receipt Verification Procedure

**Version:** 1.0.0  
**Date:** 2026-06-24  
**Status:** Normative  
**Author:** ONLY INSTITUTE / PIR  

---

## 1. Purpose

Every DGV evidence package (`evidence/dgv_tc_*_evidence.json`) contains a `settlement_receipt` block. This document defines the exact, independently reproducible procedure for verifying that receipt — confirming that the evidence file has not been tampered with since it was produced by the DGV runner.

This is not a trust-the-operator claim. Any third party — auditor, regulator, or peer reviewer — can follow this procedure without contacting the ONLY INSTITUTE.

---

## 2. Receipt Structure

```json
"settlement_receipt": {
  "layer": "GitOps Cryptographic Registry",
  "anchor_method": "sha256-content-hash",
  "transaction_id": "dgv-sha256:<64 hex chars>",
  "signature":      "dgv-sha256:<64 hex chars>",
  "verification_procedure": "https://github.com/vdmo/only-dgv-tc/blob/main/RECEIPT_VERIFICATION.md",
  "timestamp": "2026-06-24T00:00:00Z"
}
```

| Field | Meaning |
|---|---|
| `layer` | Always `"GitOps Cryptographic Registry"` — the anchor is the git-committed file itself |
| `anchor_method` | Always `"sha256-content-hash"` — the hash covers the canonical JSON of the evidence body |
| `transaction_id` | `dgv-sha256:` followed by the 64-char lowercase hex SHA-256 digest |
| `signature` | Identical to `transaction_id` for this method |
| `verification_procedure` | URI of this document |
| `timestamp` | UTC time the runner computed the hash |

---

## 3. What is hashed

The SHA-256 is computed over the **canonical JSON serialization** of the evidence package body — that is, all fields **except** `settlement_receipt` itself, serialized with:

- Keys sorted alphabetically (`sort_keys=True`)
- Two-space indentation (`indent=2`)
- UTF-8 encoding, no BOM

This is the exact output of:

```python
import json, hashlib

with open("dgv_tc_001_evidence.json") as f:
    evidence = json.load(f)

body = {k: v for k, v in evidence.items() if k != "settlement_receipt"}
canonical = json.dumps(body, indent=2, sort_keys=True).encode("utf-8")
digest = hashlib.sha256(canonical).hexdigest()
assert evidence["settlement_receipt"]["transaction_id"] == f"dgv-sha256:{digest}"
```

---

## 4. Step-by-step verification

### Step 1 — Obtain the evidence file

```bash
# From the published git repository
git clone https://github.com/vdmo/only-dgv-tc.git
cat only-dgv-tc/evidence/dgv_tc_001_evidence.json
```

The file must be read from a **pinned git commit** to establish a tamper-evident baseline. Any future edit to the file will change the commit hash, which is recorded in the public git log.

### Step 2 — Recompute the canonical hash

Save this as `verify_receipt.py`:

```python
#!/usr/bin/env python3
import json
import hashlib
import sys

def verify(path: str) -> bool:
    with open(path, encoding="utf-8") as f:
        evidence = json.load(f)

    receipt = evidence.get("settlement_receipt")
    if not receipt:
        print(f"FAIL: no settlement_receipt in {path}")
        return False

    expected_id = receipt.get("transaction_id", "")
    if not expected_id.startswith("dgv-sha256:"):
        print(f"FAIL: unrecognised anchor_method — expected dgv-sha256 prefix")
        return False

    expected_hex = expected_id.removeprefix("dgv-sha256:")

    body = {k: v for k, v in evidence.items() if k != "settlement_receipt"}
    canonical = json.dumps(body, indent=2, sort_keys=True).encode("utf-8")
    actual_hex = hashlib.sha256(canonical).hexdigest()

    if actual_hex == expected_hex:
        print(f"PASS  {path}")
        print(f"      hash: sha256:{actual_hex}")
        return True
    else:
        print(f"FAIL  {path}")
        print(f"      expected: sha256:{expected_hex}")
        print(f"      computed: sha256:{actual_hex}")
        return False

if __name__ == "__main__":
    paths = sys.argv[1:] or []
    if not paths:
        print("Usage: python3 verify_receipt.py evidence/dgv_tc_*.json")
        sys.exit(1)
    results = [verify(p) for p in paths]
    sys.exit(0 if all(results) else 1)
```

Run it:

```bash
python3 verify_receipt.py evidence/dgv_tc_001_evidence.json
# PASS  evidence/dgv_tc_001_evidence.json
#       hash: sha256:a1b2c3...

# Verify the full suite at once
python3 verify_receipt.py --all
```

### Step 3 — Confirm the file is git-committed

```bash
git log --follow --oneline -- evidence/dgv_tc_001_evidence.json
# e.g.: a3f1b2c  Publish DGV test suite v0.6.0 — 42 test cards
```

The commit hash in the public git log is the tamper-evident anchor. Anyone can independently retrieve it from the public repository and confirm it matches. Any modification to the evidence file after commit would require a new commit — which would be visible in the public log.

---

## 5. Why SHA-256 content-hash rather than a blockchain anchor

The previous evidence releases used Sui testnet transaction IDs as anchors. These were removed because:

1. **Testnet transactions are ephemeral.** Sui testnet is periodically reset. Transaction IDs become unresolvable after a reset — the anchor cannot be independently verified.
2. **There was no published verification procedure.** A `sui-tx:0x...` ID requires knowing which RPC endpoint to query, which epoch, and which node to trust. None of that was documented.
3. **The signature field was not a real signature.** `"sui-sig:sui-tx:0x..."` was a copy of the transaction ID, not a cryptographic signature over the evidence content.

The SHA-256 content-hash method is stronger because:

- **Self-contained:** The hash is computed directly from the file. No external service, node, or network required.
- **Deterministic:** Any verifier running `verify_receipt.py` on the same file gets the same result.
- **Git-anchored:** The public git commit history is append-only and publicly auditable on GitHub without trusting the operator.
- **Upgradeable:** This document defines the procedure, and `anchor_method` is a versioned field. Future releases can add `"anchor_method": "scitt-receipt"` or `"anchor_method": "ed25519-signed"` without breaking existing verifiers.

---

## 6. Comparison to TRACE/SCITT anchoring

AgentTrust's TRACE specification uses SCITT (RFC 9052 / draft-ietf-scitt-architecture) receipts for transparency anchoring (TR-ANC module). SCITT provides a cryptographically signed, append-only transparency log with an IETF-standardised verification path.

The DGV GitOps receipt is at a lower assurance level than SCITT for one specific reason: it relies on the public git repository's tamper-evidence rather than a dedicated signed transparency log. The practical difference is:

| Property | DGV GitOps receipt | SCITT receipt |
|---|---|---|
| Tamper evidence | Git commit history (append-only, public) | Signed Merkle tree (RFC 9052) |
| Verification tooling | `sha256sum` + `git log` | `scitt-api-emulator` or IETF compliant library |
| Network dependency | GitHub (or any git mirror) | SCITT transparency service |
| Standard | Git protocol + SHA-256 | IETF SCITT |
| Current DGV coverage | All 30 test cards | Planned for DGV-TC-030 TR-ANC (Phase 2) |

The upgrade path from GitOps to SCITT is: submit the evidence file's SHA-256 hash to a SCITT transparency service and record the receipt in an additional `scitt_receipt` field. The `verify_receipt.py` script would be extended to optionally verify the SCITT receipt. This is tracked in the TC-030 `excluded_scope` field as TR-ANC (Phase 2).

---

## 7. Verification tool location

The canonical `verify_receipt.py` is maintained at:

```
https://github.com/vdmo/only-dgv-tc/blob/main/verify_receipt.py
```

It is included in the repository alongside this document. No external dependencies are required beyond the Python standard library.
