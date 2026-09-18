#!/usr/bin/env python3
"""Offline verifier for a dgv-gate decision-chain export.

Verifies a batch of decisions exported via `GET /decisions/export` with no
network access and no dependency on the gate still running — only the
exported JSON file and the gate's Ed25519 verifying key (included in the
export itself) are needed.

For each decision, checks three independent things, matching what the gate
itself guarantees on the live path:

  1. Hash chain contiguous  — this record's parent_decision_hash equals the
     previous record's decision_hash (the very first record's parent must be
     null).
  2. Payload hash correct   — decision_hash is a correct RFC 8785 (JCS)
     canonical re-derivation of {action, gate_state, params, reason_codes,
     request_id, tool}, exactly matching dgv-gate's own compute_decision_hash.
  3. Signature valid        — the Ed25519 signature verifies against the
     gate's verifying_key over decision_hash's raw bytes.

Usage:
    pip install pynacl
    python scripts/verify_decision_chain.py decisions_export.json

Exit code 0 if every record passes all three checks; 1 otherwise, with the
first failing record and which check failed printed to stderr.
"""
import argparse
import hashlib
import json
import sys

try:
    from nacl.signing import VerifyKey
    from nacl.exceptions import BadSignatureError
except ImportError:
    print("Missing dependency: pip install pynacl", file=sys.stderr)
    sys.exit(2)


def jcs_canonicalize(value):
    """Minimal RFC 8785 (JCS) canonical JSON: sorted object keys, no
    insignificant whitespace, recursively. Matches serde_jcs's behavior for
    the JSON shapes dgv-gate signs (no non-finite floats, no exotic number
    formatting beyond what json.dumps already produces for ints/simple
    floats — sufficient for verifying dgv-gate's own output)."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_decision_hash(request_id, gate_state, reason_codes, tool, action, params):
    canonical_input = {
        "action": action,
        "gate_state": gate_state,
        "params": params,
        "reason_codes": reason_codes,
        "request_id": request_id,
        "tool": tool,
    }
    canonical = jcs_canonicalize(canonical_input)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def verify_chain(export):
    decisions = export["decisions"]
    verify_key = VerifyKey(bytes.fromhex(export["verifying_key"]))
    errors = []
    prev_hash = None

    for i, d in enumerate(decisions):
        replay = d.get("replay_inputs", {})
        tool = replay.get("tool", "")
        action = replay.get("action", "")
        params = replay.get("params", {})
        reason_codes = d.get("reason_codes", [])

        rederived = compute_decision_hash(
            d["request_id"], d["gate_state"], reason_codes, tool, action, params
        )
        payload_ok = rederived == d["decision_hash"]

        try:
            # dgv-gate signs the *hex string* of decision_hash as UTF-8 text
            # (Rust's `sk.sign(decision_hash.as_bytes())` on a String), not
            # the 32 raw bytes the hex decodes to — match that exactly.
            verify_key.verify(
                d["decision_hash"].encode("utf-8"),
                bytes.fromhex(d["signature"]),
            )
            sig_ok = True
        except BadSignatureError:
            sig_ok = False

        chain_ok = d.get("parent_decision_hash") == prev_hash

        status = "OK" if (payload_ok and sig_ok and chain_ok) else "FAIL"
        print(
            f"  [{i}] {d['run_id']}  chain={'OK' if chain_ok else 'BROKEN'}  "
            f"hash={'OK' if payload_ok else 'MISMATCH'}  sig={'OK' if sig_ok else 'INVALID'}  -> {status}"
        )
        if status == "FAIL":
            errors.append((i, d["run_id"], chain_ok, payload_ok, sig_ok))

        prev_hash = d["decision_hash"]

    return errors


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("export_file", help="JSON file from GET /decisions/export")
    args = ap.parse_args()

    with open(args.export_file) as f:
        export = json.load(f)

    print(f"Loaded {len(export['decisions'])} decision(s) from {args.export_file}\n")
    errors = verify_chain(export)

    print()
    if errors:
        print(f"❌ {len(errors)} record(s) failed verification:", file=sys.stderr)
        for i, run_id, chain_ok, payload_ok, sig_ok in errors:
            reasons = []
            if not chain_ok:
                reasons.append("chain link broken")
            if not payload_ok:
                reasons.append("decision_hash does not match re-derived canonical hash")
            if not sig_ok:
                reasons.append("Ed25519 signature invalid")
            print(f"  [{i}] {run_id}: {', '.join(reasons)}", file=sys.stderr)
        sys.exit(1)
    else:
        print("✅ All decisions verified — chain contiguous, hashes correct, signatures valid.")
        sys.exit(0)


if __name__ == "__main__":
    main()
