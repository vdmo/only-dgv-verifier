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

Redacted exports (`GET /decisions/export?redact=true`) omit params, so check 2
cannot be performed. The chain (1) and signatures (3) are still verified; check
2 is reported as SKIPPED for those records and the run says so at the end. A
skipped check is not a pass: a redacted export proves ordering and gate
signing, not that the recorded parameters match the hash.
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


JCS_MAX_SAFE_INT = 9007199254740991


def _es6_number(f):
    """ECMAScript Number::toString for a finite double (RFC 8785 sec. 3.2.2.3)."""
    import math, re
    if math.isnan(f) or math.isinf(f):
        raise ValueError("non-finite number cannot be canonicalized")
    if f == 0:
        return "0"                       # also covers -0.0
    if f == int(f) and abs(f) < 1e21:
        return str(int(f))
    r = repr(f)                          # shortest round-trip digits
    m = re.fullmatch(r"(-?)(\d+(?:\.\d+)?)e([+-])(\d+)", r)
    if m:                                # Python 'e-07' -> ES6 'e-7'
        sign, mant, es, ed = m.groups()
        r = f"{sign}{mant}e{es}{int(ed)}"
    return r


def _canon(value):
    if isinstance(value, bool) or value is None:
        return json.dumps(value)
    if isinstance(value, int):
        if abs(value) > JCS_MAX_SAFE_INT:
            # mirror dgv-gate exact_big_ints: tagged object, exact decimal
            return '{"$dgv_int":' + json.dumps(str(value)) + "}"
        return str(value)
    if isinstance(value, float):
        return _es6_number(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ",".join(_canon(v) for v in value) + "]"
    if isinstance(value, dict):
        # RFC 8785: keys sorted by UTF-16 code units
        keys = sorted(value, key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + _canon(value[k]) for k in keys) + "}"
    raise TypeError(f"unsupported JSON type {type(value)}")


def jcs_canonicalize(value):
    """RFC 8785 (JCS) canonical JSON matching dgv-gate's serde_jcs output:
    sorted keys (UTF-16 order), ES6 number formatting (1.0 -> 1, -0.0 -> 0),
    and — because JCS formats numbers as doubles — integers beyond +/-(2^53-1)
    are replaced by {"$dgv_int":"<exact decimal>"} exactly as the gate does
    (see exact_big_ints in dgv-gate/src/main.rs). Verified against the shared
    vectors in scripts/decision_hash_vectors.json."""
    return _canon(value)


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
        redacted = bool(replay.get("params_redacted"))
        tool = replay.get("tool", "")
        action = replay.get("action", "")
        params = replay.get("params", {})
        reason_codes = d.get("reason_codes", [])

        if redacted:
            payload_ok = True  # not checkable without params; reported as SKIPPED
        else:
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
            f"hash={'SKIPPED' if redacted else ('OK' if payload_ok else 'MISMATCH')}  sig={'OK' if sig_ok else 'INVALID'}  -> {status}"
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
        skipped = sum(1 for d in export["decisions"] if d.get("replay_inputs", {}).get("params_redacted"))
        if skipped:
            print(
                f"⚠️  Chain contiguous and signatures valid for all decisions, but hash re-derivation "
                f"was SKIPPED for {skipped} redacted record(s) — parameters were withheld, so "
                f"this does not prove they match the signed hash."
            )
        else:
            print("✅ All decisions verified — chain contiguous, hashes correct, signatures valid.")
        sys.exit(0)


if __name__ == "__main__":
    main()
