#!/usr/bin/env python3
"""
DGV Evidence Receipt Verifier
==============================
Verifies the settlement_receipt in one or more DGV evidence packages.

Usage:
    python3 verify_receipt.py evidence/dgv_tc_001_evidence.json
    python3 verify_receipt.py evidence/dgv_tc_*_evidence.json
    python3 verify_receipt.py --all

The receipt is a SHA-256 content-hash computed over the canonical JSON of the
evidence body (all fields except settlement_receipt itself, sort_keys=True,
indent=2, UTF-8). See RECEIPT_VERIFICATION.md for the full procedure.

Exit code: 0 if all files pass, 1 if any fail.
"""

import glob
import hashlib
import json
import os
import sys


def verify(path: str) -> bool:
    try:
        with open(path, encoding="utf-8") as f:
            evidence = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print(f"FAIL  {path}")
        print(f"      could not read file: {e}")
        return False

    receipt = evidence.get("settlement_receipt")
    if not receipt:
        print(f"FAIL  {path}")
        print(f"      no settlement_receipt field present")
        return False

    anchor_method = receipt.get("anchor_method", "")
    if anchor_method != "sha256-content-hash":
        print(f"FAIL  {path}")
        print(f"      unsupported anchor_method: {anchor_method!r}")
        print(f"      this verifier handles sha256-content-hash only")
        return False

    expected_id = receipt.get("transaction_id", "")
    if not expected_id.startswith("dgv-sha256:"):
        print(f"FAIL  {path}")
        print(
            f"      transaction_id does not start with 'dgv-sha256:': {expected_id!r}"
        )
        return False

    expected_hex = expected_id.removeprefix("dgv-sha256:")
    if len(expected_hex) != 64 or not all(
        c in "0123456789abcdef" for c in expected_hex
    ):
        print(f"FAIL  {path}")
        print(
            f"      transaction_id hex is not 64 lowercase hex chars: {expected_hex!r}"
        )
        return False

    # Reconstruct the canonical body — everything except settlement_receipt
    body = {k: v for k, v in evidence.items() if k != "settlement_receipt"}
    canonical = json.dumps(body, indent=2, sort_keys=True).encode("utf-8")
    actual_hex = hashlib.sha256(canonical).hexdigest()

    if actual_hex == expected_hex:
        card_id = evidence.get("test_card_id", os.path.basename(path))
        print(f"PASS  [{card_id}] {os.path.basename(path)}")
        print(f"      sha256:{actual_hex}")
        return True
    else:
        print(f"FAIL  {path}")
        print(f"      expected : sha256:{expected_hex}")
        print(f"      computed : sha256:{actual_hex}")
        print(f"      The file has been modified since the receipt was generated.")
        return False


def main() -> int:
    args = sys.argv[1:]

    if not args:
        print(__doc__)
        return 1

    # --all flag: resolve all evidence files in the standard location
    if args == ["--all"]:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        pattern = os.path.join(script_dir, "evidence", "dgv_tc_*_evidence.json")
        paths = sorted(glob.glob(pattern))
        if not paths:
            print(f"No evidence files found matching: {pattern}")
            return 1
    else:
        paths = args

    print(f"DGV Receipt Verifier — checking {len(paths)} file(s)\n")
    results = [verify(p) for p in paths]
    total = len(results)
    passed = sum(results)
    failed = total - passed

    print(f"\n{'─' * 60}")
    print(f"  {passed}/{total} passed   {failed} failed")
    if failed == 0:
        print(f"  All receipts verified. Evidence suite is tamper-evident.")
    else:
        print(
            f"  VERIFICATION FAILED. {failed} file(s) have been modified or corrupted."
        )
    print(f"{'─' * 60}")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
