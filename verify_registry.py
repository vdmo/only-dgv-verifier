#!/usr/bin/env python3
"""
DGV Public Registry Verifier

Validates the public claims registry against the official JSON Schema,
checks every evidence receipt by recomputing SHA-256 content hashes,
enforces badge rules (verified vs gold), and reports expired certifications.

Usage:
    python3 verify_registry.py [--registry PATH] [--schema PATH] [--evidence-dir PATH]

Exit codes:
    0 — all checks passed
    1 — schema validation or badge rule failure
    2 — receipt verification failure
    3 — expired certifications found (warning level)
"""

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

try:
    import jsonschema
except ImportError:
    print("ERROR: jsonschema is required. Install with: pip install jsonschema")
    sys.exit(1)


DEFAULT_REGISTRY = Path(__file__).parent / "registry.json"
DEFAULT_SCHEMA = Path(__file__).parent / "registry.schema.json"
DEFAULT_EVIDENCE_DIR = Path(__file__).parent / "evidence"


def load_json(path: Path):
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def verify_receipt(evidence_path: Path, expected_tx_id: str) -> tuple[bool, str]:
    """
    Recompute SHA-256 content hash of the evidence body (excluding
    settlement_receipt) and compare against the expected transaction ID.
    The prefix (e.g. 'dgv-sha256:', 'llm-sha256:') is ignored — only the
    hex digest is compared.
    Returns (success, computed_hash).
    """
    if not evidence_path.exists():
        return False, "FILE_NOT_FOUND"

    with evidence_path.open(encoding="utf-8") as f:
        evidence = json.load(f)

    # The settlement_receipt is excluded from the hash because it is derived
    # from the body — including it would be circular.
    body = {k: v for k, v in evidence.items() if k != "settlement_receipt"}
    canonical = json.dumps(body, indent=2, sort_keys=True).encode("utf-8")
    digest = hashlib.sha256(canonical).hexdigest()

    # Extract just the hex digest from both sides (strip any prefix before ':')
    expected_digest = expected_tx_id.split(":")[-1] if ":" in expected_tx_id else expected_tx_id
    computed = f"dgv-sha256:{digest}"

    return digest == expected_digest, computed


def resolve_evidence_path(package_uri: str, evidence_dir: Path) -> Path:
    """
    Resolve a package_uri to a local file path.
    Handles GitHub blob URLs, relative paths, and file:// URIs.
    """
    if package_uri.startswith("file://"):
        return Path(urlparse(package_uri).path)

    # GitHub blob URL → local file
    if "github.com" in package_uri and "/blob/" in package_uri:
        # Extract the filename from the URL path
        # e.g. .../blob/main/evidence/dgv_tc_001_evidence.json → dgv_tc_001_evidence.json
        parts = urlparse(package_uri).path.split("/")
        filename = parts[-1]
        return evidence_dir / filename

    # Relative path
    if not package_uri.startswith("http"):
        return Path(package_uri)

    # Fallback: try filename from URL
    parts = urlparse(package_uri).path.split("/")
    filename = parts[-1]
    return evidence_dir / filename


def main():
    parser = argparse.ArgumentParser(description="DGV Public Registry Verifier")
    parser.add_argument(
        "--registry", type=Path, default=DEFAULT_REGISTRY,
        help="Path to registry.json"
    )
    parser.add_argument(
        "--schema", type=Path, default=DEFAULT_SCHEMA,
        help="Path to registry.schema.json"
    )
    parser.add_argument(
        "--evidence-dir", type=Path, default=DEFAULT_EVIDENCE_DIR,
        help="Directory containing evidence packages"
    )
    parser.add_argument(
        "--skip-receipts", action="store_true",
        help="Skip receipt hash verification (schema + badge rules only)"
    )
    args = parser.parse_args()

    # ── 1. Load and validate against schema ──────────────────────────────
    print("=" * 60)
    print("DGV Public Registry Verifier")
    print("=" * 60)

    if not args.schema.exists():
        print(f"ERROR: Schema not found at {args.schema}")
        sys.exit(1)
    if not args.registry.exists():
        print(f"ERROR: Registry not found at {args.registry}")
        sys.exit(1)

    schema = load_json(args.schema)
    registry = load_json(args.registry)

    print(f"\nRegistry version:    {registry.get('registry_version', '?')}")
    print(f"Benchmark version:   {registry.get('dgv_benchmark_version', '?')}")
    print(f"Generated at:        {registry.get('generated_at', '?')}")
    print(f"Systems:             {len(registry.get('systems', []))}")

    try:
        jsonschema.validate(instance=registry, schema=schema)
        print("\n[OK] Registry conforms to JSON Schema (Draft 2020-12)")
    except jsonschema.ValidationError as e:
        print(f"\n[FAIL] Schema validation failed: {e.message}")
        print(f"       Path: {' -> '.join(str(p) for p in e.absolute_path)}")
        sys.exit(1)

    # ── 2. Check each certification ──────────────────────────────────────
    now = datetime.now(timezone.utc)
    errors = 0
    warnings = 0
    receipts_checked = 0
    receipts_passed = 0

    for system in registry["systems"]:
        sys_name = f"{system['system_name']} ({system['system_version']})"
        print(f"\n{'─' * 60}")
        print(f"System: {sys_name}")
        print(f"  ID:       {system['system_id']}")
        print(f"  Publisher: {system['publisher']['name']}")
        print(f"  Certifications: {len(system['certifications'])}")

        for cert in system["certifications"]:
            claim = f"{cert['claim_id']} — {cert['claim_name']}"
            badge = cert["badge_status"]
            print(f"\n  [{badge.upper():>10}] {claim}")
            print(f"    Test card: {cert['test_card_id']} v{cert['test_card_version']}")

            # ── Expiry check ──
            expires_str = cert.get("expires_at", "")
            if expires_str:
                try:
                    expires = datetime.fromisoformat(
                        expires_str.replace("Z", "+00:00")
                    )
                    if expires < now:
                        print(f"    [WARN] EXPIRED on {expires_str}")
                        warnings += 1
                    else:
                        days_left = (expires - now).days
                        print(f"    [OK]   Valid until {expires_str} ({days_left}d left)")
                except ValueError:
                    print(f"    [WARN] Invalid expiry date format: {expires_str}")
                    warnings += 1

            # ── Badge rule enforcement ──
            evidence = cert.get("evidence", {})
            has_audit = "independent_audit" in evidence
            has_receipt = "receipt" in evidence
            exec_mode = cert.get("execution_mode", "unknown")

            # Parse badge: can be "verified:native", "gold:audited_live", etc.
            badge_parts = badge.split(":")
            badge_base = badge_parts[0]
            badge_mode = badge_parts[1] if len(badge_parts) > 1 else None

            if badge_base == "gold":
                if not has_audit:
                    print("    [FAIL] gold badge requires independent_audit record")
                    errors += 1
                else:
                    audit = evidence["independent_audit"]
                    print(f"    [OK]   Independent audit: {audit.get('auditor', '?')}")
                    print(f"           Report: {audit.get('report_uri', '?')}")
                    print(f"           Type: {audit.get('audit_type', '?')}")
                    # Gold requires audited_live or live execution mode
                    if exec_mode not in ("audited_live", "live"):
                        print(f"    [FAIL] gold badge requires execution_mode 'audited_live' or 'live', got '{exec_mode}'")
                        errors += 1
                if not has_receipt:
                    print("    [FAIL] gold badge requires a receipt")
                    errors += 1
            elif badge_base == "verified":
                if not has_receipt:
                    print("    [FAIL] verified badge requires a receipt")
                    errors += 1
                else:
                    print("    [OK]   Receipt present")
                # Verify badge mode matches execution_mode
                if badge_mode and badge_mode != exec_mode:
                    print(f"    [FAIL] badge mode '{badge_mode}' does not match execution_mode '{exec_mode}'")
                    errors += 1
                else:
                    print(f"    [OK]   Execution mode: {exec_mode}")
            elif badge_base == "unverified":
                print("    [INFO] No verification claim made")

            # ── Execution mode consistency check ──
            if exec_mode not in ("simulation", "native", "live", "audited_live"):
                print(f"    [FAIL] Invalid execution_mode: {exec_mode}")
                errors += 1

            # ── Receipt hash verification ──
            if not args.skip_receipts and has_receipt:
                receipt = evidence["receipt"]
                tx_id = receipt.get("transaction_id", "")
                anchor = receipt.get("anchor_method", "")

                if anchor in ("sha256-content-hash", "gitops-sha256") and tx_id:
                    package_uri = evidence.get("package_uri", "")
                    ev_path = resolve_evidence_path(package_uri, args.evidence_dir)
                    ok, computed = verify_receipt(ev_path, tx_id)
                    receipts_checked += 1
                    if ok:
                        print(f"    [OK]   Receipt verified ({anchor})")
                        receipts_passed += 1
                    elif computed == "FILE_NOT_FOUND":
                        print(f"    [SKIP] Evidence file not found: {ev_path.name}")
                    else:
                        print(f"    [FAIL] Receipt hash mismatch")
                        print(f"           expected: {tx_id}")
                        print(f"           computed: {computed}")
                        errors += 1
                elif anchor == "ed25519-signed":
                    sig = receipt.get("signature", "")
                    if sig:
                        print(f"    [SKIP] Ed25519 signature present (manual verification needed)")
                    else:
                        print(f"    [FAIL] ed25519-signed anchor missing signature field")
                        errors += 1
                elif anchor == "scitt":
                    print(f"    [SKIP] SCITT receipt (external transparency log verification needed)")
                else:
                    print(f"    [SKIP] Unknown anchor method: {anchor}")

    # ── 3. Cross-consistency checks ─────────────────────────────────────
    print(f"\n{'─' * 60}")
    print("Cross-Consistency Checks")
    print(f"{'─' * 60}")

    for system in registry["systems"]:
        certs = system["certifications"]
        versions = set()
        benchmark_versions = set()
        exec_modes = set()
        card_ids = set()

        for cert in certs:
            versions.add(cert.get("test_card_version", ""))
            benchmark_versions.add(cert.get("test_card_version", ""))
            exec_modes.add(cert.get("execution_mode", ""))
            card_ids.add(cert.get("test_card_id", ""))

            # Check evidence file exists
            ev_uri = cert.get("evidence", {}).get("package_uri", "")
            ev_path = resolve_evidence_path(ev_uri, args.evidence_dir)
            if not ev_path.exists():
                print(f"  [FAIL] Evidence file missing for {cert['test_card_id']}: {ev_path.name}")
                errors += 1

        # Version consistency
        if len(versions) > 1:
            print(f"  [WARN] Multiple test card versions found: {versions}")
            warnings += 1
        else:
            print(f"  [OK]   Version consistency: all {len(certs)} certs at v{versions.pop() if versions else '?'}")

        # Execution mode distribution
        print(f"  [INFO] Execution modes: {dict((m, sum(1 for c in certs if c.get('execution_mode') == m)) for m in exec_modes)}")

        # Check for duplicate test card IDs
        if len(card_ids) != len(certs):
            print(f"  [FAIL] Duplicate test card IDs detected ({len(card_ids)} unique vs {len(certs)} certs)")
            errors += 1
        else:
            print(f"  [OK]   No duplicate test card IDs ({len(card_ids)} unique)")

        # Check all benchmark versions match registry version
        reg_bv = registry.get("dgv_benchmark_version", "")
        for bv in benchmark_versions:
            if bv and reg_bv and bv != reg_bv:
                print(f"  [FAIL] Benchmark version mismatch: cert has {bv}, registry has {reg_bv}")
                errors += 1

    # ── 4. Summary ───────────────────────────────────────────────────────
    print(f"\n{'=' * 60}")
    print("SUMMARY")
    print(f"{'=' * 60}")
    total_certs = sum(len(s["certifications"]) for s in registry["systems"])
    print(f"  Total certifications:  {total_certs}")
    print(f"  Receipts checked:      {receipts_checked}")
    print(f"  Receipts verified:     {receipts_passed}")
    print(f"  Errors:                {errors}")
    print(f"  Warnings:              {warnings}")

    if errors > 0:
        print(f"\n[FAIL] {errors} error(s) found — registry verification FAILED")
        sys.exit(1 if errors > 0 else 3)
    elif warnings > 0:
        print(f"\n[WARN] {warnings} warning(s) — registry valid but has expired entries")
        sys.exit(3)
    else:
        print(f"\n[OK] Registry verification PASSED")
        sys.exit(0)


if __name__ == "__main__":
    main()
