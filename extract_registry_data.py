#!/usr/bin/env python3
"""Extract registry data from evidence files and generate registry.json matching the schema."""

import json
import hashlib
from datetime import datetime, timedelta
from pathlib import Path

EVIDENCE_DIR = Path(__file__).parent / "evidence"
REGISTRY_PATH = Path(__file__).parent / "registry.json"

def compute_content_hash(data: dict) -> str:
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

# Map svrnos_layer values to schema enum
LAYER_MAP = {
    "L1: Authorization": "L1: Authorization",
    "L1": "L1: Authorization",
    "L2: Compute Verification": "L2: Compute Verification",
    "L2": "L2: Compute Verification",
    "NONE": "L1: Authorization",  # default
}

def normalize_layer(layer: str) -> str:
    return LAYER_MAP.get(layer, layer if layer in [
        "L1: Compute Substrate", "L1: Authorization",
        "L2: Component & Provenance", "L2: Compute Verification",
        "L3: Routing & Boundary", "L4: Evidence Transport",
        "L5: Session & State", "L6: Risk Interpretation",
        "L7: Application Enforcement"
    ] else "L1: Authorization")

def main():
    certifications = []
    seen_card_ids = set()
    for ev_file in sorted(EVIDENCE_DIR.glob("*_evidence.json")):
        # Skip LLM evidence files (they duplicate test card IDs)
        if "_llm_evidence" in ev_file.name:
            continue
        with open(ev_file) as f:
            evidence = json.load(f)

        test_card_id = evidence.get("test_card_id", "")
        if test_card_id in seen_card_ids:
            continue
        seen_card_ids.add(test_card_id)
        claim_class = evidence.get("claim_name", evidence.get("claim_class", ""))
        svrnos_layer = normalize_layer(evidence.get("svrnos_layer", ""))
        benchmark_version = evidence.get("benchmark_version", "1.0.0")
        verified_timestamp = evidence.get("verified_timestamp", "")
        execution_mode = evidence.get("execution_mode", "native")
        is_negative = evidence.get("negative_test", False)

        # Use the receipt hash from the evidence file's settlement_receipt
        settlement = evidence.get("settlement_receipt", {})
        receipt_hash = settlement.get("transaction_id", "")
        receipt_timestamp = settlement.get("timestamp", verified_timestamp)
        anchor_method = settlement.get("anchor_method", "sha256-content-hash")

        # Compute expiry (365 days from verification)
        try:
            verified_dt = datetime.strptime(verified_timestamp, "%Y-%m-%dT%H:%M:%SZ")
            expiry = (verified_dt + timedelta(days=365)).strftime("%Y-%m-%dT%H:%M:%SZ")
        except (ValueError, TypeError):
            expiry = "2027-08-30T00:00:00Z"

        # Badge status includes execution mode
        badge = f"verified:{execution_mode}"

        cert = {
            "claim_id": test_card_id.replace("DGV-TC-", "DGV-CL-"),
            "claim_name": claim_class,
            "test_card_id": test_card_id,
            "test_card_version": benchmark_version,
            "execution_mode": execution_mode,
            "svrnos_layer": svrnos_layer,
            "badge_status": badge,
            "certified_at": verified_timestamp,
            "expires_at": expiry,
            "evidence": {
                "package_uri": f"evidence/{ev_file.name}",
                "receipt": {
                    "anchor_method": anchor_method,
                    "transaction_id": receipt_hash,
                    "timestamp": receipt_timestamp,
                },
            },
        }
        if is_negative:
            cert["notes"] = "Negative test card — verifies the verifier correctly detects and rejects violations."
        certifications.append(cert)

    # Read the real TC-001 receipt for the gold certification example
    tc001_evidence_path = EVIDENCE_DIR / "dgv_tc_001_evidence.json"
    tc001_receipt = ""
    if tc001_evidence_path.exists():
        with open(tc001_evidence_path) as f:
            tc001_ev = json.load(f)
        tc001_receipt = tc001_ev.get("settlement_receipt", {}).get("transaction_id", "")

    registry = {
        "registry_version": "1.0.0",
        "generated_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "dgv_benchmark_version": "1.0.0",
        "systems": [
            {
                "system_id": "only-engine",
                "system_name": "Only Engine",
                "system_version": "1.3.0",
                "publisher": {
                    "name": "PIR Institute",
                    "url": "https://github.com/vdmo",
                },
                "description": "Deterministic AI agent runtime with governance enforcement",
                "source_repository": "https://github.com/vdmo/only-engine",
                "certifications": certifications,
            },
            {
                "system_id": "only-dgv-verifier",
                "system_name": "DGV Verifier (Self-Certification Example)",
                "system_version": "1.0.0",
                "publisher": {
                    "name": "PIR Institute",
                    "url": "https://github.com/vdmo",
                },
                "description": "Example gold certification showing NDA-gated source review audit metadata. This is a template — actual gold certifications require a real third-party audit.",
                "source_repository": "https://github.com/vdmo/only-dgv-verifier",
                "certifications": [
                    {
                        "claim_id": "DGV-CL-GOLD-001",
                        "claim_name": "Deterministic Execution (Gold — Audited Live)",
                        "test_card_id": "DGV-TC-001",
                        "test_card_version": "1.0.0",
                        "execution_mode": "audited_live",
                        "svrnos_layer": "L6: Risk Interpretation",
                        "badge_status": "gold:audited_live",
                        "scope": "dgv-verifier binary v1.0.0 on x86_64-unknown-linux-gnu",
                        "certified_at": "2026-08-30T00:00:00Z",
                        "expires_at": "2027-08-30T00:00:00Z",
                        "re_certification_policy": "Required on any system version change or DGV benchmark major version bump",
                        "evidence": {
                            "package_uri": "evidence/dgv_tc_001_evidence.json",
                            "receipt": {
                                "anchor_method": "sha256-content-hash",
                                "transaction_id": tc001_receipt,
                                "verification_procedure": "https://github.com/vdmo/only-dgv-verifier/blob/main/RECEIPT_VERIFICATION.md",
                                "timestamp": "2026-08-30T00:00:00Z",
                            },
                            "independent_audit": {
                                "auditor": "Example Security Auditors LLC (NDA-2026-001)",
                                "report_uri": "https://example.com/audit-reports/dgv-verifier-v1.0.0-source-review.pdf",
                                "audit_date": "2026-08-15",
                                "audit_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                                "audit_type": "source_review",
                                "review_path": "attestation",
                                "nda_reference": "NDA-2026-001",
                                "scope": "verifier source, build chain, receipt hashing, PIR tension computation",
                                "findings": "PASS: All reviewed components match specification. Receipt hashing is correct. PIR tension computation is mathematically sound. No backdoors or bypass logic detected.",
                            },
                        },
                        "notes": "EXAMPLE gold certification — demonstrates the schema for NDA-gated source review. This is not a real audit. Replace with actual audit metadata when a real third-party review is completed.",
                    }
                ],
            },
        ],
    }

    with open(REGISTRY_PATH, "w") as f:
        json.dump(registry, f, indent=2)

    print(f"Generated registry.json with {len(certifications)} certifications")

if __name__ == "__main__":
    main()
