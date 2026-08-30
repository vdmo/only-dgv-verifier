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
    for ev_file in sorted(EVIDENCE_DIR.glob("*_evidence.json")):
        with open(ev_file) as f:
            evidence = json.load(f)

        test_card_id = evidence.get("test_card_id", "")
        test_card_name = evidence.get("test_card_name", "")
        claim_class = evidence.get("claim_class", "")
        svrnos_layer = normalize_layer(evidence.get("svrnos_layer", ""))
        benchmark_version = evidence.get("benchmark_version", "1.0.0")
        verified_timestamp = evidence.get("verified_timestamp", "")

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

        cert = {
            "claim_id": test_card_id.replace("DGV-TC-", "DGV-CL-"),
            "claim_name": claim_class,
            "test_card_id": test_card_id,
            "test_card_version": benchmark_version,
            "svrnos_layer": svrnos_layer,
            "badge_status": "verified",
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
        certifications.append(cert)

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
            }
        ],
    }

    with open(REGISTRY_PATH, "w") as f:
        json.dump(registry, f, indent=2)

    print(f"Generated registry.json with {len(certifications)} certifications")

if __name__ == "__main__":
    main()
