#!/usr/bin/env python3
"""DGV A2A envelope v2 and receipt v2: the signed formats, and an offline verifier.

    python dgv_a2a_v2.py evidence.json --gate-key HEX --sender-key HEX [--payload-file F | --sealed-file F]

Needs only this file and `cryptography`. No network, no gate. Get the two public keys from somewhere you trust,
NOT from the evidence file or from whoever handed it to you.

Exit status: 0 verified, 1 not verified, 2 wrong usage.

See A2A_ENVELOPE_V2.md for the format and for what a verified receipt does and does not show.
"""

import argparse
import base64
import hashlib
import json
import sys

ENVELOPE_DOMAIN = "dgv-a2a-envelope-v2"
RECEIPT_DOMAIN = "dgv-a2a-receipt-v2"
MAX_SAFE_INT = 2**53 - 1
MAX_ID_BYTES = 256
MAX_REF_BYTES = 2048
CLOCK_SKEW_MS = 60_000

ENVELOPE_FIELDS = ("envelope_id", "sender_id", "recipient_id", "payload_hash", "nonce",
                   "sent_unix_ms", "expires_unix_ms", "transport_ref")
RECEIPT_FIELDS = ("decision", "decided_unix_ms", "envelope_hash", "envelope_id", "sender_id",
                  "recipient_id", "payload_hash", "gate_key_id")


class EvidenceError(ValueError):
    """The data is malformed or does not verify."""


def _text(name, value, limit=MAX_ID_BYTES):
    if not isinstance(value, str):
        raise EvidenceError(f"{name} must be a string")
    try:
        size = len(value.encode("utf-8"))
    except UnicodeEncodeError:
        raise EvidenceError(f"{name} is not valid Unicode") from None
    if not 1 <= size <= limit:
        raise EvidenceError(f"{name} must be 1 to {limit} bytes")


def _hash(name, value):
    if not (isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)):
        raise EvidenceError(f"{name} must be 64 lowercase hex characters")


def _time(name, value):
    if type(value) is not int or not 0 <= value <= MAX_SAFE_INT:
        raise EvidenceError(f"{name} must be an integer from 0 to 2^53-1")


def _exact_fields(what, obj, fields):
    if not isinstance(obj, dict) or set(obj) != set(fields):
        got = sorted(obj) if isinstance(obj, dict) else type(obj).__name__
        raise EvidenceError(f"{what} must have exactly the fields {sorted(fields)}, got {got}")


def _jcs(obj):
    """RFC 8785 canonical JSON, for the restricted values used here: ASCII keys, strings, null, and
    integers within 2^53-1. For these, sorted compact JSON with raw Unicode is the canonical form."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def envelope_bytes(envelope):
    """The exact bytes the sender signs."""
    _exact_fields("envelope", envelope, ENVELOPE_FIELDS)
    for name in ("envelope_id", "sender_id", "recipient_id", "nonce"):
        _text(name, envelope[name])
    _hash("payload_hash", envelope["payload_hash"])
    _time("sent_unix_ms", envelope["sent_unix_ms"])
    _time("expires_unix_ms", envelope["expires_unix_ms"])
    if envelope["expires_unix_ms"] <= envelope["sent_unix_ms"]:
        raise EvidenceError("expires_unix_ms must be after sent_unix_ms")
    if envelope["transport_ref"] is not None:
        _text("transport_ref", envelope["transport_ref"], MAX_REF_BYTES)
    return _jcs({"domain": ENVELOPE_DOMAIN, **envelope})


def envelope_hash(envelope):
    return hashlib.sha256(envelope_bytes(envelope)).hexdigest()


def gate_key_id(gate_public_key_hex):
    return hashlib.sha256(bytes.fromhex(gate_public_key_hex)).hexdigest()


def receipt_bytes(receipt):
    """The exact bytes the gate signs."""
    _exact_fields("receipt", receipt, RECEIPT_FIELDS)
    if receipt["decision"] != "accepted":
        raise EvidenceError("receipt decision must be 'accepted'")
    _time("decided_unix_ms", receipt["decided_unix_ms"])
    for name in ("envelope_hash", "payload_hash", "gate_key_id"):
        _hash(name, receipt[name])
    for name in ("envelope_id", "sender_id", "recipient_id"):
        _text(name, receipt[name])
    return _jcs({"domain": RECEIPT_DOMAIN, **receipt})


def _check_signature(what, public_key_hex, signature_hex, data):
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        key.verify(bytes.fromhex(signature_hex), data)
    except (InvalidSignature, ValueError, TypeError):
        raise EvidenceError(f"{what} does not verify") from None


def verify_sender(envelope, signature, sender_public_key_hex):
    _check_signature("sender signature", sender_public_key_hex, signature, envelope_bytes(envelope))


def verify_receipt(envelope, receipt, gate_signature, gate_public_key_hex):
    """The pinned gate key signed this receipt, and the receipt is about this envelope, decided in its lifetime."""
    data = receipt_bytes(receipt)
    try:
        expected_id = gate_key_id(gate_public_key_hex)
    except ValueError:
        raise EvidenceError("gate key is not hex") from None
    if receipt["gate_key_id"] != expected_id:
        raise EvidenceError("receipt names a different gate key than the one you trust")
    _check_signature("gate receipt signature", gate_public_key_hex, gate_signature, data)
    if receipt["envelope_hash"] != envelope_hash(envelope):
        raise EvidenceError("receipt is not about this envelope (envelope hash differs)")
    for name in ("envelope_id", "sender_id", "recipient_id", "payload_hash"):
        if receipt[name] != envelope[name]:
            raise EvidenceError(f"receipt and envelope disagree on {name}")
    decided = receipt["decided_unix_ms"]
    if not envelope["sent_unix_ms"] - CLOCK_SKEW_MS <= decided < envelope["expires_unix_ms"]:
        raise EvidenceError("decision time falls outside the envelope's lifetime")


def sealed_hash(sealed):
    """payload_hash of a dgv-sealed-v3 message (same formula as dgv_sdk.sealed_payload_hash)."""
    try:
        if sealed["v"] != "dgv-sealed-v3":
            raise EvidenceError("only dgv-sealed-v3 payloads can be checked")
        fields = (sealed["v"].encode(), sealed["envelope_id"].encode(),
                  int(sealed["counter"]).to_bytes(8, "big"), base64.b64decode(sealed["ct"], validate=True))
    except EvidenceError:
        raise
    except Exception:
        raise EvidenceError("sealed payload is malformed") from None
    return hashlib.sha256(b"".join(len(f).to_bytes(8, "big") + f for f in fields)).hexdigest()


def verify_evidence(evidence, gate_public_key_hex, sender_public_key_hex, payload=None, sealed=None):
    """Verify {envelope, signature, receipt, gate_receipt}. Raises EvidenceError; returns the receipt."""
    _exact_fields("evidence", evidence, ("envelope", "signature", "receipt", "gate_receipt"))
    envelope = evidence["envelope"]
    verify_sender(envelope, evidence["signature"], sender_public_key_hex)
    verify_receipt(envelope, evidence["receipt"], evidence["gate_receipt"], gate_public_key_hex)
    if payload is not None and hashlib.sha256(payload).hexdigest() != envelope["payload_hash"]:
        raise EvidenceError("payload does not match payload_hash")
    if sealed is not None and sealed_hash(sealed) != envelope["payload_hash"]:
        raise EvidenceError("sealed payload does not match payload_hash")
    return evidence["receipt"]


def main(argv=None):
    ap = argparse.ArgumentParser(description="Verify a DGV A2A receipt offline.")
    ap.add_argument("evidence", help="JSON file: {envelope, signature, receipt, gate_receipt}")
    ap.add_argument("--gate-key", required=True, help="gate Ed25519 public key (hex) that you already trust")
    ap.add_argument("--sender-key", required=True, help="sender Ed25519 public key (hex) that you already trust")
    group = ap.add_mutually_exclusive_group()
    group.add_argument("--payload-file", help="raw payload bytes whose SHA-256 is payload_hash")
    group.add_argument("--sealed-file", help="dgv-sealed-v3 JSON message whose hash is payload_hash")
    args = ap.parse_args(argv)
    try:
        with open(args.evidence, encoding="utf-8") as f:
            evidence = json.load(f)
        payload = sealed = None
        if args.payload_file:
            with open(args.payload_file, "rb") as f:
                payload = f.read()
        if args.sealed_file:
            with open(args.sealed_file, encoding="utf-8") as f:
                sealed = json.load(f)
        receipt = verify_evidence(evidence, args.gate_key, args.sender_key, payload, sealed)
    except (OSError, ValueError, RecursionError) as e:
        print(f"NOT VERIFIED: {e}")
        return 1
    checked = "payload checked" if (payload is not None or sealed is not None) else "payload NOT checked"
    print("VERIFIED")
    print(f"  the sender key signed envelope {receipt['envelope_id']!r}")
    print(f"  from {receipt['sender_id']!r} to {receipt['recipient_id']!r}, payload hash {receipt['payload_hash']}")
    print(f"  the gate key signed that it accepted it at {receipt['decided_unix_ms']} (Unix ms, gate's clock)")
    print(f"  {checked}")
    print("  This does not show that the recipient received or read it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
