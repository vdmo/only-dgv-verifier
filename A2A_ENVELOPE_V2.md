# A2A envelope v2 and receipt v2

What an agent signs when it sends, what the gate signs when it accepts, and how to check both later without the gate.

Reference implementations: `dgv_a2a_v2.py` (Python) and `native/dgv-gate/src/main.rs` (Rust). Both are tested against the same vectors, `test_vectors/a2a_v2.json`.

## Encoding

The signed bytes are the **RFC 8785 (JCS)** canonical JSON of one object, UTF-8. Values here are only strings, `null`, and integers from 0 to 2^53-1. A `domain` field names the kind of object, so an envelope signature cannot be read as a receipt signature.

Signatures are Ed25519, hex.

## Envelope (signed by the sender)

| Field | Type | Rule |
|---|---|---|
| `domain` | string | `dgv-a2a-envelope-v2` (signed; not sent as a request field) |
| `envelope_id` | string | 1 to 256 bytes; unique at the gate |
| `sender_id`, `recipient_id` | string | 1 to 256 bytes |
| `payload_hash` | string | 64 lowercase hex characters (SHA-256) |
| `nonce` | string | 1 to 256 bytes; unique per sender |
| `sent_unix_ms`, `expires_unix_ms` | integer | `expires` after `sent` |
| `transport_ref` | string or `null` | 1 to 2048 bytes; always present in the signed object, `null` if none |

`POST /a2a/send` takes these fields plus `"version": "dgv-a2a-envelope-v2"` and `signature`.

The gate refuses, in this order: another `version` (400 `unsupported_envelope_version`), a field outside the rules (400 `invalid_envelope`), an unknown sender or bad signature (403), an expired envelope (410), `sent` more than 60 s in the future (400), a lifetime longer than `DGV_A2A_MAX_LIFETIME_MS` (default 3 600 000; 400 `lifetime_too_long`), a revoked or unknown party (403), a replay (409).

## Receipt (signed by the gate)

| Field | Meaning |
|---|---|
| `domain` | `dgv-a2a-receipt-v2` (signed; not included in the returned object) |
| `decision` | `accepted` |
| `decided_unix_ms` | when, by the gate's clock |
| `envelope_hash` | SHA-256 of the envelope's signed bytes |
| `envelope_id`, `sender_id`, `recipient_id`, `payload_hash` | copied from the envelope |
| `gate_key_id` | SHA-256 of the gate's raw Ed25519 public key |

The send response is `{accepted, envelope_id, receipt, gate_receipt, verifying_key}`; `gate_receipt` is the signature. The recipient finds the receipt in the inbox record as `receipt_json` with `gate_receipt_signature`.

## Evidence and offline verification

Keep four things: `{"envelope": {...}, "signature": "...", "receipt": {...}, "gate_receipt": "..."}` (`dgv_sdk.a2a_evidence` builds it; `send_sealed_a2a` returns it).

```
python dgv_a2a_v2.py evidence.json --gate-key HEX --sender-key HEX [--sealed-file message.json]
```

It needs only that file and `cryptography`, and makes no network calls. Exit status 0 verified, 1 not verified, 2 wrong usage.

It checks the sender's signature, the gate's signature under **your** gate key, that the receipt is about exactly this envelope, that the decision time falls inside the envelope's lifetime (60 s skew), and optionally that a payload matches the hash.

**Get both public keys beforehand through a channel you trust.** The `verifying_key` in a send response proves nothing on its own.

## What a verified receipt does not show

- That the recipient received, opened or acted on the message.
- That the message content is true, safe or authorised by any policy beyond this gate's A2A checks.
- That the sender or recipient was not revoked **later**.
- That the time is accurate: it is the gate's clock.
- Anything against a dishonest gate operator, who holds the gate key. An operator with admin access can also have that key sign other text (for example a policy script), including text shaped like a receipt.
- That a refused envelope was refused: **refusals are not signed.**
- There is no chain linking receipts, so a missing receipt cannot be detected.

Not independently reviewed. No legal or regulatory standing is claimed.

## Upgrading from the earlier format

Not compatible with the previous `a|b|c` signing string: the gate and every agent must be upgraded together. **Let inboxes empty first**: an envelope stored before the upgrade fails the recipient's signature check, and `recv_sealed_a2a` stops at it. The database gains one column, `a2a_envelopes.receipt_json`, added at start-up.
