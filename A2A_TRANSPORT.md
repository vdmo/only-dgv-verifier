# A2A Sealed Transport — `dgv-sealed-v1`

The DGV stack splits agent-to-agent messaging into a **control plane** (this
gate) and a **data plane** (any opaque transport — the reference one is
`onlystate-relay`). The gate authorizes envelopes and binds them to ciphertext
hashes; it never sees plaintext. The relay sees only opaque queue IDs and
ciphertext; it never learns who talks to whom.

```
Agent A                                          Agent B
   │ 1. GET /agents/keys/agent-b  (X25519 pub)       │
   │ 2. ECDH → shared_key → seal(plaintext)          │
   │ 3. POST /a2a/send ──────────────► DGV GATE      │
   │      signed envelope + payload_hash             │  authorize:
   │      + transport_ref                            │  signature, replay,
   │ ◄──────────── gate receipt                      │  expiry, revocation
   │ 4. POST relay /send/{queue_id}                  │
   │      {ciphertext, counter}  ──── opaque ───────►│
   │                                                 │ 5. GET /a2a/inbox
   │                                                 │ 6. GET relay /recv
   │                                                 │ 7. hash-check, open,
   │                                                 │    POST /a2a/ack
```

## Roles

| Component | Sees | Never sees |
|---|---|---|
| **DGV gate** | envelope metadata, Ed25519 signature, `payload_hash`, `transport_ref` | plaintext, ciphertext, encryption keys |
| **onlystate-relay** | queue IDs, ciphertext blobs, counters | sender/recipient identity, plaintext |
| **Agents** | plaintext, peer public keys (from gate registry) | peer private keys |

## Key registry

`POST /agents/keys` (admin) registers `{agent_id, public_key_hex,
enc_public_key_hex?}` — Ed25519 for envelope signatures, X25519 for ECDH.
`GET /agents/keys/:agent_id` is public: agents resolve peer keys from the
registry, never from in-band message data (prevents key-substitution).

## Sealed payload — `dgv-sealed-v1`

Agent-side crypto (SDK helpers in `dgv_sdk.py`), mirroring
`libonlystate::messages::envelope`:

```
shared_key = X25519(sender_enc_sk, recipient_enc_pk)
enc_key    = SHA3-256("enc"   || shared_key || counter_be8)
nonce      = SHA3-256("nonce" || counter_be8)[..12]
ciphertext = ChaCha20Poly1305(enc_key, nonce, plaintext)
```

- `counter` is a per-(sender, recipient) monotonic value supplied by the
  sender — every message gets a unique key+nonce without a handshake.
- Static-static ECDH means the shared key is constant per pair; per-message
  KDF gives unique AEAD keys. Post-quantum upgrade path: WOTS+ envelope
  signatures from libonlystate (not wired here yet — Ed25519 only).

## Hash binding

The gate binds the authorized envelope to the ciphertext:

```
payload_hash = SHA-256("dgv-sealed-v1" || "|" || envelope_id || "|"
                       || counter_be8 || ciphertext)
```

Recipient MUST verify `sealed_payload_hash(received) == envelope.payload_hash`
before opening. A swapped/tampered ciphertext fails this check even if it
decrypts — the authorized content is the *specific* ciphertext, not "whatever
arrives for this envelope."

## transport_ref

Opaque string recorded on the envelope and delivered verbatim to the
recipient. Formats:

- `relay:<relay_base_url>|<queue_id>` — fetch ciphertext from this relay queue
- `direct:<url>` — push delivery out of band (SDK does not implement; hooks for
  agent-defined transports)
- absent — legacy hash-only envelopes (unsealed path, still supported)

## Relay wire format

`onlystate-relay` endpoints:

- `POST /queue` `{"queue_id": "<64 hex>"}` — idempotent create
- `POST /send/{queue_id}` — `Envelope{queue_id, ciphertext(b64), counter, submitted_at}`
- `GET /recv/{queue_id}` — long-poll, returns `Envelope` or `{"status":"timeout"}`
- `DELETE /queue/{queue_id}` — destroy queue
- `GET /health`

The relay `ciphertext` field carries `base64(JSON)` of the sealed dict
`{"v","envelope_id","counter","ct"}` — no plaintext fields, no identities.

## Queue derivation

```
queue_id = SHA-256("dgv-a2a-queue" || "|" || recipient_id)
```

Deterministic — senders need no out-of-band queue discovery. The relay's
zero-knowledge property is preserved: queues carry no identity; correlating a
queue to a recipient requires knowing `recipient_id` *and* computing the hash
(a relay operator could attempt dictionary guesses on known agent IDs — an
accepted limitation; rotate queue IDs if this matters).

## Failure semantics

| Event | Result |
|---|---|
| Forged envelope signature | gate 403, nothing stored |
| Sender/recipient revoked | gate 403 |
| Swapped ciphertext on relay | recipient `payload_hash` mismatch → refuse, no ack |
| AEAD tamper | decrypt raises → refuse, no ack |
| Wrong recipient key | different shared key → AEAD failure |
| Relay down | envelope stays authorized at gate; delivery retried by sender |
| Gate down | fail-closed by default (see DGV_PARTITION_POLICY) |

## What this does NOT provide (honest non-claims)

- **No post-quantum signatures** — envelopes are Ed25519; libonlystate's WOTS+
  exists but is not integrated in this path.
- **No forward secrecy across key rotation** — rotating an agent's enc key
  changes future shared keys but old ciphertext remains decryptable to anyone
  holding the old private key.
- **No sender anonymity from the gate** — the gate necessarily knows
  sender→recipient to authorize. Only the relay is identity-blind.
- **No traffic-analysis resistance** — timing/size metadata is observable.
- **Queue correlation** — deterministic queue IDs are dictionary-guessable
  (see above).

Verified by `test_a2a_transport.py` (15 checks against a live gate + live
onlystate-relay binary).
