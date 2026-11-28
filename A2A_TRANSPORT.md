# A2A Sealed Transport — `dgv-sealed-v3`

> **Security notice.** `dgv-sealed-v1` and `dgv-sealed-v2` are withdrawn.
> v1 used the same key and nonce for both directions between two agents (and
> again if a counter repeated), which exposes message contents. v2's
> "post-quantum" layer added no post-quantum protection, and its forward
> secrecy did not hold if the recipient's key was stolen. Treat anything sent
> with v1 or v2 as potentially readable, and rotate any secrets it carried.

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

## Sealed payload — `dgv-sealed-v3`

HPKE (RFC 9180), base mode, from the `cryptography` library (tested with
50.0.2): DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305.

```
LP(f1, f2, ...) = for each field: len(f) as 8 bytes big-endian || f
info = LP("dgv-sealed-v3", sender_x25519_pk, recipient_x25519_pk,
          envelope_id, counter_be8)
ct   = HPKE-Seal(recipient_x25519_pk, info, plaintext)   # enc || ciphertext
```

- Each message uses a fresh ephemeral key, so keys and nonces do not repeat
  even if `counter` does. `counter` is still carried for the relay.
- **HPKE base mode does not authenticate the sender.** The recipient MUST verify
  the sender's Ed25519 envelope signature (which covers `payload_hash`) against
  the sender's registry key. `recv_sealed_a2a` does this before opening.
- Old v1/v2 messages open only with `allow_legacy=True`.

## Hash binding

```
payload_hash = SHA-256(LP("dgv-sealed-v3", envelope_id, counter_be8, ct))
```

The recipient MUST check `sealed_payload_hash(received) == envelope.payload_hash`
before opening. A swapped ciphertext fails this check.

## Inbox and ack authorization

`POST /a2a/ack/:envelope_id` only marks an envelope whose recipient equals the
caller's `agent_id`. With JWT configured, `agent_id` must equal the verified
subject. Without JWT, inbox and ack return 401 unless the gate is started with
`DGV_A2A_ALLOW_UNAUTHENTICATED=1`, a development-only setting in which
`agent_id` is self-declared and anyone who knows it can act as that agent.

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

## What this does NOT provide

- **No post-quantum protection** — neither encryption (X25519) nor signatures
  (Ed25519).
- **No forward secrecy against the recipient's key** — whoever obtains the
  recipient's X25519 private key can open the messages sealed to it.
- **No independent security review** of this protocol.
- **Gate receipts are narrow** — the delivery receipt signs the envelope,
  sender and recipient IDs, not the payload hash or time.
- **Envelope signing string** — fields are joined with `|` without escaping.
- **No sender anonymity from the gate**, and **no traffic-analysis resistance**.
- **Queue correlation** — deterministic queue IDs are dictionary-guessable.

Sealing is covered by `test_a2a_security.py`, inbox and ack authorization by
`test_a2a_ack_authz.py`, and the gate + relay path by `test_a2a_transport.py`.
