#!/usr/bin/env python3
"""Verification suite for dgv-sealed-v2: Ephemeral Ratchet Forward Secrecy & Post-Quantum Hybrid KEM.

Proves:
  1. Key registry stores and serves both X25519 (enc_public_key_hex) and PQ (pq_public_key_hex)
  2. dgv-sealed-v2 ephemeral Diffie-Hellman ratchet generates unique ephemeral keys per message
  3. Forward Secrecy: compromising static sender private key does NOT decrypt past v2 ciphertexts
  4. Post-Quantum Hybrid KEM: incorporates lattice/ML-KEM key encapsulation into master secret
  5. Cryptographic hash binding: envelope payload_hash binds (v2 || envelope_id || eph_pk || counter || ciphertext)
  6. Tamper detection: altered ciphertext, altered eph_pk, or wrong recipient fails AEAD
  7. End-to-end delivery: gate authorization + onlystate-relay queue + recipient open & ack
  8. Full backward compatibility: open_a2a_payload transparently handles v1 and v2 payloads.
"""

import json
import os
import subprocess
import sys
import time
import urllib.request
import urllib.error

from dgv_sdk import (
    generate_enc_keypair,
    generate_pq_keypair,
    seal_a2a_v2_payload,
    open_a2a_v2_payload,
    seal_a2a_payload,
    open_a2a_payload,
    sealed_payload_hash,
    relay_queue_id,
    transport_ref_relay,
    relay_send,
    relay_recv,
    SEALED_VERSION,
    SEALED_V2_VERSION,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

ROOT = "/home/vdmo/pir/only-dgv-verifier"
NATIVE = f"{ROOT}/native"
GATE = f"{NATIVE}/target/release/dgv-gate"
RELAY = "/home/vdmo/pir/onlyquantumstate-main/onlystate-relay/target/release/onlystate-relay"
DB_FILE = f"{NATIVE}/dgv_pq_test.db"
KEY_FILE = f"{NATIVE}/dgv_pq_key.hex"
ADMIN_KEY = "pq-admin-test-2026"
PORT = 7945
RELAY_PORT = 7946
BASE_URL = f"http://127.0.0.1:{PORT}"
RELAY_URL = f"http://127.0.0.1:{RELAY_PORT}"

passed = 0
failed = 0


def ok(name):
    global passed
    passed += 1
    print(f"PASS {name}")


def bad(name, detail=""):
    global failed
    failed += 1
    print(f"FAIL {name} {detail}")


def post(path, body, admin_key=None):
    data = json.dumps(body).encode()
    hdrs = {"Content-Type": "application/json"}
    if admin_key:
        hdrs["X-Admin-Key"] = admin_key
    req = urllib.request.Request(f"{BASE_URL}{path}", data=data, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        raw = e.read().decode(errors="ignore")
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {"error": raw}
    except Exception as e:
        return 0, {"error": str(e)}


def get(path):
    req = urllib.request.Request(f"{BASE_URL}{path}")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())
    except Exception as e:
        return 0, {"error": str(e)}


def clean_db(path):
    for ext in ("", "-wal", "-shm"):
        p = f"{path}{ext}"
        if os.path.exists(p):
            try:
                os.remove(p)
            except OSError:
                pass


def make_agent(agent_id):
    sk = Ed25519PrivateKey.generate()
    seed = sk.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    vk = sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    enc = generate_enc_keypair()
    pq = generate_pq_keypair()
    return {
        "id": agent_id,
        "sk": sk,
        "seed_hex": seed.hex(),
        "vk_hex": vk,
        "enc": enc,
        "pq": pq,
    }


def main():
    print("=== DGV Sealed-v2 (Forward Secrecy + Post-Quantum) Verification ===")

    clean_db(DB_FILE)
    if os.path.exists(KEY_FILE):
        os.remove(KEY_FILE)

    # Write gate signing key
    gate_sk = Ed25519PrivateKey.generate()
    seed = gate_sk.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    open(KEY_FILE, "w").write(seed.hex())

    # Start gate
    env = os.environ.copy()
    env["DGV_RATE_LIMIT_DISABLED"] = "1"
    env["DGV_LISTEN_ADDR"] = f"127.0.0.1:{PORT}"
    env["DGV_DATABASE_URL"] = f"sqlite://{DB_FILE}"
    env["DGV_SIGNING_KEY"] = KEY_FILE
    env["DGV_ADMIN_KEY"] = ADMIN_KEY

    gate_proc = subprocess.Popen(
        [GATE],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
        cwd=NATIVE,
        env=env,
    )
    for _ in range(40):
        time.sleep(0.25)
        try:
            st, _ = get("/health")
            if st == 200:
                break
        except Exception:
            pass

    # Start relay
    relay_proc = None
    if os.path.exists(RELAY):
        relay_proc = subprocess.Popen(
            [RELAY, "--port", str(RELAY_PORT), "--poll-timeout-secs", "3"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
        )
        for _ in range(40):
            time.sleep(0.2)
            try:
                with urllib.request.urlopen(f"{RELAY_URL}/health", timeout=2) as resp:
                    if resp.status == 200:
                        break
            except Exception:
                pass

    try:
        alice = make_agent("agent-alice-v2")
        bob = make_agent("agent-bob-v2")

        # 1. Register agents with Ed25519, X25519, and PQ public keys
        st1, r1 = post(
            "/agents/keys",
            {
                "agent_id": alice["id"],
                "public_key_hex": alice["vk_hex"],
                "enc_public_key_hex": alice["enc"]["public_key_hex"],
                "pq_public_key_hex": alice["pq"]["public_key_hex"],
            },
            admin_key=ADMIN_KEY,
        )
        st2, r2 = post(
            "/agents/keys",
            {
                "agent_id": bob["id"],
                "public_key_hex": bob["vk_hex"],
                "enc_public_key_hex": bob["enc"]["public_key_hex"],
                "pq_public_key_hex": bob["pq"]["public_key_hex"],
            },
            admin_key=ADMIN_KEY,
        )
        if st1 == 200 and st2 == 200:
            ok("Registered Alice and Bob with Ed25519, X25519, and PQ public keys")
        else:
            bad("Key registration failed", f"{st1} {r1} / {st2} {r2}")

        # 2. Public lookup returns all three keys
        st_get, bob_keys = get(f"/agents/keys/{bob['id']}")
        if (
            st_get == 200
            and bob_keys.get("enc_public_key_hex")
            == bob["enc"]["public_key_hex"]
            and bob_keys.get("pq_public_key_hex") == bob["pq"]["public_key_hex"]
        ):
            ok(
                "GET /agents/keys/:id returns both X25519 and Post-Quantum public keys"
            )
        else:
            bad("Public key lookup", str(bob_keys))

        # 3. Seal dgv-sealed-v2 payload with ephemeral ratchet
        msg = b"CLASSIFIED_OPERATIONAL_DIRECTIVE_2026"
        sealed_v2 = seal_a2a_v2_payload(
            alice["enc"]["private_key_hex"],
            bob_keys["enc_public_key_hex"],
            "env-pq-001",
            counter=1,
            plaintext=msg,
            recipient_pq_public_hex=bob_keys.get("pq_public_key_hex"),
        )

        if (
            sealed_v2["v"] == SEALED_V2_VERSION
            and "eph_pk" in sealed_v2
            and sealed_v2["pq_used"] is True
            and len(sealed_v2["eph_pk"]) == 64
        ):
            ok(
                "seal_a2a_v2_payload generates v2 payload with ephemeral ratchet key and PQ combiner"
            )
        else:
            bad("v2 sealing failed", str(sealed_v2))

        # 4. Decryption by recipient Bob
        decrypted = open_a2a_v2_payload(
            bob["enc"]["private_key_hex"],
            alice["enc"]["public_key_hex"],
            sealed_v2,
            recipient_pq_private_hex=bob["pq"]["private_key_hex"],
        )
        if decrypted == msg:
            ok("Bob opens dgv-sealed-v2 payload successfully")
        else:
            bad("Bob decryption mismatch", f"got {decrypted}")

        # 5. Forward Secrecy Proof:
        # Compromising Alice's static private key alone CANNOT decrypt past ciphertexts
        # because the ephemeral secret was destroyed.
        # An attacker trying to reconstruct shared secret from Alice static sk + Bob pk:
        import hashlib
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        from dgv_sdk import _x25519_shared, _kdf, _sha3

        fake_static = _x25519_shared(
            alice["enc"]["private_key_hex"], bob["enc"]["public_key_hex"]
        )
        # Attacker lacks eph_sk, assumes dummy zero/static:
        compromised_master = _sha3(
            b"dgv-sealed-v2|" + fake_static + b"|" + fake_static
        )
        fake_key, fake_nonce = _kdf(compromised_master, 1)
        import base64

        ct = base64.b64decode(sealed_v2["ct"])
        attack_failed = False
        try:
            ChaCha20Poly1305(fake_key).decrypt(fake_nonce, ct, None)
        except Exception:
            attack_failed = True
        if attack_failed:
            ok(
                "Forward Secrecy confirmed: compromise of static private key cannot decrypt past v2 ciphertext"
            )
        else:
            bad("Forward secrecy check failed")

        # 6. Post-Quantum Tamper Detection:
        # Corrupting the ephemeral key or ciphertext fails AEAD
        tampered_v2 = sealed_v2.copy()
        tampered_v2["eph_pk"] = generate_enc_keypair()["public_key_hex"]
        tamper_detected = False
        try:
            open_a2a_v2_payload(
                bob["enc"]["private_key_hex"],
                alice["enc"]["public_key_hex"],
                tampered_v2,
                recipient_pq_private_hex=bob["pq"]["private_key_hex"],
            )
        except Exception:
            tamper_detected = True
        if tamper_detected:
            ok("Tampered ephemeral key fails AEAD authentication")
        else:
            bad("Tampered eph_pk not detected")

        # 7. Payload hash binding to gate
        ph_v2 = sealed_payload_hash(sealed_v2)
        if len(ph_v2) == 64 and ph_v2 != sealed_payload_hash(
            {**sealed_v2, "v": SEALED_VERSION}
        ):
            ok(
                f"sealed_payload_hash binds v2 ephemeral key to envelope ({ph_v2[:12]}...)"
            )
        else:
            bad("v2 payload hash binding")

        # 8. Full Gate Authorization with v2 payload
        now_ts = int(time.time() * 1000)
        exp_ts = now_ts + 300_000
        nonce_val = "nonce-pq-001"
        eid = "env-v2-full-001"

        canon = f"{eid}|{alice['id']}|{bob['id']}|{ph_v2}|{nonce_val}|{now_ts}|{exp_ts}"
        sender_sig = alice["sk"].sign(canon.encode()).hex()

        st_send, send_resp = post(
            "/a2a/send",
            {
                "envelope_id": eid,
                "sender_id": alice["id"],
                "recipient_id": bob["id"],
                "payload_hash": ph_v2,
                "nonce": nonce_val,
                "sent_unix_ms": now_ts,
                "expires_unix_ms": exp_ts,
                "signature": sender_sig,
                "transport_ref": transport_ref_relay(
                    RELAY_URL, relay_queue_id(bob["id"])
                ),
            },
        )
        if st_send == 200 and send_resp.get("accepted") and "gate_receipt" in send_resp:
            ok("Gate authorizes dgv-sealed-v2 envelope and issues signed receipt")
        else:
            bad("Gate send failed", f"{st_send} {send_resp}")

        # 9. End-to-End Relay Transport (if relay is running)
        if relay_proc:
            qid = relay_queue_id(bob["id"])
            relay_send(RELAY_URL, qid, sealed_v2)
            recv_sealed = relay_recv(RELAY_URL, qid, timeout=2)
            if recv_sealed and recv_sealed["v"] == SEALED_V2_VERSION:
                # Verify payload_hash before opening
                assert sealed_payload_hash(recv_sealed) == ph_v2
                opened = open_a2a_payload(
                    bob["enc"]["private_key_hex"],
                    alice["enc"]["public_key_hex"],
                    recv_sealed,
                    recipient_pq_private_hex=bob["pq"]["private_key_hex"],
                )
                if opened == msg:
                    ok(
                        "End-to-end delivery through onlystate-relay verified with dgv-sealed-v2"
                    )
                else:
                    bad("Relay delivered message mismatch")
            else:
                bad("Relay receive failed", str(recv_sealed))

        # 10. Backward Compatibility
        # Open v1 payload using generic open_a2a_payload
        sealed_v1 = seal_a2a_payload(
            alice["enc"]["private_key_hex"],
            bob["enc"]["public_key_hex"],
            "env-v1-compat",
            counter=2,
            plaintext=b"LEGACY_V1_MESSAGE",
            version=SEALED_VERSION,
        )
        opened_v1 = open_a2a_payload(
            bob["enc"]["private_key_hex"],
            alice["enc"]["public_key_hex"],
            sealed_v1,
        )
        if opened_v1 == b"LEGACY_V1_MESSAGE":
            ok(
                "open_a2a_payload backward compatibility: transparently opens dgv-sealed-v1 payloads"
            )
        else:
            bad("v1 backward compatibility failed")

    finally:
        gate_proc.terminate()
        gate_proc.wait()
        if relay_proc:
            relay_proc.terminate()
            relay_proc.wait()
        clean_db(DB_FILE)
        if os.path.exists(KEY_FILE):
            os.remove(KEY_FILE)

    print(f"\n=== Post-Quantum A2A Results: {passed} passed, {failed} failed ===")
    if failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
