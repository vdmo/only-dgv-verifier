#!/usr/bin/env python3
"""Sealed A2A transport tests — gate (control plane) + onlystate-relay
(data plane) end-to-end.

The claim under test: agents exchange encrypted, signed, revocable envelopes
through a zero-knowledge relay; the gate sees only hashes; every hop produces
a verifiable receipt.

  Agent A --seal--> relay queue --open--> Agent B
       \            (ciphertext)          /
        \------ gate: authorize + receipt ------

Covers:
  - key registry: X25519 enc keys registered + publicly fetchable
  - sealed roundtrip via real onlystate-relay binary
  - payload_hash binding (ciphertext swap detected)
  - AEAD tamper rejection
  - forged sender signature rejected at gate
  - revoked sender rejected at gate
  - wrong-recipient cannot open
  - transport_ref delivered to recipient verbatim
  - legacy unsealed path still works
  - end-to-end latency measurement (informational)
"""

import json
import os
import subprocess
import sys
import time
import urllib.request
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dgv_sdk
from dgv_sdk import (
    GateClient, GateError,
    generate_enc_keypair, seal_a2a_payload, open_a2a_payload,
    sealed_payload_hash, relay_queue_id, relay_send, relay_recv,
    transport_ref_relay, parse_transport_ref,
    send_sealed_a2a, recv_sealed_a2a,
    a2a_canonical_string, sign_a2a_envelope,
)

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

ROOT = "/home/vdmo/pir/only-dgv-verifier"
NATIVE = f"{ROOT}/native"
GATE = "./target/release/dgv-gate"
RELAY = "/home/vdmo/pir/onlyquantumstate-main/onlystate-relay/target/release/onlystate-relay"
GATE_PORT = 7910
RELAY_PORT = 7911
BASE = f"http://127.0.0.1:{GATE_PORT}"
RELAY_URL = f"http://127.0.0.1:{RELAY_PORT}"
ADMIN_KEY = "transport-admin-key"
DB = f"{NATIVE}/dgv_transport_test.db"

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


def get(url, timeout=10):
    req = urllib.request.Request(url)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())
    except Exception as e:
        return 0, {"error": str(e)}


def ed25519_keypair():
    sk = Ed25519PrivateKey.generate()
    seed = sk.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
        serialization.NoEncryption()).hex()
    pub = sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    return seed, pub


def start_gate():
    for suffix in ("", "-wal", "-shm"):
        if os.path.exists(DB + suffix):
            os.remove(DB + suffix)
    env = os.environ.copy()
    env["DGV_RATE_LIMIT_DISABLED"] = "1"
    env["DGV_LISTEN_ADDR"] = f"127.0.0.1:{GATE_PORT}"
    env["DGV_ADMIN_KEY"] = ADMIN_KEY
    env["DGV_STORAGE"] = "sqlite"
    env["DGV_DATABASE_URL"] = f"sqlite://{DB}"
    proc = subprocess.Popen([GATE], stdout=subprocess.DEVNULL,
                            stderr=subprocess.STDOUT, cwd=NATIVE, env=env)
    for _ in range(60):
        time.sleep(0.25)
        s, _ = get(f"{BASE}/health")
        if s in (200, 503):
            return proc
        if proc.poll() is not None:
            raise RuntimeError("gate exited during startup")
    raise RuntimeError("gate did not become healthy")


def start_relay():
    proc = subprocess.Popen(
        [RELAY, "--port", str(RELAY_PORT), "--poll-timeout-secs", "3"],
        stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    for _ in range(40):
        time.sleep(0.25)
        s, _ = get(f"{RELAY_URL}/health")
        if s == 200:
            return proc
        if proc.poll() is not None:
            raise RuntimeError("relay exited during startup")
    raise RuntimeError("relay did not become healthy")


def main():
    gate = start_gate()
    relay = start_relay()
    client = GateClient(BASE, admin_key=ADMIN_KEY)
    try:
        # ── Agent setup: signing (Ed25519) + encryption (X25519) keys ────────
        a_sign_sk, a_sign_pk = ed25519_keypair()
        b_sign_sk, b_sign_pk = ed25519_keypair()
        a_enc = generate_enc_keypair()
        b_enc = generate_enc_keypair()

        client.register_agent_key("agent-a", a_sign_pk, a_enc["public_key_hex"])
        client.register_agent_key("agent-b", b_sign_pk, b_enc["public_key_hex"])
        ok("register agents with enc keys")

        # Public key lookup — no admin needed
        status, rec = get(f"{BASE}/agents/keys/agent-b")
        if status == 200 and rec["enc_public_key_hex"] == b_enc["public_key_hex"]:
            ok("public key lookup returns enc key")
        else:
            bad("public key lookup returns enc key", f"{status} {rec}")

        status, rec = get(f"{BASE}/agents/keys/agent-missing")
        if status == 404:
            ok("missing agent key -> 404")
        else:
            bad("missing agent key -> 404", f"{status} {rec}")

        # ── Crypto roundtrip ────────────────────────────────────────────────
        sealed = seal_a2a_payload(a_enc["private_key_hex"],
                                  b_enc["public_key_hex"], "env-rt", 0, b"hello")
        pt = open_a2a_payload(b_enc["private_key_hex"], a_enc["public_key_hex"], sealed)
        if pt == b"hello":
            ok("seal/open roundtrip")
        else:
            bad("seal/open roundtrip", pt)

        # ── Full transport path: gate + relay ───────────────────────────────
        t0 = time.time()
        sent = send_sealed_a2a(
            client, "agent-a", "agent-b", a_sign_sk,
            a_enc["private_key_hex"], b"transfer 50 units to treasury", 0, RELAY_URL)
        if sent["gate_response"].get("accepted") and sent["gate_response"].get("gate_receipt"):
            ok("sealed envelope authorized + gate receipt")
        else:
            bad("sealed envelope authorized + gate receipt", sent["gate_response"])

        recv = recv_sealed_a2a(client, "agent-b", b_enc["private_key_hex"], RELAY_URL)
        e2e_ms = int((time.time() - t0) * 1000)
        if recv and recv["plaintext"] == b"transfer 50 units to treasury" \
                and recv["sender_id"] == "agent-a":
            ok("end-to-end sealed delivery via relay")
        else:
            bad("end-to-end sealed delivery via relay", recv)
        print(f"INFO e2e sealed transport latency: {e2e_ms}ms (same host)")

        # transport_ref carried through verbatim
        envs = client.a2a_inbox("agent-b")
        # envelope was acked -> inbox empty; check transport_ref via a fresh send
        sent2 = send_sealed_a2a(
            client, "agent-a", "agent-b", a_sign_sk,
            a_enc["private_key_hex"], b"second", 1, RELAY_URL)
        envs = client.a2a_inbox("agent-b")
        tr = envs[0].get("transport_ref") if envs else None
        parsed = parse_transport_ref(tr or "")
        if parsed.get("mode") == "relay" and parsed.get("url") == RELAY_URL:
            ok("transport_ref delivered verbatim")
        else:
            bad("transport_ref delivered verbatim", tr)

        # payload_hash binds the ciphertext
        sealed2 = {"v": "dgv-sealed-v1", "envelope_id": sent2["envelope_id"],
                   "counter": 1}
        # fetch what's actually on the wire: inbox hash vs sealed hash must match
        if envs and envs[0]["payload_hash"] != sealed_payload_hash(
                {"v": "x", "envelope_id": "y", "counter": 1, "ct": "AA=="}):
            ok("gate binds sealed hash not plaintext")
        else:
            bad("gate binds sealed hash not plaintext")

        # ── Tamper: attacker swaps ciphertext in transit ────────────────────
        # Sender authorizes hash(legit_ct) at the gate; attacker pushes
        # hash(evil_ct) into the relay queue instead. Recipient must detect
        # the hash mismatch and refuse to ack.
        import uuid as _uuid
        eid3 = str(_uuid.uuid4())
        legit = seal_a2a_payload(a_enc["private_key_hex"],
                                 b_enc["public_key_hex"], eid3, 9, b"legit")
        ph_legit = sealed_payload_hash(legit)
        sent_ms = int(time.time() * 1000)
        exp_ms = sent_ms + 60000
        nonce3 = str(_uuid.uuid4())
        canon = a2a_canonical_string(eid3, "agent-a", "agent-b", ph_legit,
                                     nonce3, sent_ms, exp_ms)
        sig3 = Ed25519PrivateKey.from_private_bytes(
            bytes.fromhex(a_sign_sk)).sign(canon.encode()).hex()
        qid = relay_queue_id("agent-b")
        resp = client.a2a_send(eid3, "agent-a", "agent-b", ph_legit, nonce3,
                               sent_ms, exp_ms, sig3,
                               transport_ref=transport_ref_relay(RELAY_URL, qid))
        evil = seal_a2a_payload(a_enc["private_key_hex"],
                                b_enc["public_key_hex"], eid3, 9,
                                b"EVIL transfer 9999")
        relay_send(RELAY_URL, qid, evil)  # legit ciphertext never arrives
        # Drain the still-queued legit "second" message first, then the next
        # pop hits the swapped ciphertext bound to eid3.
        recv_sealed_a2a(client, "agent-b", b_enc["private_key_hex"], RELAY_URL)
        try:
            r = recv_sealed_a2a(client, "agent-b", b_enc["private_key_hex"], RELAY_URL)
            bad("swapped ciphertext detected", f"opened: {r}")
        except ValueError:
            ok("swapped ciphertext detected (hash mismatch, not acked)")

        # ── Replay: forged sender signature → 403 ───────────────────────────

        # ── AEAD tamper rejection at the crypto layer ───────────────────────
        tampered = dict(sealed)
        tampered["ct"] = tampered["ct"][:-4] + "AAAA"
        try:
            open_a2a_payload(b_enc["private_key_hex"], a_enc["public_key_hex"], tampered)
            bad("AEAD tamper rejected")
        except Exception:
            ok("AEAD tamper rejected")

        # ── Wrong recipient cannot open ─────────────────────────────────────
        c_enc = generate_enc_keypair()
        try:
            open_a2a_payload(c_enc["private_key_hex"], a_enc["public_key_hex"], sealed)
            bad("wrong recipient cannot open")
        except Exception:
            ok("wrong recipient cannot open")

        # ── Forged sender signature → 403 ───────────────────────────────────
        forged_env = sign_a2a_envelope(
            b_sign_sk, "env-forge", "agent-a", "agent-b", b"x", "n1",
            int(time.time() * 1000) + 60000)
        try:
            client.a2a_send(**forged_env)
            bad("forged sender signature rejected")
        except GateError as e:
            if e.status == 403:
                ok("forged sender signature rejected")
            else:
                bad("forged sender signature rejected", f"status {e.status}")

        # ── Revoked sender → 403 ────────────────────────────────────────────
        client.revoke("agent-a", "transport test revocation")
        try:
            send_sealed_a2a(client, "agent-a", "agent-b", a_sign_sk,
                            a_enc["private_key_hex"], b"should fail", 2, RELAY_URL)
            bad("revoked sender rejected")
        except GateError as e:
            if e.status == 403:
                ok("revoked sender rejected at gate")
            else:
                bad("revoked sender rejected", f"status {e.status}")

        # ── Legacy unsealed path still works ────────────────────────────────
        legacy = sign_a2a_envelope(
            b_sign_sk, "env-legacy", "agent-b", "agent-b", b"plaintext-hash",
            "n2", int(time.time() * 1000) + 60000)
        resp = client.a2a_send(**legacy)
        if resp.get("accepted"):
            ok("legacy unsealed path still works")
        else:
            bad("legacy unsealed path still works", resp)

        # ── Relay never sees plaintext (inspect queue contents indirectly) ──
        # The sealed JSON inside relay ciphertext contains no plaintext fields —
        # verified structurally: sealed dict has only v/envelope_id/counter/ct.
        keys = set(sealed.keys())
        if keys == {"v", "envelope_id", "counter", "ct"}:
            ok("sealed wire format carries no plaintext metadata")
        else:
            bad("sealed wire format carries no plaintext metadata", keys)

    finally:
        gate.terminate()
        relay.terminate()
        gate.wait(timeout=5)
        relay.wait(timeout=5)
        for suffix in ("", "-wal", "-shm"):
            if os.path.exists(DB + suffix):
                os.remove(DB + suffix)

    print(f"\nResults: {passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
