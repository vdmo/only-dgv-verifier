#!/usr/bin/env python3
"""Security regression tests for A2A payload sealing. No gate or relay needed.

    python test_a2a_security.py        (needs `cryptography` with HPKE support)

The legacy vectors below were produced by the old dgv-sealed-v1 / v2 code with
throwaway test keys, so that old messages stay readable on explicit request.
"""

import base64
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dgv_sdk as sdk
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

LEGACY = {
    "sender_public": "8ed4591f1cd953c4a72796393202fe9672581e256dc0c5ec5414fa302f7f3161",
    "recipient_private": "38d8f4bce99bfb786625b44908b6c874b3a35b7e12a19c2e976050e0522b9e7b",
    "v1": {"v": "dgv-sealed-v1", "envelope_id": "legacy-env-1", "counter": 5,
           "ct": "StjA2Vww7iazCK5OBFyuKqUueE6gEQbZLBxvGztTloXPd8sEbB4="},
    "v2": {"v": "dgv-sealed-v2", "envelope_id": "legacy-env-2", "counter": 6,
           "eph_pk": "a1f693ff62e229ce0358fa11040b4aadd509e09556acc9ca99c6b4964b0e3453", "pq_used": False,
           "ct": "nivai9+1FB5JrnEAoPyFyAQADqGZoQOWsIX4kkP8Z7BzRtEByt4="},
}

results = []


def test(fn):
    try:
        fn()
        results.append((True, fn.__name__, ""))
    except Exception as e:  # noqa: BLE001 - a test runner reports everything
        results.append((False, fn.__name__, f"{type(e).__name__}: {e}"))
    return fn


def must_raise(call):
    try:
        call()
    except Exception:
        return
    raise AssertionError("expected an error, got success")


def agents():
    return sdk.generate_enc_keypair(), sdk.generate_enc_keypair()


def seal(frm, to, envelope_id, counter, text, **kw):
    return sdk.seal_a2a_payload(frm["private_key_hex"], to["public_key_hex"], envelope_id, counter, text, **kw)


def open_(by, frm, sealed, **kw):
    return sdk.open_a2a_payload(by["private_key_hex"], frm["public_key_hex"], sealed, **kw)


def keystream_reused(s1, p1, s2, p2):
    """With a reused (key, nonce), c1 XOR c2 equals p1 XOR p2."""
    c1, c2 = base64.b64decode(s1["ct"]), base64.b64decode(s2["ct"])
    n = min(len(p1), len(p2))
    want = bytes(x ^ y for x, y in zip(p1, p2))[:n]
    # try every plausible header length (v1: none; HPKE: 32-byte encapsulated key)
    return any(bytes(x ^ y for x, y in zip(c1[off:], c2[off:]))[:n] == want for off in (0, 32))


P1 = b"PAY 100 to the approved vendor"
P2 = b"the code word for today: orchid"


@test
def opposite_directions_with_same_counter_do_not_share_a_keystream():
    a, b = agents()
    s1, s2 = seal(a, b, "e1", 1, P1), seal(b, a, "e2", 1, P2)
    assert not keystream_reused(s1, P1, s2, P2), "key and nonce reused between A->B and B->A"


@test
def a_restarted_counter_does_not_share_a_keystream():
    a, b = agents()
    s1, s2 = seal(a, b, "e1", 1, P1), seal(a, b, "e2", 1, P2)
    assert not keystream_reused(s1, P1, s2, P2), "key and nonce reused when the counter repeats"


@test
def sealing_identical_input_twice_gives_different_ciphertext():
    a, b = agents()
    assert seal(a, b, "e", 1, P1)["ct"] != seal(a, b, "e", 1, P1)["ct"]


@test
def default_version_is_v3_and_roundtrips_both_directions():
    a, b = agents()
    for frm, to in ((a, b), (b, a)):
        s = seal(frm, to, "e", 3, P1)
        assert s["v"] == "dgv-sealed-v3", s["v"]
        assert open_(to, frm, s) == P1


@test
def tamper_wrong_keys_and_changed_context_are_rejected():
    a, b = agents()
    c = sdk.generate_enc_keypair()
    s = seal(a, b, "e", 3, P1)
    raw = bytearray(base64.b64decode(s["ct"]))
    raw[-1] ^= 1
    must_raise(lambda: open_(b, a, {**s, "ct": base64.b64encode(bytes(raw)).decode()}))
    must_raise(lambda: open_(c, a, s))                                  # wrong recipient
    must_raise(lambda: open_(b, c, s))                                  # claimed from someone else
    must_raise(lambda: open_(a, b, s))                                  # reflected back
    must_raise(lambda: open_(b, a, {**s, "envelope_id": "other"}))      # moved to another envelope
    must_raise(lambda: open_(b, a, {**s, "counter": 4}))                # counter changed


@test
def old_formats_cannot_be_used_to_send():
    a, b = agents()
    must_raise(lambda: seal(a, b, "e", 1, P1, version="dgv-sealed-v1"))
    must_raise(lambda: seal(a, b, "e", 1, P1, version="dgv-sealed-v2"))
    must_raise(lambda: sdk.seal_a2a_v2_payload(a["private_key_hex"], b["public_key_hex"], "e", 1, P1))


@test
def the_placeholder_post_quantum_layer_is_gone():
    a, b = agents()
    must_raise(sdk.generate_pq_keypair)
    must_raise(lambda: seal(a, b, "e", 1, P1, recipient_pq_public_hex="00" * 32))


@test
def old_messages_open_only_when_asked_for():
    keys = (LEGACY["recipient_private"], LEGACY["sender_public"])
    for v in ("v1", "v2"):
        must_raise(lambda: sdk.open_a2a_payload(*keys, LEGACY[v]))
        assert sdk.open_a2a_payload(*keys, LEGACY[v], allow_legacy=True) == f"legacy {v} test message".encode()


@test
def payload_hash_does_not_confuse_field_boundaries():
    base = {"v": "dgv-sealed-v3", "counter": 1, "ct": base64.b64encode(b"x" * 48).decode()}
    shifted = {**base, "envelope_id": "a"}
    other = {**base, "envelope_id": "a\x00"}
    assert sdk.sealed_payload_hash(shifted) != sdk.sealed_payload_hash(other)


def ed25519():
    sk = Ed25519PrivateKey.generate()
    raw, enc = serialization.Encoding.Raw, serialization.PublicFormat.Raw
    seed = sk.private_bytes(raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()).hex()
    return seed, sk.public_key().public_bytes(raw, enc).hex()


def deliver(forge):
    """Run recv_sealed_a2a against a fake gate and relay. `forge` signs the envelope with a key that is not the sender's."""
    a, b = agents()
    sign_sk, sign_pk = ed25519()
    sealed = seal(a, b, "env-r", 1, P1)
    env = sdk.sign_a2a_envelope(ed25519()[0] if forge else sign_sk, "env-r", "agent-a", "agent-b", b"", "n-1", 2**62)
    env["payload_hash"] = sdk.sealed_payload_hash(sealed)
    key = ed25519()[0] if forge else sign_sk
    canonical = sdk.a2a_canonical_string("env-r", "agent-a", "agent-b", env["payload_hash"], "n-1",
                                         env["sent_unix_ms"], env["expires_unix_ms"])
    sig = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(key)).sign(canonical.encode()).hex()
    record = {**env, "sender_signature": sig, "transport_ref": "relay:http://unused|q"}
    acked = []

    class FakeGate:
        def a2a_inbox(self, agent_id):
            return [record]

        def get_agent_key(self, agent_id):
            return {"public_key_hex": sign_pk, "enc_public_key_hex": a["public_key_hex"]}

        def a2a_ack(self, envelope_id, agent_id):
            acked.append(envelope_id)

    original, sdk.relay_recv = sdk.relay_recv, lambda *args, **kw: sealed
    try:
        return sdk.recv_sealed_a2a(FakeGate(), "agent-b", b["private_key_hex"], "http://unused"), acked
    finally:
        sdk.relay_recv = original


@test
def recipient_accepts_an_envelope_signed_by_the_sender():
    got, acked = deliver(forge=False)
    assert got["plaintext"] == P1 and acked == ["env-r"]


@test
def recipient_rejects_an_envelope_the_sender_did_not_sign():
    try:
        deliver(forge=True)
    except ValueError as e:
        assert "signature" in str(e), str(e)
        return
    raise AssertionError("forged envelope was opened and acknowledged")


for ok, name, why in results:
    print("PASS" if ok else "FAIL", name, why)
failed = sum(not r[0] for r in results)
print(f"\n{len(results) - failed} passed, {failed} failed")
sys.exit(1 if failed else 0)
