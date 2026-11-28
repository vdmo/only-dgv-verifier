#!/usr/bin/env python3
"""A2A envelope v2 and receipt v2: format, limits and offline verification.

    python test_a2a_evidence.py                  format + offline verifier (no gate)
    python test_a2a_evidence.py --gate           also against a real gate (cargo build -p dgv-gate)

Vectors in test_vectors/a2a_v2.json use fixed throwaway keys; the gate's Rust tests read the same file.
Needs `cryptography`.
"""

import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import dgv_a2a_v2 as v2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

VECTORS = json.load(open(os.path.join(HERE, "test_vectors", "a2a_v2.json"), encoding="utf-8"))
results = []


def test(name, fn):
    try:
        fn()
        results.append((True, name, ""))
    except Exception as e:  # noqa: BLE001
        results.append((False, name, f"{type(e).__name__}: {e}"))


def public_hex(seed_hex):
    sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))
    return sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def sign(seed_hex, data):
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex)).sign(data).hex()


SENDER = VECTORS["sender_seed_hex"]
GATE = VECTORS["gate_seed_hex"]
GOOD = VECTORS["cases"][0]


def evidence(case=GOOD):
    return copy.deepcopy({"envelope": case["envelope"], "signature": case["signature"],
                          "receipt": case["receipt"], "gate_receipt": case["gate_receipt"]})


def verify(ev, gate_key=None, sender_key=None, **kw):
    return v2.verify_evidence(ev, gate_key or public_hex(GATE), sender_key or public_hex(SENDER), **kw)


def must_fail(call, needle):
    try:
        call()
    except v2.EvidenceError as e:
        assert needle in str(e), f"failed for the wrong reason: {e}"
        return
    raise AssertionError("accepted")


def vectors_match():
    assert len(VECTORS["cases"]) >= 3
    for c in VECTORS["cases"]:
        env = v2.envelope_bytes(c["envelope"])
        assert env.decode() == c["envelope_canonical"], c["name"]
        assert v2.envelope_hash(c["envelope"]) == c["receipt"]["envelope_hash"]
        assert sign(SENDER, env) == c["signature"]
        rec = v2.receipt_bytes(c["receipt"])
        assert rec.decode() == c["receipt_canonical"]
        assert sign(GATE, rec) == c["gate_receipt"]
        verify(evidence(c))


def boundaries_cannot_shift():
    a = {**GOOD["envelope"], "envelope_id": "e|alice", "sender_id": "bob"}
    b = {**GOOD["envelope"], "envelope_id": "e", "sender_id": "alice|bob"}
    assert v2.envelope_bytes(a) != v2.envelope_bytes(b)


def every_envelope_field_is_signed():
    for field in GOOD["envelope"]:
        ev = evidence()
        old = ev["envelope"][field]
        ev["envelope"][field] = old + 1 if isinstance(old, int) else (
            "0" * 64 if field == "payload_hash" else "relay:http://elsewhere|q")
        must_fail(lambda: verify(ev), "")


def every_receipt_field_is_signed():
    for field in GOOD["receipt"]:
        ev = evidence()
        old = ev["receipt"][field]
        ev["receipt"][field] = old + 1 if isinstance(old, int) else "0" * 64
        must_fail(lambda: verify(ev), "")


def extra_or_missing_fields_are_rejected():
    ev = evidence(); ev["receipt"]["note"] = "x"
    must_fail(lambda: verify(ev), "fields")
    ev = evidence(); del ev["envelope"]["transport_ref"]
    must_fail(lambda: verify(ev), "fields")


def only_the_pinned_keys_count():
    other = "99" * 32
    must_fail(lambda: verify(evidence(), gate_key=public_hex(other)), "gate")
    must_fail(lambda: verify(evidence(), sender_key=public_hex(other)), "sender signature")


def a_receipt_cannot_be_moved_to_another_envelope():
    ev = evidence(); other = evidence(VECTORS["cases"][1])
    ev["receipt"], ev["gate_receipt"] = other["receipt"], other["gate_receipt"]
    must_fail(lambda: verify(ev), "envelope")


def a_validly_signed_but_untimely_receipt_is_rejected():
    for when in (GOOD["envelope"]["expires_unix_ms"], GOOD["envelope"]["sent_unix_ms"] - 120_000):
        ev = evidence(); ev["receipt"]["decided_unix_ms"] = when
        ev["gate_receipt"] = sign(GATE, v2.receipt_bytes(ev["receipt"]))
        must_fail(lambda: verify(ev), "time")


def bad_values_cannot_be_encoded():
    for change in ({"envelope_id": ""}, {"sender_id": "x" * 257}, {"payload_hash": "ABC"},
                   {"sent_unix_ms": 2**53}, {"sent_unix_ms": True}, {"expires_unix_ms": 1.5},
                   {"transport_ref": "r" * 2049}, {"nonce": 7}, {"expires_unix_ms": GOOD["envelope"]["sent_unix_ms"]}):
        must_fail(lambda c=change: v2.envelope_bytes({**GOOD["envelope"], **c}), "")


def payload_can_be_checked():
    verify(evidence(), payload=VECTORS["payload"].encode())
    must_fail(lambda: verify(evidence(), payload=b"something else"), "payload")


def command_line_verifier():
    work = tempfile.mkdtemp()
    try:
        good, bad = os.path.join(work, "good.json"), os.path.join(work, "bad.json")
        json.dump(evidence(), open(good, "w"))
        ev = evidence(); ev["receipt"]["decided_unix_ms"] += 1
        json.dump(ev, open(bad, "w"))
        script = os.path.join(HERE, "dgv_a2a_v2.py")
        keys = ["--gate-key", public_hex(GATE), "--sender-key", public_hex(SENDER)]
        run = lambda *a: subprocess.run([sys.executable, script, *a], capture_output=True, text=True, timeout=60)
        r = run(good, *keys); assert r.returncode == 0 and "VERIFIED" in r.stdout, r.stdout + r.stderr
        r = run(bad, *keys); assert r.returncode == 1 and "NOT VERIFIED" in r.stdout, r.stdout + r.stderr
        r = run(good); assert r.returncode == 2, "keys must be required"
        open(bad, "w").write("not json")
        r = run(bad, *keys); assert r.returncode == 1 and "Traceback" not in r.stderr, r.stderr
    finally:
        shutil.rmtree(work, ignore_errors=True)


for fn in (vectors_match, boundaries_cannot_shift, every_envelope_field_is_signed, every_receipt_field_is_signed,
           extra_or_missing_fields_are_rejected, only_the_pinned_keys_count, a_receipt_cannot_be_moved_to_another_envelope,
           a_validly_signed_but_untimely_receipt_is_rejected, bad_values_cannot_be_encoded, payload_can_be_checked,
           command_line_verifier):
    test(fn.__name__, fn)


# ── against a real gate ──────────────────────────────────────────────────────

def gate_tests():
    import dgv_sdk as sdk
    sys.path.insert(0, os.path.join(HERE, "demo"))
    from a2a_demo import find_gate, free_port, wait_healthy

    work = tempfile.mkdtemp(prefix="dgv-evidence-")
    port, admin = free_port(), "evidence-test-admin"
    env = {k: val for k, val in os.environ.items() if not k.startswith("DGV_")}
    env.update({"DGV_STORAGE": "sqlite", "DGV_ADMIN_KEY": admin, "DGV_RATE_LIMIT_DISABLED": "1",
                "DGV_DATABASE_URL": "sqlite://" + os.path.join(work, "g.db").replace("\\", "/"),
                "DGV_LISTEN_ADDR": f"127.0.0.1:{port}", "DGV_SIGNING_KEY": os.path.join(work, "gate.key"),
                "DGV_A2A_ALLOW_UNAUTHENTICATED": "1", "DGV_A2A_MAX_LIFETIME_MS": "120000"})
    proc = subprocess.Popen([find_gate()], cwd=work, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    try:
        url = f"http://127.0.0.1:{port}"
        wait_healthy(url, proc, "gate")
        gate = sdk.GateClient(url, admin_key=admin)
        gate.register_agent_key("alice", public_hex(SENDER))
        gate.register_agent_key("bob", public_hex("22" * 32))
        pinned = gate._request("GET", "/health")["verifying_key"]  # a real verifier gets this beforehand

        def envelope(ttl=60_000, **kw):
            return sdk.sign_a2a_envelope(SENDER, str(uuid.uuid4()), "alice", "bob", b"hello", str(uuid.uuid4()),
                                         int(time.time() * 1000) + ttl, **kw)

        def refused(body, status, needle):
            try:
                gate._request("POST", "/a2a/send", body)
            except sdk.GateError as e:
                assert e.status == status and needle in json.dumps(e.body), (e.status, e.body)
                return
            raise AssertionError("gate accepted")

        def receipt_verifies_offline_and_matches_inbox():
            body = envelope(transport_ref="direct:https://example.invalid/x")
            resp = gate._request("POST", "/a2a/send", body)
            ev = sdk.a2a_evidence(body, resp)
            v2.verify_evidence(ev, pinned, public_hex(SENDER), payload=b"hello")
            rec = next(r for r in gate.a2a_inbox("bob") if r["envelope_id"] == body["envelope_id"])
            assert json.loads(rec["receipt_json"]) == resp["receipt"]
            assert rec["gate_receipt_signature"] == resp["gate_receipt"]

        def old_format_is_refused():
            body = envelope(); del body["version"]
            refused(body, 400, "unsupported_envelope_version")

        def transport_ref_is_signed():
            body = envelope(transport_ref="direct:https://example.invalid/a")
            body["transport_ref"] = "direct:https://example.invalid/b"
            refused(body, 403, "invalid_signature")
            body = envelope(); body["transport_ref"] = "direct:https://example.invalid/added"
            refused(body, 403, "invalid_signature")

        def lifetime_is_capped():
            refused(envelope(ttl=10 * 60_000), 400, "lifetime_too_long")

        def invalid_fields_are_refused():
            for change in ({"nonce": ""}, {"envelope_id": "x" * 300}, {"payload_hash": "zz"},
                           {"expires_unix_ms": 2**53}):
                refused({**envelope(), **change}, 400, "invalid_envelope")

        for fn in (receipt_verifies_offline_and_matches_inbox, old_format_is_refused, transport_ref_is_signed,
                   lifetime_is_capped, invalid_fields_are_refused):
            test("gate: " + fn.__name__, fn)
    finally:
        proc.terminate()
        proc.wait(timeout=10)
        shutil.rmtree(work, ignore_errors=True)


if "--gate" in sys.argv:
    gate_tests()

for ok, name, why in results:
    print("PASS" if ok else "FAIL", name, why)
failed = sum(not r[0] for r in results)
print(f"\n{len(results) - failed} passed, {failed} failed")
sys.exit(1 if failed else 0)
