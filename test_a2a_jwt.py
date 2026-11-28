#!/usr/bin/env python3
"""A2A with login tokens (JWT) switched on: who may read an inbox or acknowledge? Runs a real gate.

    cargo build -p dgv-gate        (in native/)
    python test_a2a_jwt.py         (needs `cryptography`)

Covers HS256 (shared secret) and RS256 (pinned public key). Tokens are made here with throwaway keys.
Not covered: JWKS / OIDC discovery.
"""

import base64
import hashlib
import hmac
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "demo"))
import dgv_sdk as sdk  # noqa: E402
import gate_testlib  # noqa: E402
from a2a_demo import free_port, wait_healthy  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import padding, rsa  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

ADMIN = "jwt-test-admin"
SECRET = "jwt-test-shared-secret-not-for-real-use"
ISSUER = "https://issuer.test.invalid"
AUDIENCE = "dgv-gate-test"
results = []


def check(name, condition, detail=""):
    results.append(bool(condition))
    print("PASS" if condition else "FAIL", name, "" if condition else detail)


def b64(data):
    if isinstance(data, dict):
        data = json.dumps(data, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def token(sub, alg="HS256", key=SECRET, **claims):
    body = {"sub": sub, "iss": ISSUER, "aud": AUDIENCE, "exp": int(time.time()) + 300, **claims}
    body = {k: v for k, v in body.items() if v is not None}
    head = b64({"alg": alg, "typ": "JWT"}) + "." + b64(body)
    if alg == "HS256":
        sig = hmac.new(key if isinstance(key, bytes) else key.encode(), head.encode(), hashlib.sha256).digest()
    elif alg == "RS256":
        sig = key.sign(head.encode(), padding.PKCS1v15(), hashes.SHA256())
    else:
        sig = b""
    return head + "." + b64(sig)


class Gate:
    def __init__(self, work, name, extra):
        port = free_port()
        self.url = f"http://127.0.0.1:{port}"
        env = {k: v for k, v in os.environ.items() if not k.startswith("DGV_")}
        env.update({"DGV_LISTEN_ADDR": f"127.0.0.1:{port}", "DGV_ADMIN_KEY": ADMIN, "DGV_RATE_LIMIT_DISABLED": "1",
                    "DGV_SIGNING_KEY": os.path.join(work, name + ".key"),
                    **gate_testlib.db_env(os.path.join(work, name + ".db")), **extra})
        self.proc = subprocess.Popen([gate_testlib.gate_bin()], cwd=work, env=env,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
        try:
            wait_healthy(self.url, self.proc, "gate")
        except BaseException:
            self.stop()  # never leave a half-started gate behind
            raise

    def call(self, method, path, body=None, bearer=None):
        headers = {"Content-Type": "application/json"}
        if bearer is not None:
            headers["Authorization"] = "Bearer " + bearer
        req = urllib.request.Request(self.url + path, method=method, headers=headers,
                                     data=json.dumps(body).encode() if body is not None else None)
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                return e.code, json.loads(raw)
            except ValueError:
                return e.code, {"raw": raw.decode(errors="replace")}

    def stop(self):
        self.proc.terminate()
        self.proc.wait(timeout=10)


def make_agents(gate, tag):
    admin = sdk.GateClient(gate.url, admin_key=ADMIN, jwt_token=token("test-admin"))
    agents = {}
    for who in ("alice", "bob", "mallory"):
        name = f"{who}-{tag}"
        seed = os.urandom(32)
        pub = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        enc = sdk.generate_enc_keypair()
        admin.register_agent_key(name, pub, enc["public_key_hex"])
        agents[who] = {"id": name, "seed": seed.hex(), "enc": enc}
    return agents


def send(gate, agents):
    a, b = agents["alice"], agents["bob"]
    envelope = sdk.sign_a2a_envelope(a["seed"], str(uuid.uuid4()), a["id"], b["id"], b"x", str(uuid.uuid4()),
                                     int(time.time() * 1000) + 60_000)
    status, body = gate.call("POST", "/a2a/send", envelope)  # no token: the envelope signature authenticates it
    assert status == 200, (status, body)
    return envelope["envelope_id"]


def access_rules(gate, agents, mode, good, bad_tokens):
    """good(sub) makes a valid token for an agent id; bad_tokens maps a description to a token for bob."""
    bob, mallory = agents["bob"]["id"], agents["mallory"]["id"]
    eid = send(gate, agents)
    a = agents["alice"]
    forged = sdk.sign_a2a_envelope(agents["mallory"]["seed"], str(uuid.uuid4()), a["id"], bob, b"x",
                                   str(uuid.uuid4()), int(time.time() * 1000) + 60_000)
    s, _ = gate.call("POST", "/a2a/send", forged, bearer=good(a["id"]))
    check(f"{mode}: a valid token does not make a forged envelope signature acceptable", s == 403, str(s))
    inbox, ack = f"/a2a/inbox/{bob}", f"/a2a/ack/{eid}"

    for label, bearer in [("no token", None), *bad_tokens.items()]:
        s1, _ = gate.call("GET", inbox, bearer=bearer)
        s2, _ = gate.call("POST", ack, {"agent_id": bob}, bearer=bearer)
        check(f"{mode}: {label} cannot read or acknowledge", s1 == 401 and s2 == 401, f"inbox {s1}, ack {s2}")

    s, body = gate.call("GET", inbox, bearer=good(mallory))
    check(f"{mode}: mallory's own token cannot read bob's inbox", s == 403 and "envelopes" not in body, f"{s} {body}")
    s, _ = gate.call("POST", ack, {"agent_id": bob}, bearer=good(mallory))
    check(f"{mode}: mallory cannot acknowledge while claiming to be bob", s == 403, str(s))
    s, _ = gate.call("POST", ack, {"agent_id": mallory}, bearer=good(mallory))
    check(f"{mode}: mallory cannot acknowledge bob's envelope as herself or himself", s == 409, str(s))

    s, body = gate.call("GET", inbox, bearer=good(bob))
    check(f"{mode}: bob reads his inbox, envelope still waiting",
          s == 200 and eid in [e["envelope_id"] for e in body.get("envelopes", [])], f"{s} {body}")
    s, _ = gate.call("POST", ack, {"agent_id": bob}, bearer=good(bob))
    check(f"{mode}: bob acknowledges", s == 200, str(s))


def main():
    work = tempfile.mkdtemp(prefix="dgv-jwt-")
    gate = None
    common = {"DGV_JWT_ISSUER": ISSUER, "DGV_JWT_AUDIENCE": AUDIENCE,
              "DGV_A2A_ALLOW_UNAUTHENTICATED": "1"}  # must make no difference once JWT is configured
    try:
        # ── HS256 ────────────────────────────────────────────────────────────
        gate = Gate(work, "hs", {"DGV_JWT_SECRET": SECRET, **common})
        agents = make_agents(gate, "hs-" + uuid.uuid4().hex[:6])
        bob = agents["bob"]["id"]
        access_rules(gate, agents, "HS256", token, {
            "a wrong secret": token(bob, key="some-other-secret"),
            "an expired token": token(bob, exp=int(time.time()) - 3600),
            "a token with no expiry": token(bob, exp=None),
            "a wrong issuer": token(bob, iss="https://evil.invalid"),
            "a wrong audience": token(bob, aud="another-service"),
            "an unsigned alg=none token": token(bob, alg="none"),
            "garbage": "not-a-token",
        })

        # the SDK path end to end, with bob holding his own token
        a, b = agents["alice"], agents["bob"]
        relay_port = free_port()
        relay = gate_testlib.StandInRelay(relay_port)
        try:
            relay_url = f"http://127.0.0.1:{relay_port}"
            sender = sdk.GateClient(gate.url)
            sdk.send_sealed_a2a(sender, a["id"], b["id"], a["seed"], a["enc"]["private_key_hex"], b"synthetic", 1, relay_url)
            bob_client = sdk.GateClient(gate.url, jwt_token=token(b["id"]))
            got = sdk.recv_sealed_a2a(bob_client, b["id"], b["enc"]["private_key_hex"], relay_url, poll_timeout=10)
            check("HS256: SDK receive works with the recipient's token", got and got["plaintext"] == b"synthetic", str(got))
        finally:
            relay.terminate()
        gate.stop()

        # ── RS256 with a pinned public key ───────────────────────────────────
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = key.public_key().public_bytes(serialization.Encoding.PEM,
                                            serialization.PublicFormat.SubjectPublicKeyInfo)
        gate = Gate(work, "rs", {"DGV_JWT_PUBLIC_KEY": pem.decode(), **common})
        # key registration also goes through a gate with RS256, so the helper needs an RS256 token
        original, globals()["token"] = token, lambda sub, **kw: original(sub, alg="RS256", key=key, **kw)
        try:
            agents = make_agents(gate, "rs-" + uuid.uuid4().hex[:6])
        finally:
            globals()["token"] = original
        bob = agents["bob"]["id"]
        rs = lambda sub, **kw: token(sub, alg="RS256", key=key, **kw)
        access_rules(gate, agents, "RS256", rs, {
            "a token from another key": token(bob, alg="RS256", key=other),
            "an HS256 token signed with the public key (algorithm confusion)": token(bob, alg="HS256", key=pem),
            "an expired token": rs(bob, exp=int(time.time()) - 3600),
        })
    finally:
        if gate and gate.proc.poll() is None:
            gate.stop()
        shutil.rmtree(work, ignore_errors=True)
    failed = results.count(False)
    print(f"\n{results.count(True)} passed, {failed} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
