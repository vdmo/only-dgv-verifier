#!/usr/bin/env python3
"""Who may read an A2A inbox and acknowledge an envelope? Runs a real gate (SQLite).

    cargo build -p dgv-gate        (in native/)
    python test_a2a_ack_authz.py   (needs `cryptography`; DGV_GATE_BIN overrides the binary path)
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from dgv_sdk import sign_a2a_envelope
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

EXE = ".exe" if os.name == "nt" else ""
GATE = os.environ.get("DGV_GATE_BIN", os.path.join(HERE, "native", "target", "debug", "dgv-gate" + EXE))
PORT = 7931
BASE = f"http://127.0.0.1:{PORT}"
ADMIN = "ack-authz-test-admin"
failed = []


def check(name, cond, detail=""):
    print("PASS" if cond else "FAIL", name, "" if cond else detail)
    if not cond:
        failed.append(name)


def call(method, path, body=None, admin=False):
    headers = {"Content-Type": "application/json"}
    if admin:
        headers["X-Admin-Key"] = ADMIN
    req = urllib.request.Request(BASE + path, method=method, headers=headers,
                                 data=json.dumps(body).encode() if body is not None else None)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, {"raw": raw.decode(errors="replace")}


def start(workdir, extra):
    env = {k: v for k, v in os.environ.items() if not k.startswith("DGV_")}
    db = os.path.join(workdir, "authz.db").replace("\\", "/")
    env.update({
        "DGV_STORAGE": "sqlite", "DGV_DATABASE_URL": f"sqlite://{db}",
        "DGV_LISTEN_ADDR": f"127.0.0.1:{PORT}", "DGV_ADMIN_KEY": ADMIN, "DGV_RATE_LIMIT_DISABLED": "1",
        "DGV_SIGNING_KEY": os.path.join(workdir, "gate.key"),
    })
    env.update(extra)
    proc = subprocess.Popen([GATE], cwd=workdir, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    for _ in range(80):
        time.sleep(0.25)
        if proc.poll() is not None:
            raise RuntimeError("gate exited during startup")
        try:
            if call("GET", "/health")[0] == 200:
                return proc
        except OSError:
            pass
    proc.kill()
    raise RuntimeError("gate did not become healthy")


def stop(proc):
    proc.terminate()
    proc.wait(timeout=10)


def register(agent_id):
    sk = Ed25519PrivateKey.generate()
    raw = serialization.Encoding.Raw
    seed = sk.private_bytes(raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()).hex()
    pub = sk.public_key().public_bytes(raw, serialization.PublicFormat.Raw).hex()
    status, body = call("POST", "/agents/keys", {"agent_id": agent_id, "public_key_hex": pub}, admin=True)
    assert status == 200, (status, body)
    return seed


def send(seed, envelope_id):
    env = sign_a2a_envelope(seed, envelope_id, "alice", "bob", b"payload", "nonce-" + envelope_id,
                            int(time.time() * 1000) + 60_000)
    status, body = call("POST", "/a2a/send", env)
    assert status == 200, (status, body)


def inbox_ids():
    return [e["envelope_id"] for e in call("GET", "/a2a/inbox/bob")[1].get("envelopes", [])]


def main():
    workdir = tempfile.mkdtemp(prefix="dgv-authz-")
    gate = None
    try:
        # 1. recipient binding (development mode: unauthenticated A2A explicitly allowed)
        gate = start(workdir, {"DGV_A2A_ALLOW_UNAUTHENTICATED": "1"})
        alice = register("alice")
        register("bob")
        register("mallory")
        send(alice, "env-1")

        status, body = call("POST", "/a2a/ack/env-1", {"agent_id": "mallory"})
        check("another agent cannot acknowledge bob's envelope", status != 200, f"{status} {body}")
        check("the envelope is still waiting for bob", "env-1" in inbox_ids())
        status, body = call("POST", "/a2a/ack/env-1", {})
        check("an ack without agent_id is refused", status != 200, f"{status} {body}")
        status, body = call("POST", "/a2a/ack/env-1", {"agent_id": "bob"})
        check("the recipient can acknowledge", status == 200, f"{status} {body}")
        check("acknowledged envelope leaves the inbox", "env-1" not in inbox_ids())
        status, _ = call("POST", "/a2a/ack/env-1", {"agent_id": "bob"})
        check("a second ack is refused", status == 409, str(status))
        stop(gate)

        # 2. default: no JWT configured and no opt-in -> inbox and ack are closed
        gate = start(workdir, {})
        send(alice, "env-2")
        status, body = call("GET", "/a2a/inbox/bob")
        check("without authentication the inbox is closed by default", status == 401, f"{status} {body}")
        status, body = call("POST", "/a2a/ack/env-2", {"agent_id": "bob"})
        check("without authentication ack is closed by default", status == 401, f"{status} {body}")
    finally:
        if gate and gate.poll() is None:
            stop(gate)
        shutil.rmtree(workdir, ignore_errors=True)
    print(f"\n{len(failed)} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
