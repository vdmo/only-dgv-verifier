#!/usr/bin/env python3
"""Token delegation tests — monotonic authority decay.

The claim under test: a parent agent can mint child tokens whose authority is
a strict subset of its own — same tool+action, params ⊆, expiry ≤, approvals
inherited, depth bounded. Every delegation is signed by the delegator's
registered key and recorded as a DelegationRecord on the receipt chain.
Revoking an ancestor kills all delegated authority.

Also verifies the grantee binding: a token is usable only by the agent it was
granted to.
"""

import json
import os
import subprocess
import sys
import time
import urllib.request
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dgv_sdk import GateClient, GateError, delegate_canonical_string

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

ROOT = "/home/vdmo/pir/only-dgv-verifier"
NATIVE = f"{ROOT}/native"
GATE = "./target/release/dgv-gate"
PORT = 7920
BASE = f"http://127.0.0.1:{PORT}"
ADMIN_KEY = "delegation-admin-key"
DB = f"{NATIVE}/dgv_delegation_test.db"

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


def post(path, body, admin=False):
    hdrs = {"Content-Type": "application/json"}
    if admin:
        hdrs["X-Admin-Key"] = ADMIN_KEY
    req = urllib.request.Request(f"{BASE}{path}", data=json.dumps(body).encode(),
                                 headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
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


def sign(seed_hex, msg: str) -> str:
    return Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(seed_hex)).sign(msg.encode()).hex()


def govern(agent_id, req_id, params):
    return post("/govern", {
        "request_id": req_id,
        "agent_id": agent_id,
        "workflow": "delegation-test",
        "tool": "send_email",
        "action": "send",
        "params": params,
        "justification": "delegation test",
        "risk_level": "1000",
        "identity": {},
    })


def execute(token_id, executor_id, params):
    return post("/execute", {
        "token_id": token_id,
        "executor_id": executor_id,
        "tool": "send_email",
        "action": "send",
        "params": params,
    })


def delegate_raw(parent_token_id, delegator_id, delegatee_id, seed_hex,
                 params_hash, expiry, params=None):
    canon = delegate_canonical_string(parent_token_id, delegator_id,
                                      delegatee_id, params_hash, expiry)
    return post("/delegate", {
        "parent_token_id": parent_token_id,
        "delegator_id": delegator_id,
        "delegatee_id": delegatee_id,
        "params": params,
        "expires_unix_ms": expiry,
        "signature": sign(seed_hex, canon),
    })


def params_hash(params):
    import hashlib
    return hashlib.sha256(
        json.dumps(params, separators=(",", ":"), sort_keys=True).encode()
    ).hexdigest()


def start_gate():
    for suffix in ("", "-wal", "-shm"):
        if os.path.exists(DB + suffix):
            os.remove(DB + suffix)
    env = os.environ.copy()
    env["DGV_RATE_LIMIT_DISABLED"] = "1"
    env["DGV_LISTEN_ADDR"] = f"127.0.0.1:{PORT}"
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


def main():
    gate = start_gate()
    client = GateClient(BASE, admin_key=ADMIN_KEY)
    try:
        orch_sk, orch_pk = ed25519_keypair()
        w1_sk, w1_pk = ed25519_keypair()
        w2_sk, w2_pk = ed25519_keypair()
        w3_sk, w3_pk = ed25519_keypair()
        rogue_sk, _ = ed25519_keypair()
        for aid, pk in [("orch", orch_pk), ("w1", w1_pk), ("w2", w2_pk), ("w3", w3_pk)]:
            client.register_agent_key(aid, pk)

        parent_params = {"to": ["a@x.com", "b@x.com"], "subject": "hi", "urgent": True}

        # ── Happy path: subset params, tighter expiry ────────────────────────
        s, gov = govern("orch", "req-p1", parent_params)
        if not (s == 200 and gov["decision"]["gate_state"] == "ALLOW"):
            bad("root govern", f"{s} {gov}")
            raise SystemExit(1)
        tok = gov["decision"]["auth_token"]["token_id"]
        pexp = gov["decision"]["auth_token"]["expires_unix_ms"]
        ok("root token issued")

        child_params = {"to": ["a@x.com"], "subject": "hi"}
        resp = client.delegate(
            parent_token_id=tok, delegator_id="orch", delegatee_id="w1",
            delegator_signing_key_hex=orch_sk,
            parent_params=parent_params, parent_expires_unix_ms=pexp,
            params=child_params, expires_unix_ms=pexp - 1000)
        child_tok = resp.get("child_token_id")
        if resp.get("delegated") and child_tok:
            ok("delegation minted child token")
        else:
            bad("delegation minted child token", resp)

        s, ex = execute(child_tok, "w1", child_params)
        if s == 200 and ex.get("allowed"):
            ok("child token executes narrowed action")
        else:
            bad("child token executes narrowed action", f"{s} {ex}")

        # ── Parent retains its own authority (attenuating copy) ─────────────
        s, ex = execute(tok, "orch", parent_params)
        if s == 200 and ex.get("allowed"):
            ok("parent token still executes (delegation is a copy, not handoff)")
        else:
            bad("parent token still executes", f"{s} {ex}")

        # ── Depth chain: orch → w1 → w2 → w3, depth 4 denied ────────────────
        s, gov = govern("orch", "req-p2", parent_params)
        tok2 = gov["decision"]["auth_token"]["token_id"]
        pexp2 = gov["decision"]["auth_token"]["expires_unix_ms"]
        r = client.delegate(parent_token_id=tok2, delegator_id="orch",
                            delegatee_id="w1", delegator_signing_key_hex=orch_sk,
                            parent_params=parent_params,
                            parent_expires_unix_ms=pexp2, params=child_params)
        t1 = r["child_token_id"]
        r = client.delegate(parent_token_id=t1, delegator_id="w1",
                            delegatee_id="w2", delegator_signing_key_hex=w1_sk,
                            parent_params=child_params,
                            parent_expires_unix_ms=pexp2, params=child_params)
        t2 = r.get("child_token_id")
        r = client.delegate(parent_token_id=t2, delegator_id="w2",
                            delegatee_id="w3", delegator_signing_key_hex=w2_sk,
                            parent_params=child_params,
                            parent_expires_unix_ms=pexp2, params=child_params)
        t3 = r.get("child_token_id")
        if t1 and t2 and t3:
            ok("3-deep delegation chain minted")
        else:
            bad("3-deep delegation chain minted", r)
        try:
            client.delegate(parent_token_id=t3, delegator_id="w3",
                            delegatee_id="w1", delegator_signing_key_hex=w3_sk,
                            parent_params=child_params,
                            parent_expires_unix_ms=pexp2, params=child_params)
            bad("depth 4 delegation denied")
        except GateError as e:
            if e.status == 403:
                ok("depth 4 delegation denied (DGV_MAX_DELEGATION_DEPTH=3)")
            else:
                bad("depth 4 delegation denied", f"status {e.status}")

        # ── Widening attempts all denied ────────────────────────────────────
        # changed value
        s, gov = govern("orch", "req-p3", parent_params)
        tok3 = gov["decision"]["auth_token"]["token_id"]
        pexp3 = gov["decision"]["auth_token"]["expires_unix_ms"]
        wider = {"to": ["a@x.com"], "subject": "DIFFERENT"}
        resp = delegate_raw(tok3, "orch", "w1", orch_sk, params_hash(wider),
                            pexp3, params=wider)
        if resp[0] == 403:
            ok("changed param value denied")
        else:
            bad("changed param value denied", resp)
        # extra key
        wider2 = dict(parent_params, extra="nope")
        resp = delegate_raw(tok3, "orch", "w1", orch_sk, params_hash(wider2),
                            pexp3, params=wider2)
        if resp[0] == 403:
            ok("added param key denied")
        else:
            bad("added param key denied", resp)
        # new array element not in parent's list
        wider3 = dict(parent_params, to=["a@x.com", "z@evil.com"])
        resp = delegate_raw(tok3, "orch", "w1", orch_sk, params_hash(wider3),
                            pexp3, params=wider3)
        if resp[0] == 403:
            ok("added array element denied")
        else:
            bad("added array element denied", resp)
        # expiry exceeds parent
        resp = delegate_raw(tok3, "orch", "w1", orch_sk,
                            params_hash(child_params), pexp3 + 60000,
                            params=child_params)
        if resp[0] == 403:
            ok("expiry exceeding parent denied")
        else:
            bad("expiry exceeding parent denied", resp)

        # ── Forgery: wrong signer / wrong delegator / unregistered ──────────
        resp = delegate_raw(tok3, "orch", "w1", rogue_sk,
                            params_hash(child_params), pexp3, params=child_params)
        if resp[0] == 403:
            ok("forged delegator signature denied")
        else:
            bad("forged delegator signature denied", resp)
        resp = delegate_raw(tok3, "w1", "w2", w1_sk, params_hash(child_params),
                            pexp3, params=child_params)
        if resp[0] == 403:
            ok("non-grantee delegator denied")
        else:
            bad("non-grantee delegator denied", resp)
        resp = delegate_raw(tok3, "orch", "w1", orch_sk,
                            params_hash(child_params), pexp3,
                            params=child_params)
        # this should succeed — use a fresh parent
        s, gov4 = govern("orch", "req-p4", parent_params)
        tok4 = gov4["decision"]["auth_token"]["token_id"]
        pexp4 = gov4["decision"]["auth_token"]["expires_unix_ms"]

        # ── Grantee binding: wrong executor cannot consume a token ──────────
        s, ex = execute(tok4, "w1", parent_params)
        if s == 403 and "grantee" in str(ex.get("deny_reason", "")):
            ok("token_grantee_mismatch: wrong executor denied")
        else:
            bad("token_grantee_mismatch: wrong executor denied", f"{s} {ex}")

        # ── Delegation chain endpoint returns lineage ───────────────────────
        status, chain = get(f"{BASE}/delegations/{t3}")
        if status == 200 and chain.get("depth") == 3 and \
                chain["chain"][0]["delegator_id"] == "orch":
            ok("delegation chain returns full lineage root→leaf")
        else:
            bad("delegation chain returns lineage", f"{status} {chain}")

        # ── Consumed parent cannot delegate ─────────────────────────────────
        s, gov5 = govern("orch", "req-p5", parent_params)
        tok5 = gov5["decision"]["auth_token"]["token_id"]
        pexp5 = gov5["decision"]["auth_token"]["expires_unix_ms"]
        execute(tok5, "orch", parent_params)  # consume
        resp = delegate_raw(tok5, "orch", "w1", orch_sk,
                            params_hash(child_params), pexp5, params=child_params)
        if resp[0] == 403:
            ok("consumed parent cannot delegate")
        else:
            bad("consumed parent cannot delegate", resp)

        # ── Ancestor revocation cascade — must run last ─────────────────────
        # tok2 chain: orch→w1→w2→w3 (t3 granted to w3, still live)
        client.revoke("orch", "delegation cascade test")
        s, ex = execute(t3, "w3", child_params)
        if s == 403 and "ancestor" in str(ex.get("deny_reason", "")):
            ok("ancestor revocation kills delegated token")
        else:
            bad("ancestor revocation kills delegated token", f"{s} {ex}")

        # fresh delegation with revoked delegator → denied
        s, gov6 = govern("orch", "req-p6", parent_params)
        if s == 200 and gov6["decision"]["gate_state"] == "DENY":
            ok("revoked delegator cannot even govern")
        else:
            bad("revoked delegator cannot even govern", f"{s} {gov6}")

    finally:
        gate.terminate()
        gate.wait(timeout=5)
        for suffix in ("", "-wal", "-shm"):
            if os.path.exists(DB + suffix):
                os.remove(DB + suffix)

    print(f"\nResults: {passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
