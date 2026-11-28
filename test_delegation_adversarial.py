#!/usr/bin/env python3
"""Adversarial delegation / expiry / revocation semantics against a live gate.

Covers: wildcard & traversal & case-fold widening, ttl-zero and boundary
expiry, mid-chain revocation, T0->T1 revocation (TOCTOU), duplicate-key
shadowing in the request body. Self-contained: starts its own gate.
"""
import json, os, subprocess, sys, tempfile, time, urllib.request, urllib.error
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from dgv_sdk import GateClient, GateError, delegate_canonical_string
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import hashlib
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gate_testlib  # noqa: E402

NATIVE = os.path.join(HERE, "native")
GATE = gate_testlib.gate_bin()
PORT = 7971
BASE = f"http://127.0.0.1:{PORT}"
ADMIN = "adv-admin"
passed = failed = 0


def check(name, cond, detail=""):
    global passed, failed
    if cond: passed += 1; print(f"PASS {name}")
    else: failed += 1; print(f"FAIL {name} {str(detail)[:240]}")


def raw(path, body=None, method="POST", data=None):
    hdr = {"Content-Type": "application/json", "X-Admin-Key": ADMIN}
    if data is None and body is not None: data = json.dumps(body).encode()
    req = urllib.request.Request(BASE + path, data=data, headers=hdr, method=method)
    try:
        with urllib.request.urlopen(req, timeout=15) as r: return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        try: return e.code, json.loads(e.read())
        except Exception: return e.code, {}


def keypair():
    sk = Ed25519PrivateKey.generate()
    seed = sk.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()).hex()
    pub = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    return seed, pub


def sign(seed, msg): return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed)).sign(msg.encode()).hex()
def phash(p): return hashlib.sha256(json.dumps(p, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def govern(agent, rid, params):
    return raw("/govern", {"request_id": rid, "agent_id": agent, "workflow": "adv", "tool": "send_email",
                           "action": "send", "params": params, "justification": "adv", "risk_level": "1000", "identity": {}})


def execute(tok, who, params):
    return raw("/execute", {"token_id": tok, "executor_id": who, "tool": "send_email", "action": "send", "params": params})


def token(agent, rid, params):
    s, g = govern(agent, rid, params)
    t = g["decision"]["auth_token"]
    return t["token_id"], t["expires_unix_ms"]


def delegate(tok, frm, to, seed, params, exp):
    canon = delegate_canonical_string(tok, frm, to, phash(params), exp)
    return raw("/delegate", {"parent_token_id": tok, "delegator_id": frm, "delegatee_id": to,
                             "params": params, "expires_unix_ms": exp, "signature": sign(seed, canon)})


def main():
    tmp = tempfile.mkdtemp(prefix="dgv_adv_")
    env = os.environ.copy()
    env.update({"DGV_RATE_LIMIT_DISABLED": "1", "DGV_LISTEN_ADDR": f"127.0.0.1:{PORT}", "DGV_ADMIN_KEY": ADMIN,
                "DGV_STORAGE": "sqlite", "DGV_DATABASE_URL": gate_testlib.sqlite_url(os.path.join(tmp, "g.db"))})
    gate = subprocess.Popen([GATE], env=env, cwd=NATIVE, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    try:
        for _ in range(60):
            time.sleep(0.25)
            try:
                if raw("/health", method="GET")[0] in (200, 503): break
            except Exception: pass
        client = GateClient(BASE, admin_key=ADMIN)
        ks = {a: keypair() for a in ("orch", "w1", "w2", "w3")}
        for a, (_, pub) in ks.items(): client.register_agent_key(a, pub)
        P = {"to": ["a@x.com", "b@x.com"], "path": "/data/reports/q1", "role": "reader"}
        now = lambda: int(time.time() * 1000)

        # 1. ttl zero / past / negative expiry -> 410, never a token (and never a 5xx)
        tok, pexp = token("orch", "adv-1", P)
        for label, exp in (("now", now()), ("zero", 0), ("negative", -1), ("one ms ago", now() - 1)):
            s, r = delegate(tok, "orch", "w1", ks["orch"][0], P, exp)
            check(f"ttl-zero/expired child ({label}) denied 410", s == 410 and "child_token_id" not in r, (s, r))

        # 2. exact boundary: child expiry == parent expiry allowed; parent+1 denied
        s, r = delegate(tok, "orch", "w1", ks["orch"][0], P, pexp)
        check("child expiry == parent expiry is allowed (boundary)", s == 200 and r.get("delegated"), (s, r))
        tok2, pexp2 = token("orch", "adv-2", P)
        s, r = delegate(tok2, "orch", "w1", ks["orch"][0], P, pexp2 + 1)
        check("child expiry == parent expiry + 1 denied 403", s == 403, (s, r))

        # 3. widening attempts via wildcard / traversal / case-fold
        tok3, pexp3 = token("orch", "adv-3", P)
        attempts = {
            "wildcard value": {"to": ["*"]},
            "wildcard key": {"*": True},
            "path traversal": {"path": "/data/reports/q1/../../secrets"},
            "path dot-segment": {"path": "/data/reports/./q1"},
            "path trailing slash": {"path": "/data/reports/q1/"},
            "case-fold role": {"role": "Reader"},
            "unicode lookalike role": {"role": "ｒeader"},
            "recipient case": {"to": ["A@x.com"]},
        }
        for label, params in attempts.items():
            s, r = delegate(tok3, "orch", "w1", ks["orch"][0], params, pexp3)
            check(f"widening denied: {label}", s == 403 and "child_token_id" not in r, (s, r))
        s, r = delegate(tok3, "ORCH", "w1", ks["orch"][0], P, pexp3)
        check("delegator id case-fold impersonation denied", s == 403, (s, r))

        # 4. mid-chain revocation: orch -> w1 -> w2 ; revoke w1
        tok4, pexp4 = token("orch", "adv-4", P)
        s, r1 = delegate(tok4, "orch", "w1", ks["orch"][0], P, pexp4)
        t_w1 = r1["child_token_id"]
        s, r2 = delegate(t_w1, "w1", "w2", ks["w1"][0], P, pexp4)
        t_w2 = r2["child_token_id"]
        check("setup: 2-deep chain minted", bool(t_w1 and t_w2), (r1, r2))
        client.revoke("w1", "mid-chain revocation")
        s, ex = execute(t_w2, "w2", P)
        check("revoked ancestor (mid-chain) blocks descendant at T1", s == 403 and not ex.get("allowed"), (s, ex))
        s, ex = execute(t_w1, "w1", P)
        check("revoked delegator's own token blocked at T1", s == 403 and not ex.get("allowed"), (s, ex))
        s, r = delegate(t_w1, "w1", "w3", ks["w1"][0], P, pexp4)
        check("revoked actor cannot delegate further", s in (403, 410), (s, r))
        tok5, _ = token("orch", "adv-5", P)
        s, ex = execute(tok5, "orch", P)
        check("unrelated root authority (orch) is unaffected by w1's revocation", s == 200 and ex.get("allowed"), (s, ex))

        # 5. TOCTOU: token granted at T0, grantee revoked before T1
        tok6, _ = token("w3", "adv-6", P)
        client.revoke("w3", "toctou")
        s, ex = execute(tok6, "w3", P)
        check("revocation between T0 and T1 denies execution", s == 403 and not ex.get("allowed"), (s, ex))

        # 6. duplicate-key shadowing in the request body (parser is last-wins)
        body = ('{"request_id":"adv-dup","agent_id":"orch","workflow":"adv","tool":"send_email","action":"send",'
                '"params":{"to":"attacker@x.com"},"params":{"to":"a@x.com"},'
                '"justification":"dup","risk_level":"1000","identity":{}}').encode()
        s, g = raw("/govern", data=body)
        d = g.get("decision", {})
        if d.get("gate_state") == "ALLOW":
            tk = d["auth_token"]["token_id"]
            s1, e1 = execute(tk, "orch", {"to": "attacker@x.com"})
            check("duplicate 'params' key: shadowed (first) value cannot be executed", not e1.get("allowed"), (s1, e1))
            s2, e2 = execute(tk, "orch", {"to": "a@x.com"})
            check("duplicate 'params' key: effective (last) value is what was authorized", e2.get("allowed") is True, (s2, e2))
        else:
            check("duplicate 'params' key request fails closed (not allowed)", d.get("gate_state") != "ALLOW" or s >= 400, (s, g))
    finally:
        gate.terminate(); gate.wait(timeout=5)
    print(f"=== Results: {passed} passed, {failed} failed ===")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
