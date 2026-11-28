#!/usr/bin/env python3
"""End-to-end: a validly signed peer answer of "revoked" WITHOUT a record must deny.

Before the fix, dgv-gate ignored such a peer (neither clean nor revoked), so a
reachable revoker plus one clean peer still reached quorum and /govern ALLOWed.
Mock peers speak the real wire protocol (POST /revocations/quorum-check,
Ed25519 over `dgv-quorum-v1|actor|status|nonce|ts|vk`).
"""
import json, os, subprocess, sys, tempfile, threading, time, urllib.request, urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gate_testlib  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
NATIVE = os.path.join(HERE, "native")
GATE = gate_testlib.gate_bin()
passed = failed = 0


def check(name, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1; print(f"PASS {name}")
    else:
        failed += 1; print(f"FAIL {name} {detail}")


def new_key():
    sk = Ed25519PrivateKey.generate()
    seed = sk.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                            serialization.NoEncryption())
    vk = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    return sk, seed.hex(), vk


class Peer:
    """Mock quorum peer. mode: clean | revoked_no_record | revoked_with_record | forged_revoked"""
    def __init__(self, mode):
        self.mode = mode
        self.sk, _, self.vk = new_key()
        peer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a): pass
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                actor, nonce = body["actor_id"], body["nonce"]
                ts = int(time.time() * 1000)
                revoked = peer.mode != "clean"
                status = "revoked" if revoked else "clean"
                canon = f"dgv-quorum-v1|{actor}|{status}|{nonce}|{ts}|{peer.vk}".encode()
                sig = peer.sk.sign(canon)
                if peer.mode == "forged_revoked":
                    sig = bytes(64)           # invalid signature
                record = None
                if peer.mode == "revoked_with_record":
                    record = {"actor_id": actor, "reason": "mock", "revoked_unix_ms": ts, "revoked_by": "mock"}
                out = {"actor_id": actor, "status": status, "record": record,
                       "responder_vk": peer.vk, "nonce": nonce, "timestamp_ms": ts,
                       "signature": sig.hex()}
                data = json.dumps(out).encode()
                self.send_response(200); self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)

        self.srv = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.srv.server_port}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def stop(self): self.srv.shutdown()


def http(method, url, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def run_scenario(name, modes, quorum_size, port):
    tmp = tempfile.mkdtemp(prefix="dgv_norec_")
    _, seed, gate_vk = new_key()
    keyf = os.path.join(tmp, "k.hex"); open(keyf, "w").write(seed)
    peers = [Peer(m) for m in modes]
    env = os.environ.copy()
    env.update({
        "DGV_RATE_LIMIT_DISABLED": "1", "DGV_LISTEN_ADDR": f"127.0.0.1:{port}",
        "DGV_DATABASE_URL": gate_testlib.sqlite_url(os.path.join(tmp, "g.db")),
        "DGV_SIGNING_KEY": keyf, "DGV_ADMIN_KEY": "admin",
        "DGV_GOSSIP_KEYS": ",".join(p.vk for p in peers),
        "DGV_QUORUM_PEERS": ",".join(p.url for p in peers),
        "DGV_QUORUM_SIZE": str(quorum_size), "DGV_PARTITION_POLICY": "fail_closed",
    })
    proc = subprocess.Popen([GATE], env=env, cwd=NATIVE, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    base = f"http://127.0.0.1:{port}"
    try:
        for _ in range(40):
            time.sleep(0.25)
            try:
                if http("GET", f"{base}/health")[0] in (200, 503): break
            except Exception: pass
        st, resp = http("POST", f"{base}/govern", {
            "request_id": f"req-{name}", "agent_id": f"agent-{name}", "workflow": "q-test",
            "tool": "record_fact", "action": "record_fact", "params": {"field": name},
            "justification": "no-record test", "risk_level": "1000", "identity": {}})
        return st, resp.get("decision", {}), resp
    finally:
        proc.terminate(); proc.wait(timeout=5)
        for p in peers: p.stop()


def main():
    print("=== Quorum: peer 'revoked' without a record ===")
    # Control: both peers clean -> allowed (proves the harness can reach ALLOW).
    st, d, _ = run_scenario("control", ["clean", "clean"], 2, 7961)
    check("control: two clean peers -> ALLOW with token", st == 200 and d.get("gate_state") == "ALLOW" and d.get("auth_token"), str(d))

    # The bug: 1 clean peer + self = 2 >= quorum 2, but the other peer says revoked (no record).
    st, d, _ = run_scenario("norec", ["clean", "revoked_no_record"], 2, 7962)
    check("revoked-without-record peer -> NOT allowed", d.get("gate_state") != "ALLOW", str(d))
    check("revoked-without-record peer -> no auth token", d.get("auth_token") is None, str(d))
    check("revoked-without-record peer -> fail-closed DENY citing the reason",
          d.get("gate_state") == "DENY" and "without a record" in json.dumps(d.get("reason_codes", [])), str(d))

    # Revoked WITH record -> deny (existing behaviour, regression guard).
    st, d, _ = run_scenario("withrec", ["clean", "revoked_with_record"], 2, 7963)
    check("revoked-with-record peer -> DENY, no token", d.get("gate_state") == "DENY" and d.get("auth_token") is None, str(d))

    # Trust boundary: a FORGED (bad signature) revoked answer is ignored; clean quorum still holds.
    st, d, _ = run_scenario("forged", ["clean", "forged_revoked"], 2, 7964)
    check("forged-signature 'revoked' is ignored (documented trust boundary)", d.get("gate_state") == "ALLOW", str(d))

    print(f"=== Results: {passed} passed, {failed} failed ===")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
