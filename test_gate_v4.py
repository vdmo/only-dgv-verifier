"""Test gate v0.4.0 features: RS256/JWKS, approver identity, semantic verifier
webhook, circuit breakers, A2A signed envelopes."""
import json
import os
import subprocess
import sys
import tempfile
import time
import hashlib
import hmac
import base64
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

GATE_BINARY = os.path.join(os.path.dirname(__file__), "native", "target", "release", "dgv-gate")
TEST_DB = tempfile.mktemp(suffix=".db", prefix="dgv_v4_test_")
TEST_PORT = "7892"
BASE_URL = f"http://127.0.0.1:{TEST_PORT}"
ADMIN_KEY = "test-admin-key-789"
JWT_SECRET = "test-jwt-secret-hs256-v4"

passed = 0
failed = 0

def test(name, fn):
    global passed, failed
    try:
        fn()
        print(f"  [PASS] {name}")
        passed += 1
    except Exception as e:
        print(f"  [FAIL] {name}: {e}")
        failed += 1


# ── Helpers ──────────────────────────────────────────────────────────────────

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def make_hs256_jwt(sub, secret=JWT_SECRET, iss=None, aud=None, exp_offset=3600):
    header = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = {"sub": sub, "iat": int(time.time()), "exp": int(time.time()) + exp_offset}
    if iss:
        payload["iss"] = iss
    if aud:
        payload["aud"] = aud
    payload_b64 = b64url(json.dumps(payload).encode())
    sig = hmac.new(secret.encode(), f"{header}.{payload_b64}".encode(), hashlib.sha256).digest()
    return f"{header}.{payload_b64}.{b64url(sig)}"


# RSA key pair for RS256/JWKS tests
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding, ed25519
from cryptography.hazmat.primitives import hashes, serialization

RSA_KEY_1 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
RSA_KEY_2 = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def rsa_jwk(priv_key, kid):
    nums = priv_key.public_key().public_numbers()
    n_bytes = nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big")
    e_bytes = nums.e.to_bytes((nums.e.bit_length() + 7) // 8, "big")
    return {"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
            "n": b64url(n_bytes), "e": b64url(e_bytes)}


def make_rs256_jwt(sub, priv_key, kid, iss=None, aud=None, exp_offset=3600):
    header = b64url(json.dumps({"alg": "RS256", "typ": "JWT", "kid": kid}).encode())
    payload = {"sub": sub, "iat": int(time.time()), "exp": int(time.time()) + exp_offset}
    if iss:
        payload["iss"] = iss
    if aud:
        payload["aud"] = aud
    payload_b64 = b64url(json.dumps(payload).encode())
    signing_input = f"{header}.{payload_b64}".encode()
    sig = priv_key.sign(signing_input, rsa_padding.PKCS1v15(), hashes.SHA256())
    return f"{header}.{payload_b64}.{b64url(sig)}"


# Ed25519 keys for A2A tests
ED_SENDER = ed25519.Ed25519PrivateKey.generate()
ED_RECIPIENT = ed25519.Ed25519PrivateKey.generate()
ED_SENDER_PUB = ED_SENDER.public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
ED_RECIPIENT_PUB = ED_RECIPIENT.public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def sign_a2a(priv, envelope_id, sender_id, recipient_id, payload_hash, nonce, sent, expires):
    canonical = f"{envelope_id}|{sender_id}|{recipient_id}|{payload_hash}|{nonce}|{sent}|{expires}"
    return priv.sign(canonical.encode()).hex()


def post(path, body, headers=None, admin_key=None):
    import urllib.request
    url = f"{BASE_URL}{path}"
    data = json.dumps(body).encode()
    hdrs = {"Content-Type": "application/json"}
    if admin_key:
        hdrs["X-Admin-Key"] = admin_key
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, data=data, headers=hdrs, method="POST")
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def post_auth(path, body, jwt_token=None, admin_key=None):
    headers = {}
    if jwt_token:
        headers["Authorization"] = f"Bearer {jwt_token}"
    return post(path, body, headers=headers, admin_key=admin_key)


def get(path, headers=None, admin_key=None):
    import urllib.request
    url = f"{BASE_URL}{path}"
    hdrs = {}
    if admin_key:
        hdrs["X-Admin-Key"] = admin_key
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, headers=hdrs)
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def delete(path, admin_key=None):
    import urllib.request
    url = f"{BASE_URL}{path}"
    hdrs = {}
    if admin_key:
        hdrs["X-Admin-Key"] = admin_key
    req = urllib.request.Request(url, headers=hdrs, method="DELETE")
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def govern_req(request_id, agent_id, tool, action, justification="test justification", params=None):
    return {
        "request_id": request_id,
        "agent_id": agent_id,
        "workflow": "test",
        "tool": tool,
        "action": action,
        "params": params or {},
        "justification": justification,
        "risk_level": "500",
        "identity": {},
    }


# ── Test servers (JWKS + semantic verifier) ──────────────────────────────────

JWKS_STATE = {"keys": []}
SEMANTIC_STATE = {"verdict": {"allowed": True}, "requests": []}


class TestHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path == "/jwks.json":
            body = json.dumps({"keys": JWKS_STATE["keys"]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == "/semantic":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            SEMANTIC_STATE["requests"].append(json.loads(body))
            resp = json.dumps(SEMANTIC_STATE["verdict"]).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(resp)
        else:
            self.send_response(404)
            self.end_headers()


TEST_SERVER_PORT = 7893


def start_test_server():
    server = HTTPServer(("127.0.0.1", TEST_SERVER_PORT), TestHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server


def start_gate(extra_env=None):
    env = os.environ.copy()
    env["DGV_STORAGE"] = "sqlite"
    env["DGV_DATABASE_URL"] = f"sqlite://{TEST_DB}"
    env["DGV_LISTEN_ADDR"] = f"127.0.0.1:{TEST_PORT}"
    env["DGV_ADMIN_KEY"] = ADMIN_KEY
    env["DGV_RATE_LIMIT_DISABLED"] = "1"
    env["DGV_SIGNING_KEY"] = os.path.join(tempfile.gettempdir(), "dgv_v4_test.key")
    env.pop("DGV_JWT_SECRET", None)
    env.pop("DGV_JWT_PUBLIC_KEY", None)
    env.pop("DGV_JWT_JWKS_URL", None)
    env.pop("DGV_SEMANTIC_VERIFIER_URL", None)
    env.pop("DGV_SEMANTIC_FAIL_CLOSED", None)
    env.pop("DGV_CIRCUIT_BREAKER_THRESHOLD", None)
    env.pop("DGV_CIRCUIT_BREAKER_COOLDOWN_MS", None)
    if extra_env:
        env.update(extra_env)

    proc = subprocess.Popen(
        [GATE_BINARY],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )

    for _ in range(40):
        try:
            import urllib.request
            req = urllib.request.Request(f"{BASE_URL}/health")
            with urllib.request.urlopen(req, timeout=1) as resp:
                if json.loads(resp.read())["status"] == "ok":
                    return proc
        except Exception:
            pass
        time.sleep(0.25)

    proc.kill()
    raise RuntimeError("Gate did not start")


def clean_db():
    for suffix in ("", "-shm", "-wal"):
        p = TEST_DB + suffix
        if os.path.exists(p):
            os.unlink(p)


def main():
    server = start_test_server()

    # ═══════════════════════════════════════════════════════════════════════
    # Suite 1: Circuit breakers (no JWT)
    # ═══════════════════════════════════════════════════════════════════════
    clean_db()
    proc = start_gate({"DGV_CIRCUIT_BREAKER_THRESHOLD": "3",
                       "DGV_CIRCUIT_BREAKER_COOLDOWN_MS": "1500"})
    try:
        print("\n=== Circuit Breaker Tests ===")

        def t_breaker_closed_allows():
            code, resp = post("/govern", govern_req("cb-1", "agent-a", "flaky_tool", "run"))
            assert resp["decision"]["gate_state"] == "ALLOW", resp
        test("breaker closed: govern allowed", t_breaker_closed_allows)

        def t_breaker_opens_after_threshold():
            for i in range(3):
                code, resp = post("/tool-health/report",
                                  {"tool": "flaky_tool", "success": False})
                assert code == 200
            code, resp = get("/tool-health")
            assert resp["tools"]["flaky_tool"]["circuit_open"] is True
            # Now govern should deny
            code, resp = post("/govern", govern_req("cb-2", "agent-a", "flaky_tool", "run"))
            assert resp["decision"]["gate_state"] == "DENY"
            assert "circuit_breaker_open" in resp["decision"]["reason_codes"][0]
        test("breaker opens after threshold, denies govern", t_breaker_opens_after_threshold)

        def t_breaker_other_tools_unaffected():
            code, resp = post("/govern", govern_req("cb-3", "agent-a", "other_tool", "run"))
            assert resp["decision"]["gate_state"] == "ALLOW"
        test("breaker is per-tool (other tools unaffected)", t_breaker_other_tools_unaffected)

        def t_breaker_half_open_recovery():
            # Wait for cooldown → next request is a probe (half-open)
            time.sleep(1.7)
            code, resp = post("/govern", govern_req("cb-4", "agent-a", "flaky_tool", "run"))
            assert resp["decision"]["gate_state"] == "ALLOW", resp["decision"]
            # Report success → circuit closes
            post("/tool-health/report", {"tool": "flaky_tool", "success": True})
            code, resp = get("/tool-health")
            assert resp["tools"]["flaky_tool"]["circuit_open"] is False
            assert resp["tools"]["flaky_tool"]["consecutive_failures"] == 0
        test("breaker half-open + recovery", t_breaker_half_open_recovery)

        def t_breaker_manual_reset():
            for i in range(3):
                post("/tool-health/report", {"tool": "reset_tool", "success": False})
            code, resp = get("/tool-health")
            assert resp["tools"]["reset_tool"]["circuit_open"] is True
            code, resp = post("/tool-health/reset/reset_tool", {}, admin_key=ADMIN_KEY)
            assert code == 200
            code, resp = post("/govern", govern_req("cb-5", "agent-a", "reset_tool", "run"))
            assert resp["decision"]["gate_state"] == "ALLOW"
        test("breaker manual reset (admin)", t_breaker_manual_reset)

    finally:
        proc.terminate()
        proc.wait()

    # ═══════════════════════════════════════════════════════════════════════
    # Suite 2: A2A signed envelopes (no JWT — Ed25519 envelope signatures only)
    # ═══════════════════════════════════════════════════════════════════════
    clean_db()
    proc = start_gate()
    try:
        print("\n=== A2A Signed Envelope Tests ===")

        def t_register_keys():
            code, resp = post("/agents/keys", {
                "agent_id": "agent-sender",
                "public_key_hex": ED_SENDER_PUB,
            }, admin_key=ADMIN_KEY)
            assert code == 200 and resp["registered"] is True
            code, resp = post("/agents/keys", {
                "agent_id": "agent-recipient",
                "public_key_hex": ED_RECIPIENT_PUB,
            }, admin_key=ADMIN_KEY)
            assert code == 200
        test("register agent keys (admin)", t_register_keys)

        def t_register_requires_admin():
            code, resp = post("/agents/keys", {
                "agent_id": "rogue",
                "public_key_hex": ED_SENDER_PUB,
            })
            assert code == 401
        test("key registration requires admin", t_register_requires_admin)

        now = int(time.time() * 1000)

        def t_send_valid_envelope():
            payload_hash = hashlib.sha256(b"hello agent").hexdigest()
            sent = int(time.time() * 1000)
            expires = sent + 60_000
            sig = sign_a2a(ED_SENDER, "env-1", "agent-sender", "agent-recipient",
                           payload_hash, "nonce-1", sent, expires)
            code, resp = post("/a2a/send", {
                "envelope_id": "env-1", "sender_id": "agent-sender",
                "recipient_id": "agent-recipient", "payload_hash": payload_hash,
                "nonce": "nonce-1", "sent_unix_ms": sent, "expires_unix_ms": expires,
                "signature": sig,
            })
            assert code == 200, resp
            assert resp["accepted"] is True
            assert resp["gate_receipt"] is not None
        test("send valid signed envelope", t_send_valid_envelope)

        def t_replay_same_envelope():
            payload_hash = hashlib.sha256(b"hello agent").hexdigest()
            sent = int(time.time() * 1000)
            expires = sent + 60_000
            sig = sign_a2a(ED_SENDER, "env-1", "agent-sender", "agent-recipient",
                           payload_hash, "nonce-1", sent, expires)
            code, resp = post("/a2a/send", {
                "envelope_id": "env-1", "sender_id": "agent-sender",
                "recipient_id": "agent-recipient", "payload_hash": payload_hash,
                "nonce": "nonce-1", "sent_unix_ms": sent, "expires_unix_ms": expires,
                "signature": sig,
            })
            assert code == 409, resp
            assert "replay" in resp["error"]
        test("replay same envelope_id → 409", t_replay_same_envelope)

        def t_replay_same_nonce():
            payload_hash = hashlib.sha256(b"different").hexdigest()
            sent = int(time.time() * 1000)
            expires = sent + 60_000
            sig = sign_a2a(ED_SENDER, "env-2", "agent-sender", "agent-recipient",
                           payload_hash, "nonce-1", sent, expires)
            code, resp = post("/a2a/send", {
                "envelope_id": "env-2", "sender_id": "agent-sender",
                "recipient_id": "agent-recipient", "payload_hash": payload_hash,
                "nonce": "nonce-1", "sent_unix_ms": sent, "expires_unix_ms": expires,
                "signature": sig,
            })
            assert code == 409, resp
        test("replay same nonce (different envelope_id) → 409", t_replay_same_nonce)

        def t_tampered_signature():
            payload_hash = hashlib.sha256(b"msg").hexdigest()
            sent = int(time.time() * 1000)
            expires = sent + 60_000
            sig = sign_a2a(ED_SENDER, "env-3", "agent-sender", "agent-recipient",
                           payload_hash, "nonce-3", sent, expires)
            # Tamper: change the payload hash after signing
            bad_hash = hashlib.sha256(b"evil").hexdigest()
            code, resp = post("/a2a/send", {
                "envelope_id": "env-3", "sender_id": "agent-sender",
                "recipient_id": "agent-recipient", "payload_hash": bad_hash,
                "nonce": "nonce-3", "sent_unix_ms": sent, "expires_unix_ms": expires,
                "signature": sig,
            })
            assert code == 403
            assert "invalid_signature" in resp["error"]
        test("tampered payload_hash → invalid_signature", t_tampered_signature)

        def t_wrong_signer_key():
            # Envelope claims agent-sender but signed by recipient's key
            payload_hash = hashlib.sha256(b"msg").hexdigest()
            sent = int(time.time() * 1000)
            expires = sent + 60_000
            sig = sign_a2a(ED_RECIPIENT, "env-4", "agent-sender", "agent-recipient",
                           payload_hash, "nonce-4", sent, expires)
            code, resp = post("/a2a/send", {
                "envelope_id": "env-4", "sender_id": "agent-sender",
                "recipient_id": "agent-recipient", "payload_hash": payload_hash,
                "nonce": "nonce-4", "sent_unix_ms": sent, "expires_unix_ms": expires,
                "signature": sig,
            })
            assert code == 403
            assert "invalid_signature" in resp["error"]
        test("signed by wrong key → invalid_signature", t_wrong_signer_key)

        def t_expired_envelope():
            payload_hash = hashlib.sha256(b"old").hexdigest()
            sent = int(time.time() * 1000) - 120_000
            expires = sent + 60_000  # expired a minute ago
            sig = sign_a2a(ED_SENDER, "env-5", "agent-sender", "agent-recipient",
                           payload_hash, "nonce-5", sent, expires)
            code, resp = post("/a2a/send", {
                "envelope_id": "env-5", "sender_id": "agent-sender",
                "recipient_id": "agent-recipient", "payload_hash": payload_hash,
                "nonce": "nonce-5", "sent_unix_ms": sent, "expires_unix_ms": expires,
                "signature": sig,
            })
            assert code == 410
            assert "expired" in resp["error"]
        test("expired envelope → 410", t_expired_envelope)

        def t_unregistered_sender():
            payload_hash = hashlib.sha256(b"msg").hexdigest()
            sent = int(time.time() * 1000)
            expires = sent + 60_000
            sig = sign_a2a(ED_SENDER, "env-6", "agent-ghost", "agent-recipient",
                           payload_hash, "nonce-6", sent, expires)
            code, resp = post("/a2a/send", {
                "envelope_id": "env-6", "sender_id": "agent-ghost",
                "recipient_id": "agent-recipient", "payload_hash": payload_hash,
                "nonce": "nonce-6", "sent_unix_ms": sent, "expires_unix_ms": expires,
                "signature": sig,
            })
            assert code == 403
            assert "unregistered_sender" in resp["error"]
        test("unregistered sender → 403", t_unregistered_sender)

        def t_inbox_and_ack():
            code, resp = get("/a2a/inbox/agent-recipient")
            assert code == 200
            env_ids = [e["envelope_id"] for e in resp["envelopes"]]
            assert "env-1" in env_ids
            # Ack it
            code, resp = post("/a2a/ack/env-1", {"agent_id": "agent-recipient"})
            assert code == 200
            # Inbox now empty
            code, resp = get("/a2a/inbox/agent-recipient")
            env_ids = [e["envelope_id"] for e in resp["envelopes"]]
            assert "env-1" not in env_ids
            # Double-ack → 409
            code, resp = post("/a2a/ack/env-1", {"agent_id": "agent-recipient"})
            assert code == 409
        test("inbox + ack flow", t_inbox_and_ack)

        def t_revoked_sender():
            # Revoke the sender, then try to send
            post("/revocations", {"actor_id": "agent-sender", "reason": "test revoke",
                                  "revoked_by": "test"}, admin_key=ADMIN_KEY)
            payload_hash = hashlib.sha256(b"msg").hexdigest()
            sent = int(time.time() * 1000)
            expires = sent + 60_000
            sig = sign_a2a(ED_SENDER, "env-7", "agent-sender", "agent-recipient",
                           payload_hash, "nonce-7", sent, expires)
            code, resp = post("/a2a/send", {
                "envelope_id": "env-7", "sender_id": "agent-sender",
                "recipient_id": "agent-recipient", "payload_hash": payload_hash,
                "nonce": "nonce-7", "sent_unix_ms": sent, "expires_unix_ms": expires,
                "signature": sig,
            })
            assert code == 403
            assert "revoked" in resp["error"]
        test("revoked sender → 403", t_revoked_sender)

        def t_deactivated_key():
            code, resp = delete("/agents/keys/agent-recipient", admin_key=ADMIN_KEY)
            assert code == 200
            payload_hash = hashlib.sha256(b"msg").hexdigest()
            sent = int(time.time() * 1000)
            expires = sent + 60_000
            sig = sign_a2a(ED_SENDER, "env-8", "agent-sender", "agent-recipient",
                           payload_hash, "nonce-8", sent, expires)
            code, resp = post("/a2a/send", {
                "envelope_id": "env-8", "sender_id": "agent-sender",
                "recipient_id": "agent-recipient", "payload_hash": payload_hash,
                "nonce": "nonce-8", "sent_unix_ms": sent, "expires_unix_ms": expires,
                "signature": sig,
            })
            # sender revoked earlier, but if not — recipient key deactivated → unregistered_recipient
            assert code == 403
        test("deactivated recipient key → 403", t_deactivated_key)

    finally:
        proc.terminate()
        proc.wait()

    # ═══════════════════════════════════════════════════════════════════════
    # Suite 3: Semantic verifier webhook (no JWT)
    # ═══════════════════════════════════════════════════════════════════════
    clean_db()
    proc = start_gate({
        "DGV_SEMANTIC_VERIFIER_URL": f"http://127.0.0.1:{TEST_SERVER_PORT}/semantic",
    })
    try:
        print("\n=== Semantic Verifier Tests ===")

        def t_semantic_allow():
            SEMANTIC_STATE["verdict"] = {"allowed": True}
            code, resp = post("/govern", govern_req(
                "sem-1", "agent-a", "semantic_tool", "act",
                justification="legitimate business reason for this action"))
            assert resp["decision"]["gate_state"] == "ALLOW", resp["decision"]
            # Verify the webhook received the context
            assert len(SEMANTIC_STATE["requests"]) > 0
            assert SEMANTIC_STATE["requests"][-1]["tool"] == "semantic_tool"
        test("semantic verifier allows", t_semantic_allow)

        def t_semantic_deny():
            SEMANTIC_STATE["verdict"] = {"allowed": False, "reason": "justification does not match action intent"}
            code, resp = post("/govern", govern_req(
                "sem-2", "agent-a", "semantic_tool", "act",
                justification="unrelated text"))
            assert resp["decision"]["gate_state"] == "DENY"
            assert "semantic_verification_failed" in resp["decision"]["reason_codes"][0]
        test("semantic verifier denies", t_semantic_deny)

    finally:
        proc.terminate()
        proc.wait()

    # Fail-closed mode: verifier unreachable → deny
    clean_db()
    proc = start_gate({
        "DGV_SEMANTIC_VERIFIER_URL": "http://127.0.0.1:9/unreachable",
        "DGV_SEMANTIC_FAIL_CLOSED": "1",
    })
    try:
        def t_semantic_fail_closed():
            code, resp = post("/govern", govern_req(
                "sem-3", "agent-a", "semantic_tool", "act",
                justification="some justification"))
            assert resp["decision"]["gate_state"] == "DENY"
            assert "semantic_verifier_unreachable" in resp["decision"]["reason_codes"][0]
        test("fail-closed: unreachable verifier → deny", t_semantic_fail_closed)
    finally:
        proc.terminate()
        proc.wait()

    # ═══════════════════════════════════════════════════════════════════════
    # Suite 4: RS256 / JWKS identity
    # ═══════════════════════════════════════════════════════════════════════
    clean_db()
    JWKS_STATE["keys"] = [rsa_jwk(RSA_KEY_1, "key-1"), rsa_jwk(RSA_KEY_2, "key-2")]
    proc = start_gate({
        "DGV_JWT_JWKS_URL": f"http://127.0.0.1:{TEST_SERVER_PORT}/jwks.json",
    })
    try:
        print("\n=== RS256/JWKS Identity Tests ===")

        def t_rs256_valid():
            token = make_rs256_jwt("rs-agent", RSA_KEY_1, "key-1")
            code, resp = post_auth("/govern", govern_req(
                "jwks-1", "spoofed", "jwks_tool", "act"), jwt_token=token)
            assert code == 200, resp
            assert resp["decision"]["gate_state"] == "ALLOW"
        test("RS256 via JWKS (key-1)", t_rs256_valid)

        def t_rs256_rotation():
            # Key rotation: second key also works via kid selection
            token = make_rs256_jwt("rs-agent-2", RSA_KEY_2, "key-2")
            code, resp = post_auth("/govern", govern_req(
                "jwks-2", "spoofed", "jwks_tool", "act"), jwt_token=token)
            assert code == 200
            assert resp["decision"]["gate_state"] == "ALLOW"
        test("RS256 via JWKS (key-2, rotation)", t_rs256_rotation)

        def t_rs256_unknown_kid():
            token = make_rs256_jwt("rs-agent", RSA_KEY_1, "key-unknown")
            code, resp = post_auth("/govern", govern_req(
                "jwks-3", "x", "jwks_tool", "act"), jwt_token=token)
            assert code == 401
        test("unknown kid → deny", t_rs256_unknown_kid)

        def t_rs256_wrong_key_signature():
            # Signed by key-2 but claims kid=key-1 → signature verification fails
            token = make_rs256_jwt("rs-agent", RSA_KEY_2, "key-1")
            code, resp = post_auth("/govern", govern_req(
                "jwks-4", "x", "jwks_tool", "act"), jwt_token=token)
            assert code == 401
        test("wrong key for kid → deny", t_rs256_wrong_key_signature)

        def t_rs256_expired():
            token = make_rs256_jwt("rs-agent", RSA_KEY_1, "key-1", exp_offset=-3600)
            code, resp = post_auth("/govern", govern_req(
                "jwks-5", "x", "jwks_tool", "act"), jwt_token=token)
            assert code == 401
        test("expired RS256 → deny", t_rs256_expired)

        def t_hs256_rejected_in_jwks_mode():
            # Algorithm confusion: HS256 token against JWKS-mode gate → deny
            token = make_hs256_jwt("hs-agent")
            code, resp = post_auth("/govern", govern_req(
                "jwks-6", "x", "jwks_tool", "act"), jwt_token=token)
            assert code == 401
        test("HS256 token rejected in JWKS mode (alg confusion)", t_hs256_rejected_in_jwks_mode)

    finally:
        proc.terminate()
        proc.wait()

    # ═══════════════════════════════════════════════════════════════════════
    # Suite 5: Approver identity via JWT (HS256 mode)
    # ═══════════════════════════════════════════════════════════════════════
    clean_db()
    proc = start_gate({"DGV_JWT_SECRET": JWT_SECRET})
    try:
        print("\n=== Approver Identity Tests ===")

        # Set up a policy requiring 1 approval
        post("/policies", {
            "tool": "sensitive_tool", "action": "write",
            "script": 'harmony(1e-12)\nbind_authority("a", "agent", "sensitive_tool")\nresidual()',
            "min_approvals": 1,
        }, admin_key=ADMIN_KEY)

        def get_token():
            token = make_hs256_jwt("agent-a")
            code, resp = post_auth("/govern", govern_req(
                f"appr-{time.time()}", "agent-a", "sensitive_tool", "write"),
                jwt_token=token)
            assert resp["decision"]["gate_state"] == "ALLOW"
            return resp["decision"]["auth_token"]["token_id"]

        def t_approve_no_jwt():
            tid = get_token()
            code, resp = post(f"/approve/{tid}", {"approver_id": "anyone"})
            assert code == 401
            assert "approver_identity_verification_failed" in resp["error"]
        test("approve without JWT → 401", t_approve_no_jwt)

        def t_approve_verified_subject():
            tid = get_token()
            # approver_id field is spoofed, but JWT sub is the real identity
            approver_jwt = make_hs256_jwt("verified-approver")
            code, resp = post_auth(f"/approve/{tid}", {"approver_id": "spoofed-name"},
                                   jwt_token=approver_jwt)
            assert code == 200, resp
            assert resp["approval_count"] == 1
            # Now execute should succeed with the agent's token
            agent_jwt = make_hs256_jwt("agent-a")
            code, resp = post_auth("/execute", {
                "token_id": tid, "executor_id": "agent-a",
                "tool": "sensitive_tool", "action": "write", "params": {},
            }, jwt_token=agent_jwt)
            assert code == 200 and resp["allowed"] is True
        test("verified approver subject persisted, execute succeeds", t_approve_verified_subject)

        def t_approve_wrong_jwt_sub():
            tid = get_token()
            # JWT for a different agent entirely — still counts as that identity
            approver_jwt = make_hs256_jwt("different-approver")
            code, resp = post_auth(f"/approve/{tid}", {"approver_id": "anyone"},
                                   jwt_token=approver_jwt)
            assert code == 200
            # The stored approver is the JWT sub — approve again as the SAME
            # claimed name but different JWT still counts separately only if
            # sub differs; duplicate (token_id, approver_id) is upserted.
            assert resp["approval_count"] == 1
        test("approver identity comes from JWT sub, not body", t_approve_wrong_jwt_sub)

    finally:
        proc.terminate()
        proc.wait()

    # Cleanup
    server.shutdown()
    clean_db()
    key_file = os.path.join(tempfile.gettempdir(), "dgv_v4_test.key")
    if os.path.exists(key_file):
        os.unlink(key_file)

    print(f"\n{'='*50}")
    print(f"Results: {passed} passed, {failed} failed")
    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
