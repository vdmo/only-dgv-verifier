"""Test gate v0.3.0 features: JWT identity, approval workflow, policy signing,
context hashing, justification enforcement."""
import json
import os
import subprocess
import sys
import tempfile
import time
import hashlib
import hmac
import base64

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

GATE_BINARY = os.path.join(os.path.dirname(__file__), "native", "target", "release", "dgv-gate")
TEST_DB = tempfile.mktemp(suffix=".db", prefix="dgv_v3_test_")
TEST_PORT = "7891"
BASE_URL = f"http://127.0.0.1:{TEST_PORT}"
ADMIN_KEY = "test-admin-key-456"
JWT_SECRET = "test-jwt-secret-for-hs256"

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


def make_jwt(sub, secret=JWT_SECRET, iss=None, aud=None, exp_offset=3600):
    """Create a minimal HS256 JWT for testing."""
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).rstrip(b"=")
    payload = {"sub": sub, "iat": int(time.time()), "exp": int(time.time()) + exp_offset}
    if iss:
        payload["iss"] = iss
    if aud:
        payload["aud"] = aud
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=")
    signature = hmac.new(secret.encode(), f"{header.decode()}.{payload_b64.decode()}".encode(), hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(signature).rstrip(b"=")
    return f"{header.decode()}.{payload_b64.decode()}.{sig_b64.decode()}"


def post(path, body, headers=None, admin_key=None):
    """POST to the gate."""
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
    """POST with optional JWT."""
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


def start_gate(jwt_enabled=False):
    env = os.environ.copy()
    env["DGV_STORAGE"] = "sqlite"
    env["DGV_DATABASE_URL"] = f"sqlite://{TEST_DB}"
    env["DGV_LISTEN_ADDR"] = f"127.0.0.1:{TEST_PORT}"
    env["DGV_ADMIN_KEY"] = ADMIN_KEY
    env["DGV_RATE_LIMIT_DISABLED"] = "1"
    env["DGV_SIGNING_KEY"] = os.path.join(tempfile.gettempdir(), "dgv_v3_test.key")
    if jwt_enabled:
        env["DGV_JWT_SECRET"] = JWT_SECRET

    proc = subprocess.Popen(
        [GATE_BINARY],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )

    for _ in range(30):
        try:
            import urllib.request
            req = urllib.request.Request(f"{BASE_URL}/health")
            with urllib.request.urlopen(req, timeout=1) as resp:
                if json.loads(resp.read())["status"] == "ok":
                    return proc
        except:
            pass
        time.sleep(0.2)

    proc.kill()
    raise RuntimeError("Gate did not start")


def main():
    # ── Test without JWT first ────────────────────────────────────────────────
    proc = start_gate(jwt_enabled=False)
    try:
        print("\n=== Feature Tests (no JWT) ===")

        def t_health():
            code, resp = get("/health")
            assert code == 200 and resp["status"] == "ok"
        test("health", t_health)

        # ── Justification enforcement ────────────────────────────────────────
        def t_justification_enforced():
            # Store a policy requiring min 50 char justification
            code, resp = post("/policies", {
                "tool": "send_email",
                "action": "bulk_send",
                "script": 'harmony(1e-12)\nbind_authority("test", "agent", "send_email")\nresidual()',
                "min_justification_length": 50,
            }, admin_key=ADMIN_KEY)
            assert code == 200

            # Govern with short justification — should deny
            code, resp = post("/govern", {
                "request_id": "req-short",
                "agent_id": "test",
                "workflow": "test",
                "tool": "send_email",
                "action": "bulk_send",
                "params": {},
                "justification": "too short",
                "risk_level": "500",
                "identity": {},
            })
            assert resp["decision"]["gate_state"] == "DENY"
            assert "justification_too_short" in resp["decision"]["reason_codes"][0]
        test("justification enforcement (short = deny)", t_justification_enforced)

        def t_justification_passes():
            # Same tool with adequate justification — should pass
            code, resp = post("/govern", {
                "request_id": "req-long",
                "agent_id": "test",
                "workflow": "test",
                "tool": "send_email",
                "action": "bulk_send",
                "params": {},
                "justification": "This is a detailed justification explaining why we need to send this email campaign to our customers.",
                "risk_level": "500",
                "identity": {},
            })
            assert resp["decision"]["gate_state"] == "ALLOW", f"Got: {resp['decision']['gate_state']} — {resp['decision']['reason_codes']}"
        test("justification enforcement (long = allow)", t_justification_passes)

        # ── Approval workflow ─────────────────────────────────────────────────
        def t_approval_required():
            # Store a policy requiring 2 approvals
            code, resp = post("/policies", {
                "tool": "deploy_code",
                "action": "production",
                "script": 'harmony(1e-12)\nbind_authority("test", "agent", "deploy_code")\nresidual()',
                "min_approvals": 2,
            }, admin_key=ADMIN_KEY)
            assert code == 200

            # Govern — should get a token with approvals_required=2
            code, resp = post("/govern", {
                "request_id": "req-approve",
                "agent_id": "deploy-bot",
                "workflow": "deploy",
                "tool": "deploy_code",
                "action": "production",
                "params": {"version": "v2.0"},
                "justification": "deploy new version",
                "risk_level": "100",
                "identity": {},
            })
            assert resp["decision"]["gate_state"] == "ALLOW"
            assert resp["decision"]["approvals_required"] == 2
            token_id = resp["decision"]["auth_token"]["token_id"]

            # Execute without approvals — should fail
            code, resp = post("/execute", {
                "token_id": token_id,
                "executor_id": "deploy-bot",
                "tool": "deploy_code",
                "action": "production",
                "params": {"version": "v2.0"},
            })
            assert code == 403
            assert "insufficient_approvals" in resp["deny_reason"]
            assert resp["receipt"]["approvals_required"] == 2
            assert resp["receipt"]["approvals_received"] == 0

            # First approval
            code, resp = post(f"/approve/{token_id}", {"approver_id": "alice"}, admin_key=ADMIN_KEY)
            assert code == 200
            assert resp["approval_count"] == 1

            # Still not enough — 1 < 2
            code, resp = post("/execute", {
                "token_id": token_id,
                "executor_id": "deploy-bot",
                "tool": "deploy_code",
                "action": "production",
                "params": {"version": "v2.0"},
            })
            assert code == 403
            assert "insufficient_approvals" in resp["deny_reason"]

            # Second approval
            code, resp = post(f"/approve/{token_id}", {"approver_id": "bob"}, admin_key=ADMIN_KEY)
            assert code == 200
            assert resp["approval_count"] == 2

            # Now execute should work
            code, resp = post("/execute", {
                "token_id": token_id,
                "executor_id": "deploy-bot",
                "tool": "deploy_code",
                "action": "production",
                "params": {"version": "v2.0"},
            })
            assert code == 200
            assert resp["allowed"] == True
        test("approval workflow (2 required)", t_approval_required)

        # ── Policy signing ────────────────────────────────────────────────────
        def t_policy_signed():
            code, resp = post("/policies", {
                "tool": "signed_tool",
                "action": "signed_action",
                "script": 'harmony(1e-12)\nresidual()',
            }, admin_key=ADMIN_KEY)
            assert code == 200
            assert resp["signature"] is not None
            assert len(resp["signature"]) == 128  # hex-encoded Ed25519 sig

            # Get the policy — should include signature
            code, resp = get("/policies/signed_tool/signed_action")
            assert code == 200
            assert resp["signature"] is not None
        test("policy signing", t_policy_signed)

        # ── Context hashing ───────────────────────────────────────────────────
        def t_context_hash():
            # Provide a full context hash — this should be used in bind_context
            context = {"memory": {"facts": ["customer is premium", "order count: 5"]}, "session": "abc123"}
            context_hash = hashlib.sha256(json.dumps(context, sort_keys=True).encode()).hexdigest()

            code, resp = post("/govern", {
                "request_id": "req-context",
                "agent_id": "test",
                "workflow": "test",
                "tool": "send_email",
                "action": "send",
                "params": {"to": "test@example.com"},
                "justification": "test",
                "risk_level": "500",
                "identity": {},
                "context_hash": context_hash,
            })
            assert resp["decision"]["gate_state"] == "ALLOW"
        test("full context hashing", t_context_hash)

    finally:
        proc.terminate()
        proc.wait()

    # ── Test with JWT enabled ──────────────────────────────────────────────────
    # Clean the DB for a fresh start
    if os.path.exists(TEST_DB):
        os.unlink(TEST_DB)

    proc = start_gate(jwt_enabled=True)
    try:
        print("\n=== JWT Identity Tests ===")

        def t_jwt_required():
            # No JWT → should get 401
            code, resp = post("/govern", {
                "request_id": "req-jwt",
                "agent_id": "test",
                "workflow": "test",
                "tool": "send_email",
                "action": "send",
                "params": {},
                "justification": "test",
                "risk_level": "500",
                "identity": {},
            })
            assert code == 401
            assert "identity_verification_failed" in resp["decision"]["reason_codes"][0]
        test("JWT required (no token = deny)", t_jwt_required)

        def t_jwt_valid():
            # Valid JWT → agent_id comes from sub claim
            token = make_jwt("verified-agent-001")
            code, resp = post_auth("/govern", {
                "request_id": "req-jwt-valid",
                "agent_id": "spoofed-agent",  # This should be overridden by JWT sub
                "workflow": "test",
                "tool": "send_email",
                "action": "send",
                "params": {"to": "test@example.com"},
                "justification": "test",
                "risk_level": "500",
                "identity": {},
            }, jwt_token=token)
            assert code == 200
            assert resp["decision"]["gate_state"] == "ALLOW"
        test("JWT valid (sub overrides agent_id)", t_jwt_valid)

        def t_jwt_expired():
            token = make_jwt("expired-agent", exp_offset=-3600)  # expired 1 hour ago
            code, resp = post_auth("/govern", {
                "request_id": "req-jwt-expired",
                "agent_id": "test",
                "workflow": "test",
                "tool": "send_email",
                "action": "send",
                "params": {},
                "justification": "test",
                "risk_level": "500",
                "identity": {},
            }, jwt_token=token)
            assert code == 401
            assert "identity_verification_failed" in resp["decision"]["reason_codes"][0]
        test("JWT expired", t_jwt_expired)

        def t_jwt_wrong_secret():
            token = make_jwt("wrong-secret-agent", secret="wrong-secret")
            code, resp = post_auth("/govern", {
                "request_id": "req-jwt-wrong",
                "agent_id": "test",
                "workflow": "test",
                "tool": "send_email",
                "action": "send",
                "params": {},
                "justification": "test",
                "risk_level": "500",
                "identity": {},
            }, jwt_token=token)
            assert code == 401
        test("JWT wrong secret", t_jwt_wrong_secret)

        def t_jwt_execute():
            # Govern with valid JWT
            token = make_jwt("exec-agent")
            code, resp = post_auth("/govern", {
                "request_id": "req-jwt-exec",
                "agent_id": "exec-agent",
                "workflow": "test",
                "tool": "send_email",
                "action": "send",
                "params": {"to": "test@example.com"},
                "justification": "test",
                "risk_level": "500",
                "identity": {},
            }, jwt_token=token)
            assert resp["decision"]["gate_state"] == "ALLOW"
            token_id = resp["decision"]["auth_token"]["token_id"]

            # Execute with valid JWT
            code, resp = post_auth("/execute", {
                "token_id": token_id,
                "executor_id": "exec-agent",
                "tool": "send_email",
                "action": "send",
                "params": {"to": "test@example.com"},
            }, jwt_token=token)
            assert code == 200
            assert resp["allowed"] == True
        test("JWT on execute", t_jwt_execute)

        def t_jwt_execute_no_token():
            # Execute without JWT — should fail
            code, resp = post("/execute", {
                "token_id": "fake-token",
                "executor_id": "exec-agent",
                "tool": "send_email",
                "action": "send",
                "params": {},
            })
            assert code == 401
        test("JWT required on execute", t_jwt_execute_no_token)

    finally:
        proc.terminate()
        proc.wait()

    # Cleanup
    if os.path.exists(TEST_DB):
        os.unlink(TEST_DB)
    key_file = os.path.join(tempfile.gettempdir(), "dgv_v3_test.key")
    if os.path.exists(key_file):
        os.unlink(key_file)

    print(f"\n{'='*50}")
    print(f"Results: {passed} passed, {failed} failed")
    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
