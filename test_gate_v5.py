"""Test gate v0.4.0 hardening: graceful shutdown, health depth, structured
logging, Prometheus metrics, policy versioning/rollback, OIDC discovery,
CrewAI adapter, govern_all_tools middleware."""
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import hashlib
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

GATE_BINARY = os.path.join(os.path.dirname(__file__), "native", "target", "release", "dgv-gate")
TEST_DB = tempfile.mktemp(suffix=".db", prefix="dgv_v5_test_")
TEST_PORT = "7894"
BASE_URL = f"http://127.0.0.1:{TEST_PORT}"
ADMIN_KEY = "test-admin-key-v5"

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


def get(path, headers=None, admin_key=None, raw=False):
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
            body = resp.read()
            return resp.status, (body.decode() if raw else json.loads(body))
    except urllib.error.HTTPError as e:
        body = e.read()
        return e.code, (body.decode() if raw else json.loads(body))


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


# ── OIDC discovery test server ───────────────────────────────────────────────

OIDC_STATE = {"jwks_uri": None, "issuer": None}


class OidcHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path == "/.well-known/openid-configuration":
            body = json.dumps({
                "issuer": OIDC_STATE["issuer"],
                "jwks_uri": OIDC_STATE["jwks_uri"],
            }).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()


def start_gate(extra_env=None, capture_output=False):
    env = os.environ.copy()
    env["DGV_STORAGE"] = "sqlite"
    env["DGV_DATABASE_URL"] = f"sqlite://{TEST_DB}"
    env["DGV_LISTEN_ADDR"] = f"127.0.0.1:{TEST_PORT}"
    env["DGV_ADMIN_KEY"] = ADMIN_KEY
    env["DGV_RATE_LIMIT_DISABLED"] = "1"
    env["DGV_SIGNING_KEY"] = os.path.join(tempfile.gettempdir(), "dgv_v5_test.key")
    for k in ("DGV_JWT_SECRET", "DGV_JWT_PUBLIC_KEY", "DGV_JWT_JWKS_URL",
              "DGV_OIDC_ISSUER", "DGV_SEMANTIC_VERIFIER_URL", "DGV_LOG_FORMAT"):
        env.pop(k, None)
    if extra_env:
        env.update(extra_env)

    proc = subprocess.Popen(
        [GATE_BINARY],
        env=env,
        stdout=subprocess.PIPE if capture_output else subprocess.DEVNULL,
        stderr=subprocess.STDOUT if capture_output else subprocess.DEVNULL,
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
    # ═══════════════════════════════════════════════════════════════════════
    # Suite 1: Health depth + metrics + structured logging + graceful shutdown
    # ═══════════════════════════════════════════════════════════════════════
    clean_db()
    proc = start_gate({"DGV_LOG_FORMAT": "json"}, capture_output=True)
    try:
        print("\n=== Observability Tests ===")

        def t_health_depth():
            code, resp = get("/health")
            assert code == 200
            assert resp["status"] == "ok"
            assert "uptime_ms" in resp
            assert resp["uptime_ms"] >= 0
            assert resp["version"] == "0.4.0"
            assert resp["storage"] == "connected"
            assert resp["signing_key_loaded"] is True
            assert resp["jwt_mode"] == "disabled"
            assert resp["admin_auth"] is True
        test("health check depth", t_health_depth)

        def t_metrics_endpoint():
            # Make a decision first so counters are non-zero
            post("/govern", govern_req("m-1", "agent-a", "metric_tool", "run"))
            code, body = get("/metrics", raw=True)
            assert code == 200
            assert "dgv_decisions_total" in body
            assert "dgv_denials_total" in body
            assert "dgv_tokens_issued_total" in body
            assert "dgv_uptime_ms" in body
            # Verify it's valid Prometheus text format (key value lines)
            lines = [l for l in body.strip().split("\n") if not l.startswith("#")]
            assert all(" " in l for l in lines), "metrics lines must be 'name value'"
            import re
            m = re.search(r"dgv_decisions_total (\d+)", body)
            assert m and int(m.group(1)) >= 1
        test("Prometheus /metrics endpoint", t_metrics_endpoint)

        def t_structured_logging():
            # Gate was started with DGV_LOG_FORMAT=json — startup lines should be JSON
            time.sleep(0.3)
            proc.stdout.flush()
            # Read whatever is available without blocking
            import fcntl
            fd = proc.stdout.fileno()
            fl = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
            try:
                out = proc.stdout.read() or b""
            except Exception:
                out = b""
            lines = [l for l in out.decode(errors="replace").strip().split("\n") if l.strip()]
            json_lines = 0
            for line in lines:
                try:
                    obj = json.loads(line)
                    if "event" in obj and "ts_unix_ms" in obj:
                        json_lines += 1
                except json.JSONDecodeError:
                    pass
            assert json_lines >= 2, f"expected JSON log lines, got: {lines[:5]}"
        test("structured JSON logging", t_structured_logging)

    finally:
        pass  # proc used below for shutdown test

    def t_graceful_shutdown():
        proc.send_signal(signal.SIGTERM)
        try:
            rc = proc.wait(timeout=10)
            assert rc == 0, f"expected clean exit (0), got {rc}"
        except subprocess.TimeoutExpired:
            proc.kill()
            raise AssertionError("gate did not shut down within 10s")
    test("graceful shutdown (SIGTERM → exit 0)", t_graceful_shutdown)

    # ═══════════════════════════════════════════════════════════════════════
    # Suite 2: Policy versioning + rollback
    # ═══════════════════════════════════════════════════════════════════════
    clean_db()
    proc = start_gate()
    try:
        print("\n=== Policy Versioning Tests ===")

        def t_policy_versions():
            # Store v1
            code, r1 = post("/policies", {
                "tool": "versioned_tool", "action": "act",
                "script": 'harmony(1e-12)\nresidual()',
                "policy_version": "v1",
            }, admin_key=ADMIN_KEY)
            assert code == 200
            v1_id = r1["policy_id"]

            # Store v2 (deactivates v1)
            code, r2 = post("/policies", {
                "tool": "versioned_tool", "action": "act",
                "script": 'harmony(1e-12)\nbind_authority("x", "agent", "versioned_tool")\nresidual()',
                "policy_version": "v2",
            }, admin_key=ADMIN_KEY)
            assert code == 200

            # List versions — should have both, v2 active
            code, resp = get("/policies/versioned_tool/act/versions")
            assert code == 200
            versions = resp["versions"]
            assert len(versions) == 2
            active = [v for v in versions if v["active"]]
            assert len(active) == 1
            assert active[0]["policy_version"] == "v2"
            return v1_id
        v1_id_holder = []
        def t_policy_versions_wrap():
            v1_id_holder.append(t_policy_versions())
        test("policy versions listed (v1+v2, v2 active)", t_policy_versions_wrap)

        def t_policy_rollback():
            v1_id = v1_id_holder[0]
            code, resp = post(f"/policies/{v1_id}/rollback", {}, admin_key=ADMIN_KEY)
            assert code == 200 and resp["rolled_back"] is True

            # Now v1 should be active again
            code, resp = get("/policies/versioned_tool/act")
            assert resp["policy_version"] == "v1"

            # And versions show v1 active, v2 inactive
            code, resp = get("/policies/versioned_tool/act/versions")
            active = [v for v in resp["versions"] if v["active"]]
            assert len(active) == 1 and active[0]["policy_version"] == "v1"
        test("policy rollback reactivates previous version", t_policy_rollback)

        def t_rollback_nonexistent():
            code, resp = post("/policies/nonexistent-id/rollback", {}, admin_key=ADMIN_KEY)
            assert code == 404
        test("rollback nonexistent policy → 404", t_rollback_nonexistent)

        def t_rollback_requires_admin():
            v1_id = v1_id_holder[0]
            code, resp = post(f"/policies/{v1_id}/rollback", {})
            assert code == 401
        test("rollback requires admin", t_rollback_requires_admin)

    finally:
        proc.terminate()
        proc.wait()

    # ═══════════════════════════════════════════════════════════════════════
    # Suite 3: OIDC discovery
    # ═══════════════════════════════════════════════════════════════════════
    # Serve a discovery doc pointing at a JWKS URL (reuse v4 test approach)
    from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
    from cryptography.hazmat.primitives import hashes
    import base64, hmac as hmac_mod

    def b64url(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    nums = rsa_key.public_key().public_numbers()
    jwks = {"keys": [{
        "kty": "RSA", "kid": "oidc-key-1", "use": "sig", "alg": "RS256",
        "n": b64url(nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big")),
        "e": b64url(nums.e.to_bytes((nums.e.bit_length() + 7) // 8, "big")),
    }]}

    OIDC_PORT = 7895

    class FullOidcHandler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def do_GET(self):
            if self.path == "/.well-known/openid-configuration":
                body = json.dumps({
                    "issuer": f"http://127.0.0.1:{OIDC_PORT}",
                    "jwks_uri": f"http://127.0.0.1:{OIDC_PORT}/jwks.json",
                }).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body)
            elif self.path == "/jwks.json":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(jwks).encode())
            else:
                self.send_response(404)
                self.end_headers()

    oidc_server = HTTPServer(("127.0.0.1", OIDC_PORT), FullOidcHandler)
    threading.Thread(target=oidc_server.serve_forever, daemon=True).start()

    clean_db()
    proc = start_gate({"DGV_OIDC_ISSUER": f"http://127.0.0.1:{OIDC_PORT}"})
    try:
        print("\n=== OIDC Discovery Tests ===")

        def t_oidc_rs256_works():
            # Gate should have discovered jwks_uri via OIDC — sign with RSA key
            header = b64url(json.dumps({"alg": "RS256", "typ": "JWT", "kid": "oidc-key-1"}).encode())
            payload = {"sub": "oidc-agent", "iat": int(time.time()),
                       "exp": int(time.time()) + 3600,
                       "iss": f"http://127.0.0.1:{OIDC_PORT}"}
            payload_b64 = b64url(json.dumps(payload).encode())
            sig = rsa_key.sign(f"{header}.{payload_b64}".encode(),
                               rsa_padding.PKCS1v15(), hashes.SHA256())
            token = f"{header}.{payload_b64}.{b64url(sig)}"

            code, resp = post("/govern", govern_req("oidc-1", "spoofed", "oidc_tool", "act"),
                              headers={"Authorization": f"Bearer {token}"})
            assert code == 200, resp
            assert resp["decision"]["gate_state"] == "ALLOW"
        test("OIDC discovery → RS256 verification works", t_oidc_rs256_works)

        def t_oidc_no_token_denied():
            code, resp = post("/govern", govern_req("oidc-2", "x", "oidc_tool", "act"))
            assert code == 401
        test("OIDC mode: no token → 401", t_oidc_no_token_denied)

    finally:
        proc.terminate()
        proc.wait()
        oidc_server.shutdown()

    # ═══════════════════════════════════════════════════════════════════════
    # Suite 4: CrewAI adapter + govern_all_tools
    # ═══════════════════════════════════════════════════════════════════════
    clean_db()
    proc = start_gate()
    try:
        print("\n=== Framework Adapter Tests ===")

        def t_crewai_governed_tool():
            from dgv_crewai import CrewAIGovernedTool

            class MockTool:
                name = "crew_search"
                description = "Search the web"
                def _run(self, query: str = "") -> str:
                    return f"results for {query}"

            governed = CrewAIGovernedTool(
                tool=MockTool(),
                gate_url=BASE_URL,
                agent_id="crew-agent",
            )
            result = json.loads(governed.run(query="test query"))
            assert result["governance"]["gate_state"] == "ALLOW"
            assert result["execution"]["allowed"] is True
            assert "results for test query" in result["result"]
        test("CrewAI GovernedTool (allow path)", t_crewai_governed_tool)

        def t_crewai_denied():
            from dgv_crewai import CrewAIGovernedTool
            # Revoke the agent first
            post("/revocations", {"actor_id": "bad-crew-agent", "reason": "test",
                                  "revoked_by": "test"}, admin_key=ADMIN_KEY)

            class MockTool:
                name = "crew_write"
                def _run(self, **kw):
                    return "should not run"

            governed = CrewAIGovernedTool(
                tool=MockTool(),
                gate_url=BASE_URL,
                agent_id="bad-crew-agent",
            )
            result = json.loads(governed.run(data="x"))
            assert result["error"] == "governance_denied"
        test("CrewAI GovernedTool (deny path)", t_crewai_denied)

        def t_crewai_real_basetool():
            try:
                from crewai.tools import BaseTool
            except ImportError:
                print("    (skipped — crewai not installed)")
                return
            from dgv_crewai import CrewAIGovernedTool

            class RealSearchTool(BaseTool):
                name: str = "real_search"
                description: str = "Real CrewAI search tool"
                def _run(self, query: str = "", **kw) -> str:
                    return f"real results for {query}"

            governed = CrewAIGovernedTool(
                tool=RealSearchTool(),
                gate_url=BASE_URL,
                agent_id="real-crew-agent",
            )
            # Must be a real BaseTool instance — usable in a Crew directly
            assert isinstance(governed, BaseTool)
            result = json.loads(governed.run(query="crewai"))
            assert result["governance"]["gate_state"] == "ALLOW"
            assert "real results for crewai" in result["result"]
        test("CrewAI real BaseTool (end-to-end)", t_crewai_real_basetool)

        def t_govern_all_tools():
            try:
                from langchain_core.tools import tool as lc_tool
                from dgv_langchain import govern_all_tools
            except ImportError:
                print("    (skipped — langchain-core not installed)")
                return

            @lc_tool
            def tool_a(x: str) -> str:
                """Tool A."""
                return f"A:{x}"

            @lc_tool
            def tool_b(y: int) -> str:
                """Tool B."""
                return f"B:{y}"

            governed = govern_all_tools([tool_a, tool_b], gate_url=BASE_URL,
                                        agent_id="executor-agent")
            assert len(governed) == 2
            assert governed[0].name == "governed_tool_a"
            assert governed[1].name == "governed_tool_b"
            # Invoke one — should go through govern+execute
            result = json.loads(governed[0].invoke({"x": "hi"}))
            assert result["governance"]["gate_state"] == "ALLOW"
            assert "A:hi" in result["result"]
        test("govern_all_tools middleware", t_govern_all_tools)

    finally:
        proc.terminate()
        proc.wait()

    # Cleanup
    clean_db()
    key_file = os.path.join(tempfile.gettempdir(), "dgv_v5_test.key")
    if os.path.exists(key_file):
        os.unlink(key_file)

    print(f"\n{'='*50}")
    print(f"Results: {passed} passed, {failed} failed")
    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
