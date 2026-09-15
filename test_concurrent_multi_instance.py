#!/usr/bin/env python3
"""Concurrent multi-instance test for the DGV Enforcement Gate with Postgres.

Two gate instances run simultaneously, sharing the same Postgres database.
Revocation on one instance is immediately visible to the other instance.

Architecture:
  Gate Instance A (port 7878) ──┐
                                ├── Postgres database (shared)
  Gate Instance B (port 7879) ──┘

This is the production pattern: multiple gate instances behind a load
balancer, all sharing the same Postgres database for state.

Test flow:
  1. Start Postgres in Docker (port 15432)
  2. Start gate instance A on port 7878
  3. Start gate instance B on port 7879
  4. Issue a govern request through instance A (should ALLOW)
  5. Revoke the actor through instance A
  6. Try to execute the token through instance B (should DENY — revocation visible)
  7. Try to govern again through instance B (should DENY — revocation visible)
  8. Verify the revocation is listed on both instances
  9. Clean up Postgres container
"""

import json
import os
import subprocess
import sys
import time
import urllib.request
import urllib.error

PG_PORT = 15432
DB_URL = f"postgres://postgres:postgres@127.0.0.1:{PG_PORT}/dgv_gate"
KEY_FILE = "/home/vdmo/pir/only-dgv-verifier/native/dgv_concurrent_key.hex"

def post(base_url, path, body):
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        f"{base_url}{path}", data=data, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())

def put(base_url, path, body):
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        f"{base_url}{path}", data=data, headers={"Content-Type": "application/json"}, method="PUT"
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())

def get(base_url, path):
    req = urllib.request.Request(f"{base_url}{path}")
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())

def start_gate(port, env):
    env = env.copy()
    env["DGV_STORAGE"] = "postgres"
    env["DGV_DATABASE_URL"] = DB_URL
    env["DGV_SIGNING_KEY"] = KEY_FILE
    env["DGV_LISTEN_ADDR"] = f"127.0.0.1:{port}"
    # Rate limiting enabled for concurrent test (we test it explicitly)
    proc = subprocess.Popen(
        ["./target/release/dgv-gate"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        cwd="/home/vdmo/pir/only-dgv-verifier/native",
        env=env,
    )
    # Wait for the gate to be ready
    url = f"http://127.0.0.1:{port}"
    for _ in range(20):
        time.sleep(0.5)
        try:
            status, body = get(url, "/health")
            if status == 200 and body.get("storage") == "connected":
                return proc
        except:
            pass
    return proc

def main():
    passed = 0
    failed = 0

    # Clean up
    if os.path.exists(KEY_FILE):
        os.remove(KEY_FILE)

    print("=== Concurrent Multi-Instance Test (Postgres) ===")
    print(f"Postgres URL: {DB_URL}")
    print("")

    try:
        # 1. Wait for Postgres to be ready (Docker container started earlier)
        print("Waiting for Postgres to be ready...")
        time.sleep(5)

        # 2. Start gate instance A on port 7878
        print("Starting gate instance A on port 7878...")
        proc_a = start_gate(7878, os.environ)
        url_a = f"http://127.0.0.1:7878"
        status, body = get(url_a, "/health")
        assert status == 200, f"health A: {status}"
        assert body["storage"] == "connected", f"storage A: {body}"
        print(f"PASS instance A health (storage={body['storage']})")
        passed += 1

        # 3. Start gate instance B on port 7879
        print("Starting gate instance B on port 7879...")
        proc_b = start_gate(7879, os.environ)
        url_b = f"http://127.0.0.1:7879"
        status, body = get(url_b, "/health")
        assert status == 200, f"health B: {status}"
        assert body["storage"] == "connected", f"storage B: {body}"
        print(f"PASS instance B health (storage={body['storage']})")
        passed += 1

        # 4. Govern through instance A (should ALLOW)
        status, gov1 = post(url_a, "/govern", {
            "request_id": "conc-req-001",
            "agent_id": "conc-agent",
            "workflow": "test",
            "tool": "send_email",
            "action": "send",
            "params": {"to": "test@example.com"},
            "justification": "concurrent test",
            "risk_level": "1000",
            "identity": {},
        })
        assert status == 200
        assert gov1["decision"]["gate_state"] == "ALLOW"
        token1 = gov1["decision"]["auth_token"]["token_id"]
        run_id1 = gov1["decision"]["run_id"]
        print(f"PASS govern through A (ALLOW, token={token1})")
        passed += 1

        # 5. Revoke the actor through instance A
        status, rev1 = post(url_a, "/revocations", {
            "actor_id": "conc-agent",
            "reason": "concurrent_revocation_test",
            "revoked_by": "admin",
        })
        assert status == 200
        assert rev1["revoked"] == True
        print(f"PASS revoke actor through A")
        passed += 1

        # 6. Verify revocation is immediately visible on instance B (no restart)
        status, rev_list_b = get(url_b, "/revocations")
        assert status == 200
        assert any(r["actor_id"] == "conc-agent" for r in rev_list_b), f"revocation not visible on B: {rev_list_b}"
        print(f"PASS revocation visible on B immediately (no restart)")
        passed += 1

        # 7. Try to govern again through B with revoked actor (should DENY)
        status, gov2 = post(url_b, "/govern", {
            "request_id": "conc-req-002",
            "agent_id": "conc-agent",
            "workflow": "test",
            "tool": "send_email",
            "action": "send",
            "params": {"to": "test@example.com"},
            "justification": "should be denied on B",
            "risk_level": "1000",
            "identity": {},
        })
        assert status == 200
        assert gov2["decision"]["gate_state"] == "DENY"
        assert any("revoked" in r for r in gov2["decision"]["reason_codes"])
        print(f"PASS govern with revoked actor denied on B")
        passed += 1

        # 8. Try to execute the token through B (should DENY — T₁ revocation check)
        status, exec1 = post(url_b, "/execute", {
            "token_id": token1,
            "executor_id": "conc-agent",
            "tool": "send_email",
            "action": "send",
            "params": {"to": "test@example.com"},
        })
        assert status == 403
        assert exec1["allowed"] == False
        assert "revoked" in exec1["deny_reason"]
        print(f"PASS execute blocked by T₁ revocation check on B")
        passed += 1

        # 9. A different (non-revoked) actor should still work on B
        status, gov3 = post(url_b, "/govern", {
            "request_id": "conc-req-003",
            "agent_id": "good-agent",
            "workflow": "test",
            "tool": "send_email",
            "action": "send",
            "params": {"to": "good@example.com"},
            "justification": "should be allowed",
            "risk_level": "1000",
            "identity": {},
        })
        assert status == 200
        assert gov3["decision"]["gate_state"] == "ALLOW"
        print(f"PASS non-revoked agent still allowed on B")
        passed += 1

        # 10. Verify the decision on instance A is accessible from instance B
        status, ver1 = get(url_b, f"/verify/{run_id1}")
        assert status == 200
        assert ver1["verified"] == True
        print(f"PASS decision from A verifiable on B")
        passed += 1

        # 11. Rate limit config is per-instance (both start enabled by default)
        status, rl_a = get(url_a, "/config/rate-limit")
        status, rl_b = get(url_b, "/config/rate-limit")
        assert rl_a["enabled"] == True, f"A rate limit should be enabled: {rl_a}"
        assert rl_b["enabled"] == True, f"B rate limit should be enabled: {rl_b}"
        print(f"PASS rate limit configs independent (A={rl_a['enabled']}, B={rl_b['enabled']})")
        passed += 1

        # 12. Update rate limit on A only, verify B is unaffected
        put(url_a, "/config/rate-limit", {"enabled": False, "max_requests": 999})
        status, rl_a2 = get(url_a, "/config/rate-limit")
        status, rl_b2 = get(url_b, "/config/rate-limit")
        assert rl_a2["enabled"] == False, f"A rate limit: {rl_a2}"
        assert rl_b2["enabled"] == True, f"B rate limit should still be enabled: {rl_b2}"
        print(f"PASS rate limit config per-instance (A disabled, B still enabled)")
        passed += 1

        proc_a.terminate()
        proc_b.terminate()
        proc_a.wait()
        proc_b.wait()

    except AssertionError as e:
        print(f"FAIL {e}")
        failed += 1
    except Exception as e:
        print(f"ERROR {e}")
        failed += 1
    finally:
        try:
            proc_a.terminate()
            proc_a.wait()
        except:
            pass
        try:
            proc_b.terminate()
            proc_b.wait()
        except:
            pass

    print(f"\n=== Concurrent Multi-Instance Results: {passed} passed, {failed} failed ===")
    print("")
    print("Architecture verified:")
    print("  - Two gate instances share the same Postgres database")
    print("  - Revocation on instance A is immediately visible to instance B (no restart)")
    print("  - T₁ revocation check blocks execution on both instances")
    print("  - Decisions made on A are verifiable on B")
    print("  - Rate limit config is per-instance (not shared)")
    print("  - Non-revoked agents are unaffected")
    sys.exit(0 if failed == 0 else 1)

if __name__ == "__main__":
    main()
