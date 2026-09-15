#!/usr/bin/env python3
"""End-to-end test for the DGV Enforcement Gate v0.2.0 (persistent storage)."""

import json
import os
import subprocess
import sys
import time
import urllib.request
import urllib.error

GATE_URL = "http://127.0.0.1:7878"
DB_FILE = "/home/vdmo/pir/only-dgv-verifier/native/dgv_gate_test.db"
KEY_FILE = "/home/vdmo/pir/only-dgv-verifier/native/dgv_test_key.hex"

def post(path, body):
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        f"{GATE_URL}{path}", data=data, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())

def put(path, body):
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        f"{GATE_URL}{path}", data=data, headers={"Content-Type": "application/json"}, method="PUT"
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())

def get(path):
    req = urllib.request.Request(f"{GATE_URL}{path}")
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())

def main():
    passed = 0
    failed = 0

    # Clean up any old test DB and key
    for f in [DB_FILE, KEY_FILE]:
        if os.path.exists(f):
            os.remove(f)

    # Start the gate with SQLite
    env = os.environ.copy()
    env["DGV_STORAGE"] = "sqlite"
    env["DGV_DATABASE_URL"] = f"sqlite://{DB_FILE}"
    env["DGV_SIGNING_KEY"] = KEY_FILE
    proc = subprocess.Popen(
        ["./target/release/dgv-gate"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        cwd="/home/vdmo/pir/only-dgv-verifier/native",
        env=env,
    )
    time.sleep(2)

    try:
        # 1. Health check
        status, body = get("/health")
        assert status == 200, f"health: expected 200, got {status}"
        assert body["status"] == "ok", f"health: {body}"
        assert body["storage"] == "connected", f"health storage: {body}"
        print(f"PASS health check (storage={body['storage']})")
        passed += 1

        # 2. Govern - valid proposal (should ALLOW)
        status, gov1 = post("/govern", {
            "request_id": "req-001",
            "agent_id": "agent-42",
            "workflow": "loan_approval",
            "tool": "send_email",
            "action": "send",
            "params": {"to": "client@example.com"},
            "justification": "user requested",
            "risk_level": "1000",
            "identity": {},
        })
        assert status == 200, f"govern: expected 200, got {status}"
        assert gov1["decision"]["gate_state"] == "ALLOW", f"govern: {gov1['decision']['gate_state']}"
        token1 = gov1["decision"]["auth_token"]["token_id"]
        run_id1 = gov1["decision"]["run_id"]
        decision_hash1 = gov1["decision"]["decision_hash"]
        print(f"PASS govern (ALLOW) - token={token1}")
        passed += 1

        # 3. Execute - valid token
        status, exec1 = post("/execute", {
            "token_id": token1,
            "executor_id": "agent-42",
            "tool": "send_email",
            "action": "send",
            "params": {"to": "client@example.com"},
        })
        assert status == 200, f"execute: expected 200, got {status}"
        assert exec1["allowed"] == True
        print(f"PASS execute (valid token)")
        passed += 1

        # 4. Execute - replay (should fail)
        status, exec2 = post("/execute", {
            "token_id": token1,
            "executor_id": "agent-42",
            "tool": "send_email",
            "action": "send",
            "params": {"to": "client@example.com"},
        })
        assert status == 403
        assert exec2["allowed"] == False
        assert "consumed" in exec2["deny_reason"]
        print(f"PASS execute (replay blocked)")
        passed += 1

        # 5. Verify
        status, ver1 = get(f"/verify/{run_id1}")
        assert status == 200
        assert ver1["verified"] == True
        assert ver1["stored_decision_hash"] == decision_hash1
        print(f"PASS verify (hash matches)")
        passed += 1

        # 6. Store a custom policy
        status, pol1 = post("/policies", {
            "tool": "delete_file",
            "action": "delete",
            "script": "harmony(1e-12)\nbind_authority(\"{agent}\", \"admin\", \"delete_file\")\nbind_objective(\"delete\", [\"delete\"])\nevolve(2)\ndata(100)\ncheck_authority(\"{agent}\")\ncheck_objective_drift(\"delete\")\nresidual()",
        })
        assert status == 200, f"store policy: {status}"
        assert pol1["active"] == True
        print(f"PASS store policy (delete_file/delete)")
        passed += 1

        # 7. Get the stored policy
        status, pol2 = get("/policies/delete_file/delete")
        assert status == 200, f"get policy: {status}"
        assert pol2["tool"] == "delete_file"
        assert pol2["action"] == "delete"
        print(f"PASS get policy")
        passed += 1

        # 8. Revoke an actor
        status, rev1 = post("/revocations", {
            "actor_id": "agent-bad",
            "reason": "terminated",
            "revoked_by": "admin",
        })
        assert status == 200, f"revoke: {status}"
        assert rev1["revoked"] == True
        print(f"PASS revoke actor")
        passed += 1

        # 9. List revocations
        status, rev_list = get("/revocations")
        assert status == 200
        assert len(rev_list) >= 1
        assert any(r["actor_id"] == "agent-bad" for r in rev_list)
        print(f"PASS list revocations ({len(rev_list)} found)")
        passed += 1

        # 10. Govern with revoked actor (should DENY)
        status, gov2 = post("/govern", {
            "request_id": "req-002",
            "agent_id": "agent-bad",
            "workflow": "loan_approval",
            "tool": "send_email",
            "action": "send",
            "params": {"to": "client@example.com"},
            "justification": "user requested",
            "risk_level": "1000",
            "identity": {},
        })
        assert status == 200
        assert gov2["decision"]["gate_state"] == "DENY", f"revoked actor should DENY: {gov2['decision']['gate_state']}"
        assert any("revoked" in r for r in gov2["decision"]["reason_codes"])
        print(f"PASS govern (revoked actor denied)")
        passed += 1

        # 11. Store tenant-specific policy
        status, tp1 = post("/tenant/acme-corp/policies", {
            "tool": "send_email",
            "action": "send",
            "script": "harmony(1e-12)\nbind_authority(\"{agent}\", \"tenant_user\", \"send_email\")\nevolve(2)\ndata(500)\nresidual()",
        })
        assert status == 200
        assert tp1["active"] == True
        print(f"PASS store tenant policy (acme-corp)")
        passed += 1

        # 12. Govern with tenant_id (should use tenant policy)
        status, gov3 = post("/govern", {
            "request_id": "req-003",
            "agent_id": "agent-tenant",
            "workflow": "tenant_workflow",
            "tool": "send_email",
            "action": "send",
            "params": {"to": "tenant@example.com"},
            "justification": "tenant work",
            "risk_level": "500",
            "identity": {},
            "tenant_id": "acme-corp",
        })
        assert status == 200
        assert gov3["decision"]["gate_state"] == "ALLOW", f"tenant govern: {gov3['decision']['gate_state']}"
        print(f"PASS govern (tenant policy)")
        passed += 1

        # 13. Stats
        status, stats = get("/stats")
        assert status == 200
        assert stats["decisions_made"] >= 3
        assert stats["tokens_issued"] >= 2
        assert stats["tokens_consumed"] >= 1
        print(f"PASS stats (decisions={stats['decisions_made']}, issued={stats['tokens_issued']}, consumed={stats['tokens_consumed']})")
        passed += 1

        # 14. Persistence test - restart the gate and check data survives
        proc.terminate()
        proc.wait()
        time.sleep(1)

        proc = subprocess.Popen(
            ["./target/release/dgv-gate"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            cwd="/home/vdmo/pir/only-dgv-verifier/native",
            env=env,
        )
        time.sleep(2)

        # 15. Verify old decision still exists after restart
        status, ver2 = get(f"/verify/{run_id1}")
        assert status == 200, f"verify after restart: {status}"
        assert ver2["verified"] == True
        assert ver2["stored_decision_hash"] == decision_hash1
        print(f"PASS verify (persisted across restart)")
        passed += 1

        # 16. Revocation still active after restart
        status, rev_list2 = get("/revocations")
        assert status == 200
        assert any(r["actor_id"] == "agent-bad" for r in rev_list2)
        print(f"PASS revocation (persisted across restart)")
        passed += 1

        # 17. Old token should still be consumed after restart
        status, exec3 = post("/execute", {
            "token_id": token1,
            "executor_id": "agent-42",
            "tool": "send_email",
            "action": "send",
            "params": {"to": "client@example.com"},
        })
        assert status == 403, f"token consumption: expected 403, got {status}"
        assert exec3["allowed"] == False, f"token consumption: should not be allowed: {exec3}"
        assert "consumed" in exec3.get("deny_reason", ""), f"token consumption: wrong reason: {exec3.get('deny_reason')}"
        print(f"PASS token consumption (persisted across restart)")
        passed += 1

        # 18. Policy still active after restart
        status, pol3 = get("/policies/delete_file/delete")
        assert status == 200
        assert pol3["tool"] == "delete_file"
        print(f"PASS policy (persisted across restart)")
        passed += 1

        # 19. Rate limit config endpoint
        status, rl_config = get("/config/rate-limit")
        assert status == 200, f"rate limit config: {status}"
        assert "max_requests" in rl_config
        assert "window_ms" in rl_config
        assert "enabled" in rl_config
        print(f"PASS get rate limit config (max={rl_config['max_requests']}, window={rl_config['window_ms']}ms)")
        passed += 1

        # 20. Load policies from YAML file
        status, load_result = post("/policies/load-file", {
            "file_path": "/home/vdmo/pir/only-dgv-verifier/test_policies.yaml"
        })
        assert status == 200, f"load policy file: {status}"
        assert load_result["loaded"] >= 4, f"load policy file: expected >=4, got {load_result['loaded']}"
        assert len(load_result["errors"]) == 0, f"load policy file errors: {load_result['errors']}"
        print(f"PASS load YAML policies ({load_result['loaded']} loaded)")
        passed += 1

        # 21. Verify YAML-loaded global policy
        status, pol4 = get("/policies/export_data/export")
        assert status == 200, f"get yaml policy: {status}"
        assert pol4["tool"] == "export_data"
        assert pol4["action"] == "export"
        assert "exporter" in pol4["script"]
        print(f"PASS verify YAML-loaded global policy")
        passed += 1

        # 22. Verify YAML-loaded tenant policy (acme-corp should now have a new send_email policy)
        status, gov4 = post("/govern", {
            "request_id": "req-004",
            "agent_id": "acme-agent",
            "workflow": "tenant_workflow",
            "tool": "send_email",
            "action": "send",
            "params": {"to": "tenant@example.com"},
            "justification": "tenant work",
            "risk_level": "2000",
            "identity": {},
            "tenant_id": "acme-corp",
        })
        assert status == 200
        assert gov4["decision"]["gate_state"] == "ALLOW", f"yaml tenant govern: {gov4['decision']['gate_state']}"
        print(f"PASS govern with YAML-loaded tenant policy")
        passed += 1

        # 23. Verify YAML-loaded tenant policy (beta-inc)
        status, gov5 = post("/govern", {
            "request_id": "req-005",
            "agent_id": "beta-admin",
            "workflow": "tenant_workflow",
            "tool": "delete_file",
            "action": "delete",
            "params": {"path": "/tmp/test"},
            "justification": "tenant cleanup",
            "risk_level": "500",
            "identity": {},
            "tenant_id": "beta-inc",
        })
        assert status == 200
        assert gov5["decision"]["gate_state"] == "ALLOW", f"yaml beta tenant govern: {gov5['decision']['gate_state']}"
        print(f"PASS govern with YAML-loaded beta-inc tenant policy")
        passed += 1

        # 24. Rate limiting test - update config at runtime via PUT
        status, rl_get = get("/config/rate-limit")
        assert status == 200
        assert rl_get["enabled"] == True
        assert rl_get["max_requests"] == 100
        print(f"PASS get rate limit config (max={rl_get['max_requests']}, enabled={rl_get['enabled']})")
        passed += 1

        # 25. Update rate limit at runtime via PUT
        status, rl_updated = put("/config/rate-limit", {
            "max_requests": 3,
            "window_ms": 60000,
            "enabled": True,
        })
        assert status == 200, f"update rate limit: {status}"
        assert rl_updated["max_requests"] == 3, f"updated config: {rl_updated}"
        print(f"PASS update rate limit at runtime (max={rl_updated['max_requests']})")
        passed += 1

        # 26. Send 3 requests (should succeed with new limit)
        rl_passes = 0
        for i in range(3):
            status, _ = post("/govern", {
                "request_id": f"req-rl-{i}",
                "agent_id": "rl-test-agent",
                "workflow": "test",
                "tool": "rl_test_tool",
                "action": "test",
                "params": {"i": i},
                "justification": "rate limit test",
                "risk_level": "1000",
                "identity": {},
            })
            if status == 200:
                rl_passes += 1

        # 4th request should be rate limited
        status, rl_blocked = post("/govern", {
            "request_id": "req-rl-blocked",
            "agent_id": "rl-test-agent",
            "workflow": "test",
            "tool": "rl_test_tool",
            "action": "test",
            "params": {"i": 99},
            "justification": "rate limit test",
            "risk_level": "1000",
            "identity": {},
        })
        assert status == 429, f"rate limit: expected 429, got {status}"
        assert rl_blocked["decision"]["gate_state"] == "DENY"
        assert "rate_limit_exceeded" in rl_blocked["decision"]["reason_codes"]
        assert rl_passes == 3, f"rate limit: expected 3 passes, got {rl_passes}"
        print(f"PASS rate limiting (3 allowed, 4th blocked with 429)")
        passed += 1

        # 27. Different agent should not be rate limited
        status, rl_other = post("/govern", {
            "request_id": "req-rl-other",
            "agent_id": "other-agent",
            "workflow": "test",
            "tool": "rl_test_tool",
            "action": "test",
            "params": {"i": 0},
            "justification": "rate limit test",
            "risk_level": "1000",
            "identity": {},
        })
        assert status == 200, f"rate limit other agent: expected 200, got {status}"
        assert rl_other["decision"]["gate_state"] == "ALLOW"
        print(f"PASS rate limiting (different agent not blocked)")
        passed += 1

        # 28. Disable rate limiting at runtime
        status, rl_disabled = put("/config/rate-limit", {
            "enabled": False,
        })
        assert status == 200
        assert rl_disabled["enabled"] == False
        print(f"PASS disable rate limiting at runtime")
        passed += 1

        # 29. Now the 4th request should succeed (rate limiting disabled)
        status, rl_allowed = post("/govern", {
            "request_id": "req-rl-disabled",
            "agent_id": "rl-test-agent",
            "workflow": "test",
            "tool": "rl_test_tool",
            "action": "test",
            "params": {"i": 100},
            "justification": "rate limit disabled test",
            "risk_level": "1000",
            "identity": {},
        })
        assert status == 200, f"rate limit disabled: expected 200, got {status}"
        assert rl_allowed["decision"]["gate_state"] == "ALLOW"
        print(f"PASS rate limiting disabled (request allowed)")
        passed += 1

    except AssertionError as e:
        print(f"FAIL {e}")
        failed += 1
    except Exception as e:
        print(f"ERROR {e}")
        failed += 1
    finally:
        proc.terminate()
        proc.wait()

    print(f"\n=== Results: {passed} passed, {failed} failed ===")
    sys.exit(0 if failed == 0 else 1)

if __name__ == "__main__":
    main()
