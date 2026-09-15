"""Test dgv_python PyO3 bindings — in-process governance without HTTP server."""
import dgv_python
import tempfile
import os

def main():
    # Use in-memory SQLite for testing
    gate = dgv_python.Gate("sqlite", ":memory:")
    print("[PASS] Gate created")

    # Test 1: Govern — should ALLOW
    result = gate.govern({
        "request_id": "req-001",
        "agent_id": "test-agent",
        "workflow": "test",
        "tool": "send_email",
        "action": "send",
        "params": {"to": "alice@example.com"},
        "justification": "test",
        "risk_level": "500",
        "identity": {"type": "agent"},
    })
    assert result["gate_state"] == "ALLOW", f"Expected ALLOW, got {result['gate_state']}"
    assert result["allowed"] == True
    assert result["token_id"] is not None
    token_id = result["token_id"]
    print(f"[PASS] Govern ALLOW, token_id={token_id}")

    # Test 2: Execute with valid token
    exec_result = gate.execute(token_id, "executor-1", "send_email", "send", {"to": "alice@example.com"})
    assert exec_result["allowed"] == True, f"Expected allowed=True, got {exec_result}"
    assert exec_result["receipt"]["params_hash"] is not None
    print(f"[PASS] Execute allowed, params_hash={exec_result['receipt']['params_hash'][:16]}...")

    # Test 3: Replay same token — should fail
    try:
        exec_result2 = gate.execute(token_id, "executor-1", "send_email", "send", {"to": "alice@example.com"})
        if exec_result2["allowed"]:
            print("[FAIL] Replay should have been denied")
        else:
            print(f"[PASS] Replay denied: {exec_result2.get('deny_reason', 'unknown')}")
    except Exception as e:
        print(f"[PASS] Replay raised exception: {e}")

    # Test 4: Execute with wrong tool — should fail
    try:
        bad_result = gate.execute(token_id, "executor-1", "wrong_tool", "send", {})
        if bad_result["allowed"]:
            print("[FAIL] Wrong tool should have been denied")
        else:
            print(f"[PASS] Wrong tool denied: {bad_result.get('deny_reason', 'unknown')}")
    except Exception as e:
        print(f"[PASS] Wrong tool raised exception: {e}")

    # Test 5: Revoke agent, then govern again
    gate.revoke("test-agent", "security incident", "admin")
    result2 = gate.govern({
        "request_id": "req-002",
        "agent_id": "test-agent",
        "workflow": "test",
        "tool": "send_email",
        "action": "send",
        "params": {"to": "bob@example.com"},
        "justification": "test",
        "risk_level": "500",
        "identity": {"type": "agent"},
    })
    assert result2["gate_state"] == "DENY", f"Expected DENY after revocation, got {result2['gate_state']}"
    assert "revoked" in result2["reason_codes"][0].lower()
    print(f"[PASS] Revocation blocks govern: {result2['reason_codes']}")

    # Test 6: Verify decision
    verify = gate.verify(result["run_id"])
    assert verify["verified"] == True
    print(f"[PASS] Verify: {verify}")

    # Test 7: Verify key
    vk = gate.verifying_key
    assert len(vk) == 64  # hex-encoded Ed25519 public key
    print(f"[PASS] Verifying key: {vk[:16]}...")

    # Test 8: Store and use a policy
    gate.store_policy("custom_tool", "custom_action", 
        'harmony(1e-12)\nbind_authority("test-agent", "agent", "custom_tool")\nresidual()', 
        "v1.0")
    result3 = gate.govern({
        "request_id": "req-003",
        "agent_id": "test-agent-2",
        "workflow": "test",
        "tool": "custom_tool",
        "action": "custom_action",
        "params": {},
        "justification": "test",
        "risk_level": "100",
        "identity": {},
    })
    print(f"[PASS] Custom policy govern: {result3['gate_state']}")

    print("\nAll dgv_python tests passed!")

if __name__ == "__main__":
    main()
