"""Test dgv_sdk.py + dgv_langchain.py against a running gate."""
import json
import os
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dgv_sdk import GateClient, GateError

GATE_BINARY = os.path.join(os.path.dirname(__file__), "native", "target", "release", "dgv-gate")
TEST_DB = tempfile.mktemp(suffix=".db", prefix="dgv_sdk_test_")
TEST_PORT = "7890"
BASE_URL = f"http://127.0.0.1:{TEST_PORT}"
ADMIN_KEY = "test-admin-key-123"

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


def start_gate():
    env = os.environ.copy()
    env["DGV_STORAGE"] = "sqlite"
    env["DGV_DATABASE_URL"] = f"sqlite://{TEST_DB}"
    env["DGV_LISTEN_ADDR"] = f"127.0.0.1:{TEST_PORT}"
    env["DGV_ADMIN_KEY"] = ADMIN_KEY
    env["DGV_RATE_LIMIT_DISABLED"] = "1"
    env["DGV_SIGNING_KEY"] = os.path.join(tempfile.gettempdir(), "dgv_sdk_test.key")

    proc = subprocess.Popen(
        [GATE_BINARY],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )

    for _ in range(30):
        try:
            client = GateClient(BASE_URL)
            h = client.health()
            if h.status == "ok":
                return proc
        except:
            pass
        time.sleep(0.2)

    proc.kill()
    raise RuntimeError("Gate did not start")


def main():
    proc = start_gate()
    try:
        client = GateClient(BASE_URL, admin_key=ADMIN_KEY)

        # ── SDK tests ────────────────────────────────────────────────────────
        print("\n=== SDK Tests ===")

        def t_health():
            h = client.health()
            assert h.status == "ok"
            assert h.version == "0.4.0"
        test("health", t_health)

        def t_govern_allow():
            d = client.govern(
                agent_id="sdk-test",
                workflow="test",
                tool="send_email",
                action="send",
                params={"to": "alice@example.com"},
                justification="test",
                risk_level="500",
            )
            assert d.allowed, f"Expected ALLOW, got {d.gate_state}"
            assert d.token_id is not None
            assert len(d.decision_hash) == 64
            assert len(d.signature) == 128
            assert len(d.verifying_key) == 64
        test("govern allow", t_govern_allow)

        def t_execute():
            d = client.govern(
                agent_id="sdk-test",
                workflow="test",
                tool="send_email",
                action="send",
                params={"to": "bob@example.com"},
                justification="test",
                risk_level="500",
            )
            assert d.allowed
            r = client.execute(
                token_id=d.token_id,
                executor_id="sdk-test",
                tool="send_email",
                action="send",
                params={"to": "bob@example.com"},
            )
            assert r.allowed
            assert r.receipt["consumed_unix_ms"] > 0
        test("execute", t_execute)

        def t_replay():
            d = client.govern(
                agent_id="sdk-test",
                workflow="test",
                tool="send_email",
                action="send",
                params={"to": "carol@example.com"},
                justification="test",
                risk_level="500",
            )
            r1 = client.execute(token_id=d.token_id, executor_id="sdk-test",
                               tool="send_email", action="send", params={"to": "carol@example.com"})
            assert r1.allowed
            r2 = client.execute(token_id=d.token_id, executor_id="sdk-test",
                               tool="send_email", action="send", params={"to": "carol@example.com"})
            assert not r2.allowed
            assert r2.deny_reason == "token_already_consumed"
        test("replay prevention", t_replay)

        def t_wrong_params():
            d = client.govern(
                agent_id="sdk-test",
                workflow="test",
                tool="send_email",
                action="send",
                params={"to": "dave@example.com"},
                justification="test",
                risk_level="500",
            )
            r = client.execute(token_id=d.token_id, executor_id="sdk-test",
                              tool="send_email", action="send", params={"to": "eve@example.com"})
            assert not r.allowed
            assert r.deny_reason == "token_params_mismatch"
        test("params mismatch", t_wrong_params)

        def t_verify():
            d = client.govern(
                agent_id="sdk-test",
                workflow="test",
                tool="send_email",
                action="send",
                params={"to": "frank@example.com"},
                justification="test",
                risk_level="500",
            )
            v = client.verify(d.run_id)
            assert v.verified
            assert v.stored_decision_hash == d.decision_hash
        test("verify", t_verify)

        def t_stats():
            s = client.stats()
            assert s.decisions_made > 0
        test("stats", t_stats)

        def t_revoke():
            client.revoke("sdk-revoked", "test revocation", "test")
            d = client.govern(
                agent_id="sdk-revoked",
                workflow="test",
                tool="send_email",
                action="send",
                params={},
                justification="test",
                risk_level="500",
            )
            assert d.denied
            assert "revoked" in d.reason_codes[0].lower()
        test("revocation", t_revoke)

        def t_policy():
            client.store_policy("custom_tool", "custom_action",
                'harmony(1e-12)\nbind_authority("sdk-test", "agent", "custom_tool")\nresidual()', "v1")
            p = client.get_policy("custom_tool", "custom_action")
            assert p is not None
            assert p.tool == "custom_tool"
        test("store/get policy", t_policy)

        def t_admin_auth():
            no_auth = GateClient(BASE_URL)  # no admin key
            try:
                no_auth.revoke("should-fail", "test", "test")
                assert False, "Should have gotten 401"
            except GateError as e:
                assert e.status == 401
        test("admin auth required", t_admin_auth)

        def t_rate_limit():
            rl = client.get_rate_limit()
            assert rl.enabled == False  # disabled in test
            client.update_rate_limit(max_requests=5, window_ms=60000, enabled=True)
            rl2 = client.get_rate_limit()
            assert rl2.max_requests == 5
        test("rate limit config", t_rate_limit)

        # ── LangChain tests ──────────────────────────────────────────────────
        print("\n=== LangChain Tests ===")

        try:
            from langchain_core.tools import tool
            HAS_LC = True
        except ImportError:
            HAS_LC = False
            print("  [SKIP] langchain-core not installed")

        if HAS_LC:
            def t_langchain_governed_allow():
                from dgv_langchain import GovernedTool

                @tool
                def check_inventory(item: str) -> str:
                    """Check inventory for an item."""
                    return f"5 units of {item}"

                governed = GovernedTool(
                    tool=check_inventory,
                    gate_url=BASE_URL,
                    agent_id="lc-test",
                    workflow="inventory",
                )
                result = governed.invoke({"item": "widgets"})
                result_json = json.loads(result)
                assert "governance" in result_json
                assert result_json["governance"]["gate_state"] == "ALLOW"
                assert "result" in result_json
            test("LangChain governed tool (allow)", t_langchain_governed_allow)

            def t_langchain_governed_deny():
                from dgv_langchain import GovernedTool

                @tool
                def delete_database(confirm: str) -> str:
                    """Delete the database."""
                    return "Deleted"

                governed = GovernedTool(
                    tool=delete_database,
                    gate_url=BASE_URL,
                    agent_id="sdk-revoked",  # revoked agent
                    workflow="dangerous",
                )
                result = governed.invoke({"confirm": "yes"})
                result_json = json.loads(result)
                assert "error" in result_json
                assert result_json["error"] == "governance_denied"
                assert result_json["gate_state"] == "DENY"
            test("LangChain governed tool (deny)", t_langchain_governed_deny)

            def t_langchain_gate_tool():
                from dgv_langchain import GateTool

                gov = GateTool(
                    gate_url=BASE_URL,
                    agent_id="lc-test",
                    workflow="eval",
                )
                result = gov.invoke({
                    "tool": "send_email",
                    "action": "send",
                    "params": {"to": "test@example.com"},
                    "justification": "test",
                })
                result_json = json.loads(result)
                assert result_json["gate_state"] == "ALLOW"
                assert result_json["allowed"] == True
            test("LangChain GateTool", t_langchain_gate_tool)

            def t_langchain_callback():
                from dgv_langchain import GovernanceCallbackHandler

                cb = GovernanceCallbackHandler(
                    gate_url=BASE_URL,
                    agent_id="lc-test",
                )
                # Simulate a tool start event
                cb.on_tool_start(
                    {"name": "send_email"},
                    json.dumps({"to": "test@example.com"}),
                )
                assert len(cb.decisions) == 1
                assert cb.decisions[0].gate_state == "ALLOW"
            test("LangChain callback handler", t_langchain_callback)

    finally:
        proc.terminate()
        proc.wait()
        if os.path.exists(TEST_DB):
            os.unlink(TEST_DB)
        key_file = os.path.join(tempfile.gettempdir(), "dgv_sdk_test.key")
        if os.path.exists(key_file):
            os.unlink(key_file)

    print(f"\n{'='*50}")
    print(f"Results: {passed} passed, {failed} failed")
    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
