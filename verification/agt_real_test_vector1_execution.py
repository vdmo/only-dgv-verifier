"""Real end-to-end test of Vector 1 (mid-flight revocation) against the actual
agent-os-kernel HTTP execution path — not just the session-validation unit level
agt_real_test.py already covered.

Flow: bootstrap a session bound to a static token, hit the real FastAPI
/api/v1/execute endpoint with it (should succeed), revoke that same session,
hit /api/v1/execute again with the same token (should now be refused).

Reproduce (needs Python >= 3.11):
    uv venv --python 3.12 env
    uv pip install --python env/bin/python agent-os-kernel pyyaml pydantic fastapi httpx
    env/bin/python agt_real_test_vector1_execution.py

Last run 2026-09-22 against agent-os-kernel 3.7.0:
    T0 (valid session) execute -> 200 {'success': True, ...}
    T1 (same token, after revoke_session) execute -> 401 Invalid or expired execute bearer token.

Scope: this exercises agent-os-kernel's default StatelessKernel.execute() with no
custom policies, through GovServer/create_app with an MCPSessionAuthenticator as
execute_authenticator. It does not exercise a real deployment's own action handlers,
custom policies, or AgentMesh. It shows the SHIPPED execute_authenticator wiring
(when you configure it) does check revocation per request. It does not show that
every AGT deployment configures this path, or that policy engines integrated
downstream of kernel.execute() re-check revocation themselves.
"""
import asyncio
from datetime import timedelta

import httpx
from fastapi.testclient import TestClient

from agent_os.mcp_session_auth import MCPSessionAuthenticator
from agent_os.server.app import GovServer

TOKEN = "vector1-test-token"
AGENT_ID = "payments-agent"


def main():
    auth = MCPSessionAuthenticator()
    auth.bootstrap_session(AGENT_ID, TOKEN, ttl=timedelta(hours=1))

    server = GovServer(execute_authenticator=auth, allow_unauthenticated_execute=False)
    client = TestClient(server.app)
    headers = {"Authorization": f"Bearer {TOKEN}"}
    body = {"action": "chat", "params": {"message": "hello"}, "policies": []}

    r0 = client.post("/api/v1/execute", json=body, headers=headers)
    print("T0 (valid session) execute ->", r0.status_code, r0.json())

    auth.revoke_session(TOKEN)

    r1 = client.post("/api/v1/execute", json=body, headers=headers)
    print("T1 (same token, after revoke_session) execute ->", r1.status_code, r1.json().get("detail", r1.json()))

    if r1.status_code == 401:
        print("\nRESULT: real execution path DOES refuse a revoked token at execution time (when configured).")
    else:
        print("\nRESULT: real execution path DID NOT refuse a revoked token — unexpected, investigate.")


if __name__ == "__main__":
    main()
