"""Differential checks against the REAL Microsoft agent-os-kernel (component of AGT).

Reproduce (needs Python >= 3.11):
    uv venv --python 3.12 env && uv pip install --python env/bin/python agent-os-kernel pyyaml pydantic
    env/bin/python agt_real_test.py

Last run 2026-09-21 against agent-os-kernel 3.7.0:
    A1 extra-action child: BLOCKED
    A2 param-widened child: ALLOWED
    intent revoke-like methods: []
    D validate before revoke: True
    D validate after revoke: False

Scope: these results describe agent-os-kernel 3.7.0 only, not every AGT component
(e.g. AgentMesh trust) and not any particular customer deployment.
"""
import asyncio
import importlib.metadata as m

from agent_os.intent import IntentAction, IntentManager, IntentScopeError
from agent_os.mcp_session_auth import MCPSessionAuthenticator
from agent_os.stateless import MemoryBackend

print("agent-os-kernel", m.version("agent-os-kernel"))


async def main():
    im = IntentManager(MemoryBackend())
    parent = await im.declare_intent("orch", [IntentAction("disburse", {"max": 100}), IntentAction("read")])
    await im.approve_intent(parent.intent_id)

    try:  # A1: child adds an action the parent never declared
        await im.create_child_intent(parent.intent_id, "w1", [IntentAction("delete_db")])
        print("A1 extra-action child: ALLOWED")
    except IntentScopeError:
        print("A1 extra-action child: BLOCKED")

    try:  # A2: same action, looser parameter limit
        await im.create_child_intent(parent.intent_id, "w2", [IntentAction("disburse", {"max": 1000000})])
        print("A2 param-widened child: ALLOWED")
    except IntentScopeError:
        print("A2 param-widened child: BLOCKED")

    print(
        "intent revoke-like methods:",
        [n for n in dir(im) if any(k in n.lower() for k in ("revok", "cancel", "kill", "abort"))],
    )

    auth = MCPSessionAuthenticator()  # D: session revocation primitive
    tok = auth.create_session("agent-1")
    print("D validate before revoke:", auth.validate_session("agent-1", tok) is not None)
    auth.revoke_session(tok)
    print("D validate after revoke:", auth.validate_session("agent-1", tok) is not None)


asyncio.run(main())
