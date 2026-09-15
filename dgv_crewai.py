#!/usr/bin/env python3
"""
DGV CrewAI adapter — governance middleware for CrewAI agents.

Provides:
  - CrewAIGovernedTool: wraps any CrewAI tool (or duck-typed callable) with
    /govern + /execute before the inner tool runs
  - govern_crew_tools: wrap an entire crew's tool list

Usage:
    from dgv_crewai import CrewAIGovernedTool, govern_crew_tools

    # Wrap a single CrewAI tool
    governed = CrewAIGovernedTool(
        tool=my_crewai_tool,
        gate_url="http://localhost:7878",
        agent_id="research-agent",
    )

    # Or wrap a whole tool list for a crew
    governed_tools = govern_crew_tools(crew_tools, gate_url=..., agent_id=...)

Works without crewai installed — the wrapper is duck-typed: the inner tool
needs a `name`, an optional `description`, and a `run(**kwargs)` or
`_run(**kwargs)` method. If `crewai.tools.BaseTool` is available, the wrapper
subclasses it so it can be used directly in a Crew's tools list.
"""

import json
from typing import Any, Dict, List, Optional

from dgv_sdk import GateClient, GateError

try:
    from crewai.tools import BaseTool as CrewAIBaseTool
    HAS_CREWAI = True
except ImportError:
    HAS_CREWAI = False
    CrewAIBaseTool = object


class CrewAIGovernedTool(CrewAIBaseTool):
    """A CrewAI tool wrapper that enforces DGV governance before executing.

    Every call first goes through /govern; if ALLOW, executes via /execute
    with the issued token, then runs the inner tool. DENY returns a JSON
    error object instead of calling the inner tool.
    """

    def __init__(self, tool: Any, gate_url: str = "http://localhost:7878",
                 agent_id: str = "crewai-agent", workflow: str = "default",
                 admin_key: Optional[str] = None, jwt_token: Optional[str] = None):
        name = f"governed_{getattr(tool, 'name', 'tool')}"
        description = f"Governed version of {getattr(tool, 'name', 'tool')}: {getattr(tool, 'description', '')}"
        if HAS_CREWAI:
            super().__init__(name=name, description=description)
        self.inner_tool = tool
        self.gate_url = gate_url
        self.agent_id = agent_id
        self.workflow = workflow
        self.client = GateClient(gate_url, admin_key=admin_key, jwt_token=jwt_token)

    # CrewAI's BaseTool calls _run; plain callables may expose run
    def _run(self, **kwargs) -> str:
        return self._governed_call(**kwargs)

    def run(self, **kwargs) -> str:
        return self._governed_call(**kwargs)

    def _governed_call(self, **kwargs) -> str:
        tool_name = getattr(self.inner_tool, "name", "unknown_tool")

        try:
            decision = self.client.govern(
                agent_id=self.agent_id,
                workflow=self.workflow,
                tool=tool_name,
                action=tool_name,
                params=kwargs,
                justification=f"CrewAI tool call: {tool_name}",
                risk_level="1000",
            )
        except GateError as e:
            return json.dumps({"error": f"gate_error: {e}", "allowed": False})

        if not decision.allowed:
            return json.dumps({
                "error": "governance_denied",
                "gate_state": decision.gate_state,
                "reason_codes": decision.reason_codes,
                "run_id": decision.run_id,
            })

        token_id = decision.token_id
        if not token_id:
            return json.dumps({"error": "no_token_issued", "gate_state": decision.gate_state})

        exec_result = self.client.execute(
            token_id=token_id,
            executor_id=self.agent_id,
            tool=tool_name,
            action=tool_name,
            params=kwargs,
        )
        if not exec_result.allowed:
            return json.dumps({
                "error": "execution_denied",
                "deny_reason": exec_result.deny_reason,
                "run_id": exec_result.run_id,
            })

        # Governance passed — invoke the inner tool
        inner = self.inner_tool
        if hasattr(inner, "_run"):
            result = inner._run(**kwargs)
        elif hasattr(inner, "run"):
            result = inner.run(**kwargs)
        elif callable(inner):
            result = inner(**kwargs)
        else:
            return json.dumps({"error": "inner_tool_not_callable"})

        return json.dumps({
            "governance": {
                "gate_state": decision.gate_state,
                "run_id": decision.run_id,
                "decision_hash": decision.decision_hash,
                "signature": decision.signature,
            },
            "execution": {"allowed": True, "receipt": exec_result.receipt},
            "result": result,
        })


def govern_crew_tools(
    tools: List[Any],
    gate_url: str = "http://localhost:7878",
    agent_id: str = "crewai-agent",
    workflow: str = "default",
    admin_key: Optional[str] = None,
    jwt_token: Optional[str] = None,
) -> List[CrewAIGovernedTool]:
    """Wrap an entire tool list — crew-level middleware.

    Usage:
        crew = Crew(agents=[...], tasks=[...])
        for agent in crew.agents:
            agent.tools = govern_crew_tools(agent.tools, gate_url=..., agent_id=...)
    """
    return [
        CrewAIGovernedTool(
            tool=t,
            gate_url=gate_url,
            agent_id=agent_id,
            workflow=workflow,
            admin_key=admin_key,
            jwt_token=jwt_token,
        )
        for t in tools
    ]
