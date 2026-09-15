#!/usr/bin/env python3
"""
DGV LangChain adapter — governance middleware for LangChain agents.

Provides:
  - GateTool: a LangChain Tool that wraps the /govern endpoint
  - GovernedTool: a wrapper that adds governance to any existing LangChain tool
  - GovernanceCallbackHandler: a callback that intercepts tool calls before execution

Usage:
    from dgv_langchain import GateClient, GovernedTool, GovernanceCallbackHandler
    from langchain_core.tools import tool

    # Option 1: Wrap an existing tool with governance
    @tool
    def send_email(to: str, subject: str, body: str) -> str:
        '''Send an email.'''
        return f"Sent to {to}: {subject}"

    governed_send_email = GovernedTool(
        tool=send_email,
        gate_url="http://localhost:7878",
        agent_id="my-agent",
        workflow="email_campaign",
    )

    # Option 2: Use as a standalone governance tool
    govern_tool = GateTool(gate_url="http://localhost:7878")

    # Option 3: Callback that intercepts all tool calls
    callback = GovernanceCallbackHandler(
        gate_url="http://localhost:7878",
        agent_id="my-agent",
    )
"""

import json
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional, Type

try:
    from langchain_core.tools import BaseTool, tool
    from langchain_core.callbacks import BaseCallbackHandler
    from langchain_core.outputs import LLMResult
    HAS_LANGCHAIN = True
except ImportError:
    HAS_LANGCHAIN = False
    BaseTool = object
    BaseCallbackHandler = object

from dgv_sdk import GateClient, GateError, Decision, ExecutionResult


class GateClientAdapter:
    """Thin wrapper around GateClient for LangChain integration."""

    def __init__(self, gate_url: str = "http://localhost:7878", admin_key: Optional[str] = None):
        self.client = GateClient(gate_url, admin_key=admin_key)

    def govern(self, **kwargs) -> Decision:
        return self.client.govern(**kwargs)

    def execute(self, **kwargs) -> ExecutionResult:
        return self.client.execute(**kwargs)


if HAS_LANGCHAIN:

    class GateTool(BaseTool):
        """A LangChain tool that evaluates proposals through the DGV gate.

        This tool doesn't execute anything itself — it evaluates whether
        a proposed action should be allowed. Use it as a governance check
        before executing sensitive tools.
        """

        name: str = "dgv_govern"
        description: str = (
            "Evaluate a tool call proposal against governance policies. "
            "Returns ALLOW or DENY with reason codes. "
            "Use this before executing any sensitive action."
        )
        gate_url: str = "http://localhost:7878"
        admin_key: Optional[str] = None
        agent_id: str = "langchain-agent"
        workflow: str = "default"

        def _run(self, tool: str, action: str, params: Dict, justification: str = "", risk_level: str = "1000") -> str:
            """Evaluate a proposal. Returns a JSON decision string."""
            client = GateClientAdapter(self.gate_url, self.admin_key)
            try:
                decision = client.govern(
                    agent_id=self.agent_id,
                    workflow=self.workflow,
                    tool=tool,
                    action=action,
                    params=params,
                    justification=justification,
                    risk_level=risk_level,
                )
                return json.dumps({
                    "gate_state": decision.gate_state,
                    "reason_codes": decision.reason_codes,
                    "run_id": decision.run_id,
                    "decision_hash": decision.decision_hash,
                    "allowed": decision.allowed,
                    "token_id": decision.token_id,
                })
            except GateError as e:
                return json.dumps({"error": str(e), "allowed": False})

    class GovernedTool(BaseTool):
        """A LangChain tool wrapper that adds DGV governance to any existing tool.

        Wraps an existing tool so that every call first goes through the
        /govern endpoint, then (if allowed) executes via /execute with the token.

        This is the primary integration pattern: wrap any tool and get
        governance for free.
        """

        name: str = "governed_tool"
        description: str = "A governed tool that enforces DGV policies before executing."
        inner_tool: Any = None  # The wrapped tool
        gate_url: str = "http://localhost:7878"
        admin_key: Optional[str] = None
        agent_id: str = "langchain-agent"
        workflow: str = "default"

        def __init__(self, tool: BaseTool, gate_url: str = "http://localhost:7878",
                     agent_id: str = "langchain-agent", workflow: str = "default",
                     admin_key: Optional[str] = None, **kwargs):
            super().__init__(**kwargs)
            self.inner_tool = tool
            self.name = f"governed_{tool.name}"
            self.description = f"Governed version of {tool.name}: {tool.description}"
            self.gate_url = gate_url
            self.agent_id = agent_id
            self.workflow = workflow
            self.admin_key = admin_key

        def _run(self, **kwargs) -> str:
            """Evaluate via govern, then execute if allowed."""
            client = GateClientAdapter(self.gate_url, self.admin_key)

            # Build params from the tool's input schema
            params = kwargs
            tool_name = self.inner_tool.name
            action = self.inner_tool.name  # Use tool name as action

            try:
                # Step 1: Govern
                decision = client.govern(
                    agent_id=self.agent_id,
                    workflow=self.workflow,
                    tool=tool_name,
                    action=action,
                    params=params,
                    justification=f"LangChain tool call: {tool_name}",
                    risk_level="1000",
                )

                if not decision.allowed:
                    return json.dumps({
                        "error": "governance_denied",
                        "gate_state": decision.gate_state,
                        "reason_codes": decision.reason_codes,
                        "run_id": decision.run_id,
                    })

                # Step 2: Execute with the token
                token_id = decision.token_id
                if not token_id:
                    return json.dumps({
                        "error": "no_token_issued",
                        "gate_state": decision.gate_state,
                    })

                exec_result = client.execute(
                    token_id=token_id,
                    executor_id=self.agent_id,
                    tool=tool_name,
                    action=action,
                    params=params,
                )

                if not exec_result.allowed:
                    return json.dumps({
                        "error": "execution_denied",
                        "deny_reason": exec_result.deny_reason,
                        "run_id": exec_result.run_id,
                    })

                # Step 3: Execute the actual tool
                inner_result = self.inner_tool.invoke(params)

                return json.dumps({
                    "governance": {
                        "gate_state": decision.gate_state,
                        "run_id": decision.run_id,
                        "decision_hash": decision.decision_hash,
                        "signature": decision.signature,
                    },
                    "execution": {
                        "allowed": exec_result.allowed,
                        "receipt": exec_result.receipt,
                    },
                    "result": inner_result,
                })

            except GateError as e:
                return json.dumps({"error": str(e), "allowed": False})

    class GovernanceCallbackHandler(BaseCallbackHandler):
        """LangChain callback that intercepts tool calls and enforces governance.

        Attach this to an agent executor or tool chain to get governance
        on every tool call without modifying the tools themselves.

        Note: This is a monitoring/audit callback — it evaluates governance
        but doesn't block execution. For enforcement, use GovernedTool.
        """

        def __init__(self, gate_url: str = "http://localhost:7878",
                     agent_id: str = "langchain-agent",
                     admin_key: Optional[str] = None,
                     on_deny: Optional[callable] = None):
            self.client = GateClientAdapter(gate_url, admin_key)
            self.agent_id = agent_id
            self.on_deny = on_deny or (lambda tool, decision: print(f"DENIED: {tool} — {decision.reason_codes}"))
            self.decisions: List[Decision] = []

        def on_tool_start(self, serialized: Dict[str, Any], input_str: str, **kwargs) -> None:
            """Called before a tool executes. Evaluate governance."""
            tool_name = serialized.get("name", "unknown")
            try:
                params = json.loads(input_str) if isinstance(input_str, str) else input_str
            except:
                params = {"input": input_str}

            decision = self.client.govern(
                agent_id=self.agent_id,
                workflow="langchain_chain",
                tool=tool_name,
                action=tool_name,
                params=params,
                justification=f"LangChain callback intercept: {tool_name}",
                risk_level="1000",
            )
            self.decisions.append(decision)

            if decision.denied:
                self.on_deny(tool_name, decision)

        def on_tool_end(self, output: str, **kwargs) -> None:
            """Called after a tool executes."""
            pass

        def on_tool_error(self, error: BaseException, **kwargs) -> None:
            """Called when a tool raises an error."""
            pass

        def get_decisions(self) -> List[Decision]:
            """Get all governance decisions made by this callback."""
            return self.decisions

        def clear(self) -> None:
            """Clear the decision history."""
            self.decisions = []

    def govern_all_tools(
        tools: List[BaseTool],
        gate_url: str = "http://localhost:7878",
        agent_id: str = "langchain-agent",
        workflow: str = "default",
        admin_key: Optional[str] = None,
    ) -> List[BaseTool]:
        """Wrap every tool in a list with GovernedTool — agent-level middleware.

        This is the full executor integration pattern: instead of wrapping one
        tool at a time, wrap the agent's entire tool list before constructing
        the AgentExecutor. Every tool call in the agent run then goes through
        /govern + /execute automatically.

        Usage:
            tools = [send_email, query_db, write_file]
            governed = govern_all_tools(tools, gate_url=..., agent_id=...)
            agent = create_tool_calling_agent(llm, governed, prompt)
            executor = AgentExecutor(agent=agent, tools=governed)
        """
        return [
            GovernedTool(
                tool=t,
                gate_url=gate_url,
                agent_id=agent_id,
                workflow=workflow,
                admin_key=admin_key,
            )
            for t in tools
        ]


else:
    # Fallback when LangChain is not installed
    class GateTool:
        """Placeholder — install langchain-core to use."""
        def __init__(self, *args, **kwargs):
            raise ImportError("Install langchain-core: pip install langchain-core")

    class GovernedTool:
        """Placeholder — install langchain-core to use."""
        def __init__(self, *args, **kwargs):
            raise ImportError("Install langchain-core: pip install langchain-core")

    class GovernanceCallbackHandler:
        """Placeholder — install langchain-core to use."""
        def __init__(self, *args, **kwargs):
            raise ImportError("Install langchain-core: pip install langchain-core")

    def govern_all_tools(*args, **kwargs):
        raise ImportError("Install langchain-core: pip install langchain-core")
