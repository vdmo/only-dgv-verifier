#!/usr/bin/env python3
"""
DGV Python SDK — clean client for the DGV Enforcement Gate HTTP API.

Usage:
    from dgv_sdk import GateClient

    client = GateClient("http://localhost:7878")

    # Evaluate a proposal
    decision = client.govern(
        agent_id="my-agent",
        workflow="loan_approval",
        tool="send_email",
        action="send",
        params={"to": "client@example.com"},
        justification="user requested",
        risk_level="1000",
    )

    if decision.allowed:
        # Execute with the token
        result = client.execute(
            token_id=decision.token_id,
            executor_id="my-agent",
            tool="send_email",
            action="send",
            params={"to": "client@example.com"},
        )
        print(f"Executed: {result.receipt}")
    else:
        print(f"Denied: {decision.reason_codes}")

    # Verify a decision later
    verified = client.verify(decision.run_id)
    print(f"Verified: {verified.verified}")
"""

import json
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Decision:
    """A governance decision returned by /govern."""
    request_id: str
    gate_state: str  # ALLOW, DENY, SILENCE, ESCALATE
    reason_codes: List[str]
    run_id: str
    decision_hash: str
    signature: str
    verifying_key: str
    auth_token: Optional[Dict[str, Any]] = None
    approvals_required: int = 0
    approvals_received: int = 0

    @property
    def allowed(self) -> bool:
        return self.gate_state == "ALLOW"

    @property
    def denied(self) -> bool:
        return self.gate_state == "DENY"

    @property
    def token_id(self) -> Optional[str]:
        return self.auth_token["token_id"] if self.auth_token else None


@dataclass
class ExecutionResult:
    """Result of /execute."""
    allowed: bool
    deny_reason: Optional[str]
    receipt: Dict[str, Any]
    run_id: str


@dataclass
class VerifyResult:
    """Result of /verify/:run_id."""
    run_id: str
    verified: bool
    stored_decision_hash: Optional[str]
    rederived_decision_hash: Optional[str]
    gate_state: Optional[str]
    reason_codes: Optional[List[str]]
    created_unix_ms: Optional[int]


@dataclass
class HealthResult:
    """Result of /health."""
    status: str
    version: str
    storage: str
    verifying_key: str


@dataclass
class StatsResult:
    """Result of /stats."""
    decisions_made: int
    tokens_issued: int
    tokens_consumed: int
    denials: int


@dataclass
class PolicyRecord:
    """A governance policy."""
    policy_id: str
    tool: str
    action: str
    script: str
    policy_version: str
    created_unix_ms: int
    active: bool
    signature: Optional[str] = None
    min_approvals: int = 0
    min_justification_length: int = 0


@dataclass
class RateLimitConfig:
    """Rate limit configuration."""
    max_requests: int
    window_ms: int
    enabled: bool


@dataclass
class RevocationRecord:
    """A revocation record."""
    actor_id: str
    reason: str
    revoked_unix_ms: int
    revoked_by: str


class GateError(Exception):
    """Error returned by the gate."""
    def __init__(self, status: int, body: Dict[str, Any]):
        self.status = status
        self.body = body
        self.error = body.get("error", f"HTTP {status}")
        self.hint = body.get("hint", "")
        super().__init__(f"{self.error}: {self.hint}" if self.hint else self.error)


class GateClient:
    """Client for the DGV Enforcement Gate HTTP API."""

    def __init__(self, base_url: str = "http://localhost:7878", admin_key: Optional[str] = None,
                 jwt_token: Optional[str] = None):
        self.base_url = base_url.rstrip("/")
        self.admin_key = admin_key
        self.jwt_token = jwt_token

    def _request(self, method: str, path: str, body: Optional[Dict] = None) -> Dict:
        url = f"{self.base_url}{path}"
        headers = {"Content-Type": "application/json"}
        if self.admin_key:
            headers["X-Admin-Key"] = self.admin_key
        if self.jwt_token:
            headers["Authorization"] = f"Bearer {self.jwt_token}"

        data = json.dumps(body).encode() if body else None
        req = urllib.request.Request(url, data=data, headers=headers, method=method)

        try:
            with urllib.request.urlopen(req) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            try:
                body_json = json.loads(e.read())
            except:
                body_json = {"error": f"HTTP {e.code}"}
            raise GateError(e.code, body_json)

    # ── Core endpoints ────────────────────────────────────────────────────────

    def govern(
        self,
        agent_id: str,
        workflow: str,
        tool: str,
        action: str,
        params: Dict[str, Any],
        justification: str,
        risk_level: str = "1000",
        identity: Optional[Dict] = None,
        tenant_id: Optional[str] = None,
        context_hash: Optional[str] = None,
    ) -> Decision:
        """Evaluate a proposal. Returns a Decision."""
        body = {
            "request_id": f"req-{agent_id}-{workflow}",
            "agent_id": agent_id,
            "workflow": workflow,
            "tool": tool,
            "action": action,
            "params": params,
            "justification": justification,
            "risk_level": risk_level,
            "identity": identity or {},
        }
        if tenant_id:
            body["tenant_id"] = tenant_id
        if context_hash:
            body["context_hash"] = context_hash

        resp = self._request("POST", "/govern", body)
        d = resp["decision"]
        return Decision(
            request_id=d["request_id"],
            gate_state=d["gate_state"],
            reason_codes=d["reason_codes"],
            run_id=d["run_id"],
            decision_hash=d["decision_hash"],
            signature=resp["signature"],
            verifying_key=resp["verifying_key"],
            auth_token=d.get("auth_token"),
            approvals_required=d.get("approvals_required", 0),
            approvals_received=d.get("approvals_received", 0),
        )

    def execute(
        self,
        token_id: str,
        executor_id: str,
        tool: str,
        action: str,
        params: Dict[str, Any],
    ) -> ExecutionResult:
        """Execute with a token. Returns an ExecutionResult."""
        body = {
            "token_id": token_id,
            "executor_id": executor_id,
            "tool": tool,
            "action": action,
            "params": params,
        }
        try:
            resp = self._request("POST", "/execute", body)
            return ExecutionResult(
                allowed=resp["allowed"],
                deny_reason=resp.get("deny_reason"),
                receipt=resp["receipt"],
                run_id=resp["run_id"],
            )
        except GateError as e:
            if e.status == 403:
                body = e.body
                return ExecutionResult(
                    allowed=False,
                    deny_reason=body.get("deny_reason", "forbidden"),
                    receipt=body.get("receipt", {}),
                    run_id=body.get("run_id", ""),
                )
            raise

    def verify(self, run_id: str) -> VerifyResult:
        """Verify a decision. Returns a VerifyResult."""
        try:
            resp = self._request("GET", f"/verify/{run_id}")
            return VerifyResult(
                run_id=resp["run_id"],
                verified=resp["verified"],
                stored_decision_hash=resp.get("stored_decision_hash"),
                rederived_decision_hash=resp.get("rederived_decision_hash"),
                gate_state=resp.get("gate_state"),
                reason_codes=resp.get("reason_codes"),
                created_unix_ms=resp.get("created_unix_ms"),
            )
        except GateError as e:
            if e.status == 404:
                return VerifyResult(run_id=run_id, verified=False, stored_decision_hash=None,
                                    rederived_decision_hash=None, gate_state=None, reason_codes=None, created_unix_ms=None)
            raise

    def health(self) -> HealthResult:
        """Check gate health."""
        resp = self._request("GET", "/health")
        return HealthResult(
            status=resp["status"],
            version=resp["version"],
            storage=resp["storage"],
            verifying_key=resp["verifying_key"],
        )

    def stats(self) -> StatsResult:
        """Get gate statistics."""
        resp = self._request("GET", "/stats")
        return StatsResult(
            decisions_made=resp["decisions_made"],
            tokens_issued=resp["tokens_issued"],
            tokens_consumed=resp["tokens_consumed"],
            denials=resp["denials"],
        )

    # ── Admin endpoints ───────────────────────────────────────────────────────

    def store_policy(self, tool: str, action: str, script: str, policy_version: str = "v1",
                     min_approvals: int = 0, min_justification_length: int = 0) -> str:
        """Store a policy. Requires admin key."""
        body = {
            "tool": tool,
            "action": action,
            "script": script,
            "policy_version": policy_version,
        }
        if min_approvals > 0:
            body["min_approvals"] = min_approvals
        if min_justification_length > 0:
            body["min_justification_length"] = min_justification_length
        resp = self._request("POST", "/policies", body)
        return resp["policy_id"]

    def get_policy(self, tool: str, action: str) -> Optional[PolicyRecord]:
        """Get the active policy for a tool+action."""
        try:
            resp = self._request("GET", f"/policies/{tool}/{action}")
            return PolicyRecord(**resp)
        except GateError as e:
            if e.status == 404:
                return None
            raise

    def load_policy_file(self, file_path: str) -> Dict[str, Any]:
        """Load policies from a YAML/JSON file. Requires admin key."""
        return self._request("POST", "/policies/load-file", {"file_path": file_path})

    def revoke(self, actor_id: str, reason: str, revoked_by: str = "admin") -> bool:
        """Revoke an actor. Requires admin key."""
        resp = self._request("POST", "/revocations", {
            "actor_id": actor_id,
            "reason": reason,
            "revoked_by": revoked_by,
        })
        return resp.get("revoked", False)

    def list_revocations(self) -> List[RevocationRecord]:
        """List all revocations."""
        resp = self._request("GET", "/revocations")
        return [RevocationRecord(**r) for r in resp]

    def store_tenant_policy(self, tenant_id: str, tool: str, action: str, script: str, policy_version: str = "v1") -> str:
        """Store a tenant-specific policy. Requires admin key."""
        resp = self._request("POST", f"/tenant/{tenant_id}/policies", {
            "tool": tool,
            "action": action,
            "script": script,
            "policy_version": policy_version,
        })
        return resp["policy_id"]

    def get_rate_limit(self) -> RateLimitConfig:
        """Get current rate limit config."""
        resp = self._request("GET", "/config/rate-limit")
        return RateLimitConfig(**resp)

    def update_rate_limit(self, max_requests: Optional[int] = None, window_ms: Optional[int] = None, enabled: Optional[bool] = None) -> RateLimitConfig:
        """Update rate limit config. Requires admin key."""
        body = {}
        if max_requests is not None:
            body["max_requests"] = max_requests
        if window_ms is not None:
            body["window_ms"] = window_ms
        if enabled is not None:
            body["enabled"] = enabled
        resp = self._request("PUT", "/config/rate-limit", body)
        return RateLimitConfig(**resp)

    def approve(self, token_id: str, approver_id: str) -> Dict[str, Any]:
        """Approve a token (for multi-approval policies). Requires admin key."""
        return self._request("POST", f"/approve/{token_id}", {"approver_id": approver_id})
