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

import dgv_a2a_v2


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

    def policy_versions(self, tool: str, action: str) -> List[PolicyRecord]:
        """List all versions of a policy (active and inactive), newest first."""
        resp = self._request("GET", f"/policies/{tool}/{action}/versions")
        return [PolicyRecord(**v) for v in resp.get("versions", [])]

    def rollback_policy(self, policy_id: str) -> Dict[str, Any]:
        """Reactivate a previous policy version. Requires admin key."""
        return self._request("POST", f"/policies/{policy_id}/rollback")

    def metrics(self) -> str:
        """Fetch Prometheus metrics (text exposition format)."""
        import urllib.request
        req = urllib.request.Request(f"{self.base_url}/metrics")
        with urllib.request.urlopen(req) as resp:
            return resp.read().decode()

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
        """Approve a token (for multi-approval policies). Requires JWT when configured."""
        return self._request("POST", f"/approve/{token_id}", {"approver_id": approver_id})

    # ── Circuit breaker / tool health ──────────────────────────────────────────

    def report_tool_health(self, tool: str, success: bool, detail: Optional[str] = None) -> Dict[str, Any]:
        """Report a tool execution outcome. Failures feed the circuit breaker —
        after DGV_CIRCUIT_BREAKER_THRESHOLD consecutive failures the tool is
        auto-disabled at /govern until the cooldown elapses."""
        body: Dict[str, Any] = {"tool": tool, "success": success}
        if detail:
            body["detail"] = detail
        return self._request("POST", "/tool-health/report", body)

    def tool_health(self) -> Dict[str, Any]:
        """Get circuit breaker state for all tracked tools."""
        return self._request("GET", "/tool-health")

    def reset_tool_health(self, tool: str) -> Dict[str, Any]:
        """Manually reset a tool's circuit breaker. Requires admin key."""
        return self._request("POST", f"/tool-health/reset/{tool}")

    # ── Agent-to-Agent (A2A) signed envelopes ──────────────────────────────────

    def register_agent_key(self, agent_id: str, public_key_hex: str,
                           enc_public_key_hex: Optional[str] = None) -> Dict[str, Any]:
        """Register an agent's Ed25519 signing key (and optional X25519
        encryption key for sealed payloads). Requires admin key."""
        body: Dict[str, Any] = {"agent_id": agent_id, "public_key_hex": public_key_hex}
        if enc_public_key_hex is not None:
            body["enc_public_key_hex"] = enc_public_key_hex
        return self._request("POST", "/agents/keys", body)

    def get_agent_key(self, agent_id: str) -> Dict[str, Any]:
        """Fetch an agent's registered public keys. Public endpoint — agents
        should resolve peer keys here, not from in-band message data."""
        return self._request("GET", f"/agents/keys/{agent_id}")

    def deactivate_agent_key(self, agent_id: str) -> Dict[str, Any]:
        """Deactivate an agent's key — agent can no longer send A2A envelopes. Admin."""
        return self._request("DELETE", f"/agents/keys/{agent_id}")

    def a2a_send(
        self,
        envelope_id: str,
        sender_id: str,
        recipient_id: str,
        payload_hash: str,
        nonce: str,
        sent_unix_ms: int,
        expires_unix_ms: int,
        signature: str,
        transport_ref: Optional[str] = None,
        version: str = dgv_a2a_v2.ENVELOPE_DOMAIN,
    ) -> Dict[str, Any]:
        """Submit a signed A2A envelope (dgv-a2a-envelope-v2). Build it with
        sign_a2a_envelope(); the signature covers every field, including
        transport_ref. The response carries the gate's signed `receipt`."""
        body: Dict[str, Any] = {
            "version": version,
            "envelope_id": envelope_id,
            "sender_id": sender_id,
            "recipient_id": recipient_id,
            "payload_hash": payload_hash,
            "nonce": nonce,
            "sent_unix_ms": sent_unix_ms,
            "expires_unix_ms": expires_unix_ms,
            "signature": signature,
        }
        if transport_ref is not None:
            body["transport_ref"] = transport_ref
        return self._request("POST", "/a2a/send", body)

    def a2a_inbox(self, agent_id: str) -> List[Dict[str, Any]]:
        """Fetch undelivered envelopes for an agent. JWT sub must match when configured."""
        resp = self._request("GET", f"/a2a/inbox/{agent_id}")
        return resp.get("envelopes", [])

    def a2a_ack(self, envelope_id: str, agent_id: str) -> Dict[str, Any]:
        """Acknowledge delivery of an envelope."""
        return self._request("POST", f"/a2a/ack/{envelope_id}", {"agent_id": agent_id})

    # ── Delegation ────────────────────────────────────────────────────────────

    def delegate(
        self,
        parent_token_id: str,
        delegator_id: str,
        delegatee_id: str,
        delegator_signing_key_hex: str,
        parent_params: Dict[str, Any],
        parent_expires_unix_ms: int,
        params: Optional[Dict[str, Any]] = None,
        expires_unix_ms: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Mint a strictly-narrower child token. `params` must be a JSON subset
        of `parent_params` (omit keys to narrow; values never added/changed);
        `expires_unix_ms` must not exceed the parent's. The delegator signs the
        canonical string with its registered Ed25519 key."""
        import hashlib
        child_params = params if params is not None else parent_params
        ph = hashlib.sha256(
            json.dumps(child_params, separators=(",", ":"), sort_keys=True).encode()
        ).hexdigest()
        exp = expires_unix_ms if expires_unix_ms is not None else parent_expires_unix_ms
        canonical = delegate_canonical_string(
            parent_token_id, delegator_id, delegatee_id, ph, exp)
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        sig = Ed25519PrivateKey.from_private_bytes(
            bytes.fromhex(delegator_signing_key_hex)).sign(canonical.encode()).hex()
        return self._request("POST", "/delegate", {
            "parent_token_id": parent_token_id,
            "delegator_id": delegator_id,
            "delegatee_id": delegatee_id,
            "params": params,
            "expires_unix_ms": exp,
            "signature": sig,
        })

    def delegation_chain(self, token_id: str) -> Dict[str, Any]:
        """Fetch the delegation lineage (root → ... → this token)."""
        return self._request("GET", f"/delegations/{token_id}")


def delegate_canonical_string(
    parent_token_id: str,
    delegator_id: str,
    delegatee_id: str,
    params_hash: str,
    expires_unix_ms: int,
) -> str:
    """Canonical string the delegator signs — binds the delegation request."""
    return (f"dgv-delegate-v1|{parent_token_id}|{delegator_id}"
            f"|{delegatee_id}|{params_hash}|{expires_unix_ms}")


def sign_a2a_envelope(
    signing_key_hex: str,
    envelope_id: str,
    sender_id: str,
    recipient_id: str,
    payload: bytes,
    nonce: str,
    expires_unix_ms: int,
    sent_unix_ms: Optional[int] = None,
    transport_ref: Optional[str] = None,
    payload_hash: Optional[str] = None,
) -> Dict[str, Any]:
    """Build and sign an A2A envelope (format: A2A_ENVELOPE_V2.md). Needs
    PyNaCl or `cryptography`.

    Returns a dict ready for GateClient.a2a_send(**result). `payload_hash` is
    SHA-256 of `payload` unless given (the payload never transits the gate)."""
    import hashlib
    import time
    try:
        import nacl.signing
        signer = nacl.signing.SigningKey(bytes.fromhex(signing_key_hex))
        sign = lambda msg: signer.sign(msg).signature.hex()
    except ImportError:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(signing_key_hex))
        sign = lambda msg: sk.sign(msg).hex()

    envelope = {
        "envelope_id": envelope_id,
        "sender_id": sender_id,
        "recipient_id": recipient_id,
        "payload_hash": payload_hash or hashlib.sha256(payload).hexdigest(),
        "nonce": nonce,
        "sent_unix_ms": sent_unix_ms if sent_unix_ms is not None else int(time.time() * 1000),
        "expires_unix_ms": expires_unix_ms,
        "transport_ref": transport_ref,
    }
    signature = sign(dgv_a2a_v2.envelope_bytes(envelope))
    return {"version": dgv_a2a_v2.ENVELOPE_DOMAIN, **envelope, "signature": signature}


def a2a_evidence(sent: Dict[str, Any], response: Dict[str, Any]) -> Dict[str, Any]:
    """The record to keep for offline verification: what was signed (from
    sign_a2a_envelope) plus the gate's signed receipt (from a2a_send).
    Check it with dgv_a2a_v2.py."""
    return {
        "envelope": {k: sent[k] for k in dgv_a2a_v2.ENVELOPE_FIELDS},
        "signature": sent["signature"],
        "receipt": response["receipt"],
        "gate_receipt": response["gate_receipt"],
    }


# ── Sealed A2A transport (dgv-sealed-v3) ─────────────────────────────────────
#
# Data plane for A2A: the gate authorizes envelopes (control plane) while the
# ciphertext travels a relay (onlystate-relay). The gate sees only SHA-256
# hashes; the relay sees only opaque queue IDs.
#
# Encryption is HPKE (RFC 9180), base mode, from the `cryptography` library:
# DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20-Poly1305. Every message
# gets a fresh ephemeral key, so keys and nonces are not reused even if the
# caller's counter repeats. `info` binds sender key, recipient key, envelope id
# and counter.
#
# What it does NOT give:
#   - sender authentication by itself: anyone can encrypt to a public key. The
#     sender is authenticated by the Ed25519 envelope signature over
#     payload_hash, which recv_sealed_a2a verifies.
#   - forward secrecy against theft of the recipient's private key.
#   - post-quantum security.
#
# dgv-sealed-v1 and -v2 can no longer be used to send: v1 reused key and nonce
# between the two directions of a pair, and v2's "post-quantum" part added no
# protection. Old messages open only with allow_legacy=True.
#
# payload_hash bound by the gate (v3) = SHA-256 over the length-prefixed fields
#   ("dgv-sealed-v3", envelope_id, counter_be8, encapsulated_key || ciphertext)
#
# transport_ref format: "relay:<relay_base_url>|<queue_id>" or "direct:<url>".
# Relay queue for a recipient = SHA-256("dgv-a2a-queue" || "|" || recipient_id).

SEALED_VERSION = "dgv-sealed-v3"
SEALED_V1_VERSION = "dgv-sealed-v1"
SEALED_V2_VERSION = "dgv-sealed-v2"


def _sha3(data: bytes) -> bytes:
    import hashlib
    return hashlib.sha3_256(data).digest()


def generate_enc_keypair() -> Dict[str, str]:
    """Generate an X25519 encryption keypair for sealed A2A payloads.
    Returns {"private_key_hex": ..., "public_key_hex": ...}.
    Requires `cryptography` (`pip install cryptography`)."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    sk = X25519PrivateKey.generate()
    return {
        "private_key_hex": sk.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
            serialization.NoEncryption()).hex(),
        "public_key_hex": sk.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex(),
    }


def _x25519_shared(private_key_hex: str, peer_public_key_hex: str) -> bytes:
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey, X25519PublicKey)
    sk = X25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
    pk = X25519PublicKey.from_public_bytes(bytes.fromhex(peer_public_key_hex))
    return sk.exchange(pk)


def _kdf(shared: bytes, counter: int) -> "tuple[bytes, bytes]":
    """Legacy v1/v2 derivation. For reading old messages only: with a constant
    `shared` it repeats keys and nonces. Never use it to encrypt."""
    cb = counter.to_bytes(8, "big")
    return _sha3(b"enc" + shared + cb), _sha3(b"nonce" + cb)[:12]


def relay_queue_id(recipient_id: str) -> str:
    """Deterministic relay queue for a recipient — no out-of-band discovery."""
    import hashlib
    return hashlib.sha256(b"dgv-a2a-queue|" + recipient_id.encode()).hexdigest()


def transport_ref_relay(relay_url: str, queue_id: str) -> str:
    return f"relay:{relay_url}|{queue_id}"


def parse_transport_ref(ref: str) -> Dict[str, str]:
    """Parse "relay:<url>|<queue_id>" → {"mode": "relay", "url": ..., "queue_id": ...}"""
    if ref.startswith("relay:"):
        url, _, queue_id = ref[len("relay:"):].partition("|")
        return {"mode": "relay", "url": url, "queue_id": queue_id}
    if ref.startswith("direct:"):
        return {"mode": "direct", "url": ref[len("direct:"):]}
    return {"mode": "unknown", "raw": ref}


def generate_pq_keypair() -> Dict[str, str]:
    """Removed. The previous function did not create ML-KEM keys and the layer
    built on it gave no post-quantum protection."""
    raise NotImplementedError(
        "No post-quantum encryption is implemented. The former dgv-sealed-v2 "
        "'hybrid PQ' layer added no protection and has been removed.")


def seal_a2a_v2_payload(*_args: Any, **_kwargs: Any) -> Dict[str, Any]:
    """Removed: dgv-sealed-v2 can no longer be used to send."""
    raise ValueError("dgv-sealed-v2 is withdrawn; use seal_a2a_payload (dgv-sealed-v3)")


def _lp(*fields: bytes) -> bytes:
    """Length-prefix each field so different field values never encode alike."""
    return b"".join(len(f).to_bytes(8, "big") + f for f in fields)


def _hpke_suite():
    try:
        from cryptography.hazmat.primitives import hpke
    except ImportError as exc:
        raise ImportError(
            "Sealed A2A needs `cryptography` with HPKE support "
            "(tested with 50.0.2): pip install --upgrade cryptography") from exc
    return hpke.Suite(hpke.KEM.X25519, hpke.KDF.HKDF_SHA256, hpke.AEAD.CHACHA20_POLY1305)


def _x25519_public_bytes(private_key) -> bytes:
    from cryptography.hazmat.primitives import serialization
    return private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _v3_info(sender_pub: bytes, recipient_pub: bytes, envelope_id: str, counter: int) -> bytes:
    return _lp(SEALED_VERSION.encode(), sender_pub, recipient_pub,
               envelope_id.encode(), counter.to_bytes(8, "big"))


def seal_a2a_payload(
    sender_enc_private_hex: str,
    recipient_enc_public_hex: str,
    envelope_id: str,
    counter: int,
    plaintext: bytes,
    recipient_pq_public_hex: Optional[str] = None,
    version: str = SEALED_VERSION,
) -> Dict[str, Any]:
    """Seal a payload for `recipient` with HPKE (dgv-sealed-v3).

    `counter` is carried for the relay and bound into the message; secrecy no
    longer depends on it being unique. This call does not authenticate the
    sender: sign the envelope (see send_sealed_a2a)."""
    if version != SEALED_VERSION:
        raise ValueError(f"cannot seal with {version}: only {SEALED_VERSION} is supported")
    if recipient_pq_public_hex is not None:
        raise ValueError("post-quantum encryption is not implemented")
    import base64
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey, X25519PublicKey)
    sender = X25519PrivateKey.from_private_bytes(bytes.fromhex(sender_enc_private_hex))
    recipient_pub = bytes.fromhex(recipient_enc_public_hex)
    info = _v3_info(_x25519_public_bytes(sender), recipient_pub, envelope_id, counter)
    ct = _hpke_suite().encrypt(
        plaintext, X25519PublicKey.from_public_bytes(recipient_pub), info=info)
    return {
        "v": SEALED_VERSION,
        "envelope_id": envelope_id,
        "counter": counter,
        "ct": base64.b64encode(ct).decode(),
    }


def sealed_payload_hash(sealed: Dict[str, Any]) -> str:
    """The payload_hash the gate binds to the envelope. Also computes the old
    v1/v2 formulas so stored legacy messages can still be checked."""
    import base64
    import hashlib
    v = sealed.get("v")
    ct = base64.b64decode(sealed["ct"])
    counter = int(sealed["counter"]).to_bytes(8, "big")
    eid = sealed["envelope_id"].encode()
    if v == SEALED_VERSION:
        return hashlib.sha256(_lp(v.encode(), eid, counter, ct)).hexdigest()
    if v == SEALED_V2_VERSION:
        eph = bytes.fromhex(sealed.get("eph_pk", ""))
        return hashlib.sha256(
            v.encode() + b"|" + eid + b"|" + eph + b"|" + counter + ct).hexdigest()
    if v == SEALED_V1_VERSION:
        return hashlib.sha256(v.encode() + b"|" + eid + b"|" + counter + ct).hexdigest()
    raise ValueError(f"unsupported sealed version: {v}")


def _open_legacy(recipient_enc_private_hex: str, sender_enc_public_hex: str,
                 sealed: Dict[str, Any], recipient_pq_private_hex: Optional[str]) -> bytes:
    import base64
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    shared = _x25519_shared(recipient_enc_private_hex, sender_enc_public_hex)
    if sealed["v"] == SEALED_V2_VERSION:
        eph_pk = sealed.get("eph_pk")
        if not eph_pk:
            raise ValueError("dgv-sealed-v2 missing ephemeral public key (eph_pk)")
        eph_shared = _x25519_shared(recipient_enc_private_hex, eph_pk)
        pq_ss = b""
        if sealed.get("pq_used"):
            if not recipient_pq_private_hex:
                raise ValueError("this old v2 message needs the old pq private value")
            pq_pub = _sha3(b"dgv-pq-ml-kem-768-vk|" + bytes.fromhex(recipient_pq_private_hex))
            pq_ss = _sha3(b"dgv-pq-kem-ss|" + pq_pub + eph_shared)
        shared = _sha3(b"dgv-sealed-v2|" + shared + b"|" + eph_shared + b"|" + pq_ss)
    key, nonce = _kdf(shared, int(sealed["counter"]))
    return ChaCha20Poly1305(key).decrypt(nonce, base64.b64decode(sealed["ct"]), None)


def open_a2a_payload(
    recipient_enc_private_hex: str,
    sender_enc_public_hex: str,
    sealed: Dict[str, Any],
    recipient_pq_private_hex: Optional[str] = None,
    allow_legacy: bool = False,
) -> bytes:
    """Open a sealed payload. Raises on tampering, wrong keys or changed context.

    Success shows the payload was sealed for this recipient and context, NOT who
    sealed it: verify the envelope signature too (recv_sealed_a2a does).
    `allow_legacy=True` also reads old v1/v2 messages, whose confidentiality
    should be assumed weak."""
    v = sealed.get("v")
    if v in (SEALED_V1_VERSION, SEALED_V2_VERSION):
        if not allow_legacy:
            raise ValueError(f"{v} is withdrawn; pass allow_legacy=True to read an old message")
        return _open_legacy(recipient_enc_private_hex, sender_enc_public_hex,
                            sealed, recipient_pq_private_hex)
    if v != SEALED_VERSION:
        raise ValueError(f"unsupported sealed version: {v}")
    import base64
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    recipient = X25519PrivateKey.from_private_bytes(bytes.fromhex(recipient_enc_private_hex))
    info = _v3_info(bytes.fromhex(sender_enc_public_hex), _x25519_public_bytes(recipient),
                    sealed["envelope_id"], int(sealed["counter"]))
    return _hpke_suite().decrypt(base64.b64decode(sealed["ct"]), recipient, info=info)


def relay_send(relay_url: str, queue_id: str, sealed: Dict[str, Any]) -> Dict[str, Any]:
    """Push a sealed payload through an onlystate-relay queue.
    Creates the queue first (idempotent) so sends never 404."""
    import base64
    import time
    import urllib.request
    url = relay_url.rstrip("/")
    urllib.request.urlopen(urllib.request.Request(
        f"{url}/queue", method="POST",
        data=json.dumps({"queue_id": queue_id}).encode(),
        headers={"Content-Type": "application/json"}), timeout=10).read()
    body = {
        "queue_id": queue_id,
        "ciphertext": base64.b64encode(json.dumps(sealed).encode()).decode(),
        "counter": int(sealed["counter"]),
        "submitted_at": int(time.time()),
    }
    resp = urllib.request.urlopen(urllib.request.Request(
        f"{url}/send/{queue_id}", method="POST",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"}), timeout=10).read()
    return json.loads(resp)


def relay_recv(relay_url: str, queue_id: str, timeout: int = 35) -> Optional[Dict[str, Any]]:
    """Long-poll one envelope from the relay. Returns the sealed dict or None."""
    import base64
    import urllib.request
    url = relay_url.rstrip("/")
    try:
        raw = urllib.request.urlopen(f"{url}/recv/{queue_id}", timeout=timeout).read()
    except Exception:
        return None
    env = json.loads(raw)
    if "ciphertext" not in env:
        return None  # {"status": "timeout"}
    sealed = json.loads(base64.b64decode(env["ciphertext"]))
    if int(sealed.get("counter", -1)) != int(env["counter"]):
        raise ValueError("relay counter mismatch")
    return sealed


def send_sealed_a2a(
    client: "GateClient",
    sender_id: str,
    recipient_id: str,
    sender_signing_key_hex: str,
    sender_enc_private_hex: str,
    plaintext: bytes,
    counter: int,
    relay_url: str,
    envelope_id: Optional[str] = None,
    expires_in_ms: int = 60_000,
) -> Dict[str, Any]:
    """Full sealed-send path: fetch recipient's enc key from the gate registry,
    seal, sign + govern the envelope at the gate, then push ciphertext to the
    relay. Returns {"envelope_id", "gate_response"}."""
    import time
    import uuid
    rec = client.get_agent_key(recipient_id)
    enc_pub = rec.get("enc_public_key_hex")
    if not enc_pub:
        raise GateError(400, {"error": "recipient_has_no_enc_key", "recipient_id": recipient_id})
    eid = envelope_id or str(uuid.uuid4())
    sealed = seal_a2a_payload(sender_enc_private_hex, enc_pub, eid, counter, plaintext)
    sent = int(time.time() * 1000)
    queue_id = relay_queue_id(recipient_id)
    envelope = sign_a2a_envelope(
        sender_signing_key_hex, eid, sender_id, recipient_id, b"", str(uuid.uuid4()),
        sent + expires_in_ms, sent_unix_ms=sent,
        transport_ref=transport_ref_relay(relay_url, queue_id),
        payload_hash=sealed_payload_hash(sealed))
    resp = client.a2a_send(**envelope)
    relay_send(relay_url, queue_id, sealed)
    return {"envelope_id": eid, "gate_response": resp,
            "evidence": a2a_evidence(envelope, resp)}


def _verify_envelope(env: Dict[str, Any], recipient_id: str,
                     sender_public_hex: Optional[str],
                     gate_public_key_hex: Optional[str]) -> None:
    """Check end to end that the registered sender signed this envelope for this
    recipient, instead of relying on the gate's say-so. With a pinned gate key,
    also check the gate's receipt."""
    if not sender_public_hex:
        raise ValueError("sender has no signing key: envelope signature cannot be verified")
    try:
        envelope = {k: env.get(k) for k in dgv_a2a_v2.ENVELOPE_FIELDS}
        envelope["recipient_id"] = recipient_id
        dgv_a2a_v2.verify_sender(envelope, env.get("sender_signature"), sender_public_hex)
    except dgv_a2a_v2.EvidenceError as exc:
        raise ValueError(f"envelope signature verification failed: {exc}") from exc
    if gate_public_key_hex is None:
        return
    try:
        receipt = json.loads(env.get("receipt_json") or "null")
        dgv_a2a_v2.verify_receipt(envelope, receipt, env.get("gate_receipt_signature"),
                                  gate_public_key_hex)
    except ValueError as exc:
        raise ValueError(f"gate receipt verification failed: {exc}") from exc


def recv_sealed_a2a(
    client: "GateClient",
    agent_id: str,
    enc_private_hex: str,
    relay_url: str,
    poll_timeout: int = 35,
    gate_public_key_hex: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Receive one sealed envelope: gate inbox → relay fetch → hash-binding
    check → verify the sender's envelope signature (and, if
    `gate_public_key_hex` is given, the gate's receipt) → open → ack. Returns
    {"envelope_id", "sender_id", "plaintext"} or None if the inbox is empty.
    Raises on hash mismatch, bad signature, key mismatch, or decryption
    failure — nothing is acked."""
    for env in client.a2a_inbox(agent_id):
        ref = env.get("transport_ref")
        if not ref:
            continue
        t = parse_transport_ref(ref)
        if t["mode"] != "relay":
            continue
        sealed = relay_recv(t["url"], t["queue_id"], timeout=poll_timeout)
        if sealed is None:
            continue
        if sealed.get("envelope_id") != env["envelope_id"]:
            raise ValueError(f"sealed envelope_id mismatch: {sealed.get('envelope_id')}")
        if sealed_payload_hash(sealed) != env["payload_hash"]:
            raise ValueError("payload_hash mismatch: ciphertext does not match gate record")
        sender_keys = client.get_agent_key(env["sender_id"])
        _verify_envelope(env, agent_id, sender_keys.get("public_key_hex"),
                         gate_public_key_hex)
        sender_enc = sender_keys.get("enc_public_key_hex")
        if not sender_enc:
            raise ValueError("sender_has_no_enc_key")
        plaintext = open_a2a_payload(enc_private_hex, sender_enc, sealed)
        client.a2a_ack(env["envelope_id"], agent_id)
        return {
            "envelope_id": env["envelope_id"],
            "sender_id": env["sender_id"],
            "plaintext": plaintext,
        }
    return None
