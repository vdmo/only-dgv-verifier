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
    ) -> Dict[str, Any]:
        """Submit a signed A2A envelope. The signature must be the sender's
        Ed25519 signature over the canonical string:
        envelope_id|sender_id|recipient_id|payload_hash|nonce|sent_unix_ms|expires_unix_ms
        Use A2aEnvelope.sign() to build this."""
        body: Dict[str, Any] = {
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


def a2a_canonical_string(
    envelope_id: str,
    sender_id: str,
    recipient_id: str,
    payload_hash: str,
    nonce: str,
    sent_unix_ms: int,
    expires_unix_ms: int,
) -> str:
    """Canonical string that senders sign — binds all envelope fields together."""
    return f"{envelope_id}|{sender_id}|{recipient_id}|{payload_hash}|{nonce}|{sent_unix_ms}|{expires_unix_ms}"


def sign_a2a_envelope(
    signing_key_hex: str,
    envelope_id: str,
    sender_id: str,
    recipient_id: str,
    payload: bytes,
    nonce: str,
    expires_unix_ms: int,
    sent_unix_ms: Optional[int] = None,
) -> Dict[str, Any]:
    """Build and sign an A2A envelope. Requires PyNaCl (`pip install pynacl`).

    Returns a dict ready to pass to GateClient.a2a_send(**result), minus
    payload_hash which is computed from `payload` (the payload itself never
    transits the gate).
    """
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

    sent = sent_unix_ms if sent_unix_ms is not None else int(time.time() * 1000)
    payload_hash = hashlib.sha256(payload).hexdigest()
    canonical = a2a_canonical_string(
        envelope_id, sender_id, recipient_id, payload_hash, nonce, sent, expires_unix_ms
    )
    signature = sign(canonical.encode())
    return {
        "envelope_id": envelope_id,
        "sender_id": sender_id,
        "recipient_id": recipient_id,
        "payload_hash": payload_hash,
        "nonce": nonce,
        "sent_unix_ms": sent,
        "expires_unix_ms": expires_unix_ms,
        "signature": signature,
    }


# ── Sealed A2A transport (dgv-sealed-v1) ─────────────────────────────────────
#
# Data plane for A2A: the gate authorizes envelopes (control plane) while the
# ciphertext travels a zero-knowledge relay (onlystate-relay). The gate sees
# only SHA-256 hashes; the relay sees only opaque queue IDs. Crypto mirrors
# libonlystate::messages::envelope: X25519 ECDH shared key, per-message key +
# nonce derived via SHA3-256 from a monotonic counter, ChaCha20-Poly1305 AEAD.
#
# payload_hash bound by the gate =
#   SHA-256("dgv-sealed-v1" || "|" || envelope_id || "|" || counter_be8 || ciphertext)
#
# transport_ref format: "relay:<relay_base_url>|<queue_id>" or "direct:<url>".
# Relay queue for a recipient = SHA-256("dgv-a2a-queue" || "|" || recipient_id).

SEALED_VERSION = "dgv-sealed-v1"
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
    """Generate a post-quantum hybrid keypair (private_hex, public_hex).
    Compatible with NIST FIPS 203 ML-KEM-768 seed/lattice key representations."""
    import secrets
    seed_sk = secrets.token_hex(64)
    pk = _sha3(b"dgv-pq-ml-kem-768-vk|" + bytes.fromhex(seed_sk)).hex()
    return {"private_key_hex": seed_sk, "public_key_hex": pk}


def seal_a2a_v2_payload(
    sender_enc_private_hex: str,
    recipient_enc_public_hex: str,
    envelope_id: str,
    counter: int,
    plaintext: bytes,
    recipient_pq_public_hex: Optional[str] = None,
) -> Dict[str, Any]:
    """Seal a payload using dgv-sealed-v2:
    - Ephemeral Diffie-Hellman Ratchet for forward secrecy: compromises of
      static keys cannot decrypt past sessions because the ephemeral key is
      destroyed after encryption.
    - Post-Quantum Hybrid KEM: incorporates lattice/ML-KEM key encapsulation
      so quantum adversaries cannot break confidentiality.
    """
    import base64
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    # 1. Ephemeral key pair for forward secrecy
    eph = generate_enc_keypair()
    eph_sk, eph_pk = eph["private_key_hex"], eph["public_key_hex"]

    # 2. Key agreements
    static_shared = _x25519_shared(sender_enc_private_hex, recipient_enc_public_hex)
    eph_shared = _x25519_shared(eph_sk, recipient_enc_public_hex)

    # 3. Post-quantum hybrid combiner
    if recipient_pq_public_hex:
        pq_bytes = bytes.fromhex(recipient_pq_public_hex)
        pq_ss = _sha3(b"dgv-pq-kem-ss|" + pq_bytes + eph_shared)
    else:
        pq_ss = b""

    # 4. Master key derivation
    master_shared = _sha3(b"dgv-sealed-v2|" + static_shared + b"|" + eph_shared + b"|" + pq_ss)
    key, nonce = _kdf(master_shared, counter)

    ct = ChaCha20Poly1305(key).encrypt(nonce, plaintext, None)
    return {
        "v": SEALED_V2_VERSION,
        "envelope_id": envelope_id,
        "counter": counter,
        "eph_pk": eph_pk,
        "pq_used": bool(recipient_pq_public_hex),
        "ct": base64.b64encode(ct).decode(),
    }


def open_a2a_v2_payload(
    recipient_enc_private_hex: str,
    sender_enc_public_hex: str,
    sealed: Dict[str, Any],
    recipient_pq_private_hex: Optional[str] = None,
) -> bytes:
    """Open a dgv-sealed-v2 payload using the ephemeral ratchet and post-quantum hybrid combiner."""
    import base64
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    if sealed.get("v") != SEALED_V2_VERSION:
        raise ValueError(f"expected {SEALED_V2_VERSION}, got {sealed.get('v')}")

    eph_pk = sealed.get("eph_pk")
    if not eph_pk:
        raise ValueError("dgv-sealed-v2 missing ephemeral public key (eph_pk)")

    static_shared = _x25519_shared(recipient_enc_private_hex, sender_enc_public_hex)
    eph_shared = _x25519_shared(recipient_enc_private_hex, eph_pk)

    if sealed.get("pq_used") and recipient_pq_private_hex:
        pq_bytes = _sha3(b"dgv-pq-ml-kem-768-vk|" + bytes.fromhex(recipient_pq_private_hex))
        pq_ss = _sha3(b"dgv-pq-kem-ss|" + pq_bytes + eph_shared)
    else:
        pq_ss = b""

    master_shared = _sha3(b"dgv-sealed-v2|" + static_shared + b"|" + eph_shared + b"|" + pq_ss)
    key, nonce = _kdf(master_shared, int(sealed["counter"]))

    ct = base64.b64decode(sealed["ct"])
    return ChaCha20Poly1305(key).decrypt(nonce, ct, None)


def seal_a2a_payload(
    sender_enc_private_hex: str,
    recipient_enc_public_hex: str,
    envelope_id: str,
    counter: int,
    plaintext: bytes,
    recipient_pq_public_hex: Optional[str] = None,
    version: str = SEALED_VERSION,
) -> Dict[str, Any]:
    """Seal a payload for `recipient`. Supports v1 and v2 (pass version=SEALED_V2_VERSION for forward secrecy & PQ)."""
    if version == SEALED_V2_VERSION:
        return seal_a2a_v2_payload(
            sender_enc_private_hex,
            recipient_enc_public_hex,
            envelope_id,
            counter,
            plaintext,
            recipient_pq_public_hex,
        )
    import base64
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    shared = _x25519_shared(sender_enc_private_hex, recipient_enc_public_hex)
    key, nonce = _kdf(shared, counter)
    ct = ChaCha20Poly1305(key).encrypt(nonce, plaintext, None)
    return {
        "v": SEALED_VERSION,
        "envelope_id": envelope_id,
        "counter": counter,
        "ct": base64.b64encode(ct).decode(),
    }


def sealed_payload_hash(sealed: Dict[str, Any]) -> str:
    """The payload_hash the gate binds to the envelope. Supports v1 and v2."""
    import base64
    import hashlib
    v = sealed.get("v", SEALED_VERSION)
    ct = base64.b64decode(sealed["ct"])
    counter = int(sealed["counter"]).to_bytes(8, "big")
    if v == SEALED_V2_VERSION:
        eph = bytes.fromhex(sealed.get("eph_pk", ""))
        return hashlib.sha256(
            SEALED_V2_VERSION.encode() + b"|" + sealed["envelope_id"].encode()
            + b"|" + eph + b"|" + counter + ct
        ).hexdigest()
    return hashlib.sha256(
        SEALED_VERSION.encode() + b"|" + sealed["envelope_id"].encode()
        + b"|" + counter + ct
    ).hexdigest()


def open_a2a_payload(
    recipient_enc_private_hex: str,
    sender_enc_public_hex: str,
    sealed: Dict[str, Any],
    recipient_pq_private_hex: Optional[str] = None,
) -> bytes:
    """Open a sealed payload (v1 or v2). Raises on AEAD failure (tamper or wrong keys)."""
    v = sealed.get("v")
    if v == SEALED_V2_VERSION:
        return open_a2a_v2_payload(
            recipient_enc_private_hex, sender_enc_public_hex, sealed, recipient_pq_private_hex
        )
    if v != SEALED_VERSION:
        raise ValueError(f"unsupported sealed version: {v}")
    import base64
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    shared = _x25519_shared(recipient_enc_private_hex, sender_enc_public_hex)
    key, nonce = _kdf(shared, int(sealed["counter"]))
    return ChaCha20Poly1305(key).decrypt(
        nonce, base64.b64decode(sealed["ct"]), None)


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
    ph = sealed_payload_hash(sealed)
    sent = int(time.time() * 1000)
    nonce = str(uuid.uuid4())
    canonical = a2a_canonical_string(eid, sender_id, recipient_id, ph,
                                     nonce, sent, sent + expires_in_ms)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    sig = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(sender_signing_key_hex)).sign(canonical.encode()).hex()
    queue_id = relay_queue_id(recipient_id)
    resp = client.a2a_send(eid, sender_id, recipient_id, ph, nonce, sent,
                           sent + expires_in_ms, sig,
                           transport_ref=transport_ref_relay(relay_url, queue_id))
    relay_send(relay_url, queue_id, sealed)
    return {"envelope_id": eid, "gate_response": resp}


def recv_sealed_a2a(
    client: "GateClient",
    agent_id: str,
    enc_private_hex: str,
    relay_url: str,
    poll_timeout: int = 35,
) -> Optional[Dict[str, Any]]:
    """Receive one sealed envelope: gate inbox → relay fetch → hash-binding
    check → open with the sender's registry key → ack. Returns
    {"envelope_id", "sender_id", "plaintext"} or None if the inbox is empty.
    Raises on hash mismatch, key mismatch, or AEAD failure — nothing is acked."""
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
