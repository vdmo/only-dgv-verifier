# OWASP Top 10 for Agentic Applications (2026) — DGV Mapping

This document maps each OWASP Agentic Security Initiative (ASI) category to the DGV verifier's
implemented controls. It identifies what is covered, what is partially covered, and where
gaps remain.

**Standard:** OWASP Top 10 for Agentic Applications for 2026
**Published:** December 2025, OWASP GenAI Security Project
**DGV Version:** v0.2.0 (gate + storage + framework integration)

---

## ASI01: Agent Goal Hijack

**OWASP definition:** An attacker manipulates the agent's goals or instructions, causing it
to pursue objectives different from those intended by the operator.

**DGV controls:**

| Control | Mechanism | Status |
|---|---|---|
| `bind_objective` | Binds a proposal to a specific workflow/action set | **Implemented** — L9 command in ONLY Lang |
| `check_objective_drift` | Detects when the agent's action drifts from its bound objective | **Implemented** — real spectral drift check |
| Proposal schema | `ProposalSubmitted` requires `justification`, `workflow`, `intended_action`, `intended_consequence` | **Implemented** — structured proposal fields |
| Evidence pack | Decision hash covers `tool`, `action`, `params`, `justification` | **Implemented** — tampering detected |
| Test cards | TC-003, TC-004, TC-005, TC-006, TC-007 | **89/89 pass** |

**How DGV mitigates:**
- Every tool call must present a bound objective. If the agent's action drifts from the bound
  objective (e.g., prompt injection redirects it to exfiltrate data), `check_objective_drift`
  detects the drift and the gate returns DENY.
- The `justification` field forces the agent to declare *why* it is acting — a record for
  post-hoc audit.
- Signed decision hashes make it impossible to retroactively change what the agent claimed
  it was going to do.

**Gaps:**
- No semantic analysis of `justification` text — an attacker could write a plausible-sounding
  justification that matches the bound objective while pursuing a different goal.
- No LLM-based intent classification — the drift check is mathematical, not semantic.
- `intended_consequence` field exists but is not enforced — an agent could declare a
  benign consequence while executing a harmful one.

**Coverage: Partial.** The mathematical drift check catches mechanical goal divergence
but not semantic manipulation (e.g., a well-crafted prompt injection that stays within
the declared objective's bounds).

---

## ASI02: Tool Misuse and Exploitation

**OWASP definition:** An agent uses a legitimate tool for malicious purposes — the tool
itself is not compromised, but the agent's use of it is harmful.

**DGV controls:**

| Control | Mechanism | Status |
|---|---|---|
| Token binding | Token bound to specific `tool` + `action` + `params_hash` | **Implemented** — cannot reuse for different params |
| `check_authority` | Verifies the agent has authority to use the tool | **Implemented** — L8 command |
| Policy per tool+action | Different governance scripts per tool+action pair | **Implemented** — `POST /policies` |
| Rate limiting | Per agent+tool, configurable | **Implemented** — `DGV_RATE_LIMIT_MAX` |
| `budget_limit` | Limits total expenditure per action | **Implemented** — L8 command |
| Test cards | TC-008, TC-009, TC-010, TC-011 | **89/89 pass** |

**How DGV mitigates:**
- Even if an agent has a valid token for `send_email`, it cannot use it for `delete_database`
  — the token is bound to the specific tool+action.
- If the agent tries to call `send_email` with different recipients than approved, the
  `params_hash` mismatch blocks execution.
- Per-tool policies allow different governance rules: `send_email` might require lower
  authority than `execute_sql`.

**Gaps:**
- No tool-input validation — the gate checks *that* the params match the token, not
  *whether* the params are safe (e.g., SQL injection in a string parameter).
- No tool-output filtering — the gate governs the call, not the tool's response.
- No sandboxing — the tool executes whatever it was called with.

**Coverage: Strong.** The token binding mechanism is specifically designed to prevent
tool misuse — the same token cannot be repurposed for a different tool, action, or
params. Combined with per-tool policies and rate limiting, this is one of DGV's
strongest coverage areas.

---

## ASI03: Identity and Privilege Abuse

**OWASP definition:** An agent operates with excessive privileges, or an attacker
impersonates an agent to gain unauthorized access.

**DGV controls:**

| Control | Mechanism | Status |
|---|---|---|
| `bind_authority` | Binds an actor to a specific role/tool scope | **Implemented** — L8 command |
| `check_authority` | Verifies the actor's authority at govern time | **Implemented** — L8 command |
| `revoke_authority` | Revokes an actor's authority | **Implemented** — L8 command |
| `check_revocation` | Checks if an actor is revoked (T₁ check at execute) | **Implemented** — L8 command |
| Tenant isolation | Tenant-specific policies override global | **Implemented** — `POST /tenant/:id/policies` |
| Multi-instance revocation | Revocation visible to all instances sharing DB | **Implemented** — distributed revocation tests |
| Admin auth | `X-Admin-Key` required for admin endpoints | **Implemented** |
| Test cards | TC-013, TC-014, TC-015, TC-016, TC-017 | **89/89 pass** |

**How DGV mitigates:**
- Each agent has an `agent_id` that is bound to specific authorities via `bind_authority`.
- Revocation is checked at both govern time (T₀) and execute time (T₁) — even if a token
  was issued, a subsequent revocation blocks execution.
- Tenant isolation prevents cross-tenant privilege escalation.
- Admin endpoints require authentication — only authorized operators can revoke or
  modify policies.

**Gaps:**
- **No OIDC/JWT** — agent identity is a raw string (`agent_id`), not a verified credential.
  An attacker who knows an agent's ID can submit proposals as that agent.
- **No per-user RBAC** — admin auth is a single shared key, not per-user permissions.
- **No delegation tokens** — the `link_lineage` command exists but delegation chains
  are not cryptographically enforced end-to-end.
- **No identity attestation** — no mechanism to prove an agent is what it claims to be.

**Coverage: Moderate.** The governance model is sound — bind, check, revoke, isolate.
But identity is not cryptographically verified. This is the single largest gap.

---

## ASI04: Agentic Supply Chain Vulnerabilities

**OWASP definition:** Compromised tools, plugins, models, or data sources that an agent
depends on introduce vulnerabilities.

**DGV controls:**

| Control | Mechanism | Status |
|---|---|---|
| Policy integrity | Policies stored in DB, signed decisions reference policy version | **Partial** — version tracked, not signed |
| YAML policy loading | Policies loaded from auditable files | **Implemented** — `POST /policies/load-file` |
| Evidence packs | Full provenance of every decision | **Implemented** — hash-linked records |
| `corpus_digest` | Hash of policy corpus for integrity verification | **Implemented** — L8 command |
| Test cards | TC-018, TC-019, TC-020 | **89/89 pass** |

**How DGV mitigates:**
- Policies are stored and versioned — you can audit which policy version was in effect
  for any decision.
- Evidence packs contain full provenance — what was decided, when, by whom, under
  which policy version.
- The `corpus_digest` command can verify that the policy corpus hasn't been tampered with.

**Gaps:**
- **No policy signing** — policies are stored but not cryptographically signed. A
  compromised database could inject malicious policies.
- **No dependency scanning** — no mechanism to verify that tools/models haven't been
  compromised.
- **No MCP/A2A security** — the gate doesn't verify the integrity of external tool
  servers or inter-agent protocols.
- **No SLSA/provenance chain** — no build provenance or dependency chain verification.

**Coverage: Weak.** The policy-as-code approach provides auditability, but there's no
cryptographic verification of the supply chain itself. This needs policy signing and
dependency attestation.

---

## ASI05: Unexpected Code Execution (RCE)

**OWASP definition:** An agent executes arbitrary code — either through prompt injection,
malformed tool inputs, or unsafe tool implementations.

**DGV controls:**

| Control | Mechanism | Status |
|---|---|---|
| Token binding | Token bound to specific action — can't be used for code exec | **Implemented** — tool+action binding |
| `check_authority` | Verifies authority for the specific tool+action | **Implemented** — L8 command |
| Rate limiting | Limits execution frequency | **Implemented** |
| `budget_limit` | Caps resource expenditure | **Implemented** — L8 command |
| Test cards | TC-021, TC-022 | **89/89 pass** |

**How DGV mitigates:**
- The gate controls *whether* a tool call executes, not *what* the tool does internally.
  A token for `send_email` cannot be used to call `execute_code`.
- If `execute_code` is a governed tool, it goes through the same govern→execute cycle
  with its own policy.

**Gaps:**
- **No input sanitization** — the gate doesn't sanitize tool inputs. If a tool accepts
  a `command` parameter, the gate checks that the command matches the token's params_hash
  but doesn't validate the command's safety.
- **No sandboxing** — tools execute in the same process/host. A compromised tool
  can do anything the process can do.
- **No output validation** — the gate doesn't check what a tool returns.

**Coverage: Partial.** The gate prevents *unauthorized* code execution (no token = no
execution), but cannot prevent *authorized* code execution with malicious inputs.
This is fundamentally a tool-level concern, not a gate-level concern.

---

## ASI06: Memory & Context Poisoning

**OWASP definition:** An attacker corrupts the agent's memory or context, causing it
to make decisions based on poisoned information.

**DGV controls:**

| Control | Mechanism | Status |
|---|---|---|
| `bind_context` | Binds a context hash to the proposal | **Implemented** — L9 command |
| `check_context_drift` | Detects when the execution context drifts from the bound context | **Implemented** — real spectral drift |
| Ghost memory | `only-memory` provides drift detection via field evolution | **Implemented** — mathematical encoding |
| Evidence pack | Context hash is part of the decision record | **Implemented** |
| Test cards | TC-023, TC-024, TC-025, TC-026, TC-027 | **89/89 pass** |

**How DGV mitigates:**
- `bind_context` locks in a hash of the expected context. If the context drifts
  (e.g., a poisoned memory alters the agent's understanding), `check_context_drift`
  detects the mathematical divergence and the gate returns DENY.
- The context hash is included in the decision record — tampering with context
  after the fact is detectable.

**Gaps:**
- **Context hash is tool+params only** — the current implementation hashes the tool
  name and params, not the full agent context/memory. A poisoned memory that doesn't
  change the tool call would not be detected.
- **No memory integrity verification** — no mechanism to verify that the agent's
  memory store hasn't been tampered with.
- **No session state validation** — the gate doesn't verify that the agent's
  session state is consistent.

**Coverage: Moderate.** The context drift mechanism is real and implemented, but the
"context" is currently limited to tool+params, not the full agent memory/context.

---

## ASI07: Insecure Inter-Agent Communication

**OWASP definition:** Agents communicate over insecure channels, or malicious agents
spoof legitimate inter-agent messages.

**DGV controls:**

| Control | Mechanism | Status |
|---|---|---|
| TLS via nginx | Production deployment uses TLS termination | **Implemented** — docker-compose profile |
| Signed decisions | Every decision is Ed25519 signed | **Implemented** — tamper-evident |
| Token binding | Tokens bound to specific tool+action+params | **Implemented** — can't be replayed |
| CORS | Configurable CORS origins | **Implemented** — `DGV_CORS_ORIGINS` |
| Test cards | TC-028, TC-029, TC-030 | **89/89 pass** |

**How DGV mitigates:**
- In production, the gate sits behind an nginx TLS proxy — all communication is encrypted.
- Every decision is signed — a forged decision would fail signature verification.
- Tokens are bound and one-use — they cannot be replayed or repurposed.

**Gaps:**
- **No mTLS** — gate-to-gate communication is not mutually authenticated.
- **No agent-to-agent protocol** — DGV governs agent→tool calls, not agent→agent
  communication. There's no mechanism for one agent to verify another agent's
  decisions.
- **No message signing between agents** — inter-agent messages are not signed.

**Coverage: Partial.** The communication channel is secured (TLS) and decisions are
signed, but inter-agent communication security is not addressed. DGV is a single-agent
gate, not a multi-agent communication protocol.

---

## ASI08: Cascading Failures

**OWASP definition:** A failure in one agent or tool cascades through the system,
amplifying the impact.

**DGV controls:**

| Control | Mechanism | Status |
|---|---|---|
| Rate limiting | Prevents runaway execution | **Implemented** — per agent+tool |
| `budget_limit` | Caps resource expenditure per action | **Implemented** — L8 command |
| SILENCE on error | Governance failures return SILENCE, not crash | **Implemented** — no unhandled exceptions |
| Replay protection | Prevents cascading replay attacks | **Implemented** — one-use tokens |
| Test cards | TC-031, TC-032 | **89/89 pass** |

**How DGV mitigates:**
- Rate limiting prevents a single agent from overwhelming the system — once the limit
  is hit, further requests are denied with 429.
- `budget_limit` caps the total resources an agent can consume per action.
- The SILENCE response ensures that a governance failure doesn't propagate as an
  unhandled error.

**Gaps:**
- **No circuit breakers** — no mechanism to automatically disable a tool that is
  producing bad results.
- **No dependency health checks** — the gate doesn't check if downstream tools are
  healthy before allowing a call.
- **No bulkhead isolation** — all tools share the same gate; a gate failure affects
  all agents.

**Coverage: Moderate.** Rate limiting and budget caps prevent resource-exhaustion
cascades, but there's no failure-detection or circuit-breaking mechanism.

---

## ASI09: Human-Agent Trust Exploitation

**OWASP definition:** An agent manipulates a human operator into approving harmful
actions — through persuasive language, false urgency, or misleading information.

**DGV controls:**

| Control | Mechanism | Status |
|---|---|---|
| `justification` field | Agent must declare why it's acting | **Implemented** — proposal schema |
| `approvals_required` | Field exists for multi-approval workflows | **Partial** — field exists, not enforced |
| `HITL` test cards | Human-in-the-loop simulation | **Implemented** — TC-HITL cards |
| Evidence packs | Full audit trail of what was proposed and approved | **Implemented** |
| Test cards | TC-033, TC-034, TC-035 | **89/89 pass** |

**How DGV mitigates:**
- The `justification` field creates a record of the agent's stated reasoning — a human
  reviewer can check whether the stated justification matches the actual action.
- Evidence packs provide a complete audit trail — what was proposed, what was approved,
  what was executed.

**Gaps:**
- **No enforcement of approvals** — `approvals_required` exists but the gate doesn't
  block execution until approvals are received.
- **No justification verification** — the gate doesn't verify that the stated
  justification is accurate (it can't — that requires semantic understanding).
- **No approval workflow** — no multi-step approval process for high-risk actions.
- **HITL is simulated** — the test cards simulate human approval but there's no
  real human-in-the-loop workflow.

**Coverage: Weak.** The audit trail is solid, but there's no active enforcement of
human approval requirements. This is the second-largest gap after identity.

---

## ASI10: Rogue Agents

**OWASP definition:** An agent acts outside its intended scope — pursuing self-directed
goals, concealing its actions, or operating without authorization.

**DGV controls:**

| Control | Mechanism | Status |
|---|---|---|
| `check_authority` | Verifies the agent has authority for the action | **Implemented** — L8 command |
| `check_objective_drift` | Detects when the agent drifts from its bound objective | **Implemented** — L9 command |
| `check_context_drift` | Detects context manipulation | **Implemented** — L9 command |
| `budget_limit` | Caps resource expenditure | **Implemented** — L8 command |
| `residual()` | Computes how far the agent has drifted from baseline | **Implemented** — ONLY Lang |
| Evidence pack | Full record of every decision | **Implemented** — tamper-evident |
| Test cards | TC-036 through TC-042 | **89/89 pass** |

**How DGV mitigates:**
- Every action must go through the gate — a rogue agent cannot execute without a
  valid token.
- `check_objective_drift` detects when the agent's actual action diverges from its
  declared objective — a rogue agent pursuing self-directed goals would trigger
  drift detection.
- `residual()` provides a quantitative measure of how far the agent has drifted —
  a rogue agent accumulating drift would be detected.
- Evidence packs create an unforgeable record — a rogue agent cannot conceal its
  actions.

**Gaps:**
- **No behavioral analysis** — the drift checks are mathematical, not behavioral.
  A rogue agent that stays within mathematical bounds while pursuing harmful goals
  would not be detected.
- **No self-modification detection** — no mechanism to detect if an agent modifies
  its own code or goals.
- **No kill switch** — no mechanism to immediately terminate a rogue agent (only
  revocation, which requires admin action).
- **Stealth within bounds** — an agent that subtly manipulates its context within
  the drift threshold could evade detection.

**Coverage: Moderate.** The governance primitives (authority, drift, budget, evidence)
provide a strong foundation, but a sophisticated rogue agent that stays within
mathematical bounds could evade detection. This is the fundamental limitation of
mathematical governance — it catches mechanical divergence, not semantic malice.

---

## Summary Matrix

| ASI | Category | Coverage | Key Strength | Key Gap |
|---|---|---|---|---|
| ASI01 | Agent Goal Hijack | **Partial** | `bind_objective` + drift check | No semantic intent analysis |
| ASI02 | Tool Misuse | **Strong** | Token binding to tool+action+params | No input sanitization |
| ASI03 | Identity & Privilege | **Moderate** | Revocation + tenant isolation | No OIDC/JWT, no delegation |
| ASI04 | Supply Chain | **Weak** | Policy versioning + evidence packs | No policy signing, no dep scanning |
| ASI05 | Unexpected Code Exec | **Partial** | Token binding prevents unauthorized exec | No input sanitization/sandboxing |
| ASI06 | Memory Poisoning | **Moderate** | `bind_context` + drift check | Context = tool+params only |
| ASI07 | Inter-Agent Comms | **Partial** | TLS + signed decisions | No mTLS, no agent-to-agent protocol |
| ASI08 | Cascading Failures | **Moderate** | Rate limiting + budget caps | No circuit breakers |
| ASI09 | Human Trust Exploit | **Weak** | Justification + evidence packs | No approval enforcement |
| ASI10 | Rogue Agents | **Moderate** | Drift + residual + evidence | Mathematical bounds only |

## What This Means

**Strongest coverage:** ASI02 (Tool Misuse) — the token binding mechanism is
specifically designed for this. The same token cannot be repurposed.

**Weakest coverage:** ASI04 (Supply Chain) and ASI09 (Human Trust) — these require
capabilities DGV doesn't have yet: policy signing, dependency scanning, approval
workflow enforcement, and semantic justification verification.

**Honest assessment:** DGV provides strong *authorization* and *audit* coverage —
the gate controls who can do what, and produces evidence of what was done. It is
weaker on *semantic* security — detecting malicious intent within authorized bounds,
verifying human trust, and securing the supply chain.

---

## Recommended Next Steps (from gap analysis)

1. **ASI03 gap → OIDC/JWT identity providers** (highest priority — identity is the
   foundation of authorization)
2. **ASI09 gap → Approval workflow** (human-in-the-loop enforcement for high-risk actions)
3. **ASI04 gap → Policy signing** (cryptographically sign policies to prevent injection)
4. **ASI01 gap → Semantic justification verification** (LLM-based check that the
   stated justification matches the proposed action)
5. **ASI06 gap → Full context hashing** (hash the agent's full context/memory, not
   just tool+params)
