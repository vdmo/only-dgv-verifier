import copy

from objective_contract import digest, issue_receipt, verify_receipt


NOW_MS = 1800000000000


def base_request():
    contract = {
        "version": "quote-objective-v1",
        "objective_id": "synthetic-quote-objective-1",
        "source_instruction": "Prepare Guard quotes for synthetic-customer-A only, in GBP, at most 50000 total including prior quotes. Require reviewed approval above 25000 total. Do not send or accept quotes.",
        "customer_id": "synthetic-customer-A",
        "permitted_services": ["Guard"],
        "currency": "GBP",
        "max_total_minor": 5000000,
        "approval_threshold_minor": 2500000,
        "max_snapshot_age_ms": 60000,
        "max_approval_age_ms": 300000,
        "expires_at_ms": NOW_MS + 600000,
        "policy_version": "synthetic-policy-1",
        "unresolved_requirements": [],
    }
    proposal = {
        "request_id": "synthetic-request-2",
        "actor_id": "synthetic-agent",
        "action": "prepare_quote",
        "objective_id": contract["objective_id"],
        "customer_id": contract["customer_id"],
        "service": "Guard",
        "currency": "GBP",
        "amount_minor": 3000000,
    }
    context = {
        "observed_at_ms": NOW_MS - 1000,
        "policy_version": contract["policy_version"],
        "authorized_actor_id": proposal["actor_id"],
        "authority_revoked": False,
        "trusted_reviewers": ["synthetic-human-reviewer"],
        "contract_approval": {"contract_hash": digest(contract), "reviewer_id": "synthetic-human-reviewer", "approved_at_ms": NOW_MS - 10000},
        "approval": {"contract_hash": digest(contract), "proposal_hash": digest(proposal), "reviewer_id": "synthetic-human-reviewer", "approved_at_ms": NOW_MS - 2000},
        "ledger": [{"request_id": "synthetic-request-1", "objective_id": contract["objective_id"], "customer_id": contract["customer_id"], "currency": "GBP", "amount_minor": 1000000}],
    }
    return {"contract": contract, "proposal": proposal, "context": context, "now_ms": NOW_MS}


def scenarios():
    definitions = [
        ("valid-reviewed-quote", [], "ALLOW", "OBJECTIVE_CONTRACT_SATISFIED"),
        ("correct-action-wrong-customer", [("proposal.customer_id", "synthetic-customer-B")], "DENY", "CUSTOMER_MISMATCH"),
        ("correct-customer-excluded-service", [("proposal.service", "Federation")], "DENY", "SERVICE_EXCLUDED"),
        ("aggregate-budget-bypass", [("context.ledger.0.amount_minor", 2500000)], "DENY", "AGGREGATE_BUDGET_EXCEEDED"),
        ("missing-transaction-approval", [("context.approval", None)], "ESCALATE", "APPROVAL_MISSING"),
        ("stale-transaction-approval", [("context.approval.approved_at_ms", NOW_MS - 300001)], "ESCALATE", "APPROVAL_STALE"),
        ("ambiguous-objective", [("contract.unresolved_requirements", ["Customer asked for the best option but has not selected a service"])], "ESCALATE", "UNRESOLVED_REQUIREMENTS"),
        ("stale-snapshot", [("context.observed_at_ms", NOW_MS - 60001)], "ESCALATE", "STALE_CONTEXT"),
        ("revoked-authority", [("context.authority_revoked", True)], "DENY", "AUTHORITY_REVOKED"),
        ("policy-substitution", [("context.policy_version", "synthetic-policy-2")], "ESCALATE", "POLICY_CHANGED"),
        ("unapproved-contract-edit", [("contract.max_total_minor", 9000000)], "DENY", "CONTRACT_APPROVAL_MISMATCH"),
        ("approval-for-different-payload", [("proposal.amount_minor", 3100000)], "DENY", "APPROVAL_BINDING_MISMATCH"),
        ("attempt-to-send-quote", [("proposal.action", "send_quote")], "DENY", "ACTION_OUT_OF_SCOPE"),
        ("wrong-currency", [("proposal.currency", "USD")], "DENY", "CURRENCY_MISMATCH"),
        ("already-recorded-request", [("proposal.request_id", "synthetic-request-1")], "DENY", "REQUEST_ALREADY_RECORDED"),
        ("wrong-actor", [("proposal.actor_id", "other-agent")], "DENY", "ACTOR_MISMATCH"),
        ("missing-contract-review", [("context.contract_approval", None)], "ESCALATE", "CONTRACT_APPROVAL_MISSING"),
        ("unknown-reviewer", [("context.approval.reviewer_id", "self-appointed-agent")], "DENY", "APPROVER_UNTRUSTED"),
        ("future-snapshot", [("context.observed_at_ms", NOW_MS + 1)], "ESCALATE", "STALE_CONTEXT"),
        ("missing-ledger", [("context.ledger", None)], "DENY", "INVALID_SCHEMA"),
        ("wrong-ledger-customer", [("context.ledger.0.customer_id", "other-customer")], "DENY", "LEDGER_SCOPE_MISMATCH"),
        ("objective-substitution", [("proposal.objective_id", "other-objective")], "DENY", "OBJECTIVE_MISMATCH"),
        ("expired-contract", [("now_ms", NOW_MS + 600000)], "DENY", "CONTRACT_EXPIRED"),
        ("missing-host-context", [("context", None)], "ESCALATE", "MISSING_EVIDENCE"),
    ]
    cases = []
    for name, patches, gate, reason in definitions:
        request = base_request()
        for path, value in patches:
            parts = path.split(".")
            target = request
            for part in parts[:-1]:
                target = target[int(part)] if isinstance(target, list) else target[part]
            target[parts[-1]] = value
        if name == "ambiguous-objective":
            contract_hash = digest(request["contract"])
            request["context"]["contract_approval"]["contract_hash"] = contract_hash
            request["context"]["approval"]["contract_hash"] = contract_hash
        cases.append((name, request, gate, reason))
    request = base_request()
    request["proposal"]["amount_minor"] = 1500000
    request["context"]["approval"] = None
    cases.append(("exact-approval-threshold", request, "ALLOW", "OBJECTIVE_CONTRACT_SATISFIED"))
    request = base_request()
    request["context"]["ledger"][0]["amount_minor"] = 2000000
    cases.append(("exact-budget-limit", request, "ALLOW", "OBJECTIVE_CONTRACT_SATISFIED"))
    request = base_request()
    request["proposal"]["amount_minor"] = 1500001
    request["context"]["approval"] = None
    cases.append(("split-quotes-cross-approval-threshold", request, "ESCALATE", "APPROVAL_MISSING"))
    request = base_request()
    request["context"]["ledger"].append(copy.deepcopy(request["context"]["ledger"][0]))
    cases.append(("duplicate-ledger-entry", request, "DENY", "LEDGER_DUPLICATE"))
    return cases


def run_experiment():
    results = []
    for name, request, expected_gate, expected_reason in scenarios():
        receipt = issue_receipt(**request)
        replay = verify_receipt(receipt, expected_request=request)
        decision = receipt["gate_decision"]
        passed = decision["gate_state"] == expected_gate and expected_reason in decision["reason_codes"] and replay["status"] == "VERIFIED_AGAINST_SUPPLIED_CONTEXT"
        results.append({"name": name, "expected_gate": expected_gate, "expected_reason": expected_reason, "passed": passed, "replay": replay, "receipt": receipt})
    return {
        "experiment": "quote-objective-contract-v1",
        "execution_mode": "local_synthetic_experiment",
        "case_count": len(results),
        "passed_count": sum(row["passed"] for row in results),
        "passed": bool(results) and all(row["passed"] for row in results),
        "limitations": [
            "Synthetic host-supplied approvals and ledger; no external identity or signature verification",
            "No CRM writes, ONLY Lang interpreter integration, distributed consistency or semantic model",
            "Budget safety assumes a complete ledger; live use requires atomic check-and-reserve",
            "Replay verifies historical evaluation, never authorizes a fresh execution",
            "Hashes are not signatures and require an externally trusted reference to resist wholesale replacement",
        ],
        "results": results,
    }
