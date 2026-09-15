import copy
import hashlib
import json


PROFILE = "DGV-OBJECTIVE-EXPERIMENT-1"
EVALUATOR = "quote-objective-v1"
MAX_INT = 9007199254740991


def canonical_bytes(value):
    def validate(item, depth=0):
        if depth > 32:
            raise ValueError("JSON nesting exceeds 32 levels")
        if item is None or type(item) is bool:
            return
        if type(item) is int and abs(item) <= MAX_INT:
            return
        if type(item) is str and len(item) <= 16384 and item.isascii():
            return
        if type(item) is list and len(item) <= 10000:
            for child in item:
                validate(child, depth + 1)
            return
        if type(item) is dict and len(item) <= 1000:
            for key, child in item.items():
                if type(key) is not str:
                    raise ValueError("JSON keys must be strings")
                validate(key, depth + 1)
                validate(child, depth + 1)
            return
        raise ValueError("Profile permits only bounded ASCII strings, safe integers, booleans, null, arrays and objects")

    validate(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def digest(value):
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def load_json(stream):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate JSON key: " + key)
            result[key] = value
        return result

    value = json.load(stream, object_pairs_hook=pairs)
    canonical_bytes(value)
    return value


def _text(value):
    return type(value) is str and bool(value.strip())


def _integer(value):
    return type(value) is int and 0 <= value <= MAX_INT


def _texts(value):
    return type(value) is list and all(_text(item) for item in value) and len(set(value)) == len(value)


def _hash(value):
    return type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _object(value, fields):
    return type(value) is dict and value.keys() == fields.keys() and all(check(value[key]) for key, check in fields.items())


CONTRACT_FIELDS = {
    "version": lambda x: x == EVALUATOR,
    "objective_id": _text,
    "source_instruction": _text,
    "customer_id": _text,
    "permitted_services": lambda x: _texts(x) and bool(x),
    "currency": lambda x: x in ("GBP", "EUR", "USD"),
    "max_total_minor": _integer,
    "approval_threshold_minor": _integer,
    "max_snapshot_age_ms": _integer,
    "max_approval_age_ms": _integer,
    "expires_at_ms": _integer,
    "policy_version": _text,
    "unresolved_requirements": _texts,
}
PROPOSAL_FIELDS = {
    "request_id": _text,
    "actor_id": _text,
    "action": _text,
    "objective_id": _text,
    "customer_id": _text,
    "service": _text,
    "currency": _text,
    "amount_minor": _integer,
}
CONTRACT_APPROVAL_FIELDS = {
    "contract_hash": _hash,
    "reviewer_id": _text,
    "approved_at_ms": _integer,
}
APPROVAL_FIELDS = {**CONTRACT_APPROVAL_FIELDS, "proposal_hash": _hash}
LEDGER_FIELDS = {
    "request_id": _text,
    "objective_id": _text,
    "customer_id": _text,
    "currency": _text,
    "amount_minor": _integer,
}
CONTEXT_FIELDS = {
    "observed_at_ms": _integer,
    "policy_version": _text,
    "authorized_actor_id": _text,
    "authority_revoked": lambda x: type(x) is bool,
    "trusted_reviewers": lambda x: _texts(x) and bool(x),
    "contract_approval": lambda x: x is None or _object(x, CONTRACT_APPROVAL_FIELDS),
    "approval": lambda x: x is None or _object(x, APPROVAL_FIELDS),
    "ledger": lambda x: type(x) is list and all(_object(row, LEDGER_FIELDS) for row in x),
}


def evaluate(*, contract, proposal, context, now_ms):
    checks = []

    def check(code, passed, failure="DENY"):
        checks.append({"code": code, "passed": bool(passed), "on_failure": failure})

    def decision():
        failures = [row for row in checks if not row["passed"]]
        state = "DENY" if any(row["on_failure"] == "DENY" for row in failures) else "ESCALATE" if failures else "ALLOW"
        return {"gate_state": state, "reason_codes": [row["code"] for row in failures] or ["OBJECTIVE_CONTRACT_SATISFIED"], "checks": checks}

    try:
        canonical_bytes([contract, proposal, context, now_ms])
    except ValueError:
        check("INVALID_SCHEMA", False)
        return decision()
    if contract is None or proposal is None or context is None:
        check("MISSING_EVIDENCE", False, "ESCALATE")
        return decision()
    if not (_object(contract, CONTRACT_FIELDS) and _object(proposal, PROPOSAL_FIELDS) and _object(context, CONTEXT_FIELDS) and _integer(now_ms)):
        check("INVALID_SCHEMA", False)
        return decision()

    check("UNRESOLVED_REQUIREMENTS", not contract["unresolved_requirements"], "ESCALATE")
    check("CONTRACT_EXPIRED", now_ms < contract["expires_at_ms"])
    check("POLICY_CHANGED", context["policy_version"] == contract["policy_version"], "ESCALATE")
    check("ACTOR_MISMATCH", proposal["actor_id"] == context["authorized_actor_id"])
    check("AUTHORITY_REVOKED", not context["authority_revoked"])
    check("STALE_CONTEXT", 0 <= now_ms - context["observed_at_ms"] <= contract["max_snapshot_age_ms"], "ESCALATE")

    review = context["contract_approval"]
    check("CONTRACT_APPROVAL_MISSING", review is not None, "ESCALATE")
    if review is not None:
        check("CONTRACT_APPROVAL_MISMATCH", review["contract_hash"] == digest(contract))
        check("CONTRACT_REVIEWER_UNTRUSTED", review["reviewer_id"] in context["trusted_reviewers"])
        check("CONTRACT_APPROVAL_TIME_INVALID", review["approved_at_ms"] <= context["observed_at_ms"] <= now_ms, "ESCALATE")

    check("ACTION_OUT_OF_SCOPE", proposal["action"] == "prepare_quote")
    check("OBJECTIVE_MISMATCH", proposal["objective_id"] == contract["objective_id"])
    check("CUSTOMER_MISMATCH", proposal["customer_id"] == contract["customer_id"])
    check("SERVICE_EXCLUDED", proposal["service"] in contract["permitted_services"])
    check("CURRENCY_MISMATCH", proposal["currency"] == contract["currency"])

    ledger = context["ledger"]
    ids = [row["request_id"] for row in ledger]
    check("LEDGER_DUPLICATE", len(ids) == len(set(ids)))
    check("REQUEST_ALREADY_RECORDED", proposal["request_id"] not in ids)
    check("LEDGER_SCOPE_MISMATCH", all(row["objective_id"] == contract["objective_id"] and row["customer_id"] == contract["customer_id"] and row["currency"] == contract["currency"] for row in ledger))
    total = sum(row["amount_minor"] for row in ledger) + proposal["amount_minor"]
    check("AGGREGATE_BUDGET_EXCEEDED", total <= contract["max_total_minor"])

    if total > contract["approval_threshold_minor"]:
        approval = context["approval"]
        check("APPROVAL_MISSING", approval is not None, "ESCALATE")
        if approval is not None:
            check("APPROVAL_BINDING_MISMATCH", approval["proposal_hash"] == digest(proposal) and approval["contract_hash"] == digest(contract))
            check("APPROVER_UNTRUSTED", approval["reviewer_id"] in context["trusted_reviewers"])
            check("APPROVAL_STALE", 0 <= now_ms - approval["approved_at_ms"] <= contract["max_approval_age_ms"] and approval["approved_at_ms"] <= context["observed_at_ms"], "ESCALATE")
    return decision()


def issue_receipt(*, contract, proposal, context, now_ms):
    request = copy.deepcopy({"contract": contract, "proposal": proposal, "context": context, "now_ms": now_ms})
    result = evaluate(**request)
    receipt = {
        "profile": PROFILE,
        "evaluator": EVALUATOR,
        "execution_mode": "local_synthetic_experiment",
        "execution_performed": False,
        "canonicalization": "ascii-safe-integer-json-v1",
        "replay_inputs": request,
        "contract_hash": digest(request["contract"]),
        "proposal_hash": digest(request["proposal"]),
        "context_hash": digest(request["context"]),
        "gate_decision": result,
        "decision_hash": digest(result),
        "assurance": "Deterministic evaluation of host-supplied evidence; no identity authentication, signature, live execution or continuous-authority proof",
    }
    receipt["receipt_hash"] = digest(receipt)
    return receipt


def verify_receipt(receipt, *, expected_request=None):
    def result(status, *reasons):
        return {"status": status, "reason_codes": list(reasons), "execution_authorized": False}

    try:
        if type(receipt) is not dict or receipt.get("profile") != PROFILE:
            return result("INVALID", "UNSUPPORTED_PROFILE")
        body = {key: value for key, value in receipt.items() if key != "receipt_hash"}
        if digest(body) != receipt.get("receipt_hash"):
            return result("INVALID", "HASH_MISMATCH")
        request = receipt["replay_inputs"]
        if not _object(request, {"contract": lambda x: True, "proposal": lambda x: True, "context": lambda x: True, "now_ms": _integer}):
            return result("INVALID", "INVALID_REPLAY_INPUTS")
        if canonical_bytes(issue_receipt(**request)) != canonical_bytes(receipt):
            return result("INVALID", "REPLAY_MISMATCH")
        if expected_request is None:
            return result("UNVERIFIABLE", "EXTERNAL_CONTEXT_REQUIRED")
        if canonical_bytes(request) != canonical_bytes(expected_request):
            return result("INVALID", "EXTERNAL_CONTEXT_MISMATCH")
        return result("VERIFIED_AGAINST_SUPPLIED_CONTEXT", "HASH_AND_DECISION_MATCH")
    except (KeyError, TypeError, ValueError, RecursionError):
        return result("INVALID", "INVALID_RECEIPT")
