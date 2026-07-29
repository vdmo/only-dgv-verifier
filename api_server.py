import os
import json
import time
import hashlib
import subprocess
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, HTTPException, Body
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import dgv_runner

app = FastAPI(
    title="DGV Governance & Compliance API",
    description="REST API for automated DGV Compliance Testing and real-time LLM Gating guardrails",
    version="0.6.0"
)

# Enable CORS for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DGV_DIR = os.path.dirname(os.path.abspath(__file__))
CARDS_DIR = os.path.join(DGV_DIR, "test_cards")
EVIDENCE_DIR = os.path.join(DGV_DIR, "evidence")

# Map of card_id (e.g. DGV-TC-042) to its absolute file path
CARD_MAP: Dict[str, str] = {}

def load_card_map():
    CARD_MAP.clear()
    if os.path.exists(CARDS_DIR):
        for f in os.listdir(CARDS_DIR):
            if f.endswith(".json") and f.startswith("dgv_tc_"):
                path = os.path.join(CARDS_DIR, f)
                try:
                    with open(path, "r") as file:
                        data = json.load(file)
                        cid = data.get("id")
                        if cid:
                            CARD_MAP[cid] = path
                except Exception:
                    pass

load_card_map()

class Message(BaseModel):
    role: str
    content: str

class GatingPolicy(BaseModel):
    check_injection: Optional[bool] = False
    check_phi: Optional[bool] = False
    check_corpus: Optional[bool] = False
    check_hitl: Optional[bool] = False
    phi_restricted: Optional[bool] = False
    corpus_text: Optional[str] = None
    registered_digest: Optional[str] = None
    bypass_hitl: Optional[bool] = False

class CompletionRequest(BaseModel):
    model: str = "gpt-4o"
    messages: List[Message]
    gating_policy: Optional[GatingPolicy] = None

@app.get("/")
def get_root():
    return {
        "status": "online",
        "service": "DGV Compliance & Gating API",
        "version": "v0.6.0",
        "test_cards_count": len(CARD_MAP),
        "supported_protocols": ["SVRNOS-L1", "SVRNOS-L2", "SVRNOS-L3", "SVRNOS-L4"]
    }

@app.get("/v1/test-cards")
def list_test_cards():
    load_card_map()
    cards_summary = []
    for cid, path in sorted(CARD_MAP.items()):
        try:
            with open(path, "r") as file:
                card = json.load(file)
                evidence_filename = f"{cid.lower().replace('-', '_')}_evidence.json"
                evidence_path = os.path.join(EVIDENCE_DIR, evidence_filename)
                status = "untested"
                if os.path.exists(evidence_path):
                    try:
                        with open(evidence_path, "r") as ef:
                            ev = json.load(ef)
                            status = ev.get("status", "untested")
                    except Exception:
                        pass
                
                cards_summary.append({
                    "id": cid,
                    "claim_name": card.get("claim_name"),
                    "svrnos_layer": card.get("svrnos_layer"),
                    "ger_mapping": card.get("ger_mapping"),
                    "version": card.get("version"),
                    "status": status
                })
        except Exception:
            pass
    return cards_summary

@app.get("/v1/test-cards/{card_id}")
def get_test_card(card_id: str):
    load_card_map()
    if card_id not in CARD_MAP:
        raise HTTPException(status_code=404, detail=f"Test card {card_id} not found")
    try:
        with open(CARD_MAP[card_id], "r") as file:
            return json.load(file)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read card: {e}")

@app.post("/v1/test-cards/{card_id}/run")
def run_card(card_id: str):
    load_card_map()
    if card_id not in CARD_MAP:
        raise HTTPException(status_code=404, detail=f"Test card {card_id} not found")

    bin_path = dgv_runner.find_binary()
    gate_path = dgv_runner.find_gate_binary()

    if not bin_path:
        raise HTTPException(status_code=500, detail="dgv-verifier binary not found. Please build it first.")

    SIM_FLAGS = {
        "DGV-TC-009": "--simulate-replay-token",
        "DGV-TC-010": "--simulate-latency-ms=100",
        "DGV-TC-011": "--simulate-explain",
        "DGV-TC-012": "--simulate-prompt-injection",
        "DGV-TC-013": "--simulate-bias-check",
        "DGV-TC-014": "--simulate-provenance",
        "DGV-TC-015": "--simulate-heartbeat-failure",
        "DGV-TC-016": "--simulate-codon-delegation",
        "DGV-TC-017": "--simulate-rlwe-signature",
        "DGV-TC-018": "--simulate-spectral-drift",
        "DGV-TC-019": "--simulate-non-expansive-repair",
        "DGV-TC-020": "--simulate-transitive-revocation",
        "DGV-TC-021": "--simulate-multisig-escape",
        "DGV-TC-022": "--simulate-double-spend",
        "DGV-TC-023": "--simulate-coherence-escalation",
        "DGV-TC-024": "--simulate-legal-hold",
        "DGV-TC-025": "--simulate-dpia-gate",
        "DGV-TC-026": "--simulate-security-linkage",
        "DGV-TC-027": "--simulate-weight-mismatch",
        "DGV-TC-028": "--simulate-unregistered-ai-id",
        "DGV-TC-029": "--simulate-drift-exceeded",
        "DGV-TC-030": "--simulate-trace-profile",
    }

    try:
        with open(CARD_MAP[card_id], "r") as file:
            card = json.load(file)
        
        card["simulation_flag"] = SIM_FLAGS.get(card["id"])
        evidence_cases = []
        card_passed = True

        # ── only-gate executor ────────────────────────────────────────────────
        if card.get("executor") == "only-gate":
            if not gate_path:
                raise HTTPException(
                    status_code=500,
                    detail=f"only-gate binary not found. Required for executing {card_id}."
                )
            for case in card["test_cases"]:
                try:
                    run_res = dgv_runner.run_gate_check(gate_path, case["input"])
                    expected = case.get("expected", {})
                    passed = dgv_runner.evaluate_case(run_res, expected, card["pass_threshold"])
                except Exception as e:
                    run_res = {"error": str(e)}
                    passed = False
                
                is_mandatory = case.get("mandatory", True)
                evidence_cases.append({
                    "case_id": case["id"],
                    "passed": passed,
                    "runs_count": None,
                    "runs_identical": None,
                    "output_sample": run_res,
                })
                if not passed and is_mandatory:
                    card_passed = False
        else:
            # ── dgv-verifier executor ─────────────────────────────────────────────
            for case in card["test_cases"]:
                script = case["input"]["script"]
                payload = case["input"]["payload"]
                extra_args = case["input"].get("extra_args")
                expected = case.get("expected", {})
                is_mandatory = case.get("mandatory", True)

                sim_flag = card.get("simulation_flag")
                if extra_args is None:
                    extra_args = [sim_flag] if sim_flag else []

                if card.get("multi_run", False) or card["id"] in ("DGV-TC-001", "DGV-TC-008"):
                    runs = []
                    for _ in range(5):
                        runs.append(dgv_runner.run_test_case(bin_path, script, payload, extra_args=extra_args))
                        time.sleep(0.01)
                    
                    first_run = runs[0]
                    runs_identical = all(
                        r.get("pass") == first_run.get("pass")
                        and r.get("residual_final") == first_run.get("residual_final")
                        and r.get("indices_healed") == first_run.get("indices_healed")
                        for r in runs[1:]
                    )
                    passed = runs_identical and dgv_runner.evaluate_case(first_run, expected, card["pass_threshold"])
                    if expected.get("runs_identical") is False:
                        passed = not runs_identical

                    evidence_cases.append({
                        "case_id": case["id"],
                        "passed": passed,
                        "runs_count": len(runs),
                        "runs_identical": runs_identical,
                        "output_sample": first_run,
                    })
                else:
                    run_res = dgv_runner.run_test_case(bin_path, script, payload, extra_args=extra_args)
                    if card["id"] == "DGV-TC-030":
                        module_results = run_res.get("module_results", [])
                        mandatory_passed = all(m["passed"] for m in module_results if m.get("mandatory"))
                        overall_pass_rate = run_res.get("overall_pass_rate", 0.0)
                        passed = run_res.get("pass") is True and mandatory_passed and overall_pass_rate >= 1.0
                        evidence_cases.append({
                            "case_id": case["id"],
                            "passed": passed,
                            "trace_level": run_res.get("trace_level"),
                            "eat_profile": run_res.get("eat_profile"),
                            "tee_provider": run_res.get("tee_provider"),
                            "policy_bundle_hash": run_res.get("policy_bundle_hash"),
                            "audit_chain_root": run_res.get("audit_chain_root"),
                            "audit_chain_tip": run_res.get("audit_chain_tip"),
                            "audit_chain_length": run_res.get("audit_chain_length"),
                            "module_results": module_results,
                            "overall_pass_rate": overall_pass_rate,
                            "conformance_tool_version": run_res.get("conformance_tool_version"),
                            "output": run_res,
                        })
                    else:
                        passed = dgv_runner.evaluate_case(run_res, expected, card["pass_threshold"])
                        evidence_cases.append({
                            "case_id": case["id"],
                            "passed": passed,
                            "runs_count": None,
                            "runs_identical": None,
                            "output_sample": run_res,
                        })

                if not passed and is_mandatory:
                    card_passed = False

        # Generate evidence package for this card
        evidence_filename = f"{card['id'].lower().replace('-', '_')}_evidence.json"
        evidence_path = os.path.join(EVIDENCE_DIR, evidence_filename)

        evidence_pack = {
            "test_card_id": card["id"],
            "claim_name": card["claim_name"],
            "svrnos_layer": card.get("svrnos_layer"),
            "ger_mapping": card.get("ger_mapping"),
            "benchmark_version": "0.6.0",
            "verified_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "status": "passed" if card_passed else "failed",
            "results": evidence_cases,
        }

        if card["id"] == "DGV-TC-030" and evidence_cases:
            first = evidence_cases[0]
            evidence_pack.update({
                "trace_level": first.get("trace_level"),
                "gateway_claim_eat_profile": first.get("eat_profile"),
                "tee_provider": first.get("tee_provider"),
                "policy_bundle_hash": first.get("policy_bundle_hash"),
                "audit_chain_root": first.get("audit_chain_root"),
                "audit_chain_tip": first.get("audit_chain_tip"),
                "audit_chain_length": first.get("audit_chain_length"),
                "module_results": first.get("module_results"),
                "overall_pass_rate": first.get("overall_pass_rate"),
                "conformance_tool_version": first.get("conformance_tool_version"),
                "gateway_claim_path": "evidence/gateway_claim_tc030.jwt",
            })

        evidence_bytes = json.dumps(evidence_pack, indent=2, sort_keys=True).encode("utf-8")
        evidence_sha256 = hashlib.sha256(evidence_bytes).hexdigest()
        evidence_pack["settlement_receipt"] = {
            "layer": "GitOps Cryptographic Registry",
            "anchor_method": "sha256-content-hash",
            "transaction_id": f"dgv-sha256:{evidence_sha256}",
            "signature": f"dgv-sha256:{evidence_sha256}",
            "verification_procedure": "https://github.com/only-engine/dgv/blob/main/RECEIPT_VERIFICATION.md",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

        if not os.path.exists(EVIDENCE_DIR):
            os.makedirs(EVIDENCE_DIR)

        with open(evidence_path, "w") as ef:
            json.dump(evidence_pack, ef, indent=2)

        return evidence_pack

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Runtime error executing card: {e}")

@app.post("/v1/test-cards/run-all")
def run_all_test_cards():
    load_card_map()
    results = {}
    for cid in sorted(CARD_MAP.keys()):
        try:
            res = run_card(cid)
            results[cid] = {
                "status": res.get("status"),
                "receipt": res.get("settlement_receipt", {}).get("transaction_id")
            }
        except Exception as e:
            results[cid] = {"status": "error", "error": str(e)}
    return {
        "status": "complete",
        "results": results
    }

@app.post("/v1/gate/completions")
def gate_completions(request: CompletionRequest):
    prompt = request.messages[-1].content if request.messages else ""
    policy = request.gating_policy

    gate_status = "OPEN"
    rejection_reason = None
    refusal_text = None

    gate_path = dgv_runner.find_gate_binary()

    # 1. Check for prompt injection
    if policy and policy.check_injection:
        injection_triggers = [
            "ignore original instructions",
            "ignore previous instructions",
            "print credentials",
            "override settings",
            "bypass system instructions"
        ]
        if any(trigger in prompt.lower() for trigger in injection_triggers):
            gate_status = "CLOSED"
            rejection_reason = "adversarial_prompt_injection_detected"
            refusal_text = "Request blocked by ONLY-GATE. Policy violation detected: adversarial prompt injection (GER-312)."

    # 2. Check PHI Boundary (simulated via only-gate if present, otherwise fallback)
    if gate_status == "OPEN" and policy and policy.check_phi:
        phi_triggers = ["phi", "medical", "patient", "private record"]
        if any(trigger in prompt.lower() for trigger in phi_triggers):
            if gate_path:
                try:
                    # Run only-gate with phi check parameters
                    run_res = dgv_runner.run_gate_check(gate_path, {
                        "check": "phi",
                        "phi_label_detected": "true",
                        "phi_token_count": "3"
                    })
                    if run_res.get("gate_status") == "CLOSED":
                        gate_status = "CLOSED"
                        rejection_reason = run_res.get("rejection_reason", "phi_boundary_violation_detected")
                        refusal_text = f"Request blocked by ONLY-GATE. Policy violation detected: {rejection_reason}."
                except Exception:
                    pass
            
            # Fallback mock if only-gate failed or isn't built
            if gate_status == "OPEN":
                gate_status = "CLOSED"
                rejection_reason = "phi_boundary_violation_detected"
                refusal_text = "Request blocked by ONLY-GATE. Policy violation detected: PHI boundary violation (GER-429)."

    # 3. Check RAG Corpus Digest
    if gate_status == "OPEN" and policy and policy.check_corpus:
        if policy.corpus_text and policy.registered_digest:
            if gate_path:
                try:
                    run_res = dgv_runner.run_gate_check(gate_path, {
                        "check": "corpus-digest",
                        "corpus": policy.corpus_text,
                        "registered_digest": policy.registered_digest
                    })
                    if run_res.get("gate_status") == "CLOSE":
                        gate_status = "CLOSED"
                        rejection_reason = run_res.get("rejection_reason", "rag_corpus_digest_mismatch")
                        refusal_text = "Request blocked by ONLY-GATE. Policy violation detected: RAG corpus digest mismatch (GER-427)."
                except Exception:
                    pass

    # 4. Check HITL bypass
    if gate_status == "OPEN" and policy and policy.check_hitl:
        if not policy.bypass_hitl:
            gate_status = "CLOSED"
            rejection_reason = "hitl_approval_required"
            refusal_text = "Request blocked by ONLY-GATE. Policy violation detected: HITL approval required (GER-332)."

    # Return response payload
    if gate_status == "CLOSED":
        # Create dummy signature for refusal receipt
        refusal_payload = {
            "gate_status": gate_status,
            "rejection_reason": rejection_reason,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }
        refusal_bytes = json.dumps(refusal_payload, sort_keys=True).encode("utf-8")
        receipt_hash = hashlib.sha256(refusal_bytes).hexdigest()
        
        return JSONResponse(
            status_code=200,
            content={
                "id": f"gate-refusal-{receipt_hash[:8]}",
                "object": "chat.completion.refusal",
                "created": int(time.time()),
                "model": request.model,
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": None,
                            "refusal": refusal_text,
                            "gate_status": "CLOSED",
                            "evidence_receipt": f"dgv-sha256:{receipt_hash}"
                        },
                        "finish_reason": "policy_violation"
                    }
                ]
            }
        )

    # If Open, mock response generation representing LLM completion
    success_payload = {
        "gate_status": "OPEN",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }
    success_bytes = json.dumps(success_payload, sort_keys=True).encode("utf-8")
    receipt_hash = hashlib.sha256(success_bytes).hexdigest()

    return {
        "id": f"chatcmpl-{receipt_hash[:8]}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": request.model,
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": f"ONLY-GATE Status: OPEN. Processing prompt: '{prompt[:40]}...' - Query successfully validated against corporate policy."
                },
                "finish_reason": "stop"
            }
        ],
        "usage": {
            "prompt_tokens": len(prompt.split()),
            "completion_tokens": 20,
            "total_tokens": len(prompt.split()) + 20
        },
        "gate_status": "OPEN",
        "evidence_receipt": f"dgv-sha256:{receipt_hash}"
    }
