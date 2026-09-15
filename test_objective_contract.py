import copy
import io
import json
import unittest
from contextlib import redirect_stdout

from objective_contract import canonical_bytes, digest, evaluate, issue_receipt, load_json, verify_receipt
from objective_experiment import base_request, scenarios, run_experiment


class ObjectiveContractTests(unittest.TestCase):
    def test_scenarios(self):
        for name, request, expected_gate, expected_reason in scenarios():
            with self.subTest(name=name):
                decision = evaluate(**request)
                self.assertEqual(decision["gate_state"], expected_gate)
                self.assertIn(expected_reason, decision["reason_codes"])

    def test_replay_every_scenario(self):
        for name, request, _, _ in scenarios():
            with self.subTest(name=name):
                receipt = issue_receipt(**request)
                result = verify_receipt(receipt, expected_request=request)
                self.assertEqual(result["status"], "VERIFIED_AGAINST_SUPPLIED_CONTEXT")
                self.assertEqual(result["execution_authorized"], False)

    def test_untrusted_receipt_cannot_verify_its_own_authority(self):
        result = verify_receipt(issue_receipt(**base_request()))
        self.assertEqual(result["status"], "UNVERIFIABLE")
        self.assertIn("EXTERNAL_CONTEXT_REQUIRED", result["reason_codes"])

    def test_hash_binds_every_receipt_field(self):
        request = base_request()
        receipt = issue_receipt(**request)
        for key in receipt:
            with self.subTest(key=key):
                modified = copy.deepcopy(receipt)
                modified[key] = "changed"
                self.assertEqual(verify_receipt(modified, expected_request=request)["status"], "INVALID")

    def test_rehashed_false_allow_fails_rederivation(self):
        request = base_request()
        request["proposal"]["customer_id"] = "other-customer"
        receipt = issue_receipt(**request)
        receipt["gate_decision"]["gate_state"] = "ALLOW"
        receipt["receipt_hash"] = digest({k: v for k, v in receipt.items() if k != "receipt_hash"})
        result = verify_receipt(receipt, expected_request=request)
        self.assertIn("REPLAY_MISMATCH", result["reason_codes"])
        self.assertEqual(result["status"], "INVALID")

    def test_rehashed_context_substitution_rejected(self):
        original = base_request()
        replacement = copy.deepcopy(original)
        replacement["context"]["ledger"][0]["amount_minor"] = 0
        receipt = issue_receipt(**replacement)
        self.assertIn("EXTERNAL_CONTEXT_MISMATCH", verify_receipt(receipt, expected_request=original)["reason_codes"])

    def test_key_order_is_irrelevant_and_evaluation_does_not_mutate(self):
        request = base_request()
        original = copy.deepcopy(request)
        receipt = issue_receipt(**request)
        reordered = json.loads(json.dumps(request, sort_keys=True))
        self.assertEqual(issue_receipt(**reordered), receipt)
        self.assertEqual(original, request)

    def test_strict_json_profile(self):
        for value in [float("nan"), float("inf"), 1.5, 9007199254740992, {"key": "\ud800"}, {1: "value"}]:
            with self.subTest(value=repr(value)):
                with self.assertRaises(ValueError):
                    canonical_bytes(value)
        for raw in ['{"a": 1, "a": 2}', '{"a": NaN}', '{"a": 1.1}']:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                load_json(io.StringIO(raw))

    def test_malformed_money_fails_closed(self):
        for amount in [True, -1, "100", 1.5, None, 9007199254740992]:
            request = base_request()
            request["proposal"]["amount_minor"] = amount
            with self.subTest(amount=amount):
                self.assertEqual(evaluate(**request)["gate_state"], "DENY")

    def test_unknown_fields_and_rules_fail_closed(self):
        for field in ["contract", "proposal", "context"]:
            request = base_request()
            request[field]["ignore_checks"] = True
            with self.subTest(field=field):
                self.assertIn("INVALID_SCHEMA", evaluate(**request)["reason_codes"])

    def test_missing_inputs_never_allow(self):
        for field in ["contract", "proposal", "context"]:
            request = base_request()
            request[field] = None
            with self.subTest(field=field):
                self.assertNotEqual(evaluate(**request)["gate_state"], "ALLOW")

    def test_expiry_and_freshness_boundaries(self):
        request = base_request()
        request["now_ms"] = request["contract"]["expires_at_ms"]
        self.assertIn("CONTRACT_EXPIRED", evaluate(**request)["reason_codes"])
        request = base_request()
        request["context"]["observed_at_ms"] = request["now_ms"] - request["contract"]["max_snapshot_age_ms"]
        request["context"]["contract_approval"]["approved_at_ms"] = request["context"]["observed_at_ms"] - 1
        request["context"]["approval"]["approved_at_ms"] = request["context"]["observed_at_ms"] - 1
        self.assertEqual(evaluate(**request)["gate_state"], "ALLOW")
        request["context"]["observed_at_ms"] -= 1
        self.assertIn("STALE_CONTEXT", evaluate(**request)["reason_codes"])

    def test_deny_takes_precedence_over_escalation(self):
        request = base_request()
        request["proposal"]["customer_id"] = "other"
        request["context"]["approval"] = None
        self.assertEqual(evaluate(**request)["gate_state"], "DENY")

    def test_experiment_measures_failures(self):
        report = run_experiment()
        self.assertTrue(report["passed"])
        self.assertEqual(report["case_count"], len(report["results"]))
        self.assertEqual(report["execution_mode"], "local_synthetic_experiment")
        self.assertTrue(all(row["passed"] for row in report["results"]))

    def test_cli_receipt_replay_and_no_clobber(self):
        import subprocess
        import sys
        import tempfile
        from pathlib import Path
        root = Path(__file__).parent
        with tempfile.TemporaryDirectory() as directory:
            request_path = Path(directory) / "request.json"
            receipt_path = Path(directory) / "receipt.json"
            request_path.write_text(json.dumps(base_request()), encoding="utf-8")
            command = [sys.executable, str(root / "dgv_runner.py"), "--objective-request", str(request_path), "--output", str(receipt_path)]
            self.assertEqual(subprocess.run(command, capture_output=True).returncode, 0)
            original = receipt_path.read_bytes()
            self.assertEqual(subprocess.run(command, capture_output=True).returncode, 1)
            self.assertEqual(receipt_path.read_bytes(), original)
            command = [sys.executable, str(root / "verify_receipt.py"), "--objective-receipt", str(receipt_path)]
            untrusted = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(untrusted.returncode, 1)
            self.assertIn("UNVERIFIABLE", untrusted.stdout)
            trusted = subprocess.run(command + ["--objective-request", str(request_path)], capture_output=True, text=True)
            self.assertEqual(trusted.returncode, 0)
            self.assertIn("VERIFIED_AGAINST_SUPPLIED_CONTEXT", trusted.stdout)
            request = base_request()
            request["context"]["approval"] = None
            request_path.write_text(json.dumps(request), encoding="utf-8")
            denied = subprocess.run([sys.executable, str(root / "dgv_runner.py"), "--objective-request", str(request_path)], capture_output=True, text=True)
            self.assertEqual(denied.returncode, 1)
            self.assertEqual(json.loads(denied.stdout)["gate_decision"]["gate_state"], "ESCALATE")

    def test_saved_experiment_matches_current_code(self):
        from pathlib import Path
        path = Path(__file__).parent / "evidence" / "objective_contract_experiment.json"
        with path.open(encoding="utf-8") as stream:
            self.assertEqual(load_json(stream), run_experiment())

    def test_budget_predicate_detects_exhaustive_small_grid(self):
        for prior in range(0, 6000001, 1000000):
            for proposed in range(0, 6000001, 1000000):
                request = base_request()
                request["context"]["ledger"][0]["amount_minor"] = prior
                request["proposal"]["amount_minor"] = proposed
                request["context"]["approval"]["proposal_hash"] = digest(request["proposal"])
                result = evaluate(**request)
                with self.subTest(prior=prior, proposed=proposed):
                    self.assertEqual(result["gate_state"], "DENY" if prior + proposed > 5000000 else "ALLOW")

    def test_legacy_receipt_verifier_still_works(self):
        import hashlib
        import tempfile
        from pathlib import Path
        from verify_receipt import verify
        body = {"test_card_id": "LEGACY-TEST", "results": []}
        legacy_hash = hashlib.sha256(json.dumps(body, indent=2, sort_keys=True).encode("utf-8")).hexdigest()
        body["settlement_receipt"] = {"anchor_method": "sha256-content-hash", "transaction_id": "dgv-sha256:" + legacy_hash}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipt.json"
            path.write_text(json.dumps(body), encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                self.assertTrue(verify(str(path)))


if __name__ == "__main__":
    unittest.main()
