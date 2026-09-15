import copy
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from revocation_store import AuthorityStore, audit_history
from revocation_experiment import run_experiment, verify_report


class RevocationStoreTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "authority.sqlite"
        self.store = AuthorityStore.create(self.path)
        self.store.set_authority("agent", revoked=False)
        self.payload = {"action": "synthetic_write", "customer_id": "synthetic-A", "amount_minor": 100}

    def issue(self, action_id="action-1", ttl_ms=60000):
        return self.store.issue_token("agent", action_id, self.payload, "synthetic-destination", ttl_ms=ttl_ms)

    def execute(self, token, action_id="action-1", payload=None, audience="synthetic-destination"):
        return self.store.execute(token, action_id, self.payload if payload is None else payload, audience, gate_id="test-gate")

    def test_revocation_blocks_token_issued_before_it(self):
        token = self.issue()
        cached = self.store.observe("agent")
        revocation = self.store.set_authority("agent", revoked=True)
        result = self.execute(token)
        self.assertFalse(cached["revoked"])
        self.assertEqual(result["reason"], "AUTHORITY_REVOKED")
        self.assertGreater(result["event_seq"], revocation["event_seq"])
        self.assertEqual(self.store.snapshot()["actions"], [])
        self.assertTrue(audit_history(self.store.snapshot())["valid"])

    def test_old_token_does_not_revive_after_regrant(self):
        token = self.issue()
        self.store.set_authority("agent", revoked=True)
        self.store.set_authority("agent", revoked=False)
        self.assertEqual(self.execute(token)["reason"], "TOKEN_VERSION_STALE")
        self.assertTrue(self.execute(self.issue())["execution_confirmed"])

    def test_replay_and_action_idempotency(self):
        token = self.issue()
        other_token = self.issue()
        self.assertTrue(self.execute(token)["execution_confirmed"])
        self.assertEqual(self.execute(token)["reason"], "TOKEN_USED")
        self.assertEqual(self.execute(other_token)["reason"], "ACTION_ALREADY_COMMITTED")
        self.assertEqual(len(self.store.snapshot()["actions"]), 1)
        self.assertTrue(audit_history(self.store.snapshot())["valid"])

    def test_payload_audience_and_action_are_bound(self):
        token = self.issue()
        changed = {**self.payload, "customer_id": "synthetic-B"}
        for arguments in [{"payload": changed}, {"action_id": "other"}, {"audience": "other"}]:
            with self.subTest(arguments=arguments):
                self.assertEqual(self.execute(token, **arguments)["reason"], "TOKEN_BINDING_MISMATCH")
        self.assertTrue(self.execute(token)["execution_confirmed"])
        self.assertTrue(audit_history(self.store.snapshot())["valid"])

    def test_expired_token_denied_at_expiry_boundary(self):
        now_ms = time.time_ns() // 1000000 + 10000
        with patch("revocation_store.time.time_ns", return_value=now_ms * 1000000):
            token = self.issue(ttl_ms=1000)
        with patch("revocation_store.time.time_ns", return_value=(now_ms + 1000) * 1000000):
            self.assertEqual(self.execute(token)["reason"], "TOKEN_EXPIRED")
        self.assertEqual(self.store.snapshot()["actions"], [])

    def test_locked_store_fails_closed_without_consuming_token(self):
        token = self.issue()
        connection = self.store.connect()
        try:
            connection.execute("BEGIN EXCLUSIVE")
            result = self.execute(token)
            self.assertEqual(result["reason"], "STORE_UNAVAILABLE")
            self.assertFalse(result["execution_confirmed"])
        finally:
            connection.rollback()
            connection.close()
        self.assertEqual(self.store.snapshot()["actions"], [])
        self.assertTrue(self.execute(token)["execution_confirmed"])

    def test_missing_store_not_recreated_and_wrong_store_rejected(self):
        missing = self.path.with_name("missing.sqlite")
        unavailable = AuthorityStore(missing, self.store.store_id)
        token = self.issue()
        result = unavailable.execute(token, "action-1", self.payload, "synthetic-destination", gate_id="offline")
        self.assertEqual(result["reason"], "STORE_UNAVAILABLE")
        self.assertFalse(missing.exists())
        wrong = AuthorityStore(self.path, "0" * 32)
        self.assertEqual(wrong.execute(token, "action-1", self.payload, "synthetic-destination", gate_id="wrong")["reason"], "STORE_UNAVAILABLE")

    def test_clock_rollback_fails_closed(self):
        token = self.issue()
        with patch("revocation_store.time.time_ns", return_value=0):
            self.assertEqual(self.execute(token)["reason"], "STORE_UNAVAILABLE")
        self.assertEqual(self.store.snapshot()["actions"], [])

    def test_revoked_or_unknown_actor_cannot_get_token(self):
        self.store.set_authority("agent", revoked=True)
        with self.assertRaises(PermissionError):
            self.issue()
        with self.assertRaises(PermissionError):
            self.store.issue_token("unknown", "x", self.payload, "synthetic-destination")

    def test_malformed_and_unknown_tokens_fail_closed(self):
        for token in [None, "bad", 123, "0" * 64]:
            with self.subTest(token=token):
                self.assertEqual(self.execute(token)["decision"], "DENY")
        self.assertEqual(self.store.snapshot()["actions"], [])

    def test_revocation_does_not_undo_prior_write(self):
        allowed = self.execute(self.issue())
        revoked = self.store.set_authority("agent", revoked=True)
        self.assertLess(allowed["event_seq"], revoked["event_seq"])
        self.assertEqual(len(self.store.snapshot()["actions"]), 1)
        self.assertTrue(audit_history(self.store.snapshot())["valid"])

    def test_action_and_token_roll_back_if_destination_write_fails(self):
        token = self.issue()
        connection = self.store.connect()
        try:
            connection.execute("CREATE TRIGGER fail_write BEFORE INSERT ON actions BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END")
        finally:
            connection.close()
        result = self.execute(token)
        self.assertFalse(result["execution_confirmed"])
        snapshot = self.store.snapshot()
        self.assertEqual(snapshot["actions"], [])
        self.assertIsNone(snapshot["tokens"][0]["consumed_seq"])
        self.assertTrue(audit_history(snapshot)["valid"])

    def test_audit_detects_reordering_omission_and_changed_write(self):
        token = self.issue()
        self.execute(token)
        self.store.set_authority("agent", revoked=True)
        snapshot = self.store.snapshot()
        mutated = copy.deepcopy(snapshot)
        mutated["events"][2], mutated["events"][3] = mutated["events"][3], mutated["events"][2]
        self.assertFalse(audit_history(mutated)["valid"])
        mutated = copy.deepcopy(snapshot)
        mutated["events"].pop(1)
        self.assertFalse(audit_history(mutated)["valid"])
        mutated = copy.deepcopy(snapshot)
        mutated["actions"][0]["payload"]["amount_minor"] = 999
        self.assertFalse(audit_history(mutated)["valid"])

    def test_audit_rejects_allow_after_revocation(self):
        token = self.issue()
        self.store.set_authority("agent", revoked=True)
        self.execute(token)
        snapshot = self.store.snapshot()
        snapshot["events"][-1]["decision"] = "ALLOW"
        snapshot["events"][-1]["reason"] = "AUTHORIZED_AT_WRITE"
        self.assertFalse(audit_history(snapshot)["valid"])

    def test_create_never_overwrites_existing_store(self):
        before = self.path.read_bytes()
        with self.assertRaises(FileExistsError):
            AuthorityStore.create(self.path)
        self.assertEqual(before, self.path.read_bytes())


class RevocationExperimentTests(unittest.TestCase):
    def test_cli_run_verification_and_no_overwrite(self):
        import subprocess
        import sys
        root = Path(__file__).parent
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            command = [sys.executable, str(root / "dgv_runner.py"), "--revocation-experiment", "--race-trials", "2", "--output", str(output)]
            run = subprocess.run(command, capture_output=True, text=True, timeout=30)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            original = output.read_bytes()
            report = json.loads(original)
            check = [sys.executable, str(root / "verify_receipt.py"), "--revocation-report", str(output)]
            self.assertEqual(subprocess.run(check, capture_output=True, timeout=15).returncode, 1)
            verified = subprocess.run(check + ["--expected-hash", report["report_hash"]], capture_output=True, text=True, timeout=15)
            self.assertEqual(verified.returncode, 0, verified.stdout + verified.stderr)
            self.assertEqual(subprocess.run(check + ["--expected-hash", "0" * 64], capture_output=True, timeout=15).returncode, 1)
            self.assertEqual(subprocess.run(command, capture_output=True, timeout=30).returncode, 1)
            self.assertEqual(original, output.read_bytes())
            invalid = subprocess.run([sys.executable, str(root / "dgv_runner.py"), "--revocation-experiment", "--race-trials", "0"], capture_output=True, timeout=15)
            self.assertEqual(invalid.returncode, 2)

    def test_two_process_experiment_and_evidence(self):
        report = run_experiment(race_trials=8)
        self.assertTrue(report["passed"], json.dumps(report["cases"], indent=2))
        self.assertEqual(len(set(report["gate_pids"].values())), 2)
        self.assertEqual(report["race_trials"], 8)
        self.assertTrue(report["history_audit"]["valid"])
        self.assertEqual(verify_report(report)["status"], "UNVERIFIABLE")
        self.assertEqual(verify_report(report, expected_hash=report["report_hash"])["status"], "VERIFIED_LOCAL_HISTORY")
        tampered = copy.deepcopy(report)
        tampered["snapshot"]["actions"][0]["payload"]["amount_minor"] = 9
        self.assertEqual(verify_report(tampered, expected_hash=report["report_hash"])["status"], "INVALID")


if __name__ == "__main__":
    unittest.main()
