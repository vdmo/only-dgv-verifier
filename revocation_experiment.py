import hashlib
import json
import multiprocessing
import os
import platform
import sqlite3
import tempfile
import time
from pathlib import Path

from objective_contract import canonical_bytes, digest
from revocation_store import AuthorityStore, audit_history


PROFILE = "DGV-REVOCATION-EXPERIMENT-1"
AUDIENCE = "synthetic-destination"


def _gate_worker(path, store_id, gate_id, connection, release):
    store = AuthorityStore(path, store_id)
    cached = None
    connection.send({"pid": os.getpid()})
    try:
        while True:
            command = connection.recv()
            operation = command.pop("operation")
            if operation == "stop":
                return
            if command.pop("barrier", False):
                connection.send({"ready": True})
                if not release.wait(10):
                    connection.send({"worker_error": "BarrierTimeout"})
                    continue
            started = time.perf_counter_ns()
            try:
                if operation == "observe":
                    cached = store.observe(command["actor_id"])
                    result = cached
                elif operation == "revoke":
                    result = store.set_authority(command["actor_id"], revoked=True)
                elif operation == "execute":
                    result = store.execute(**command, gate_id=gate_id)
                else:
                    raise ValueError("Unknown gate operation")
                connection.send({"operation": operation, "gate_id": gate_id, "pid": os.getpid(), "duration_us": (time.perf_counter_ns() - started) // 1000, "cached_authority": cached, "result": result})
            except Exception as error:
                connection.send({"worker_error": type(error).__name__})
    finally:
        connection.close()


class _GateProcess:
    def __init__(self, context, store, gate_id, release):
        self.connection, child = context.Pipe()
        self.process = context.Process(target=_gate_worker, args=(str(store.path), store.store_id, gate_id, child, release))
        self.process.start()
        child.close()
        try:
            self.pid = self.receive()["pid"]
        except Exception:
            self.close()
            raise

    def send(self, operation, *, barrier=False, **arguments):
        self.connection.send({"operation": operation, "barrier": barrier, **arguments})

    def receive(self):
        if not self.connection.poll(15):
            raise RuntimeError("Gate process did not respond")
        response = self.connection.recv()
        if "worker_error" in response:
            raise RuntimeError("Gate process error: " + response["worker_error"])
        return response

    def call(self, operation, **arguments):
        self.send(operation, **arguments)
        return self.receive()

    def close(self):
        if self.process.is_alive():
            try:
                self.send("stop")
            except (BrokenPipeError, OSError):
                pass
        self.process.join(3)
        if self.process.is_alive():
            self.process.terminate()
            self.process.join(3)
        self.connection.close()


def run_experiment(race_trials=24):
    if type(race_trials) is not int or not 1 <= race_trials <= 100:
        raise ValueError("race_trials must be an integer from 1 to 100")
    started = time.perf_counter_ns()
    context = multiprocessing.get_context("spawn")
    release = context.Event()
    release.set()
    cases, raw_tokens, race_orderings = [], [], []
    with tempfile.TemporaryDirectory(prefix="dgv-revocation-") as directory:
        store = AuthorityStore.create(Path(directory) / "authority.sqlite")
        gates = []
        try:
            gates.append(_GateProcess(context, store, "gate-A", release))
            gates.append(_GateProcess(context, store, "gate-B", release))
            gate_a, gate_b = gates

            def issue(label):
                actor = "actor-" + label
                payload = {"action": "synthetic_write", "customer_id": "synthetic-" + label, "amount_minor": 100}
                store.set_authority(actor, revoked=False)
                token = store.issue_token(actor, label, payload, AUDIENCE)
                raw_tokens.append(token)
                return actor, {"token": token, "action_id": label, "payload": payload, "audience": AUDIENCE}

            def record(name, passed, expected, *observations):
                cases.append({"name": name, "passed": bool(passed), "expected": expected, "observations": list(observations)})

            def simultaneous(first_operation, first, second_operation, second):
                release.clear()
                gate_a.send(first_operation, barrier=True, **first)
                gate_b.send(second_operation, barrier=True, **second)
                if gate_a.receive() != {"ready": True} or gate_b.receive() != {"ready": True}:
                    raise RuntimeError("Gate barrier handshake failed")
                release.set()
                return gate_a.receive(), gate_b.receive()

            actor, request = issue("stale-cache")
            cached = gate_b.call("observe", actor_id=actor)
            revoked = gate_a.call("revoke", actor_id=actor)
            after_revoke = time.perf_counter_ns()
            denied = gate_b.call("execute", **request)
            revoke_ack_to_denial_us = (time.perf_counter_ns() - after_revoke) // 1000
            record("stale-cache-after-committed-revocation", cached["result"]["revoked"] is False and denied["result"]["reason"] == "AUTHORITY_REVOKED" and denied["result"]["event_seq"] > revoked["result"]["event_seq"], "DENY despite cached active authority; execution check ordered after committed revocation", cached, revoked, denied)

            store.set_authority(actor, revoked=False)
            stale_token = gate_b.call("execute", **request)
            record("old-token-after-regrant", stale_token["result"]["reason"] == "TOKEN_VERSION_STALE", "DENY old authority generation even when the actor is active again", stale_token)
            fresh_token = store.issue_token(actor, request["action_id"], request["payload"], AUDIENCE)
            raw_tokens.append(fresh_token)
            request["token"] = fresh_token
            fresh = gate_b.call("execute", **request)
            record("fresh-token-after-regrant", fresh["result"]["execution_confirmed"], "ALLOW fresh version-bound token", fresh)
            replay = gate_a.call("execute", **request)
            record("token-replay-on-other-gate", replay["result"]["reason"] == "TOKEN_USED", "DENY replay; destination write remains one-use across gates", replay)
            duplicate_token = store.issue_token(actor, request["action_id"], request["payload"], AUDIENCE)
            raw_tokens.append(duplicate_token)
            duplicate = gate_a.call("execute", **{**request, "token": duplicate_token})
            record("duplicate-action-with-new-token", duplicate["result"]["reason"] == "ACTION_ALREADY_COMMITTED", "DENY duplicate action ID even with another unused token", duplicate)

            actor, request = issue("write-first")
            written = gate_b.call("execute", **request)
            revoked = gate_a.call("revoke", actor_id=actor)
            record("write-committed-before-revocation", written["result"]["execution_confirmed"] and written["result"]["event_seq"] < revoked["result"]["event_seq"] and any(row["action_id"] == request["action_id"] for row in store.snapshot()["actions"]), "Earlier committed write remains in history; revocation is not retroactive", written, revoked)

            actor, request = issue("store-outage")
            cached = gate_b.call("observe", actor_id=actor)
            lock = store.connect()
            try:
                lock.execute("BEGIN EXCLUSIVE")
                unavailable = gate_b.call("execute", **request)
            finally:
                lock.rollback()
                lock.close()
            no_write = not any(row["action_id"] == request["action_id"] for row in store.snapshot()["actions"])
            record("store-timeout-no-cache-fallback", unavailable["result"]["reason"] == "STORE_UNAVAILABLE" and not unavailable["result"]["execution_confirmed"] and no_write, "DENY on database lock timeout; cached permission cannot authorize; no destination row", cached, unavailable)
            recovered = gate_b.call("execute", **request)
            record("store-recovery-fresh-check", recovered["result"]["execution_confirmed"], "ALLOW after authoritative store recovers; failed attempt did not consume token", recovered)

            actor, request = issue("binding")
            altered = gate_b.call("execute", **{**request, "payload": {**request["payload"], "customer_id": "wrong-customer"}})
            record("payload-substitution", altered["result"]["reason"] == "TOKEN_BINDING_MISMATCH", "DENY token used for different payload", altered)
            wrong_audience = gate_b.call("execute", **{**request, "audience": "other-destination"})
            record("destination-substitution", wrong_audience["result"]["reason"] == "TOKEN_BINDING_MISMATCH", "DENY token used at different destination", wrong_audience)
            unknown = gate_b.call("execute", **{**request, "token": "0" * 64})
            record("unknown-token", unknown["result"]["reason"] == "UNKNOWN_TOKEN", "DENY unregistered token", unknown)

            actor, request = issue("double-use-race")
            left, right = simultaneous("execute", request, "execute", request)
            record("concurrent-token-use", sorted([left["result"]["reason"], right["result"]["reason"]]) == ["AUTHORIZED_AT_WRITE", "TOKEN_USED"], "Exactly one ALLOW and one TOKEN_USED denial", left, right)

            for index in range(race_trials):
                actor, request = issue("race-" + str(index))
                revocation, execution = simultaneous("revoke", {"actor_id": actor}, "execute", request)
                rseq, eseq = revocation["result"]["event_seq"], execution["result"]["event_seq"]
                write_first = eseq is not None and eseq < rseq
                correct = eseq is not None and execution["result"]["reason"] == ("AUTHORIZED_AT_WRITE" if write_first else "AUTHORITY_REVOKED")
                race_orderings.append("write_before_revoke" if write_first else "revoke_before_check" if eseq is not None else "unconfirmed")
                record("revocation-write-race-" + str(index), correct, "ALLOW only if the synthetic write commits before revocation; otherwise DENY", revocation, execution)
            snapshot = store.snapshot()
            gate_pids = {"gate-A": gate_a.pid, "gate-B": gate_b.pid}
        finally:
            release.set()
            for gate in gates:
                gate.close()
    history = audit_history(snapshot)
    report = {
        "profile": PROFILE,
        "execution_mode": "two_local_processes_single_sqlite_authority",
        "gate_pids": gate_pids,
        "race_trials": race_trials,
        "case_count": len(cases),
        "passed_count": sum(case["passed"] for case in cases),
        "passed": all(case["passed"] for case in cases) and history["valid"],
        "cases": cases,
        "snapshot": snapshot,
        "history_audit": history,
        "measurements": {
            "elapsed_us": (time.perf_counter_ns() - started) // 1000,
            "revoke_ack_to_denial_roundtrip_us": revoke_ack_to_denial_us,
            "race_orderings": {ordering: race_orderings.count(ordering) for ordering in sorted(set(race_orderings))},
            "store_busy_timeout_ms": store.timeout_ms,
            "sqlite_version": sqlite3.sqlite_version,
            "python_version": platform.python_version(),
        },
        "implementation_sha256": {name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest() for name in ("revocation_store.py", "revocation_experiment.py", "objective_contract.py")},
        "limitations": [
            "Two local processes share one SQLite database; no network transport, replication or consensus experiment",
            "Unavailable-store fault is a SQLite lock timeout, not a real network partition",
            "Trusted processes have local database access; production requires authenticated service roles and protected destination writes",
            "Only synthetic rows are executed; no CRM action, ONLY Lang integration or external tool side effect",
            "Ordering guarantees apply only when authority checks, token consumption and destination writes share this transaction",
            "Wall-clock TTL uses a persisted rollback check but is not a trusted time service",
            "Commit errors are unconfirmed: reconcile by action ID before retries; no external exactly-once guarantee",
            "Latency samples describe this run and do not establish a production SLA or propagation bound",
            "The history hash is not a signature; an independent trusted checkpoint is needed to detect wholesale replacement or restored old databases",
        ],
    }
    encoded = json.dumps(report, sort_keys=True)
    if any(token in encoded for token in raw_tokens):
        raise RuntimeError("Bearer token leaked into experiment report")
    report["report_hash"] = digest(report)
    return report


def verify_report(report, *, expected_hash=None):
    try:
        if type(report) is not dict or report.get("profile") != PROFILE:
            raise ValueError("Unsupported profile")
        actual = digest({key: value for key, value in report.items() if key != "report_hash"})
        if actual != report["report_hash"] or (expected_hash is not None and actual != expected_hash):
            raise ValueError("Report hash mismatch")
        history = audit_history(report["snapshot"])
        if not history["valid"] or history != report["history_audit"]:
            raise ValueError("History verification failed")
        if report["case_count"] != len(report["cases"]) or report["passed_count"] != sum(case["passed"] for case in report["cases"]) or report["passed"] != all(case["passed"] for case in report["cases"]):
            raise ValueError("Case tally mismatch")
        events = {event["seq"]: event for event in report["snapshot"]["events"]}
        if len(set(report["gate_pids"].values())) != 2:
            raise ValueError("Experiment did not identify two gate processes")
        for case in report["cases"]:
            for observation in case["observations"]:
                if observation["pid"] != report["gate_pids"][observation["gate_id"]] or type(observation["duration_us"]) is not int or observation["duration_us"] < 0:
                    raise ValueError("Invalid gate observation")
                result = observation["result"]
                if observation["operation"] == "execute":
                    seq = result["event_seq"]
                    if seq is None:
                        if result["execution_confirmed"] or result["decision"] != "DENY" or result["reason"] != "STORE_UNAVAILABLE":
                            raise ValueError("Invalid unavailable-store outcome")
                    else:
                        event = events[seq]
                        if event["kind"] != "EXECUTE" or event["gate_id"] != observation["gate_id"] or any(result[key] != event[key] for key in ("decision", "reason")) or result["execution_confirmed"] != (event["decision"] == "ALLOW") or result["authority_version"] != event["version"]:
                            raise ValueError("Execution observation does not match committed history")
                elif observation["operation"] == "revoke":
                    event = events[result["event_seq"]]
                    if event["kind"] != "REVOKE" or event["actor_id"] != result["actor_id"] or event["version"] != result["version"] or result["revoked"] is not True:
                        raise ValueError("Revocation observation does not match committed history")
                elif observation["operation"] != "observe":
                    raise ValueError("Unknown observation")
        canonical_bytes(report)
        return {"status": "VERIFIED_LOCAL_HISTORY" if expected_hash is not None else "UNVERIFIABLE", "reason": "HASH_AND_HISTORY_MATCH" if expected_hash is not None else "INDEPENDENT_CHECKPOINT_REQUIRED", "execution_authorized": False, "history_audit": history}
    except (KeyError, TypeError, ValueError, RecursionError):
        return {"status": "INVALID", "reason": "REPORT_OR_HISTORY_MISMATCH", "execution_authorized": False}
