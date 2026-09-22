"""Real test of Vector 3 (decision evidence & independent verifiability) against
Microsoft's real FlightRecorder (agent_control_plane.flight_recorder), the actual
hash-chained audit logger shipped with agent-os-kernel — not the modeled reference
in benchmark_agt_vs_dgv.py.

Reproduce (needs Python >= 3.11):
    uv venv --python 3.12 env
    uv pip install --python env/bin/python agent-os-kernel pyyaml pydantic
    env/bin/python agt_real_test_vector3_evidence.py

Last run 2026-09-22 against agent-os-kernel 3.7.0 (agent_control_plane.flight_recorder):
    Logged 1 success + 1 violation (denial).
    verify_integrity() before tampering: {'valid': True, ...}
    Tampered policy_verdict on the violation row directly in SQLite, without recomputing content_hash.
    verify_integrity() after tampering:  {'valid': False, 'first_tampered_id': ..., 'error': 'Content hash mismatch...'}

Findings vs. the original modeled claims in BENCHMARK_AGT_VS_DGV.md:
  - "Denial Proofs: None (Denials are unreceipted exceptions)" is WRONG for the real
    product. log_violation() updates the SAME chained row start_trace() created and
    recomputes its content_hash — a denial gets the identical hash-chain treatment
    as a success. This needs correcting.
  - "Evidence Format: Merkle hash chain (JSON block)" and "Verification Complexity:
    O(N)" HOLD UP: this is a real Merkle-style chain (entry_hash links to
    previous_hash) and verify_integrity() does walk the full chain in insertion
    order — confirmed by reading its implementation, consistent with what we ran.
  - "Offline Verification: No (Requires trusting the logger node)" HOLDS UP in a
    narrower, more accurate sense: there is no Ed25519 (or any) signature — nothing
    here is independently verifiable by a third party without access to and trust
    in the SQLite database file itself. That is a real, still-standing difference
    from DGV's signed, standalone receipts, but the original phrasing ("denials are
    unreceipted exceptions") overstated it by implying denials aren't recorded at
    all, when they are recorded and chained, just not signed for offline proof.

Scope: this is agent_control_plane.flight_recorder only (SQLite-backed). We did not
check whether every deployment path in AGT actually wires log_violation() /
log_success() into every governed action, or whether other evidence backends exist
elsewhere in the toolkit.
"""
import json
import sqlite3
import tempfile
from pathlib import Path

from agent_control_plane.flight_recorder import FlightRecorder


def main():
    db_path = Path(tempfile.mkdtemp()) / "flight_recorder_test.db"
    rec = FlightRecorder(db_path=str(db_path), enable_batching=False)

    t1 = rec.start_trace("payments-agent", "disburse_funds", {"amount": 2500})
    rec.log_success(t1, result="disbursed", execution_time_ms=12.3)

    t2 = rec.start_trace("payments-agent", "drop_table", {"table": "users"})
    rec.log_violation(t2, "destructive action blocked by policy")

    rec.flush()

    before = rec.verify_integrity()
    print("Logged 1 success + 1 violation (denial).")
    print("verify_integrity() before tampering:", before)

    # Tamper directly with the SQLite file, bypassing FlightRecorder's own API —
    # simulating an operator (or an attacker with DB access) editing the denial
    # after the fact, exactly the scenario a hash chain exists to catch.
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "UPDATE audit_log SET policy_verdict = 'allowed', violation_reason = NULL WHERE trace_id = ?",
        (t2,),
    )
    conn.commit()
    conn.close()

    rec2 = FlightRecorder(db_path=str(db_path), enable_batching=False)
    after = rec2.verify_integrity()
    print("\nTampered policy_verdict on the violation row directly in SQLite, without recomputing content_hash.")
    print("verify_integrity() after tampering: ", after)

    print("\nRESULT:", "tamper detected correctly" if not after["valid"] else "TAMPER NOT DETECTED — investigate")


if __name__ == "__main__":
    main()
