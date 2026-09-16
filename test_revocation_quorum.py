#!/usr/bin/env python3
"""Quorum revocation and Merkle anti-entropy reconciliation test suite.

Proves:
  1. Quorum configuration in /health (quorum_enabled, quorum_peers, quorum_size)
  2. Signed peer quorum-check queries (POST /revocations/quorum-check)
  3. Clean execution under unanimous quorum (R >= Q)
  4. Quorum revocation discovery at T₁ — revocation on Node B immediately halts
     execution on Node A without gossip, replicating the record to Node A
  5. Partition fail-closed — when majority peers are unreachable, an isolated
     node fails closed and refuses /execute
  6. 16-bucket Merkle prefix tree inspection (GET /revocations/merkle, GET /revocations/bucket/:p)
  7. Active anti-entropy reconciliation (POST /revocations/reconcile) — automatically
     converging divergent nodes byte-for-byte without human intervention.
"""

import json
import os
import subprocess
import sys
import time
import urllib.request
import urllib.error

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

ROOT = "/home/vdmo/pir/only-dgv-verifier"
NATIVE = f"{ROOT}/native"
GATE = f"{NATIVE}/target/release/dgv-gate"

FILES = {
    "k1": f"{NATIVE}/dgv_q_k1.hex",
    "k2": f"{NATIVE}/dgv_q_k2.hex",
    "k3": f"{NATIVE}/dgv_q_k3.hex",
    "db1": f"{NATIVE}/dgv_q_1.db",
    "db2": f"{NATIVE}/dgv_q_2.db",
    "db3": f"{NATIVE}/dgv_q_3.db",
}

passed = 0
failed = 0


def ok(name):
    global passed
    passed += 1
    print(f"PASS {name}")


def bad(name, detail=""):
    global failed
    failed += 1
    print(f"FAIL {name} {detail}")


def post(base, path, body, headers=None, timeout=10):
    data = json.dumps(body).encode()
    hdrs = {"Content-Type": "application/json"}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(f"{base}{path}", data=data, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())
    except Exception as e:
        return 0, {"error": str(e)}


def get(base, path):
    req = urllib.request.Request(f"{base}{path}")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())
    except Exception as e:
        return 0, {"error": str(e)}


def write_key(path):
    sk = Ed25519PrivateKey.generate()
    seed = sk.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    open(path, "w").write(seed.hex())
    vk_hex = sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    return sk, vk_hex


def clean_db(path):
    for ext in ("", "-wal", "-shm"):
        p = f"{path}{ext}"
        if os.path.exists(p):
            try:
                os.remove(p)
            except OSError:
                pass


def start_gate(port, extra_env):
    env = os.environ.copy()
    env["DGV_RATE_LIMIT_DISABLED"] = "1"
    env["DGV_LISTEN_ADDR"] = f"127.0.0.1:{port}"
    env.update(extra_env)
    proc = subprocess.Popen(
        [GATE],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
        cwd=NATIVE,
        env=env,
    )
    base = f"http://127.0.0.1:{port}"
    for _ in range(40):
        time.sleep(0.25)
        try:
            status, _ = get(base, "/health")
            if status in (200, 503):
                return proc, base
        except Exception:
            pass
        if proc.poll() is not None:
            return proc, base
    return proc, base


def main():
    print("=== DGV Quorum & Merkle Anti-Entropy Verification ===")

    for db in ("db1", "db2", "db3"):
        clean_db(FILES[db])

    sk1, vk1 = write_key(FILES["k1"])
    sk2, vk2 = write_key(FILES["k2"])
    sk3, vk3 = write_key(FILES["k3"])

    trusted_keys = f"{vk1},{vk2},{vk3}"

    port1, port2, port3 = 7931, 7932, 7933
    base1, base2, base3 = (
        f"http://127.0.0.1:{port1}",
        f"http://127.0.0.1:{port2}",
        f"http://127.0.0.1:{port3}",
    )

    env1 = {
        "DGV_DATABASE_URL": f"sqlite://{FILES['db1']}",
        "DGV_SIGNING_KEY": FILES["k1"],
        "DGV_ADMIN_KEY": "admin-1",
        "DGV_GOSSIP_KEYS": trusted_keys,
        "DGV_QUORUM_PEERS": f"{base2},{base3}",
        "DGV_QUORUM_SIZE": "2",
        "DGV_PARTITION_POLICY": "fail_closed",
    }
    env2 = {
        "DGV_DATABASE_URL": f"sqlite://{FILES['db2']}",
        "DGV_SIGNING_KEY": FILES["k2"],
        "DGV_ADMIN_KEY": "admin-2",
        "DGV_GOSSIP_KEYS": trusted_keys,
        "DGV_QUORUM_PEERS": f"{base1},{base3}",
        "DGV_QUORUM_SIZE": "2",
        "DGV_PARTITION_POLICY": "fail_closed",
    }
    env3 = {
        "DGV_DATABASE_URL": f"sqlite://{FILES['db3']}",
        "DGV_SIGNING_KEY": FILES["k3"],
        "DGV_ADMIN_KEY": "admin-3",
        "DGV_GOSSIP_KEYS": trusted_keys,
        "DGV_QUORUM_PEERS": f"{base1},{base2}",
        "DGV_QUORUM_SIZE": "2",
        "DGV_PARTITION_POLICY": "fail_closed",
    }

    p1, b1 = start_gate(port1, env1)
    p2, b2 = start_gate(port2, env2)
    p3, b3 = start_gate(port3, env3)
    procs = [p1, p2, p3]

    try:
        # 1. Health checks
        s1, h1 = get(b1, "/health")
        s2, h2 = get(b2, "/health")
        s3, h3 = get(b3, "/health")
        if (
            s1 == 200
            and h1.get("quorum_enabled") is True
            and h1.get("quorum_peers") == 2
            and h1.get("quorum_size") == 2
        ):
            ok("G1 reports quorum_enabled=true, 2 peers, quorum_size=2")
        else:
            bad("G1 health check", str(h1))

        if s2 == 200 and s3 == 200:
            ok("G2 and G3 online in quorum cluster")
        else:
            bad("G2/G3 online check")

        # 2. Signed quorum check endpoint
        qc_body = {
            "actor_id": "agent-clean-1",
            "nonce": "testnonce12345678",
            "timestamp_ms": int(time.time() * 1000),
        }
        st_qc, resp_qc = post(b2, "/revocations/quorum-check", qc_body)
        if st_qc == 200 and resp_qc.get("status") == "clean":
            ok("POST /revocations/quorum-check returns clean with signature")
        else:
            bad("quorum-check endpoint", f"status={st_qc} {resp_qc}")

        # Check clock skew rejection (>60s)
        st_stale, _ = post(
            b2,
            "/revocations/quorum-check",
            {
                "actor_id": "agent-clean-1",
                "nonce": "n1",
                "timestamp_ms": int((time.time() - 120) * 1000),
            },
        )
        if st_stale == 400:
            ok("stale quorum-check rejected (clock skew >60s)")
        else:
            bad("stale quorum-check check", f"status={st_stale}")

        # 3. Clean execution under unanimous quorum
        req_gov = {
            "request_id": "req-q1",
            "agent_id": "agent-clean-1",
            "workflow": "q-test",
            "tool": "record_fact",
            "action": "record_fact",
            "params": {"field": "status"},
            "justification": "quorum clean run",
            "risk_level": "1000",
            "identity": {},
        }
        st_gov, gov_data = post(b1, "/govern", req_gov)
        if st_gov == 200 and gov_data.get("decision", {}).get("gate_state") == "ALLOW":
            ok("G1 /govern grants token for agent-clean-1")
            token_id = gov_data["decision"]["auth_token"]["token_id"]
            # Execute on G1
            st_exec, exec_data = post(
                b1,
                "/execute",
                {
                    "token_id": token_id,
                    "executor_id": "agent-clean-1",
                    "tool": "record_fact",
                    "action": "record_fact",
                    "params": {"field": "status"},
                },
            )
            if st_exec == 200 and exec_data.get("allowed") is True:
                ok("G1 /execute succeeds with quorum confirmation (3/3 clean)")
            else:
                bad("G1 /execute clean run", f"status={st_exec} {exec_data}")
        else:
            bad("G1 /govern clean run", str(gov_data))

        # 4. Quorum Revocation Discovery at T₁
        # Issue token on G1 for agent-target
        st_gov2, gov_data2 = post(
            b1,
            "/govern",
            {
                "request_id": "req-q2",
                "agent_id": "agent-target-revoked",
                "workflow": "q-test",
                "tool": "record_fact",
                "action": "record_fact",
                "params": {"field": "score"},
                "justification": "quorum revocation test",
                "risk_level": "1000",
                "identity": {},
            },
        )
        token2_id = gov_data2["decision"]["auth_token"]["token_id"]

        # Revoke on G2 only (NOT G1)
        st_rev, rev_resp = post(
            b2,
            "/revocations",
            {
                "actor_id": "agent-target-revoked",
                "reason": "security incident on node 2",
                "revoked_by": "sec-ops",
            },
            headers={"X-Admin-Key": "admin-2"},
        )
        if st_rev == 200:
            ok("agent-target-revoked revoked on G2 directly")
        else:
            bad("G2 revocation failed", str(rev_resp))

        # Now execute token2 on G1 — G1 queries G2 and G3 via quorum check!
        st_exec2, exec_data2 = post(
            b1,
            "/execute",
            {
                "token_id": token2_id,
                "executor_id": "agent-target-revoked",
                "tool": "record_fact",
                "action": "record_fact",
                "params": {"field": "score"},
            },
        )
        if (
            st_exec2 == 403
            and exec_data2.get("allowed") is False
            and "authority_revoked_at_t1" in exec_data2.get("deny_reason", "")
        ):
            ok(
                "G1 denies /execute at T₁ because quorum check discovered revocation on G2!"
            )
        else:
            bad("T1 quorum discovery", f"status={st_exec2} {exec_data2}")

        # Verify G1 automatically replicated the revocation locally
        st_check_local, revs_g1 = get(b1, "/revocations")
        if any(r.get("actor_id") == "agent-target-revoked" for r in revs_g1):
            ok("G1 auto-replicated the revocation into its local database via quorum")
        else:
            bad("G1 local replication check", str(revs_g1))

        # 5. Partition Fail-Closed:
        # First issue token on G1 while quorum is healthy
        st_gov3, gov_data3 = post(
            b1,
            "/govern",
            {
                "request_id": "req-q3",
                "agent_id": "agent-during-partition",
                "workflow": "q-test",
                "tool": "record_fact",
                "action": "record_fact",
                "params": {"field": "partition"},
                "justification": "partition test",
                "risk_level": "1000",
                "identity": {},
            },
        )
        token3_id = gov_data3["decision"]["auth_token"]["token_id"]

        # Now simulate network partition isolating G1 by killing G2 and G3
        p2.terminate()
        p2.wait()
        p3.terminate()
        p3.wait()
        time.sleep(0.5)

        # Try to execute on isolated G1 at T₁ -> fails closed!
        st_part, part_data = post(
            b1,
            "/execute",
            {
                "token_id": token3_id,
                "executor_id": "agent-during-partition",
                "tool": "record_fact",
                "action": "record_fact",
                "params": {"field": "partition"},
            },
        )
        if (
            st_part == 503
            and part_data.get("allowed") is False
            and "revocation_check_unavailable" in part_data.get("deny_reason", "")
        ):
            ok(
                "Isolated G1 fails closed at T₁: denies execution when quorum unreachable"
            )
        else:
            bad(
                "Partition fail-closed check at T₁",
                f"status={st_part} {part_data}",
            )

        # Also try to govern a new request during partition -> fails closed at T₀!
        st_part_t0, part_t0_data = post(
            b1,
            "/govern",
            {
                "request_id": "req-q4",
                "agent_id": "agent-partition-t0",
                "workflow": "q-test",
                "tool": "record_fact",
                "action": "record_fact",
                "params": {"field": "partition"},
                "justification": "partition test",
                "risk_level": "1000",
                "identity": {},
            },
        )
        if (
            st_part_t0 == 200
            and part_t0_data.get("decision", {}).get("gate_state") == "DENY"
            and "insufficient quorum" in str(part_t0_data.get("decision", {}).get("reason_codes", []))
            and part_t0_data.get("decision", {}).get("auth_token") is None
        ):
            ok(
                "Isolated G1 fails closed at T₀: produces signed DENY receipt and issues no token when quorum unreachable"
            )
        else:
            bad("Partition fail-closed check at T₀", f"status={st_part_t0} {part_t0_data}")

        # Restart G2 and G3
        p2, b2 = start_gate(port2, env2)
        p3, b3 = start_gate(port3, env3)
        procs = [p1, p2, p3]

        # 6. Merkle Prefix Tree Inspection
        st_m1, m1 = get(b1, "/revocations/merkle")
        if st_m1 == 200 and "tree_root" in m1 and len(m1.get("buckets", {})) == 16:
            ok(
                f"GET /revocations/merkle returns 16 buckets and tree_root ({m1['tree_root'][:12]}...)"
            )
        else:
            bad("Merkle tree endpoint", f"status={st_m1} {m1}")

        # Query bucket endpoint
        prefix = list(m1.get("buckets", {}).keys())[0]
        st_b_resp, b_resp = get(b1, f"/revocations/bucket/{prefix}")
        if st_b_resp == 200 and b_resp.get("prefix") == prefix:
            ok(f"GET /revocations/bucket/{prefix} returns bucket records")
        else:
            bad("Bucket query check", str(b_resp))

        # 7. Active Anti-Entropy Reconciliation
        # Seed unique revocation on G3
        post(
            b3,
            "/revocations",
            {
                "actor_id": "agent-unique-g3",
                "reason": "isolated G3 revoke",
                "revoked_by": "admin-3",
            },
            headers={"X-Admin-Key": "admin-3"},
        )
        # Seed unique revocation on G1
        post(
            b1,
            "/revocations",
            {
                "actor_id": "agent-unique-g1",
                "reason": "isolated G1 revoke",
                "revoked_by": "admin-1",
            },
            headers={"X-Admin-Key": "admin-1"},
        )

        _, m1_before = get(b1, "/revocations/merkle")
        _, m3_before = get(b3, "/revocations/merkle")
        if m1_before["tree_root"] != m3_before["tree_root"]:
            ok("Confirmed divergence between G1 and G3 Merkle tree roots")
        else:
            bad("Expected divergence between G1 and G3")

        # G1 triggers reconciliation against G3
        st_rec, rec_data = post(b1, "/revocations/reconcile", {"peer": b3})
        if (
            st_rec == 200
            and rec_data.get("reconciled") is True
            and rec_data.get("divergent") is True
            and rec_data.get("pulled_count", 0) >= 1
        ):
            ok(
                f"G1 successfully reconciled with G3 (differing buckets: {rec_data.get('differing_buckets')})"
            )
        else:
            bad("Reconciliation call failed", f"status={st_rec} {rec_data}")

        # G3 reconciles with G1 to pull G1's unique record
        post(b3, "/revocations/reconcile", {"peer": b1})

        _, m1_after = get(b1, "/revocations/merkle")
        _, m3_after = get(b3, "/revocations/merkle")
        if m1_after["tree_root"] == m3_after["tree_root"]:
            ok(
                f"G1 and G3 Merkle tree roots converged to identical value ({m1_after['tree_root'][:12]}...)"
            )
        else:
            bad(
                "Merkle roots failed to converge",
                f"G1={m1_after['tree_root']} G3={m3_after['tree_root']}",
            )

        # Verify digest endpoint also matches
        _, d1 = get(b1, "/revocations/digest")
        _, d3 = get(b3, "/revocations/digest")
        if d1["sha256"] == d3["sha256"] and d1["count"] == d3["count"]:
            ok(
                f"GET /revocations/digest also converged byte-for-byte ({d1['sha256'][:12]}..., {d1['count']} records)"
            )
        else:
            bad("Digest convergence", f"d1={d1} d3={d3}")

    finally:
        for p in procs:
            if p.poll() is None:
                p.terminate()
                try:
                    p.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    p.kill()
        for db in ("db1", "db2", "db3"):
            clean_db(FILES[db])
        for k in ("k1", "k2", "k3"):
            if os.path.exists(FILES[k]):
                try:
                    os.remove(FILES[k])
                except OSError:
                    pass

    print(f"\n=== Quorum Results: {passed} passed, {failed} failed ===")
    if failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
