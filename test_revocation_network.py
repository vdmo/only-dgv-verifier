#!/usr/bin/env python3
"""Phase 8 network-scale revocation tests for the DGV Enforcement Gate.

Covers three distinct mechanisms (kept separate on purpose — they are NOT
interchangeable claims):

  A. Signed gossip     — disconnected nodes (separate SQLite DBs) exchange
                         Ed25519-signed revocation records one hop at a time.
                         Authenticated eventual propagation, NOT consensus.
  B. Digest            — GET /revocations/digest detects divergence cheaply.
  C. Partition policy  — a gate that cannot reach storage fails CLOSED
                         (default) or OPEN (explicit DGV_PARTITION_POLICY=fail_open).

Also measures real propagation latency for both the gossip path and the
shared-storage path (two gates, one SQLite file — same-host lower bound).

Topology:
  G1 (7890, db1) <--signed gossip--> G2 (7891, db2)   [peers, mutual trust]
  G3 (7892, db3)   standalone — no peers, no trusted gossip keys
  G4 (7893)        postgres -> dead port 15999 (partitioned, fail_closed)
  G5 (7894)        postgres -> dead port 15999 (partitioned, fail_open)
  A  (7895) + B (7896)  share db_shared (shared-storage latency path)
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
GATE = "./target/release/dgv-gate"
DEAD_PG = "postgres://postgres:postgres@127.0.0.1:15999/dgv_gate"

FILES = {
    "k1": f"{NATIVE}/dgv_net_k1.hex",
    "k2": f"{NATIVE}/dgv_net_k2.hex",
    "db1": f"{NATIVE}/dgv_net_1.db",
    "db2": f"{NATIVE}/dgv_net_2.db",
    "db3": f"{NATIVE}/dgv_net_3.db",
    "db_shared": f"{NATIVE}/dgv_net_shared.db",
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


def load_key(path):
    seed = bytes.fromhex(open(path).read().strip())
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    vk_hex = sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    return sk, vk_hex


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


def gossip_canonical(g):
    return (
        f"dgv-revocation-v1|{g['actor_id']}|{g['reason']}|"
        f"{g['revoked_unix_ms']}|{g['revoked_by']}|{g['origin']}"
    )


def make_gossip(sk, vk_hex, actor_id, reason, ts, by="net-test"):
    g = {
        "actor_id": actor_id,
        "reason": reason,
        "revoked_unix_ms": ts,
        "revoked_by": by,
        "origin": vk_hex,
        "signature": "",
    }
    g["signature"] = sk.sign(gossip_canonical(g).encode()).hex()
    return g


def start_gate(port, extra_env):
    env = os.environ.copy()
    env["DGV_RATE_LIMIT_DISABLED"] = "1"
    env["DGV_LISTEN_ADDR"] = f"127.0.0.1:{port}"
    env.update(extra_env)
    proc = subprocess.Popen(
        [GATE], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
        cwd=NATIVE, env=env,
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
            return proc, base  # exited early (expected for invalid config)
    return proc, base


def govern(base, agent_id, req_id):
    return post(base, "/govern", {
        "request_id": req_id,
        "agent_id": agent_id,
        "workflow": "net-test",
        "tool": "send_email",
        "action": "send",
        "params": {"to": "x@example.com"},
        "justification": "network revocation test",
        "risk_level": "1000",
        "identity": {},
    })


def wait_revocation(base, actor_id, timeout_s=8):
    t0 = time.time()
    while time.time() - t0 < timeout_s:
        status, lst = get(base, "/revocations")
        if status == 200 and any(r["actor_id"] == actor_id for r in lst):
            return int((time.time() - t0) * 1000)
        time.sleep(0.05)
    return None


def main():
    for f in FILES.values():
        for suffix in ("", "-wal", "-shm"):
            if os.path.exists(f + suffix):
                os.remove(f + suffix)

    sk1, vk1 = write_key(FILES["k1"])
    sk2, vk2 = write_key(FILES["k2"])

    print("=== Phase 8: Network-Scale Revocation ===\n")

    procs = []

    # ── A. Signed gossip between disconnected nodes ─────────────────────────
    print("--- A. Signed gossip (separate DBs, no shared storage) ---")
    g1, u1 = start_gate(7890, {
        "DGV_STORAGE": "sqlite", "DGV_DATABASE_URL": f"sqlite://{FILES['db1']}",
        "DGV_SIGNING_KEY": FILES["k1"],
        "DGV_PEERS": "http://127.0.0.1:7891",
        "DGV_GOSSIP_KEYS": vk2,
    })
    procs.append(g1)
    g2, u2 = start_gate(7891, {
        "DGV_STORAGE": "sqlite", "DGV_DATABASE_URL": f"sqlite://{FILES['db2']}",
        "DGV_SIGNING_KEY": FILES["k2"],
        "DGV_PEERS": "http://127.0.0.1:7890",
        "DGV_GOSSIP_KEYS": vk1,
    })
    procs.append(g2)
    g3, u3 = start_gate(7892, {
        "DGV_STORAGE": "sqlite", "DGV_DATABASE_URL": f"sqlite://{FILES['db3']}",
        "DGV_SIGNING_KEY": FILES["k1"],  # same key ok; no peers/trust config
    })
    procs.append(g3)

    status, h = get(u1, "/health")
    if status == 200 and h.get("partition_policy") == "fail_closed" and h.get("gossip_peers") == 1:
        ok("health reports partition_policy=fail_closed + gossip_peers=1")
    else:
        bad("health gossip fields", f"{status} {h}")

    # Revoke on G1 -> gossip -> visible on G2 (latency measured)
    status, _ = post(u1, "/revocations", {
        "actor_id": "rogue-agent", "reason": "compromised", "revoked_by": "admin",
    })
    lat = wait_revocation(u2, "rogue-agent")
    if lat is not None:
        ok(f"gossip propagation G1->G2 ({lat} ms)")
    else:
        bad("gossip propagation", "revocation never visible on G2")

    # Gossiped revocation enforced on G2's govern path
    status, d = govern(u2, "rogue-agent", "net-gossip-1")
    if status == 200 and d["decision"]["gate_state"] == "DENY" and any(
        "revoked" in r for r in d["decision"]["reason_codes"]
    ):
        ok("gossiped revocation enforced on G2 /govern")
    else:
        bad("gossip enforcement on G2", f"{status} {d.get('decision', {})}")

    # Digest convergence across gossiped nodes
    d1, d2m = None, None
    for _ in range(40):
        _, d1 = get(u1, "/revocations/digest")
        _, d2m = get(u2, "/revocations/digest")
        if d1 and d2m and d1.get("sha256") == d2m.get("sha256"):
            break
        time.sleep(0.1)
    if d1 and d2m and d1.get("sha256") == d2m.get("sha256") and d1.get("count") == 1:
        ok(f"digest convergence G1==G2 (sha256={d1['sha256'][:16]}...)")
    else:
        bad("digest convergence", f"G1={d1} G2={d2m}")

    # Forged gossip: random key, valid format — must be rejected
    forged_sk = Ed25519PrivateKey.generate()
    forged_vk = forged_sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    forged = make_gossip(forged_sk, forged_vk, "innocent-agent", "forged", int(time.time() * 1000))
    status, body = post(u2, "/revocations/gossip", forged)
    if status == 403 and "invalid_signature" in body.get("error", ""):
        ok("forged gossip rejected (untrusted signer)")
    else:
        bad("forged gossip", f"{status} {body}")
    _, lst = get(u2, "/revocations")
    if not any(r["actor_id"] == "innocent-agent" for r in lst):
        ok("forged gossip did not revoke anyone")
    else:
        bad("forged gossip stored", "")

    # Malformed signature hex
    bad_sig = dict(forged)
    bad_sig["signature"] = "zzzz"
    status, body = post(u2, "/revocations/gossip", bad_sig)
    if status == 403:
        ok("malformed gossip signature rejected")
    else:
        bad("malformed gossip", f"{status} {body}")

    # Stale gossip must not overwrite a newer revocation
    stale = make_gossip(sk1, vk1, "rogue-agent", "stale-reason",
                        int(time.time() * 1000) - 60000)
    status, body = post(u2, "/revocations/gossip", stale)
    _, lst = get(u2, "/revocations")
    cur = next(r for r in lst if r["actor_id"] == "rogue-agent")
    if status == 200 and body.get("stored") is False and cur["reason"] == "compromised":
        ok("stale gossip rejected (monotonicity guard)")
    else:
        bad("stale gossip", f"{status} {body} current={cur}")

    # Valid gossip to a node with NO trusted keys -> rejected
    msg = make_gossip(sk1, vk1, "g3-target", "should-not-land", int(time.time() * 1000))
    status, body = post(u3, "/revocations/gossip", msg)
    if status == 403 and body.get("error") == "gossip_not_configured":
        ok("gossip rejected when DGV_GOSSIP_KEYS unset")
    else:
        bad("gossip to untrusting node", f"{status} {body}")

    # Divergence detection: standalone G3 diverges from G1
    post(u3, "/revocations", {
        "actor_id": "g3-local", "reason": "local-only", "revoked_by": "admin",
    })
    _, dg1 = get(u1, "/revocations/digest")
    _, dg3 = get(u3, "/revocations/digest")
    if dg1.get("sha256") != dg3.get("sha256"):
        ok("digest detects divergence between partitioned nodes")
    else:
        bad("digest divergence", f"{dg1} vs {dg3}")

    # ── B. Partition handling ───────────────────────────────────────────────
    print("\n--- B. Partition handling (Postgres unreachable) ---")
    g4, u4 = start_gate(7893, {
        "DGV_STORAGE": "postgres", "DGV_DATABASE_URL": DEAD_PG,
        "DGV_SIGNING_KEY": FILES["k1"],
    })
    procs.append(g4)

    if g4.poll() is None:
        ok("partitioned gate boots degraded (lazy connect, no crash)")
    else:
        bad("degraded boot", "gate exited on unreachable DB")

    status, h = get(u4, "/health")
    if status == 503 and h.get("storage") == "disconnected":
        ok("health reports degraded under partition")
    else:
        bad("degraded health", f"{status} {h}")

    status, d = govern(u4, "any-agent", "net-part-1")
    denied = status == 200 and d["decision"]["gate_state"] == "DENY" and any(
        "revocation_check_unavailable" in r for r in d["decision"]["reason_codes"]
    )
    if denied:
        ok("fail_closed: /govern denies when revocation unverifiable")
    else:
        bad("fail_closed govern", f"{status} {d.get('decision', {})}")

    status, e = post(u4, "/execute", {
        "token_id": "tok_nonexistent", "executor_id": "any-agent",
        "tool": "send_email", "action": "send", "params": {},
    })
    if status in (403, 500, 503) and e.get("allowed") is False:
        ok("fail_closed: /execute cannot allow under partition")
    else:
        bad("fail_closed execute", f"{status} {e}")

    status, a = post(u4, "/a2a/send", {
        "envelope_id": "env-1", "sender_id": "s", "recipient_id": "r",
        "payload_hash": "h", "nonce": "n", "sent_unix_ms": int(time.time() * 1000),
        "expires_unix_ms": int(time.time() * 1000) + 60000, "signature": "00" * 64,
    })
    if status >= 400:
        ok("fail_closed: /a2a/send cannot deliver under partition")
    else:
        bad("fail_closed a2a", f"{status} {a}")

    # fail_open dev mode: revocation check passes through, decision computed
    g5, u5 = start_gate(7894, {
        "DGV_STORAGE": "postgres", "DGV_DATABASE_URL": DEAD_PG,
        "DGV_SIGNING_KEY": FILES["k1"],
        "DGV_PARTITION_POLICY": "fail_open",
    })
    procs.append(g5)
    # Under fail_open every storage call burns the pool acquire timeout and
    # /govern makes several, so this request needs a longer client timeout.
    status, d = post(u5, "/govern", {
        "request_id": "net-part-2", "agent_id": "any-agent",
        "workflow": "net-test", "tool": "send_email", "action": "send",
        "params": {"to": "x@example.com"}, "justification": "t",
        "risk_level": "1000", "identity": {},
    }, timeout=30)
    if status == 200 and d["decision"]["gate_state"] == "ALLOW":
        ok("fail_open: /govern allows (explicit dev opt-in)")
        # Note: token was never persisted (storage down), so it cannot round-trip.
        status2, e2 = post(u5, "/execute", {
            "token_id": d["decision"]["auth_token"]["token_id"],
            "executor_id": "any-agent", "tool": "send_email",
            "action": "send", "params": {"to": "x@example.com"},
        })
        if e2.get("allowed") is False:
            ok("fail_open token cannot round-trip (persistence still failed)")
        else:
            bad("fail_open token round-trip", f"{status2} {e2}")
    else:
        bad("fail_open govern", f"{status} {d.get('decision', {})}")

    # Invalid policy value -> refuse to start
    proc = subprocess.Popen(
        [GATE], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        cwd=NATIVE,
        env={**os.environ, "DGV_PARTITION_POLICY": "bogus",
             "DGV_LISTEN_ADDR": "127.0.0.1:7897",
             "DGV_DATABASE_URL": f"sqlite://{FILES['db1']}",
             "DGV_SIGNING_KEY": FILES["k1"]},
    )
    rc = proc.wait(timeout=15)
    if rc == 2:
        ok("invalid DGV_PARTITION_POLICY refused at startup")
    else:
        bad("invalid policy value", f"exit={rc}")

    # ── C. Shared-storage propagation latency ───────────────────────────────
    print("\n--- C. Shared-storage propagation latency (two gates, one DB) ---")
    ga, ua = start_gate(7895, {
        "DGV_STORAGE": "sqlite", "DGV_DATABASE_URL": f"sqlite://{FILES['db_shared']}",
        "DGV_SIGNING_KEY": FILES["k1"],
    })
    procs.append(ga)
    gb, ub = start_gate(7896, {
        "DGV_STORAGE": "sqlite", "DGV_DATABASE_URL": f"sqlite://{FILES['db_shared']}",
        "DGV_SIGNING_KEY": FILES["k1"],
    })
    procs.append(gb)

    samples = []
    for i in range(5):
        actor = f"shared-agent-{i}"
        post(ua, "/revocations", {
            "actor_id": actor, "reason": "latency-measure", "revoked_by": "admin",
        })
        lat = wait_revocation(ub, actor)
        if lat is not None:
            samples.append(lat)
    if samples:
        ok(f"shared-storage propagation: {len(samples)} samples, "
           f"min={min(samples)}ms max={max(samples)}ms "
           f"avg={sum(samples)//len(samples)}ms")
    else:
        bad("shared-storage latency", "revocation never propagated")

    _, da = get(ua, "/revocations/digest")
    _, db = get(ub, "/revocations/digest")
    if da.get("sha256") == db.get("sha256") and da.get("count") == 5:
        ok("digest identical on shared storage (single consistency boundary)")
    else:
        bad("shared digest", f"{da} vs {db}")

    for p in procs:
        try:
            p.terminate()
            p.wait(timeout=5)
        except Exception:
            pass

    print(f"\n=== Results: {passed} passed, {failed} failed ===")
    print("""
Honest scope notes:
  - Signed gossip = authenticated one-hop propagation, NOT consensus/quorum.
  - Shared-storage latency measured on same-host SQLite — a lower bound;
    Postgres cross-node latency will be higher and is measured separately.
  - Partition test uses an unreachable Postgres DSN: pool connect fails,
    every storage call errors, partition policy governs the outcome.
""")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
