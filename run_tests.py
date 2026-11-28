#!/usr/bin/env python3
"""Run the gate test files and print one table.

    python run_tests.py                              the default set, SQLite (what CI runs)
    python run_tests.py --postgres URL --psql PSQL   the Postgres-capable set; URL is any database on a THROWAWAY
                                                     server whose user may create databases (one is made per test)
    python run_tests.py --only test_gate_v4.py ...

Build the gate first (cargo build -p dgv-gate in native/), or set DGV_GATE_BIN. Needs `cryptography`.
"""

import argparse
import os
import subprocess
import sys
import time
import uuid
from urllib.parse import urlsplit, urlunsplit

ROOT = os.path.dirname(os.path.abspath(__file__))

# name -> arguments. The default set, on temporary SQLite files. Fast format checks first.
SQLITE_SET = {
    "test_a2a_security.py": [],
    "test_a2a_evidence.py": ["--gate"],
    "test_a2a_ack_authz.py": [],
    "test_a2a_jwt.py": [],
    "test_a2a_transport.py": [],
    "demo/a2a_demo.py": [],
    "test_decision_hash_vectors.py": [],
    "test_objective_contract.py": [],
    "test_gate.py": [],
    "test_gate_v3.py": [],
    "test_gate_v4.py": [],
    "test_gate_v5.py": [],
    "test_sdk_langchain.py": [],  # the LangChain checks skip themselves if it is not installed
    "test_delegation.py": [],
    "test_delegation_adversarial.py": [],
    "test_revocation.py": [],
    "test_distributed_revocation.py": [],
    "test_revocation_quorum.py": [],
    "test_revocation_network.py": [],
    "test_quorum_revoked_without_record.py": [],
}
# These run on Postgres (they honour DGV_TEST_DATABASE_URL).
POSTGRES_SET = ["test_a2a_evidence.py", "test_a2a_ack_authz.py", "test_a2a_jwt.py", "test_a2a_transport.py",
                "demo/a2a_demo.py", "test_gate_v4.py", "test_concurrent_multi_instance.py"]
# test_gate_v5 checks use fcntl and SIGTERM
POSIX_ONLY = {"test_gate_v5.py"}


def fresh_database(url, psql):
    name = "dgv_t_" + uuid.uuid4().hex[:12]
    subprocess.run([psql, "-v", "ON_ERROR_STOP=1", "-qc", f"CREATE DATABASE {name}", "-d", url], check=True, timeout=60)
    parts = urlsplit(url)
    return urlunsplit(parts._replace(path="/" + name))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--postgres", help="URL of a throwaway Postgres server")
    ap.add_argument("--psql", default="psql")
    ap.add_argument("--only", nargs="+", help="run just these files")
    ap.add_argument("--timeout", type=int, default=420)
    args = ap.parse_args()

    names = args.only or (POSTGRES_SET if args.postgres else list(SQLITE_SET))
    results = []
    for name in names:
        if os.name == "nt" and name in POSIX_ONLY:
            results.append((name, "skipped (POSIX)", 0.0))
            continue
        env = dict(os.environ, PYTHONUTF8="1")
        env.pop("DGV_TEST_DATABASE_URL", None)
        if args.postgres:
            env["DGV_TEST_DATABASE_URL"] = fresh_database(args.postgres, args.psql)
        started = time.time()
        print(f"\n===== {name}", flush=True)
        try:
            code = subprocess.run([sys.executable, os.path.join(ROOT, name), *SQLITE_SET.get(name, [])],
                                  cwd=ROOT, env=env, timeout=args.timeout).returncode
            outcome = "pass" if code == 0 else f"FAIL (exit {code})"
        except subprocess.TimeoutExpired:
            outcome = "FAIL (timeout)"
        results.append((name, outcome, time.time() - started))

    print(f"\n{'Postgres' if args.postgres else 'SQLite'} results")
    for name, outcome, seconds in results:
        print(f"  {outcome:18} {name:40} {seconds:5.1f}s")
    sys.exit(1 if any(o.startswith("FAIL") for _, o, _ in results) else 0)


if __name__ == "__main__":
    main()
