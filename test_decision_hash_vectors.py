#!/usr/bin/env python3
"""Cross-implementation check: the offline verifier's decision hash must equal the
Rust gate's for every shared vector (scripts/decision_hash_vectors.json)."""
import importlib.util, json, os, sys, types
HERE = os.path.dirname(os.path.abspath(__file__))
# verify_decision_chain imports pynacl at module load; stub it so the hash code can be tested alone.
for name in ("nacl", "nacl.signing", "nacl.exceptions"):
    sys.modules.setdefault(name, types.ModuleType(name))
sys.modules["nacl.signing"].VerifyKey = object
sys.modules["nacl.exceptions"].BadSignatureError = Exception
spec = importlib.util.spec_from_file_location("vdc", os.path.join(HERE, "scripts", "verify_decision_chain.py"))
vdc = importlib.util.module_from_spec(spec); spec.loader.exec_module(vdc)

vectors = json.load(open(os.path.join(HERE, "scripts", "decision_hash_vectors.json")))
bad = 0
for v in vectors:
    params = json.loads(v["params_json"])
    got = vdc.compute_decision_hash("r1", "ALLOW", ["rc"], "t", "send", params)
    ok = got == v["expected_sha256"]
    bad += not ok
    print(("PASS" if ok else "FAIL"), v["name"], "" if ok else f"got {got} want {v['expected_sha256']}")
# 2^53 and 2^53+1 must differ in the verifier too
a = vdc.compute_decision_hash("r", "ALLOW", [], "t", "x", {"n": 2**53})
b = vdc.compute_decision_hash("r", "ALLOW", [], "t", "x", {"n": 2**53 + 1})
print(("PASS" if a != b else "FAIL"), "verifier distinguishes 2^53 from 2^53+1"); bad += (a == b)
print(f"=== {len(vectors)+1-bad} passed, {bad} failed ===")
sys.exit(1 if bad else 0)
