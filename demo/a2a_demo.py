#!/usr/bin/env python3
"""Watch two agents talk through the DGV gate, and watch the gate and the recipient refuse what they should.

    cargo build -p dgv-gate                       (in native/)
    python demo/a2a_demo.py                       local stand-in relay
    python demo/a2a_demo.py --relay-bin PATH      real onlystate-relay (it listens on all network interfaces)

Starts a throwaway gate (temporary SQLite, random admin key, 127.0.0.1) and a relay, runs the scenes with made-up
data, writes an HTML report, and stops everything. Exit status 1 if any scene did not behave as described.

Needs `cryptography` with HPKE support (tested with 50.0.2).
"""

import argparse
import html
import json
import os
import queue
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
import dgv_a2a_v2 as v2  # noqa: E402
import dgv_sdk as sdk  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

MESSAGE = b"Synthetic order 1042: move 50 test units to warehouse B"


# ── stand-in relay (used unless --relay-bin is given) ────────────────────────

class StandInRelay(BaseHTTPRequestHandler):
    """The four onlystate-relay routes the SDK uses, in memory, on 127.0.0.1. Not the real relay."""
    queues = {}

    def log_message(self, *args):
        pass

    def _reply(self, obj):
        body = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _queue(self):
        return self.queues.setdefault(self.path.rsplit("/", 1)[-1], queue.Queue())

    def do_GET(self):
        if self.path == "/health":
            return self._reply({"status": "ok"})
        try:
            return self._reply(self._queue().get(timeout=3))
        except queue.Empty:
            return self._reply({"status": "timeout"})

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if self.path.startswith("/send/"):
            self._queue().put(body)
        self._reply({"status": "ok"})


# ── process helpers ──────────────────────────────────────────────────────────

def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_healthy(url, proc, what):
    for _ in range(80):
        if proc is not None and proc.poll() is not None:
            raise RuntimeError(f"{what} exited during startup")
        try:
            with urllib.request.urlopen(url + "/health", timeout=2) as r:
                if r.status == 200:
                    return
        except OSError:
            pass
        time.sleep(0.25)
    raise RuntimeError(f"{what} did not become healthy")


def find_gate():
    exe = "dgv-gate.exe" if os.name == "nt" else "dgv-gate"
    for path in (os.environ.get("DGV_GATE_BIN"),
                 os.path.join(ROOT, "native", "target", "release", exe),
                 os.path.join(ROOT, "native", "target", "debug", exe)):
        if path and os.path.isfile(path):
            return path
    sys.exit("dgv-gate not found: run `cargo build -p dgv-gate` in native/, or set DGV_GATE_BIN")


# ── scenes ───────────────────────────────────────────────────────────────────

class Demo:
    def __init__(self, gate_url, relay_url, admin_key):
        self.gate = sdk.GateClient(gate_url, admin_key=admin_key)
        self.relay = relay_url
        self.scenes = []
        self.agents = {}
        self.evidence_path = None
        # pinned before any message is sent; a real verifier gets it through a channel it trusts
        self.gate_key = self.gate._request("GET", "/health")["verifying_key"]

    def agent(self, name):
        sk = Ed25519PrivateKey.generate()
        raw = serialization.Encoding.Raw
        seed = sk.private_bytes(raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()).hex()
        pub = sk.public_key().public_bytes(raw, serialization.PublicFormat.Raw).hex()
        enc = sdk.generate_enc_keypair()
        self.gate.register_agent_key(name, pub, enc["public_key_hex"])
        self.agents[name] = {"sign": seed, "public": pub, "enc": enc}

    def scene(self, title, expect, kind="protects"):
        s = {"title": title, "expect": expect, "kind": kind, "lines": [], "ok": True}
        self.scenes.append(s)
        print(f"\n{len(self.scenes)}. {title}\n   expected: {expect}")
        return s

    def note(self, text):
        self.scenes[-1]["lines"].append(("info", text))
        print(f"   - {text}")

    def check(self, passed, text):
        s = self.scenes[-1]
        s["ok"] = s["ok"] and bool(passed)
        s["lines"].append(("ok" if passed else "bad", text))
        print(f"   {'[as expected]' if passed else '[UNEXPECTED]'} {text}")

    def refused(self, call, what, needle=""):
        """The call must fail. `needle` must appear in the reason, so an unrelated error does not count."""
        try:
            call()
        except (sdk.GateError, ValueError) as e:
            reason = json.dumps(e.body) if isinstance(e, sdk.GateError) else str(e)
            code = f"HTTP {e.status}: " if isinstance(e, sdk.GateError) else ""
            self.check(needle in reason, f"{what} refused ({code}{reason})")
            return
        self.check(False, f"{what} was ACCEPTED")

    def send(self, text=MESSAGE, sender="alice", recipient="bob", counter=0):
        a = self.agents[sender]
        return sdk.send_sealed_a2a(self.gate, sender, recipient, a["sign"], a["enc"]["private_key_hex"],
                                   text, counter, self.relay)

    def receive(self, name="bob"):
        return sdk.recv_sealed_a2a(self.gate, name, self.agents[name]["enc"]["private_key_hex"], self.relay,
                                   poll_timeout=10, gate_public_key_hex=self.gate_key)

    def waiting(self, name="bob"):
        return [e["envelope_id"] for e in self.gate.a2a_inbox(name)]

    def signed_envelope(self, signer, sender="alice", recipient="bob", ttl_ms=60_000, payload=b"x"):
        now = int(time.time() * 1000)
        # a negative ttl builds a well-formed envelope that ran out in the past
        sent = now if ttl_ms > 0 else now + 2 * ttl_ms - 60_000
        expires = now + ttl_ms
        return sdk.sign_a2a_envelope(self.agents[signer]["sign"], str(uuid.uuid4()), sender, recipient,
                                     payload, str(uuid.uuid4()), expires, sent_unix_ms=sent)

    def captured_send(self, counter, push=True):
        """Send, keeping a copy of what went to the relay. push=False holds the ciphertext back."""
        captured = {}
        original = sdk.relay_send

        def spy(url, queue_id, sealed):
            captured.update(queue=queue_id, sealed=sealed)
            if push:
                return original(url, queue_id, sealed)
            return {}

        sdk.relay_send = spy
        try:
            sent = self.send(counter=counter)
        finally:
            sdk.relay_send = original
        return sent, captured

    def run(self):
        for name in ("alice", "bob", "mallory"):
            self.agent(name)

        self.scene("A signed, encrypted message is delivered", "Bob reads it; the gate only ever sees a hash")
        sent, wire = self.captured_send(counter=1)
        record = next(e for e in self.gate.a2a_inbox("bob") if e["envelope_id"] == sent["envelope_id"])
        self.note(f"what the gate stored: payload_hash {record['payload_hash'][:24]}…, no content")
        self.check(MESSAGE.decode() not in json.dumps(wire["sealed"]) + json.dumps(record),
                   f"plaintext appears neither in the relay payload ({wire['sealed']['v']}) nor in the gate record")
        got = self.receive()
        self.check(got and got["plaintext"] == MESSAGE and got["sender_id"] == "alice",
                   f"bob opened: {got['plaintext'].decode() if got else None!r}")
        self.check(sent["envelope_id"] not in self.waiting(), "acknowledged, so it left bob's inbox")

        self.scene("The receipt can be checked offline",
                   "Using keys known beforehand, with no gate: it verifies, and fails if anything changes")
        evidence = sent["evidence"]
        alice_pub = self.agents["alice"]["public"]
        sealed_wire = wire["sealed"]

        def verifies(ev, **kw):
            try:
                v2.verify_evidence(ev, self.gate_key, alice_pub, **kw)
                return True
            except v2.EvidenceError:
                return False

        self.check(verifies(evidence, sealed=sealed_wire),
                   "sender signature, gate receipt and the sealed message all match")
        for field, value in (("decided_unix_ms", evidence["receipt"]["decided_unix_ms"] + 1),
                             ("payload_hash", "0" * 64), ("recipient_id", "mallory")):
            altered = json.loads(json.dumps(evidence))
            altered["receipt"][field] = value
            self.check(not verifies(altered), f"receipt with a changed {field} is rejected")
        if self.evidence_path:
            os.makedirs(os.path.dirname(self.evidence_path), exist_ok=True)
            with open(self.evidence_path, "w", encoding="utf-8") as f:
                json.dump(evidence, f, indent=1)
            self.note(f"saved for the command-line verifier: python dgv_a2a_v2.py "
                      f"{os.path.relpath(self.evidence_path, ROOT)} --gate-key {self.gate_key} --sender-key {alice_pub}")
        self.note("limit: a receipt shows the gate accepted the envelope, not that bob received or read it")

        self.scene("A forged sender is refused", "Mallory cannot send as Alice")
        env = self.signed_envelope(signer="mallory", sender="alice")
        self.refused(lambda: self.gate.a2a_send(**env), "envelope signed by mallory in alice's name", "signature")

        self.scene("An altered delivery address is refused", "The transport reference is covered by the signature")
        env = self.signed_envelope(signer="alice")
        env["transport_ref"] = "direct:https://attacker.invalid/inbox"
        self.refused(lambda: self.gate.a2a_send(**env), "envelope with an added transport reference", "signature")
        self.refused(lambda: self.gate.a2a_send(**self.signed_envelope(signer="alice", ttl_ms=48 * 3600 * 1000)),
                     "envelope valid for two days", "lifetime_too_long")

        self.scene("A swapped message is refused", "Bob neither opens nor acknowledges it; the real one still arrives")
        sent, wire = self.captured_send(counter=2, push=False)
        alice_enc = self.agents["alice"]["enc"]["private_key_hex"]
        bob_pub = self.agents["bob"]["enc"]["public_key_hex"]
        evil = sdk.seal_a2a_payload(alice_enc, bob_pub, sent["envelope_id"], 2, b"Synthetic order 1042: move 5000 units")
        self.note("worst case: the replacement is sealed with Alice's encryption key, and still differs from what she signed")
        sdk.relay_send(self.relay, wire["queue"], evil)
        self.refused(self.receive, "swapped ciphertext", "payload_hash mismatch")
        self.check(sent["envelope_id"] in self.waiting(), "still unacknowledged")
        sdk.relay_send(self.relay, wire["queue"], wire["sealed"])
        got = self.receive()
        self.check(got and got["plaintext"] == MESSAGE, "the genuine ciphertext then opens and is acknowledged")

        self.scene("A replayed envelope is refused", "The same signed envelope cannot be accepted twice")
        env = self.signed_envelope(signer="alice")
        self.check(self.gate.a2a_send(**env).get("accepted"), "first submission accepted")
        self.refused(lambda: self.gate.a2a_send(**env), "second submission", "replay")

        self.scene("Someone else cannot acknowledge Bob's message", "Mallory's acknowledgement changes nothing")
        target = env["envelope_id"]
        self.refused(lambda: self.gate.a2a_ack(target, "mallory"), "mallory's ack", "already_delivered_or_not_found")
        self.check(target in self.waiting(), "the envelope is still waiting for bob")

        self.scene("An expired envelope is refused", "Old authority is not accepted")
        old = self.signed_envelope(signer="alice", ttl_ms=-1000)
        self.refused(lambda: self.gate.a2a_send(**old), "expired envelope", "expired")

        self.scene("A withdrawn format cannot be used", "The SDK will not seal with the old, broken versions")
        for version in ("dgv-sealed-v1", "dgv-sealed-v2"):
            self.refused(lambda v=version: sdk.seal_a2a_payload(alice_enc, bob_pub, "e", 1, b"x", version=v),
                         version, "only dgv-sealed-v3")

        self.scene("A revoked agent is cut off", "After revocation Alice can no longer send")
        self.gate.revoke("alice", "demo: key reported stolen", "demo-admin")
        late = self.signed_envelope(signer="alice")
        self.refused(lambda: self.gate.a2a_send(**late), "alice after revocation", "revoked")

        self.scene("What this setup does NOT stop",
                   "Without login tokens, anyone who can reach the gate can claim to be Bob", kind="limit")
        self.note("this demo gate runs with DGV_A2A_ALLOW_UNAUTHENTICATED=1, a development-only setting")
        answer = self.gate.a2a_ack(target, "bob")  # mallory, simply claiming bob's id
        self.check(answer.get("delivered") is True,
                   "mallory claimed agent_id 'bob' and the ack went through. Configure JWT to prevent this.")


# ── report ───────────────────────────────────────────────────────────────────

def write_report(path, scenes, relay_name):
    e = html.escape
    good = sum(s["ok"] for s in scenes)
    cards = []
    for n, s in enumerate(scenes, 1):
        state = "bad" if not s["ok"] else ("limit" if s["kind"] == "limit" else "ok")
        label = {"ok": "behaved as expected", "limit": "known limit, shown on purpose", "bad": "UNEXPECTED"}[state]
        items = "".join(f'<li class="{k}">{e(t)}</li>' for k, t in s["lines"])
        cards.append(f'<section class="{state}"><h2>{n}. {e(s["title"])}</h2><span class="tag">{label}</span>'
                     f'<p>{e(s["expect"])}</p><ul>{items}</ul></section>')
    page = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>DGV A2A demo report</title><style>
:root{{--bg:#f4f6f8;--card:#fff;--text:#17212b;--dim:#566576;--line:#d9e0e7;--ok:#1d7a46;--bad:#b3261e;--limit:#8a5a00}}
@media(prefers-color-scheme:dark){{:root{{--bg:#10151b;--card:#18202a;--text:#e6edf3;--dim:#9aa9b8;--line:#2b3644;--ok:#5ec27f;--bad:#ff7a70;--limit:#f0b429}}}}
body{{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,Segoe UI,sans-serif}}
main{{max-width:760px;margin:0 auto;padding:24px 16px 48px}}h1{{margin:0 0 4px;font-size:22px}}
header p,section p{{color:var(--dim);margin:4px 0}}
section{{background:var(--card);border:1px solid var(--line);border-left:5px solid var(--ok);border-radius:10px;padding:14px 16px;margin-top:14px}}
section.bad{{border-left-color:var(--bad)}}section.limit{{border-left-color:var(--limit)}}h2{{font-size:16px;margin:0}}
.tag{{font-size:12px;color:var(--ok)}}.bad .tag{{color:var(--bad)}}.limit .tag{{color:var(--limit)}}
ul{{padding-left:18px;margin:8px 0 0}}li{{overflow-wrap:anywhere}}li.info{{color:var(--dim)}}li.bad{{color:var(--bad);font-weight:600}}
</style></head><body><main><header><h1>DGV agent-to-agent demo</h1>
<p>{good} of {len(scenes)} scenes behaved as described. Run {e(time.strftime("%Y-%m-%d %H:%M"))} on one machine with made-up data. Relay: {e(relay_name)}.</p>
<p>This is the <code>dgv</code> protocol. It is <b>not</b> Google's Agent2Agent (A2A) protocol. Encryption is HPKE (<code>dgv-sealed-v3</code>):
not post-quantum, no forward secrecy if the recipient's key is stolen, and not independently reviewed.</p></header>
{"".join(cards)}</main></body></html>"""
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(page)


def main():
    ap = argparse.ArgumentParser(description="DGV agent-to-agent demo")
    ap.add_argument("--relay-bin", help="path to a built onlystate-relay (listens on all interfaces)")
    ap.add_argument("--report", default=os.path.join(HERE, "out", "report.html"))
    args = ap.parse_args()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")

    gate_bin = find_gate()
    work = tempfile.mkdtemp(prefix="dgv-demo-")
    procs, server, demo = [], None, None
    try:
        gate_port, admin = free_port(), secrets.token_hex(16)
        env = {k: v for k, v in os.environ.items() if not k.startswith("DGV_")}
        env.update({
            "DGV_STORAGE": "sqlite", "DGV_DATABASE_URL": "sqlite://" + os.path.join(work, "gate.db").replace("\\", "/"),
            "DGV_LISTEN_ADDR": f"127.0.0.1:{gate_port}", "DGV_ADMIN_KEY": admin, "DGV_RATE_LIMIT_DISABLED": "1",
            "DGV_SIGNING_KEY": os.path.join(work, "gate.key"), "DGV_A2A_ALLOW_UNAUTHENTICATED": "1",
        })
        quiet = {"stdout": subprocess.DEVNULL, "stderr": subprocess.STDOUT}
        procs.append(subprocess.Popen([gate_bin], cwd=work, env=env, **quiet))
        gate_url = f"http://127.0.0.1:{gate_port}"
        wait_healthy(gate_url, procs[-1], "gate")

        relay_port = free_port()
        relay_url = f"http://127.0.0.1:{relay_port}"
        if args.relay_bin:
            relay_name = "onlystate-relay (real)"
            procs.append(subprocess.Popen(
                [args.relay_bin, "--port", str(relay_port), "--poll-timeout-secs", "3"], **quiet))
            wait_healthy(relay_url, procs[-1], "relay")
        else:
            relay_name = "local stand-in, not onlystate-relay"
            server = ThreadingHTTPServer(("127.0.0.1", relay_port), StandInRelay)
            threading.Thread(target=server.serve_forever, daemon=True).start()
        print(f"gate {gate_url} | relay {relay_url} ({relay_name})")

        demo = Demo(gate_url, relay_url, admin)
        demo.evidence_path = os.path.join(os.path.dirname(os.path.abspath(args.report)), "evidence.json")
        demo.run()
    finally:
        for p in reversed(procs):
            p.terminate()
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()
        if server:
            server.shutdown()
        shutil.rmtree(work, ignore_errors=True)

    write_report(args.report, demo.scenes, relay_name)
    good = sum(s["ok"] for s in demo.scenes)
    print(f"\n{good} of {len(demo.scenes)} scenes behaved as described. Report: {os.path.abspath(args.report)}")
    sys.exit(0 if good == len(demo.scenes) else 1)


if __name__ == "__main__":
    main()
