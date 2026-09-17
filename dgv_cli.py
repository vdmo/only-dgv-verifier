#!/usr/bin/env python3
"""
dgv — governed agent metaharness CLI (stdlib only, like dgv_sdk).

One governance layer around any agent CLI without changing how the agent
is invoked: `dgv launch <cmd>` wraps the command in a governed launch —
T0 authorize, run, T1 receipt — and `dgv shim install` puts governed
shims on PATH so `claude`, `codex`, … route through the gate transparently.

Commands:
    dgv setup <gate-url> [--issuer URL] [--client-id ID]
    dgv login [--token JWT]       # device flow when an OIDC issuer is set
    dgv logout
    dgv status                    # gate health + desired vs applied revision
    dgv apply                     # reconcile policy revision without launching
    dgv verify                    # exit non-zero on drift / unreachable / no auth
    dgv launch <cmd...>           # governed launch: govern -> run -> execute
    dgv shim install <names...>   # PATH shims that exec `dgv launch <name>`
    dgv evidence push <file> [--ref URI] [--meta JSON]
    dgv evidence get <id> [-o out]
    dgv evidence list

State (override dir with DGV_CONFIG_HOME):
    ~/.config/dgv/config.json    {gate_url, oidc_issuer, client_id}
    ~/.config/dgv/session.json   {access_token, obtained_unix_ms}   (0600)
    ~/.config/dgv/state.json     {applied_revision, applied_unix_ms}

Env overrides: DGV_GATE_URL, DGV_TOKEN, DGV_ADMIN_KEY.
"""

import hashlib
import json
import os
import signal
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

LAUNCHER_VERSION = "dgv-cli/0.1.0"
GOVERNED_TOOL = "agent.cli"
GOVERNED_ACTION = "launch"

EXIT_OK = 0
EXIT_DENY = 77
EXIT_DRIFT = 2
EXIT_UNREACHABLE = 3
EXIT_AUTH = 4


# ── state files ──────────────────────────────────────────────────────────────

def _config_dir() -> str:
    return os.environ.get(
        "DGV_CONFIG_HOME", os.path.join(os.path.expanduser("~"), ".config", "dgv")
    )


def _load(name: str) -> dict:
    path = os.path.join(_config_dir(), name)
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


def _save(name: str, data: dict, mode: int = 0o600) -> None:
    os.makedirs(_config_dir(), exist_ok=True)
    path = os.path.join(_config_dir(), name)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    os.chmod(path, mode)


def _config() -> dict:
    c = _load("config.json")
    if os.environ.get("DGV_GATE_URL"):
        c["gate_url"] = os.environ["DGV_GATE_URL"]
    return c


def _token() -> str:
    if os.environ.get("DGV_TOKEN"):
        return os.environ["DGV_TOKEN"]
    return _load("session.json").get("access_token", "")


def _agent_id() -> str:
    """Effective caller id: JWT sub when a token exists (the gate binds
    executor identity to the verified sub), else a stable local identity."""
    tok = _token()
    if tok:
        sub = _jwt_claim(tok, "sub")
        if sub:
            return sub
    if os.environ.get("DGV_AGENT_ID"):
        return os.environ["DGV_AGENT_ID"]
    import getpass
    import socket

    return f"cli:{getpass.getuser()}@{socket.gethostname()}"


def _jwt_claim(token: str, name: str):
    try:
        import base64

        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload)).get(name)
    except Exception:
        return None


# ── HTTP ─────────────────────────────────────────────────────────────────────

def _req(method: str, path: str, body: dict = None, timeout: float = 10.0,
         base: str = None) -> dict:
    url = (base or _config().get("gate_url", "")).rstrip("/") + path
    headers = {"Content-Type": "application/json"}
    tok = _token()
    if tok:
        headers["Authorization"] = f"Bearer {tok}"
    admin = os.environ.get("DGV_ADMIN_KEY")
    if admin:
        headers["X-Admin-Key"] = admin
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            j = json.loads(raw)
        except Exception:
            j = {"error": f"HTTP {e.code}", "body": raw[:200].decode("utf-8", "replace")}
        j["_status"] = e.code
        return j
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        # -1, not 0: every caller checks `if resp.get("_status")`, and 0 is
        # falsy in Python — a real HTTP status is always >= 100 (truthy), so
        # -1 is the cheapest fix that keeps every existing check correct.
        return {"_status": -1, "error": f"unreachable: {e}"}


def _die(msg: str, code: int = 1):
    print(f"dgv: {msg}", file=sys.stderr)
    sys.exit(code)


def _gate_url_or_die() -> str:
    url = _config().get("gate_url")
    if not url:
        _die("not configured — run `dgv setup <gate-url>` first")
    return url


# ── commands ─────────────────────────────────────────────────────────────────

def cmd_setup(args):
    if not args:
        _die("usage: dgv setup <gate-url> [--issuer URL] [--client-id ID]")
    cfg = {"gate_url": args[0].rstrip("/")}
    if "--issuer" in args:
        cfg["oidc_issuer"] = args[args.index("--issuer") + 1]
    if "--client-id" in args:
        cfg["client_id"] = args[args.index("--client-id") + 1]
    _save("config.json", cfg)

    wk = _req("GET", "/.well-known/dgv", base=cfg["gate_url"])
    if wk.get("_status"):
        print(f"saved. warning: gate unreachable at {cfg['gate_url']} ({wk.get('error')})")
        return
    print(f"connected to {cfg['gate_url']}")
    print(f"  contract v{wk.get('contract_version')}  gate {wk.get('gate_version')}"
          f"  jwt={wk.get('auth', {}).get('jwt_mode')}"
          f"  partition={wk.get('capabilities', {}).get('partition_policy')}")


def cmd_login(args):
    cfg = _config()
    _gate_url_or_die()
    token = None
    if "--token" in args:
        token = args[args.index("--token") + 1]
    elif os.environ.get("DGV_TOKEN"):
        token = os.environ["DGV_TOKEN"]

    if token is None and cfg.get("oidc_issuer"):
        token = _device_flow(cfg["oidc_issuer"], cfg.get("client_id", "dgv-cli"))
    if token is None:
        _die("no token — pass --token, set DGV_TOKEN, or configure --issuer for device flow",
             EXIT_AUTH)

    _save("session.json", {"access_token": token, "obtained_unix_ms": int(time.time() * 1000)})
    print(f"logged in as {_jwt_claim(token, 'sub') or 'unknown'} "
          f"(exp {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(_jwt_claim(token, 'exp') or 0))})")


def _device_flow(issuer: str, client_id: str) -> str:
    """RFC 8628 device authorization grant (stdlib)."""
    disc = _req("GET", "/.well-known/openid-configuration", base=issuer)
    ep = disc.get("device_authorization_endpoint")
    tok_ep = disc.get("token_endpoint")
    if not ep or not tok_ep:
        _die(f"issuer {issuer} does not advertise a device flow")

    def form(url, fields):
        r = urllib.request.Request(
            url, data=urllib.parse.urlencode(fields).encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"})
        try:
            with urllib.request.urlopen(r, timeout=15) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            return json.loads(e.read() or "{}")

    dev = form(ep, {"client_id": client_id, "scope": "openid"})
    if "device_code" not in dev:
        _die(f"device flow rejected: {dev.get('error_description') or dev}")
    print(f"\n  Go to: {dev.get('verification_uri_complete') or dev['verification_uri']}")
    print(f"  Code:  {dev.get('user_code', '')}\n")
    interval = dev.get("interval", 5)
    deadline = time.time() + dev.get("expires_in", 600)
    while time.time() < deadline:
        time.sleep(interval)
        t = form(tok_ep, {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": dev["device_code"],
            "client_id": client_id,
        })
        if t.get("access_token"):
            return t["access_token"]
        if t.get("error") == "authorization_pending":
            continue
        if t.get("error") == "slow_down":
            interval += 5
            continue
        _die(f"device flow failed: {t.get('error')}")
    _die("device flow timed out")


def cmd_logout(_args):
    path = os.path.join(_config_dir(), "session.json")
    try:
        os.remove(path)
    except OSError:
        pass
    print("logged out")


def _fetch_revision() -> dict:
    return _req("GET", "/governance/revision")


def cmd_status(_args):
    _gate_url_or_die()
    h = _req("GET", "/health")
    if h.get("_status"):
        _die(f"gate unreachable ({h.get('error')})", EXIT_UNREACHABLE)
    rev = _fetch_revision()
    applied = _load("state.json")
    print(f"gate:        {h.get('status')} (v{h.get('version')}, "
          f"jwt={h.get('jwt_mode')}, partition={h.get('partition_policy')})")
    print(f"quorum:      {'enabled' if h.get('quorum_enabled') else 'disabled'} "
          f"({h.get('quorum_peers', 0)} peers, size {h.get('quorum_size')})")
    print(f"revision:    {rev.get('revision', '?')[:16]}… "
          f"({rev.get('active_policies')} policies, {rev.get('revocations')} revocations)")
    ap = applied.get("applied_revision")
    if ap:
        match = "MATCH" if ap == rev.get("revision") else "DRIFTED"
        print(f"applied:     {ap[:16]}…  [{match}]")
    else:
        print("applied:     (none — run `dgv apply`)")
    print(f"identity:    {_agent_id()}"
          f"{' (JWT)' if _token() else ' (no token)'}")


def cmd_apply(_args):
    """Fetch the desired governance revision and record it as applied,
    without launching anything. Idempotent — safe to run on a schedule
    (cron, CI step, container entrypoint) ahead of any `dgv launch`."""
    _gate_url_or_die()
    rev = _fetch_revision()
    if rev.get("_status"):
        _die(f"gate unreachable ({rev.get('error')})", EXIT_UNREACHABLE)
    _save("state.json", {
        "applied_revision": rev["revision"],
        "applied_unix_ms": int(time.time() * 1000),
        "active_policies": rev.get("active_policies"),
        "revocations": rev.get("revocations"),
    })
    print(f"applied {rev['revision'][:16]}…  "
          f"({rev.get('active_policies')} policies, {rev.get('revocations')} revocations)")


def cmd_verify(_args):
    """Exit non-zero on drift, an unreachable gate, or missing auth when the
    gate requires it. Meant for a pre-flight check in scripts/CI: `dgv verify
    && dgv launch ...`. Prints nothing on success beyond a one-line OK."""
    _gate_url_or_die()
    wk = _req("GET", "/.well-known/dgv")
    if wk.get("_status"):
        _die(f"unreachable ({wk.get('error')})", EXIT_UNREACHABLE)

    jwt_mode = wk.get("auth", {}).get("jwt_mode", "disabled")
    if jwt_mode != "disabled" and not _token():
        _die("gate requires auth but no token is set — run `dgv login`", EXIT_AUTH)
    tok = _token()
    if tok:
        exp = _jwt_claim(tok, "exp")
        if exp and exp * 1000 < int(time.time() * 1000):
            _die("token expired — run `dgv login`", EXIT_AUTH)

    rev = _fetch_revision()
    if rev.get("_status"):
        _die(f"unreachable ({rev.get('error')})", EXIT_UNREACHABLE)
    applied = _load("state.json").get("applied_revision")
    if applied != rev.get("revision"):
        print(f"dgv: drift — applied {str(applied)[:16]}… != desired "
              f"{rev['revision'][:16]}… (run `dgv apply`)", file=sys.stderr)
        sys.exit(EXIT_DRIFT)
    print("ok")


def _sha256_file(path: str) -> "tuple[str, int]":
    h = hashlib.sha256()
    size = 0
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
            size += len(chunk)
    return h.hexdigest(), size


MAX_INLINE_EVIDENCE_BYTES = 262_144  # matches the gate's inline-artifact cap


def cmd_evidence(args):
    if not args:
        _die("usage: dgv evidence push|get|list ...")
    sub, rest = args[0], args[1:]
    if sub == "push":
        _evidence_push(rest)
    elif sub == "get":
        _evidence_get(rest)
    elif sub == "list":
        _evidence_list(rest)
    else:
        _die(f"unknown evidence subcommand: {sub}")


def _evidence_push(args):
    if not args:
        _die("usage: dgv evidence push <file> [--ref URI] [--meta JSON]")
    path = args[0]
    ref = args[args.index("--ref") + 1] if "--ref" in args else None
    meta = json.loads(args[args.index("--meta") + 1]) if "--meta" in args else None

    digest, size = _sha256_file(path)
    body = {"sha256": digest, "size_bytes": size, "registered_by": _agent_id()}
    if meta is not None:
        body["metadata"] = meta
    if ref:
        body["content_ref"] = ref
    elif size <= MAX_INLINE_EVIDENCE_BYTES:
        import base64
        with open(path, "rb") as f:
            body["content_b64"] = base64.b64encode(f.read()).decode()
    else:
        _die(f"{path} is {size} bytes (> {MAX_INLINE_EVIDENCE_BYTES}) — pass --ref "
             f"with a content-addressed URI (s3://…, file://…) instead of inlining")

    resp = _req("POST", "/evidence/artifacts", body)
    if resp.get("_status"):
        _die(f"push failed: {resp.get('error')}")
    print(f"pushed {resp['artifact_id']}  sha256={digest[:16]}…  "
          f"verified={resp.get('verified')}  {size} bytes")


def _evidence_get(args):
    if not args:
        _die("usage: dgv evidence get <id> [-o out]")
    artifact_id = args[0]
    out = args[args.index("-o") + 1] if "-o" in args else None

    resp = _req("GET", f"/evidence/artifacts/{urllib.parse.quote(artifact_id, safe='')}")
    if resp.get("_status"):
        _die(f"get failed: {resp.get('error')}")

    if out:
        content_b64 = resp.get("content_b64")
        if not content_b64:
            _die(f"{artifact_id} has no inline content (content_ref={resp.get('content_ref')}) "
                 f"— fetch it from that ref directly")
        import base64
        raw = base64.b64decode(content_b64)
        actual = hashlib.sha256(raw).hexdigest()
        if actual != resp["sha256"]:
            _die(f"hash mismatch on download: expected {resp['sha256']}, got {actual}")
        with open(out, "wb") as f:
            f.write(raw)
        print(f"wrote {out}  ({len(raw)} bytes, sha256 verified)")
    else:
        printable = {k: v for k, v in resp.items() if k != "content_b64"}
        print(json.dumps(printable, indent=2))


def _evidence_list(_args):
    resp = _req("GET", "/evidence/artifacts")
    if resp.get("_status"):
        _die(f"list failed: {resp.get('error')}")
    for a in resp.get("artifacts", []):
        print(f"{a['artifact_id']:<24} sha256={a['sha256'][:12]}…  "
              f"{a.get('size_bytes', 0):>8} B  verified={a.get('verified')}  "
              f"by={a.get('registered_by')}")


def cmd_shim_install(args):
    """Write PATH shims for the given agent command names, each execing
    `dgv launch <name> "$@"` so invoking the native command name transparently
    routes through governance. Refuses to clobber a file it didn't create."""
    if not args:
        _die("usage: dgv shim install <names...>")
    shim_dir = os.path.join(_config_dir(), "shims")
    os.makedirs(shim_dir, exist_ok=True)
    dgv_path = os.path.abspath(sys.argv[0])

    for name in args:
        shim_path = os.path.join(shim_dir, name)
        marker = "# dgv-managed-shim\n"
        if os.path.exists(shim_path):
            with open(shim_path) as f:
                first_lines = f.read(200)
            if marker not in first_lines:
                print(f"dgv: skipping {shim_path} — exists and is not a dgv shim", file=sys.stderr)
                continue
        script = (
            "#!/bin/sh\n"
            f"{marker}"
            f'exec "{sys.executable}" "{dgv_path}" launch {name} "$@"\n'
        )
        with open(shim_path, "w") as f:
            f.write(script)
        os.chmod(shim_path, os.stat(shim_path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        print(f"installed {shim_path}")

    if shim_dir not in os.environ.get("PATH", "").split(os.pathsep):
        print(f"\nadd this to your shell profile so shims take priority:\n"
              f'  export PATH="{shim_dir}:$PATH"')


def cmd_launch(args):
    """Governed launch: T0 authorize -> run -> T1 receipt.

    Exits with the wrapped command's own exit code on success, so scripts
    and shells treat `dgv launch <cmd>` exactly like running <cmd> directly.
    Denies exit EXIT_DENY without running the command at all.
    """
    if not args:
        _die("usage: dgv launch <cmd...>")
    _gate_url_or_die()

    workflow = f"launch:{args[0]}"
    justification = f"{LAUNCHER_VERSION} governed launch of '{' '.join(args)}'"
    params = {"cmd": args}

    t0 = _req("POST", "/govern", {
        "request_id": f"req-{_agent_id()}-{workflow}-{int(time.time() * 1000)}",
        "agent_id": _agent_id(),
        "workflow": workflow,
        "tool": GOVERNED_TOOL,
        "action": GOVERNED_ACTION,
        "params": params,
        "justification": justification,
        "risk_level": "1000",
        "identity": {},
    })
    if t0.get("_status"):
        _die(f"gate unreachable at authorize step ({t0.get('error')})", EXIT_UNREACHABLE)

    decision = t0.get("decision", {})
    state = decision.get("gate_state")
    if state != "ALLOW":
        reasons = ", ".join(decision.get("reason_codes", [])) or "no reason given"
        print(f"dgv: launch denied ({state}): {reasons}", file=sys.stderr)
        sys.exit(EXIT_DENY)

    token_id = (decision.get("auth_token") or {}).get("token_id")
    run_id = decision.get("run_id")

    # Run the wrapped command with inherited stdio, forwarding SIGINT/SIGTERM
    # so the child sees the same signals the launcher does.
    proc = subprocess.Popen(args)

    def _forward(sig, _frame):
        try:
            proc.send_signal(sig)
        except ProcessLookupError:
            pass

    old_int = signal.signal(signal.SIGINT, _forward)
    old_term = signal.signal(signal.SIGTERM, _forward)
    try:
        exit_code = proc.wait()
    finally:
        signal.signal(signal.SIGINT, old_int)
        signal.signal(signal.SIGTERM, old_term)

    if token_id:
        t1 = _req("POST", "/execute", {
            "token_id": token_id,
            "executor_id": _agent_id(),
            "tool": GOVERNED_TOOL,
            "action": GOVERNED_ACTION,
            "params": {**params, "exit_code": exit_code},
        })
        if t1.get("_status"):
            print(f"dgv: warning — T1 receipt failed ({t1.get('error')}); "
                  f"run_id={run_id} completed with exit {exit_code} but is unreceipted",
                  file=sys.stderr)

    sys.exit(exit_code)


# ── dispatch ─────────────────────────────────────────────────────────────────

COMMANDS = {
    "setup": cmd_setup,
    "login": cmd_login,
    "logout": cmd_logout,
    "status": cmd_status,
    "apply": cmd_apply,
    "verify": cmd_verify,
    "launch": cmd_launch,
    "evidence": cmd_evidence,
}


def main():
    argv = sys.argv[1:]
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        sys.exit(EXIT_OK)

    cmd = argv[0]
    if cmd == "shim":
        if len(argv) < 2 or argv[1] != "install":
            _die("usage: dgv shim install <names...>")
        cmd_shim_install(argv[2:])
        return

    fn = COMMANDS.get(cmd)
    if fn is None:
        _die(f"unknown command: {cmd} (see `dgv --help`)")
    fn(argv[1:])


if __name__ == "__main__":
    main()
