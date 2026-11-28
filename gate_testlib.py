"""Shared helpers so the gate tests run from any checkout, on Linux or Windows.

Environment:
  DGV_GATE_BIN           gate binary to test (default: native/target/release, then debug)
  DGV_TEST_DATABASE_URL  run the tests that support it on this Postgres database instead of a temporary SQLite file.
                         Use an EMPTY, throwaway database: the tests register agents and revoke them.
"""

import json
import os
import queue
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.abspath(__file__))
NATIVE = os.path.join(ROOT, "native")
EXE = ".exe" if os.name == "nt" else ""


def gate_bin():
    override = os.environ.get("DGV_GATE_BIN")
    if override:
        return override
    for profile in ("release", "debug"):
        path = os.path.join(NATIVE, "target", profile, "dgv-gate" + EXE)
        if os.path.isfile(path):
            return path
    return os.path.join(NATIVE, "target", "release", "dgv-gate" + EXE)  # reported as missing when started


def sqlite_url(path):
    return "sqlite://" + str(path).replace("\\", "/")


def db_env(sqlite_path):
    """Storage settings for a test gate: the shared Postgres URL if given, else this SQLite file."""
    url = os.environ.get("DGV_TEST_DATABASE_URL")
    if url:
        return {"DGV_STORAGE": "postgres", "DGV_DATABASE_URL": url}
    return {"DGV_STORAGE": "sqlite", "DGV_DATABASE_URL": sqlite_url(sqlite_path)}


class _StandInRelay(BaseHTTPRequestHandler):
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
        return self.server.queues.setdefault(self.path.rsplit("/", 1)[-1], queue.Queue())

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


class StandInRelay:
    """The relay routes the SDK uses, in memory on 127.0.0.1. NOT onlystate-relay.
    Behaves enough like a process handle (terminate, wait, poll) for the tests."""

    def __init__(self, port):
        self.server = ThreadingHTTPServer(("127.0.0.1", port), _StandInRelay)
        self.server.queues = {}
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def terminate(self):
        self.server.shutdown()
        self.server.server_close()

    kill = terminate

    def wait(self, timeout=None):
        return 0

    def poll(self):
        return None
