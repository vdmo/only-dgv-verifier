import json
import os
import secrets
import sqlite3
import time
from contextlib import closing, contextmanager
from pathlib import Path

from objective_contract import canonical_bytes, digest


class StoreUnavailable(RuntimeError):
    pass


def _identifier(value):
    return type(value) is str and 0 < len(value) <= 256 and value.isascii() and value.isprintable()


def _hex(value, length=64):
    return type(value) is str and len(value) == length and all(c in "0123456789abcdef" for c in value)


def _denial(authority, token, now_ms, action_id, payload_hash, audience, action_exists):
    if token is None:
        return "UNKNOWN_TOKEN"
    if authority is None or authority["revoked"]:
        return "AUTHORITY_REVOKED"
    if token["version"] != authority["version"]:
        return "TOKEN_VERSION_STALE"
    if token["consumed_seq"] is not None:
        return "TOKEN_USED"
    if now_ms >= token["expires_at_ms"]:
        return "TOKEN_EXPIRED"
    if (token["action_id"], token["payload_hash"], token["audience"]) != (action_id, payload_hash, audience):
        return "TOKEN_BINDING_MISMATCH"
    if action_exists:
        return "ACTION_ALREADY_COMMITTED"
    return None


class AuthorityStore:
    def __init__(self, path, store_id, timeout_ms=100):
        if not _hex(store_id, 32) or type(timeout_ms) is not int or not 1 <= timeout_ms <= 10000:
            raise ValueError("Invalid store identity or timeout")
        self.path = Path(path).resolve()
        self.store_id = store_id
        self.timeout_ms = timeout_ms

    @classmethod
    def create(cls, path):
        path = Path(path).resolve()
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(descriptor)
        store_id = secrets.token_hex(16)
        with closing(sqlite3.connect(path)) as connection:
            connection.executescript("""
                PRAGMA journal_mode=DELETE;
                PRAGMA synchronous=FULL;
                CREATE TABLE metadata (store_id TEXT NOT NULL, last_time_ms INTEGER NOT NULL);
                CREATE TABLE authorities (actor_id TEXT PRIMARY KEY, version INTEGER NOT NULL, revoked INTEGER NOT NULL CHECK (revoked IN (0, 1)));
                CREATE TABLE tokens (token_hash TEXT PRIMARY KEY, actor_id TEXT NOT NULL, version INTEGER NOT NULL, action_id TEXT NOT NULL, payload_hash TEXT NOT NULL, audience TEXT NOT NULL, expires_at_ms INTEGER NOT NULL, consumed_seq INTEGER);
                CREATE TABLE events (seq INTEGER PRIMARY KEY AUTOINCREMENT, body TEXT NOT NULL);
                CREATE TABLE actions (action_id TEXT PRIMARY KEY, actor_id TEXT NOT NULL, version INTEGER NOT NULL, payload_hash TEXT NOT NULL, audience TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, event_seq INTEGER NOT NULL UNIQUE, payload TEXT NOT NULL);
            """)
            connection.execute("INSERT INTO metadata VALUES (?, 0)", (store_id,))
            connection.commit()
        return cls(path, store_id)

    def connect(self):
        connection = sqlite3.connect(self.path.as_uri() + "?mode=rw", uri=True, isolation_level=None, timeout=self.timeout_ms / 1000)
        connection.row_factory = sqlite3.Row
        try:
            metadata = connection.execute("SELECT store_id FROM metadata").fetchall()
            if len(metadata) != 1 or metadata[0]["store_id"] != self.store_id:
                raise StoreUnavailable("Authority store identity mismatch")
            connection.execute("PRAGMA synchronous=FULL")
            return connection
        except Exception:
            connection.close()
            raise

    @contextmanager
    def transaction(self):
        with closing(self.connect()) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                now_ms = time.time_ns() // 1000000
                last_time = connection.execute("SELECT last_time_ms FROM metadata").fetchone()[0]
                if now_ms < last_time:
                    raise StoreUnavailable("Authority store clock moved backwards")
                connection.execute("UPDATE metadata SET last_time_ms = ?", (now_ms,))
                yield connection, now_ms
                connection.commit()
            except Exception:
                connection.rollback()
                raise

    @staticmethod
    def _authority(connection, actor_id):
        row = connection.execute("SELECT * FROM authorities WHERE actor_id = ?", (actor_id,)).fetchone()
        return {**dict(row), "revoked": bool(row["revoked"])} if row else None

    @staticmethod
    def _event(connection, event):
        return connection.execute("INSERT INTO events (body) VALUES (?)", (canonical_bytes(event).decode("ascii"),)).lastrowid

    def observe(self, actor_id):
        with closing(self.connect()) as connection:
            return self._authority(connection, actor_id)

    def set_authority(self, actor_id, *, revoked):
        if not _identifier(actor_id) or type(revoked) is not bool:
            raise ValueError("Invalid authority update")
        with self.transaction() as (connection, now_ms):
            previous = self._authority(connection, actor_id)
            if previous is None and revoked:
                raise LookupError("Cannot revoke an unknown actor")
            version = previous["version"] + 1 if previous else 1
            connection.execute("INSERT INTO authorities VALUES (?, ?, ?) ON CONFLICT(actor_id) DO UPDATE SET version = excluded.version, revoked = excluded.revoked", (actor_id, version, int(revoked)))
            seq = self._event(connection, {"kind": "REVOKE" if revoked else "GRANT", "actor_id": actor_id, "version": version, "observed_at_ms": now_ms})
        return {"event_seq": seq, "actor_id": actor_id, "version": version, "revoked": revoked}

    def issue_token(self, actor_id, action_id, payload, audience, *, ttl_ms=60000):
        if not all(_identifier(value) for value in (actor_id, action_id, audience)) or type(payload) is not dict or type(ttl_ms) is not int or not 1 <= ttl_ms <= 3600000:
            raise ValueError("Invalid token request")
        payload_hash = digest(payload)
        token = secrets.token_hex(32)
        token_hash = digest(token)
        with self.transaction() as (connection, now_ms):
            authority = self._authority(connection, actor_id)
            if authority is None or authority["revoked"]:
                raise PermissionError("Actor has no active authority")
            record = {"token_hash": token_hash, "actor_id": actor_id, "version": authority["version"], "action_id": action_id, "payload_hash": payload_hash, "audience": audience, "expires_at_ms": now_ms + ttl_ms, "consumed_seq": None}
            connection.execute("INSERT INTO tokens VALUES (:token_hash, :actor_id, :version, :action_id, :payload_hash, :audience, :expires_at_ms, :consumed_seq)", record)
            self._event(connection, {"kind": "TOKEN_ISSUED", "observed_at_ms": now_ms, **record})
        return token

    def execute(self, token, action_id, payload, audience, *, gate_id):
        failure = {"decision": "DENY", "execution_confirmed": False, "event_seq": None}
        if not _hex(token) or not all(_identifier(value) for value in (action_id, audience, gate_id)) or type(payload) is not dict:
            return {**failure, "reason": "INVALID_REQUEST"}
        try:
            payload_bytes = canonical_bytes(payload)
            payload_hash = digest(payload)
        except (ValueError, RecursionError):
            return {**failure, "reason": "INVALID_REQUEST"}
        try:
            with self.transaction() as (connection, now_ms):
                token_hash = digest(token)
                row = connection.execute("SELECT * FROM tokens WHERE token_hash = ?", (token_hash,)).fetchone()
                token_record = dict(row) if row else None
                actor_id = token_record["actor_id"] if token_record else None
                authority = self._authority(connection, actor_id)
                action_exists = connection.execute("SELECT 1 FROM actions WHERE action_id = ?", (action_id,)).fetchone() is not None
                reason = _denial(authority, token_record, now_ms, action_id, payload_hash, audience, action_exists)
                event = {"kind": "EXECUTE", "actor_id": actor_id, "version": authority["version"] if authority else None, "token_hash": token_hash, "action_id": action_id, "payload_hash": payload_hash, "audience": audience, "gate_id": gate_id, "observed_at_ms": now_ms, "decision": "DENY" if reason else "ALLOW", "reason": reason or "AUTHORIZED_AT_WRITE"}
                seq = self._event(connection, event)
                if reason is None:
                    connection.execute("UPDATE tokens SET consumed_seq = ? WHERE token_hash = ?", (seq, token_hash))
                    connection.execute("INSERT INTO actions VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (action_id, actor_id, authority["version"], payload_hash, audience, token_hash, seq, payload_bytes.decode("ascii")))
            return {"decision": event["decision"], "reason": event["reason"], "execution_confirmed": reason is None, "event_seq": seq, "authority_version": event["version"]}
        except (sqlite3.Error, StoreUnavailable, OSError):
            return {**failure, "reason": "STORE_UNAVAILABLE", "commit_status": "UNCONFIRMED"}

    def snapshot(self):
        with closing(self.connect()) as connection:
            connection.execute("BEGIN")
            result = {
                "store_id": self.store_id,
                "authorities": [{**dict(row), "revoked": bool(row["revoked"])} for row in connection.execute("SELECT * FROM authorities ORDER BY actor_id")],
                "tokens": [dict(row) for row in connection.execute("SELECT * FROM tokens ORDER BY token_hash")],
                "actions": [{**dict(row), "payload": json.loads(row["payload"])} for row in connection.execute("SELECT * FROM actions ORDER BY action_id")],
                "events": [{"seq": row["seq"], **json.loads(row["body"])} for row in connection.execute("SELECT * FROM events ORDER BY seq")],
            }
            connection.rollback()
        return result


def audit_history(snapshot):
    def require(condition):
        if not condition:
            raise ValueError("History or destination state is inconsistent")

    try:
        canonical_bytes(snapshot)
        require(set(snapshot) == {"store_id", "authorities", "tokens", "actions", "events"})
        require(_hex(snapshot["store_id"], 32))
        authorities, tokens, actions = {}, {}, {}
        last_time = 0
        for seq, event in enumerate(snapshot["events"], 1):
            require(type(event["seq"]) is int and event["seq"] == seq and type(event["observed_at_ms"]) is int and event["observed_at_ms"] >= last_time)
            require(event["version"] is None or (type(event["version"]) is int and event["version"] > 0))
            last_time = event["observed_at_ms"]
            kind, actor_id = event["kind"], event["actor_id"]
            if kind in ("GRANT", "REVOKE"):
                require(set(event) == {"seq", "kind", "actor_id", "version", "observed_at_ms"})
                require(_identifier(actor_id))
                previous = authorities.get(actor_id)
                require(event["version"] == (previous["version"] + 1 if previous else 1))
                require(kind != "REVOKE" or previous is not None)
                authorities[actor_id] = {"actor_id": actor_id, "version": event["version"], "revoked": kind == "REVOKE"}
            elif kind == "TOKEN_ISSUED":
                require(set(event) == {"seq", "kind", "observed_at_ms", "token_hash", "actor_id", "version", "action_id", "payload_hash", "audience", "expires_at_ms", "consumed_seq"})
                authority = authorities.get(actor_id)
                require(authority is not None and not authority["revoked"] and authority["version"] == event["version"])
                require(event["token_hash"] not in tokens and _hex(event["token_hash"]) and _hex(event["payload_hash"]))
                require(event["consumed_seq"] is None and type(event["expires_at_ms"]) is int and 1 <= event["expires_at_ms"] - event["observed_at_ms"] <= 3600000)
                require(_identifier(event["action_id"]) and _identifier(event["audience"]))
                tokens[event["token_hash"]] = {key: value for key, value in event.items() if key not in ("seq", "kind", "observed_at_ms")}
            elif kind == "EXECUTE":
                require(set(event) == {"seq", "kind", "actor_id", "version", "token_hash", "action_id", "payload_hash", "audience", "gate_id", "observed_at_ms", "decision", "reason"})
                require(_hex(event["token_hash"]) and _hex(event["payload_hash"]) and all(_identifier(event[key]) for key in ("action_id", "audience", "gate_id")))
                token = tokens.get(event["token_hash"])
                require(actor_id == (token["actor_id"] if token else None))
                authority = authorities.get(actor_id)
                require(event["version"] == (authority["version"] if authority else None))
                reason = _denial(authority, token, event["observed_at_ms"], event["action_id"], event["payload_hash"], event["audience"], event["action_id"] in actions)
                require(event["decision"] == ("DENY" if reason else "ALLOW") and event["reason"] == (reason or "AUTHORIZED_AT_WRITE"))
                if reason is None:
                    token["consumed_seq"] = seq
                    actions[event["action_id"]] = {key: event[key] for key in ("action_id", "actor_id", "version", "payload_hash", "audience", "token_hash")}
                    actions[event["action_id"]]["event_seq"] = seq
            else:
                raise ValueError("Unknown history event")
        require(canonical_bytes(snapshot["authorities"]) == canonical_bytes(sorted(authorities.values(), key=lambda row: row["actor_id"])))
        require(canonical_bytes(snapshot["tokens"]) == canonical_bytes(sorted(tokens.values(), key=lambda row: row["token_hash"])))
        actual_actions = []
        for row in snapshot["actions"]:
            require(type(row["payload"]) is dict and digest(row["payload"]) == row["payload_hash"])
            actual_actions.append({key: value for key, value in row.items() if key != "payload"})
        require(actual_actions == sorted(actions.values(), key=lambda row: row["action_id"]))
        return {"valid": True, "events_checked": len(snapshot["events"]), "writes_checked": len(actions), "violations": []}
    except (KeyError, TypeError, ValueError, RecursionError):
        return {"valid": False, "violations": ["HISTORY_OR_STATE_MISMATCH"]}
