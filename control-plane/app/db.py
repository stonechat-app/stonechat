"""Storage. Deliberately minimal — this is the whole privacy budget of the
control plane: a pubkey, an ID derived from it, a hashed auth token, and the
current server record. No names, no emails, no contact graph, no messages.
"""

import hashlib
import json
import sqlite3
import threading
from datetime import datetime, timezone


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Store:
    def __init__(self, path: str):
        self._lock = threading.Lock()
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                zeon_id    TEXT PRIMARY KEY,
                pubkey     TEXT NOT NULL,          -- base64
                token_hash TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS servers (
                zeon_id      TEXT PRIMARY KEY REFERENCES users(zeon_id),
                provider     TEXT NOT NULL,
                status       TEXT NOT NULL,        -- provisioning | running | error
                machine      TEXT NOT NULL,        -- MachineSpec as JSON
                resource_id  TEXT,
                address      TEXT,
                server_token TEXT,
                meta         TEXT NOT NULL DEFAULT '{}',
                error        TEXT,
                created_at   TEXT NOT NULL
            );
            """
        )
        self._db.commit()

    # -- users ---------------------------------------------------------------

    def create_user(self, zeon_id: str, pubkey_b64: str, token: str) -> bool:
        with self._lock:
            try:
                self._db.execute(
                    "INSERT INTO users (zeon_id, pubkey, token_hash, created_at) VALUES (?, ?, ?, ?)",
                    (zeon_id, pubkey_b64, hash_token(token), _now()),
                )
                self._db.commit()
                return True
            except sqlite3.IntegrityError:
                return False

    def user_by_token(self, token: str) -> dict | None:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM users WHERE token_hash = ?", (hash_token(token),)
            ).fetchone()
        return dict(row) if row else None

    def user_by_id(self, zeon_id: str) -> dict | None:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM users WHERE zeon_id = ?", (zeon_id,)
            ).fetchone()
        return dict(row) if row else None

    # -- servers -------------------------------------------------------------

    def create_server(self, zeon_id: str, provider: str, machine: dict, server_token: str) -> bool:
        """Atomically claim the one-server-per-user slot. False if occupied."""
        with self._lock:
            try:
                self._db.execute(
                    "INSERT INTO servers (zeon_id, provider, status, machine, server_token, created_at)"
                    " VALUES (?, ?, 'provisioning', ?, ?, ?)",
                    (zeon_id, provider, json.dumps(machine), server_token, _now()),
                )
                self._db.commit()
                return True
            except sqlite3.IntegrityError:
                return False

    def server_for(self, zeon_id: str) -> dict | None:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM servers WHERE zeon_id = ?", (zeon_id,)
            ).fetchone()
        if not row:
            return None
        server = dict(row)
        server["machine"] = json.loads(server["machine"])
        server["meta"] = json.loads(server["meta"])
        return server

    def mark_running(self, zeon_id: str, resource_id: str, address: str, meta: dict) -> None:
        with self._lock:
            self._db.execute(
                "UPDATE servers SET status='running', resource_id=?, address=?, meta=?, error=NULL"
                " WHERE zeon_id=?",
                (resource_id, address, json.dumps(meta), zeon_id),
            )
            self._db.commit()

    def mark_error(self, zeon_id: str, error: str) -> None:
        with self._lock:
            self._db.execute(
                "UPDATE servers SET status='error', error=? WHERE zeon_id=?",
                (error[:1000], zeon_id),
            )
            self._db.commit()

    def delete_server(self, zeon_id: str) -> None:
        with self._lock:
            self._db.execute("DELETE FROM servers WHERE zeon_id = ?", (zeon_id,))
            self._db.commit()
