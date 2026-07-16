"""Storage. Deliberately minimal — this is the whole privacy budget of the
hub: a pubkey, an ID derived from it, a hashed auth token, the
current server record, and (since billing) a subscription row. No names, no
emails, no contact graph, no messages.

Billing expands the budget deliberately: after a code is redeemed the hub
links zeon_id ↔ stripe_customer_id (Stripe knows who paid; we know which
Zeon ID they paid for). The activation code itself is stored in plaintext
only until it's claimed — the success page must be able to re-display it —
then nulled, leaving just the hash.
"""

import hashlib
import json
import sqlite3
import threading
import uuid
from datetime import datetime, timezone

from .words import candidate_handles


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
                handle     TEXT NOT NULL UNIQUE,   -- zn-word-word-word
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
                host_agent_token TEXT,             -- dedicated VMs: agent admin secret
                tls_fp       TEXT,                 -- relay cert fingerprint (observed)
                tls_sig      TEXT,                 -- owner's signature over it
                meta         TEXT NOT NULL DEFAULT '{}',
                error        TEXT,
                created_at   TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS subscriptions (
                id                     TEXT PRIMARY KEY,  -- uuid4
                source                 TEXT NOT NULL,     -- stripe | comp
                plan                   TEXT NOT NULL,     -- private | sovereign
                status                 TEXT NOT NULL,     -- active | grace | lapsed
                stripe_customer_id     TEXT,
                stripe_subscription_id TEXT UNIQUE,
                checkout_session_id    TEXT UNIQUE,
                code_hash              TEXT NOT NULL UNIQUE,
                code_plain             TEXT,              -- NULLed on redeem
                zeon_id                TEXT REFERENCES users(zeon_id),
                current_period_end     TEXT,
                grace_since            TEXT,
                lapsed_at              TEXT,
                note                   TEXT,              -- comp grants
                created_at             TEXT NOT NULL,
                updated_at             TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_subscriptions_zeon
                ON subscriptions(zeon_id);
            CREATE TABLE IF NOT EXISTS stripe_events (    -- webhook idempotency
                event_id    TEXT PRIMARY KEY,
                type        TEXT NOT NULL,
                received_at TEXT NOT NULL
            );
            """
        )
        self._db.commit()

    def _free_handle(self, zeon_id: str) -> str:
        for handle in candidate_handles(zeon_id):
            taken = self._db.execute(
                "SELECT 1 FROM users WHERE handle = ?", (handle,)
            ).fetchone()
            if not taken:
                return handle
        raise RuntimeError("unreachable")  # generator is infinite

    # -- users ---------------------------------------------------------------

    def create_user(self, zeon_id: str, pubkey_b64: str, token: str) -> str | None:
        """Returns the assigned handle, or None if the key is already registered."""
        with self._lock:
            handle = self._free_handle(zeon_id)
            try:
                self._db.execute(
                    "INSERT INTO users (zeon_id, pubkey, token_hash, handle, created_at)"
                    " VALUES (?, ?, ?, ?, ?)",
                    (zeon_id, pubkey_b64, hash_token(token), handle, _now()),
                )
                self._db.commit()
                return handle
            except sqlite3.IntegrityError:
                return None

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

    def user_by_handle(self, handle: str) -> dict | None:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM users WHERE handle = ?", (handle,)
            ).fetchone()
        return dict(row) if row else None

    # -- servers -------------------------------------------------------------

    def create_server(self, zeon_id: str, provider: str, machine: dict, server_token: str,
                      host_agent_token: str | None = None) -> bool:
        """Atomically claim the one-server-per-user slot. False if occupied."""
        with self._lock:
            try:
                self._db.execute(
                    "INSERT INTO servers (zeon_id, provider, status, machine, server_token,"
                    " host_agent_token, created_at)"
                    " VALUES (?, ?, 'provisioning', ?, ?, ?, ?)",
                    (zeon_id, provider, json.dumps(machine), server_token,
                     host_agent_token, _now()),
                )
                self._db.commit()
                return True
            except sqlite3.IntegrityError:
                return False

    def create_external_server(self, zeon_id: str, address: str, tls_fp: str | None) -> bool:
        """User provisioned their own relay; we only list its address.
        No server_token stored — it never leaves the user's device."""
        with self._lock:
            try:
                self._db.execute(
                    "INSERT INTO servers (zeon_id, provider, status, machine, address, tls_fp, created_at)"
                    " VALUES (?, 'external', 'running', '{}', ?, ?, ?)",
                    (zeon_id, address, tls_fp, _now()),
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

    def mark_running(self, zeon_id: str, resource_id: str, address: str, meta: dict,
                     tls_fp: str | None) -> None:
        with self._lock:
            self._db.execute(
                "UPDATE servers SET status='running', resource_id=?, address=?, meta=?,"
                " tls_fp=?, tls_sig=NULL, error=NULL"  # new box, new cert — old sig is void
                " WHERE zeon_id=?",
                (resource_id, address, json.dumps(meta), tls_fp, zeon_id),
            )
            self._db.commit()

    def set_tls_sig(self, zeon_id: str, tls_sig: str) -> None:
        with self._lock:
            self._db.execute(
                "UPDATE servers SET tls_sig=? WHERE zeon_id=?", (tls_sig, zeon_id)
            )
            self._db.commit()

    def mark_error(self, zeon_id: str, error: str) -> None:
        with self._lock:
            self._db.execute(
                "UPDATE servers SET status='error', error=? WHERE zeon_id=?",
                (error[:1000], zeon_id),
            )
            self._db.commit()

    def reapable_servers(self, providers: tuple[str, ...], lapsed_before: str) -> list[dict]:
        """Servers on paid providers whose owner has no live subscription and
        whose most recent one lapsed before the cutoff. Owners with no
        subscription rows at all are left alone — ambiguous state (pre-billing
        data, manual grants) is not a kill signal."""
        if not providers:
            return []
        marks = ",".join("?" * len(providers))
        with self._lock:
            rows = self._db.execute(
                f"SELECT s.* FROM servers s"
                f" WHERE s.provider IN ({marks})"
                "  AND NOT EXISTS (SELECT 1 FROM subscriptions"
                "    WHERE zeon_id = s.zeon_id AND status IN ('active', 'grace'))"
                "  AND (SELECT MAX(lapsed_at) FROM subscriptions"
                "    WHERE zeon_id = s.zeon_id AND status = 'lapsed') <= ?",
                (*providers, lapsed_before),
            ).fetchall()
        servers = []
        for row in rows:
            server = dict(row)
            server["machine"] = json.loads(server["machine"])
            server["meta"] = json.loads(server["meta"])
            servers.append(server)
        return servers

    def delete_server(self, zeon_id: str) -> None:
        with self._lock:
            self._db.execute("DELETE FROM servers WHERE zeon_id = ?", (zeon_id,))
            self._db.commit()

    # -- billing ---------------------------------------------------------------

    def record_event(self, event_id: str, event_type: str) -> bool:
        """Webhook idempotency: True if this is the first delivery."""
        with self._lock:
            cur = self._db.execute(
                "INSERT OR IGNORE INTO stripe_events (event_id, type, received_at)"
                " VALUES (?, ?, ?)",
                (event_id, event_type, _now()),
            )
            self._db.commit()
            return cur.rowcount == 1

    def create_subscription(
        self,
        plan: str,
        source: str,
        code_hash: str,
        code_plain: str,
        *,
        stripe_customer_id: str | None = None,
        stripe_subscription_id: str | None = None,
        checkout_session_id: str | None = None,
        note: str | None = None,
    ) -> dict:
        """Raises sqlite3.IntegrityError on a duplicate code hash, checkout
        session, or Stripe subscription id — callers retry or bail."""
        now = _now()
        row_id = str(uuid.uuid4())
        with self._lock:
            self._db.execute(
                "INSERT INTO subscriptions (id, source, plan, status,"
                " stripe_customer_id, stripe_subscription_id, checkout_session_id,"
                " code_hash, code_plain, note, created_at, updated_at)"
                " VALUES (?, ?, ?, 'active', ?, ?, ?, ?, ?, ?, ?, ?)",
                (row_id, source, plan, stripe_customer_id, stripe_subscription_id,
                 checkout_session_id, code_hash, code_plain, note, now, now),
            )
            self._db.commit()
            row = self._db.execute(
                "SELECT * FROM subscriptions WHERE id = ?", (row_id,)
            ).fetchone()
        return dict(row)

    def subscription_by_session(self, session_id: str) -> dict | None:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM subscriptions WHERE checkout_session_id = ?",
                (session_id,),
            ).fetchone()
        return dict(row) if row else None

    def subscription_by_stripe_sub(self, sub_id: str) -> dict | None:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM subscriptions WHERE stripe_subscription_id = ?",
                (sub_id,),
            ).fetchone()
        return dict(row) if row else None

    def claim_subscription(self, code_hash: str, zeon_id: str) -> dict | None:
        """Atomically bind an unclaimed, non-lapsed code to an account and
        drop the plaintext code. None if the code is unknown, spent, or dead."""
        with self._lock:
            cur = self._db.execute(
                "UPDATE subscriptions SET zeon_id = ?, code_plain = NULL,"
                " updated_at = ?"
                " WHERE code_hash = ? AND zeon_id IS NULL AND status != 'lapsed'",
                (zeon_id, _now(), code_hash),
            )
            self._db.commit()
            if cur.rowcount != 1:
                return None
            row = self._db.execute(
                "SELECT * FROM subscriptions WHERE code_hash = ?", (code_hash,)
            ).fetchone()
        return dict(row) if row else None

    def entitlement_for(self, zeon_id: str) -> dict | None:
        """The account's best live subscription (sovereign beats private).
        `grace` still counts — payment trouble shouldn't cut service instantly."""
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM subscriptions"
                " WHERE zeon_id = ? AND status IN ('active', 'grace')"
                " ORDER BY CASE plan WHEN 'sovereign' THEN 0 ELSE 1 END, created_at"
                " LIMIT 1",
                (zeon_id,),
            ).fetchone()
        return dict(row) if row else None

    def set_subscription_status(
        self,
        stripe_subscription_id: str,
        status: str,
        *,
        current_period_end: str | None = None,
    ) -> bool:
        """Lifecycle transitions, guarded so out-of-order webhooks can't
        resurrect a lapsed subscription or re-grace an already-lapsed one."""
        now = _now()
        with self._lock:
            if status == "active":
                cur = self._db.execute(
                    "UPDATE subscriptions SET status = 'active', grace_since = NULL,"
                    " current_period_end = COALESCE(?, current_period_end),"
                    " updated_at = ?"
                    " WHERE stripe_subscription_id = ? AND status != 'lapsed'",
                    (current_period_end, now, stripe_subscription_id),
                )
            elif status == "grace":
                cur = self._db.execute(
                    "UPDATE subscriptions SET status = 'grace', grace_since = ?,"
                    " updated_at = ?"
                    " WHERE stripe_subscription_id = ? AND status = 'active'",
                    (now, now, stripe_subscription_id),
                )
            elif status == "lapsed":
                cur = self._db.execute(
                    "UPDATE subscriptions SET status = 'lapsed', lapsed_at = ?,"
                    " updated_at = ?"
                    " WHERE stripe_subscription_id = ? AND status != 'lapsed'",
                    (now, now, stripe_subscription_id),
                )
            else:
                raise ValueError(f"unknown subscription status: {status}")
            self._db.commit()
            return cur.rowcount == 1
