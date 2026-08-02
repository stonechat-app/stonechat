"""Storage. Deliberately minimal — this is the whole privacy budget of the
hub: a pubkey, an ID derived from it, a hashed auth token, the
current server record, and (since billing) a subscription row. No names, no
emails, no contact graph, no messages.

Billing expands the budget deliberately: after a code is redeemed the hub
links stonechat_id ↔ stripe_customer_id (Stripe knows who paid; we know which
Stonechat ID they paid for). The activation code itself is stored in plaintext
only until it's claimed — the success page must be able to re-display it —
then nulled, leaving just the hash.
"""

import hashlib
import json
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Store:
    """One sqlite connection per thread, WAL mode: reads run concurrently
    across the threadpool FastAPI dispatches sync handlers to; writers queue
    on busy_timeout. No global lock — statement-level atomicity (single
    UPDATE/INSERT claims) is what correctness rests on, same as before."""

    def __init__(self, path: str):
        self._path = path
        self._local = threading.local()
        self._db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                stonechat_id    TEXT PRIMARY KEY,
                pubkey     TEXT NOT NULL,          -- base64
                pq_pk      TEXT,                   -- base64 X-Wing identity key
                pq_sig     TEXT,                   -- Ed25519 sig over "stonechat-v1-pqpk"||pq_pk
                token_hash TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                banned_at  TEXT,                   -- abuse: no more provisioning
                ban_reason TEXT
            );
            CREATE TABLE IF NOT EXISTS servers (
                stonechat_id      TEXT PRIMARY KEY REFERENCES users(stonechat_id),
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
                stonechat_id                TEXT REFERENCES users(stonechat_id),
                current_period_end     TEXT,
                grace_since            TEXT,
                lapsed_at              TEXT,
                note                   TEXT,              -- comp grants
                created_at             TEXT NOT NULL,
                updated_at             TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_subscriptions_stonechat
                ON subscriptions(stonechat_id);
            CREATE TABLE IF NOT EXISTS stripe_events (    -- webhook idempotency
                event_id    TEXT PRIMARY KEY,
                type        TEXT NOT NULL,
                received_at TEXT NOT NULL
            );
            -- Append-only record of machines we destroyed for abuse. Separate
            -- from `servers` on purpose: `servers` holds at most one *live*
            -- machine per user (that PRIMARY KEY is the one-per-user claim), so
            -- a tombstone kept there would lock a wrongly-hit user out of
            -- re-provisioning. Here it can be preserved indefinitely — abuse
            -- cases carry evidence-preservation duties (ABUSE.md §5) and the
            -- second report from a provider is only easy to answer if the
            -- first one was written down.
            -- Link grants in flight (MULTIDEVICE.md "Linking a device").
            --
            -- The hub is the dead drop for one reason: a device being linked
            -- has no identity, no account and no idea which relay to poll —
            -- the hub URL is the only address it knows, because onboarding
            -- asks for it. The relay cannot serve this bootstrap for the same
            -- reason it cannot be found.
            --
            -- What is stored is opaque: sealed to an ephemeral key that
            -- exists only on the new device, carried there by the user
            -- pointing a camera at a screen. The hub cannot open it, and the
            -- key it is filed under is the hash of a secret that never
            -- touches the hub. Single-use and short-lived besides.
            CREATE TABLE IF NOT EXISTS link_grants (
                key        TEXT PRIMARY KEY,
                sealed     TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS server_tombstones (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                stonechat_id      TEXT NOT NULL,
                provider     TEXT NOT NULL,
                resource_id  TEXT,
                address      TEXT,
                meta         TEXT NOT NULL DEFAULT '{}',
                reason       TEXT NOT NULL,
                created_at   TEXT NOT NULL,        -- when the machine was made
                destroyed_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_tombstones_stonechat
                ON server_tombstones(stonechat_id);
            -- Abuse reports raised by users against other users (report.py).
            --
            -- This table is the largest deliberate expansion of the privacy
            -- budget in the file header, and it is worth naming precisely.
            -- A row records that `reporter_id` complained about
            -- `reported_id`: an edge in the contact graph the hub otherwise
            -- never holds. Storing a hash of the reporter instead would be
            -- theatre — the hub owns the `users` table, so any candidate ID
            -- is one cheap brute-force away. Retention is the real mitigation
            -- (STONECHAT_REPORT_RETENTION_DAYS, purged by the reaper), and the
            -- outcome of an actioned report outlives its row in
            -- `server_tombstones` and `users.ban_reason` anyway.
            --
            -- `evidence` is an opaque JSON document composed by the reporting
            -- client and stored verbatim: the hub never parses it and its
            -- bytes are covered by the report signature. NULL is the default
            -- and the common case — plaintext arrives only when the reporter
            -- explicitly attached it.
            CREATE TABLE IF NOT EXISTS reports (
                id          TEXT PRIMARY KEY,      -- uuid4, the reference number
                reported_id TEXT NOT NULL,
                reporter_id TEXT NOT NULL,         -- derived from the signing pubkey
                category    TEXT NOT NULL,
                note        TEXT NOT NULL DEFAULT '',
                evidence    TEXT,                  -- opaque client JSON, usually NULL
                created_at  TEXT NOT NULL,
                status      TEXT NOT NULL DEFAULT 'open',  -- open | actioned | dismissed
                resolution  TEXT,
                resolved_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_reports_reported
                ON reports(reported_id);
            CREATE INDEX IF NOT EXISTS idx_reports_triage
                ON reports(status, created_at);
            """
        )
        self._migrate()

    # -- link grants (MULTIDEVICE.md "Linking a device") ----------------------

    LINK_TTL_S = 600
    MAX_PENDING_LINKS = 8

    def put_link_grant(self, key: str, sealed: str) -> bool:
        """False when too many are already pending. Unauthenticated writers
        are rate-limited at the route; this bounds storage regardless."""
        self._drop_stale_grants()
        pending = self._db.execute(
            "SELECT COUNT(*) AS n FROM link_grants"
        ).fetchone()["n"]
        if pending >= self.MAX_PENDING_LINKS:
            return False
        self._db.execute(
            "INSERT INTO link_grants (key, sealed, created_at) VALUES (?, ?, ?) "
            "ON CONFLICT(key) DO UPDATE SET sealed=excluded.sealed, "
            "created_at=excluded.created_at",
            (key, sealed, _now()),
        )
        self._db.commit()
        return True

    def take_link_grant(self, key: str) -> str | None:
        """Returns and deletes: single-use, so a replayed fetch gets nothing
        and a stolen QR stops being useful the moment it is used."""
        self._drop_stale_grants()
        row = self._db.execute(
            "SELECT sealed FROM link_grants WHERE key = ?", (key,)
        ).fetchone()
        if row is None:
            return None
        self._db.execute("DELETE FROM link_grants WHERE key = ?", (key,))
        self._db.commit()
        return row["sealed"]

    def _drop_stale_grants(self) -> None:
        cutoff = (
            datetime.now(timezone.utc) - timedelta(seconds=self.LINK_TTL_S)
        ).isoformat()
        self._db.execute("DELETE FROM link_grants WHERE created_at < ?", (cutoff,))
        self._db.commit()

    def _migrate(self) -> None:
        """Additive column migrations for hubs whose DB predates them.
        CREATE TABLE IF NOT EXISTS only builds fresh databases; the deployed
        hub.db needs the ALTER. Idempotent, so it runs on every boot."""
        have = {r["name"] for r in self._db.execute("PRAGMA table_info(users)")}
        for column, ddl in (
            ("banned_at", "ALTER TABLE users ADD COLUMN banned_at TEXT"),
            ("ban_reason", "ALTER TABLE users ADD COLUMN ban_reason TEXT"),
            # Nullable by necessity (SQLite can't ALTER-in NOT NULL): rows
            # from before the PQ cutover have no X-Wing key. Registration
            # always writes both; resolvers refuse entries without a valid
            # pq_pk, so legacy junk rows are unreachable, not insecure.
            ("pq_pk", "ALTER TABLE users ADD COLUMN pq_pk TEXT"),
            ("pq_sig", "ALTER TABLE users ADD COLUMN pq_sig TEXT"),
        ):
            if column not in have:
                self._db.execute(ddl)

    @property
    def _db(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            # autocommit: each statement commits at once, so a failed INSERT
            # (dup-key claim) can never leave a transaction idling on the WAL
            # write lock. No method needs multi-statement atomicity.
            # isolation_level=None is the ≤3.11-compatible spelling (the
            # autocommit= kwarg is 3.12+; the deployed hub runs Debian 12's
            # 3.11) — legacy autocommit mode, same per-statement behavior.
            conn = sqlite3.connect(self._path, timeout=5, isolation_level=None)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=5000")
            conn.execute("PRAGMA synchronous=NORMAL")
            self._local.conn = conn
        return conn

    # -- users ---------------------------------------------------------------

    def create_user(
        self,
        stonechat_id: str,
        pubkey_b64: str,
        pq_pk_b64: str,
        pq_sig_b64: str,
        token: str,
    ) -> bool:
        """True on success, False if the key is already registered."""
        try:
            self._db.execute(
                "INSERT INTO users (stonechat_id, pubkey, pq_pk, pq_sig, token_hash,"
                " created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (stonechat_id, pubkey_b64, pq_pk_b64, pq_sig_b64, hash_token(token), _now()),
            )
            return True
        except sqlite3.IntegrityError:
            return False

    def rotate_token(self, stonechat_id: str, token: str) -> None:
        """Identity recovery: the recovering device becomes the account —
        whatever held the previous token (an old phone, a thief) is out."""
        self._db.execute(
            "UPDATE users SET token_hash = ? WHERE stonechat_id = ?",
            (hash_token(token), stonechat_id),
        )

    def user_by_token(self, token: str) -> dict | None:
        row = self._db.execute(
            "SELECT * FROM users WHERE token_hash = ?", (hash_token(token),)
        ).fetchone()
        return dict(row) if row else None

    def user_by_id(self, stonechat_id: str) -> dict | None:
        row = self._db.execute(
            "SELECT * FROM users WHERE stonechat_id = ?", (stonechat_id,)
        ).fetchone()
        return dict(row) if row else None

    def set_ban(self, stonechat_id: str, reason: str | None) -> bool:
        """Ban (reason set) or unban (reason None). False if no such user.

        A ban only refuses future infrastructure — it does not delete the
        account, and a banned identity can still be recovered and still
        resolves in the directory. Making "banned" indistinguishable from
        "never existed" would hand the hub a censorship lever it should not
        have, and identities are cheap to regenerate anyway: this is a cost on
        paying abusers, a speed bump on everyone else (notes/docs/ABUSE.md, internal)."""
        cur = self._db.execute(
            "UPDATE users SET banned_at = ?, ban_reason = ? WHERE stonechat_id = ?",
            (_now() if reason else None, reason, stonechat_id),
        )
        return cur.rowcount > 0

    # -- servers -------------------------------------------------------------

    def create_server(self, stonechat_id: str, provider: str, machine: dict, server_token: str,
                      host_agent_token: str | None = None) -> bool:
        """Atomically claim the one-server-per-user slot. False if occupied."""
        try:
            self._db.execute(
                "INSERT INTO servers (stonechat_id, provider, status, machine, server_token,"
                " host_agent_token, created_at)"
                " VALUES (?, ?, 'provisioning', ?, ?, ?, ?)",
                (stonechat_id, provider, json.dumps(machine), server_token,
                 host_agent_token, _now()),
            )
            return True
        except sqlite3.IntegrityError:
            return False

    def create_external_server(self, stonechat_id: str, address: str, tls_fp: str | None) -> bool:
        """User provisioned their own relay; we only list its address.
        No server_token stored — it never leaves the user's device."""
        try:
            self._db.execute(
                "INSERT INTO servers (stonechat_id, provider, status, machine, address, tls_fp, created_at)"
                " VALUES (?, 'external', 'running', '{}', ?, ?, ?)",
                (stonechat_id, address, tls_fp, _now()),
            )
            return True
        except sqlite3.IntegrityError:
            return False

    def server_for(self, stonechat_id: str) -> dict | None:
        row = self._db.execute(
            "SELECT * FROM servers WHERE stonechat_id = ?", (stonechat_id,)
        ).fetchone()
        if not row:
            return None
        server = dict(row)
        server["machine"] = json.loads(server["machine"])
        server["meta"] = json.loads(server["meta"])
        return server

    def server_by_token(self, server_token: str) -> dict | None:
        """Auth for GET /v1/relay-binary: the fetching VM presents the
        server_token its startup script carries. External servers never
        match — their token is NULL (never stored)."""
        row = self._db.execute(
            "SELECT * FROM servers WHERE server_token = ?", (server_token,)
        ).fetchone()
        return dict(row) if row else None

    def mark_running(self, stonechat_id: str, resource_id: str, address: str, meta: dict,
                     tls_fp: str | None) -> None:
        self._db.execute(
            "UPDATE servers SET status='running', resource_id=?, address=?, meta=?,"
            " tls_fp=?, tls_sig=NULL, error=NULL"  # new box, new cert — old sig is void
            " WHERE stonechat_id=?",
            (resource_id, address, json.dumps(meta), tls_fp, stonechat_id),
        )

    def set_tls_sig(self, stonechat_id: str, tls_sig: str) -> None:
        self._db.execute(
            "UPDATE servers SET tls_sig=? WHERE stonechat_id=?", (tls_sig, stonechat_id)
        )

    def mark_error(self, stonechat_id: str, error: str) -> None:
        self._db.execute(
            "UPDATE servers SET status='error', error=? WHERE stonechat_id=?",
            (error[:1000], stonechat_id),
        )

    def reapable_servers(self, providers: tuple[str, ...], lapsed_before: str) -> list[dict]:
        """Servers on paid providers whose owner has no live subscription and
        whose most recent one lapsed before the cutoff. Owners with no
        subscription rows at all are left alone — ambiguous state (pre-billing
        data, manual grants) is not a kill signal."""
        if not providers:
            return []
        marks = ",".join("?" * len(providers))
        rows = self._db.execute(
            f"SELECT s.* FROM servers s"
            f" WHERE s.provider IN ({marks})"
            "  AND NOT EXISTS (SELECT 1 FROM subscriptions"
            "    WHERE stonechat_id = s.stonechat_id AND status IN ('active', 'grace'))"
            "  AND (SELECT MAX(lapsed_at) FROM subscriptions"
            "    WHERE stonechat_id = s.stonechat_id AND status = 'lapsed') <= ?",
            (*providers, lapsed_before),
        ).fetchall()
        servers = []
        for row in rows:
            server = dict(row)
            server["machine"] = json.loads(server["machine"])
            server["meta"] = json.loads(server["meta"])
            servers.append(server)
        return servers

    def delete_server(self, stonechat_id: str) -> None:
        self._db.execute("DELETE FROM servers WHERE stonechat_id = ?", (stonechat_id,))

    def servers_by_host(self, host: str) -> list[dict]:
        """Abuse triage: an abuse report carries an IP and nothing else, so
        this is the only lookup that matters operationally.

        Matches the *host component* exactly rather than a LIKE '%ip%' over
        the address, which would report 10.0.0.1 and 110.0.0.19 as the same
        machine — an off-by-one-character way to destroy the wrong customer's
        mailbox. No index: a leading-wildcard LIKE could not use one anyway,
        the table is one row per customer, and this runs when a human asks."""
        wanted = host.strip().lower().strip("[]")
        found = []
        for row in self._db.execute("SELECT * FROM servers WHERE address IS NOT NULL"):
            server = dict(row)
            hostname = urlsplit(server["address"]).hostname or ""
            if hostname.lower() == wanted:
                server["machine"] = json.loads(server["machine"])
                server["meta"] = json.loads(server["meta"])
                found.append(server)
        return found

    def record_tombstone(self, server: dict, reason: str) -> None:
        """Write the abuse record *before* the machine goes away — a destroy
        that half-fails must not also lose the evidence of what was there."""
        self._db.execute(
            "INSERT INTO server_tombstones (stonechat_id, provider, resource_id, address,"
            " meta, reason, created_at, destroyed_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (server["stonechat_id"], server["provider"], server["resource_id"],
             server["address"], json.dumps(server.get("meta") or {}), reason,
             server["created_at"], _now()),
        )

    def tombstones_for(self, stonechat_id: str) -> list[dict]:
        return [dict(r) for r in self._db.execute(
            "SELECT * FROM server_tombstones WHERE stonechat_id = ? ORDER BY id DESC",
            (stonechat_id,),
        )]

    # -- reports ---------------------------------------------------------------

    def create_report(self, reported_id: str, reporter_id: str, category: str,
                      note: str, evidence: str | None) -> str:
        """Record one user's report about another. Returns the reference id."""
        report_id = str(uuid.uuid4())
        self._db.execute(
            "INSERT INTO reports (id, reported_id, reporter_id, category, note,"
            " evidence, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (report_id, reported_id, reporter_id, category, note, evidence, _now()),
        )
        return report_id

    def report_by_id(self, report_id: str) -> dict | None:
        row = self._db.execute(
            "SELECT * FROM reports WHERE id = ?", (report_id,)
        ).fetchone()
        return dict(row) if row else None

    def list_reports(self, status: str | None = None, limit: int = 100) -> list[dict]:
        """Triage queue, newest first. `evidence` is replaced by its size:
        the list view is for choosing what to open, and a queue that pastes
        every attached conversation into one response is a queue nobody reads
        — and a much worse thing to leave in a terminal scrollback."""
        if status:
            rows = self._db.execute(
                "SELECT * FROM reports WHERE status = ?"
                " ORDER BY created_at DESC LIMIT ?", (status, limit),
            )
        else:
            rows = self._db.execute(
                "SELECT * FROM reports ORDER BY created_at DESC LIMIT ?", (limit,)
            )
        out = []
        for row in rows:
            report = dict(row)
            evidence = report.pop("evidence")
            report["evidence_bytes"] = len(evidence) if evidence else 0
            out.append(report)
        return out

    def report_counts(self, reported_id: str) -> dict:
        """How many reports this account has drawn, and from how many distinct
        reporters. The second number is the one that matters: ten reports from
        one person is a feud, three from strangers who cannot know each other
        is a pattern."""
        row = self._db.execute(
            "SELECT COUNT(*) AS total, COUNT(DISTINCT reporter_id) AS reporters"
            " FROM reports WHERE reported_id = ?", (reported_id,),
        ).fetchone()
        return {"total": row["total"], "distinct_reporters": row["reporters"]}

    def resolve_report(self, report_id: str, status: str, resolution: str) -> bool:
        """Close a report. False if there is no such report.

        Resolving also drops the evidence: it has served its purpose once a
        human has decided, and the decision itself is preserved here, in
        `server_tombstones`, and in `users.ban_reason`. Keeping the plaintext
        past the decision buys nothing and costs everything."""
        cur = self._db.execute(
            "UPDATE reports SET status = ?, resolution = ?, resolved_at = ?,"
            " evidence = NULL WHERE id = ?",
            (status, resolution, _now(), report_id),
        )
        return cur.rowcount > 0

    def purge_reports(self, older_than: str) -> int:
        """Delete reports created before `older_than` (ISO-8601), whatever
        their status. Unresolved is not a reason to keep plaintext forever —
        a report nobody triaged in the retention window is a process failure,
        not a record to preserve."""
        cur = self._db.execute(
            "DELETE FROM reports WHERE created_at < ?", (older_than,)
        )
        return cur.rowcount

    # -- billing ---------------------------------------------------------------

    def record_event(self, event_id: str, event_type: str) -> bool:
        """Webhook idempotency: True if this is the first delivery."""
        cur = self._db.execute(
            "INSERT OR IGNORE INTO stripe_events (event_id, type, received_at)"
            " VALUES (?, ?, ?)",
            (event_id, event_type, _now()),
        )
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
        self._db.execute(
            "INSERT INTO subscriptions (id, source, plan, status,"
            " stripe_customer_id, stripe_subscription_id, checkout_session_id,"
            " code_hash, code_plain, note, created_at, updated_at)"
            " VALUES (?, ?, ?, 'active', ?, ?, ?, ?, ?, ?, ?, ?)",
            (row_id, source, plan, stripe_customer_id, stripe_subscription_id,
             checkout_session_id, code_hash, code_plain, note, now, now),
        )
        row = self._db.execute(
            "SELECT * FROM subscriptions WHERE id = ?", (row_id,)
        ).fetchone()
        return dict(row)

    def subscription_by_session(self, session_id: str) -> dict | None:
        row = self._db.execute(
            "SELECT * FROM subscriptions WHERE checkout_session_id = ?",
            (session_id,),
        ).fetchone()
        return dict(row) if row else None

    def subscription_by_stripe_sub(self, sub_id: str) -> dict | None:
        row = self._db.execute(
            "SELECT * FROM subscriptions WHERE stripe_subscription_id = ?",
            (sub_id,),
        ).fetchone()
        return dict(row) if row else None

    def claim_subscription(self, code_hash: str, stonechat_id: str) -> dict | None:
        """Atomically bind an unclaimed, non-lapsed code to an account and
        drop the plaintext code. None if the code is unknown, spent, or dead."""
        cur = self._db.execute(
            "UPDATE subscriptions SET stonechat_id = ?, code_plain = NULL,"
            " updated_at = ?"
            " WHERE code_hash = ? AND stonechat_id IS NULL AND status != 'lapsed'",
            (stonechat_id, _now(), code_hash),
        )
        if cur.rowcount != 1:
            return None
        row = self._db.execute(
            "SELECT * FROM subscriptions WHERE code_hash = ?", (code_hash,)
        ).fetchone()
        return dict(row) if row else None

    def entitlement_for(self, stonechat_id: str) -> dict | None:
        """The account's best live subscription (sovereign beats private).
        `grace` still counts — payment trouble shouldn't cut service instantly."""
        row = self._db.execute(
            "SELECT * FROM subscriptions"
            " WHERE stonechat_id = ? AND status IN ('active', 'grace')"
            " ORDER BY CASE plan WHEN 'sovereign' THEN 0 ELSE 1 END, created_at"
            " LIMIT 1",
            (stonechat_id,),
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
        return cur.rowcount == 1
