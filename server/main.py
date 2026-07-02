"""Zeon routing server — a single user's encrypted mailbox.

Runs on a VM the user owns. Stores only opaque encrypted envelopes addressed
to its owner and deletes each one the moment the owner's device acks it.
Plaintext never exists here.

Config (env):
    ZEON_OWNER_ID     Zeon ID of the owner (the only valid recipient)
    ZEON_OWNER_TOKEN  shared secret the owner's device presents on /ws
    ZEON_PORT         listen port (default 8080)
    ZEON_DB           sqlite path (default ./mailbox.db)
"""

import asyncio
import json
import logging
import os
import sqlite3
import threading
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect

OWNER_ID = os.environ["ZEON_OWNER_ID"]
OWNER_TOKEN = os.environ["ZEON_OWNER_TOKEN"]
DB_PATH = os.environ.get("ZEON_DB", "mailbox.db")

MAX_ENVELOPE_BYTES = 64 * 1024
MAX_QUEUE_DEPTH = 10_000
ENVELOPE_TYPES = {"msg", "contact_request", "contact_accept"}
REQUIRED_FIELDS = {"v", "id", "type", "from", "to", "sent_at", "nonce", "ciphertext"}

log = logging.getLogger("zeon.server")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


class Mailbox:
    """SQLite-backed envelope queue. Rows die on ack."""

    def __init__(self, path: str):
        self._lock = threading.Lock()
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS envelopes ("
            "  id TEXT PRIMARY KEY,"
            "  body TEXT NOT NULL,"
            "  received_at TEXT NOT NULL)"
        )
        self._db.commit()

    def put(self, envelope: dict) -> bool:
        with self._lock:
            depth = self._db.execute("SELECT COUNT(*) FROM envelopes").fetchone()[0]
            if depth >= MAX_QUEUE_DEPTH:
                return False
            self._db.execute(
                "INSERT OR IGNORE INTO envelopes (id, body, received_at) VALUES (?, ?, ?)",
                (
                    envelope["id"],
                    json.dumps(envelope, separators=(",", ":")),
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            self._db.commit()
            return True

    def all(self) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT body FROM envelopes ORDER BY received_at"
            ).fetchall()
        return [json.loads(r[0]) for r in rows]

    def delete(self, envelope_id: str) -> None:
        with self._lock:
            self._db.execute("DELETE FROM envelopes WHERE id = ?", (envelope_id,))
            self._db.commit()

    def depth(self) -> int:
        with self._lock:
            return self._db.execute("SELECT COUNT(*) FROM envelopes").fetchone()[0]


class OwnerLink:
    """At most one live WebSocket to the owner's device."""

    def __init__(self):
        self._ws: WebSocket | None = None
        self._send_lock = asyncio.Lock()

    async def attach(self, ws: WebSocket) -> None:
        old, self._ws = self._ws, ws
        if old is not None:
            try:
                await old.close(code=4000, reason="replaced by newer connection")
            except Exception:
                pass

    def detach(self, ws: WebSocket) -> None:
        if self._ws is ws:
            self._ws = None

    async def push(self, envelope: dict) -> bool:
        ws = self._ws
        if ws is None:
            return False
        try:
            async with self._send_lock:
                await ws.send_text(json.dumps(envelope, separators=(",", ":")))
            return True
        except Exception:
            return False


mailbox = Mailbox(DB_PATH)
link = OwnerLink()


@asynccontextmanager
async def lifespan(_: FastAPI):
    log.info("mailbox up for owner %s…%s, %d queued", OWNER_ID[:7], OWNER_ID[-4:], mailbox.depth())
    yield


app = FastAPI(title="zeon-routing-server", lifespan=lifespan)


@app.get("/health")
async def health():
    return {"owner": OWNER_ID, "status": "ok", "queued": mailbox.depth()}


@app.post("/inbox")
async def inbox(request: Request):
    raw = await request.body()
    if len(raw) > MAX_ENVELOPE_BYTES:
        raise HTTPException(413, "envelope too large")
    try:
        envelope = json.loads(raw)
    except json.JSONDecodeError:
        raise HTTPException(400, "not json")
    if not isinstance(envelope, dict) or not REQUIRED_FIELDS.issubset(envelope):
        raise HTTPException(400, "missing fields")
    if envelope["type"] not in ENVELOPE_TYPES:
        raise HTTPException(400, "unknown envelope type")
    if envelope["to"] != OWNER_ID:
        raise HTTPException(403, "not this mailbox's owner")

    if not mailbox.put(envelope):
        raise HTTPException(503, "mailbox full")
    # Best-effort immediate push; the row is only removed when the device acks.
    await link.push(envelope)
    return {"status": "queued"}


@app.websocket("/ws")
async def ws_owner(ws: WebSocket):
    if ws.query_params.get("token") != OWNER_TOKEN:
        await ws.close(code=4401, reason="bad token")
        return
    await ws.accept()
    await link.attach(ws)
    log.info("owner connected, draining %d envelopes", mailbox.depth())
    try:
        for envelope in mailbox.all():
            await link.push(envelope)
        while True:
            msg = await ws.receive_text()
            try:
                ack = json.loads(msg)
            except json.JSONDecodeError:
                continue
            if isinstance(ack, dict) and isinstance(ack.get("ack"), str):
                mailbox.delete(ack["ack"])
    except WebSocketDisconnect:
        pass
    finally:
        link.detach(ws)
        log.info("owner disconnected, %d queued", mailbox.depth())


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("ZEON_PORT", "8080")))
