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
import re
import sqlite3
import threading
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, Response, WebSocket, WebSocketDisconnect

OWNER_ID = os.environ["ZEON_OWNER_ID"]
OWNER_TOKEN = os.environ["ZEON_OWNER_TOKEN"]
DB_PATH = os.environ.get("ZEON_DB", "mailbox.db")
BLOB_DIR = Path(os.environ.get("ZEON_BLOBS", "blobs"))
PUSH_GATEWAY = os.environ.get("ZEON_PUSH_GATEWAY", "").rstrip("/")
PUSH_DEBOUNCE_S = 5.0

MAX_ENVELOPE_BYTES = 64 * 1024
MAX_QUEUE_DEPTH = 10_000
MAX_BLOB_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BLOB_BYTES = 500 * 1024 * 1024
BLOB_TTL_SECONDS = 14 * 24 * 3600
ENVELOPE_TYPES = {
    "msg", "media", "contact_request", "contact_accept",
    "group_create", "group_update", "group_msg", "group_leave",
}
REQUIRED_FIELDS = {"v", "id", "type", "from", "to", "sent_at", "nonce", "ciphertext"}
BLOB_ID_RE = re.compile(r"^[a-f0-9-]{36}$")

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
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS push_config ("
            "  id INTEGER PRIMARY KEY CHECK (id = 1),"  # single owner, single row
            "  device_token TEXT NOT NULL,"
            "  platform TEXT NOT NULL)"
        )
        self._db.commit()

    def set_push_config(self, device_token: str, platform: str) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO push_config (id, device_token, platform) VALUES (1, ?, ?)"
                " ON CONFLICT(id) DO UPDATE SET device_token=excluded.device_token,"
                " platform=excluded.platform",
                (device_token, platform),
            )
            self._db.commit()

    def push_config(self) -> tuple[str, str] | None:
        with self._lock:
            row = self._db.execute(
                "SELECT device_token, platform FROM push_config WHERE id = 1"
            ).fetchone()
        return (row[0], row[1]) if row else None

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
        """Delete an acked envelope — and its blob, if it referenced one."""
        with self._lock:
            row = self._db.execute(
                "SELECT body FROM envelopes WHERE id = ?", (envelope_id,)
            ).fetchone()
            self._db.execute("DELETE FROM envelopes WHERE id = ?", (envelope_id,))
            self._db.commit()
        if row:
            blob_id = json.loads(row[0]).get("blob_id")
            if blob_id:
                blobs.delete(blob_id)

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


class BlobStore:
    """Encrypted media blobs, held only until their envelope is acked.
    Plain files on disk; the server can't decrypt them (secretbox key travels
    inside the envelope ciphertext)."""

    def __init__(self, root: Path):
        self._root = root
        root.mkdir(parents=True, exist_ok=True)

    def _path(self, blob_id: str) -> Path:
        if not BLOB_ID_RE.match(blob_id):
            raise HTTPException(400, "bad blob id")
        return self._root / blob_id

    def put(self, data: bytes) -> str:
        self.collect_garbage()
        used = sum(f.stat().st_size for f in self._root.iterdir() if f.is_file())
        if used + len(data) > MAX_TOTAL_BLOB_BYTES:
            raise HTTPException(507, "blob storage full")
        blob_id = str(uuid.uuid4())
        (self._root / blob_id).write_bytes(data)
        return blob_id

    def get(self, blob_id: str) -> bytes:
        path = self._path(blob_id)
        if not path.is_file():
            raise HTTPException(404, "no such blob")
        return path.read_bytes()

    def delete(self, blob_id: str) -> None:
        try:
            self._path(blob_id).unlink(missing_ok=True)
        except HTTPException:
            pass  # malformed id in an old envelope — nothing to delete

    def collect_garbage(self) -> None:
        cutoff = time.time() - BLOB_TTL_SECONDS
        for f in self._root.iterdir():
            if f.is_file() and f.stat().st_mtime < cutoff:
                f.unlink(missing_ok=True)


blobs = BlobStore(BLOB_DIR)
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
    blob_id = envelope.get("blob_id")
    if blob_id is not None and (
        not isinstance(blob_id, str) or not BLOB_ID_RE.match(blob_id)
    ):
        raise HTTPException(400, "bad blob_id")

    if not mailbox.put(envelope):
        raise HTTPException(503, "mailbox full")
    # Best-effort immediate push; the row is only removed when the device acks.
    delivered_live = await link.push(envelope)
    if not delivered_live:
        asyncio.get_running_loop().create_task(_ping_gateway())
    return {"status": "queued"}


_last_gateway_ping = 0.0


async def _ping_gateway() -> None:
    """Owner is offline — ask the push gateway to wake their device.
    Content-free: only the device token leaves this box. Best-effort."""
    global _last_gateway_ping
    if not PUSH_GATEWAY:
        return
    config = mailbox.push_config()
    if config is None:
        return
    now = time.monotonic()
    if now - _last_gateway_ping < PUSH_DEBOUNCE_S:
        return
    _last_gateway_ping = now
    device_token, platform = config
    try:
        import httpx

        async with httpx.AsyncClient(timeout=5) as client:
            await client.post(
                f"{PUSH_GATEWAY}/v1/ping",
                json={"device_token": device_token, "platform": platform},
            )
    except Exception as e:  # push is best-effort; envelopes are safe regardless
        log.debug("gateway ping failed: %s", e)


@app.post("/push-config")
async def push_config(request: Request, token: str = ""):
    if token != OWNER_TOKEN:
        raise HTTPException(401, "owner only")
    try:
        body = json.loads(await request.body())
        device_token = body["device_token"]
        platform = body["platform"]
    except (json.JSONDecodeError, KeyError, TypeError):
        raise HTTPException(400, "expected {device_token, platform}")
    if platform not in ("ios", "android") or not isinstance(device_token, str):
        raise HTTPException(400, "bad platform or token")
    mailbox.set_push_config(device_token, platform)
    return {"status": "ok"}


@app.post("/blob")
async def blob_upload(request: Request):
    data = await request.body()
    if not data:
        raise HTTPException(400, "empty blob")
    if len(data) > MAX_BLOB_BYTES:
        raise HTTPException(413, "blob too large")
    return {"blob_id": blobs.put(data)}


@app.get("/blob/{blob_id}")
async def blob_download(blob_id: str, token: str = ""):
    if token != OWNER_TOKEN:
        raise HTTPException(401, "owner only")
    return Response(content=blobs.get(blob_id), media_type="application/octet-stream")


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
