"""Zeon routing server — a single user's encrypted mailbox.

Runs on a VM the user owns. Stores only sealed envelopes addressed to its
owner and deletes each one the moment the owner's device acks it. Plaintext
never exists here, and neither does sender identity: everything beyond the
recipient rides inside an anonymous sealed box only the owner can open
(PROTOCOL.md "Envelope") — this mailbox cannot tell who wrote to its owner.
It also serves the owner's PUBLIC prekeys (PROTOCOL.md "Prekeys") so peers
can start forward-secret sessions while the owner is offline — private
halves never leave the owner's phone.

Config (env):
    ZEON_OWNER_ID     Zeon ID of the owner (the only valid recipient)
    ZEON_OWNER_TOKEN  shared secret the owner's device presents on /ws
    ZEON_PORT         listen port (default 8080)
    ZEON_DB           sqlite path (default ./mailbox.db)
    ZEON_TLS_DIR      where the TLS key/cert live (default: the DB's directory)

Transport: everything is served over TLS with a self-signed certificate
generated on first boot. Clients don't trust it via any CA — they pin its
fingerprint, which the owner signs with their identity key (PROTOCOL.md
"Transport"). The TLS key protects the pipe only; messages are end-to-end
encrypted before they reach it.
"""

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import re
import sqlite3
import subprocess
import threading
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, Response, WebSocket, WebSocketDisconnect

OWNER_ID = os.environ["ZEON_OWNER_ID"]
OWNER_TOKEN = os.environ["ZEON_OWNER_TOKEN"]
# Optional TURN relay (PROTOCOL.md "Calls"): a coturn container beside this
# server, sharing this secret (coturn: use-auth-secret + static-auth-secret).
# Unset → /turn-credentials 404s and clients fall back to STUN-only.
TURN_SECRET = os.environ.get("ZEON_TURN_SECRET", "")
TURN_PORT = int(os.environ.get("ZEON_TURN_PORT", "3478"))
TURN_TTL_S = 6 * 3600
DB_PATH = os.environ.get("ZEON_DB", "mailbox.db")
BLOB_DIR = Path(os.environ.get("ZEON_BLOBS", "blobs"))
TLS_DIR = Path(os.environ.get("ZEON_TLS_DIR", str(Path(DB_PATH).resolve().parent)))
PUSH_GATEWAY = os.environ.get("ZEON_PUSH_GATEWAY", "").rstrip("/")
# Hub-minted gateway credential (PROTOCOL.md "Push gateway"). Empty → sent
# bare; the gateway only enforces it when its mint secret is configured.
PUSH_KEY = os.environ.get("ZEON_PUSH_KEY", "")
PUSH_DEBOUNCE_S = 5.0
# A socket write succeeding is not delivery: a freshly-backgrounded phone
# keeps its TCP connection open while the suspended app never reads the
# frame. Live delivery only counts once the device acks — envelopes still
# queued after this grace window get a gateway ping like any offline
# delivery. Call offers use the shorter window; ringing can't wait.
PUSH_ACK_GRACE_S = 10.0
PUSH_ACK_GRACE_RING_S = 2.0

MAX_ENVELOPE_BYTES = 64 * 1024
MAX_QUEUE_DEPTH = 10_000
MAX_BLOB_BYTES = 64 * 1024 * 1024  # videos/documents; mirrored in the app
MAX_TOTAL_BLOB_BYTES = 1024 * 1024 * 1024
BLOB_TTL_SECONDS = 14 * 24 * 3600
MAX_OPKS = 256
REQUIRED_FIELDS = {"v", "id", "to", "sealed"}
BLOB_ID_RE = re.compile(r"^[a-f0-9-]{36}$")


def validate_envelope(envelope: dict) -> None:
    """Shape checks only — the sealed body is opaque by design; sender, type
    and session header are all inside it. Raises HTTPException."""
    if not isinstance(envelope, dict) or not REQUIRED_FIELDS.issubset(envelope):
        raise HTTPException(400, "missing fields")
    if envelope["v"] != 1:
        raise HTTPException(400, "unsupported protocol version (v1 only)")
    if not isinstance(envelope["id"], str) or not envelope["id"]:
        raise HTTPException(400, "bad id")
    if not isinstance(envelope["sealed"], str) or not envelope["sealed"]:
        raise HTTPException(400, "bad sealed body")
    blob_id = envelope.get("blob_id")
    if blob_id is not None and (
        not isinstance(blob_id, str) or not BLOB_ID_RE.match(blob_id)
    ):
        raise HTTPException(400, "bad blob_id")
    # Delivery hints (PROTOCOL.md "Envelope"): all optional, all booleans.
    for hint in ("transient", "push", "ring"):
        if hint in envelope and not isinstance(envelope[hint], bool):
            raise HTTPException(400, f"bad {hint} flag")

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
        # Public prekeys (PROTOCOL.md). Private halves never reach this box.
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS signed_prekey ("
            "  row INTEGER PRIMARY KEY CHECK (row = 1),"
            "  id INTEGER NOT NULL,"
            "  pub TEXT NOT NULL,"
            "  sig TEXT NOT NULL)"
        )
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS one_time_prekeys ("
            "  id INTEGER PRIMARY KEY,"
            "  pub TEXT NOT NULL)"
        )
        self._db.commit()

    def set_prekeys(self, spk: dict, opks: list[dict]) -> None:
        """Owner upload: replace the SPK and the whole OPK stock. The owner
        is the source of truth for which private halves it still holds —
        merging by id kept keys from a previous install alive forever, and
        senders got bundles the owner could no longer decrypt."""
        with self._lock:
            self._db.execute(
                "INSERT INTO signed_prekey (row, id, pub, sig) VALUES (1, ?, ?, ?)"
                " ON CONFLICT(row) DO UPDATE SET id=excluded.id,"
                " pub=excluded.pub, sig=excluded.sig",
                (spk["id"], spk["pub"], spk["sig"]),
            )
            self._db.execute("DELETE FROM one_time_prekeys")
            for opk in opks[:MAX_OPKS]:
                self._db.execute(
                    "INSERT OR IGNORE INTO one_time_prekeys (id, pub) VALUES (?, ?)",
                    (opk["id"], opk["pub"]),
                )
            self._db.commit()

    def take_bundle(self) -> dict | None:
        """The prekey bundle for a sender starting a session. Consumes the
        returned one-time prekey — each is handed out at most once."""
        with self._lock:
            spk = self._db.execute(
                "SELECT id, pub, sig FROM signed_prekey WHERE row = 1"
            ).fetchone()
            if spk is None:
                return None
            opk = self._db.execute(
                "SELECT id, pub FROM one_time_prekeys ORDER BY id LIMIT 1"
            ).fetchone()
            if opk:
                self._db.execute(
                    "DELETE FROM one_time_prekeys WHERE id = ?", (opk[0],)
                )
            self._db.commit()
        return {
            "spk": {"id": spk[0], "pub": spk[1], "sig": spk[2]},
            "opk": {"id": opk[0], "pub": opk[1]} if opk else None,
        }

    def prekey_status(self) -> dict:
        with self._lock:
            has_spk = self._db.execute(
                "SELECT COUNT(*) FROM signed_prekey"
            ).fetchone()[0] > 0
            opks = self._db.execute(
                "SELECT COUNT(*) FROM one_time_prekeys"
            ).fetchone()[0]
        return {"spk": has_spk, "opks": opks}

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

    def has(self, envelope_id: str) -> bool:
        with self._lock:
            return self._db.execute(
                "SELECT 1 FROM envelopes WHERE id = ?", (envelope_id,)
            ).fetchone() is not None

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


class Tls:
    """Self-signed cert, generated once and kept for the mailbox's lifetime.
    fingerprint = BLAKE2b-256 of the DER certificate (what clients pin)."""

    def __init__(self, directory: Path):
        directory.mkdir(parents=True, exist_ok=True)
        self.key_file = directory / "tls_key.pem"
        self.cert_file = directory / "tls_cert.pem"
        if not (self.key_file.is_file() and self.cert_file.is_file()):
            subprocess.run(
                ["openssl", "req", "-x509", "-newkey", "ec",
                 "-pkeyopt", "ec_paramgen_curve:prime256v1",
                 "-keyout", str(self.key_file), "-out", str(self.cert_file),
                 "-days", "36500", "-nodes", "-subj", "/CN=zeon-mailbox"],
                check=True, capture_output=True,
            )
            self.key_file.chmod(0o600)
        der = subprocess.run(
            ["openssl", "x509", "-in", str(self.cert_file), "-outform", "der"],
            check=True, capture_output=True,
        ).stdout
        self.fingerprint_b64 = base64.b64encode(
            hashlib.blake2b(der, digest_size=32).digest()
        ).decode()


blobs = BlobStore(BLOB_DIR)
mailbox = Mailbox(DB_PATH)
link = OwnerLink()
tls = Tls(TLS_DIR)


@asynccontextmanager
async def lifespan(_: FastAPI):
    log.info("mailbox up for owner %s…%s, %d queued", OWNER_ID[:7], OWNER_ID[-4:], mailbox.depth())
    yield


app = FastAPI(title="zeon-routing-server", lifespan=lifespan)


@app.get("/health")
async def health():
    return {
        "owner": OWNER_ID,
        "status": "ok",
        "queued": mailbox.depth(),
        "prekeys": mailbox.prekey_status(),
        "tls_fp": tls.fingerprint_b64,
    }


@app.post("/prekeys")
async def upload_prekeys(request: Request, token: str = ""):
    if token != OWNER_TOKEN:
        raise HTTPException(401, "owner only")
    raw = await request.body()
    if len(raw) > MAX_ENVELOPE_BYTES:
        raise HTTPException(413, "too large")
    try:
        body = json.loads(raw)
        spk, opks = body["spk"], body.get("opks", [])
        assert isinstance(spk["id"], int)
        assert isinstance(spk["pub"], str) and isinstance(spk["sig"], str)
        assert isinstance(opks, list) and len(opks) <= MAX_OPKS
        assert all(
            isinstance(o["id"], int) and isinstance(o["pub"], str) for o in opks
        )
    except (json.JSONDecodeError, KeyError, TypeError, AssertionError):
        raise HTTPException(400, "expected {spk: {id, pub, sig}, opks: [{id, pub}]}")
    mailbox.set_prekeys(spk, opks)
    return {"status": "ok", "prekeys": mailbox.prekey_status()}


@app.get("/prekeys/bundle")
async def prekey_bundle():
    """Anyone may start a session (like /inbox). Consumes the returned OPK;
    a drained pool returns opk=null and senders fall back to 3-DH."""
    bundle = mailbox.take_bundle()
    if bundle is None:
        raise HTTPException(404, "owner has not published prekeys yet")
    return bundle


@app.post("/inbox")
async def inbox(request: Request):
    raw = await request.body()
    if len(raw) > MAX_ENVELOPE_BYTES:
        raise HTTPException(413, "envelope too large")
    try:
        envelope = json.loads(raw)
    except json.JSONDecodeError:
        raise HTTPException(400, "not json")
    validate_envelope(envelope)
    if envelope["to"] != OWNER_ID:
        raise HTTPException(403, "not this mailbox's owner")

    # Transient envelopes (typing indicators) are only worth anything live:
    # never queued, never woken for. If the owner isn't connected they vanish.
    if envelope.get("transient") is True:
        delivered_live = await link.push(envelope)
        return {"status": "delivered" if delivered_live else "dropped"}

    if not mailbox.put(envelope):
        raise HTTPException(503, "mailbox full")
    # Best-effort immediate push; the row is only removed when the device acks.
    delivered_live = await link.push(envelope)
    if envelope.get("push") is not False:
        # push: false (receipts) → deliver on the next connect, don't wake the
        # phone. ring: true (call offers) → always ping, skipping the debounce.
        ring = envelope.get("ring") is True
        if delivered_live:
            asyncio.get_running_loop().create_task(
                _ping_gateway_if_unacked(envelope["id"], ring=ring))
        else:
            asyncio.get_running_loop().create_task(_ping_gateway(ring=ring))
    return {"status": "queued"}


async def _ping_gateway_if_unacked(envelope_id: str, ring: bool = False) -> None:
    """The live socket accepted the frame, but that's only TCP: a suspended
    app never reads it and never acks, and the connection can look healthy
    for tens of seconds before the WebSocket ping timeout notices. If the
    envelope hasn't been acked (deleted) after a grace window, treat the
    owner as offline and wake the device."""
    await asyncio.sleep(PUSH_ACK_GRACE_RING_S if ring else PUSH_ACK_GRACE_S)
    if mailbox.has(envelope_id):
        await _ping_gateway(ring=ring)


_last_gateway_ping = 0.0


async def _ping_gateway(ring: bool = False) -> None:
    """Owner is offline — ask the push gateway to wake their device.
    Content-free: only the device token leaves this box. Best-effort.
    ring=True marks a call offer: never debounced, and flagged to the
    gateway so it can escalate to a VoIP/high-priority push (the gateway
    ignores the flag until it grows that path)."""
    global _last_gateway_ping
    if not PUSH_GATEWAY:
        return
    config = mailbox.push_config()
    if config is None:
        return
    now = time.monotonic()
    if not ring and now - _last_gateway_ping < PUSH_DEBOUNCE_S:
        return
    _last_gateway_ping = now
    device_token, platform = config
    try:
        import httpx

        async with httpx.AsyncClient(timeout=5) as client:
            r = await client.post(
                f"{PUSH_GATEWAY}/v1/ping",
                json={"device_token": device_token, "platform": platform,
                      "ring": ring},
                headers={"X-Zeon-Push-Key": PUSH_KEY} if PUSH_KEY else {},
            )
            if r.status_code != 200:
                log.warning("gateway ping rejected: %s %s",
                            r.status_code, r.text[:200])
    except Exception as e:  # push is best-effort; envelopes are safe regardless
        # warning, not debug: a misconfigured/unreachable gateway looks
        # exactly like "push doesn't work" and must be visible in logs.
        log.warning("gateway ping failed: %s", e)


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


@app.get("/turn-credentials")
async def turn_credentials(request: Request, token: str = ""):
    """Ephemeral credentials for this box's coturn (TURN REST API scheme).
    Owner-only: the relay carries the owner's call media, nobody else's.
    The TURN host is the same address the owner reached this server at."""
    if token != OWNER_TOKEN:
        raise HTTPException(401, "owner only")
    if not TURN_SECRET:
        raise HTTPException(404, "no TURN relay on this mailbox")
    username = f"{int(time.time()) + TURN_TTL_S}:zeon"
    credential = base64.b64encode(
        hmac.new(TURN_SECRET.encode(), username.encode(), hashlib.sha1).digest()
    ).decode()
    host = request.url.hostname
    return {
        "urls": [f"turn:{host}:{TURN_PORT}?transport=udp"],
        "username": username,
        "credential": credential,
        "ttl": TURN_TTL_S,
    }


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

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=int(os.environ.get("ZEON_PORT", "8080")),
        ssl_certfile=str(tls.cert_file),
        ssl_keyfile=str(tls.key_file),
    )
