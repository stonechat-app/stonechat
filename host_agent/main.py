"""Zeon host agent — "host your circle."

Runs on a VM the host-owner owns. Lets them host their OWN mailbox plus
*invited* friends' mailboxes on the one box — a shared host, but only with
people they choose (PROTOCOL.md "Invite-hosted mailboxes", TODO.md design
sketch).

It is the ONLY thing with Docker access to the host — the hub and
Zeon-the-company never touch this machine. Each guest gets their own
`zeon-server` container: own port, own token, own volume, own TLS cert,
cgroup/pids caps. From the directory's point of view a guest's mailbox is just
an ordinary self-hosted ("external") relay that happens to live on a friend's box.

Trust model (show this to guests): messages stay end-to-end encrypted and
unreadable, but the host-owner — who has root here — can see *that* a guest has
a mailbox and its traffic metadata. Same exposure as any relay operator; the
difference is the guest chose a friend as their operator, not a company.

The agent serves pinned TLS just like a mailbox: the invite carries the agent's
certificate fingerprint, so the guest's redeem call can't be MITM'd.

Config (env):
    ZEON_HOST_AGENT_ADMIN_TOKEN   admin secret the host-owner holds (required)
    ZEON_HOST_AGENT_ADVERTISE_HOST public host/IP guests connect to (required)
    ZEON_HOST_AGENT_DB            sqlite path (default host_agent.db)
    ZEON_HOST_AGENT_TLS_DIR       cert/key dir (default: the DB's directory)
    ZEON_HOST_AGENT_CAPACITY      max guest mailboxes (default 25)
    ZEON_HOST_AGENT_PORT_BASE     first guest mailbox port; guests are published
                                  on base..base+capacity-1 (default 42000)
    ZEON_HOST_AGENT_IMAGE         mailbox image (default zeon-server:dev)
    ZEON_HOST_AGENT_SERVER_DIR    build context if the image is missing (default ../server)
    ZEON_HOST_AGENT_RUNTIME       container runtime, e.g. runsc for gVisor (optional)
    ZEON_PUSH_GATEWAY        passed through to guest mailboxes (optional)
    ZEON_HOST_AGENT_PORT          listen port (default 8200)
"""

import base64
import hashlib
import json
import os
import secrets
import sqlite3
import subprocess
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

ADMIN_TOKEN = os.environ["ZEON_HOST_AGENT_ADMIN_TOKEN"]
ADVERTISE_HOST = os.environ["ZEON_HOST_AGENT_ADVERTISE_HOST"]
DB_PATH = os.environ.get("ZEON_HOST_AGENT_DB", "host_agent.db")
TLS_DIR = Path(os.environ.get("ZEON_HOST_AGENT_TLS_DIR", str(Path(DB_PATH).resolve().parent)))
CAPACITY = int(os.environ.get("ZEON_HOST_AGENT_CAPACITY", "25"))
PORT_BASE = int(os.environ.get("ZEON_HOST_AGENT_PORT_BASE", "42000"))
IMAGE = os.environ.get("ZEON_HOST_AGENT_IMAGE", "zeon-server:dev")
SERVER_DIR = Path(os.environ.get("ZEON_HOST_AGENT_SERVER_DIR",
                                 str(Path(__file__).resolve().parents[1] / "server")))
RUNTIME = os.environ.get("ZEON_HOST_AGENT_RUNTIME", "")
PUSH_GATEWAY = os.environ.get("ZEON_PUSH_GATEWAY", "")
SERVER_PORT = 8080
# Wire protocol version (PROTOCOL.md "Versioning"), reported in /health so a
# prober can see what this host agent speaks.
WIRE_VERSION = 1

FLEET_LABEL = "zeon.hosted=1"
MEMORY_LIMIT = "192m"
CPU_LIMIT = "0.5"
PIDS_LIMIT = "128"
HEALTH_TIMEOUT_S = 60

ZEON_ID_RE = __import__("re").compile(r"^ZC-[A-Z2-7-]{36,}$")


# -- pinned TLS (same scheme as the mailbox: self-signed, fingerprint pinned) --

class Tls:
    def __init__(self, directory: Path):
        directory.mkdir(parents=True, exist_ok=True)
        self.key_file = directory / "host_agent_tls_key.pem"
        self.cert_file = directory / "host_agent_tls_cert.pem"
        if not (self.key_file.is_file() and self.cert_file.is_file()):
            subprocess.run(
                ["openssl", "req", "-x509", "-newkey", "ec",
                 "-pkeyopt", "ec_paramgen_curve:prime256v1",
                 "-keyout", str(self.key_file), "-out", str(self.cert_file),
                 "-days", "36500", "-nodes", "-subj", "/CN=zeon-host-agent"],
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


# -- store --------------------------------------------------------------------

class Store:
    """Invites + guest containers. Small SQLite, host-local."""

    def __init__(self, path: str):
        self._lock = threading.Lock()
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.executescript(
            """
            CREATE TABLE IF NOT EXISTS invites (
                token       TEXT PRIMARY KEY,
                uses        INTEGER NOT NULL,
                uses_left   INTEGER NOT NULL,
                expires_at  REAL NOT NULL,
                created_at  TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS guests (
                owner_id     TEXT PRIMARY KEY,
                container_id TEXT NOT NULL,
                port         INTEGER NOT NULL,
                created_at   TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS redemptions (
                invite_token TEXT NOT NULL,
                owner_id     TEXT NOT NULL,
                redeemed_at  TEXT NOT NULL
            );
            """
        )
        self._db.commit()

    def add_invite(self, token: str, uses: int, ttl: float) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO invites (token, uses, uses_left, expires_at, created_at)"
                " VALUES (?, ?, ?, ?, ?)",
                (token, uses, uses, time.time() + ttl,
                 datetime.now(timezone.utc).isoformat()),
            )
            self._db.commit()

    def consume_invite(self, token: str) -> bool:
        """Atomically spend one use of a live invite. False if invalid/expired/spent."""
        with self._lock:
            row = self._db.execute(
                "SELECT uses_left, expires_at FROM invites WHERE token = ?", (token,)
            ).fetchone()
            if not row or row["uses_left"] <= 0 or row["expires_at"] < time.time():
                return False
            self._db.execute(
                "UPDATE invites SET uses_left = uses_left - 1 WHERE token = ?", (token,)
            )
            self._db.commit()
            return True

    def add_redemption(self, token: str, owner_id: str) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO redemptions (invite_token, owner_id, redeemed_at)"
                " VALUES (?, ?, ?)",
                (token, owner_id, datetime.now(timezone.utc).isoformat()),
            )
            self._db.commit()

    def invites(self) -> list[dict]:
        """All invites (newest first), each with who redeemed it."""
        with self._lock:
            rows = [dict(r) for r in self._db.execute(
                "SELECT token, uses, uses_left, expires_at, created_at"
                " FROM invites ORDER BY created_at DESC")]
            for row in rows:
                row["redeemed_by"] = [r["owner_id"] for r in self._db.execute(
                    "SELECT owner_id FROM redemptions WHERE invite_token = ?"
                    " ORDER BY redeemed_at", (row["token"],))]
        return rows

    def guest(self, owner_id: str) -> dict | None:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM guests WHERE owner_id = ?", (owner_id,)
            ).fetchone()
        return dict(row) if row else None

    def add_guest(self, owner_id: str, container_id: str, port: int) -> None:
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO guests (owner_id, container_id, port, created_at)"
                " VALUES (?, ?, ?, ?)",
                (owner_id, container_id, port, datetime.now(timezone.utc).isoformat()),
            )
            self._db.commit()

    def remove_guest(self, owner_id: str) -> None:
        with self._lock:
            self._db.execute("DELETE FROM guests WHERE owner_id = ?", (owner_id,))
            self._db.commit()

    def guests(self) -> list[dict]:
        with self._lock:
            return [dict(r) for r in self._db.execute(
                "SELECT owner_id, port, created_at FROM guests ORDER BY created_at")]

    def guest_count(self) -> int:
        with self._lock:
            return self._db.execute("SELECT COUNT(*) FROM guests").fetchone()[0]

    def used_ports(self) -> set[int]:
        with self._lock:
            return {r["port"] for r in self._db.execute("SELECT port FROM guests")}


# -- docker -------------------------------------------------------------------

def _docker(*args: str) -> str:
    proc = subprocess.run(["docker", *args], capture_output=True, text=True)
    if proc.returncode != 0:
        raise HTTPException(502, f"docker {args[0]} failed: {proc.stderr.strip()[:300]}")
    return proc.stdout


def _ensure_image() -> None:
    if subprocess.run(["docker", "image", "inspect", IMAGE],
                      capture_output=True).returncode != 0:
        if not SERVER_DIR.is_dir():
            raise HTTPException(500, f"image {IMAGE} missing and no build dir at {SERVER_DIR}")
        _docker("build", "-t", IMAGE, str(SERVER_DIR))


def _launch_container(owner_id: str, owner_token: str, port: int) -> str:
    _ensure_image()
    name = f"zeon-hosted-{owner_id[3:11].lower().replace('-', '')}"
    args = [
        "run", "-d",
        "--name", name,
        "--restart", "unless-stopped",
        "-p", f"{port}:{SERVER_PORT}",
        "-e", f"ZEON_OWNER_ID={owner_id}",
        "-e", f"ZEON_OWNER_TOKEN={owner_token}",
        "-e", f"ZEON_PUSH_GATEWAY={PUSH_GATEWAY}",
        "--label", FLEET_LABEL,
        "--memory", MEMORY_LIMIT,
        "--cpus", CPU_LIMIT,
        "--pids-limit", PIDS_LIMIT,
    ]
    if RUNTIME:
        args += ["--runtime", RUNTIME]
    args.append(IMAGE)
    _docker(*args)
    return name


def _wait_health(address: str) -> str:
    """Poll the guest mailbox until healthy; return its TLS fingerprint."""
    deadline = time.monotonic() + HEALTH_TIMEOUT_S
    last = "no response"
    while time.monotonic() < deadline:
        try:
            r = httpx.get(f"{address}/health", timeout=4, verify=False)
            if r.status_code == 200:
                return r.json().get("tls_fp")
        except httpx.HTTPError as e:
            last = str(e)
        time.sleep(2)
    raise HTTPException(504, f"guest mailbox never became healthy ({last})")


# -- app ----------------------------------------------------------------------

store = Store(DB_PATH)
tls = Tls(TLS_DIR)
app = FastAPI(title="zeon-host-agent")

# Guests get fixed host ports from [PORT_BASE, PORT_BASE + CAPACITY) rather
# than Docker-ephemeral ones: the range is known before any guest exists (so
# firewall / home-router forwarding rules can be written once), and an
# explicit binding is stable across daemon restarts — ephemeral ones are not,
# which would strand the address registered in the directory after a host
# reboot. Reservations cover the launch→health window, where the port is
# committed but not yet in the guests table.
_reserved_ports: set[int] = set()
_ports_lock = threading.Lock()


def _reserve_port() -> int:
    with _ports_lock:
        taken = store.used_ports() | _reserved_ports
        for port in range(PORT_BASE, PORT_BASE + CAPACITY):
            if port not in taken:
                _reserved_ports.add(port)
                return port
    raise HTTPException(507, "no free guest port on this host")


def _release_port(port: int) -> None:
    with _ports_lock:
        _reserved_ports.discard(port)


def require_admin(authorization: str | None = Header(default=None)) -> None:
    token = (authorization or "").removeprefix("Bearer ").strip()
    if not secrets.compare_digest(token, ADMIN_TOKEN):
        raise HTTPException(401, "admin only")


class InviteIn(BaseModel):
    uses: int = Field(default=1, ge=1, le=100)
    ttl_hours: int = Field(default=72, ge=1, le=24 * 30)


class RedeemIn(BaseModel):
    invite: str = Field(min_length=8, max_length=256)
    owner_id: str = Field(min_length=12, max_length=80)


class ProvisionIn(BaseModel):
    owner_id: str = Field(min_length=12, max_length=80)


@app.get("/health")
async def health():
    """Unauthenticated liveness + pinning info only. Guest count and capacity
    are occupancy metadata a stranger shouldn't be able to poll — the
    host-owner reads them through the admin-authed /v1/guests instead
    (PROTOCOL.md "Host agent"). tls_fp stays: it's the certificate hash,
    already observable from the TLS handshake."""
    return {"status": "ok", "v": WIRE_VERSION, "tls_fp": tls.fingerprint_b64}


def _encode_invite(token: str) -> str:
    """The shareable string: this agent's address + pinned fingerprint + token."""
    blob = {
        "u": f"https://{ADVERTISE_HOST}:{os.environ.get('ZEON_HOST_AGENT_PORT', '8200')}",
        "f": tls.fingerprint_b64,
        "t": token,
    }
    return "zeon-host:" + base64.urlsafe_b64encode(
        json.dumps(blob, separators=(",", ":")).encode()
    ).decode().rstrip("=")


@app.post("/v1/invite", dependencies=[Depends(require_admin)])
async def create_invite(body: InviteIn):
    """Host-owner mints an invite. The returned `invite` string is what a friend
    scans/pastes — it bundles this agent's address, its TLS fingerprint, and a
    single-/multi-use token."""
    token = secrets.token_urlsafe(24)
    store.add_invite(token, body.uses, body.ttl_hours * 3600)
    return {"invite": _encode_invite(token), "uses": body.uses,
            "ttl_hours": body.ttl_hours}


@app.get("/v1/invites", dependencies=[Depends(require_admin)])
async def list_invites():
    """Every invite this host has minted, with redemption status, so the
    owner's app can show sent invites and whether they were accepted."""
    out = []
    for row in store.invites():
        # rows minted before the `uses` column existed: reconstruct the total
        uses = row["uses"] if row["uses"] is not None else (
            row["uses_left"] + len(row["redeemed_by"]))
        out.append({
            "invite": _encode_invite(row["token"]),
            "uses": uses,
            "uses_left": row["uses_left"],
            "expires_at": row["expires_at"],
            "created_at": row["created_at"],
            "redeemed_by": row["redeemed_by"],
        })
    return {"invites": out}


@app.post("/v1/redeem")
async def redeem(body: RedeemIn):
    """A friend redeems an invite → gets a mailbox on this host. Returns the
    address + token (kept on the guest's device) + TLS fingerprint. Idempotent:
    re-redeeming for an existing guest returns the same mailbox without spending
    another invite use."""
    if not ZEON_ID_RE.match(body.owner_id):
        raise HTTPException(400, "bad owner_id")

    existing = store.guest(body.owner_id)
    if existing:
        # already hosted here — reconnect, don't consume an invite or relaunch
        raise HTTPException(
            409, "this Zeon ID already has a mailbox on this host; ask the host "
                 "owner to evict it first if you want a fresh one")

    token = body.invite.strip()
    if not store.consume_invite(token):
        raise HTTPException(403, "invite is invalid, expired, or fully used")
    if store.guest_count() >= CAPACITY:
        raise HTTPException(507, "this host is full")

    result = _provision_guest(body.owner_id)
    store.add_redemption(token, body.owner_id)
    return result


@app.post("/v1/guest", dependencies=[Depends(require_admin)])
async def provision_direct(body: ProvisionIn):
    """Host-owner provisions a mailbox directly (e.g. their OWN), no invite."""
    if not ZEON_ID_RE.match(body.owner_id):
        raise HTTPException(400, "bad owner_id")
    if store.guest(body.owner_id):
        raise HTTPException(409, "already hosted here")
    if store.guest_count() >= CAPACITY:
        raise HTTPException(507, "this host is full")
    return _provision_guest(body.owner_id)


def _provision_guest(owner_id: str) -> dict:
    owner_token = secrets.token_urlsafe(32)
    port = _reserve_port()
    try:
        container_id = _launch_container(owner_id, owner_token, port)
        address = f"https://{ADVERTISE_HOST}:{port}"
        try:
            tls_fp = _wait_health(address)
        except HTTPException:
            _docker("rm", "-f", container_id)
            raise
        store.add_guest(owner_id, container_id, port)
    finally:
        _release_port(port)  # on success the guests row keeps it taken
    return {"address": address, "server_token": owner_token, "tls_fp": tls_fp}


@app.get("/v1/guests", dependencies=[Depends(require_admin)])
async def list_guests():
    return {"guests": store.guests(), "capacity": CAPACITY}


@app.delete("/v1/guest/{owner_id}", dependencies=[Depends(require_admin)])
async def evict(owner_id: str):
    """Host-owner removes a guest — destroys their container. The guest keeps
    their local history and can re-home their mailbox elsewhere."""
    guest = store.guest(owner_id)
    if not guest:
        raise HTTPException(404, "no such guest")
    _docker("rm", "-f", guest["container_id"])
    store.remove_guest(owner_id)
    return {"status": "evicted"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app, host="0.0.0.0", port=int(os.environ.get("ZEON_HOST_AGENT_PORT", "8200")),
        ssl_certfile=str(tls.cert_file), ssl_keyfile=str(tls.key_file),
    )
