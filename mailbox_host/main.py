"""Stonechat mailbox host — the one thing that runs mailboxes.

Every box that holds mailboxes runs this, and nothing else does. Two ways in,
and they are the same machinery with different authority:

* **Invite mode** (the default, "host your circle"): the host-owner runs this
  on a VM they own to host their OWN mailbox plus *invited* friends' — a shared
  host, but only with people they choose (PROTOCOL.md "Invite-hosted
  mailboxes"). From the directory's point of view a guest's mailbox is an
  ordinary self-hosted ("external") relay that happens to live on a friend's box.
* **Managed mode** (``STONECHAT_MAILBOX_HOST_MANAGED=1``): the box belongs to a
  hub operator, and a hub places mailboxes on it over this same API — the
  shared tier the Mailbox plan sells (hub/app/providers/mailbox_host.py).
  Invites are refused outright: a managed host has exactly one authority, and a
  box that answered to both the hub and whoever held an invite token would be a
  box nobody is accountable for.

This replaced the `fleet` provider, which drove a bare Docker daemon over SSH
from the hub. Same containers, same limits, same pinned ports — but the hub now
holds an admin token for a scoped API instead of membership in the `docker`
group on every mailbox host, which was root there in all but name.

It is the ONLY thing with Docker access to the host — the hub and
Stonechat-the-company never touch this machine's daemon. Each guest gets their
own `stonechat-relay` container: own port, own token, own volume, own TLS cert,
cgroup/pids caps.

Trust model (show this to guests): messages stay end-to-end encrypted and
unreadable, but the host-owner — who has root here — can see *that* a guest has
a mailbox and its traffic metadata. Same exposure as any relay operator; the
difference is the guest chose a friend as their operator, not a company.

The mailbox host serves pinned TLS just like a mailbox: the invite carries its
certificate fingerprint, so the guest's redeem call can't be MITM'd. The invite
also carries the redeem token, so it is itself a secret to be shared privately.

Config (env):
    STONECHAT_MAILBOX_HOST_ADMIN_TOKEN     admin secret the host-owner holds (required)
    STONECHAT_MAILBOX_HOST_ADVERTISE_HOST  public host/IP guests connect to (required)
    STONECHAT_MAILBOX_HOST_MANAGED         1 → managed by a hub; invites refused
    STONECHAT_MAILBOX_HOST_DB              sqlite path (default mailbox_host.db)
    STONECHAT_MAILBOX_HOST_TLS_DIR         cert/key dir (default: the DB's directory)
    STONECHAT_MAILBOX_HOST_RELAY_DIR       where uploaded relay binaries are kept
                                           (default: the DB's directory)
    STONECHAT_MAILBOX_HOST_CAPACITY        max guest mailboxes (default 25)
    STONECHAT_MAILBOX_HOST_PORT_BASE       first guest mailbox port; guests are published
                                           on base..base+capacity-1 (default 42000)
    STONECHAT_MAILBOX_HOST_IMAGE           mailbox image, pulled if not present locally
                                           (default ghcr.io/stonechat-app/relay:latest).
                                           Managed mode refuses the floating default —
                                           see _relay_image().
    STONECHAT_MAILBOX_HOST_RUNTIME         container runtime, e.g. runsc for gVisor (optional)
    STONECHAT_MAILBOX_HOST_PORT            listen port (default 8200)
    STONECHAT_PUSH_GATEWAY                 passed through to guest mailboxes (optional)
    STONECHAT_PUSH_MINT_SECRET             mints a per-mailbox push key when the
                                           caller supplies none (optional)
"""

import asyncio
import base64
import hashlib
import hmac
import json
import os
import secrets
import shutil
import sqlite3
import subprocess
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field

# The shortest admin token this will start with. Not a strength meter — it is
# here because the variable being *set* says nothing about it being *filled in*:
# .env.example ships it empty, and an empty token is one every request with no
# Authorization header presents.
MIN_ADMIN_TOKEN_CHARS = 16


def _required(name: str, min_chars: int = 1) -> str:
    value = os.environ.get(name, "").strip()
    if len(value) < min_chars:
        raise SystemExit(
            f"{name} is {'empty' if not value else 'too short'}: set it to at "
            f"least {min_chars} characters before starting the mailbox host"
            + (" (generate one with `openssl rand -hex 24`)"
               if min_chars > 1 else "")
        )
    return value


ADMIN_TOKEN = _required("STONECHAT_MAILBOX_HOST_ADMIN_TOKEN", MIN_ADMIN_TOKEN_CHARS)
ADVERTISE_HOST = _required("STONECHAT_MAILBOX_HOST_ADVERTISE_HOST")
MANAGED = os.environ.get("STONECHAT_MAILBOX_HOST_MANAGED", "").strip() not in ("", "0")
DB_PATH = os.environ.get("STONECHAT_MAILBOX_HOST_DB", "mailbox_host.db")
TLS_DIR = Path(os.environ.get("STONECHAT_MAILBOX_HOST_TLS_DIR", str(Path(DB_PATH).resolve().parent)))
RELAY_DIR = Path(os.environ.get(
    "STONECHAT_MAILBOX_HOST_RELAY_DIR", str(Path(DB_PATH).resolve().parent)))
CAPACITY = int(os.environ.get("STONECHAT_MAILBOX_HOST_CAPACITY", "25"))
PORT_BASE = int(os.environ.get("STONECHAT_MAILBOX_HOST_PORT_BASE", "42000"))
DEFAULT_IMAGE = "ghcr.io/stonechat-app/relay:latest"
IMAGE = os.environ.get("STONECHAT_MAILBOX_HOST_IMAGE", DEFAULT_IMAGE)
RUNTIME = os.environ.get("STONECHAT_MAILBOX_HOST_RUNTIME", "")
PUSH_GATEWAY = os.environ.get("STONECHAT_PUSH_GATEWAY", "")
PUSH_MINT_SECRET = os.environ.get("STONECHAT_PUSH_MINT_SECRET", "")
# A relay is a few megabytes. The cap is what stops an upload from being read
# into memory without limit; it is not a statement about how big one may get.
MAX_RELAY_BYTES = 64 * 1024 * 1024


SERVER_PORT = 8080
# The browser transport (QUIC, so UDP — relay/src/wt.rs). Published on the SAME
# host port number as the mailbox's TCP port: one number per guest, so the
# firewall rule for the guest range covers both protocols and there is no second
# range to forget. TCP and UDP bindings of one number do not collide.
WT_PORT = 8443
# Wire protocol version (PROTOCOL.md "Versioning"), reported in /health so a
# prober can see what this mailbox host speaks.
WIRE_VERSION = 1

HOSTED_LABEL = "stonechat.hosted=1"

# Measured on a real host rather than guessed (2026-08-20, with the streaming
# relay): under 25 concurrent 64 MiB blob downloads, three concurrent uploads,
# 1200 queued envelopes and mixed traffic, a container's *unreclaimable* working
# set peaked at ~9 MiB — anon plus slab. Everything above that is page cache,
# which cgroup v2 charges here but reclaims under pressure rather than
# OOM-killing. Runs at 48m, 32m and even 24m completed with zero oom_kill and no
# measurable slowdown (the CPU cap dominates).
#
# 48m is deliberately ~5x the measured peak rather than a tight fit: the
# measurement is minutes long and says nothing about SQLite page cache or
# allocator drift over months. The old 192m was inherited from the retired
# Python relay. Watch memory.events on live containers — under `--restart
# unless-stopped` an OOM kill is otherwise silent.
MEMORY_LIMIT = "48m"
CPU_LIMIT = "0.5"
PIDS_LIMIT = "128"
HEALTH_TIMEOUT_S = 60

# Where the entrypoint lives inside the image, and where the outgoing binary is
# parked so a failed roll has something to go back to (scripts/roll_relay.py).
RELAY_TARGET = "/stonechat-relay"
RELAY_BACKUP = "/stonechat-relay.prev"

# Runtime image for a mailbox built from a prebuilt binary. Byte-for-byte the
# stage relay/Dockerfile ends in, and the same text as
# hub/app/providers/bootstrap.py RELAY_RUNTIME_DOCKERFILE — a mailbox must not
# depend on which of the two built it.
RELAY_RUNTIME_DOCKERFILE = """\
FROM scratch
COPY stonechat-relay /stonechat-relay
ENV STONECHAT_DB=/data/mailbox.db
ENV STONECHAT_BLOBS=/data/blobs
ENV STONECHAT_TLS_DIR=/data
EXPOSE 8080
ENTRYPOINT ["/stonechat-relay"]
"""

STONECHAT_ID_RE = __import__("re").compile(r"^SC-[A-Z2-7-]{36,}$")


# -- pinned TLS (same scheme as the mailbox: self-signed, fingerprint pinned) --

class Tls:
    def __init__(self, directory: Path):
        directory.mkdir(parents=True, exist_ok=True)
        self.key_file = directory / "mailbox_host_tls_key.pem"
        self.cert_file = directory / "mailbox_host_tls_cert.pem"
        if not (self.key_file.is_file() and self.cert_file.is_file()):
            subprocess.run(
                ["openssl", "req", "-x509", "-newkey", "ec",
                 "-pkeyopt", "ec_paramgen_curve:prime256v1",
                 "-keyout", str(self.key_file), "-out", str(self.cert_file),
                 "-days", "36500", "-nodes", "-subj", "/CN=stonechat-mailbox-host"],
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
            -- Which relay binary new guests get. A row, not an env var: it is
            -- set by uploading a binary (POST /v1/relay) and must survive the
            -- restart that follows, or the next guest silently lands on
            -- whatever the image tag used to mean.
            CREATE TABLE IF NOT EXISTS settings (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            """
        )
        self._db.commit()

    def setting(self, key: str) -> str | None:
        with self._lock:
            row = self._db.execute(
                "SELECT value FROM settings WHERE key = ?", (key,)
            ).fetchone()
        return row["value"] if row else None

    def set_setting(self, key: str, value: str) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO settings (key, value) VALUES (?, ?)"
                " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
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
        # container_id included: rolling a release and reading a relay's build
        # both address the container, and re-deriving its name from the owner id
        # would be a second copy of the naming rule in _launch_container.
        with self._lock:
            return [dict(r) for r in self._db.execute(
                "SELECT owner_id, container_id, port, created_at FROM guests"
                " ORDER BY created_at")]

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


def _build_id(data: bytes) -> str:
    """The hash the relay computes for itself at boot and reports as `build` on
    /status: BLAKE2b-256 of the executable, first 16 hex chars (see
    relay/src/main.rs `own_build_id`). Deriving it here from the bytes we are
    about to ship is what makes the post-roll check mean anything — and it is
    the same string hub/app/providers/local.py puts in the image tag, so
    `docker images` and a relay's own answer can be read against each other."""
    return hashlib.blake2b(data, digest_size=32).hexdigest()[:16]


def _mint_push_key() -> str:
    """A relay push credential, or "" when no mint secret is configured.

    Mirrors hub/app/pushkey.py — `pk_<random>:HMAC-SHA256(secret, key_id)`,
    which the gateway verifies offline. Duplicated rather than imported: the
    mailbox host is its own deployable and does not ship the hub package. In
    managed mode the hub mints the key and passes it, so this only fires for a
    host-owner running their own gateway."""
    if not PUSH_MINT_SECRET:
        return ""
    key_id = "pk_" + secrets.token_hex(8)
    tag = hmac.new(PUSH_MINT_SECRET.encode(), key_id.encode(),
                   hashlib.sha256).hexdigest()
    return f"{key_id}:{tag}"


def _installed_relay() -> tuple[str, str] | None:
    """(build id, binary path) of the relay uploaded through POST /v1/relay, or
    None. The file is checked, not just the row: a state directory restored
    without it would otherwise report a build it cannot run."""
    build = store.setting("relay_build")
    if not build:
        return None
    path = RELAY_DIR / f"stonechat-relay-{build}"
    return (build, str(path)) if path.is_file() else None


def _extract_relay_from_image(image: str) -> tuple[str, str]:
    """Pull the relay binary back out of a mailbox image: (build id, path).

    This is what lets a registry be the single source of truth. A mailbox's data
    lives in its container's writable layer with no volume behind it, so an
    upgrade can never be `docker run` on a new image — it has to be a binary
    swap, and a swap needs a file. Rather than make the operator upload the same
    bytes a second time, take them from the image the host is already pinned to.

    Cached under RELAY_DIR by build id, so a second roll copies nothing.
    """
    _ensure_image_present(image)
    RELAY_DIR.mkdir(parents=True, exist_ok=True)
    tmp = RELAY_DIR / f".extract-{os.getpid()}"
    cid = _docker("create", image).strip()
    try:
        _docker("cp", f"{cid}:{RELAY_TARGET}", str(tmp))
    finally:
        subprocess.run(["docker", "rm", "-f", cid], capture_output=True)
    try:
        build = _build_id(tmp.read_bytes())
        path = RELAY_DIR / f"stonechat-relay-{build}"
        if not path.is_file():
            tmp.chmod(0o755)
            tmp.replace(path)
        return build, str(path)
    finally:
        tmp.unlink(missing_ok=True)


def _roll_source() -> tuple[str, str]:
    """(build id, path) of the binary a roll should swap in.

    An uploaded binary wins; otherwise the image this host launches new mailboxes
    from, which keeps "what new guests get" and "what running guests are rolled
    to" the same artifact by construction.
    """
    installed = _installed_relay()
    if installed is not None:
        _recheck_installed(*installed)
        return installed
    return _extract_relay_from_image(_relay_image())


def _recheck_installed(build: str, path: str) -> None:
    """The uploaded binary, hashed again at the moment it is about to be
    copied into mailboxes — not trusted because its file name says what it is.
    This is what notices a file changed on disk since the upload, before it
    runs anywhere rather than after the first mailbox reports an unexpected
    build."""
    if _build_id(Path(path).read_bytes()) != build:
        raise HTTPException(
            409, f"the installed relay no longer hashes to {build}; upload it "
                 "again")


def _build_relay_image(binary: Path, build: str) -> str:
    """Wrap a relay binary in a `FROM scratch` image, tagged by its build id.

    Not a compile — a two-line COPY of a static binary, seconds at most. Tagging
    by content is what keeps a new upload from being shadowed by a cached image
    of the same name, which is how a "rolled" host silently keeps launching the
    old relay for every new guest.
    """
    tag = f"stonechat-relay:{build}"
    if subprocess.run(["docker", "image", "inspect", tag],
                      capture_output=True).returncode == 0:
        return tag
    with tempfile.TemporaryDirectory() as td:
        shutil.copy(binary, Path(td) / "stonechat-relay")
        (Path(td) / "Dockerfile").write_text(RELAY_RUNTIME_DOCKERFILE)
        _docker("build", "-t", tag, td)
    return tag


def _relay_image() -> str:
    """The image new guest mailboxes are launched from.

    An uploaded binary wins: it is the hub's own artifact, pinned by content,
    and the only thing a managed host should ever run. Otherwise fall back to
    the configured image, pulling it once.

    Managed mode refuses the floating default. `:latest` means the hub cannot
    say which relay its customers are running, and two hosts provisioned a week
    apart would silently differ — the exact drift the fleet provider avoided by
    shipping one pinned artifact everywhere. Pin a digest, or upload a binary.
    """
    installed = _installed_relay()
    if installed is not None:
        build, path = installed
        return _build_relay_image(Path(path), build)
    if MANAGED and IMAGE == DEFAULT_IMAGE:
        raise HTTPException(
            503,
            "this host is managed but has no pinned relay: upload one with "
            "POST /v1/relay (scripts/roll_relay.py), or set "
            "STONECHAT_MAILBOX_HOST_IMAGE to a digest-pinned image",
        )
    _ensure_image_present(IMAGE)
    return IMAGE


def _ensure_image_present(image: str) -> None:
    """Pull the image unless this daemon already has it."""
    if subprocess.run(["docker", "image", "inspect", image],
                      capture_output=True).returncode != 0:
        _docker("pull", image)


def _launch_container(owner_id: str, owner_token: str, port: int,
                      push_key: str, push_gateway: str) -> str:
    image = _relay_image()
    name = f"stonechat-hosted-{owner_id[3:11].lower().replace('-', '')}"
    args = [
        "run", "-d",
        "--name", name,
        "--restart", "unless-stopped",
        "-p", f"{port}:{SERVER_PORT}",
        # The browser transport. Same host port number, UDP — see WT_PORT.
        "-p", f"{port}:{WT_PORT}/udp",
        # The name the browser transport's certificates must carry. The relay
        # cannot discover it (inside the container it sees a private address),
        # and a certificate without a matching SAN is refused by browsers with
        # an error that reads like a pin mismatch.
        "-e", f"STONECHAT_WT_ADVERTISE={ADVERTISE_HOST}",
        "-e", f"STONECHAT_OWNER_ID={owner_id}",
        "-e", f"STONECHAT_OWNER_TOKEN={owner_token}",
        "-e", f"STONECHAT_PUSH_GATEWAY={push_gateway}",
        "-e", f"STONECHAT_PUSH_KEY={push_key}",
        "--label", HOSTED_LABEL,
        "--memory", MEMORY_LIMIT,
        "--cpus", CPU_LIMIT,
        "--pids-limit", PIDS_LIMIT,
    ]
    if RUNTIME:
        args += ["--runtime", RUNTIME]
    args.append(image)
    _docker(*args)
    return name


def _local_url(port: int) -> str:
    """How this process reaches a guest mailbox it just started.

    Loopback, not ADVERTISE_HOST: this is a liveness check on a container on
    this box, and routing it out to the public address makes it fail on every
    host that cannot reach its own external IP (hairpin NAT — AWS, and most home
    routers). It says nothing about outside reachability, which is the cloud
    firewall's business and was never what this proved.
    """
    return f"https://127.0.0.1:{port}"


def _wait_health(port: int) -> str:
    """Poll the guest mailbox until healthy; return its TLS fingerprint."""
    deadline = time.monotonic() + HEALTH_TIMEOUT_S
    last = "no response"
    while time.monotonic() < deadline:
        try:
            r = httpx.get(f"{_local_url(port)}/health", timeout=4, verify=False)
            if r.status_code == 200:
                return r.json().get("tls_fp")
        except httpx.HTTPError as e:
            last = str(e)
        time.sleep(2)
    raise HTTPException(504, f"guest mailbox never became healthy ({last})")


# -- rolling the relay inside running mailboxes --------------------------------
#
# A mailbox keeps its queue, prekeys, TLS key and WebTransport certificate
# schedule in the container's own writable layer, with no volume behind it —
# that is the privacy property. So `docker run` with a new image is not an
# upgrade path: it would hand every guest a new, empty mailbox. A release is a
# swap instead — copy the binary over the entrypoint, restart, verify the
# process came back on the build we shipped, and roll that one guest back if it
# did not. scripts/roll_relay.py drives this, one guest at a time.


def _guest_owner_token(container: str) -> str:
    """Read the mailbox's own token out of the container's env.

    /status is owner-authenticated, and the point of the roll is to ask the
    relay which binary it is *running* — a hash of the file on disk would only
    say the copy landed. The token is already on this box (this process created
    it), so reading it back beats storing a second copy in the DB.
    """
    env = _docker("inspect", "-f",
                  "{{range .Config.Env}}{{println .}}{{end}}", container)
    return next(
        (line.split("=", 1)[1] for line in env.splitlines()
         if line.startswith("STONECHAT_OWNER_TOKEN=")),
        "",
    )


def _running_build(port: int, owner_token: str) -> str | None:
    """Which binary the relay is running, asked over its own API.

    Never raises, and the difference between the two falsy answers matters:
    None means it did not answer at all (down, or not up yet), "" means it
    answered but reports no build — an older relay, healthy but unidentifiable.
    Conflating them would make a rollback look like a dead mailbox.
    """
    try:
        r = httpx.get(f"{_local_url(port)}/status", params={"token": owner_token},
                      timeout=5, verify=False)
    except httpx.HTTPError:
        return None
    if r.status_code != 200:
        return None
    try:
        return str(r.json().get("build") or "")
    except ValueError:
        return None


def _wait_build(port: int, owner_token: str) -> str | None:
    deadline = time.monotonic() + HEALTH_TIMEOUT_S
    while time.monotonic() < deadline:
        got = _running_build(port, owner_token)
        if got is not None:
            return got
        time.sleep(1)
    return None


def _roll_guest(guest: dict, binary: Path, want: str, force: bool) -> dict:
    """Swap one mailbox onto `binary`. Returns a result dict; never raises."""
    container, port = guest["container_id"], guest["port"]
    owner = guest["owner_id"]
    try:
        token = _guest_owner_token(container)
    except HTTPException as e:
        return {"owner_id": owner, "ok": False, "detail": str(e.detail)}
    before = _running_build(port, token)
    if before is not None and before == want:
        return {"owner_id": owner, "ok": True, "from": before, "to": want,
                "detail": "already on this build"}
    # Refuse a mailbox that is already down: the rollback target is whatever sits
    # at the entrypoint right now, so rolling one of these parks an unverified
    # binary as the fallback, and the check afterwards cannot tell a bad new
    # build from the failure that was already there.
    if before is None and not force:
        return {"owner_id": owner, "ok": False, "from": None,
                "detail": "down before the roll; use force to override"}

    # The outgoing binary has to be pulled out to local disk: `docker cp` always
    # has one foot on the host, so a container-to-container rollback silently
    # does nothing. The in-container copy at RELAY_BACKUP is for a human
    # arriving later, not for this code.
    tmp = Path(tempfile.gettempdir()) / f".stonechat-prev-{container}"
    have_backup = False
    try:
        try:
            _docker("cp", f"{container}:{RELAY_TARGET}", str(tmp))
            have_backup = tmp.is_file()
            subprocess.run(["docker", "cp", str(tmp), f"{container}:{RELAY_BACKUP}"],
                           capture_output=True)
            _docker("cp", str(binary), f"{container}:{RELAY_TARGET}")
            _docker("restart", container)
            after = _wait_build(port, token)
            why = None if after == want else (
                "did not come back" if after is None else f"reports {after}")
        except HTTPException as e:
            after, why = None, str(e.detail)

        if why is None:
            return {"owner_id": owner, "ok": True, "from": before, "to": after}

        if not have_backup:
            return {"owner_id": owner, "ok": False, "from": before,
                    "detail": f"{why}; NO BACKUP to roll back to — needs a human"}
        subprocess.run(["docker", "cp", str(tmp), f"{container}:{RELAY_TARGET}"],
                       capture_output=True)
        subprocess.run(["docker", "restart", container], capture_output=True)
    finally:
        tmp.unlink(missing_ok=True)

    recovered = _wait_build(port, token)
    if recovered is None:
        return {"owner_id": owner, "ok": False, "from": before,
                "detail": f"{why}; ROLLBACK ALSO FAILED — mailbox down, needs a human"}
    return {"owner_id": owner, "ok": False, "from": before, "rolled_back_to": recovered,
            "detail": f"{why}; rolled back"}


# -- app ----------------------------------------------------------------------

store = Store(DB_PATH)
tls = Tls(TLS_DIR)
app = FastAPI(title="stonechat-mailbox-host")

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
    # Bytes, not str: compare_digest raises on non-ASCII text, which would turn
    # a wrong token into a 500. And never an empty one, whatever ADMIN_TOKEN is.
    if not token or not secrets.compare_digest(token.encode(), ADMIN_TOKEN.encode()):
        raise HTTPException(401, "admin only")


def require_invites() -> None:
    """Invites exist only on a host someone owns personally.

    A managed host answers to its hub and to nothing else. Leaving the invite
    door open there would put mailboxes on it that the hub's directory, billing
    and reaper know nothing about, on ports it thinks are free — and make the
    box accountable to two parties at once.
    """
    if MANAGED:
        raise HTTPException(
            403, "this host is managed by a hub; invites are disabled on it")


class InviteIn(BaseModel):
    uses: int = Field(default=1, ge=1, le=100)
    ttl_hours: int = Field(default=72, ge=1, le=24 * 30)


class RedeemIn(BaseModel):
    invite: str = Field(min_length=8, max_length=256)
    owner_id: str = Field(min_length=12, max_length=80)


class ProvisionIn(BaseModel):
    owner_id: str = Field(min_length=12, max_length=80)
    # Supplied by a hub, which has already recorded it as the mailbox token it
    # will hand the owner's app (hub/app/main.py mints one per mailbox). Absent
    # → this host generates it, which is the invite flow.
    owner_token: str | None = Field(default=None, min_length=16, max_length=128)
    # Also the hub's, because only it holds STONECHAT_PUSH_MINT_SECRET. Absent →
    # minted locally if this host has a secret of its own, else empty (the
    # gateway then accepts bare pings, or there is no gateway at all).
    push_key: str | None = Field(default=None, max_length=256)
    # Where mailboxes send their wake-ups. The caller's, so the address has one
    # home per mode: a hub knows its own gateway and passes it here, while an
    # invite host-owner configures STONECHAT_PUSH_GATEWAY on this box. Absent
    # falls back to that, so nothing changes for invite hosts.
    push_gateway: str | None = Field(default=None, max_length=256)


class RollIn(BaseModel):
    only: str | None = Field(default=None, max_length=80)  # one owner_id
    dry_run: bool = False
    # Roll a mailbox that is already down. Its rollback target will be a binary
    # nobody verified, so this is a deliberate override, never a default.
    force: bool = False


@app.get("/health")
async def health():
    """Unauthenticated liveness + pinning info only. Guest count and capacity
    are occupancy metadata a stranger shouldn't be able to poll — the
    host-owner reads them through the admin-authed /v1/guests instead
    (PROTOCOL.md "Mailbox host"). tls_fp stays: it's the certificate hash,
    already observable from the TLS handshake."""
    return {"status": "ok", "v": WIRE_VERSION, "tls_fp": tls.fingerprint_b64}


def _encode_invite(token: str) -> str:
    """The shareable string: this host's address + pinned fingerprint + token."""
    blob = {
        "u": f"https://{ADVERTISE_HOST}:{os.environ.get('STONECHAT_MAILBOX_HOST_PORT', '8200')}",
        "f": tls.fingerprint_b64,
        "t": token,
    }
    return "stonechat-host:" + base64.urlsafe_b64encode(
        json.dumps(blob, separators=(",", ":")).encode()
    ).decode().rstrip("=")


@app.post("/v1/invite", dependencies=[Depends(require_admin), Depends(require_invites)])
async def create_invite(body: InviteIn):
    """Host-owner mints an invite. The returned `invite` string is what a friend
    scans/pastes — it bundles this host's address, its TLS fingerprint, and a
    single-/multi-use token."""
    token = secrets.token_urlsafe(24)
    store.add_invite(token, body.uses, body.ttl_hours * 3600)
    return {"invite": _encode_invite(token), "uses": body.uses,
            "ttl_hours": body.ttl_hours}


@app.get("/v1/invites", dependencies=[Depends(require_admin), Depends(require_invites)])
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


@app.post("/v1/redeem", dependencies=[Depends(require_invites)])
def redeem(body: RedeemIn):
    """A friend redeems an invite → gets a mailbox on this host. Returns the
    address + token (kept on the guest's device) + TLS fingerprint. Not
    idempotent: redeeming for an ID that already has a mailbox here is a 409
    and spends no invite use."""
    if not STONECHAT_ID_RE.match(body.owner_id):
        raise HTTPException(400, "bad owner_id")

    existing = store.guest(body.owner_id)
    if existing:
        # already hosted here — reconnect, don't consume an invite or relaunch
        raise HTTPException(
            409, "this Stonechat ID already has a mailbox on this host; ask the host "
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
def provision_direct(body: ProvisionIn):
    """Provision a mailbox directly, no invite: the host-owner's OWN mailbox, or
    — on a managed host — one the hub is placing here.

    Sync, not async: everything below shells out to Docker and then waits for a
    relay to come up, which is seconds. FastAPI runs a `def` handler in the
    threadpool, so /health keeps answering while it does.
    """
    if not STONECHAT_ID_RE.match(body.owner_id):
        raise HTTPException(400, "bad owner_id")
    if store.guest(body.owner_id):
        raise HTTPException(409, "already hosted here")
    if store.guest_count() >= CAPACITY:
        raise HTTPException(507, "this host is full")
    return _provision_guest(body.owner_id, owner_token=body.owner_token,
                            push_key=body.push_key,
                            push_gateway=body.push_gateway)


def _provision_guest(owner_id: str, owner_token: str | None = None,
                     push_key: str | None = None,
                     push_gateway: str | None = None) -> dict:
    # A caller-supplied token is the hub's: it has already stored that value as
    # the mailbox token it will hand the owner's app, so minting our own here
    # would strand the mailbox behind a token nobody holds.
    owner_token = owner_token or secrets.token_urlsafe(32)
    push_key = push_key if push_key is not None else _mint_push_key()
    push_gateway = push_gateway if push_gateway is not None else PUSH_GATEWAY
    port = _reserve_port()
    try:
        container_id = _launch_container(owner_id, owner_token, port, push_key,
                                         push_gateway)
        address = f"https://{ADVERTISE_HOST}:{port}"
        try:
            tls_fp = _wait_health(port)
        except HTTPException:
            _docker("rm", "-f", container_id)
            raise
        store.add_guest(owner_id, container_id, port)
    finally:
        _release_port(port)  # on success the guests row keeps it taken
    return {
        "address": address,
        "mailbox_token": owner_token,
        "tls_fp": tls_fp,
        # Same host port number, UDP. Published rather than derived: nothing
        # else can tell whether this host maps the browser transport at all.
        "wt_address": f"{ADVERTISE_HOST}:{port}",
    }


@app.get("/v1/guests", dependencies=[Depends(require_admin)])
async def list_guests():
    """Occupancy, which is also how a hub places: it reads `count` and
    `capacity` across its hosts and picks the emptiest one in the country the
    user asked for (hub/app/providers/mailbox_host.py)."""
    guests = store.guests()
    return {"guests": guests, "count": len(guests), "capacity": CAPACITY,
            "managed": MANAGED}


@app.delete("/v1/guest/{owner_id}", dependencies=[Depends(require_admin)])
def evict(owner_id: str):
    """Remove a guest — destroys their container. The guest keeps their local
    history and can re-home their mailbox elsewhere.

    Idempotent on purpose: a hub destroying a mailbox it has already forgotten
    must not get an error it cannot act on. Unknown guest, container already
    gone, both are success.
    """
    guest = store.guest(owner_id)
    if not guest:
        return {"status": "gone"}
    subprocess.run(["docker", "rm", "-f", guest["container_id"]],
                   capture_output=True)
    store.remove_guest(owner_id)
    return {"status": "evicted"}


# -- relay releases ------------------------------------------------------------

@app.get("/v1/relay", dependencies=[Depends(require_admin)])
def relay_status():
    """What new guests are launched from, and what the running ones report.

    The per-guest `build` is read from each relay's own /status, so this shows a
    half-finished roll for what it is rather than restating the configuration.

    Sync, so FastAPI runs it in the threadpool: it inspects a container and waits
    on an HTTP call per guest, and a full host would otherwise block the event
    loop long enough to fail this service's own health check.
    """
    installed = _installed_relay()
    guests = []
    for guest in store.guests():
        try:
            token = _guest_owner_token(guest["container_id"])
        except HTTPException:
            token = ""
        guests.append({
            "owner_id": guest["owner_id"],
            "build": _running_build(guest["port"], token) if token else None,
        })
    return {
        "installed_build": installed[0] if installed else None,
        "image": IMAGE if installed is None else f"stonechat-relay:{installed[0]}",
        "managed": MANAGED,
        "guests": guests,
    }


@app.post("/v1/relay", dependencies=[Depends(require_admin)])
async def install_relay(request: Request):
    """Upload the relay binary new guests should be launched from.

    Raw `application/octet-stream` body rather than a multipart form: it is one
    file of a few megabytes and multipart would add a dependency
    (python-multipart) for nothing.

    This does NOT touch running mailboxes — POST /v1/relay/roll does that. The
    two are separate because they fail differently: an upload that lands is
    harmless, while a roll can take a mailbox down, and the operator should be
    able to stage the artifact first.
    """
    data = bytearray()
    async for chunk in request.stream():
        data += chunk
        if len(data) > MAX_RELAY_BYTES:
            raise HTTPException(413, "too large to be a relay binary")
    data = bytes(data)
    if not data:
        raise HTTPException(400, "empty body; POST the relay binary itself")
    # A static musl ELF, because the image is FROM scratch — no loader, no libc.
    # Checked here rather than at launch: a wrong artifact caught on upload is a
    # 400, and caught on launch is a mailbox that cannot exec.
    if data[:4] != b"\x7fELF":
        raise HTTPException(400, "not an ELF binary (build the static musl relay)")
    build = _build_id(data)
    RELAY_DIR.mkdir(parents=True, exist_ok=True)
    path = RELAY_DIR / f"stonechat-relay-{build}"
    # Written under a temp name and renamed: a half-written binary at the final
    # path would be indistinguishable from a good one on the next boot.
    tmp = path.with_suffix(".part")
    tmp.write_bytes(data)
    tmp.chmod(0o755)
    tmp.replace(path)
    await asyncio.to_thread(_build_relay_image, path, build)
    store.set_setting("relay_build", build)
    return {"build": build, "bytes": len(data), "image": f"stonechat-relay:{build}"}


@app.post("/v1/relay/roll", dependencies=[Depends(require_admin)])
def roll_relay(body: RollIn):
    """Swap running mailboxes onto the relay this host is pinned to.

    One guest at a time, stopping at the first failure with the rest untouched
    and still serving: a bad build should cost one mailbox of downtime, not all
    of them. The mailbox that failed is rolled back to the binary it was running.
    """
    # No upload needed when the host is pinned to an image: the binary comes out
    # of that image, so a roll and a fresh mailbox are the same artifact.
    want, path = _roll_source()
    binary = Path(path)

    guests = store.guests()
    if body.only:
        guests = [g for g in guests if g["owner_id"] == body.only]
        if not guests:
            raise HTTPException(404, "no such guest on this host")

    results = []
    for guest in guests:
        if body.dry_run:
            try:
                token = _guest_owner_token(guest["container_id"])
                before = _running_build(guest["port"], token)
            except HTTPException:
                before = None
            results.append({"owner_id": guest["owner_id"], "ok": True,
                            "from": before, "to": want, "detail": "dry run"})
            continue
        result = _roll_guest(guest, binary, want, body.force)
        results.append(result)
        if not result["ok"]:
            return {"build": want, "rolled": results, "stopped": True}
    return {"build": want, "rolled": results, "stopped": False}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app, host="0.0.0.0", port=int(os.environ.get("STONECHAT_MAILBOX_HOST_PORT", "8200")),
        ssl_certfile=str(tls.cert_file), ssl_keyfile=str(tls.key_file),
    )
