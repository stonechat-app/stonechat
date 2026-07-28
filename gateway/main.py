"""Stonechat push gateway — the only place APNs/FCM credentials live.

Deliberately a separate service from the hub:
- it holds the app-wide push credentials (most dangerous secret in the system),
- it sees device tokens + timing but NO identities (the hub knows
  identities but no tokens — keep that join impossible by design),
- it is stateless: no database, safe to run N replicas.

Mailboxes POST /v1/ping when an envelope arrives and the owner's socket is
down. The push itself is content-free: a generic "you have new messages"
alert; the phone connects to its own mailbox to fetch the actual (encrypted)
envelopes.

Config (env) — with none set the gateway runs in dev mode and just logs:
    STONECHAT_APNS_KEY        path to the .p8 signing key        (iOS)
    STONECHAT_APNS_KEY_ID     key id
    STONECHAT_APNS_TEAM_ID    Apple team id
    STONECHAT_APNS_TOPIC      app bundle id, e.g. com.stonechat.stonechat
    STONECHAT_APNS_SANDBOX    "1" for the APNs sandbox host
    STONECHAT_FCM_CREDENTIALS path to a Firebase service-account JSON (Android)
    STONECHAT_GATEWAY_DEBUG   "1" → expose GET /v1/debug/pings (dev/e2e only)
    STONECHAT_PUSH_MINT_SECRET  shared with the hub; when set, /v1/ping requires a
                           hub-minted X-Stonechat-Push-Key (PROTOCOL.md "Push
                           gateway"). Unset → open, as before.
    STONECHAT_PUSH_BLOCKLIST  path to a file of revoked key ids (one per line,
                         # comments ok); reloaded on mtime change.
"""

import hashlib
import hmac
import logging
import os
import time
from collections import deque
from typing import Annotated

import httpx
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

log = logging.getLogger("stonechat.gateway")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

MIN_INTERVAL_S = 3.0  # per-token debounce; mailboxes also debounce their side

app = FastAPI(title="stonechat-push-gateway")

_last_ping: dict[str, float] = {}  # token -> monotonic ts (bounded below)
_debug_pings: deque = deque(maxlen=100)

DEBUG = os.environ.get("STONECHAT_GATEWAY_DEBUG") == "1"


class PingIn(BaseModel):
    device_token: str = Field(min_length=8, max_length=4096)
    platform: str = Field(pattern="^(ios|android)$")


# -- push-key auth ----------------------------------------------------------------
# The hub mints each relay an opaque credential `pk_<id>:<hmac>` where the hmac
# is HMAC-SHA256(STONECHAT_PUSH_MINT_SECRET, key_id). Verification is pure local
# computation — no identity lookup, no hub round-trip — so this stays a
# tokens+timing-only service. Revocation = key id in the blocklist file.

MINT_SECRET = os.environ.get("STONECHAT_PUSH_MINT_SECRET", "")
BLOCKLIST_PATH = os.environ.get("STONECHAT_PUSH_BLOCKLIST", "")

_blocklist_cache: tuple[float, frozenset[str]] = (0.0, frozenset())


def _blocklist() -> frozenset[str]:
    global _blocklist_cache
    if not BLOCKLIST_PATH:
        return frozenset()
    try:
        mtime = os.stat(BLOCKLIST_PATH).st_mtime
    except OSError:
        return frozenset()
    if mtime != _blocklist_cache[0]:
        with open(BLOCKLIST_PATH) as f:
            ids = frozenset(
                line.strip() for line in f
                if line.strip() and not line.startswith("#")
            )
        _blocklist_cache = (mtime, ids)
    return _blocklist_cache[1]


def _check_push_key(push_key: str | None) -> str:
    """Returns the key id (for abuse tracing), or raises 403.
    No-op ('') when STONECHAT_PUSH_MINT_SECRET is unset."""
    if not MINT_SECRET:
        return ""
    if not push_key or ":" not in push_key or len(push_key) > 256:
        raise HTTPException(403, "push key required")
    key_id, tag = push_key.split(":", 1)
    want = hmac.new(MINT_SECRET.encode(), key_id.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(want, tag):
        raise HTTPException(403, "bad push key")
    if key_id in _blocklist():
        raise HTTPException(403, "push key revoked")
    return key_id


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "apns": _apns_configured(),
        "fcm": _fcm_configured(),
    }


@app.post("/v1/ping")
async def ping(
    body: PingIn,
    x_stonechat_push_key: Annotated[str | None, Header()] = None,
):
    key_id = _check_push_key(x_stonechat_push_key)
    now = time.monotonic()
    if now - _last_ping.get(body.device_token, 0.0) < MIN_INTERVAL_S:
        return {"sent": False, "reason": "debounced"}
    _last_ping[body.device_token] = now
    if len(_last_ping) > 100_000:  # bound memory; losing debounce state is harmless
        _last_ping.clear()

    if DEBUG:
        _debug_pings.append(
            {"device_token": body.device_token, "platform": body.platform,
             "at": time.time()}
        )

    if body.platform == "ios":
        if not _apns_configured():
            log.info("dev mode: would push (ios) to …%s", body.device_token[-8:])
            return {"sent": False, "reason": "apns not configured"}
        await _send_apns(body.device_token, key_id)
    else:
        if not _fcm_configured():
            log.info("dev mode: would push (android) to …%s", body.device_token[-8:])
            return {"sent": False, "reason": "fcm not configured"}
        await _send_fcm(body.device_token, key_id)
    return {"sent": True}


@app.get("/v1/debug/pings")
async def debug_pings():
    if not DEBUG:
        raise HTTPException(404)
    return list(_debug_pings)


# -- APNs -----------------------------------------------------------------------

def _apns_configured() -> bool:
    return all(
        os.environ.get(k)
        for k in ("STONECHAT_APNS_KEY", "STONECHAT_APNS_KEY_ID", "STONECHAT_APNS_TEAM_ID", "STONECHAT_APNS_TOPIC")
    )


_apns_jwt: tuple[str, float] | None = None  # (token, issued_at)


def _apns_auth_token() -> str:
    """ES256 provider token, cached ~50 min (Apple allows 20–60)."""
    global _apns_jwt
    import jwt  # pyjwt[crypto]

    now = time.time()
    if _apns_jwt and now - _apns_jwt[1] < 50 * 60:
        return _apns_jwt[0]
    with open(os.environ["STONECHAT_APNS_KEY"]) as f:
        key = f.read()
    token = jwt.encode(
        {"iss": os.environ["STONECHAT_APNS_TEAM_ID"], "iat": int(now)},
        key,
        algorithm="ES256",
        headers={"kid": os.environ["STONECHAT_APNS_KEY_ID"]},
    )
    _apns_jwt = (token, now)
    return token


async def _send_apns(device_token: str, key_id: str = "") -> None:
    host = (
        "https://api.sandbox.push.apple.com"
        if os.environ.get("STONECHAT_APNS_SANDBOX") == "1"
        else "https://api.push.apple.com"
    )
    # Content-free by design: a generic visible alert. Planned follow-up: a
    # Notification Service Extension that fetches + decrypts on-device and
    # rewrites this.
    payload = {
        "aps": {
            "alert": {"title": "Stonechat", "body": "You have new messages"},
            "sound": "default",
            "mutable-content": 1,
        }
    }
    async with httpx.AsyncClient(http2=True, timeout=10) as client:
        r = await client.post(
            f"{host}/3/device/{device_token}",
            json=payload,
            headers={
                "authorization": f"bearer {_apns_auth_token()}",
                "apns-topic": os.environ["STONECHAT_APNS_TOPIC"],
                "apns-push-type": "alert",
                "apns-collapse-id": "stonechat-new-messages",
            },
        )
    if r.status_code != 200:
        # key_id identifies the minted credential, never the user — but it is
        # what you blocklist when one relay floods us with bad tokens.
        log.warning("apns %s (key %s): %s", r.status_code, key_id or "-", r.text[:200])


# -- FCM ------------------------------------------------------------------------

def _fcm_configured() -> bool:
    return bool(os.environ.get("STONECHAT_FCM_CREDENTIALS"))


_fcm_token: tuple[str, float] | None = None


def _fcm_auth() -> tuple[str, str]:
    """Returns (access_token, project_id), token cached ~50 min."""
    global _fcm_token
    import json

    from google.auth.transport.requests import Request
    from google.oauth2 import service_account

    path = os.environ["STONECHAT_FCM_CREDENTIALS"]
    with open(path) as f:
        project_id = json.load(f)["project_id"]
    now = time.time()
    if _fcm_token and now - _fcm_token[1] < 50 * 60:
        return _fcm_token[0], project_id
    creds = service_account.Credentials.from_service_account_file(
        path, scopes=["https://www.googleapis.com/auth/firebase.messaging"]
    )
    creds.refresh(Request())
    _fcm_token = (creds.token, now)
    return creds.token, project_id


async def _send_fcm(device_token: str, key_id: str = "") -> None:
    access_token, project_id = _fcm_auth()
    message = {
        "message": {
            "token": device_token,
            "notification": {"title": "Stonechat", "body": "You have new messages"},
            "android": {"collapse_key": "stonechat-new-messages", "priority": "HIGH"},
        }
    }
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.post(
            f"https://fcm.googleapis.com/v1/projects/{project_id}/messages:send",
            json=message,
            headers={"authorization": f"Bearer {access_token}"},
        )
    if r.status_code != 200:
        log.warning("fcm %s (key %s): %s", r.status_code, key_id or "-", r.text[:200])


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("STONECHAT_GATEWAY_PORT", "8100")))
