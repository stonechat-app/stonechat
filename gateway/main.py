"""Zeon push gateway — the only place APNs/FCM credentials live.

Deliberately a separate service from the control plane:
- it holds the app-wide push credentials (most dangerous secret in the system),
- it sees device tokens + timing but NO identities (the control plane knows
  identities but no tokens — keep that join impossible by design),
- it is stateless: no database, safe to run N replicas.

Mailboxes POST /v1/ping when an envelope arrives and the owner's socket is
down. The push itself is content-free: a generic "you have new messages"
alert; the phone connects to its own mailbox to fetch the actual (encrypted)
envelopes.

Config (env) — with none set the gateway runs in dev mode and just logs:
    ZEON_APNS_KEY        path to the .p8 signing key        (iOS)
    ZEON_APNS_KEY_ID     key id
    ZEON_APNS_TEAM_ID    Apple team id
    ZEON_APNS_TOPIC      app bundle id, e.g. com.zeon.zeonChat
    ZEON_APNS_SANDBOX    "1" for the APNs sandbox host
    ZEON_FCM_CREDENTIALS path to a Firebase service-account JSON (Android)
    ZEON_GATEWAY_DEBUG   "1" → expose GET /v1/debug/pings (dev/e2e only)
"""

import logging
import os
import time
from collections import deque

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

log = logging.getLogger("zeon.gateway")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

MIN_INTERVAL_S = 3.0  # per-token debounce; mailboxes also debounce their side

app = FastAPI(title="zeon-push-gateway")

_last_ping: dict[str, float] = {}  # token -> monotonic ts (bounded below)
_debug_pings: deque = deque(maxlen=100)

DEBUG = os.environ.get("ZEON_GATEWAY_DEBUG") == "1"


class PingIn(BaseModel):
    device_token: str = Field(min_length=8, max_length=4096)
    platform: str = Field(pattern="^(ios|android)$")


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "apns": _apns_configured(),
        "fcm": _fcm_configured(),
    }


@app.post("/v1/ping")
async def ping(body: PingIn):
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
        await _send_apns(body.device_token)
    else:
        if not _fcm_configured():
            log.info("dev mode: would push (android) to …%s", body.device_token[-8:])
            return {"sent": False, "reason": "fcm not configured"}
        await _send_fcm(body.device_token)
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
        for k in ("ZEON_APNS_KEY", "ZEON_APNS_KEY_ID", "ZEON_APNS_TEAM_ID", "ZEON_APNS_TOPIC")
    )


_apns_jwt: tuple[str, float] | None = None  # (token, issued_at)


def _apns_auth_token() -> str:
    """ES256 provider token, cached ~50 min (Apple allows 20–60)."""
    global _apns_jwt
    import jwt  # pyjwt[crypto]

    now = time.time()
    if _apns_jwt and now - _apns_jwt[1] < 50 * 60:
        return _apns_jwt[0]
    with open(os.environ["ZEON_APNS_KEY"]) as f:
        key = f.read()
    token = jwt.encode(
        {"iss": os.environ["ZEON_APNS_TEAM_ID"], "iat": int(now)},
        key,
        algorithm="ES256",
        headers={"kid": os.environ["ZEON_APNS_KEY_ID"]},
    )
    _apns_jwt = (token, now)
    return token


async def _send_apns(device_token: str) -> None:
    host = (
        "https://api.sandbox.push.apple.com"
        if os.environ.get("ZEON_APNS_SANDBOX") == "1"
        else "https://api.push.apple.com"
    )
    # Content-free by design: a generic visible alert. Planned follow-up: a
    # Notification Service Extension that fetches + decrypts on-device and
    # rewrites this.
    payload = {
        "aps": {
            "alert": {"title": "Zeon", "body": "You have new messages"},
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
                "apns-topic": os.environ["ZEON_APNS_TOPIC"],
                "apns-push-type": "alert",
                "apns-collapse-id": "zeon-new-messages",
            },
        )
    if r.status_code != 200:
        log.warning("apns %s: %s", r.status_code, r.text[:200])


# -- FCM ------------------------------------------------------------------------

def _fcm_configured() -> bool:
    return bool(os.environ.get("ZEON_FCM_CREDENTIALS"))


_fcm_token: tuple[str, float] | None = None


def _fcm_auth() -> tuple[str, str]:
    """Returns (access_token, project_id), token cached ~50 min."""
    global _fcm_token
    import json

    from google.auth.transport.requests import Request
    from google.oauth2 import service_account

    path = os.environ["ZEON_FCM_CREDENTIALS"]
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


async def _send_fcm(device_token: str) -> None:
    access_token, project_id = _fcm_auth()
    message = {
        "message": {
            "token": device_token,
            "notification": {"title": "Zeon", "body": "You have new messages"},
            "android": {"collapse_key": "zeon-new-messages", "priority": "HIGH"},
        }
    }
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.post(
            f"https://fcm.googleapis.com/v1/projects/{project_id}/messages:send",
            json=message,
            headers={"authorization": f"Bearer {access_token}"},
        )
    if r.status_code != 200:
        log.warning("fcm %s: %s", r.status_code, r.text[:200])


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("ZEON_GATEWAY_PORT", "8100")))
