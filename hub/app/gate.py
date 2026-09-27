"""Gate: who may use the gated providers, decided by a service outside the hub.

The hub knows **tiers** — `mailbox` and `machine`, and which providers need
which (main.py GATED_PROVIDERS) — and nothing about how anyone gets one. A
hub started with STONECHAT_GATE_URL asks that service; one started without it
is open, and every provider is free to use. Payment, coupons, invite codes,
an allowlist: all of it is the gate's business, behind one small contract
(PROTOCOL.md "Gate"):

    GET  {gate}/v1/access/{stonechat_id}          → access object
    POST {gate}/v1/access/{stonechat_id}/claim    {"code"} → access object | 404 | 409
    POST {gate}/v1/access/{stonechat_id}/release  account deleted → 2xx | 409

    access object: {"tier": "mailbox"|"machine"|null, "status", "until",
                    "revoked_at", "notice"}

Every call carries `Authorization: Bearer STONECHAT_GATE_TOKEN`. The gate takes
the Stonechat ID on trust: the hub has already authenticated the user.

The hub keeps no copy of any answer, so the two can never disagree. The cost is
that a gate outage refuses gated provisioning (fail closed) and skips a reap
pass (fail safe); nothing that is already running is touched.

Config (env):
    STONECHAT_GATE_URL    base URL of the gate; unset → open hub
    STONECHAT_GATE_TOKEN  shared secret presented to it
"""

import logging
import os
from urllib.parse import quote

import httpx
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from .deps import User

log = logging.getLogger("stonechat.hub.gate")

GATE_URL = os.environ.get("STONECHAT_GATE_URL", "").strip().rstrip("/")
GATED = bool(GATE_URL)

# Machine outranks mailbox: a Machine holder may also run on a shared host.
TIER_RANK = {"mailbox": 1, "machine": 2}

router = APIRouter()


class GateUnavailable(Exception):
    """The gate could not be reached or answered with an error of its own."""


class GateRefused(Exception):
    """The gate said no (404/409). `detail` is its own body, passed through to
    the client unchanged — the gate words its refusals, not the hub."""

    def __init__(self, status: int, detail):
        super().__init__(f"gate refused ({status})")
        self.status = status
        self.detail = detail


def _call(method: str, stonechat_id: str, action: str = "", body: dict | None = None) -> dict:
    url = f"{GATE_URL}/v1/access/{quote(stonechat_id, safe='')}{action}"
    try:
        r = httpx.request(
            method, url, json=body, timeout=10,
            headers={"Authorization": f"Bearer {os.environ.get('STONECHAT_GATE_TOKEN', '')}"},
        )
    except httpx.HTTPError as e:
        raise GateUnavailable(str(e)) from e
    if r.status_code in (404, 409):
        try:
            detail = r.json().get("detail")
        except ValueError:
            detail = None
        raise GateRefused(r.status_code, detail or "refused")
    if r.status_code >= 400:
        raise GateUnavailable(f"HTTP {r.status_code}")
    try:
        return r.json()
    except ValueError as e:
        raise GateUnavailable("not JSON") from e


def _clean(obj: dict) -> dict:
    """The access object with an unknown tier read as none: a gate that grants
    a tier this hub has never heard of grants nothing here."""
    tier = obj.get("tier")
    return {
        "tier": tier if tier in TIER_RANK else None,
        "status": obj.get("status"),
        "until": obj.get("until"),
        "revoked_at": obj.get("revoked_at"),
        "notice": obj.get("notice"),
    }


def access(stonechat_id: str) -> dict:
    """The ID's access object. Raises GateUnavailable."""
    return _clean(_call("GET", stonechat_id))


def claim(stonechat_id: str, code: str) -> dict:
    """Redeem a code for the ID. Raises GateRefused (invalid code, already
    granted) or GateUnavailable."""
    return _clean(_call("POST", stonechat_id, "/claim", {"code": code}))


def release(stonechat_id: str) -> None:
    """The account is being deleted: the gate ends whatever it grants (and
    whatever the user pays for). Raises GateRefused when it cannot."""
    _call("POST", stonechat_id, "/release")


def satisfies(granted: str | None, required: str) -> bool:
    return TIER_RANK.get(granted or "", 0) >= TIER_RANK[required]


# -- app-facing routes ----------------------------------------------------------

def _unavailable(e: GateUnavailable) -> HTTPException:
    log.error("gate unavailable: %s", e)
    return HTTPException(503, {
        "code": "gate_unavailable",
        "message": "Plans can't be checked right now — try again in a minute.",
    })


@router.get("/v1/access")
def get_access(user: User):
    """The caller's tier. `gated: false` means this hub is open: nothing
    needs one, and the app has nothing to offer the user to redeem."""
    if not GATED:
        return {"gated": False, "tier": None, "status": None, "until": None,
                "notice": None}
    try:
        a = access(user["stonechat_id"])
    except GateUnavailable as e:
        raise _unavailable(e)
    return {"gated": True, "tier": a["tier"], "status": a["status"],
            "until": a["until"], "notice": a["notice"]}


class ClaimIn(BaseModel):
    code: str = Field(max_length=40)


@router.post("/v1/access/claim")
def post_claim(body: ClaimIn, user: User):
    if not GATED:
        raise HTTPException(404, {"code": "not_gated",
                                  "message": "this hub has no plans to redeem"})
    try:
        a = claim(user["stonechat_id"], body.code)
    except GateRefused as e:
        raise HTTPException(e.status, e.detail)
    except GateUnavailable as e:
        raise _unavailable(e)
    log.info("access claimed by %s (%s)", user["stonechat_id"][:12], a["tier"])
    return {"gated": True, "tier": a["tier"], "status": a["status"],
            "until": a["until"], "notice": a["notice"]}
