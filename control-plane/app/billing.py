"""Billing: Stripe webhooks in, activation codes out.

The flow (PROTOCOL.md "Billing"): a buyer pays through a Stripe Payment Link
on the landing page → `checkout.session.completed` lands here → we mint an
activation code and park it, unbound. The landing success page fetches the
code by checkout session id; the buyer redeems it in the app, which binds
the subscription to their Zeon ID. Stripe never learns the Zeon ID; we never
learn the buyer's name or email.

Assumes a single uvicorn process (as deployed): the rate limiter is
in-process and the Store is thread-lock guarded.

Config (env):
    ZEON_STRIPE_WEBHOOK_SECRET  webhook signing secret (whsec_…); unset →
                                webhook endpoint answers 503
    ZEON_ADMIN_TOKEN            enables POST /v1/billing/comp (comp grants
                                for testers); unset → endpoint disabled
"""

import logging
import os
import re
import secrets
import sqlite3
import time
from datetime import datetime, timezone
from typing import Annotated, Literal

import stripe
from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel, Field

from .db import hash_token
from .deps import User, store

log = logging.getLogger("zeon.control-plane.billing")

router = APIRouter()

PLANS = ("private", "sovereign")

# No 0/O/1/I/L/U — codes get read off a screen and typed on a phone.
_CODE_ALPHABET = "ABCDEFGHJKMNPQRSTVWXYZ23456789"
_CODE_LEN = 8


def mint_code() -> str:
    body = "".join(secrets.choice(_CODE_ALPHABET) for _ in range(_CODE_LEN))
    return f"ZEON-{body[:4]}-{body[4:]}"


def normalize_code(raw: str) -> str:
    """Uppercase, strip separators and the ZEON prefix: what gets hashed."""
    s = re.sub(r"[^A-Za-z0-9]", "", raw).upper()
    return s.removeprefix("ZEON")


def _code_hash(raw: str) -> str:
    return hash_token(normalize_code(raw))


# -- activation-page rate limit (per IP, in-process) ---------------------------

_BUCKETS: dict[str, list[float]] = {}
_RATE_LIMIT = 30  # requests
_RATE_WINDOW = 60.0  # seconds


def _rate_limit(key: str) -> None:
    now = time.monotonic()
    bucket = _BUCKETS.setdefault(key, [])
    bucket[:] = [t for t in bucket if now - t < _RATE_WINDOW]
    if len(bucket) >= _RATE_LIMIT:
        raise HTTPException(429, "too many requests")
    bucket.append(now)
    if len(_BUCKETS) > 10_000:  # bound memory under address churn
        _BUCKETS.clear()


# -- webhook --------------------------------------------------------------------

@router.post("/v1/billing/webhook")
async def stripe_webhook(request: Request):
    secret = os.environ.get("ZEON_STRIPE_WEBHOOK_SECRET")
    if not secret:
        raise HTTPException(503, "billing is not configured")
    payload = await request.body()
    signature = request.headers.get("stripe-signature", "")
    try:
        event = stripe.Webhook.construct_event(payload, signature, secret)
    except Exception:
        raise HTTPException(400, "invalid signature")

    if not store.record_event(event["id"], event["type"]):
        return {"status": "duplicate"}

    obj = event["data"]["object"]
    match event["type"]:
        case "checkout.session.completed":
            _handle_checkout_completed(obj)
        case "invoice.paid":
            _handle_invoice(obj, paid=True)
        case "invoice.payment_failed":
            _handle_invoice(obj, paid=False)
        case "customer.subscription.deleted":
            store.set_subscription_status(obj["id"], "lapsed")
            log.info("subscription %s lapsed (deleted at Stripe)", obj["id"])
        case other:
            log.info("ignoring webhook event type %s", other)
    return {"status": "ok"}


def _handle_checkout_completed(session) -> None:
    if session.get("mode") != "subscription":
        return
    plan = (session.get("metadata") or {}).get("plan")
    if plan not in PLANS:
        # Payment Link is missing its plan metadata — money was taken but we
        # can't fulfil. Loud log; fix the link and replay the event.
        log.error("checkout %s has no usable plan metadata: %r",
                  session.get("id"), plan)
        return
    if store.subscription_by_session(session["id"]):
        return  # replay of an already-processed session
    sub_id = session.get("subscription")
    if isinstance(sub_id, dict):
        sub_id = sub_id.get("id")
    for _ in range(5):  # code collision is ~2^-39 per try; retry regardless
        code = mint_code()
        try:
            store.create_subscription(
                plan,
                "stripe",
                _code_hash(code),
                code,
                stripe_customer_id=session.get("customer"),
                stripe_subscription_id=sub_id,
                checkout_session_id=session["id"],
            )
            log.info("subscription created for checkout %s (%s)",
                     session["id"], plan)
            return
        except sqlite3.IntegrityError:
            continue
    log.error("could not store subscription for checkout %s", session.get("id"))


def _invoice_subscription_id(invoice) -> str | None:
    """Newer Stripe API versions moved invoice.subscription under
    parent.subscription_details — accept both shapes."""
    sub = invoice.get("subscription")
    if not sub:
        details = (invoice.get("parent") or {}).get("subscription_details") or {}
        sub = details.get("subscription")
    if isinstance(sub, dict):
        return sub.get("id")
    return sub


def _invoice_period_end(invoice) -> str | None:
    try:
        end = invoice["lines"]["data"][0]["period"]["end"]
        return datetime.fromtimestamp(end, timezone.utc).isoformat()
    except (KeyError, IndexError, TypeError):
        return None


def _handle_invoice(invoice, *, paid: bool) -> None:
    sub_id = _invoice_subscription_id(invoice)
    if not sub_id:
        return
    if not store.subscription_by_stripe_sub(sub_id):
        # invoice.paid for the first invoice can race the session event that
        # creates the row; Stripe retries failed deliveries, so we converge.
        log.info("invoice for unknown subscription %s — dropped", sub_id)
        return
    if paid:
        store.set_subscription_status(
            sub_id, "active", current_period_end=_invoice_period_end(invoice))
    else:
        if store.set_subscription_status(sub_id, "grace"):
            log.info("subscription %s entered grace (payment failed)", sub_id)


# -- landing success page ---------------------------------------------------------

@router.get("/v1/billing/activation/{session_id}")
async def activation(session_id: str, request: Request):
    """Code lookup for the /activate page. The checkout session id (cs_…,
    high-entropy, only ever handed to the buyer's browser) is the secret."""
    _rate_limit(request.client.host if request.client else "unknown")
    sub = store.subscription_by_session(session_id)
    if not sub:
        # also the "webhook hasn't arrived yet" case — the page polls on 404
        raise HTTPException(404, "unknown checkout session")
    claimed = sub["zeon_id"] is not None
    return {
        "plan": sub["plan"],
        "code": None if claimed else sub["code_plain"],
        "claimed": claimed,
        "status": sub["status"],
    }


# -- app ----------------------------------------------------------------------

class RedeemIn(BaseModel):
    code: str = Field(max_length=40)


@router.post("/v1/billing/redeem")
async def redeem(body: RedeemIn, user: User):
    if store.entitlement_for(user["zeon_id"]):
        raise HTTPException(409, {
            "code": "already_subscribed",
            "message": "this account already has an active plan",
        })
    normalized = normalize_code(body.code)
    sub = (
        store.claim_subscription(hash_token(normalized), user["zeon_id"])
        if len(normalized) == _CODE_LEN
        else None
    )
    if not sub:
        # invalid, spent and lapsed all look identical — no oracle
        raise HTTPException(404, "invalid or already used code")
    log.info("code redeemed by %s (%s)", user["zeon_id"][:12], sub["plan"])
    return {
        "plan": sub["plan"],
        "status": sub["status"],
        "current_period_end": sub["current_period_end"],
    }


@router.get("/v1/billing/entitlement")
async def entitlement(user: User):
    ent = store.entitlement_for(user["zeon_id"])
    if not ent:
        return {"plan": None}
    return {
        "plan": ent["plan"],
        "status": ent["status"],
        "source": ent["source"],
        "current_period_end": ent["current_period_end"],
    }


# -- admin ----------------------------------------------------------------------

class CompIn(BaseModel):
    plan: Literal["private", "sovereign"]
    note: str = Field(default="", max_length=200)


@router.post("/v1/billing/comp", status_code=201)
async def comp(
    body: CompIn,
    x_admin_token: Annotated[str | None, Header()] = None,
):
    """Mint a free activation code (TestFlight testers, e2e). Redeemed in the
    app exactly like a paid one. Disabled unless ZEON_ADMIN_TOKEN is set."""
    admin_token = os.environ.get("ZEON_ADMIN_TOKEN")
    if not admin_token or not x_admin_token or not secrets.compare_digest(
            admin_token, x_admin_token):
        raise HTTPException(403, "admin token required")
    for _ in range(5):
        code = mint_code()
        try:
            store.create_subscription(
                body.plan, "comp", _code_hash(code), code, note=body.note or None)
            return {"plan": body.plan, "code": code}
        except sqlite3.IntegrityError:
            continue
    raise HTTPException(500, "could not mint a code")
