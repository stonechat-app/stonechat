"""Stonechat hub — provisioner + directory.

Run: uvicorn app.main:app --port 8000
Config (env):
    STONECHAT_HUB_DB                  sqlite path (default hub.db)
    STONECHAT_GCP_PROJECT            required for provider=gcp
    STONECHAT_LOCAL_HOST             advertised host for provider=local (default 127.0.0.1)
    STONECHAT_BILLING                "off" disables the billing plane entirely: no
                                billing endpoints, no plan gates (every
                                provider is free to use), no reaper (default on)
    STONECHAT_STRIPE_WEBHOOK_SECRET  Stripe webhook signing secret (billing.py)
    STONECHAT_ADMIN_TOKEN            enables comp grants (billing.py) and the
                                abuse routes under /v1/admin (admin.py)
    STONECHAT_TEST_CODE              reusable tester activation code (billing.py)
    STONECHAT_CORS_EXTRA             comma-separated extra CORS origins (dev)
    STONECHAT_REAP_RETENTION_DAYS    destroy mailboxes this many days after their
                                subscription lapses (default 14; -1 disables)
    STONECHAT_REAP_INTERVAL_S        seconds between reap passes (default 3600)
    STONECHAT_REPORT_RETENTION_DAYS  delete user-filed abuse reports this many days
                                after they are filed (default 180; -1 disables
                                the purge, which also discards the retention
                                promise the privacy policy makes — report.py)
"""

import asyncio
import base64
import json
import logging
import os
import re
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

import httpx
from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field, model_validator

import os

from .admin import router as admin_router
from .billing import router as billing_router
from .countries import UnavailableCountry
from .countries import catalog as country_catalog
from .countries import resolve as resolve_country
from .deps import UnbannedUser, User, store
from .identity import PQ_PK_LEN, PUBKEY_LEN, normalize_stonechat_id, stonechat_id_from_pubkey
from .ratelimit import RateLimiter
from .report import RETENTION_DAYS as REPORT_RETENTION_DAYS
from .report import router as report_router
from .providers import (
    MachineSpec,
    ProviderError,
    ProvisionRequest,
    available_providers,
    get_provider,
)
from .providers.bootstrap import MACHINE_HOST_PORT, relay_binary_path

log = logging.getLogger("stonechat.hub")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

REAP_RETENTION_DAYS = int(os.environ.get("STONECHAT_REAP_RETENTION_DAYS", "14"))
REAP_INTERVAL_S = int(os.environ.get("STONECHAT_REAP_INTERVAL_S", "3600"))

# Billing exists for the hosted service; a private hub doesn't need it.
# STONECHAT_BILLING=off removes the whole plane: the /v1/billing/* endpoints are
# not mounted, no provider requires a plan, and mailboxes are never reaped —
# lifecycle is billing-driven, so without billing nothing lapses.
BILLING = os.environ.get("STONECHAT_BILLING", "on").strip().lower() != "off"

# Wire protocol version served by hub.stonechat.app (PROTOCOL.md "Versioning").
# Clients send theirs in X-Stonechat-Version; anything below the minimum is told to
# upgrade rather than served a contract it can't speak. An absent header is a
# legacy (pre-versioning) client and is allowed through.
WIRE_VERSION = 1
MIN_WIRE_VERSION = 1


async def require_wire_version(x_stonechat_version: int | None = Header(default=None)):
    if x_stonechat_version is not None and x_stonechat_version < MIN_WIRE_VERSION:
        raise HTTPException(
            426,
            {"code": "upgrade_required", "min_version": MIN_WIRE_VERSION,
             "message": "This app version is no longer supported — please update."},
        )


@asynccontextmanager
async def _lifespan(app: FastAPI):
    tasks = []
    if BILLING and REAP_RETENTION_DAYS >= 0:
        tasks.append(asyncio.create_task(_reap_loop()))
    # Deliberately not conditioned on BILLING: a hub with billing off still
    # accepts reports, and a retention promise that only holds on the paid
    # configuration is not a retention promise.
    if REPORT_RETENTION_DAYS >= 0:
        tasks.append(asyncio.create_task(_purge_reports_loop()))
    yield
    for task in tasks:
        task.cancel()


app = FastAPI(title="stonechat-hub", lifespan=_lifespan,
              dependencies=[Depends(require_wire_version)])
if BILLING:
    app.include_router(billing_router)
else:
    log.info("billing disabled (STONECHAT_BILLING=off) — all providers ungated")

# Abuse handling is not part of the billing plane — a hub with billing off
# still hosts machines someone can complain about. Every route inside is dead
# unless STONECHAT_ADMIN_TOKEN is set.
app.include_router(admin_router)

# Filing a report, unlike reading one, is open to any client that can sign as
# a Stonechat ID — including one belonging to another hub (report.py). It stays
# mounted even with no STONECHAT_ADMIN_TOKEN: refusing to *record* a complaint
# because nobody has configured a way to read it is the wrong failure.
app.include_router(report_router)

# Browser access used to be only the landing page's activation lookup, hence
# GET-only. The **web client** is a browser too, and it needs POST: parking its
# link offer is a POST with a JSON content-type, which is not CORS-safelisted
# and so also triggers a preflight. Without this the client fails with a bare
# "Failed to fetch" — the browser tells the page nothing — and the symptom
# surfaces two hops away, on the *phone*, as "that code has expired".
#
# The origin list stays a small allowlist. Serving the web client from an
# origin means naming it here or in STONECHAT_CORS_EXTRA; there is no wildcard,
# and `allow_credentials` stays off because every authenticated call carries a
# bearer token rather than a cookie.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://stonechat.app",
        "https://www.stonechat.app",
        # The web client. First-party, so it belongs in the allowlist rather
        # than in STONECHAT_CORS_EXTRA — that variable is for a developer's
        # localhost, and a production origin that only works when an env var
        # is set is one deploy away from being broken.
        "https://webapp.stonechat.app",
        *[o for o in os.environ.get("STONECHAT_CORS_EXTRA", "").split(",") if o],
    ],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

HEALTH_TIMEOUT_S = 240  # cloud VMs need to apt-get + pip install on first boot

# Paid providers and the plan each requires. Machine outranks mailbox, so a
# Machine subscriber may also run on a shared machine host. `local` and
# `external` (self-hosted free tier) stay ungated. With billing off nothing
# is gated (and the reap query, which sweeps these providers, matches nothing).
GATED_PROVIDERS = {
    "machine_host": "mailbox",
    "gcp": "machine",
    "aws": "machine",
    "digitalocean": "machine",
    "hetzner": "machine",
    "vultr": "machine",
} if BILLING else {}
PLAN_RANK = {"mailbox": 1, "machine": 2}
# Dedicated-VM providers get the machine host baked into the VM.
DEDICATED_PROVIDERS = {"gcp", "aws", "digitalocean", "hetzner", "vultr"}


# -- schemas --------------------------------------------------------------------

class RegisterIn(BaseModel):
    pubkey: str  # base64-encoded Ed25519 identity public key
    # X-Wing identity encryption key (1216 bytes → 1622 base64 chars) and the
    # Ed25519 signature over "stonechat-v1-pqpk" || pq_pk that lets every resolver
    # trust it (notes/docs/POST_QUANTUM.md — hybrid envelope seal).
    pq_pk: str = Field(max_length=1700)
    pq_sig: str = Field(max_length=128)


class RecoverIn(BaseModel):
    pubkey: str = Field(max_length=64)  # base64 Ed25519 identity public key
    timestamp: int  # unix seconds, signed by the client
    signature: str = Field(max_length=128)  # sig over "stonechat-v1-recover"||str(timestamp)


class MachineIn(BaseModel):
    machine_type: str = Field(examples=["e2-micro", "t3.micro"])
    region: str = Field(examples=["us-central1-a", "us-east-1"])
    disk_gb: int = Field(default=10, ge=10, le=100)


class MailboxIn(BaseModel):
    """Either a country (the app's vocabulary) or an explicit provider+machine.

    `country` is what clients send: the hub resolves it against the catalog and
    the caller's plan, so which cloud serves which flag stays a hub-side
    decision (countries.py). provider+machine remains for scripts, tests and
    app builds that predate the picker — dropping it would break every
    installed client the moment this deploys.
    """

    country: str | None = Field(default=None, max_length=2, examples=["CH"])
    provider: str | None = None
    machine: MachineIn | None = None

    @model_validator(mode="after")
    def _exactly_one_form(self):
        if (self.country is None) == (self.provider is None):
            raise ValueError("send either 'country' or 'provider'+'machine'")
        if self.provider is not None and self.machine is None:
            raise ValueError("'provider' requires 'machine'")
        return self


class ExternalMailboxIn(BaseModel):
    address: str = Field(max_length=200, examples=["https://203.0.113.7:8080"])
    # Where the browser transport listens, if it does. Stated by the owner
    # because for a mailbox the hub did not provision, nobody else can know —
    # there is no port mapping we performed and no fixed convention we set.
    wt_address: str | None = Field(default=None, max_length=200,
                                   examples=["203.0.113.7:8443"])


class TlsSigIn(BaseModel):
    tls_fp: str = Field(max_length=64)  # base64 BLAKE2b-256 of the relay's DER cert
    tls_sig: str = Field(max_length=128)  # owner's Ed25519 sig over "stonechat-v1-tls"||fp


class WtCertIn(BaseModel):
    sha256: str = Field(max_length=64)  # base64 SHA-256 of the DER
    not_before: int
    not_after: int


class WtCertsIn(BaseModel):
    # Bounded by the relay's own schedule length; a list far longer than that
    # is not a schedule, it is someone filling the directory.
    certs: list[WtCertIn] = Field(max_length=64)
    wt_sig: str = Field(max_length=128)


# -- routes ---------------------------------------------------------------------

@app.get("/health")
async def health():
    return {"status": "ok", "providers": available_providers()}


@app.get("/v1/relay-binary")
def relay_binary(authorization: str | None = Header(default=None)):
    """The static relay binary dedicated-VM startup scripts fetch (their pinned
    SHA-256 makes this integrity-critical path tamper-evident — bootstrap.py).
    Auth is the fetching VM's mailbox_token, which the startup script already
    carries; it gates egress cost only — integrity comes from the pin, and
    the binary itself is not secret. 404 until the operator sets
    STONECHAT_RELAY_BINARY."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "missing bearer token")
    if not store.mailbox_by_token(authorization.removeprefix("Bearer ").strip()):
        raise HTTPException(401, "invalid token")
    path = relay_binary_path()
    if path is None or not path.is_file():
        raise HTTPException(404, "no relay binary configured on this hub")
    return FileResponse(path, media_type="application/octet-stream",
                        filename="stonechat-relay")


# Registration is once per install, so 10/min/IP is roomy even for a NAT'd
# office — while a scripted loop dies on its first second (ABUSE.md
# "Scripted registration").
#
# Overridable only because scripts/e2e.py creates a dozen identities from one
# address in seconds and would otherwise trip a limit that exists for humans.
# The default is the production value; the env var is a test-rig knob.
_register_limiter = RateLimiter(
    limit=int(os.environ.get("STONECHAT_REGISTER_LIMIT", "10")), window_s=60.0
)


@app.post("/v1/register", status_code=201)
def register(body: RegisterIn, request: Request):
    """Create an identity: deliberately open, no auth.

    The Stonechat ID is derived (identity.py) from the submitted Ed25519 pubkey,
    so there is nothing to squat or hijack — "registering as someone else"
    requires their pubkey and just yields the ID they'd get anyway (409 if
    taken). Returns the account_token that authenticates every account-scoped
    endpoint; anything costly (provisioning) additionally sits behind plan
    entitlements. Rate-limited per IP: mass signups are cheap junk rows to
    us, but read as card-testing fraud to the payment stack.
    """
    _register_limiter.check(request.client.host if request.client else "unknown")
    try:
        pubkey = base64.b64decode(body.pubkey, validate=True)
    except Exception:
        raise HTTPException(400, "pubkey is not valid base64")
    if len(pubkey) != PUBKEY_LEN:
        raise HTTPException(400, f"pubkey must be {PUBKEY_LEN} bytes")
    # The X-Wing identity key rides in the directory only under a valid
    # Ed25519 signature. Clients re-verify on every resolve (the directory
    # is untrusted); rejecting garbage here just fails fast at signup.
    try:
        pq_pk = base64.b64decode(body.pq_pk, validate=True)
    except Exception:
        raise HTTPException(400, "pq_pk is not valid base64")
    if len(pq_pk) != PQ_PK_LEN:
        raise HTTPException(400, f"pq_pk must be {PQ_PK_LEN} bytes")
    try:
        from nacl.signing import VerifyKey

        VerifyKey(pubkey).verify(
            b"stonechat-v1-pqpk" + pq_pk, base64.b64decode(body.pq_sig)
        )
    except Exception:
        raise HTTPException(400, "bad pq_sig")

    stonechat_id = stonechat_id_from_pubkey(pubkey)
    token = secrets.token_urlsafe(32)
    if not store.create_user(stonechat_id, body.pubkey, body.pq_pk, body.pq_sig, token):
        raise HTTPException(409, "this key is already registered")
    log.info("registered %s", stonechat_id[:12])
    return {"stonechat_id": stonechat_id, "account_token": token}


# Same budget as registration: recovery is a rare, human-paced event, and a
# guessing loop should die instantly (each attempt also costs a signature
# verify).
_recover_limiter = RateLimiter(limit=10, window_s=60.0)


@app.post("/v1/recover")
def recover(body: RecoverIn, request: Request):
    """Re-issue an account token to whoever holds the identity secret key.

    Restore path for an identity export (the app's Settings → Identity
    export): the same key always derives the same Stonechat ID, but /v1/register
    409s once the key exists, and the old token is gone with the old phone.
    Possession is proven with a signature over "stonechat-v1-recover" || the
    current unix time; the ±5-minute freshness window bounds replay to the
    TLS channel it was heard on. Success rotates the account token, so the
    recovering device becomes the account and any previous token dies —
    recovery is also the remedy for a stolen still-registered phone.
    """
    _recover_limiter.check(request.client.host if request.client else "unknown")
    try:
        pubkey = base64.b64decode(body.pubkey, validate=True)
    except Exception:
        raise HTTPException(400, "pubkey is not valid base64")
    if len(pubkey) != PUBKEY_LEN:
        raise HTTPException(400, f"pubkey must be {PUBKEY_LEN} bytes")
    now = int(datetime.now(timezone.utc).timestamp())
    if abs(now - body.timestamp) > 300:
        raise HTTPException(400, "signature timestamp out of range — check the device clock")
    try:
        from nacl.signing import VerifyKey

        VerifyKey(pubkey).verify(
            b"stonechat-v1-recover" + str(body.timestamp).encode(),
            base64.b64decode(body.signature),
        )
    except Exception:
        raise HTTPException(401, "bad signature")

    user = store.user_by_id(stonechat_id_from_pubkey(pubkey))
    if not user:
        raise HTTPException(404, "unknown identity")
    token = secrets.token_urlsafe(32)
    store.rotate_token(user["stonechat_id"], token)
    log.info("recovered %s", user["stonechat_id"][:12])
    return {"stonechat_id": user["stonechat_id"], "account_token": token}


# Deliberately generous: a cold-cache group send resolves every member at
# once, and NAT'd networks share an IP — the wall only exists for floods
# (each lookup costs a DB read; the data itself is public to ID-holders).
_directory_limiter = RateLimiter(limit=120, window_s=60.0)


# -- device linking (MULTIDEVICE.md "Linking a device") ------------------------
#
# The hub is the dead drop, not the relay. A device being linked has no
# identity, no account, and no way to know which relay to poll — the hub URL
# is the only address it has, because onboarding asked for it. What is parked
# here is sealed to an ephemeral key that exists only on the new device; the
# hub stores bytes it cannot open, filed under the hash of a secret it never
# sees.
_link_limiter = RateLimiter(limit=30, window_s=60.0)


def _valid_link_key(key: str) -> bool:
    """BLAKE2b-256 hex, matching the relay's own key validation."""
    return len(key) == 64 and all(c in "0123456789abcdef" for c in key)


@app.post("/v1/link")
def put_link_grant(body: dict, request: Request):
    """Park a sealed grant. Unauthenticated: the parking key is a capability
    derived from a secret only the two devices hold, and the payload is
    opaque, so an account check would add nothing an attacker could not
    already satisfy."""
    _link_limiter.check(request.client.host if request.client else "unknown")
    key, sealed = body.get("key"), body.get("sealed")
    if not isinstance(key, str) or not _valid_link_key(key):
        raise HTTPException(400, "bad key")
    if not isinstance(sealed, str) or not sealed or len(sealed) > 64 * 1024:
        raise HTTPException(400, "bad sealed")
    if not store.put_link_grant(key, sealed):
        raise HTTPException(503, "too many pending links")
    return {"status": "ok"}


@app.get("/v1/link/{key}")
def take_link_grant(key: str, request: Request):
    """Collect and delete. Possession of the QR is the credential."""
    _link_limiter.check(request.client.host if request.client else "unknown")
    if not _valid_link_key(key):
        raise HTTPException(400, "bad key")
    sealed = store.take_link_grant(key)
    if sealed is None:
        raise HTTPException(404, "no such grant")
    return {"sealed": sealed}


LINK_OFFER_CONTEXT = b"stonechat-link-offer"


def _offer_commitment(seal_b64: str, sig_b64: str) -> str:
    """blake2b-256 over the two public keys, hex.

    Domain-separated so this hash can never be mistaken for — or replayed as —
    any other blake2b in the protocol (the parking key is one over the lookup
    secret, the TLS fingerprint another over a certificate).
    """
    import hashlib

    h = hashlib.blake2b(digest_size=32)
    h.update(LINK_OFFER_CONTEXT)
    h.update(base64.b64decode(seal_b64, validate=True))
    h.update(base64.b64decode(sig_b64, validate=True))
    return h.hexdigest()


@app.post("/v1/link/offer")
def put_link_offer(body: dict, request: Request):
    """Park a new device's public keys under a commitment to them.

    Unauthenticated, like the grant drop, and for a stronger reason: the
    contents are public keys. What makes it safe is that the **key is the
    hash** — recomputed here — so this endpoint cannot be used to serve a
    device keys that do not match the commitment their user scanned. The
    scanning device verifies again anyway; our word does not count.
    """
    _link_limiter.check(request.client.host if request.client else "unknown")
    key, offer = body.get("key"), body.get("offer")
    if not isinstance(key, str) or not _valid_link_key(key):
        raise HTTPException(400, "bad key")
    if not isinstance(offer, dict):
        raise HTTPException(400, "bad offer")
    seal, sig = offer.get("seal"), offer.get("sig")
    if not isinstance(seal, str) or not isinstance(sig, str):
        raise HTTPException(400, "offer must carry seal and sig")
    try:
        if len(base64.b64decode(seal, validate=True)) != 1216:
            raise ValueError
        if len(base64.b64decode(sig, validate=True)) != 32:
            raise ValueError
        commitment = _offer_commitment(seal, sig)
    except Exception:
        raise HTTPException(400, "offer keys are malformed")
    if commitment != key:
        raise HTTPException(400, "key is not the commitment to those offer keys")
    if not store.put_link_offer(key, json.dumps({"seal": seal, "sig": sig})):
        raise HTTPException(503, "too many pending links")
    return {"status": "ok"}


@app.get("/v1/link/offer/{key}")
def get_link_offer(key: str, request: Request):
    """Read the parked keys. **Not** single-use — see db.peek_link_offer."""
    _link_limiter.check(request.client.host if request.client else "unknown")
    if not _valid_link_key(key):
        raise HTTPException(400, "bad key")
    offer = store.peek_link_offer(key)
    if offer is None:
        raise HTTPException(404, "no such offer")
    return {"offer": json.loads(offer)}


@app.get("/v1/directory/{stonechat_id}")
def directory(stonechat_id: str, request: Request):
    """Resolve a SC- cryptographic ID to its record. Lookup is by full ID
    only — there is no enumerable handle namespace (a Stonechat ID is a 160-bit
    commitment, not walkable). Clients MUST still verify the returned pubkey
    hashes to the returned stonechat_id; the directory is untrusted — and open:
    senders on other hubs resolve through here with no account
    on this hub, and auth would add nothing when accounts are free."""
    _directory_limiter.check(request.client.host if request.client else "unknown")
    try:
        canonical = normalize_stonechat_id(stonechat_id)
    except ValueError as e:
        raise HTTPException(400, str(e))
    user = store.user_by_id(canonical)
    if not user:
        raise HTTPException(404, "unknown Stonechat ID")

    mailbox = store.mailbox_for(user["stonechat_id"])
    return {
        "stonechat_id": user["stonechat_id"],
        "pubkey": user["pubkey"],
        "pq_pk": user["pq_pk"],
        "pq_sig": user["pq_sig"],
        "mailbox": (
            {
                "address": mailbox["address"],
                "status": mailbox["status"],
                "tls_fp": mailbox["tls_fp"],
                "tls_sig": mailbox["tls_sig"],
                # Where the browser transport listens (UDP). Unsigned, and
                # safe to be: rewriting it sends a client to a mailbox whose
                # certificate is not in the owner-signed schedule, so the
                # connection is refused. Denial of service, not compromise —
                # the same property `address` has behind `tls_fp`.
                "wt_address": mailbox["wt_address"],
                # The browser transport's pinned certificate schedule. Null
                # when the mailbox has no browser transport, or when the owner
                # has not vouched for it yet — an unsigned schedule is served
                # as no schedule, because a client must not pin one.
                "wt_certs": (
                    json.loads(mailbox["wt_certs"]) if mailbox["wt_certs"] else None
                ),
                "wt_sig": mailbox["wt_sig"],
            }
            if mailbox and mailbox["status"] == "running"
            else None
        ),
    }


@app.get("/v1/countries")
def list_countries():
    """Where a mailbox can live, in the app's vocabulary.

    Unauthenticated on purpose: the picker is shown during onboarding, and the
    answer is identical for everyone — it reveals our provider footprint, which
    is a marketing page, not a secret. Each entry carries both the jurisdiction
    line and its caveat; clients must render both (countries.py).
    """
    return {"countries": country_catalog()}


@app.post("/v1/mailbox", status_code=202)
def create_mailbox(body: MailboxIn, user: UnbannedUser, background: BackgroundTasks):
    provider, machine = body.provider, body.machine
    if body.country is not None:
        # Country form: the plan decides the tier, the catalog decides the
        # cloud. Resolve before the gate so an unplaced country fails with
        # "not available there" rather than a misleading payment prompt.
        entitlement = store.entitlement_for(user["stonechat_id"]) if BILLING else None
        plan = entitlement["plan"] if entitlement else "machine"
        try:
            provider, machine_dict = resolve_country(body.country, plan)
        except UnavailableCountry as e:
            raise HTTPException(400, {"code": "country_unavailable", "message": str(e)})
        machine = MachineIn(**machine_dict)

    if provider not in available_providers():
        raise HTTPException(
            400, f"unknown provider; available: {', '.join(available_providers())}"
        )
    required = GATED_PROVIDERS.get(provider)
    if required is not None:
        entitlement = store.entitlement_for(user["stonechat_id"])
        if entitlement is None or (
            PLAN_RANK.get(entitlement["plan"], 0) < PLAN_RANK[required]
        ):
            raise HTTPException(402, {
                "code": "subscription_required",
                "plan_required": required,
                "message": f"the '{provider}' provider requires an active"
                           f" {required} plan",
            })
    mailbox_token = secrets.token_urlsafe(32)
    # Dedicated VMs ship with the machine host pre-installed (PROTOCOL.md "Host
    # agent") — mint its admin token here so the app can pick it up from
    # GET /v1/mailbox and mint invites with zero manual setup.
    machine_host_token = (
        secrets.token_urlsafe(32) if provider in DEDICATED_PROVIDERS else None
    )
    if not store.create_mailbox(
        user["stonechat_id"], provider, machine.model_dump(), mailbox_token,
        machine_host_token,
    ):
        raise HTTPException(409, "you already have a mailbox (one per user)")

    background.add_task(
        _provision, user["stonechat_id"], provider, machine, mailbox_token,
        machine_host_token,
    )
    return {"status": "provisioning"}


@app.post("/v1/mailbox/external", status_code=201)
def register_external_mailbox(body: ExternalMailboxIn, user: UnbannedUser):
    """The free tier: the user runs their own relay anywhere and we list it in
    the directory. Ownership is proven, not claimed: the relay confirms this
    user's Stonechat ID via /owner (it never exposes its owner to anonymous callers,
    so this probe leaks nothing). We never see their token.

    Banned accounts are refused here too, not just on /v1/mailbox: this is the
    cheaper door, and a ban that left it open would be bypassed in one call."""
    address = body.address.strip().rstrip("/")
    if not re.match(r"^https://[a-zA-Z0-9.\-:\[\]]+$", address):
        raise HTTPException(400, "address must look like https://host[:port]")

    try:
        # verify=False: relay certs are self-signed by design; the client-side
        # pin (owner-signed fingerprint) is the real trust anchor, not this probe.
        # Sync client: this handler runs in the threadpool, so the up-to-8s
        # probe never touches the event loop.
        with httpx.Client(timeout=8, verify=False) as client:
            health = client.get(f"{address}/health").json()
            # Confirm ownership by asking the box to agree to the caller's own
            # ID — it answers 200/404, never handing back an identity.
            owner_ok = (client.get(
                f"{address}/owner",
                params={"stonechat_id": user["stonechat_id"]})).status_code == 200
    except Exception:
        raise HTTPException(
            400,
            "couldn't reach a Stonechat mailbox at that address — it must be "
            "reachable from the internet",
        )
    if not owner_ok:
        raise HTTPException(400, "that mailbox belongs to a different Stonechat ID")

    wt_address = (body.wt_address or "").strip()
    # The bracketed alternative is not decoration: an IPv6 literal is full of
    # colons, so a host pattern that excludes them rejects every IPv6 mailbox.
    wt_match = re.match(
        r"^(?:\[[0-9A-Fa-f:.]+\]|[a-zA-Z0-9.\-]+):(\d{1,5})$", wt_address
    )
    if wt_address and (not wt_match or not 0 < int(wt_match.group(1)) <= 65535):
        raise HTTPException(400, "wt_address must look like host:port")

    tls_fp = health.get("tls_fp")
    if not store.create_external_mailbox(user["stonechat_id"], address, tls_fp):
        raise HTTPException(409, "you already have a mailbox (one per user)")
    if wt_address:
        store.set_wt_address(user["stonechat_id"], wt_address)
    log.info("external relay registered for %s", user["stonechat_id"][:12])
    return {"status": "running", "address": address, "tls_fp": tls_fp}


@app.post("/v1/mailbox/tls")
def publish_tls_sig(body: TlsSigIn, user: User):
    """The owner vouches for their mailbox's TLS key: an Ed25519 signature
    over "stonechat-v1-tls" || fingerprint, verifiable by anyone against the
    identity key their Stonechat ID commits to. We check it so the directory never
    serves garbage, but clients re-verify — our word doesn't count."""
    mailbox = store.mailbox_for(user["stonechat_id"])
    if not mailbox or mailbox["status"] != "running":
        raise HTTPException(404, "no running mailbox")
    if mailbox["tls_fp"] is not None and mailbox["tls_fp"] != body.tls_fp:
        raise HTTPException(400, "fingerprint does not match this mailbox's certificate")
    try:
        from nacl.signing import VerifyKey

        VerifyKey(base64.b64decode(user["pubkey"])).verify(
            b"stonechat-v1-tls" + base64.b64decode(body.tls_fp),
            base64.b64decode(body.tls_sig),
        )
    except Exception:
        raise HTTPException(400, "signature does not verify against your identity key")
    store.set_tls_sig(user["stonechat_id"], body.tls_sig)
    return {"status": "ok"}


@app.post("/v1/mailbox/wt")
def publish_wt_certs(body: WtCertsIn, user: User):
    """The owner vouches for their mailbox's **browser-transport** certificate
    schedule.

    A relay's `/wt/certs` states which short-lived certificates it will present;
    it cannot vouch for them, being the thing under authentication. This is the
    owner's signature over that list, verifiable by anyone against the identity
    key their Stonechat ID commits to.

    Checked here so the directory never serves garbage — but clients re-verify,
    because our word does not count. A client that pins these hashes without
    checking the signature has pinned whatever the network told it to.
    """
    mailbox = store.mailbox_for(user["stonechat_id"])
    if not mailbox or mailbox["status"] != "running":
        raise HTTPException(404, "no running mailbox")
    certs = [c.model_dump() for c in body.certs]
    try:
        from nacl.signing import VerifyKey

        VerifyKey(base64.b64decode(user["pubkey"])).verify(
            b"stonechat-v1-wtcerts" + _wtcerts_signing_bytes(certs),
            base64.b64decode(body.wt_sig),
        )
    except Exception:
        raise HTTPException(400, "signature does not verify against your identity key")
    # Stored as the exact list that was signed. Re-serializing it differently
    # on the way out would be harmless (clients rebuild the signing bytes from
    # the fields), but keeping them together is what makes that true.
    store.set_wt_certs(user["stonechat_id"], json.dumps(certs), body.wt_sig)
    return {"status": "ok"}


def _wtcerts_signing_bytes(certs: list[dict]) -> bytes:
    """Mirrors core/src/wtcerts.rs. Length-prefixed and ordered, not JSON:
    three implementations sign or verify this, and JSON is not canonical.

    The leading count is what stops a truncated list verifying as a prefix of
    the signed one — and truncating away the *future* certificates is exactly
    how an attacker strands a client on one they already hold."""
    out = bytearray(len(certs).to_bytes(4, "big"))
    for cert in certs:
        for field in (
            cert["sha256"].encode(),
            int(cert["not_before"]).to_bytes(8, "big", signed=True),
            int(cert["not_after"]).to_bytes(8, "big", signed=True),
        ):
            out += len(field).to_bytes(4, "big") + field
    return bytes(out)


def _machine_host_address(mailbox_address: str) -> str:
    """The machine host lives on the same VM as the mailbox, on its own port:
    https://<ip>:8080 → https://<ip>:8200."""
    host = mailbox_address.rsplit(":", 1)[0]
    return f"{host}:{MACHINE_HOST_PORT}"


@app.get("/v1/mailbox")
def get_mailbox(user: User):
    mailbox = store.mailbox_for(user["stonechat_id"])
    if not mailbox:
        return {"status": "none"}
    return {
        "status": mailbox["status"],
        "provider": mailbox["provider"],
        "machine": mailbox["machine"],
        "address": mailbox["address"],
        "mailbox_token": mailbox["mailbox_token"],
        "tls_fp": mailbox["tls_fp"],
        "error": mailbox["error"],
        # Dedicated VMs come with the machine host pre-installed; hand the app
        # its address + admin token so the Invites screen connects itself.
        "machine_host": (
            {
                "address": _machine_host_address(mailbox["address"]),
                "admin_token": mailbox["machine_host_token"],
            }
            if mailbox["machine_host_token"] and mailbox["status"] == "running"
            and mailbox["address"]
            else None
        ),
    }


@app.delete("/v1/mailbox")
def delete_mailbox(user: User):
    mailbox = store.mailbox_for(user["stonechat_id"])
    if not mailbox:
        raise HTTPException(404, "no mailbox")
    if mailbox["resource_id"]:
        try:
            provider = get_provider(mailbox["provider"])
            provider.destroy(mailbox["resource_id"], mailbox["meta"])
        except ProviderError as e:
            raise HTTPException(502, f"failed to destroy: {e}")
    store.delete_mailbox(user["stonechat_id"])
    return {"status": "deleted"}


# -- provisioning (background) ---------------------------------------------------

def _provision(stonechat_id: str, provider_name: str, machine: MachineIn, mailbox_token: str,
               machine_host_token: str | None = None):
    """Runs in a worker thread (sync BackgroundTask). Updates the row when done."""
    try:
        provider = get_provider(provider_name)
        result = provider.provision(
            ProvisionRequest(
                owner_id=stonechat_id,
                owner_token=mailbox_token,
                spec=MachineSpec(**machine.model_dump()),
                machine_host_token=machine_host_token,
            )
        )
        tls_fp = _wait_healthy(result.address)
        store.mark_running(stonechat_id, result.resource_id, result.address,
                           result.meta, tls_fp, result.wt_address)
        log.info("mailbox for %s running at %s", stonechat_id[:12], result.address)
    except Exception as e:
        log.exception("provisioning failed for %s", stonechat_id[:12])
        store.mark_error(stonechat_id, str(e))


# -- reaping (background) ---------------------------------------------------------
#
# Mailbox lifecycle is billing-driven, never activity-driven: the hub must not
# learn (or be able to leak) when a mailbox is used. A paid-up mailbox runs
# forever, idle or not. When the owner's last subscription has been lapsed
# longer than the retention window, the sweep destroys the machine. The Stripe
# webhook only marks `lapsed`; this pass is the sole executor, so a missed
# webhook retry or a mid-destroy crash just gets picked up next hour.

async def _reap_loop():
    while True:
        await asyncio.sleep(REAP_INTERVAL_S)
        try:
            await asyncio.to_thread(_reap_once)
        except Exception:
            log.exception("reap pass failed")


async def _purge_reports_loop():
    """Enforce the abuse-report retention window (report.py's module
    docstring explains why there is one). Runs on the same interval as the
    reaper; the window is measured in days, so the cadence barely matters."""
    while True:
        await asyncio.sleep(REAP_INTERVAL_S)
        try:
            cutoff = datetime.now(timezone.utc) - timedelta(days=REPORT_RETENTION_DAYS)
            purged = await asyncio.to_thread(store.purge_reports, cutoff.isoformat())
            if purged:
                log.info("purged %d report(s) older than %d days",
                         purged, REPORT_RETENTION_DAYS)
        except Exception:
            log.exception("report purge failed")


def _reap_once() -> None:
    cutoff = datetime.now(timezone.utc) - timedelta(days=REAP_RETENTION_DAYS)
    for mailbox in store.reapable_mailboxes(tuple(GATED_PROVIDERS), cutoff.isoformat()):
        stonechat_id = mailbox["stonechat_id"]
        try:
            if mailbox["resource_id"]:
                provider = get_provider(mailbox["provider"])
                provider.destroy(mailbox["resource_id"], mailbox["meta"])
            store.delete_mailbox(stonechat_id)
            # The one place user data dies without the user asking — keep an
            # audit trail for the support inbox.
            log.info(
                "reaped %s mailbox %s of %s: subscription lapsed > %d days",
                mailbox["provider"], mailbox["resource_id"], stonechat_id[:12],
                REAP_RETENTION_DAYS,
            )
        except Exception:
            log.exception("failed to reap mailbox of %s — retrying next pass",
                          stonechat_id[:12])


def _wait_healthy(address: str) -> str | None:
    """Poll until the mailbox answers; returns the TLS fingerprint it reports.
    verify=False is fine here: this fingerprint only bootstraps the owner, who
    signs it — every other client trusts the signature, not this probe."""
    import time

    deadline = time.monotonic() + HEALTH_TIMEOUT_S
    last_error = "no response"
    while time.monotonic() < deadline:
        try:
            resp = httpx.get(f"{address}/health", timeout=5, verify=False)
            if resp.status_code == 200:
                return resp.json().get("tls_fp")
            last_error = f"HTTP {resp.status_code}"
        except httpx.HTTPError as e:
            last_error = str(e)
        time.sleep(3)
    raise ProviderError(
        f"mailbox never became healthy at {address} ({last_error}) — VM left running, "
        "delete and retry"
    )
