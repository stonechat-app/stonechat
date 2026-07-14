"""Zeon hub — provisioner + directory.

Run: uvicorn app.main:app --port 8000
Config (env):
    ZEON_HUB_DB                  sqlite path (default hub.db)
    ZEON_GCP_PROJECT            required for provider=gcp
    ZEON_LOCAL_HOST             advertised host for provider=local (default 127.0.0.1)
    ZEON_STRIPE_WEBHOOK_SECRET  Stripe webhook signing secret (billing.py)
    ZEON_ADMIN_TOKEN            enables comp grants (billing.py)
    ZEON_TEST_CODE              reusable tester activation code (billing.py)
    ZEON_CORS_EXTRA             comma-separated extra CORS origins (dev)
"""

import base64
import logging
import re
import secrets

import httpx
from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

import os

from .billing import router as billing_router
from .deps import User, store
from .identity import PUBKEY_LEN, normalize_zeon_id, zeon_id_from_pubkey
from .words import looks_like_handle, normalize_handle
from .providers import (
    MachineSpec,
    ProviderError,
    ProvisionRequest,
    available_providers,
    get_provider,
)
from .providers.bootstrap import HOST_AGENT_PORT

log = logging.getLogger("zeon.hub")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

app = FastAPI(title="zeon-hub")
app.include_router(billing_router)

# Browser access is only the landing page's activation lookup (GET); the
# webhook is server-to-server and the app is not a browser.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://zeonchat.com",
        "https://www.zeonchat.com",
        *[o for o in os.environ.get("ZEON_CORS_EXTRA", "").split(",") if o],
    ],
    allow_methods=["GET"],
    allow_headers=["*"],
)

HEALTH_TIMEOUT_S = 240  # cloud VMs need to apt-get + pip install on first boot

# Paid providers and the plan each requires. Sovereign outranks private, so a
# Sovereign subscriber may also run on the shared fleet. `local` and
# `external` (self-hosted free tier) stay ungated.
GATED_PROVIDERS = {
    "fleet": "private",
    "gcp": "sovereign",
    "aws": "sovereign",
    "digitalocean": "sovereign",
}
PLAN_RANK = {"private": 1, "sovereign": 2}
# Dedicated-VM providers get the host agent baked into the VM.
DEDICATED_PROVIDERS = {"gcp", "aws", "digitalocean"}


# -- schemas --------------------------------------------------------------------

class RegisterIn(BaseModel):
    pubkey: str  # base64-encoded Ed25519 identity public key


class MachineIn(BaseModel):
    machine_type: str = Field(examples=["e2-micro", "t3.micro"])
    region: str = Field(examples=["us-central1-a", "us-east-1"])
    disk_gb: int = Field(default=10, ge=10, le=100)


class ServerIn(BaseModel):
    provider: str
    machine: MachineIn


class ExternalServerIn(BaseModel):
    address: str = Field(max_length=200, examples=["https://203.0.113.7:8080"])


class TlsSigIn(BaseModel):
    tls_fp: str = Field(max_length=64)  # base64 BLAKE2b-256 of the relay's DER cert
    tls_sig: str = Field(max_length=128)  # owner's Ed25519 sig over "zeon-v1-tls"||fp


# -- routes ---------------------------------------------------------------------

@app.get("/health")
async def health():
    return {"status": "ok", "providers": available_providers()}


@app.post("/v1/register", status_code=201)
async def register(body: RegisterIn):
    try:
        pubkey = base64.b64decode(body.pubkey, validate=True)
    except Exception:
        raise HTTPException(400, "pubkey is not valid base64")
    if len(pubkey) != PUBKEY_LEN:
        raise HTTPException(400, f"pubkey must be {PUBKEY_LEN} bytes")

    zeon_id = zeon_id_from_pubkey(pubkey)
    token = secrets.token_urlsafe(32)
    handle = store.create_user(zeon_id, body.pubkey, token)
    if handle is None:
        raise HTTPException(409, "this key is already registered")
    log.info("registered %s (%s)", zeon_id[:12], handle)
    return {"zeon_id": zeon_id, "handle": handle, "account_token": token}


@app.get("/v1/directory/{id_or_handle}")
async def directory(id_or_handle: str):
    """Resolve either form: a ZC- cryptographic ID or a zn-word-word-word
    handle. Clients MUST still verify the returned pubkey hashes to the
    returned zeon_id — handles are directory-trust, the ID is not."""
    if looks_like_handle(id_or_handle):
        user = store.user_by_handle(normalize_handle(id_or_handle))
        if not user:
            raise HTTPException(404, "unknown handle")
    else:
        try:
            canonical = normalize_zeon_id(id_or_handle)
        except ValueError as e:
            raise HTTPException(400, str(e))
        user = store.user_by_id(canonical)
        if not user:
            raise HTTPException(404, "unknown Zeon ID")

    server = store.server_for(user["zeon_id"])
    return {
        "zeon_id": user["zeon_id"],
        "handle": user["handle"],
        "pubkey": user["pubkey"],
        "server": (
            {
                "address": server["address"],
                "status": server["status"],
                "tls_fp": server["tls_fp"],
                "tls_sig": server["tls_sig"],
            }
            if server and server["status"] == "running"
            else None
        ),
    }


@app.post("/v1/server", status_code=202)
async def create_server(body: ServerIn, user: User, background: BackgroundTasks):
    if body.provider not in available_providers():
        raise HTTPException(
            400, f"unknown provider; available: {', '.join(available_providers())}"
        )
    required = GATED_PROVIDERS.get(body.provider)
    if required is not None:
        entitlement = store.entitlement_for(user["zeon_id"])
        if entitlement is None or (
            PLAN_RANK.get(entitlement["plan"], 0) < PLAN_RANK[required]
        ):
            raise HTTPException(402, {
                "code": "subscription_required",
                "plan_required": required,
                "message": f"the '{body.provider}' provider requires an active"
                           f" {required} plan",
            })
    server_token = secrets.token_urlsafe(32)
    # Dedicated VMs ship with the host agent pre-installed (PROTOCOL.md "Host
    # agent") — mint its admin token here so the app can pick it up from
    # GET /v1/server and mint invites with zero manual setup.
    host_agent_token = (
        secrets.token_urlsafe(32) if body.provider in DEDICATED_PROVIDERS else None
    )
    if not store.create_server(
        user["zeon_id"], body.provider, body.machine.model_dump(), server_token,
        host_agent_token,
    ):
        raise HTTPException(409, "you already have a server (one per user)")

    background.add_task(
        _provision, user["zeon_id"], body.provider, body.machine, server_token,
        host_agent_token,
    )
    return {"status": "provisioning"}


@app.post("/v1/server/external", status_code=201)
async def register_external_server(body: ExternalServerIn, user: User):
    """The free tier: the user runs their own relay anywhere and we list it in
    the directory. Ownership is proven, not claimed: the relay at that address
    must report this user's Zeon ID as its owner. We never see their token."""
    address = body.address.strip().rstrip("/")
    if not re.match(r"^https://[a-zA-Z0-9.\-:\[\]]+$", address):
        raise HTTPException(400, "address must look like https://host[:port]")

    try:
        # verify=False: relay certs are self-signed by design; the client-side
        # pin (owner-signed fingerprint) is the real trust anchor, not this probe.
        async with httpx.AsyncClient(timeout=8, verify=False) as client:
            resp = await client.get(f"{address}/health")
        health = resp.json()
    except Exception:
        raise HTTPException(
            400,
            "couldn't reach a Zeon mailbox at that address — it must be "
            "reachable from the internet",
        )
    if health.get("owner") != user["zeon_id"]:
        raise HTTPException(400, "that mailbox belongs to a different Zeon ID")

    if not store.create_external_server(user["zeon_id"], address, health.get("tls_fp")):
        raise HTTPException(409, "you already have a server (one per user)")
    log.info("external relay registered for %s", user["zeon_id"][:12])
    return {"status": "running", "address": address, "tls_fp": health.get("tls_fp")}


@app.post("/v1/server/tls")
async def publish_tls_sig(body: TlsSigIn, user: User):
    """The owner vouches for their mailbox's TLS key: an Ed25519 signature
    over "zeon-v1-tls" || fingerprint, verifiable by anyone against the
    identity key their Zeon ID commits to. We check it so the directory never
    serves garbage, but clients re-verify — our word doesn't count."""
    server = store.server_for(user["zeon_id"])
    if not server or server["status"] != "running":
        raise HTTPException(404, "no running server")
    if server["tls_fp"] is not None and server["tls_fp"] != body.tls_fp:
        raise HTTPException(400, "fingerprint does not match this mailbox's certificate")
    try:
        from nacl.signing import VerifyKey

        VerifyKey(base64.b64decode(user["pubkey"])).verify(
            b"zeon-v1-tls" + base64.b64decode(body.tls_fp),
            base64.b64decode(body.tls_sig),
        )
    except Exception:
        raise HTTPException(400, "signature does not verify against your identity key")
    store.set_tls_sig(user["zeon_id"], body.tls_sig)
    return {"status": "ok"}


def _host_agent_address(server_address: str) -> str:
    """The host agent lives on the same VM as the mailbox, on its own port:
    https://<ip>:8080 → https://<ip>:8200."""
    host = server_address.rsplit(":", 1)[0]
    return f"{host}:{HOST_AGENT_PORT}"


@app.get("/v1/server")
async def get_server(user: User):
    server = store.server_for(user["zeon_id"])
    if not server:
        return {"status": "none"}
    return {
        "status": server["status"],
        "provider": server["provider"],
        "machine": server["machine"],
        "address": server["address"],
        "server_token": server["server_token"],
        "tls_fp": server["tls_fp"],
        "error": server["error"],
        # Dedicated VMs come with the host agent pre-installed; hand the app
        # its address + admin token so the Invites screen connects itself.
        "host_agent": (
            {
                "address": _host_agent_address(server["address"]),
                "admin_token": server["host_agent_token"],
            }
            if server["host_agent_token"] and server["status"] == "running"
            and server["address"]
            else None
        ),
    }


@app.delete("/v1/server")
async def delete_server(user: User):
    server = store.server_for(user["zeon_id"])
    if not server:
        raise HTTPException(404, "no server")
    if server["resource_id"]:
        try:
            provider = get_provider(server["provider"])
            provider.destroy(server["resource_id"], server["meta"])
        except ProviderError as e:
            raise HTTPException(502, f"failed to destroy: {e}")
    store.delete_server(user["zeon_id"])
    return {"status": "deleted"}


# -- provisioning (background) ---------------------------------------------------

def _provision(zeon_id: str, provider_name: str, machine: MachineIn, server_token: str,
               host_agent_token: str | None = None):
    """Runs in a worker thread (sync BackgroundTask). Updates the row when done."""
    try:
        provider = get_provider(provider_name)
        result = provider.provision(
            ProvisionRequest(
                owner_id=zeon_id,
                owner_token=server_token,
                spec=MachineSpec(**machine.model_dump()),
                host_agent_token=host_agent_token,
            )
        )
        tls_fp = _wait_healthy(result.address)
        store.mark_running(zeon_id, result.resource_id, result.address, result.meta, tls_fp)
        log.info("server for %s running at %s", zeon_id[:12], result.address)
    except Exception as e:
        log.exception("provisioning failed for %s", zeon_id[:12])
        store.mark_error(zeon_id, str(e))


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
        f"server never became healthy at {address} ({last_error}) — VM left running, "
        "delete and retry"
    )
