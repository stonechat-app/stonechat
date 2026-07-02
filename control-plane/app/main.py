"""Zeon control plane — provisioner + directory.

Run: uvicorn app.main:app --port 8000
Config (env):
    ZEON_CP_DB          sqlite path (default control_plane.db)
    ZEON_GCP_PROJECT    required for provider=gcp
    ZEON_LOCAL_HOST     advertised host for provider=local (default 127.0.0.1)
"""

import base64
import logging
import secrets
from typing import Annotated

import httpx
from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

import os

from .db import Store
from .identity import PUBKEY_LEN, normalize_zeon_id, zeon_id_from_pubkey
from .providers import (
    MachineSpec,
    ProviderError,
    ProvisionRequest,
    available_providers,
    get_provider,
)

log = logging.getLogger("zeon.control-plane")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

store = Store(os.environ.get("ZEON_CP_DB", "control_plane.db"))
app = FastAPI(title="zeon-control-plane")

HEALTH_TIMEOUT_S = 240  # cloud VMs need to apt-get + pip install on first boot


# -- auth ---------------------------------------------------------------------

def current_user(authorization: Annotated[str | None, Header()] = None) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "missing bearer token")
    user = store.user_by_token(authorization.removeprefix("Bearer ").strip())
    if not user:
        raise HTTPException(401, "invalid token")
    return user


User = Annotated[dict, Depends(current_user)]


# -- schemas --------------------------------------------------------------------

class RegisterIn(BaseModel):
    pubkey: str  # base64-encoded X25519 public key


class MachineIn(BaseModel):
    machine_type: str = Field(examples=["e2-micro", "t3.micro"])
    region: str = Field(examples=["us-central1-a", "us-east-1"])
    disk_gb: int = Field(default=10, ge=10, le=100)


class ServerIn(BaseModel):
    provider: str
    machine: MachineIn


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
    if not store.create_user(zeon_id, body.pubkey, token):
        raise HTTPException(409, "this key is already registered")
    log.info("registered %s", zeon_id[:12])
    return {"zeon_id": zeon_id, "account_token": token}


@app.get("/v1/directory/{zeon_id}")
async def directory(zeon_id: str):
    try:
        canonical = normalize_zeon_id(zeon_id)
    except ValueError as e:
        raise HTTPException(400, str(e))
    user = store.user_by_id(canonical)
    if not user:
        raise HTTPException(404, "unknown Zeon ID")

    server = store.server_for(canonical)
    return {
        "zeon_id": canonical,
        "pubkey": user["pubkey"],
        "server": (
            {"address": server["address"], "status": server["status"]}
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
    server_token = secrets.token_urlsafe(32)
    if not store.create_server(
        user["zeon_id"], body.provider, body.machine.model_dump(), server_token
    ):
        raise HTTPException(409, "you already have a server (one per user)")

    background.add_task(
        _provision, user["zeon_id"], body.provider, body.machine, server_token
    )
    return {"status": "provisioning"}


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
        "error": server["error"],
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

def _provision(zeon_id: str, provider_name: str, machine: MachineIn, server_token: str):
    """Runs in a worker thread (sync BackgroundTask). Updates the row when done."""
    try:
        provider = get_provider(provider_name)
        result = provider.provision(
            ProvisionRequest(
                owner_id=zeon_id,
                owner_token=server_token,
                spec=MachineSpec(**machine.model_dump()),
            )
        )
        _wait_healthy(result.address)
        store.mark_running(zeon_id, result.resource_id, result.address, result.meta)
        log.info("server for %s running at %s", zeon_id[:12], result.address)
    except Exception as e:
        log.exception("provisioning failed for %s", zeon_id[:12])
        store.mark_error(zeon_id, str(e))


def _wait_healthy(address: str) -> None:
    import time

    deadline = time.monotonic() + HEALTH_TIMEOUT_S
    last_error = "no response"
    while time.monotonic() < deadline:
        try:
            resp = httpx.get(f"{address}/health", timeout=5)
            if resp.status_code == 200:
                return
            last_error = f"HTTP {resp.status_code}"
        except httpx.HTTPError as e:
            last_error = str(e)
        time.sleep(3)
    raise ProviderError(
        f"server never became healthy at {address} ({last_error}) — VM left running, "
        "delete and retry"
    )
