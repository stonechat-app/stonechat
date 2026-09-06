"""Offline conformance check for the Hetzner and Vultr adapters.

    python hub/scripts/check_providers.py

Neither cloud is free to provision against, so this drives both adapters over
a stubbed HTTP transport: real request building (base URL, auth header, JSON
body), real response parsing, real polling loop, fake wire. It catches the
class of bug an adapter is actually made of — a wrong field name, a status
value that never arrives, an error body read as success — and catches nothing
about whether the cloud behaves as documented. **A live-token provision is
still required before either provider serves a country** (TODO.md §20: "test
hairpin NAT first on every new provider").

The transport is injected by shimming the module's `httpx`, so the client the
adapter builds is the client under test rather than one this script hands it.
"""

import base64
import json
import sys
import time
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import os  # noqa: E402

# build_startup_script needs a relay binary to pin; any file will do, since
# nothing here executes the script.
os.environ.setdefault("STONECHAT_RELAY_BINARY", __file__)
os.environ.setdefault("STONECHAT_HUB_URL", "https://hub.stonechat.app")
os.environ.setdefault("STONECHAT_PUSH_GATEWAY", "https://push.stonechat.app")
os.environ.setdefault("STONECHAT_HETZNER_TOKEN", "test-hetzner-token")
os.environ.setdefault("STONECHAT_VULTR_TOKEN", "test-vultr-token")

from app.providers import ProviderError, ProvisionRequest, MachineSpec  # noqa: E402
from app.providers import hetzner, vultr  # noqa: E402

OWNER = "SC-A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0"
FAILURES: list[str] = []


# -- harness -------------------------------------------------------------------

class _Shim:
    """Stands in for a provider module's `httpx`, minting mocked clients."""

    def __init__(self, handler):
        self._handler = handler

    def __getattr__(self, name):
        return getattr(httpx, name)

    def Client(self, **kw):
        return httpx.Client(transport=httpx.MockTransport(self._handler), **kw)


def with_transport(module, handler):
    module.httpx = _Shim(handler)


def check(label, condition, detail=""):
    if condition:
        print(f"  ok    {label}")
    else:
        FAILURES.append(f"{label}{' — ' + detail if detail else ''}")
        print(f"  FAIL  {label}{' — ' + detail if detail else ''}")


def raises(label, fn, needle):
    try:
        fn()
    except ProviderError as e:
        check(label, needle in str(e), f"message was {str(e)!r}")
    except Exception as e:  # noqa: BLE001
        check(label, False, f"raised {type(e).__name__}: {e}")
    else:
        check(label, False, "did not raise")


def req(machine_type, region, machine_host=True):
    return ProvisionRequest(
        owner_id=OWNER,
        owner_token="owner-token",
        spec=MachineSpec(machine_type=machine_type, region=region),
        machine_host_token="mh-token" if machine_host else None,
    )


# Polling loops sleep 3s between attempts; nothing here waits on wall clock.
time.sleep = lambda _s: None


# -- Hetzner -------------------------------------------------------------------

def check_hetzner():
    print("hetzner")
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.setdefault("calls", []).append((request.method, str(request.url)))
        if request.method == "POST" and request.url.path == "/v1/servers":
            seen["create"] = json.loads(request.content)
            seen["auth"] = request.headers.get("authorization")
            return httpx.Response(201, json={"server": {"id": 4242, "status": "initializing"}})
        if request.method == "GET" and request.url.path == "/v1/servers/4242":
            # First poll: still booting, no address yet. Second: running.
            seen["polls"] = seen.get("polls", 0) + 1
            if seen["polls"] == 1:
                return httpx.Response(200, json={"server": {"status": "initializing", "public_net": {"ipv4": None}}})
            return httpx.Response(200, json={
                "server": {"status": "running", "public_net": {"ipv4": {"ip": "128.140.1.2"}}}
            })
        return httpx.Response(404, json={"error": {"code": "not_found", "message": "nope"}})

    with_transport(hetzner, handler)
    result = hetzner.HetznerProvider().provision(req("cx22", "fsn1"))

    body = seen["create"]
    check("create hits api.hetzner.cloud/v1/servers",
          ("POST", "https://api.hetzner.cloud/v1/servers") in seen["calls"])
    check("bearer token on the request", seen["auth"] == "Bearer test-hetzner-token")
    check("name derives from the owner id", body["name"] == "stonechat-a1b2c3d4")
    check("location is the MachineSpec region", body["location"] == "fsn1")
    check("server_type is the MachineSpec machine_type", body["server_type"] == "cx22")
    check("image is debian-12", body["image"] == "debian-12")
    check("starts after create", body["start_after_create"] is True)
    check("labelled for the abuse desk", body["labels"] == {"stonechat": "mailbox"})
    check("user_data is sent plain (not base64)",
          body["user_data"].startswith("#!/usr/bin/env bash"))
    check("machine host is baked in", "stonechat-machine-host" in body["user_data"])
    check("user_data fits Hetzner's 32 KiB cap",
          len(body["user_data"]) <= 32 * 1024, f"{len(body['user_data'])} bytes")
    check("polls past a server that is not running yet", seen["polls"] == 2)
    check("address is the relay port over the public IP",
          result.address == "https://128.140.1.2:8080", result.address)
    check("wt_address is the QUIC port", result.wt_address == "128.140.1.2:8443")
    check("resource_id is the server id", result.resource_id == "4242")
    check("meta carries the location for destroy", result.meta == {"location": "fsn1"})

    raises("ARM server types are refused before any API call",
           lambda: hetzner.HetznerProvider().provision(req("cax11", "fsn1")),
           "ARM64")

    # A create that never reaches "running".
    def stuck(request):
        if request.method == "POST":
            return httpx.Response(201, json={"server": {"id": 7, "status": "initializing"}})
        return httpx.Response(200, json={"server": {"status": "deleting", "public_net": {"ipv4": None}}})

    with_transport(hetzner, stuck)
    raises("a server that enters 'deleting' fails fast",
           lambda: hetzner.HetznerProvider().provision(req("cx22", "fsn1")),
           "deleting")

    # Errors carry Hetzner's machine-readable code, not just the HTTP status.
    with_transport(hetzner, lambda r: httpx.Response(
        409, json={"error": {"code": "uniqueness_error", "message": "name already used"}}))
    raises("create errors surface the Hetzner error code",
           lambda: hetzner.HetznerProvider().provision(req("cx22", "fsn1")),
           "uniqueness_error")

    with_transport(hetzner, lambda r: httpx.Response(
        404, json={"error": {"code": "not_found", "message": "gone"}}))
    try:
        hetzner.HetznerProvider().destroy("4242", {"location": "fsn1"})
        check("destroy is idempotent when the server is already gone", True)
    except Exception as e:  # noqa: BLE001
        check("destroy is idempotent when the server is already gone", False, str(e))

    with_transport(hetzner, lambda r: httpx.Response(
        500, json={"error": {"code": "server_error", "message": "boom"}}))
    raises("destroy raises on a real failure",
           lambda: hetzner.HetznerProvider().destroy("4242", {}),
           "server_error")


# -- Vultr ---------------------------------------------------------------------

def check_vultr():
    print("vultr")
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.setdefault("calls", []).append((request.method, str(request.url)))
        if request.method == "POST" and request.url.path == "/v2/instances":
            seen["create"] = json.loads(request.content)
            seen["auth"] = request.headers.get("authorization")
            return httpx.Response(202, json={
                "instance": {"id": "cb676a46-66fd-4dfb-b839-443f2e6c0b60",
                             "status": "pending", "main_ip": "0.0.0.0"}
            })
        if request.method == "GET" and request.url.path.startswith("/v2/instances/"):
            seen["polls"] = seen.get("polls", 0) + 1
            if seen["polls"] == 1:
                # Vultr reports "no address yet" as 0.0.0.0, not as an absence.
                return httpx.Response(200, json={
                    "instance": {"status": "pending", "main_ip": "0.0.0.0"}})
            return httpx.Response(200, json={
                "instance": {"status": "active", "main_ip": "45.32.1.2"}})
        return httpx.Response(404, json={"error": "not found", "status": 404})

    with_transport(vultr, handler)
    result = vultr.VultrProvider().provision(req("vc2-1c-1gb", "sao"))

    body = seen["create"]
    check("create hits api.vultr.com/v2/instances",
          ("POST", "https://api.vultr.com/v2/instances") in seen["calls"])
    check("bearer token on the request", seen["auth"] == "Bearer test-vultr-token")
    check("region is the MachineSpec region", body["region"] == "sao")
    check("plan is the MachineSpec machine_type", body["plan"] == "vc2-1c-1gb")
    check("os_id is Debian 12 x64", body["os_id"] == 2136)
    check("label derives from the owner id", body["label"] == "stonechat-a1b2c3d4")
    check("tagged for the abuse desk", body["tags"] == ["stonechat-mailbox"])
    check("backups off", body["backups"] == "disabled")

    decoded = base64.b64decode(body["user_data"]).decode()
    check("user_data is base64 (Vultr's one difference from the others)",
          decoded.startswith("#!/usr/bin/env bash"), decoded[:40])
    check("machine host is baked in", "stonechat-machine-host" in decoded)
    check("polls past main_ip 0.0.0.0", seen["polls"] == 2)
    check("address is the relay port over the public IP",
          result.address == "https://45.32.1.2:8080", result.address)
    check("wt_address is the QUIC port", result.wt_address == "45.32.1.2:8443")
    check("resource_id is the instance uuid",
          result.resource_id == "cb676a46-66fd-4dfb-b839-443f2e6c0b60")
    check("meta carries the region", result.meta == {"region": "sao"})

    def suspended(request):
        if request.method == "POST":
            return httpx.Response(202, json={"instance": {"id": "x", "status": "pending",
                                                          "main_ip": "0.0.0.0"}})
        return httpx.Response(200, json={"instance": {"status": "suspended",
                                                      "main_ip": "0.0.0.0"}})

    with_transport(vultr, suspended)
    raises("a suspended instance fails fast instead of burning the timeout",
           lambda: vultr.VultrProvider().provision(req("vc2-1c-1gb", "sao")),
           "suspended")

    with_transport(vultr, lambda r: httpx.Response(
        403, json={"error": "Invalid API key or unauthorized IP", "status": 403}))
    raises("create errors surface Vultr's message (403 = the IP allow-list)",
           lambda: vultr.VultrProvider().provision(req("vc2-1c-1gb", "sao")),
           "unauthorized IP")

    with_transport(vultr, lambda r: httpx.Response(404, json={"error": "not found"}))
    try:
        vultr.VultrProvider().destroy("gone", {"region": "sao"})
        check("destroy is idempotent when the instance is already gone", True)
    except Exception as e:  # noqa: BLE001
        check("destroy is idempotent when the instance is already gone", False, str(e))

    with_transport(vultr, lambda r: httpx.Response(500, json={"error": "boom"}))
    raises("destroy raises on a real failure",
           lambda: vultr.VultrProvider().destroy("x", {}),
           "boom")


# -- the shared startup script --------------------------------------------------

def check_bootstrap():
    """Both new clouds depend on the metadata probe added for them."""
    print("bootstrap")
    from app.providers.bootstrap import build_startup_script

    script = build_startup_script(OWNER, "owner-token", "mh-token")
    for cloud, url in (
        ("GCP", "metadata.google.internal"),
        ("EC2", "169.254.169.254/latest/meta-data/public-ipv4"),
        ("Hetzner", "169.254.169.254/hetzner/v1/metadata/public-ipv4"),
        ("DigitalOcean", "169.254.169.254/metadata/v1/interfaces/public/0/ipv4/address"),
        ("Vultr", "169.254.169.254/v1/interfaces/0/ipv4/address"),
    ):
        check(f"public IP is probed on {cloud}", url in script)
    check("metadata probes use curl -f so a 404 body can't become the address",
          "curl -fsS --max-time 3" in script)
    check("falls back to the interface's own global address",
          "ip -4 -o addr show scope global" in script)


if __name__ == "__main__":
    check_hetzner()
    check_vultr()
    check_bootstrap()
    print()
    if FAILURES:
        print(f"{len(FAILURES)} failed:")
        for f in FAILURES:
            print(f"  - {f}")
        sys.exit(1)
    print("all checks passed (mock transport — a live provision is still owed)")
