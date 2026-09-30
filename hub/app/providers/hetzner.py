"""Hetzner Cloud provider.

Auth: STONECHAT_HETZNER_TOKEN env var (a project API token with read+write).
Plain REST via httpx, like digitalocean.py — the surface we need is three
calls, so hcloud-python would be more dependency than help, and httpx is
already a hub requirement.

MachineSpec mapping: machine_type = server type name ("cx22", "cpx11"),
region = *location* name ("fsn1", "nbg1", "hel1", "sin"). disk_gb is ignored —
the disk is fixed by the server type, as on DigitalOcean.

Locations, and the types they take (countries.py is the only caller that needs
this table):

    fsn1  Falkenstein, DE  cx22 / cpx11
    nbg1  Nuremberg, DE    cx22 / cpx11
    hel1  Helsinki, FI     cx22 / cpx11
    sin   Singapore, SG    cpx11          (the Intel CX line is EU-only)
    ash   Ashburn, US      cpx11
    hil   Hillsboro, US    cpx11

Why Hetzner: the cheapest RAM in the industry, which
is where the Mailbox tier's margin is actually decided, plus cheap IPv4 for the
Machine tier — the only provider that wins both. DE, FI and SG in one adapter.

Networking, and why it lands in the same shape as DigitalOcean:
- The public IPv4 sits on the server's own interface — no 1:1 NAT, so the
  mailbox host's from-inside health checks of guest mailboxes just work. This
  is the property EC2 lacks and that killed the AWS adapter.
- A new server has NO firewall attached unless one is asked for, so the mailbox
  (8080/tcp), the browser transport (8443/udp), TURN and the mailbox host's
  guest port range are reachable without the rule ceremony GCP and AWS need.
  The bootstrap script does not enable ufw, so nothing on the box blocks them
  either.
- user_data is capped at 32 KiB by the API; the dedicated script measures
  ~15 KB today. Checked at provision time so growth fails loudly here rather
  than as a cryptic server-create error.

**x86 only.** The relay ships as a static *x86_64*-musl binary, so Hetzner's
ARM types (cax*) would fetch an artifact the kernel cannot exec: the pinned
SHA-256 check passes, systemd then fails in a loop, and the only symptom is a
health poll that times out four minutes later. Refused up front instead, where
the message can name the actual cause.
"""

import os
import time

import httpx

from .base import CloudProvider, ProviderError, ProvisionRequest, ProvisionResult
from .bootstrap import SERVER_PORT, WT_PORT, build_startup_script

API = "https://api.hetzner.cloud/v1"
IMAGE = "debian-12"
USER_DATA_LIMIT = 32 * 1024
PROVISION_TIMEOUT_S = 300
# Hetzner's ARM64 line. The relay binary is x86_64 — see the module docstring.
ARM_TYPE_PREFIX = "cax"


class HetznerProvider(CloudProvider):
    name = "hetzner"

    def __init__(self):
        self.token = os.environ.get("STONECHAT_HETZNER_TOKEN")
        if not self.token:
            raise ProviderError("STONECHAT_HETZNER_TOKEN env var is not set")

    def _client(self) -> httpx.Client:
        return httpx.Client(
            base_url=API,
            headers={"Authorization": f"Bearer {self.token}"},
            timeout=30,
        )

    def provision(self, req: ProvisionRequest) -> ProvisionResult:
        server_type = req.spec.machine_type
        if server_type.lower().startswith(ARM_TYPE_PREFIX):
            raise ProviderError(
                f"server type {server_type!r} is ARM64; the relay is a static "
                f"x86_64-musl binary. Use an x86 type (cx22, cpx11)."
            )

        user_data = build_startup_script(
            req.owner_id, req.owner_token, req.mailbox_host_token
        )
        if len(user_data) > USER_DATA_LIMIT:
            raise ProviderError(
                f"startup script is {len(user_data)} bytes; Hetzner caps "
                f"user_data at {USER_DATA_LIMIT} (see bootstrap.py)"
            )

        name = f"stonechat-{req.owner_id[3:11].lower().replace('-', '')}"
        with self._client() as client:
            resp = client.post(
                "/servers",
                json={
                    "name": name,
                    "location": req.spec.region,
                    "server_type": server_type,
                    "image": IMAGE,
                    "user_data": user_data,
                    "start_after_create": True,
                    "labels": {"stonechat": "mailbox"},
                },
            )
            if resp.status_code >= 400:
                raise ProviderError(
                    f"server create failed ({resp.status_code}): "
                    f"{_error(resp)}"
                )
            server_id = resp.json()["server"]["id"]
            ip = self._wait_public_ip(client, server_id)

        return ProvisionResult(
            resource_id=str(server_id),
            address=f"https://{ip}:{SERVER_PORT}",
            # Fixed port on a VM, so derivable — published anyway so every
            # provider answers the same question the same way.
            wt_address=f"{ip}:{WT_PORT}",
            meta={"location": req.spec.region},
        )

    def destroy(self, resource_id: str, meta: dict) -> None:
        # Hetzner *accepts* the delete and runs it as an action; a 200 means
        # queued, not finished. Same fire-and-forget posture as DigitalOcean —
        # but the hub drops its row on success, so a queued delete that then
        # fails leaves a server that bills forever and that nothing else knows
        # about. Only the Hetzner console would show it.
        with self._client() as client:
            resp = client.delete(f"/servers/{resource_id}")
            if resp.status_code == 404:
                return  # already gone — destroy is idempotent
            if resp.status_code >= 400:
                raise ProviderError(
                    f"server delete failed ({resp.status_code}): "
                    f"{_error(resp)}"
                )

    def _wait_public_ip(self, client: httpx.Client, server_id: int) -> str:
        """Block until the server is running and holds an IPv4.

        Hetzner returns the address in the create response already, but the
        create can still be followed by a failure the API only reports through
        `status`. Polling costs one request per three seconds and turns a
        server that never boots into an error here rather than a health-check
        timeout four minutes later.
        """
        deadline = time.monotonic() + PROVISION_TIMEOUT_S
        while time.monotonic() < deadline:
            resp = client.get(f"/servers/{server_id}")
            if resp.status_code == 404:
                # Deleted out from under us. It cannot come back, so waiting
                # out the timeout only delays the same answer.
                raise ProviderError(
                    f"server {server_id} disappeared while provisioning"
                )
            if resp.status_code < 400:
                server = resp.json()["server"]
                ipv4 = (server.get("public_net") or {}).get("ipv4")
                if server["status"] == "running" and ipv4 and ipv4.get("ip"):
                    return ipv4["ip"]
                if server["status"] in ("deleting", "unknown"):
                    raise ProviderError(
                        f"server {server_id} entered status {server['status']!r} "
                        f"while provisioning"
                    )
            time.sleep(3)
        raise ProviderError(
            f"server {server_id} never became running with a public IP"
        )


def _error(resp: httpx.Response) -> str:
    """Hetzner's error envelope, degrading to the raw body.

    Every failure carries `{"error": {"code", "message"}}`; the code is the
    half worth reading (`uniqueness_error`, `resource_unavailable`,
    `invalid_input`), so surface both.
    """
    try:
        err = resp.json()["error"]
        return f"{err['code']}: {err['message']}"
    except Exception:
        return resp.text[:300]
