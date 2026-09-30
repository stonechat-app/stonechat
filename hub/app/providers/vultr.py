"""Vultr provider.

Auth: STONECHAT_VULTR_TOKEN env var (the account's API key). Note that Vultr
gates the API behind an **IP allow-list** as well as the key — Account → API →
Access Control — so the hub box's egress address has to be listed there. A
missing entry answers 403, which reads exactly like a bad key and is not one.

Plain REST via httpx, same shape as digitalocean.py and hetzner.py.

MachineSpec mapping: machine_type = plan id ("vc2-1c-1gb"), region = region id
("sao", "scl", "mex", "sgp", "nrt", "icn"). disk_gb is ignored — the disk is
fixed by the plan.

Why Vultr: it is the LatAm *and* Asia answer in one
adapter — São Paulo, Santiago, Mexico City, Tokyo, Osaka, Seoul, Singapore,
Mumbai. `vc2-1c-1gb` is the cheapest plan available in all of them.

**India is reachable and must stay unused** (countries.py): CERT-In mandates
180-day log retention and VPS KYC, which is why IN is excluded on principle.
`bom` being one API call away is exactly the reason that decision is written
down rather than enforced by what we happen to have integrated.

Networking, and why it lands in the same shape as DigitalOcean:
- The public IPv4 sits on the instance's own interface — no 1:1 NAT, so the
  mailbox host's from-inside health checks of guest mailboxes just work.
- A new instance belongs to no firewall group unless one is named, so the
  mailbox (8080/tcp), the browser transport (8443/udp), TURN and the machine
  host's guest port range are reachable with no rule ceremony. The bootstrap
  script does not enable ufw either.
- user_data must be **base64-encoded** on this API (the others take it plain),
  and it is the one thing here that fails silently rather than loudly: send it
  raw and the instance boots a cloud-init that ran nothing.
"""

import base64
import os
import time

import httpx

from .base import CloudProvider, ProviderError, ProvisionRequest, ProvisionResult
from .bootstrap import SERVER_PORT, WT_PORT, build_startup_script

API = "https://api.vultr.com/v2"
# Debian 12 x64 (bookworm), from GET /v2/os — an unauthenticated endpoint, so
# this is checkable with curl when it eventually goes stale.
OS_ID = 2136
PROVISION_TIMEOUT_S = 300
# Vultr reports an instance with no address yet as 0.0.0.0 rather than omitting
# the field, so "has an IP" is a value test, not a presence test.
UNASSIGNED_IP = "0.0.0.0"


class VultrProvider(CloudProvider):
    name = "vultr"

    def __init__(self):
        self.token = os.environ.get("STONECHAT_VULTR_TOKEN")
        if not self.token:
            raise ProviderError("STONECHAT_VULTR_TOKEN env var is not set")

    def _client(self) -> httpx.Client:
        return httpx.Client(
            base_url=API,
            headers={"Authorization": f"Bearer {self.token}"},
            timeout=30,
        )

    def provision(self, req: ProvisionRequest) -> ProvisionResult:
        user_data = build_startup_script(
            req.owner_id, req.owner_token, req.mailbox_host_token
        )
        label = f"stonechat-{req.owner_id[3:11].lower().replace('-', '')}"
        with self._client() as client:
            resp = client.post(
                "/instances",
                json={
                    "region": req.spec.region,
                    "plan": req.spec.machine_type,
                    "os_id": OS_ID,
                    "label": label,
                    "hostname": label,
                    "tags": ["stonechat-mailbox"],
                    "backups": "disabled",
                    "user_data": base64.b64encode(
                        user_data.encode()
                    ).decode(),
                },
            )
            if resp.status_code >= 400:
                raise ProviderError(
                    f"instance create failed ({resp.status_code}): "
                    f"{_error(resp)}"
                )
            instance_id = resp.json()["instance"]["id"]
            ip = self._wait_public_ip(client, instance_id)

        return ProvisionResult(
            resource_id=instance_id,
            address=f"https://{ip}:{SERVER_PORT}",
            # Fixed port on a VM, so derivable — published anyway so every
            # provider answers the same question the same way.
            wt_address=f"{ip}:{WT_PORT}",
            meta={"region": req.spec.region},
        )

    def destroy(self, resource_id: str, meta: dict) -> None:
        with self._client() as client:
            resp = client.delete(f"/instances/{resource_id}")
            if resp.status_code == 404:
                return  # already gone — destroy is idempotent
            if resp.status_code >= 400:
                raise ProviderError(
                    f"instance delete failed ({resp.status_code}): "
                    f"{_error(resp)}"
                )

    def _wait_public_ip(self, client: httpx.Client, instance_id: str) -> str:
        deadline = time.monotonic() + PROVISION_TIMEOUT_S
        while time.monotonic() < deadline:
            resp = client.get(f"/instances/{instance_id}")
            if resp.status_code == 404:
                # Deleted out from under us; it cannot come back.
                raise ProviderError(
                    f"instance {instance_id} disappeared while provisioning"
                )
            if resp.status_code < 400:
                instance = resp.json()["instance"]
                ip = instance.get("main_ip") or ""
                if instance["status"] == "active" and ip and ip != UNASSIGNED_IP:
                    return ip
                # Vultr suspends instances for billing and for abuse, and a
                # suspended instance never becomes active. Fail now rather than
                # spend the whole timeout on a state that cannot change.
                if instance["status"] == "suspended":
                    raise ProviderError(
                        f"instance {instance_id} was suspended while "
                        f"provisioning (billing or abuse hold on the account)"
                    )
            time.sleep(3)
        raise ProviderError(
            f"instance {instance_id} never became active with a public IP"
        )


def _error(resp: httpx.Response) -> str:
    """Vultr answers failures with `{"error": "...", "status": n}`."""
    try:
        return str(resp.json()["error"])
    except Exception:
        return resp.text[:300]
