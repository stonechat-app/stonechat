"""DigitalOcean provider.

Auth: STONECHAT_DO_TOKEN env var (a DO personal access token with write scope).
Plain REST via httpx — DO's API is simple enough that an SDK would be more
dependency than help.

MachineSpec mapping: machine_type = droplet size slug ("s-1vcpu-1gb"),
region = DO region slug ("fra1", "nyc1"). disk_gb is ignored — droplet disk
is fixed by the size slug.

Networking notes, and why DO is a good fit (BUSINESS.md):
- The public IPv4 sits directly on the droplet's interface — no 1:1 NAT, so
  the machine host's from-inside health checks of guest mailboxes just work.
- New droplets have NO default cloud firewall: every port is reachable, which
  covers the mailbox (8080), the browser transport (8443/udp), TURN, the host
  agent (8200) and the guest port range without the rule ceremony the GCP/AWS
  providers need. The bootstrap
  script does not enable ufw, so nothing on the box blocks them either.
- user_data is capped at 64 KiB; the bootstrap script is ~30 KB (gzipped
  payloads). Checked at provision time so growth fails loudly here, not as a
  cryptic droplet-create error.
"""

import os
import time

import httpx

from .base import CloudProvider, ProviderError, ProvisionRequest, ProvisionResult
from .bootstrap import SERVER_PORT, WT_PORT, build_startup_script

API = "https://api.digitalocean.com/v2"
IMAGE = "debian-12-x64"
USER_DATA_LIMIT = 64 * 1024
PROVISION_TIMEOUT_S = 300


class DOProvider(CloudProvider):
    name = "digitalocean"

    def __init__(self):
        self.token = os.environ.get("STONECHAT_DO_TOKEN")
        if not self.token:
            raise ProviderError("STONECHAT_DO_TOKEN env var is not set")

    def _client(self) -> httpx.Client:
        return httpx.Client(
            base_url=API,
            headers={"Authorization": f"Bearer {self.token}"},
            timeout=30,
        )

    def provision(self, req: ProvisionRequest) -> ProvisionResult:
        user_data = build_startup_script(
            req.owner_id, req.owner_token, req.machine_host_token
        )
        if len(user_data) > USER_DATA_LIMIT:
            raise ProviderError(
                f"startup script is {len(user_data)} bytes; DigitalOcean caps "
                f"user_data at {USER_DATA_LIMIT} (see bootstrap.py)"
            )

        name = f"stonechat-{req.owner_id[3:11].lower().replace('-', '')}"
        with self._client() as client:
            resp = client.post(
                "/droplets",
                json={
                    "name": name,
                    "region": req.spec.region,
                    "size": req.spec.machine_type,
                    "image": IMAGE,
                    "user_data": user_data,
                    "tags": ["stonechat-mailbox"],
                },
            )
            if resp.status_code >= 400:
                raise ProviderError(
                    f"droplet create failed ({resp.status_code}): "
                    f"{resp.text[:300]}"
                )
            droplet_id = resp.json()["droplet"]["id"]
            ip = self._wait_public_ip(client, droplet_id)

        return ProvisionResult(
            resource_id=str(droplet_id),
            address=f"https://{ip}:{SERVER_PORT}",
            # Fixed port on a VM, so derivable — published anyway so every
            # provider answers the same question the same way.
            wt_address=f"{ip}:{WT_PORT}",
            meta={"region": req.spec.region},
        )

    def destroy(self, resource_id: str, meta: dict) -> None:
        with self._client() as client:
            resp = client.delete(f"/droplets/{resource_id}")
            if resp.status_code == 404:
                return  # already gone — destroy is idempotent
            if resp.status_code >= 400:
                raise ProviderError(
                    f"droplet delete failed ({resp.status_code}): "
                    f"{resp.text[:300]}"
                )

    def _wait_public_ip(self, client: httpx.Client, droplet_id: int) -> str:
        deadline = time.monotonic() + PROVISION_TIMEOUT_S
        while time.monotonic() < deadline:
            droplet = client.get(f"/droplets/{droplet_id}").json()["droplet"]
            if droplet["status"] == "active":
                for net in droplet["networks"]["v4"]:
                    if net["type"] == "public":
                        return net["ip_address"]
            time.sleep(3)
        raise ProviderError(
            f"droplet {droplet_id} never became active with a public IP"
        )
