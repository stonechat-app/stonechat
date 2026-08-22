"""Google Cloud provider.

Auth: Application Default Credentials (GOOGLE_APPLICATION_CREDENTIALS or
`gcloud auth application-default login`).
Config: STONECHAT_GCP_PROJECT env var.

MachineSpec mapping: machine_type = GCP machine type ("e2-micro"),
region = GCP *zone* ("us-central1-a").
"""

import os

from .base import CloudProvider, ProviderError, ProvisionRequest, ProvisionResult
from .bootstrap import (
    GUEST_PORT_RANGE,
    MACHINE_HOST_PORT,
    SERVER_PORT,
    TURN_PORT,
    TURN_RELAY_PORTS,
    WT_PORT,
    build_startup_script,
)

FIREWALL_NAME = "stonechat-allow-mailbox"
NETWORK_TAG = "stonechat-mailbox"
SOURCE_IMAGE = "projects/debian-cloud/global/images/family/debian-12"


class GCPProvider(CloudProvider):
    name = "gcp"

    def __init__(self):
        try:
            from google.cloud import compute_v1  # noqa: F401
        except ImportError as e:
            raise ProviderError(
                "google-cloud-compute is not installed; "
                "pip install google-cloud-compute"
            ) from e
        self.project = os.environ.get("STONECHAT_GCP_PROJECT")
        if not self.project:
            raise ProviderError("STONECHAT_GCP_PROJECT env var is not set")

    def provision(self, req: ProvisionRequest) -> ProvisionResult:
        from google.cloud import compute_v1

        zone = req.spec.region
        instance_name = f"stonechat-{req.owner_id[3:11].lower().replace('-', '')}"

        self._ensure_firewall()

        instance = compute_v1.Instance(
            name=instance_name,
            machine_type=f"zones/{zone}/machineTypes/{req.spec.machine_type}",
            disks=[
                compute_v1.AttachedDisk(
                    boot=True,
                    auto_delete=True,
                    initialize_params=compute_v1.AttachedDiskInitializeParams(
                        source_image=SOURCE_IMAGE,
                        disk_size_gb=req.spec.disk_gb,
                    ),
                )
            ],
            network_interfaces=[
                compute_v1.NetworkInterface(
                    access_configs=[
                        compute_v1.AccessConfig(
                            name="External NAT",
                            type_="ONE_TO_ONE_NAT",
                        )
                    ]
                )
            ],
            metadata=compute_v1.Metadata(
                items=[
                    compute_v1.Items(
                        key="startup-script",
                        value=build_startup_script(
                            req.owner_id, req.owner_token, req.machine_host_token
                        ),
                    )
                ]
            ),
            tags=compute_v1.Tags(items=[NETWORK_TAG]),
        )

        client = compute_v1.InstancesClient()
        operation = client.insert(
            project=self.project, zone=zone, instance_resource=instance
        )
        operation.result(timeout=300)

        created = client.get(project=self.project, zone=zone, instance=instance_name)
        try:
            ip = created.network_interfaces[0].access_configs[0].nat_i_p
        except (IndexError, AttributeError) as e:
            raise ProviderError("instance created but has no external IP") from e

        return ProvisionResult(
            resource_id=instance_name,
            address=f"https://{ip}:{SERVER_PORT}",
            # Fixed port on a VM, so derivable — published anyway so every
            # provider answers the same question the same way.
            wt_address=f"{ip}:{WT_PORT}",
            meta={"zone": zone},
        )

    def destroy(self, resource_id: str, meta: dict) -> None:
        from google.api_core.exceptions import NotFound
        from google.cloud import compute_v1

        client = compute_v1.InstancesClient()
        try:
            operation = client.delete(
                project=self.project, zone=meta["zone"], instance=resource_id
            )
            operation.result(timeout=300)
        except NotFound:
            pass  # already gone — destroy is idempotent

    def _ensure_firewall(self) -> None:
        from google.cloud import compute_v1

        # Two rules by name so pre-TURN deployments grow the UDP rule too:
        # the mailbox itself, and coturn (TURN 3478 + its relay range).
        self._ensure_firewall_rule(
            FIREWALL_NAME,
            [compute_v1.Allowed(I_p_protocol="tcp", ports=[str(SERVER_PORT)])],
        )
        self._ensure_firewall_rule(
            f"{FIREWALL_NAME}-turn",
            [
                compute_v1.Allowed(
                    I_p_protocol="udp",
                    ports=[
                        str(TURN_PORT),
                        f"{TURN_RELAY_PORTS[0]}-{TURN_RELAY_PORTS[1]}",
                    ],
                )
            ],
        )
        # The browser transport: QUIC, so UDP, on its own fixed port. A rule of
        # its own by name so deployments predating it grow one on the next
        # provision — same reason TURN got a separate rule.
        self._ensure_firewall_rule(
            f"{FIREWALL_NAME}-wt",
            [compute_v1.Allowed(I_p_protocol="udp", ports=[str(WT_PORT)])],
        )
        # Machine host + the ports Docker publishes its guest mailboxes on.
        self._ensure_firewall_rule(
            f"{FIREWALL_NAME}-machine-host",
            [
                compute_v1.Allowed(
                    I_p_protocol="tcp",
                    ports=[
                        str(MACHINE_HOST_PORT),
                        f"{GUEST_PORT_RANGE[0]}-{GUEST_PORT_RANGE[1]}",
                    ],
                )
            ],
        )

    def _ensure_firewall_rule(self, name: str, allowed: list) -> None:
        from google.api_core.exceptions import Conflict, NotFound
        from google.cloud import compute_v1

        client = compute_v1.FirewallsClient()
        try:
            client.get(project=self.project, firewall=name)
            return
        except NotFound:
            pass
        rule = compute_v1.Firewall(
            name=name,
            direction="INGRESS",
            allowed=allowed,
            source_ranges=["0.0.0.0/0"],
            target_tags=[NETWORK_TAG],
        )
        try:
            client.insert(project=self.project, firewall_resource=rule).result(
                timeout=120
            )
        except Conflict:
            pass  # raced with another provision — rule exists
