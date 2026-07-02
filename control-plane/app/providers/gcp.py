"""Google Cloud provider.

Auth: Application Default Credentials (GOOGLE_APPLICATION_CREDENTIALS or
`gcloud auth application-default login`).
Config: ZEON_GCP_PROJECT env var.

MachineSpec mapping: machine_type = GCP machine type ("e2-micro"),
region = GCP *zone* ("us-central1-a").
"""

import os

from .base import CloudProvider, ProviderError, ProvisionRequest, ProvisionResult
from .bootstrap import SERVER_PORT, build_startup_script

FIREWALL_NAME = "zeon-allow-server"
NETWORK_TAG = "zeon-server"
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
        self.project = os.environ.get("ZEON_GCP_PROJECT")
        if not self.project:
            raise ProviderError("ZEON_GCP_PROJECT env var is not set")

    def provision(self, req: ProvisionRequest) -> ProvisionResult:
        from google.cloud import compute_v1

        zone = req.spec.region
        instance_name = f"zeon-{req.owner_id[3:11].lower().replace('-', '')}"

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
                        value=build_startup_script(req.owner_id, req.owner_token),
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
            address=f"http://{ip}:{SERVER_PORT}",
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
        from google.api_core.exceptions import Conflict, NotFound
        from google.cloud import compute_v1

        client = compute_v1.FirewallsClient()
        try:
            client.get(project=self.project, firewall=FIREWALL_NAME)
            return
        except NotFound:
            pass
        rule = compute_v1.Firewall(
            name=FIREWALL_NAME,
            direction="INGRESS",
            allowed=[
                compute_v1.Allowed(I_p_protocol="tcp", ports=[str(SERVER_PORT)])
            ],
            source_ranges=["0.0.0.0/0"],
            target_tags=[NETWORK_TAG],
        )
        try:
            client.insert(project=self.project, firewall_resource=rule).result(
                timeout=120
            )
        except Conflict:
            pass  # raced with another provision — rule exists
