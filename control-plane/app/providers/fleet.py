"""Fleet provider — the shared-host tier.

One mailbox container per customer, packed onto a pool of Docker hosts.
Placement is least-loaded (fewest zeon containers). Each container gets its
own port, cgroup memory/CPU caps and a pids limit; the advertised address is
``http://<host advertise addr>:<port>``.

Host pool config (env)::

    ZEON_FLEET_HOSTS="berlin=ssh://root@10.0.0.5|203.0.113.5,local=|127.0.0.1"

Comma-separated ``name=docker_endpoint|advertise_host``. An empty endpoint
means the local Docker daemon. SSH endpoints need key auth set up for the
control-plane user. Unset → a single local-daemon host advertising
ZEON_LOCAL_HOST (dev mode, same as the ``local`` provider but with fleet
packing/limits).

Optional hardening: ZEON_FLEET_RUNTIME=runsc runs every container under
gVisor (host must have it installed).
"""

import json
import os
import subprocess
from dataclasses import dataclass

from .base import CloudProvider, ProviderError, ProvisionRequest, ProvisionResult
from .bootstrap import SERVER_PORT
from .local import IMAGE, SERVER_DIR

FLEET_LABEL = "zeon.fleet=1"
MEMORY_LIMIT = "192m"
CPU_LIMIT = "0.5"
PIDS_LIMIT = "128"


@dataclass
class FleetHost:
    name: str
    endpoint: str  # docker -H value; "" = local daemon
    advertise: str  # public address clients connect to


def _parse_hosts() -> list[FleetHost]:
    raw = os.environ.get("ZEON_FLEET_HOSTS", "").strip()
    if not raw:
        return [
            FleetHost(
                name="local",
                endpoint="",
                advertise=os.environ.get("ZEON_LOCAL_HOST", "127.0.0.1"),
            )
        ]
    hosts = []
    for part in raw.split(","):
        try:
            name, rest = part.strip().split("=", 1)
            endpoint, advertise = rest.split("|", 1)
        except ValueError:
            raise ProviderError(
                f"bad ZEON_FLEET_HOSTS entry {part!r}; "
                "expected name=docker_endpoint|advertise_host"
            )
        hosts.append(FleetHost(name=name, endpoint=endpoint, advertise=advertise))
    return hosts


class FleetProvider(CloudProvider):
    name = "fleet"

    def __init__(self):
        self.hosts = _parse_hosts()
        self.runtime = os.environ.get("ZEON_FLEET_RUNTIME", "")
        try:
            self._docker(self.hosts[0], "version", "--format", "{{.Server.Version}}")
        except (ProviderError, FileNotFoundError) as e:
            raise ProviderError(f"docker unreachable on fleet host {self.hosts[0].name}") from e

    # -- docker plumbing ----------------------------------------------------------

    def _docker(self, host: FleetHost, *args: str) -> str:
        cmd = ["docker"]
        if host.endpoint:
            cmd += ["-H", host.endpoint]
        cmd += list(args)
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            raise ProviderError(
                f"docker on {host.name} failed: {proc.stderr.strip()[:500]}"
            )
        return proc.stdout

    def _host_by_name(self, name: str) -> FleetHost | None:
        for host in self.hosts:
            if host.name == name:
                return host
        return None

    def _tenant_count(self, host: FleetHost) -> int:
        out = self._docker(
            host, "ps", "-q", "--filter", f"label={FLEET_LABEL}"
        )
        return len(out.split())

    def _ensure_image(self, host: FleetHost) -> None:
        probe = subprocess.run(
            ["docker"] + (["-H", host.endpoint] if host.endpoint else [])
            + ["image", "inspect", IMAGE],
            capture_output=True,
        )
        if probe.returncode != 0:
            # docker build ships the local server/ context to the remote daemon
            self._docker(host, "build", "-t", IMAGE, str(SERVER_DIR))

    # -- provider interface ----------------------------------------------------------

    def provision(self, req: ProvisionRequest) -> ProvisionResult:
        host = min(self.hosts, key=self._tenant_count)
        self._ensure_image(host)

        name = f"zeon-{req.owner_id[3:11].lower().replace('-', '')}"
        args = [
            "run", "-d",
            "--name", name,
            "--restart", "unless-stopped",
            "-p", f"0:{SERVER_PORT}",
            "-e", f"ZEON_OWNER_ID={req.owner_id}",
            "-e", f"ZEON_OWNER_TOKEN={req.owner_token}",
            "--label", FLEET_LABEL,
            "--memory", MEMORY_LIMIT,
            "--cpus", CPU_LIMIT,
            "--pids-limit", PIDS_LIMIT,
        ]
        if self.runtime:
            args += ["--runtime", self.runtime]
        args.append(IMAGE)
        self._docker(host, *args)

        port = self._published_port(host, name)
        return ProvisionResult(
            resource_id=name,
            address=f"http://{host.advertise}:{port}",
            meta={"host": host.name},
        )

    def destroy(self, resource_id: str, meta: dict) -> None:
        host = self._host_by_name(meta.get("host", ""))
        candidates = [host] if host else self.hosts  # config may have changed
        for h in candidates:
            try:
                self._docker(h, "rm", "-f", resource_id)
                return
            except ProviderError:
                continue  # not on this host / already gone — idempotent

    def _published_port(self, host: FleetHost, name: str) -> str:
        info = json.loads(self._docker(host, "inspect", name))[0]
        bindings = info["NetworkSettings"]["Ports"].get(f"{SERVER_PORT}/tcp")
        if not bindings:
            raise ProviderError("container has no published port")
        return bindings[0]["HostPort"]
