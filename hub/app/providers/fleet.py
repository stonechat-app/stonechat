"""Fleet provider — the shared-host tier.

One mailbox container per customer, packed onto a pool of Docker hosts.
Placement is least-loaded (fewest stonechat containers). Each container gets its
own port, cgroup memory/CPU caps and a pids limit; the advertised address is
``http://<host advertise addr>:<port>``.

Host pool config (env, REQUIRED)::

    STONECHAT_FLEET_HOSTS="berlin=ssh://stonechat-fleet@10.0.0.5|203.0.113.5"

Comma-separated ``name=docker_endpoint|advertise_host``. An empty endpoint
means the local Docker daemon — that is for LAPTOP DEV ONLY (e.g. the e2e
harness uses ``local=|127.0.0.1``): mailboxes never run on the deployed
hub machine, so there is deliberately no unset-fallback. SSH
endpoints need key auth set up for the hub user (see
deploy/fleet-host.sh).

Optional hardening: STONECHAT_FLEET_RUNTIME=runsc runs every container under
gVisor (host must have it installed).
"""

import json
import os
import random
import subprocess
from dataclasses import dataclass

from ..pushkey import mint_push_key
from .base import CloudProvider, ProviderError, ProvisionRequest, ProvisionResult
from .bootstrap import (
    PORT_ATTEMPTS,
    SERVER_PORT,
    WT_PORT,
    is_port_conflict,
    pick_ports,
    replace_ports,
)
from .local import image_context, image_tag

FLEET_LABEL = "stonechat.fleet=1"

MEMORY_LIMIT = "192m"
CPU_LIMIT = "0.5"
PIDS_LIMIT = "128"


@dataclass
class FleetHost:
    name: str
    endpoint: str  # docker -H value; "" = local daemon
    advertise: str  # public address clients connect to


def _parse_hosts() -> list[FleetHost]:
    raw = os.environ.get("STONECHAT_FLEET_HOSTS", "").strip()
    if not raw:
        # No silent local fallback: mailboxes must never land on the
        # hub machine. Dev/e2e opts into localhost EXPLICITLY.
        raise ProviderError(
            "STONECHAT_FLEET_HOSTS is not set; the fleet provider never uses the "
            "local daemon implicitly (mailboxes don't run on the "
            'hub box). For laptop dev use "local=|127.0.0.1".'
        )
    hosts = []
    for part in raw.split(","):
        try:
            name, rest = part.strip().split("=", 1)
            endpoint, advertise = rest.split("|", 1)
        except ValueError:
            raise ProviderError(
                f"bad STONECHAT_FLEET_HOSTS entry {part!r}; "
                "expected name=docker_endpoint|advertise_host"
            )
        hosts.append(FleetHost(name=name, endpoint=endpoint, advertise=advertise))
    return hosts


class FleetProvider(CloudProvider):
    name = "fleet"

    def __init__(self):
        self.hosts = _parse_hosts()
        self.runtime = os.environ.get("STONECHAT_FLEET_RUNTIME", "")
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
            + ["image", "inspect", image_tag()],
            capture_output=True,
        )
        if probe.returncode != 0:
            # docker build ships the local context to the remote daemon. With
            # STONECHAT_RELAY_BINARY set this is a prebuilt-binary COPY (instant);
            # without it the host compiles the crate — dev only, keep real
            # fleet hosts on the prebuilt path.
            with image_context() as ctx:
                self._docker(host, "build", "-t", image_tag(), ctx)

    # -- provider interface ----------------------------------------------------------

    def provision(self, req: ProvisionRequest) -> ProvisionResult:
        host = min(self.hosts, key=self._tenant_count)
        self._ensure_image(host)

        name = f"stonechat-{req.owner_id[3:11].lower().replace('-', '')}"
        tcp_port, udp_port = pick_ports()
        args = [
            "run", "-d",
            "--name", name,
            "--restart", "unless-stopped",
            # **Pinned, not `0:`.** Letting Docker choose means it chooses
            # again on every restart — and `--restart unless-stopped` means a
            # host reboot restarts everything. Every stored address would then
            # be wrong, with nothing in any log to say why. Pinned ports
            # survive restarts; verified, not assumed.
            "-p", f"{tcp_port}:{SERVER_PORT}",
            # The browser transport, same reasoning. UDP, because QUIC.
            "-p", f"{udp_port}:{WT_PORT}/udp",
            # The names the browser transport's certificates must carry. The
            # relay cannot discover this — inside the container it sees a
            # private address — and a certificate without a matching SAN is
            # refused by browsers with an error that reads like a pin mismatch.
            "-e", f"STONECHAT_WT_ADVERTISE={host.advertise}",
            "-e", f"STONECHAT_OWNER_ID={req.owner_id}",
            "-e", f"STONECHAT_OWNER_TOKEN={req.owner_token}",
            "-e", f"STONECHAT_PUSH_GATEWAY={os.environ.get('STONECHAT_PUSH_GATEWAY', '')}",
            "-e", f"STONECHAT_PUSH_KEY={mint_push_key()}",
            "--label", FLEET_LABEL,
            "--memory", MEMORY_LIMIT,
            "--cpus", CPU_LIMIT,
            "--pids-limit", PIDS_LIMIT,
        ]
        if self.runtime:
            args += ["--runtime", self.runtime]
        args.append(image_tag())
        self._run_with_free_ports(host, name, args)

        port = self._published_port(host, name)
        wt_port = self._published_port(host, name, WT_PORT, "udp")
        return ProvisionResult(
            resource_id=name,
            address=f"https://{host.advertise}:{port}",
            wt_address=f"{host.advertise}:{wt_port}" if wt_port else None,
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

    def _run_with_free_ports(self, host: FleetHost, name: str, args: list[str]) -> None:
        """Start the container, re-rolling the ports if either is taken.

        Check-then-act would still race two concurrent provisions against each
        other; letting `docker run` fail cannot. It also catches the case
        Docker cannot see — the kernel handing that port to an outbound socket,
        since this *is* the ephemeral range.

        A failed `docker run` leaves the container in `created` state, so the
        name has to be freed before retrying.
        """
        for _ in range(PORT_ATTEMPTS):
            try:
                self._docker(host, *args)
                return
            except ProviderError as e:
                if not is_port_conflict(e):
                    raise  # a real failure — do not mask it as a collision
                try:
                    self._docker(host, "rm", "-f", name)
                except ProviderError:
                    pass
                tcp, udp = pick_ports()
                args = replace_ports(args, tcp, udp)
        raise ProviderError(
            f"no free port pair on {host.name} after {PORT_ATTEMPTS} attempts"
        )

    def _published_port(
        self, host: FleetHost, name: str, port: int = SERVER_PORT, proto: str = "tcp"
    ) -> str | None:
        """The host port Docker mapped, or None when it mapped none.

        None is fatal for the mailbox and merely a missing feature for the
        browser transport, so the caller decides — a fleet host still running
        an image from before the UDP port existed should keep provisioning."""
        info = json.loads(self._docker(host, "inspect", name))[0]
        bindings = info["NetworkSettings"]["Ports"].get(f"{port}/{proto}")
        if not bindings:
            if port == SERVER_PORT:
                raise ProviderError("container has no published port")
            return None
        return bindings[0]["HostPort"]
