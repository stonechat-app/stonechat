"""Local Docker provider — for development, no cloud account needed.

"Provisions" a routing server as a Docker container on the machine running the
hub. The image comes from `image_context()`: with STONECHAT_RELAY_BINARY set (a
prebuilt static x86_64-musl relay), the build is an instant two-line COPY;
without it, relay/'s self-building Dockerfile compiles the crate inside the
build (dev fallback — also the path that produces the right architecture on
ARM laptops). The advertised address uses STONECHAT_LOCAL_HOST (default
127.0.0.1); set it to your machine's LAN IP when testing from a real phone.

MachineSpec is accepted but only used as labels — a container has no
machine_type.
"""

import contextlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from ..pushkey import mint_push_key
from .base import CloudProvider, ProviderError, ProvisionRequest, ProvisionResult
from .bootstrap import RELAY_RUNTIME_DOCKERFILE, SERVER_PORT, WT_PORT, relay_binary_path

IMAGE = "stonechat-server:dev"
RELAY_DIR = Path(__file__).resolve().parents[3] / "relay"


@contextlib.contextmanager
def image_context():
    """Docker build context for the relay image: a prebuilt-binary context
    when STONECHAT_RELAY_BINARY is set (instant build, what fleet hosts should
    get), else the self-building relay/ crate."""
    binary = relay_binary_path()
    if binary is None:
        yield str(RELAY_DIR)
        return
    if not binary.is_file():
        raise ProviderError(f"STONECHAT_RELAY_BINARY={binary} does not exist")
    with tempfile.TemporaryDirectory() as td:
        shutil.copy(binary, Path(td) / "stonechat-relay")
        (Path(td) / "Dockerfile").write_text(RELAY_RUNTIME_DOCKERFILE)
        yield td


def _run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    proc = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if proc.returncode != 0:
        raise ProviderError(f"{' '.join(cmd[:3])}… failed: {proc.stderr.strip()[:500]}")
    return proc


class LocalDockerProvider(CloudProvider):
    name = "local"

    def __init__(self):
        try:
            _run(["docker", "version", "--format", "{{.Server.Version}}"])
        except (ProviderError, FileNotFoundError) as e:
            raise ProviderError("docker is not available") from e

    def provision(self, req: ProvisionRequest) -> ProvisionResult:
        self._ensure_image()
        name = f"stonechat-{req.owner_id[3:11].lower().replace('-', '')}"
        _run(
            [
                "docker", "run", "-d",
                "--name", name,
                "--restart", "unless-stopped",
                "-p", f"0:{SERVER_PORT}",
                # The browser transport. Docker picks the host port, so it is
                # discovered after the fact rather than chosen — which is why
                # it has to be published and cannot be derived.
                "-p", f"0:{WT_PORT}/udp",
                "-e",
                f"STONECHAT_WT_ADVERTISE="
                f"{os.environ.get('STONECHAT_LOCAL_HOST', '127.0.0.1')}",
                "-e", f"STONECHAT_OWNER_ID={req.owner_id}",
                "-e", f"STONECHAT_OWNER_TOKEN={req.owner_token}",
                "-e", f"STONECHAT_PUSH_GATEWAY={os.environ.get('STONECHAT_PUSH_GATEWAY', '')}",
                "-e", f"STONECHAT_PUSH_KEY={mint_push_key()}",
                "--label", f"stonechat.machine_type={req.spec.machine_type}",
                IMAGE,
            ]
        )
        port = self._host_port(name)
        host = os.environ.get("STONECHAT_LOCAL_HOST", "127.0.0.1")
        wt_port = self._host_port(name, WT_PORT, "udp")
        return ProvisionResult(
            resource_id=name,
            address=f"https://{host}:{port}",
            wt_address=f"{host}:{wt_port}" if wt_port else None,
            meta={},
        )

    def destroy(self, resource_id: str, meta: dict) -> None:
        subprocess.run(
            ["docker", "rm", "-f", resource_id], capture_output=True, text=True
        )  # non-zero (already gone) is fine — destroy is idempotent

    def _ensure_image(self) -> None:
        exists = subprocess.run(
            ["docker", "image", "inspect", IMAGE], capture_output=True
        )
        if exists.returncode != 0:
            with image_context() as ctx:
                _run(["docker", "build", "-t", IMAGE, ctx])

    def _host_port(
        self, name: str, port: int = SERVER_PORT, proto: str = "tcp"
    ) -> str | None:
        """The host port Docker mapped, or None when it mapped none.

        None is fatal for the mailbox itself and merely a missing feature for
        the browser transport, so the caller decides — an image built before
        the UDP port existed should still provision."""
        out = _run(["docker", "inspect", name]).stdout
        info = json.loads(out)[0]
        bindings = info["NetworkSettings"]["Ports"].get(f"{port}/{proto}")
        if not bindings:
            if port == SERVER_PORT:
                raise ProviderError("container has no published port")
            return None
        return bindings[0]["HostPort"]
