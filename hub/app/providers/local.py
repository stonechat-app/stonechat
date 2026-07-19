"""Local Docker provider — for development, no cloud account needed.

"Provisions" a routing server as a Docker container on the machine running the
hub. The image comes from `image_context()`: with ZEON_RELAY_BINARY set (a
prebuilt static x86_64-musl relay), the build is an instant two-line COPY;
without it, relay/'s self-building Dockerfile compiles the crate inside the
build (dev fallback — also the path that produces the right architecture on
ARM laptops). The advertised address uses ZEON_LOCAL_HOST (default
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
from .bootstrap import RELAY_RUNTIME_DOCKERFILE, SERVER_PORT, relay_binary_path

IMAGE = "zeon-server:dev"
RELAY_DIR = Path(__file__).resolve().parents[3] / "relay"


@contextlib.contextmanager
def image_context():
    """Docker build context for the relay image: a prebuilt-binary context
    when ZEON_RELAY_BINARY is set (instant build, what fleet hosts should
    get), else the self-building relay/ crate."""
    binary = relay_binary_path()
    if binary is None:
        yield str(RELAY_DIR)
        return
    if not binary.is_file():
        raise ProviderError(f"ZEON_RELAY_BINARY={binary} does not exist")
    with tempfile.TemporaryDirectory() as td:
        shutil.copy(binary, Path(td) / "zeon-relay")
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
        name = f"zeon-{req.owner_id[3:11].lower().replace('-', '')}"
        _run(
            [
                "docker", "run", "-d",
                "--name", name,
                "--restart", "unless-stopped",
                "-p", f"0:{SERVER_PORT}",
                "-e", f"ZEON_OWNER_ID={req.owner_id}",
                "-e", f"ZEON_OWNER_TOKEN={req.owner_token}",
                "-e", f"ZEON_PUSH_GATEWAY={os.environ.get('ZEON_PUSH_GATEWAY', '')}",
                "-e", f"ZEON_PUSH_KEY={mint_push_key()}",
                "--label", f"zeon.machine_type={req.spec.machine_type}",
                IMAGE,
            ]
        )
        port = self._host_port(name)
        host = os.environ.get("ZEON_LOCAL_HOST", "127.0.0.1")
        return ProvisionResult(
            resource_id=name,
            address=f"https://{host}:{port}",
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

    def _host_port(self, name: str) -> str:
        out = _run(["docker", "inspect", name]).stdout
        info = json.loads(out)[0]
        bindings = info["NetworkSettings"]["Ports"].get(f"{SERVER_PORT}/tcp")
        if not bindings:
            raise ProviderError("container has no published port")
        return bindings[0]["HostPort"]
