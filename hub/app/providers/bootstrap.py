"""Builds the startup script that turns a bare VM into a Zeon routing server.

The relay is a static Rust binary (relay/ — see docs/RUST_PORT.md), far too
big to inline in a startup script (clouds cap them: GCP 256 KB, DigitalOcean
64 KB, AWS 16 KB — the old gzip+base64-embedded Python relay already broke
AWS). So the script is a **fetch-stub**: it downloads the binary and verifies
a SHA-256 **pinned inside the script** before executing anything. The pin is
what keeps the trust model intact — this script travels over the cloud
metadata channel that already carries the owner token, so a hostile artifact
host or network can only make provisioning fail, never substitute a relay.

Where the binary comes from (hub env):

    ZEON_RELAY_BINARY      path to a static x86_64-musl `zeon-relay` on the
                           hub box. The hub serves it at GET /v1/relay-binary
                           (auth: the fetching VM's server_token, which this
                           script already carries) and pins its SHA-256 in
                           every startup script.
    ZEON_RELAY_BINARY_URL  URL the VM fetches. Defaults to
                           {ZEON_HUB_URL}/v1/relay-binary; point it at a GCS
                           bucket / GitHub release to take the hub out of the
                           download path.
    ZEON_HUB_URL           public base URL of this hub (e.g.
                           https://hub.zeonchat.com) — needed only to build
                           the default URL above.

Dedicated (sovereign) VMs additionally get the **host agent** pre-installed
(PROTOCOL.md "Host agent"): the hub mints an admin token, bakes it into the
startup script, and the owner's app connects to `https://<vm>:8200` to mint
invites — no SSH required. The agent is still Python, so its section installs
a venv; its guest-mailbox build context is the fetched relay binary plus a
two-line Dockerfile. Agent install is best-effort: a VM where Docker or pip
fails still routes its owner's mail.
"""

import base64
import gzip
import hashlib
import os
from pathlib import Path

from ..pushkey import mint_push_key
from .base import ProviderError

_HOST_AGENT_SOURCE = Path(__file__).resolve().parents[3] / "host_agent" / "main.py"

# Runtime image for a relay container built from a prebuilt binary — the same
# stage relay/Dockerfile ends in. Shared with the local/fleet providers.
RELAY_RUNTIME_DOCKERFILE = """\
FROM scratch
COPY zeon-relay /zeon-relay
ENV ZEON_DB=/data/mailbox.db
ENV ZEON_BLOBS=/data/blobs
ENV ZEON_TLS_DIR=/data
EXPOSE 8080
ENTRYPOINT ["/zeon-relay"]
"""

_TEMPLATE = """#!/usr/bin/env bash
set -euo pipefail

mkdir -p /opt/zeon /var/lib/zeon

# ---- fetch the relay binary (pinned SHA-256; see bootstrap.py) --------------
if ! command -v curl >/dev/null; then
  if command -v apt-get >/dev/null; then apt-get update -y && apt-get install -y curl
  elif command -v dnf >/dev/null; then dnf install -y curl
  fi
fi
curl -fsSL --retry 5 --retry-delay 3 {binary_auth}"{binary_url}" -o /opt/zeon/zeon-relay
echo "{binary_sha256}  /opt/zeon/zeon-relay" | sha256sum -c -
chmod +x /opt/zeon/zeon-relay

# Cloud VMs sit behind 1:1 NAT — services must advertise the public address
# (coturn below, and the host agent's invite URLs).
PUBLIC_IP=$(curl -s --max-time 3 -H "Metadata-Flavor: Google" \\
  "http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip" \\
  2>/dev/null || true)
if [ -z "$PUBLIC_IP" ]; then
  PUBLIC_IP=$(curl -s --max-time 3 http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || true)
fi

# TURN relay for calls (PROTOCOL.md "Calls"). Best-effort: a mailbox without
# coturn still routes mail — the app just falls back to STUN-only calling.
TURN_SECRET=""
if command -v apt-get >/dev/null; then
  apt-get update -y && apt-get install -y coturn openssl || true
elif command -v dnf >/dev/null; then
  dnf install -y coturn openssl || true
fi
if command -v turnserver >/dev/null; then
  TURN_SECRET=$(openssl rand -hex 32)
  cat > /etc/turnserver.conf <<TURN_EOF
listening-port={turn_port}
fingerprint
use-auth-secret
static-auth-secret=$TURN_SECRET
realm=zeon
min-port={turn_min_port}
max-port={turn_max_port}
no-cli
no-tls
no-dtls
TURN_EOF
  if [ -n "$PUBLIC_IP" ]; then echo "external-ip=$PUBLIC_IP" >> /etc/turnserver.conf; fi
  # Older Debian ships coturn disabled by default.
  sed -i 's/^#TURNSERVER_ENABLED=1/TURNSERVER_ENABLED=1/' /etc/default/coturn 2>/dev/null || true
  {{ systemctl enable coturn && systemctl restart coturn; }} 2>/dev/null || \\
    {{ systemctl enable turnserver && systemctl restart turnserver; }} 2>/dev/null || true
fi

cat > /etc/systemd/system/zeon.service <<UNIT_EOF
[Unit]
Description=Zeon routing server
After=network-online.target

[Service]
Environment=ZEON_OWNER_ID={owner_id}
Environment=ZEON_OWNER_TOKEN={owner_token}
Environment=ZEON_PORT={port}
Environment=ZEON_DB=/var/lib/zeon/mailbox.db
Environment=ZEON_BLOBS=/var/lib/zeon/blobs
Environment=ZEON_PUSH_GATEWAY={push_gateway}
Environment=ZEON_PUSH_KEY={push_key}
Environment=ZEON_TURN_SECRET=$TURN_SECRET
Environment=ZEON_TURN_PORT={turn_port}
ExecStart=/opt/zeon/zeon-relay
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
UNIT_EOF

systemctl daemon-reload
systemctl enable --now zeon
{host_agent_section}"""

# Appended after the mailbox is up so the hub's health poll never waits on
# Docker/pip installs. The agent itself is still Python.
_HOST_AGENT_TEMPLATE = """
# ---- host agent ("host your circle") ----------------------------------------
# Best-effort from here on: the owner's mailbox is already serving.
set +e

# Guest-mailbox build context: the relay binary + its runtime Dockerfile.
mkdir -p /opt/zeon/server
cp /opt/zeon/zeon-relay /opt/zeon/server/zeon-relay
cat > /opt/zeon/server/Dockerfile <<'DOCKER_EOF'
{runtime_dockerfile}DOCKER_EOF

cat > /opt/zeon/host_agent.py.gz.b64 <<'ZEON_EOF'
{host_agent_b64}
ZEON_EOF
base64 -d /opt/zeon/host_agent.py.gz.b64 | gunzip > /opt/zeon/host_agent.py

if command -v apt-get >/dev/null; then
  apt-get install -y docker.io python3-venv
elif command -v dnf >/dev/null; then
  dnf install -y docker python3 python3-pip
fi
systemctl enable --now docker

python3 -m venv /opt/zeon/venv
/opt/zeon/venv/bin/pip install --no-cache-dir "fastapi>=0.115" "uvicorn[standard]>=0.32" "httpx>=0.27"

cat > /etc/systemd/system/zeon-host-agent.service <<UNIT_EOF
[Unit]
Description=Zeon host agent
After=network-online.target docker.service
Requires=docker.service

[Service]
Environment=ZEON_HOST_AGENT_ADMIN_TOKEN={host_agent_token}
Environment=ZEON_HOST_AGENT_ADVERTISE_HOST=$PUBLIC_IP
Environment=ZEON_HOST_AGENT_PORT={host_agent_port}
Environment=ZEON_HOST_AGENT_DB=/var/lib/zeon/host_agent.db
Environment=ZEON_HOST_AGENT_TLS_DIR=/var/lib/zeon
Environment=ZEON_HOST_AGENT_SERVER_DIR=/opt/zeon/server
Environment=ZEON_PUSH_GATEWAY={push_gateway}
ExecStart=/opt/zeon/venv/bin/python /opt/zeon/host_agent.py
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
UNIT_EOF

systemctl daemon-reload
systemctl enable --now zeon-host-agent
"""

SERVER_PORT = 8080
TURN_PORT = 3478
TURN_RELAY_PORTS = (49152, 65535)  # coturn's default ephemeral relay range
HOST_AGENT_PORT = 8200
# The host agent publishes guest mailboxes on fixed ports from
# ZEON_HOST_AGENT_PORT_BASE (default 42000..42000+capacity-1, inside this
# range). The firewall rule stays the historical Docker-ephemeral range —
# it covers the agent's range and matches what deployed VMs already have open.
GUEST_PORT_RANGE = (32768, 60999)


def relay_binary_path() -> Path | None:
    path = os.environ.get("ZEON_RELAY_BINARY", "")
    return Path(path) if path else None


def _relay_binary_sha256() -> str:
    path = relay_binary_path()
    if path is None or not path.is_file():
        raise ProviderError(
            "sovereign provisioning needs ZEON_RELAY_BINARY: a static "
            "x86_64-musl zeon-relay build on the hub box (see relay/README.md)"
        )
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _relay_binary_url() -> str:
    url = os.environ.get("ZEON_RELAY_BINARY_URL", "")
    if url:
        return url
    hub_url = os.environ.get("ZEON_HUB_URL", "").rstrip("/")
    if not hub_url:
        raise ProviderError(
            "set ZEON_RELAY_BINARY_URL (artifact URL VMs can reach) or "
            "ZEON_HUB_URL (the hub then serves the binary at /v1/relay-binary)"
        )
    return f"{hub_url}/v1/relay-binary"


def _b64_wrap(data: bytes) -> str:
    encoded = base64.b64encode(data).decode()
    # wrap for readability in cloud consoles
    return "\n".join(encoded[i : i + 96] for i in range(0, len(encoded), 96))


def _gz_b64(data: bytes) -> str:
    # mtime=0: identical input always yields an identical script
    return _b64_wrap(gzip.compress(data, mtime=0))


def build_startup_script(
    owner_id: str, owner_token: str, host_agent_token: str | None = None
) -> str:
    push_gateway = os.environ.get("ZEON_PUSH_GATEWAY", "")
    host_agent_section = ""
    if host_agent_token:
        host_agent_section = _HOST_AGENT_TEMPLATE.format(
            runtime_dockerfile=RELAY_RUNTIME_DOCKERFILE,
            host_agent_b64=_gz_b64(_HOST_AGENT_SOURCE.read_bytes()),
            host_agent_token=host_agent_token,
            host_agent_port=HOST_AGENT_PORT,
            push_gateway=push_gateway,
        )
    # Hub-served downloads authenticate with the server_token this script
    # already carries (egress gate — main.py relay_binary). An external
    # artifact URL (GCS, GitHub) is fetched anonymously.
    hub_served = not os.environ.get("ZEON_RELAY_BINARY_URL", "")
    return _TEMPLATE.format(
        binary_url=_relay_binary_url(),
        binary_auth=(
            f'-H "Authorization: Bearer {owner_token}" ' if hub_served else ""
        ),
        binary_sha256=_relay_binary_sha256(),
        owner_id=owner_id,
        owner_token=owner_token,
        port=SERVER_PORT,
        push_gateway=push_gateway,
        push_key=mint_push_key(),
        turn_port=TURN_PORT,
        turn_min_port=TURN_RELAY_PORTS[0],
        turn_max_port=TURN_RELAY_PORTS[1],
        host_agent_section=host_agent_section,
    )
