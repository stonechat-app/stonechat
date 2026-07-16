"""Builds the startup script that turns a bare VM into a Zeon routing server.

The routing server is a single file (server/main.py). We embed it gzipped and
base64-encoded in a cloud-init/startup script, so every provider boots the
exact same server with zero provider-specific packaging — no image registry
required. Payloads are compressed because clouds cap startup-script size:
GCP allows 256 KB but DigitalOcean and Azure allow only 64 KB (AWS's 16 KB
can't fit even the compressed script — that provider needs a fetch-stub
approach instead, see TODO.md).

Dedicated (sovereign) VMs additionally get the **host agent** pre-installed
(PROTOCOL.md "Host agent"): the hub mints an admin token, bakes it into the
startup script, and the owner's app connects to `https://<vm>:8200` to mint
invites — no SSH required. The agent needs Docker plus the zeon-server build
context on the box, both of which this script provides. Agent install is
best-effort: a VM where Docker fails to install still routes its owner's mail.
"""

import base64
import gzip
import os
from pathlib import Path

from ..pushkey import mint_push_key

_DEFAULT_SOURCE = Path(__file__).resolve().parents[3] / "server" / "main.py"
_HOST_AGENT_SOURCE = Path(__file__).resolve().parents[3] / "host_agent" / "main.py"

_TEMPLATE = """#!/usr/bin/env bash
set -euo pipefail

mkdir -p /opt/zeon /var/lib/zeon

cat > /opt/zeon/main.py.gz.b64 <<'ZEON_EOF'
{source_b64}
ZEON_EOF
base64 -d /opt/zeon/main.py.gz.b64 | gunzip > /opt/zeon/main.py

# Debian/Ubuntu vs Amazon Linux/Fedora (openssl: self-signed TLS cert at boot)
if command -v apt-get >/dev/null; then
  apt-get update -y && apt-get install -y python3-venv openssl
elif command -v dnf >/dev/null; then
  dnf install -y python3 python3-pip openssl
fi

python3 -m venv /opt/zeon/venv
/opt/zeon/venv/bin/pip install --no-cache-dir "fastapi>=0.115" "uvicorn[standard]>=0.32" "httpx>=0.27"

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
  apt-get install -y coturn || true
elif command -v dnf >/dev/null; then
  dnf install -y coturn || true
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
ExecStart=/opt/zeon/venv/bin/python /opt/zeon/main.py
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
UNIT_EOF

systemctl daemon-reload
systemctl enable --now zeon
{host_agent_section}"""

# Appended after the mailbox is up so the hub's health poll never waits on a
# Docker install. Same venv: the agent's deps are a subset of the server's.
_HOST_AGENT_TEMPLATE = """
# ---- host agent ("host your circle") ----------------------------------------
# Best-effort from here on: the owner's mailbox is already serving.
set +e

mkdir -p /opt/zeon/server
cat > /opt/zeon/server.tar.gz.b64 <<'ZEON_EOF'
{server_ctx_b64}
ZEON_EOF
base64 -d /opt/zeon/server.tar.gz.b64 | tar -xz -C /opt/zeon/server

cat > /opt/zeon/host_agent.py.gz.b64 <<'ZEON_EOF'
{host_agent_b64}
ZEON_EOF
base64 -d /opt/zeon/host_agent.py.gz.b64 | gunzip > /opt/zeon/host_agent.py

if command -v apt-get >/dev/null; then
  apt-get install -y docker.io
elif command -v dnf >/dev/null; then
  dnf install -y docker
fi
systemctl enable --now docker

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


def server_source() -> str:
    path = Path(os.environ.get("ZEON_SERVER_SOURCE", _DEFAULT_SOURCE))
    return path.read_text()


def _b64_wrap(data: bytes) -> str:
    encoded = base64.b64encode(data).decode()
    # wrap for readability in cloud consoles
    return "\n".join(encoded[i : i + 96] for i in range(0, len(encoded), 96))


def _gz_b64(data: bytes) -> str:
    # mtime=0: identical input always yields an identical script
    return _b64_wrap(gzip.compress(data, mtime=0))


def _server_context_tar() -> bytes:
    """The zeon-server docker build context (main.py, Dockerfile,
    requirements.txt) as a tar.gz, for the host agent to build guest images."""
    import io
    import tarfile

    source_dir = Path(os.environ.get("ZEON_SERVER_SOURCE", _DEFAULT_SOURCE)).parent
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name in ("main.py", "Dockerfile", "requirements.txt"):
            tar.add(source_dir / name, arcname=name)
    return buf.getvalue()


def build_startup_script(
    owner_id: str, owner_token: str, host_agent_token: str | None = None
) -> str:
    push_gateway = os.environ.get("ZEON_PUSH_GATEWAY", "")
    host_agent_section = ""
    if host_agent_token:
        host_agent_section = _HOST_AGENT_TEMPLATE.format(
            server_ctx_b64=_b64_wrap(_server_context_tar()),
            host_agent_b64=_gz_b64(_HOST_AGENT_SOURCE.read_bytes()),
            host_agent_token=host_agent_token,
            host_agent_port=HOST_AGENT_PORT,
            push_gateway=push_gateway,
        )
    return _TEMPLATE.format(
        source_b64=_gz_b64(server_source().encode()),
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
