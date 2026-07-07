"""Builds the startup script that turns a bare VM into a Zeon routing server.

The routing server is a single file (server/main.py). We embed it base64-encoded
in a cloud-init/startup script, so every provider boots the exact same server
with zero provider-specific packaging — no image registry required.
"""

import base64
import os
from pathlib import Path

_DEFAULT_SOURCE = Path(__file__).resolve().parents[3] / "server" / "main.py"

_TEMPLATE = """#!/usr/bin/env bash
set -euo pipefail

mkdir -p /opt/zeon /var/lib/zeon

cat > /opt/zeon/main.py.b64 <<'ZEON_EOF'
{source_b64}
ZEON_EOF
base64 -d /opt/zeon/main.py.b64 > /opt/zeon/main.py

# Debian/Ubuntu vs Amazon Linux/Fedora (openssl: self-signed TLS cert at boot)
if command -v apt-get >/dev/null; then
  apt-get update -y && apt-get install -y python3-venv openssl
elif command -v dnf >/dev/null; then
  dnf install -y python3 python3-pip openssl
fi

python3 -m venv /opt/zeon/venv
/opt/zeon/venv/bin/pip install --no-cache-dir "fastapi>=0.115" "uvicorn[standard]>=0.32" "httpx>=0.27"

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
  # Cloud VMs sit behind 1:1 NAT — coturn must advertise the public address.
  PUBLIC_IP=$(curl -s --max-time 3 -H "Metadata-Flavor: Google" \\
    "http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip" \\
    2>/dev/null || true)
  if [ -z "$PUBLIC_IP" ]; then
    PUBLIC_IP=$(curl -s --max-time 3 http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || true)
  fi
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
"""

SERVER_PORT = 8080
TURN_PORT = 3478
TURN_RELAY_PORTS = (49152, 65535)  # coturn's default ephemeral relay range


def server_source() -> str:
    path = Path(os.environ.get("ZEON_SERVER_SOURCE", _DEFAULT_SOURCE))
    return path.read_text()


def build_startup_script(owner_id: str, owner_token: str) -> str:
    source_b64 = base64.b64encode(server_source().encode()).decode()
    # wrap for readability in cloud consoles
    wrapped = "\n".join(source_b64[i : i + 96] for i in range(0, len(source_b64), 96))
    return _TEMPLATE.format(
        source_b64=wrapped,
        owner_id=owner_id,
        owner_token=owner_token,
        port=SERVER_PORT,
        push_gateway=os.environ.get("ZEON_PUSH_GATEWAY", ""),
        turn_port=TURN_PORT,
        turn_min_port=TURN_RELAY_PORTS[0],
        turn_max_port=TURN_RELAY_PORTS[1],
    )
