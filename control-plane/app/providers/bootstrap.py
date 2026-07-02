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

# Debian/Ubuntu vs Amazon Linux/Fedora
if command -v apt-get >/dev/null; then
  apt-get update -y && apt-get install -y python3-venv
elif command -v dnf >/dev/null; then
  dnf install -y python3 python3-pip
fi

python3 -m venv /opt/zeon/venv
/opt/zeon/venv/bin/pip install --no-cache-dir "fastapi>=0.115" "uvicorn[standard]>=0.32"

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
    )
