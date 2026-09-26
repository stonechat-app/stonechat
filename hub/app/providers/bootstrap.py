"""Builds the startup script that turns a bare VM into a Stonechat routing server.

The relay is a static Rust binary (relay/ — see notes/docs/RUST_PORT.md), far too
big to inline in a startup script (clouds cap them: GCP 256 KB, DigitalOcean
64 KB, AWS 16 KB — the old gzip+base64-embedded Python relay already broke
AWS). So the script is a **fetch-stub**: it downloads the binary and verifies
a SHA-256 **pinned inside the script** before executing anything. The pin is
what keeps the trust model intact — this script travels over the cloud
metadata channel that already carries the owner token, so a hostile artifact
host or network can only make provisioning fail, never substitute a relay.

Where the binary comes from (hub env):

    STONECHAT_RELAY_BINARY      path to a static x86_64-musl `stonechat-relay` on the
                           hub box. The hub serves it at GET /v1/relay-binary
                           (auth: the fetching VM's mailbox_token, which this
                           script already carries) and pins its SHA-256 in
                           every startup script.
    STONECHAT_RELAY_BINARY_URL  URL the VM fetches. Defaults to
                           {STONECHAT_HUB_URL}/v1/relay-binary; point it at a GCS
                           bucket / GitHub release to take the hub out of the
                           download path.
    STONECHAT_HUB_URL           public base URL of this hub (e.g.
                           https://hub.stonechat.app) — needed only to build
                           the default URL above.

Dedicated (Machine plan) VMs additionally get the **machine host** pre-installed
(PROTOCOL.md "Machine host"): the hub mints an admin token, bakes it into the
startup script, and the owner's app connects to `https://<vm>:8200` to mint
invites — no SSH required. It is still Python, so its section installs
a venv; its guest-mailbox build context is the fetched relay binary plus a
two-line Dockerfile. That install is best-effort: a VM where Docker or pip
fails still routes its owner's mail.
"""

import base64
import gzip
import hashlib
import os
import random
from pathlib import Path

from ..pushkey import mint_push_key
from .base import ProviderError

_MACHINE_HOST_SOURCE = Path(__file__).resolve().parents[3] / "machine_host" / "main.py"

# Runtime image for a relay container built from a prebuilt binary — the same
# stage relay/Dockerfile ends in. Shared with the local provider and, in the
# same text, with machine_host/main.py.
RELAY_RUNTIME_DOCKERFILE = """\
FROM scratch
COPY stonechat-relay /stonechat-relay
ENV STONECHAT_DB=/data/mailbox.db
ENV STONECHAT_BLOBS=/data/blobs
ENV STONECHAT_TLS_DIR=/data
EXPOSE 8080
ENTRYPOINT ["/stonechat-relay"]
"""

_TEMPLATE = """#!/usr/bin/env bash
set -euo pipefail

mkdir -p /opt/stonechat /var/lib/stonechat

# ---- fetch the relay binary (pinned SHA-256; see bootstrap.py) --------------
if ! command -v curl >/dev/null; then
  if command -v apt-get >/dev/null; then apt-get update -y && apt-get install -y curl
  elif command -v dnf >/dev/null; then dnf install -y curl
  fi
fi
curl -fsSL --retry 5 --retry-delay 3 {binary_auth}"{binary_url}" -o /opt/stonechat/stonechat-relay
echo "{binary_sha256}  /opt/stonechat/stonechat-relay" | sha256sum -c -
chmod +x /opt/stonechat/stonechat-relay

# Cloud VMs behind 1:1 NAT (GCP, EC2) must advertise the *public* address —
# coturn's external-ip and the machine host's invite URLs — and the only thing
# that knows it is the cloud's own metadata service. Every cloud puts it
# somewhere different, so ask them in turn, then fall back to the interface's
# own global address, which IS the public one on every provider that does not
# NAT (Hetzner, DigitalOcean, Vultr).
#
# -f on each probe is load-bearing. Several clouds serve a *different* metadata
# tree at 169.254.169.254, and without it curl prints the 404 body and that
# body becomes the "address" — a subjectAltName and a coturn external-ip built
# out of an error page, on a box where every other check passes.
PUBLIC_IP=""
public_ip_ok() {{
  case "$1" in
    ""|*[!0-9.]*) return 1 ;;
    # RFC1918, loopback, link-local and CGNAT: reachable from nowhere, so
    # advertising one is strictly worse than advertising nothing.
    10.*|127.*|169.254.*|192.168.*) return 1 ;;
    172.1[6-9].*|172.2[0-9].*|172.3[01].*) return 1 ;;
    100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*) return 1 ;;
  esac
  echo "$1" | grep -q '^[0-9][0-9]*[.][0-9][0-9]*[.][0-9][0-9]*[.][0-9][0-9]*$'
}}
probe_ip() {{
  if [ -n "$PUBLIC_IP" ]; then return 0; fi
  candidate=$(curl -fsS --max-time 3 "$@" 2>/dev/null || true)
  if public_ip_ok "$candidate"; then PUBLIC_IP="$candidate"; fi
  return 0
}}
probe_ip -H "Metadata-Flavor: Google" \\
  "http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip"
probe_ip "http://169.254.169.254/latest/meta-data/public-ipv4"                  # EC2
probe_ip "http://169.254.169.254/hetzner/v1/metadata/public-ipv4"               # Hetzner
probe_ip "http://169.254.169.254/metadata/v1/interfaces/public/0/ipv4/address"  # DigitalOcean
probe_ip "http://169.254.169.254/v1/interfaces/0/ipv4/address"                  # Vultr
if [ -z "$PUBLIC_IP" ]; then
  candidate=$(ip -4 -o addr show scope global 2>/dev/null \\
    | tr -s ' ' | cut -d' ' -f4 | cut -d/ -f1 | head -n 1)
  if public_ip_ok "$candidate"; then PUBLIC_IP="$candidate"; fi
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
realm=stonechat
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

cat > /etc/systemd/system/stonechat.service <<UNIT_EOF
[Unit]
Description=Stonechat routing server
After=network-online.target

[Service]
Environment=STONECHAT_OWNER_ID={owner_id}
Environment=STONECHAT_OWNER_TOKEN={owner_token}
Environment=STONECHAT_PORT={port}
Environment=STONECHAT_DB=/var/lib/stonechat/mailbox.db
Environment=STONECHAT_BLOBS=/var/lib/stonechat/blobs
Environment=STONECHAT_PUSH_GATEWAY={push_gateway}
Environment=STONECHAT_PUSH_KEY={push_key}
Environment=STONECHAT_TURN_SECRET=$TURN_SECRET
Environment=STONECHAT_TURN_PORT={turn_port}
# The browser transport's certificates must name the address clients dial.
# A certificate with no matching subjectAltName is refused by browsers with an
# error that reads like a pin mismatch and is not one. Empty on a box where the
# metadata service says nothing — the relay still serves native clients, and
# only browser sessions are lost.
Environment=STONECHAT_WT_ADVERTISE=$PUBLIC_IP
ExecStart=/opt/stonechat/stonechat-relay
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
UNIT_EOF

systemctl daemon-reload
systemctl enable --now stonechat
{machine_host_section}"""

# Appended after the mailbox is up so the hub's health poll never waits on
# Docker/pip installs. The machine host itself is still Python.
_MACHINE_HOST_TEMPLATE = """
# ---- machine host ("host your circle") --------------------------------------
# Best-effort from here on: the owner's mailbox is already serving.
set +e

# Guest-mailbox image: the pinned relay binary + its runtime Dockerfile, built
# below (a copy, not a compile). The machine host uses a local image as-is and
# only pulls from the registry when it is missing, so this VM's guests run the
# same verified binary as its owner's mailbox.
mkdir -p /opt/stonechat/relay
cp /opt/stonechat/stonechat-relay /opt/stonechat/relay/stonechat-relay
cat > /opt/stonechat/relay/Dockerfile <<'DOCKER_EOF'
{runtime_dockerfile}DOCKER_EOF

cat > /opt/stonechat/machine_host.py.gz.b64 <<'STONECHAT_EOF'
{machine_host_b64}
STONECHAT_EOF
base64 -d /opt/stonechat/machine_host.py.gz.b64 | gunzip > /opt/stonechat/machine_host.py

if command -v apt-get >/dev/null; then
  apt-get install -y docker.io python3-venv
elif command -v dnf >/dev/null; then
  dnf install -y docker python3 python3-pip
fi
systemctl enable --now docker
docker build -t stonechat-relay:dev /opt/stonechat/relay

python3 -m venv /opt/stonechat/venv
/opt/stonechat/venv/bin/pip install --no-cache-dir "fastapi>=0.115" "uvicorn[standard]>=0.32" "httpx>=0.27"

cat > /etc/systemd/system/stonechat-machine-host.service <<UNIT_EOF
[Unit]
Description=Stonechat machine host
After=network-online.target docker.service
Requires=docker.service

[Service]
Environment=STONECHAT_MACHINE_HOST_ADMIN_TOKEN={machine_host_token}
Environment=STONECHAT_MACHINE_HOST_ADVERTISE_HOST=$PUBLIC_IP
Environment=STONECHAT_MACHINE_HOST_PORT={machine_host_port}
Environment=STONECHAT_MACHINE_HOST_DB=/var/lib/stonechat/machine_host.db
Environment=STONECHAT_MACHINE_HOST_TLS_DIR=/var/lib/stonechat
Environment=STONECHAT_MACHINE_HOST_IMAGE=stonechat-relay:dev
Environment=STONECHAT_PUSH_GATEWAY={push_gateway}
ExecStart=/opt/stonechat/venv/bin/python /opt/stonechat/machine_host.py
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
UNIT_EOF

systemctl daemon-reload
systemctl enable --now stonechat-machine-host
"""

SERVER_PORT = 8080
# The browser transport (QUIC/UDP, relay/src/wt.rs). Fixed inside the relay;
# container providers map it to a random host port, VM providers expose it as
# is. Separate from SERVER_PORT so a host that blocks UDP loses browser
# sessions rather than its mailbox.
WT_PORT = 8443

# Docker's default ephemeral range, and the range the firewall rules already
# open on mailbox hosts (the cloud firewall rules). Allocating
# inside it means pinning ports needs no firewall change.
EPHEMERAL_RANGE = (32768, 61000)
PORT_ATTEMPTS = 20


def pick_ports() -> tuple[int, int]:
    """A TCP and a UDP port, chosen at random.

    Random rather than sequential: sequential allocation would leak how many
    mailboxes a host carries and the order they were created, which is cheap
    metadata to give away for nothing. It also keeps two concurrent provisions
    from converging on the same candidate.
    """
    return (
        random.randrange(*EPHEMERAL_RANGE),
        random.randrange(*EPHEMERAL_RANGE),
    )


def is_port_conflict(error: Exception) -> bool:
    text = str(error).lower()
    return (
        "port is already allocated" in text
        or "external connectivity" in text
        or "address already in use" in text
    )


def replace_ports(args: list[str], tcp: int, udp: int) -> list[str]:
    out = list(args)
    for i, a in enumerate(out):
        if a.endswith(f":{SERVER_PORT}") and ":" in a:
            out[i] = f"{tcp}:{SERVER_PORT}"
        elif a.endswith(f":{WT_PORT}/udp"):
            out[i] = f"{udp}:{WT_PORT}/udp"
    return out

TURN_PORT = 3478
TURN_RELAY_PORTS = (49152, 65535)  # coturn's default ephemeral relay range
MACHINE_HOST_PORT = 8200
# The machine host publishes guest mailboxes on fixed ports from
# STONECHAT_MACHINE_HOST_PORT_BASE (default 42000..42000+capacity-1, inside this
# range). The firewall rule stays the historical Docker-ephemeral range —
# it covers the machine host's range and matches what deployed VMs already have open.
GUEST_PORT_RANGE = (32768, 60999)


def relay_binary_path() -> Path | None:
    path = os.environ.get("STONECHAT_RELAY_BINARY", "")
    return Path(path) if path else None


def _relay_binary_sha256() -> str:
    """The pin baked into every startup script.

    STONECHAT_RELAY_SHA256 wins when set: with the binary published as a release
    asset, the hub pins what a VM will fetch without keeping a copy of it, which
    is what takes the hub out of the download path entirely (see
    STONECHAT_RELAY_BINARY_URL). Read it from the release's SHA256SUMS.

    Unset, the hub hashes its own copy, which is the only thing it can honestly
    pin when it is also the one serving the file.
    """
    configured = os.environ.get("STONECHAT_RELAY_SHA256", "").strip().lower()
    path = relay_binary_path()
    if configured:
        if len(configured) != 64 or any(c not in "0123456789abcdef" for c in configured):
            raise ProviderError(
                "STONECHAT_RELAY_SHA256 must be 64 hex characters (the value from "
                f"the release's SHA256SUMS); got {configured[:16]!r}"
            )
        # When the hub is ALSO the download source, a pin that disagrees with the
        # file it will serve means every VM fails `sha256sum -c` after a
        # perfectly successful download. Refuse now, with the reason, rather than
        # after a VM has been created and billed.
        if not os.environ.get("STONECHAT_RELAY_BINARY_URL", "").strip():
            if path is None or not path.is_file():
                raise ProviderError(
                    "STONECHAT_RELAY_SHA256 is set but there is nothing to fetch: "
                    "also set STONECHAT_RELAY_BINARY_URL (where VMs download the "
                    "binary), or STONECHAT_RELAY_BINARY (the hub serves its own copy)"
                )
            local = hashlib.sha256(path.read_bytes()).hexdigest()
            if local != configured:
                raise ProviderError(
                    f"STONECHAT_RELAY_SHA256 ({configured[:12]}…) does not match the "
                    f"binary this hub serves at /v1/relay-binary ({local[:12]}…)"
                )
        return configured
    if path is None or not path.is_file():
        raise ProviderError(
            "dedicated-VM provisioning needs a relay to pin: either "
            "STONECHAT_RELAY_BINARY (a static x86_64-musl build on the hub box) or "
            "STONECHAT_RELAY_BINARY_URL plus STONECHAT_RELAY_SHA256 (a published "
            "release asset — see relay/README.md)"
        )
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _relay_binary_url() -> str:
    url = os.environ.get("STONECHAT_RELAY_BINARY_URL", "")
    if url:
        return url
    hub_url = os.environ.get("STONECHAT_HUB_URL", "").rstrip("/")
    if not hub_url:
        raise ProviderError(
            "set STONECHAT_RELAY_BINARY_URL (artifact URL VMs can reach) or "
            "STONECHAT_HUB_URL (the hub then serves the binary at /v1/relay-binary)"
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
    owner_id: str, owner_token: str, machine_host_token: str | None = None
) -> str:
    push_gateway = os.environ.get("STONECHAT_PUSH_GATEWAY", "")
    machine_host_section = ""
    if machine_host_token:
        machine_host_section = _MACHINE_HOST_TEMPLATE.format(
            runtime_dockerfile=RELAY_RUNTIME_DOCKERFILE,
            machine_host_b64=_gz_b64(_MACHINE_HOST_SOURCE.read_bytes()),
            machine_host_token=machine_host_token,
            machine_host_port=MACHINE_HOST_PORT,
            push_gateway=push_gateway,
        )
    # Hub-served downloads authenticate with the mailbox_token this script
    # already carries (egress gate — main.py relay_binary). An external
    # artifact URL (GCS, GitHub) is fetched anonymously.
    hub_served = not os.environ.get("STONECHAT_RELAY_BINARY_URL", "")
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
        machine_host_section=machine_host_section,
    )
