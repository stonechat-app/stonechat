#!/usr/bin/env bash
#
# Stonechat single-box deploy: hub + local Docker provider on one VM.
# Good for a first live test (you + a friend). Run as root on a fresh
# Debian/Ubuntu box, from inside a checkout of this repo:
#
#     sudo STONECHAT_PUBLIC_IP=203.0.113.7 deploy/setup.sh
#
# Add STONECHAT_HUB_DOMAIN=hub.example.com to front it with Caddy + Let's Encrypt
# (the name must already resolve here).
#
# It installs Docker + Python, builds a venv for the hub, writes a
# systemd unit, opens the firewall, and starts everything. Idempotent: safe to
# re-run after a `git pull` to pick up changes (it rebuilds and restarts).
#
set -euo pipefail

# -- config -------------------------------------------------------------------

: "${STONECHAT_PUBLIC_IP:?set STONECHAT_PUBLIC_IP to this VM public IP - the address phones connect to}"
STONECHAT_HUB_PORT="${STONECHAT_HUB_PORT:-8000}"
SERVICE_USER="${SERVICE_USER:-root}"
# Optional: public hostname for the hub. Set it and Caddy fronts the hub with
# an auto-renewing Let's Encrypt cert, so the app can use https://. The name
# must ALREADY resolve to this box — Caddy proves ownership over :80 on
# startup and the issue fails if DNS points elsewhere. Empty → plain HTTP.
STONECHAT_HUB_DOMAIN="${STONECHAT_HUB_DOMAIN:-}"
# Fleet host pool for the "fleet" provider (mailbox containers on SEPARATE
# machines — mailboxes never run on this box; see deploy/README.md):
#   STONECHAT_FLEET_HOSTS="fleet1=ssh://stonechat-fleet@10.0.0.5|203.0.113.5"
STONECHAT_FLEET_HOSTS="${STONECHAT_FLEET_HOSTS:-}"
# Which catalog countries the Mailbox plan may be offered in (hub/app/countries.py):
#   STONECHAT_FLEET_COUNTRIES="DE,FI"
# Empty → Mailbox is hidden everywhere and only Machine is offered. NOTE:
# placement is still least-loaded across the WHOLE pool, so a country listed
# here is a claim about the picker, not about where the container lands.
STONECHAT_FLEET_COUNTRIES="${STONECHAT_FLEET_COUNTRIES:-}"
# Optional: address of the push gateway, reachable from mailbox CONTAINERS.
# On Linux that's the Docker bridge host address (172.17.0.1), not 127.0.0.1.
# Leave empty to run without push (see deploy/README.md "Enable push").
STONECHAT_PUSH_GATEWAY="${STONECHAT_PUSH_GATEWAY:-}"
# Optional: shared secret for hub-minted push keys (PROTOCOL.md "Push
# gateway"). Set the SAME value on the gateway service. Empty → pings unsigned.
STONECHAT_PUSH_MINT_SECRET="${STONECHAT_PUSH_MINT_SECRET:-}"
# Where relay pings come FROM (fleet hosts / mailbox VMs) — used to open the
# gateway port to internal traffic only. GCP's internal range by default.
STONECHAT_PUSH_SOURCE_CIDR="${STONECHAT_PUSH_SOURCE_CIDR:-10.128.0.0/9}"
# Optional: GCP project id. Set to enable the "gcp" provider (per-user mailbox
# VMs on Compute Engine). Needs credentials via ADC — on GCE, attach a service
# account with compute.instanceAdmin.v1 + compute.securityAdmin to this VM.
STONECHAT_GCP_PROJECT="${STONECHAT_GCP_PROJECT:-}"
# Set to "off" to run without the billing plane entirely: no /v1/billing/*
# endpoints, every provider ungated, no reaper, and the stripe package is not
# installed. The right choice for a private hub (docs/SELF_HOSTED_HUB.md).
STONECHAT_BILLING="${STONECHAT_BILLING:-on}"

# Relay binary (Rust, docs/RUST_PORT.md). A static x86_64-musl `stonechat-relay`
# on this box: fleet hosts then build their image from it instantly (no
# compile), and dedicated VM startup scripts fetch it (served by the hub at
# /v1/relay-binary, SHA-256-pinned). Without it, fleet/local hosts compile
# the crate via relay/'s Dockerfile and dedicated-VM provisioning is refused.
STONECHAT_RELAY_BINARY="${STONECHAT_RELAY_BINARY:-}"
# Public base URL of this hub (e.g. https://hub.example.com) — how dedicated
# VMs reach /v1/relay-binary. STONECHAT_RELAY_BINARY_URL overrides with an
# external artifact URL (GCS bucket, GitHub release).
STONECHAT_HUB_URL="${STONECHAT_HUB_URL:-}"
STONECHAT_RELAY_BINARY_URL="${STONECHAT_RELAY_BINARY_URL:-}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV="$REPO_ROOT/hub/.venv"
DB_PATH="/var/lib/stonechat/hub.db"

if [[ $EUID -ne 0 ]]; then
  echo "run me as root (sudo)" >&2
  exit 1
fi

echo "==> Stonechat deploy"
echo "    repo:        $REPO_ROOT"
echo "    public IP:   $STONECHAT_PUBLIC_IP"
echo "    hub port:    $STONECHAT_HUB_PORT"
echo "    gcp project: ${STONECHAT_GCP_PROJECT:-(unset — gcp provider disabled)}"
echo "    fleet hosts: ${STONECHAT_FLEET_HOSTS:-(unset — fleet provider disabled)}"
echo "    fleet countries: ${STONECHAT_FLEET_COUNTRIES:-(unset — Mailbox hidden, Machine only)}"
echo "    domain:      ${STONECHAT_HUB_DOMAIN:-(unset — plain HTTP, no TLS)}"
echo "    billing:     $STONECHAT_BILLING"

# -- packages -----------------------------------------------------------------

echo "==> installing packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y python3-venv python3-pip git curl ufw

if ! command -v docker >/dev/null; then
  echo "==> installing Docker"
  curl -fsSL https://get.docker.com | sh
fi
systemctl enable --now docker

# -- hub venv ------------------------------------------------------------------

echo "==> building hub venv"
python3 -m venv "$VENV"
"$VENV/bin/pip" install --quiet --upgrade pip
"$VENV/bin/pip" install --quiet -r "$REPO_ROOT/hub/requirements.txt"
if [[ "$STONECHAT_BILLING" != "off" ]]; then
  echo "==> installing billing dependency (stripe)"
  "$VENV/bin/pip" install --quiet "stripe>=11"
fi
if [[ -n "$STONECHAT_GCP_PROJECT" ]]; then
  echo "==> installing GCP provider dependency (google-cloud-compute)"
  "$VENV/bin/pip" install --quiet "google-cloud-compute>=1.19"
fi

mkdir -p "$(dirname "$DB_PATH")"

# No relay image is built here: mailboxes never run on this box. The fleet
# provider ships the server/ build context to the fleet host's Docker daemon
# over SSH on first ignite.

# -- systemd unit -------------------------------------------------------------

echo "==> writing systemd unit"
cat > /etc/systemd/system/stonechat-hub.service <<UNIT
[Unit]
Description=Stonechat hub (provisioner + directory)
After=network-online.target docker.service
Requires=docker.service

[Service]
User=$SERVICE_USER
WorkingDirectory=$REPO_ROOT/hub
Environment=STONECHAT_HUB_DB=$DB_PATH
Environment=STONECHAT_BILLING=$STONECHAT_BILLING
Environment=STONECHAT_LOCAL_HOST=$STONECHAT_PUBLIC_IP
Environment=STONECHAT_PUSH_GATEWAY=$STONECHAT_PUSH_GATEWAY
Environment=STONECHAT_PUSH_MINT_SECRET=$STONECHAT_PUSH_MINT_SECRET
Environment=STONECHAT_GCP_PROJECT=$STONECHAT_GCP_PROJECT
Environment="STONECHAT_FLEET_HOSTS=$STONECHAT_FLEET_HOSTS"
Environment="STONECHAT_FLEET_COUNTRIES=$STONECHAT_FLEET_COUNTRIES"
Environment=STONECHAT_RELAY_BINARY=$STONECHAT_RELAY_BINARY
Environment=STONECHAT_HUB_URL=$STONECHAT_HUB_URL
Environment=STONECHAT_RELAY_BINARY_URL=$STONECHAT_RELAY_BINARY_URL
ExecStart=$VENV/bin/uvicorn app.main:app --host 0.0.0.0 --port $STONECHAT_HUB_PORT
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now stonechat-hub
systemctl restart stonechat-hub

# -- TLS (optional) -----------------------------------------------------------

# Caddy terminates HTTPS and proxies to the hub on loopback. It fetches and
# renews the certificate itself; there is no certbot timer to babysit.
if [[ -n "$STONECHAT_HUB_DOMAIN" ]]; then
  if ! command -v caddy >/dev/null; then
    echo "==> installing Caddy"
    apt-get install -y debian-keyring debian-archive-keyring apt-transport-https
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
      | gpg --dearmor --yes -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
      > /etc/apt/sources.list.d/caddy-stable.list
    apt-get update -y
    apt-get install -y caddy
  fi

  echo "==> configuring Caddy for $STONECHAT_HUB_DOMAIN"
  cat > /etc/caddy/Caddyfile <<CADDY
$STONECHAT_HUB_DOMAIN {
	reverse_proxy 127.0.0.1:$STONECHAT_HUB_PORT
}
CADDY
  systemctl enable --now caddy
  systemctl restart caddy
fi

# -- firewall -----------------------------------------------------------------

# Mailboxes NEVER run on this box (they live on fleet hosts / their own VMs),
# so only the hub port is opened here.
echo "==> configuring firewall (ufw)"
ufw allow OpenSSH >/dev/null 2>&1 || ufw allow 22/tcp
ufw allow "${STONECHAT_HUB_PORT}/tcp" comment "stonechat hub"
# Caddy needs :80 as well as :443 — that's where it answers the ACME
# challenge, so closing it breaks renewal 60 days later, not today.
if [[ -n "$STONECHAT_HUB_DOMAIN" ]]; then
  ufw allow 80/tcp comment "stonechat hub (ACME challenge)"
  ufw allow 443/tcp comment "stonechat hub (TLS)"
fi
# The push gateway (:8100 on this box) must be reachable from the fleet
# hosts' relays — but never from the public internet. Without this rule
# relay pings time out SILENTLY and push just doesn't work.
if [ -n "$STONECHAT_PUSH_GATEWAY" ]; then
  ufw allow from "$STONECHAT_PUSH_SOURCE_CIDR" to any port 8100 proto tcp \
    comment "stonechat push gateway (internal only)"
fi
ufw --force enable

# -- done ---------------------------------------------------------------------

echo
echo "==> health check"
# uvicorn can take >10s to boot on the smallest VMs — retry, don't race it.
health_ok=""
for _ in $(seq 1 15); do
  if curl -fsS "http://127.0.0.1:${STONECHAT_HUB_PORT}/health"; then
    health_ok=1
    break
  fi
  sleep 2
done
if [[ -n "$health_ok" ]]; then
  HUB_URL="http://${STONECHAT_PUBLIC_IP}:${STONECHAT_HUB_PORT}"
  if [[ -n "$STONECHAT_HUB_DOMAIN" ]]; then
    HUB_URL="https://${STONECHAT_HUB_DOMAIN}"
    echo
    echo
    echo "==> checking TLS"
    # The first certificate takes a few seconds to issue. A failure here is
    # almost always DNS: the name must point at THIS box for the challenge.
    tls_ok=""
    for _ in $(seq 1 15); do
      if curl -fsS "https://${STONECHAT_HUB_DOMAIN}/health" >/dev/null 2>&1; then
        tls_ok=1
        break
      fi
      sleep 2
    done
    if [[ -z "$tls_ok" ]]; then
      echo "  TLS not answering yet on https://${STONECHAT_HUB_DOMAIN}"
      echo "  Check that ${STONECHAT_HUB_DOMAIN} resolves to ${STONECHAT_PUBLIC_IP}, that"
      echo "  80 and 443 are open in the CLOUD firewall, then:"
      echo "      journalctl -u caddy -n 50 --no-pager"
    else
      echo "  https://${STONECHAT_HUB_DOMAIN} serving a valid certificate"
    fi
  fi
  echo
  echo
  echo "Hub is up. Point the app at:"
  echo "    ${HUB_URL}"
  echo
  echo "Build the app with that baked in:"
  echo "    flutter build ipa --dart-define=STONECHAT_HUB=${HUB_URL}"
  echo
  echo "IMPORTANT: also open port ${STONECHAT_HUB_PORT}${STONECHAT_HUB_DOMAIN:+, 80 and 443} to this box"
  echo "in your CLOUD firewall / security group (ufw alone isn't enough on"
  echo "AWS/GCP/Azure)."
  echo "Mailbox ports (32768-60999) are opened on the FLEET HOSTS, never here"
  echo "— see deploy/fleet-host.sh."
else
  echo
  echo "Health check failed — inspect logs with:"
  echo "    journalctl -u stonechat-hub -n 50 --no-pager"
  exit 1
fi
