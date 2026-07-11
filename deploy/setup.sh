#!/usr/bin/env bash
#
# Zeon single-box deploy: hub + local Docker provider on one VM.
# Good for a first live test (you + a friend). Run as root on a fresh
# Debian/Ubuntu box, from inside a checkout of this repo:
#
#     sudo ZEON_PUBLIC_IP=203.0.113.7 deploy/setup.sh
#
# It installs Docker + Python, builds a venv for the hub, writes a
# systemd unit, opens the firewall, and starts everything. Idempotent: safe to
# re-run after a `git pull` to pick up changes (it rebuilds and restarts).
#
set -euo pipefail

# -- config -------------------------------------------------------------------

: "${ZEON_PUBLIC_IP:?set ZEON_PUBLIC_IP to this VM public IP - the address phones connect to}"
ZEON_HUB_PORT="${ZEON_HUB_PORT:-8000}"
SERVICE_USER="${SERVICE_USER:-root}"
# Fleet host pool for the "fleet" provider (mailbox containers on SEPARATE
# machines — mailboxes never run on this box; see deploy/README.md):
#   ZEON_FLEET_HOSTS="fleet1=ssh://zeon-fleet@10.0.0.5|203.0.113.5"
ZEON_FLEET_HOSTS="${ZEON_FLEET_HOSTS:-}"
# Optional: address of the push gateway, reachable from mailbox CONTAINERS.
# On Linux that's the Docker bridge host address (172.17.0.1), not 127.0.0.1.
# Leave empty to run without push (see deploy/README.md "Enable push").
ZEON_PUSH_GATEWAY="${ZEON_PUSH_GATEWAY:-}"
# Optional: GCP project id. Set to enable the "gcp" provider (per-user mailbox
# VMs on Compute Engine). Needs credentials via ADC — on GCE, attach a service
# account with compute.instanceAdmin.v1 + compute.securityAdmin to this VM.
ZEON_GCP_PROJECT="${ZEON_GCP_PROJECT:-}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV="$REPO_ROOT/hub/.venv"
DB_PATH="/var/lib/zeon/hub.db"

if [[ $EUID -ne 0 ]]; then
  echo "run me as root (sudo)" >&2
  exit 1
fi

echo "==> Zeon deploy"
echo "    repo:        $REPO_ROOT"
echo "    public IP:   $ZEON_PUBLIC_IP"
echo "    hub port:    $ZEON_HUB_PORT"
echo "    gcp project: ${ZEON_GCP_PROJECT:-(unset — gcp provider disabled)}"
echo "    fleet hosts: ${ZEON_FLEET_HOSTS:-(unset — fleet provider disabled)}"

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
if [[ -n "$ZEON_GCP_PROJECT" ]]; then
  echo "==> installing GCP provider dependency (google-cloud-compute)"
  "$VENV/bin/pip" install --quiet "google-cloud-compute>=1.19"
fi

mkdir -p "$(dirname "$DB_PATH")"

# No relay image is built here: mailboxes never run on this box. The fleet
# provider ships the server/ build context to the fleet host's Docker daemon
# over SSH on first ignite.

# -- systemd unit -------------------------------------------------------------

echo "==> writing systemd unit"
cat > /etc/systemd/system/zeon-hub.service <<UNIT
[Unit]
Description=Zeon hub (provisioner + directory)
After=network-online.target docker.service
Requires=docker.service

[Service]
User=$SERVICE_USER
WorkingDirectory=$REPO_ROOT/hub
Environment=ZEON_HUB_DB=$DB_PATH
Environment=ZEON_LOCAL_HOST=$ZEON_PUBLIC_IP
Environment=ZEON_PUSH_GATEWAY=$ZEON_PUSH_GATEWAY
Environment=ZEON_GCP_PROJECT=$ZEON_GCP_PROJECT
Environment="ZEON_FLEET_HOSTS=$ZEON_FLEET_HOSTS"
ExecStart=$VENV/bin/uvicorn app.main:app --host 0.0.0.0 --port $ZEON_HUB_PORT
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now zeon-hub
systemctl restart zeon-hub

# -- firewall -----------------------------------------------------------------

# Mailboxes NEVER run on this box (they live on fleet hosts / their own VMs),
# so only the hub port is opened here.
echo "==> configuring firewall (ufw)"
ufw allow OpenSSH >/dev/null 2>&1 || ufw allow 22/tcp
ufw allow "${ZEON_HUB_PORT}/tcp" comment "zeon hub"
ufw --force enable

# -- done ---------------------------------------------------------------------

echo
echo "==> health check"
# uvicorn can take >10s to boot on the smallest VMs — retry, don't race it.
health_ok=""
for _ in $(seq 1 15); do
  if curl -fsS "http://127.0.0.1:${ZEON_HUB_PORT}/health"; then
    health_ok=1
    break
  fi
  sleep 2
done
if [[ -n "$health_ok" ]]; then
  echo
  echo
  echo "Hub is up. Point the app at:"
  echo "    http://${ZEON_PUBLIC_IP}:${ZEON_HUB_PORT}"
  echo
  echo "Build the app with that baked in:"
  echo "    flutter build ipa --dart-define=ZEON_HUB=http://${ZEON_PUBLIC_IP}:${ZEON_HUB_PORT}"
  echo
  echo "IMPORTANT: also open port ${ZEON_HUB_PORT} to this box in your CLOUD"
  echo "firewall / security group (ufw alone isn't enough on AWS/GCP/Azure)."
  echo "Mailbox ports (32768-60999) are opened on the FLEET HOSTS, never here"
  echo "— see deploy/fleet-host.sh."
else
  echo
  echo "Health check failed — inspect logs with:"
  echo "    journalctl -u zeon-hub -n 50 --no-pager"
  exit 1
fi
