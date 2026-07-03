#!/usr/bin/env bash
#
# Zeon single-box deploy: control plane + local Docker provider on one VM.
# Good for a first live test (you + a friend). Run as root on a fresh
# Debian/Ubuntu box, from inside a checkout of this repo:
#
#     sudo ZEON_PUBLIC_IP=203.0.113.7 deploy/setup.sh
#
# It installs Docker + Python, builds a venv for the control plane, writes a
# systemd unit, opens the firewall, and starts everything. Idempotent: safe to
# re-run after a `git pull` to pick up changes (it rebuilds and restarts).
#
set -euo pipefail

# -- config -------------------------------------------------------------------

: "${ZEON_PUBLIC_IP:?set ZEON_PUBLIC_IP to this VM public IP - the address phones connect to}"
ZEON_CP_PORT="${ZEON_CP_PORT:-8000}"
# Docker publishes each mailbox to a random host port from the kernel's
# ephemeral range; we open that range so phones can reach the mailboxes.
MAILBOX_PORT_RANGE="${MAILBOX_PORT_RANGE:-32768:60999}"
SERVICE_USER="${SERVICE_USER:-root}"
# Optional: address of the push gateway, reachable from mailbox CONTAINERS.
# On Linux that's the Docker bridge host address (172.17.0.1), not 127.0.0.1.
# Leave empty to run without push (see deploy/README.md "Enable push").
ZEON_PUSH_GATEWAY="${ZEON_PUSH_GATEWAY:-}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV="$REPO_ROOT/control-plane/.venv"
DB_PATH="/var/lib/zeon/control_plane.db"

if [[ $EUID -ne 0 ]]; then
  echo "run me as root (sudo)" >&2
  exit 1
fi

echo "==> Zeon deploy"
echo "    repo:        $REPO_ROOT"
echo "    public IP:   $ZEON_PUBLIC_IP"
echo "    CP port:     $ZEON_CP_PORT"
echo "    mailbox ports: $MAILBOX_PORT_RANGE"

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

# -- control-plane venv -------------------------------------------------------

echo "==> building control-plane venv"
python3 -m venv "$VENV"
"$VENV/bin/pip" install --quiet --upgrade pip
"$VENV/bin/pip" install --quiet -r "$REPO_ROOT/control-plane/requirements.txt"

mkdir -p "$(dirname "$DB_PATH")"

# Prebuild the relay image so the first user's Ignite isn't slow / racy.
echo "==> building the relay image (zeon-server:dev)"
docker build -q -t zeon-server:dev "$REPO_ROOT/server" >/dev/null

# -- systemd unit -------------------------------------------------------------

echo "==> writing systemd unit"
cat > /etc/systemd/system/zeon-control-plane.service <<UNIT
[Unit]
Description=Zeon control plane (provisioner + directory)
After=network-online.target docker.service
Requires=docker.service

[Service]
User=$SERVICE_USER
WorkingDirectory=$REPO_ROOT/control-plane
Environment=ZEON_CP_DB=$DB_PATH
Environment=ZEON_LOCAL_HOST=$ZEON_PUBLIC_IP
Environment=ZEON_PUSH_GATEWAY=$ZEON_PUSH_GATEWAY
ExecStart=$VENV/bin/uvicorn app.main:app --host 0.0.0.0 --port $ZEON_CP_PORT
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now zeon-control-plane
systemctl restart zeon-control-plane

# -- firewall -----------------------------------------------------------------

echo "==> configuring firewall (ufw)"
ufw allow OpenSSH >/dev/null 2>&1 || ufw allow 22/tcp
ufw allow "${ZEON_CP_PORT}/tcp" comment "zeon control plane"
ufw allow "${MAILBOX_PORT_RANGE%:*}:${MAILBOX_PORT_RANGE#*:}/tcp" comment "zeon mailboxes"
ufw --force enable

# -- done ---------------------------------------------------------------------

sleep 2
echo
echo "==> health check"
if curl -fsS "http://127.0.0.1:${ZEON_CP_PORT}/health"; then
  echo
  echo
  echo "Control plane is up. Point the app at:"
  echo "    http://${ZEON_PUBLIC_IP}:${ZEON_CP_PORT}"
  echo
  echo "Build the app with that baked in:"
  echo "    flutter build ipa --dart-define=ZEON_CP=http://${ZEON_PUBLIC_IP}:${ZEON_CP_PORT}"
  echo
  echo "IMPORTANT: also open port ${ZEON_CP_PORT} and range ${MAILBOX_PORT_RANGE}"
  echo "in your CLOUD firewall / security group (ufw alone isn't enough on"
  echo "AWS/GCP/Azure; on DigitalOcean/Hetzner cloud firewalls, add them too)."
else
  echo
  echo "Health check failed — inspect logs with:"
  echo "    journalctl -u zeon-control-plane -n 50 --no-pager"
  exit 1
fi
