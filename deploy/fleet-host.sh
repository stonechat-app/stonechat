#!/usr/bin/env bash
#
# Stonechat fleet host: prepare a VM to hold mailbox containers for the `fleet`
# provider. Mailboxes NEVER run on the hub box — they live on one
# or more of these. Run as root on a fresh Debian/Ubuntu VM:
#
#     sudo STONECHAT_HUB_PUBKEY="ssh-ed25519 AAAA... root@stonechat-hub" deploy/fleet-host.sh
#
# It installs Docker, creates a `stonechat-fleet` user the hub reaches
# over SSH (docker -H ssh://stonechat-fleet@<this-host>), and opens the mailbox
# port range. Idempotent: safe to re-run.
#
# The hub then lists this host in STONECHAT_FLEET_HOSTS, e.g.:
#     STONECHAT_FLEET_HOSTS="de1=ssh://stonechat-fleet@<internal-ip>|<public-ip>|DE"
# The trailing ISO 3166-1 alpha-2 code is required — it is the jurisdiction
# this host sells, and mailboxes are only ever placed on a host in the
# country the user picked.
#
set -euo pipefail

: "${STONECHAT_HUB_PUBKEY:?set STONECHAT_HUB_PUBKEY to the hub SSH public key}"
# Host ports Docker publishes mailboxes on (the kernel ephemeral range).
MAILBOX_PORT_RANGE="${MAILBOX_PORT_RANGE:-32768:60999}"
FLEET_USER="${FLEET_USER:-stonechat-fleet}"

if [[ $EUID -ne 0 ]]; then
  echo "run me as root (sudo)" >&2
  exit 1
fi

echo "==> Stonechat fleet host"
echo "    fleet user:    $FLEET_USER"
echo "    mailbox ports: $MAILBOX_PORT_RANGE"

# -- packages -----------------------------------------------------------------

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y curl ufw

if ! command -v docker >/dev/null; then
  echo "==> installing Docker"
  curl -fsSL https://get.docker.com | sh
fi
systemctl enable --now docker

# -- hub access -----------------------------------------------------------------

echo "==> creating $FLEET_USER (docker group, key-only SSH)"
id "$FLEET_USER" >/dev/null 2>&1 || useradd -m -s /bin/bash "$FLEET_USER"
usermod -aG docker "$FLEET_USER"
install -d -m 700 -o "$FLEET_USER" -g "$FLEET_USER" "/home/$FLEET_USER/.ssh"
touch "/home/$FLEET_USER/.ssh/authorized_keys"
grep -qF "$STONECHAT_HUB_PUBKEY" "/home/$FLEET_USER/.ssh/authorized_keys" ||
  echo "$STONECHAT_HUB_PUBKEY" >> "/home/$FLEET_USER/.ssh/authorized_keys"
chmod 600 "/home/$FLEET_USER/.ssh/authorized_keys"
chown "$FLEET_USER:$FLEET_USER" "/home/$FLEET_USER/.ssh/authorized_keys"

# -- firewall -----------------------------------------------------------------

echo "==> configuring firewall (ufw)"
ufw allow OpenSSH >/dev/null 2>&1 || ufw allow 22/tcp
ufw allow "${MAILBOX_PORT_RANGE%:*}:${MAILBOX_PORT_RANGE#*:}/tcp" comment "stonechat mailboxes"
# The browser transport is QUIC, so UDP, and Docker publishes it on a random
# host port from the same ephemeral range. TCP alone leaves every mailbox
# unreachable from a browser while looking completely healthy to a phone.
ufw allow "${MAILBOX_PORT_RANGE%:*}:${MAILBOX_PORT_RANGE#*:}/udp" comment "stonechat mailboxes (webtransport)"
ufw --force enable

# -- done ---------------------------------------------------------------------

echo
echo "Fleet host ready. On the hub box, add it to the pool:"
echo "    STONECHAT_FLEET_HOSTS=\"de1=ssh://$FLEET_USER@<this-host-reachable-addr>|<this-host-PUBLIC-ip>|<ISO-COUNTRY>\""
echo
echo "REMEMBER: open ${MAILBOX_PORT_RANGE/:/-} in the CLOUD firewall for this"
echo "host too (security group / VPC rule), and pre-trust this host's key on"
echo "the hub box:  ssh-keyscan <this-host-reachable-addr> >> ~/.ssh/known_hosts"
