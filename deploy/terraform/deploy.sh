#!/usr/bin/env bash
#
# Put Stonechat on the machines `tofu apply` created:
#
#   1. wait for each VM's startup script to finish
#   2. authorize the hub's SSH key on every fleet host and pre-trust their
#      host keys on the hub
#   3. write the infrastructure-derived values (STONECHAT_FLEET_HOSTS, and the
#      push gateway address when that profile is on) into your .env
#   4. upload this checkout, the .env, and optionally the relay binary and
#      APNs key, then `docker compose up -d --build` on the hub
#
#     deploy/terraform/deploy.sh --env deploy/.env \
#         [--relay path/to/stonechat-relay] [--apns-key path/to/AuthKey.p8]
#
# Idempotent: re-run after any code or .env change. The checkout is sent as it
# is, uncommitted edits to tracked files included; untracked files are not.
# gcloud must be logged in to the project (CLOUDSDK_ACTIVE_CONFIG_NAME picks a
# named configuration). Needs tofu or terraform, gcloud, git and python3.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(git -C "$here" rev-parse --show-toplevel)"

env_file="" relay="" apns_key=""
while [ $# -gt 0 ]; do
  case "$1" in
    --env) env_file="$2"; shift 2 ;;
    --relay) relay="$2"; shift 2 ;;
    --apns-key) apns_key="$2"; shift 2 ;;
    -h | --help) sed -n '2,21p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $1 (see --help)" >&2; exit 2 ;;
  esac
done
[ -n "$env_file" ] || { echo "--env is required: start from deploy/.env.example" >&2; exit 2; }
for f in "$env_file" $relay $apns_key; do
  [ -f "$f" ] || { echo "no such file: $f" >&2; exit 2; }
done

tf="$(command -v tofu || command -v terraform || true)"
[ -n "$tf" ] || { echo "need tofu or terraform on PATH" >&2; exit 2; }
outputs="$("$tf" -chdir="$here" output -json)"

# tfout hub.name → a value from `tofu output -json`
tfout() {
  printf '%s' "$outputs" | python3 -c '
import json, sys
v = json.load(sys.stdin)
path = sys.argv[1].split(".")
v = v[path[0]]["value"]
for key in path[1:]:
    v = v[key]
print(v if isinstance(v, str) else " ".join(v) if isinstance(v, dict) else json.dumps(v))
' "$1"
}

project="$(tfout project)"
hub="$(tfout hub.name)"
hub_zone="$(tfout hub.zone)"
hub_ip="$(tfout hub.public_ip)"
fleet_keys="$(tfout fleet_hosts)"

say() { printf '\n==> %s\n' "$*"; }

gssh() { # name zone command
  gcloud compute ssh "$1" --zone "$2" --project "$project" --quiet --command "$3" -- -o LogLevel=ERROR
}

wait_bootstrapped() { # name zone
  for _ in $(seq 60); do
    if gssh "$1" "$2" 'test -f /var/local/stonechat-bootstrapped' 2>/dev/null; then return 0; fi
    sleep 10
  done
  echo "$1 never finished its startup script — on the box: sudo journalctl -u google-startup-scripts" >&2
  exit 1
}

# set_env KEY=VALUE… — replace the line if present, append it if not.
set_env() {
  python3 - "$env_file" "$@" <<'PY'
import re, sys
path, pairs = sys.argv[1], sys.argv[2:]
text = open(path).read()
for pair in pairs:
    key, value = pair.split("=", 1)
    line = f"{key}={value}"
    text, n = re.subn(rf"^{re.escape(key)}=.*$", lambda _: line, text, flags=re.M)
    if not n:
        text = text.rstrip("\n") + "\n" + line + "\n"
open(path, "w").write(text)
PY
}
get_env() { sed -n "s/^$1=//p" "$env_file" | tail -1; }

# -- 1 + 2: the boxes, and the hub's access to the fleet ----------------------------

say "waiting for $hub to finish bootstrapping"
wait_bootstrapped "$hub" "$hub_zone"
hub_pubkey="$(gssh "$hub" "$hub_zone" 'sudo cat /root/.ssh/id_ed25519.pub')"

for key in $fleet_keys; do
  name="$(tfout "fleet_hosts.$key.name")"
  zone="$(tfout "fleet_hosts.$key.zone")"
  internal="$(tfout "fleet_hosts.$key.internal_ip")"

  say "fleet host $key ($name)"
  wait_bootstrapped "$name" "$zone"
  gssh "$name" "$zone" "sudo grep -qxF '$hub_pubkey' /home/stonechat-fleet/.ssh/authorized_keys \
    || echo '$hub_pubkey' | sudo tee -a /home/stonechat-fleet/.ssh/authorized_keys >/dev/null"

  # Re-scan every time: a recreated fleet VM can come back on the same internal
  # IP with a new host key, and a stale entry fails the first ignite.
  gssh "$hub" "$hub_zone" "sudo ssh-keygen -q -R $internal -f /root/.ssh/known_hosts >/dev/null 2>&1; \
    sudo sh -c 'ssh-keyscan -H $internal 2>/dev/null >> /root/.ssh/known_hosts'; \
    sudo docker -H ssh://stonechat-fleet@$internal version --format '    docker over ssh OK (engine {{.Server.Version}})'"
done

# -- 3: .env ---------------------------------------------------------------------------

say "updating infrastructure values in $env_file"
set_env "STONECHAT_FLEET_HOSTS=$(tfout env.STONECHAT_FLEET_HOSTS)"
case ",$(get_env COMPOSE_PROFILES)," in
  *,push_gateway,*)
    set_env "STONECHAT_PUSH_BIND=$(tfout env.STONECHAT_PUSH_BIND)" \
            "STONECHAT_PUSH_GATEWAY=$(tfout env.STONECHAT_PUSH_GATEWAY)"
    [ -n "$apns_key" ] || echo "    note: push_gateway is on but no --apns-key given; relying on the one already on the hub"
    ;;
esac

domain="$(get_env STONECHAT_HUB_DOMAIN)"
if [ -n "$domain" ]; then
  resolved="$(python3 -c 'import socket, sys; print(socket.gethostbyname(sys.argv[1]))' "$domain" 2>/dev/null || true)"
  if [ "$resolved" != "$hub_ip" ]; then
    echo "    warning: $domain resolves to ${resolved:-nothing}, not $hub_ip — Caddy cannot get a certificate until the A record points at the hub" >&2
  fi
fi

# -- 4: code + config onto the hub ------------------------------------------------------

say "uploading to $hub"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# `git stash create` snapshots tracked edits without touching the worktree;
# it prints nothing when the tree is clean.
rev="$(git -C "$repo" stash create)"
git -C "$repo" archive --format=tar.gz -o "$tmp/src.tgz" "${rev:-HEAD}"
cp "$env_file" "$tmp/env"
[ -z "$relay" ] || cp "$relay" "$tmp/stonechat-relay"
[ -z "$apns_key" ] || cp "$apns_key" "$tmp/apns.p8"

gssh "$hub" "$hub_zone" 'rm -rf /tmp/stonechat-deploy && mkdir -m 700 /tmp/stonechat-deploy'
gcloud compute scp --zone "$hub_zone" --project "$project" --quiet "$tmp"/* "$hub:/tmp/stonechat-deploy/"

say "docker compose up on $hub"
gssh "$hub" "$hub_zone" '
set -euo pipefail
d=/tmp/stonechat-deploy

# The checkout holds no state (hub.db is /var/lib/stonechat, certificates are
# compose volumes), so replace it wholesale.
rm -rf ~/stonechat.new && mkdir ~/stonechat.new
tar -xzf $d/src.tgz -C ~/stonechat.new
install -m 600 $d/env ~/stonechat.new/deploy/.env
rm -rf ~/stonechat && mv ~/stonechat.new ~/stonechat

relay_changed=
if [ -f $d/stonechat-relay ] && ! sudo cmp -s $d/stonechat-relay /var/lib/stonechat/stonechat-relay; then
  sudo install -m 755 $d/stonechat-relay /var/lib/stonechat/stonechat-relay
  relay_changed=1
fi
[ ! -f $d/apns.p8 ] || sudo install -m 600 $d/apns.p8 /etc/stonechat/apns.p8
sudo touch /etc/stonechat/push-blocklist
rm -rf $d

cd ~/stonechat/deploy
sudo docker compose up -d --build --remove-orphans
# The hub hashes the relay at startup; a new binary needs a restart to count.
[ -z "$relay_changed" ] || sudo docker compose restart hub

for _ in $(seq 36); do
  [ "$(sudo docker compose ps hub --format "{{.Health}}")" = healthy ] && break
  sleep 5
done
sudo docker compose ps
[ "$(sudo docker compose ps hub --format "{{.Health}}")" = healthy ] || {
  sudo docker compose logs --tail 50 hub
  echo "hub did not become healthy" >&2
  exit 1
}
'

say "done"
echo "    hub: ${domain:+https://$domain }($hub_ip)"
[ -z "$fleet_keys" ] || echo "    fleet: $(tfout env.STONECHAT_FLEET_HOSTS)"
