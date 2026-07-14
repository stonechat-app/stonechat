# Deploying Zeon for a first live test

This gets **two VMs** running the backend: one for the hub +
directory, and one **fleet host** where every mailbox lives as a Docker
container (the `fleet` provider). Enough for you and a friend to chat over
real iPhones.

> **Topology rule: mailboxes never run on the hub machine.** The
> hub holds the directory and provisioning credentials; mailboxes
> hold users' (encrypted) mail and are exposed to the open internet on a wide
> port range. Keeping them on separate machines means a compromised mailbox
> host can't touch the directory, and the hub's attack surface
> stays one port.

Everything here assumes fresh **Debian or Ubuntu** VMs. Per
[BUSINESS.md](../BUSINESS.md), **DigitalOcean or Hetzner** are the right hosts
(≈$4–5/mo, bundled IPv4, and — unlike AWS — you can reach your own public IP
from inside the box, which the health checks rely on).

## 1. Get two VMs

- Smallest droplet / cloud instance is plenty for each (1 vCPU, 1 GB).
- Note both **public IPv4s** — call them `HUB_IP` (hub) and
  `FLEET_IP` (fleet host). Phones connect to both.
- SSH in as root (or a sudo user).

## 2. Prepare the fleet host

Copy `deploy/fleet-host.sh` to the fleet VM (it needs nothing else from the
repo) and run it with the **hub box's SSH public key** (generate one
there first: `ssh-keygen -t ed25519 -N '' -f ~/.ssh/id_ed25519`):

```bash
# on the FLEET VM
sudo ZEON_HUB_PUBKEY="ssh-ed25519 AAAA... root@zeon-hub" ./fleet-host.sh
```

It installs Docker, creates a `zeon-fleet` user (docker group, key-only SSH)
that the hub drives the daemon through, and opens the mailbox port
range in `ufw`. The relay image is built automatically on first ignite — the
hub ships the build context over SSH.

## 3. Put the repo on the hub box

```bash
# on the hub VM
git clone <your-repo-url> zeonchat && cd zeonchat
# (private repo → use a deploy key or a PAT)
```

Pre-trust the fleet host's SSH key, then verify Docker-over-SSH works:

```bash
ssh-keyscan <FLEET_ADDR> >> ~/.ssh/known_hosts   # internal IP if same VPC
docker -H ssh://zeon-fleet@<FLEET_ADDR> version
```

## 4. Run the setup script

```bash
sudo ZEON_PUBLIC_IP=<HUB_IP> \
     ZEON_FLEET_HOSTS="fleet1=ssh://zeon-fleet@<FLEET_ADDR>|<FLEET_IP>" \
     deploy/setup.sh
```

It installs Docker + Python, builds the hub venv, writes a
**systemd** service (`zeon-hub`), opens the host firewall with
`ufw`, and health-checks itself. Re-run it any time after a `git pull` — it
rebuilds and restarts idempotently.

Knobs (env vars):

| Var | Default | Meaning |
|---|---|---|
| `ZEON_PUBLIC_IP` | — (required) | Address phones use for the hub |
| `ZEON_FLEET_HOSTS` | — | Fleet host pool: `name=ssh://user@addr\|advertise_ip,…` (unset → fleet provider disabled) |
| `ZEON_HUB_PORT` | `8000` | Hub listen port |

## 5. Open the CLOUD firewall too

`ufw` guards the OS, but cloud providers have a **separate** network firewall
you must also open. Add inbound TCP rules for:

- **`8000`** (or your `ZEON_HUB_PORT`) — to the **hub** VM only
- **`32768–60999`** — to the **fleet host(s)** only (Docker's published-port
  range for mailbox containers)

On DigitalOcean/Hetzner that's the "Cloud Firewall" UI; on AWS/GCP it's the
security group / VPC firewall. Without this, the app reaches nothing.

> Why such a wide mailbox range: the fleet provider lets Docker pick a random
> host port per mailbox, from the kernel's ephemeral range. For a handful of
> users this is fine. To pin it down later, constrain the range or add a fixed
> port base to the provider (see "Beyond a friends test").

## 5. Build the app and send it to your friend

You need the **Apple Developer Program** ($99/yr) — enroll first, approval can
take a day or two. Then, on your Mac:

```bash
cd app
flutter build ipa \
  --dart-define=ZEON_HUB=http://<HUB_IP>:8000 \
  --dart-define=ZEON_PROVIDER=fleet
```

Baking `ZEON_HUB` in means neither of you has to type the server address.
Upload the archive (Xcode → Organizer, or `xcrun altool`) to **TestFlight**,
then add your friend as an **internal tester** in App Store Connect — internal
testing needs no Apple review, so this is same-day.

(No Mac/Apple account yet? For a quick local proof you can instead run the app
from `flutter run` on a simulator or a USB-tethered iPhone with the same
`--dart-define`, and skip TestFlight.)

## 6. The actual test

Both of you, in the app:

1. **Forge identity** (generates your Ed25519 key on-device).
2. **Ignite**. The hub spins up your mailbox container on the
   fleet host and the app pins its TLS certificate.
3. Exchange **handles** (the `zn-word-word-word` on your ID screen) — type or QR.
4. Send a message, a photo, a voice note.
5. The finale: hit **Turn off** and watch the mailbox container get destroyed —
   "delete the only server my messages ever touched."

Keep the app **foregrounded**: there are no push notifications yet, so delivery
happens over the live WebSocket while the app is open or on resume.

## Operating it

```bash
# on the hub box:
systemctl status zeon-hub          # is it up?
journalctl -u zeon-hub -f          # live logs
docker -H ssh://zeon-fleet@<FLEET_ADDR> ps   # running mailboxes (on the fleet host)
systemctl restart zeon-hub         # after config changes

# update to the latest code:
cd ~/zeonchat && git pull && \
  sudo ZEON_PUBLIC_IP=<HUB_IP> ZEON_FLEET_HOSTS="fleet1=ssh://zeon-fleet@<FLEET_ADDR>|<FLEET_IP>" deploy/setup.sh
```

State that survives restarts: the hub DB at
`/var/lib/zeon/hub.db` and each mailbox's SQLite + TLS key inside its
container volume. Destroying a mailbox from the app (or `docker rm -f`) is
final — its undelivered ciphertext is gone, by design.

### The reusable tester code (`ZEON_TEST_CODE`)

TestFlight testers activate with a shared code that survives identity resets
(PROTOCOL.md "Billing"). It lives in a **systemd drop-in** — deliberately not
in `setup.sh`, which rewrites the main unit on every deploy — so it persists
across code updates:

```bash
# on the hub box — set (or rotate) the code:
sudo mkdir -p /etc/systemd/system/zeon-hub.service.d
printf '[Service]\nEnvironment=ZEON_TEST_CODE=ZEON-XXXX-XXXX\n' \
  | sudo tee /etc/systemd/system/zeon-hub.service.d/test-code.conf
sudo systemctl daemon-reload && sudo systemctl restart zeon-hub

# REVOKE it (anyone who knows the code gets a free plan — kill it
# before opening TestFlight beyond people you trust):
sudo rm /etc/systemd/system/zeon-hub.service.d/test-code.conf
sudo systemctl daemon-reload && sudo systemctl restart zeon-hub
```

Revoking stops new activations only: subscriptions it already minted stay
active (`source = 'test'` in the `subscriptions` table — audit or purge them
there). Never publish the code value; it is not in the repo, only in the
drop-in on the box.

## Enable push (optional)

Without this, messages arrive only while the app is foregrounded or on resume —
fine for a quick test. To get real background wake-ups, stand up the push
gateway. It's the only component that holds APNs/FCM credentials, and it never
learns identities (the relay pings it with just a device token). The app→relay→
gateway wiring is already built; you only need credentials + the service.

**1. Apple push key.** In your Apple Developer account: Certificates, IDs &
Profiles → Keys → create an **APNs Auth Key** (`.p8`). Note the Key ID and your
Team ID. Enable the **Push Notifications** capability on your app id.

**2. App build.** In Xcode add the Push Notifications capability to the Runner
target (creates `Runner.entitlements` with `aps-environment`), drop in the
Firebase config the app uses to obtain the token (`GoogleService-Info.plist`
for iOS, `google-services.json` for Android), and rebuild the IPA. Without these
the app just runs push-disabled — no crash.

> The app fetches the raw APNs token on iOS and sends it to your mailbox; our
> gateway pushes APNs-direct. Firebase here is only the token-acquisition /
> notification-lifecycle plumbing.

**3. Run the gateway** on the hub VM:

```bash
cd ~/zeonchat/gateway
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
sudo mkdir -p /etc/zeon && sudo cp /path/to/AuthKey_XXXX.p8 /etc/zeon/apns.p8
sudo cp deploy/zeon-push-gateway.service /etc/systemd/system/
sudo nano /etc/systemd/system/zeon-push-gateway.service   # fill in key id / team id / topic
sudo systemctl daemon-reload && sudo systemctl enable --now zeon-push-gateway
curl -s localhost:8100/health     # -> {"apns": true, ...}
```

Open port 8100 **only host-to-host** (internal VPC / private-network rule from
the fleet host to the hub box) — never to the public internet. The mailbox
containers on the fleet host reach it at the hub box's internal address.
`setup.sh` adds the matching **ufw** rule when `ZEON_PUSH_GATEWAY` is set
(source range: `ZEON_PUSH_SOURCE_CIDR`, default GCP-internal `10.128.0.0/9`).
Both firewalls (cloud + ufw) must pass or relay pings time out *silently* —
the relay logs a warning, nothing else breaks, push just never arrives.

**4. Point the hub at it** and recreate mailboxes so they inherit
the setting. `ZEON_PUSH_MINT_SECRET` (same value in the gateway unit) turns on
per-relay push keys — recommended; see PROTOCOL.md "Push gateway":

```bash
cd ~/zeonchat
sudo ZEON_PUBLIC_IP=<HUB_IP> \
     ZEON_FLEET_HOSTS="fleet1=ssh://zeon-fleet@<FLEET_ADDR>|<FLEET_IP>" \
     ZEON_PUSH_GATEWAY=http://<CP_INTERNAL_IP>:8100 \
     ZEON_PUSH_MINT_SECRET=<openssl rand -hex 32, same as gateway> deploy/setup.sh
```

Existing mailboxes keep their old (empty) gateway setting until recreated —
have each user **Turn off → Ignite** once, or destroy/re-provision. New Ignites
get it automatically. Verify with a message to a user whose app is fully closed.
The same recreate rule applies when you later enable `ZEON_PUSH_MINT_SECRET`:
old mailboxes have no push key, so the gateway will 403 them until re-Ignited.
To cut off one abusive relay: its `pk_…` id from the gateway logs → the
`ZEON_PUSH_BLOCKLIST` file (no restart needed).

## Running on Google Cloud

The same scripts deploy to GCE VMs. Differences from the DO/Hetzner
walkthrough:

1. **Project setup** (once): enable the Compute Engine API.
2. **Hub VM**: an `e2-micro` in `us-central1`/`us-west1`/`us-east1`
   is free-tier. Give it a network tag, e.g. `zeon-hub`, and promote its
   external IP to static so the address baked into app builds survives
   restarts.
3. **Fleet host VM**: another `e2-micro` (or bigger as users grow), network
   tag `zeon-fleet`, static IP too — mailbox addresses embed it. Use the
   **internal** VPC address in `ZEON_FLEET_HOSTS`'s SSH endpoint and the
   static **external** IP as the advertise address.
4. **Cloud firewall**: VPC firewall rules replace the DO/Hetzner cloud
   firewall UI — allow `tcp:8000` to the `zeon-hub` tag and
   `tcp:32768-60999` to the `zeon-fleet` tag. (Same-VPC SSH between the two
   boxes is covered by `default-allow-internal`.)
5. **Deploy** as in steps 2–4 above.

### Optional: per-user mailbox VMs (`gcp` provider)

GCP is also the one cloud where the per-user-VM tier already has a finished
adapter — each user gets their own `e2-micro` instead of a container. Extra
setup: create a service account for the hub, grant it
`roles/compute.instanceAdmin.v1` + `roles/compute.securityAdmin` on the
project, attach it to the hub VM (`--scopes=cloud-platform` — ADC, no key
files), and deploy with `ZEON_GCP_PROJECT=<PROJECT_ID>` set (this installs
`google-cloud-compute`). Mailbox VMs get their own auto-created firewall rule
(`zeon-allow-server`, tcp:8080). Release builds of the app default to this
provider (`gcp` / `e2-micro` / `us-central1-a`); pass
`--dart-define=ZEON_PROVIDER=fleet` to use the fleet instead. Cost note: a
per-user `e2-micro` + IPv4 runs ~$7–10/mo, vs ~$0.30/user on a shared fleet
host.

Unlike AWS, a GCE VM *can* reach its own external IP, so the self-health-check
works.

## Host friends on your box ("host your circle")

Want your VM to also host a few friends' mailboxes? Run the **host agent**
(`host_agent/README.md`) alongside the hub — it mints invites and spins up
a container per invited friend on the same box, each end-to-end encrypted and
unreadable to you. Open port 8200 (host agent) plus the mailbox range, and share
invites from the app ("Host friends on my server"). Friends redeem with
"Join a friend's host."

## What this setup skips (fine for two people)

- **The reconciler, billing, abuse handling** — the "before charging money"
  list in BUSINESS.md. Not needed for a test.
- **A domain + HTTPS on the hub** — the app talks to it over plain
  HTTP here. (Mailbox traffic is already pinned TLS regardless.) For anything
  public, put the hub behind a domain with Caddy/Let's Encrypt and
  build with `--dart-define=ZEON_HUB=https://…`.

## Beyond a friends test

You're already on the production topology (hub + fleet hosts).
When you outgrow one fleet host, the moves — all already scaffolded in the
codebase — are: add hosts to `ZEON_FLEET_HOSTS` (placement is least-loaded),
harden containers with `ZEON_FLEET_RUNTIME=runsc` (gVisor), offer per-user
VMs as the premium tier (`gcp` provider today; `DigitalOceanProvider`/
`HetznerProvider` adapters to come), pin the mailbox port range, add the
reconciler and push gateway, and front the hub with TLS. See
BUSINESS.md's "Before charging money" checklist.
