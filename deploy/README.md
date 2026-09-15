# Deploying Stonechat for a first live test

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
the internal business notes (notes/BUSINESS.md), **DigitalOcean or Hetzner** are the right hosts
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
sudo STONECHAT_HUB_PUBKEY="ssh-ed25519 AAAA... root@stonechat-hub" ./fleet-host.sh
```

It installs Docker, creates a `stonechat-fleet` user (docker group, key-only SSH)
that the hub drives the daemon through, and opens the mailbox port
range in `ufw`. The relay image is built automatically on first ignite — the
hub ships the build context over SSH.

## 3. Put the repo on the hub box

```bash
# on the hub VM
git clone <your-repo-url> stonechat && cd stonechat
# (private repo → use a deploy key or a PAT)
```

Pre-trust the fleet host's SSH key, then verify Docker-over-SSH works:

```bash
ssh-keyscan <FLEET_ADDR> >> ~/.ssh/known_hosts   # internal IP if same VPC
docker -H ssh://stonechat-fleet@<FLEET_ADDR> version
```

## 4. Start the hub

The hub ships as a container (`hub/Dockerfile`). The hosted service runs the
same image self-hosters do, so there is one path to keep working rather than
two. It needs Docker Compose **2.23.1 or newer** (`docker compose version`):
the Caddyfile for the `tls` profile is written inline in `docker-compose.yml`.

```bash
cd deploy
cp .env.example .env
$EDITOR .env          # at minimum STONECHAT_FLEET_HOSTS
docker compose up -d --build
```

Check it came up — compose health-checks `/health` on its own, so `ps` is the
answer:

```bash
docker compose ps          # "healthy" once it is serving
docker compose logs -f
```

Re-run `docker compose up -d --build` after a `git pull`; it rebuilds and
restarts in place, and `hub.db` is a bind mount so it survives.

> **`ufw` does not police published container ports.** Docker inserts its own
> iptables rules ahead of ufw's, so `STONECHAT_BIND=0.0.0.0` means the hub port
> is reachable from the internet whatever ufw says — the old `setup.sh` path
> behaved differently here. Terminating TLS on this box? Set
> `STONECHAT_BIND=127.0.0.1` so only Caddy can reach the hub.

`deploy/setup.sh` is the previous bare-metal installer (venv + systemd + ufw).
It is kept for reference and is no longer maintained; don't run it on a box
already using compose, since the two fight over the hub port and
`/var/lib/stonechat`.

Knobs — all of them live in `deploy/.env`, which is gitignored because it
holds the provider tokens:

| Var | Default | Meaning |
|---|---|---|
| `STONECHAT_FLEET_HOSTS` | — | Fleet host pool: `name=ssh://user@addr\|advertise_ip\|COUNTRY,…` (unset → fleet provider disabled). The ISO country code is required and is the single source of both placement and which countries the Mailbox plan offers. |
| `STONECHAT_HUB_PORT` | `8000` | Host port the hub is published on |
| `STONECHAT_BIND` | `0.0.0.0` | Host address to publish on. `127.0.0.1` when Caddy fronts the hub — see the ufw note above |
| `STONECHAT_STATE_DIR` | `/var/lib/stonechat` | Host directory holding `hub.db`. The same path the systemd unit used, so an existing box keeps its data |
| `STONECHAT_SSH_DIR` | `/root/.ssh` | Host directory with the key the hub drives fleet hosts with, plus a `known_hosts` that already contains them. Mounted read-only, so `ssh` cannot add an unknown host itself — hence the `ssh-keyscan` in step 3 |
| `STONECHAT_RELAY_DIR` | `/var/lib/stonechat` | Host directory holding the prebuilt static `stonechat-relay` — defaults to the state dir, which is where the deployed hub already keeps it, so the same path is mounted twice (rw for the DB, ro for the relay) (see `relay/README.md`). Fleet hosts then build their mailbox image instantly from it (no Rust compile on the host), and the hub serves it at `/v1/relay-binary` for dedicated VMs (authenticated with the per-mailbox token in their startup script). Absent → fleet hosts compile the crate on first ignite; dedicated-VM provisioning refused. It is a *directory*, not the file: bind-mounting a file that does not exist yet creates a directory in its place, which reads as a corrupt relay rather than a missing one |
| `WITH_BILLING` / `WITH_GCP` | `1` / `0` | Build args, not runtime config: whether `stripe` and `google-cloud-compute` are installed in the image. Change either and rebuild (`up -d --build`) |
| `STONECHAT_HUB_URL` | — | Public base URL of the hub (`https://hub.example.com`) — how dedicated-VM startup scripts reach `/v1/relay-binary` |
| `STONECHAT_RELAY_BINARY_URL` | — | Override: fetch the relay from an external artifact URL (GCS/GitHub release) instead of the hub |
| `STONECHAT_HETZNER_TOKEN` | — | Hetzner Cloud project API token (read+write) → enables the `hetzner` provider. Locations `fsn1`/`nbg1` (DE), `hel1` (FI), `sin` (SG); x86 server types only (`cx22`, `cpx11`) — the relay binary is x86_64-musl. |
| `STONECHAT_VULTR_TOKEN` | — | Vultr API key → enables the `vultr` provider (São Paulo, Santiago, Mexico City, Tokyo, Osaka, Seoul, Singapore). Vultr **also** gates the API on an IP allow-list (Account → API → Access Control): the hub's egress address must be listed there or every call answers 403. |
| `STONECHAT_DO_TOKEN` | — | DigitalOcean personal access token (write scope) → enables the `digitalocean` provider |
| `STONECHAT_CORS_EXTRA` | — | Comma-separated extra browser origins allowed to call the hub. **The web client needs this**: it is a browser, so every call is cross-origin. Serving it from `http://localhost:3000` during a test means setting `STONECHAT_CORS_EXTRA=http://localhost:3000`. Without it the client fails with a bare "Failed to fetch" and the symptom appears on the *phone* as "that code has expired" |

## 5. Open the CLOUD firewall too

`ufw` guards the OS, but cloud providers have a **separate** network firewall
you must also open. Add inbound TCP rules for:

- **`8000`** (or your `STONECHAT_HUB_PORT`) — to the **hub** VM only
- **`8100`** — to the **hub** VM, from the fleet hosts' *internal* addresses
  only, and only if you enable push (GCP's `default-allow-internal` already
  covers this)
- **`32768–60999` TCP** — to the **fleet host(s)** only (Docker's published-port
  range for mailbox containers)
- **`32768–60999` UDP** — same hosts. The browser transport is QUIC, and
  Docker publishes it on a random host port from the same range. Without this
  the web client cannot reach any mailbox, while phones work perfectly — a
  failure that looks like a client bug and is not.

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
  --dart-define=STONECHAT_HUB=http://<HUB_IP>:8000 \
  --dart-define=STONECHAT_PROVIDER=fleet
```

Baking `STONECHAT_HUB` in means neither of you has to type the hub address.
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
   "delete the only machine my messages ever touched."

Keep the app **foregrounded**: there are no push notifications yet, so delivery
happens over the live WebSocket while the app is open or on resume.

## Operating it

```bash
# on the hub box, from deploy/:
docker compose ps                       # is it up? "healthy" = serving /health
docker compose logs -f                  # live logs
docker compose up -d                    # after editing .env (restart does NOT re-read it)
docker -H ssh://stonechat-fleet@<FLEET_ADDR> ps   # running mailboxes (on the fleet host)

# update to the latest code:
cd ~/stonechat && git pull && cd deploy && docker compose up -d --build
```

### Upgrading the relay without destroying mailboxes

`git pull && docker compose up -d --build` updates the **hub**. It does not touch mailboxes:
they are running containers, and a mailbox's queue, prekeys, TLS key and
WebTransport certificates live in its container — not in a volume — so that
destroying it destroys the data with it. Recreating a container to pick up new
relay code would therefore reset every user's mailbox.

So relay releases are rolled in place: the new binary is copied over the
entrypoint and the container restarted. The data layer survives a restart, and
the published ports are pinned at create time, so the address the hub already
handed out stays valid.

The roll runs *inside* the hub container: the image already carries
`scripts/roll_relay.py`, the Docker CLI and the fleet SSH key, which is the
whole set of things the roll needs.

```bash
# 1. build the artifact (see relay/README.md "Producing the production artifact")
docker build --platform linux/amd64 -t stonechat-relay-build relay/
id=$(docker create --platform linux/amd64 stonechat-relay-build) && \
  docker cp "$id":/stonechat-relay ./stonechat-relay && docker rm "$id"

# 2. put it where the hub already looks — STONECHAT_RELAY_DIR, mounted at
#    /opt/stonechat inside the container
install -m 755 ./stonechat-relay /opt/stonechat/stonechat-relay

# 3. see what would change, without changing it
cd deploy
docker compose exec hub python /srv/scripts/roll_relay.py \
  --binary /opt/stonechat/stonechat-relay --dry-run

# 4. roll it
docker compose exec hub python /srv/scripts/roll_relay.py \
  --binary /opt/stonechat/stonechat-relay
```

Each relay reports the hash of the binary it is running on `/status`, so the
script verifies the swap took rather than assuming it did. It goes one mailbox
at a time, and on the first failure it rolls that mailbox back to its previous
binary and stops — leaving the rest of the fleet up on the old release.

New mailboxes are built from `STONECHAT_RELAY_BINARY`, which is that same
mounted path — so step 2 already pointed it at the new artifact. Restart the
hub (`docker compose restart hub`) to pick up the new content hash, or the next
user provisioned lands on the old code.

State that survives restarts: the hub DB at
`/var/lib/stonechat/hub.db` (WAL mode — recent writes live in the `-wal`/`-shm`
sidecars, so snapshot a *live* hub with `sqlite3 hub.db ".backup out.db"`,
not a bare `cp hub.db`) and each mailbox's SQLite + TLS key in its container's
own writable layer — no volume, deliberately. Destroying a mailbox from the app
(or `docker rm -f`) is final: the layer goes with the container and its
undelivered ciphertext is gone, by design. That is also why relay upgrades are
a binary swap rather than a recreate (above).

### The reusable tester code (`STONECHAT_TEST_CODE`)

TestFlight testers activate with a shared code that survives identity resets
(PROTOCOL.md "Billing"). It lives in a **systemd drop-in** — deliberately not
in `setup.sh`, which rewrites the main unit on every deploy — so it persists
across code updates:

```bash
# on the hub box — set (or rotate) the codes; several codes with per-code
# plans are supported (plan omitted → mailbox):
sudo mkdir -p /etc/systemd/system/stonechat-hub.service.d
printf '[Service]\nEnvironment=STONECHAT_TEST_CODES=STONECHAT-XXXX-XXXX=mailbox,STONECHAT-YYYY-YYYY=machine\n' \
  | sudo tee /etc/systemd/system/stonechat-hub.service.d/test-code.conf
sudo systemctl daemon-reload && sudo systemctl restart stonechat-hub

# REVOKE it (anyone who knows the code gets a free plan — kill it
# before opening TestFlight beyond people you trust):
sudo rm /etc/systemd/system/stonechat-hub.service.d/test-code.conf
sudo systemctl daemon-reload && sudo systemctl restart stonechat-hub
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

**3. Run it** on the hub box, as the `push_gateway` compose profile:

```bash
sudo mkdir -p /etc/stonechat && sudo cp /path/to/AuthKey_XXXX.p8 /etc/stonechat/apns.p8
cd ~/stonechat/deploy
$EDITOR .env          # the push block: APNs ids + topic, STONECHAT_PUSH_BIND
docker compose --profile push_gateway up -d --build
docker compose --profile push_gateway ps  # push_gateway: "healthy"
curl -s http://<STONECHAT_PUSH_BIND>:8100/health  # -> {"apns": true, ...}
```

Put `COMPOSE_PROFILES=push_gateway` in `.env` so every later plain `docker compose`
command includes it. The container gets only the push variables from `.env`,
never the hub's tokens, and `/etc/stonechat` is mounted read-only.

It must be reachable **from mailboxes, never from the internet**. Mailboxes
run on the fleet hosts, so publish it on this box's *private* address
(`STONECHAT_PUSH_BIND`) and allow 8100 from the internal network only in the
cloud firewall. `ufw` cannot do this part: as with the hub port, Docker's
rules bypass it. If the fleet host cannot reach it, pings fail quietly — the
relay logs `gateway ping failed`, nothing else breaks, push just never arrives.
Check from the fleet host with `curl http://<HUB_INTERNAL_IP>:8100/health`.

**4. Point the hub at it** in the same `.env`, then `docker compose up -d`:

```bash
STONECHAT_PUSH_GATEWAY=http://<HUB_INTERNAL_IP>:8100
STONECHAT_PUSH_MINT_SECRET=<openssl rand -hex 32>
```

The mint secret turns on per-relay push keys (recommended; see PROTOCOL.md
"Push gateway"): the hub mints one into each mailbox and the push service
refuses pings without it. Mailboxes pick all of this up when they are
provisioned, so set it before the first Ignite, or re-ignite existing ones.
Verify with a message to a user whose app is fully closed.
To cut off one abusive relay: its `pk_…` id from `docker compose logs push_gateway` →
`/etc/stonechat/push-blocklist` (no restart needed).


## Running on Google Cloud

The same scripts deploy to GCE VMs. Differences from the DO/Hetzner
walkthrough:

1. **Project setup** (once): enable the Compute Engine API.
2. **Hub VM**: an `e2-micro` in `us-central1`/`us-west1`/`us-east1`
   is free-tier. Give it a network tag, e.g. `stonechat-hub`, and promote its
   external IP to static so the address baked into app builds survives
   restarts.
3. **Fleet host VM**: another `e2-micro` (or bigger as users grow), network
   tag `stonechat-fleet`, static IP too — mailbox addresses embed it. Use the
   **internal** VPC address in `STONECHAT_FLEET_HOSTS`'s SSH endpoint and the
   static **external** IP as the advertise address.
4. **Cloud firewall**: VPC firewall rules replace the DO/Hetzner cloud
   firewall UI — allow `tcp:8000` to the `stonechat-hub` tag and
   `tcp:32768-60999` **and `udp:32768-60999`** to the `stonechat-fleet` tag.
   TCP alone leaves every mailbox reachable from phones and silently
   unreachable from browsers: the browser transport is QUIC, and Docker
   publishes it on a random host port from the same range. (Same-VPC SSH
   between the two boxes is covered by `default-allow-internal`, including
   across regions.)
5. **Deploy** as in steps 2–4 above.

### Optional: per-user mailbox VMs (`gcp` provider)

GCP is also the one cloud where the per-user-VM tier already has a finished
adapter — each user gets their own `e2-micro` instead of a container. Extra
setup: create a service account for the hub, grant it
`roles/compute.instanceAdmin.v1` + `roles/compute.securityAdmin` on the
project, attach it to the hub VM (`--scopes=cloud-platform` — ADC, no key
files), and deploy with `STONECHAT_GCP_PROJECT=<PROJECT_ID>` set (this installs
`google-cloud-compute`). Mailbox VMs get their own auto-created firewall rule
(`stonechat-allow-mailbox`, tcp:8080). Release builds pick the provider from the
account's plan (mailbox → `fleet`, machine → `gcp`, defaults `e2-micro` /
`us-central1-a`); baking `--dart-define=STONECHAT_PROVIDER=...` into a build
overrides the plan mapping for every install — test builds only. Cost note: a
per-user `e2-micro` + IPv4 runs ~$7–10/mo, vs ~$0.30/user on a shared fleet
host.

Unlike AWS, a GCE VM *can* reach its own external IP, so the self-health-check
works.

## Host friends on your box ("host your circle")

Want your VM to also host a few friends' mailboxes? Run the **machine host**
(`machine_host/README.md`) alongside the hub — it mints invites and spins up
a container per invited friend on the same box, each end-to-end encrypted and
unreadable to you. Open port 8200 (machine host) plus the guest mailbox ports
(42000–42024 by default; `STONECHAT_MACHINE_HOST_PORT_BASE`), and share
invites from the app ("Host friends on your machine"). Friends redeem with
"Join a friend's host."

## What this setup skips (fine for two people)

- **The reconciler, billing, abuse handling** — the "before charging money"
  list in notes/BUSINESS.md (internal). Not needed for a test.
- **A domain + HTTPS on the hub** — the app talks to it over plain HTTP
  unless you set one. (Mailbox traffic is already pinned TLS regardless.) For
  anything public, point a name at the box, set
  `STONECHAT_HUB_DOMAIN=hub.example.com` in `.env` and start with
  `--profile tls`: Caddy fetches and renews the certificate on its own. Then build the app with
  `--dart-define=STONECHAT_HUB=https://hub.example.com`. Set the DNS record *first* —
  Caddy proves ownership over port 80 at startup.

## Adding a country (a new fleet host)

A country is offered on the Mailbox plan exactly when a fleet host declares
it in `STONECHAT_FLEET_HOSTS` — there is no separate country list, so this
checklist *is* the feature. Example: Germany, GCP `europe-west3`.

```bash
# 1. VM, tagged so the fleet firewall rule applies to it
gcloud compute instances create stonechat-fleet-de-1 --zone europe-west3-a \
  --machine-type e2-micro --image-family debian-12 --image-project debian-cloud \
  --tags stonechat-fleet

# 2. Cloud firewall for the mailbox port range — TCP *and* UDP, once per tag
gcloud compute firewall-rules create stonechat-allow-fleet-mailboxes \
  --allow tcp:32768-60999,udp:32768-60999 \
  --target-tags stonechat-fleet --source-ranges 0.0.0.0/0

# 3. STATIC external IP. Easy to skip — nothing complains until much later.
#    Promoting the ephemeral address the VM already has is in-place and needs
#    no restart; reserving it up front works too.
gcloud compute addresses create stonechat-fleet-de-1-ip \
  --addresses <THE-VM-EXTERNAL-IP> --region europe-west3

# 4. Prepare the host (installs Docker, creates the fleet user, opens ufw)
gcloud compute scp deploy/fleet-host.sh stonechat-fleet-de-1:/tmp/ --zone europe-west3-a
gcloud compute ssh stonechat-fleet-de-1 --zone europe-west3-a --command \
  'sudo STONECHAT_HUB_PUBKEY="<hub root ssh pubkey>" bash /tmp/fleet-host.sh'

# 5. Pre-trust the host key ON THE HUB, or docker-over-SSH fails on first ignite
gcloud compute ssh <hub> --command \
  'sudo sh -c "ssh-keyscan -H <FLEET_INTERNAL_IP> >> /root/.ssh/known_hosts"'
```

Then add it to the pool in `deploy/.env` (comma-separated, next to any hosts
already there):

```bash
STONECHAT_FLEET_HOSTS=de1=ssh://stonechat-fleet@<INTERNAL_IP>|<STATIC_EXTERNAL_IP>|DE
```

`docker compose up -d` to recreate the hub with it, then verify the
country actually became purchasable — this reads the host list, so it is a
real check, not a restatement of what you configured:

```bash
curl -s https://<hub>/v1/countries | jq '.countries[] | {code, plans}'
```

**Why the static IP matters.** The host's external address is the advertise
address: it is baked into every mailbox address the hub stores and hands to
clients, and nothing re-resolves it. An ephemeral IP survives right up until
the first stop/start, then every mailbox on that host is unreachable with
nothing in any log to say why — the same failure the pinned container ports
avoid one level down (`providers/fleet.py`).

The first ignite on a fresh host is slow: it has no relay image yet and builds
one from the hub's `STONECHAT_RELAY_BINARY`.

## Beyond a friends test

You're already on the production topology (hub + fleet hosts).
When you outgrow one fleet host, the moves — all already scaffolded in the
codebase — are: add hosts to `STONECHAT_FLEET_HOSTS` (placement is least-loaded *within the requested country*),
harden containers with `STONECHAT_FLEET_RUNTIME=runsc` (gVisor), offer per-user
VMs as the premium tier (`gcp`, `hetzner`, `vultr` and `digitalocean`
adapters all exist; only `gcp` has been provisioned against for real), pin the mailbox port range, and add the
reconciler. See
the "Before charging money" checklist in notes/BUSINESS.md (internal).
