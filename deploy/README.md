# Deploying Stonechat for a first live test

This gets **two VMs** running the backend: one for the hub + directory, and one
**machine host** where every mailbox lives as a Docker container. Enough for you
and a friend to chat over real iPhones.

> **Topology rule: mailboxes never run on the hub machine.** The hub holds the
> directory and provisioning credentials; mailboxes hold users' (encrypted) mail
> and are exposed to the open internet on a range of ports. Keeping them on
> separate machines means a compromised mailbox host can't touch the directory,
> and the hub's attack surface stays one port.

The hub does not reach into the mailbox host's Docker daemon. Each such box runs
the **machine host** ([`machine_host/README.md`](../machine_host/README.md)) in
managed mode, and the hub places mailboxes on it over that HTTPS API, holding an
admin token and the host's certificate fingerprint. The earlier `fleet` provider
drove the daemon over SSH as a member of the `docker` group, which is root on
every mailbox host in all but name.

Everything here assumes fresh **Debian or Ubuntu** VMs. Per the internal business
notes (notes/BUSINESS.md), **DigitalOcean or Hetzner** are the right hosts
(≈$4–5/mo, bundled IPv4, and — unlike AWS — you can reach your own public IP from
inside the box).

## 1. Get two VMs

- Smallest droplet / cloud instance is plenty for each (1 vCPU, 1 GB).
- Note both **public IPv4s** — call them `HUB_IP` and `MAILBOX_IP`. Phones
  connect to both.
- Make the mailbox host's IP **static** (reserved / floating / elastic). It is
  baked into every mailbox address the hub stores, and nothing re-resolves it: an
  ephemeral address works right up until the first stop/start, and then every
  mailbox there is unreachable with nothing in any log to say why.
- SSH in as root (or a sudo user).

## 2. Prepare the machine host

Follow [`machine_host/README.md`](../machine_host/README.md) — install Docker,
`cp .env.example .env`, set the admin token and
`STONECHAT_MACHINE_HOST_ADVERTISE_HOST`, then `docker compose up -d --build`. Two
extra values make it a hub-managed host rather than a personal one:

```bash
# in machine_host/.env on the MAILBOX VM
STONECHAT_MACHINE_HOST_MANAGED=1        # invites refused; the hub is the only authority
STONECHAT_MACHINE_HOST_CAPACITY=200     # how many mailboxes this box sells
```

Then read the fingerprint the hub will pin, and keep it with the admin token:

```bash
curl -sk https://127.0.0.1:8200/health   # → {"status":"ok","v":1,"tls_fp":"…"}
```

## 3. Start the hub

The hub ships as a container. Compose **2.23.1 or newer** (`docker compose
version`): the Caddyfile for the `tls` profile is written inline in the compose
file.

```bash
# on the HUB VM
git clone <your-repo-url> stonechat && cd stonechat/hub
cp .env.example .env
$EDITOR .env          # at minimum STONECHAT_MACHINE_HOSTS
docker compose up -d --build
```

The pool is one line, and every field is required:

```bash
STONECHAT_MACHINE_HOSTS=de1=https://<MAILBOX_INTERNAL_IP>:8200|DE|<admin token>|<tls fp>
```

The ISO country code is both where mailboxes land and the country list
`/v1/countries` offers — a country is purchasable exactly when a host declares
it, so there is no second list to keep in sync. The fingerprint is the whole
trust anchor: the machine host self-signs, so without it anything on the path
between the two boxes can collect an admin token that provisions mailboxes.

Check it came up — compose health-checks `/health`, so `ps` is the answer — and
then check the pool, which reads the host list rather than restating it:

```bash
docker compose ps          # "healthy" once it is serving
docker compose logs -f
curl -s http://127.0.0.1:8000/v1/countries | jq '.countries[] | {code, plans}'
```

A country shows `"mailbox"` in `plans` only if a machine host declares it.

Re-run `docker compose up -d --build` after a `git pull`; it rebuilds and
restarts in place, and `hub.db` is a bind mount, so it survives. Editing `.env`
needs `up -d`, not `restart` — a restart does not re-read it.

> **`ufw` does not police published container ports.** Docker inserts its own
> iptables rules ahead of ufw's, so `STONECHAT_BIND=0.0.0.0` means the hub port
> is reachable from the internet whatever ufw says. Terminating TLS on this box?
> Set `STONECHAT_BIND=127.0.0.1` so only Caddy can reach the hub.

Knobs live in `hub/.env` (gitignored — it holds the machine hosts' admin tokens);
that file documents each one.

## 4. Open the CLOUD firewall too

`ufw` guards the OS, but cloud providers have a **separate** network firewall you
must also open. Inbound rules:

- **`8000`** (or your `STONECHAT_HUB_PORT`) — to the **hub** VM only.
- **`8200`** — to the **machine host**, from the hub's address only. It is a
  control plane, not a public service.
- **`42000–42024` TCP *and UDP*** — to the **machine host** (the guest mailbox
  range: `STONECHAT_MACHINE_HOST_PORT_BASE` through base + capacity − 1). Each
  mailbox uses the same number for both protocols, so this is one range, not two.
  The UDP half carries the browser transport, which is QUIC. Without it phones
  work perfectly and no browser can reach any mailbox — a failure that looks like
  a client bug and is not.

On DigitalOcean/Hetzner that's the "Cloud Firewall" UI; on AWS/GCP the security
group / VPC firewall. Without this, the app reaches nothing.

## 5. Ship the relay

New mailboxes are built from the relay binary the hub sends its hosts, and that
upload is what pins the version — so do it before the first ignite:

```bash
# build the artifact (relay/README.md "Producing the production artifact")
docker build --platform linux/amd64 -t stonechat-relay-build relay/
id=$(docker create --platform linux/amd64 stonechat-relay-build) && \
  docker cp "$id":/stonechat-relay ./stonechat-relay && docker rm "$id"

# STONECHAT_RELAY_DIR is mounted at /opt/stonechat inside the hub container
install -m 755 ./stonechat-relay /var/lib/stonechat/stonechat-relay
cd hub && docker compose exec hub python /srv/scripts/roll_relay.py \
  --binary /opt/stonechat/stonechat-relay
```

Skip this and a managed host refuses to provision rather than falling back to
`ghcr.io/stonechat-app/relay:latest`, because a floating tag means the hub cannot
say which relay its users are running.

## 6. Build the app and send it to your friend

You need the **Apple Developer Program** ($99/yr) — enroll first, approval can
take a day or two. Then, on your Mac:

```bash
cd app
flutter build ipa --dart-define=STONECHAT_HUB=http://<HUB_IP>:8000
```

Baking `STONECHAT_HUB` in means neither of you has to type the hub address. The
provider is not baked in: a release build asks the hub which tier the account's
plan entitles it to. Upload the archive (Xcode → Organizer, or `xcrun altool`) to
**TestFlight**, then add your friend as an **internal tester** in App Store
Connect — internal testing needs no Apple review, so this is same-day.

(No Mac/Apple account yet? For a quick local proof, run the app from `flutter
run` on a simulator or a USB-tethered iPhone with the same `--dart-define`, and
skip TestFlight.)

## 7. The actual test

Both of you, in the app:

1. **Forge identity** (generates your Ed25519 key on-device).
2. **Ignite**. The hub asks the machine host for a container, and the app pins the
   mailbox's TLS certificate.
3. Exchange **handles** (the three words on your ID screen) — type or QR.
4. Send a message, a photo, a voice note.
5. The finale: hit **Turn off** and watch the mailbox container get destroyed —
   "delete the only machine my messages ever touched."

Without push (below), keep the app **foregrounded**: delivery happens over the
live WebSocket while the app is open or on resume.

## Operating it

```bash
# on the hub box, from hub/:
docker compose ps                       # is it up? "healthy" = serving /health
docker compose logs -f                  # live logs
docker compose up -d                    # after editing .env (restart does NOT re-read it)

# what the pool is holding, asked of the host itself:
curl -sk https://<MAILBOX_IP>:8200/v1/guests -H "Authorization: Bearer <admin token>"

# update to the latest code:
cd ~/stonechat && git pull && cd hub && docker compose up -d --build
```

### Upgrading the relay without destroying mailboxes

`git pull && docker compose up -d --build` updates the **hub**. It does not touch
mailboxes: a mailbox's queue, prekeys, TLS key and WebTransport certificates live
in its container's writable layer — not in a volume — so destroying it destroys
the data with it. Recreating a container to pick up new relay code would
therefore reset every user's mailbox.

So relay releases are rolled in place: the new binary is copied over the
entrypoint and the container restarted. The data layer survives a restart, and
the published ports are pinned at create time, so the address the hub already
handed out stays valid.

The swap happens **on each machine host**, which is where Docker access lives.
`scripts/roll_relay.py` uploads the binary and then asks each host to roll:

```bash
# 1. build the artifact (relay/README.md "Producing the production artifact"),
#    then put it where the hub already looks
install -m 755 ./stonechat-relay /var/lib/stonechat/stonechat-relay

# 2. see what would change, without changing it (uploads nothing)
cd hub
docker compose exec hub python /srv/scripts/roll_relay.py \
  --binary /opt/stonechat/stonechat-relay --dry-run

# 3. roll it
docker compose exec hub python /srv/scripts/roll_relay.py \
  --binary /opt/stonechat/stonechat-relay
```

Each relay reports the hash of the binary it is running on `/status`, so the host
verifies the swap took rather than assuming it did. It goes one mailbox at a
time, and on the first failure it rolls that mailbox back to its previous binary
and stops — leaving the rest of the host up on the old release.

The upload also sets what **new** mailboxes are built from, so there is nothing
else to remember afterwards. (Under the old fleet provider this was a separate
step: ship the binary, then restart the hub, or the next user provisioned landed
on the old code.)

State that survives restarts: the hub DB at `/var/lib/stonechat/hub.db` (WAL mode
— recent writes live in the `-wal`/`-shm` sidecars, so snapshot a *live* hub with
`sqlite3 hub.db ".backup out.db"`, not a bare `cp`), the machine host's
`machine_host.db` and TLS keypair, and each mailbox's SQLite + TLS key in its
container's own writable layer — no volume, deliberately. Destroying a mailbox
from the app (or `docker rm -f`) is final: the layer goes with the container and
its undelivered ciphertext is gone, by design. That is also why relay upgrades
are a binary swap rather than a recreate.

### The reusable tester code (`STONECHAT_TEST_CODE`)

TestFlight testers activate with a shared code that survives identity resets
(PROTOCOL.md "Billing"). It lives in the hub's `.env`, so it persists across code
updates:

```bash
# on the hub box, in hub/.env — several codes with per-code plans are supported
# (plan omitted → mailbox):
STONECHAT_TEST_CODES=STONECHAT-XXXX-XXXX=mailbox,STONECHAT-YYYY-YYYY=machine
```

`docker compose up -d` to apply. To **revoke** (anyone who knows the code gets a
free plan — kill it before opening TestFlight beyond people you trust), delete
the line and `up -d` again.

Revoking stops new activations only: subscriptions it already minted stay active
(`source = 'test'` in the `subscriptions` table — audit or purge them there).
Never publish the code value; it is not in the repo, only in `.env` on the box.

## Enable push (optional)

Without push, messages arrive only while the app is open or on resume. The push
gateway is its own compose project, deployed separately from the hub — see
[`push_gateway/README.md`](../push_gateway/README.md). Read its "Before you run
this" first: it only wakes phones running an app build signed with your own
Apple/Firebase credentials.

Once it runs, point the hub at it in `hub/.env` and `docker compose up -d`:

```bash
STONECHAT_PUSH_GATEWAY=http://<GATEWAY_PRIVATE_IP>:8100
STONECHAT_PUSH_MINT_SECRET=<openssl rand -hex 32>
```

The address must be one **mailboxes** can reach — they run on the machine host,
so never `127.0.0.1` — and the gateway must hold the same mint secret. The hub
mints a key into each mailbox it places, so set both before the first ignite, or
re-ignite afterwards.

## Adding a country (a new machine host)

A country is offered on the Mailbox plan exactly when a machine host declares it
in `STONECHAT_MACHINE_HOSTS` — there is no separate country list, so this
checklist *is* the feature.

1. **VM** with a **static** public IP, in the country you are adding.
2. **Cloud firewall**: `8200/tcp` from the hub only, and `42000–42024` **TCP and
   UDP** for the mailboxes.
3. **Machine host**: install it per
   [`machine_host/README.md`](../machine_host/README.md) with
   `STONECHAT_MACHINE_HOST_MANAGED=1`, then read its `tls_fp` from `/health`.
4. **Add it to the pool** in `hub/.env` (comma-separated, next to the hosts
   already there) and `docker compose up -d`:

   ```bash
   STONECHAT_MACHINE_HOSTS=de1=https://10.0.0.5:8200|DE|<token>|<fp>,fr1=https://10.0.0.9:8200|FR|<token>|<fp>
   ```

5. **Ship it a relay**: `roll_relay.py --binary <path> --host fr1`. A managed host
   with no relay installed refuses to provision rather than guessing at one.
6. **Verify the country became purchasable** — this reads the host list, so it is
   a real check rather than a restatement of what you configured:

   ```bash
   curl -s https://<hub>/v1/countries | jq '.countries[] | {code, plans}'
   ```

Placement is least-loaded **within the requested country** and never falls back
to another: a mailbox quietly placed somewhere the user did not pick is the one
failure this feature exists to prevent.

## Host friends on your box ("host your circle")

The same program, without a hub in front of it: leave
`STONECHAT_MACHINE_HOST_MANAGED` unset and it mints invites instead, spinning up
a container per invited friend, each end-to-end encrypted and unreadable to you.
See [`machine_host/README.md`](../machine_host/README.md); friends redeem with
"Join a friend's host."

## What this setup skips (fine for two people)

- **The reconciler, billing, abuse handling** — the "before charging money" list
  in notes/BUSINESS.md (internal). Not needed for a test.
- **A domain + HTTPS on the hub** — the app talks to it over plain HTTP unless
  you set one. (Mailbox traffic is already pinned TLS regardless.) For anything
  public, point a name at the box, set `STONECHAT_HUB_DOMAIN=hub.example.com` in
  `hub/.env` and start with `--profile tls`: Caddy fetches and renews the
  certificate on its own. Then build the app with
  `--dart-define=STONECHAT_HUB=https://hub.example.com`. Set the DNS record
  *first* — Caddy proves ownership over port 80 at startup.

## Beyond a friends test

You're already on the production topology (hub + machine hosts). When you outgrow
one host, the moves — all already scaffolded — are: add hosts to
`STONECHAT_MACHINE_HOSTS` (placement is least-loaded within the requested
country), harden containers with `STONECHAT_MACHINE_HOST_RUNTIME=runsc` (gVisor,
set on the host), offer per-user VMs as the premium tier (`gcp`, `hetzner`,
`vultr` and `digitalocean` adapters all exist; only `gcp` has been provisioned
against for real), and add the reconciler. See the "Before charging money"
checklist in notes/BUSINESS.md (internal).
