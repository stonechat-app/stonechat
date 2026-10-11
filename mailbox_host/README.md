# Stonechat mailbox host — the program that runs mailboxes

Run this on a VM **you own** to host your own mailbox *plus* invited friends'
mailboxes on the same box. A shared host, but only with people you choose.

It is also what every box holding mailboxes runs, including the hosted
service's. Two ways in, one program:

| | Who decides who lands here | How |
|---|---|---|
| **Invite mode** (default) | you, the owner | you mint invites and friends redeem them |
| **Managed mode** (`STONECHAT_MAILBOX_HOST_MANAGED=1`) | a hub you also run | the hub places mailboxes over this API ("Hosting for a hub" below) |

Managed mode refuses invites outright, so a box has exactly one authority. It
replaced the `fleet` provider, where the hub reached mailbox hosts by SSH as a
member of the `docker` group — root there in all but name. The containers are
the same; what the hub holds is now a token for this API. That token places,
lists and destroys mailboxes on the box — and can upload the relay binary
new mailboxes are built from and rolled onto, so whoever holds it can ship
code to this box. Signing releases so that it cannot is planned.

> Machine-tier VMs provisioned by the hub come with this service
> **pre-installed** (see `hub/app/providers/bootstrap.py`) — the app picks up
> its address and admin token from `GET /v1/mailbox` automatically. The manual
> steps below are for self-hosters.

Each guest gets their own `stonechat-relay` container — own port, own token, own
TLS cert, cgroup/pids caps. From the directory's point of view a guest's mailbox
is just an ordinary self-hosted ("external") relay that happens to live on your
box. The hub and Stonechat-the-company never touch this machine; the mailbox host
is the only thing here with Docker access.

## Trust model (tell your guests)

Messages stay **end-to-end encrypted and unreadable** — you cannot read your
friends' chats, even as root on this box; you'd see only undelivered ciphertext.
But you *can* see **that** a friend has a mailbox here and its traffic metadata
(who/when/size, connecting IPs). That's the same exposure any relay operator has
— the difference is your friend chose *you* as their operator instead of a
company. Only invite people who are OK with you seeing that metadata.

One honest wrinkle: the mailbox host generates each guest's mailbox token, and you have
root, so the token isn't a secret *from you* (it protects against third
parties). Consistent with the model — the guest already trusts you enough to
live on your box, and E2EE still protects content.

## Host your own Stonechat, step by step

From nothing to chatting with friends whose mailboxes all live on a box you
control. Budget ~30 minutes, most of it waiting on a VM.

You need: a Linux VM from any provider (the smallest tier is plenty — 1 vCPU,
1 GB, ~$5/mo) or an always-on Linux box at home, and the Stonechat app from the
App Store / Google Play on your phone and each friend's.

### 1. Get the box online

- Create the VM (Debian/Ubuntu is the easy path) with a **static public IP** —
  providers call it reserved, floating, or elastic. The IP is baked into every
  mailbox address on this host, so it must not change across restarts.
- Open inbound in the provider's firewall (and `ufw`, if you run it):
  **8200/tcp** (the mailbox host) and **42000–42024 TCP _and UDP_** (guest
  mailboxes: `STONECHAT_MAILBOX_HOST_PORT_BASE` through base + capacity − 1 —
  fixed ports, not Docker-ephemeral, so the rule survives reboots). Each guest
  uses the same number for both protocols, so there is one range to open, not
  two. The UDP half carries the browser transport (QUIC): without it phones work
  perfectly and no browser can reach any mailbox on this box, which reads like a
  client bug and is not.
- Also **43000–43049/udp** (`STONECHAT_MAILBOX_HOST_TURN_PORT_BASE` through base
  + 2 × capacity − 1): each guest's call relay, two ports per guest. Without
  them messaging is untouched and calls only connect where the two phones can
  reach each other directly — which, from a phone on mobile data, they
  usually cannot.
- Hosting at home instead? Forward those same ports on your router to the box,
  and use your connection's public IP (or a dynamic-DNS name if it rotates).

### 2. Install and run the mailbox host (Docker Compose)

SSH in and:

```bash
curl -fsSL https://get.docker.com | sudo sh     # Docker Engine + compose plugin
sudo git clone https://github.com/stonechat-app/stonechat.git /opt/stonechat
cd /opt/stonechat/mailbox_host

sudo cp .env.example .env
openssl rand -hex 24     # your ADMIN TOKEN — save it; you'll paste it into the app
sudo nano .env           # set STONECHAT_MAILBOX_HOST_ADMIN_TOKEN and _ADVERTISE_HOST

sudo docker compose up -d --build
curl -sk https://127.0.0.1:8200/health    # → {"status":"ok","v":1,"tls_fp":"..."}
```

That's it — `restart: always` brings it back after crashes and reboots. What
the compose file sets up, and why:

- **The Docker socket is mounted in.** Guest mailboxes are *sibling*
  containers on the host's Docker, started on demand with
  `--restart unless-stopped` — they are not compose services, and they keep
  running through `docker compose down`. Holding the socket is root on the
  box; that is this service's whole job.
- **Host networking** (`network_mode: host`, Linux only), so it listens on the
  box's own :8200 and reaches freshly launched guests exactly as the host does.
- **State lives in `/var/lib/stonechat`** (`STONECHAT_STATE_DIR` to move it):
  `mailbox_host.db` plus the TLS keypair. **Back it up** — every invite you've
  sent carries that certificate's fingerprint, and the app pins it.

Nothing gets compiled on your box. The first mailbox provision pulls the
published relay image (`ghcr.io/stonechat-app/relay:latest`, ~10 MB); later
ones reuse it and start in seconds. To update the mailbox host: `git pull`
then `sudo docker compose up -d --build` — running guests are untouched. New
guests keep using the relay image already on the box until you
`sudo docker pull ghcr.io/stonechat-app/relay:latest`.

Upgrading a relay is a **binary swap, never a container recreate**: a mailbox
keeps its queue, prekeys and TLS key in the container's own writable layer with
no volume behind it, so `docker run` on a new image would hand every guest an
empty mailbox. `POST /v1/relay/roll` does the swap, one mailbox at a time,
checking each relay reports the new build on `/status` and rolling that one back
if it does not.

Where the new binary comes from depends on how the host is configured, and both
ways end at the same artifact:

- **Pinned to an image** (`STONECHAT_MAILBOX_HOST_IMAGE=…@sha256:…`) — the usual
  case. Nothing to upload: the host takes the binary out of that image, so what
  a fresh mailbox runs and what a rolled one runs cannot drift apart. Point the
  host at a new digest, restart it, then roll.
- **Given a binary** (`POST /v1/relay`) — for an air-gapped box or a build that
  is not published yet. It also becomes what new mailboxes are built from.
  `scripts/roll_relay.py` drives this end of it.

All the knobs (in `.env`):

| Env | Default | Meaning |
|---|---|---|
| `STONECHAT_MAILBOX_HOST_ADMIN_TOKEN` | — (required) | Secret you hold; authorizes minting/eviction. At least 16 characters — the host refuses to start on an empty or short one |
| `STONECHAT_MAILBOX_HOST_ADVERTISE_HOST` | — (required) | Public host/IP guests connect to |
| `STONECHAT_MAILBOX_HOST_CAPACITY` | `25` | Max guest mailboxes on this host |
| `STONECHAT_MAILBOX_HOST_PORT_BASE` | `42000` | First guest mailbox port; guests get `base…base+capacity−1` |
| `STONECHAT_MAILBOX_HOST_TURN_PORT_BASE` | `43000` | First call-relay port; guest *i* gets `base+2i` and the next (UDP, same numbers inside and out) |
| `STONECHAT_MAILBOX_HOST_IMAGE` | `ghcr.io/stonechat-app/relay:latest` | Mailbox image; pulled if not already on the box. Ignored once a binary is uploaded through `POST /v1/relay`. Managed mode refuses this floating default — pin a digest or upload a binary, or the hub cannot say which relay its users run |
| `STONECHAT_MAILBOX_HOST_MANAGED` | — | `1` → a hub places mailboxes here; invites are refused |
| `STONECHAT_MAILBOX_HOST_RELAY_DIR` | the DB's directory | Where uploaded relay binaries are kept |
| `STONECHAT_PUSH_MINT_SECRET` | — | Mints a push key into each guest. Only useful with your own gateway, which must hold the same secret. In managed mode the hub mints it instead |
| `STONECHAT_MAILBOX_HOST_RUNTIME` | — | Set to `runsc` for gVisor hardening |
| `STONECHAT_PUSH_GATEWAY` | — | Passed through to guest mailboxes |
| `STONECHAT_MAILBOX_HOST_PORT` | `8200` | Listen port |
| `STONECHAT_STATE_DIR` | `/var/lib/stonechat` | Host directory for the DB and TLS keypair (compose only) |

<details>
<summary>Without Docker Compose: plain Python + systemd</summary>

Requirements: Docker, `openssl`, Python 3.11+.

```bash
sudo apt-get update && sudo apt-get install -y docker.io git python3-venv openssl
sudo systemctl enable --now docker

sudo git clone https://github.com/stonechat-app/stonechat.git /opt/stonechat
cd /opt/stonechat/mailbox_host
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
```

```ini
# /etc/systemd/system/stonechat-mailbox-host.service
[Unit]
Description=Stonechat mailbox host
After=network-online.target docker.service
Requires=docker.service

[Service]
Environment=STONECHAT_MAILBOX_HOST_ADMIN_TOKEN=<your admin token>
Environment=STONECHAT_MAILBOX_HOST_ADVERTISE_HOST=<your static public IP>
Environment=STONECHAT_MAILBOX_HOST_DB=/var/lib/stonechat/mailbox_host.db
Environment=STONECHAT_MAILBOX_HOST_TLS_DIR=/var/lib/stonechat
ExecStart=/opt/stonechat/mailbox_host/.venv/bin/python /opt/stonechat/mailbox_host/main.py
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
```

```bash
sudo mkdir -p /var/lib/stonechat
sudo systemctl daemon-reload && sudo systemctl enable --now stonechat-mailbox-host
curl -sk https://127.0.0.1:8200/health
```

Both paths use the same `/var/lib/stonechat`, so you can switch between them
without losing invites or guests (stop one before starting the other).

</details>

### 3. Create your own mailbox on the box

Install Stonechat, **forge your identity**, and copy your Stonechat ID
(`SC-…`). The app can't create a mailbox on a mailbox host yet — invites are
for friends — so make yours directly, on the box:

```bash
curl -sk -X POST https://127.0.0.1:8200/v1/guest \
  -H "Authorization: Bearer <your admin token>" \
  -H 'content-type: application/json' \
  -d '{"owner_id": "SC-…"}'
# → {"address": "https://<your-ip>:42000", "mailbox_token": "…", "tls_fp": "…"}
```

In the app: **Mailbox** screen → **Self-host** → paste the `address` and
`mailbox_token` → **Connect my mailbox**. The token now lives on your phone;
nothing else needs it.

### 4. Connect your app to the mailbox host

With your mailbox running, the Mailbox screen shows an **Invites** card
("Host friends on your machine"). Open it → **Mailbox host address**
`https://<your-ip>:8200` + **Admin token** → **Connect** → **New invite**.
The invite is copied to your clipboard; it's single-use and valid for 3 days,
and the list below shows whether each one was accepted.

### 5. Bring the friends

Send each friend the `stonechat-host:…` invite string **privately**. It
contains the token that redeems it, so anyone who sees it before it is used
can claim a mailbox on your box with it. The fingerprint inside protects
something else: their app pins the connection to your host's certificate, so
the redeem call itself can't be intercepted. Each friend: install
the app → forge an identity → **Mailbox** screen → **A friend's machine** →
paste the invite → **Join with invite**. Their mailbox spins up on your box;
its token stays on their phone.

### 6. Chat

Exchange Stonechat IDs (QR or text) and message away. Everything is
end-to-end encrypted on the phones — your box only ever holds ciphertext,
deleted on delivery. If your box ever dies, nobody's history is lost: it
lives on their phones, and they can re-home their mailboxes anywhere.

### TL;DR

1. Linux VM (or home box) with a **static public IP**; open inbound
   **8200/tcp**, **42000–42024** (TCP and UDP) and **43000–43049/udp**.
2. `curl -fsSL https://get.docker.com | sudo sh`, then
   `sudo git clone https://github.com/stonechat-app/stonechat.git /opt/stonechat`.
3. In `/opt/stonechat/mailbox_host`: `cp .env.example .env`, set the admin
   token (`openssl rand -hex 24`) and your public IP, then
   `sudo docker compose up -d --build`.
4. In your app: forge identity, copy your `SC-…` ID. On the box:
   `POST /v1/guest` with it (curl above).
5. App: **Mailbox** → **Self-host** → address + mailbox token → **Connect my
   mailbox**.
6. App: **Invites** → host address + admin token → **Connect** → **New invite**.
7. Friends: install app → forge identity → **A friend's machine** → paste →
   **Join with invite**.
8. Swap Stonechat IDs, chat.

## API

Guests never call the admin endpoints; the app does the redeem for them.

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/health` | none | Liveness + pinning: `{status, v, tls_fp}`. Guest count/capacity are admin-only (see `/v1/guests`). |
| POST | `/v1/invite` | admin | `{uses, ttl_hours}` → `{invite}` — the string you share. 403 in managed mode |
| GET | `/v1/invites` | admin | every minted invite with status: `{invites: [{invite, uses, uses_left, expires_at, created_at, redeemed_by}]}`. 403 in managed mode |
| POST | `/v1/redeem` | none | `{invite: <token>, owner_id}` → `{address, mailbox_token, tls_fp, wt_address}`. 403 in managed mode |
| POST | `/v1/guest` | admin | `{owner_id}` — provision directly, no invite (e.g. your own mailbox). A hub also sends `owner_token` (the token it has already recorded for that mailbox) and `push_key` |
| GET | `/v1/guests` | admin | `{guests, count, capacity, managed}` — occupancy, which is how a hub picks the emptiest host in a country |
| DELETE | `/v1/guest/{owner_id}` | admin | evict — destroys that guest's container. Idempotent: an unknown guest answers `{"status": "gone"}` |
| GET | `/v1/relay` | admin | which binary new guests get, and what each running relay reports on its own `/status` — so a half-finished roll shows as one |
| POST | `/v1/relay` | admin | upload a relay binary (raw `application/octet-stream`); it becomes what new guests are built from. Refuses anything that is not an ELF |
| POST | `/v1/relay/roll` | admin | `{only?, dry_run?, force?}` — swap the pinned binary (uploaded, or taken from the pinned image) into running mailboxes, one at a time, stopping and rolling back at the first failure |

The `invite` string is `stonechat-host:` + base64url(`{u: host-url, f: tls-fp, t:
token}`). The guest's app pins the connection to `f`, so the redeem can't
be MITM'd. `t` is the redeem token: the invite is a bearer secret until it is
used up or expires.

## Hosting for a hub (managed mode)

For someone running **both** a hub and the boxes its shared tier sells. The hub
never reads mail here — it holds the directory and places containers; the
ciphertext and the TLS keys live on this box and nowhere else.

On the mailbox host, set two extra values in `.env` and restart:

```bash
STONECHAT_MAILBOX_HOST_MANAGED=1
STONECHAT_MAILBOX_HOST_CAPACITY=200        # how many mailboxes this box sells
```

Then read its certificate fingerprint, which is what the hub pins:

```bash
curl -sk https://127.0.0.1:8200/health     # → {"status":"ok","v":1,"tls_fp":"…"}
```

On the hub, add the box to the pool (`hub/.env`) and restart it:

```bash
STONECHAT_MAILBOX_HOSTS=de1=https://10.0.0.5:8200|DE|<admin token>|<tls fp>
```

Four fields, all required: address, ISO country code, that host's admin token,
and the fingerprint. The country is both where mailboxes land and what the
Mailbox plan offers — `GET /v1/countries` on the hub is derived from this list,
so a country is purchasable exactly when a host here declares it. The
fingerprint is the whole trust anchor, because the mailbox host self-signs:
without it, anything on the path can collect an admin token that provisions
mailboxes. Verify the hub agrees:

```bash
curl -s https://<hub>/v1/countries | jq '.countries[] | {code, plans}'
```

Then ship it a relay, which is also what pins the version its mailboxes run:

```bash
hub/.venv/bin/python scripts/roll_relay.py --binary ./stonechat-relay
```

Keep this box's **public IP static**. It is baked into every mailbox address the
hub hands out and nothing re-resolves it: an ephemeral address works right up
until the first stop/start, and then every mailbox here is unreachable with
nothing in any log to say why.

## Resilience

If this box dies or you stop paying, guests' mailboxes go down — but their
identity and history live on their phones, so they just re-home their mailbox
elsewhere ("Turn on my mailbox" on another provider, or another friend's host).
Evicting a guest is likewise recoverable for them.
