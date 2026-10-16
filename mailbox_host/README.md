# Stonechat mailbox host

Runs mailboxes on a server you own: yours, plus mailboxes for friends you
invite. Each guest gets their own relay container, with its own port, token
and TLS certificate. Everyone stays on the main Stonechat directory.

| Mode | Who decides who lands here |
|---|---|
| **Invite** (default) | You: you create invites, friends redeem them |
| **Managed** (`STONECHAT_MAILBOX_HOST_MANAGED=1`) | A hub you run ("Hosting for your own hub" below). Invites are refused |

## Trust model (tell your guests)

Messages are end-to-end encrypted: even as root on this server you cannot read
your friends' chats. You *can* see that a friend has a mailbox here and its
traffic metadata (when, how much, from which IPs). You also generate each
guest's mailbox token, so it is not a secret from you. Only host people who
are fine with that.

## Step by step

You need a Linux server (1 vCPU / 1 GB is plenty) with a **static public IP**,
and the Stonechat app on your phone and each friend's.

### 1. Open the ports

In your cloud firewall, or forwarded on your router at home:

- **8200/tcp**: the mailbox host.
- **42000–42024, TCP and UDP**: guest mailboxes (`PORT_BASE` through base +
  capacity − 1). The UDP half is the browser transport; browser access to
  guest mailboxes isn't wired up in the app yet, but open it anyway.
- **43000–43049/udp**: each guest's call relay, two ports per guest
  (`TURN_PORT_BASE` through base + 2 × capacity − 1). Without them calls only
  connect when the two phones can reach each other directly.

The IP is baked into every mailbox address on this server, so it must not
change. At home, use a dynamic-DNS name if your IP rotates.

### 2. Install and start

```bash
curl -fsSL https://get.docker.com | sudo sh
sudo git clone https://github.com/stonechat-app/stonechat.git /opt/stonechat
cd /opt/stonechat/mailbox_host

sudo cp .env.example .env
openssl rand -hex 24     # your admin token; save it
sudo nano .env           # set STONECHAT_MAILBOX_HOST_ADMIN_TOKEN and STONECHAT_MAILBOX_HOST_ADVERTISE_HOST

sudo docker compose up -d --build
curl -sk https://127.0.0.1:8200/health    # → {"status":"ok","v":1,"tls_fp":"…"}
```

- It mounts the Docker socket and starts each guest as a sibling container
  (`--restart unless-stopped`), so guests keep running through
  `docker compose down`.
- It uses host networking (Linux only).
- State lives in `/var/lib/stonechat`: `mailbox_host.db` and the TLS keypair.
  **Back it up.** Every invite carries the certificate's fingerprint, and the
  app pins it.

### 3. Create your own mailbox

In the app, create your account and copy your Stonechat ID (`SC-…`). The app
can't create a mailbox on a mailbox host yet, so do it on the server:

```bash
curl -sk -X POST https://127.0.0.1:8200/v1/guest \
  -H "Authorization: Bearer <admin token>" \
  -H 'content-type: application/json' \
  -d '{"owner_id": "SC-…"}'
# → {"address": "https://<ip>:42000", "mailbox_token": "…", "tls_fp": "…"}
```

In the app: **Mailbox** → **Self-host** → paste `address` and `mailbox_token`
→ **Connect my mailbox**.

### 4. Invite friends

In the app: **Mailbox** → **Invites** → **Mailbox host address**
`https://<ip>:8200` and **Admin token** → **Connect** → **New invite**. The
invite is copied to your clipboard; it is single-use and valid for 3 days.

Send it **privately**: it contains the token that redeems it, so whoever uses
it first gets the mailbox.

Each friend: install the app → create an account → **Mailbox** → **A friend's
machine** → paste the invite → **Join with invite**.

## Configuration (`.env`)

| Variable | Default | |
|---|---|---|
| `STONECHAT_MAILBOX_HOST_ADMIN_TOKEN` | required | At least 16 characters |
| `STONECHAT_MAILBOX_HOST_ADVERTISE_HOST` | required | Public IP or DNS name guests connect to |
| `STONECHAT_MAILBOX_HOST_CAPACITY` | `25` | Max guest mailboxes |
| `STONECHAT_MAILBOX_HOST_PORT_BASE` | `42000` | Guest *i* gets `base+i` (TCP and UDP) |
| `STONECHAT_MAILBOX_HOST_TURN_PORT_BASE` | `43000` | Guest *i* gets `base+2i` and the next (UDP) |
| `STONECHAT_MAILBOX_HOST_IMAGE` | `ghcr.io/stonechat-app/relay:latest` | Relay image. Pin a digest (`relay@sha256:…`); managed mode requires it |
| `STONECHAT_MAILBOX_HOST_MANAGED` | | `1`: a hub places mailboxes here |
| `STONECHAT_MAILBOX_HOST_PORT` | `8200` | Listen port |
| `STONECHAT_MAILBOX_HOST_RUNTIME` | | `runsc` for gVisor |
| `STONECHAT_MAILBOX_HOST_RELAY_DIR` | the DB's directory | Where uploaded relay binaries are kept |
| `STONECHAT_PUSH_GATEWAY` | | Passed to guest mailboxes |
| `STONECHAT_PUSH_MINT_SECRET` | | Mints a push key into each guest; must match your gateway's |
| `STONECHAT_STATE_DIR` | `/var/lib/stonechat` | Host directory for the DB and TLS keypair |

## Upgrading

- **The mailbox host:** `git pull && sudo docker compose up -d --build`.
  Running guests are untouched.
- **The relay in running mailboxes:** a guest's data lives in its container,
  so never recreate one; that would be an empty mailbox. Point
  `STONECHAT_MAILBOX_HOST_IMAGE` at the new digest, restart, then call
  `POST /v1/relay/roll`. It swaps the binary into one mailbox at a time and
  rolls back any that does not come up.

If the server dies, nobody loses history: it lives on their phones, and each
guest can move their mailbox elsewhere.

<details>
<summary>Without Docker Compose (Python + systemd)</summary>

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
Environment=STONECHAT_MAILBOX_HOST_ADMIN_TOKEN=<admin token>
Environment=STONECHAT_MAILBOX_HOST_ADVERTISE_HOST=<static public IP>
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
```

Both setups use `/var/lib/stonechat`, so you can switch between them (stop one
first).

</details>

## API

| Method | Path | Auth | |
|---|---|---|---|
| GET | `/health` | none | `{status, v, tls_fp}` |
| POST | `/v1/invite` | admin | `{uses, ttl_hours}` → `{invite}`. 403 in managed mode |
| GET | `/v1/invites` | admin | Every invite and its status. 403 in managed mode |
| POST | `/v1/redeem` | none | `{invite, owner_id}` → `{address, mailbox_token, tls_fp, wt_address}`. 403 in managed mode |
| POST | `/v1/guest` | admin | `{owner_id}`: create a mailbox without an invite. A hub also sends `owner_token` and `push_key` |
| GET | `/v1/guests` | admin | `{guests, count, capacity, managed}` |
| DELETE | `/v1/guest/{owner_id}` | admin | Destroy a guest's mailbox. Idempotent |
| GET | `/v1/relay` | admin | The binary new guests get, and what each running relay reports |
| POST | `/v1/relay` | admin | Upload a relay binary (ELF, `application/octet-stream`); new guests use it |
| POST | `/v1/relay/roll` | admin | `{only?, dry_run?, force?}`: swap the current binary into running mailboxes |

An invite is `stonechat-host:` + base64url(`{u: host URL, f: TLS fingerprint,
t: redeem token}`). The app pins the connection to `f`, so the redeem can't be
intercepted.

The admin token can upload relay binaries, so whoever holds it can run code on
this server. Keep it secret.

## Hosting for your own hub (managed mode)

Only if you run your own hub (see [docs/SELF-HOST.md](../docs/SELF-HOST.md)).
The hub places mailboxes here over this API; the mail and TLS keys stay on
this server.

On the mailbox host, add to `.env` and restart:

```bash
STONECHAT_MAILBOX_HOST_MANAGED=1
STONECHAT_MAILBOX_HOST_CAPACITY=200
STONECHAT_MAILBOX_HOST_IMAGE=ghcr.io/stonechat-app/relay@sha256:<digest>
```

Read its fingerprint with `curl -sk https://127.0.0.1:8200/health`, then add it
to the hub's `.env` and restart the hub:

```bash
STONECHAT_MAILBOX_HOSTS=de1=https://10.0.0.5:8200|DE|<admin token>|<tls_fp>
```

The fields are address, ISO country code, admin token and fingerprint. The
country is where the mailboxes land and what the app's country picker offers.
The fingerprint is required: the mailbox host self-signs, and without the pin
anyone on the path could collect the admin token. Check it with
`curl -s https://<hub>/v1/countries`.

Allow 8200/tcp from the hub only, and keep the public IP static: it is baked
into every mailbox address the hub hands out.
