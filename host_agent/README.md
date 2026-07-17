# Zeon host agent — "host your circle"

Run this on a VM **you own** to host your own mailbox *plus* invited friends'
mailboxes on the same box. A shared host, but only with people you choose.

> Sovereign-tier VMs provisioned by the hub come with this agent
> **pre-installed** (see `hub/app/providers/bootstrap.py`) — the app picks up
> its address and admin token from `GET /v1/server` automatically. The manual
> steps below are for self-hosters.

Each guest gets their own `zeon-server` container — own port, own token, own
TLS cert, cgroup/pids caps. From the directory's point of view a guest's mailbox
is just an ordinary self-hosted ("external") relay that happens to live on your
box. The hub and Zeon-the-company never touch this machine; the agent
is the only thing here with Docker access.

## Trust model (tell your guests)

Messages stay **end-to-end encrypted and unreadable** — you cannot read your
friends' chats, even as root on this box; you'd see only undelivered ciphertext.
But you *can* see **that** a friend has a mailbox here and its traffic metadata
(who/when/size, connecting IPs). That's the same exposure any relay operator has
— the difference is your friend chose *you* as their operator instead of a
company. Only invite people who are OK with you seeing that metadata.

One honest wrinkle: the agent generates each guest's mailbox token, and you have
root, so the token isn't a secret *from you* (it protects against third
parties). Consistent with the model — the guest already trusts you enough to
live on your box, and E2EE still protects content.

## Host your own Zeon, step by step

From nothing to chatting with friends whose mailboxes all live on a box you
control. Budget ~30 minutes, most of it waiting on a VM.

You need: a VM from any provider (the smallest tier is plenty — 1 vCPU, 1 GB,
~$5/mo) or an always-on Linux box at home, and the Zeon app from the App
Store / Google Play on your phone and each friend's.

### 1. Get the box online

- Create the VM (Debian/Ubuntu is the easy path) with a **static public IP** —
  providers call it reserved, floating, or elastic. The IP is baked into every
  mailbox address on this host, so it must not change across restarts.
- Open inbound TCP in the provider's firewall (and `ufw`, if you run it):
  **8200** (the agent) and **42000–42024** (guest mailboxes:
  `ZEON_HOST_AGENT_PORT_BASE` through base + capacity − 1 — fixed ports, not
  Docker-ephemeral, so the rule survives reboots).
- Hosting at home instead? Forward those same ports on your router to the box,
  and use your connection's public IP (or a dynamic-DNS name if it rotates).

### 2. Install the agent

Requirements: Docker, `openssl`, Python 3.11+. SSH in and:

```bash
sudo apt-get update && sudo apt-get install -y docker.io git python3-venv openssl
sudo systemctl enable --now docker

sudo git clone <repo-url> /opt/zeon
cd /opt/zeon/host_agent
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt

openssl rand -hex 24     # your ADMIN TOKEN — save it; you'll paste it into the app
```

### 3. Run it for keeps

A systemd unit keeps the agent alive across crashes and reboots:

```ini
# /etc/systemd/system/zeon-host-agent.service
[Unit]
Description=Zeon host agent
After=network-online.target docker.service
Requires=docker.service

[Service]
Environment=ZEON_HOST_AGENT_ADMIN_TOKEN=<your admin token>
Environment=ZEON_HOST_AGENT_ADVERTISE_HOST=<your static public IP>
Environment=ZEON_HOST_AGENT_DB=/var/lib/zeon/host_agent.db
Environment=ZEON_HOST_AGENT_TLS_DIR=/var/lib/zeon
Environment=ZEON_HOST_AGENT_SERVER_DIR=/opt/zeon/server
ExecStart=/opt/zeon/host_agent/.venv/bin/python /opt/zeon/host_agent/main.py
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
```

```bash
sudo mkdir -p /var/lib/zeon
sudo systemctl daemon-reload && sudo systemctl enable --now zeon-host-agent
curl -sk https://<your-ip>:8200/health    # → {"status":"ok","v":1,"tls_fp":"..."}
```

The first mailbox provision builds the `zeon-server` image from
`/opt/zeon/server`, so it takes an extra minute; later ones are seconds.

(Just kicking the tires? You can skip systemd and run it in the foreground:)

```bash
ZEON_HOST_AGENT_ADMIN_TOKEN=<your admin token> \
ZEON_HOST_AGENT_ADVERTISE_HOST=<your-public-ip> \
  .venv/bin/python main.py            # serves pinned TLS on :8200
```

All the knobs:

| Env | Default | Meaning |
|---|---|---|
| `ZEON_HOST_AGENT_ADMIN_TOKEN` | — (required) | Secret you hold; authorizes minting/eviction |
| `ZEON_HOST_AGENT_ADVERTISE_HOST` | — (required) | Public host/IP guests connect to |
| `ZEON_HOST_AGENT_CAPACITY` | `25` | Max guest mailboxes on this host |
| `ZEON_HOST_AGENT_PORT_BASE` | `42000` | First guest mailbox port; guests get `base…base+capacity−1` |
| `ZEON_HOST_AGENT_IMAGE` | `zeon-server:dev` | Mailbox image (built from `../server` if missing) |
| `ZEON_HOST_AGENT_RUNTIME` | — | Set to `runsc` for gVisor hardening |
| `ZEON_PUSH_GATEWAY` | — | Passed through to guest mailboxes |
| `ZEON_HOST_AGENT_PORT` | `8200` | Listen port |

### 4. Connect your app

Install Zeon, **forge your identity**, then: mailbox screen → **Host friends
on my server** → enter `https://<your-ip>:8200` + your admin token. Turn on
your own mailbox there, then **Create an invite**.

### 5. Bring the friends

Send each friend the `zeon-host:…` invite string over any channel they trust
came from you — it carries no secrets, and their app pins the connection to
your agent's certificate, so it can't be intercepted. Each friend: install
the app → forge an identity → mailbox screen → **Join a friend's host** →
paste the invite. Their mailbox spins up on your box; its token stays on
their phone.

### 6. Chat

Exchange Zeon IDs or handles (QR or text) and message away. Everything is
end-to-end encrypted on the phones — your box only ever holds ciphertext,
deleted on delivery. If your box ever dies, nobody's history is lost: it
lives on their phones, and they can re-home their mailboxes anywhere.

### TL;DR

1. VM (or home box) with a **static public IP**; open inbound TCP **8200**
   and **42000–42024**.
2. `sudo apt-get install -y docker.io git python3-venv openssl` and enable Docker.
3. `sudo git clone <repo-url> /opt/zeon && cd /opt/zeon/host_agent && python3 -m venv .venv && .venv/bin/pip install -r requirements.txt`
4. `openssl rand -hex 24` → your admin token.
5. Run `main.py` with `ZEON_HOST_AGENT_ADMIN_TOKEN` and
   `ZEON_HOST_AGENT_ADVERTISE_HOST` set (systemd unit above), then
   `curl -sk https://<ip>:8200/health`.
6. In your app: forge identity → **Host friends on my server** → agent
   address + admin token → mailbox on, **Create an invite**.
7. Friends: install app → forge identity → **Join a friend's host** → paste
   the invite.
8. Swap Zeon IDs, chat.

## API

Guests never call the admin endpoints; the app does the redeem for them.

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/health` | none | Liveness + pinning: `{status, v, tls_fp}`. Guest count/capacity are admin-only (see `/v1/guests`). |
| POST | `/v1/invite` | admin | `{uses, ttl_hours}` → `{invite}` — the string you share |
| GET | `/v1/invites` | admin | every minted invite with status: `{invites: [{invite, uses, uses_left, expires_at, created_at, redeemed_by}]}` |
| POST | `/v1/redeem` | none | `{invite: <token>, owner_id}` → `{address, server_token, tls_fp}` |
| POST | `/v1/guest` | admin | `{owner_id}` — provision directly, no invite (e.g. your own mailbox) |
| GET | `/v1/guests` | admin | list current guests |
| DELETE | `/v1/guest/{owner_id}` | admin | evict — destroys that guest's container |

The `invite` string is `zeon-host:` + base64url(`{u: agent-url, f: tls-fp, t:
token}`). The guest's app pins the agent connection to `f`, so the redeem can't
be MITM'd — same trust chain as everything else in Zeon.

## Resilience

If this box dies or you stop paying, guests' mailboxes go down — but their
identity and history live on their phones, so they just re-home their mailbox
elsewhere ("Turn on my mailbox" on another provider, or another friend's host).
Evicting a guest is likewise recoverable for them. See `TODO.md` for the
planned reconciler awareness of `hosted` mailboxes.
