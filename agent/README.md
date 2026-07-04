# Zeon host agent — "host your circle"

Run this on a VM **you own** to host your own mailbox *plus* invited friends'
mailboxes on the same box. A shared host, but only with people you choose.

Each guest gets their own `zeon-server` container — own port, own token, own
TLS cert, cgroup/pids caps. From the directory's point of view a guest's mailbox
is just an ordinary self-hosted ("external") relay that happens to live on your
box. The control plane and Zeon-the-company never touch this machine; the agent
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

## Run it

Requirements: Docker, `openssl`, Python 3.11+. The `zeon-server:dev` image must
be buildable (the agent builds it from `../server` on first use) or already
present.

```bash
cd agent
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt

ZEON_AGENT_ADMIN_TOKEN=$(openssl rand -hex 24) \
ZEON_AGENT_ADVERTISE_HOST=<your-public-ip> \
  .venv/bin/python main.py            # serves pinned TLS on :8200
```

Keep the admin token — you need it to mint invites. Open port **8200** (and the
mailbox container range, same as the relays) in your firewall so friends can
reach the agent and their mailboxes.

| Env | Default | Meaning |
|---|---|---|
| `ZEON_AGENT_ADMIN_TOKEN` | — (required) | Secret you hold; authorizes minting/eviction |
| `ZEON_AGENT_ADVERTISE_HOST` | — (required) | Public host/IP guests connect to |
| `ZEON_AGENT_CAPACITY` | `25` | Max guest mailboxes on this host |
| `ZEON_AGENT_RUNTIME` | — | Set to `runsc` for gVisor hardening |
| `ZEON_PUSH_GATEWAY` | — | Passed through to guest mailboxes |
| `ZEON_AGENT_PORT` | `8200` | Listen port |

## API

Guests never call the admin endpoints; the app does the redeem for them.

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/health` | none | `{guests, capacity, tls_fp}` |
| POST | `/v1/invite` | admin | `{uses, ttl_hours}` → `{invite}` — the string you share |
| POST | `/v1/redeem` | none | `{invite: <token>, owner_id}` → `{address, server_token, tls_fp}` |
| POST | `/v1/guest` | admin | `{owner_id}` — provision directly, no invite (e.g. your own mailbox) |
| GET | `/v1/guests` | admin | list current guests |
| DELETE | `/v1/guest/{owner_id}` | admin | evict — destroys that guest's container |

The `invite` string is `zeon-host:` + base64url(`{u: agent-url, f: tls-fp, t:
token}`). The guest's app pins the agent connection to `f`, so the redeem can't
be MITM'd — same trust chain as everything else in Zeon.

## In the app

- **Guest**: mailbox screen → "Join a friend's host" → paste the invite. Their
  mailbox is created here and registered like a self-hosted relay (token stays
  on their phone).
- **Host-owner**: mailbox screen → "Host friends on my server" → enter this
  agent's address + admin token → "Create an invite" → share the string.

## Resilience

If this box dies or you stop paying, guests' mailboxes go down — but their
identity and history live on their phones, so they just re-home their mailbox
elsewhere ("Turn on my mailbox" on another provider, or another friend's host).
Evicting a guest is likewise recoverable for them. See `TODO.md` for the
planned reconciler awareness of `hosted` mailboxes.
