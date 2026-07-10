# Zeon Chat

Privacy-first messaging where **every user runs their own server**.

- No central message store. Your "relay" is a tiny VM you spin up (GCP, AWS, or
  a local Docker container for dev) whose only job is to hold **end-to-end
  encrypted envelopes** until your phone picks them up — then they're deleted.
- **Forward secrecy**: X3DH + double ratchet (Signal-style), with prekeys
  served by your own relay instead of a central server. Every message gets a
  fresh key; stealing keys today can't decrypt traffic recorded yesterday.
- **Pinned TLS, no CAs**: relays self-sign their certificates; clients pin a
  fingerprint the owner signs with their identity key and publishes in the
  directory. Trust chains to the Zeon ID, not to any authority — same as
  everything else in the protocol.
- Message history lives on your phone only. Uninstall the app and it's gone.
- No phone number, no email. Your identity is an Ed25519 keypair generated on
  device; your **Zeon ID** (`ZC-XXXX-…`) is a hash commitment to the public key.
  Share it by QR or text — it reveals nothing about you.

See [PROTOCOL.md](PROTOCOL.md) for the full wire protocol and threat notes.

## Components

| Directory | What it is |
|---|---|
| `app/` | Flutter app (iOS/Android). Keys, history, encryption — all client-side. |
| `server/` | Routing server ("relay"). Single-file FastAPI + SQLite mailbox that runs on the user's VM. Stores ciphertext only, deletes on ack. |
| `control-plane/` | Provisioner + directory. Boots/destroys relays via a pluggable provider layer and maps Zeon IDs → pubkeys + current relay address. Never sees message content. |
| `gateway/` | Push gateway. Stateless; the only holder of APNs/FCM credentials. Mailboxes ping it when the owner is offline; it sends a content-free wake-up. Sees device tokens + timing, never identities. |
| `agent/` | Host agent ("host your circle"). Runs on a user-owned VM; mints invites and provisions invited friends' mailboxes as containers on that box. The only thing with Docker access to the host. |
| `landing/` | Marketing site (Astro). Static landing + pricing pages; `cd landing && npm install && npm run dev` (Node 22+). |

## Quick start (all local, no cloud account)

Requirements: Python 3.11+, Docker, Flutter.

```bash
# 1. control plane
cd control-plane
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/uvicorn app.main:app --port 8000

# 2. app (simulator)
cd ../app
flutter run
```

In the app: **Forge identity** → open the relay screen → pick **LOCAL** →
**Ignite**. The control plane builds the relay Docker image from `server/` and
runs it as a container. Run a second simulator, forge a second identity,
exchange Zeon IDs, and chat.

Testing from a real phone: start the control plane with
`ZEON_LOCAL_HOST=<your-mac-LAN-IP>` and point the app's "control plane" field
(onboarding → advanced) at `http://<your-mac-LAN-IP>:8000`.

## Self-hosting your mailbox (free tier)

Run the relay on any box you control — the directory lists your address so
you can message everyone, and the mailbox token never leaves your phone:

```bash
docker run -d --restart unless-stopped -p 8080:8080 \
  -e ZEON_OWNER_ID=<your ZC- id> \
  -e ZEON_OWNER_TOKEN=<any long random secret you keep> \
  zeon-server   # or: python server/main.py with the same env
```

In the app: Mailbox → **I already run a mailbox** → enter
`http://<your-host>:8080` + your token → Connect. Registration only succeeds
if the mailbox at that address reports *your* Zeon ID as its owner.

## Cloud providers

The provider layer (`control-plane/app/providers/`) is deliberately thin:
every provider boots the **same** startup script that embeds `server/main.py`,
so an adapter is only "create VM, pass script, return IP".

| Provider | Setup |
|---|---|
| `gcp` | `pip install google-cloud-compute`, set `ZEON_GCP_PROJECT`, auth via ADC (`gcloud auth application-default login`). `region` = zone, e.g. `us-central1-a`; `machine_type` e.g. `e2-micro` (free tier). |
| `aws` | `pip install boto3`, standard AWS credential chain. `region` e.g. `us-east-1`; `machine_type` e.g. `t3.micro`. |
| `local` | Docker only. For development. |
| `fleet` | Container-per-user across a pool of shared Docker hosts (`ZEON_FLEET_HOSTS="name=ssh://user@addr\|advertise_host,…"` — required; hosts prepared with `deploy/fleet-host.sh`), with cgroup/pids limits and optional gVisor via `ZEON_FLEET_RUNTIME=runsc`. Mailboxes never share the control-plane machine. The Private-plan workhorse — see BUSINESS.md. |

Adding one: subclass `CloudProvider` (two methods: `provision`, `destroy`) and
register it in `providers/__init__.py`.

## Testing

```bash
# end-to-end: register → provision (docker) → handshake → message → ack → destroy
# (ZEON_FLEET_HOSTS opts the fleet provider into the local daemon — laptop only)
cd control-plane && .venv/bin/pip install pynacl websockets
ZEON_FLEET_HOSTS="local=|127.0.0.1" .venv/bin/uvicorn app.main:app --port 8477 &
.venv/bin/python ../scripts/e2e.py

# app unit tests + static analysis
cd app && flutter test && flutter analyze
```

## Honest limitations (v1)

- **The control plane is a centralized directory.** It stores routing metadata
  (ID → pubkey → relay IP), never content. Self-hosted relays reduce its
  knowledge further (it never sees their tokens); running your own control
  plane is possible but puts you on a separate directory island.
- **Push needs credentials to go live.** The full path is wired end to end —
  app fetches a device token → registers it with its own mailbox → mailbox
  pings the gateway → content-free wake-up. It stays dormant until you supply
  APNs/FCM credentials and a Firebase config in the build (see
  `deploy/README.md` "Enable push"); without them the app falls back to
  live-socket / on-resume delivery.
- **Metadata: the destination IP is unavoidable.** Transport is pinned TLS
  (relays self-sign; clients pin an owner-signed fingerprint through the
  directory — no CAs), so on-path observers no longer read envelope metadata
  or the owner token. But one mailbox = one user, so *which IP you connect to*
  still reveals *that* you contacted that person. Inherent to per-user servers;
  hiding it (padding, onion routing) is a separate, larger project.
- **The ratchet is young.** The protocol implements X3DH + double ratchet to
  spec (see PROTOCOL.md "Session crypto"), but it has not had an external
  cryptographic review yet — get one before charging money for privacy.
- **Groups are minimal**: client-side fan-out, creator-as-admin, ~25 members,
  text-only (media in groups is planned — see PROTOCOL.md).
