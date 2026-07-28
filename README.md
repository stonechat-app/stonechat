# Stonechat

Privacy-first messaging where **every user runs their own server**.

- No central message store. Your "relay" is a tiny VM you spin up (GCP, AWS, or
  a local Docker container for dev) whose only job is to hold **end-to-end
  encrypted envelopes** until your phone picks them up — then they're deleted.
- **Forward secrecy, post-quantum hybrid**: PQXDH (X3DH + ML-KEM-768) +
  double ratchet (Signal-style), with prekeys served by your own relay
  instead of a central server. Every message gets a fresh key; stealing keys
  today can't decrypt traffic recorded yesterday, and recording traffic
  today doesn't let a future quantum computer decrypt it
  (notes/docs/POST_QUANTUM.md, internal).
- **Pinned TLS, no CAs**: relays self-sign their certificates; clients pin a
  fingerprint the owner signs with their identity key and publishes in the
  directory. Trust chains to the Stonechat ID, not to any authority — same as
  everything else in the protocol.
- Message history lives on your phone only. Uninstall the app and it's gone.
- No phone number, no email. Your identity is an Ed25519 keypair generated on
  device; your **Stonechat ID** (`SC-XXXX-…`) is a hash commitment to the public key.
  Share it by QR or text — it reveals nothing about you.

See PROTOCOL.md (notes/docs/PROTOCOL.md, internal) for the full wire protocol and threat notes.

## Components

| Directory | What it is |
|---|---|
| `app/` | Flutter app (iOS/Android). Keys, history, encryption — all client-side. |
| `relay/` | Routing server ("relay", "mailbox"). Rust + SQLite; a static binary that runs on the user's VM. Stores ciphertext only, deletes on ack. |
| `hub/` | Provisioner + directory. Boots/destroys relays via a pluggable provider layer and maps Stonechat IDs → pubkeys + current relay address. Never sees message content. |
| `gateway/` | Push gateway. Stateless; the only holder of APNs/FCM credentials. Mailboxes ping it when the owner is offline; it sends a content-free wake-up. Sees device tokens + timing, never identities. |
|  `host_agent/` | Host agent ("host your circle"). Runs on a user-owned VM; mints invites and provisions invited friends' mailboxes as containers on that box. The only thing with Docker access to the host. |

Marketing site lives in its own private repo: `stonechat-app/landing`.

## Quick start (all local, no cloud account)

Requirements: Python 3.11+, Docker, Flutter.

```bash
# 1. hub
cd hub
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/uvicorn app.main:app --port 8000

# 2. app (simulator)
cd ../app
flutter run
```

In the app: **Forge identity** → open the relay screen → pick **LOCAL** →
**Ignite**. The hub builds the relay Docker image from `relay/` and
runs it as a container. Run a second simulator, forge a second identity,
exchange Stonechat IDs, and chat.

Testing from a real phone: start the hub with
`STONECHAT_LOCAL_HOST=<your-mac-LAN-IP>` and point the app's "hub" field
(onboarding → advanced) at `http://<your-mac-LAN-IP>:8000`.

## Self-hosting your mailbox (free tier)

Run the relay on any box you control — the directory lists your address so
you can message everyone, and the mailbox token never leaves your phone:

```bash
docker run -d --restart unless-stopped -p 8080:8080 \
  -e STONECHAT_OWNER_ID=<your SC- id> \
  -e STONECHAT_OWNER_TOKEN=<any long random secret you keep> \
  stonechat-server   # image built from relay/ (see relay/README.md)
```

In the app: Mailbox → **I already run a mailbox** → enter
`http://<your-host>:8080` + your token → Connect. Registration only succeeds
if the mailbox at that address reports *your* Stonechat ID as its owner.

### Host your circle (one box, invited friends)

Want to self-host for yourself **and a few friends** without each of them
running a server? Run the **host agent** (`host_agent/`) on one box you own.
It hosts your mailbox plus a container-per-friend — each with its own port,
token, TLS cert, and resource caps — and it's the only thing on the box with
Docker access; the hub never touches this machine.

```bash
cd host_agent
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt

STONECHAT_HOST_AGENT_ADMIN_TOKEN=$(openssl rand -hex 24) \
STONECHAT_HOST_AGENT_ADVERTISE_HOST=<your-public-ip> \
  .venv/bin/python main.py            # pinned TLS on :8200
```

Open ports **8200** (the agent) and **42000–42024** (guest mailboxes) in your
firewall or home router. In the app: Mailbox → **Host friends on my server** →
enter the agent's address + admin token → **Create an invite** → share the
`stonechat-host:…` string. Friends install the app, forge an identity, and paste it
under **Join a friend's host** — their mailbox appears in the directory as an
ordinary self-hosted relay, and its token stays on their phone. Exchange Stonechat
IDs and chat.

Message content stays end-to-end encrypted — unreadable even to the
host-owner — but the host-owner can see that a friend hosts there and their
traffic metadata, like any relay operator. Details, API, and the full trust
model: [host_agent/README.md](host_agent/README.md).

### Running your own hub (a private network)

The two options above keep you on the main directory, so you can still message
everyone. If instead you want a network that depends on nobody — a company, a
family, an experiment — you can run the hub itself:
`notes/docs/SELF_HOSTED_HUB.md` (internal).

Know the trade before you start: **there is no federation.** Hubs never talk to
each other — no server-to-server protocol, no shared namespace, no replicated
state — so people on your hub can message each other and nobody else.
Self-host your *mailbox* if what you want is your own infrastructure without
giving up the network.

## Cloud providers

The provider layer (`hub/app/providers/`) is deliberately thin:
every provider boots the **same** startup script, a small fetch-stub that
downloads the static relay binary (`relay/`) and verifies its pinned
SHA-256, so an adapter is only "create VM, pass script, return IP".

| Provider | Setup |
|---|---|
| `gcp` | `pip install google-cloud-compute`, set `STONECHAT_GCP_PROJECT`, auth via ADC (`gcloud auth application-default login`). `region` = zone, e.g. `us-central1-a`; `machine_type` e.g. `e2-micro` (free tier). |
| `aws` | `pip install boto3`, standard AWS credential chain. `region` e.g. `us-east-1`; `machine_type` e.g. `t3.micro`. |
| `local` | Docker only. For development. |
| `fleet` | Container-per-user across a pool of shared Docker hosts (`STONECHAT_FLEET_HOSTS="name=ssh://user@addr\|advertise_host,…"` — required; hosts prepared with `deploy/fleet-host.sh`), with cgroup/pids limits and optional gVisor via `STONECHAT_FLEET_RUNTIME=runsc`. Mailboxes never share the hub machine. The Private-plan workhorse — see notes/BUSINESS.md (internal). |

Adding one: subclass `CloudProvider` (two methods: `provision`, `destroy`) and
register it in `providers/__init__.py`.

## Testing

```bash
# once: build the pqcore KEM library the protocol clients load
# (ML-KEM/X-Wing — notes/docs/POST_QUANTUM.md; needs a Rust toolchain)
./scripts/build_pqcore.sh host

# end-to-end: register → provision (docker) → handshake → message → ack → destroy
# (STONECHAT_FLEET_HOSTS opts the fleet provider into the local daemon — laptop only;
#  STONECHAT_ADMIN_TOKEN lets the test mint the comp entitlement the fleet gate needs)
cd hub && .venv/bin/pip install pynacl websockets
STONECHAT_FLEET_HOSTS="local=|127.0.0.1" STONECHAT_ADMIN_TOKEN=test-admin STONECHAT_TEST_CODE=STONECHAT-TEST-TEST .venv/bin/uvicorn app.main:app --port 8477 &
.venv/bin/python ../scripts/e2e.py

# app unit tests + static analysis (pqcore lib enables the FFI vector tests)
cd app && STONECHAT_PQCORE_LIB=$PWD/../pqcore/target/release/libpqcore.dylib flutter test && flutter analyze
```

## Honest limitations (v1)

- **The hub is a centralized directory.** It stores routing metadata
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
- **The ratchet is young.** The protocol implements PQXDH + double ratchet to
  spec (see notes/docs/PROTOCOL.md "Session crypto"), but it has not had an external
  cryptographic review yet — get one before charging money for privacy.
- **Groups are minimal**: client-side fan-out, creator-as-admin, ~25 members,
  text-only (media in groups is planned — see notes/docs/PROTOCOL.md).
