# Stonechat

Privacy-first messaging where **every user runs their own relay**.

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

See [PROTOCOL.md](PROTOCOL.md) for the full wire protocol and threat notes.

## Components

| Directory       | What it is                                                                                                                                                                                     |
| --------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `app/`          | Flutter app (iOS/Android). Keys, history, encryption — all client-side.                                                                                                                        |
| `relay/`        | The mailbox program ("relay" = the software, "mailbox" = one running instance). Rust + SQLite; a static binary that runs on the user's VM. Stores ciphertext only, deletes on ack.             |
| `hub/`          | Provisioner + directory. Boots/destroys relays via a pluggable provider layer and maps Stonechat IDs → pubkeys + current relay address. Never sees message content.                            |
| `push_gateway/` | Push gateway. Stateless; the only holder of APNs/FCM credentials. Mailboxes ping it when the owner is offline; it sends a content-free wake-up. Sees device tokens + timing, never identities. |
| `machine_host/` | Machine host ("host your circle"). Runs on a user-owned VM; mints invites and provisions invited friends' mailboxes as containers on that box. The only thing with Docker access to the host.  |
| `agent_client/` | Agent client. A headless **device** on a user's identity — links like a phone or a browser tab, holds no identity secret, runs unattended on a server. Rust, links `core` directly.            |

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
  stonechat-relay    # image built from relay/ (see relay/README.md)
```

In the app: Mailbox → **I already run a mailbox** → enter
`http://<your-host>:8080` + your token → Connect. Registration only succeeds
if the mailbox at that address reports _your_ Stonechat ID as its owner.

### Host your circle (one box, invited friends)

Want to self-host for yourself **and a few friends** without each of them
running a machine? Run the **machine host** (`machine_host/`) on one box you own.
It hosts your mailbox plus a container-per-friend — each with its own port,
token, TLS cert, and resource caps — and it's the only thing on the box with
Docker access; the hub never touches this machine.

```bash
cd machine_host
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt

STONECHAT_MACHINE_HOST_ADMIN_TOKEN=$(openssl rand -hex 24) \
STONECHAT_MACHINE_HOST_ADVERTISE_HOST=<your-public-ip> \
  .venv/bin/python main.py            # pinned TLS on :8200
```

Open ports **8200** (the machine host) and **42000–42024** (guest mailboxes) in your
firewall or home router. In the app: Mailbox → **Host friends on your machine** →
enter its address + admin token → **Create an invite** → share the
`stonechat-host:…` string. Friends install the app, forge an identity, and paste it
under **Join a friend's host** — their mailbox appears in the directory as an
ordinary self-hosted relay, and its token stays on their phone. Exchange Stonechat
IDs and chat.

Message content stays end-to-end encrypted — unreadable even to the
host-owner — but the host-owner can see that a friend hosts there and their
traffic metadata, like any relay operator. Details, API, and the full trust
model: [machine_host/README.md](machine_host/README.md).

### Running your own hub (a private network)

The two options above keep you on the main directory, so you can still message
everyone. If instead you want a network that depends on nobody — a company, a
family, an experiment — you can run the hub itself:
`notes/docs/SELF_HOSTED_HUB.md` (internal).

Know the trade before you start: **there is no federation.** Hubs never talk to
each other — no server-to-server protocol, no shared namespace, no replicated
state — so people on your hub can message each other and nobody else.
Self-host your _mailbox_ if what you want is your own infrastructure without
giving up the network.

## Cloud providers

The provider layer (`hub/app/providers/`) is deliberately thin:
every provider boots the **same** startup script, a small fetch-stub that
downloads the static relay binary (`relay/`) and verifies its pinned
SHA-256, so an adapter is only "create VM, pass script, return IP".

| Provider | Setup                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `gcp`    | `pip install google-cloud-compute`, set `STONECHAT_GCP_PROJECT`, auth via ADC (`gcloud auth application-default login`). `region` = zone, e.g. `us-central1-a`; `machine_type` e.g. `e2-micro` (free tier).                                                                                                                                                                                                                                          |
| `aws`    | `pip install boto3`, standard AWS credential chain. `region` e.g. `us-east-1`; `machine_type` e.g. `t3.micro`.                                                                                                                                                                                                                                                                                                                                       |
| `local`  | Docker only. For development.                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `fleet`  | Container-per-user across a pool of shared Docker hosts (`STONECHAT_FLEET_HOSTS="name=ssh://user@addr\|advertise_host\|COUNTRY,…"` — required; the country is where that host places and what the picker offers; hosts prepared with `deploy/fleet-host.sh`), with cgroup/pids limits and optional gVisor via `STONECHAT_FLEET_RUNTIME=runsc`. Mailboxes never share the hub machine. The Mailbox-plan workhorse — see notes/BUSINESS.md (internal). |

Adding one: subclass `CloudProvider` (two methods: `provision`, `destroy`) and
register it in `providers/__init__.py`.

## Testing

```bash
# once: build the stonechat-core library the app and protocol clients load
# (session engine + ML-KEM/X-Wing KEMs; needs a Rust toolchain)
./scripts/build_core.sh host

# end-to-end: register → provision (docker) → handshake → message → ack → destroy
# (STONECHAT_FLEET_HOSTS opts the fleet provider into the local daemon — laptop only;
#  STONECHAT_ADMIN_TOKEN lets the test mint the comp entitlement the fleet gate needs)
cd hub && .venv/bin/pip install pynacl websockets
#  STONECHAT_REGISTER_LIMIT and STONECHAT_REPORT_LIMIT lift the per-IP signup
#  and abuse-report walls, which a full run exceeds and a rerun exceeds again)
STONECHAT_FLEET_HOSTS="local=|127.0.0.1|DE" STONECHAT_ADMIN_TOKEN=test-admin STONECHAT_TEST_CODE=STONECHAT-TEST-TEST STONECHAT_REGISTER_LIMIT=1000 STONECHAT_REPORT_LIMIT=1000 .venv/bin/uvicorn app.main:app --port 8477 &
.venv/bin/python ../scripts/e2e.py

# multi-device end to end — no Docker: it runs relays directly and lists them
# via the hub's external-mailbox path. Link grant, per-device prekeys and
# queues, fan-out, revocation.
#   (the venv's console scripts have stale shebangs — use `python -m`)
cd hub && .venv/bin/python -m uvicorn app.main:app --port 8477 &
hub/.venv/bin/python scripts/e2e_multidevice.py

# app unit tests + static analysis (pqcore lib enables the FFI vector tests)
cd app && STONECHAT_CORE_LIB=$PWD/../core/target/release/libstonechat_core.dylib flutter test && flutter analyze

# fan-out latency: serial vs bounded-concurrent group sends, against a real
# relay over TLS with an in-process delay proxy so handshakes pay real round
# trips. Answers "how big can a group get" with numbers instead of arithmetic.
# Start a relay first (see the conformance instructions in relay/README.md).
python3 scripts/bench_fanout.py 127.0.0.1 <relay_port>
python3 scripts/bench_devices.py 127.0.0.1 <relay_port>   # multi-device: does
                                                          # connection reuse pay?
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
  or the owner token. But one mailbox = one user, so _which IP you connect to_
  still reveals _that_ you contacted that person. Inherent to per-user mailboxes;
  hiding it (padding, onion routing) is a separate, larger project.
- **The ratchet is young.** The protocol implements PQXDH + double ratchet to
  spec (see [PROTOCOL.md](PROTOCOL.md) "Session crypto"), but it has not had an external
  cryptographic review yet — get one before charging money for privacy.
- **Groups are minimal**: client-side fan-out, creator-as-admin, ~25 members,
  text-only (media in groups is planned — see [PROTOCOL.md](PROTOCOL.md)).

---

## License

**Stonechat is licensed under the GNU Affero General Public License v3.0**
([LICENSE](LICENSE)) — all of it: the clients, the protocol core, the relay,
the hub, the push gateway.

AGPL §13 is the part that matters: anyone who runs a modified version as a
network service must offer its users the source of their modifications. You
may compete with Stonechat and you may charge for it; you may not do it with a
secret fork, and you may not sell a closed-source Stonechat to companies. Same
license as Signal and SimpleX, for the same reason — a messenger that asks for
your trust has no business being unreadable.

Two carve-outs: **[PROTOCOL.md](PROTOCOL.md) is CC-BY-4.0**, because
independent implementations reach the same directory and the same users; and
the **name, logo and bird mark are trademarks of GazelleLabs LLC**, not
covered by the AGPL. Say your project is based on or compatible with
Stonechat; don't name it Stonechat, and use your own icon.

Full detail, including what the AGPL asks of you if you self-host or fork:
**[LICENSING.md](LICENSING.md)**.

## Contributing

Contributions are welcome to the server and the clients alike. Sign your
commits off (`git commit -s`) to certify you have the right to submit the
code; you keep your copyright. Read [CONTRIBUTING.md](CONTRIBUTING.md) first,
especially the invariants: breaking one is expensive and quiet.

Security issues go to security@stonechat.app, not the issue tracker. See
[SECURITY.md](SECURITY.md).
