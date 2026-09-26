# Stonechat

Privacy-first messaging where **every user runs their own relay**.

- No central message store. Your "relay" is a mailbox of your own — a container
  on a box that hosts a handful of people, a whole VM if you want one, or
  something you run yourself at home — whose only job is to hold **end-to-end
  encrypted envelopes** until your phone picks them up, then delete them.
- No phone number, no email. Your identity is an Ed25519 keypair generated on
  device; your **Stonechat ID** (`SC-XXXX-…`) is a hash commitment to the public key.
  Share it by QR or text — it reveals nothing about you.
- **Forward secrecy, post-quantum hybrid**: PQXDH (X3DH + ML-KEM-768) +
  double ratchet (Signal-style), with prekeys served by your own relay
  instead of a central server. Every message gets a fresh key; stealing keys
  today can't decrypt traffic recorded yesterday, and recording traffic
  today doesn't let a future quantum computer decrypt it
  (docs/POST_QUANTUM.md).
- **Pinned TLS, no CAs**: relays self-sign their certificates; clients pin a
  fingerprint the owner signs with their identity key and publishes in the
  directory. Trust chains to the Stonechat ID, not to any authority — same as
  everything else in the protocol.
- Message history lives on your phone only. Uninstall the app and it's gone. Well you can do an encrypted backup if you want, but you need to take care of that backup.

See [PROTOCOL.md](PROTOCOL.md) for the full wire protocol and threat notes.

## Components

| Directory       | What it is                                                                                                                                                                                                                                                                                                                   |
| --------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `app/`          | Flutter app (iOS/Android). Keys, history, encryption — all client-side.                                                                                                                                                                                                                                                      |
| `relay/`        | The mailbox. Rust + SQLite; a static binary that runs on the user's VM. Stores ciphertext only, deletes on ack.                                                                                                                                                                                                              |
| `hub/`          | Provisioner + directory. Boots/destroys relays via a pluggable provider layer and maps Stonechat IDs → pubkeys + current relay address. Never sees message content.                                                                                                                                                          |
| `push_gateway/` | Push gateway for mobile push notifications. Stateless. The only holder of APNs/FCM credentials. Mailboxes ping it when the owner is offline; it sends a content-free wake-up. Sees device tokens + timing, never identities.                                                                                                 |
| `machine_host/` | Machine host, hosts multiple mailboxes. Runs on a user-owned VM; mints invites and provisions invited friends' mailboxes as containers on that box. If you want to host mailboxes, for friends or family, in your own machine, you should use this. Still connects to the main Stonechat directory (where all the users are) |
| `agent_client/` | Agent client. A headless **device** on a user's identity — links like a phone or a browser tab, holds no identity secret, runs unattended on a server.                                                                                                                                                                       |

## Quick start (all local, no cloud account)

Requirements: Python 3.11+, Docker, Flutter.

```bash
# 1. hub
cd hub
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
# `python -m`, not .venv/bin/uvicorn — the venv's console scripts carry stale
# shebangs from wherever it was first created.
.venv/bin/python -m uvicorn app.main:app --port 8000

# 2. app (simulator)
cd ../app
flutter run
```

In the app: **Forge identity** → **Mailbox** → **Ignite**. A debug build
provisions to "This computer" on its own, so there is nothing to choose: the hub
builds the relay image from `relay/` and runs it as a local container. Run a second simulator, forge a second identity,
exchange Stonechat IDs, and chat.

Testing from a real phone: start the hub with
`STONECHAT_LOCAL_HOST=<your-mac-LAN-IP>` and point the app's "hub" field
(onboarding → advanced) at `http://<your-mac-LAN-IP>:8000`.

## Self-hosting your mailbox (free tier)

Run the relay on any box with a public address — the directory lists it so
you can message everyone, and the mailbox token never leaves your phone:

```bash
docker run -d --name stonechat-mailbox --restart unless-stopped \
  -p 8080:8080 -p 8443:8443/udp \
  -v stonechat-mailbox:/data \
  -e STONECHAT_OWNER_ID=<your SC- id> \
  -e STONECHAT_OWNER_TOKEN=<a long random secret: openssl rand -hex 32> \
  -e STONECHAT_WT_ADVERTISE=<this box's public IP or hostname> \
  ghcr.io/stonechat-app/relay:latest
```

- **The image** is published with every relay release (`relay/README.md`
  "Releases") and pulls with no credentials. It is **amd64 only** for now — the
  arm64 leg needs GitHub's arm64 runners, which are free only for public
  repositories, so on arm64 you build it yourself for the moment. Pin a version
  such as `:0.1` instead of `latest` if you would rather upgrade on purpose. To upgrade, `docker pull`
  the image and recreate the container; the volume keeps your mail and
  certificate. Prefer building it yourself? `docker build -t stonechat-relay relay/`
  and run `stonechat-relay` instead.

- **Keep the `/data` volume.** It holds your undelivered mail and the TLS key
  your contacts pin. Without it, recreating the container empties the mailbox
  and changes its certificate.
- **Open TCP 8080 and UDP 8443** in your cloud firewall as well. 8080 is for
  phones. 8443 is the browser transport, which the app registers as
  `<host>:8443`, so publish it on that same port.
  `STONECHAT_WT_ADVERTISE` must name the address browsers dial: the
  certificates they pin are issued for it.
- **No proxy in front.** The relay terminates TLS itself with a self-signed
  certificate. No domain or CA is needed, and a TLS-terminating proxy would
  present a different certificate than the one your contacts pin.

In the app: Mailbox → **Self-host** → enter `https://<your-host>:8080` and
your token → **Connect my mailbox**. The app checks the token against the
relay first, and registration only succeeds if the mailbox reports _your_
Stonechat ID as its owner and the hub can reach it from the internet.

### Host your circle (one box, invited friends)

Want to self-host for yourself **and a few friends** without each of them
running a machine? Run the **machine host** (`machine_host/`) on one box you own.
It hosts your mailbox plus a container-per-friend — each with its own port,
token, TLS cert, and resource caps — and it's the only thing on the box with
Docker access; the hub never touches this machine.

```bash
cd machine_host
cp .env.example .env      # admin token (openssl rand -hex 24) + your public IP
docker compose up -d --build        # pinned TLS on :8200
```

Nothing is compiled: guest mailboxes run the published relay image, pulled on
first use. Open port **8200** (the machine host) and **42000–42024 TCP *and UDP*** (guest
mailboxes — each uses the same number for both, the UDP half being the browser
transport) in your firewall or home router. Create your own mailbox on it
(`POST /v1/guest`, see the machine host README) and connect it in the app under
Mailbox → **Self-host**; then **Invites** → its address + admin token →
**New invite** → share the `stonechat-host:…` string. Friends install the app,
forge an identity, and paste it under **A friend's machine** → **Join with
invite** — their mailbox appears in the directory as an ordinary self-hosted
relay, and its token stays on their phone. Exchange Stonechat IDs and chat.

Message content stays end-to-end encrypted — unreadable even to the
host-owner — but the host-owner can see that a friend hosts there and their
traffic metadata, like any relay operator. Details, API, and the full trust
model: [machine_host/README.md](machine_host/README.md).

### Running your own hub (a private network)

The two options above keep you on the main directory, so you can still message
everyone. If instead you want a network that depends on nobody — a company, a
family, an experiment — you can run the hub itself. It is one container and one
SQLite file: `hub/docker-compose.yml` plus the walkthrough in
[deploy/README.md](deploy/README.md), which covers the hub, the machine hosts it
places mailboxes on, and the firewall rules both need.

Know the trade before you start: **there is no federation.** Hubs never talk to
each other — no server-to-server protocol, no shared namespace, no replicated
state — so people on your hub can message each other and nobody else.
Self-host your _mailbox_ if what you want is your own infrastructure without
giving up the network.

## Cloud providers

The provider layer (`hub/app/providers/`) is deliberately thin: every *VM*
provider boots the **same** startup script, a small fetch-stub that downloads the
static relay binary (`relay/`) and verifies its pinned SHA-256, so an adapter is
only "create VM, pass script, return IP". `machine_host` is the exception and
boots nothing — the box is already running, so the hub asks the machine host
there for a container.

| Provider       | Setup                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| -------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `gcp`          | `pip install google-cloud-compute`, set `STONECHAT_GCP_PROJECT`, auth via ADC (`gcloud auth application-default login`). `region` = zone, e.g. `us-central1-a`; `machine_type` e.g. `e2-micro` (free tier).                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| `aws`          | `pip install boto3`, standard AWS credential chain. `region` e.g. `us-east-1`; `machine_type` e.g. `t3.micro`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `hetzner` / `vultr` / `digitalocean` | One VM per user, enabled by setting that provider's API token. The adapters exist and are checked against a stubbed transport (`hub/scripts/check_providers.py`); only `gcp` has been provisioned against for real. |
| `local`        | Docker only. For development.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `machine_host` | Container-per-user across a pool of boxes that each run `machine_host/main.py` in managed mode, placed over its HTTPS API (`STONECHAT_MACHINE_HOSTS="name=https://host:8200\|COUNTRY\|admin_token\|tls_fp,…"` — required; the country is where that host places and what the picker offers; `tls_fp` pins the host's self-signed certificate, the literal `insecure` skips the pin and is laptop dev only; hosts set up per `machine_host/README.md`), with cgroup/pids limits and optional gVisor via `STONECHAT_MACHINE_HOST_RUNTIME=runsc` on the host. Mailboxes never share the hub machine. This is the workhorse: it is what the hosted service runs. |

Adding one: subclass `CloudProvider` (two methods: `provision`, `destroy`) and
register it in `providers/__init__.py`.

## Testing

```bash
# once: build the stonechat-core library the app and protocol clients load
# (session engine + ML-KEM/X-Wing KEMs; needs a Rust toolchain)
./scripts/build_core.sh host

# end-to-end: register → provision (docker) → handshake → message → ack → destroy
# (STONECHAT_MACHINE_HOSTS points the hub at the machine host e2e.py starts itself;
#  `insecure` skips the certificate pin — laptop only. STONECHAT_ADMIN_TOKEN lets
#  the test mint the comp entitlement the shared tier needs)
cd hub && .venv/bin/pip install pynacl websockets
#  STONECHAT_REGISTER_LIMIT and STONECHAT_REPORT_LIMIT lift the per-IP signup
#  and abuse-report walls, which a full run exceeds and a rerun exceeds again)
STONECHAT_MACHINE_HOSTS="local=https://127.0.0.1:8201|DE|e2e-machine-host-admin|insecure" STONECHAT_ADMIN_TOKEN=test-admin STONECHAT_TEST_CODE=STONECHAT-TEST-TEST STONECHAT_REGISTER_LIMIT=1000 STONECHAT_REPORT_LIMIT=1000 .venv/bin/python -m uvicorn app.main:app --port 8477 &
.venv/bin/python ../scripts/e2e.py

# multi-device end to end — no Docker: it runs relays directly and lists them
# via the hub's external-mailbox path. Link grant, per-device prekeys and
# queues, fan-out, revocation.
#   (the venv's console scripts have stale shebangs — use `python -m`)
cd hub && .venv/bin/python -m uvicorn app.main:app --port 8477 &
.venv/bin/python ../scripts/e2e_multidevice.py

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
