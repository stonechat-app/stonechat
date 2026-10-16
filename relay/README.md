# stonechat-relay — the mailbox program

The per-user mailbox: holds end-to-end encrypted envelopes until the owner's
devices collect them, then deletes them. It links no protocol code; prekeys and
certificates are opaque strings to it.

- Wire contract: [PROTOCOL.md](../PROTOCOL.md) "Mailbox API".
- Behavioral contract: the golden corpus in `tests/`, not the code.
- One process per user, so idle memory is the unit cost: about 10 MB idle.
- No schema migrations before launch: an older volume is wiped, not upgraded
  (`src/db.rs`).

## Run

```bash
cargo build --release
STONECHAT_OWNER_ID=SC-… STONECHAT_OWNER_TOKEN=secret ./target/release/stonechat-relay
```

| Variable | Default | |
|---|---|---|
| `STONECHAT_OWNER_ID` | required | The one identity this mailbox serves |
| `STONECHAT_OWNER_TOKEN` | required | Device 1's token |
| `STONECHAT_PORT` | `8080` | TLS listener (HTTP + `/ws`) |
| `STONECHAT_WT_PORT` | `8443` | Browser transport, UDP; `0` disables |
| `STONECHAT_WT_ADVERTISE` | | Hosts/IPs clients dial, comma-separated; see below |
| `STONECHAT_TURN_PORT` | `3478` | Call relay, UDP, plus the next port; `0` disables |
| `STONECHAT_DB` | `mailbox.db` | |
| `STONECHAT_BLOBS` | `blobs` | |
| `STONECHAT_TLS_DIR` | the DB's directory | TLS key, WebTransport schedule, TURN secret |
| `STONECHAT_PUSH_GATEWAY`, `STONECHAT_PUSH_KEY` | | Push gateway URL and credential |
| `STONECHAT_MAX_QUEUE_BYTES` | 64 MiB | Per device |
| `STONECHAT_LIMIT_INBOX`, `_BLOB`, `_BUNDLE` | see below | Rate limits |

Docker: `docker build -t stonechat-relay .` compiles it; releases ship a
prebuilt image (see "Releases").

## Who may manage the mailbox

A device token covers that device's own things. Only device 1, the primary
(`STONECHAT_OWNER_TOKEN`), manages the mailbox.

| | primary (device 1) | linked device | no valid token |
|---|---|---|---|
| `GET /status`, `POST /prekeys`, `POST /push-config`, `GET /ws` | own | own | 401 (`/ws`: 403 handshake) |
| `GET /devices`, `GET /turn-credentials` | yes | yes | 401 |
| `POST /devices` | yes | **403** | 401 |
| `DELETE /devices/{id}`, a linked device | yes | itself only, else **403** | 401 |
| `DELETE /devices/1` | **403** | **403** | 401 |
| `GET /blob/{id}` | yes | yes | that blob's fetch token, else 401 |
| `DELETE /blob/{id}` | yes | unless a sibling still has it queued (**403**) | 401 |
| `GET /prekeys/devices`, `GET /prekeys/bundle?device=` | yes | yes | the bundle token, else 401 |
| `POST /inbox`, `POST /blob`, `GET /prekeys/bundle`, `GET /health`, `GET /owner`, `GET /wt/certs` | open | open | open |

Nobody can revoke the primary, so the owner can't lock themselves out. A linked
device can't add devices or revoke siblings, so one stolen laptop can't evict
the others.

## What a stranger can cost

`/inbox`, `/blob` and `/prekeys/bundle` take no token, by design. What they
can make the relay hold is bounded:

- A device drains its queue in pages of 16 envelopes (1 MiB at most), never
  whole.
- New deposits wake the connection, which reads them from SQLite. Only
  transient envelopes travel in memory, through a 32-frame (2 MiB) channel;
  when it is full they are dropped and the sender gets `dropped`.
- A peer whose writes stall for 30 s is disconnected.
- Each device's queue is capped at 10,000 envelopes and
  `STONECHAT_MAX_QUEUE_BYTES`; either answers `503 mailbox full`.
- A duplicate envelope id gets `{"status": "queued"}` and nothing else.
- Push pings are debounced: 5 s, or 2 s for `ring: true`.

Rates are limited per source address and in total, answering `429` with
`Retry-After: 1`:

| Variable | Default | Meters |
|---|---|---|
| `STONECHAT_LIMIT_INBOX` | `20/200,100/1000` | `POST /inbox` |
| `STONECHAT_LIMIT_BLOB` | `1/60,4/240` | `POST /blob` |
| `STONECHAT_LIMIT_BUNDLE` | `0.5/30,5/300` | `GET /prekeys/bundle` |

Format: `<per-address>,<global>`, each `<requests per second>/<burst>`; `off`
disables it. An IPv6 sender counts as its /64. Each limiter tracks at most 4096
addresses and evicts the longest idle.

The defaults fit an honest sender. Turn them up or `off` for the benchmarks
(`scripts/bench_*.py`, run with `STONECHAT_LIMIT_INBOX=off`), and behind
anything that makes every client one address (a reverse proxy, Docker's
userland proxy).

## The browser transport (`STONECHAT_WT_PORT`)

Browsers can't open `/ws`: the relay is a self-signed certificate on a bare IP.
WebTransport's `serverCertificateHashes` can pin such a certificate, so the
relay runs a second, QUIC listener carrying the same owner socket and the whole
HTTP surface (one stream per request). Each request goes through the same
`axum::Router` as the TLS listener, so every route exists once. The session
itself is unauthenticated: `POST /inbox` must stay open to senders, and each
route checks its own token.

Browsers require **SHA-256 of the DER** and certificates valid for **at most
14 days**. `wtcert.rs` keeps a schedule of 12 certificates (about 5 months),
serves the live one, rotates in place, and publishes every unexpired hash at
`GET /wt/certs`. Clients pin the whole set. The owner signs the list
(`stonechat-v1-wtcerts`, canonical form in `core/src/wtcerts.rs`) and publishes
it with `POST /v1/mailbox/wt` on the hub; the directory serves it only with
that signature. The address is published as `mailbox.wt_address`, unsigned: a
rewritten one leads to a certificate outside the signed schedule, which the
client refuses.

The listener is separate from TLS: a host that blocks UDP loses browser access,
not its mailbox. A bind failure is logged, not fatal.

### `STONECHAT_WT_ADVERTISE` is required in a container

Every certificate must name the address clients dial. Without it Chrome fails
with `QUIC_TLS_CERTIFICATE_UNKNOWN … CERTIFICATE_VERIFY_FAILED`, which looks
like a pin mismatch but isn't. Rust QUIC clients skip this check, so tests pass
anyway.

Inside a container the relay only sees a private address, so whoever creates
the container passes the public one. Loopback is always added, so a binary run
directly needs nothing. Changing the value regenerates the schedule; the
current names are in `<tls_dir>/wt/sans.txt`.

## The call relay (`STONECHAT_TURN_PORT`)

Calls go phone to phone over WebRTC. When NAT blocks that, the owner's mailbox
forwards the packets: `src/turn.rs` is a TURN server (RFC 5766) in this binary.
Media is DTLS-SRTP between the phones, so it forwards ciphertext.

- Two UDP ports: `STONECHAT_TURN_PORT` (also answers plain STUN) and the next
  one, the relay port. Publish both on the **same numbers** outside a
  container; the relay tells the other phone which port to use.
- One allocation per owner. `GET /turn-credentials`, called before every call,
  ends the previous one.
- Credentials use coturn's REST scheme, valid six hours, from a secret
  generated into `<tls_dir>/turn-secret`.
- `0` disables it: the route answers 404 and the app refuses to place calls.
  There is no third-party STUN fallback.

## How deployments run it

- **Mailbox hosts** run the image `ghcr.io/stonechat-app/relay`, one container
  per mailbox. Pin it with `STONECHAT_MAILBOX_HOST_IMAGE` at a digest; a
  hub-managed host refuses a floating tag.
- **Dedicated VMs** boot a startup script that downloads the binary and checks
  a SHA-256 pinned in the script. The hub serves it at `GET /v1/relay-binary`
  (set `STONECHAT_RELAY_BINARY` on the hub), or set `STONECHAT_RELAY_BINARY_URL`
  to host it elsewhere.
- **The local provider** builds `stonechat-relay:dev` from this directory, or
  from `STONECHAT_RELAY_BINARY` when set.

**Upgrading is a binary swap, never a container recreate.** A hosted mailbox
keeps its data in the container itself, so a new container would be an empty
mailbox. `scripts/roll_relay.py` uploads the binary to each mailbox host, whose
`POST /v1/relay/roll` swaps it into one mailbox at a time and rolls back any
that does not come up.

`/status` (owner token) reports `build`: the first 16 hex characters of the
BLAKE2b-256 of the running executable. That is how a swap is verified.

## Releases

Push a tag `relay-v<version>` matching `Cargo.toml`. The **Build relay**
workflow (`.github/workflows/relay-build.yml`) builds the static musl binary,
runs the unit tests and the golden corpus, and publishes:

- a GitHub Release with `stonechat-relay-x86_64-linux-musl` and `SHA256SUMS`;
- the image `ghcr.io/stonechat-app/relay`, tagged `<version>`, `<major>.<minor>`,
  `<major>` and `latest`: the tested binary on `scratch`
  (`Dockerfile.release`).

A manual run with **image** ticked pushes `:edge` and `:sha-<commit>` instead.
arm64 builds only while the repository is public (GitHub's arm64 runners are
free only there). Pin digests, never `:latest`.

Building the binary without CI, on or for x86_64 Linux:

```bash
docker build --platform linux/amd64 -t stonechat-relay-build relay/
id=$(docker create --platform linux/amd64 stonechat-relay-build) && \
  docker cp "$id":/stonechat-relay ./stonechat-relay && docker rm "$id"
```

## Tests

```bash
cargo test   # unit tests, parity vectors, router, WebTransport
```

Conformance needs a **fresh** relay (empty data dir; the corpus is stateful and
ordered), started with `STONECHAT_OWNER_ID=SC-TEST-OWNER
STONECHAT_OWNER_TOKEN=tok-secret STONECHAT_TURN_PORT=0`:

```bash
python3 tests/conformance.py https://127.0.0.1:<port>            # check
python3 tests/conformance.py https://127.0.0.1:<port> --record   # only after an intentional change
python3 tests/ws_test.py https://127.0.0.1:<port>                # needs `websockets`
```

The corpus holds 105 HTTP cases (status codes and bodies). What it can't
express (paging, the bounded channel, write timeouts, rate limits) is covered
by `cargo test`.
