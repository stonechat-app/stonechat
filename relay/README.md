# stonechat-relay — the mailbox program

The per-user mailbox. Wire contract: PROTOCOL.md "Mailbox API";
behavioral contract: the golden corpus in `tests/` (recorded at the 2026-07
cutover that retired the Python relay — notes/docs/RUST_PORT.md is the port
record). SQLite schema and TLS PEM handling are unchanged from the Python
era, so a relay pointed at an old volume serves its queued mail with an
unchanged pinned TLS fingerprint.

Why it exists: one relay process runs per hosted user, so idle RSS is the
Mailbox plan's unit cost. Measured at port time: **Python 57 MB → Rust
10 MB idle** (macOS dev build of a mailbox host's dominant cost; lower still in
the `scratch` container). Full economics: notes/docs/COSTS.md.

## Run

```bash
cargo build --release
STONECHAT_OWNER_ID=SC-… STONECHAT_OWNER_TOKEN=secret ./target/release/stonechat-relay
```

Env contract: `STONECHAT_PORT` (8080), `STONECHAT_WT_PORT` (8443, UDP; `0`
disables), `STONECHAT_WT_ADVERTISE` (comma-separated hosts/IPs the browser
transport's certificates must name — see below), `STONECHAT_DB` (`mailbox.db`),
`STONECHAT_BLOBS` (`blobs`),
`STONECHAT_TLS_DIR` (DB's directory),
`STONECHAT_TURN_SECRET`/`STONECHAT_TURN_PORT`, `STONECHAT_PUSH_GATEWAY`/`STONECHAT_PUSH_KEY`.

### The browser transport (`STONECHAT_WT_PORT`)

A second listener, QUIC/UDP, carrying the **same owner socket** as `/ws`:
envelopes down, `{"ack": id}` up, one drainer per device. It exists because a
browser cannot open the socket `/ws` uses — a relay is a self-signed
certificate on a bare IP, and `fetch`/`WebSocket` refuse that with no API to
accept it (WEB_CLIENT.md blocker 1).

WebTransport's `serverCertificateHashes` is the exception, and it is the *same*
trust model Stonechat already has — pin the certificate, ignore CAs — with two
differences that are not ours to negotiate: the pin is **SHA-256 of the DER**
(not BLAKE2b), and the certificate may be valid for **at most 14 days**.

That cap is the whole design problem, and `wtcert.rs` answers it by running
ahead: the relay keeps a **schedule** of twelve certificates covering ~5 months,
serves the currently-live one, and publishes every unexpired hash at
`GET /wt/certs`. A client pins the whole set, so rotation is silent and it only
has to refresh before its *last* pin lapses. Rotation happens in place
(`reload_config`), so live sessions are not dropped.

`/wt/certs` is unauthenticated and states rather than vouches — every value in
it is a hash of a certificate the relay hands to anyone who connects. What
makes it trustworthy is the **owner's signature** over the same list in the hub
directory, exactly as with the long-lived fingerprint. **That signature does
not exist yet** — see "Not finished" below.

Separate from the TLS listener on purpose: native clients keep the transport
they pin today, and a host that blocks UDP loses browser sessions rather than
its mailbox. A bind failure is logged, not fatal.

The owner's signature over the schedule **now exists** (`POST /v1/mailbox/wt`
on the hub, signed with `stonechat-v1-wtcerts` over the canonical form in
`core/src/wtcerts.rs`). The directory serves the list and the signature
together, or neither — an unsigned schedule is served as no schedule, because
a client must not pin one.

The address is published too, as `mailbox.wt_address` in the directory.
Container providers map `-p 0:8443/udp` and read the port back; VM providers
expose the fixed port. Unsigned, and safe to be: rewriting it sends a client to
a mailbox whose certificate is not in the owner-signed schedule, so the
connection is refused — denial of service, not compromise, the same property
`address` already has behind `tls_fp`.

#### `STONECHAT_WT_ADVERTISE` is not optional in a container

Every certificate must carry a **subjectAltName naming the address clients
dial**. `serverCertificateHashes` does not exempt a certificate from being well
formed, and browsers stopped honouring CommonName as a name years ago. Without
one, Chrome refuses with:

```
ERR_QUIC_PROTOCOL_ERROR.QUIC_TLS_CERTIFICATE_UNKNOWN
  … 46: certificate unknown … CERTIFICATE_VERIFY_FAILED
```

which reads as "the pin did not match" and is nothing of the sort — the pin
matches fine. Worse, **Rust QUIC clients skip name checks when given hashes**,
so a SAN-less certificate passes every test in this repo, including the three
end-to-end WebTransport ones and a live connection against production. It fails
only in the one place that matters. That is how it shipped.

The relay cannot discover the name itself: inside a container it sees a private
address, and the address clients dial belongs to the host. Whoever creates the
container knows it and passes it — the machine host and local provider set it
from the address they publish the mailbox at, and VM startup scripts from the
metadata service. Loopback is always appended, so running the binary directly
needs no configuration.

Changing it regenerates the whole schedule: the names are baked into every
certificate, and a relay that moved would otherwise keep serving certificates
naming its old address. The current set is recorded in `<tls_dir>/wt/sans.txt`.

#### One router, two transports

The whole HTTP surface is carried too, one bidirectional stream per request:

```text
{"method":"POST","path":"/inbox","len":1234}\n<1234 bytes>
{"status":200,"headers":{…},"len":56}\n<56 bytes>
```

`/ws` is the exception and it is the HTTP one — the relay answers
`{"status":101}` and the stream then carries the owner socket.

Requests are **not reimplemented**. `wt::dispatch` turns the frame into an
`http::Request` and hands it to the same `axum::Router` the TLS listener
serves, so every route exists once, with its own extractors, body limit and
status codes. An adapter that reimplemented even one of them would be a second
relay to keep correct, and the conformance corpus only covers the first.

**The session is deliberately unauthenticated.** It is tempting to check a
device token at CONNECT and let streams inherit it — and that is wrong: most of
a relay's surface is open by design. `POST /inbox` takes no token, because
sealed sender means anyone can post to anyone's mailbox and a *sender* holds no
token for the *recipient's* relay. Gating the session made delivery impossible
for exactly the case this transport exists to serve; it was caught by writing
the client. Each route authenticates itself, as it does over HTTP.

Docker: `docker build -t stonechat-relay:rust .` (self-building dev image;
production ships a prebuilt binary — RUST_PORT.md "Packaging").

## How deployments consume this crate

All provisioning paths use the Rust relay (hub integration landed 2026-07-19):

- **The local provider** builds the image tagged `stonechat-relay:dev` from
  this directory. With `STONECHAT_RELAY_BINARY` set on the hub (path to a static
  **x86_64-musl** `stonechat-relay`), the build context becomes binary + two-line
  Dockerfile — instant, no compile on the host. Unset, it compiles the
  crate via this Dockerfile (dev fallback; also what produces the right
  architecture on ARM laptops). A machine host the hub manages compiles nothing:
  it wraps a binary uploaded with `POST /v1/relay` in an image tagged by that
  binary's build id, and builds every later mailbox from it.
- **Dedicated-VM startup scripts** are fetch-stubs (~3 KB — fits every
  cloud's cap, including AWS's 16 KB): they download the binary and verify a
  SHA-256 pinned in the script. The hub serves the artifact at
  `GET /v1/relay-binary`, authenticated with the per-mailbox token the
  script already carries — an egress-cost gate, not an integrity measure
  (that's the pin). Set `STONECHAT_HUB_URL` for the default URL, or
  `STONECHAT_RELAY_BINARY_URL` to host it on GCS/GitHub instead (fetched
  anonymously).
- **Machine host** guest mailboxes run the published image
  `ghcr.io/stonechat-app/relay`, pulled on first use and never built. On
  dedicated VMs the startup script instead builds `stonechat-relay:dev` from the
  same pinned binary (`/opt/stonechat/relay/`: binary + Dockerfile) and points
  the machine host at it, so those guests never touch the registry.

Producing the production artifact: run the **Build relay** workflow
(`.github/workflows/relay-build.yml`) manually. It builds the static musl
binary natively on Linux, runs the unit tests and the golden corpus against
it, checks it needs no loader, and uploads it as the
`stonechat-relay-x86_64-<commit>` artifact. Without CI (on/for x86_64 Linux):

```bash
docker build --platform linux/amd64 -t stonechat-relay-build relay/
id=$(docker create --platform linux/amd64 stonechat-relay-build) && \
  docker cp "$id":/stonechat-relay ./stonechat-relay && docker rm "$id"
# → scp to the hub box, set STONECHAT_RELAY_BINARY=/path/to/stonechat-relay
```

That covers mailboxes created *after* the release. Mailboxes already running
are upgraded in place — `scripts/roll_relay.py` copies the binary over the
entrypoint and restarts each container — because their data lives in the
container itself and recreating one would reset a user's mailbox. See
deploy/README.md "Upgrading the relay without destroying mailboxes".

`/status` reports `build`: BLAKE2b-256 of the executable the process is
actually running, first 16 hex chars, computed at boot from
`current_exe()`. That is what makes an in-place swap verifiable — a version
constant compiled into the source would report the new number whether or not
the file on disk had changed. It is on `/status` (owner token) rather than
`/health` (open) so an exact build fingerprint is not handed to anyone who
asks the day a relay bug is published.

### Releases (what self-hosters run)

Push a tag `relay-v<version>`, where the version is the one in `Cargo.toml`
(e.g. `relay-v0.1.0`; the workflow refuses a mismatch). The same workflow
builds and tests, then publishes:

- a GitHub Release with `stonechat-relay-x86_64-linux-musl`,
  `stonechat-relay-aarch64-linux-musl` and `SHA256SUMS`
- `ghcr.io/stonechat-app/relay` for amd64 and arm64, tagged `0.1.0`, `0.1`,
  `0` and `latest`. The image is `Dockerfile.release`: the tested binary on
  `scratch` and nothing else.

A manual run with **image** ticked pushes `:edge` and `:sha-<commit>`
instead, to try an image before tagging it.

Who consumes which of the two, and why there are two:

| Consumer | Artifact | How it is pinned |
|---|---|---|
| Machine hosts (shared tier and friend-hosted alike) | the image | `STONECHAT_MACHINE_HOST_IMAGE` at a digest. A roll extracts the binary from that image, so no separate download |
| Dedicated VMs | the release asset | `STONECHAT_RELAY_BINARY_URL` + `STONECHAT_RELAY_SHA256`, the latter baked into the startup script that fetches it |

A VM gets the binary rather than the image because its startup script runs the
relay directly, and because the cloud metadata channel that carries the script
caps its size — the script is a fetch-stub with a hash in it
(hub/app/providers/bootstrap.py). Same bytes either way: the image is that
binary on `scratch`.

Pin digests, never `:latest`. A mailbox whose build nobody can name is one
nobody can reason about the day a relay bug is published, which is why a
hub-managed machine host refuses to launch from the floating tag at all.

While the repository is private, only x86_64 is built, because GitHub's arm64
runners are free for public repositories only. A package's first push to
ghcr.io is private as well: make it public once, in the organization's
Packages → relay → Package settings.

## Tests

```bash
cargo test          # unit + parity vectors (TLS fingerprint, TURN HMAC)
```

Conformance against the golden corpus (start a **fresh** relay —
`STONECHAT_OWNER_ID=SC-TEST-OWNER STONECHAT_OWNER_TOKEN=tok-secret`, empty data
dir — the corpus is stateful and order-dependent):

```bash
python3 tests/conformance.py https://127.0.0.1:<port>            # check
python3 tests/conformance.py https://127.0.0.1:<port> --record   # after intentional changes
python3 tests/ws_test.py https://127.0.0.1:<port>   # needs `websockets`
```

Status at last run: 91/91 HTTP corpus identical to the goldens (status
codes + bodies, including the FastAPI-style `{"detail": …}` error shapes
inherited from the Python era), WS suite pass (drain order, ack-delete +
blob GC, close 4000 replacement, 403 bad token). Provenance: the live
Python↔Rust diff passed 40/40 pre-PQXDH (2026-07-19); the PQXDH prekey
surface was then added to both relays in lockstep, and the goldens were
recorded from the Rust relay at cutover (2026-07-27). Ten expectations for
the group-media surface followed on 2026-07-30 with the original 42
unchanged, and 27 for the device model on 2026-07-31 (MULTIDEVICE.md phase
1) — that change re-recorded six earlier expectations, all of them purely
additive. Phase 3's linking surface followed on 2026-08-02: device kind and
lifetime, an expired device authenticating as nobody, and `/link` grant
parking (single-use, unauthenticated collection).
