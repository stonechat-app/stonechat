# stonechat-relay — the routing server

The per-user mailbox. Wire contract: PROTOCOL.md "Routing server API";
behavioral contract: the golden corpus in `tests/` (recorded at the 2026-07
cutover that retired the Python relay — notes/docs/RUST_PORT.md is the port
record). SQLite schema and TLS PEM handling are unchanged from the Python
era, so a relay pointed at an old volume serves its queued mail with an
unchanged pinned TLS fingerprint.

Why it exists: one relay process runs per hosted user, so idle RSS is the
Private plan's unit cost. Measured at port time: **Python 57 MB → Rust
10 MB idle** (macOS dev build of the fleet's dominant cost; lower still in
the `scratch` container). Full economics: notes/docs/COSTS.md.

## Run

```bash
cargo build --release
STONECHAT_OWNER_ID=SC-… STONECHAT_OWNER_TOKEN=secret ./target/release/stonechat-relay
```

Env contract: `STONECHAT_PORT` (8080), `STONECHAT_DB`
(`mailbox.db`), `STONECHAT_BLOBS` (`blobs`), `STONECHAT_TLS_DIR` (DB's directory),
`STONECHAT_TURN_SECRET`/`STONECHAT_TURN_PORT`, `STONECHAT_PUSH_GATEWAY`/`STONECHAT_PUSH_KEY`.

Docker: `docker build -t stonechat-server:rust .` (self-building dev image;
production ships a prebuilt binary — RUST_PORT.md "Packaging").

## How deployments consume this crate

All provisioning paths use the Rust relay (hub integration landed 2026-07-19):

- **local / fleet providers** build the image tagged `stonechat-server:dev` from
  this directory. With `STONECHAT_RELAY_BINARY` set on the hub (path to a static
  **x86_64-musl** `stonechat-relay`), the build context becomes binary + two-line
  Dockerfile — instant, no compile on the host. Unset, hosts compile the
  crate via this Dockerfile (dev fallback; also what produces the right
  architecture on ARM laptops).
- **Sovereign VM startup scripts** are fetch-stubs (~3 KB — fits every
  cloud's cap, including AWS's 16 KB): they download the binary and verify a
  SHA-256 pinned in the script. The hub serves the artifact at
  `GET /v1/relay-binary`, authenticated with the per-server token the
  script already carries — an egress-cost gate, not an integrity measure
  (that's the pin). Set `STONECHAT_HUB_URL` for the default URL, or
  `STONECHAT_RELAY_BINARY_URL` to host it on GCS/GitHub instead (fetched
  anonymously).
- **Host agent** guest mailboxes build from the same binary; the sovereign
  startup script writes `/opt/stonechat/server/` (binary + Dockerfile) for it.

Producing the production artifact (on/for x86_64 Linux):

```bash
docker build --platform linux/amd64 -t stonechat-relay-build relay/
id=$(docker create --platform linux/amd64 stonechat-relay-build) && \
  docker cp "$id":/stonechat-relay ./stonechat-relay && docker rm "$id"
# → scp to the hub box, set STONECHAT_RELAY_BINARY=/path/to/stonechat-relay
```

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

Status at last run: 52/52 HTTP corpus identical to the goldens (status
codes + bodies, including the FastAPI-style `{"detail": …}` error shapes
inherited from the Python era), WS suite pass (drain order, ack-delete +
blob GC, close 4000 replacement, 403 bad token). Provenance: the live
Python↔Rust diff passed 40/40 pre-PQXDH (2026-07-19); the PQXDH prekey
surface was then added to both relays in lockstep, and the goldens were
recorded from the Rust relay at cutover (2026-07-27). The last ten
expectations are the group-media surface — shared blob upload, capability
scoping, owner delete — added 2026-07-30 with the original 42 unchanged.
