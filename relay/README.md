# zeon-relay — Rust port of the routing server

Rust implementation of the per-user mailbox (`server/main.py`). Same wire
contract (PROTOCOL.md "Routing server API"), same SQLite schema, same TLS
PEM files — a Rust relay pointed at a volume the Python relay wrote serves
its queued mail with an **unchanged pinned TLS fingerprint**, in both
directions. `server/main.py` remains in-tree as the executable spec until
cutover (docs/RUST_PORT.md "Rollout").

Why it exists: one relay process runs per hosted user, so idle RSS is the
Private plan's unit cost. Measured at port time: **Python 57 MB → Rust
10 MB idle** (macOS dev build of the fleet's dominant cost; lower still in
the `scratch` container). Full economics: docs/COSTS.md.

## Run

```bash
cargo build --release
ZEON_OWNER_ID=ZC-… ZEON_OWNER_TOKEN=secret ./target/release/zeon-relay
```

Same env contract as the Python relay: `ZEON_PORT` (8080), `ZEON_DB`
(`mailbox.db`), `ZEON_BLOBS` (`blobs`), `ZEON_TLS_DIR` (DB's directory),
`ZEON_TURN_SECRET`/`ZEON_TURN_PORT`, `ZEON_PUSH_GATEWAY`/`ZEON_PUSH_KEY`.

Docker: `docker build -t zeon-server:rust .` (self-building dev image;
production ships a prebuilt binary — RUST_PORT.md "Packaging").

## How deployments consume this crate

All provisioning paths use the Rust relay (hub integration landed 2026-07-19):

- **local / fleet providers** build the image tagged `zeon-server:dev` from
  this directory. With `ZEON_RELAY_BINARY` set on the hub (path to a static
  **x86_64-musl** `zeon-relay`), the build context becomes binary + two-line
  Dockerfile — instant, no compile on the host. Unset, hosts compile the
  crate via this Dockerfile (dev fallback; also what produces the right
  architecture on ARM laptops).
- **Sovereign VM startup scripts** are fetch-stubs (~3 KB — fits every
  cloud's cap, including AWS's 16 KB): they download the binary and verify a
  SHA-256 pinned in the script. The hub serves the artifact at
  `GET /v1/relay-binary`, authenticated with the per-server token the
  script already carries — an egress-cost gate, not an integrity measure
  (that's the pin). Set `ZEON_HUB_URL` for the default URL, or
  `ZEON_RELAY_BINARY_URL` to host it on GCS/GitHub instead (fetched
  anonymously).
- **Host agent** guest mailboxes build from the same binary; the sovereign
  startup script writes `/opt/zeon/server/` (binary + Dockerfile) for it.

Producing the production artifact (on/for x86_64 Linux):

```bash
docker build --platform linux/amd64 -t zeon-relay-build relay/
id=$(docker create --platform linux/amd64 zeon-relay-build) && \
  docker cp "$id":/zeon-relay ./zeon-relay && docker rm "$id"
# → scp to the hub box, set ZEON_RELAY_BINARY=/path/to/zeon-relay
```

## Tests

```bash
cargo test          # unit + parity vectors (TLS fingerprint, TURN HMAC)
```

Conformance against the Python relay (both started with
`ZEON_OWNER_ID=ZC-TEST-OWNER ZEON_OWNER_TOKEN=tok-secret` on fresh data
dirs; python needs the hub venv's fastapi/uvicorn):

```bash
python3 tests/conformance.py https://127.0.0.1:<py_port> https://127.0.0.1:<rs_port>
python3 tests/ws_test.py https://127.0.0.1:<either_port>   # needs `websockets`
```

Status at last run: 40/40 HTTP corpus identical (status codes + bodies,
including FastAPI-style `{"detail": …}` error shapes), WS suite identical
(drain order, ack-delete + blob GC, close 4000 replacement, 403 bad token),
volume-takeover fingerprint match verified.
