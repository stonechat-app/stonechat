# Stonechat web client

Design and threat analysis: `notes/docs/WEB_CLIENT.md` (internal). This
README is the build record and the open decisions.

Status: **spike.** The core runs in a JS host; nothing else exists yet.

## What works

`stonechat-core` compiles to `wasm32-unknown-unknown` unmodified — the crate
was written for it (`Cargo.toml`: *"one implementation for app (FFI), iOS NSE
(static lib), desktop, and wasm"*, with `getrandom` already excluded because
randomness is caller-supplied). 538 KB, C ABI intact.

```bash
cd ../core && cargo build --release --target wasm32-unknown-unknown
node test/wasm_smoke.mjs
```

The smoke test checks the *bridge*, not the crypto (core/ owns that):
allocate → write → call → read a core-allocated result → free, and that the
identity derived in WASM is **byte-identical to the native core's**. A WASM
build that quietly disagreed would produce an identity no peer could resolve.

One change was needed: `stonechat_alloc`, symmetric with the existing
`stonechat_free`. Native callers allocate with their own runtime; a JS host
can read and write the exported `memory` but has no way to know which of it
is free.

### The contract the bindings must enforce

Fixed-size inputs (a 64-byte secret key, a 32-byte seed) carry **no length**,
so the core cannot detect a short buffer — it reads whatever follows in
linear memory and returns a confident wrong answer. Native callers get this
free from their FFI type signatures. JavaScript does not, so the binding
layer is the only place it can be checked. The smoke test pins this as a
property rather than pretending the core validates it.

Variable-length inputs do carry a length and are validated (`rc = -1`).

## Two decisions before any UI

Both come from tensions inside WEB_CLIENT.md itself. Neither is mine to
settle unilaterally.

### 1. Does the web device hold the shared identity key?

The multi-device design has **every device share one identity key** — that is
what lets the outer envelope seal (to the user's single `pq_pk` in the
directory) be opened by any of them.

WEB_CLIENT.md's defensible shape says the opposite: *"The identity key never
leaves the phone"*, *"the web device's keys are its own, authorized by an
identity-signed grant"* — while also calling the web device *"a real device in
the MULTIDEVICE.md sense"*. Those cannot both hold.

- **Shared identity** — everything built works unchanged, and the web client
  is a few weeks of UI. But a coerced origin steals the identity *permanently*,
  which destroys the entire argument that a browser client is defensible. The
  doc's own threat analysis exists to avoid exactly this.
- **Per-device keys + an identity-signed certificate** — matches the threat
  model. Costs a protocol extension: per-device seal keys in the bundle, and
  peers verifying a device certificate chain.

The second is more work and strictly better, and it would also fix a
limitation flagged throughout the docs: revocation is currently *"a delivery
cut, not a cryptographic excision"*. With expiring per-device certificates,
revoking a device would actually mean something cryptographically.

### 2. Flutter web, or a purpose-built bundle?

WEB_CLIENT.md's attestation story rests on a tiny root of trust: *"tiny
index.html → SRI-pinned JS → integrity-fetched WASM means the entire attack
surface is one human-readable file"*, enabling reproducible builds and a
public transparency log of release hashes.

Flutter web emits a large opaque bundle (`main.dart.js` plus a renderer),
which fights that story badly — nobody audits a megabyte of compiled Dart,
and the hash root stops being meaningful. It also cannot reach WebTransport
or the WASM core without JS interop anyway, so the "share code with the app"
benefit is thin.

A small hand-written TypeScript app costs a UI rewrite and serves the
security argument that justifies the whole project.

## Not started

- **WebTransport endpoint on the relay** (`serverCertificateHashes`, option B
  in WEB_CLIENT.md) — the largest remaining unknown, and relay work rather
  than client work.
- **Silent cert rotation** — WebTransport caps certificate validity at 14
  days, which makes the batch pre-signing scheme load-bearing rather than
  optional.
- **Storage** — no SQLCipher in a browser. The tethered shape says no history
  at all, which makes this smaller than it looks.
- **CORS on the relay** (there is none) and moving `?token=` out of the query
  string.
