# stonechat-core

The single implementation of the Stonechat session protocol — PQXDH
establishment, double ratchet, X-Wing hybrid envelope seal, device
certificates — so every process that must encrypt or decrypt links the same
code:

| Consumer | How |
|---|---|
| Flutter app | dart:ffi over the C ABI (`app/lib/core/core_ffi.dart`); `session.dart` is a thin wrapper |
| iOS Notification Service Extension | Swift over the C ABI, static lib (`app/ios/NotificationService/`) |
| Headless agent (`agent_client/`) | the Rust crate, linked directly |
| Browser client (`webclient/`, docs/WEB_CLIENT.md) | wasm32 (`cargo build --release --target wasm32-unknown-unknown`), bound by hand in `webclient/src/core.ts` over the same C ABI |
| Python reference clients (`scripts/e2e.py`) | the KEM half only, over ctypes (`scripts/pqcore.py`); the rest is restated in Python against PROTOCOL.md |

One artifact serves everything: the staticlib/cdylib carries this crate's
session ABI **and** pqcore's KEM symbols (`scripts/build_core.sh`
supersedes `build_pqcore.sh`; iOS links `app/ios/Core/libstonechat_core.a`
with `-force_load`).

The **relay is deliberately not a consumer**: it links neither this crate nor
`pqcore` — prekeys and certificates are opaque strings to it — and must never
grow a dependency on protocol code.

## Design rules

- **State-in/state-out.** No network, no filesystem, no clock. A session is
  a value; hosts persist it and hand it back. The serde JSON form is
  byte-compatible with the Dart `RatchetSession.toJson`, so the same DB
  rows work in either implementation during migration.
- **Caller-supplied randomness** (pqcore's rule): every operation that
  needs entropy takes explicit CSPRNG bytes — deterministic, corpus-
  testable, and wasm needs no getrandom shim. Keep dependencies'
  `getrandom` features off.
- **Pure Rust, no libsodium linkage.** RustCrypto/dalek implementations of
  the same standardized algorithms libsodium ships (X25519, Ed25519,
  XChaCha20-Poly1305, BLAKE2b) — byte-identical output, pinned by
  `tests/vectors.rs` (vectors generated with hashlib.blake2b + PyNaCl).
- **Sessions carry no owner/peer id.** Hosts key storage by
  (peer, device) per MULTIDEVICE.md, so multi-device never touches the
  state shape.

## Layout

- `src/primitives.rs` — KDFs, AEAD, X25519, Ed25519↔X25519 conversions,
  context-prefixed signatures.
- `src/identity.rs` — the identity and everything derived from it: keygen
  from a caller-supplied seed, the X-Wing derivation (hash of the **full
  64-byte** secret key), `pq_pk` signature, recovery and abuse-report
  signatures.
- `src/vault.rs` — the passphrase container behind `.stonechatbackup` and
  the identity-export string: Argon2id whose parameters ride inside the
  container and are authenticated as the AEAD's associated data.
- `src/session.rs` — PQXDH initiate/respond + double ratchet (MAX_SKIP=256,
  at most 512 stored skipped keys, trial-then-commit decrypt) + the sparse
  post-quantum ratchet (an ML-KEM secret mixed into the root key at most
  once per 50 messages; `decrypt` takes 64 bytes of randomness for it). The
  long-term keys in the handshake are the two *devices'* signing keys; the
  caller verifies the certificates that tie them to identities.
- `src/envelope.rs` — X-Wing hybrid seal/unseal over content padded to a
  size bucket, `x3dh` block codec.
- `src/devcert.rs` — device certificates: the length-prefixed signing bytes,
  signing with the identity key, and verification (signature, commitment to
  the named SC- ID, expiry).
- `src/wtcerts.rs` — the owner's signature over a mailbox's WebTransport
  certificate schedule, in the same length-prefixed style.
- `src/ids.rs` — Stonechat ID derive/normalize (SC- base32 + checksum).
- `src/ffi.rs` — the C ABI every non-Rust host calls.

PROTOCOL.md ("Devices", "Session crypto", "Envelope") is the spec, and this
crate is its implementation. `scripts/e2e.py` is the independent restatement
it is checked against.

## Tests

- `tests/vectors.rs` — libsodium byte-compatibility vectors (KDF chain/root,
  PQXDH KDF, hseal key, ID derivation, Ed25519↔X25519, scalarmult, AEAD).
- `tests/protocol.rs` — handshakes (with and without one-time prekeys),
  two-way ratcheting, out-of-order via skipped keys, replay rejection,
  absurd-gap refusal, tamper/state-untouched guarantees, Dart-shape JSON
  round-trip, hybrid-seal round trip.

- `tests/golden.rs` + `tests/fixtures/dart_transcript.json` — the frozen
  transcript recorded from the retired Dart ratchet (via
  `app/test/golden_transcript_test.dart`, which now exercises the FFI
  path instead). It is the compatibility baseline for session rows
  written before the cutover — regenerate only deliberately.
- `tests/abi.rs` — a full conversation driven through the C functions
  exactly as a foreign host would.

Follow-ups (tracked in ROADMAP.md):

1. The NSE itself: app-group storage + shared keychain, then the Swift
   extension linking this same static lib.
2. Zeroization pass (secret material in state blobs and FFI buffers).
3. ~~Migrate the rest of `crypto.dart`~~ — done 2026-07-30: the app has no
   cryptography of its own left and libsodium is out of its pubspec. The
   app supplies randomness (`Random.secure()`); this crate still draws
   none.
