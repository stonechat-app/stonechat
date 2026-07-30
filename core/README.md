# stonechat-core

The single implementation of the Stonechat session protocol — PQXDH
establishment, double ratchet, X-Wing hybrid envelope seal — extracted from
the Dart app so every process that must encrypt or decrypt links the same
code (notes/docs/ROADMAP.md is the decision record):

| Consumer | How | Status |
|---|---|---|
| Flutter app | dart:ffi over the C ABI (`app/lib/core/core_ffi.dart`) | **live** — `session.dart` is a thin wrapper since the cutover |
| iOS Notification Service Extension | Swift over the C ABI, static lib | next — the reason the ABI exists |
| Desktop (Flutter) | same dart:ffi bindings | later |
| Web (tethered device, WEB_CLIENT.md) | wasm32 + wasm-bindgen wrapper | later — `cargo build --target wasm32-unknown-unknown` works today |

One artifact serves everything: the staticlib/cdylib carries this crate's
session ABI **and** pqcore's KEM symbols (`scripts/build_core.sh`
supersedes `build_pqcore.sh`; iOS links `app/ios/Core/libstonechat_core.a`
with `-force_load`).

The **relay is deliberately not a consumer**: it depends on `pqcore` alone
and must never grow a dependency on protocol code.

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
- `src/session.rs` — PQXDH initiate/respond + double ratchet. Mirrors
  `app/lib/core/session.dart` (same MAX_SKIP=256 / 512 skipped-key
  bounds, same trial-then-commit decrypt semantics).
- `src/envelope.rs` — X-Wing hybrid seal/unseal, `x3dh` block codec.
- `src/ids.rs` — Stonechat ID derive/normalize (SC- base32 + checksum).

PROTOCOL.md ("Session crypto", "Envelope") is the spec; the Dart files are
the executable reference until the app switches over.

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
