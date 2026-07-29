# stonechat-core

The single implementation of the Stonechat session protocol — PQXDH
establishment, double ratchet, X-Wing hybrid envelope seal — extracted from
the Dart app so every process that must encrypt or decrypt links the same
code (notes/docs/ROADMAP.md is the decision record):

| Consumer | How | Status |
|---|---|---|
| Flutter app | dart:ffi over the C ABI (like pqcore) | planned — replaces `session.dart` internals |
| iOS Notification Service Extension | Swift over the C ABI, static lib | planned — the first payoff |
| Desktop (Flutter) | same dart:ffi bindings | later |
| Web (tethered device, WEB_CLIENT.md) | wasm32 + wasm-bindgen wrapper | later — `cargo build --target wasm32-unknown-unknown` works today |

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
  context-prefixed signatures. Mirrors `app/lib/core/crypto.dart`.
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

Follow-ups, in order (tracked in ROADMAP.md):

1. **Dart↔Rust golden corpus**: record handshake + ratchet transcripts from
   the running Dart implementation and replay them here (and vice versa) —
   the cross-implementation gate before the app switches. The e2e harness
   (`scripts/e2e.py`) already speaks the protocol from Python and is the
   natural recorder.
2. **C ABI for sessions** (state blob in → state blob + result out),
   designed against the NSE's 24 MB budget; then the PqCore-style iOS
   framework wrapper.
3. Zeroization pass (secret material in state blobs) once the ABI shape is
   settled.
