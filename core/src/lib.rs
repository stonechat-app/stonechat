//! Stonechat protocol core.
//!
//! The single implementation of the Stonechat session protocol — PQXDH
//! establishment, double ratchet, X-Wing hybrid envelope seal — shared by
//! every process that must encrypt or decrypt: the Flutter app (dart:ffi),
//! the iOS Notification Service Extension (Swift over the C ABI), the
//! headless agent (as a crate) and the browser client (wasm). The relay
//! links neither this crate nor `pqcore`: prekeys and certificates are
//! opaque strings to it.
//!
//! Design rules (PROTOCOL.md "Session crypto" is the spec; the Dart
//! original is app/lib/core/session.dart + crypto.dart):
//!
//! - **State-in/state-out.** Nothing here touches the network, the
//!   filesystem, or a clock. A session is a value: hosts persist it
//!   (serde JSON, byte-compatible with the Dart `RatchetSession.toJson`
//!   shape) and hand it back for the next message.
//! - **Caller-supplied randomness**, like pqcore: every operation that
//!   needs entropy takes explicit CSPRNG bytes. Deterministic, golden-
//!   corpus-testable, and wasm needs no getrandom shim.
//! - **Pure Rust.** libsodium's algorithms via RustCrypto/dalek — the
//!   implementations libsignal ships. Byte-identical output (pinned by
//!   the reference vectors in tests/, generated with hashlib.blake2b and
//!   PyNaCl against the constants in PROTOCOL.md).
//! - Sessions are values with no owner id inside — hosts key storage by
//!   (peer, device) so the multi-device migration
//!   never touches this crate's state shape.
//!
//! The C ABI (src/ffi.rs) is the session surface every host calls:
//! state blob in → result + advanced state blob out, core-allocated
//! buffers released via `stonechat_free`. The staticlib/cdylib builds
//! also carry pqcore's `stonechat_mlkem_*`/`stonechat_xwing_*` symbols,
//! so one linked artifact serves both ABIs.

pub mod devcert;
pub mod devices;
pub mod envelope;
pub mod ffi;
pub mod identity;
pub mod ids;
pub mod primitives;
pub mod session;
pub mod vault;
pub mod wtcerts;

pub use pqcore;

/// Bumped whenever the exported C ABI changes shape.
pub const ABI_VERSION: u32 = 3;

#[unsafe(no_mangle)]
pub extern "C" fn stonechat_core_abi_version() -> u32 {
    ABI_VERSION
}
