//! Encoding, randomness and the crate's error type.
//!
//! Randomness lives here and nowhere else. `stonechat-core` takes every secret
//! it needs as an argument (its "caller-supplied randomness" rule), so this
//! module is the whole boundary between the OS CSPRNG and the protocol.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;

pub type Error = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T> = std::result::Result<T, Error>;

/// A failure with a sentence attached. The agent runs unattended, so its log
/// is the only thing anyone will ever read about a failure — `err!` exists to
/// make sure what lands there is a sentence rather than a variant name.
#[macro_export]
macro_rules! err {
    ($($arg:tt)*) => {
        Box::<dyn std::error::Error + Send + Sync>::from(format!($($arg)*))
    };
}

pub fn b64(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

pub fn unb64(s: &str) -> Result<Vec<u8>> {
    B64.decode(s).map_err(|e| err!("not base64: {e}"))
}

/// Fixed-width base64 decode, for the many places where the wrong length is a
/// forged key rather than a typo.
pub fn unb64_n<const N: usize>(s: &str, what: &str) -> Result<[u8; N]> {
    let raw = unb64(s)?;
    let len = raw.len();
    raw.try_into()
        .map_err(|_| err!("{what}: expected {N} bytes, got {len}"))
}

pub fn b64url_nopad(bytes: &[u8]) -> String {
    B64URL.encode(bytes)
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Fresh CSPRNG bytes. Panics if the OS cannot supply entropy, which is not a
/// condition worth degrading through: every alternative to stopping here ends
/// with a key an attacker can guess.
pub fn random<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).expect("OS CSPRNG unavailable");
    out
}

/// Unkeyed BLAKE2b-256 — `crypto_generichash(msg, outlen=32)`, the hash the
/// link commitment, the parking key and the TLS fingerprint all use.
pub fn blake2b_256(msg: &[u8]) -> [u8; 32] {
    stonechat_core::primitives::hash_var(msg, 32)
        .try_into()
        .expect("hash_var honours its length")
}

/// Compare two secrets without leaking where they first differ.
pub fn secret_eq(a: &str, b: &str) -> bool {
    stonechat_core::primitives::bytes_eq(a.as_bytes(), b.as_bytes())
}
