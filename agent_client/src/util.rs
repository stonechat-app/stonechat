//! Encoding, randomness and the crate's error type.
//!
//! Randomness lives here and nowhere else. `stonechat-core` takes every secret
//! it needs as an argument (its "caller-supplied randomness" rule), so this
//! module is the whole boundary between the OS CSPRNG and the protocol.

use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;

/// A failure with a sentence attached, and one bit that matters more than
/// the sentence: whether trying again could help.
///
/// The distinction decides what happens to an envelope. One whose handling
/// failed **transiently** — the hub or a mailbox could not be reached — is
/// left un-acked and redelivered on the next connection, because acking it
/// would throw a message away over a network blip. One that failed
/// **permanently** — malformed, undecryptable, from a device that no longer
/// speaks for its sender — is acked and dropped, because leaving it queued
/// would replay it on every connect forever.
#[derive(Debug)]
pub enum Error {
    Transient(String),
    Permanent(String),
}

impl Error {
    pub fn is_transient(&self) -> bool {
        matches!(self, Error::Transient(_))
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Transient(s) | Error::Permanent(s) => f.write_str(s),
        }
    }
}

impl std::error::Error for Error {}

// Network libraries only ever fail for reasons the network might fix.
impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        Error::Transient(format!("{e}"))
    }
}

impl From<tokio_tungstenite::tungstenite::Error> for Error {
    fn from(e: tokio_tungstenite::tungstenite::Error) -> Self {
        Error::Transient(format!("{e}"))
    }
}

/// A state file that cannot be written is not a reason to ack anything, so
/// filesystem trouble counts as "try again" rather than "drop".
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Transient(format!("{e}"))
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Permanent(format!("{e}"))
    }
}

impl From<stonechat_core::session::SessionError> for Error {
    fn from(e: stonechat_core::session::SessionError) -> Self {
        Error::Permanent(format!("{e}"))
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// A permanent failure. The agent runs unattended, so its log is the only
/// thing anyone will ever read about a failure — `err!` exists to make sure
/// what lands there is a sentence rather than a variant name.
#[macro_export]
macro_rules! err {
    ($($arg:tt)*) => {
        $crate::util::Error::Permanent(format!($($arg)*))
    };
}

/// A failure worth retrying: the other end could not be reached.
#[macro_export]
macro_rules! transient {
    ($($arg:tt)*) => {
        $crate::util::Error::Transient(format!($($arg)*))
    };
}

/// Whether an HTTP status is the server's passing trouble rather than our
/// request's fault. Rate limits and 5xx clear up; a 4xx will not.
pub fn status_is_transient(status: reqwest::StatusCode) -> bool {
    status.is_server_error()
        || status == reqwest::StatusCode::TOO_MANY_REQUESTS
        || status == reqwest::StatusCode::REQUEST_TIMEOUT
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

/// Unix seconds, clamped at zero so it fits the certificate's `u64`.
pub fn now_s() -> u64 {
    chrono::Utc::now().timestamp().max(0) as u64
}

pub fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// Whether a value is a UUID in its canonical 36-character form.
///
/// Envelope and blob ids are UUIDs by construction — every client mints them
/// with a UUID generator — so anything else was not written by a client. They
/// end up in URLs (`/blob/{id}`) and in file names, so the shape is refused
/// where it enters rather than escaped at every use.
pub fn is_wire_id(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 36 {
        return false;
    }
    b.iter().enumerate().all(|(i, c)| match i {
        8 | 13 | 18 | 23 => *c == b'-',
        _ => c.is_ascii_hexdigit(),
    })
}

/// Percent-encode a query value. Device tokens are base64url and need none
/// of this; the encoding is for a token that is not.
pub fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// The first twelve characters of an ID, for log lines.
pub fn short(id: &str) -> String {
    id.chars().take(12).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_ids_are_canonical_uuids() {
        assert!(is_wire_id("123e4567-e89b-12d3-a456-426614174000"));
        assert!(is_wire_id("123E4567-E89B-12D3-A456-426614174000"));
        assert!(!is_wire_id("123e4567e89b12d3a456426614174000"));
        assert!(!is_wire_id("../123e4567-e89b-12d3-a456-4266141740"));
        assert!(!is_wire_id(""));
    }
}
