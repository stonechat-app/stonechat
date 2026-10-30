//! The X-Wing hybrid envelope seal and the x3dh block codec
//! (PROTOCOL.md "Envelope"). Wire form of a sealed envelope:
//!
//! ```text
//! kem_ct (1120) || nonce (24) || xchacha20poly1305(pad(inner), ad="stonechat-v1-hseal")
//!     with key = H(kem_ss, key="stonechat-v1-hsealkdf", 32)
//! ```
//!
//! Anonymous and hybrid: fresh encapsulation per envelope, no sender key
//! anywhere on the wire (sealed sender), X25519 + ML-KEM-768 in one KEM.
//!
//! What is sealed is **padded** to a size bucket ([`padded_len`]), so a
//! mailbox cannot tell a receipt from a message from a roster by length.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use pqcore::{
    XWING_CIPHERTEXT_BYTES, XWING_ENCAPS_RANDOM_BYTES, XWING_PUBLIC_BYTES, XWING_SEED_BYTES,
    xwing_decaps, xwing_encaps,
};
use serde::{Deserialize, Serialize};

use crate::primitives::{
    AEAD_NONCE_BYTES, AEAD_TAG_BYTES, HSEAL_AD, HSEAL_KDF_KEY, aead_open, aead_seal, keyed_hash_32,
};

/// Smallest padded size: everything short — receipts, typing, text, group
/// text — lands in this one bucket.
pub const PAD_MIN: usize = 2048;
/// Up to here buckets double; above, they are multiples of [`PAD_STEP`], so
/// padding never costs a large envelope more than a kilobyte against the
/// mailbox's size limit.
pub const PAD_DOUBLING_MAX: usize = 32768;
pub const PAD_STEP: usize = 1024;

/// The bucket a message of `len` bytes is padded to: the smallest of 2048,
/// 4096, … 32768 that holds `len + 1`, else the next multiple of 1024.
/// Always greater than `len` — the marker byte is never optional.
pub fn padded_len(len: usize) -> usize {
    let need = len + 1;
    if need > PAD_DOUBLING_MAX {
        return need.div_ceil(PAD_STEP) * PAD_STEP;
    }
    let mut bucket = PAD_MIN;
    while bucket < need {
        bucket *= 2;
    }
    bucket
}

/// `message || 0x80 || 0x00…` up to [`padded_len`] (ISO/IEC 7816-4).
fn pad(message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(padded_len(message.len()));
    out.extend_from_slice(message);
    out.push(0x80);
    out.resize(padded_len(message.len()), 0);
    out
}

/// Inverse of [`pad`]. `None` unless the bytes end in `0x80 0x00…` and are
/// exactly the bucket their content pads to — an unpadded or oddly padded
/// seal is refused rather than guessed at.
fn unpad(mut padded: Vec<u8>) -> Option<Vec<u8>> {
    let total = padded.len();
    let marker = padded.iter().rposition(|&b| b != 0)?;
    if padded[marker] != 0x80 || padded_len(marker) != total {
        return None;
    }
    padded.truncate(marker);
    Some(padded)
}

/// Seal `message` to an X-Wing public key. For envelopes that is the
/// recipient **device's** `seal_pub`, taken from a device certificate the
/// host has verified. `random` must be fresh CSPRNG output, `nonce`
/// likewise. `None` when the key doesn't parse.
pub fn seal_to(
    seal_pub: &[u8; XWING_PUBLIC_BYTES],
    message: &[u8],
    random: &[u8; XWING_ENCAPS_RANDOM_BYTES],
    nonce: &[u8; AEAD_NONCE_BYTES],
) -> Option<Vec<u8>> {
    let (ct, ss) = xwing_encaps(seal_pub, random)?;
    let key = keyed_hash_32(&ss, HSEAL_KDF_KEY);
    let boxed = aead_seal(&key, nonce, &pad(message), HSEAL_AD);
    let mut out = Vec::with_capacity(ct.len() + nonce.len() + boxed.len());
    out.extend_from_slice(&ct);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&boxed);
    Some(out)
}

/// Unseal with an X-Wing seed — for envelopes, this device's own seal
/// seed. `None` when the envelope wasn't sealed to that key (a wrong
/// recipient decapsulates to a wrong shared secret and the AEAD refuses), is
/// garbage, or is not padded as [`seal_to`] pads.
pub fn unseal(seed: &[u8; XWING_SEED_BYTES], sealed: &[u8]) -> Option<Vec<u8>> {
    if sealed.len() < XWING_CIPHERTEXT_BYTES + AEAD_NONCE_BYTES + AEAD_TAG_BYTES {
        return None;
    }
    let kem_ct: &[u8; XWING_CIPHERTEXT_BYTES] = sealed[..XWING_CIPHERTEXT_BYTES].try_into().ok()?;
    let nonce: &[u8; AEAD_NONCE_BYTES] = sealed
        [XWING_CIPHERTEXT_BYTES..XWING_CIPHERTEXT_BYTES + AEAD_NONCE_BYTES]
        .try_into()
        .ok()?;
    let boxed = &sealed[XWING_CIPHERTEXT_BYTES + AEAD_NONCE_BYTES..];
    let ss = xwing_decaps(seed, kem_ct);
    let key = keyed_hash_32(&ss, HSEAL_KDF_KEY);
    unpad(aead_open(&key, nonce, boxed, HSEAL_AD)?)
}

/// The `x3dh` block attached to a session's initial envelopes until the
/// initiator has decrypted one reply. JSON field names are the wire form
/// (and identical to the Dart `X3dhBlock.toJson`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct X3dhBlock {
    /// Sender DEVICE's Ed25519 signing key, base64 — the key the
    /// certificate travelling beside this block (`cert`, a host-layer field
    /// this struct does not carry) must vouch for. Not the identity key.
    pub ik: String,
    /// Sender's ephemeral X25519 key, base64.
    pub ek: String,
    pub spk_id: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opk_id: Option<u64>,
    /// ML-KEM-768 ciphertext (PQXDH), base64.
    pub kct: String,
    /// Id of the KEM prekey encapsulated to.
    pub kem_id: u64,
    /// Whether `kem_id` names a one-time KEM prekey.
    #[serde(default)]
    pub kem_one_time: bool,
}

impl X3dhBlock {
    pub fn ik_bytes(&self) -> Option<[u8; 32]> {
        B64.decode(&self.ik).ok()?.try_into().ok()
    }

    pub fn ek_bytes(&self) -> Option<[u8; 32]> {
        B64.decode(&self.ek).ok()?.try_into().ok()
    }

    pub fn kct_bytes(&self) -> Option<[u8; pqcore::MLKEM_CIPHERTEXT_BYTES]> {
        B64.decode(&self.kct).ok()?.try_into().ok()
    }
}
