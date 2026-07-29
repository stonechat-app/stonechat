//! Stonechat IDs (PROTOCOL.md "Identity"):
//! `"SC-" + base32(blake2b20(pubkey) || checksum2)`, grouped in fours.
//! Mirrors app/lib/core/crypto.dart.

use crate::primitives::hash_var;

const B32_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

pub fn base32_encode(bytes: &[u8]) -> String {
    let mut out = String::new();
    let mut buffer: u64 = 0;
    let mut bits = 0u32;
    for &byte in bytes {
        buffer = (buffer << 8) | byte as u64;
        bits += 8;
        while bits >= 5 {
            out.push(B32_ALPHABET[((buffer >> (bits - 5)) & 31) as usize] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        out.push(B32_ALPHABET[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

pub fn base32_decode(s: &str) -> Result<Vec<u8>, IdError> {
    let mut out = Vec::new();
    let mut buffer: u64 = 0;
    let mut bits = 0u32;
    for ch in s.bytes() {
        let v = B32_ALPHABET
            .iter()
            .position(|&a| a == ch)
            .ok_or(IdError::BadCharacter)?;
        buffer = (buffer << 5) | v as u64;
        bits += 5;
        if bits >= 8 {
            out.push(((buffer >> (bits - 8)) & 255) as u8);
            bits -= 8;
        }
    }
    Ok(out)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdError {
    BadCharacter,
    BadPrefix,
    BadLength,
    BadChecksum,
}

impl std::fmt::Display for IdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            IdError::BadCharacter => "invalid base32 character",
            IdError::BadPrefix => "Stonechat IDs start with SC-",
            IdError::BadLength => "that ID has the wrong length",
            IdError::BadChecksum => "checksum mismatch",
        })
    }
}

impl std::error::Error for IdError {}

fn grouped(b32: &str) -> String {
    let groups: Vec<&str> = b32
        .as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect();
    format!("SC-{}", groups.join("-"))
}

/// Derive the ID an Ed25519 identity public key commits to.
pub fn derive_stonechat_id(pubkey: &[u8]) -> String {
    let hash = hash_var(pubkey, 20);
    let check = hash_var(&hash, 16);
    let mut payload = hash;
    payload.push(check[0]);
    payload.push(check[1]);
    grouped(&base32_encode(&payload))
}

/// Canonicalize user input (case, spacing, hyphens) and verify the checksum.
pub fn normalize_stonechat_id(raw: &str) -> Result<String, IdError> {
    let compact: String = raw
        .trim()
        .to_uppercase()
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect();
    let b32 = compact.strip_prefix("SC").ok_or(IdError::BadPrefix)?;
    if b32.len() != 36 {
        return Err(IdError::BadLength);
    }
    let payload = base32_decode(b32)?;
    let check = hash_var(&payload[..20], 16);
    if payload[20] != check[0] || payload[21] != check[1] {
        return Err(IdError::BadChecksum);
    }
    Ok(grouped(b32))
}

/// Any identity key we're handed must hash back to the ID it claims.
pub fn pubkey_matches_id(pubkey: &[u8], stonechat_id: &str) -> bool {
    derive_stonechat_id(pubkey) == stonechat_id
}
