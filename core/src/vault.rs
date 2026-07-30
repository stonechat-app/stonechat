//! Passphrase-protected containers: the encrypted backup file
//! (`.stonechatbackup`) and the identity export string behind a QR code.
//! Both are local artifacts — never on the wire — so they share one
//! self-describing format instead of the two libsodium constructions
//! (`secretbox` and `secretstream`) the app used before the core existed.
//!
//! ```text
//! offset size  field
//! 0      1     format version (2)
//! 1      1     kdf id (1 = Argon2id, v19)
//! 2      4     m_cost, KiB, little-endian
//! 6      4     t_cost, little-endian
//! 10     1     salt length (16)
//! 11     16    salt
//! 27     24    nonce
//! 51     —     XChaCha20-Poly1305(payload), ad = the 51-byte header
//! ```
//!
//! The header is the AEAD's associated data, so tampering with the KDF
//! parameters is a decryption failure rather than a silent downgrade —
//! the one thing the old format left unauthenticated. Parameters are read
//! back from the container, never from current constants, so they can be
//! raised later without a format bump.

use argon2::{Algorithm, Argon2, Params, Version};

use crate::primitives::{AEAD_NONCE_BYTES, AEAD_TAG_BYTES, aead_open, aead_seal};

pub const FORMAT_VERSION: u8 = 2;
pub const KDF_ARGON2ID: u8 = 1;
pub const SALT_BYTES: usize = 16;
pub const HEADER_BYTES: usize = 51;

/// Defaults matching libsodium's "moderate" profile, which is what the
/// app asked for before: 256 MiB, 3 passes.
pub const DEFAULT_M_COST_KIB: u32 = 256 * 1024;
pub const DEFAULT_T_COST: u32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultError {
    /// Not one of our containers (bad magic/length).
    Malformed,
    /// A newer format version — the caller should ask the user to update.
    UnsupportedVersion,
    /// Wrong passphrase, or the container was tampered with. Deliberately
    /// one outcome: they are indistinguishable to the AEAD, and "wrong
    /// passphrase" is the message worth showing either way.
    WrongPassphrase,
    /// KDF parameters outside anything we will spend memory on.
    UnreasonableParameters,
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            VaultError::Malformed => "not a Stonechat container",
            VaultError::UnsupportedVersion => "created by a newer version of Stonechat",
            VaultError::WrongPassphrase => "wrong passphrase, or the file is damaged",
            VaultError::UnreasonableParameters => "unreasonable KDF parameters",
        })
    }
}

impl std::error::Error for VaultError {}

fn derive_key(
    passphrase: &[u8],
    salt: &[u8],
    m_cost_kib: u32,
    t_cost: u32,
) -> Result<[u8; 32], VaultError> {
    // Refuse to be talked into an OOM by a crafted header, and refuse
    // parameters too weak to be worth calling a KDF.
    if !(8 * 1024..=1024 * 1024).contains(&m_cost_kib) || !(1..=10).contains(&t_cost) {
        return Err(VaultError::UnreasonableParameters);
    }
    let params = Params::new(m_cost_kib, t_cost, 1, Some(32))
        .map_err(|_| VaultError::UnreasonableParameters)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon
        .hash_password_into(passphrase, salt, &mut key)
        .map_err(|_| VaultError::UnreasonableParameters)?;
    Ok(key)
}

fn header(
    m_cost_kib: u32,
    t_cost: u32,
    salt: &[u8; SALT_BYTES],
    nonce: &[u8; AEAD_NONCE_BYTES],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_BYTES);
    out.push(FORMAT_VERSION);
    out.push(KDF_ARGON2ID);
    out.extend_from_slice(&m_cost_kib.to_le_bytes());
    out.extend_from_slice(&t_cost.to_le_bytes());
    out.push(SALT_BYTES as u8);
    out.extend_from_slice(salt);
    out.extend_from_slice(nonce);
    out
}

/// Encrypt `plaintext` under `passphrase`. `salt` and `nonce` must be
/// fresh CSPRNG output (caller-supplied, like everywhere in this crate).
pub fn seal(
    passphrase: &[u8],
    plaintext: &[u8],
    salt: &[u8; SALT_BYTES],
    nonce: &[u8; AEAD_NONCE_BYTES],
    m_cost_kib: u32,
    t_cost: u32,
) -> Result<Vec<u8>, VaultError> {
    let key = derive_key(passphrase, salt, m_cost_kib, t_cost)?;
    let head = header(m_cost_kib, t_cost, salt, nonce);
    let mut out = head.clone();
    out.extend_from_slice(&aead_seal(&key, nonce, plaintext, &head));
    Ok(out)
}

/// Decrypt a container, deriving the key from ITS parameters.
pub fn open(passphrase: &[u8], container: &[u8]) -> Result<Vec<u8>, VaultError> {
    if container.len() < HEADER_BYTES + AEAD_TAG_BYTES {
        return Err(VaultError::Malformed);
    }
    if container[0] > FORMAT_VERSION {
        return Err(VaultError::UnsupportedVersion);
    }
    if container[0] != FORMAT_VERSION
        || container[1] != KDF_ARGON2ID
        || container[10] as usize != SALT_BYTES
    {
        return Err(VaultError::Malformed);
    }
    let m_cost_kib = u32::from_le_bytes(container[2..6].try_into().unwrap());
    let t_cost = u32::from_le_bytes(container[6..10].try_into().unwrap());
    let salt: [u8; SALT_BYTES] = container[11..11 + SALT_BYTES].try_into().unwrap();
    let nonce: [u8; AEAD_NONCE_BYTES] = container[27..27 + AEAD_NONCE_BYTES].try_into().unwrap();
    let key = derive_key(passphrase, &salt, m_cost_kib, t_cost)?;
    aead_open(
        &key,
        &nonce,
        &container[HEADER_BYTES..],
        &container[..HEADER_BYTES],
    )
    .ok_or(VaultError::WrongPassphrase)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Keep test runs quick: the shape is what matters here, and the
    // production parameters are exercised by the app's own tests.
    const M: u32 = 8 * 1024;
    const T: u32 = 1;

    #[test]
    fn round_trips() {
        let sealed = seal(b"correct horse", b"payload", &[7; 16], &[9; 24], M, T).unwrap();
        assert_eq!(open(b"correct horse", &sealed).unwrap(), b"payload");
    }

    #[test]
    fn wrong_passphrase_is_one_error() {
        let sealed = seal(b"right", b"payload", &[7; 16], &[9; 24], M, T).unwrap();
        assert_eq!(open(b"wrong", &sealed), Err(VaultError::WrongPassphrase));
    }

    #[test]
    fn header_is_authenticated() {
        // Downgrading the KDF parameters must fail loudly, not silently.
        let mut sealed = seal(b"pw", b"payload", &[7; 16], &[9; 24], M, T).unwrap();
        sealed[2..6].copy_from_slice(&(8u32 * 1024).to_le_bytes());
        sealed[6..10].copy_from_slice(&2u32.to_le_bytes());
        assert!(open(b"pw", &sealed).is_err());
    }

    #[test]
    fn rejects_garbage_and_future_versions() {
        assert_eq!(open(b"pw", b"short"), Err(VaultError::Malformed));
        let mut sealed = seal(b"pw", b"payload", &[7; 16], &[9; 24], M, T).unwrap();
        sealed[0] = FORMAT_VERSION + 1;
        assert_eq!(open(b"pw", &sealed), Err(VaultError::UnsupportedVersion));
    }

    #[test]
    fn refuses_absurd_memory_costs() {
        // A crafted container must not be able to demand gigabytes.
        let mut sealed = seal(b"pw", b"payload", &[7; 16], &[9; 24], M, T).unwrap();
        sealed[2..6].copy_from_slice(&(4u32 * 1024 * 1024).to_le_bytes());
        assert_eq!(
            open(b"pw", &sealed),
            Err(VaultError::UnreasonableParameters)
        );
    }
}
