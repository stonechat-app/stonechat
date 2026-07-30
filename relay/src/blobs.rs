//! Encrypted media blobs, held only until their envelope is acked.
//! Plain files on disk; the server can't decrypt them (secretbox key travels
//! inside the envelope ciphertext).
//!
//! Differences from the retired Python relay, per RUST_PORT.md "Permitted
//! improvements": used-bytes is tracked incrementally (one scan at boot)
//! instead of re-stat()ing the whole directory on every upload, and TTL GC
//! runs on a timer plus on-demand when the cap would reject an upload —
//! same limits, same status codes.

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::SystemTime;

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};

use crate::{BLOB_TTL, MAX_TOTAL_BLOB_BYTES};

type Blake2b256 = Blake2b<U32>;

pub fn valid_blob_id(id: &str) -> bool {
    // Python: ^[a-f0-9-]{36}$
    id.len() == 36 && id.bytes().all(|b| matches!(b, b'a'..=b'f' | b'0'..=b'9' | b'-'))
}

/// Per-blob read capability, for group media (PROTOCOL.md "Groups").
///
/// A group sender parks *one* ciphertext on their own mailbox and hands every
/// member this token inside the (already encrypted) envelope. It grants read
/// on exactly one blob and nothing else — members never see the owner token,
/// and knowing one blob's token says nothing about another's.
///
/// Blake2b is not length-extendable, so `H(key || msg)` is a sound MAC and we
/// avoid pulling in HMAC/SHA-2 for it. Derived, never stored: the relay keeps
/// no per-blob row, and a token stays valid exactly as long as the blob does.
pub fn fetch_token(owner_token: &str, blob_id: &str) -> String {
    let mut h = Blake2b256::new();
    h.update(owner_token.as_bytes());
    h.update(b"|stonechat-blob-fetch|");
    h.update(blob_id.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// Length-independent, byte-constant-time string compare — token checks must
/// not leak a prefix through timing.
pub fn secret_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

pub enum PutError {
    StorageFull, // 507
}

pub struct BlobStore {
    root: PathBuf,
    used: Mutex<u64>,
}

impl BlobStore {
    pub fn open(root: &PathBuf) -> std::io::Result<Self> {
        std::fs::create_dir_all(root)?;
        let mut used = 0u64;
        for entry in std::fs::read_dir(root)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                used += entry.metadata()?.len();
            }
        }
        Ok(Self { root: root.clone(), used: Mutex::new(used) })
    }

    pub fn put(&self, data: &[u8]) -> Result<String, PutError> {
        {
            let used = *self.used.lock().unwrap();
            if used + data.len() as u64 > MAX_TOTAL_BLOB_BYTES {
                // Expired blobs might free enough — Python GC'd on every put,
                // we only pay that walk when the cap actually bites.
                self.collect_garbage();
                let used = *self.used.lock().unwrap();
                if used + data.len() as u64 > MAX_TOTAL_BLOB_BYTES {
                    return Err(PutError::StorageFull);
                }
            }
        }
        let blob_id = uuid::Uuid::new_v4().to_string();
        std::fs::write(self.root.join(&blob_id), data).map_err(|_| PutError::StorageFull)?;
        *self.used.lock().unwrap() += data.len() as u64;
        Ok(blob_id)
    }

    /// `None` = no such blob (or malformed id) → 404 upstream.
    pub fn get(&self, blob_id: &str) -> Option<Vec<u8>> {
        if !valid_blob_id(blob_id) {
            return None;
        }
        std::fs::read(self.root.join(blob_id)).ok()
    }

    pub fn delete(&self, blob_id: &str) {
        if !valid_blob_id(blob_id) {
            return; // malformed id in an old envelope — nothing to delete
        }
        let path = self.root.join(blob_id);
        if let Ok(meta) = std::fs::metadata(&path) {
            if std::fs::remove_file(&path).is_ok() {
                let mut used = self.used.lock().unwrap();
                *used = used.saturating_sub(meta.len());
            }
        }
    }

    pub fn collect_garbage(&self) {
        let cutoff = SystemTime::now() - BLOB_TTL;
        let Ok(entries) = std::fs::read_dir(&self.root) else { return };
        for entry in entries.flatten() {
            let Ok(meta) = entry.metadata() else { continue };
            if !meta.is_file() {
                continue;
            }
            let expired = meta.modified().map(|m| m < cutoff).unwrap_or(false);
            if expired && std::fs::remove_file(entry.path()).is_ok() {
                let mut used = self.used.lock().unwrap();
                *used = used.saturating_sub(meta.len());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{fetch_token, secret_eq, valid_blob_id};

    #[test]
    fn fetch_token_is_derived_and_scoped() {
        let a = "123e4567-e89b-42d3-a456-426614174000";
        let b = "223e4567-e89b-42d3-a456-426614174000";
        // Deterministic: no per-blob state to lose across restarts.
        assert_eq!(fetch_token("tok-secret", a), fetch_token("tok-secret", a));
        assert_eq!(fetch_token("tok-secret", a).len(), 64);
        // One blob's token opens nothing else, and no mailbox's token opens another's.
        assert_ne!(fetch_token("tok-secret", a), fetch_token("tok-secret", b));
        assert_ne!(fetch_token("tok-secret", a), fetch_token("tok-other", a));
        // Never equal to the owner token it is derived from.
        assert_ne!(fetch_token("tok-secret", a), "tok-secret");
    }

    #[test]
    fn secret_eq_matches_plain_eq() {
        assert!(secret_eq("abc", "abc"));
        assert!(!secret_eq("abc", "abd"));
        assert!(!secret_eq("abc", "ab")); // length mismatch, no panic
        assert!(!secret_eq("", "x"));
        assert!(secret_eq("", ""));
    }

    #[test]
    fn blob_id_shape() {
        assert!(valid_blob_id("123e4567-e89b-42d3-a456-426614174000"));
        assert!(!valid_blob_id("123E4567-E89B-42D3-A456-426614174000")); // upper
        assert!(!valid_blob_id("../../../../../../etc/passwd-xxxxxxxx")); // traversal
        assert!(!valid_blob_id("123e4567-e89b-42d3-a456-42661417400")); // 35
        assert!(!valid_blob_id("123e4567-e89b-42d3-a456-4266141740000")); // 37
        assert!(!valid_blob_id(""));
    }
}
