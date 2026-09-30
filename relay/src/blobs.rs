//! Encrypted media blobs, held only until their envelope is acked.
//! Plain files on disk; the server can't decrypt them (secretbox key travels
//! inside the envelope ciphertext).
//!
//! Differences from the retired Python relay: used-bytes is tracked
//! incrementally (one scan at boot) instead of re-stat()ing the whole
//! directory on every upload, and TTL GC runs on a timer plus on-demand when
//! the cap would reject an upload — same limits, same status codes.
//!
//! **Blobs stream; they are never held whole in memory.** A blob is up to
//! MAX_BLOB_BYTES (64 MiB) and a mailbox container runs under a cgroup cap, so
//! buffering one would put peak RSS at the mercy of how many transfers happen
//! to overlap — a few concurrent group-media fetches of one video would OOM the
//! mailbox. Both directions move in 64 KiB chunks instead, which keeps relay
//! memory flat in blob size and is what lets the per-mailbox memory cap be set
//! from steady state rather than from the worst case.
//!
//! Uploads land in `incoming/` and are renamed into place only once complete,
//! so a truncated upload can never be served as a blob: `valid_blob_id` shapes
//! the public names, and a rename within one filesystem is atomic. That
//! subdirectory is also why the boot scan and the GC walk test `is_file()` —
//! both skip it, so partials count against neither the used-bytes total nor
//! the TTL sweep.

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::SystemTime;

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use tokio::io::AsyncWriteExt;

use crate::{BLOB_TTL, MAX_TOTAL_BLOB_BYTES};

/// Where partial uploads live until they are complete. A name `valid_blob_id`
/// rejects, so it can never be addressed as a blob even if it were served.
const INCOMING_DIR: &str = "incoming";

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

/// An upload in progress: a file under `incoming/` plus what has landed in it.
///
/// Dropping one without committing deletes the partial, so every abandoned
/// upload — client vanished mid-stream, blob too large, storage full — cleans
/// up on the way out of the handler with no separate reaper to get wrong.
pub struct Incoming {
    path: PathBuf,
    file: Option<tokio::fs::File>,
    len: u64,
    committed: bool,
}

impl Incoming {
    pub async fn write(&mut self, chunk: &[u8]) -> std::io::Result<()> {
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| std::io::Error::other("write after commit"))?;
        file.write_all(chunk).await?;
        self.len += chunk.len() as u64;
        Ok(())
    }

    pub fn len(&self) -> u64 {
        self.len
    }
}

impl Drop for Incoming {
    fn drop(&mut self) {
        if !self.committed {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

pub struct BlobStore {
    root: PathBuf,
    used: Mutex<u64>,
}

impl BlobStore {
    pub fn open(root: &PathBuf) -> std::io::Result<Self> {
        std::fs::create_dir_all(root)?;
        let incoming = root.join(INCOMING_DIR);
        std::fs::create_dir_all(&incoming)?;
        // Anything still in here is a partial from a process that died
        // mid-upload: no id was ever handed out for it, so nothing can refer
        // to it and it is pure leak. Cleared at boot rather than on a timer.
        if let Ok(entries) = std::fs::read_dir(&incoming) {
            for entry in entries.flatten() {
                let _ = std::fs::remove_file(entry.path());
            }
        }
        let mut used = 0u64;
        for entry in std::fs::read_dir(root)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                used += entry.metadata()?.len();
            }
        }
        Ok(Self { root: root.clone(), used: Mutex::new(used) })
    }

    /// Would `len` more bytes fit? GCs once before saying no, exactly as the
    /// old whole-buffer `put` did — Python GC'd on every put, we only pay that
    /// walk when the cap actually bites.
    ///
    /// Advisory when called before a body is read (Content-Length can lie, and
    /// concurrent uploads race), which is why `commit` checks again with the
    /// byte count that actually landed. Checking here too means an oversized
    /// upload is refused before it is streamed to disk rather than after.
    pub fn has_room(&self, len: u64) -> bool {
        let fits = |used: u64| used + len <= MAX_TOTAL_BLOB_BYTES;
        if fits(*self.used.lock().unwrap()) {
            return true;
        }
        self.collect_garbage();
        fits(*self.used.lock().unwrap())
    }

    /// Open a staging file for an upload whose length is not yet known.
    pub async fn begin(&self) -> std::io::Result<Incoming> {
        let path = self.root.join(INCOMING_DIR).join(uuid::Uuid::new_v4().to_string());
        let file = tokio::fs::File::create(&path).await?;
        Ok(Incoming { path, file: Some(file), len: 0, committed: false })
    }

    /// Publish a completed upload under a fresh blob id.
    ///
    /// The cap is re-checked here against the bytes that actually arrived: a
    /// client that understated Content-Length gets its upload rejected at the
    /// end rather than storing more than the cap allows.
    pub async fn commit(&self, mut inc: Incoming) -> Result<String, PutError> {
        // Flush and close before the rename: the bytes must be in the file,
        // not in a buffer, by the time the blob is addressable.
        if let Some(mut file) = inc.file.take() {
            file.flush().await.map_err(|_| PutError::StorageFull)?;
        }
        if !self.has_room(inc.len) {
            return Err(PutError::StorageFull); // Drop removes the partial
        }
        let blob_id = uuid::Uuid::new_v4().to_string();
        std::fs::rename(&inc.path, self.root.join(&blob_id))
            .map_err(|_| PutError::StorageFull)?;
        *self.used.lock().unwrap() += inc.len;
        inc.committed = true;
        Ok(blob_id)
    }

    /// The open file and its length, for streaming a download.
    /// `None` = no such blob (or malformed id) → 404 upstream.
    pub async fn open_read(&self, blob_id: &str) -> Option<(tokio::fs::File, u64)> {
        if !valid_blob_id(blob_id) {
            return None;
        }
        let file = tokio::fs::File::open(self.root.join(blob_id)).await.ok()?;
        let len = file.metadata().await.ok()?.len();
        Some((file, len))
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
