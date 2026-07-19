//! Encrypted media blobs, held only until their envelope is acked.
//! Plain files on disk; the server can't decrypt them (secretbox key travels
//! inside the envelope ciphertext).
//!
//! Differences from server/main.py, per RUST_PORT.md "Permitted
//! improvements": used-bytes is tracked incrementally (one scan at boot)
//! instead of re-stat()ing the whole directory on every upload, and TTL GC
//! runs on a timer plus on-demand when the cap would reject an upload —
//! same limits, same status codes.

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::SystemTime;

use crate::{BLOB_TTL, MAX_TOTAL_BLOB_BYTES};

pub fn valid_blob_id(id: &str) -> bool {
    // Python: ^[a-f0-9-]{36}$
    id.len() == 36 && id.bytes().all(|b| matches!(b, b'a'..=b'f' | b'0'..=b'9' | b'-'))
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
    use super::valid_blob_id;

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
