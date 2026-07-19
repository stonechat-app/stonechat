//! SQLite-backed envelope queue + prekey/push-config store. Rows die on ack.
//!
//! Schema is byte-identical to server/main.py's — a Rust relay pointed at a
//! volume Python wrote must serve the queued mail it left there (that is the
//! canary/rollback guarantee in RUST_PORT.md).

use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension};
use serde_json::Value;

use crate::{MAX_OPKS, MAX_QUEUE_DEPTH};

pub struct SpkUpload {
    pub id: i64,
    pub pub_key: String,
    pub sig: String,
}

pub struct OpkUpload {
    pub id: i64,
    pub pub_key: String,
}

pub struct Mailbox {
    db: Mutex<Connection>,
}

impl Mailbox {
    pub fn open(path: &str) -> rusqlite::Result<Self> {
        let db = Connection::open(path)?;
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS envelopes (
               id TEXT PRIMARY KEY,
               body TEXT NOT NULL,
               received_at TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS push_config (
               id INTEGER PRIMARY KEY CHECK (id = 1),
               device_token TEXT NOT NULL,
               platform TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS signed_prekey (
               row INTEGER PRIMARY KEY CHECK (row = 1),
               id INTEGER NOT NULL,
               pub TEXT NOT NULL,
               sig TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS one_time_prekeys (
               id INTEGER PRIMARY KEY,
               pub TEXT NOT NULL);",
        )?;
        Ok(Self { db: Mutex::new(db) })
    }

    /// Owner upload: replace the SPK and the whole OPK stock. The owner is
    /// the source of truth for which private halves it still holds — merge
    /// semantics kept keys from a previous install alive forever, handing
    /// senders bundles the owner could no longer decrypt.
    pub fn set_prekeys(&self, spk: &SpkUpload, opks: &[OpkUpload]) {
        let db = self.db.lock().unwrap();
        db.execute(
            "INSERT INTO signed_prekey (row, id, pub, sig) VALUES (1, ?1, ?2, ?3)
             ON CONFLICT(row) DO UPDATE SET id=excluded.id,
             pub=excluded.pub, sig=excluded.sig",
            params![spk.id, spk.pub_key, spk.sig],
        )
        .unwrap();
        db.execute("DELETE FROM one_time_prekeys", []).unwrap();
        for opk in opks.iter().take(MAX_OPKS) {
            db.execute(
                "INSERT OR IGNORE INTO one_time_prekeys (id, pub) VALUES (?1, ?2)",
                params![opk.id, opk.pub_key],
            )
            .unwrap();
        }
    }

    /// The prekey bundle for a sender starting a session. Consumes the
    /// returned one-time prekey — each is handed out at most once.
    pub fn take_bundle(&self) -> Option<Value> {
        let db = self.db.lock().unwrap();
        let spk: Option<(i64, String, String)> = db
            .query_row(
                "SELECT id, pub, sig FROM signed_prekey WHERE row = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .unwrap();
        let (spk_id, spk_pub, spk_sig) = spk?;
        let opk: Option<(i64, String)> = db
            .query_row(
                "SELECT id, pub FROM one_time_prekeys ORDER BY id LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .unwrap();
        if let Some((opk_id, _)) = &opk {
            db.execute("DELETE FROM one_time_prekeys WHERE id = ?1", params![opk_id])
                .unwrap();
        }
        Some(serde_json::json!({
            "spk": {"id": spk_id, "pub": spk_pub, "sig": spk_sig},
            "opk": opk.map(|(id, pub_key)| serde_json::json!({"id": id, "pub": pub_key})),
        }))
    }

    pub fn prekey_status(&self) -> Value {
        let db = self.db.lock().unwrap();
        let has_spk: i64 = db
            .query_row("SELECT COUNT(*) FROM signed_prekey", [], |r| r.get(0))
            .unwrap();
        let opks: i64 = db
            .query_row("SELECT COUNT(*) FROM one_time_prekeys", [], |r| r.get(0))
            .unwrap();
        serde_json::json!({"spk": has_spk > 0, "opks": opks})
    }

    pub fn set_push_config(&self, device_token: &str, platform: &str) {
        let db = self.db.lock().unwrap();
        db.execute(
            "INSERT INTO push_config (id, device_token, platform) VALUES (1, ?1, ?2)
             ON CONFLICT(id) DO UPDATE SET device_token=excluded.device_token,
             platform=excluded.platform",
            params![device_token, platform],
        )
        .unwrap();
    }

    pub fn push_config(&self) -> Option<(String, String)> {
        let db = self.db.lock().unwrap();
        db.query_row(
            "SELECT device_token, platform FROM push_config WHERE id = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .unwrap()
    }

    /// Queue an envelope. `false` means the mailbox is full. Duplicate ids
    /// are silently ignored (INSERT OR IGNORE) — idempotent delivery.
    pub fn put(&self, envelope: &Value) -> bool {
        let db = self.db.lock().unwrap();
        let depth: i64 = db
            .query_row("SELECT COUNT(*) FROM envelopes", [], |r| r.get(0))
            .unwrap();
        if depth >= MAX_QUEUE_DEPTH {
            return false;
        }
        db.execute(
            "INSERT OR IGNORE INTO envelopes (id, body, received_at) VALUES (?1, ?2, ?3)",
            params![
                envelope["id"].as_str().unwrap(),
                serde_json::to_string(envelope).unwrap(),
                chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, false),
            ],
        )
        .unwrap();
        true
    }

    /// All queued envelope bodies, oldest first (the /ws drain order).
    pub fn all(&self) -> Vec<String> {
        let db = self.db.lock().unwrap();
        let mut stmt = db
            .prepare("SELECT body FROM envelopes ORDER BY received_at")
            .unwrap();
        let rows = stmt.query_map([], |r| r.get::<_, String>(0)).unwrap();
        rows.map(|r| r.unwrap()).collect()
    }

    pub fn has(&self, envelope_id: &str) -> bool {
        let db = self.db.lock().unwrap();
        db.query_row(
            "SELECT 1 FROM envelopes WHERE id = ?1",
            params![envelope_id],
            |_| Ok(()),
        )
        .optional()
        .unwrap()
        .is_some()
    }

    /// Delete an acked envelope; returns its blob_id if it referenced one
    /// (the caller deletes the blob file — AppState::delete_envelope).
    pub fn delete(&self, envelope_id: &str) -> Option<String> {
        let db = self.db.lock().unwrap();
        let body: Option<String> = db
            .query_row(
                "SELECT body FROM envelopes WHERE id = ?1",
                params![envelope_id],
                |r| r.get(0),
            )
            .optional()
            .unwrap();
        db.execute("DELETE FROM envelopes WHERE id = ?1", params![envelope_id])
            .unwrap();
        let body = body?;
        serde_json::from_str::<Value>(&body)
            .ok()?
            .get("blob_id")?
            .as_str()
            .map(str::to_string)
    }

    pub fn depth(&self) -> i64 {
        let db = self.db.lock().unwrap();
        db.query_row("SELECT COUNT(*) FROM envelopes", [], |r| r.get(0))
            .unwrap()
    }
}
