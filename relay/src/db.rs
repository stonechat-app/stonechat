//! SQLite-backed envelope queue + prekey/push-config store. Rows die on ack.
//!
//! Schema is byte-identical to the retired Python relay's — the cutover
//! guarantee (RUST_PORT.md) was that a Rust relay pointed at a volume
//! Python wrote serves the queued mail it left there; keep it true for any
//! long-lived volumes.

use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension};
use serde_json::Value;

use crate::{MAX_KOPKS, MAX_OPKS, MAX_QUEUE_DEPTH};

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
               pub TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS kem_signed_prekey (
               row INTEGER PRIMARY KEY CHECK (row = 1),
               id INTEGER NOT NULL,
               pub TEXT NOT NULL,
               sig TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS kem_one_time_prekeys (
               id INTEGER PRIMARY KEY,
               pub TEXT NOT NULL);",
        )?;
        Ok(Self { db: Mutex::new(db) })
    }

    /// Owner upload: replace the SPK/KSPK and the whole OPK/KOPK stock. The
    /// owner is the source of truth for which private halves it still holds
    /// — merge semantics kept keys from a previous install alive forever,
    /// handing senders bundles the owner could no longer decrypt.
    pub fn set_prekeys(
        &self,
        spk: &SpkUpload,
        opks: &[OpkUpload],
        kspk: &SpkUpload,
        kopks: &[OpkUpload],
    ) {
        let db = self.db.lock().unwrap();
        for (table, signed) in [("signed_prekey", spk), ("kem_signed_prekey", kspk)] {
            db.execute(
                &format!(
                    "INSERT INTO {table} (row, id, pub, sig) VALUES (1, ?1, ?2, ?3)
                     ON CONFLICT(row) DO UPDATE SET id=excluded.id,
                     pub=excluded.pub, sig=excluded.sig"
                ),
                params![signed.id, signed.pub_key, signed.sig],
            )
            .unwrap();
        }
        db.execute("DELETE FROM one_time_prekeys", []).unwrap();
        for opk in opks.iter().take(MAX_OPKS) {
            db.execute(
                "INSERT OR IGNORE INTO one_time_prekeys (id, pub) VALUES (?1, ?2)",
                params![opk.id, opk.pub_key],
            )
            .unwrap();
        }
        db.execute("DELETE FROM kem_one_time_prekeys", []).unwrap();
        for kopk in kopks.iter().take(MAX_KOPKS) {
            db.execute(
                "INSERT OR IGNORE INTO kem_one_time_prekeys (id, pub) VALUES (?1, ?2)",
                params![kopk.id, kopk.pub_key],
            )
            .unwrap();
        }
    }

    /// The prekey bundle for a sender starting a session. Consumes the
    /// returned one-time prekeys (X25519 and ML-KEM independently) — each
    /// is handed out at most once. No bundle until both signed halves are
    /// published: PQXDH has no classical-only fallback.
    pub fn take_bundle(&self) -> Option<Value> {
        let db = self.db.lock().unwrap();
        let signed = |table: &str| -> Option<(i64, String, String)> {
            db.query_row(
                &format!("SELECT id, pub, sig FROM {table} WHERE row = 1"),
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .unwrap()
        };
        let (spk_id, spk_pub, spk_sig) = signed("signed_prekey")?;
        let (kspk_id, kspk_pub, kspk_sig) = signed("kem_signed_prekey")?;
        let take_one = |table: &str| -> Option<(i64, String)> {
            let one: Option<(i64, String)> = db
                .query_row(
                    &format!("SELECT id, pub FROM {table} ORDER BY id LIMIT 1"),
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()
                .unwrap();
            if let Some((id, _)) = &one {
                db.execute(&format!("DELETE FROM {table} WHERE id = ?1"), params![id])
                    .unwrap();
            }
            one
        };
        let opk = take_one("one_time_prekeys");
        let kopk = take_one("kem_one_time_prekeys");
        Some(serde_json::json!({
            "spk": {"id": spk_id, "pub": spk_pub, "sig": spk_sig},
            "opk": opk.map(|(id, pub_key)| serde_json::json!({"id": id, "pub": pub_key})),
            "kspk": {"id": kspk_id, "pub": kspk_pub, "sig": kspk_sig},
            "kopk": kopk.map(|(id, pub_key)| serde_json::json!({"id": id, "pub": pub_key})),
        }))
    }

    pub fn prekey_status(&self) -> Value {
        let db = self.db.lock().unwrap();
        let count = |sql: &str| -> i64 { db.query_row(sql, [], |r| r.get(0)).unwrap() };
        let has_spk = count("SELECT COUNT(*) FROM signed_prekey") > 0;
        let opks = count("SELECT COUNT(*) FROM one_time_prekeys");
        let has_kspk = count("SELECT COUNT(*) FROM kem_signed_prekey") > 0;
        let kopks = count("SELECT COUNT(*) FROM kem_one_time_prekeys");
        serde_json::json!({"spk": has_spk, "opks": opks, "kspk": has_kspk, "kopks": kopks})
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
