//! SQLite-backed envelope queue + prekey/push-config store. Rows die on ack.
//!
//! The device dimension runs through almost every table: one queue, one
//! prekey pool and one push registration per device.
//! Pre-launch, so there is no schema migration — the tables are created as
//! they are meant to be, and an older volume is wiped rather than upgraded.

use std::collections::HashMap;
use std::sync::Mutex;

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::Value;

use crate::{MAX_KOPKS, MAX_OPKS, MAX_QUEUE_DEPTH};

/// What became of an envelope handed to [`Mailbox::put`].
#[derive(Debug, PartialEq, Eq)]
pub enum Put {
    /// A new row. The caller delivers and wakes.
    Queued,
    /// This device already holds this id. Nothing was written, and nothing
    /// may be delivered or woken for: a retry is answered, not repeated.
    Duplicate,
    /// The device's queue is at its row or byte cap.
    Full,
}

/// How much one device's queue holds. Kept in memory because the byte cap is
/// checked on every deposit, and asking SQLite for `SUM(LENGTH(body))` reads
/// every queued body to answer.
#[derive(Default, Clone, Copy)]
struct Usage {
    rows: i64,
    bytes: u64,
}

struct QueueState {
    /// The rowid the next envelope gets. Assigned here rather than left to
    /// SQLite, which hands out `max(rowid) + 1` and so *reuses* a number once
    /// the newest row is acked — and a drain cursor that has already passed
    /// that number would skip the envelope that inherited it.
    next_seq: i64,
    usage: HashMap<i64, Usage>,
}

type Blake2b256 = Blake2b<U32>;

/// The bootstrap device: provisioning mints one credential, and the device
/// holding it is device 1. `STONECHAT_OWNER_TOKEN` is its token, which is what
/// makes the hub's `mailbox_token` handoff a device login without needing a
/// second concept.
pub const PRIMARY_DEVICE: i64 = 1;

/// Device tokens are stored hashed, never in the clear: the DB file is the
/// one artifact a snapshot or a backup of the VM would carry off.
pub fn token_hash(token: &str) -> String {
    let mut h = Blake2b256::new();
    h.update(b"stonechat-device-token|");
    h.update(token.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

pub struct Device {
    pub device_id: i64,
    /// Opaque certificate blob, or null until the device publishes one.
    pub cert: Option<String>,
    /// `primary` (provisioned the mailbox), `linked` (another of the owner's
    /// apps) or `web` (a browser session). Advisory — the protocol treats
    /// devices uniformly; this exists so a device list can be shown honestly
    /// and so a browser session can be given a lifetime.
    pub kind: String,
    pub created_at: String,
    /// RFC-3339, or null for a device that lives until revoked. A web session
    /// is bounded on purpose: the browser is a bad place for
    /// long-lived authority, so its authority expires on its own.
    pub expires_at: Option<String>,
    pub last_seen: Option<String>,
}

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
    /// Locked after `db`, never before it.
    queue: Mutex<QueueState>,
    max_queue_bytes: u64,
}

impl Mailbox {
    pub fn open(path: &str, owner_token: &str, max_queue_bytes: u64) -> rusqlite::Result<Self> {
        let db = Connection::open(path)?;
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS envelopes (
               id TEXT NOT NULL,
               device INTEGER NOT NULL DEFAULT 1,
               body TEXT NOT NULL,
               received_at TEXT NOT NULL,
               PRIMARY KEY (id, device));
             CREATE TABLE IF NOT EXISTS push_config (
               device INTEGER PRIMARY KEY,
               device_token TEXT NOT NULL,
               platform TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS signed_prekey (
               device INTEGER PRIMARY KEY,
               id INTEGER NOT NULL,
               pub TEXT NOT NULL,
               sig TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS one_time_prekeys (
               device INTEGER NOT NULL,
               id INTEGER NOT NULL,
               pub TEXT NOT NULL,
               PRIMARY KEY (device, id));
             CREATE TABLE IF NOT EXISTS kem_signed_prekey (
               device INTEGER PRIMARY KEY,
               id INTEGER NOT NULL,
               pub TEXT NOT NULL,
               sig TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS kem_one_time_prekeys (
               device INTEGER NOT NULL,
               id INTEGER NOT NULL,
               pub TEXT NOT NULL,
               PRIMARY KEY (device, id));
             CREATE TABLE IF NOT EXISTS devices (
               device_id INTEGER PRIMARY KEY,
               token_hash TEXT NOT NULL UNIQUE,
               kind TEXT NOT NULL DEFAULT 'primary',
               created_at TEXT NOT NULL,
               expires_at TEXT,
               last_seen TEXT,
               -- The device's certificate, signed by its owner's identity
               -- root (core/src/devcert.rs). Stored opaque and served
               -- verbatim: the relay has no idea what is in it and no way to
               -- check it — the owner's identity key lives on their primary,
               -- and verification happens at the far end, on the sender's
               -- device, against a key from the directory. A relay that
               -- validated certificates would be a relay you had to trust.
               cert TEXT);
             CREATE TABLE IF NOT EXISTS meta (
               key TEXT PRIMARY KEY,
               value TEXT NOT NULL);",
        )?;
        let queue = {
            let next_seq: i64 = db.query_row(
                "SELECT IFNULL(MAX(rowid), 0) + 1 FROM envelopes",
                [],
                |r| r.get(0),
            )?;
            let mut usage: HashMap<i64, Usage> = HashMap::new();
            let mut stmt = db.prepare(
                "SELECT device, COUNT(*), IFNULL(SUM(LENGTH(CAST(body AS BLOB))), 0)
                 FROM envelopes GROUP BY device",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?))
            })?;
            for row in rows {
                let (device, rows, bytes) = row?;
                usage.insert(device, Usage { rows, bytes: bytes as u64 });
            }
            QueueState { next_seq, usage }
        };
        let mailbox = Self {
            db: Mutex::new(db),
            queue: Mutex::new(queue),
            max_queue_bytes,
        };
        mailbox.seed_primary_device(owner_token);
        Ok(mailbox)
    }

    /// Device 1 is `STONECHAT_OWNER_TOKEN`. Re-seeded on every boot so that
    /// rotating the env var rotates the primary's token rather than locking
    /// the owner out of their own mailbox.
    fn seed_primary_device(&self, owner_token: &str) {
        let db = self.db.lock().unwrap();
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, false);
        db.execute(
            "INSERT INTO devices (device_id, token_hash, created_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(device_id) DO UPDATE SET token_hash = excluded.token_hash",
            params![PRIMARY_DEVICE, token_hash(owner_token), now],
        )
        .unwrap();
        db.execute(
            "INSERT OR IGNORE INTO meta (key, value) VALUES ('devices_v', '1')",
            [],
        )
        .unwrap();
    }

    /// Devices whose lifetime has run out. Revoking them is the caller's job
    /// (it drops queues and bumps devices_v), which is what makes a web
    /// session end by itself rather than merely stop being shown.
    pub fn expired_devices(&self) -> Vec<i64> {
        let db = self.db.lock().unwrap();
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, false);
        let mut stmt = db
            .prepare(
                "SELECT device_id FROM devices
                 WHERE expires_at IS NOT NULL AND expires_at < ?1",
            )
            .unwrap();
        let rows = stmt.query_map(params![now], |r| r.get(0)).unwrap();
        rows.map(|r| r.unwrap()).collect()
    }

    // -- devices -------------------------------------------------------------

    /// Which device is presenting this token, if any. The only authentication
    /// the relay has: possession of a device token is being that device.
    ///
    /// An expired device authenticates as nobody. The timed sweep revokes it
    /// properly (queues, prekeys, devices_v), but authority has to end at the
    /// deadline rather than at the next sweep.
    pub fn device_for_token(&self, token: &str) -> Option<i64> {
        if token.is_empty() {
            return None;
        }
        let db = self.db.lock().unwrap();
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, false);
        db.query_row(
            "SELECT device_id FROM devices
             WHERE token_hash = ?1 AND (expires_at IS NULL OR expires_at > ?2)",
            params![token_hash(token), now],
            |r| r.get(0),
        )
        .optional()
        .unwrap()
    }

    pub fn devices(&self) -> Vec<Device> {
        let db = self.db.lock().unwrap();
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, false);
        let mut stmt = db
            .prepare(
                "SELECT device_id, kind, created_at, expires_at, last_seen, cert
                 FROM devices
                 WHERE expires_at IS NULL OR expires_at > ?1
                 ORDER BY device_id",
            )
            .unwrap();
        let rows = stmt
            .query_map(params![now], |r| {
                Ok(Device {
                    device_id: r.get(0)?,
                    kind: r.get(1)?,
                    created_at: r.get(2)?,
                    expires_at: r.get(3)?,
                    last_seen: r.get(4)?,
                    cert: r.get(5)?,
                })
            })
            .unwrap();
        rows.map(|r| r.unwrap()).collect()
    }

    /// Monotonic version of the device set. Contacts watch it to know when to
    /// re-fetch a bundle; it never decreases, even if a device is removed.
    pub fn devices_v(&self) -> i64 {
        let db = self.db.lock().unwrap();
        db.query_row("SELECT value FROM meta WHERE key = 'devices_v'", [], |r| {
            r.get::<_, String>(0)
        })
        .optional()
        .unwrap()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1)
    }

    fn bump_devices_v(db: &Connection) {
        db.execute(
            "UPDATE meta SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT)
             WHERE key = 'devices_v'",
            [],
        )
        .unwrap();
    }

    /// Mint a device. Ids are never reused — a revoked device's id stays
    /// spent so a stale envelope addressed to it can never land in a new
    /// device's queue.
    pub fn add_device(&self, token: &str, kind: &str, expires_at: Option<&str>) -> i64 {
        let db = self.db.lock().unwrap();
        // Monotonic, NOT max(device_id)+1: revoking device 2 and minting the
        // next one would otherwise hand the new device the old one's id, and
        // an envelope still in flight to the revoked device would land in the
        // new device's queue — addressed to a session it cannot open, from a
        // sender who thinks it arrived.
        let highest: i64 = db
            .query_row(
                "SELECT IFNULL(MAX(CAST(value AS INTEGER)), 0) FROM meta WHERE key = 'devices_high'",
                [],
                |r| r.get(0),
            )
            .optional()
            .unwrap()
            .unwrap_or(0);
        let existing_max: i64 = db
            .query_row("SELECT IFNULL(MAX(device_id), 0) FROM devices", [], |r| r.get(0))
            .unwrap();
        let next = highest.max(existing_max) + 1;
        db.execute(
            "INSERT INTO meta (key, value) VALUES ('devices_high', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![next.to_string()],
        )
        .unwrap();
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, false);
        db.execute(
            "INSERT INTO devices (device_id, token_hash, kind, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![next, token_hash(token), kind, now, expires_at],
        )
        .unwrap();
        Self::bump_devices_v(&db);
        next
    }

    /// Revoke: the device's queue, prekeys and push registration all go with
    /// it. Returns the blob ids its dropped envelopes referenced so the caller
    /// can release them, and false if there was no such device.
    ///
    /// Device 1 is not revocable. Its token is `STONECHAT_OWNER_TOKEN`, so
    /// removing the row would lock the owner out of their own mailbox until
    /// the next boot re-seeded it. Refused here as well as in the route, so
    /// no later caller can do it by accident.
    pub fn remove_device(&self, device_id: i64) -> (bool, Vec<String>) {
        if device_id == PRIMARY_DEVICE {
            return (false, Vec::new());
        }
        let db = self.db.lock().unwrap();
        let existed = db
            .execute("DELETE FROM devices WHERE device_id = ?1", params![device_id])
            .unwrap()
            > 0;
        if !existed {
            return (false, Vec::new());
        }
        let blob_ids = {
            let mut stmt = db
                .prepare("SELECT body FROM envelopes WHERE device = ?1")
                .unwrap();
            let rows = stmt.query_map(params![device_id], |r| r.get::<_, String>(0)).unwrap();
            rows.filter_map(|body| {
                serde_json::from_str::<Value>(&body.ok()?)
                    .ok()?
                    .get("blob_id")?
                    .as_str()
                    .map(str::to_string)
            })
            .collect()
        };
        for table in [
            "envelopes",
            "push_config",
            "signed_prekey",
            "kem_signed_prekey",
            "one_time_prekeys",
            "kem_one_time_prekeys",
        ] {
            db.execute(
                &format!("DELETE FROM {table} WHERE device = ?1"),
                params![device_id],
            )
            .unwrap();
        }
        Self::bump_devices_v(&db);
        self.queue.lock().unwrap().usage.remove(&device_id);
        (true, blob_ids)
    }

    pub fn touch_device(&self, device_id: i64) {
        let db = self.db.lock().unwrap();
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, false);
        db.execute(
            "UPDATE devices SET last_seen = ?1 WHERE device_id = ?2",
            params![now, device_id],
        )
        .unwrap();
    }

    /// Owner upload: replace the SPK/KSPK and the whole OPK/KOPK stock. The
    /// owner is the source of truth for which private halves it still holds
    /// — merge semantics kept keys from a previous install alive forever,
    /// handing senders bundles the owner could no longer decrypt.
    /// Replacement is scoped to the authenticated device: one device
    /// restocking must never clear a sibling's pool.
    pub fn set_prekeys(
        &self,
        device: i64,
        spk: &SpkUpload,
        opks: &[OpkUpload],
        kspk: &SpkUpload,
        kopks: &[OpkUpload],
        cert: Option<&str>,
    ) {
        let db = self.db.lock().unwrap();
        // A device publishes its own certificate alongside its own prekeys:
        // same operation, same authentication, and the two are useless apart.
        // Absent leaves whatever is stored, so a restock never drops it.
        if let Some(cert) = cert {
            db.execute(
                "UPDATE devices SET cert = ?1 WHERE device_id = ?2",
                params![cert, device],
            )
            .unwrap();
        }
        for (table, signed) in [("signed_prekey", spk), ("kem_signed_prekey", kspk)] {
            db.execute(
                &format!(
                    "INSERT INTO {table} (device, id, pub, sig) VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT(device) DO UPDATE SET id=excluded.id,
                     pub=excluded.pub, sig=excluded.sig"
                ),
                params![device, signed.id, signed.pub_key, signed.sig],
            )
            .unwrap();
        }
        db.execute("DELETE FROM one_time_prekeys WHERE device = ?1", params![device])
            .unwrap();
        for opk in opks.iter().take(MAX_OPKS) {
            db.execute(
                "INSERT OR IGNORE INTO one_time_prekeys (device, id, pub) VALUES (?1, ?2, ?3)",
                params![device, opk.id, opk.pub_key],
            )
            .unwrap();
        }
        db.execute(
            "DELETE FROM kem_one_time_prekeys WHERE device = ?1",
            params![device],
        )
        .unwrap();
        for kopk in kopks.iter().take(MAX_KOPKS) {
            db.execute(
                "INSERT OR IGNORE INTO kem_one_time_prekeys (device, id, pub) VALUES (?1, ?2, ?3)",
                params![device, kopk.id, kopk.pub_key],
            )
            .unwrap();
        }
    }

    /// The prekey bundle for a sender starting a session. Consumes the
    /// returned one-time prekeys (X25519 and ML-KEM independently) — each
    /// is handed out at most once. No bundle until both signed halves are
    /// published: PQXDH has no classical-only fallback.
    pub fn take_bundle(&self, device: i64) -> Option<Value> {
        let db = self.db.lock().unwrap();
        let signed = |table: &str| -> Option<(i64, String, String)> {
            db.query_row(
                &format!("SELECT id, pub, sig FROM {table} WHERE device = ?1"),
                params![device],
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
                    &format!("SELECT id, pub FROM {table} WHERE device = ?1 ORDER BY id LIMIT 1"),
                    params![device],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()
                .unwrap();
            if let Some((id, _)) = &one {
                db.execute(
                    &format!("DELETE FROM {table} WHERE device = ?1 AND id = ?2"),
                    params![device, id],
                )
                .unwrap();
            }
            one
        };
        let opk = take_one("one_time_prekeys");
        let kopk = take_one("kem_one_time_prekeys");
        let cert: Option<String> = db
            .query_row(
                "SELECT cert FROM devices WHERE device_id = ?1",
                params![device],
                |r| r.get(0),
            )
            .optional()
            .unwrap()
            .flatten();
        Some(serde_json::json!({
            "cert": cert.and_then(|c| serde_json::from_str::<Value>(&c).ok()),
            "spk": {"id": spk_id, "pub": spk_pub, "sig": spk_sig},
            "opk": opk.map(|(id, pub_key)| serde_json::json!({"id": id, "pub": pub_key})),
            "kspk": {"id": kspk_id, "pub": kspk_pub, "sig": kspk_sig},
            "kopk": kopk.map(|(id, pub_key)| serde_json::json!({"id": id, "pub": pub_key})),
        }))
    }

    /// Every device's SPK/KSPK, no one-time keys consumed — the free listing
    /// half of the bundle split. A
    /// device with no published signed prekeys is omitted: a sender has
    /// nothing to X3DH against there.
    pub fn device_prekeys(&self) -> Vec<Value> {
        let db = self.db.lock().unwrap();
        let mut stmt = db
            .prepare(
                "SELECT s.device, s.id, s.pub, s.sig, k.id, k.pub, k.sig, d.cert
                 FROM signed_prekey s
                 JOIN kem_signed_prekey k ON k.device = s.device
                 JOIN devices d ON d.device_id = s.device
                 WHERE d.expires_at IS NULL OR d.expires_at > ?1
                 ORDER BY s.device",
            )
            .unwrap();
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, false);
        let rows = stmt
            .query_map(params![now], |r| {
                Ok(serde_json::json!({
                    "device_id": r.get::<_, i64>(0)?,
                    "spk": {"id": r.get::<_, i64>(1)?, "pub": r.get::<_, String>(2)?,
                            "sig": r.get::<_, String>(3)?},
                    "kspk": {"id": r.get::<_, i64>(4)?, "pub": r.get::<_, String>(5)?,
                             "sig": r.get::<_, String>(6)?},
                    // Served back as the object it arrived as — the sender
                    // needs it to know which key to seal to, and to check the
                    // prekey signatures above against the device key it names.
                    "cert": r.get::<_, Option<String>>(7)?
                        .and_then(|c| serde_json::from_str::<Value>(&c).ok()),
                }))
            })
            .unwrap();
        rows.map(|r| r.unwrap()).collect()
    }

    /// Prekey inventory for the authenticated device only — /status is that
    /// device's view of its own mailbox.
    pub fn prekey_status(&self, device: i64) -> Value {
        let db = self.db.lock().unwrap();
        let count = |table: &str| -> i64 {
            db.query_row(
                &format!("SELECT COUNT(*) FROM {table} WHERE device = ?1"),
                params![device],
                |r| r.get(0),
            )
            .unwrap()
        };
        serde_json::json!({
            "spk": count("signed_prekey") > 0,
            "opks": count("one_time_prekeys"),
            "kspk": count("kem_signed_prekey") > 0,
            "kopks": count("kem_one_time_prekeys"),
        })
    }

    pub fn set_push_config(&self, device: i64, device_token: &str, platform: &str) {
        let db = self.db.lock().unwrap();
        db.execute(
            "INSERT INTO push_config (device, device_token, platform) VALUES (?1, ?2, ?3)
             ON CONFLICT(device) DO UPDATE SET device_token=excluded.device_token,
             platform=excluded.platform",
            params![device, device_token, platform],
        )
        .unwrap();
    }

    pub fn push_config(&self, device: i64) -> Option<(String, String)> {
        let db = self.db.lock().unwrap();
        db.query_row(
            "SELECT device_token, platform FROM push_config WHERE device = ?1",
            params![device],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .unwrap()
    }

    /// Queue an envelope for one device. The caps meter *delivery*, so they
    /// are per device — one device that
    /// stops draining must not stop the others receiving mail.
    ///
    /// Two caps, because rows alone bound nothing: 10,000 envelopes of 64 KiB
    /// are 640 MiB. A duplicate is reported before either is checked — the
    /// envelope is already here, which is what its sender wants to know.
    pub fn put(&self, device: i64, envelope_id: &str, body: &str) -> Put {
        let db = self.db.lock().unwrap();
        let mut queue = self.queue.lock().unwrap();
        let held: bool = db
            .query_row(
                "SELECT 1 FROM envelopes WHERE id = ?1 AND device = ?2",
                params![envelope_id, device],
                |_| Ok(()),
            )
            .optional()
            .unwrap()
            .is_some();
        if held {
            return Put::Duplicate;
        }
        let used = queue.usage.get(&device).copied().unwrap_or_default();
        if used.rows >= MAX_QUEUE_DEPTH
            || used.bytes + body.len() as u64 > self.max_queue_bytes
        {
            return Put::Full;
        }
        db.execute(
            "INSERT INTO envelopes (rowid, id, device, body, received_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                queue.next_seq,
                envelope_id,
                device,
                body,
                chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, false),
            ],
        )
        .unwrap();
        queue.next_seq += 1;
        let used = queue.usage.entry(device).or_default();
        used.rows += 1;
        used.bytes += body.len() as u64;
        Put::Queued
    }

    /// The next `limit` of one device's queued envelopes after `after`,
    /// oldest first, each with the sequence number to resume from. The drain
    /// reads the queue through this and nothing else, so what it holds in
    /// memory is a page, never the queue (link.rs "pump").
    pub fn page(&self, device: i64, after: i64, limit: usize) -> Vec<(i64, String)> {
        let db = self.db.lock().unwrap();
        let mut stmt = db
            .prepare(
                "SELECT rowid, body FROM envelopes
                 WHERE device = ?1 AND rowid > ?2 ORDER BY rowid LIMIT ?3",
            )
            .unwrap();
        let rows = stmt
            .query_map(params![device, after, limit as i64], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
            })
            .unwrap();
        rows.map(|r| r.unwrap()).collect()
    }

    pub fn has(&self, device: i64, envelope_id: &str) -> bool {
        let db = self.db.lock().unwrap();
        db.query_row(
            "SELECT 1 FROM envelopes WHERE id = ?1 AND device = ?2",
            params![envelope_id, device],
            |_| Ok(()),
        )
        .optional()
        .unwrap()
        .is_some()
    }

    /// Delete one device's copy of an acked envelope; returns its blob_id if
    /// it referenced one. The blob may still be owed to a sibling device, so
    /// the caller refcounts rather than deleting outright
    /// (AppState::delete_envelope).
    pub fn delete(&self, device: i64, envelope_id: &str) -> Option<String> {
        let db = self.db.lock().unwrap();
        let body: Option<String> = db
            .query_row(
                "SELECT body FROM envelopes WHERE id = ?1 AND device = ?2",
                params![envelope_id, device],
                |r| r.get(0),
            )
            .optional()
            .unwrap();
        db.execute(
            "DELETE FROM envelopes WHERE id = ?1 AND device = ?2",
            params![envelope_id, device],
        )
        .unwrap();
        let body = body?;
        if let Some(used) = self.queue.lock().unwrap().usage.get_mut(&device) {
            used.rows = (used.rows - 1).max(0);
            used.bytes = used.bytes.saturating_sub(body.len() as u64);
        }
        serde_json::from_str::<Value>(&body)
            .ok()?
            .get("blob_id")?
            .as_str()
            .map(str::to_string)
    }

    /// How many queued envelopes still reference this blob, across every
    /// device. Zero means the last reader acked and the file can go.
    pub fn blob_refcount(&self, blob_id: &str) -> i64 {
        let db = self.db.lock().unwrap();
        db.query_row(
            "SELECT COUNT(*) FROM envelopes WHERE body LIKE '%' || ?1 || '%'",
            params![blob_id],
            |r| r.get(0),
        )
        .unwrap()
    }

    /// Whether a device other than `device` still has this blob queued. What
    /// stops a linked device deleting media a sibling has yet to fetch.
    pub fn blob_owed_to_sibling(&self, blob_id: &str, device: i64) -> bool {
        let db = self.db.lock().unwrap();
        db.query_row(
            "SELECT COUNT(*) FROM envelopes
             WHERE device != ?2 AND body LIKE '%' || ?1 || '%'",
            params![blob_id, device],
            |r| r.get::<_, i64>(0),
        )
        .unwrap()
            > 0
    }

    /// Total queued across all devices — what /status reports and the boot
    /// log prints.
    pub fn depth(&self) -> i64 {
        let db = self.db.lock().unwrap();
        db.query_row("SELECT COUNT(*) FROM envelopes", [], |r| r.get(0))
            .unwrap()
    }

    pub fn device_depth(&self, device: i64) -> i64 {
        let db = self.db.lock().unwrap();
        db.query_row(
            "SELECT COUNT(*) FROM envelopes WHERE device = ?1",
            params![device],
            |r| r.get(0),
        )
        .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mailbox(max_queue_bytes: u64) -> Mailbox {
        Mailbox::open(":memory:", "owner-token", max_queue_bytes).unwrap()
    }

    fn body(id: &str, pad: usize) -> String {
        format!(r#"{{"v":1,"id":"{id}","sealed":"{}"}}"#, "a".repeat(pad))
    }

    #[test]
    fn a_duplicate_id_is_reported_and_not_stored_twice() {
        let m = mailbox(1 << 20);
        assert_eq!(m.put(1, "e-1", &body("e-1", 10)), Put::Queued);
        assert_eq!(m.put(1, "e-1", &body("e-1", 10)), Put::Duplicate);
        assert_eq!(m.device_depth(1), 1);
        // The same id for a sibling is that sibling's own row.
        let two = m.add_device(&"t".repeat(32), "linked", None);
        assert_eq!(m.put(two, "e-1", &body("e-1", 10)), Put::Queued);
    }

    #[test]
    fn the_byte_cap_is_per_device_and_released_by_an_ack() {
        let one = body("x", 300);
        let m = mailbox(one.len() as u64 * 2);
        let two = m.add_device(&"t".repeat(32), "linked", None);
        assert_eq!(m.put(1, "a", &one), Put::Queued);
        assert_eq!(m.put(1, "b", &one), Put::Queued);
        assert_eq!(m.put(1, "c", &one), Put::Full);
        // A full sibling does not stop this one receiving.
        assert_eq!(m.put(two, "c", &one), Put::Queued);
        // A retry of something already held is still a duplicate, not "full".
        assert_eq!(m.put(1, "a", &one), Put::Duplicate);
        m.delete(1, "a");
        assert_eq!(m.put(1, "c", &one), Put::Queued);
        // Acking an id that is not queued must not credit the device.
        m.delete(1, "never-queued");
        assert_eq!(m.put(1, "d", &one), Put::Full);
    }

    #[test]
    fn usage_is_recounted_from_the_rows_on_open() {
        let dir = std::env::temp_dir().join(format!("stonechat-db-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("mailbox.db");
        let one = body("x", 300);
        {
            let m = Mailbox::open(path.to_str().unwrap(), "t", one.len() as u64 * 2).unwrap();
            assert_eq!(m.put(1, "a", &one), Put::Queued);
            assert_eq!(m.put(1, "b", &one), Put::Queued);
        }
        let m = Mailbox::open(path.to_str().unwrap(), "t", one.len() as u64 * 2).unwrap();
        assert_eq!(m.put(1, "c", &one), Put::Full);
        assert_eq!(m.page(1, 0, 10).len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pages_are_bounded_ordered_and_resume_from_the_cursor() {
        let m = mailbox(1 << 20);
        for i in 0..7 {
            m.put(1, &format!("e-{i}"), &body(&format!("e-{i}"), 4));
        }
        let first = m.page(1, 0, 3);
        assert_eq!(first.len(), 3);
        assert!(first[0].1.contains("e-0") && first[2].1.contains("e-2"));
        let second = m.page(1, first[2].0, 3);
        assert!(second[0].1.contains("e-3"));
        let rest = m.page(1, second[2].0, 3);
        assert_eq!(rest.len(), 1);
        assert!(m.page(1, rest[0].0, 3).is_empty());
    }

    #[test]
    fn a_sequence_number_is_never_reused_after_an_ack() {
        // SQLite's own rowid would be: ack the newest row and the next insert
        // inherits its number, behind a cursor that already passed it.
        let m = mailbox(1 << 20);
        m.put(1, "a", &body("a", 4));
        let cursor = m.page(1, 0, 10)[0].0;
        m.delete(1, "a");
        m.put(1, "b", &body("b", 4));
        let next = m.page(1, cursor, 10);
        assert_eq!(next.len(), 1, "the envelope after an ack was skipped");
        assert!(next[0].0 > cursor);
    }

    #[test]
    fn the_primary_device_cannot_be_removed() {
        let m = mailbox(1 << 20);
        assert_eq!(m.remove_device(PRIMARY_DEVICE), (false, Vec::new()));
        assert_eq!(m.device_for_token("owner-token"), Some(PRIMARY_DEVICE));
        let two = m.add_device(&"t".repeat(32), "linked", None);
        m.put(two, "a", &body("a", 4));
        assert!(m.remove_device(two).0);
        assert_eq!(m.device_depth(two), 0);
    }

    #[test]
    fn a_blob_is_owed_to_a_sibling_only_while_the_sibling_has_it_queued() {
        let m = mailbox(1 << 20);
        let two = m.add_device(&"t".repeat(32), "linked", None);
        let blob = "123e4567-e89b-42d3-a456-426614174000";
        m.put(1, "a", &format!(r#"{{"id":"a","blob_id":"{blob}"}}"#));
        assert!(m.blob_owed_to_sibling(blob, two));
        assert!(!m.blob_owed_to_sibling(blob, 1));
        m.delete(1, "a");
        assert!(!m.blob_owed_to_sibling(blob, two));
    }
}
