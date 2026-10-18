//! Everything the agent is, on disk.
//!
//! A phone keeps this in a keystore. An agent keeps it in a file, and that is
//! a real downgrade — stated plainly in the README rather than implied away.
//! What bounds it is scope: **there is no identity secret in here.** The
//! worst this file can do if stolen is act as one device until the owner
//! revokes it, which is exactly the bound device certificates were built to
//! give.
//!
//! The double ratchet is mutable state that advances on every message, so
//! this is written **before** an envelope is allowed to leave and after every
//! one that is opened. A crash that loses an advance is how a message key
//! gets reused.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use stonechat_core::session::SessionState;

use crate::err;
use crate::util::{Result, now_s, unb64_n};

/// An X25519 prekey we published and still hold the private half of.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Prekey {
    pub id: u64,
    pub secret_b64: String,
    pub public_b64: String,
    /// Unix seconds. Signed prekeys are replaced once a week; a key from
    /// before this field existed reads as old and is rotated on the next
    /// connect, with the previous one kept for handshakes in flight.
    #[serde(default)]
    pub created_at: u64,
}

/// An ML-KEM-768 prekey. Stored as its 64-byte seed, like everywhere else in
/// the protocol — pqcore regenerates the key from it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KemPrekey {
    pub id: u64,
    pub seed_b64: String,
    pub public_b64: String,
    #[serde(default)]
    pub created_at: u64,
}

/// Someone the owner knows, as the phone told us over `sync_history` or
/// `sync_contact`. The agent never decides who is a contact: it learns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    /// Their Ed25519 identity key, checked to commit to their ID before it
    /// was stored. For a known peer this is the key — the directory is never
    /// asked for it again.
    pub pubkey_b64: String,
    /// `accepted`, `pending_in` or `pending_out`, as on the wire.
    pub status: String,
    #[serde(default)]
    pub display_name: String,
}

/// A peer device we can encrypt to, keyed `"<SC- id>|<device id>"`.
pub fn peer_key(stonechat_id: &str, device: u32) -> String {
    format!("{stonechat_id}|{device}")
}

/// The peer half of a `peer_key`.
pub fn peer_of(key: &str) -> &str {
    key.split('|').next().unwrap_or(key)
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct State {
    // -- who we are a device of ----------------------------------------------
    pub hub_url: String,
    pub stonechat_id: String,
    #[serde(default)]
    pub display_name: String,
    /// The owner's Ed25519 **public** key. The secret half is on their phone
    /// and has never been here; this is what our certificate verifies against.
    pub identity_pub_b64: String,
    /// The certificate the primary signed over our own two keys. Public, and
    /// the only authority we hold — we cannot extend or reissue it. The
    /// primary renews it over `sync_cert` while we are still listed.
    pub cert: Value,
    pub device_id: u32,

    // -- our own keys --------------------------------------------------------
    /// Ed25519 seed. Signs our prekeys; PQXDH runs against it device-to-device.
    pub dev_sig_seed_b64: String,
    /// X-Wing seed. Envelopes addressed to this device are sealed to it.
    pub dev_seal_seed_b64: String,

    // -- our mailbox ---------------------------------------------------------
    pub relay_address: String,
    pub relay_tls_fp: String,
    pub device_token: String,
    /// The capability that lets a contact list our devices. Rides every
    /// envelope we send so peers can reach all of them, not just the primary.
    #[serde(default)]
    pub bundle_token: Option<String>,

    // -- prekeys we have published -------------------------------------------
    #[serde(default)]
    pub spk: Option<Prekey>,
    #[serde(default)]
    pub kspk: Option<KemPrekey>,
    /// The signed prekeys before the last rotation. A handshake made against
    /// a bundle fetched just before we rotated still names them, so they are
    /// kept through one rotation and nothing older.
    #[serde(default)]
    pub prev_spk: Option<Prekey>,
    #[serde(default)]
    pub prev_kspk: Option<KemPrekey>,
    /// id → X25519 secret. One-time means one time: consumed on use.
    #[serde(default)]
    pub opks: BTreeMap<u64, String>,
    /// id → ML-KEM seed, same lifetime rule.
    #[serde(default)]
    pub kopks: BTreeMap<u64, String>,
    #[serde(default = "one")]
    pub next_prekey_id: u64,

    // -- conversations -------------------------------------------------------
    /// `"<peer>|<device>"` → ratchet. Keyed by device because two devices of
    /// one peer cannot share a ratchet.
    #[serde(default)]
    pub sessions: BTreeMap<String, SessionState>,
    /// `"<peer>|<device>"` → their device certificate. Cached because every
    /// send needs the seal key it names, and every receive checks it again.
    #[serde(default)]
    pub peer_certs: BTreeMap<String, Value>,
    /// peer → their bundle token, learned from envelopes they sent us or from
    /// the phone's contact sync.
    #[serde(default)]
    pub bundle_tokens: BTreeMap<String, String>,
    /// peer → the mailbox's `devices_v` as last reported. A higher value on
    /// a later answer means the device set changed under us.
    #[serde(default)]
    pub devices_v: BTreeMap<String, u64>,

    // -- what the phone told us ----------------------------------------------
    /// peer → contact. Only an `accepted` contact gets an answer.
    #[serde(default)]
    pub contacts: BTreeMap<String, Contact>,
    /// peer → when the owner blocked them (ms). Blocked senders are decrypted
    /// (the ratchet stays current for an unblock) and otherwise ignored.
    #[serde(default)]
    pub blocked: BTreeMap<String, i64>,
    /// identity → its newest verified device manifest, as served (with
    /// `sig`). Our own identity's included: it decides which of our siblings
    /// we mirror to, and is the version every envelope we send states.
    #[serde(default)]
    pub manifests: BTreeMap<String, Value>,
}

fn one() -> u64 {
    1
}

impl State {
    pub fn dev_sig_seed(&self) -> Result<[u8; 32]> {
        unb64_n(&self.dev_sig_seed_b64, "device signing seed")
    }

    pub fn dev_seal_seed(&self) -> Result<[u8; 32]> {
        unb64_n(&self.dev_seal_seed_b64, "device seal seed")
    }

    pub fn identity_pub(&self) -> Result<[u8; 32]> {
        unb64_n(&self.identity_pub_b64, "owner identity key")
    }

    /// When our certificate runs out. After that peers **refuse to encrypt to
    /// us** — correct behaviour, and the reason `run` warns on approach.
    pub fn cert_not_after(&self) -> i64 {
        self.cert
            .get("not_after")
            .and_then(Value::as_i64)
            .unwrap_or(0)
    }

    /// The signed prekey a handshake names: the current one or, through one
    /// rotation, the previous.
    pub fn spk_for(&self, id: u64) -> Result<&Prekey> {
        [self.spk.as_ref(), self.prev_spk.as_ref()]
            .into_iter()
            .flatten()
            .find(|p| p.id == id)
            .ok_or_else(|| {
                err!(
                    "handshake names signed prekey {id}, we hold {}",
                    self.spk.as_ref().map(|p| p.id.to_string()).unwrap_or_else(|| "none".into())
                )
            })
    }

    pub fn kem_seed_for(&self, id: u64, one_time: bool) -> Result<[u8; 64]> {
        if one_time {
            let seed = self
                .kopks
                .get(&id)
                .ok_or_else(|| err!("no one-time KEM prekey {id} — already used?"))?;
            return unb64_n(seed, "one-time KEM prekey");
        }
        let kspk = [self.kspk.as_ref(), self.prev_kspk.as_ref()]
            .into_iter()
            .flatten()
            .find(|k| k.id == id)
            .ok_or_else(|| err!("envelope names KEM prekey {id}, which we do not hold"))?;
        unb64_n(&kspk.seed_b64, "signed KEM prekey")
    }

    /// An accepted, unblocked contact: the only kind of person the agent
    /// answers.
    pub fn is_contact(&self, stonechat_id: &str) -> bool {
        self.contacts
            .get(stonechat_id)
            .is_some_and(|c| c.status == "accepted")
            && !self.blocked.contains_key(stonechat_id)
    }

    /// The identity key we already hold for a peer — our own, or a
    /// contact's — provided it still commits to the ID. An ID commits to
    /// exactly one key, so for a peer we know the directory is never asked
    /// for it again.
    pub fn held_identity_key(&self, stonechat_id: &str) -> Option<[u8; 32]> {
        let b64 = if stonechat_id == self.stonechat_id {
            &self.identity_pub_b64
        } else {
            &self.contacts.get(stonechat_id)?.pubkey_b64
        };
        let key: [u8; 32] = unb64_n(b64, "held identity key").ok()?;
        stonechat_core::ids::pubkey_matches_id(&key, stonechat_id).then_some(key)
    }

    pub fn bundle_token_for(&self, stonechat_id: &str) -> Option<&str> {
        if stonechat_id == self.stonechat_id {
            return self.bundle_token.as_deref();
        }
        self.bundle_tokens.get(stonechat_id).map(String::as_str)
    }

    /// The certificate we hold for a peer device, if it has not run out.
    /// An expired one is forgotten here: it is not something to encrypt
    /// to, nor something that vouches for an envelope.
    pub fn held_cert(&mut self, key: &str) -> Option<Value> {
        let cert = self.peer_certs.get(key)?;
        let not_after = cert.get("not_after").and_then(Value::as_u64).unwrap_or(0);
        if not_after <= now_s() {
            self.peer_certs.remove(key);
            return None;
        }
        Some(cert.clone())
    }

    /// Everything we hold about one peer's devices, gone. For a contact the
    /// phone removed, or a peer whose mailbox says a device no longer exists.
    pub fn forget_device(&mut self, stonechat_id: &str, device: u32) {
        let key = peer_key(stonechat_id, device);
        self.sessions.remove(&key);
        self.peer_certs.remove(&key);
    }

    pub fn forget_peer(&mut self, stonechat_id: &str) {
        self.sessions.retain(|k, _| peer_of(k) != stonechat_id);
        self.peer_certs.retain(|k, _| peer_of(k) != stonechat_id);
        self.bundle_tokens.remove(stonechat_id);
        self.devices_v.remove(stonechat_id);
    }

    /// The version of our own device manifest, stated in every envelope we
    /// send; 0 while we hold none.
    pub fn own_manifest_v(&self) -> u64 {
        self.manifests
            .get(&self.stonechat_id)
            .and_then(|m| m.get("version"))
            .and_then(Value::as_u64)
            .unwrap_or(0)
    }
}

pub fn state_path() -> PathBuf {
    if let Ok(p) = std::env::var("STONECHAT_AGENT_STATE") {
        return PathBuf::from(p);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    Path::new(&home).join(".stonechat").join("agent.json")
}

pub fn load() -> Result<Option<State>> {
    let path = state_path();
    if !path.exists() {
        return Ok(None);
    }
    let raw = std::fs::read(&path).map_err(|e| err!("cannot read {}: {e}", path.display()))?;
    let state = serde_json::from_slice(&raw)
        .map_err(|e| err!("{} is not a state file this build understands: {e}", path.display()))?;
    Ok(Some(state))
}

/// Write via a temp file and rename.
///
/// The ratchet is the reason. A half-written state file is a device that has
/// lost track of which message keys it has already used — atomicity here is
/// not tidiness, it is the difference between resuming and being unable to
/// decrypt anything ever again.
///
/// The temp file is **created** with mode 0600, not created and then
/// restricted: between those two steps the device token and every ratchet
/// would sit under whatever the umask allowed.
pub fn save(state: &State) -> Result<()> {
    let path = state_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| err!("cannot create {}: {e}", dir.display()))?;
    }
    let tmp = path.with_extension("json.tmp");
    let body = serde_json::to_vec_pretty(state)?;
    // A leftover from an interrupted earlier save would make create_new fail.
    let _ = std::fs::remove_file(&tmp);
    {
        use std::io::Write;
        let mut file = open_private(&tmp)
            .map_err(|e| err!("cannot create {}: {e}", tmp.display()))?;
        file.write_all(&body)
            .and_then(|_| file.sync_all())
            .map_err(|e| err!("cannot write {}: {e}", tmp.display()))?;
    }
    std::fs::rename(&tmp, &path).map_err(|e| err!("cannot replace {}: {e}", path.display()))?;
    Ok(())
}

/// 0600 from the first byte. Not a substitute for a keystore, and the README
/// says so — but a world-readable device token is a different order of
/// mistake.
#[cfg(unix)]
fn open_private(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn open_private(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new().write(true).create_new(true).open(path)
}

pub fn require() -> Result<State> {
    load()?.ok_or_else(|| {
        err!(
            "no agent state at {} — run `stonechat-agent link` first",
            state_path().display()
        )
    })
}

/// Public halves, recomputed rather than stored: two copies of a key is one
/// chance for them to disagree.
pub fn sig_public(seed: &[u8; 32]) -> [u8; 32] {
    stonechat_core::primitives::ed25519_pk_from_seed(seed)
}

pub fn seal_public(seed: &[u8; 32]) -> [u8; stonechat_core::pqcore::XWING_PUBLIC_BYTES] {
    stonechat_core::pqcore::xwing_pk_from_seed(seed)
}
