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
use crate::util::{Result, unb64_n};

/// An X25519 prekey we published and still hold the private half of.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Prekey {
    pub id: u64,
    pub secret_b64: String,
    pub public_b64: String,
}

/// An ML-KEM-768 prekey. Stored as its 64-byte seed, like everywhere else in
/// the protocol — pqcore regenerates the key from it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KemPrekey {
    pub id: u64,
    pub seed_b64: String,
    pub public_b64: String,
}

/// A peer device we can encrypt to, keyed `"<SC- id>|<device id>"`.
pub fn peer_key(stonechat_id: &str, device: u32) -> String {
    format!("{stonechat_id}|{device}")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// the only authority we hold — we cannot extend or reissue it.
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
    /// send needs the seal key it names, and fetching one costs the peer a
    /// one-time prekey.
    #[serde(default)]
    pub peer_certs: BTreeMap<String, Value>,
    /// peer → their bundle token, learned from envelopes they sent us.
    #[serde(default)]
    pub bundle_tokens: BTreeMap<String, String>,
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

    /// When our certificate runs out. After that peers **refuse to encrypt to
    /// us** — correct behaviour, and the reason `run` warns on approach.
    pub fn cert_not_after(&self) -> i64 {
        self.cert
            .get("not_after")
            .and_then(Value::as_i64)
            .unwrap_or(0)
    }

    pub fn kem_seed_for(&self, id: u64, one_time: bool) -> Result<[u8; 64]> {
        if one_time {
            let seed = self
                .kopks
                .get(&id)
                .ok_or_else(|| err!("no one-time KEM prekey {id} — already used?"))?;
            return unb64_n(seed, "one-time KEM prekey");
        }
        let kspk = self
            .kspk
            .as_ref()
            .ok_or_else(|| err!("no signed KEM prekey published"))?;
        if kspk.id != id {
            return Err(err!(
                "envelope names KEM prekey {id}, we published {}",
                kspk.id
            ));
        }
        unb64_n(&kspk.seed_b64, "signed KEM prekey")
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
pub fn save(state: &State) -> Result<()> {
    let path = state_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| err!("cannot create {}: {e}", dir.display()))?;
    }
    let tmp = path.with_extension("json.tmp");
    let body = serde_json::to_vec_pretty(state)?;
    std::fs::write(&tmp, &body).map_err(|e| err!("cannot write {}: {e}", tmp.display()))?;
    restrict(&tmp)?;
    std::fs::rename(&tmp, &path).map_err(|e| err!("cannot replace {}: {e}", path.display()))?;
    Ok(())
}

/// 0600. Not a substitute for a keystore, and the README says so — but a
/// world-readable device token is a different order of mistake.
#[cfg(unix)]
fn restrict(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| err!("cannot restrict {}: {e}", path.display()))
}

#[cfg(not(unix))]
fn restrict(_path: &Path) -> Result<()> {
    Ok(())
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
