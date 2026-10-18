//! Device manifests: the identity's signed list of which devices speak for
//! it now (PROTOCOL.md "Device manifest").
//!
//! A certificate says a device *was* the identity's, until a date. The
//! manifest is the primary's statement of the current set, numbered so a
//! newer one supersedes an older. A holder encrypts only to listed devices
//! and accepts envelopes only from listed devices — so a revoked device is
//! cut off by its owner's signature, not only by a queue deleted on a relay
//! the contact has to trust.
//!
//! Verification is `core::devices`; this module is the wire form, the
//! forward-only rule, and what a manifest says about a device.

use serde_json::Value;
use stonechat_core::devices::Manifest;

use crate::state::State;
use crate::util::unb64_n;

/// Parse and verify a manifest against `identity_pub` — the key the
/// directory gave for this identity, already checked to commit to its ID.
/// `None` unless it is that identity's genuine, well-formed manifest **for
/// `stonechat_id`**: a valid manifest for somebody else is as useless as a
/// forged one.
pub fn verified(json: &Value, stonechat_id: &str, identity_pub: &[u8; 32]) -> Option<Manifest> {
    let manifest = Manifest::from_json(json)?;
    if manifest.stonechat_id != stonechat_id {
        return None;
    }
    let sig: [u8; 64] = unb64_n(json.get("sig")?.as_str()?, "manifest signature").ok()?;
    manifest.verify(identity_pub, &sig).then_some(manifest)
}

/// The manifest we hold for an identity. It was verified when it was stored;
/// a state file is not re-verified against itself.
pub fn held(st: &State, stonechat_id: &str) -> Option<Manifest> {
    st.manifests
        .get(stonechat_id)
        .and_then(Manifest::from_json)
}

/// Keep a verified manifest, but only forward: a directory serving an older
/// manifest than the one we hold is serving a stale one, and we keep ours.
/// Returns whether anything changed.
pub fn adopt(st: &mut State, stonechat_id: &str, json: &Value, manifest: &Manifest) -> bool {
    if let Some(current) = held(st, stonechat_id)
        && current.version >= manifest.version
    {
        return false;
    }
    st.manifests
        .insert(stonechat_id.to_string(), json.clone());
    true
}

/// Whether a manifest lists `device` under the key the certificate we hold
/// for it carries. A listed slot with another key is a relay that swapped
/// certificates between slots, and is not listed.
pub fn lists(manifest: &Manifest, device: u32, cert: &Value) -> bool {
    match crate::cert::sig_key(cert) {
        Ok(sig_pub) => manifest.lists(device, &sig_pub),
        Err(_) => false,
    }
}
