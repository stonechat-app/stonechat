//! What the phone tells us about who the owner knows.
//!
//! The agent never decides who is a contact — accepting a request, blocking
//! someone, removing a contact are identity-level acts, and a program
//! guessing at them on its owner's behalf eventually guesses wrong. It
//! learns, from the two channels the protocol gives a linked device
//! (PROTOCOL.md "Self-sync"): the primary's `sync_history` once, after
//! linking, and `sync_contact` / `sync_block` for every change afterwards.
//!
//! Every entry it keeps was checked the same way: the identity key must hash
//! to the ID it is filed under. From then on that key, not the directory, is
//! what a certificate from that peer is verified against.

use serde_json::Value;

use crate::err;
use crate::state::{Contact, State};
use crate::util::{Result, short, unb64_n};

const STATUSES: [&str; 3] = ["accepted", "pending_in", "pending_out"];

/// `sync_contact`: the contact as the sending device now holds it. Returns
/// a line for the log.
pub fn apply_sync_contact(st: &mut State, payload: &Value) -> Result<String> {
    let peer = field(payload, "peer")?;
    let status = field(payload, "status")?;
    if status == "removed" {
        if st.contacts.remove(peer).is_none() {
            return Ok(format!("{} removed — was not a contact here", short(peer)));
        }
        st.forget_peer(peer);
        return Ok(format!("{} removed from contacts", short(peer)));
    }
    let pubkey_b64 = field(payload, "pubkey")?;
    record(st, peer, pubkey_b64, status, payload)?;
    Ok(format!("{} is now {status}", short(peer)))
}

/// `sync_block`: `blocked_at` set blocks, `null` unblocks.
pub fn apply_sync_block(st: &mut State, payload: &Value) -> Result<String> {
    let peer = field(payload, "peer")?;
    match payload.get("blocked_at").and_then(Value::as_i64) {
        Some(at) => {
            st.blocked.insert(peer.to_string(), at);
            Ok(format!("{} blocked", short(peer)))
        }
        None => {
            st.blocked.remove(peer);
            Ok(format!("{} unblocked", short(peer)))
        }
    }
}

/// The primary's export (`stonechat-backup`), merged under the backup's
/// rule: what we already hold wins. Only contacts and blocks are taken —
/// the agent keeps no history and is in no group. Returns how many of each
/// were added.
pub fn merge_backup(st: &mut State, payload: &Value) -> Result<(usize, usize)> {
    if payload.get("format").and_then(Value::as_str) != Some("stonechat-backup") {
        return Err(err!("export is not a stonechat-backup"));
    }
    let rows = |key: &str| -> Vec<&Value> {
        payload
            .get(key)
            .and_then(Value::as_array)
            .map(|a| a.iter().filter(|r| r.is_object()).collect())
            .unwrap_or_default()
    };
    let mut contacts = 0;
    for row in rows("contacts") {
        let (Some(peer), Some(pubkey), Some(status)) = (
            row.get("stonechat_id").and_then(Value::as_str),
            row.get("pubkey").and_then(Value::as_str),
            row.get("status").and_then(Value::as_str),
        ) else {
            continue;
        };
        if st.contacts.contains_key(peer) {
            continue; // held wins
        }
        if record(st, peer, pubkey, status, row).is_ok() {
            contacts += 1;
        }
    }
    let mut blocked = 0;
    for row in rows("blocked") {
        let (Some(peer), Some(at)) = (
            row.get("stonechat_id").and_then(Value::as_str),
            row.get("blocked_at").and_then(Value::as_i64),
        ) else {
            continue;
        };
        if st.blocked.contains_key(peer) {
            continue;
        }
        st.blocked.insert(peer.to_string(), at);
        blocked += 1;
    }
    Ok((contacts, blocked))
}

/// One contact, checked before it is kept: not ourselves, a known status,
/// and a key that commits to the ID. `extra` may carry `display_name` and
/// `bundle_token` (both optional on either channel).
fn record(st: &mut State, peer: &str, pubkey_b64: &str, status: &str, extra: &Value) -> Result<()> {
    if peer == st.stonechat_id {
        return Err(err!("a contact entry names ourselves"));
    }
    if !STATUSES.contains(&status) {
        return Err(err!("contact {} has unknown status {status:?}", short(peer)));
    }
    let pubkey: [u8; 32] = unb64_n(pubkey_b64, "contact pubkey")?;
    if !stonechat_core::ids::pubkey_matches_id(&pubkey, peer) {
        return Err(err!(
            "contact {}'s key does not commit to its ID — dropping the entry",
            short(peer)
        ));
    }
    let display_name = extra
        .get("display_name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or_else(|| st.contacts.get(peer).map(|c| c.display_name.clone()))
        .unwrap_or_default();
    st.contacts.insert(
        peer.to_string(),
        Contact {
            pubkey_b64: pubkey_b64.to_string(),
            status: status.to_string(),
            display_name,
        },
    );
    if let Some(token) = extra
        .get("bundle_token")
        .and_then(Value::as_str)
        .filter(|t| !t.is_empty())
    {
        st.bundle_tokens.insert(peer.to_string(), token.to_string());
    }
    Ok(())
}

fn field<'a>(payload: &'a Value, key: &str) -> Result<&'a str> {
    payload
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| err!("payload has no {key}"))
}
