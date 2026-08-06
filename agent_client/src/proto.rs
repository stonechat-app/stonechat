//! Envelopes: building them, opening them, and the sessions underneath.
//!
//! The cryptography is entirely `stonechat-core` — PQXDH, the double ratchet
//! and the X-Wing seal all live there and are not reimplemented here. What
//! this module owns is the part core deliberately refuses to have: which keys
//! to fetch, which certificate to check them against, what the associated data
//! says, and when to persist the advanced ratchet.
//!
//! Two rules from the wider design govern most of the code below:
//!
//! - **One message to a peer with k devices is k envelopes**, each on its own
//!   ratchet. There is no fan-out at the relay (MULTIDEVICE.md "Why not let
//!   the relay fan out?").
//! - **Both device numbers are bound into the AEAD**, always, in one form. A
//!   relabelled envelope simply fails to decrypt.

use serde_json::{Value, json};
use stonechat_core::envelope::{self, X3dhBlock};
use stonechat_core::pqcore::{XWING_ENCAPS_RANDOM_BYTES, XWING_PUBLIC_BYTES};
use stonechat_core::primitives::{
    AEAD_NONCE_BYTES, KSPK_SIG_CONTEXT, SPK_SIG_CONTEXT, verify_with_context,
};
use stonechat_core::session::{Identity, InitiateRandom, PrekeyBundle, RatchetHeader, SessionState};

use crate::hub::{Hub, Peer};
use crate::mailbox::Mailbox;
use crate::state::{State, peer_key};
use crate::util::{Result, b64, random, unb64, unb64_n};
use crate::{PRIMARY_DEVICE, cert, err};

/// An envelope we successfully opened.
pub struct Incoming {
    pub from: String,
    pub from_device: u32,
    pub kind: String,
    pub payload: Value,
}

/// `stonechat/v1|from|from_device|to|device|type`, the prefix core appends the
/// ratchet header to. One form, no conditional — this is the one place where
/// a second code path would mean silent decryption failure.
fn ad_prefix(from: &str, from_device: u32, to: &str, device: u32, kind: &str) -> String {
    format!("stonechat/v1|{from}|{from_device}|{to}|{device}|{kind}")
}

fn header_of(inner: &Value) -> Result<RatchetHeader> {
    serde_json::from_value(
        inner
            .get("ratchet")
            .cloned()
            .ok_or_else(|| err!("envelope carries no ratchet header"))?,
    )
    .map_err(|e| err!("malformed ratchet header: {e}"))
}

// -- receiving ----------------------------------------------------------------

/// Unseal, decrypt, and advance the ratchet.
///
/// The caller persists afterwards. Nothing here mutates `st` until a decrypt
/// has actually succeeded: a failed AEAD must never burn ratchet state, which
/// is why the established-session path works on a clone.
pub async fn open(st: &mut State, hub: &Hub, outer: &Value) -> Result<Incoming> {
    let sealed_b64 = outer
        .get("sealed")
        .and_then(Value::as_str)
        .ok_or_else(|| err!("wire envelope has no sealed body"))?;
    let seal_seed = st.dev_seal_seed()?;
    let opened = envelope::unseal(&seal_seed, &unb64(sealed_b64)?).ok_or_else(|| {
        err!(
            "envelope is not sealed to this device's key — it was addressed to \
             a different device, or our certificate has been replaced"
        )
    })?;
    let inner: Value =
        serde_json::from_slice(&opened).map_err(|e| err!("inner envelope is not JSON: {e}"))?;

    let from = inner
        .get("from")
        .and_then(Value::as_str)
        .ok_or_else(|| err!("inner envelope has no sender"))?
        .to_string();
    let from_device = inner
        .get("from_device")
        .and_then(Value::as_u64)
        .unwrap_or(PRIMARY_DEVICE as u64) as u32;
    let kind = inner
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    // Their bundle token rides every envelope. It is what lets a reply reach
    // all of their devices instead of only their primary — without it a
    // browser session never sees an answer to the message it just sent.
    if let Some(token) = inner.get("bundle_token").and_then(Value::as_str) {
        st.bundle_tokens.insert(from.clone(), token.to_string());
    }

    let prefix = ad_prefix(&from, from_device, &st.stonechat_id, st.device_id, &kind);
    let header = header_of(&inner)?;
    let nonce: [u8; AEAD_NONCE_BYTES] = unb64_n(
        inner
            .get("nonce")
            .and_then(Value::as_str)
            .ok_or_else(|| err!("envelope has no nonce"))?,
        "envelope nonce",
    )?;
    let ciphertext = unb64(
        inner
            .get("ciphertext")
            .and_then(Value::as_str)
            .ok_or_else(|| err!("envelope has no ciphertext"))?,
    )?;

    let key = peer_key(&from, from_device);
    let has_x3dh = inner.get("x3dh").is_some_and(|v| !v.is_null());

    // An established session, tried on a copy.
    if let Some(existing) = st.sessions.get(&key) {
        let mut trial = existing.clone();
        if let Some(plain) = trial.decrypt(&header, &nonce, &ciphertext, &prefix, &random::<32>()) {
            st.sessions.insert(key, trial);
            return Ok(Incoming {
                from,
                from_device,
                kind,
                payload: parse_payload(&plain)?,
            });
        }
        if !has_x3dh {
            return Err(err!(
                "could not decrypt an envelope from {from} device {from_device} \
                 on the established session, and it carries no handshake to \
                 start a new one"
            ));
        }
        // Falling through is deliberate: a peer who reinstalled sends a fresh
        // handshake on top of a session we still hold.
    }

    let (mut fresh, consumed) = respond(st, hub, &inner, &from, from_device).await?;
    let plain = fresh
        .decrypt(&header, &nonce, &ciphertext, &prefix, &random::<32>())
        .ok_or_else(|| {
            err!("handshake from {from} device {from_device} verified but its first message did not decrypt")
        })?;

    // One-time means one time, and only once the message it protected has
    // actually opened — burning a prekey on a envelope that failed would let
    // anyone drain the pool with garbage.
    if let Some(opk_id) = consumed.opk {
        st.opks.remove(&opk_id);
    }
    if let Some(kopk_id) = consumed.kopk {
        st.kopks.remove(&kopk_id);
    }
    st.sessions.insert(key, fresh);
    Ok(Incoming {
        from,
        from_device,
        kind,
        payload: parse_payload(&plain)?,
    })
}

struct Consumed {
    opk: Option<u64>,
    kopk: Option<u64>,
}

/// Responder PQXDH from an initial envelope's x3dh block.
///
/// Two checks replace the old "does this key hash to the sender's ID": the
/// certificate against the identity key their SC- ID *does* commit to, then
/// the handshake key against what that certificate vouches for. Skipping the
/// second would make the certificate decoration.
async fn respond(
    st: &mut State,
    hub: &Hub,
    inner: &Value,
    from: &str,
    from_device: u32,
) -> Result<(SessionState, Consumed)> {
    let x3dh = inner
        .get("x3dh")
        .filter(|v| !v.is_null())
        .ok_or_else(|| err!("no session with {from} device {from_device} and no handshake"))?;
    let block: X3dhBlock = serde_json::from_value(x3dh.clone())
        .map_err(|e| err!("malformed handshake block: {e}"))?;
    let sender_cert = x3dh
        .get("cert")
        .filter(|v| !v.is_null())
        .ok_or_else(|| err!("initial envelope from {from} carries no device certificate"))?;

    let peer = hub.resolve(from).await?;
    cert::verify(sender_cert, &peer.identity_pub, Some(from_device))?;
    let certified_sig = cert::sig_key(sender_cert)?;
    let block_ik: [u8; 32] = unb64_n(&block.ik, "handshake identity key")?;
    if certified_sig != block_ik {
        return Err(err!(
            "the handshake key from {from} is not the one its certificate \
             vouches for — refusing it"
        ));
    }

    let spk = st
        .spk
        .clone()
        .ok_or_else(|| err!("we have published no signed prekey — cannot answer a handshake"))?;
    if block.spk_id != spk.id {
        return Err(err!(
            "handshake names signed prekey {}, we published {}",
            block.spk_id,
            spk.id
        ));
    }
    let spk_pub: [u8; 32] = unb64_n(&spk.public_b64, "our signed prekey")?;
    let spk_sec: [u8; 32] = unb64_n(&spk.secret_b64, "our signed prekey secret")?;
    // Read, not removed: the one-time key is only spent once its message has
    // decrypted.
    let opk_sec = match block.opk_id {
        Some(id) => Some(
            st.opks
                .get(&id)
                .ok_or_else(|| err!("handshake uses one-time prekey {id}, which we no longer hold"))
                .and_then(|s| unb64_n::<32>(s, "one-time prekey"))?,
        ),
        None => None,
    };
    let kem_seed = st.kem_seed_for(block.kem_id, block.kem_one_time)?;

    let identity = Identity::from_ed25519_seed(&st.dev_sig_seed()?);
    let session = SessionState::respond(
        &identity,
        &block_ik,
        &block,
        &spk_pub,
        &spk_sec,
        opk_sec.as_ref(),
        &kem_seed,
    )?;

    // Cache the certificate: every send needs the seal key it names, and
    // fetching one otherwise costs the peer a one-time prekey.
    st.peer_certs
        .insert(peer_key(from, from_device), sender_cert.clone());

    Ok((
        session,
        Consumed {
            opk: block.opk_id,
            kopk: if block.kem_one_time {
                Some(block.kem_id)
            } else {
                None
            },
        },
    ))
}

fn parse_payload(plain: &[u8]) -> Result<Value> {
    serde_json::from_slice(plain).map_err(|e| err!("payload is not JSON: {e}"))
}

// -- sending ------------------------------------------------------------------

/// Send one logical message to every device of a peer we can reach.
///
/// One dead device does not stop its siblings: whichever took a copy will show
/// the message, so this only fails when *nothing* got through.
pub async fn send(
    st: &mut State,
    peer: &Peer,
    kind: &str,
    payload: &Value,
    also: &[u32],
) -> Result<usize> {
    let envelope_id = uuid::Uuid::new_v4().to_string();
    let mailbox = Mailbox::new(&peer.relay_address, &peer.relay_tls_fp)?;
    let mut delivered = 0usize;
    let mut last_error: Option<crate::util::Error> = None;

    for device in target_devices(st, peer, also).await {
        match one_device(st, peer, &mailbox, kind, payload, device, &envelope_id).await {
            Ok(()) => delivered += 1,
            Err(e) => {
                eprintln!("  ! {} device {device}: {e}", short(&peer.stonechat_id));
                last_error = Some(e);
            }
        }
    }
    if delivered == 0 {
        return Err(last_error.unwrap_or_else(|| err!("no reachable device for {}", peer.stonechat_id)));
    }
    Ok(delivered)
}

async fn one_device(
    st: &mut State,
    peer: &Peer,
    mailbox: &Mailbox,
    kind: &str,
    payload: &Value,
    device: u32,
    envelope_id: &str,
) -> Result<()> {
    let key = peer_key(&peer.stonechat_id, device);
    ensure_session(st, peer, mailbox, device).await?;

    let prefix = ad_prefix(
        &st.stonechat_id,
        st.device_id,
        &peer.stonechat_id,
        device,
        kind,
    );
    let nonce = random::<AEAD_NONCE_BYTES>();
    let (header, ciphertext, x3dh) = {
        let session = st
            .sessions
            .get_mut(&key)
            .ok_or_else(|| err!("no session for {key} after establishing one"))?;
        let (header, ciphertext) =
            session.encrypt(&serde_json::to_vec(payload)?, &prefix, &nonce)?;
        // Our certificate travels with the handshake so the responder can
        // trust the device key inside it without fetching anything. core
        // builds the cryptographic parts of the block; the certificate is a
        // client-layer addition (the same split as the Dart `withCert`).
        let x3dh = match &session.pending_x3dh {
            Some(block) => {
                let mut v = serde_json::to_value(block)?;
                v["cert"] = st.cert.clone();
                Some(v)
            }
            None => None,
        };
        (header, ciphertext, x3dh)
    };

    // Persist the advanced chain **before** the envelope can leave. A crash
    // after send must never reuse a message key, so the ordering is: advance,
    // write, then transmit. Losing the message is recoverable; reusing a key
    // is not.
    crate::state::save(st)?;

    let mut inner = json!({
        "v": 1,
        "id": envelope_id,
        "type": kind,
        "from": st.stonechat_id,
        "from_device": st.device_id,
        "to": peer.stonechat_id,
        "device": device,
        "sent_at": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "ratchet": serde_json::to_value(&header)?,
        "nonce": b64(&nonce),
        "ciphertext": b64(&ciphertext),
    });
    if let Some(x3dh) = x3dh {
        inner["x3dh"] = x3dh;
    }
    if let Some(token) = &st.bundle_token {
        // So the peer can reach all of *our* devices, not just the primary.
        inner["bundle_token"] = Value::String(token.clone());
    }

    let seal_pub = seal_target(st, &key)?;
    let sealed = envelope::seal_to(
        &seal_pub,
        &serde_json::to_vec(&inner)?,
        &random::<XWING_ENCAPS_RANDOM_BYTES>(),
        &random::<AEAD_NONCE_BYTES>(),
    )
    .ok_or_else(|| err!("that device's certified seal key does not parse"))?;

    let outer = json!({
        "v": 1,
        "id": envelope_id,
        "to": peer.stonechat_id,
        "device": device,
        "sealed": b64(&sealed),
    });
    mailbox.deliver(&outer).await
}

fn seal_target(st: &State, key: &str) -> Result<[u8; XWING_PUBLIC_BYTES]> {
    let cached = st
        .peer_certs
        .get(key)
        .ok_or_else(|| err!("no certificate cached for {key} — nothing to encrypt to"))?;
    cert::seal_key(cached)
}

/// Establish a session with one device of a peer, if we do not have one.
///
/// The certificate matters on **every** send, not just the first: an
/// established session never re-fetches a bundle, so a session whose
/// certificate we lost needs one fetched deliberately.
async fn ensure_session(
    st: &mut State,
    peer: &Peer,
    mailbox: &Mailbox,
    device: u32,
) -> Result<()> {
    let key = peer_key(&peer.stonechat_id, device);
    if st.sessions.contains_key(&key) && st.peer_certs.contains_key(&key) {
        return Ok(());
    }

    let token = st.bundle_tokens.get(&peer.stonechat_id).cloned();
    let bundle = mailbox.prekey_bundle(device, token.as_deref()).await?;

    // Two steps, and the order is the whole point: the certificate is checked
    // against the peer's IDENTITY key (which their SC- ID commits to), and the
    // prekeys are then checked against the DEVICE key that certificate names.
    let peer_cert = bundle
        .get("cert")
        .filter(|v| !v.is_null())
        .ok_or_else(|| err!("device {device} publishes no certificate — nothing to encrypt to"))?
        .clone();
    cert::verify(&peer_cert, &peer.identity_pub, Some(device))?;
    let device_sig = cert::sig_key(&peer_cert)?;

    let spk_pub = unb64(signed_field(&bundle, "spk", "pub")?)?;
    let spk_sig: [u8; 64] = unb64_n(signed_field(&bundle, "spk", "sig")?, "spk signature")?;
    if !verify_with_context(&device_sig, SPK_SIG_CONTEXT, &spk_pub, &spk_sig) {
        return Err(err!(
            "device {device}'s signed prekey is not signed by the key its \
             certificate names — refusing it"
        ));
    }
    let kspk_pub = unb64(signed_field(&bundle, "kspk", "pub")?)?;
    let kspk_sig: [u8; 64] = unb64_n(signed_field(&bundle, "kspk", "sig")?, "kspk signature")?;
    if !verify_with_context(&device_sig, KSPK_SIG_CONTEXT, &kspk_pub, &kspk_sig) {
        return Err(err!(
            "device {device}'s KEM prekey is not signed by the key its \
             certificate names — refusing it"
        ));
    }

    st.peer_certs.insert(key.clone(), peer_cert);
    if st.sessions.contains_key(&key) {
        // We only needed the certificate; the ratchet is fine.
        return Ok(());
    }

    let parsed = PrekeyBundle::from_relay_json(&bundle)
        .ok_or_else(|| err!("device {device}'s prekey bundle does not parse"))?;
    let identity = Identity::from_ed25519_seed(&st.dev_sig_seed()?);
    let session = SessionState::initiate(
        &identity,
        &device_sig,
        &parsed,
        &InitiateRandom {
            ek_sk: random::<32>(),
            ratchet_sk: random::<32>(),
            kem_random: random::<32>(),
        },
    )?;
    st.sessions.insert(key, session);
    Ok(())
}

fn signed_field<'a>(bundle: &'a Value, block: &str, field: &str) -> Result<&'a str> {
    bundle
        .get(block)
        .and_then(|b| b.get(field))
        .and_then(Value::as_str)
        .ok_or_else(|| err!("prekey bundle has no {block}.{field}"))
}

/// Which of a peer's devices to encrypt for.
///
/// Not a nicety: a browser session is device 2 or later, so a reply that only
/// ever went to device 1 would reach their phone and never the tab that sent
/// the message. Which devices exist comes from their bundle token; without one
/// we can reach only their primary, which is exactly what a stranger's first
/// message gets.
async fn target_devices(st: &State, peer: &Peer, also: &[u32]) -> Vec<u32> {
    let mut ids: Vec<u32> = Vec::new();
    if let Some(token) = st.bundle_tokens.get(&peer.stonechat_id)
        && let Ok(mailbox) = Mailbox::new(&peer.relay_address, &peer.relay_tls_fp)
        && let Ok(listed) = mailbox.devices(token).await
    {
        // A listing we cannot fetch is not a reason to send nothing.
        ids = listed;
    }
    for device in also.iter().copied() {
        if !ids.contains(&device) {
            ids.push(device);
        }
    }
    if ids.is_empty() {
        ids.push(PRIMARY_DEVICE);
    }
    ids.sort_unstable();
    ids
}

pub fn short(id: &str) -> String {
    id.chars().take(12).collect()
}
