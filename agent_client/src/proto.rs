//! Envelopes: building them, opening them, and the sessions underneath.
//!
//! The cryptography is entirely `stonechat-core` — PQXDH, the double ratchet
//! and the X-Wing seal all live there and are not reimplemented here. What
//! this module owns is the part core deliberately refuses to have: which keys
//! to fetch, which certificate to check them against, which devices a peer
//! has and which of those still speak for it, what the associated data says,
//! and when to persist the advanced ratchet.
//!
//! Three rules from the wider design govern most of the code below:
//!
//! - **One message to a peer with k devices is k envelopes**, each on its own
//!   ratchet. There is no fan-out at the relay.
//! - **Both device numbers are bound into the AEAD**, always, in one form. A
//!   relabelled envelope simply fails to decrypt.
//! - **A device is trusted on every envelope, not once.** Its certificate
//!   must be unexpired and, when its identity has published a device
//!   manifest, it must be on it (PROTOCOL.md "What a recipient checks").
//!
//! [`Agent`] is one running device: the state file, the hub, and the caches
//! that live for one run — resolved addresses, device lists, which manifests
//! were already looked for.

use std::collections::{HashMap, HashSet};

use serde_json::{Value, json};
use stonechat_core::devices::Manifest;
use stonechat_core::envelope::{self, X3dhBlock};
use stonechat_core::pqcore::XWING_ENCAPS_RANDOM_BYTES;
use stonechat_core::primitives::{
    AEAD_NONCE_BYTES, KSPK_SIG_CONTEXT, SPK_SIG_CONTEXT, aead_open, verify_with_context,
};
use stonechat_core::session::{Identity, InitiateRandom, PrekeyBundle, RatchetHeader, SessionState};

use crate::hub::{Entry, Hub, Peer};
use crate::mailbox::{Deposit, Mailbox};
use crate::state::{State, peer_key};
use crate::util::{Error, Result, b64, is_wire_id, random, short, unb64, unb64_n};
use crate::{PRIMARY_DEVICE, cert, contacts, err, manifest, state};

/// An envelope we opened and whose sending device we trust.
pub struct Incoming {
    pub id: String,
    pub from: String,
    pub from_device: u32,
    pub kind: String,
    pub payload: Value,
}

/// What a fan-out achieved: how many devices took a copy, under which id.
pub struct Sent {
    pub delivered: usize,
    pub id: String,
}

/// Delivery hints for the recipient's mailbox (PROTOCOL.md "Envelope").
#[derive(Default, Clone, Copy)]
pub struct SendOpts {
    /// Queue, but never wake the device: receipts and self-sync.
    pub no_push: bool,
}

/// One running device.
pub struct Agent {
    pub st: State,
    pub hub: Hub,
    /// Print message text to the log. Off by default: a container's stdout
    /// is kept by the host, and the owner's mail does not belong there.
    pub show_text: bool,
    /// peer → devices listed by their mailbox, for this run. Dropped on a
    /// `devices_v` bump, a `410`, a new bundle token or a newer manifest.
    device_lists: HashMap<String, Vec<u32>>,
    /// Peers whose manifest was refetched this run because their mailbox
    /// listed a device the manifest did not.
    manifest_refetched: HashSet<String>,
    /// Identities the directory said have published no manifest, this run,
    /// so a stream of envelopes does not become a stream of lookups.
    no_manifest_this_run: HashSet<String>,
    /// Mailbox addresses resolved this run.
    directory: HashMap<String, Peer>,
}

/// `stonechat/v1|from|from_device|to|device|type`, the prefix core appends the
/// ratchet header to. One form, no conditional — this is the one place where
/// a second code path would mean silent decryption failure.
fn ad_prefix(from: &str, from_device: u32, to: &str, device: u32, kind: &str) -> String {
    format!("stonechat/v1|{from}|{from_device}|{to}|{device}|{kind}")
}

/// The inner envelope after the shape checks, before any cryptography.
struct Inner {
    id: String,
    kind: String,
    from: String,
    from_device: u32,
    device: u32,
    header: RatchetHeader,
    x3dh: Option<Value>,
    nonce: [u8; AEAD_NONCE_BYTES],
    ciphertext: Vec<u8>,
    bundle_token: Option<String>,
    manifest_v: u64,
}

/// What a successful decrypt wants written to state — held back until the
/// sending device is trusted, so an envelope left for redelivery has not
/// already burned the ratchet step or a one-time prekey.
struct Commit {
    key: String,
    session: SessionState,
    opk: Option<u64>,
    kopk: Option<u64>,
    /// The sender's certificate from the handshake block, when this was one.
    cert: Option<Value>,
}

impl Agent {
    pub fn new(st: State, hub: Hub, show_text: bool) -> Agent {
        Agent {
            st,
            hub,
            show_text,
            device_lists: HashMap::new(),
            manifest_refetched: HashSet::new(),
            no_manifest_this_run: HashSet::new(),
            directory: HashMap::new(),
        }
    }

    pub fn save(&self) -> Result<()> {
        state::save(&self.st)
    }

    // -- resolving --------------------------------------------------------

    /// A directory lookup, with its manifest adopted (forward only) and its
    /// mailbox remembered for the run.
    async fn resolve(&mut self, stonechat_id: &str) -> Result<Entry> {
        let entry = self.hub.resolve(stonechat_id).await?;
        match &entry.manifest {
            Some((json, parsed)) => {
                if manifest::adopt(&mut self.st, stonechat_id, json, parsed) {
                    self.device_lists.remove(stonechat_id);
                }
            }
            None => {
                self.no_manifest_this_run.insert(stonechat_id.to_string());
            }
        }
        if let Ok(peer) = entry.peer() {
            self.directory.insert(stonechat_id.to_string(), peer);
        }
        Ok(entry)
    }

    /// Where to write to a peer. Our own mailbox comes from the grant, never
    /// from the directory: the pin our primary handed us is the pin.
    async fn peer_for(&mut self, stonechat_id: &str) -> Result<Peer> {
        if stonechat_id == self.st.stonechat_id {
            return Ok(Peer {
                stonechat_id: stonechat_id.to_string(),
                identity_pub: self.st.identity_pub()?,
                relay_address: self.st.relay_address.clone(),
                relay_tls_fp: self.st.relay_tls_fp.clone(),
            });
        }
        if let Some(peer) = self.directory.get(stonechat_id) {
            return Ok(peer.clone());
        }
        self.resolve(stonechat_id).await?.peer()
    }

    /// The identity key for a peer: what we hold, else the directory's. For
    /// a known peer the directory is never asked — an ID commits to exactly
    /// one key, and asking again would only tell the hub who writes to whom.
    async fn identity_key_for(&mut self, stonechat_id: &str) -> Result<[u8; 32]> {
        if let Some(key) = self.st.held_identity_key(stonechat_id) {
            return Ok(key);
        }
        Ok(self.resolve(stonechat_id).await?.identity_pub)
    }

    /// Our own directory record, for the manifest our primary publishes.
    /// Once per connect: it is what decides which siblings we mirror to and
    /// the version every envelope we send states.
    pub async fn refresh_own_manifest(&mut self) {
        let me = self.st.stonechat_id.clone();
        if let Err(e) = self.resolve(&me).await {
            eprintln!("  ! could not read our own directory record: {e}");
        }
    }

    // -- device manifests ---------------------------------------------------

    /// The manifest we hold for an identity, fetching from the directory
    /// when we hold none, or when `wanted` is a version above the one we
    /// hold. `None` when the identity has published none, or it cannot be
    /// fetched now — then certificates alone decide.
    async fn manifest_for(&mut self, stonechat_id: &str, wanted: u64) -> Option<Manifest> {
        let held = manifest::held(&self.st, stonechat_id);
        match &held {
            Some(m) if m.version >= wanted => return held,
            // Already looked and found none this run — unless an envelope now
            // says there is one, which is exactly the prompt to look again.
            None if wanted == 0 && self.no_manifest_this_run.contains(stonechat_id) => return None,
            _ => {}
        }
        if let Err(e) = self.resolve(stonechat_id).await {
            // Directory unreachable, or lying: judge by what we hold.
            eprintln!("  ! could not refresh {}'s device manifest: {e}", short(stonechat_id));
        }
        manifest::held(&self.st, stonechat_id)
    }

    /// The devices of a peer we may encrypt to: those listed, narrowed to
    /// the identity's manifest when it has one. A listed device that is not
    /// on the manifest we hold has the manifest refetched once — it may have
    /// just been linked — and is left out if it is still not there: a relay
    /// that keeps serving a revoked device's certificate must not get that
    /// device a copy.
    async fn allowed_devices(&mut self, stonechat_id: &str, listed: Vec<u32>) -> Vec<u32> {
        let Some(mut held) = self.manifest_for(stonechat_id, 0).await else {
            return listed;
        };
        let unlisted = |m: &Manifest, d: u32| !m.devices.iter().any(|e| e.device_id == d);
        if listed.iter().any(|d| unlisted(&held, *d))
            && self.manifest_refetched.insert(stonechat_id.to_string())
            && let Some(newer) = self.manifest_for(stonechat_id, held.version + 1).await
        {
            held = newer;
        }
        let mut allowed = Vec::with_capacity(listed.len());
        for device in listed {
            let key = peer_key(stonechat_id, device);
            // Without a certificate the fan-out skips the device anyway; with
            // one, the key must be the listed one.
            let ok = !unlisted(&held, device)
                && match self.st.held_cert(&key) {
                    None => true,
                    Some(c) => manifest::lists(&held, device, &c),
                };
            if ok {
                allowed.push(device);
            } else {
                println!(
                    "  device {device} of {} is not in their device manifest — not encrypting to it",
                    short(stonechat_id)
                );
            }
        }
        allowed
    }

    // -- certificates -------------------------------------------------------

    /// Verify a peer device's certificate and keep it. A certificate that
    /// does not verify is dropped: it is either a mailbox serving something
    /// it was not given, or a device that is not this peer's. Either way
    /// there is nothing to encrypt to.
    fn record_cert(&mut self, stonechat_id: &str, device: u32, cert: &Value, identity_pub: &[u8; 32]) -> Result<()> {
        verify_peer_cert(cert, stonechat_id, identity_pub, device)?;
        self.st
            .peer_certs
            .insert(peer_key(stonechat_id, device), cert.clone());
        Ok(())
    }

    /// Ask a peer's mailbox for its current certificates: the device listing
    /// when we hold their bundle token, else — for the primary only — the
    /// open bundle, which costs them a one-time prekey.
    async fn refetch_cert(&mut self, peer: &Peer, mailbox: &Mailbox, device: u32) -> Result<()> {
        if self.st.bundle_token_for(&peer.stonechat_id).is_some() {
            self.device_lists.remove(&peer.stonechat_id);
            self.list_devices(peer, mailbox).await?;
        } else if device == PRIMARY_DEVICE {
            let bundle = mailbox.prekey_bundle(PRIMARY_DEVICE, None).await?;
            if let Some(c) = bundle.get("cert").filter(|c| !c.is_null())
                && let Err(e) = self.record_cert(&peer.stonechat_id, device, c, &peer.identity_pub)
            {
                eprintln!("  ! {}: {e}", short(&peer.stonechat_id));
            }
        }
        Ok(())
    }

    /// The certificate for one of a peer's devices — the thing that says
    /// which key to seal to. Refetched when the one we hold is nearing
    /// expiry rather than when it has lapsed: a stale-but-valid certificate
    /// beats refusing to send because a refresh could not happen right now.
    /// An expired one is not valid: a device whose certificate has run out
    /// is not encrypted to, whatever its mailbox still lists.
    async fn cert_for(&mut self, peer: &Peer, mailbox: &Mailbox, device: u32) -> Result<Option<Value>> {
        let key = peer_key(&peer.stonechat_id, device);
        if let Some(held) = self.st.held_cert(&key)
            && !cert::needs_refresh(&held)
        {
            return Ok(Some(held));
        }
        if let Err(e) = self.refetch_cert(peer, mailbox, device).await {
            eprintln!(
                "  ! could not refresh device {device} of {}'s certificate: {e}",
                short(&peer.stonechat_id)
            );
        }
        Ok(self.st.held_cert(&key))
    }

    /// List a peer's devices, recording the certificate each publishes.
    /// Cached for the run. Without a bundle token only the primary is
    /// reachable, which is what a stranger's first message gets.
    async fn list_devices(&mut self, peer: &Peer, mailbox: &Mailbox) -> Result<Vec<u32>> {
        let id = &peer.stonechat_id;
        if let Some(cached) = self.device_lists.get(id) {
            return Ok(cached.clone());
        }
        let Some(token) = self.st.bundle_token_for(id).map(str::to_string) else {
            return Ok(vec![PRIMARY_DEVICE]);
        };
        let listed = mailbox.devices(&token).await?;
        let mut ids = Vec::with_capacity(listed.devices.len());
        for (device, cert) in listed.devices {
            ids.push(device);
            if let Some(c) = cert
                && let Err(e) = self.record_cert(id, device, &c, &peer.identity_pub)
            {
                eprintln!("  ! {} device {device}: {e}", short(id));
            }
        }
        if let Some(v) = listed.devices_v {
            self.note_devices_v(id, v);
        }
        if ids.is_empty() {
            ids.push(PRIMARY_DEVICE);
        }
        self.device_lists.insert(id.clone(), ids.clone());
        Ok(ids)
    }

    /// A peer's device set changed — drop the cached list so the next send
    /// re-reads it, and remember the version we saw.
    fn note_devices_v(&mut self, stonechat_id: &str, devices_v: u64) {
        let held = self.st.devices_v.get(stonechat_id).copied().unwrap_or(0);
        if devices_v > held {
            self.device_lists.remove(stonechat_id);
            self.st
                .devices_v
                .insert(stonechat_id.to_string(), devices_v);
        }
    }

    // -- receiving ----------------------------------------------------------

    /// Unseal, check, decrypt, and decide whether the sending device still
    /// speaks for its sender — in that order, and nothing is written to
    /// state until the last step passes.
    ///
    /// A `Permanent` error is an envelope to drop and ack; a `Transient` one
    /// (the sender's mailbox or the directory could not be reached while
    /// checking a certificate) is one to leave queued, which is safe exactly
    /// because nothing was committed.
    pub async fn open(&mut self, outer: &Value) -> Result<Incoming> {
        let me = self.st.stonechat_id.clone();
        if outer.get("to").and_then(Value::as_str) != Some(me.as_str()) {
            return Err(err!("wire envelope is addressed to someone else"));
        }
        let outer_id = outer
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| err!("wire envelope has no id"))?;
        let sealed_b64 = outer
            .get("sealed")
            .and_then(Value::as_str)
            .ok_or_else(|| err!("wire envelope has no sealed body"))?;
        let seal_seed = self.st.dev_seal_seed()?;
        let opened = envelope::unseal(&seal_seed, &unb64(sealed_b64)?).ok_or_else(|| {
            err!(
                "envelope is not sealed to this device's key, or is not padded as the \
                 protocol pads — it was addressed to a different device, or our \
                 certificate has been replaced"
            )
        })?;
        let raw: Value =
            serde_json::from_slice(&opened).map_err(|e| err!("inner envelope is not JSON: {e}"))?;
        let inner = parse_inner(&raw, outer_id, &me, self.st.device_id)?;

        let (plain, commit) = self.decrypt(&inner).await?;
        let payload: Value =
            serde_json::from_slice(&plain).map_err(|e| err!("payload is not JSON: {e}"))?;
        if !payload.is_object() {
            return Err(err!("payload is not an object"));
        }

        // The device that wrote this must still speak for the sender: its
        // certificate unexpired, and listed in the sender's device manifest
        // when the sender has one. A session that was fine when it started
        // does not settle this — the device may have been revoked since.
        let sender_cert = self.sender_cert(&inner, commit.cert.as_ref()).await?;
        if let Some(m) = self.manifest_for(&inner.from, inner.manifest_v).await
            && !manifest::lists(&m, inner.from_device, &sender_cert)
        {
            return Err(err!(
                "sender device {} of {} is not in their device manifest (version {}) — dropping",
                inner.from_device,
                short(&inner.from),
                m.version
            ));
        }

        // Only now does anything change.
        self.st.sessions.insert(commit.key, commit.session);
        if let Some(id) = commit.opk {
            self.st.opks.remove(&id);
        }
        if let Some(id) = commit.kopk {
            self.st.kopks.remove(&id);
        }
        if let Some(c) = commit.cert {
            self.st
                .peer_certs
                .insert(peer_key(&inner.from, inner.from_device), c);
        }
        // Their bundle token rides every envelope. It is what lets a reply
        // reach all of their devices instead of only their primary; learned
        // from anyone, but only once the envelope has decrypted.
        if inner.from != me
            && let Some(token) = &inner.bundle_token
            && self.st.bundle_tokens.get(&inner.from) != Some(token)
        {
            self.st
                .bundle_tokens
                .insert(inner.from.clone(), token.clone());
            self.device_lists.remove(&inner.from);
        }

        Ok(Incoming {
            id: inner.id,
            from: inner.from,
            from_device: inner.from_device,
            kind: inner.kind,
            payload,
        })
    }

    /// Decrypt on the sender's session, or establish a responder session
    /// from the envelope's handshake block. Nothing is written to state.
    async fn decrypt(&mut self, inner: &Inner) -> Result<(Vec<u8>, Commit)> {
        let me = self.st.stonechat_id.clone();
        let prefix = ad_prefix(&inner.from, inner.from_device, &me, inner.device, &inner.kind);
        let key = peer_key(&inner.from, inner.from_device);

        if let Some(existing) = self.st.sessions.get(&key) {
            // Simultaneous initiation: both sides started a session with each
            // other, and each holds an unconfirmed one it initiated. The lower
            // Stonechat ID's wins (PROTOCOL.md "PQXDH"): if theirs does, ours
            // is skipped and theirs adopted below; if ours does, their initial
            // envelope is dropped rather than allowed to replace a session
            // they are about to adopt. Between two of our own devices the IDs
            // are equal and the lower device number decides.
            let racing = inner.x3dh.is_some() && !existing.confirmed && existing.initiated_by_us;
            let theirs_wins = racing
                && (inner.from < me || (inner.from == me && inner.from_device < self.st.device_id));
            if !theirs_wins {
                let mut trial = existing.clone();
                if let Some(plain) = trial.decrypt(
                    &inner.header,
                    &inner.nonce,
                    &inner.ciphertext,
                    &prefix,
                    &random::<32>(),
                    &random::<64>(),
                ) {
                    return Ok((
                        plain,
                        Commit {
                            key,
                            session: trial,
                            opk: None,
                            kopk: None,
                            cert: None,
                        },
                    ));
                }
                if inner.x3dh.is_none() {
                    return Err(err!(
                        "could not decrypt an envelope from {} device {} on the established \
                         session, and it carries no handshake to start a new one",
                        short(&inner.from),
                        inner.from_device
                    ));
                }
                if racing {
                    return Err(err!(
                        "simultaneous handshake with {} device {} — ours wins, theirs dropped",
                        short(&inner.from),
                        inner.from_device
                    ));
                }
                // Falling through is deliberate: a peer who reinstalled sends
                // a fresh handshake on top of a session we still hold.
            }
        }

        let (mut fresh, consumed, sender_cert) = self.respond(inner).await?;
        let plain = fresh
            .decrypt(
                &inner.header,
                &inner.nonce,
                &inner.ciphertext,
                &prefix,
                &random::<32>(),
                &random::<64>(),
            )
            .ok_or_else(|| {
                err!(
                    "handshake from {} device {} verified but its first message did not decrypt",
                    short(&inner.from),
                    inner.from_device
                )
            })?;
        Ok((
            plain,
            Commit {
                key,
                session: fresh,
                opk: consumed.0,
                kopk: consumed.1,
                cert: Some(sender_cert),
            },
        ))
    }

    /// Responder PQXDH from an initial envelope's x3dh block.
    ///
    /// Two checks: the certificate against the identity key the sender's
    /// SC- ID *does* commit to, then the handshake key against what that
    /// certificate vouches for. Skipping the second would make the
    /// certificate decoration. The one-time prekeys named are read, not
    /// removed: they are spent only once the message has decrypted and the
    /// device has been trusted.
    async fn respond(&mut self, inner: &Inner) -> Result<(SessionState, (Option<u64>, Option<u64>), Value)> {
        let x3dh = inner.x3dh.as_ref().ok_or_else(|| {
            err!(
                "no session with {} device {} and no handshake",
                short(&inner.from),
                inner.from_device
            )
        })?;
        let block: X3dhBlock = serde_json::from_value(x3dh.clone())
            .map_err(|e| err!("malformed handshake block: {e}"))?;
        let sender_cert = x3dh
            .get("cert")
            .filter(|v| !v.is_null())
            .cloned()
            .ok_or_else(|| err!("initial envelope from {} carries no device certificate", short(&inner.from)))?;

        // The identity key comes from what we hold, or the directory — never
        // from the envelope.
        let identity_pub = self.identity_key_for(&inner.from).await?;
        verify_peer_cert(&sender_cert, &inner.from, &identity_pub, inner.from_device)?;
        let certified_sig = cert::sig_key(&sender_cert)?;
        let block_ik: [u8; 32] = unb64_n(&block.ik, "handshake identity key")?;
        if certified_sig != block_ik {
            return Err(err!(
                "the handshake key from {} is not the one its certificate vouches for — refusing it",
                short(&inner.from)
            ));
        }

        let spk = self.st.spk_for(block.spk_id)?.clone();
        let spk_pub: [u8; 32] = unb64_n(&spk.public_b64, "our signed prekey")?;
        let spk_sec: [u8; 32] = unb64_n(&spk.secret_b64, "our signed prekey secret")?;
        let opk_sec = match block.opk_id {
            Some(id) => Some(
                self.st
                    .opks
                    .get(&id)
                    .ok_or_else(|| err!("handshake uses one-time prekey {id}, which we no longer hold"))
                    .and_then(|s| unb64_n::<32>(s, "one-time prekey"))?,
            ),
            None => None,
        };
        let kem_seed = self.st.kem_seed_for(block.kem_id, block.kem_one_time)?;

        let identity = Identity::from_ed25519_seed(&self.st.dev_sig_seed()?);
        let session = SessionState::respond(
            &identity,
            &block_ik,
            &block,
            &spk_pub,
            &spk_sec,
            opk_sec.as_ref(),
            &kem_seed,
        )?;
        let kopk = block.kem_one_time.then_some(block.kem_id);
        Ok((session, (block.opk_id, kopk), sender_cert))
    }

    /// The certificate that vouches for the device an envelope came from:
    /// the handshake's, or the one held, or — when that has expired — a
    /// renewed one from the sender's mailbox, which a device still linked
    /// has and a revoked one does not.
    async fn sender_cert(&mut self, inner: &Inner, from_block: Option<&Value>) -> Result<Value> {
        if let Some(c) = from_block {
            return Ok(c.clone());
        }
        let key = peer_key(&inner.from, inner.from_device);
        if let Some(held) = self.st.held_cert(&key) {
            return Ok(held);
        }
        let peer = self.peer_for(&inner.from).await?;
        let mailbox = Mailbox::new(&peer.relay_address, &peer.relay_tls_fp)?;
        self.refetch_cert(&peer, &mailbox, inner.from_device).await?;
        self.st.held_cert(&key).ok_or_else(|| {
            err!(
                "sender device {} of {}: certificate expired and none newer is published — dropping",
                inner.from_device,
                short(&inner.from)
            )
        })
    }

    // -- sending ------------------------------------------------------------

    /// Send one logical message to every device of a peer we may reach:
    /// those its mailbox lists (plus `also`, the device that spoke to us,
    /// which exists whatever the listing says), narrowed to its manifest.
    ///
    /// One dead device does not stop its siblings: whichever took a copy will
    /// show the message, so this only fails when *nothing* got through.
    pub async fn send_to_peer(
        &mut self,
        stonechat_id: &str,
        kind: &str,
        payload: &Value,
        also: &[u32],
        opts: SendOpts,
    ) -> Result<Sent> {
        let peer = self.peer_for(stonechat_id).await?;
        let mailbox = Mailbox::new(&peer.relay_address, &peer.relay_tls_fp)?;
        let mut devices = match self.list_devices(&peer, &mailbox).await {
            Ok(listed) => listed,
            Err(e) => {
                // A listing we cannot fetch is not a reason to send nothing.
                eprintln!("  ! could not list {}'s devices: {e}", short(stonechat_id));
                Vec::new()
            }
        };
        for device in also {
            if !devices.contains(device) {
                devices.push(*device);
            }
        }
        if devices.is_empty() {
            devices.push(PRIMARY_DEVICE);
        }
        let to_self = stonechat_id == self.st.stonechat_id;
        if to_self {
            devices.retain(|d| *d != self.st.device_id);
        }
        devices.sort_unstable();
        let allowed = self.allowed_devices(stonechat_id, devices).await;
        let envelope_id = uuid::Uuid::new_v4().to_string();
        if allowed.is_empty() {
            return if to_self {
                Ok(Sent { delivered: 0, id: envelope_id }) // no siblings is not a failure
            } else {
                Err(err!("no device of {} may be encrypted to", short(stonechat_id)))
            };
        }

        let mut delivered = 0usize;
        let mut last_error: Option<Error> = None;
        for device in allowed {
            match self
                .one_device(&peer, &mailbox, kind, payload, device, &envelope_id, opts)
                .await
            {
                Ok(()) => delivered += 1,
                Err(e) => {
                    eprintln!("  ! {} device {device}: {e}", short(stonechat_id));
                    last_error = Some(e);
                }
            }
        }
        if delivered == 0 {
            return Err(last_error.unwrap_or_else(|| err!("no reachable device for {}", short(stonechat_id))));
        }
        Ok(Sent { delivered, id: envelope_id })
    }

    /// Mirror something to our own other devices. Best-effort, `push: false`
    /// throughout — our own laptop catching up is never worth lighting up
    /// our own phone.
    pub async fn sync_to_siblings(&mut self, kind: &str, payload: &Value) {
        let me = self.st.stonechat_id.clone();
        if let Err(e) = self
            .send_to_peer(&me, kind, payload, &[], SendOpts { no_push: true })
            .await
        {
            eprintln!("  ! could not mirror {kind} to our other devices: {e}");
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn one_device(
        &mut self,
        peer: &Peer,
        mailbox: &Mailbox,
        kind: &str,
        payload: &Value,
        device: u32,
        envelope_id: &str,
        opts: SendOpts,
    ) -> Result<()> {
        let key = peer_key(&peer.stonechat_id, device);
        self.ensure_session(peer, mailbox, device).await?;
        // Which key this device's mail is sealed to, from its certificate.
        // No certificate, or an expired one, means there is nothing to
        // encrypt to — skip it rather than falling back to anything else,
        // which is exactly what certificates replaced.
        let target = self
            .cert_for(peer, mailbox, device)
            .await?
            .ok_or_else(|| err!("no usable certificate — not encrypting to it"))?;
        let seal_pub = cert::seal_key(&target)?;

        let prefix = ad_prefix(
            &self.st.stonechat_id,
            self.st.device_id,
            &peer.stonechat_id,
            device,
            kind,
        );
        let nonce = random::<AEAD_NONCE_BYTES>();
        let (header, ciphertext, x3dh) = {
            let own_cert = self.st.cert.clone();
            let session = self
                .st
                .sessions
                .get_mut(&key)
                .ok_or_else(|| err!("no session for {key} after establishing one"))?;
            let (header, ciphertext) =
                session.encrypt(&serde_json::to_vec(payload)?, &prefix, &nonce)?;
            // Our certificate travels with the handshake so the responder can
            // trust the device key inside it without fetching anything. core
            // builds the cryptographic parts of the block; the certificate is
            // a client-layer addition (the same split as the Dart `withCert`).
            let x3dh = match &session.pending_x3dh {
                Some(block) => {
                    let mut v = serde_json::to_value(block)?;
                    v["cert"] = own_cert;
                    Some(v)
                }
                None => None,
            };
            (header, ciphertext, x3dh)
        };

        // Persist the advanced chain **before** the envelope can leave. A
        // crash after send must never reuse a message key, so the ordering
        // is: advance, write, then transmit. Losing the message is
        // recoverable; reusing a key is not.
        self.save()?;

        let mut inner = json!({
            "v": 1,
            "id": envelope_id,
            "type": kind,
            "from": self.st.stonechat_id,
            "from_device": self.st.device_id,
            "to": peer.stonechat_id,
            "device": device,
            "sent_at": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "ratchet": serde_json::to_value(&header)?,
            "nonce": b64(&nonce),
            "ciphertext": b64(&ciphertext),
            "manifest_v": self.st.own_manifest_v(),
        });
        if let Some(x3dh) = x3dh {
            inner["x3dh"] = x3dh;
        }
        if let Some(token) = &self.st.bundle_token {
            // So the peer can reach all of *our* devices, not just the primary.
            inner["bundle_token"] = Value::String(token.clone());
        }

        let sealed = envelope::seal_to(
            &seal_pub,
            &serde_json::to_vec(&inner)?,
            &random::<XWING_ENCAPS_RANDOM_BYTES>(),
            &random::<AEAD_NONCE_BYTES>(),
        )
        .ok_or_else(|| err!("that device's certified seal key does not parse"))?;

        let mut outer = json!({
            "v": 1,
            "id": envelope_id,
            "to": peer.stonechat_id,
            "device": device,
            "sealed": b64(&sealed),
        });
        if opts.no_push {
            outer["push"] = Value::Bool(false);
        }
        match mailbox.deliver(&outer).await? {
            Deposit::Accepted { devices_v } => {
                if let Some(v) = devices_v {
                    self.note_devices_v(&peer.stonechat_id, v);
                }
                Ok(())
            }
            Deposit::Gone { devices_v } => {
                // Revoked or never existed. Forget it and its ratchet; nobody
                // is owed a copy for a device that is gone.
                self.st.forget_device(&peer.stonechat_id, device);
                self.device_lists.remove(&peer.stonechat_id);
                if let Some(v) = devices_v {
                    self.note_devices_v(&peer.stonechat_id, v);
                }
                Err(err!("that device is gone (410) — forgotten"))
            }
        }
    }

    /// Establish a session with one device of a peer, if we do not have one.
    ///
    /// Two steps, and the order is the whole point: the bundle's certificate
    /// is checked against the peer's IDENTITY key (which their SC- ID
    /// commits to), and the prekeys are then checked against the DEVICE key
    /// that certificate names.
    async fn ensure_session(&mut self, peer: &Peer, mailbox: &Mailbox, device: u32) -> Result<()> {
        let key = peer_key(&peer.stonechat_id, device);
        if self.st.sessions.contains_key(&key) {
            return Ok(());
        }
        let token = self.st.bundle_token_for(&peer.stonechat_id).map(str::to_string);
        let bundle = mailbox.prekey_bundle(device, token.as_deref()).await?;

        let peer_cert = bundle
            .get("cert")
            .filter(|v| !v.is_null())
            .cloned()
            .ok_or_else(|| err!("device {device} publishes no certificate — nothing to encrypt to"))?;
        self.record_cert(&peer.stonechat_id, device, &peer_cert, &peer.identity_pub)?;
        let device_sig = cert::sig_key(&peer_cert)?;

        let spk_pub = unb64(signed_field(&bundle, "spk", "pub")?)?;
        let spk_sig: [u8; 64] = unb64_n(signed_field(&bundle, "spk", "sig")?, "spk signature")?;
        if !verify_with_context(&device_sig, SPK_SIG_CONTEXT, &spk_pub, &spk_sig) {
            return Err(err!(
                "device {device}'s signed prekey is not signed by the key its certificate names — refusing it"
            ));
        }
        let kspk_pub = unb64(signed_field(&bundle, "kspk", "pub")?)?;
        let kspk_sig: [u8; 64] = unb64_n(signed_field(&bundle, "kspk", "sig")?, "kspk signature")?;
        if !verify_with_context(&device_sig, KSPK_SIG_CONTEXT, &kspk_pub, &kspk_sig) {
            return Err(err!(
                "device {device}'s KEM prekey is not signed by the key its certificate names — refusing it"
            ));
        }

        let parsed = PrekeyBundle::from_relay_json(&bundle)
            .ok_or_else(|| err!("device {device}'s prekey bundle does not parse"))?;
        let identity = Identity::from_ed25519_seed(&self.st.dev_sig_seed()?);
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
        self.st.sessions.insert(key, session);
        Ok(())
    }

    // -- self-sync we apply ---------------------------------------------------

    /// The primary renewed this device's certificate: adopt it if it is
    /// ours in every respect — our identity, our slot, our keys — and later
    /// than the one we hold. The caller republishes prekeys under it so
    /// peers pick it up. Returns whether anything changed.
    pub fn apply_sync_cert(&mut self, payload: &Value) -> Result<bool> {
        let renewed = payload
            .get("cert")
            .filter(|c| c.is_object())
            .ok_or_else(|| err!("sync_cert carries no certificate"))?;
        let identity_pub = self.st.identity_pub()?;
        let parsed = verify_peer_cert(renewed, &self.st.stonechat_id, &identity_pub, self.st.device_id)?;
        if parsed.sig_pub != state::sig_public(&self.st.dev_sig_seed()?)
            || parsed.seal_pub != state::seal_public(&self.st.dev_seal_seed()?)
        {
            return Err(err!("renewed certificate names other keys — not ours"));
        }
        if parsed.not_after <= cert::not_after(&self.st.cert) {
            return Ok(false); // not later than the one held
        }
        self.st.cert = renewed.clone();
        Ok(true)
    }

    /// Our primary's export, for this freshly linked device: contacts and
    /// blocks are taken, the rest is not ours to keep (PROTOCOL.md "History
    /// bootstrap"). Fetched from our own mailbox — and nowhere else — with
    /// the capability in the payload, opened with the key beside it.
    pub async fn apply_sync_history(&mut self, payload: &Value) -> Result<String> {
        let s = |k: &str| payload.get(k).and_then(Value::as_str);
        if s("blob_host") != Some(self.st.relay_address.as_str())
            || s("blob_tls_fp") != Some(self.st.relay_tls_fp.as_str())
        {
            return Err(err!("sync_history names a blob host that is not our own mailbox"));
        }
        let blob_id = s("blob_id").filter(|id| is_wire_id(id)).ok_or_else(|| err!("sync_history blob_id is not a UUID"))?;
        // A capability on that one blob — never our device token, which is a
        // login to the mailbox, not a capability on a blob.
        let fetch_token = s("fetch_token").filter(|t| !t.is_empty()).ok_or_else(|| err!("sync_history carries no fetch token"))?;
        let key: [u8; 32] = unb64_n(s("key").unwrap_or(""), "blob key")?;
        let nonce: [u8; AEAD_NONCE_BYTES] = unb64_n(s("blob_nonce").unwrap_or(""), "blob nonce")?;

        let mailbox = Mailbox::new(&self.st.relay_address, &self.st.relay_tls_fp)?;
        let sealed = mailbox
            .fetch_blob(blob_id, fetch_token)
            .await?
            .ok_or_else(|| err!("sync_history blob {blob_id} is gone from our mailbox — nothing applied"))?;
        let compressed = aead_open(&key, &nonce, &sealed, b"")
            .ok_or_else(|| err!("sync_history blob does not open with the key sent for it"))?;
        let mut plain = Vec::new();
        std::io::Read::read_to_end(&mut flate2::read::GzDecoder::new(&compressed[..]), &mut plain)
            .map_err(|e| err!("sync_history payload is not gzip: {e}"))?;
        let export: Value =
            serde_json::from_slice(&plain).map_err(|e| err!("sync_history payload is not JSON: {e}"))?;
        let (added, blocked) = contacts::merge_backup(&mut self.st, &export)?;
        self.device_lists.clear();
        Ok(format!(
            "bootstrapped from our primary: {added} contacts and {blocked} blocks added ({} contacts held)",
            self.st.contacts.len()
        ))
    }
}

/// A certificate for `device` of `stonechat_id`, verified against the
/// identity key that ID commits to. `core` checks the signature, the
/// commitment and the expiry; the name and the slot are checked here, as
/// PROTOCOL.md's checks 4 and 5 — a certificate that is *true* is not yet
/// the *right* one.
fn verify_peer_cert(
    cert_json: &Value,
    stonechat_id: &str,
    identity_pub: &[u8; 32],
    device: u32,
) -> Result<stonechat_core::devcert::DeviceCert> {
    let parsed = cert::verify(cert_json, identity_pub, Some(device))?;
    if parsed.stonechat_id != stonechat_id {
        return Err(err!(
            "certificate is for {} but arrived for {}",
            short(&parsed.stonechat_id),
            short(stonechat_id)
        ));
    }
    Ok(parsed)
}

/// The shape checks PROTOCOL.md "What a recipient checks" requires before
/// any cryptography is attempted. Cheap, the same on every client, and an
/// envelope that fails one is dropped — and acked, because it can never
/// succeed.
fn parse_inner(j: &Value, outer_id: &str, me: &str, my_device: u32) -> Result<Inner> {
    if !j.is_object() {
        return Err(err!("inner envelope is not an object"));
    }
    let s = |k: &str| j.get(k).and_then(Value::as_str);
    let id = s("id").ok_or_else(|| err!("inner envelope has no id"))?;
    if !is_wire_id(id) {
        return Err(err!("inner id is not a UUID"));
    }
    // One id names a message everywhere — it is what gets acked, stored and
    // receipted — and an inner id that disagrees is a sender trying to be
    // filed under a name the mailbox never saw.
    if id != outer_id {
        return Err(err!("inner id differs from the id on the wire"));
    }
    if s("to") != Some(me) {
        return Err(err!("inner envelope is addressed to someone else"));
    }
    let kind = s("type").filter(|t| !t.is_empty()).ok_or_else(|| err!("inner envelope has no type"))?;
    let from = s("from").filter(|f| !f.is_empty()).ok_or_else(|| err!("inner envelope has no sender"))?;
    // Both are bound into the AEAD; a default for either would make sender
    // and receiver agree on what "absent" meant.
    let device_field = |k: &str| -> Result<u32> {
        j.get(k)
            .and_then(Value::as_u64)
            .and_then(|d| u32::try_from(d).ok())
            .filter(|d| *d >= 1)
            .ok_or_else(|| err!("inner envelope {k} is missing or not a device number"))
    };
    let from_device = device_field("from_device")?;
    let device = device_field("device")?;
    if device != my_device {
        return Err(err!("inner envelope is addressed to another of our devices"));
    }
    if let Some(blob_id) = j.get("blob_id").filter(|b| !b.is_null())
        && !blob_id.as_str().is_some_and(is_wire_id)
    {
        return Err(err!("blob_id is not a UUID"));
    }
    let header: RatchetHeader = serde_json::from_value(
        j.get("ratchet")
            .cloned()
            .ok_or_else(|| err!("envelope carries no ratchet header"))?,
    )
    .map_err(|e| err!("malformed ratchet header: {e}"))?;
    let nonce: [u8; AEAD_NONCE_BYTES] =
        unb64_n(s("nonce").ok_or_else(|| err!("envelope has no nonce"))?, "envelope nonce")?;
    let ciphertext = unb64(s("ciphertext").ok_or_else(|| err!("envelope has no ciphertext"))?)?;
    Ok(Inner {
        id: id.to_string(),
        kind: kind.to_string(),
        from: from.to_string(),
        from_device,
        device,
        header,
        x3dh: j.get("x3dh").filter(|x| x.is_object()).cloned(),
        nonce,
        ciphertext,
        bundle_token: s("bundle_token").filter(|t| !t.is_empty()).map(str::to_string),
        manifest_v: j.get("manifest_v").and_then(Value::as_u64).unwrap_or(0),
    })
}

fn signed_field<'a>(bundle: &'a Value, block: &str, field: &str) -> Result<&'a str> {
    bundle
        .get(block)
        .and_then(|b| b.get(field))
        .and_then(Value::as_str)
        .ok_or_else(|| err!("prekey bundle has no {block}.{field}"))
}
