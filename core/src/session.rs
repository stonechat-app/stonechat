//! Forward-secret pairwise sessions: PQXDH establishment + double ratchet
//! + the sparse post-quantum ratchet (PROTOCOL.md "Session crypto"). The serialized JSON form keeps the shape
//! of the retired Dart `RatchetSession.toJson`.
//!
//! Sessions are **device to device**. The long-term Ed25519 keys this
//! module is handed — [`Identity`], `peer_ed_pk`, `sender_ed_pk` — are the
//! two devices' *signing* keys, not identity keys. Tying a device key to a
//! Stonechat ID is the host's job, done with a device certificate
//! (devcert.rs) before anything here is called.
//!
//! A session is a value. Nothing here talks to the network or storage, and
//! all randomness is caller-supplied. Sessions carry no owner/peer id:
//! hosts key persistence by (peer, device).

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde::{Deserialize, Serialize};

use crate::envelope::X3dhBlock;
use crate::primitives::{
    AEAD_NONCE_BYTES, aead_open, aead_seal, bytes_eq, dh, ed25519_pk_from_seed,
    ed25519_pk_to_x25519, ed25519_seed_to_x25519_sk, kdf_chain, kdf_pq, kdf_root,
    x3dh_shared_key, x25519_pk,
};

/// Per-chain gap tolerance.
pub const MAX_SKIP: u64 = 256;
/// Skipped message keys stored per session; oldest evicted.
pub const MAX_SKIPPED_KEYS: usize = 512;

/// Ratchet messages (sent + received) between two post-quantum ratchet
/// steps: once this many have passed since the last KEM secret was mixed in,
/// the initiator advertises a fresh ML-KEM key at its next sending chain.
pub const PQ_INTERVAL: u64 = 50;
/// How many messages at the start of a sending chain carry the pending KEM
/// key or ciphertext. More than one so a reordered or lost first message
/// does not cost a whole round trip; bounded so a monologue does not pay
/// for it on every message.
pub const PQ_ATTACH: u64 = 3;

/// This device's long-term handshake key, expanded from an Ed25519 seed.
/// Hosts pass the **device signing key's** seed. The type keeps its name
/// from when the identity key played this part; it no longer does.
#[derive(Clone)]
pub struct Identity {
    pub ed_seed: [u8; 32],
    pub ed_pk: [u8; 32],
    x_sk: [u8; 32],
}

impl Identity {
    pub fn from_ed25519_seed(seed: &[u8; 32]) -> Self {
        Identity {
            ed_seed: *seed,
            ed_pk: ed25519_pk_from_seed(seed),
            x_sk: ed25519_seed_to_x25519_sk(seed),
        }
    }

    pub fn ed_pk_b64(&self) -> String {
        B64.encode(self.ed_pk)
    }
}

/// A peer device's prekey bundle as served by their mailbox. Before this
/// reaches the session layer the host must have verified the device's
/// certificate against the peer's identity key, and the SPK/KSPK signatures
/// against the device key that certificate names. The one-time prekeys
/// (`opk`, `kopk`) carry no signature and cannot be verified.
#[derive(Debug, Clone)]
pub struct PrekeyBundle {
    pub spk_id: u64,
    pub spk_pub: [u8; 32],
    pub opk_id: Option<u64>,
    pub opk_pub: Option<[u8; 32]>,
    pub kspk_id: u64,
    pub kspk_pub: [u8; pqcore::MLKEM_PUBLIC_BYTES],
    pub kopk_id: Option<u64>,
    pub kopk_pub: Option<[u8; pqcore::MLKEM_PUBLIC_BYTES]>,
}

impl PrekeyBundle {
    /// Parse the bundle exactly as the peer's mailbox serves it
    /// (`GET /prekeys/bundle`, PROTOCOL.md "Prekeys"):
    /// `{"spk": {id, pub, sig}, "opk": {...}|null, "kspk": {...}, "kopk": {...}|null}`.
    /// Signatures are NOT checked here — that stays with the host, which
    /// holds the peer device's verified certificate.
    pub fn from_relay_json(v: &serde_json::Value) -> Option<PrekeyBundle> {
        fn b64<const N: usize>(v: &serde_json::Value) -> Option<[u8; N]> {
            B64.decode(v.as_str()?).ok()?.try_into().ok()
        }
        let spk = &v["spk"];
        let kspk = &v["kspk"];
        let opk = v.get("opk").filter(|o| !o.is_null());
        let kopk = v.get("kopk").filter(|k| !k.is_null());
        Some(PrekeyBundle {
            spk_id: spk["id"].as_u64()?,
            spk_pub: b64(&spk["pub"])?,
            opk_id: match opk {
                Some(o) => Some(o["id"].as_u64()?),
                None => None,
            },
            opk_pub: match opk {
                Some(o) => Some(b64(&o["pub"])?),
                None => None,
            },
            kspk_id: kspk["id"].as_u64()?,
            kspk_pub: b64(&kspk["pub"])?,
            kopk_id: match kopk {
                Some(k) => Some(k["id"].as_u64()?),
                None => None,
            },
            kopk_pub: match kopk {
                Some(k) => Some(b64(&k["pub"])?),
                None => None,
            },
        })
    }
}

/// An ML-KEM-768 encapsulation key the session's initiator advertises.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqKey {
    pub id: u64,
    /// Base64, 1184 bytes.
    #[serde(rename = "pub")]
    pub public: String,
}

/// The responder's encapsulation to the key named by `id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqCiphertext {
    pub id: u64,
    /// Base64, 1088 bytes.
    pub ct: String,
}

/// Post-quantum ratchet fields of a header (`ratchet.pq`). Absent on most
/// messages; every field is optional.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqHeader {
    /// Id of the KEM secret mixed into the root key when this sending chain
    /// began. Repeated on every message of the chain: whichever arrives
    /// first has to say so.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mix: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ek: Option<PqKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ct: Option<PqCiphertext>,
}

/// Double-ratchet message header (`ratchet` in the inner envelope).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RatchetHeader {
    /// Base64 ratchet public key.
    pub dh: String,
    pub pn: u64,
    pub n: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pq: Option<PqHeader>,
}

/// Caller-supplied CSPRNG bytes for [`SessionState::initiate`].
pub struct InitiateRandom {
    /// Secret for the ephemeral X25519 key `EK`.
    pub ek_sk: [u8; 32],
    /// Secret for the initial ratchet key `DHs`.
    pub ratchet_sk: [u8; 32],
    /// ML-KEM encapsulation randomness.
    pub kem_random: [u8; pqcore::MLKEM_ENCAPS_RANDOM_BYTES],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionError {
    /// The bundle's KEM prekey did not parse as an ML-KEM-768 key —
    /// treat like a forged bundle.
    BadKemKey,
    /// The x3dh block carried malformed key material.
    BadX3dhBlock,
    /// `encrypt` before the send chain exists (responder pre-first-receive).
    NotReadyToSend,
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            SessionError::BadKemKey => "KEM prekey does not parse (forged bundle?)",
            SessionError::BadX3dhBlock => "malformed x3dh block",
            SessionError::NotReadyToSend => "session not ready to send (no send chain yet)",
        })
    }
}

impl std::error::Error for SessionError {}

mod b64_arr {
    use super::B64;
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&B64.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        B64.decode(&s)
            .map_err(Error::custom)?
            .try_into()
            .map_err(|_| Error::custom("expected 32 bytes"))
    }
}

mod b64_arr_opt {
    use super::B64;
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer>(v: &Option<[u8; 32]>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(v) => s.serialize_some(&B64.encode(v)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 32]>, D::Error> {
        let s = Option::<String>::deserialize(d)?;
        match s {
            None => Ok(None),
            Some(s) => Ok(Some(
                B64.decode(&s)
                    .map_err(Error::custom)?
                    .try_into()
                    .map_err(|_| Error::custom("expected 32 bytes"))?,
            )),
        }
    }
}

/// One stored skipped message key; `k` is `"{dh_b64}/{n}"` as in Dart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkippedKey {
    pub k: String,
    #[serde(with = "b64_arr")]
    pub mk: [u8; 32],
}

/// Initiator: the KEM key it is advertising, until a ciphertext answers it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqLocal {
    pub id: u64,
    /// Base64 ML-KEM-768 seed (64 bytes). Deleted on decapsulation.
    pub seed: String,
}

/// Initiator: a decapsulated secret waiting for the next sending chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqInbound {
    pub id: u64,
    #[serde(with = "b64_arr")]
    pub ss: [u8; 32],
}

/// Responder: its encapsulation, kept until the initiator mixes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqOutbound {
    pub id: u64,
    /// Base64 ciphertext, re-sent until acknowledged by a `mix`.
    pub ct: String,
    #[serde(with = "b64_arr")]
    pub ss: [u8; 32],
}

/// Post-quantum ratchet state (PROTOCOL.md "Post-quantum ratchet"). The
/// session's initiator generates KEM keys, the responder encapsulates, and
/// the initiator mixes the shared secret into the root key at the start of
/// a sending chain. All defaults on a session that has not needed it yet,
/// in which case it is left out of the serialized form.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqState {
    /// Messages sent + received since the last mix (or since PQXDH).
    #[serde(default)]
    pub count: u64,
    /// Highest key id this side has advertised (initiator).
    #[serde(default)]
    pub issued: u64,
    /// Highest key id mixed into the root key.
    #[serde(default)]
    pub mixed: u64,
    /// Messages of the current sending chain that will still carry the
    /// pending key or ciphertext.
    #[serde(default)]
    pub attach: u64,
    /// The id mixed in when the current sending chain began, if one was.
    #[serde(default)]
    pub mix: Option<u64>,
    #[serde(default)]
    pub local: Option<PqLocal>,
    #[serde(default)]
    pub inbound: Option<PqInbound>,
    #[serde(default)]
    pub outbound: Option<PqOutbound>,
}

impl PqState {
    fn is_idle(&self) -> bool {
        *self == PqState::default()
    }
}

/// The full ratchet state. Serializes to the exact JSON shape of the Dart
/// `RatchetSession.toJson` (insertion-ordered `skipped`, base64 fields,
/// nulls present for absent chain keys). `pq` is this crate's addition and
/// is omitted while it holds nothing, so a Dart-written row still round
/// trips unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionState {
    pub initiated_by_us: bool,
    pub confirmed: bool,
    #[serde(with = "b64_arr")]
    pub rk: [u8; 32],
    #[serde(with = "b64_arr")]
    pub dhs_pub: [u8; 32],
    #[serde(with = "b64_arr")]
    pub dhs_sec: [u8; 32],
    #[serde(with = "b64_arr_opt")]
    pub dhr: Option<[u8; 32]>,
    #[serde(with = "b64_arr_opt")]
    pub cks: Option<[u8; 32]>,
    #[serde(with = "b64_arr_opt")]
    pub ckr: Option<[u8; 32]>,
    pub ns: u64,
    pub nr: u64,
    pub pn: u64,
    pub pending_x3dh: Option<X3dhBlock>,
    #[serde(default)]
    pub skipped: Vec<SkippedKey>,
    #[serde(default, skip_serializing_if = "PqState::is_idle")]
    pub pq: PqState,
}

impl SessionState {
    /// PQXDH as the initiator. `peer_ed_pk` is the peer **device's** signing
    /// key, taken from a device certificate the host has already verified
    /// against the peer's identity key; the bundle's SPK + KSPK signatures
    /// must already have been checked against it.
    pub fn initiate(
        identity: &Identity,
        peer_ed_pk: &[u8; 32],
        bundle: &PrekeyBundle,
        random: &InitiateRandom,
    ) -> Result<SessionState, SessionError> {
        let peer_ikx = ed25519_pk_to_x25519(peer_ed_pk).ok_or(SessionError::BadX3dhBlock)?;
        let ek_pk = x25519_pk(&random.ek_sk);

        let mut dhs = vec![
            dh(&identity.x_sk, &bundle.spk_pub), // DH1
            dh(&random.ek_sk, &peer_ikx),        // DH2
            dh(&random.ek_sk, &bundle.spk_pub),  // DH3
        ];
        if let Some(opk_pub) = &bundle.opk_pub {
            dhs.push(dh(&random.ek_sk, opk_pub)); // DH4
        }

        // The KEM half: one-time prekey when the pool had one, else the
        // signed last-resort key (same degradation story as DH4).
        let kem_one_time = bundle.kopk_pub.is_some();
        let kem_pk = bundle.kopk_pub.as_ref().unwrap_or(&bundle.kspk_pub);
        let (kct, kem_ss) =
            pqcore::mlkem_encaps(kem_pk, &random.kem_random).ok_or(SessionError::BadKemKey)?;
        let sk = x3dh_shared_key(&dhs, &kem_ss);

        // The peer's SPK doubles as their initial ratchet key.
        let ratchet_pub = x25519_pk(&random.ratchet_sk);
        let (rk, cks) = kdf_root(&sk, &dh(&random.ratchet_sk, &bundle.spk_pub));

        Ok(SessionState {
            initiated_by_us: true,
            confirmed: false,
            rk,
            dhs_pub: ratchet_pub,
            dhs_sec: random.ratchet_sk,
            dhr: Some(bundle.spk_pub),
            cks: Some(cks),
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            pending_x3dh: Some(X3dhBlock {
                ik: identity.ed_pk_b64(),
                ek: B64.encode(ek_pk),
                spk_id: bundle.spk_id,
                opk_id: bundle.opk_id,
                kct: B64.encode(kct),
                kem_id: if kem_one_time {
                    bundle.kopk_id.unwrap()
                } else {
                    bundle.kspk_id
                },
                kem_one_time,
            }),
            skipped: Vec::new(),
            pq: PqState::default(),
        })
    }

    /// PQXDH as the responder, from an initial envelope's x3dh block and
    /// our stored prekey private halves. `sender_ed_pk` is the sender
    /// **device's** signing key (`block.ik`): the host must already have
    /// verified the certificate in the block against the identity key the
    /// envelope's `from` commits to, and checked that it vouches for this
    /// key. `kem_seed` is the stored seed of the KEM prekey named by
    /// `block.kem_id`.
    ///
    /// Nothing is authenticated by this call: it cannot fail on a wrong key,
    /// it only derives a different secret. The host MUST decrypt the
    /// envelope's message with the returned session and discard the session
    /// if that fails.
    pub fn respond(
        identity: &Identity,
        sender_ed_pk: &[u8; 32],
        block: &X3dhBlock,
        spk_pub: &[u8; 32],
        spk_sec: &[u8; 32],
        opk_sec: Option<&[u8; 32]>,
        kem_seed: &[u8; pqcore::MLKEM_SEED_BYTES],
    ) -> Result<SessionState, SessionError> {
        let sender_ikx = ed25519_pk_to_x25519(sender_ed_pk).ok_or(SessionError::BadX3dhBlock)?;
        let ek = block.ek_bytes().ok_or(SessionError::BadX3dhBlock)?;
        let kct = block.kct_bytes().ok_or(SessionError::BadX3dhBlock)?;

        let mut dhs = vec![
            dh(spk_sec, &sender_ikx), // DH1
            dh(&identity.x_sk, &ek),  // DH2
            dh(spk_sec, &ek),         // DH3
        ];
        if let Some(opk_sec) = opk_sec {
            dhs.push(dh(opk_sec, &ek)); // DH4
        }
        let kem_ss = pqcore::mlkem_decaps(kem_seed, &kct);
        let sk = x3dh_shared_key(&dhs, &kem_ss);

        // Our SPK is our initial ratchet key; the first received header
        // triggers the usual DH-ratchet step before we can send.
        Ok(SessionState {
            initiated_by_us: false,
            // A responder never needs to resend the handshake, so it is
            // "confirmed" from birth. That is NOT a claim that anything has
            // been decrypted: the host must discard this session if the
            // message it was created for does not open.
            confirmed: true,
            rk: sk,
            dhs_pub: *spk_pub,
            dhs_sec: *spk_sec,
            dhr: None,
            cks: None,
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            pending_x3dh: None,
            skipped: Vec::new(),
            pq: PqState::default(),
        })
    }

    pub fn can_send(&self) -> bool {
        self.cks.is_some()
    }

    /// `{prefix}|{dh}|{pn}|{n}`, and when the header carries a `pq` block,
    /// `|pq|{mix}|{ek.id}|{ek.pub}|{ct.id}|{ct.ct}` after it (absent fields
    /// empty) — so the KEM material is authenticated by the message key.
    fn ad(ad_prefix: &str, header: &RatchetHeader) -> Vec<u8> {
        let mut ad = format!("{ad_prefix}|{}|{}|{}", header.dh, header.pn, header.n);
        if let Some(pq) = &header.pq {
            let num = |v: Option<u64>| v.map(|v| v.to_string()).unwrap_or_default();
            ad.push_str(&format!(
                "|pq|{}|{}|{}|{}|{}",
                num(pq.mix),
                num(pq.ek.as_ref().map(|k| k.id)),
                pq.ek.as_ref().map(|k| k.public.as_str()).unwrap_or(""),
                num(pq.ct.as_ref().map(|c| c.id)),
                pq.ct.as_ref().map(|c| c.ct.as_str()).unwrap_or(""),
            ));
        }
        ad.into_bytes()
    }

    /// The `pq` block for the next outgoing message, if it needs one.
    fn pq_header_for_send(&mut self) -> Option<PqHeader> {
        let mut pq = PqHeader {
            mix: self.pq.mix,
            ek: None,
            ct: None,
        };
        if self.pq.attach > 0 {
            if let Some(local) = &self.pq.local {
                let seed: Option<[u8; pqcore::MLKEM_SEED_BYTES]> =
                    B64.decode(&local.seed).ok().and_then(|s| s.try_into().ok());
                pq.ek = seed.map(|seed| PqKey {
                    id: local.id,
                    public: B64.encode(pqcore::mlkem_pk_from_seed(&seed)),
                });
            }
            if let Some(out) = &self.pq.outbound {
                pq.ct = Some(PqCiphertext {
                    id: out.id,
                    ct: out.ct.clone(),
                });
            }
            if pq.ek.is_some() || pq.ct.is_some() {
                self.pq.attach -= 1;
            }
        }
        (pq != PqHeader::default()).then_some(pq)
    }

    /// Take in the KEM material of a header whose message just
    /// authenticated. The responder encapsulates to a new key; the
    /// initiator decapsulates the answer to the key it is advertising.
    /// Anything stale, repeated or malformed is ignored — the message
    /// itself was genuine and still decrypts.
    fn absorb_pq(&mut self, header: &RatchetHeader, pq_random: &[u8; 64]) {
        let Some(pq) = &header.pq else { return };
        if let (false, Some(ek)) = (self.initiated_by_us, &pq.ek) {
            let newer = self.pq.outbound.as_ref().is_none_or(|o| o.id < ek.id);
            let key: Option<[u8; pqcore::MLKEM_PUBLIC_BYTES]> =
                B64.decode(&ek.public).ok().and_then(|k| k.try_into().ok());
            if let (true, true, Some(key)) = (ek.id > self.pq.mixed, newer, key) {
                let random: &[u8; pqcore::MLKEM_ENCAPS_RANDOM_BYTES] =
                    pq_random[..pqcore::MLKEM_ENCAPS_RANDOM_BYTES].try_into().unwrap();
                if let Some((ct, ss)) = pqcore::mlkem_encaps(&key, random) {
                    self.pq.outbound = Some(PqOutbound {
                        id: ek.id,
                        ct: B64.encode(ct),
                        ss,
                    });
                    self.pq.attach = PQ_ATTACH;
                }
            }
        }
        if let (true, Some(ct)) = (self.initiated_by_us, &pq.ct) {
            let seed: Option<[u8; pqcore::MLKEM_SEED_BYTES]> = self
                .pq
                .local
                .as_ref()
                .filter(|l| l.id == ct.id)
                .and_then(|l| B64.decode(&l.seed).ok())
                .and_then(|s| s.try_into().ok());
            let ct_bytes: Option<[u8; pqcore::MLKEM_CIPHERTEXT_BYTES]> =
                B64.decode(&ct.ct).ok().and_then(|c| c.try_into().ok());
            if let (Some(seed), Some(ct_bytes)) = (seed, ct_bytes) {
                self.pq.inbound = Some(PqInbound {
                    id: ct.id,
                    ss: pqcore::mlkem_decaps(&seed, &ct_bytes),
                });
                self.pq.local = None; // the private half is done with
            }
        }
    }

    /// Encrypt one message. `ad_prefix` is
    /// `"stonechat/v1|from|from_device|to|device|type"` — the routing
    /// fields, both device numbers included, get bound into the AEAD; this
    /// function appends `|dh|pn|n`. `nonce` must be
    /// fresh CSPRNG output; it travels beside the ciphertext in the inner
    /// envelope. Mutates the session; persist it before handing the
    /// envelope to the network.
    pub fn encrypt(
        &mut self,
        plaintext: &[u8],
        ad_prefix: &str,
        nonce: &[u8; AEAD_NONCE_BYTES],
    ) -> Result<(RatchetHeader, Vec<u8>), SessionError> {
        let send_chain = self.cks.ok_or(SessionError::NotReadyToSend)?;
        let (mk, ck_next) = kdf_chain(&send_chain);
        self.cks = Some(ck_next);
        let header = RatchetHeader {
            dh: B64.encode(self.dhs_pub),
            pn: self.pn,
            n: self.ns,
            pq: self.pq_header_for_send(),
        };
        let ad = Self::ad(ad_prefix, &header);
        let ciphertext = aead_seal(&mk, nonce, plaintext, &ad);
        self.ns += 1;
        self.pq.count += 1;
        Ok((header, ciphertext))
    }

    /// Decrypt one message. Returns `None` on failure, in which case the
    /// session state is untouched. On success the state has advanced —
    /// persist it. `fresh_ratchet_sk` must be fresh CSPRNG output; it is
    /// consumed only when the header carries a new remote ratchet key.
    /// `pq_random` is 64 more bytes of fresh CSPRNG output, **independent
    /// of `fresh_ratchet_sk`** (whose public half goes on the wire): the
    /// post-quantum ratchet draws a KEM key or an encapsulation from it
    /// when this message calls for one.
    pub fn decrypt(
        &mut self,
        header: &RatchetHeader,
        nonce: &[u8; AEAD_NONCE_BYTES],
        ciphertext: &[u8],
        ad_prefix: &str,
        fresh_ratchet_sk: &[u8; 32],
        pq_random: &[u8; 64],
    ) -> Option<Vec<u8>> {
        let ad = Self::ad(ad_prefix, header);

        // Skipped key from an earlier out-of-order message?
        let skipped_key = format!("{}/{}", header.dh, header.n);
        if let Some(pos) = self.skipped.iter().position(|s| s.k == skipped_key) {
            let entry = self.skipped.remove(pos);
            match aead_open(&entry.mk, nonce, ciphertext, &ad) {
                Some(plain) => {
                    self.confirmed = true;
                    self.pending_x3dh = None;
                    self.pq.count += 1;
                    self.absorb_pq(header, pq_random);
                    return Some(plain);
                }
                None => {
                    self.skipped.push(entry); // not it — put it back
                    return None;
                }
            }
        }

        // Work on a copy: a failed AEAD must not burn ratchet state.
        let mut trial = self.clone();
        let header_dh: [u8; 32] = B64.decode(&header.dh).ok()?.try_into().ok()?;
        let is_new_ratchet_key = match &trial.dhr {
            Some(dhr) => !bytes_eq(&header_dh, dhr),
            None => true,
        };
        if is_new_ratchet_key {
            if !trial.skip_receive_keys(header.pn) {
                return None;
            }
            // A chain that says a KEM secret was mixed in when it began: it
            // has to be the one we encapsulated, or we cannot follow.
            let mixed = match header.pq.as_ref().and_then(|pq| pq.mix) {
                Some(id) => Some(trial.pq.outbound.take().filter(|o| o.id == id)?),
                None => None,
            };
            trial.dh_ratchet(&header_dh, fresh_ratchet_sk, mixed.as_ref(), pq_random);
        }
        if !trial.skip_receive_keys(header.n) {
            return None;
        }
        let chain = trial.ckr?;
        let (mk, ck_next) = kdf_chain(&chain);
        trial.ckr = Some(ck_next);
        trial.nr += 1;
        let plain = aead_open(&mk, nonce, ciphertext, &ad)?;
        trial.confirmed = true;
        trial.pending_x3dh = None;
        trial.pq.count += 1;
        trial.absorb_pq(header, pq_random);
        *self = trial;
        Some(plain)
    }

    /// Derive and stash message keys for messages we haven't seen yet, up
    /// to (but not including) `until` on the current receive chain.
    fn skip_receive_keys(&mut self, until: u64) -> bool {
        if self.nr + MAX_SKIP < until {
            return false; // absurd gap — refuse
        }
        let Some(mut chain) = self.ckr else {
            return self.nr >= until;
        };
        let dh_b64 = self.dhr.map(|d| B64.encode(d)).unwrap_or_default();
        while self.nr < until {
            let (mk, ck_next) = kdf_chain(&chain);
            chain = ck_next;
            self.skipped.push(SkippedKey {
                k: format!("{dh_b64}/{}", self.nr),
                mk,
            });
            if self.skipped.len() > MAX_SKIPPED_KEYS {
                self.skipped.remove(0);
            }
            self.nr += 1;
        }
        self.ckr = Some(chain);
        true
    }

    /// The DH-ratchet step, with the post-quantum ratchet's two hooks: a
    /// KEM secret is mixed into the root key immediately before the chain
    /// its initiator-side owner sends on is derived — `peer_mixed` when
    /// that is the chain we are about to receive, our own `inbound` when it
    /// is the one we are about to send on.
    fn dh_ratchet(
        &mut self,
        header_dh: &[u8; 32],
        fresh_ratchet_sk: &[u8; 32],
        peer_mixed: Option<&PqOutbound>,
        pq_random: &[u8; 64],
    ) {
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        self.dhr = Some(*header_dh);
        if let Some(out) = peer_mixed {
            self.rk = kdf_pq(&self.rk, &out.ss);
            self.pq.mixed = out.id;
            self.pq.count = 0;
        }
        let (rk1, ckr_new) = kdf_root(&self.rk, &dh(&self.dhs_sec, header_dh));
        self.rk = rk1;
        self.ckr = Some(ckr_new);
        self.dhs_sec = *fresh_ratchet_sk;
        self.dhs_pub = x25519_pk(fresh_ratchet_sk);
        self.pq.mix = None;
        if let Some(inbound) = self.pq.inbound.take() {
            self.rk = kdf_pq(&self.rk, &inbound.ss);
            self.pq.mix = Some(inbound.id);
            self.pq.mixed = inbound.id;
            self.pq.count = 0;
        }
        let (rk2, cks_new) = kdf_root(&self.rk, &dh(&self.dhs_sec, header_dh));
        self.rk = rk2;
        self.cks = Some(cks_new);

        // A new sending chain re-offers whatever is still unanswered, and
        // is where the initiator starts the next KEM exchange once enough
        // traffic has passed since the last.
        self.pq.attach = PQ_ATTACH;
        if self.initiated_by_us && self.pq.local.is_none() && self.pq.count >= PQ_INTERVAL {
            self.pq.issued += 1;
            self.pq.local = Some(PqLocal {
                id: self.pq.issued,
                seed: B64.encode(pq_random),
            });
        }
    }
}
