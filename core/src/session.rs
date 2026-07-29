//! Forward-secret pairwise sessions: PQXDH establishment + double ratchet
//! (PROTOCOL.md "Session crypto"). Faithful port of the Dart
//! `RatchetSession` (app/lib/core/session.dart); the serialized JSON form
//! is byte-compatible with its `toJson`, so a host can hand the same DB
//! rows to either implementation during migration.
//!
//! A session is a value. Nothing here talks to the network or storage, and
//! all randomness is caller-supplied. Sessions carry no owner/peer id:
//! hosts key persistence by (peer, device) per MULTIDEVICE.md.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde::{Deserialize, Serialize};

use crate::envelope::X3dhBlock;
use crate::primitives::{
    AEAD_NONCE_BYTES, aead_open, aead_seal, bytes_eq, dh, ed25519_pk_from_seed,
    ed25519_pk_to_x25519, ed25519_seed_to_x25519_sk, kdf_chain, kdf_root, x3dh_shared_key,
    x25519_pk,
};

/// Per-chain gap tolerance.
pub const MAX_SKIP: u64 = 256;
/// Skipped message keys stored per session; oldest evicted.
pub const MAX_SKIPPED_KEYS: usize = 512;

/// Own identity, expanded from the Ed25519 seed (the first 32 bytes of the
/// libsodium signing key the app stores).
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

/// A peer's prekey bundle as served by their mailbox. The host must have
/// verified the SPK/KSPK signatures and the identity-key commitment before
/// this reaches the session layer.
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
    /// holds the peer's verified identity key.
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

/// Double-ratchet message header (`ratchet` in the inner envelope).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RatchetHeader {
    /// Base64 ratchet public key.
    pub dh: String,
    pub pn: u64,
    pub n: u64,
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

/// The full ratchet state. Serializes to the exact JSON shape of the Dart
/// `RatchetSession.toJson` (insertion-ordered `skipped`, base64 fields,
/// nulls present for absent chain keys).
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
}

impl SessionState {
    /// PQXDH as the initiator. The peer's Ed25519 key must already be
    /// commitment-verified against their Stonechat ID and the bundle's
    /// SPK + KSPK signatures checked by the host.
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
        })
    }

    /// PQXDH as the responder, from an initial envelope's x3dh block and
    /// our stored prekey private halves. The sender's Ed25519 key must
    /// already be commitment-verified against the envelope's `from`.
    /// `kem_seed` is the stored seed of the KEM prekey named by
    /// `block.kem_id`.
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
            confirmed: true, // born from a successfully decrypted message
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
        })
    }

    pub fn can_send(&self) -> bool {
        self.cks.is_some()
    }

    fn ad(ad_prefix: &str, dh_b64: &str, pn: u64, n: u64) -> Vec<u8> {
        format!("{ad_prefix}|{dh_b64}|{pn}|{n}").into_bytes()
    }

    /// Encrypt one message. `ad_prefix` is `"stonechat/v1|from|to|type"` — the
    /// cleartext routing fields get bound into the AEAD. `nonce` must be
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
        let dh_b64 = B64.encode(self.dhs_pub);
        let ad = Self::ad(ad_prefix, &dh_b64, self.pn, self.ns);
        let ciphertext = aead_seal(&mk, nonce, plaintext, &ad);
        let header = RatchetHeader {
            dh: dh_b64,
            pn: self.pn,
            n: self.ns,
        };
        self.ns += 1;
        Ok((header, ciphertext))
    }

    /// Decrypt one message. Returns `None` on failure, in which case the
    /// session state is untouched. On success the state has advanced —
    /// persist it. `fresh_ratchet_sk` must be fresh CSPRNG output; it is
    /// consumed only when the header carries a new remote ratchet key.
    pub fn decrypt(
        &mut self,
        header: &RatchetHeader,
        nonce: &[u8; AEAD_NONCE_BYTES],
        ciphertext: &[u8],
        ad_prefix: &str,
        fresh_ratchet_sk: &[u8; 32],
    ) -> Option<Vec<u8>> {
        let ad = Self::ad(ad_prefix, &header.dh, header.pn, header.n);

        // Skipped key from an earlier out-of-order message?
        let skipped_key = format!("{}/{}", header.dh, header.n);
        if let Some(pos) = self.skipped.iter().position(|s| s.k == skipped_key) {
            let entry = self.skipped.remove(pos);
            match aead_open(&entry.mk, nonce, ciphertext, &ad) {
                Some(plain) => {
                    self.confirmed = true;
                    self.pending_x3dh = None;
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
            trial.dh_ratchet(&header_dh, fresh_ratchet_sk);
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

    fn dh_ratchet(&mut self, header_dh: &[u8; 32], fresh_ratchet_sk: &[u8; 32]) {
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        self.dhr = Some(*header_dh);
        let (rk1, ckr_new) = kdf_root(&self.rk, &dh(&self.dhs_sec, header_dh));
        self.rk = rk1;
        self.ckr = Some(ckr_new);
        self.dhs_sec = *fresh_ratchet_sk;
        self.dhs_pub = x25519_pk(fresh_ratchet_sk);
        let (rk2, cks_new) = kdf_root(&self.rk, &dh(&self.dhs_sec, header_dh));
        self.rk = rk2;
        self.cks = Some(cks_new);
    }
}
