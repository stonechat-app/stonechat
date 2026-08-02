//! Device certificates: the identity key vouching for a device's own keys.
//!
//! Until this existed, every device of a user held a copy of the identity
//! secret — the seal target and the prekey-signing authority were both
//! derived from it, so a device without it could neither read its own mail
//! nor publish prekeys anyone would trust. That is defensible for a phone
//! you own and indefensible for a browser tab, and it is why revocation
//! could only ever be a delivery cut: a revoked device still held the key.
//!
//! Under this module the identity key stops being a messaging key and
//! becomes a **root that signs for devices**. Each device generates its own
//! signing and seal keys, never shares them, and carries a short public
//! statement that they are its owner's:
//!
//! > device 3's keys are K_sig / K_seal, belonging to SC-…, until <expiry>
//!
//! Senders verify that against the SC- ID's identity key from the directory,
//! then seal to `K_seal` and check prekeys against `K_sig`. A device whose
//! certificate has expired or been revoked is one peers **refuse to encrypt
//! to** — revocation becomes cryptographic rather than a routing preference.
//!
//! The root still lives on the primary device (decided 2026-08-03), so a
//! stolen primary remains total compromise. What this bounds is every
//! *other* device.

use crate::primitives::{DEVCERT_SIG_CONTEXT, sign_with_context, verify_with_context};

/// Everything a peer must agree on before it will encrypt to a device.
///
/// Serialized for signing in a fixed order with length prefixes — not JSON.
/// A signature over a re-serialized JSON object is a signature over whatever
/// the other implementation's serializer happened to emit; two clients that
/// order keys differently would reject each other's certificates and the
/// failure would look like a forged key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceCert {
    pub stonechat_id: String,
    pub device_id: u32,
    /// Ed25519 public key the device signs its own prekeys with.
    pub sig_pub: [u8; 32],
    /// X-Wing public key envelopes to this device are sealed to.
    pub seal_pub: [u8; pqcore::XWING_PUBLIC_BYTES],
    /// Unix seconds. A certificate that has run out is not a valid target,
    /// which is what gives a browser session a lifetime it cannot extend.
    pub not_after: u64,
}

impl DeviceCert {
    /// The exact bytes that get signed. Length-prefixed and ordered, so the
    /// encoding is unambiguous regardless of who produced it.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.seal_pub.len() + 96);
        let mut field = |bytes: &[u8]| {
            out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            out.extend_from_slice(bytes);
        };
        field(self.stonechat_id.as_bytes());
        field(&self.device_id.to_be_bytes());
        field(&self.sig_pub);
        field(&self.seal_pub);
        field(&self.not_after.to_be_bytes());
        out
    }

    /// Sign with the identity root. `identity_seed` is the 32-byte Ed25519
    /// seed — the primary's, and nothing else holds it.
    pub fn sign(&self, identity_seed: &[u8; 32]) -> [u8; 64] {
        sign_with_context(identity_seed, DEVCERT_SIG_CONTEXT, &self.signing_bytes())
    }

    /// Check a certificate against the owner's identity key and a clock.
    ///
    /// `now` is caller-supplied like every other input here: the core takes
    /// no ambient anything, and a client that lies to itself about the time
    /// is already lost.
    pub fn verify(&self, identity_pub: &[u8; 32], sig: &[u8; 64], now: u64) -> CertStatus {
        if !verify_with_context(identity_pub, DEVCERT_SIG_CONTEXT, &self.signing_bytes(), sig) {
            return CertStatus::BadSignature;
        }
        if now >= self.not_after {
            return CertStatus::Expired;
        }
        CertStatus::Valid
    }
}

/// Why a certificate was rejected — distinguished because they mean very
/// different things. Expired is routine and self-healing (the owner renews);
/// a bad signature is someone claiming a device that is not theirs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CertStatus {
    Valid,
    Expired,
    BadSignature,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityKeys;

    fn cert(device_id: u32, not_after: u64) -> DeviceCert {
        DeviceCert {
            stonechat_id: "SC-TEST".into(),
            device_id,
            sig_pub: [9u8; 32],
            seal_pub: [3u8; pqcore::XWING_PUBLIC_BYTES],
            not_after,
        }
    }

    fn root() -> IdentityKeys {
        IdentityKeys::generate(&[1u8; 32])
    }

    #[test]
    fn a_signed_cert_verifies_against_the_identity() {
        let id = root();
        let c = cert(2, 1000);
        let sig = c.sign(&id.seed());
        assert_eq!(c.verify(&id.public, &sig, 999), CertStatus::Valid);
    }

    #[test]
    fn expiry_is_enforced_at_the_boundary() {
        let id = root();
        let c = cert(2, 1000);
        let sig = c.sign(&id.seed());
        assert_eq!(c.verify(&id.public, &sig, 999), CertStatus::Valid);
        // not_after is exclusive: at the stated second it is already over.
        assert_eq!(c.verify(&id.public, &sig, 1000), CertStatus::Expired);
        assert_eq!(c.verify(&id.public, &sig, 5000), CertStatus::Expired);
    }

    #[test]
    fn another_identity_cannot_vouch_for_this_device() {
        let mine = root();
        let theirs = IdentityKeys::generate(&[2u8; 32]);
        let c = cert(2, 1000);
        let sig = c.sign(&theirs.seed());
        assert_eq!(c.verify(&mine.public, &sig, 1), CertStatus::BadSignature);
    }

    #[test]
    fn every_field_is_covered_by_the_signature() {
        // The point of a certificate is that none of it can be edited. Each
        // field is changed in turn against one fixed signature.
        let id = root();
        let original = cert(2, 1000);
        let sig = original.sign(&id.seed());

        let mut other_device = original.clone();
        other_device.device_id = 3;
        assert_eq!(
            other_device.verify(&id.public, &sig, 1),
            CertStatus::BadSignature,
            "a cert must not be replayable onto another device id"
        );

        let mut other_owner = original.clone();
        other_owner.stonechat_id = "SC-SOMEONE".into();
        assert_eq!(other_owner.verify(&id.public, &sig, 1), CertStatus::BadSignature);

        let mut other_sig_key = original.clone();
        other_sig_key.sig_pub = [8u8; 32];
        assert_eq!(other_sig_key.verify(&id.public, &sig, 1), CertStatus::BadSignature);

        let mut other_seal_key = original.clone();
        other_seal_key.seal_pub = [4u8; pqcore::XWING_PUBLIC_BYTES];
        assert_eq!(
            other_seal_key.verify(&id.public, &sig, 1),
            CertStatus::BadSignature,
            "swapping the seal key would redirect every envelope"
        );

        let mut later = original.clone();
        later.not_after = u64::MAX;
        assert_eq!(
            later.verify(&id.public, &sig, 1),
            CertStatus::BadSignature,
            "a device must not be able to extend its own lifetime"
        );
    }

    #[test]
    fn field_boundaries_are_unambiguous() {
        // Length-prefixed encoding: moving a byte across a field boundary
        // must change the signed bytes. Concatenation without prefixes would
        // let ("SC-AB", 1) and ("SC-A", 0xB1…) collide.
        let a = DeviceCert { stonechat_id: "SC-AB".into(), ..cert(1, 10) };
        let b = DeviceCert { stonechat_id: "SC-A".into(), ..cert(1, 10) };
        assert_ne!(a.signing_bytes(), b.signing_bytes());
    }
}
