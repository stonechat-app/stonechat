//! The identity's signed list of its devices (PROTOCOL.md "Device manifest").
//!
//! A device certificate says a device *was* the identity's, until a date.
//! Nothing it carries can say the identity has since cut the device off.
//! The manifest is that statement: the primary signs the set of devices
//! that currently speak for the identity, numbered so that a newer one
//! supersedes an older, and publishes it to the directory. A contact who
//! holds the manifest encrypts only to devices on it and accepts envelopes
//! only from devices on it — so revocation is a new manifest without the
//! device, not only a queue deleted on the relay.
//!
//! Each entry names the device slot and the signing key its certificate
//! carries, so a relay that moved a certificate between slots, or served a
//! certificate from before a device was re-keyed, is caught by the pair not
//! matching.
//!
//! Signed as length-prefixed ordered bytes, not JSON, for the reason
//! [`crate::wtcerts`] gives.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;

use crate::ids::pubkey_matches_id;
use crate::primitives::{DEVICES_SIG_CONTEXT, sign_with_context, verify_with_context};

/// Up to this many devices in one manifest. Far above what any client
/// mints; a bound on what a directory record can make a client hold.
pub const MAX_DEVICES: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceEntry {
    pub device_id: u32,
    /// The device's Ed25519 signing key — the `sig_pub` of its certificate.
    pub sig_pub: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub stonechat_id: String,
    /// Increases with every change. A client holding version *n* ignores
    /// any manifest numbered *n* or below.
    pub version: u64,
    /// Unix seconds when it was signed. Informational: nothing expires it.
    pub issued_at: i64,
    pub devices: Vec<DeviceEntry>,
}

impl Manifest {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + self.devices.len() * 44);
        let mut field = |bytes: &[u8]| {
            out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            out.extend_from_slice(bytes);
        };
        field(self.stonechat_id.as_bytes());
        field(&self.version.to_be_bytes());
        field(&self.issued_at.to_be_bytes());
        // The count, so a truncated list is not a prefix of the signed one.
        field(&(self.devices.len() as u32).to_be_bytes());
        for device in &self.devices {
            field(&device.device_id.to_be_bytes());
            field(&device.sig_pub);
        }
        out
    }

    pub fn sign(&self, identity_seed: &[u8; 32]) -> [u8; 64] {
        sign_with_context(identity_seed, DEVICES_SIG_CONTEXT, &self.signing_bytes())
    }

    /// Valid iff the signature verifies under `identity_pub`, that key is
    /// the one the manifest's Stonechat ID commits to, the list is within
    /// bounds, and no device is listed twice.
    pub fn verify(&self, identity_pub: &[u8; 32], sig: &[u8; 64]) -> bool {
        if self.devices.is_empty() || self.devices.len() > MAX_DEVICES {
            return false;
        }
        let mut ids: Vec<u32> = self.devices.iter().map(|d| d.device_id).collect();
        ids.sort_unstable();
        if ids.windows(2).any(|w| w[0] == w[1]) {
            return false;
        }
        if !pubkey_matches_id(identity_pub, &self.stonechat_id) {
            return false;
        }
        verify_with_context(identity_pub, DEVICES_SIG_CONTEXT, &self.signing_bytes(), sig)
    }

    /// Whether `device_id` is listed with exactly this signing key.
    pub fn lists(&self, device_id: u32, sig_pub: &[u8; 32]) -> bool {
        self.devices
            .iter()
            .any(|d| d.device_id == device_id && &d.sig_pub == sig_pub)
    }

    /// Parse the wire form:
    /// `{"stonechat_id", "version", "issued_at", "devices": [{"device_id", "sig_pub"}]}`
    /// (`sig`, if present, is ignored here and read by the caller).
    pub fn from_json(v: &serde_json::Value) -> Option<Manifest> {
        let devices = v.get("devices")?.as_array()?;
        Some(Manifest {
            stonechat_id: v.get("stonechat_id")?.as_str()?.to_string(),
            version: v.get("version")?.as_u64()?,
            issued_at: v.get("issued_at")?.as_i64()?,
            devices: devices
                .iter()
                .map(|d| {
                    Some(DeviceEntry {
                        device_id: u32::try_from(d.get("device_id")?.as_u64()?).ok()?,
                        sig_pub: B64
                            .decode(d.get("sig_pub")?.as_str()?)
                            .ok()?
                            .try_into()
                            .ok()?,
                    })
                })
                .collect::<Option<Vec<_>>>()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityKeys;
    use crate::ids::derive_stonechat_id;

    fn seed() -> [u8; 32] {
        [9u8; 32]
    }

    fn manifest() -> Manifest {
        let identity = IdentityKeys::generate(&seed());
        Manifest {
            stonechat_id: derive_stonechat_id(&identity.public),
            version: 3,
            issued_at: 1_790_000_000,
            devices: vec![
                DeviceEntry { device_id: 1, sig_pub: [1u8; 32] },
                DeviceEntry { device_id: 3, sig_pub: [3u8; 32] },
            ],
        }
    }

    #[test]
    fn round_trips_and_lists() {
        let m = manifest();
        let sig = m.sign(&seed());
        let public = IdentityKeys::generate(&seed()).public;
        assert!(m.verify(&public, &sig));
        assert!(m.lists(3, &[3u8; 32]));
        assert!(!m.lists(2, &[2u8; 32]), "a revoked slot is not listed");
        assert!(!m.lists(3, &[4u8; 32]), "the key must match the slot");
    }

    #[test]
    fn every_field_is_covered() {
        let sig = manifest().sign(&seed());
        let public = IdentityKeys::generate(&seed()).public;
        for mutate in [
            |m: &mut Manifest| m.version += 1,
            |m: &mut Manifest| m.issued_at -= 1,
            |m: &mut Manifest| m.devices[1].device_id = 4,
            |m: &mut Manifest| m.devices[1].sig_pub[0] ^= 1,
            |m: &mut Manifest| m.devices.truncate(1),
            |m: &mut Manifest| m.devices.push(DeviceEntry { device_id: 5, sig_pub: [5u8; 32] }),
            |m: &mut Manifest| m.devices.swap(0, 1),
        ] {
            let mut tampered = manifest();
            mutate(&mut tampered);
            assert!(!tampered.verify(&public, &sig), "a change escaped the signature");
        }
    }

    #[test]
    fn another_identity_does_not_verify() {
        let m = manifest();
        let sig = m.sign(&[8u8; 32]);
        let other = IdentityKeys::generate(&[8u8; 32]).public;
        // Correctly signed by the other key — but that key is not the one
        // the manifest's ID commits to.
        assert!(!m.verify(&other, &sig));
        assert!(!m.verify(&IdentityKeys::generate(&seed()).public, &sig));
    }

    #[test]
    fn malformed_lists_are_refused() {
        let public = IdentityKeys::generate(&seed()).public;
        let mut empty = manifest();
        empty.devices.clear();
        assert!(!empty.verify(&public, &empty.sign(&seed())));
        let mut twice = manifest();
        twice.devices.push(DeviceEntry { device_id: 1, sig_pub: [7u8; 32] });
        assert!(!twice.verify(&public, &twice.sign(&seed())));
    }

    #[test]
    fn signing_bytes_match_the_hub() {
        // The same manifest through hub/app/main.py `_devices_signing_bytes`.
        let m = Manifest {
            stonechat_id: "SC-X".into(),
            version: 2,
            issued_at: 5,
            devices: vec![DeviceEntry { device_id: 1, sig_pub: [1u8; 32] }],
        };
        let hex: String = m.signing_bytes().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "0000000453432d5800000008000000000000000200000008000000000000000500000004000000010000000400000001000000200101010101010101010101010101010101010101010101010101010101010101");
    }

    #[test]
    fn parses_the_wire_form() {
        let v: serde_json::Value = serde_json::from_str(
            r#"{"stonechat_id":"SC-X","version":2,"issued_at":5,
                "devices":[{"device_id":1,"sig_pub":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="}],
                "sig":"ignored"}"#,
        )
        .unwrap();
        let m = Manifest::from_json(&v).unwrap();
        assert_eq!((m.version, m.issued_at, m.devices.len()), (2, 5, 1));
        assert_eq!(m.devices[0].sig_pub, [1u8; 32]);
        assert!(Manifest::from_json(&serde_json::json!({"version": 1})).is_none());
    }
}
