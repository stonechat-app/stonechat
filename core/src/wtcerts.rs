//! The owner vouching for their mailbox's **browser-transport** certificates.
//!
//! A relay serves `GET /wt/certs`: the SHA-256 of every short-lived
//! WebTransport certificate it will present over the next few months, with the
//! window each is live for (`relay/src/wtcert.rs`). That endpoint *states*; it
//! cannot *vouch*, because it is the thing being authenticated. A browser that
//! pins those hashes straight off the wire has pinned whatever the network told
//! it to — which is precisely what pinning exists to prevent.
//!
//! So the owner signs the list with their identity key, exactly as they already
//! sign the long-lived TLS fingerprint, and the signature is published to the
//! hub directory. A client resolves the owner (whose SC- ID commits to that
//! identity key), verifies, and only then pins.
//!
//! ## Why this is not "sign the JSON"
//!
//! The relay serves JSON, and JSON is not a canonical form: key order,
//! whitespace and integer formatting all vary between serializers, and three
//! implementations sign or verify this (Dart, TypeScript, Python's e2e). A
//! signature over bytes one of them cannot reproduce is a signature that fails
//! for reasons nobody can debug.
//!
//! The signing bytes are therefore length-prefixed and ordered, like
//! [`crate::devcert`] — the same reasoning, the same shape.

use crate::primitives::{sign_with_context, verify_with_context, WTCERTS_SIG_CONTEXT};

/// One published certificate: its hash and the window it is live for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WtCert {
    /// SHA-256 of the DER, base64 — what a browser is handed. Carried as the
    /// text the relay published rather than decoded bytes, so what is signed
    /// is exactly what a client compares against.
    pub sha256_b64: String,
    pub not_before: i64,
    pub not_after: i64,
}

/// The bytes an owner signs. Order is the list's own order, which is the
/// relay's (ascending by `not_before`); reordering changes the signature,
/// which is correct — a reordered schedule is a different claim.
pub fn signing_bytes(certs: &[WtCert]) -> Vec<u8> {
    let mut out = Vec::with_capacity(certs.len() * 64 + 4);
    // The count first, so a truncated list cannot be a prefix of a longer one.
    // Without it, dropping trailing certificates would leave a signature that
    // still verified — and dropping the *future* ones is exactly how an
    // attacker would force a client back to a certificate they control.
    out.extend_from_slice(&(certs.len() as u32).to_be_bytes());
    for cert in certs {
        let mut field = |bytes: &[u8]| {
            out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            out.extend_from_slice(bytes);
        };
        field(cert.sha256_b64.as_bytes());
        field(&cert.not_before.to_be_bytes());
        field(&cert.not_after.to_be_bytes());
    }
    out
}

pub fn sign(certs: &[WtCert], identity_seed: &[u8; 32]) -> [u8; 64] {
    sign_with_context(identity_seed, WTCERTS_SIG_CONTEXT, &signing_bytes(certs))
}

pub fn verify(certs: &[WtCert], identity_pub: &[u8; 32], sig: &[u8; 64]) -> bool {
    verify_with_context(identity_pub, WTCERTS_SIG_CONTEXT, &signing_bytes(certs), sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed() -> [u8; 32] {
        [7u8; 32]
    }

    fn pubkey() -> [u8; 32] {
        crate::identity::IdentityKeys::generate(&seed()).public
    }

    fn schedule() -> Vec<WtCert> {
        vec![
            WtCert { sha256_b64: "aGFzaC1vbmU=".into(), not_before: 100, not_after: 200 },
            WtCert { sha256_b64: "aGFzaC10d28=".into(), not_before: 190, not_after: 290 },
            WtCert { sha256_b64: "aGFzaC10aHJlZQ==".into(), not_before: 280, not_after: 380 },
        ]
    }

    #[test]
    fn round_trips() {
        let sig = sign(&schedule(), &seed());
        assert!(verify(&schedule(), &pubkey(), &sig));
    }

    #[test]
    fn every_field_is_covered() {
        let sig = sign(&schedule(), &seed());
        for mutate in [
            |c: &mut Vec<WtCert>| c[0].sha256_b64 = "b3RoZXI=".into(),
            |c: &mut Vec<WtCert>| c[1].not_before += 1,
            |c: &mut Vec<WtCert>| c[2].not_after -= 1,
        ] {
            let mut tampered = schedule();
            mutate(&mut tampered);
            assert!(!verify(&tampered, &pubkey(), &sig), "a field escaped the signature");
        }
    }

    #[test]
    fn truncation_is_detected() {
        // The attack the length prefix exists for: strip the future
        // certificates and a client is stranded on the current one, which is
        // the one an attacker who has it wants them stuck with.
        let sig = sign(&schedule(), &seed());
        let mut shorter = schedule();
        shorter.pop();
        assert!(!verify(&shorter, &pubkey(), &sig));
    }

    #[test]
    fn reordering_is_detected() {
        let sig = sign(&schedule(), &seed());
        let mut swapped = schedule();
        swapped.swap(0, 2);
        assert!(!verify(&swapped, &pubkey(), &sig));
    }

    #[test]
    fn another_identity_does_not_verify() {
        let sig = sign(&schedule(), &seed());
        let other = crate::identity::IdentityKeys::generate(&[9u8; 32]).public;
        assert!(!verify(&schedule(), &other, &sig));
    }

    /// The canonical encoding, pinned as bytes.
    ///
    /// Four implementations build these: this one, the hub's
    /// `_wtcerts_signing_bytes`, the Dart client and the TypeScript one. They
    /// agree today; this vector is what tells you *which* of them drifted when
    /// they stop, instead of "the signature does not verify".
    #[test]
    fn signing_bytes_match_the_published_vector() {
        let certs = vec![
            WtCert { sha256_b64: "aGFzaC1vbmU=".into(), not_before: 100, not_after: 200 },
            WtCert { sha256_b64: "aGFzaC10d28=".into(), not_before: 190, not_after: 290 },
        ];
        let hex: String = signing_bytes(&certs)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            hex,
            "00000002\
             0000000c6147467a61433176626d553d\
             00000008000000000000006400000008\
             00000000000000c8\
             0000000c6147467a614331306432383d\
             00000008000000000000\
             00be000000080000000000000122"
        );
    }

    #[test]
    fn fields_cannot_be_run_together() {
        // Without length prefixes, "ab" + "c" and "a" + "bc" would sign
        // identically. Concatenation ambiguity is how signature schemes get
        // quietly broken.
        let a = vec![WtCert { sha256_b64: "ab".into(), not_before: 1, not_after: 2 }];
        let b = vec![WtCert { sha256_b64: "a".into(), not_before: 1, not_after: 2 }];
        assert_ne!(signing_bytes(&a), signing_bytes(&b));
    }

    #[test]
    fn the_context_is_distinct_from_the_tls_one() {
        // Signing the same bytes under two contexts must give two signatures,
        // or a fingerprint signature could be replayed as a schedule one.
        assert_ne!(WTCERTS_SIG_CONTEXT, crate::primitives::TLS_SIG_CONTEXT);
    }
}
