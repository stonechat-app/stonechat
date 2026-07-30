//! The Stonechat identity and everything derived from it
//! (PROTOCOL.md "Identity"): an Ed25519 keypair, the X-Wing identity for
//! the envelope seal, the SC- ID, and every context-prefixed signature the
//! protocol defines.
//!
//! This is the layer that used to live in the app's `crypto.dart` on
//! libsodium. It moved here so the app, the notification extension and any
//! future client derive identical values by construction — a value two
//! processes compute separately is a bug waiting (the extension once
//! hashed the 32-byte seed where the app hashes the 64-byte secret key,
//! and no sealed envelope opened).
//!
//! The libsodium secret-key layout is kept: 64 bytes, `seed || public`.

use crate::primitives::{
    PQID_SEED_KEY, PQPK_SIG_CONTEXT, RECOVER_SIG_CONTEXT, REPORT_SIG_CONTEXT, ed25519_pk_from_seed,
    hash_var, keyed_hash_32, sign_with_context, verify_with_context,
};

pub const SECRET_KEY_BYTES: usize = 64;

/// A full identity, expanded from the 64-byte secret key.
pub struct IdentityKeys {
    /// `seed || public`, as libsodium's `crypto_sign` keeps it.
    pub secret: [u8; SECRET_KEY_BYTES],
    pub public: [u8; 32],
    /// X-Wing identity seed (`pq_pk` is derived from it, never stored).
    pub pq_seed: [u8; 32],
}

impl IdentityKeys {
    /// Expand a caller-supplied 32-byte CSPRNG seed into a fresh identity.
    pub fn generate(seed: &[u8; 32]) -> IdentityKeys {
        let public = ed25519_pk_from_seed(seed);
        let mut secret = [0u8; SECRET_KEY_BYTES];
        secret[..32].copy_from_slice(seed);
        secret[32..].copy_from_slice(&public);
        IdentityKeys::from_secret(&secret)
    }

    /// Restore from the stored secret key.
    pub fn from_secret(secret: &[u8; SECRET_KEY_BYTES]) -> IdentityKeys {
        let mut public = [0u8; 32];
        public.copy_from_slice(&secret[32..]);
        IdentityKeys {
            secret: *secret,
            public,
            // Derived from the WHOLE secret key — matching what the app
            // has always published as `pq_pk`.
            pq_seed: keyed_hash_32(secret, PQID_SEED_KEY),
        }
    }

    pub fn seed(&self) -> [u8; 32] {
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&self.secret[..32]);
        seed
    }

    pub fn pq_public(&self) -> [u8; pqcore::XWING_PUBLIC_BYTES] {
        pqcore::xwing_pk_from_seed(&self.pq_seed)
    }

    pub fn stonechat_id(&self) -> String {
        crate::ids::derive_stonechat_id(&self.public)
    }

    /// Sign with any of the protocol's domain-separation contexts.
    pub fn sign(&self, context: &[u8], message: &[u8]) -> [u8; 64] {
        sign_with_context(&self.seed(), context, message)
    }

    /// The owner vouching for their X-Wing identity key; published beside
    /// it in the hub directory and verified by every resolver.
    pub fn sign_pq_pk(&self) -> [u8; 64] {
        self.sign(PQPK_SIG_CONTEXT, &self.pq_public())
    }

    /// Proof of key possession for `POST /v1/recover`: a signature over
    /// the context and the current unix time, so the hub can re-issue an
    /// account token without ever having stored one.
    pub fn sign_recovery(&self, unix_seconds: i64) -> [u8; 64] {
        self.sign(RECOVER_SIG_CONTEXT, unix_seconds.to_string().as_bytes())
    }

    /// Signs an abuse report (PROTOCOL.md "Reporting"). The body is
    /// committed to by digest rather than signed directly, because it has
    /// to survive a round trip through JSON, where field order and
    /// whitespace do not. 0x1f (unit separator) between fields: without it
    /// a note ending in what looks like the next field could collide with
    /// a different report.
    pub fn sign_report(
        &self,
        reported_id: &str,
        unix_seconds: i64,
        category: &str,
        note: &str,
        evidence: Option<&str>,
    ) -> [u8; 64] {
        let mut body = Vec::new();
        body.extend_from_slice(category.as_bytes());
        body.push(0x1f);
        body.extend_from_slice(note.as_bytes());
        body.push(0x1f);
        body.extend_from_slice(evidence.unwrap_or("").as_bytes());
        let digest = hash_var(&body, 32);

        let mut message = Vec::new();
        message.extend_from_slice(reported_id.as_bytes());
        message.extend_from_slice(unix_seconds.to_string().as_bytes());
        message.extend_from_slice(&digest);
        self.sign(REPORT_SIG_CONTEXT, &message)
    }
}

/// Verify any context-prefixed signature against a peer's identity key.
pub fn verify(ed_pk: &[u8; 32], context: &[u8], message: &[u8], sig: &[u8; 64]) -> bool {
    verify_with_context(ed_pk, context, message, sig)
}
