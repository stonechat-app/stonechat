//! Shared primitives, mirroring app/lib/core/crypto.dart one-to-one.
//! `H(msg, key, n)` throughout is libsodium `crypto_generichash` — keyed
//! BLAKE2b — exactly as PROTOCOL.md "Session crypto" specifies.

use blake2::digest::consts::{U32, U64};
use blake2::digest::{FixedOutput, Update, VariableOutput};
use blake2::{Blake2bMac, Blake2bVar};
use chacha20poly1305::aead::{Aead, Payload};
// One KeyInit serves both: blake2 and chacha20poly1305 re-export the same trait.
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha512};

pub const AEAD_NONCE_BYTES: usize = 24;
pub const AEAD_TAG_BYTES: usize = 16;

// Domain-separation constants — must match crypto.dart, scripts/e2e.py and
// PROTOCOL.md.
pub const X3DH_KDF_KEY: &[u8] = b"stonechat-v1-pqxdh-kdf";
pub const PQ_RATCHET_KDF_INFO: &[u8] = b"stonechat-v1-pqratchet";
pub const HSEAL_KDF_KEY: &[u8] = b"stonechat-v1-hsealkdf";
pub const HSEAL_AD: &[u8] = b"stonechat-v1-hseal";
pub const PQID_SEED_KEY: &[u8] = b"stonechat-v1-pqidseed";
pub const SPK_SIG_CONTEXT: &[u8] = b"stonechat-v1-spk";
pub const KSPK_SIG_CONTEXT: &[u8] = b"stonechat-v1-kspk";
pub const PQPK_SIG_CONTEXT: &[u8] = b"stonechat-v1-pqpk";
pub const TLS_SIG_CONTEXT: &[u8] = b"stonechat-v1-tls";
pub const RECOVER_SIG_CONTEXT: &[u8] = b"stonechat-v1-recover";
/// Account deletion (hub `POST /v1/account/delete`); signed by the app.
pub const DELETE_SIG_CONTEXT: &[u8] = b"stonechat-v1-delete";
pub const REPORT_SIG_CONTEXT: &[u8] = b"stonechat-v1-report";
/// The identity root vouching for one of its devices (devcert.rs). Its own
/// context so a device certificate can never be mistaken for — or replayed
/// as — any other signature this identity makes.
pub const DEVCERT_SIG_CONTEXT: &[u8] = b"stonechat-v1-devcert";

/// The owner vouching for their mailbox's browser-transport certificate
/// schedule (wtcerts.rs). Distinct from TLS_SIG_CONTEXT so a signature over
/// the long-lived fingerprint can never be replayed as one over the
/// short-lived WebTransport hashes, or the reverse.
pub const WTCERTS_SIG_CONTEXT: &[u8] = b"stonechat-v1-wtcerts";

/// `crypto_generichash(msg, key, 32)`. Key must be 16–64 bytes.
pub fn keyed_hash_32(msg: &[u8], key: &[u8]) -> [u8; 32] {
    let mut mac = Blake2bMac::<U32>::new_from_slice(key).expect("key must be 16-64 bytes");
    Update::update(&mut mac, msg);
    mac.finalize_fixed().into()
}

/// `crypto_generichash(msg, key, 64)`. Key must be 16–64 bytes.
pub fn keyed_hash_64(msg: &[u8], key: &[u8]) -> [u8; 64] {
    let mut mac = Blake2bMac::<U64>::new_from_slice(key).expect("key must be 16-64 bytes");
    Update::update(&mut mac, msg);
    mac.finalize_fixed().into()
}

/// Unkeyed `crypto_generichash(msg, outlen=n)`, n in 16..=64.
pub fn hash_var(msg: &[u8], n: usize) -> Vec<u8> {
    let mut h = Blake2bVar::new(n).expect("outlen must be 1-64");
    Update::update(&mut h, msg);
    let mut out = vec![0u8; n];
    h.finalize_variable(&mut out).expect("length matches");
    out
}

// -- ratchet KDFs (PROTOCOL.md "Double ratchet") ------------------------------

/// `KDF_RK(rk, dh): out = H(dh, key=rk, 64) → (rk', ck)`.
pub fn kdf_root(rk: &[u8; 32], dh_out: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let out = keyed_hash_64(dh_out, rk);
    (out[..32].try_into().unwrap(), out[32..].try_into().unwrap())
}

/// `KDF_PQ(rk, ss): rk' = H("stonechat-v1-pqratchet" || ss, key=rk, 32)` —
/// folds a post-quantum ratchet KEM secret into the root key.
pub fn kdf_pq(rk: &[u8; 32], kem_ss: &[u8; 32]) -> [u8; 32] {
    let mut msg = Vec::with_capacity(PQ_RATCHET_KDF_INFO.len() + 32);
    msg.extend_from_slice(PQ_RATCHET_KDF_INFO);
    msg.extend_from_slice(kem_ss);
    keyed_hash_32(&msg, rk)
}

/// `KDF_CK(ck): mk = H(0x01, key=ck, 32); ck' = H(0x02, key=ck, 32)`.
pub fn kdf_chain(ck: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    (keyed_hash_32(&[1], ck), keyed_hash_32(&[2], ck))
}

/// `SK = H(DH1 || DH2 || DH3 [|| DH4] || KEM_SS, key="stonechat-v1-pqxdh-kdf", 32)`.
pub fn x3dh_shared_key(dhs: &[[u8; 32]], kem_ss: &[u8; 32]) -> [u8; 32] {
    let mut msg = Vec::with_capacity(dhs.len() * 32 + 32);
    for dh in dhs {
        msg.extend_from_slice(dh);
    }
    msg.extend_from_slice(kem_ss);
    keyed_hash_32(&msg, X3DH_KDF_KEY)
}

// -- AEAD (crypto_aead_xchacha20poly1305_ietf, combined mode) -----------------

/// Returns `ciphertext || tag`, libsodium's combined form.
pub fn aead_seal(
    key: &[u8; 32],
    nonce: &[u8; AEAD_NONCE_BYTES],
    plaintext: &[u8],
    ad: &[u8],
) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad: ad,
            },
        )
        .expect("xchacha20poly1305 encryption is infallible for in-memory buffers")
}

/// `None` on authentication failure.
pub fn aead_open(
    key: &[u8; 32],
    nonce: &[u8; AEAD_NONCE_BYTES],
    ciphertext: &[u8],
    ad: &[u8],
) -> Option<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: ad,
            },
        )
        .ok()
}

// -- X25519 (crypto_scalarmult) ------------------------------------------------

/// `crypto_scalarmult_base`: public half of an X25519 secret.
pub fn x25519_pk(sk: &[u8; 32]) -> [u8; 32] {
    x25519_dalek::x25519(*sk, x25519_dalek::X25519_BASEPOINT_BYTES)
}

/// `crypto_scalarmult(secret, pub)` — the DH used everywhere in X3DH and
/// the ratchet.
pub fn dh(sk: &[u8; 32], pk: &[u8; 32]) -> [u8; 32] {
    x25519_dalek::x25519(*sk, *pk)
}

// -- Ed25519 ↔ X25519 (crypto_sign_ed25519_*_to_curve25519) --------------------

/// A peer's Ed25519 identity key as X25519 (birational map). `None` when
/// the bytes are not a valid Ed25519 point.
pub fn ed25519_pk_to_x25519(ed_pk: &[u8; 32]) -> Option<[u8; 32]> {
    let vk = VerifyingKey::from_bytes(ed_pk).ok()?;
    Some(vk.to_montgomery().to_bytes())
}

/// Own Ed25519 seed as an X25519 secret: `clamp(SHA-512(seed)[0..32])` —
/// what libsodium's `sk_to_curve25519` computes from the 64-byte signing
/// key (whose first half is this seed).
pub fn ed25519_seed_to_x25519_sk(seed: &[u8; 32]) -> [u8; 32] {
    let h = Sha512::digest(seed);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h[..32]);
    out[0] &= 248;
    out[31] &= 127;
    out[31] |= 64;
    out
}

// -- Ed25519 signatures (context-prefixed, PROTOCOL.md conventions) ------------

pub fn ed25519_pk_from_seed(seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

/// `crypto_sign_detached(context || message)`.
pub fn sign_with_context(seed: &[u8; 32], context: &[u8], message: &[u8]) -> [u8; 64] {
    let sk = SigningKey::from_bytes(seed);
    let mut m = Vec::with_capacity(context.len() + message.len());
    m.extend_from_slice(context);
    m.extend_from_slice(message);
    sk.sign(&m).to_bytes()
}

pub fn verify_with_context(
    ed_pk: &[u8; 32],
    context: &[u8],
    message: &[u8],
    sig: &[u8; 64],
) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(ed_pk) else {
        return false;
    };
    let mut m = Vec::with_capacity(context.len() + message.len());
    m.extend_from_slice(context);
    m.extend_from_slice(message);
    vk.verify_strict(&m, &ed25519_dalek::Signature::from_bytes(sig))
        .is_ok()
}

/// Constant-time byte equality (ratchet header comparison).
pub fn bytes_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}
