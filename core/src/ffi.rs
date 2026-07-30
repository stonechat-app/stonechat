//! The C ABI: session operations as state-in/state-out over JSON bytes.
//!
//! Contract (every consumer — Dart bindings, Swift NSE — relies on this):
//!
//! - Inputs are caller-owned buffers; fixed-size ones are documented per
//!   function, variable ones travel as `(ptr, len)` UTF-8 JSON or raw bytes.
//! - Outputs are core-allocated: on return `0` the function writes a fresh
//!   buffer to `(*out_ptr, *out_len)` which the caller MUST release with
//!   [`stonechat_free`]. On any nonzero return nothing was allocated.
//! - Return codes: `0` ok · `-1` malformed input (bad JSON/base64/length)
//!   · `-2` internal panic (bug — report it) · `-3` crypto refusal
//!   (AEAD failed, not ready to send, forged bundle). `-3` is a normal
//!   runtime outcome; the session state is unchanged and still valid.
//! - Randomness is always caller-supplied (CSPRNG bytes), like pqcore.
//!
//! Result JSON shapes:
//! - initiate/respond → the session state object itself (the initiator's
//!   `pending_x3dh` block rides inside it).
//! - encrypt → `{"state": {...}, "header": {...}, "ciphertext": "<b64>"}`
//! - decrypt → `{"state": {...}, "plaintext": "<b64>"}`

use serde_json::{Value, json};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;

use crate::envelope;
use crate::primitives::{PQID_SEED_KEY, hash_var, keyed_hash_32};
use crate::session::{Identity, InitiateRandom, PrekeyBundle, RatchetHeader, SessionState};

const OK: i32 = 0;
const ERR_INPUT: i32 = -1;
const ERR_PANIC: i32 = -2;
const ERR_REFUSED: i32 = -3;

macro_rules! ffi_guard {
    ($body:expr) => {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| $body)) {
            Ok(code) => code,
            Err(_) => ERR_PANIC,
        }
    };
}

/// # Safety
/// `ptr` and `len` must come from a successful stonechat_* call, unmodified,
/// and be freed exactly once. `ptr == NULL` is a no-op.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stonechat_free(ptr: *mut u8, len: usize) {
    if !ptr.is_null() {
        // Buffers are handed out as into_boxed_slice, so len == capacity.
        drop(unsafe { Vec::from_raw_parts(ptr, len, len) });
    }
}

/// Hand `bytes` to the caller (len == capacity, see [`stonechat_free`]).
unsafe fn emit(bytes: Vec<u8>, out_ptr: *mut *mut u8, out_len: *mut usize) {
    let mut boxed = bytes.into_boxed_slice();
    unsafe {
        *out_ptr = boxed.as_mut_ptr();
        *out_len = boxed.len();
    }
    std::mem::forget(boxed);
}

unsafe fn arr<'a, const N: usize>(ptr: *const u8) -> Option<&'a [u8; N]> {
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { &*ptr.cast::<[u8; N]>() })
    }
}

unsafe fn slice<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { std::slice::from_raw_parts(ptr, len) })
    }
}

fn state_from(bytes: &[u8]) -> Option<SessionState> {
    serde_json::from_slice(bytes).ok()
}

unsafe fn emit_json(v: &Value, out_ptr: *mut *mut u8, out_len: *mut usize) -> i32 {
    match serde_json::to_vec(v) {
        Ok(bytes) => {
            unsafe { emit(bytes, out_ptr, out_len) };
            OK
        }
        Err(_) => ERR_PANIC,
    }
}

/// PQXDH as the initiator. The host must already have commitment-verified
/// `peer_ed_pk` and checked the bundle's SPK/KSPK signatures.
///
/// # Safety
/// `ed_seed`, `peer_ed_pk`, `ek_sk`, `ratchet_sk`, `kem_random`: 32 readable
/// bytes each. `bundle_json`: `bundle_len` readable bytes — the bundle
/// exactly as the peer's mailbox serves it (`GET /prekeys/bundle`).
/// `out_ptr`/`out_len` writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stonechat_session_initiate(
    ed_seed: *const u8,
    peer_ed_pk: *const u8,
    bundle_json: *const u8,
    bundle_len: usize,
    ek_sk: *const u8,
    ratchet_sk: *const u8,
    kem_random: *const u8,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    ffi_guard!({
        let (Some(seed), Some(peer), Some(bundle_bytes)) = (
            unsafe { arr::<32>(ed_seed) },
            unsafe { arr::<32>(peer_ed_pk) },
            unsafe { slice(bundle_json, bundle_len) },
        ) else {
            return ERR_INPUT;
        };
        let (Some(ek), Some(ratchet), Some(kem)) = (
            unsafe { arr::<32>(ek_sk) },
            unsafe { arr::<32>(ratchet_sk) },
            unsafe { arr::<32>(kem_random) },
        ) else {
            return ERR_INPUT;
        };
        let Some(bundle_value) = serde_json::from_slice::<Value>(bundle_bytes).ok() else {
            return ERR_INPUT;
        };
        let Some(bundle) = PrekeyBundle::from_relay_json(&bundle_value) else {
            return ERR_INPUT;
        };
        let identity = Identity::from_ed25519_seed(seed);
        let random = InitiateRandom {
            ek_sk: *ek,
            ratchet_sk: *ratchet,
            kem_random: *kem,
        };
        match SessionState::initiate(&identity, peer, &bundle, &random) {
            Ok(state) => match serde_json::to_value(&state) {
                Ok(v) => unsafe { emit_json(&v, out_ptr, out_len) },
                Err(_) => ERR_PANIC,
            },
            Err(_) => ERR_REFUSED,
        }
    })
}

/// PQXDH as the responder, from an initial envelope's `x3dh` block and our
/// stored prekey private halves. The host must already have
/// commitment-verified `sender_ed_pk` against the envelope's `from`.
///
/// # Safety
/// `ed_seed`, `sender_ed_pk`, `spk_pub`, `spk_sec`: 32 readable bytes.
/// `opk_sec`: 32 readable bytes or NULL (bundle served without an OPK).
/// `kem_seed`: 64 readable bytes (the prekey named by the block's `kem_id`).
/// `x3dh_json`: `x3dh_len` readable bytes. `out_ptr`/`out_len` writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stonechat_session_respond(
    ed_seed: *const u8,
    sender_ed_pk: *const u8,
    x3dh_json: *const u8,
    x3dh_len: usize,
    spk_pub: *const u8,
    spk_sec: *const u8,
    opk_sec: *const u8,
    kem_seed: *const u8,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    ffi_guard!({
        let (Some(seed), Some(sender), Some(block_bytes)) = (
            unsafe { arr::<32>(ed_seed) },
            unsafe { arr::<32>(sender_ed_pk) },
            unsafe { slice(x3dh_json, x3dh_len) },
        ) else {
            return ERR_INPUT;
        };
        let (Some(spk_p), Some(spk_s), Some(kem)) = (
            unsafe { arr::<32>(spk_pub) },
            unsafe { arr::<32>(spk_sec) },
            unsafe { arr::<64>(kem_seed) },
        ) else {
            return ERR_INPUT;
        };
        let opk = unsafe { arr::<32>(opk_sec) }; // NULL → None, by design
        let Ok(block) = serde_json::from_slice(block_bytes) else {
            return ERR_INPUT;
        };
        let identity = Identity::from_ed25519_seed(seed);
        match SessionState::respond(&identity, sender, &block, spk_p, spk_s, opk, kem) {
            Ok(state) => match serde_json::to_value(&state) {
                Ok(v) => unsafe { emit_json(&v, out_ptr, out_len) },
                Err(_) => ERR_PANIC,
            },
            Err(_) => ERR_REFUSED,
        }
    })
}

/// Encrypt one message; result carries the advanced state — persist it
/// before the envelope reaches the network.
///
/// # Safety
/// `state_json`: `state_len` readable. `plaintext`: `plaintext_len`
/// readable. `ad`: `ad_len` readable (the full AD prefix string).
/// `nonce`: 24 readable bytes of fresh CSPRNG output. `out_*` writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stonechat_session_encrypt(
    state_json: *const u8,
    state_len: usize,
    plaintext: *const u8,
    plaintext_len: usize,
    ad: *const u8,
    ad_len: usize,
    nonce: *const u8,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    ffi_guard!({
        let (Some(state_bytes), Some(plain), Some(ad_bytes), Some(nonce)) = (
            unsafe { slice(state_json, state_len) },
            unsafe { slice(plaintext, plaintext_len) },
            unsafe { slice(ad, ad_len) },
            unsafe { arr::<24>(nonce) },
        ) else {
            return ERR_INPUT;
        };
        let Some(mut state) = state_from(state_bytes) else {
            return ERR_INPUT;
        };
        let Ok(ad_str) = std::str::from_utf8(ad_bytes) else {
            return ERR_INPUT;
        };
        match state.encrypt(plain, ad_str, nonce) {
            Ok((header, ciphertext)) => {
                let v = json!({
                    "state": state,
                    "header": header,
                    "ciphertext": B64.encode(ciphertext),
                });
                unsafe { emit_json(&v, out_ptr, out_len) }
            }
            Err(_) => ERR_REFUSED,
        }
    })
}

/// Decrypt one message. On `-3` the state is unchanged and still valid —
/// the caller keeps its current copy. On `0` the result carries the
/// advanced state — persist it.
///
/// # Safety
/// `state_json`/`header_json`/`ciphertext`/`ad`: readable per their lens.
/// `nonce`: 24 readable bytes. `fresh_ratchet_sk`: 32 readable bytes of
/// fresh CSPRNG output (consumed only on a DH-ratchet step). `out_*`
/// writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stonechat_session_decrypt(
    state_json: *const u8,
    state_len: usize,
    header_json: *const u8,
    header_len: usize,
    nonce: *const u8,
    ciphertext: *const u8,
    ciphertext_len: usize,
    ad: *const u8,
    ad_len: usize,
    fresh_ratchet_sk: *const u8,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    ffi_guard!({
        let (Some(state_bytes), Some(header_bytes), Some(nonce), Some(ct)) = (
            unsafe { slice(state_json, state_len) },
            unsafe { slice(header_json, header_len) },
            unsafe { arr::<24>(nonce) },
            unsafe { slice(ciphertext, ciphertext_len) },
        ) else {
            return ERR_INPUT;
        };
        let (Some(ad_bytes), Some(fresh)) = (unsafe { slice(ad, ad_len) }, unsafe {
            arr::<32>(fresh_ratchet_sk)
        }) else {
            return ERR_INPUT;
        };
        let Some(mut state) = state_from(state_bytes) else {
            return ERR_INPUT;
        };
        let Ok(header) = serde_json::from_slice::<RatchetHeader>(header_bytes) else {
            return ERR_INPUT;
        };
        let Ok(ad_str) = std::str::from_utf8(ad_bytes) else {
            return ERR_INPUT;
        };
        match state.decrypt(&header, nonce, ct, ad_str, fresh) {
            Some(plain) => {
                let v = json!({
                    "state": state,
                    "plaintext": B64.encode(plain),
                });
                unsafe { emit_json(&v, out_ptr, out_len) }
            }
            None => ERR_REFUSED,
        }
    })
}

// -- envelope + identity helpers (the NSE's non-session needs) -----------------

/// Derive the X-Wing identity seed the same way the app does
/// (crypto.dart `_pqSeed`): a domain-separated hash of the **full
/// 64-byte libsodium Ed25519 secret key** (seed || public half), NOT of
/// the 32-byte seed. Hashing the seed alone yields a different identity
/// and every sealed envelope silently fails to open.
///
/// # Safety
/// `ed_secret`: 64 readable bytes. `pq_seed_out`: 32 writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stonechat_pq_seed_from_ed_secret(
    ed_secret: *const u8,
    pq_seed_out: *mut u8,
) -> i32 {
    ffi_guard!({
        let Some(secret) = (unsafe { arr::<64>(ed_secret) }) else {
            return ERR_INPUT;
        };
        let pq = keyed_hash_32(secret, PQID_SEED_KEY);
        unsafe { pq_seed_out.copy_from_nonoverlapping(pq.as_ptr(), pq.len()) };
        OK
    })
}

/// Open a sealed envelope (X-Wing hybrid seal, PROTOCOL.md "Envelope") with
/// our identity seed. `-3` when it wasn't sealed to this identity or is
/// garbage — a normal outcome, drop the envelope.
///
/// # Safety
/// `pq_seed`: 32 readable bytes. `sealed`: `sealed_len` readable bytes.
/// `out_ptr`/`out_len` writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stonechat_unseal(
    pq_seed: *const u8,
    sealed: *const u8,
    sealed_len: usize,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    ffi_guard!({
        let (Some(seed), Some(sealed)) = (unsafe { arr::<32>(pq_seed) }, unsafe {
            slice(sealed, sealed_len)
        }) else {
            return ERR_INPUT;
        };
        match envelope::unseal(seed, sealed) {
            Some(inner) => {
                unsafe { emit(inner, out_ptr, out_len) };
                OK
            }
            None => ERR_REFUSED,
        }
    })
}

/// What clients pin: BLAKE2b-256 over the relay certificate's DER bytes
/// (PROTOCOL.md "Transport"). Compare base64(out) with the stored `tls_fp`.
///
/// # Safety
/// `cert_der`: `der_len` readable bytes. `fp_out`: 32 writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stonechat_tls_fingerprint(
    cert_der: *const u8,
    der_len: usize,
    fp_out: *mut u8,
) -> i32 {
    ffi_guard!({
        let Some(der) = (unsafe { slice(cert_der, der_len) }) else {
            return ERR_INPUT;
        };
        let fp = hash_var(der, 32);
        unsafe { fp_out.copy_from_nonoverlapping(fp.as_ptr(), fp.len()) };
        OK
    })
}

// -- identity + vault (the rest of what crypto.dart used to do) ---------------

/// Expand a caller-supplied 32-byte CSPRNG seed into a fresh identity, or
/// re-expand a stored one: pass the 64-byte secret key with `from_secret`
/// non-zero. Result JSON: `{"secret":"<b64 64>","public":"<b64 32>",
/// "pq_pk":"<b64>","pq_pk_sig":"<b64>","stonechat_id":"SC-…"}`.
///
/// # Safety
/// `input`: 32 readable bytes when `from_secret == 0`, 64 when non-zero.
/// `out_*` writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stonechat_identity(
    input: *const u8,
    from_secret: i32,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    ffi_guard!({
        let keys = if from_secret != 0 {
            let Some(secret) = (unsafe { arr::<64>(input) }) else {
                return ERR_INPUT;
            };
            crate::identity::IdentityKeys::from_secret(secret)
        } else {
            let Some(seed) = (unsafe { arr::<32>(input) }) else {
                return ERR_INPUT;
            };
            crate::identity::IdentityKeys::generate(seed)
        };
        let v = json!({
            "secret": B64.encode(keys.secret),
            "public": B64.encode(keys.public),
            "pq_pk": B64.encode(keys.pq_public()),
            "pq_pk_sig": B64.encode(keys.sign_pq_pk()),
            "stonechat_id": keys.stonechat_id(),
        });
        unsafe { emit_json(&v, out_ptr, out_len) }
    })
}

/// Sign `message` with the identity and a domain-separation context
/// (the `stonechat-v1-*` byte strings in PROTOCOL.md).
///
/// # Safety
/// `ed_secret`: 64 readable. `context`/`message`: their lengths.
/// `sig_out`: 64 writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stonechat_sign(
    ed_secret: *const u8,
    context: *const u8,
    context_len: usize,
    message: *const u8,
    message_len: usize,
    sig_out: *mut u8,
) -> i32 {
    ffi_guard!({
        let (Some(secret), Some(ctx), Some(msg)) = (
            unsafe { arr::<64>(ed_secret) },
            unsafe { slice(context, context_len) },
            unsafe { slice(message, message_len) },
        ) else {
            return ERR_INPUT;
        };
        let keys = crate::identity::IdentityKeys::from_secret(secret);
        let sig = keys.sign(ctx, msg);
        unsafe { sig_out.copy_from_nonoverlapping(sig.as_ptr(), sig.len()) };
        OK
    })
}

/// Verify a context-prefixed signature. Returns `0` when it verifies,
/// `-3` when it does not (a normal answer, not an error).
///
/// # Safety
/// `ed_pk`: 32 readable. `sig`: 64 readable. Others per their lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stonechat_verify(
    ed_pk: *const u8,
    context: *const u8,
    context_len: usize,
    message: *const u8,
    message_len: usize,
    sig: *const u8,
) -> i32 {
    ffi_guard!({
        let (Some(pk), Some(ctx), Some(msg), Some(signature)) = (
            unsafe { arr::<32>(ed_pk) },
            unsafe { slice(context, context_len) },
            unsafe { slice(message, message_len) },
            unsafe { arr::<64>(sig) },
        ) else {
            return ERR_INPUT;
        };
        if crate::identity::verify(pk, ctx, msg, signature) {
            OK
        } else {
            ERR_REFUSED
        }
    })
}

/// Sign an abuse report (PROTOCOL.md "Reporting"). Strings are UTF-8
/// `(ptr, len)` pairs; `evidence` may be NULL.
///
/// # Safety
/// `ed_secret`: 64 readable. `sig_out`: 64 writable. Others per lengths.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn stonechat_sign_report(
    ed_secret: *const u8,
    reported_id: *const u8,
    reported_id_len: usize,
    unix_seconds: i64,
    category: *const u8,
    category_len: usize,
    note: *const u8,
    note_len: usize,
    evidence: *const u8,
    evidence_len: usize,
    sig_out: *mut u8,
) -> i32 {
    ffi_guard!({
        let (Some(secret), Some(id), Some(cat), Some(n)) = (
            unsafe { arr::<64>(ed_secret) },
            unsafe { slice(reported_id, reported_id_len) },
            unsafe { slice(category, category_len) },
            unsafe { slice(note, note_len) },
        ) else {
            return ERR_INPUT;
        };
        let ev = unsafe { slice(evidence, evidence_len) };
        let (Ok(id), Ok(cat), Ok(n)) = (
            std::str::from_utf8(id),
            std::str::from_utf8(cat),
            std::str::from_utf8(n),
        ) else {
            return ERR_INPUT;
        };
        let ev = match ev.map(std::str::from_utf8) {
            Some(Ok(s)) => Some(s),
            Some(Err(_)) => return ERR_INPUT,
            None => None,
        };
        let keys = crate::identity::IdentityKeys::from_secret(secret);
        let sig = keys.sign_report(id, unix_seconds, cat, n, ev);
        unsafe { sig_out.copy_from_nonoverlapping(sig.as_ptr(), sig.len()) };
        OK
    })
}

/// The SC- ID an Ed25519 identity key commits to, as a NUL-free UTF-8
/// buffer the caller frees with `stonechat_free`.
///
/// # Safety
/// `ed_pk`: 32 readable. `out_*` writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stonechat_stonechat_id(
    ed_pk: *const u8,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    ffi_guard!({
        let Some(pk) = (unsafe { arr::<32>(ed_pk) }) else {
            return ERR_INPUT;
        };
        unsafe {
            emit(
                crate::ids::derive_stonechat_id(pk).into_bytes(),
                out_ptr,
                out_len,
            )
        };
        OK
    })
}

/// Canonicalize user-typed ID input and verify its checksum. `-3` when it
/// is not a well-formed Stonechat ID.
///
/// # Safety
/// `raw`: `raw_len` readable. `out_*` writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stonechat_normalize_id(
    raw: *const u8,
    raw_len: usize,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    ffi_guard!({
        let Some(bytes) = (unsafe { slice(raw, raw_len) }) else {
            return ERR_INPUT;
        };
        let Ok(text) = std::str::from_utf8(bytes) else {
            return ERR_INPUT;
        };
        match crate::ids::normalize_stonechat_id(text) {
            Ok(id) => {
                unsafe { emit(id.into_bytes(), out_ptr, out_len) };
                OK
            }
            Err(_) => ERR_REFUSED,
        }
    })
}

/// Seal an envelope to a peer's X-Wing identity (PROTOCOL.md "Envelope").
///
/// # Safety
/// `pq_pk`: 1216 readable. `random`: 64 readable. `nonce`: 24 readable.
/// `message`: its length. `out_*` writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stonechat_seal(
    pq_pk: *const u8,
    message: *const u8,
    message_len: usize,
    random: *const u8,
    nonce: *const u8,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    ffi_guard!({
        let (Some(pk), Some(msg), Some(rnd), Some(n)) = (
            unsafe { arr::<{ pqcore::XWING_PUBLIC_BYTES }>(pq_pk) },
            unsafe { slice(message, message_len) },
            unsafe { arr::<{ pqcore::XWING_ENCAPS_RANDOM_BYTES }>(random) },
            unsafe { arr::<24>(nonce) },
        ) else {
            return ERR_INPUT;
        };
        match envelope::seal_to(pk, msg, rnd, n) {
            Some(sealed) => {
                unsafe { emit(sealed, out_ptr, out_len) };
                OK
            }
            None => ERR_REFUSED,
        }
    })
}

/// Symmetric AEAD for media blobs: the file is encrypted under a fresh
/// per-file key that travels to the recipient inside the session-encrypted
/// payload, so the blob is opaque to every server that touches it.
///
/// # Safety
/// `key`: 32 readable. `nonce`: 24 readable. `data`: its length.
/// `out_*` writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stonechat_blob_seal(
    key: *const u8,
    nonce: *const u8,
    data: *const u8,
    data_len: usize,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    ffi_guard!({
        let (Some(k), Some(n), Some(d)) = (
            unsafe { arr::<32>(key) },
            unsafe { arr::<24>(nonce) },
            unsafe { slice(data, data_len) },
        ) else {
            return ERR_INPUT;
        };
        unsafe { emit(crate::primitives::aead_seal(k, n, d, b""), out_ptr, out_len) };
        OK
    })
}

/// `-3` on tamper/corruption.
///
/// # Safety
/// As `stonechat_blob_seal`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stonechat_blob_open(
    key: *const u8,
    nonce: *const u8,
    data: *const u8,
    data_len: usize,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    ffi_guard!({
        let (Some(k), Some(n), Some(d)) = (
            unsafe { arr::<32>(key) },
            unsafe { arr::<24>(nonce) },
            unsafe { slice(data, data_len) },
        ) else {
            return ERR_INPUT;
        };
        match crate::primitives::aead_open(k, n, d, b"") {
            Some(plain) => {
                unsafe { emit(plain, out_ptr, out_len) };
                OK
            }
            None => ERR_REFUSED,
        }
    })
}

/// Passphrase container (backups, identity export). Argon2id parameters
/// ride inside the result — see `vault`.
///
/// # Safety
/// `salt`: 16 readable. `nonce`: 24 readable. Others per their lengths.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn stonechat_vault_seal(
    passphrase: *const u8,
    passphrase_len: usize,
    plaintext: *const u8,
    plaintext_len: usize,
    salt: *const u8,
    nonce: *const u8,
    m_cost_kib: u32,
    t_cost: u32,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    ffi_guard!({
        let (Some(pw), Some(plain), Some(s), Some(n)) = (
            unsafe { slice(passphrase, passphrase_len) },
            unsafe { slice(plaintext, plaintext_len) },
            unsafe { arr::<{ crate::vault::SALT_BYTES }>(salt) },
            unsafe { arr::<24>(nonce) },
        ) else {
            return ERR_INPUT;
        };
        match crate::vault::seal(pw, plain, s, n, m_cost_kib, t_cost) {
            Ok(sealed) => {
                unsafe { emit(sealed, out_ptr, out_len) };
                OK
            }
            Err(_) => ERR_INPUT,
        }
    })
}

/// Open a passphrase container. Distinguishes the outcomes the UI shows:
/// `-3` wrong passphrase or damaged, `-4` created by a newer version,
/// `-1` not one of ours.
///
/// # Safety
/// Buffers per their lengths; `out_*` writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stonechat_vault_open(
    passphrase: *const u8,
    passphrase_len: usize,
    container: *const u8,
    container_len: usize,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    ffi_guard!({
        let (Some(pw), Some(data)) = (unsafe { slice(passphrase, passphrase_len) }, unsafe {
            slice(container, container_len)
        }) else {
            return ERR_INPUT;
        };
        match crate::vault::open(pw, data) {
            Ok(plain) => {
                unsafe { emit(plain, out_ptr, out_len) };
                OK
            }
            Err(crate::vault::VaultError::UnsupportedVersion) => -4,
            Err(crate::vault::VaultError::WrongPassphrase) => ERR_REFUSED,
            Err(_) => ERR_INPUT,
        }
    })
}

/// `crypto_scalarmult_base`: the public half of an X25519 secret — the
/// app's prekey generation (crypto.dart `newX25519`).
///
/// # Safety
/// `secret`: 32 readable bytes. `pk_out`: 32 writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stonechat_x25519_public(secret: *const u8, pk_out: *mut u8) -> i32 {
    ffi_guard!({
        let Some(sk) = (unsafe { arr::<32>(secret) }) else {
            return ERR_INPUT;
        };
        let pk = crate::primitives::x25519_pk(sk);
        unsafe { pk_out.copy_from_nonoverlapping(pk.as_ptr(), pk.len()) };
        OK
    })
}

/// base32 codec for SC- IDs, exposed so the app has one implementation
/// (the Dart copy had its own, with its own tests).
///
/// # Safety
/// `bytes`: its length. `out_*` writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stonechat_base32_encode(
    bytes: *const u8,
    len: usize,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    ffi_guard!({
        let Some(data) = (unsafe { slice(bytes, len) }) else {
            return ERR_INPUT;
        };
        unsafe {
            emit(
                crate::ids::base32_encode(data).into_bytes(),
                out_ptr,
                out_len,
            )
        };
        OK
    })
}

/// `-3` on an invalid character.
///
/// # Safety
/// `text`: its length. `out_*` writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stonechat_base32_decode(
    text: *const u8,
    len: usize,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    ffi_guard!({
        let Some(bytes) = (unsafe { slice(text, len) }) else {
            return ERR_INPUT;
        };
        let Ok(s) = std::str::from_utf8(bytes) else {
            return ERR_INPUT;
        };
        match crate::ids::base32_decode(s) {
            Ok(out) => {
                unsafe { emit(out, out_ptr, out_len) };
                OK
            }
            Err(_) => ERR_REFUSED,
        }
    })
}
