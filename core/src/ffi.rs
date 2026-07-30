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
