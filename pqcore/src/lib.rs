//! Post-quantum KEM core shared by every Zeon client (C ABI for the Flutter
//! app, plain Rust for the relay and a future wasm web client).
//!
//! Wraps RustCrypto `ml-kem` (FIPS 203, ML-KEM-768 — PQXDH prekeys, see
//! PROTOCOL.md "Prekeys") and `x-wing` (draft-connolly-cfrg-xwing-kem —
//! the hybrid envelope seal, PROTOCOL.md "Envelope"). docs/POST_QUANTUM.md
//! is the design record.
//!
//! Secret keys are carried as seeds — 64 bytes for an ML-KEM-768 prekey,
//! 32 for an X-Wing identity key — so callers store small opaque blobs and
//! key expansion stays in here. Nothing in this crate draws entropy:
//! callers pass CSPRNG bytes explicitly (the app uses libsodium's
//! `randombytes`, the same source the rest of its crypto trusts), which
//! also makes every operation deterministic and testable.

use kem::{Decapsulate, Decapsulator, FromSeed, KeyExport};
use ml_kem::MlKem768;
use ml_kem::array::Array;

pub const MLKEM_SEED_BYTES: usize = 64;
pub const MLKEM_PUBLIC_BYTES: usize = 1184;
pub const MLKEM_CIPHERTEXT_BYTES: usize = 1088;
pub const MLKEM_ENCAPS_RANDOM_BYTES: usize = 32;
pub const XWING_SEED_BYTES: usize = 32;
pub const XWING_PUBLIC_BYTES: usize = 1216;
pub const XWING_CIPHERTEXT_BYTES: usize = 1120;
pub const XWING_ENCAPS_RANDOM_BYTES: usize = 64;
pub const SHARED_SECRET_BYTES: usize = 32;

// -- ML-KEM-768 (PQXDH prekeys) ----------------------------------------------

/// Expand a 64-byte seed (d || z, caller-generated) into the public
/// encapsulation key peers encapsulate to.
pub fn mlkem_pk_from_seed(seed: &[u8; MLKEM_SEED_BYTES]) -> [u8; MLKEM_PUBLIC_BYTES] {
    let (_sk, pk) = MlKem768::from_seed(&Array::from(*seed));
    pk.to_bytes().into()
}

/// Encapsulate to a peer's ML-KEM prekey. `random` must be fresh CSPRNG
/// output. `None` when `pk` is not a valid ML-KEM-768 key (modulus check).
pub fn mlkem_encaps(
    pk: &[u8; MLKEM_PUBLIC_BYTES],
    random: &[u8; MLKEM_ENCAPS_RANDOM_BYTES],
) -> Option<([u8; MLKEM_CIPHERTEXT_BYTES], [u8; SHARED_SECRET_BYTES])> {
    let pk = ml_kem::ml_kem_768::EncapsulationKey::new(&Array::from(*pk)).ok()?;
    let (ct, ss) = pk.encapsulate_deterministic(&Array::from(*random));
    Some((ct.into(), ss.into()))
}

/// Decapsulate with our stored prekey seed. Never fails: a forged
/// ciphertext yields an implicit-rejection secret (FIPS 203) and the
/// protocol layer's AEAD then rejects.
pub fn mlkem_decaps(
    seed: &[u8; MLKEM_SEED_BYTES],
    ct: &[u8; MLKEM_CIPHERTEXT_BYTES],
) -> [u8; SHARED_SECRET_BYTES] {
    let (sk, _pk) = MlKem768::from_seed(&Array::from(*seed));
    sk.decapsulate(&Array::from(*ct)).into()
}

// -- X-Wing (hybrid envelope seal) -------------------------------------------

/// Expand a 32-byte identity seed into the public key published in the hub
/// directory (`pq_pk`).
pub fn xwing_pk_from_seed(seed: &[u8; XWING_SEED_BYTES]) -> [u8; XWING_PUBLIC_BYTES] {
    let sk = x_wing::DecapsulationKey::from(*seed);
    sk.encapsulation_key().to_bytes().into()
}

/// Encapsulate to a peer's X-Wing identity key. `random` must be fresh
/// CSPRNG output. `None` when `pk` does not parse as an X-Wing key.
pub fn xwing_encaps(
    pk: &[u8; XWING_PUBLIC_BYTES],
    random: &[u8; XWING_ENCAPS_RANDOM_BYTES],
) -> Option<([u8; XWING_CIPHERTEXT_BYTES], [u8; SHARED_SECRET_BYTES])> {
    let pk = x_wing::EncapsulationKey::try_from(&pk[..]).ok()?;
    let (ct, ss) = pk.encapsulate_deterministic(&Array::from(*random));
    Some((ct.into(), ss.into()))
}

/// Decapsulate with our identity seed. Never fails (implicit rejection —
/// garbage in, garbage shared secret out; the AEAD layer rejects).
pub fn xwing_decaps(
    seed: &[u8; XWING_SEED_BYTES],
    ct: &[u8; XWING_CIPHERTEXT_BYTES],
) -> [u8; SHARED_SECRET_BYTES] {
    let sk = x_wing::DecapsulationKey::from(*seed);
    sk.decapsulate(&Array::from(*ct)).into()
}

// -- C ABI (Flutter dart:ffi) -------------------------------------------------
//
// Every function takes caller-allocated fixed-size buffers and returns 0 on
// success, -1 on invalid input. Panics cannot cross the FFI boundary: they
// are caught and reported as -2.

macro_rules! ffi_guard {
    ($body:expr) => {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| $body)) {
            Ok(code) => code,
            Err(_) => -2,
        }
    };
}

/// # Safety
/// `seed` must point to 64 readable bytes, `pk_out` to 1184 writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zeon_mlkem_pk_from_seed(seed: *const u8, pk_out: *mut u8) -> i32 {
    ffi_guard!({
        let seed = unsafe { &*seed.cast::<[u8; MLKEM_SEED_BYTES]>() };
        let pk = mlkem_pk_from_seed(seed);
        unsafe { pk_out.copy_from_nonoverlapping(pk.as_ptr(), pk.len()) };
        0
    })
}

/// # Safety
/// `pk`: 1184 readable; `random`: 32 readable; `ct_out`: 1088 writable;
/// `ss_out`: 32 writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zeon_mlkem_encaps(
    pk: *const u8,
    random: *const u8,
    ct_out: *mut u8,
    ss_out: *mut u8,
) -> i32 {
    ffi_guard!({
        let pk = unsafe { &*pk.cast::<[u8; MLKEM_PUBLIC_BYTES]>() };
        let random = unsafe { &*random.cast::<[u8; MLKEM_ENCAPS_RANDOM_BYTES]>() };
        match mlkem_encaps(pk, random) {
            Some((ct, ss)) => {
                unsafe { ct_out.copy_from_nonoverlapping(ct.as_ptr(), ct.len()) };
                unsafe { ss_out.copy_from_nonoverlapping(ss.as_ptr(), ss.len()) };
                0
            }
            None => -1,
        }
    })
}

/// # Safety
/// `seed`: 64 readable; `ct`: 1088 readable; `ss_out`: 32 writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zeon_mlkem_decaps(seed: *const u8, ct: *const u8, ss_out: *mut u8) -> i32 {
    ffi_guard!({
        let seed = unsafe { &*seed.cast::<[u8; MLKEM_SEED_BYTES]>() };
        let ct = unsafe { &*ct.cast::<[u8; MLKEM_CIPHERTEXT_BYTES]>() };
        let ss = mlkem_decaps(seed, ct);
        unsafe { ss_out.copy_from_nonoverlapping(ss.as_ptr(), ss.len()) };
        0
    })
}

/// # Safety
/// `seed`: 32 readable; `pk_out`: 1216 writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zeon_xwing_pk_from_seed(seed: *const u8, pk_out: *mut u8) -> i32 {
    ffi_guard!({
        let seed = unsafe { &*seed.cast::<[u8; XWING_SEED_BYTES]>() };
        let pk = xwing_pk_from_seed(seed);
        unsafe { pk_out.copy_from_nonoverlapping(pk.as_ptr(), pk.len()) };
        0
    })
}

/// # Safety
/// `pk`: 1216 readable; `random`: 64 readable; `ct_out`: 1120 writable;
/// `ss_out`: 32 writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zeon_xwing_encaps(
    pk: *const u8,
    random: *const u8,
    ct_out: *mut u8,
    ss_out: *mut u8,
) -> i32 {
    ffi_guard!({
        let pk = unsafe { &*pk.cast::<[u8; XWING_PUBLIC_BYTES]>() };
        let random = unsafe { &*random.cast::<[u8; XWING_ENCAPS_RANDOM_BYTES]>() };
        match xwing_encaps(pk, random) {
            Some((ct, ss)) => {
                unsafe { ct_out.copy_from_nonoverlapping(ct.as_ptr(), ct.len()) };
                unsafe { ss_out.copy_from_nonoverlapping(ss.as_ptr(), ss.len()) };
                0
            }
            None => -1,
        }
    })
}

/// # Safety
/// `seed`: 32 readable; `ct`: 1120 readable; `ss_out`: 32 writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zeon_xwing_decaps(seed: *const u8, ct: *const u8, ss_out: *mut u8) -> i32 {
    ffi_guard!({
        let seed = unsafe { &*seed.cast::<[u8; XWING_SEED_BYTES]>() };
        let ct = unsafe { &*ct.cast::<[u8; XWING_CIPHERTEXT_BYTES]>() };
        let ss = xwing_decaps(seed, ct);
        unsafe { ss_out.copy_from_nonoverlapping(ss.as_ptr(), ss.len()) };
        0
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mlkem_round_trip() {
        let seed = [7u8; MLKEM_SEED_BYTES];
        let pk = mlkem_pk_from_seed(&seed);
        let (ct, ss_sender) = mlkem_encaps(&pk, &[9u8; MLKEM_ENCAPS_RANDOM_BYTES]).unwrap();
        let ss_receiver = mlkem_decaps(&seed, &ct);
        assert_eq!(ss_sender, ss_receiver);
    }

    #[test]
    fn mlkem_keygen_is_deterministic() {
        let seed = [3u8; MLKEM_SEED_BYTES];
        assert_eq!(mlkem_pk_from_seed(&seed), mlkem_pk_from_seed(&seed));
        assert_ne!(mlkem_pk_from_seed(&seed), mlkem_pk_from_seed(&[4u8; 64]));
    }

    #[test]
    fn mlkem_forged_ciphertext_rejects_implicitly() {
        let seed = [7u8; MLKEM_SEED_BYTES];
        let pk = mlkem_pk_from_seed(&seed);
        let (mut ct, ss) = mlkem_encaps(&pk, &[9u8; 32]).unwrap();
        ct[0] ^= 1;
        assert_ne!(mlkem_decaps(&seed, &ct), ss);
    }

    #[test]
    fn xwing_round_trip() {
        let seed = [11u8; XWING_SEED_BYTES];
        let pk = xwing_pk_from_seed(&seed);
        let (ct, ss_sender) = xwing_encaps(&pk, &[13u8; XWING_ENCAPS_RANDOM_BYTES]).unwrap();
        let ss_receiver = xwing_decaps(&seed, &ct);
        assert_eq!(ss_sender, ss_receiver);
    }

    #[test]
    fn xwing_keygen_is_deterministic() {
        let seed = [5u8; XWING_SEED_BYTES];
        assert_eq!(xwing_pk_from_seed(&seed), xwing_pk_from_seed(&seed));
        assert_ne!(xwing_pk_from_seed(&seed), xwing_pk_from_seed(&[6u8; 32]));
    }

    #[test]
    fn xwing_tampered_ciphertext_rejects_implicitly() {
        let seed = [11u8; XWING_SEED_BYTES];
        let pk = xwing_pk_from_seed(&seed);
        let (mut ct, ss) = xwing_encaps(&pk, &[13u8; 64]).unwrap();
        ct[100] ^= 1;
        assert_ne!(xwing_decaps(&seed, &ct), ss);
    }

    #[test]
    fn ffi_round_trip() {
        let seed = [21u8; XWING_SEED_BYTES];
        let mut pk = [0u8; XWING_PUBLIC_BYTES];
        let mut ct = [0u8; XWING_CIPHERTEXT_BYTES];
        let (mut ss1, mut ss2) = ([0u8; 32], [0u8; 32]);
        unsafe {
            assert_eq!(zeon_xwing_pk_from_seed(seed.as_ptr(), pk.as_mut_ptr()), 0);
            assert_eq!(
                zeon_xwing_encaps(
                    pk.as_ptr(),
                    [23u8; 64].as_ptr(),
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr()
                ),
                0
            );
            assert_eq!(zeon_xwing_decaps(seed.as_ptr(), ct.as_ptr(), ss2.as_mut_ptr()), 0);
        }
        assert_eq!(ss1, ss2);
    }
}
