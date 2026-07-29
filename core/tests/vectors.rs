//! Reference vectors pinning byte-compatibility with what the Dart app
//! produces via libsodium. Generated against PROTOCOL.md constants with
//! Python's hashlib.blake2b (the same BLAKE2b libsodium's
//! crypto_generichash implements) and PyNaCl (libsodium proper) for the
//! Ed25519↔X25519 conversions, scalarmult, and the AEAD.

use stonechat_core::ids::{derive_stonechat_id, normalize_stonechat_id};
use stonechat_core::primitives::*;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hex32(s: &str) -> [u8; 32] {
    hex(s).try_into().unwrap()
}

fn seq(start: u8, n: usize) -> Vec<u8> {
    (0..n).map(|i| start.wrapping_add(i as u8)).collect()
}

#[test]
fn kdf_chain_matches_libsodium() {
    let ck: [u8; 32] = seq(0, 32).try_into().unwrap();
    let (mk, ck_next) = kdf_chain(&ck);
    assert_eq!(
        mk,
        hex32("dace1c2bbe1660f898884720cb73d4dad6e7d360260c749cee92d58f4aa0f23a")
    );
    assert_eq!(
        ck_next,
        hex32("7dc7bf77b86ed1143e85946206072f8f26504a1031d19701edd06318a0b8bc5b")
    );
}

#[test]
fn kdf_root_matches_libsodium() {
    let rk: [u8; 32] = seq(100, 32).try_into().unwrap();
    let dh_out: [u8; 32] = seq(200, 32).try_into().unwrap();
    let (rk_next, ck) = kdf_root(&rk, &dh_out);
    assert_eq!(
        rk_next,
        hex32("3d8c9cfea8aedadf3904dd15a10ee508f97320ab283c254bdb89820bb0a705e5")
    );
    assert_eq!(
        ck,
        hex32("66b2dcb07cd0d756799016b48d8a272ed4df9df6464ca21b3f08ca48c59fcaad")
    );
}

#[test]
fn x3dh_shared_key_matches_libsodium() {
    let dhs3 = [[1u8; 32], [2u8; 32], [3u8; 32]];
    let kem_ss = [9u8; 32];
    assert_eq!(
        x3dh_shared_key(&dhs3, &kem_ss),
        hex32("4f5215d97d02b45294e41193411644e4dbedd2ba8c52a9bab47c906ec96d57a7")
    );
    let dhs4 = [[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
    assert_eq!(
        x3dh_shared_key(&dhs4, &kem_ss),
        hex32("3c4320259c9160398f007982ea272dc07913a95a882213c622659cfd1444068e")
    );
}

#[test]
fn hseal_key_matches_libsodium() {
    let kem_ss = [9u8; 32];
    assert_eq!(
        keyed_hash_32(&kem_ss, HSEAL_KDF_KEY),
        hex32("dfde37117721c7769a777d2834c0cc62c0aef8de06ccee75e49079b52813ac37")
    );
}

#[test]
fn stonechat_id_matches_dart() {
    let pubkey = seq(0, 32);
    let id = derive_stonechat_id(&pubkey);
    assert_eq!(id, "SC-WGYT-HOM7-KFXG-ZAWO-3KES-55NP-KD5E-WTTR-UASA");
    // Normalization round-trips, tolerating case/spacing.
    assert_eq!(
        normalize_stonechat_id(" sc-wgyt hom7-kfxg-zawo-3kes-55np-kd5e-wttr-uasa ").unwrap(),
        id
    );
    let mut wrong = id.clone();
    wrong.replace_range(3..4, "X");
    assert!(normalize_stonechat_id(&wrong).is_err());
}

#[test]
fn ed25519_conversions_match_libsodium() {
    let seed: [u8; 32] = seq(0, 32).try_into().unwrap();
    let ed_pk = ed25519_pk_from_seed(&seed);
    assert_eq!(
        ed_pk,
        hex32("03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8")
    );
    assert_eq!(
        ed25519_pk_to_x25519(&ed_pk).unwrap(),
        hex32("4701d08488451f545a409fb58ae3e58581ca40ac3f7f114698cd71deac73ca01")
    );
    let x_sk = ed25519_seed_to_x25519_sk(&seed);
    assert_eq!(
        x_sk,
        hex32("3894eea49c580aef816935762be049559d6d1440dede12e6a125f1841fff8e6f")
    );
    // crypto_scalarmult(x_sk, crypto_scalarmult_base([42u8; 32]))
    let peer_pk = x25519_pk(&[42u8; 32]);
    assert_eq!(
        dh(&x_sk, &peer_pk),
        hex32("bbf11ad2ea63458be9c1e36c840a37c2805e9770706bcae911146998afe23956")
    );
}

#[test]
fn aead_matches_libsodium() {
    let key: [u8; 32] = seq(0, 32).try_into().unwrap();
    let nonce: [u8; 24] = seq(0, 24).try_into().unwrap();
    let ct = aead_seal(&key, &nonce, b"stonechat aead vector", b"ad-bytes");
    assert_eq!(
        ct,
        hex("edb66011f5b1e5cf476447abaa36889e2e245cca8f8bf25d8666f9f5adeda2ba374b573748")
    );
    assert_eq!(
        aead_open(&key, &nonce, &ct, b"ad-bytes").as_deref(),
        Some(b"stonechat aead vector".as_slice())
    );
    assert_eq!(aead_open(&key, &nonce, &ct, b"other-ad"), None);
}

#[test]
fn signatures_verify_with_context() {
    let seed = [7u8; 32];
    let pk = ed25519_pk_from_seed(&seed);
    let sig = sign_with_context(&seed, SPK_SIG_CONTEXT, b"prekey-bytes");
    assert!(verify_with_context(
        &pk,
        SPK_SIG_CONTEXT,
        b"prekey-bytes",
        &sig
    ));
    assert!(!verify_with_context(
        &pk,
        KSPK_SIG_CONTEXT,
        b"prekey-bytes",
        &sig
    ));
    assert!(!verify_with_context(
        &pk,
        SPK_SIG_CONTEXT,
        b"other-bytes",
        &sig
    ));
}
