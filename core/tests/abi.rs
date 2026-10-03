//! Drives a full conversation through the C ABI exactly as a foreign host
//! (Dart bindings, Swift NSE) would: relay-shaped bundle JSON in, opaque
//! state blobs shuttled in and out, buffers freed via stonechat_free.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde_json::{Value, json};
use stonechat_core::ffi::*;
use stonechat_core::primitives::{keyed_hash_32, x25519_pk};

fn rnd32(label: &str) -> [u8; 32] {
    keyed_hash_32(label.as_bytes(), b"stonechat-core-abi-test!")
}

fn rnd64(label: &str) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&rnd32(&format!("{label}/0")));
    out[32..].copy_from_slice(&rnd32(&format!("{label}/1")));
    out
}

/// Call an FFI function that emits a buffer; return the parsed JSON.
fn take(rc: i32, ptr: *mut u8, len: usize) -> Value {
    assert_eq!(rc, 0, "FFI call failed with {rc}");
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec();
    unsafe { stonechat_free(ptr, len) };
    serde_json::from_slice(&bytes).unwrap()
}

struct Out {
    ptr: *mut u8,
    len: usize,
}

impl Out {
    fn new() -> Out {
        Out {
            ptr: std::ptr::null_mut(),
            len: 0,
        }
    }
}

fn encrypt(state: &Value, plaintext: &[u8], ad: &str, nonce: &[u8; 24]) -> (Value, Value, Vec<u8>) {
    let state_bytes = serde_json::to_vec(state).unwrap();
    let mut out = Out::new();
    let rc = unsafe {
        stonechat_session_encrypt(
            state_bytes.as_ptr(),
            state_bytes.len(),
            plaintext.as_ptr(),
            plaintext.len(),
            ad.as_ptr(),
            ad.len(),
            nonce.as_ptr(),
            &mut out.ptr,
            &mut out.len,
        )
    };
    let v = take(rc, out.ptr, out.len);
    let ct = B64.decode(v["ciphertext"].as_str().unwrap()).unwrap();
    (v["state"].clone(), v["header"].clone(), ct)
}

/// Returns (new_state, plaintext) or None on refusal (state stays valid).
fn decrypt(
    state: &Value,
    header: &Value,
    nonce: &[u8; 24],
    ct: &[u8],
    ad: &str,
    fresh: &[u8; 32],
) -> Option<(Value, Vec<u8>)> {
    let state_bytes = serde_json::to_vec(state).unwrap();
    let header_bytes = serde_json::to_vec(header).unwrap();
    let mut out = Out::new();
    let rc = unsafe {
        stonechat_session_decrypt(
            state_bytes.as_ptr(),
            state_bytes.len(),
            header_bytes.as_ptr(),
            header_bytes.len(),
            nonce.as_ptr(),
            ct.as_ptr(),
            ct.len(),
            ad.as_ptr(),
            ad.len(),
            fresh.as_ptr(),
            [0x51u8; 64].as_ptr(),
            &mut out.ptr,
            &mut out.len,
        )
    };
    if rc == -3 {
        return None;
    }
    let v = take(rc, out.ptr, out.len);
    let plain = B64.decode(v["plaintext"].as_str().unwrap()).unwrap();
    Some((v["state"].clone(), plain))
}

#[test]
fn full_conversation_through_the_c_abi() {
    let alice_seed = rnd32("alice/id");
    let bob_seed = rnd32("bob/id");
    let bob = stonechat_core::session::Identity::from_ed25519_seed(&bob_seed);
    let alice = stonechat_core::session::Identity::from_ed25519_seed(&alice_seed);

    // Bob's prekeys, bundle exactly as his mailbox would serve it.
    let spk_sec = rnd32("bob/spk");
    let spk_pub = x25519_pk(&spk_sec);
    let opk_sec = rnd32("bob/opk");
    let kopk_seed = rnd64("bob/kopk");
    let kopk_pub = pqcore::mlkem_pk_from_seed(&kopk_seed);
    let kspk_seed = rnd64("bob/kspk");
    let bundle = json!({
        "spk":  {"id": 7,  "pub": B64.encode(spk_pub), "sig": "unchecked-here"},
        "opk":  {"id": 41, "pub": B64.encode(x25519_pk(&opk_sec))},
        "kspk": {"id": 5,  "pub": B64.encode(pqcore::mlkem_pk_from_seed(&kspk_seed)), "sig": "unchecked-here"},
        "kopk": {"id": 51, "pub": B64.encode(kopk_pub)},
    });
    let bundle_bytes = serde_json::to_vec(&bundle).unwrap();

    // -- Alice initiates through the ABI --------------------------------------
    let (ek, ratchet, kem) = (rnd32("a/ek"), rnd32("a/ratchet"), rnd32("a/kem"));
    let mut out = Out::new();
    let rc = unsafe {
        stonechat_session_initiate(
            alice_seed.as_ptr(),
            bob.ed_pk.as_ptr(),
            bundle_bytes.as_ptr(),
            bundle_bytes.len(),
            ek.as_ptr(),
            ratchet.as_ptr(),
            kem.as_ptr(),
            &mut out.ptr,
            &mut out.len,
        )
    };
    let mut a_state = take(rc, out.ptr, out.len);
    let block = a_state["pending_x3dh"].clone();
    assert_eq!(block["kem_one_time"], true);
    assert_eq!(block["kem_id"], 51);

    // -- Alice sends two messages ----------------------------------------------
    let ad = "stonechat/v1|SC-A|SC-B|msg";
    let n1: [u8; 24] = rnd64("n1")[..24].try_into().unwrap();
    let n2: [u8; 24] = rnd64("n2")[..24].try_into().unwrap();
    let (s, h1, ct1) = encrypt(&a_state, b"over the wire", ad, &n1);
    a_state = s;
    let (s, h2, ct2) = encrypt(&a_state, b"and another", ad, &n2);
    a_state = s;

    // -- Bob responds through the ABI ------------------------------------------
    let block_bytes = serde_json::to_vec(&block).unwrap();
    let mut out = Out::new();
    let rc = unsafe {
        stonechat_session_respond(
            bob_seed.as_ptr(),
            alice.ed_pk.as_ptr(),
            block_bytes.as_ptr(),
            block_bytes.len(),
            spk_pub.as_ptr(),
            spk_sec.as_ptr(),
            opk_sec.as_ptr(),
            kopk_seed.as_ptr(),
            &mut out.ptr,
            &mut out.len,
        )
    };
    let mut b_state = take(rc, out.ptr, out.len);

    let (s, plain) = decrypt(&b_state, &h1, &n1, &ct1, ad, &rnd32("bf1")).unwrap();
    b_state = s;
    assert_eq!(plain, b"over the wire");
    let (s, plain) = decrypt(&b_state, &h2, &n2, &ct2, ad, &rnd32("bf2")).unwrap();
    b_state = s;
    assert_eq!(plain, b"and another");

    // -- Bob replies, Alice decrypts --------------------------------------------
    let ad_back = "stonechat/v1|SC-B|SC-A|msg";
    let n3: [u8; 24] = rnd64("n3")[..24].try_into().unwrap();
    let (s, h3, ct3) = encrypt(&b_state, b"got both", ad_back, &n3);
    b_state = s;
    let (s, plain) = decrypt(&a_state, &h3, &n3, &ct3, ad_back, &rnd32("af1")).unwrap();
    assert_eq!(plain, b"got both");
    a_state = s;
    assert_eq!(a_state["confirmed"], true);
    assert_eq!(a_state["pending_x3dh"], Value::Null);

    // -- refusal semantics: tampered ciphertext, state untouched ----------------
    let n4: [u8; 24] = rnd64("n4")[..24].try_into().unwrap();
    let (_, h4, mut ct4) = encrypt(&b_state, b"tamper me", ad_back, &n4);
    ct4[0] ^= 1;
    assert!(decrypt(&a_state, &h4, &n4, &ct4, ad_back, &rnd32("af2")).is_none());
    ct4[0] ^= 1;
    assert!(decrypt(&a_state, &h4, &n4, &ct4, ad_back, &rnd32("af3")).is_some());
}

#[test]
fn abi_rejects_malformed_input_without_allocating() {
    let mut out = Out::new();
    let garbage = b"not json";
    let seed = [1u8; 32];
    let rc = unsafe {
        stonechat_session_initiate(
            seed.as_ptr(),
            seed.as_ptr(),
            garbage.as_ptr(),
            garbage.len(),
            seed.as_ptr(),
            seed.as_ptr(),
            seed.as_ptr(),
            &mut out.ptr,
            &mut out.len,
        )
    };
    assert_eq!(rc, -1);
    assert!(out.ptr.is_null(), "nothing may be allocated on error");

    // NULL input pointers refuse instead of crashing.
    let rc = unsafe {
        stonechat_session_encrypt(
            std::ptr::null(),
            0,
            garbage.as_ptr(),
            garbage.len(),
            garbage.as_ptr(),
            garbage.len(),
            seed.as_ptr(),
            &mut out.ptr,
            &mut out.len,
        )
    };
    assert_eq!(rc, -1);

    // Freeing NULL is a no-op.
    unsafe { stonechat_free(std::ptr::null_mut(), 0) };
}

#[test]
fn envelope_helpers_round_trip() {
    // pq seed derivation matches the app's domain-separated KDF, unseal
    // opens what envelope::seal_to produced, fingerprint is BLAKE2b-256.
    // The app hashes the FULL 64-byte libsodium secret key (crypto.dart
    // `_pqSeed`); this vector comes from PyNaCl + hashlib.blake2b so the
    // derivation is pinned to libsodium's, not merely self-consistent.
    let seed: [u8; 32] = (0u8..32).collect::<Vec<_>>().try_into().unwrap();
    let mut ed_secret = [0u8; 64];
    ed_secret[..32].copy_from_slice(&seed);
    ed_secret[32..].copy_from_slice(&stonechat_core::primitives::ed25519_pk_from_seed(&seed));
    let mut pq_seed = [0u8; 32];
    assert_eq!(
        unsafe { stonechat_pq_seed_from_ed_secret(ed_secret.as_ptr(), pq_seed.as_mut_ptr()) },
        0
    );
    let expected: Vec<u8> = (0..32)
        .map(|i| {
            u8::from_str_radix(
                &"ef97ecd5bf14eddfeed2c5410f605bd104f5f6efbcd2103247d5e8305addbd9b"
                    [i * 2..i * 2 + 2],
                16,
            )
            .unwrap()
        })
        .collect();
    assert_eq!(
        pq_seed.to_vec(),
        expected,
        "must match libsodium-derived pq seed"
    );

    let pq_pk = pqcore::xwing_pk_from_seed(&pq_seed);
    let sealed = stonechat_core::envelope::seal_to(
        &pq_pk,
        b"{\"v\":1}",
        &rnd64("env/r"),
        &rnd64("env/n")[..24].try_into().unwrap(),
    )
    .unwrap();

    let mut out = Out::new();
    let rc = unsafe {
        stonechat_unseal(
            pq_seed.as_ptr(),
            sealed.as_ptr(),
            sealed.len(),
            &mut out.ptr,
            &mut out.len,
        )
    };
    assert_eq!(rc, 0);
    let inner = unsafe { std::slice::from_raw_parts(out.ptr, out.len) }.to_vec();
    unsafe { stonechat_free(out.ptr, out.len) };
    assert_eq!(inner, b"{\"v\":1}");

    // Wrong identity refuses without allocating.
    let other = rnd32("env/other");
    let mut out2 = Out::new();
    let rc = unsafe {
        stonechat_unseal(
            other.as_ptr(),
            sealed.as_ptr(),
            sealed.len(),
            &mut out2.ptr,
            &mut out2.len,
        )
    };
    assert_eq!(rc, -3);
    assert!(out2.ptr.is_null());

    let der = b"pretend this is certificate DER";
    let mut fp = [0u8; 32];
    assert_eq!(
        unsafe { stonechat_tls_fingerprint(der.as_ptr(), der.len(), fp.as_mut_ptr()) },
        0
    );
    assert_eq!(fp.to_vec(), stonechat_core::primitives::hash_var(der, 32));
}
