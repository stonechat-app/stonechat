//! Replay of the Dart-recorded golden transcript
//! (fixtures/dart_transcript.json, written by
//! app/test/golden_transcript_test.dart). This is the cross-implementation
//! gate: the iOS notification extension decrypts with this crate while the
//! app decrypts with Dart, against the same session rows — so the Rust
//! side must consume real Dart output bit-for-bit: respond to Dart's
//! PQXDH block, decrypt Dart envelopes, load Dart-serialized session
//! state, and agree on every deterministic piece of ratchet state.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde_json::Value;
use stonechat_core::envelope::X3dhBlock;
use stonechat_core::ids::derive_stonechat_id;
use stonechat_core::primitives::{KSPK_SIG_CONTEXT, SPK_SIG_CONTEXT, verify_with_context};
use stonechat_core::session::{Identity, RatchetHeader, SessionState};

fn fixture() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/dart_transcript.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).expect(
        "fixture missing — record it: STONECHAT_GOLDEN_OUT=… flutter test test/golden_transcript_test.dart",
    ))
    .unwrap()
}

fn b64_arr<const N: usize>(v: &Value) -> [u8; N] {
    B64.decode(v.as_str().unwrap()).unwrap().try_into().unwrap()
}

fn b64_vec(v: &Value) -> Vec<u8> {
    B64.decode(v.as_str().unwrap()).unwrap()
}

/// Decrypt one recorded envelope against `state`.
fn deliver(
    state: &mut SessionState,
    envelope: &Value,
    ad: &str,
    fresh: &[u8; 32],
) -> Option<String> {
    let header: RatchetHeader = serde_json::from_value(envelope["header"].clone()).unwrap();
    let nonce: [u8; 24] = b64_arr(&envelope["nonce"]);
    let ct = b64_vec(&envelope["ciphertext"]);
    state
        .decrypt(&header, &nonce, &ct, ad, fresh, &[0x51; 64])
        .map(|p| String::from_utf8(p).unwrap())
}

#[test]
fn replay_dart_transcript() {
    let f = fixture();

    // -- identities: keys from libsodium, IDs from the Dart codec ------------
    let bob = Identity::from_ed25519_seed(&b64_arr(&f["bob"]["ed_seed"]));
    assert_eq!(
        bob.ed_pk_b64(),
        f["bob"]["ed_pk"].as_str().unwrap(),
        "seed→pk parity"
    );
    assert_eq!(
        derive_stonechat_id(&bob.ed_pk),
        f["bob"]["stonechat_id"].as_str().unwrap(),
        "ID derivation parity on a real key"
    );
    let alice_ed_pk: [u8; 32] = b64_arr(&f["alice"]["ed_pk"]);
    assert_eq!(
        derive_stonechat_id(&alice_ed_pk),
        f["alice"]["stonechat_id"].as_str().unwrap()
    );

    // -- prekey signatures: libsodium-signed, dalek-verified ------------------
    let pk = &f["bob_prekeys"];
    let spk_pub: [u8; 32] = b64_arr(&pk["spk_pub"]);
    let kspk_pub: Vec<u8> = b64_vec(&pk["kspk_pub"]);
    assert!(verify_with_context(
        &bob.ed_pk,
        SPK_SIG_CONTEXT,
        &spk_pub,
        &b64_arr(&pk["spk_sig"])
    ));
    assert!(verify_with_context(
        &bob.ed_pk,
        KSPK_SIG_CONTEXT,
        &kspk_pub,
        &b64_arr(&pk["kspk_sig"])
    ));

    // -- respond to Dart's PQXDH block ----------------------------------------
    let block: X3dhBlock = serde_json::from_value(f["x3dh"].clone()).unwrap();
    assert!(block.kem_one_time, "recorder used the one-time KEM prekey");
    let mut rust_bob = SessionState::respond(
        &bob,
        &alice_ed_pk,
        &block,
        &spk_pub,
        &b64_arr(&pk["spk_sec"]),
        Some(&b64_arr(&pk["opk_sec"])),
        &b64_arr(&pk["kopk_seed"]),
    )
    .unwrap();

    // -- decrypt Dart's envelopes in the recorded delivery order --------------
    let ad_ab = f["ad_a_to_b"].as_str().unwrap();
    let a_to_b = f["a_to_b"].as_array().unwrap();
    for slot in f["delivery_order"].as_array().unwrap() {
        let env = &a_to_b[slot.as_u64().unwrap() as usize];
        assert_eq!(
            deliver(&mut rust_bob, env, ad_ab, &[7u8; 32]).as_deref(),
            env["plaintext"].as_str(),
            "envelope {slot} must decrypt"
        );
    }

    // -- deterministic state must MATCH Dart's serialized Bob -----------------
    // (dhs/cks/rk involve Bob's fresh ratchet key — random, incomparable;
    // everything on the receive side is fully determined by the transcript.)
    let dart_bob: SessionState = serde_json::from_value(f["bob_state_final"].clone()).unwrap();
    assert_eq!(rust_bob.nr, dart_bob.nr, "receive counter");
    assert_eq!(rust_bob.pn, dart_bob.pn);
    assert_eq!(rust_bob.dhr, dart_bob.dhr, "remote ratchet key");
    assert_eq!(rust_bob.ckr, dart_bob.ckr, "receive chain key");
    assert_eq!(
        rust_bob.skipped, dart_bob.skipped,
        "stashed skipped message key"
    );
    assert!(rust_bob.confirmed && rust_bob.pending_x3dh.is_none());

    // -- the late message opens from the stash --------------------------------
    for slot in f["late_delivery"].as_array().unwrap() {
        let env = &a_to_b[slot.as_u64().unwrap() as usize];
        assert_eq!(
            deliver(&mut rust_bob, env, ad_ab, &[8u8; 32]).as_deref(),
            env["plaintext"].as_str(),
            "late envelope {slot} must decrypt from the skipped-key stash"
        );
    }
    assert!(rust_bob.skipped.is_empty());

    // -- load Dart-Alice's state, decrypt Dart-Bob's replies ------------------
    // Exercises the DH-ratchet receive step in Rust starting from a state
    // that Dart wrote (including Alice's serialized secrets).
    let mut rust_alice: SessionState =
        serde_json::from_value(f["alice_state_after_send"].clone()).unwrap();
    let ad_ba = f["ad_b_to_a"].as_str().unwrap();
    for env in f["b_to_a"].as_array().unwrap() {
        assert_eq!(
            deliver(&mut rust_alice, env, ad_ba, &[9u8; 32]).as_deref(),
            env["plaintext"].as_str(),
            "Bob's reply must decrypt from the Dart-written Alice state"
        );
    }
    assert!(rust_alice.confirmed && rust_alice.pending_x3dh.is_none());
}

#[test]
fn dart_state_json_round_trips_exactly() {
    // Parse → re-serialize must reproduce the Dart JSON value for value —
    // this is what lets the app and the NSE hand session rows back and
    // forth without a migration.
    let f = fixture();
    for key in ["alice_state_after_send", "bob_state_final"] {
        let state: SessionState = serde_json::from_value(f[key].clone()).unwrap();
        assert_eq!(
            serde_json::to_value(&state).unwrap(),
            f[key],
            "{key} must survive a Rust parse/serialize round trip unchanged"
        );
    }
}
