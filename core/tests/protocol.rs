//! End-to-end protocol behavior: PQXDH handshake both ways, ratchet
//! stepping, out-of-order delivery, tamper resistance, state
//! serialization parity with the Dart JSON shape.

use stonechat_core::envelope::{seal_to, unseal};
use stonechat_core::primitives::{
    PQID_SEED_KEY, ed25519_seed_to_x25519_sk, keyed_hash_32, x25519_pk,
};
use stonechat_core::session::{Identity, InitiateRandom, PrekeyBundle, SessionState};

/// Deterministic "randomness" for tests: keyed BLAKE2b of a label.
fn rnd32(label: &str) -> [u8; 32] {
    keyed_hash_32(label.as_bytes(), b"stonechat-core-test-rng!")
}

fn rnd(label: &str, n: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0u32;
    while out.len() < n {
        out.extend_from_slice(&rnd32(&format!("{label}/{i}")));
        i += 1;
    }
    out.truncate(n);
    out
}

struct Peer {
    identity: Identity,
    spk_sec: [u8; 32],
    spk_pub: [u8; 32],
    opk_sec: [u8; 32],
    kspk_seed: [u8; pqcore::MLKEM_SEED_BYTES],
    kopk_seed: [u8; pqcore::MLKEM_SEED_BYTES],
}

impl Peer {
    fn new(name: &str) -> Peer {
        let spk_sec = rnd32(&format!("{name}/spk"));
        Peer {
            identity: Identity::from_ed25519_seed(&rnd32(&format!("{name}/id"))),
            spk_sec,
            spk_pub: x25519_pk(&spk_sec),
            opk_sec: rnd32(&format!("{name}/opk")),
            kspk_seed: rnd(&format!("{name}/kspk"), 64).try_into().unwrap(),
            kopk_seed: rnd(&format!("{name}/kopk"), 64).try_into().unwrap(),
        }
    }

    fn bundle(&self, with_one_time: bool) -> PrekeyBundle {
        PrekeyBundle {
            spk_id: 7,
            spk_pub: self.spk_pub,
            opk_id: with_one_time.then_some(41),
            opk_pub: with_one_time.then(|| x25519_pk(&self.opk_sec)),
            kspk_id: 5,
            kspk_pub: pqcore::mlkem_pk_from_seed(&self.kspk_seed),
            kopk_id: with_one_time.then_some(51),
            kopk_pub: with_one_time.then(|| pqcore::mlkem_pk_from_seed(&self.kopk_seed)),
        }
    }
}

const AD: &str = "stonechat/v1|SC-ALICE|SC-BOB|msg";

fn initiate_random(label: &str) -> InitiateRandom {
    InitiateRandom {
        ek_sk: rnd32(&format!("{label}/ek")),
        ratchet_sk: rnd32(&format!("{label}/ratchet")),
        kem_random: rnd32(&format!("{label}/kem")),
    }
}

fn nonce(label: &str) -> [u8; 24] {
    rnd(label, 24).try_into().unwrap()
}

/// Full handshake: Alice initiates, Bob responds from the x3dh block, then
/// both directions ratchet.
fn handshake(with_one_time: bool) -> (SessionState, SessionState) {
    let alice = Peer::new("alice");
    let bob = Peer::new("bob");
    let mut a = SessionState::initiate(
        &alice.identity,
        &bob.identity.ed_pk,
        &bob.bundle(with_one_time),
        &initiate_random("a-init"),
    )
    .unwrap();

    let block = a
        .pending_x3dh
        .clone()
        .expect("initial envelopes carry x3dh");
    let (header, ct) = a.encrypt(b"hello bob", AD, &nonce("n0")).unwrap();

    let mut b = SessionState::respond(
        &bob.identity,
        &alice.identity.ed_pk,
        &block,
        &bob.spk_pub,
        &bob.spk_sec,
        with_one_time.then_some(&bob.opk_sec),
        if with_one_time {
            &bob.kopk_seed
        } else {
            &bob.kspk_seed
        },
    )
    .unwrap();

    let plain = b.decrypt(&header, &nonce("n0"), &ct, AD, &rnd32("b-fresh0"));
    assert_eq!(plain.as_deref(), Some(b"hello bob".as_slice()));
    (a, b)
}

#[test]
fn handshake_with_one_time_prekeys() {
    let (a, b) = handshake(true);
    assert!(a.can_send() && b.can_send());
    assert!(b.confirmed);
}

#[test]
fn handshake_with_dry_prekey_pool() {
    // No OPK/KOPK: DH4 absent, KEM falls back to the signed prekey.
    let (a, b) = handshake(false);
    assert!(a.can_send() && b.can_send());
}

#[test]
fn two_way_conversation_ratchets() {
    let (mut a, mut b) = handshake(true);

    // Bob replies — his first send after the DH-ratchet step.
    let (h, ct) = b.encrypt(b"hi alice", AD, &nonce("n1")).unwrap();
    let plain = a.decrypt(&h, &nonce("n1"), &ct, AD, &rnd32("a-fresh1"));
    assert_eq!(plain.as_deref(), Some(b"hi alice".as_slice()));
    assert!(a.confirmed, "initiator confirms on first decrypted reply");
    assert!(
        a.pending_x3dh.is_none(),
        "x3dh block dropped once confirmed"
    );

    // A few more rounds, alternating, to exercise repeated DH ratchets.
    for i in 0..4 {
        let msg = format!("ping {i}");
        let (h, ct) = a
            .encrypt(msg.as_bytes(), AD, &nonce(&format!("a{i}")))
            .unwrap();
        assert_eq!(
            b.decrypt(
                &h,
                &nonce(&format!("a{i}")),
                &ct,
                AD,
                &rnd32(&format!("bf{i}"))
            )
            .as_deref(),
            Some(msg.as_bytes())
        );
        let msg = format!("pong {i}");
        let (h, ct) = b
            .encrypt(msg.as_bytes(), AD, &nonce(&format!("b{i}")))
            .unwrap();
        assert_eq!(
            a.decrypt(
                &h,
                &nonce(&format!("b{i}")),
                &ct,
                AD,
                &rnd32(&format!("af{i}"))
            )
            .as_deref(),
            Some(msg.as_bytes())
        );
    }
}

#[test]
fn out_of_order_delivery_uses_skipped_keys() {
    let (mut a, mut b) = handshake(true);
    let (h1, ct1) = a.encrypt(b"one", AD, &nonce("m1")).unwrap();
    let (h2, ct2) = a.encrypt(b"two", AD, &nonce("m2")).unwrap();
    let (h3, ct3) = a.encrypt(b"three", AD, &nonce("m3")).unwrap();

    // Deliver 3 first: keys for 1 and 2 get stashed.
    assert_eq!(
        b.decrypt(&h3, &nonce("m3"), &ct3, AD, &rnd32("f3"))
            .as_deref(),
        Some(b"three".as_slice())
    );
    assert_eq!(b.skipped.len(), 2);
    assert_eq!(
        b.decrypt(&h1, &nonce("m1"), &ct1, AD, &rnd32("f1"))
            .as_deref(),
        Some(b"one".as_slice())
    );
    assert_eq!(
        b.decrypt(&h2, &nonce("m2"), &ct2, AD, &rnd32("f2"))
            .as_deref(),
        Some(b"two".as_slice())
    );
    assert!(b.skipped.is_empty());

    // Replay of an already-consumed message fails.
    assert_eq!(b.decrypt(&h1, &nonce("m1"), &ct1, AD, &rnd32("f1b")), None);
}

#[test]
fn absurd_gap_is_refused() {
    let (mut a, mut b) = handshake(true);
    let mut last = None;
    for i in 0..300 {
        last = Some(a.encrypt(b"x", AD, &nonce(&format!("g{i}"))).unwrap());
    }
    let (h, ct) = last.unwrap();
    // 299 skipped keys needed > MAX_SKIP=256 — refuse, state untouched.
    let before = serde_json::to_value(&b).unwrap();
    assert_eq!(b.decrypt(&h, &nonce("g299"), &ct, AD, &rnd32("gf")), None);
    assert_eq!(serde_json::to_value(&b).unwrap(), before);
}

#[test]
fn failed_aead_leaves_state_untouched() {
    let (mut a, mut b) = handshake(true);
    let (h, mut ct) = a.encrypt(b"secret", AD, &nonce("t1")).unwrap();
    ct[0] ^= 1;
    let before = serde_json::to_value(&b).unwrap();
    assert_eq!(b.decrypt(&h, &nonce("t1"), &ct, AD, &rnd32("tf")), None);
    assert_eq!(serde_json::to_value(&b).unwrap(), before);

    // Wrong AD (tampered routing fields) also refuses.
    let (h2, ct2) = a.encrypt(b"secret", AD, &nonce("t2")).unwrap();
    assert_eq!(
        b.decrypt(
            &h2,
            &nonce("t2"),
            &ct2,
            "stonechat/v1|SC-EVE|SC-BOB|msg",
            &rnd32("tf2")
        ),
        None
    );
    assert_eq!(
        b.decrypt(&h2, &nonce("t2"), &ct2, AD, &rnd32("tf3"))
            .as_deref(),
        Some(b"secret".as_slice())
    );
}

#[test]
fn state_json_round_trips_in_dart_shape() {
    let (a, _) = handshake(true);
    let json = serde_json::to_value(&a).unwrap();

    // The exact field set of RatchetSession.toJson (session.dart).
    let obj = json.as_object().unwrap();
    for key in [
        "initiated_by_us",
        "confirmed",
        "rk",
        "dhs_pub",
        "dhs_sec",
        "dhr",
        "cks",
        "ckr",
        "ns",
        "nr",
        "pn",
        "pending_x3dh",
        "skipped",
    ] {
        assert!(obj.contains_key(key), "missing {key}");
    }
    // Chain keys are base64 strings or null, exactly like Dart's output.
    assert!(json["rk"].is_string());
    assert!(json["ckr"].is_null());
    assert!(json["pending_x3dh"]["kct"].is_string());
    assert_eq!(json["pending_x3dh"]["kem_one_time"], true);

    let back: SessionState = serde_json::from_value(json.clone()).unwrap();
    assert_eq!(serde_json::to_value(&back).unwrap(), json);
    assert_eq!(back, a);
}

#[test]
fn hybrid_seal_round_trips_and_rejects_wrong_recipient() {
    // Any 32-byte X-Wing seed will do for a seal round trip; this one is a
    // keyed hash of a test seed. It is NOT how `pq_pk` is derived — that
    // hashes the full 64-byte secret key (identity.rs) — and it is not what
    // envelopes are sealed to, which is a device's own random seal seed.
    let ed_seed = rnd32("seal/id");
    let pq_seed = keyed_hash_32(&ed_seed, PQID_SEED_KEY);
    let pq_pk = pqcore::xwing_pk_from_seed(&pq_seed);

    let random: [u8; 64] = rnd("seal/r", 64).try_into().unwrap();
    let sealed = seal_to(&pq_pk, b"inner envelope json", &random, &nonce("seal/n")).unwrap();
    assert_eq!(
        unseal(&pq_seed, &sealed).as_deref(),
        Some(b"inner envelope json".as_slice())
    );

    let other_seed = keyed_hash_32(&rnd32("seal/other"), PQID_SEED_KEY);
    assert_eq!(unseal(&other_seed, &sealed), None);
    assert_eq!(unseal(&pq_seed, &sealed[..100]), None);
}

#[test]
fn x25519_secrets_match_libsodium_keypair_semantics() {
    // Sanity: an identity's X25519 public half derived through the seed
    // path equals scalarmult_base of the converted secret — the invariant
    // X3DH relies on when peers convert our published Ed25519 key.
    let seed = rnd32("kp");
    let id = Identity::from_ed25519_seed(&seed);
    let x_sk = ed25519_seed_to_x25519_sk(&seed);
    let converted = stonechat_core::primitives::ed25519_pk_to_x25519(&id.ed_pk).unwrap();
    assert_eq!(x25519_pk(&x_sk), converted);
}
