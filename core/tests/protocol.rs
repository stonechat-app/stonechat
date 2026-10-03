//! End-to-end protocol behavior: PQXDH handshake both ways, ratchet
//! stepping, out-of-order delivery, tamper resistance, state
//! serialization parity with the Dart JSON shape.

use stonechat_core::envelope::{seal_to, unseal};
use stonechat_core::primitives::{
    PQID_SEED_KEY, ed25519_seed_to_x25519_sk, keyed_hash_32, x25519_pk,
};
use stonechat_core::session::{
    Identity, InitiateRandom, PQ_ATTACH, PQ_INTERVAL, PrekeyBundle, RatchetHeader, SessionState,
};

/// Post-quantum ratchet randomness for the tests that never reach a KEM step.
const PQR: [u8; 64] = [0x51; 64];

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

    let plain = b.decrypt(&header, &nonce("n0"), &ct, AD, &rnd32("b-fresh0"), &PQR);
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
    let plain = a.decrypt(&h, &nonce("n1"), &ct, AD, &rnd32("a-fresh1"), &PQR);
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
                &rnd32(&format!("bf{i}")), &PQR
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
                &rnd32(&format!("af{i}")), &PQR
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
        b.decrypt(&h3, &nonce("m3"), &ct3, AD, &rnd32("f3"), &PQR)
            .as_deref(),
        Some(b"three".as_slice())
    );
    assert_eq!(b.skipped.len(), 2);
    assert_eq!(
        b.decrypt(&h1, &nonce("m1"), &ct1, AD, &rnd32("f1"), &PQR)
            .as_deref(),
        Some(b"one".as_slice())
    );
    assert_eq!(
        b.decrypt(&h2, &nonce("m2"), &ct2, AD, &rnd32("f2"), &PQR)
            .as_deref(),
        Some(b"two".as_slice())
    );
    assert!(b.skipped.is_empty());

    // Replay of an already-consumed message fails.
    assert_eq!(b.decrypt(&h1, &nonce("m1"), &ct1, AD, &rnd32("f1b"), &PQR), None);
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
    assert_eq!(b.decrypt(&h, &nonce("g299"), &ct, AD, &rnd32("gf"), &PQR), None);
    assert_eq!(serde_json::to_value(&b).unwrap(), before);
}

#[test]
fn failed_aead_leaves_state_untouched() {
    let (mut a, mut b) = handshake(true);
    let (h, mut ct) = a.encrypt(b"secret", AD, &nonce("t1")).unwrap();
    ct[0] ^= 1;
    let before = serde_json::to_value(&b).unwrap();
    assert_eq!(b.decrypt(&h, &nonce("t1"), &ct, AD, &rnd32("tf"), &PQR), None);
    assert_eq!(serde_json::to_value(&b).unwrap(), before);

    // Wrong AD (tampered routing fields) also refuses.
    let (h2, ct2) = a.encrypt(b"secret", AD, &nonce("t2")).unwrap();
    assert_eq!(
        b.decrypt(
            &h2,
            &nonce("t2"),
            &ct2,
            "stonechat/v1|SC-EVE|SC-BOB|msg",
            &rnd32("tf2"), &PQR
        ),
        None
    );
    assert_eq!(
        b.decrypt(&h2, &nonce("t2"), &ct2, AD, &rnd32("tf3"), &PQR)
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
fn seal_pads_to_size_buckets() {
    use stonechat_core::envelope::padded_len;
    use stonechat_core::primitives::{HSEAL_AD, HSEAL_KDF_KEY, aead_seal};

    assert_eq!(padded_len(0), 2048);
    assert_eq!(padded_len(2047), 2048);
    assert_eq!(padded_len(2048), 4096); // the marker byte always fits
    assert_eq!(padded_len(32767), 32768);
    assert_eq!(padded_len(32768), 33792); // past doubling: 1 KiB steps
    assert_eq!(padded_len(40000), 40960);

    let pq_seed = keyed_hash_32(&rnd32("pad/id"), PQID_SEED_KEY);
    let pq_pk = pqcore::xwing_pk_from_seed(&pq_seed);
    let random: [u8; 64] = rnd("pad/r", 64).try_into().unwrap();
    let overhead = 1120 + 24 + 16;

    // A receipt-sized and a message-sized inner are the same size sealed,
    // and content that ends in the padding's own bytes survives.
    let mut seen = Vec::new();
    for message in [
        vec![b'r'; 300],
        vec![b'm'; 1900],
        b"ends in the marker \x80\x00\x00".to_vec(),
        Vec::new(),
    ] {
        let sealed = seal_to(&pq_pk, &message, &random, &nonce("pad/n")).unwrap();
        assert_eq!(sealed.len(), overhead + 2048);
        assert_eq!(unseal(&pq_seed, &sealed), Some(message));
        seen.push(sealed.len());
    }
    let big = vec![b'x'; 5000];
    let sealed = seal_to(&pq_pk, &big, &random, &nonce("pad/n2")).unwrap();
    assert_eq!(sealed.len(), overhead + 8192);
    assert_eq!(unseal(&pq_seed, &sealed), Some(big));

    // A validly encrypted seal whose content is not padded, or is padded to
    // the wrong bucket, is refused.
    let (ct, ss) = pqcore::xwing_encaps(&pq_pk, &random).unwrap();
    let key = keyed_hash_32(&ss, HSEAL_KDF_KEY);
    for inner in [
        b"unpadded inner".to_vec(),
        [b"short pad".as_slice(), &[0x80, 0, 0]].concat(),
        vec![0u8; 2048],
    ] {
        let mut forged = ct.to_vec();
        forged.extend_from_slice(&nonce("pad/n3"));
        forged.extend_from_slice(&aead_seal(&key, &nonce("pad/n3"), &inner, HSEAL_AD));
        assert_eq!(unseal(&pq_seed, &forged), None);
    }
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

// -- post-quantum ratchet ---------------------------------------------------------

fn pq_random(label: &str) -> [u8; 64] {
    rnd(&format!("pq/{label}"), 64).try_into().unwrap()
}

fn open(to: &mut SessionState, h: &RatchetHeader, ct: &[u8], label: &str) -> Option<Vec<u8>> {
    to.decrypt(
        h,
        &nonce(label),
        ct,
        AD,
        &rnd32(&format!("fresh/{label}")),
        &pq_random(label),
    )
}

/// One message from `from`, delivered to `to`. Returns its header.
fn pass(from: &mut SessionState, to: &mut SessionState, label: &str) -> RatchetHeader {
    let (h, ct) = from.encrypt(label.as_bytes(), AD, &nonce(label)).unwrap();
    assert_eq!(
        open(to, &h, &ct, label).as_deref(),
        Some(label.as_bytes()),
        "{label}"
    );
    h
}

/// Ping-pong until Alice (the initiator) has a KEM key to advertise. She
/// has just received from Bob, so her next message opens a sending chain.
fn until_alice_advertises(a: &mut SessionState, b: &mut SessionState) {
    let mut i = 0;
    loop {
        pass(b, a, &format!("warm-b{i}"));
        if a.pq.local.is_some() {
            return;
        }
        pass(a, b, &format!("warm-a{i}"));
        i += 1;
        assert!(i <= PQ_INTERVAL, "no KEM key after {i} round trips");
    }
}

#[test]
fn pq_ratchet_is_quiet_until_the_interval() {
    let (mut a, mut b) = handshake(true);
    for i in 0..5 {
        let hb = pass(&mut b, &mut a, &format!("q-b{i}"));
        let ha = pass(&mut a, &mut b, &format!("q-a{i}"));
        assert!(hb.pq.is_none() && ha.pq.is_none());
    }
    // The header of an ordinary message is the three fields it always was.
    let (h, _) = a.encrypt(b"x", AD, &nonce("q-x")).unwrap();
    assert_eq!(
        serde_json::to_value(&h).unwrap().as_object().unwrap().len(),
        3
    );
}

#[test]
fn pq_ratchet_completes_an_exchange_and_keeps_going() {
    let (mut a, mut b) = handshake(true);
    until_alice_advertises(&mut a, &mut b);
    assert!(!b.initiated_by_us && b.pq.local.is_none(), "only the initiator makes keys");

    // Alice's chain offers the key; Bob encapsulates to it.
    let h = pass(&mut a, &mut b, "x-a0");
    let ek = h.pq.unwrap().ek.expect("first message of the chain carries the key");
    assert_eq!(ek.id, 1);
    assert_eq!(b.pq.outbound.as_ref().map(|o| o.id), Some(1));

    // Bob's next message carries the ciphertext; Alice decapsulates and
    // forgets the private half.
    let h = pass(&mut b, &mut a, "x-b0");
    assert_eq!(h.pq.unwrap().ct.map(|c| c.id), Some(1));
    assert!(a.pq.local.is_none());
    assert_eq!(a.pq.inbound.as_ref().map(|i| i.id), Some(1));
    assert_eq!(a.pq.inbound.as_ref().unwrap().ss, b.pq.outbound.as_ref().unwrap().ss);

    // The secret waits for Alice's next sending chain.
    let h = pass(&mut a, &mut b, "x-a1");
    assert!(h.pq.is_none());
    let h = pass(&mut b, &mut a, "x-b1");
    assert_eq!(h.pq.unwrap().ct.map(|c| c.id), Some(1), "unacknowledged: offered again");
    assert_eq!((a.pq.mixed, a.pq.mix), (1, Some(1)));
    assert!(a.pq.inbound.is_none());

    // Every message of the mixed chain says so; Bob follows on the first.
    let h = pass(&mut a, &mut b, "x-a2");
    assert_eq!(h.pq.unwrap().mix, Some(1));
    assert_eq!(b.pq.mixed, 1);
    assert!(b.pq.outbound.is_none());
    let h = pass(&mut a, &mut b, "x-a3");
    assert_eq!(h.pq.unwrap().mix, Some(1));
    assert!(a.pq.count < 5 && b.pq.count < 5, "the interval starts over");

    // And the conversation carries on to a second exchange.
    let mut i = 0;
    while a.pq.mixed < 2 {
        pass(&mut b, &mut a, &format!("y-b{i}"));
        pass(&mut a, &mut b, &format!("y-a{i}"));
        i += 1;
        assert!(i <= PQ_INTERVAL + 5, "no second exchange");
    }
    assert_eq!(b.pq.mixed, 2);
}

#[test]
fn pq_mixed_chain_needs_the_kem_secret() {
    let (mut a, mut b) = handshake(true);
    until_alice_advertises(&mut a, &mut b);
    pass(&mut a, &mut b, "s-a0");
    pass(&mut b, &mut a, "s-b0");
    pass(&mut a, &mut b, "s-a1");
    pass(&mut b, &mut a, "s-b1");
    let (h, ct) = a.encrypt(b"healed", AD, &nonce("s-a2")).unwrap();
    assert_eq!(h.pq.as_ref().unwrap().mix, Some(1));

    // Someone holding every classical secret Bob has, but not the KEM
    // shared secret, cannot follow the ratchet onto this chain.
    let mut eve = b.clone();
    eve.pq.outbound.as_mut().unwrap().ss[0] ^= 1;
    assert_eq!(open(&mut eve, &h, &ct, "s-a2"), None);
    let mut eve = b.clone();
    eve.pq.outbound = None;
    assert_eq!(open(&mut eve, &h, &ct, "s-a2"), None);

    // The pq block is authenticated: stripped or altered, nothing opens.
    let mut stripped = h.clone();
    stripped.pq = None;
    assert_eq!(open(&mut b.clone(), &stripped, &ct, "s-a2"), None);
    let mut altered = h.clone();
    altered.pq.as_mut().unwrap().mix = Some(2);
    assert_eq!(open(&mut b.clone(), &altered, &ct, "s-a2"), None);

    let before = b.clone();
    assert_eq!(open(&mut b, &h, &ct, "s-a2").as_deref(), Some(b"healed".as_slice()));
    assert_ne!(before.rk, b.rk);
}

#[test]
fn pq_key_is_offered_on_a_few_messages_and_again_next_chain() {
    let (mut a, mut b) = handshake(true);
    until_alice_advertises(&mut a, &mut b);

    // A monologue: only the first PQ_ATTACH messages pay for the key.
    let mut sent = Vec::new();
    for i in 0..PQ_ATTACH + 2 {
        let label = format!("l-a{i}");
        let (h, ct) = a.encrypt(label.as_bytes(), AD, &nonce(&label)).unwrap();
        assert_eq!(
            h.pq.as_ref().and_then(|pq| pq.ek.as_ref()).is_some(),
            i < PQ_ATTACH
        );
        sent.push((h, ct, label));
    }
    // Every message that carried it is lost; Bob only gets the last.
    let (h, ct, label) = sent.last().unwrap();
    assert!(open(&mut b, h, ct, label).is_some());
    assert!(b.pq.outbound.is_none());

    // Alice's next sending chain offers it again.
    pass(&mut b, &mut a, "l-b0");
    let h = pass(&mut a, &mut b, "l-a-next");
    assert_eq!(h.pq.unwrap().ek.map(|k| k.id), Some(1));
    assert_eq!(b.pq.outbound.as_ref().map(|o| o.id), Some(1));

    // A straggler from the old chain, opened from the skipped-key stash,
    // changes nothing.
    let (h, ct, label) = &sent[0];
    assert!(open(&mut b, h, ct, label).is_some());
    assert_eq!(b.pq.outbound.as_ref().map(|o| o.id), Some(1));

    pass(&mut b, &mut a, "l-b1");
    pass(&mut a, &mut b, "l-a1");
    pass(&mut b, &mut a, "l-b2");
    pass(&mut a, &mut b, "l-a2");
    assert_eq!((a.pq.mixed, b.pq.mixed), (1, 1));
}

#[test]
fn pq_state_is_absent_from_an_untouched_session_and_round_trips() {
    let alice = Peer::new("alice");
    let bob = Peer::new("bob");
    let fresh = SessionState::initiate(
        &alice.identity,
        &bob.identity.ed_pk,
        &bob.bundle(true),
        &initiate_random("pq-rt"),
    )
    .unwrap();
    assert!(serde_json::to_value(&fresh).unwrap().get("pq").is_none());

    let (mut a, mut b) = handshake(true);
    until_alice_advertises(&mut a, &mut b);
    pass(&mut a, &mut b, "r-a0");
    for state in [&a, &b] {
        let json = serde_json::to_value(state).unwrap();
        assert!(json.get("pq").is_some());
        let back: SessionState = serde_json::from_value(json).unwrap();
        assert_eq!(&back, state);
    }
}
