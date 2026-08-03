// Golden-transcript conformance test (companion: core/tests/golden.rs).
//
// Drives a PQXDH handshake and a short ratchet conversation end-to-end.
// Originally this exercised the pure-Dart ratchet and RECORDED the frozen
// fixture core/tests/fixtures/dart_transcript.json; since the
// stonechat-core cutover, RatchetSession runs on the Rust engine, so this
// test now proves the FFI path reproduces the retired Dart implementation's
// behavior. Do not casually re-record the fixture — it is the last
// artifact of the Dart ratchet and the compatibility baseline for every
// session row written before the cutover (STONECHAT_GOLDEN_OUT exists for
// deliberate, reviewed regeneration only).
//
// Run:
//   ./scripts/build_core.sh host   # once, for the host dylib
//   STONECHAT_CORE_LIB=$PWD/../core/target/release/libstonechat_core.dylib \
//   flutter test test/golden_transcript_test.dart
//
// Auto-skips when libsodium/the core aren't available in the host test VM.
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:stonechat/core/crypto.dart';
import 'package:stonechat/core/device_keys.dart';
import 'package:stonechat/core/session.dart';

void main() {
  CryptoService? alice;
  CryptoService? bob;

  setUpAll(() {
    try {
      alice = CryptoService.generate();
      bob = CryptoService.generate();
    } catch (_) {
      alice = null;
    }
  });

  test('PQXDH handshake + ratchet transcript (records golden fixture)', () {
    final a = alice;
    final b = bob;
    if (a == null || b == null) {
      return markTestSkipped('libsodium/pqcore unavailable in test VM');
    }

    final aliceId = a.stonechatId;
    final bobId = b.stonechatId;
    final adAtoB = 'stonechat/v1|$aliceId|$bobId|msg';
    final adBtoA = 'stonechat/v1|$bobId|$aliceId|msg';

    // -- Bob's prekeys, private halves kept for the fixture ------------------
    // Signed by Bob's DEVICE key, not his identity: prekey signatures moved
    // there when device certificates arrived. Incidental to this fixture,
    // which pins the ratchet transcript rather than the certificate layer.
    final bobDevice = DeviceKeys.generate();
    final spk = b.newX25519();
    final spkSec = spk.secretKey;
    final spkSig = b.signPrekey(bobDevice.sigSecret, spk.publicKey);
    final opk = b.newX25519();
    final opkSec = opk.secretKey;
    final kspk = b.newMlkemPrekey();
    final kspkSig = b.signKemPrekey(bobDevice.sigSecret, kspk.pub);
    final kopk = b.newMlkemPrekey();

    final bundle = PrekeyBundle.fromJson({
      'spk': {
        'id': 7,
        'pub': base64Encode(spk.publicKey),
        'sig': base64Encode(spkSig),
      },
      'opk': {'id': 41, 'pub': base64Encode(opk.publicKey)},
      'kspk': {
        'id': 5,
        'pub': base64Encode(kspk.pub),
        'sig': base64Encode(kspkSig),
      },
      'kopk': {'id': 51, 'pub': base64Encode(kopk.pub)},
    });

    // -- Alice initiates and sends three messages ----------------------------
    // The corpus predates device certificates and is a pure crypto transcript
    // shared with Rust — the core does not care whose Ed25519 key it is given,
    // so these stay identity keys. What the app passes is device keys.
    final aSession = RatchetSession.initiate(
      a,
      bobId,
      b.publicKey,
      bundle,
      ownEdSeed: a.identitySeed,
    );
    final block = aSession.pendingX3dh!;
    expect(block.kemOneTime, isTrue);

    final plaintexts = ['hello from dart', 'second message', 'third message'];
    final aToB = <Map<String, Object?>>[];
    for (final text in plaintexts) {
      final sealed = aSession.encrypt(text, adAtoB);
      aToB.add({
        'header': sealed.ratchet,
        'nonce': base64Encode(sealed.nonce),
        'ciphertext': base64Encode(sealed.ciphertext),
        'plaintext': text,
      });
    }
    // Snapshot BEFORE Alice decrypts anything: Rust loads this state and
    // must decrypt Bob's replies from it.
    final aliceStateAfterSend = aSession.toJson();

    // -- Bob responds; message 1 (index 1) arrives late ----------------------
    final bSession = RatchetSession.respond(
      b,
      aliceId,
      a.publicKey,
      block,
      ownEdSeed: b.identitySeed,
      spkPub: spk.publicKey,
      spkSec: spkSec,
      opkSec: opkSec,
      kemSeed: kopk.seed, // kem_one_time: the block encapsulated to the KOPK
    );

    String? deliver(RatchetSession s, Map<String, Object?> env, String ad) =>
        s.decrypt(
          (env['header'] as Map).cast<String, dynamic>(),
          base64Decode(env['nonce'] as String),
          base64Decode(env['ciphertext'] as String),
          ad,
        );

    expect(deliver(bSession, aToB[0], adAtoB), plaintexts[0]);
    expect(deliver(bSession, aToB[2], adAtoB), plaintexts[2]);
    expect(
      (bSession.toJson()['skipped'] as List).length,
      1,
      reason: 'message 1 skipped',
    );

    // -- Bob replies twice ----------------------------------------------------
    final replies = ['reply one', 'reply two'];
    final bToA = <Map<String, Object?>>[];
    for (final text in replies) {
      final sealed = bSession.encrypt(text, adBtoA);
      bToA.add({
        'header': sealed.ratchet,
        'nonce': base64Encode(sealed.nonce),
        'ciphertext': base64Encode(sealed.ciphertext),
        'plaintext': text,
      });
    }
    // Bob's state with the stashed skipped key still in it.
    final bobStateFinal = bSession.toJson();

    // -- Dart-side closure: the transcript must work here too ----------------
    expect(deliver(aSession, bToA[0], adBtoA), replies[0]);
    expect(deliver(aSession, bToA[1], adBtoA), replies[1]);
    expect(aSession.confirmed, isTrue);
    // The late message decrypts from Bob's stash.
    expect(deliver(bSession, aToB[1], adAtoB), plaintexts[1]);
    expect(bSession.toJson()['skipped'], isEmpty);

    // -- Fixture --------------------------------------------------------------
    final out = Platform.environment['STONECHAT_GOLDEN_OUT'];
    if (out == null) return;
    final fixture = {
      'description':
          'Recorded from the Dart implementation (golden_transcript_test.dart). '
          'Regenerate with STONECHAT_GOLDEN_OUT; do not edit by hand.',
      'alice': {'stonechat_id': aliceId, 'ed_pk': a.publicKeyB64},
      'bob': {
        'stonechat_id': bobId,
        'ed_pk': b.publicKeyB64,
        'ed_seed': base64Encode(b.exportSecretKey().sublist(0, 32)),
      },
      'bob_prekeys': {
        'spk_id': 7,
        'spk_pub': base64Encode(spk.publicKey),
        'spk_sec': base64Encode(spkSec),
        'spk_sig': base64Encode(spkSig),
        'opk_id': 41,
        'opk_pub': base64Encode(opk.publicKey),
        'opk_sec': base64Encode(opkSec),
        'kspk_id': 5,
        'kspk_pub': base64Encode(kspk.pub),
        'kspk_seed': base64Encode(kspk.seed),
        'kspk_sig': base64Encode(kspkSig),
        'kopk_id': 51,
        'kopk_pub': base64Encode(kopk.pub),
        'kopk_seed': base64Encode(kopk.seed),
      },
      'x3dh': block.toJson(),
      'ad_a_to_b': adAtoB,
      'ad_b_to_a': adBtoA,
      'a_to_b': aToB,
      'delivery_order': [0, 2],
      'late_delivery': [1],
      'alice_state_after_send': aliceStateAfterSend,
      'b_to_a': bToA,
      'bob_state_final': bobStateFinal,
    };
    File(out)
      ..parent.createSync(recursive: true)
      ..writeAsStringSync(const JsonEncoder.withIndent('  ').convert(fixture));
    // ignore: avoid_print
    print('golden fixture written: $out');
  });
}
