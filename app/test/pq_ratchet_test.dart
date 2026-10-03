// The post-quantum ratchet through the app's own binding (session.dart →
// core_ffi.dart → stonechat-core). The protocol is tested in the core
// (core/tests/protocol.rs); what this pins is that the Dart side hands the
// core what it needs — the extra randomness on decrypt, the header's `pq`
// block passed through untouched — over a conversation long enough to reach
// a KEM step.
//
// Run:
//   ./scripts/build_core.sh host
//   STONECHAT_CORE_LIB=$PWD/../core/target/release/libstonechat_core.dylib \
//   flutter test test/pq_ratchet_test.dart
import 'dart:convert';

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

  test('a long conversation mixes a KEM secret into both ends', () {
    final a = alice;
    final b = bob;
    if (a == null || b == null) {
      return markTestSkipped('stonechat-core unavailable in test VM');
    }
    const ad = 'stonechat/v1|SC-A|1|SC-B|1|msg';

    final bobDevice = DeviceKeys.generate();
    final spk = b.newX25519();
    final kspk = b.newMlkemPrekey();
    final bundle = PrekeyBundle.fromJson({
      'spk': {
        'id': 7,
        'pub': base64Encode(spk.publicKey),
        'sig': base64Encode(b.signPrekey(bobDevice.sigSecret, spk.publicKey)),
      },
      'opk': null,
      'kspk': {
        'id': 5,
        'pub': base64Encode(kspk.pub),
        'sig': base64Encode(b.signKemPrekey(bobDevice.sigSecret, kspk.pub)),
      },
      'kopk': null,
    });
    final aSession = RatchetSession.initiate(
      a,
      b.stonechatId,
      b.publicKey,
      bundle,
      ownEdSeed: a.identitySeed,
    );
    final bSession = RatchetSession.respond(
      b,
      a.stonechatId,
      a.publicKey,
      aSession.pendingX3dh!,
      ownEdSeed: b.identitySeed,
      spkPub: spk.publicKey,
      spkSec: spk.secretKey,
      kemSeed: kspk.seed,
    );

    final seen = <String>{};
    void pass(RatchetSession from, RatchetSession to, String text) {
      final sealed = from.encrypt(text, ad);
      final pq = sealed.ratchet['pq'];
      if (pq is Map) seen.addAll(pq.keys.cast<String>());
      // The header as it crosses the wire: JSON, as the envelope carries it.
      final header =
          (jsonDecode(jsonEncode(sealed.ratchet)) as Map).cast<String, dynamic>();
      expect(to.decrypt(header, sealed.nonce, sealed.ciphertext, ad), text);
    }

    int mixed(RatchetSession s) =>
        ((s.toJson()['pq'] as Map?)?['mixed'] as int?) ?? 0;

    pass(aSession, bSession, 'hello');
    for (var i = 0; i < 80 && mixed(bSession) == 0; i++) {
      pass(bSession, aSession, 'b$i');
      pass(aSession, bSession, 'a$i');
    }
    expect(mixed(aSession), 1);
    expect(mixed(bSession), 1);
    expect(seen, {'ek', 'ct', 'mix'});

    // The state survives the JSON round trip the database gives it.
    final restored = RatchetSession.fromJson(
      b,
      a.stonechatId,
      (jsonDecode(jsonEncode(bSession.toJson())) as Map).cast<String, dynamic>(),
    );
    final sealed = aSession.encrypt('after restore', ad);
    expect(
      restored.decrypt(
        sealed.ratchet.cast<String, dynamic>(),
        sealed.nonce,
        sealed.ciphertext,
        ad,
      ),
      'after restore',
    );
  });
}
