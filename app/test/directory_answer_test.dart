// Regression: the directory's key was checked against the ID in the
// directory's own answer, so a hub returning somebody else's complete record
// for a lookup passed every check — that record is internally consistent.
// The check has to be against the ID that was asked for.
//
// Auto-skips if the core library can't load in the host test VM (same
// pattern as stonechat_id_test.dart).
import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:stonechat/core/crypto.dart';

void main() {
  CryptoService? bob;
  CryptoService? mallory;

  setUpAll(() {
    try {
      bob = CryptoService.generate();
      mallory = CryptoService.generate();
    } catch (_) {
      bob = null;
    }
  });

  test('the honest answer is accepted', () {
    final b = bob;
    if (b == null) return markTestSkipped('core unavailable in test VM');
    final id = b.deriveStonechatId(b.publicKey);
    expect(
      b.directoryAnswers(
        askedFor: id,
        returnedId: id,
        pubkeyB64: base64Encode(b.publicKey),
      ),
      isTrue,
    );
  });

  test("somebody else's self-consistent record is refused", () {
    final b = bob, m = mallory;
    if (b == null || m == null) {
      return markTestSkipped('core unavailable in test VM');
    }
    final bobId = b.deriveStonechatId(b.publicKey);
    final malloryId = m.deriveStonechatId(m.publicKey);
    // The point of the test: by its own lights this record is good.
    expect(b.pubkeyMatchesId(base64Encode(m.publicKey), malloryId), isTrue);
    expect(
      b.directoryAnswers(
        askedFor: bobId,
        returnedId: malloryId,
        pubkeyB64: base64Encode(m.publicKey),
      ),
      isFalse,
    );
  });

  test('the right ID over the wrong key is refused', () {
    final b = bob, m = mallory;
    if (b == null || m == null) {
      return markTestSkipped('core unavailable in test VM');
    }
    final bobId = b.deriveStonechatId(b.publicKey);
    expect(
      b.directoryAnswers(
        askedFor: bobId,
        returnedId: bobId,
        pubkeyB64: base64Encode(m.publicKey),
      ),
      isFalse,
    );
  });

  test('a certificate signed by a key its ID does not commit to is refused', () {
    final b = bob, m = mallory;
    if (b == null || m == null) {
      return markTestSkipped('core unavailable in test VM');
    }
    final now = DateTime.now().toUtc().millisecondsSinceEpoch ~/ 1000;
    final forged = m.core.devcertSign(
      {
        'stonechat_id': b.deriveStonechatId(b.publicKey),
        'device_id': 1,
        'sig_pub': base64Encode(Uint8List(32)),
        'seal_pub': base64Encode(Uint8List(1216)),
        'not_after': now + 3600,
      },
      m.identitySeed,
    );
    expect(m.core.devcertVerify(forged, m.publicKey, now), 'wrong_identity');
    expect(m.core.devcertVerify(forged, b.publicKey, now), 'bad_signature');
  });
}
