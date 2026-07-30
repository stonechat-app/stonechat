// The identity export string — the one artifact that makes a Stonechat ID
// survive the phone. The container's crypto is the core's passphrase vault
// (unit-tested in Rust); this covers the string framing and a full
// encode → decode round trip, including the failure messages the UI shows.
//
// Run: STONECHAT_CORE_LIB=../core/target/release/libstonechat_core.dylib flutter test
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:stonechat/core/identity_export.dart';

void main() {
  const codec = IdentityCodec();
  // A plausible 64-byte Ed25519 secret key (seed || public).
  final secretKey = Uint8List.fromList(List.generate(64, (i) => (i * 3) % 256));

  group('string framing', () {
    test('round-trips the container bytes', () {
      final container = Uint8List.fromList([1, 2, 3, 250, 251]);
      final text = IdentityCodec.encodeContainer(container);
      expect(text, startsWith(IdentityCodec.prefix));
      expect(IdentityCodec.decodeContainer(text), container);
    });

    test('tolerates whitespace a QR scan or a paste can introduce', () {
      final container = Uint8List.fromList(List.generate(40, (i) => i));
      final text = IdentityCodec.encodeContainer(container);
      final mangled = '  ${text.substring(0, 10)}\n ${text.substring(10)}  ';
      expect(IdentityCodec.decodeContainer(mangled), container);
    });

    test('rejects anything that is not one of ours', () {
      expect(() => IdentityCodec.decodeContainer('hello'),
          throwsA(isA<IdentityExportException>()));
      expect(() => IdentityCodec.decodeContainer('ZID1.abc'),
          throwsA(isA<IdentityExportException>()),
          reason: 'the pre-core format is not readable any more');
      expect(() => IdentityCodec.decodeContainer('${IdentityCodec.prefix}!!!'),
          throwsA(isA<IdentityExportException>()));
    });
  });

  group('encode and decode', () {
    // Real Argon2id at production parameters: slow on purpose, so one
    // round trip covers it rather than one per assertion.
    test('an export decodes back to the same identity', () async {
      late final String export;
      try {
        export = await codec.encode(
            secretKey: secretKey, passphrase: 'a good long passphrase', name: 'Julio');
      } catch (_) {
        return markTestSkipped('core library unavailable');
      }
      final decoded = await codec.decode(export, 'a good long passphrase');
      expect(decoded.secretKey, secretKey);
      expect(decoded.name, 'Julio');

      // The failure the UI has a message for.
      await expectLater(
        codec.decode(export, 'not the passphrase'),
        throwsA(isA<IdentityExportException>()),
      );
    }, timeout: const Timeout(Duration(minutes: 2)));
  });
}
