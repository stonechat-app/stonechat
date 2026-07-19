// The ZID1 identity-export container. Restore must parse containers written
// by any past build, so the layout is pinned here byte-by-byte — a failing
// round-trip means old exports can no longer be opened, not just that a
// constant moved. Crypto itself (pwhash/secretbox) is FFI and exercised in
// the manual on-device checklist instead.
import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:zeon_chat/core/identity_export.dart';

void main() {
  final salt = Uint8List.fromList(List.generate(16, (i) => i + 1));
  final nonce = Uint8List.fromList(List.generate(24, (i) => 100 + i));
  final cipher = Uint8List.fromList(List.generate(40, (i) => 200 - i));

  group('encodeContainer', () {
    test('lays out all fields at their pinned offsets', () {
      final s = IdentityCodec.encodeContainer(salt, 3, 268435456, nonce, cipher);
      expect(s.startsWith('ZID1.'), isTrue);
      final bytes = base64Url.decode(base64.normalize(s.substring(5)));
      expect(bytes[0], 1); // format version
      expect(bytes[1], 1); // kdf id
      expect(bytes.sublist(2, 18), salt);
      final bd = ByteData.sublistView(bytes);
      expect(bd.getUint32(18, Endian.little), 3);
      expect(bd.getUint64(22, Endian.little), 268435456);
      expect(bytes.sublist(30, 54), nonce);
      expect(bytes.sublist(54), cipher);
    });
  });

  group('decodeContainer', () {
    test('round-trips what encodeContainer wrote', () {
      final decoded = IdentityCodec.decodeContainer(
          IdentityCodec.encodeContainer(salt, 2, 1 << 28, nonce, cipher));
      expect(decoded.salt, salt);
      expect(decoded.opsLimit, 2);
      expect(decoded.memLimit, 1 << 28);
      expect(decoded.nonce, nonce);
      expect(decoded.cipher, cipher);
    });

    test('tolerates surrounding and embedded whitespace (hand-typed code)',
        () {
      final s = IdentityCodec.encodeContainer(salt, 2, 1 << 28, nonce, cipher);
      final mangled = '  ${s.substring(0, 20)}\n${s.substring(20)} ';
      final decoded = IdentityCodec.decodeContainer(mangled);
      expect(decoded.cipher, cipher);
    });

    test('rejects a missing prefix as not-an-export', () {
      final s = IdentityCodec.encodeContainer(salt, 2, 1 << 28, nonce, cipher);
      expect(
        () => IdentityCodec.decodeContainer(s.substring(5)),
        throwsA(predicate((e) =>
            e is IdentityExportException &&
            e.message.contains('Not a Zeon identity export'))),
      );
    });

    test('rejects a future format version as newer-version', () {
      final s = IdentityCodec.encodeContainer(salt, 2, 1 << 28, nonce, cipher);
      final bytes = base64Url.decode(base64.normalize(s.substring(5)));
      bytes[0] = 2;
      expect(
        () => IdentityCodec.decodeContainer('ZID1.${base64UrlEncode(bytes)}'),
        throwsA(predicate((e) =>
            e is IdentityExportException &&
            e.message.contains('newer version'))),
      );
    });

    test('rejects header-only input', () {
      final s = IdentityCodec.encodeContainer(
          salt, 2, 1 << 28, nonce, Uint8List(0));
      expect(
        () => IdentityCodec.decodeContainer(s),
        throwsA(isA<IdentityExportException>()),
      );
    });

    test('rejects garbage base64', () {
      expect(
        () => IdentityCodec.decodeContainer('ZID1.@@@not-base64@@@'),
        throwsA(isA<IdentityExportException>()),
      );
    });
  });
}
