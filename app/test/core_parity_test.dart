// Cross-process parity: everything the iOS notification extension
// recomputes for itself must match what the app computes, or the
// extension silently fails and every push falls back to the generic
// alert. A derivation two processes compute separately is a bug waiting:
// an earlier identity-level KEM key once shipped with the extension
// hashing the 32-byte Ed25519 seed while the app hashed the full 64-byte
// secret key, and no test could see it because each side was internally
// consistent.
//
// Run: STONECHAT_CORE_LIB=../core/target/release/libstonechat_core.dylib flutter test
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:stonechat/core/core_ffi.dart';
import 'package:stonechat/core/crypto.dart';

void main() {
  CryptoService? crypto;

  setUpAll(() {
    try {
      crypto = CryptoService.generate();
    } catch (_) {
      crypto = null;
    }
  });

  test('the core derives the same Stonechat ID as the app', () {
    final c = crypto;
    if (c == null) return markTestSkipped('libsodium/core unavailable');
    expect(
      StonechatCore().stonechatId(c.publicKey),
      equals(c.stonechatId),
      reason: 'the extension would address nothing with a different ID',
    );
  });

  test('the TLS fingerprint matches the app pinning code', () {
    final c = crypto;
    if (c == null) return markTestSkipped('libsodium/core unavailable');
    // The extension checks the relay certificate with the core's
    // BLAKE2b-256; the app uses libsodium's generichash. Same bytes or
    // the extension refuses every mailbox connection.
    final der = List<int>.generate(140, (i) => (i * 7) % 256);
    expect(
      c.certFingerprint(Uint8List.fromList(der)),
      equals(StonechatCore().tlsFingerprintB64(Uint8List.fromList(der))),
    );
  });
}
