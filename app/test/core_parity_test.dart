// Cross-process parity: everything the iOS notification extension
// recomputes for itself must match what the app computes, or the
// extension silently fails and every push falls back to the generic
// alert. That is exactly how the X-Wing identity mismatch shipped —
// the extension hashed the 32-byte Ed25519 seed while crypto.dart hashes
// the full 64-byte libsodium secret key, so no sealed envelope ever
// opened, and no test could see it because each side was internally
// consistent.
//
// Run: STONECHAT_CORE_LIB=../core/target/release/libstonechat_core.dylib flutter test
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:stonechat/core/core_ffi.dart';
import 'package:stonechat/core/crypto.dart';
import 'package:stonechat/core/pqcore.dart';

void main() {
  CryptoService? crypto;

  setUpAll(() async {
    try {
      crypto = CryptoService.generate(await CryptoService.loadSodium());
    } catch (_) {
      crypto = null;
    }
  });

  test('the core derives the same X-Wing identity as the app', () {
    final c = crypto;
    if (c == null) return markTestSkipped('libsodium/core unavailable');
    // What the extension does: full secret key in, seed out, then the
    // published pq_pk from that seed.
    final coreSeed = StonechatCore().pqSeedFromEdSecret(c.exportSecretKey());
    final corePqPk = PqCore().xwingPkFromSeed(coreSeed);
    expect(
      corePqPk,
      equals(c.pqPublicKey),
      reason: 'the extension would unseal nothing with a different identity',
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
