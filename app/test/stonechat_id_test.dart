// Regression coverage for the SC- ID codec (see crypto.dart "Stonechat ID").
//
// Why this exists: the Zeon→Stonechat rename changed the ID prefix everywhere
// except the hyphen-stripped `startsWith` gate inside normalizeStonechatId,
// so every *valid* ID was rejected — and the suite stayed green because only
// error paths of the codec had coverage. Auto-skips if libsodium can't load
// in the host test VM (same pattern as pqcore_test.dart).
import 'package:flutter_test/flutter_test.dart';
import 'package:stonechat/core/crypto.dart';

void main() {
  CryptoService? crypto;

  setUpAll(() async {
    try {
      final sodium = await CryptoService.loadSodium();
      crypto = CryptoService.generate(sodium);
    } catch (_) {
      crypto = null;
    }
  });

  test('a freshly derived ID normalizes to itself', () {
    final c = crypto;
    if (c == null) return markTestSkipped('libsodium unavailable in test VM');
    final id = c.deriveStonechatId(c.publicKey);
    expect(id, startsWith('SC-'));
    expect(c.normalizeStonechatId(id), id);
    // lowercase / spaces / missing hyphens all canonicalize back
    expect(c.normalizeStonechatId(id.toLowerCase().replaceAll('-', ' ')), id);
  });

  test('non-SC prefix is rejected', () {
    final c = crypto;
    if (c == null) return markTestSkipped('libsodium unavailable in test VM');
    final id = c.deriveStonechatId(c.publicKey);
    expect(() => c.normalizeStonechatId('ZC-${id.substring(3)}'),
        throwsFormatException);
  });
}
