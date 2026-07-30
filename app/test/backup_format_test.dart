// The .stonechatbackup container. Since the stonechat-core cutover the
// KDF and cipher live in Rust (core/src/vault.rs, unit-tested there); what
// stays here is the file framing plus — new, and the part the old
// format-only tests could never reach — a real encrypt/decrypt round trip
// through the FFI.
//
// Run: STONECHAT_CORE_LIB=../core/target/release/libstonechat_core.dylib flutter test
import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:stonechat/core/backup.dart';
import 'package:stonechat/core/core_ffi.dart';

void main() {
  // Cheap KDF parameters: the production numbers are the core's default
  // and are exercised on device, not in a unit test.
  const mCost = 8 * 1024;
  const tCost = 1;
  final salt = Uint8List.fromList(List.generate(16, (i) => i + 1));
  final nonce = Uint8List.fromList(List.generate(24, (i) => i));

  StonechatCore? core;
  setUpAll(() {
    try {
      core = StonechatCore();
    } catch (_) {
      core = null;
    }
  });

  group('file framing', () {
    test('the magic is what restore recognises', () {
      final header = BackupService.encodeHeader();
      expect(header.length, BackupService.headerLength);
      expect(ascii.decode(header), 'SC-BAK-2');
    });

    test('a foreign file is rejected before the KDF runs', () {
      final notOurs = Uint8List.fromList(ascii.encode('PKjunkjunk'));
      expect(
          () => BackupService.checkMagic(notOurs), throwsA(isA<BackupException>()));
      // Too short to hold anything, whatever it claims to be.
      expect(() => BackupService.checkMagic(Uint8List.fromList([1, 2, 3])),
          throwsA(isA<BackupException>()));
    });
  });

  group('vault round trip', () {
    test('a backup body survives seal then open', () {
      final c = core;
      if (c == null) return markTestSkipped('core library unavailable');
      final payload =
          Uint8List.fromList(utf8.encode('{"format":"stonechat-backup"}'));
      final sealed = c.vaultSeal(
        passphrase: 'correct horse battery staple',
        plaintext: payload,
        salt: salt,
        nonce: nonce,
        mCostKib: mCost,
        tCost: tCost,
      );
      final opened = c.vaultOpen(
          passphrase: 'correct horse battery staple', container: sealed);
      expect(opened.outcome, VaultOutcome.ok);
      expect(opened.plaintext, payload);
    });

    test('a wrong passphrase is one indistinguishable outcome', () {
      final c = core;
      if (c == null) return markTestSkipped('core library unavailable');
      final sealed = c.vaultSeal(
        passphrase: 'right',
        plaintext: Uint8List.fromList([1, 2, 3]),
        salt: salt,
        nonce: nonce,
        mCostKib: mCost,
        tCost: tCost,
      );
      expect(c.vaultOpen(passphrase: 'wrong', container: sealed).outcome,
          VaultOutcome.wrongPassphrase);
      // The KDF parameters are the AEAD's associated data, so downgrading
      // them in the header is a loud failure, not a silent weakening.
      final tampered = Uint8List.fromList(sealed);
      tampered[6] = 9;
      expect(c.vaultOpen(passphrase: 'right', container: tampered).outcome,
          isNot(VaultOutcome.ok));
    });

    test('a newer container version is reported as such', () {
      final c = core;
      if (c == null) return markTestSkipped('core library unavailable');
      final sealed = c.vaultSeal(
        passphrase: 'pw',
        plaintext: Uint8List.fromList([7]),
        salt: salt,
        nonce: nonce,
        mCostKib: mCost,
        tCost: tCost,
      );
      final future = Uint8List.fromList(sealed);
      future[0] = 99;
      expect(c.vaultOpen(passphrase: 'pw', container: future).outcome,
          VaultOutcome.newerVersion);
    });
  });
}
