// This device's own keys and certificate lifecycle
// (MULTIDEVICE_IMPLEMENTATION.md "How device certificates work").
import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:stonechat/core/device_keys.dart';

Map<String, dynamic> certExpiring(DateTime when) => {
  'stonechat_id': 'SC-ALICE',
  'device_id': 3,
  'sig_pub': base64Encode(Uint8List(32)),
  'seal_pub': base64Encode(Uint8List(1216)),
  'not_after': when.toUtc().millisecondsSinceEpoch ~/ 1000,
  'sig': 'c2ln',
};

void main() {
  final now = DateTime.utc(2026, 8, 3);

  group('certificate lifetime', () {
    test('reads the expiry it carries', () {
      final expiry = DateTime.utc(2026, 12, 1);
      expect(certExpiry(certExpiring(expiry))!.toUtc(), expiry);
    });

    test('an unreadable expiry counts as needing a refresh', () {
      // A certificate we cannot parse is not one we can encrypt against, so
      // the safe reading is "go and get a fresh device list".
      expect(certNeedsRefresh({'not_after': 'soon'}), isTrue);
      expect(certNeedsRefresh(const {}), isTrue);
    });

    test('refreshes on approach, not on expiry', () {
      // The whole point of the window: waiting until it has lapsed means
      // delivery has already stopped by the time anyone looks.
      expect(
        certNeedsRefresh(certExpiring(now.add(const Duration(days: 30))), now: now),
        isFalse,
      );
      expect(
        certNeedsRefresh(certExpiring(now.add(const Duration(days: 3))), now: now),
        isTrue,
      );
      expect(
        certNeedsRefresh(certExpiring(now.subtract(const Duration(days: 1))), now: now),
        isTrue,
      );
    });

    test('the window is wide enough to survive a quiet week', () {
      // A device that is not opened for a few days must still refresh before
      // its peers stop being able to reach it.
      expect(certRefreshWindow.inDays, greaterThanOrEqualTo(3));
      expect(certRefreshWindow, lessThan(primaryCertLifetime));
    });
  });

  group('reading a certificate', () {
    test('extracts both keys at their exact sizes', () {
      final cert = certExpiring(now);
      expect(certSealKey(cert)!.length, 1216);
      expect(certSigKey(cert)!.length, 32);
    });

    test('refuses a key of the wrong size rather than guessing', () {
      // Callers skip a device whose certificate names no usable key. There is
      // nothing safe to fall back to — falling back to the directory key is
      // exactly the behaviour certificates exist to replace.
      final short = {...certExpiring(now), 'seal_pub': base64Encode(Uint8List(32))};
      expect(certSealKey(short), isNull);
      final wrongSig = {...certExpiring(now), 'sig_pub': base64Encode(Uint8List(64))};
      expect(certSigKey(wrongSig), isNull);
    });

    test('refuses malformed or missing fields', () {
      expect(certSealKey(const {}), isNull);
      expect(certSealKey(const {'seal_pub': 42}), isNull);
      expect(certSealKey(const {'seal_pub': 'not base64!!'}), isNull);
      expect(certSigKey(const {}), isNull);
    });
  });

  group('device keys', () {
    test('round-trip through storage keeps both seeds', () {
      final keys = DeviceKeys(
        sigSeed: Uint8List.fromList(List.filled(32, 3)),
        sealSeed: Uint8List.fromList(List.filled(32, 4)),
      );
      final back = DeviceKeys.decode(keys.encode());
      expect(back.sigSeed, keys.sigSeed);
      expect(back.sealSeed, keys.sealSeed);
    });

    test('what is persisted is seeds only', () {
      // One thing to store, one thing to lose. Public halves are derived, so
      // they cannot drift out of step with the secrets.
      final stored = jsonDecode(
        DeviceKeys(sigSeed: Uint8List(32), sealSeed: Uint8List(32)).encode(),
      ) as Map<String, dynamic>;
      expect(stored.keys.toSet(), {'sig', 'seal'});
    });

    test('the two seeds are independent', () {
      final keys = DeviceKeys.generate();
      expect(keys.sigSeed, isNot(keys.sealSeed));
    });
  });

  test('an unsigned certificate names exactly the signed fields', () {
    // These five are what core/src/devcert.rs covers with the signature. A
    // field added here but not there would be silently unauthenticated.
    final cert = unsignedCert(
      stonechatId: 'SC-ALICE',
      deviceId: 2,
      sigPublic: Uint8List(32),
      sealPublic: Uint8List(1216),
      notAfter: now,
    );
    expect(cert.keys.toSet(), {
      'stonechat_id',
      'device_id',
      'sig_pub',
      'seal_pub',
      'not_after',
    });
    expect(cert['not_after'], now.millisecondsSinceEpoch ~/ 1000);
  });
}
