// The signed device manifest (lib/core/device_manifest.dart, core
// devices.rs): what it says about a device, what it refuses, and the
// storage behind it. Signing and verification run through the real core.
//
// Run:
//   ./scripts/build_core.sh host
//   STONECHAT_CORE_LIB=$PWD/../core/target/release/libstonechat_core.dylib \
//   flutter test test/device_manifest_test.dart
import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart';
import 'package:stonechat/core/crypto.dart';
import 'package:stonechat/core/db.dart';
import 'package:stonechat/core/device_keys.dart';
import 'package:stonechat/core/device_manifest.dart';
import 'package:stonechat/models.dart';

void main() {
  CryptoService? alice;
  setUpAll(() {
    try {
      alice = CryptoService.generate();
    } catch (_) {
      alice = null;
    }
  });

  group('DeviceManifest', () {
    test('signs, verifies, and says which devices speak for the identity', () {
      final a = alice;
      if (a == null) return markTestSkipped('stonechat-core unavailable');
      final phone = DeviceKeys.generate();
      final laptop = DeviceKeys.generate();
      final m = DeviceManifest.sign(
        stonechatId: a.stonechatId,
        version: 4,
        devices: {1: base64Encode(phone.sigPublic), 2: base64Encode(laptop.sigPublic)},
        identitySeed: a.identitySeed,
        core: a.core,
      );
      // Through the wire form, as the directory serves it.
      final json = jsonDecode(jsonEncode(m.toJson()));
      final back = DeviceManifest.verified(json, a.stonechatId, a.publicKey, a.core);
      expect(back, isNotNull);
      expect(back!.version, 4);
      expect(back.lists(2, base64Encode(laptop.sigPublic)), isTrue);
      expect(back.lists(3, base64Encode(laptop.sigPublic)), isFalse, reason: 'not a slot it names');
      expect(back.lists(2, base64Encode(phone.sigPublic)), isFalse, reason: 'wrong key for the slot');
      expect(back.lists(2, null), isFalse);
    });

    test('refuses another identity, another name, tampering, and nonsense', () {
      final a = alice;
      if (a == null) return markTestSkipped('stonechat-core unavailable');
      final bob = CryptoService.generate();
      final m = DeviceManifest.sign(
        stonechatId: a.stonechatId,
        version: 1,
        devices: {1: base64Encode(DeviceKeys.generate().sigPublic)},
        identitySeed: a.identitySeed,
        core: a.core,
      ).toJson();
      expect(DeviceManifest.verified(m, a.stonechatId, a.publicKey, a.core), isNotNull);
      expect(DeviceManifest.verified(m, a.stonechatId, bob.publicKey, a.core), isNull,
          reason: 'not the key the ID commits to');
      expect(DeviceManifest.verified(m, bob.stonechatId, a.publicKey, a.core), isNull,
          reason: 'not the identity we asked about');
      final bumped = Map<String, dynamic>.from(m)..['version'] = 2;
      expect(DeviceManifest.verified(bumped, a.stonechatId, a.publicKey, a.core), isNull);
      final added = Map<String, dynamic>.from(m)
        ..['devices'] = [...(m['devices'] as List), {'device_id': 9, 'sig_pub': m['devices'][0]['sig_pub']}];
      expect(DeviceManifest.verified(added, a.stonechatId, a.publicKey, a.core), isNull);
      expect(DeviceManifest.fromJson({'version': 1}), isNull);
      expect(DeviceManifest.fromJson('text'), isNull);
      expect(DeviceManifest.verified(null, a.stonechatId, a.publicKey, a.core), isNull);
    });
  });

  test('an envelope states its sender\'s manifest version, or nothing', () {
    expect(manifestVersionOf({'manifest_v': 3}), 3);
    expect(manifestVersionOf({'manifest_v': 0}), 0);
    expect(manifestVersionOf({'manifest_v': 'x'}), 0);
    expect(manifestVersionOf({}), 0);
    final env = Envelope(
      v: 1, id: '8f1b6a2e-0d4c-4a1b-9c3e-2f5d7b8a9c01', type: 'msg', from: 'SC-A',
      fromDevice: 1, to: 'SC-B', device: 1, sentAt: 't', ratchet: const {},
      nonceB64: '', ciphertextB64: '', manifestV: 5,
    );
    expect(env.toJson()['manifest_v'], 5);
    expect(Envelope.fromJson(env.toJson().cast<String, dynamic>()).manifestV, 5);
    final none = Envelope.fromJson({...env.toJson()}..remove('manifest_v'));
    expect(none.manifestV, 0);
    expect(none.toJson().containsKey('manifest_v'), isFalse);
  });

  test('linked devices live weeks, and are renewed at half life', () {
    expect(linkedCertLifetime, lessThanOrEqualTo(const Duration(days: 14)));
    expect(agentCertLifetime, lessThanOrEqualTo(const Duration(days: 14)));
    expect(webCertLifetime, lessThanOrEqualTo(const Duration(days: 7)));
    expect(certRenewWindow('linked'), const Duration(days: 7));
    expect(certRefreshWindow, lessThan(certRenewWindow('web')),
        reason: 'senders refetch before a renewed certificate could lapse unseen');
  });

  test('manifests and peer certificates persist, and an old database gains the tables',
      () async {
    sqfliteFfiInit();
    final db = await databaseFactoryFfi.openDatabase(
      inMemoryDatabasePath,
      options: OpenDatabaseOptions(singleInstance: false),
    );
    await ChatDb.createSchema(db);
    await db.execute('DROP TABLE device_manifests');
    await db.execute('DROP TABLE peer_certs');
    await ChatDb.ensureDeviceTrust(db);
    await ChatDb.ensureDeviceTrust(db);
    final chat = ChatDb.forTesting(db);
    expect(await chat.manifestFor('SC-A'), isNull);
    await chat.putManifest('SC-A', 2, '{"version":2}');
    await chat.putManifest('SC-A', 3, '{"version":3}');
    expect((await chat.manifestFor('SC-A'))!.version, 3);
    await chat.putPeerCert('SC-A', 2, '{"c":1}', 99);
    expect(await chat.peerCert('SC-A', 2), '{"c":1}');
    await chat.deletePeerCert('SC-A', 2);
    expect(await chat.peerCert('SC-A', 2), isNull);
  });
}
