// The primary's own record of its devices (lib/core/own_devices.dart): the
// manifest is built from it, the relay's listing can only remove, and
// certificates are renewed over the keys the primary certified.
//
// These are the rules that close the hole where a relay that kept a revoked
// device listed got it re-manifested and re-certified.
//
// Run:
//   ./scripts/build_core.sh host
//   STONECHAT_CORE_LIB=$PWD/../core/target/release/libstonechat_core.dylib \
//   flutter test test/own_devices_test.dart
import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart';
import 'package:stonechat/core/crypto.dart';
import 'package:stonechat/core/db.dart';
import 'package:stonechat/core/device_keys.dart';
import 'package:stonechat/core/own_devices.dart';

OwnDevice _dev(
  int id, {
  String kind = 'linked',
  String sig = 'sig',
  String seal = 'seal',
  int notAfter = 1000,
  int? revokedAt,
}) => OwnDevice(
  deviceId: id,
  kind: kind,
  sigPubB64: '$sig$id',
  sealPubB64: '$seal$id',
  notAfter: notAfter,
  revokedAt: revokedAt,
);

Map<String, dynamic> _cert(
  int id, {
  String stonechatId = 'SC-ME',
  String? sig,
  String? seal,
  int notAfter = 1000,
}) => {
  'stonechat_id': stonechatId,
  'device_id': id,
  'sig_pub': sig ?? 'sig$id',
  'seal_pub': seal ?? 'seal$id',
  'not_after': notAfter,
  'sig': 'x',
};

void main() {
  group('manifestDevices', () {
    test('lists this device and recorded, listed, unrevoked devices by the '
        'recorded key', () {
      final m = manifestDevices(
        own: [_dev(2), _dev(3)],
        listed: {1, 2, 3},
        myDeviceId: 1,
        mySigPubB64: 'me',
      );
      expect(m, {1: 'me', 2: 'sig2', 3: 'sig3'});
      expect(m.keys.toList(), [1, 2, 3], reason: 'slot order');
    });

    test('a device the relay lists but the record does not know is not '
        'listed — the relay cannot add a device', () {
      final m = manifestDevices(
        own: [_dev(2)],
        listed: {1, 2, 7},
        myDeviceId: 1,
        mySigPubB64: 'me',
      );
      expect(m.containsKey(7), isFalse);
    });

    test('a revoked device the relay still lists stays out — the relay '
        'cannot bring one back', () {
      final m = manifestDevices(
        own: [_dev(2), _dev(3, revokedAt: 5)],
        listed: {1, 2, 3},
        myDeviceId: 1,
        mySigPubB64: 'me',
      );
      expect(m, {1: 'me', 2: 'sig2'});
    });

    test('a recorded device the relay no longer lists drops out — the '
        'relay can remove', () {
      final m = manifestDevices(
        own: [_dev(2), _dev(3)],
        listed: {1, 2},
        myDeviceId: 1,
        mySigPubB64: 'me',
      );
      expect(m, {1: 'me', 2: 'sig2'});
    });

    test('the key is the recorded one, whatever the relay shows', () {
      // The listing is a set of ids here on purpose: there is no way to pass
      // a key through it.
      final m = manifestDevices(
        own: [_dev(2, sig: 'recorded')],
        listed: {2},
        myDeviceId: 1,
        mySigPubB64: 'me',
      );
      expect(m[2], 'recorded2');
    });

    test('without an own certificate the manifest still carries the others',
        () {
      final m = manifestDevices(
        own: [_dev(2)],
        listed: {2},
        myDeviceId: 1,
        mySigPubB64: null,
      );
      expect(m, {2: 'sig2'});
    });
  });

  group('certMatchesRecord', () {
    final d = _dev(2);
    test('accepts our certificate for that slot over the recorded keys', () {
      expect(
        certMatchesRecord(d, _cert(2), signedByUs: (_) => true, stonechatId: 'SC-ME'),
        isTrue,
      );
    });
    test('refuses other keys, another slot, another identity, a bad signature',
        () {
      bool ok(Map<String, dynamic> c, {bool signed = true}) =>
          certMatchesRecord(d, c, signedByUs: (_) => signed, stonechatId: 'SC-ME');
      expect(ok(_cert(2, sig: 'attacker')), isFalse);
      expect(ok(_cert(2, seal: 'attacker')), isFalse);
      expect(ok(_cert(3)), isFalse);
      expect(ok(_cert(2, stonechatId: 'SC-OTHER')), isFalse);
      expect(ok(_cert(2), signed: false), isFalse);
    });
  });

  group('renewalsDue', () {
    Duration window(String kind) => const Duration(seconds: 100);

    test('renews a listed device whose certificate is inside the window, by '
        'the recorded expiry when the relay shows nothing usable', () {
      final due = renewalsDue(
        own: [_dev(2, notAfter: 1050), _dev(3, notAfter: 5000)],
        listedCerts: {2: null, 3: null},
        myDeviceId: 1,
        nowSeconds: 1000,
        renewWindow: window,
        signedByUs: (_) => true,
        stonechatId: 'SC-ME',
      );
      expect(due.map((d) => d.deviceId), [2]);
    });

    test('a verified listed certificate says how far the last renewal got', () {
      // We last signed to 5000, but the device still publishes the old one
      // (expires 1050): renew again.
      final due = renewalsDue(
        own: [_dev(2, notAfter: 5000)],
        listedCerts: {2: _cert(2, notAfter: 1050)},
        myDeviceId: 1,
        nowSeconds: 1000,
        renewWindow: window,
        signedByUs: (_) => true,
        stonechatId: 'SC-ME',
      );
      expect(due.map((d) => d.deviceId), [2]);
    });

    test('a listed certificate over other keys changes nothing', () {
      // The relay shows a certificate naming attacker keys and an expiry
      // inside the window; the record says 5000. Not ours: ignored, not
      // renewed — and never signed over.
      final due = renewalsDue(
        own: [_dev(2, notAfter: 5000)],
        listedCerts: {2: _cert(2, sig: 'attacker', notAfter: 1050)},
        myDeviceId: 1,
        nowSeconds: 1000,
        renewWindow: window,
        signedByUs: (_) => true,
        stonechatId: 'SC-ME',
      );
      expect(due, isEmpty);
    });

    test('never a revoked device, an unlisted one, an unknown one, or this one',
        () {
      final due = renewalsDue(
        own: [
          _dev(1, notAfter: 1001),
          _dev(2, notAfter: 1001, revokedAt: 999),
          _dev(3, notAfter: 1001),
        ],
        listedCerts: {1: null, 2: _cert(2, notAfter: 1001), 7: _cert(7)},
        myDeviceId: 1,
        nowSeconds: 1000,
        renewWindow: window,
        signedByUs: (_) => true,
        stonechatId: 'SC-ME',
      );
      expect(due, isEmpty);
    });
  });

  group('seedFromListing', () {
    test('takes only devices with a certificate we signed for that slot, '
        'and never this device', () {
      final seeded = seedFromListing(
        listed: [
          (deviceId: 1, kind: 'primary', cert: _cert(1)),
          (deviceId: 2, kind: 'linked', cert: _cert(2)),
          (deviceId: 3, kind: 'web', cert: _cert(3, stonechatId: 'SC-OTHER')),
          (deviceId: 4, kind: 'web', cert: _cert(5)),
          (deviceId: 5, kind: 'web', cert: null),
        ],
        heldManifest: null,
        myDeviceId: 1,
        stonechatId: 'SC-ME',
        signedByUs: (c) => c['device_id'] != 4,
      );
      expect(seeded.map((d) => d.deviceId), [2]);
      expect(seeded.single.kind, 'linked');
      expect(seeded.single.sigPubB64, 'sig2');
      expect(seeded.single.sealPubB64, 'seal2');
      expect(seeded.single.notAfter, 1000);
    });

    test('with a manifest held, only devices it lists with that key', () {
      final seeded = seedFromListing(
        listed: [
          (deviceId: 2, kind: 'linked', cert: _cert(2)),
          (deviceId: 3, kind: 'linked', cert: _cert(3)),
          (deviceId: 4, kind: 'linked', cert: _cert(4)),
        ],
        heldManifest: {1: 'me', 2: 'sig2', 3: 'other'},
        myDeviceId: 1,
        stonechatId: 'SC-ME',
        signedByUs: (_) => true,
      );
      expect(seeded.map((d) => d.deviceId), [2]);
    });
  });

  group('through the core', () {
    CryptoService? me;
    setUpAll(() {
      try {
        me = CryptoService.generate();
      } catch (_) {
        me = null;
      }
    });

    test('a relay-forged certificate does not seed, and ours does', () {
      final id = me;
      if (id == null) return markTestSkipped('stonechat-core unavailable');
      final laptop = DeviceKeys.generate();
      final now = DateTime.now().toUtc();
      final ours = id.core.devcertSign(
        unsignedCert(
          stonechatId: id.stonechatId,
          deviceId: 2,
          sigPublic: laptop.sigPublic,
          sealPublic: laptop.sealPublic,
          notAfter: now.add(linkedCertLifetime),
        ),
        id.identitySeed,
      );
      final attacker = CryptoService.generate();
      final theirs = attacker.core.devcertSign(
        unsignedCert(
          stonechatId: id.stonechatId,
          deviceId: 3,
          sigPublic: laptop.sigPublic,
          sealPublic: laptop.sealPublic,
          notAfter: now.add(linkedCertLifetime),
        ),
        attacker.identitySeed,
      );
      bool signedByUs(Map<String, dynamic> cert) =>
          id.core.devcertVerify(
            cert,
            Uint8List.fromList(base64Decode(id.publicKeyB64)),
            now.millisecondsSinceEpoch ~/ 1000,
          ) ==
          'valid';
      final seeded = seedFromListing(
        listed: [
          (deviceId: 2, kind: 'linked', cert: ours),
          (deviceId: 3, kind: 'linked', cert: theirs),
        ],
        heldManifest: null,
        myDeviceId: 1,
        stonechatId: id.stonechatId,
        signedByUs: signedByUs,
      );
      expect(seeded.map((d) => d.deviceId), [2]);
      expect(seeded.single.sigPubB64, base64Encode(laptop.sigPublic));
    });
  });

  group('storage', () {
    Future<ChatDb> fresh() async {
      sqfliteFfiInit();
      final db = await databaseFactoryFfi.openDatabase(
        inMemoryDatabasePath,
        // Otherwise every test gets the same shared in-memory database back.
        options: OpenDatabaseOptions(singleInstance: false),
      );
      await ChatDb.createSchema(db);
      return ChatDb.forTesting(db);
    }

    test('records, revokes, and keeps the revoked row', () async {
      final db = await fresh();
      await db.putOwnDevice(_dev(2));
      await db.putOwnDevice(_dev(3, kind: 'web'));
      await db.revokeOwnDevice(3, 77);
      final own = await db.ownDevices();
      expect(own.map((d) => d.deviceId), [2, 3]);
      expect(own[0].revoked, isFalse);
      expect(own[1].revoked, isTrue);
      expect(own[1].revokedAt, 77);
      expect(own[1].kind, 'web');
    });

    test('a slot is replaced wholesale when recorded again', () async {
      final db = await fresh();
      await db.putOwnDevice(_dev(2, notAfter: 10));
      await db.putOwnDevice(_dev(2, sig: 'new', notAfter: 20));
      final d = (await db.ownDevices()).single;
      expect(d.sigPubB64, 'new2');
      expect(d.notAfter, 20);
    });

    test('an old database gains the table', () async {
      sqfliteFfiInit();
      final raw = await databaseFactoryFfi.openDatabase(
        inMemoryDatabasePath,
        options: OpenDatabaseOptions(singleInstance: false),
      );
      await ChatDb.createSchema(raw);
      await raw.execute('DROP TABLE own_devices');
      await ChatDb.ensureOwnDevices(raw);
      final db = ChatDb.forTesting(raw);
      expect(await db.ownDevices(), isEmpty);
    });
  });
}
