// The .zeonbackup container format. Restore must parse headers written by
// any past build, so the layout is pinned here byte-by-byte — a failing
// round-trip means old backups can no longer be opened, not just that a
// constant moved. Crypto itself (pwhash/secretstream) is FFI and exercised
// in the manual on-device checklist instead.
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:zeon_chat/core/backup.dart';

void main() {
  final salt = Uint8List.fromList(List.generate(16, (i) => i + 1));

  group('encodeHeader', () {
    test('lays out all fields at their pinned offsets', () {
      final h = BackupService.encodeHeader(salt, 3, 268435456);
      expect(h.length, BackupService.headerLength);
      expect(String.fromCharCodes(h.sublist(0, 8)), 'ZEONBAK1');
      expect(h[8], 1); // format version
      expect(h[9], 1); // kdf id
      expect(h[10], 0); // reserved
      expect(h[11], 16); // salt length
      expect(h.sublist(12, 28), salt);
      final bd = ByteData.sublistView(h);
      expect(bd.getUint32(28, Endian.little), 3);
      expect(bd.getUint64(32, Endian.little), 268435456);
    });
  });

  group('decodeHeader', () {
    // A one-byte body: decodeHeader only rejects files with nothing at all
    // after the header.
    Uint8List withBody(Uint8List header) =>
        Uint8List.fromList([...header, 0x00]);

    test('round-trips what encodeHeader wrote', () {
      final decoded =
          BackupService.decodeHeader(withBody(BackupService.encodeHeader(salt, 2, 1 << 28)));
      expect(decoded.salt, salt);
      expect(decoded.opsLimit, 2);
      expect(decoded.memLimit, 1 << 28);
    });

    test('rejects wrong magic as not-a-backup', () {
      final h = withBody(BackupService.encodeHeader(salt, 2, 1 << 28));
      h[0] = 0x5A; // 'Z' stays, but
      h[7] = 0x32; // "ZEONBAK2" in the magic slot
      expect(
        () => BackupService.decodeHeader(h),
        throwsA(predicate((e) =>
            e is BackupException && e.message.contains('Not a Zeon backup'))),
      );
    });

    test('rejects files shorter than header+body', () {
      expect(
        () => BackupService.decodeHeader(
            BackupService.encodeHeader(salt, 2, 1 << 28)), // header only
        throwsA(isA<BackupException>()),
      );
      expect(
        () => BackupService.decodeHeader(Uint8List(10)),
        throwsA(isA<BackupException>()),
      );
    });

    test('rejects a future format version as newer-version', () {
      final h = withBody(BackupService.encodeHeader(salt, 2, 1 << 28));
      h[8] = BackupService.formatVersion + 1;
      expect(
        () => BackupService.decodeHeader(h),
        throwsA(predicate((e) =>
            e is BackupException && e.message.contains('newer version'))),
      );
    });

    test('rejects version zero as not-a-backup', () {
      final h = withBody(BackupService.encodeHeader(salt, 2, 1 << 28));
      h[8] = 0;
      expect(
        () => BackupService.decodeHeader(h),
        throwsA(predicate((e) =>
            e is BackupException && e.message.contains('Not a Zeon backup'))),
      );
    });

    test('rejects an unknown kdf id as newer-version', () {
      final h = withBody(BackupService.encodeHeader(salt, 2, 1 << 28));
      h[9] = 2;
      expect(
        () => BackupService.decodeHeader(h),
        throwsA(predicate((e) =>
            e is BackupException && e.message.contains('newer version'))),
      );
    });

    test('rejects an unexpected salt length as newer-version', () {
      final h = withBody(BackupService.encodeHeader(salt, 2, 1 << 28));
      h[11] = 32;
      expect(
        () => BackupService.decodeHeader(h),
        throwsA(predicate((e) =>
            e is BackupException && e.message.contains('newer version'))),
      );
    });
  });

  group('buildPayload', () {
    test('carries counts, version and detached copies of the rows', () {
      final contactRow = {'zeon_id': 'z1', 'display_name': 'A'};
      final payload = BackupService.buildPayload(
        contacts: [contactRow],
        groups: [],
        groupMembers: [],
        messages: [
          {'id': 'm1', 'text': 'hi', 'kind': 'text', 'sent_at': 5},
          {'id': 'm2', 'text': 'yo', 'kind': 'text', 'sent_at': 6},
        ],
        reactions: [
          {'message_id': 'm1', 'peer_id': 'z1', 'emoji': '❤️', 'at': 7},
        ],
        nowMs: 1234,
      );
      expect(payload['format'], 'zeon-backup');
      expect(payload['version'], BackupService.payloadVersion);
      expect(payload['created_at'], 1234);
      expect(payload['counts'],
          {'contacts': 1, 'groups': 0, 'group_members': 0, 'messages': 2, 'reactions': 1});
      expect((payload['messages'] as List).length, 2);

      // Rows must be copies: the originals may be sqflite's private map type,
      // and the payload crosses an isolate boundary.
      final copied = (payload['contacts'] as List).first as Map;
      expect(copied, contactRow);
      expect(identical(copied, contactRow), isFalse);
    });
  });
}
