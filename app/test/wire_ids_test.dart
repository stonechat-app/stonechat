// Regression: an incoming media file was written to `<media>/<id><ext>` with
// `id` taken from the sender's envelope as-is, so an id of `../../x` wrote
// the sender's bytes over any file in the app's sandbox. `blob_id` went into
// a URL on the user's own mailbox, next to the owner token, the same way.
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:path/path.dart' as p;
import 'package:stonechat/core/api.dart';
import 'package:stonechat/core/wire_ids.dart';
import 'package:stonechat/models.dart';

const _id = '3f2b8c1e-9a4d-4e6f-8b7a-0c1d2e3f4a5b';

const _hostile = [
  '../../databases/stonechat.db',
  '../x',
  '..',
  '/etc/passwd',
  '/absolute',
  r'..\..\x',
  'a/b',
  '$_id/../x',
  '../$_id',
  '$_id\u0000',
  '$_id ',
  '$_id?token=x',
  '$_id#frag',
  '%2e%2e%2f$_id',
  '',
];

Map<String, dynamic> _inner({Object? id = _id, Object? blobId}) => {
  'v': 1,
  'id': id,
  'type': 'media',
  'from': 'SC-A',
  'from_device': 1,
  'to': 'SC-B',
  'device': 1,
  'sent_at': '2026-09-29T00:00:00Z',
  'ratchet': {'dh': 'AA==', 'pn': 0, 'n': 0},
  'nonce': 'AA==',
  'ciphertext': 'AA==',
  'blob_id': ?blobId,
};

void main() {
  group('isWireId', () {
    test('a UUID, in either case', () {
      expect(isWireId(_id), isTrue);
      expect(isWireId(_id.toUpperCase()), isTrue);
    });

    test('nothing else', () {
      for (final bad in _hostile) {
        expect(isWireId(bad), isFalse, reason: bad);
      }
      expect(isWireId(null), isFalse);
      expect(isWireId(7), isFalse);
      expect(isWireId(_id.replaceAll('-', '')), isFalse);
    });
  });

  group('mediaFilePath', () {
    final dir = p.join(Directory.systemTemp.path, 'media');

    test('a UUID lands directly inside the media directory', () {
      final path = mediaFilePath(dir, _id, '.jpg');
      expect(path, p.join(dir, '$_id.jpg'));
      expect(p.dirname(path), dir);
    });

    test('the file name does not depend on the case the sender chose', () {
      expect(mediaFilePath(dir, _id.toUpperCase(), '.jpg'), p.join(dir, '$_id.jpg'));
    });

    test('an id that is not a UUID is refused, never escaped', () {
      for (final bad in _hostile) {
        expect(
          () => mediaFilePath(dir, bad, '.jpg'),
          throwsFormatException,
          reason: bad,
        );
      }
    });

    test('a hostile extension cannot move the file either', () {
      for (final ext in ['/../../x', '.a/b', r'.a\b', '..', '.', '', '.x' * 9, null]) {
        final path = mediaFilePath(dir, _id, ext);
        expect(path, p.join(dir, '$_id.bin'), reason: '$ext');
      }
    });

    test('an ordinary extension is kept, so documents still open', () {
      expect(mediaFilePath(dir, _id, '.pdf'), endsWith('.pdf'));
      expect(mediaFilePath(dir, _id, '.DOCX'), endsWith('.DOCX'));
    });
  });

  group('Envelope.fromJson', () {
    test('accepts UUIDs', () {
      final e = Envelope.fromJson(_inner(blobId: _id));
      expect(e.id, _id);
      expect(e.blobId, _id);
      expect(Envelope.fromJson(_inner()).blobId, isNull);
    });

    test('refuses an id that is not a UUID', () {
      for (final bad in _hostile) {
        expect(
          () => Envelope.fromJson(_inner(id: bad)),
          throwsFormatException,
          reason: bad,
        );
      }
      expect(() => Envelope.fromJson(_inner(id: 7)), throwsFormatException);
    });

    test('refuses a blob_id that is not a UUID', () {
      for (final bad in _hostile) {
        expect(
          () => Envelope.fromJson(_inner(blobId: bad)),
          throwsFormatException,
          reason: bad,
        );
      }
    });
  });

  test('downloadBlob refuses a hostile blob id before it dials', () async {
    // Nothing listens on this address. If the id were put in a URL and
    // requested, this would fail as a connection error instead.
    for (final bad in ['../prekeys/bundle', '$_id?x=1', '']) {
      await expectLater(
        downloadBlob('https://127.0.0.1:1', bad, 'SECRET', 'fp'),
        throwsFormatException,
        reason: bad,
      );
    }
  });
}
