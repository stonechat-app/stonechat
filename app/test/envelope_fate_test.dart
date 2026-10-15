// Which failures leave an envelope queued (lib/core/envelope_fate.dart).
// Regression: every exception did, so a sender could craft an envelope that
// was never acked and came back on every connect for good.
import 'dart:async';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:stonechat/core/api.dart';
import 'package:stonechat/core/envelope_fate.dart';

void main() {
  group('leavesQueued', () {
    test('an explicit deferral keeps the envelope', () {
      expect(leavesQueued(const EnvelopeDeferred('mailbox info missing')), isTrue);
    });

    test('network, timeout and file failures keep it', () {
      expect(leavesQueued(const SocketException('down')), isTrue);
      expect(leavesQueued(const HandshakeException('tls')), isTrue);
      expect(leavesQueued(TimeoutException('slow')), isTrue);
      expect(leavesQueued(const FileSystemException('disk')), isTrue);
    });

    test('a mailbox or directory failure keeps it, a refusal does not', () {
      expect(leavesQueued(ApiException('blob download failed (503)', 503)), isTrue);
      expect(leavesQueued(ApiException('no cached address')), isTrue);
      expect(leavesQueued(ApiException.refusing('key does not match')), isFalse);
    });

    test("the shapes a malformed envelope produces drop it", () {
      Object caught(void Function() f) {
        try {
          f();
        } catch (e) {
          return e;
        }
        fail('did not throw');
      }

      expect(leavesQueued(caught(() => 'x'.substring(0, 12))), isFalse);
      expect(leavesQueued(caught(() => (5 as dynamic) as String)), isFalse);
      expect(leavesQueued(caught(() => <int>[].first)), isFalse);
      expect(leavesQueued(const FormatException('not a UUID')), isFalse);
      expect(leavesQueued(ArgumentError('malformed device certificate')), isFalse);
      expect(leavesQueued(StateError('mailbox info missing')), isFalse,
          reason: 'a bare StateError is no longer the deferral signal');
      expect(leavesQueued(Exception('anything else')), isFalse);
    });
  });

  group('abbreviateId', () {
    test('shortens a long id and leaves a short one alone', () {
      expect(abbreviateId('SC-ABCD-EFGH-IJKL-MNOP'), 'SC-ABCD-EFGH…');
      expect(abbreviateId('x'), 'x');
      expect(abbreviateId(''), '');
    });
  });
}
