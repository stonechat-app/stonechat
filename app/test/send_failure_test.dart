// The send-outcome contract: a message
// that didn't land has to be able to say so, and the retry policy behind it
// is a product decision worth pinning against a casual edit.
import 'package:flutter_test/flutter_test.dart';
import 'package:stonechat/core/api.dart';
import 'package:stonechat/models.dart';
import 'package:stonechat/state/chat_state.dart';

void main() {
  group('failed status', () {
    test('ranks with pending, so a late receipt still heals the message', () {
      // The point: if a message we gave up on turns out to have landed, the
      // receipt proves it and must be allowed to move the status forward.
      expect(MessageStatus.rank(MessageStatus.failed), 0);
      expect(
        MessageStatus.rank(MessageStatus.delivered),
        greaterThan(MessageStatus.rank(MessageStatus.failed)),
      );
      expect(
        MessageStatus.rank(MessageStatus.sent),
        greaterThan(MessageStatus.rank(MessageStatus.failed)),
      );
    });

    test('never outranks a status the message already reached', () {
      // Guards the inverse mistake: failing a delivered message.
      for (final reached in [
        MessageStatus.sent,
        MessageStatus.delivered,
        MessageStatus.read,
      ]) {
        expect(
          MessageStatus.rank(MessageStatus.failed),
          lessThan(MessageStatus.rank(reached)),
          reason: 'failed must not look like progress over $reached',
        );
      }
    });
  });

  group('row round-trip', () {
    test('carries the reason and the backoff bookkeeping', () {
      final m = Message(
        id: 'abc',
        contactId: 'SC-PEER',
        outgoing: true,
        text: 'hi',
        sentAt: 1000,
        status: MessageStatus.failed,
        failReason: "Their mailbox is off right now",
        attempts: 4,
        lastAttemptAt: 99000,
      );
      final back = Message.fromRow(m.toRow());
      expect(back.status, MessageStatus.failed);
      expect(back.failReason, "Their mailbox is off right now");
      expect(back.attempts, 4);
      expect(back.lastAttemptAt, 99000);
    });

    test('a message that never failed carries no residue', () {
      final m = Message(
        id: 'def',
        contactId: 'SC-PEER',
        outgoing: true,
        text: 'yo',
        sentAt: 2000,
        status: MessageStatus.sent,
      );
      final back = Message.fromRow(m.toRow());
      expect(back.failReason, isNull);
      expect(back.attempts, 0);
      expect(back.lastAttemptAt, isNull);
    });

    test('rows from before the column existed read as a fresh message', () {
      // v3 databases have no fail_reason/attempts/last_attempt_at columns;
      // sqflite hands those back absent, not as zeroes.
      final row = Message(
        id: 'old',
        contactId: 'SC-PEER',
        outgoing: true,
        text: 'from v3',
        sentAt: 5,
        status: MessageStatus.pending,
      ).toRow()
        ..remove('fail_reason')
        ..remove('attempts')
        ..remove('last_attempt_at');
      final back = Message.fromRow(row);
      expect(back.attempts, 0);
      expect(back.failReason, isNull);
      expect(back.lastAttemptAt, isNull);
    });
  });

  group('refusals are terminal', () {
    test('a refusal is flagged on the exception, not sniffed from its text', () {
      // The three refusal sites in chat_state throw this way; classification
      // by message string would break the first time the copy is reworded.
      final refusal = ApiException.refusing(
        'Their mailbox served a forged prekey — refusing to send.',
      );
      expect(refusal.refused, isTrue);
      expect(refusal.message, contains('refusing'));
    });

    test('an ordinary unreachable-mailbox error is not a refusal', () {
      expect(ApiException("Bob's mailbox is off right now").refused, isFalse);
      expect(ApiException('blob upload failed (503)', 503).refused, isFalse);
    });
  });

  group('sendBackoffMs', () {
    test('a message never attempted is due immediately', () {
      expect(sendBackoffMs(0), 0);
      expect(sendBackoffMs(-1), 0);
    });

    test('doubles from 30s and stops at the 30-minute ceiling', () {
      expect(sendBackoffMs(1), 30 * 1000);
      expect(sendBackoffMs(2), 60 * 1000);
      expect(sendBackoffMs(3), 120 * 1000);
      expect(sendBackoffMs(7), 30 * 60 * 1000); // 32min → clamped
      expect(sendBackoffMs(50), 30 * 60 * 1000);
    });

    test('never overflows or goes backwards, however long the outage', () {
      var previous = 0;
      for (var n = 1; n < 500; n++) {
        final wait = sendBackoffMs(n);
        expect(wait, greaterThanOrEqualTo(previous));
        expect(wait, lessThanOrEqualTo(30 * 60 * 1000));
        previous = wait;
      }
    });
  });

  group('sendAgeLabel', () {
    test('stays quiet about a message that is merely a moment old', () {
      expect(sendAgeLabel(0), isNull);
      expect(sendAgeLabel(4 * 60 * 1000 + 59999), isNull);
    });

    test('reads in the coarsest useful unit', () {
      expect(sendAgeLabel(5 * 60 * 1000), '5m');
      expect(sendAgeLabel(59 * 60 * 1000), '59m');
      expect(sendAgeLabel(60 * 60 * 1000), '1h');
      expect(sendAgeLabel(23 * 3600 * 1000), '23h');
      expect(sendAgeLabel(24 * 3600 * 1000), '1d');
      expect(sendAgeLabel(3 * 24 * 3600 * 1000), '3d');
    });

    test('never renders a fractional or empty unit', () {
      for (var m = 5; m < 60 * 24 * 10; m += 13) {
        final s = sendAgeLabel(m * 60 * 1000);
        expect(s, matches(RegExp(r'^\d+[mhd]$')), reason: 'at $m minutes');
      }
    });
  });

  test('the give-up window outlasts a weekend but not a fortnight', () {
    // A product call, pinned: 24h would abandon messages to a mailbox that
    // is merely migrating over a weekend; 30d is longer than anyone keeps
    // believing "sending…".
    const day = 24 * 3600 * 1000;
    expect(sendGiveUpAfterMs, greaterThan(3 * day));
    expect(sendGiveUpAfterMs, lessThan(14 * day));
    // And a message inside the window is still worth retrying at the ceiling.
    expect(sendGiveUpAfterMs, greaterThan(sendBackoffMs(99)));
  });
}
