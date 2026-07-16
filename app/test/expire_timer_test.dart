import 'package:flutter_test/flutter_test.dart';
import 'package:zeon_chat/models.dart';

void main() {
  test('Message row round-trip preserves expiresAt', () {
    final m = Message(
      id: 'abc',
      contactId: 'ZC-PEER',
      outgoing: true,
      text: 'hi',
      sentAt: 1000,
      status: MessageStatus.sent,
      expiresAt: 1000 + 3600000,
    );
    final back = Message.fromRow(m.toRow());
    expect(back.expiresAt, 3601000);

    final never = Message(
      id: 'def',
      contactId: 'ZC-PEER',
      outgoing: false,
      text: 'yo',
      sentAt: 2000,
      status: MessageStatus.read,
    );
    expect(Message.fromRow(never.toRow()).expiresAt, isNull);
  });

  test('Contact/Group rows round-trip the timer', () {
    final c = Contact(
      zeonId: 'ZC-X',
      displayName: 'x',
      pubkeyB64: 'k',
      status: ContactStatus.accepted,
      createdAt: 1,
      expireTimerMs: 86400000,
      expireTimerAt: 42,
    );
    final backC = Contact.fromRow(c.toRow());
    expect(backC.expireTimerMs, 86400000);
    expect(backC.expireTimerAt, 42);

    final g = Group(
      id: 'g1',
      name: 'crew',
      adminId: 'ZC-A',
      version: 3,
      createdAt: 1,
      expireTimerMs: 604800000,
      expireTimerAt: 7,
    );
    final backG = Group.fromRow(g.toRow());
    expect(backG.expireTimerMs, 604800000);
    expect(backG.expireTimerAt, 7);
  });

  test('ExpireTimer labels', () {
    expect(ExpireTimer.label(0), 'Off');
    expect(ExpireTimer.label(3600000), '1 hour');
    expect(ExpireTimer.label(86400000), '24 hours');
    expect(ExpireTimer.label(604800000), '7 days');
    // Durations from a newer client still render something sensible.
    expect(ExpireTimer.label(2 * 86400000), '2 days');
    expect(ExpireTimer.label(2 * 3600000), '2 hours');
  });
}
