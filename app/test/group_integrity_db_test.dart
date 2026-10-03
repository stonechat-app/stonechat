// Storage behind the group integrity work: the columns and tables a database
// created before it gains on open, rosters still owed to members, messages
// parked until their roster arrives, and the `seen` list a group message
// vouches for.
import 'package:flutter_test/flutter_test.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart';
import 'package:stonechat/core/db.dart';
import 'package:stonechat/models.dart';

Future<Database> _open() async {
  sqfliteFfiInit();
  return databaseFactoryFfi.openDatabase(
    inMemoryDatabasePath,
    options: OpenDatabaseOptions(singleInstance: false),
  );
}

Future<ChatDb> _freshDb() async {
  final db = await _open();
  await ChatDb.createSchema(db);
  return ChatDb.forTesting(db);
}

Message _msg(String id, {required bool outgoing, String? hash, int sentAt = 1}) =>
    Message(
      id: id,
      contactId: 'g1',
      senderId: outgoing ? null : 'SC-PEER',
      outgoing: outgoing,
      text: id,
      sentAt: sentAt,
      status: MessageStatus.sent,
      contentHash: hash,
    );

void main() {
  test('a database from before gains the columns and tables, once', () async {
    final db = await _open();
    await ChatDb.createSchema(db);
    // What an earlier install looks like.
    await db.execute('DROP TABLE roster_owed');
    await db.execute('DROP TABLE group_parked');
    for (final (table, column) in [
      ('groups', 'roster_hash'),
      ('groups', 'seen_version'),
      ('messages', 'salt'),
      ('messages', 'content_hash'),
    ]) {
      await db.execute('ALTER TABLE $table DROP COLUMN $column');
    }
    await db.insert('groups', {
      'id': 'g1',
      'name': 'old',
      'admin_id': 'SC-A',
      'version': 4,
      'created_at': 1,
    });

    await ChatDb.ensureGroupIntegrity(db);
    await ChatDb.ensureGroupIntegrity(db); // every open runs it

    final chat = ChatDb.forTesting(db);
    final group = (await chat.groups()).single;
    expect(group.version, 4);
    expect(group.rosterHash, isNull);
    expect(group.seenVersion, 0);
    await chat.oweRoster('g1', ['SC-B'], 10);
    expect(await chat.rosterOwed(), hasLength(1));
  });

  test('a roster is owed until every device has it', () async {
    final chat = await _freshDb();
    await chat.oweRoster('g1', ['SC-B', 'SC-C'], 100);
    expect((await chat.rosterOwed()).map((o) => o.memberId), ['SC-B', 'SC-C']);
    expect(await chat.rosterDevicesOwed('g1', 'SC-B'), 1);

    // The fan-out reports back: B's phone took it, B's laptop did not.
    await chat.setOwedDevices(ChatDb.rosterOutboxId('g1'), 'g1', 'SC-B', [2]);
    expect(await chat.rosterDevicesOwed('g1', 'SC-B'), 1);
    await chat.setOwedDevices(ChatDb.rosterOutboxId('g1'), 'g1', 'SC-B', []);
    expect(await chat.rosterDevicesOwed('g1', 'SC-B'), 0);

    await chat.settleRoster('g1', 'SC-B');
    expect((await chat.rosterOwed()).map((o) => o.memberId), ['SC-C']);

    // Owing it again (another change) restarts the clock, not the row count.
    await chat.oweRoster('g1', ['SC-C'], 500);
    expect((await chat.rosterOwed()).single.since, 500);

    await chat.deleteGroup('g1');
    expect(await chat.rosterOwed(), isEmpty);
    expect(await chat.pendingOutbox(), isEmpty);
  });

  test('parked messages come back oldest first, once, and are bounded',
      () async {
    final chat = await _freshDb();
    for (var i = 0; i < ChatDb.parkedMax + 5; i++) {
      await chat.parkGroupMessage(
        id: 'm$i',
        groupId: i.isEven ? 'g1' : 'g2',
        envelopeJson: '{"n":$i}',
        payloadJson: '{}',
        nowMs: i,
      );
    }
    final g1 = await chat.takeParked('g1');
    final g2 = await chat.takeParked('g2');
    expect(g1.length + g2.length, ChatDb.parkedMax);
    expect(g1.first.envelopeJson, '{"n":6}', reason: 'the oldest were evicted');
    expect(await chat.takeParked('g1'), isEmpty);

    await chat.parkGroupMessage(
        id: 'old', groupId: 'g1', envelopeJson: '{}', payloadJson: '{}', nowMs: 5);
    await chat.parkGroupMessage(
        id: 'new', groupId: 'g1', envelopeJson: '{}', payloadJson: '{}', nowMs: 50);
    await chat.dropParkedBefore(10);
    expect(await chat.takeParked('g1'), hasLength(1));
  });

  test('a message vouches for what arrived since we last spoke', () async {
    final chat = await _freshDb();
    await chat.insertMessage(_msg('in-early', outgoing: false, hash: 'h0'));
    await chat.insertMessage(_msg('out-1', outgoing: true));
    // Arrival order, not sender clocks: this one claims an old sent_at.
    await chat.insertMessage(_msg('in-a', outgoing: false, hash: 'ha', sentAt: 0));
    await chat.insertMessage(_msg('in-nohash', outgoing: false));
    await chat.insertMessage(_msg('in-b', outgoing: false, hash: 'hb'));
    await chat.insertMessage(_msg('out-2', outgoing: true));
    await chat.insertMessage(_msg('in-late', outgoing: false, hash: 'hl'));

    final seen = await chat.seenBefore('g1', 'out-2', 4);
    expect(seen.map((s) => (s.id, s.hash)), [('in-b', 'hb'), ('in-a', 'ha')]);
    // A retry of out-2, after more has arrived, builds the same list.
    expect(await chat.seenBefore('g1', 'out-2', 4), hasLength(2));
    expect((await chat.seenBefore('g1', 'out-2', 1)).single.id, 'in-b');
    expect((await chat.seenBefore('g1', 'out-1', 4)).single.id, 'in-early');
  });

  test('salt and content hash survive a round trip through a row', () async {
    final chat = await _freshDb();
    await chat.insertMessage(Message(
      id: 'm',
      contactId: 'g1',
      outgoing: true,
      text: 't',
      sentAt: 1,
      status: MessageStatus.pending,
      salt: 'c2FsdA==',
    ));
    expect((await chat.messageById('m'))!.salt, 'c2FsdA==');
    await chat.insertMessage(_msg('n', outgoing: false, hash: 'hh'));
    expect((await chat.messageById('n'))!.contentHash, 'hh');
  });
}
