// Bookmarks, in-chat pins and drafts: what a database from before gains on
// open, and what the queries behind them return.
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

Message _msg(String id, String chat, {int? expiresAt}) => Message(
      id: id,
      contactId: chat,
      outgoing: false,
      text: id,
      sentAt: 1,
      status: MessageStatus.read,
      expiresAt: expiresAt,
    );

void main() {
  test('a database from before gains the column, once', () async {
    final db = await _open();
    await ChatDb.createSchema(db);
    await db.execute('DROP INDEX idx_messages_bookmarked');
    await db.execute('DROP TABLE drafts');
    for (final column in ['bookmarked_at', 'pinned_at', 'pinned_until']) {
      await db.execute('ALTER TABLE messages DROP COLUMN $column');
    }
    await ChatDb.ensureMessageMarks(db);
    await ChatDb.ensureMessageMarks(db);
    final cols = await db.rawQuery('PRAGMA table_info(messages)');
    for (final column in ['bookmarked_at', 'pinned_at', 'pinned_until']) {
      expect(cols.where((c) => c['name'] == column), hasLength(1));
    }
    await ChatDb.forTesting(db).setDraft('SC-A', 'hi');
  });

  test('bookmarks span chats, newest first, minus deleted and expired',
      () async {
    final raw = await _open();
    await ChatDb.createSchema(raw);
    final db = ChatDb.forTesting(raw);
    await db.insertMessage(_msg('a', 'SC-A'));
    await db.insertMessage(_msg('b', 'g1'));
    await db.insertMessage(_msg('c', 'SC-A'));
    await db.insertMessage(_msg('gone', 'SC-A', expiresAt: 50));
    await db.insertMessage(_msg('plain', 'SC-A'));
    await db.setMessageBookmarked('a', 10);
    await db.setMessageBookmarked('b', 30);
    await db.setMessageBookmarked('c', 20);
    await db.setMessageBookmarked('gone', 40);

    var ids = (await db.bookmarkedMessages(100)).map((m) => m.id);
    expect(ids, ['b', 'c', 'a']);
    expect((await db.messageById('b'))!.bookmarkedAt, 30);

    await db.tombstoneMessage('c');
    await db.setMessageBookmarked('a', null);
    ids = (await db.bookmarkedMessages(100)).map((m) => m.id);
    expect(ids, ['b']);
    expect((await db.messageById('c'))!.isBookmarked, isFalse);
  });

  test('live pins: newest first, lapsed and deleted ones left out', () async {
    final raw = await _open();
    await ChatDb.createSchema(raw);
    final db = ChatDb.forTesting(raw);
    for (final id in ['a', 'b', 'c', 'd']) {
      await db.insertMessage(_msg(id, 'g1'));
    }
    await db.insertMessage(_msg('other', 'SC-A'));
    await db.setMessagePin('a', 10, 1000);
    await db.setMessagePin('b', 20, 1000);
    await db.setMessagePin('c', 30, 50); // lapses at 50
    await db.setMessagePin('d', 40, 1000);
    await db.setMessagePin('other', 50, 1000);

    expect((await db.activePins('g1', 100)).map((m) => m.id), ['d', 'b', 'a']);
    await db.tombstoneMessage('d');
    await db.setMessagePin('a', null, null);
    expect((await db.activePins('g1', 100)).map((m) => m.id), ['b']);
    final b = (await db.messageById('b'))!;
    expect(b.isPinnedAt(999), isTrue);
    expect(b.isPinnedAt(1000), isFalse);
  });

  test('drafts: saved, replaced, dropped when emptied or the chat goes',
      () async {
    final raw = await _open();
    await ChatDb.createSchema(raw);
    final db = ChatDb.forTesting(raw);
    await db.setDraft('SC-A', 'first');
    await db.setDraft('SC-A', 'second');
    await db.setDraft('g1', 'group text');
    await db.setDraft('SC-B', '   ');
    expect(await db.drafts(), {'SC-A': 'second', 'g1': 'group text'});
    await db.setDraft('SC-A', '');
    await db.deleteGroup('g1');
    expect(await db.drafts(), isEmpty);
  });
}
