// Bookmarked messages: the column a database from before gains on open, and
// what the cross-chat query returns.
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
    await db.execute('ALTER TABLE messages DROP COLUMN bookmarked_at');
    await ChatDb.ensureMessageMarks(db);
    await ChatDb.ensureMessageMarks(db);
    final cols = await db.rawQuery('PRAGMA table_info(messages)');
    expect(cols.where((c) => c['name'] == 'bookmarked_at'), hasLength(1));
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
}
