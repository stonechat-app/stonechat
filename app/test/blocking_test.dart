// The block list's storage: its own table (anyone can be blocked, not only
// contacts), the one-time move out of the old contacts.blocked_at column, and
// backups — both the current `blocked` key and files written before it.
import 'package:flutter_test/flutter_test.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart';
import 'package:stonechat/core/backup.dart';
import 'package:stonechat/core/db.dart';

Future<Database> _freshDb() async {
  sqfliteFfiInit();
  final db = await databaseFactoryFfi.openDatabase(
    inMemoryDatabasePath,
    // Otherwise every test gets the same shared in-memory database back.
    options: OpenDatabaseOptions(singleInstance: false),
  );
  await ChatDb.createSchema(db);
  await ChatDb.ensureBlocked(db);
  return db;
}

Map<String, Object?> _contactRow(String id, {int? blockedAt}) => {
      'stonechat_id': id,
      'display_name': 'name-$id',
      'pubkey': 'pk-$id',
      'status': 'accepted',
      'created_at': 1,
      'blocked_at': ?blockedAt,
    };

void main() {
  test('a fresh database has the table, and no blocked_at on contacts',
      () async {
    final db = await _freshDb();
    final cols = await db.rawQuery('PRAGMA table_info(contacts)');
    expect(cols.map((c) => c['name']), isNot(contains('blocked_at')));

    final chat = ChatDb.forTesting(db);
    await chat.setBlocked('SC-STRANGER', 42);
    expect(await chat.blocked(), {'SC-STRANGER': 42});
    await chat.setBlocked('SC-STRANGER', null);
    expect(await chat.blocked(), isEmpty);
  });

  test('blocks on an old database move over exactly once', () async {
    final db = await _freshDb();
    // Recreate what a pre-move install looks like: the column, no table.
    await db.execute('DROP TABLE blocked');
    await db.execute('ALTER TABLE contacts ADD COLUMN blocked_at INTEGER');
    await db.insert('contacts', _contactRow('SC-A', blockedAt: 7));
    await db.insert('contacts', _contactRow('SC-B'));

    await ChatDb.ensureBlocked(db);
    final chat = ChatDb.forTesting(db);
    expect(await chat.blocked(), {'SC-A': 7});
    final left = await db.rawQuery(
      'SELECT COUNT(*) AS n FROM contacts WHERE blocked_at IS NOT NULL',
    );
    expect(left.first['n'], 0, reason: 'the old column is cleared as read');

    // An unblock must survive the next launch's check.
    await chat.setBlocked('SC-A', null);
    await ChatDb.ensureBlocked(db);
    expect(await chat.blocked(), isEmpty);
  });

  test('restore takes blocks from the new key and from old contact rows',
      () async {
    final chat = ChatDb.forTesting(await _freshDb());
    final result = await chat.importBackup(
      contacts: [
        _contactRow('SC-OLD', blockedAt: 5), // written before the move
        _contactRow('SC-OK'),
      ],
      groups: const [],
      groupMembers: const [],
      messages: const [],
      reactions: const [],
      blocked: const [
        {'stonechat_id': 'SC-MEMBER', 'blocked_at': 9}, // not a contact
      ],
      nowMs: 100,
    );
    expect(result.contactsAdded, 2,
        reason: 'a stray blocked_at key must not sink the contact row');
    expect(await chat.blocked(), {'SC-OLD': 5, 'SC-MEMBER': 9});
  });

  test('the backup payload carries the block list', () {
    final payload = BackupService.buildPayload(
      contacts: const [],
      groups: const [],
      groupMembers: const [],
      messages: const [],
      reactions: const [],
      blocked: const [
        {'stonechat_id': 'SC-X', 'blocked_at': 1},
      ],
      nowMs: 1,
    );
    expect(payload['blocked'], [
      {'stonechat_id': 'SC-X', 'blocked_at': 1},
    ]);
    expect((payload['counts'] as Map)['blocked'], 1);
  });
}
