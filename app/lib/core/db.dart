/// Local history. This phone is the only place messages live — by design.
library;

import 'package:path/path.dart' as p;
import 'package:sqflite/sqflite.dart';

import '../models.dart';

class ChatDb {
  final Database _db;

  ChatDb._(this._db);

  static Future<ChatDb> open() async {
    final path = p.join(await getDatabasesPath(), 'zeon.db');
    final db = await openDatabase(
      path,
      version: 4,
      onUpgrade: (db, oldVersion, _) async {
        if (oldVersion < 2) {
          await db.execute('ALTER TABLE contacts ADD COLUMN handle TEXT');
        }
        if (oldVersion < 3) {
          await db.execute(
              "ALTER TABLE messages ADD COLUMN kind TEXT NOT NULL DEFAULT 'text'");
          await db.execute('ALTER TABLE messages ADD COLUMN media_path TEXT');
          await db.execute('ALTER TABLE messages ADD COLUMN duration_ms INTEGER');
        }
        if (oldVersion < 4) {
          await db.execute('ALTER TABLE messages ADD COLUMN sender_id TEXT');
          await db.execute(_createGroups);
          await db.execute(_createGroupMembers);
          await db.execute(_createGroupOutbox);
        }
      },
      onCreate: (db, _) async {
        await db.execute('''
          CREATE TABLE contacts (
            zeon_id        TEXT PRIMARY KEY,
            display_name   TEXT NOT NULL,
            handle         TEXT,
            pubkey         TEXT NOT NULL,
            status         TEXT NOT NULL,
            server_address TEXT,
            created_at     INTEGER NOT NULL
          )
        ''');
        await db.execute('''
          CREATE TABLE messages (
            id          TEXT PRIMARY KEY,
            contact_id  TEXT NOT NULL REFERENCES contacts(zeon_id),
            outgoing    INTEGER NOT NULL,
            text        TEXT NOT NULL,
            kind        TEXT NOT NULL DEFAULT 'text',
            media_path  TEXT,
            duration_ms INTEGER,
            sent_at     INTEGER NOT NULL,
            status      TEXT NOT NULL
          )
        ''');
        await db.execute(
            'CREATE INDEX idx_messages_contact ON messages(contact_id, sent_at)');
        await db.execute(_createGroups);
        await db.execute(_createGroupMembers);
        await db.execute(_createGroupOutbox);
      },
    );
    return ChatDb._(db);
  }

  static const _createGroups = '''
    CREATE TABLE groups (
      id         TEXT PRIMARY KEY,
      name       TEXT NOT NULL,
      admin_id   TEXT NOT NULL,
      version    INTEGER NOT NULL,
      created_at INTEGER NOT NULL
    )
  ''';

  static const _createGroupMembers = '''
    CREATE TABLE group_members (
      group_id       TEXT NOT NULL,
      zeon_id        TEXT NOT NULL,
      pubkey         TEXT NOT NULL,
      display_name   TEXT NOT NULL,
      server_address TEXT,
      PRIMARY KEY (group_id, zeon_id)
    )
  ''';

  // Outgoing group messages not yet accepted by every member's mailbox:
  // one row per (message, member) still owed a delivery.
  static const _createGroupOutbox = '''
    CREATE TABLE group_outbox (
      message_id TEXT NOT NULL,
      group_id   TEXT NOT NULL,
      member_id  TEXT NOT NULL,
      PRIMARY KEY (message_id, member_id)
    )
  ''';

  // -- contacts ---------------------------------------------------------------

  Future<List<Contact>> contacts() async {
    final rows = await _db.query('contacts', orderBy: 'created_at');
    return rows.map(Contact.fromRow).toList();
  }

  Future<void> upsertContact(Contact c) async {
    await _db.insert('contacts', c.toRow(),
        conflictAlgorithm: ConflictAlgorithm.replace);
  }

  Future<void> deleteContact(String zeonId) async {
    await _db.delete('messages', where: 'contact_id = ?', whereArgs: [zeonId]);
    await _db.delete('contacts', where: 'zeon_id = ?', whereArgs: [zeonId]);
  }

  // -- messages ---------------------------------------------------------------

  Future<List<Message>> messagesFor(String contactId) async {
    final rows = await _db.query('messages',
        where: 'contact_id = ?', whereArgs: [contactId], orderBy: 'sent_at');
    return rows.map(Message.fromRow).toList();
  }

  Future<void> insertMessage(Message m) async {
    await _db.insert('messages', m.toRow(),
        conflictAlgorithm: ConflictAlgorithm.ignore);
  }

  Future<void> setMessageStatus(String id, String status) async {
    await _db.update('messages', {'status': status},
        where: 'id = ?', whereArgs: [id]);
  }

  Future<List<Message>> pendingMessages() async {
    final rows = await _db.query('messages',
        where: 'status = ? AND outgoing = 1',
        whereArgs: [MessageStatus.pending],
        orderBy: 'sent_at');
    return rows.map(Message.fromRow).toList();
  }

  // -- groups -------------------------------------------------------------------

  Future<List<Group>> groups() async {
    final rows = await _db.query('groups', orderBy: 'created_at');
    return rows.map(Group.fromRow).toList();
  }

  Future<void> upsertGroup(Group g) async {
    await _db.insert('groups', g.toRow(),
        conflictAlgorithm: ConflictAlgorithm.replace);
  }

  Future<List<GroupMember>> membersOf(String groupId) async {
    final rows = await _db
        .query('group_members', where: 'group_id = ?', whereArgs: [groupId]);
    return rows.map(GroupMember.fromRow).toList();
  }

  Future<void> replaceMembers(String groupId, List<GroupMember> members) async {
    await _db.transaction((tx) async {
      await tx.delete('group_members',
          where: 'group_id = ?', whereArgs: [groupId]);
      for (final m in members) {
        await tx.insert('group_members', m.toRow(),
            conflictAlgorithm: ConflictAlgorithm.replace);
      }
    });
  }

  Future<void> updateMember(GroupMember m) async {
    await _db.insert('group_members', m.toRow(),
        conflictAlgorithm: ConflictAlgorithm.replace);
  }

  Future<void> deleteGroup(String groupId) async {
    await _db.delete('messages', where: 'contact_id = ?', whereArgs: [groupId]);
    await _db.delete('group_outbox', where: 'group_id = ?', whereArgs: [groupId]);
    await _db.delete('group_members', where: 'group_id = ?', whereArgs: [groupId]);
    await _db.delete('groups', where: 'id = ?', whereArgs: [groupId]);
  }

  // -- group outbox ---------------------------------------------------------------

  Future<void> addOutbox(String messageId, String groupId, List<String> memberIds) async {
    await _db.transaction((tx) async {
      for (final memberId in memberIds) {
        await tx.insert(
            'group_outbox',
            {'message_id': messageId, 'group_id': groupId, 'member_id': memberId},
            conflictAlgorithm: ConflictAlgorithm.ignore);
      }
    });
  }

  Future<void> clearOutbox(String messageId, String memberId) async {
    await _db.delete('group_outbox',
        where: 'message_id = ? AND member_id = ?', whereArgs: [messageId, memberId]);
  }

  Future<int> outboxRemaining(String messageId) async {
    final rows = await _db.query('group_outbox',
        where: 'message_id = ?', whereArgs: [messageId]);
    return rows.length;
  }

  Future<Map<String, List<String>>> pendingOutbox() async {
    final rows = await _db.query('group_outbox');
    final byMessage = <String, List<String>>{};
    for (final r in rows) {
      (byMessage[r['message_id'] as String] ??= []).add(r['member_id'] as String);
    }
    return byMessage;
  }

  Future<Message?> messageById(String id) async {
    final rows =
        await _db.query('messages', where: 'id = ?', whereArgs: [id], limit: 1);
    return rows.isEmpty ? null : Message.fromRow(rows.first);
  }

  Future<Message?> lastMessageFor(String contactId) async {
    final rows = await _db.query('messages',
        where: 'contact_id = ?',
        whereArgs: [contactId],
        orderBy: 'sent_at DESC',
        limit: 1);
    return rows.isEmpty ? null : Message.fromRow(rows.first);
  }
}
