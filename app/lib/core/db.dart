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
      version: 7,
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
        if (oldVersion < 5) {
          await db.execute(_createSessions);
          await db.execute(_createPrekeys);
        }
        if (oldVersion < 6) {
          await db.execute('ALTER TABLE contacts ADD COLUMN tls_fp TEXT');
          await db.execute('ALTER TABLE group_members ADD COLUMN tls_fp TEXT');
        }
        if (oldVersion < 7) {
          // Fresh installs at v4–v6 got a `messages` table without sender_id:
          // the column only existed on this upgrade path, not in onCreate.
          final cols = await db.rawQuery('PRAGMA table_info(messages)');
          if (!cols.any((c) => c['name'] == 'sender_id')) {
            await db.execute('ALTER TABLE messages ADD COLUMN sender_id TEXT');
          }
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
            tls_fp         TEXT,
            created_at     INTEGER NOT NULL
          )
        ''');
        await db.execute('''
          CREATE TABLE messages (
            id          TEXT PRIMARY KEY,
            contact_id  TEXT NOT NULL REFERENCES contacts(zeon_id),
            sender_id   TEXT,
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
        await db.execute(_createSessions);
        await db.execute(_createPrekeys);
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
      tls_fp         TEXT,
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

  // One forward-secret ratchet session per peer (PROTOCOL.md v2). The state
  // JSON holds the session's secret keys; it lives beside the plaintext
  // history it protects, on this phone only.
  static const _createSessions = '''
    CREATE TABLE sessions (
      peer_id TEXT PRIMARY KEY,
      state   TEXT NOT NULL
    )
  ''';

  // Our prekey private halves. Public halves are parked on our mailbox
  // (every publish uploads the full stock; the mailbox replaces its store).
  // `published` is vestigial, kept to avoid a schema migration.
  static const _createPrekeys = '''
    CREATE TABLE prekeys (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      kind       TEXT NOT NULL,      -- 'spk' | 'opk'
      pub        TEXT NOT NULL,
      sec        TEXT NOT NULL,
      published  INTEGER NOT NULL DEFAULT 0,
      created_at INTEGER NOT NULL
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

  // -- ratchet sessions -------------------------------------------------------

  Future<String?> sessionState(String peerId) async {
    final rows = await _db.query('sessions',
        where: 'peer_id = ?', whereArgs: [peerId], limit: 1);
    return rows.isEmpty ? null : rows.first['state'] as String;
  }

  Future<void> saveSession(String peerId, String stateJson) async {
    await _db.insert('sessions', {'peer_id': peerId, 'state': stateJson},
        conflictAlgorithm: ConflictAlgorithm.replace);
  }

  Future<void> deleteSession(String peerId) async {
    await _db.delete('sessions', where: 'peer_id = ?', whereArgs: [peerId]);
  }

  // -- prekey private halves ----------------------------------------------------

  Future<int> insertPrekey(String kind, String pubB64, String secB64) async {
    return _db.insert('prekeys', {
      'kind': kind,
      'pub': pubB64,
      'sec': secB64,
      'published': 0,
      'created_at': DateTime.now().millisecondsSinceEpoch,
    });
  }

  Future<Map<String, Object?>?> prekeyById(int id, String kind) async {
    final rows = await _db.query('prekeys',
        where: 'id = ? AND kind = ?', whereArgs: [id, kind], limit: 1);
    return rows.isEmpty ? null : rows.first;
  }

  /// Newest signed prekey (the one we currently publish).
  Future<Map<String, Object?>?> currentSpk() async {
    final rows = await _db.query('prekeys',
        where: "kind = 'spk'", orderBy: 'id DESC', limit: 1);
    return rows.isEmpty ? null : rows.first;
  }

  Future<List<Map<String, Object?>>> opks() =>
      _db.query('prekeys', where: "kind = 'opk'", orderBy: 'id');

  Future<void> deletePrekey(int id) async {
    await _db.delete('prekeys', where: 'id = ?', whereArgs: [id]);
  }

  /// Drop retired signed prekeys (keep the newest two: current + previous,
  /// so in-flight initial messages keep working across a rotation).
  Future<void> pruneSpks() async {
    await _db.execute('''
      DELETE FROM prekeys WHERE kind = 'spk' AND id NOT IN (
        SELECT id FROM prekeys WHERE kind = 'spk' ORDER BY id DESC LIMIT 2
      )
    ''');
  }
}
