/// Local history. This phone is the only place messages live — by design.
/// The file itself is SQLCipher-encrypted; the key lives in the platform
/// keystore next to the identity key, so a lifted filesystem image (or a
/// device backup) yields ciphertext, not conversations.
library;

import 'dart:io';

import 'package:path/path.dart' as p;
import 'package:sqflite_sqlcipher/sqflite.dart';

import '../models.dart';

class ChatDb {
  final Database _db;

  ChatDb._(this._db);

  /// Delete the on-disk database and any migration artifacts. Called during a
  /// fresh-install wipe (app_state): the SQLCipher key in the keystore is
  /// being discarded, so a persisted DB encrypted under the old key would be
  /// unopenable — drop it and let a clean one be created.
  static Future<void> deleteDatabaseFiles() async {
    final base = p.join(await getDatabasesPath(), 'zeon.db');
    for (final suffix in ['', '-wal', '-shm', '.enc', '.bak']) {
      final f = File('$base$suffix');
      if (await f.exists()) await f.delete();
    }
  }

  static Future<ChatDb> open(String password) async {
    final path = p.join(await getDatabasesPath(), 'zeon.db');
    await _encryptLegacyDb(path, password);
    final db = await openDatabase(
      path,
      password: password,
      version: 12,
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
        if (oldVersion < 8) {
          await db.execute('ALTER TABLE messages ADD COLUMN edited_at INTEGER');
          await db.execute(
              'ALTER TABLE messages ADD COLUMN deleted INTEGER NOT NULL DEFAULT 0');
          await db.execute(_createReceipts);
          await db.execute(_createReactions);
        }
        if (oldVersion < 9) {
          // The `< 4` branch above creates `groups` from the current
          // _createGroups, which already has pinned_at — guard the ALTER so
          // pre-v4 databases upgrading through both branches don't crash.
          for (final table in ['contacts', 'groups']) {
            final cols = await db.rawQuery('PRAGMA table_info($table)');
            if (!cols.any((c) => c['name'] == 'pinned_at')) {
              await db
                  .execute('ALTER TABLE $table ADD COLUMN pinned_at INTEGER');
            }
          }
        }
        if (oldVersion < 10) {
          await db.execute('ALTER TABLE messages ADD COLUMN expires_at INTEGER');
          // Same double-create guard as v9: pre-v4 upgrades get `groups`
          // from the current _createGroups, which already has the columns.
          for (final table in ['contacts', 'groups']) {
            final cols = await db.rawQuery('PRAGMA table_info($table)');
            if (!cols.any((c) => c['name'] == 'expire_timer_ms')) {
              await db.execute('ALTER TABLE $table '
                  'ADD COLUMN expire_timer_ms INTEGER NOT NULL DEFAULT 0');
              await db.execute('ALTER TABLE $table '
                  'ADD COLUMN expire_timer_at INTEGER NOT NULL DEFAULT 0');
            }
          }
          await db.execute(
              'CREATE INDEX idx_messages_expires ON messages(expires_at)');
        }
        if (oldVersion < 11) {
          await db.execute('ALTER TABLE messages ADD COLUMN file_name TEXT');
          await db.execute('ALTER TABLE messages ADD COLUMN reply_to_id TEXT');
          await db
              .execute('ALTER TABLE messages ADD COLUMN reply_to_sender TEXT');
          await db
              .execute('ALTER TABLE messages ADD COLUMN reply_to_preview TEXT');
        }
        if (oldVersion < 12) {
          await db.execute('ALTER TABLE contacts ADD COLUMN blocked_at INTEGER');
          // Same double-create guard as v9/v10: pre-v4 upgrades get `groups`
          // from the current _createGroups, which already has the columns.
          for (final table in ['contacts', 'groups']) {
            final cols = await db.rawQuery('PRAGMA table_info($table)');
            if (!cols.any((c) => c['name'] == 'muted_until')) {
              await db
                  .execute('ALTER TABLE $table ADD COLUMN muted_until INTEGER');
              await db
                  .execute('ALTER TABLE $table ADD COLUMN archived_at INTEGER');
            }
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
            created_at     INTEGER NOT NULL,
            pinned_at      INTEGER,
            expire_timer_ms INTEGER NOT NULL DEFAULT 0,
            expire_timer_at INTEGER NOT NULL DEFAULT 0,
            blocked_at     INTEGER,
            muted_until    INTEGER,
            archived_at    INTEGER
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
            file_name   TEXT,
            sent_at     INTEGER NOT NULL,
            status      TEXT NOT NULL,
            edited_at   INTEGER,
            deleted     INTEGER NOT NULL DEFAULT 0,
            expires_at  INTEGER,
            reply_to_id      TEXT,
            reply_to_sender  TEXT,
            reply_to_preview TEXT
          )
        ''');
        await db.execute(
            'CREATE INDEX idx_messages_contact ON messages(contact_id, sent_at)');
        await db.execute(
            'CREATE INDEX idx_messages_expires ON messages(expires_at)');
        await db.execute(_createGroups);
        await db.execute(_createGroupMembers);
        await db.execute(_createGroupOutbox);
        await db.execute(_createSessions);
        await db.execute(_createPrekeys);
        await db.execute(_createReceipts);
        await db.execute(_createReactions);
      },
    );
    return ChatDb._(db);
  }

  /// One-time migration: installs from before DB encryption hold zeon.db as
  /// plaintext SQLite. Rewrite it through SQLCipher's own export (the
  /// canonical encrypt-in-place flow) before the encrypted open.
  static Future<void> _encryptLegacyDb(String path, String password) async {
    final file = File(path);
    final encFile = File('$path.enc');
    final bakFile = File('$path.bak');
    if (!await file.exists()) {
      if (await encFile.exists() && await bakFile.exists()) {
        // Crashed between the final two renames: the export had finished
        // (the original is only moved aside after it), so promote it.
        await encFile.rename(path);
      } else if (await bakFile.exists()) {
        await bakFile.rename(path); // resume: migrate it again below
      } else {
        return; // fresh install — nothing to migrate
      }
    }
    if (await bakFile.exists()) await bakFile.delete();
    // Encrypted databases don't carry the plaintext magic in their header.
    final raf = await file.open();
    final header = await raf.read(15);
    await raf.close();
    if (String.fromCharCodes(header) != 'SQLite format 3') return;

    final encPath = '$path.enc';
    await deleteDatabase(encPath); // stale half-migration from a crash
    final plain = await openDatabase(path); // no password → plaintext open
    try {
      await plain
          .execute('ATTACH DATABASE ? AS encrypted KEY ?', [encPath, password]);
      await plain.rawQuery("SELECT sqlcipher_export('encrypted')");
      final version = await plain.getVersion();
      await plain.execute('PRAGMA encrypted.user_version = $version');
      await plain.execute('DETACH DATABASE encrypted');
    } finally {
      await plain.close();
    }
    // Swap with a backup in between: a crash here leaves either the .bak or
    // the new file, never nothing.
    final backupPath = '$path.bak';
    await file.rename(backupPath);
    await File(encPath).rename(path);
    await File(backupPath).delete();
  }

  static const _createGroups = '''
    CREATE TABLE groups (
      id         TEXT PRIMARY KEY,
      name       TEXT NOT NULL,
      admin_id   TEXT NOT NULL,
      version    INTEGER NOT NULL,
      created_at INTEGER NOT NULL,
      pinned_at  INTEGER,
      expire_timer_ms INTEGER NOT NULL DEFAULT 0,
      expire_timer_at INTEGER NOT NULL DEFAULT 0,
      muted_until INTEGER,
      archived_at INTEGER
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

  // One forward-secret ratchet session per peer (PROTOCOL.md). The state
  // JSON holds the session's secret keys; it lives beside the plaintext
  // history it protects, on this phone only.
  static const _createSessions = '''
    CREATE TABLE sessions (
      peer_id TEXT PRIMARY KEY,
      state   TEXT NOT NULL
    )
  ''';

  // Per-peer delivery/read receipts for our outgoing messages. DMs collapse
  // straight into messages.status; group messages need one row per member to
  // know when *everyone* has the message.
  static const _createReceipts = '''
    CREATE TABLE receipts (
      message_id TEXT NOT NULL,
      peer_id    TEXT NOT NULL,
      kind       TEXT NOT NULL,      -- 'delivered' | 'read'
      at         INTEGER NOT NULL,
      PRIMARY KEY (message_id, peer_id)
    )
  ''';

  // Emoji reactions, one per (message, reactor) — a new reaction replaces the
  // old one, an empty emoji clears it. peer_id is the reactor's Zeon ID
  // (our own for reactions we set).
  static const _createReactions = '''
    CREATE TABLE reactions (
      message_id TEXT NOT NULL,
      peer_id    TEXT NOT NULL,
      emoji      TEXT NOT NULL,
      at         INTEGER NOT NULL,
      PRIMARY KEY (message_id, peer_id)
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

  /// Drop every conversation, contact, group, session and prekey. Used by
  /// identity reset — the SQLCipher key is rotated separately by the caller.
  Future<void> wipe() async {
    await _db.transaction((tx) async {
      for (final table in [
        'messages',
        'contacts',
        'groups',
        'group_members',
        'group_outbox',
        'sessions',
        'prekeys',
        'receipts',
        'reactions',
      ]) {
        await tx.delete(table);
      }
    });
  }

  // -- contacts ---------------------------------------------------------------

  Future<List<Contact>> contacts() async {
    final rows = await _db.query('contacts', orderBy: 'created_at');
    return rows.map(Contact.fromRow).toList();
  }

  Future<void> upsertContact(Contact c) async {
    await _db.insert('contacts', c.toRow(),
        conflictAlgorithm: ConflictAlgorithm.replace);
  }

  Future<void> setContactPinned(String zeonId, int? pinnedAt) async {
    await _db.update('contacts', {'pinned_at': pinnedAt},
        where: 'zeon_id = ?', whereArgs: [zeonId]);
  }

  Future<void> deleteContact(String zeonId) async {
    await _purgeConversationExtras(zeonId);
    await _db.delete('messages', where: 'contact_id = ?', whereArgs: [zeonId]);
    await _db.delete('contacts', where: 'zeon_id = ?', whereArgs: [zeonId]);
  }

  Future<void> _purgeConversationExtras(String contactId) async {
    for (final table in ['receipts', 'reactions']) {
      await _db.execute(
          'DELETE FROM $table WHERE message_id IN '
          '(SELECT id FROM messages WHERE contact_id = ?)',
          [contactId]);
    }
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

  /// [editedAt] is null when rewriting a still-pending message — the new
  /// text ships with the original send, so nothing was "edited".
  Future<void> setMessageText(String id, String text, int? editedAt) async {
    await _db.update('messages', {'text': text, 'edited_at': ?editedAt},
        where: 'id = ?', whereArgs: [id]);
  }

  /// Delete-for-everyone tombstone: the row stays (so the conversation shows
  /// "message deleted"), the content goes.
  Future<void> tombstoneMessage(String id) async {
    await _db.update(
        'messages',
        {'text': '', 'media_path': null, 'deleted': 1},
        where: 'id = ?',
        whereArgs: [id]);
  }

  /// Delete-for-me: the row itself goes.
  Future<void> deleteMessage(String id) async {
    await _db.delete('messages', where: 'id = ?', whereArgs: [id]);
    await _db.delete('receipts', where: 'message_id = ?', whereArgs: [id]);
    await _db.delete('reactions', where: 'message_id = ?', whereArgs: [id]);
  }

  // -- receipts -----------------------------------------------------------------

  /// Record a peer's receipt; read replaces delivered, never the reverse.
  Future<void> upsertReceipt(
      String messageId, String peerId, String kind, int at) async {
    await _db.execute('''
      INSERT INTO receipts (message_id, peer_id, kind, at)
      VALUES (?, ?, ?, ?)
      ON CONFLICT (message_id, peer_id) DO UPDATE SET kind = excluded.kind,
        at = excluded.at
        WHERE receipts.kind = 'delivered' AND excluded.kind = 'read'
    ''', [messageId, peerId, kind, at]);
  }

  /// How many distinct peers have at least delivered / read this message.
  /// (A read receipt implies delivery.)
  Future<({int delivered, int read})> receiptCounts(String messageId) async {
    final rows = await _db.rawQuery(
        'SELECT kind, COUNT(*) AS n FROM receipts WHERE message_id = ? GROUP BY kind',
        [messageId]);
    var delivered = 0, read = 0;
    for (final r in rows) {
      final n = r['n'] as int;
      if (r['kind'] == ReceiptKind.read) read += n;
      delivered += n;
    }
    return (delivered: delivered, read: read);
  }

  // -- reactions ----------------------------------------------------------------

  Future<void> setReaction(
      String messageId, String peerId, String emoji, int at) async {
    if (emoji.isEmpty) {
      await _db.delete('reactions',
          where: 'message_id = ? AND peer_id = ?',
          whereArgs: [messageId, peerId]);
    } else {
      await _db.insert(
          'reactions',
          {'message_id': messageId, 'peer_id': peerId, 'emoji': emoji, 'at': at},
          conflictAlgorithm: ConflictAlgorithm.replace);
    }
  }

  Future<void> clearReactions(String messageId) async {
    await _db.delete('reactions',
        where: 'message_id = ?', whereArgs: [messageId]);
  }

  /// All reactions on a conversation's messages: message id → (reactor → emoji).
  Future<Map<String, Map<String, String>>> reactionsFor(
      String contactId) async {
    final rows = await _db.rawQuery('''
      SELECT r.message_id, r.peer_id, r.emoji FROM reactions r
      JOIN messages m ON m.id = r.message_id
      WHERE m.contact_id = ?
    ''', [contactId]);
    final out = <String, Map<String, String>>{};
    for (final r in rows) {
      (out[r['message_id'] as String] ??= {})[r['peer_id'] as String] =
          r['emoji'] as String;
    }
    return out;
  }

  Future<List<Message>> pendingMessages() async {
    // deleted = 0: a tombstoned pending message must never leave the phone.
    final rows = await _db.query('messages',
        where: 'status = ? AND outgoing = 1 AND deleted = 0',
        whereArgs: [MessageStatus.pending],
        orderBy: 'sent_at');
    return rows.map(Message.fromRow).toList();
  }

  /// Disappearing messages past their expiry — full rows, so the caller can
  /// remove media files before deleting.
  Future<List<Message>> expiredMessages(int now) async {
    final rows = await _db.query('messages',
        where: 'expires_at IS NOT NULL AND expires_at <= ?', whereArgs: [now]);
    return rows.map(Message.fromRow).toList();
  }

  /// The soonest future expiry, or null when nothing is set to disappear.
  Future<int?> nextExpiryAt() async {
    final rows = await _db.rawQuery(
        'SELECT MIN(expires_at) AS t FROM messages WHERE expires_at IS NOT NULL');
    return rows.first['t'] as int?;
  }

  // -- groups -------------------------------------------------------------------

  Future<List<Group>> groups() async {
    final rows = await _db.query('groups', orderBy: 'created_at');
    return rows.map(Group.fromRow).toList();
  }

  Future<void> setGroupPinned(String id, int? pinnedAt) async {
    await _db.update('groups', {'pinned_at': pinnedAt},
        where: 'id = ?', whereArgs: [id]);
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
    await _purgeConversationExtras(groupId);
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

  /// Stop owing every remaining copy (the message was deleted).
  Future<void> clearOutboxMessage(String messageId) async {
    await _db.delete('group_outbox',
        where: 'message_id = ?', whereArgs: [messageId]);
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
