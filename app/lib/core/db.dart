/// Local history. This phone is the only place messages live — by design.
/// The file itself is SQLCipher-encrypted; the key lives in the platform
/// keystore next to the identity key, so a lifted filesystem image (or a
/// device backup) yields ciphertext, not conversations.
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter/services.dart' show MethodChannel;
import 'package:path/path.dart' as p;
import 'package:sqflite_sqlcipher/sqflite.dart';

import '../models.dart';

const _native = MethodChannel('stonechat/native');

/// On iOS the DB lives in the shared app-group container so the
/// notification service extension can open it from its own process
/// (group.app.stonechat.mobile — AppDelegate.swift is the other holder of
/// that constant). Elsewhere: the platform's default database directory.
Future<String> _databaseDir() async {
  if (Platform.isIOS) {
    try {
      final path = await _native.invokeMethod<String>('appGroupPath');
      if (path != null) return path;
    } catch (_) {
      // Channel unavailable (tests) — fall through.
    }
  }
  return getDatabasesPath();
}

class ChatDb {
  final Database _db;

  ChatDb._(this._db);

  /// Delete the on-disk database. Called during a fresh-install wipe
  /// (app_state): the SQLCipher key in the keystore is being discarded, so a
  /// persisted DB encrypted under the old key would be unopenable — drop it
  /// and let a clean one be created.
  static Future<void> deleteDatabaseFiles() async {
    final base = p.join(await _databaseDir(), 'stonechat.db');
    for (final suffix in ['', '-wal', '-shm']) {
      final f = File('$base$suffix');
      if (await f.exists()) await f.delete();
    }
  }

  static Future<ChatDb> open(String password) async {
    final path = p.join(await _databaseDir(), 'stonechat.db');
    final db = await openDatabase(
      path,
      password: password,
      // Pre-launch: no installed base, so there is no migration chain. The
      // schema below is simply the schema. An older database is wiped
      // (deleteDatabaseFiles) rather than upgraded.
      version: 1,
      onCreate: (db, _) async {
        await db.execute('''
          CREATE TABLE contacts (
            stonechat_id        TEXT PRIMARY KEY,
            display_name   TEXT NOT NULL,
            pubkey         TEXT NOT NULL,
            pq_pk          TEXT,
            status         TEXT NOT NULL,
            mailbox_address TEXT,
            tls_fp         TEXT,
            hub            TEXT,
            created_at     INTEGER NOT NULL,
            pinned_at      INTEGER,
            expire_timer_ms INTEGER NOT NULL DEFAULT 0,
            expire_timer_at INTEGER NOT NULL DEFAULT 0,
            blocked_at     INTEGER,
            muted_until    INTEGER,
            archived_at    INTEGER,
            avatar         BLOB,
            profile_at     INTEGER NOT NULL DEFAULT 0,
            devices_v      INTEGER NOT NULL DEFAULT 0,
            bundle_token   TEXT
          )
        ''');
        await db.execute('''
          CREATE TABLE messages (
            id          TEXT PRIMARY KEY,
            contact_id  TEXT NOT NULL REFERENCES contacts(stonechat_id),
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
            reply_to_preview TEXT,
            blob             TEXT,
            fail_reason      TEXT,
            attempts         INTEGER NOT NULL DEFAULT 0,
            last_attempt_at  INTEGER
          )
        ''');
        await db.execute(
          'CREATE INDEX idx_messages_contact ON messages(contact_id, sent_at)',
        );
        await db.execute(
          'CREATE INDEX idx_messages_expires ON messages(expires_at)',
        );
        await db.execute(_createGroups);
        await db.execute(_createGroupMembers);
        await db.execute(_createGroupOutbox);
        await db.execute(_createSessions);
        await db.execute(_createPrekeys);
        await db.execute(_createReceipts);
        await db.execute(_createReactions);
        await db.execute(_createKv);
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
      stonechat_id        TEXT NOT NULL,
      pubkey         TEXT NOT NULL,
      pq_pk          TEXT,
      display_name   TEXT NOT NULL,
      mailbox_address TEXT,
      tls_fp         TEXT,
      bundle_token   TEXT,
      PRIMARY KEY (group_id, stonechat_id)
    )
  ''';

  // Outgoing group messages not yet accepted by every member's mailbox:
  // one row per (message, member) still owed a delivery.
  static const _createGroupOutbox = '''
    CREATE TABLE group_outbox (
      message_id TEXT NOT NULL,
      group_id   TEXT NOT NULL,
      member_id  TEXT NOT NULL,
      device_id  INTEGER NOT NULL DEFAULT $primaryDevice,
      PRIMARY KEY (message_id, member_id, device_id)
    )
  ''';

  /// The device every peer has: provisioning mints one credential and its
  /// holder is device 1. Linked devices are numbered from 2.
  static const primaryDevice = 1;

  // One forward-secret ratchet session per (peer, device) — PROTOCOL.md. A
  // double ratchet is mutable state that advances on every message, so two
  // devices cannot share one. The state JSON holds the session's secret keys;
  // it lives beside the plaintext history it protects, on this phone only.

  static const _createSessions = '''
    CREATE TABLE sessions (
      peer_id   TEXT NOT NULL,
      device_id INTEGER NOT NULL DEFAULT $primaryDevice,
      state     TEXT NOT NULL,
      PRIMARY KEY (peer_id, device_id)
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
  // old one, an empty emoji clears it. peer_id is the reactor's Stonechat ID
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

  // Tiny key-value store for singletons that belong inside the encrypted DB
  // rather than the platform keystore — the owner's own avatar is too big
  // for a comfortable keychain item and must be ciphertext at rest.
  static const _createKv = '''
    CREATE TABLE kv (
      k TEXT PRIMARY KEY,
      v BLOB
    )
  ''';

  // Our prekey private halves. Public halves are parked on our mailbox
  // (every publish uploads the full stock; the mailbox replaces its store).
  static const _createPrekeys = '''
    CREATE TABLE prekeys (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      kind       TEXT NOT NULL,      -- 'spk' | 'opk'
      pub        TEXT NOT NULL,
      sec        TEXT NOT NULL,
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
        'kv',
      ]) {
        await tx.delete(table);
      }
    });
  }

  // -- kv -----------------------------------------------------------------------

  Future<Uint8List?> kvGet(String key) async {
    final rows = await _db.query(
      'kv',
      where: 'k = ?',
      whereArgs: [key],
      limit: 1,
    );
    final v = rows.isEmpty ? null : rows.first['v'];
    return v == null ? null : Uint8List.fromList(v as List<int>);
  }

  Future<void> kvPut(String key, Uint8List? value) async {
    if (value == null) {
      await _db.delete('kv', where: 'k = ?', whereArgs: [key]);
    } else {
      await _db.insert('kv', {
        'k': key,
        'v': value,
      }, conflictAlgorithm: ConflictAlgorithm.replace);
    }
  }

  // -- contacts ---------------------------------------------------------------

  Future<List<Contact>> contacts() async {
    final rows = await _db.query('contacts', orderBy: 'created_at');
    return rows.map(Contact.fromRow).toList();
  }

  Future<void> upsertContact(Contact c) async {
    await _db.insert(
      'contacts',
      c.toRow(),
      conflictAlgorithm: ConflictAlgorithm.replace,
    );
  }

  Future<void> setContactPinned(String stonechatId, int? pinnedAt) async {
    await _db.update(
      'contacts',
      {'pinned_at': pinnedAt},
      where: 'stonechat_id = ?',
      whereArgs: [stonechatId],
    );
  }

  Future<void> deleteContact(String stonechatId) async {
    await _purgeConversationExtras(stonechatId);
    await _db.delete(
      'messages',
      where: 'contact_id = ?',
      whereArgs: [stonechatId],
    );
    await _db.delete(
      'contacts',
      where: 'stonechat_id = ?',
      whereArgs: [stonechatId],
    );
  }

  Future<void> _purgeConversationExtras(String contactId) async {
    for (final table in ['receipts', 'reactions']) {
      await _db.execute(
        'DELETE FROM $table WHERE message_id IN '
        '(SELECT id FROM messages WHERE contact_id = ?)',
        [contactId],
      );
    }
  }

  // -- messages ---------------------------------------------------------------

  Future<List<Message>> messagesFor(String contactId) async {
    final rows = await _db.query(
      'messages',
      where: 'contact_id = ?',
      whereArgs: [contactId],
      orderBy: 'sent_at',
    );
    return rows.map(Message.fromRow).toList();
  }

  Future<void> insertMessage(Message m) async {
    await _db.insert(
      'messages',
      m.toRow(),
      conflictAlgorithm: ConflictAlgorithm.ignore,
    );
  }

  Future<void> setMessageStatus(String id, String status) async {
    await _db.update(
      'messages',
      {'status': status},
      where: 'id = ?',
      whereArgs: [id],
    );
  }

  /// Persist the outcome of a send attempt: the status it left the message in,
  /// why, and the backoff bookkeeping. One write per attempt.
  Future<void> saveSendAttempt(Message m) async {
    await _db.update(
      'messages',
      {
        'status': m.status,
        'fail_reason': m.failReason,
        'attempts': m.attempts,
        'last_attempt_at': m.lastAttemptAt,
      },
      where: 'id = ?',
      whereArgs: [m.id],
    );
  }

  /// Remember (or forget) the shared blob behind an outgoing group-media
  /// fan-out. Null once the blob has been deleted from our mailbox — the key
  /// has no reason to outlive the ciphertext it opens.
  Future<void> setMessageBlob(String id, SharedBlob? blob) async {
    await _db.update(
      'messages',
      {'blob': blob == null ? null : jsonEncode(blob.toJson())},
      where: 'id = ?',
      whereArgs: [id],
    );
  }

  /// [editedAt] is null when rewriting a still-pending message — the new
  /// text ships with the original send, so nothing was "edited".
  Future<void> setMessageText(String id, String text, int? editedAt) async {
    await _db.update(
      'messages',
      {'text': text, 'edited_at': ?editedAt},
      where: 'id = ?',
      whereArgs: [id],
    );
  }

  /// Delete-for-everyone tombstone: the row stays (so the conversation shows
  /// "message deleted"), the content goes.
  Future<void> tombstoneMessage(String id) async {
    await _db.update(
      'messages',
      {'text': '', 'media_path': null, 'deleted': 1},
      where: 'id = ?',
      whereArgs: [id],
    );
  }

  /// Delete-for-me: the row itself goes.
  Future<void> deleteMessage(String id) async {
    await _db.delete('messages', where: 'id = ?', whereArgs: [id]);
    await _db.delete('receipts', where: 'message_id = ?', whereArgs: [id]);
    await _db.delete('reactions', where: 'message_id = ?', whereArgs: [id]);
  }

  /// Clear one conversation's history, keeping the conversation itself.
  ///
  /// The contact row is deliberately untouched: clearing a chat must not cost
  /// the session, the display name or the peer's device list, or "clear" would
  /// quietly mean "start a new relationship with this person".
  ///
  /// Returns the media paths that were referenced, so the caller can delete
  /// the files: the rows are the only record of where they live, and dropping
  /// them first would leave the media orphaned on disk forever — a "clear"
  /// that leaves the photos behind is the failure this returns them to avoid.
  Future<List<String>> clearConversation(String conversationId) async {
    final rows = await _db.query(
      'messages',
      columns: ['id', 'media_path'],
      where: 'contact_id = ?',
      whereArgs: [conversationId],
    );
    final ids = [for (final r in rows) r['id'] as String];
    final media = [
      for (final r in rows)
        if (r['media_path'] != null) r['media_path'] as String,
    ];
    await _db.transaction((txn) async {
      for (final chunk in _chunks(ids)) {
        final marks = List.filled(chunk.length, '?').join(',');
        await txn.delete('receipts',
            where: 'message_id IN ($marks)', whereArgs: chunk);
        await txn.delete('reactions',
            where: 'message_id IN ($marks)', whereArgs: chunk);
      }
      await txn.delete('messages',
          where: 'contact_id = ?', whereArgs: [conversationId]);
    });
    return media;
  }

  /// SQLite caps variables per statement (999 by default), and a long-running
  /// conversation passes that easily.
  static Iterable<List<String>> _chunks(List<String> ids, [int size = 500]) sync* {
    for (var i = 0; i < ids.length; i += size) {
      yield ids.sublist(i, i + size > ids.length ? ids.length : i + size);
    }
  }

  // -- receipts -----------------------------------------------------------------

  /// Record a peer's receipt; read replaces delivered, never the reverse.
  Future<void> upsertReceipt(
    String messageId,
    String peerId,
    String kind,
    int at,
  ) async {
    await _db.execute(
      '''
      INSERT INTO receipts (message_id, peer_id, kind, at)
      VALUES (?, ?, ?, ?)
      ON CONFLICT (message_id, peer_id) DO UPDATE SET kind = excluded.kind,
        at = excluded.at
        WHERE receipts.kind = 'delivered' AND excluded.kind = 'read'
    ''',
      [messageId, peerId, kind, at],
    );
  }

  /// How many distinct peers have at least delivered / read this message.
  /// (A read receipt implies delivery.)
  Future<({int delivered, int read})> receiptCounts(String messageId) async {
    final rows = await _db.rawQuery(
      'SELECT kind, COUNT(*) AS n FROM receipts WHERE message_id = ? GROUP BY kind',
      [messageId],
    );
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
    String messageId,
    String peerId,
    String emoji,
    int at,
  ) async {
    if (emoji.isEmpty) {
      await _db.delete(
        'reactions',
        where: 'message_id = ? AND peer_id = ?',
        whereArgs: [messageId, peerId],
      );
    } else {
      await _db.insert('reactions', {
        'message_id': messageId,
        'peer_id': peerId,
        'emoji': emoji,
        'at': at,
      }, conflictAlgorithm: ConflictAlgorithm.replace);
    }
  }

  Future<void> clearReactions(String messageId) async {
    await _db.delete(
      'reactions',
      where: 'message_id = ?',
      whereArgs: [messageId],
    );
  }

  /// All reactions on a conversation's messages: message id → (reactor → emoji).
  Future<Map<String, Map<String, String>>> reactionsFor(
    String contactId,
  ) async {
    final rows = await _db.rawQuery(
      '''
      SELECT r.message_id, r.peer_id, r.emoji FROM reactions r
      JOIN messages m ON m.id = r.message_id
      WHERE m.contact_id = ?
    ''',
      [contactId],
    );
    final out = <String, Map<String, String>>{};
    for (final r in rows) {
      (out[r['message_id'] as String] ??= {})[r['peer_id'] as String] =
          r['emoji'] as String;
    }
    return out;
  }

  Future<List<Message>> pendingMessages() async {
    // deleted = 0: a tombstoned pending message must never leave the phone.
    final rows = await _db.query(
      'messages',
      where: 'status = ? AND outgoing = 1 AND deleted = 0',
      whereArgs: [MessageStatus.pending],
      orderBy: 'sent_at',
    );
    return rows.map(Message.fromRow).toList();
  }

  /// Disappearing messages past their expiry — full rows, so the caller can
  /// remove media files before deleting.
  Future<List<Message>> expiredMessages(int now) async {
    final rows = await _db.query(
      'messages',
      where: 'expires_at IS NOT NULL AND expires_at <= ?',
      whereArgs: [now],
    );
    return rows.map(Message.fromRow).toList();
  }

  /// The soonest future expiry, or null when nothing is set to disappear.
  Future<int?> nextExpiryAt() async {
    final rows = await _db.rawQuery(
      'SELECT MIN(expires_at) AS t FROM messages WHERE expires_at IS NOT NULL',
    );
    return rows.first['t'] as int?;
  }

  // -- groups -------------------------------------------------------------------

  Future<List<Group>> groups() async {
    final rows = await _db.query('groups', orderBy: 'created_at');
    return rows.map(Group.fromRow).toList();
  }

  Future<void> setGroupPinned(String id, int? pinnedAt) async {
    await _db.update(
      'groups',
      {'pinned_at': pinnedAt},
      where: 'id = ?',
      whereArgs: [id],
    );
  }

  Future<void> upsertGroup(Group g) async {
    await _db.insert(
      'groups',
      g.toRow(),
      conflictAlgorithm: ConflictAlgorithm.replace,
    );
  }

  Future<List<GroupMember>> membersOf(String groupId) async {
    final rows = await _db.query(
      'group_members',
      where: 'group_id = ?',
      whereArgs: [groupId],
    );
    return rows.map(GroupMember.fromRow).toList();
  }

  Future<void> replaceMembers(String groupId, List<GroupMember> members) async {
    await _db.transaction((tx) async {
      await tx.delete(
        'group_members',
        where: 'group_id = ?',
        whereArgs: [groupId],
      );
      for (final m in members) {
        await tx.insert(
          'group_members',
          m.toRow(),
          conflictAlgorithm: ConflictAlgorithm.replace,
        );
      }
    });
  }

  Future<void> updateMember(GroupMember m) async {
    await _db.insert(
      'group_members',
      m.toRow(),
      conflictAlgorithm: ConflictAlgorithm.replace,
    );
  }

  Future<void> deleteGroup(String groupId) async {
    await _purgeConversationExtras(groupId);
    await _db.delete('messages', where: 'contact_id = ?', whereArgs: [groupId]);
    await _db.delete(
      'group_outbox',
      where: 'group_id = ?',
      whereArgs: [groupId],
    );
    await _db.delete(
      'group_members',
      where: 'group_id = ?',
      whereArgs: [groupId],
    );
    await _db.delete('groups', where: 'id = ?', whereArgs: [groupId]);
  }

  // -- group outbox ---------------------------------------------------------------

  /// Record that [memberIds] are owed a copy of this message. Seeded against
  /// the primary device — the fan-out is the only thing that knows a peer's
  /// real device list, and reconciles these rows once it does
  /// ([owedDevices]).
  Future<void> addOutbox(
    String messageId,
    String groupId,
    List<String> memberIds, {
    int deviceId = primaryDevice,
  }) async {
    await _db.transaction((tx) async {
      for (final memberId in memberIds) {
        await tx.insert('group_outbox', {
          'message_id': messageId,
          'group_id': groupId,
          'member_id': memberId,
          'device_id': deviceId,
        }, conflictAlgorithm: ConflictAlgorithm.ignore);
      }
    });
  }

  /// Stop owing every remaining copy (the message was deleted).
  Future<void> clearOutboxMessage(String messageId) async {
    await _db.delete(
      'group_outbox',
      where: 'message_id = ?',
      whereArgs: [messageId],
    );
  }

  /// Distinct *members* still owed, not rows: the bubble says "sent to 3 of
  /// 4" about people, and a member with two outstanding devices is one person
  /// waiting, not two.
  Future<int> outboxMembersRemaining(String messageId) async {
    final rows = await _db.query(
      'group_outbox',
      columns: ['member_id'],
      where: 'message_id = ?',
      whereArgs: [messageId],
    );
    return rows.map((r) => r['member_id'] as String).toSet().length;
  }

  Future<int> outboxRemaining(String messageId) async {
    final rows = await _db.query(
      'group_outbox',
      where: 'message_id = ?',
      whereArgs: [messageId],
    );
    return rows.length;
  }

  /// Replace what a peer is owed for one message with the exact devices that
  /// did not take it. Called by the fan-out, which is the only place that
  /// knows both the device list and the per-device outcome — a peer whose
  /// phone accepted but whose laptop did not is still owed, and only at that
  /// granularity can a retry tell the difference.
  Future<void> setOwedDevices(
    String messageId,
    String conversationId,
    String memberId,
    List<int> devices,
  ) async {
    await _db.transaction((tx) async {
      await tx.delete(
        'group_outbox',
        where: 'message_id = ? AND member_id = ?',
        whereArgs: [messageId, memberId],
      );
      for (final device in devices) {
        await tx.insert('group_outbox', {
          'message_id': messageId,
          'group_id': conversationId,
          'member_id': memberId,
          'device_id': device,
        }, conflictAlgorithm: ConflictAlgorithm.ignore);
      }
    });
  }

  /// Messages still owed to someone: message id → the members owed, each
  /// listed once however many of their devices are outstanding. The retry
  /// re-sends to the member and the fan-out re-derives which of their devices
  /// still need it, so member granularity is all this has to carry.
  Future<Map<String, List<String>>> pendingOutbox() async {
    final rows = await _db.query('group_outbox');
    final byMessage = <String, List<String>>{};
    for (final r in rows) {
      final members = byMessage[r['message_id'] as String] ??= [];
      final memberId = r['member_id'] as String;
      if (!members.contains(memberId)) members.add(memberId);
    }
    return byMessage;
  }

  Future<Message?> messageById(String id) async {
    final rows = await _db.query(
      'messages',
      where: 'id = ?',
      whereArgs: [id],
      limit: 1,
    );
    return rows.isEmpty ? null : Message.fromRow(rows.first);
  }

  Future<Message?> lastMessageFor(String contactId) async {
    final rows = await _db.query(
      'messages',
      where: 'contact_id = ?',
      whereArgs: [contactId],
      orderBy: 'sent_at DESC',
      limit: 1,
    );
    return rows.isEmpty ? null : Message.fromRow(rows.first);
  }

  // -- ratchet sessions -------------------------------------------------------

  Future<String?> sessionState(String peerId, int deviceId) async {
    final rows = await _db.query(
      'sessions',
      where: 'peer_id = ? AND device_id = ?',
      whereArgs: [peerId, deviceId],
      limit: 1,
    );
    return rows.isEmpty ? null : rows.first['state'] as String;
  }

  Future<void> saveSession(String peerId, int deviceId, String stateJson) async {
    await _db.insert('sessions', {
      'peer_id': peerId,
      'device_id': deviceId,
      'state': stateJson,
    }, conflictAlgorithm: ConflictAlgorithm.replace);
  }

  /// Drop one device's session, or every device's when [deviceId] is null —
  /// the latter for blocking or removing a contact outright.
  Future<void> deleteSession(String peerId, {int? deviceId}) async {
    await _db.delete(
      'sessions',
      where: deviceId == null ? 'peer_id = ?' : 'peer_id = ? AND device_id = ?',
      whereArgs: deviceId == null ? [peerId] : [peerId, deviceId],
    );
  }

  /// Devices we hold a session with for this peer — the set to drop from when
  /// their devices_v bumps and a device has vanished.
  Future<List<int>> sessionDevices(String peerId) async {
    final rows = await _db.query(
      'sessions',
      columns: ['device_id'],
      where: 'peer_id = ?',
      whereArgs: [peerId],
    );
    return rows.map((r) => r['device_id'] as int).toList();
  }

  // -- prekey private halves ----------------------------------------------------

  Future<int> insertPrekey(String kind, String pubB64, String secB64) async {
    return _db.insert('prekeys', {
      'kind': kind,
      'pub': pubB64,
      'sec': secB64,
      'created_at': DateTime.now().millisecondsSinceEpoch,
    });
  }

  Future<Map<String, Object?>?> prekeyById(int id, String kind) async {
    final rows = await _db.query(
      'prekeys',
      where: 'id = ? AND kind = ?',
      whereArgs: [id, kind],
      limit: 1,
    );
    return rows.isEmpty ? null : rows.first;
  }

  /// Newest signed prekey of [kind] ('spk' X25519 | 'kspk' ML-KEM) — the
  /// one we currently publish.
  Future<Map<String, Object?>?> currentSigned(String kind) async {
    final rows = await _db.query(
      'prekeys',
      where: 'kind = ?',
      whereArgs: [kind],
      orderBy: 'id DESC',
      limit: 1,
    );
    return rows.isEmpty ? null : rows.first;
  }

  Future<Map<String, Object?>?> currentSpk() => currentSigned('spk');
  Future<Map<String, Object?>?> currentKspk() => currentSigned('kspk');

  /// One-time prekeys of [kind] ('opk' X25519 | 'kopk' ML-KEM).
  Future<List<Map<String, Object?>>> oneTimePrekeys(String kind) =>
      _db.query('prekeys', where: 'kind = ?', whereArgs: [kind], orderBy: 'id');

  Future<List<Map<String, Object?>>> opks() => oneTimePrekeys('opk');
  Future<List<Map<String, Object?>>> kopks() => oneTimePrekeys('kopk');

  Future<void> deletePrekey(int id) async {
    await _db.delete('prekeys', where: 'id = ?', whereArgs: [id]);
  }

  /// Drop retired signed prekeys of [kind] (keep the newest two: current +
  /// previous, so in-flight initial messages keep working across a rotation).
  Future<void> pruneSigned(String kind) async {
    await _db.execute(
      '''
      DELETE FROM prekeys WHERE kind = ? AND id NOT IN (
        SELECT id FROM prekeys WHERE kind = ? ORDER BY id DESC LIMIT 2
      )
    ''',
      [kind, kind],
    );
  }

  Future<void> pruneSpks() => pruneSigned('spk');

  // -- backup -------------------------------------------------------------------
  // Text-only export/restore. The SQL lives here beside the schema it mirrors;
  // the file format and crypto live in core/backup.dart. Never exported:
  // sessions, prekeys, kv, receipts, group_outbox, avatars, media.

  /// Message rows that belong in a backup, with [t] as the table alias:
  /// no tombstones, text-like kinds only, nothing already expired.
  static String _backupMessageWhere(String t) =>
      "$t.deleted = 0 AND $t.kind IN ('text','notice','call') "
      'AND ($t.expires_at IS NULL OR $t.expires_at > ?)';

  /// Contacts minus `avatar` (binary media) and with `profile_at` forced to 0,
  /// so a restored contact re-applies the peer's next profile broadcast and
  /// gets its avatar back that way.
  Future<List<Map<String, Object?>>> backupContacts() => _db.rawQuery(
    'SELECT stonechat_id, display_name, pubkey, status, mailbox_address, tls_fp, '
    'hub, created_at, pinned_at, expire_timer_ms, expire_timer_at, '
    'blocked_at, muted_until, archived_at, 0 AS profile_at '
    'FROM contacts ORDER BY created_at',
  );

  Future<List<Map<String, Object?>>> backupGroups() =>
      _db.query('groups', orderBy: 'created_at');

  Future<List<Map<String, Object?>>> backupGroupMembers() =>
      _db.query('group_members', orderBy: 'group_id, stonechat_id');

  Future<List<Map<String, Object?>>> backupMessages(int nowMs) => _db.rawQuery(
    'SELECT id, contact_id, sender_id, outgoing, text, kind, duration_ms, '
    'sent_at, status, edited_at, expires_at, reply_to_id, reply_to_sender, '
    'reply_to_preview FROM messages '
    'WHERE ${_backupMessageWhere('messages')} ORDER BY sent_at',
    [nowMs],
  );

  /// Reactions on exported messages only, so the payload can't hold orphans.
  Future<List<Map<String, Object?>>> backupReactions(int nowMs) => _db.rawQuery(
    'SELECT r.message_id, r.peer_id, r.emoji, r.at FROM reactions r '
    'JOIN messages m ON m.id = r.message_id '
    'WHERE ${_backupMessageWhere('m')}',
    [nowMs],
  );

  // Columns accepted from a backup payload, per table. Inserts go through this
  // whitelist so unknown keys from a future payload revision can't raise
  // "no such column", and so a crafted file can't touch other columns.
  static const _importCols = {
    'contacts': {
      'stonechat_id',
      'display_name',
      'pubkey',
      'status',
      'mailbox_address',
      'tls_fp',
      'hub',
      'created_at',
      'pinned_at',
      'expire_timer_ms',
      'expire_timer_at',
      'blocked_at',
      'muted_until',
      'archived_at',
      'profile_at',
    },
    'groups': {
      'id',
      'name',
      'admin_id',
      'version',
      'created_at',
      'pinned_at',
      'expire_timer_ms',
      'expire_timer_at',
      'muted_until',
      'archived_at',
    },
    'group_members': {
      'group_id',
      'stonechat_id',
      'pubkey',
      'display_name',
      'mailbox_address',
      'tls_fp',
    },
    'messages': {
      'id',
      'contact_id',
      'sender_id',
      'outgoing',
      'text',
      'kind',
      'duration_ms',
      'sent_at',
      'status',
      'edited_at',
      'expires_at',
      'reply_to_id',
      'reply_to_sender',
      'reply_to_preview',
    },
    'reactions': {'message_id', 'peer_id', 'emoji', 'at'},
  };

  static const _importRequired = {
    'contacts': {
      'stonechat_id',
      'display_name',
      'pubkey',
      'status',
      'created_at',
    },
    'groups': {'id', 'name', 'admin_id', 'version', 'created_at'},
    'group_members': {'group_id', 'stonechat_id', 'pubkey', 'display_name'},
    'messages': {
      'id',
      'contact_id',
      'outgoing',
      'text',
      'kind',
      'sent_at',
      'status',
    },
    'reactions': {'message_id', 'peer_id', 'emoji', 'at'},
  };

  /// Merge a decrypted backup payload into the live tables. Everything runs in
  /// one transaction with INSERT OR IGNORE: existing rows (same primary key)
  /// always win, so restoring can never clobber a contact's current key or
  /// name, and re-restoring the same file is a no-op. Malformed rows are
  /// skipped, not fatal — one bad row shouldn't sink the other few thousand.
  Future<
    ({
      int contactsAdded,
      int groupsAdded,
      int messagesAdded,
      int messagesSkipped,
    })
  >
  importBackup({
    required List<Map<String, Object?>> contacts,
    required List<Map<String, Object?>> groups,
    required List<Map<String, Object?>> groupMembers,
    required List<Map<String, Object?>> messages,
    required List<Map<String, Object?>> reactions,
    required int nowMs,
  }) async {
    return _db.transaction((tx) async {
      Future<int> count(String table) async => Sqflite.firstIntValue(
        await tx.rawQuery('SELECT COUNT(*) FROM $table'),
      )!;

      // insert() returns the last rowid even when IGNORE dropped the row, so
      // "added" has to come from before/after counts.
      Future<int> merge(
        String table,
        List<Map<String, Object?>> rows, {
        bool Function(Map<String, Object?>)? accept,
      }) async {
        final before = await count(table);
        final cols = _importCols[table]!;
        final required = _importRequired[table]!;
        for (final row in rows) {
          if (required.any((c) => row[c] == null)) continue;
          if (accept != null && !accept(row)) continue;
          try {
            await tx.insert(table, {
              for (final c in cols)
                if (row.containsKey(c)) c: row[c],
            }, conflictAlgorithm: ConflictAlgorithm.ignore);
          } catch (_) {
            // Wrong value type for a column, etc. — skip the row.
          }
        }
        return await count(table) - before;
      }

      final contactsAdded = await merge('contacts', contacts);
      final groupsAdded = await merge('groups', groups);
      await merge('group_members', groupMembers);
      final messagesAdded = await merge(
        'messages',
        messages,
        accept: (row) {
          final expiresAt = row['expires_at'];
          return expiresAt is! int || expiresAt > nowMs;
        },
      );
      await merge('reactions', reactions);

      return (
        contactsAdded: contactsAdded,
        groupsAdded: groupsAdded,
        messagesAdded: messagesAdded,
        messagesSkipped: messages.length - messagesAdded,
      );
    });
  }
}
