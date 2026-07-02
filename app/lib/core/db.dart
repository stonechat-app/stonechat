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
      version: 1,
      onCreate: (db, _) async {
        await db.execute('''
          CREATE TABLE contacts (
            zeon_id        TEXT PRIMARY KEY,
            display_name   TEXT NOT NULL,
            pubkey         TEXT NOT NULL,
            status         TEXT NOT NULL,
            server_address TEXT,
            created_at     INTEGER NOT NULL
          )
        ''');
        await db.execute('''
          CREATE TABLE messages (
            id         TEXT PRIMARY KEY,
            contact_id TEXT NOT NULL REFERENCES contacts(zeon_id),
            outgoing   INTEGER NOT NULL,
            text       TEXT NOT NULL,
            sent_at    INTEGER NOT NULL,
            status     TEXT NOT NULL
          )
        ''');
        await db.execute(
            'CREATE INDEX idx_messages_contact ON messages(contact_id, sent_at)');
      },
    );
    return ChatDb._(db);
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

  Future<Message?> lastMessageFor(String contactId) async {
    final rows = await _db.query('messages',
        where: 'contact_id = ?',
        whereArgs: [contactId],
        orderBy: 'sent_at DESC',
        limit: 1);
    return rows.isEmpty ? null : Message.fromRow(rows.first);
  }
}
