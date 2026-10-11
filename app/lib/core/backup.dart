/// Encrypted, text-only chat backup: exports the local history as a single
/// passphrase-protected `.stonechatbackup` file, and merges such a file back in.
///
/// The payload is gzip-compressed JSON (contacts, groups, members, text-kind
/// messages, reactions — see ChatDb's backup queries for what is excluded;
/// identity keys, ratchet sessions and prekeys never leave the device).
///
/// File layout: an 8-byte magic "SC-BAK-2", then stonechat-core's
/// passphrase container (core/src/vault.rs) — Argon2id with its
/// parameters inside, authenticated as the AEAD's associated data, so a
/// downgraded header is a decryption failure rather than a silent
/// weakening. The magic is checked before the expensive KDF runs, so
/// "not a backup" fails instantly.
library;

import 'dart:convert';
import 'dart:isolate';
import 'dart:io';
import 'dart:typed_data';

import 'package:intl/intl.dart';
import 'package:path/path.dart' as p;
import 'package:path_provider/path_provider.dart';
import 'core_ffi.dart';
import 'crypto.dart' show randomBytes;
import 'db.dart';

class BackupException implements Exception {
  final String message;
  const BackupException(this.message);

  @override
  String toString() => message;
}

typedef RestoreSummary = ({
  int contactsAdded,
  int groupsAdded,
  int messagesAdded,
  int messagesSkipped,
});

class BackupService {
  final ChatDb db;

  BackupService(this.db);

  static const magic = 'SC-BAK-2';
  static const saltLength = 16;
  static const nonceLength = 24;
  static const headerLength = 8; // just the magic; the vault carries its own
  static const payloadVersion = 1;
  static const minPassphraseChars = 8;

  static const _notABackup = 'Not a Stonechat backup file.';
  static const _newerVersion =
      'This backup was created by a newer version of Stonechat — update the app '
      'first.';
  static const _wrongPassphrase = 'Wrong passphrase, or the file is damaged.';

  // -- format helpers (pure, unit-tested) -------------------------------------

  static Uint8List encodeHeader() => Uint8List.fromList(ascii.encode(magic));

  /// Throws [BackupException] when this is not one of our files. Runs
  /// before the KDF, so a wrong file fails instantly.
  static void checkMagic(Uint8List file) {
    final magicBytes = ascii.encode(magic);
    if (file.length <= headerLength) throw const BackupException(_notABackup);
    for (var i = 0; i < magicBytes.length; i++) {
      if (file[i] != magicBytes[i]) throw const BackupException(_notABackup);
    }
  }

  static Map<String, Object?> buildPayload({
    required List<Map<String, Object?>> contacts,
    required List<Map<String, Object?>> groups,
    required List<Map<String, Object?>> groupMembers,
    required List<Map<String, Object?>> messages,
    required List<Map<String, Object?>> reactions,
    List<Map<String, Object?>> blocked = const [],
    required int nowMs,
  }) {
    // Plain map copies: sqflite rows are library-private map types, and the
    // payload must cross an isolate boundary.
    List<Map<String, Object?>> copy(List<Map<String, Object?>> rows) => [
      for (final r in rows) Map<String, Object?>.from(r),
    ];
    return {
      'format': 'stonechat-backup',
      'version': payloadVersion,
      'created_at': nowMs,
      'counts': {
        'contacts': contacts.length,
        'groups': groups.length,
        'group_members': groupMembers.length,
        'messages': messages.length,
        'reactions': reactions.length,
        'blocked': blocked.length,
      },
      'contacts': copy(contacts),
      'groups': copy(groups),
      'group_members': copy(groupMembers),
      'messages': copy(messages),
      'reactions': copy(reactions),
      // Added after payload version 1 without a bump: older readers ignore
      // the key, and a missing key reads as no blocks.
      'blocked': copy(blocked),
    };
  }

  // -- export -----------------------------------------------------------------

  /// Reads the exportable rows, encrypts them under [passphrase] and writes
  /// the result to the temp directory. The caller shares the returned file
  /// and deletes it afterwards.
  Future<File> createBackup(String passphrase) async {
    final nowMs = DateTime.now().millisecondsSinceEpoch;
    final payload = buildPayload(
      contacts: await db.backupContacts(),
      groups: await db.backupGroups(),
      groupMembers: await db.backupGroupMembers(),
      messages: await db.backupMessages(nowMs),
      reactions: await db.backupReactions(nowMs),
      blocked: await db.backupBlocked(),
      nowMs: nowMs,
    );
    // The whole payload lives in RAM — fine for text-only (tens of MB even
    // at 100k messages). gzip + JSON + Argon2id would jank the UI, so they
    // run in a worker isolate; the closure captures only sendable locals.
    final salt = randomBytes(saltLength);
    final nonce = randomBytes(nonceLength);
    final bytes = await Isolate.run(() {
      final plain = gzip.encode(utf8.encode(jsonEncode(payload)));
      final container = StonechatCore().vaultSeal(
        passphrase: passphrase,
        plaintext: Uint8List.fromList(plain),
        salt: salt,
        nonce: nonce,
      );
      return Uint8List.fromList([...encodeHeader(), ...container]);
    });

    final date = DateFormat('yyyy-MM-dd').format(DateTime.now());
    final file = File(
      p.join(
        (await getTemporaryDirectory()).path,
        'stonechat-backup-$date.stonechatbackup',
      ),
    );
    await file.writeAsBytes(bytes, flush: true);
    return file;
  }

  // -- restore ----------------------------------------------------------------

  /// Decrypts [file] with [passphrase] and merges its contents into the DB.
  /// Throws [BackupException] with a user-facing message on any failure.
  Future<RestoreSummary> restoreBackup(File file, String passphrase) async {
    final bytes = await file.readAsBytes();
    checkMagic(bytes); // cheap rejection before the expensive KDF
    final container = Uint8List.sublistView(bytes, headerLength);

    final opened = await Isolate.run(
      () => StonechatCore().vaultOpen(
        passphrase: passphrase,
        container: container,
      ),
    );
    switch (opened.outcome) {
      case VaultOutcome.newerVersion:
        throw const BackupException(_newerVersion);
      case VaultOutcome.malformed:
        throw const BackupException(_notABackup);
      case VaultOutcome.wrongPassphrase:
        throw const BackupException(_wrongPassphrase);
      case VaultOutcome.ok:
        break;
    }
    final summary = await mergePayloadBytes(opened.plaintext!);
    if (summary == null) throw const BackupException(_notABackup);
    return summary;
  }

  /// Merge a decrypted, gzip-compressed payload — the inside of a backup
  /// file, or of a `sync_history` blob from our primary. Null when it is not
  /// one of ours; throws [BackupException] for a newer version.
  Future<RestoreSummary?> mergePayloadBytes(Uint8List plain) async {
    Object? decoded;
    try {
      decoded = jsonDecode(utf8.decode(gzip.decode(plain)));
    } catch (_) {
      // Right key but garbage inside: truncated, or not ours.
      return null;
    }

    // `decoded` is assigned inside try/catch, so it never promotes — pin the
    // Map into a fresh local for the closure below.
    if (decoded is! Map || decoded['format'] != 'stonechat-backup') {
      return null;
    }
    final payload = decoded;
    final version = payload['version'];
    if (version is! int || version > payloadVersion) {
      throw const BackupException(_newerVersion);
    }

    List<Map<String, Object?>> rows(String key) {
      final v = payload[key];
      if (v is! List) return const [];
      return [
        for (final r in v)
          if (r is Map) r.cast<String, Object?>(),
      ];
    }

    return db.importBackup(
      contacts: rows('contacts'),
      groups: rows('groups'),
      groupMembers: rows('group_members'),
      messages: rows('messages'),
      reactions: rows('reactions'),
      blocked: rows('blocked'),
      nowMs: DateTime.now().millisecondsSinceEpoch,
    );
  }

  /// Remove exports left in the temp dir (share aborted mid-way, crash).
  Future<void> cleanupTempBackups() async {
    final dir = await getTemporaryDirectory();
    await for (final f in dir.list()) {
      if (f is File &&
          p.basename(f.path).startsWith('stonechat-backup-') &&
          f.path.endsWith('.stonechatbackup')) {
        try {
          await f.delete();
        } catch (_) {}
      }
    }
  }
}
