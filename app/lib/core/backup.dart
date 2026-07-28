/// Encrypted, text-only chat backup: exports the local history as a single
/// passphrase-protected `.stonechatbackup` file, and merges such a file back in.
///
/// The payload is gzip-compressed JSON (contacts, groups, members, text-kind
/// messages, reactions — see ChatDb's backup queries for what is excluded;
/// identity keys, ratchet sessions and prekeys never leave the device).
///
/// File layout (integers little-endian):
/// ```
/// offset  size  field
/// 0       8     magic "SC-BAK-1"
/// 8       1     format version (1)
/// 9       1     kdf id (1 = Argon2id13)
/// 10      1     reserved (0)
/// 11      1     salt length (16)
/// 12      16    Argon2id salt
/// 28      4     opslimit
/// 32      8     memlimit
/// 40      —     libsodium secretstream output verbatim: 24-byte stream
///               header, then 64 KiB chunks (+17 tag bytes each), FINAL tag
///               on the last
/// ```
/// Restore derives the key from the header's salt/limits, never from current
/// constants, so the parameters can change without a format bump. The header
/// is not AAD-authenticated (pushChunked has no AAD hook); tampering with it
/// changes the derived key, so the first chunk fails Poly1305 — the same
/// failure as a wrong passphrase, which is acceptable.
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:intl/intl.dart';
import 'package:path/path.dart' as p;
import 'package:path_provider/path_provider.dart';
import 'package:sodium/sodium_sumo.dart';

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
  final SodiumSumo sodium;
  final ChatDb db;

  BackupService(this.sodium, this.db);

  static const magic = 'SC-BAK-1';
  static const formatVersion = 1;
  static const kdfArgon2id13 = 1;
  static const saltLength = 16;
  static const headerLength = 40;
  static const chunkSize = 64 * 1024;
  static const payloadVersion = 1;
  static const minPassphraseChars = 8;

  static const _notABackup = 'Not a Stonechat backup file.';
  static const _newerVersion =
      'This backup was created by a newer version of Stonechat — update the app '
      'first.';
  static const _wrongPassphrase = 'Wrong passphrase, or the file is damaged.';

  // -- format helpers (pure, unit-tested) -------------------------------------

  static Uint8List encodeHeader(Uint8List salt, int opsLimit, int memLimit) {
    assert(salt.length == saltLength);
    final header = Uint8List(headerLength);
    header.setAll(0, ascii.encode(magic));
    header[8] = formatVersion;
    header[9] = kdfArgon2id13;
    header[11] = saltLength;
    header.setAll(12, salt);
    ByteData.sublistView(header)
      ..setUint32(28, opsLimit, Endian.little)
      ..setUint64(32, memLimit, Endian.little);
    return header;
  }

  static ({Uint8List salt, int opsLimit, int memLimit}) decodeHeader(
      Uint8List file) {
    final magicBytes = ascii.encode(magic);
    if (file.length <= headerLength) throw const BackupException(_notABackup);
    for (var i = 0; i < magicBytes.length; i++) {
      if (file[i] != magicBytes[i]) throw const BackupException(_notABackup);
    }
    if (file[8] < 1) throw const BackupException(_notABackup);
    // A version bump, an unknown KDF or a different salt size all mean a
    // layout this build doesn't know how to read.
    if (file[8] > formatVersion ||
        file[9] != kdfArgon2id13 ||
        file[11] != saltLength) {
      throw const BackupException(_newerVersion);
    }
    final bd = ByteData.sublistView(file);
    return (
      salt: file.sublist(12, 12 + saltLength),
      opsLimit: bd.getUint32(28, Endian.little),
      memLimit: bd.getUint64(32, Endian.little),
    );
  }

  static Map<String, Object?> buildPayload({
    required List<Map<String, Object?>> contacts,
    required List<Map<String, Object?>> groups,
    required List<Map<String, Object?>> groupMembers,
    required List<Map<String, Object?>> messages,
    required List<Map<String, Object?>> reactions,
    required int nowMs,
  }) {
    // Plain map copies: sqflite rows are library-private map types, and the
    // payload must cross an isolate boundary.
    List<Map<String, Object?>> copy(List<Map<String, Object?>> rows) =>
        [for (final r in rows) Map<String, Object?>.from(r)];
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
      },
      'contacts': copy(contacts),
      'groups': copy(groups),
      'group_members': copy(groupMembers),
      'messages': copy(messages),
      'reactions': copy(reactions),
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
      nowMs: nowMs,
    );
    // The whole payload lives in RAM — fine for text-only (tens of MB even at
    // 100k messages). Argon2id + gzip + jsonEncode would jank the UI, so they
    // run in a worker isolate. The closure is sent across, so it must capture
    // only sendable locals: the sodium FFI handle is, `this`/ChatDb is not —
    // never reference the service or the DB inside it.
    final sodium = this.sodium;
    final salt = sodium.randombytes.buf(saltLength);
    final opsLimit = sodium.crypto.pwhash.opsLimitModerate;
    final memLimit = sodium.crypto.pwhash.memLimitModerate;
    final bytes = await sodium.runIsolated((_, _) async {
      final plain = gzip.encode(utf8.encode(jsonEncode(payload)));
      final key = _deriveKey(sodium, passphrase, salt, opsLimit, memLimit);
      try {
        final out = BytesBuilder(copy: false)
          ..add(encodeHeader(salt, opsLimit, memLimit));
        await sodium.crypto.secretStream
            .pushChunked(
              messageStream: Stream.value(plain),
              key: key,
              chunkSize: chunkSize,
            )
            .forEach(out.add);
        return out.takeBytes();
      } finally {
        key.dispose();
      }
    });

    final date = DateFormat('yyyy-MM-dd').format(DateTime.now());
    final file = File(p.join(
        (await getTemporaryDirectory()).path, 'stonechat-backup-$date.stonechatbackup'));
    await file.writeAsBytes(bytes, flush: true);
    return file;
  }

  // -- restore ----------------------------------------------------------------

  /// Decrypts [file] with [passphrase] and merges its contents into the DB.
  /// Throws [BackupException] with a user-facing message on any failure.
  Future<RestoreSummary> restoreBackup(File file, String passphrase) async {
    final bytes = await file.readAsBytes();
    // Header checks run before the expensive KDF: "not a backup" and "newer
    // version" fail instantly.
    final header = decodeHeader(bytes);
    final body = bytes.sublist(headerLength);

    final sodium = this.sodium; // See createBackup: sendable locals only.
    Object? decoded;
    try {
      decoded = await sodium.runIsolated((_, _) async {
        final key = _deriveKey(
            sodium, passphrase, header.salt, header.opsLimit, header.memLimit);
        try {
          final out = BytesBuilder(copy: false);
          await sodium.crypto.secretStream
              .pullChunked(
                cipherStream: Stream.value(body),
                key: key,
                chunkSize: chunkSize,
              )
              .forEach(out.add);
          return jsonDecode(utf8.decode(gzip.decode(out.takeBytes())));
        } finally {
          key.dispose();
        }
      });
    } on BackupException {
      rethrow;
    } catch (_) {
      // SodiumException (bad key), truncated stream, gzip/JSON garbage — all
      // indistinguishable from a wrong passphrase without the right key.
      throw const BackupException(_wrongPassphrase);
    }

    // `decoded` is assigned inside try/catch, so it never promotes — pin the
    // Map into a fresh local for the closure below.
    if (decoded is! Map || decoded['format'] != 'stonechat-backup') {
      throw const BackupException(_notABackup);
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
      nowMs: DateTime.now().millisecondsSinceEpoch,
    );
  }

  static SecureKey _deriveKey(SodiumSumo sodium, String passphrase,
          Uint8List salt, int opsLimit, int memLimit) =>
      sodium.crypto.pwhash(
        outLen: sodium.crypto.secretStream.keyBytes,
        password: Int8List.fromList(utf8.encode(passphrase)),
        salt: salt,
        opsLimit: opsLimit,
        memLimit: memLimit,
        alg: CryptoPwhashAlgorithm.argon2id13,
      );

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
