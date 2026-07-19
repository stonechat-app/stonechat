/// Encrypted identity export: the Ed25519 identity keypair (and display
/// name) as a single passphrase-protected string, small enough for a QR
/// code. This is the one artifact that makes a Zeon ID survive the phone —
/// PROTOCOL.md's "identity dies with the app" holds unless the user
/// explicitly creates one of these.
///
/// String form: `ZID1.` + base64url(container). Container layout
/// (integers little-endian):
/// ```
/// offset  size  field
/// 0       1     format version (1)
/// 1       1     kdf id (1 = Argon2id13)
/// 2       16    Argon2id salt
/// 18      4     opslimit
/// 22      8     memlimit
/// 30      24    secretbox nonce
/// 54      —     crypto_secretbox_easy ciphertext of the payload JSON
///               {"v":1,"sk":<b64 64-byte secret key>,"name":...}
/// ```
/// Decode derives the key from the container's salt/limits, never from
/// current constants, so parameters can change without a format bump. The
/// header is not separately authenticated: tampering changes the derived
/// key or nonce, so the secretbox MAC fails — indistinguishable from a
/// wrong passphrase, which is the message we show anyway.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:sodium/sodium_sumo.dart';

class IdentityExportException implements Exception {
  final String message;
  const IdentityExportException(this.message);

  @override
  String toString() => message;
}

class IdentityCodec {
  final SodiumSumo sodium;

  IdentityCodec(this.sodium);

  static const prefix = 'ZID1.';
  static const formatVersion = 1;
  static const kdfArgon2id13 = 1;
  static const saltLength = 16;
  static const nonceLength = 24;
  static const headerLength = 54;
  static const payloadVersion = 1;
  static const minPassphraseChars = 8; // matches BackupService

  static const _notAnExport = 'Not a Zeon identity export.';
  static const _newerVersion =
      'This export was created by a newer version of Zeon — update the app '
      'first.';
  static const _wrongPassphrase = 'Wrong passphrase, or the code is damaged.';

  // -- container format (pure, unit-tested) ------------------------------------

  static String encodeContainer(Uint8List salt, int opsLimit, int memLimit,
      Uint8List nonce, Uint8List cipher) {
    assert(salt.length == saltLength && nonce.length == nonceLength);
    final header = Uint8List(headerLength);
    header[0] = formatVersion;
    header[1] = kdfArgon2id13;
    header.setAll(2, salt);
    ByteData.sublistView(header)
      ..setUint32(18, opsLimit, Endian.little)
      ..setUint64(22, memLimit, Endian.little);
    header.setAll(30, nonce);
    return prefix + base64UrlEncode(Uint8List.fromList([...header, ...cipher]));
  }

  static ({
    Uint8List salt,
    int opsLimit,
    int memLimit,
    Uint8List nonce,
    Uint8List cipher
  }) decodeContainer(String data) {
    final trimmed = data.trim();
    if (!trimmed.startsWith(prefix)) {
      throw const IdentityExportException(_notAnExport);
    }
    Uint8List bytes;
    try {
      bytes = base64Url.decode(base64.normalize(
          trimmed.substring(prefix.length).replaceAll(RegExp(r'\s'), '')));
    } catch (_) {
      throw const IdentityExportException(_notAnExport);
    }
    if (bytes.length <= headerLength) {
      throw const IdentityExportException(_notAnExport);
    }
    if (bytes[0] < 1) throw const IdentityExportException(_notAnExport);
    if (bytes[0] > formatVersion || bytes[1] != kdfArgon2id13) {
      throw const IdentityExportException(_newerVersion);
    }
    final bd = ByteData.sublistView(bytes);
    return (
      salt: bytes.sublist(2, 2 + saltLength),
      opsLimit: bd.getUint32(18, Endian.little),
      memLimit: bd.getUint64(22, Endian.little),
      nonce: bytes.sublist(30, 30 + nonceLength),
      cipher: bytes.sublist(headerLength),
    );
  }

  // -- encrypt / decrypt --------------------------------------------------------

  /// Encrypts [secretKey] (the 64-byte Ed25519 secret key) under
  /// [passphrase]. Argon2id runs in a worker isolate — same jank argument as
  /// BackupService, and the same rule: the closure captures only sendable
  /// locals (the sodium FFI handle is, `this` is not).
  Future<String> encode({
    required Uint8List secretKey,
    required String passphrase,
    String? name,
  }) async {
    final sodium = this.sodium;
    final salt = sodium.randombytes.buf(saltLength);
    final nonce = sodium.randombytes.buf(nonceLength);
    final opsLimit = sodium.crypto.pwhash.opsLimitModerate;
    final memLimit = sodium.crypto.pwhash.memLimitModerate;
    final payload = utf8.encode(jsonEncode({
      'v': payloadVersion,
      'sk': base64Encode(secretKey),
      'name': ?name,
    }));
    final cipher = await sodium.runIsolated((_, _) async {
      final key = _deriveKey(sodium, passphrase, salt, opsLimit, memLimit);
      try {
        return sodium.crypto.secretBox
            .easy(message: payload, nonce: nonce, key: key);
      } finally {
        key.dispose();
      }
    });
    return encodeContainer(salt, opsLimit, memLimit, nonce, cipher);
  }

  /// Decrypts an export string. Throws [IdentityExportException] with a
  /// user-facing message on any failure.
  Future<({Uint8List secretKey, String? name})> decode(
      String data, String passphrase) async {
    final c = decodeContainer(data);
    final sodium = this.sodium;
    final salt = c.salt, nonce = c.nonce, cipher = c.cipher;
    final opsLimit = c.opsLimit, memLimit = c.memLimit;
    Uint8List plain;
    try {
      plain = await sodium.runIsolated((_, _) async {
        final key = _deriveKey(sodium, passphrase, salt, opsLimit, memLimit);
        try {
          return sodium.crypto.secretBox
              .openEasy(cipherText: cipher, nonce: nonce, key: key);
        } finally {
          key.dispose();
        }
      });
    } catch (_) {
      throw const IdentityExportException(_wrongPassphrase);
    }
    final decoded = jsonDecode(utf8.decode(plain));
    if (decoded is! Map || decoded['sk'] is! String) {
      throw const IdentityExportException(_notAnExport);
    }
    final version = decoded['v'];
    if (version is! int || version > payloadVersion) {
      throw const IdentityExportException(_newerVersion);
    }
    final secretKey = base64Decode(decoded['sk'] as String);
    if (secretKey.length != 64) {
      throw const IdentityExportException(_notAnExport);
    }
    return (secretKey: secretKey, name: decoded['name'] as String?);
  }

  static SecureKey _deriveKey(SodiumSumo sodium, String passphrase,
          Uint8List salt, int opsLimit, int memLimit) =>
      sodium.crypto.pwhash(
        outLen: sodium.crypto.secretBox.keyBytes,
        password: Int8List.fromList(utf8.encode(passphrase)),
        salt: salt,
        opsLimit: opsLimit,
        memLimit: memLimit,
        alg: CryptoPwhashAlgorithm.argon2id13,
      );
}
