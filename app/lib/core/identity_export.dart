/// Encrypted identity export: the Ed25519 identity keypair (and display
/// name) as a single passphrase-protected string, small enough for a QR
/// code. This is the one artifact that makes a Stonechat ID survive the phone —
/// PROTOCOL.md's "identity dies with the app" holds unless the user
/// explicitly creates one of these.
///
/// String form: `SCID2.` + base64url(vault container). The container is
/// stonechat-core's passphrase format (core/src/vault.rs): Argon2id with
/// its parameters carried inside and authenticated as the AEAD's
/// associated data, wrapping the payload JSON
/// `{"v":1,"sk":<b64 64-byte secret key>,"name":...}`.
///
/// The KDF and cipher live in the core so the app has one implementation
/// of each; the string framing stays here because it is UI, not crypto.
library;

import 'dart:convert';
import 'dart:isolate';
import 'dart:typed_data';

import 'core_ffi.dart';
import 'crypto.dart' show randomBytes;

class IdentityExportException implements Exception {
  final String message;
  const IdentityExportException(this.message);

  @override
  String toString() => message;
}

class IdentityCodec {
  const IdentityCodec();

  static const prefix = 'SCID2.';
  static const saltLength = 16;
  static const nonceLength = 24;
  static const payloadVersion = 1;
  static const minPassphraseChars = 8; // matches BackupService

  static const _notAnExport = 'Not a Stonechat identity export.';
  static const _newerVersion =
      'This export was created by a newer version of Stonechat — update the app '
      'first.';
  static const _wrongPassphrase = 'Wrong passphrase, or the code is damaged.';

  // -- string framing (pure, unit-tested) --------------------------------------

  static String encodeContainer(Uint8List container) =>
      prefix + base64UrlEncode(container);

  /// Strips the prefix and whitespace; the container itself is validated
  /// by the core when it is opened.
  static Uint8List decodeContainer(String data) {
    final trimmed = data.trim();
    if (!trimmed.startsWith(prefix)) {
      throw const IdentityExportException(_notAnExport);
    }
    try {
      return base64Url.decode(
        base64.normalize(
          trimmed.substring(prefix.length).replaceAll(RegExp(r'\s'), ''),
        ),
      );
    } catch (_) {
      throw const IdentityExportException(_notAnExport);
    }
  }

  // -- encrypt / decrypt --------------------------------------------------------

  /// Encrypts [secretKey] (the 64-byte Ed25519 secret key) under
  /// [passphrase]. Argon2id is deliberately slow, so it runs in a worker
  /// isolate rather than janking the UI.
  Future<String> encode({
    required Uint8List secretKey,
    required String passphrase,
    String? name,
  }) async {
    final payload = utf8.encode(
      jsonEncode({
        'v': payloadVersion,
        'sk': base64Encode(secretKey),
        'name': ?name,
      }),
    );
    final salt = randomBytes(saltLength);
    final nonce = randomBytes(nonceLength);
    final container = await Isolate.run(
      () => StonechatCore().vaultSeal(
        passphrase: passphrase,
        plaintext: payload,
        salt: salt,
        nonce: nonce,
      ),
    );
    return encodeContainer(container);
  }

  /// Decrypts an export string. Throws [IdentityExportException] with a
  /// user-facing message on any failure.
  Future<({Uint8List secretKey, String? name})> decode(
    String data,
    String passphrase,
  ) async {
    final container = decodeContainer(data);
    final opened = await Isolate.run(
      () => StonechatCore().vaultOpen(
        passphrase: passphrase,
        container: container,
      ),
    );
    switch (opened.outcome) {
      case VaultOutcome.newerVersion:
        throw const IdentityExportException(_newerVersion);
      case VaultOutcome.malformed:
        throw const IdentityExportException(_notAnExport);
      case VaultOutcome.wrongPassphrase:
        throw const IdentityExportException(_wrongPassphrase);
      case VaultOutcome.ok:
        break;
    }
    final decoded = jsonDecode(utf8.decode(opened.plaintext!));
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
}
