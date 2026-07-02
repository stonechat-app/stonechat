/// Identity + end-to-end encryption. The only place plaintext meets keys.
///
/// Zeon ID = "ZC-" + base32(blake2b20(pubkey) || checksum2), see PROTOCOL.md.
/// Messages are sealed with crypto_box (X25519 + XSalsa20-Poly1305) — mutual
/// authentication: decrypting proves the sender held the `from` ID's key.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:sodium/sodium.dart';

const _b32Alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

String base32Encode(Uint8List bytes) {
  final out = StringBuffer();
  int buffer = 0, bits = 0;
  for (final byte in bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out.write(_b32Alphabet[(buffer >> (bits - 5)) & 31]);
      bits -= 5;
    }
  }
  if (bits > 0) {
    out.write(_b32Alphabet[(buffer << (5 - bits)) & 31]);
  }
  return out.toString();
}

Uint8List base32Decode(String s) {
  int buffer = 0, bits = 0;
  final out = <int>[];
  for (final ch in s.split('')) {
    final v = _b32Alphabet.indexOf(ch);
    if (v < 0) throw const FormatException('invalid base32 character');
    buffer = (buffer << 5) | v;
    bits += 5;
    if (bits >= 8) {
      out.add((buffer >> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Uint8List.fromList(out);
}

class CryptoService {
  final Sodium _sodium;
  final KeyPair _keyPair;

  CryptoService._(this._sodium, this._keyPair);

  static Future<Sodium> loadSodium() async => SodiumInit.init();

  /// Fresh identity (onboarding).
  factory CryptoService.generate(Sodium sodium) =>
      CryptoService._(sodium, sodium.crypto.box.keyPair());

  /// Restore from stored key material.
  factory CryptoService.fromKeys(
    Sodium sodium, {
    required Uint8List publicKey,
    required Uint8List secretKey,
  }) {
    return CryptoService._(
      sodium,
      KeyPair(
        publicKey: publicKey,
        secretKey: SecureKey.fromList(sodium, secretKey),
      ),
    );
  }

  Uint8List get publicKey => _keyPair.publicKey;
  String get publicKeyB64 => base64Encode(_keyPair.publicKey);
  Uint8List exportSecretKey() => _keyPair.secretKey.extractBytes();

  String get zeonId => deriveZeonId(_keyPair.publicKey);

  // -- Zeon ID ----------------------------------------------------------------

  String deriveZeonId(Uint8List pubkey) {
    final hash = _sodium.crypto.genericHash(message: pubkey, outLen: 20);
    final check = _sodium.crypto.genericHash(message: hash, outLen: 16);
    final payload = Uint8List.fromList([...hash, check[0], check[1]]);
    final b32 = base32Encode(payload);
    final groups = <String>[];
    for (var i = 0; i < b32.length; i += 4) {
      groups.add(b32.substring(i, i + 4));
    }
    return 'ZC-${groups.join('-')}';
  }

  /// Canonicalize user input; throws [FormatException] with a friendly message.
  String normalizeZeonId(String raw) {
    final compact =
        raw.trim().toUpperCase().replaceAll(RegExp(r'[\s-]'), '');
    if (!compact.startsWith('ZC')) {
      throw const FormatException('Zeon IDs start with ZC-');
    }
    final b32 = compact.substring(2);
    if (b32.length != 36) {
      throw const FormatException('That ID has the wrong length');
    }
    final payload = base32Decode(b32);
    final hash = Uint8List.sublistView(payload, 0, 20);
    final check = _sodium.crypto.genericHash(message: hash, outLen: 16);
    if (payload[20] != check[0] || payload[21] != check[1]) {
      throw const FormatException('Checksum mismatch — mistyped ID?');
    }
    final groups = <String>[];
    for (var i = 0; i < b32.length; i += 4) {
      groups.add(b32.substring(i, i + 4));
    }
    return 'ZC-${groups.join('-')}';
  }

  /// The directory can't be trusted blindly: the pubkey it returns must hash
  /// back to the ID we asked about.
  bool pubkeyMatchesId(String pubkeyB64, String zeonId) {
    try {
      return deriveZeonId(base64Decode(pubkeyB64)) == zeonId;
    } catch (_) {
      return false;
    }
  }

  // -- envelope crypto ---------------------------------------------------------

  ({String nonceB64, String ciphertextB64}) encrypt(
    String plaintext,
    Uint8List recipientPubkey,
  ) {
    final nonce = _sodium.randombytes.buf(_sodium.crypto.box.nonceBytes);
    final ciphertext = _sodium.crypto.box.easy(
      message: utf8.encode(plaintext),
      nonce: nonce,
      publicKey: recipientPubkey,
      secretKey: _keyPair.secretKey,
    );
    return (
      nonceB64: base64Encode(nonce),
      ciphertextB64: base64Encode(ciphertext),
    );
  }

  // -- media blobs (secretbox: one-off symmetric key per file) ------------------

  /// Encrypt a media file with a fresh random key. The key+nonce travel to
  /// the recipient inside the crypto_box envelope payload; the blob itself is
  /// opaque to every server that touches it.
  ({Uint8List key, Uint8List nonce, Uint8List ciphertext}) sealBlob(
      Uint8List data) {
    final key = _sodium.crypto.secretBox.keygen();
    final nonce = _sodium.randombytes.buf(_sodium.crypto.secretBox.nonceBytes);
    final ciphertext =
        _sodium.crypto.secretBox.easy(message: data, nonce: nonce, key: key);
    final keyBytes = key.extractBytes();
    key.dispose();
    return (key: keyBytes, nonce: nonce, ciphertext: ciphertext);
  }

  /// Returns null on tamper/corruption.
  Uint8List? openBlob(Uint8List ciphertext, Uint8List keyBytes, Uint8List nonce) {
    final key = SecureKey.fromList(_sodium, keyBytes);
    try {
      return _sodium.crypto.secretBox
          .openEasy(cipherText: ciphertext, nonce: nonce, key: key);
    } catch (_) {
      return null;
    } finally {
      key.dispose();
    }
  }

  /// Returns null if the envelope wasn't genuinely from the claimed sender
  /// (or was corrupted) — authentication failure, not an error to surface.
  String? decrypt(String nonceB64, String ciphertextB64, Uint8List senderPubkey) {
    try {
      final plain = _sodium.crypto.box.openEasy(
        cipherText: base64Decode(ciphertextB64),
        nonce: base64Decode(nonceB64),
        publicKey: senderPubkey,
        secretKey: _keyPair.secretKey,
      );
      return utf8.decode(plain);
    } catch (_) {
      return null;
    }
  }
}
