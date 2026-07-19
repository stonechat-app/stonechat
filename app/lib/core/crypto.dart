/// Identity + end-to-end encryption primitives. The only place plaintext
/// meets keys.
///
/// PROTOCOL.md: the identity is an Ed25519 signing keypair; the Zeon ID is
/// "ZC-" + base32(blake2b20(pubkey) || checksum2). Messages are encrypted
/// with per-message keys from an X3DH + double-ratchet session (session.dart)
/// — this file provides the identity and the shared primitives.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:sodium/sodium_sumo.dart';

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

/// Domain-separation constants — must match scripts/e2e.py and PROTOCOL.md.
final x3dhKdfKey = utf8.encode('zeon-v1-x3dh-kdf'); // 16 bytes, generichash min
final spkSigContext = utf8.encode('zeon-v1-spk');
final tlsSigContext = utf8.encode('zeon-v1-tls');
final recoverSigContext = utf8.encode('zeon-v1-recover');

class CryptoService {
  final SodiumSumo sodium;
  final KeyPair _identity; // Ed25519
  late final SecureKey _identityXsk; // converted X25519 secret, cached

  CryptoService._(this.sodium, this._identity) {
    _identityXsk = sodium.crypto.sign.skToCurve25519(_identity.secretKey);
  }

  static Future<SodiumSumo> loadSodium() async => SodiumSumoInit.init();

  /// Fresh identity (onboarding).
  factory CryptoService.generate(SodiumSumo sodium) =>
      CryptoService._(sodium, sodium.crypto.sign.keyPair());

  /// Restore from stored key material.
  factory CryptoService.fromKeys(
    SodiumSumo sodium, {
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

  Uint8List get publicKey => _identity.publicKey;
  String get publicKeyB64 => base64Encode(_identity.publicKey);
  Uint8List exportSecretKey() => _identity.secretKey.extractBytes();

  String get zeonId => deriveZeonId(_identity.publicKey);

  /// Own identity as X25519, for X3DH.
  SecureKey get identityXsk => _identityXsk;
  Uint8List get identityXpk =>
      sodium.crypto.sign.pkToCurve25519(_identity.publicKey);

  /// A peer's Ed25519 identity key as X25519.
  Uint8List toX25519(Uint8List edPubkey) =>
      sodium.crypto.sign.pkToCurve25519(edPubkey);

  // -- sealed envelopes (PROTOCOL.md "Envelope") --------------------------------

  /// Anonymous sealed box to a peer's identity key — the wrap that hides the
  /// sender (and every other envelope field) from the recipient's mailbox.
  Uint8List sealTo(Uint8List recipientEdPub, Uint8List message) =>
      sodium.crypto.box
          .seal(message: message, publicKey: toX25519(recipientEdPub));

  /// Returns null when the box wasn't sealed to this identity (or is garbage).
  Uint8List? unseal(Uint8List sealed) {
    try {
      return sodium.crypto.box.sealOpen(
          cipherText: sealed, publicKey: identityXpk, secretKey: _identityXsk);
    } catch (_) {
      return null;
    }
  }

  // -- Zeon ID ----------------------------------------------------------------

  String deriveZeonId(Uint8List pubkey) {
    final hash = sodium.crypto.genericHash(message: pubkey, outLen: 20);
    final check = sodium.crypto.genericHash(message: hash, outLen: 16);
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
    final check = sodium.crypto.genericHash(message: hash, outLen: 16);
    if (payload[20] != check[0] || payload[21] != check[1]) {
      throw const FormatException('Checksum mismatch — mistyped ID?');
    }
    final groups = <String>[];
    for (var i = 0; i < b32.length; i += 4) {
      groups.add(b32.substring(i, i + 4));
    }
    return 'ZC-${groups.join('-')}';
  }

  /// Any identity key we're handed (directory, x3dh block, member list) must
  /// hash back to the ID it claims to be.
  bool pubkeyMatchesId(String pubkeyB64, String zeonId) {
    try {
      return deriveZeonId(base64Decode(pubkeyB64)) == zeonId;
    } catch (_) {
      return false;
    }
  }

  /// Proof of key possession for POST /v1/recover (identity restore): a
  /// signature over "zeon-v1-recover" || the current unix time, so the hub
  /// can re-issue an account token without ever having stored one.
  String signRecovery(int unixSeconds) =>
      base64Encode(sodium.crypto.sign.detached(
        message: Uint8List.fromList(
            [...recoverSigContext, ...utf8.encode('$unixSeconds')]),
        secretKey: _identity.secretKey,
      ));

  // -- prekeys -----------------------------------------------------------------

  /// New X25519 keypair (signed prekeys, one-time prekeys, ratchet keys).
  KeyPair newX25519() => sodium.crypto.box.keyPair();

  Uint8List signPrekey(Uint8List spkPub) => sodium.crypto.sign.detached(
        message: Uint8List.fromList([...spkSigContext, ...spkPub]),
        secretKey: _identity.secretKey,
      );

  bool verifyPrekeySig(
      Uint8List spkPub, Uint8List sig, Uint8List identityEdPub) {
    try {
      return sodium.crypto.sign.verifyDetached(
        message: Uint8List.fromList([...spkSigContext, ...spkPub]),
        signature: sig,
        publicKey: identityEdPub,
      );
    } catch (_) {
      return false;
    }
  }

  // -- pinned TLS (PROTOCOL.md "Transport") --------------------------------------

  /// What clients pin: BLAKE2b-256 of the relay's DER certificate.
  String certFingerprint(Uint8List certDer) =>
      base64Encode(sodium.crypto.genericHash(message: certDer, outLen: 32));

  /// The owner vouching for their mailbox's TLS key.
  String signTlsFp(String fpB64) => base64Encode(sodium.crypto.sign.detached(
        message: Uint8List.fromList([...tlsSigContext, ...base64Decode(fpB64)]),
        secretKey: _identity.secretKey,
      ));

  bool verifyTlsSig(String fpB64, String sigB64, Uint8List identityEdPub) {
    try {
      return sodium.crypto.sign.verifyDetached(
        message:
            Uint8List.fromList([...tlsSigContext, ...base64Decode(fpB64)]),
        signature: base64Decode(sigB64),
        publicKey: identityEdPub,
      );
    } catch (_) {
      return false;
    }
  }

  // -- ratchet primitives (shared constants in PROTOCOL.md) ---------------------

  Uint8List dh(SecureKey secret, Uint8List pub) {
    final shared = sodium.crypto.scalarmult(n: secret, p: pub);
    final bytes = shared.extractBytes();
    shared.dispose();
    return bytes;
  }

  Uint8List _keyedHash(Uint8List message, Uint8List key, int outLen) {
    final k = SecureKey.fromList(sodium, key);
    try {
      return sodium.crypto.genericHash(message: message, key: k, outLen: outLen);
    } finally {
      k.dispose();
    }
  }

  /// SK = H(DH1 || DH2 || DH3 [|| DH4], key="zeon-v1-x3dh-kdf", 32)
  Uint8List x3dhSharedKey(List<Uint8List> dhs) => _keyedHash(
      Uint8List.fromList([for (final d in dhs) ...d]),
      Uint8List.fromList(x3dhKdfKey),
      32);

  /// KDF_RK: (rk', ck) from the root key and a fresh DH output.
  (Uint8List, Uint8List) kdfRoot(Uint8List rk, Uint8List dhOut) {
    final out = _keyedHash(dhOut, rk, 64);
    return (Uint8List.sublistView(out, 0, 32), Uint8List.sublistView(out, 32));
  }

  /// KDF_CK: (mk, ck') — one step down a chain.
  (Uint8List, Uint8List) kdfChain(Uint8List ck) => (
        _keyedHash(Uint8List.fromList([1]), ck, 32),
        _keyedHash(Uint8List.fromList([2]), ck, 32),
      );

  ({Uint8List nonce, Uint8List ciphertext}) aeadSeal(
      Uint8List key, Uint8List plaintext, Uint8List ad) {
    final aead = sodium.crypto.aeadXChaCha20Poly1305IETF;
    final nonce = sodium.randombytes.buf(aead.nonceBytes);
    final k = SecureKey.fromList(sodium, key);
    try {
      final ciphertext = aead.encrypt(
          message: plaintext, nonce: nonce, key: k, additionalData: ad);
      return (nonce: nonce, ciphertext: ciphertext);
    } finally {
      k.dispose();
    }
  }

  /// Returns null on authentication failure.
  Uint8List? aeadOpen(
      Uint8List key, Uint8List nonce, Uint8List ciphertext, Uint8List ad) {
    final aead = sodium.crypto.aeadXChaCha20Poly1305IETF;
    final k = SecureKey.fromList(sodium, key);
    try {
      return aead.decrypt(
          cipherText: ciphertext, nonce: nonce, key: k, additionalData: ad);
    } catch (_) {
      return null;
    } finally {
      k.dispose();
    }
  }

  // -- media blobs (secretbox: one-off symmetric key per file) ------------------

  /// Encrypt a media file with a fresh random key. The key+nonce travel to
  /// the recipient inside the session-encrypted envelope payload; the blob
  /// itself is opaque to every server that touches it.
  ({Uint8List key, Uint8List nonce, Uint8List ciphertext}) sealBlob(
      Uint8List data) {
    final key = sodium.crypto.secretBox.keygen();
    final nonce = sodium.randombytes.buf(sodium.crypto.secretBox.nonceBytes);
    final ciphertext =
        sodium.crypto.secretBox.easy(message: data, nonce: nonce, key: key);
    final keyBytes = key.extractBytes();
    key.dispose();
    return (key: keyBytes, nonce: nonce, ciphertext: ciphertext);
  }

  /// Returns null on tamper/corruption.
  Uint8List? openBlob(Uint8List ciphertext, Uint8List keyBytes, Uint8List nonce) {
    final key = SecureKey.fromList(sodium, keyBytes);
    try {
      return sodium.crypto.secretBox
          .openEasy(cipherText: ciphertext, nonce: nonce, key: key);
    } catch (_) {
      return null;
    } finally {
      key.dispose();
    }
  }
}
