/// Identity + end-to-end encryption primitives. The only place plaintext
/// meets keys.
///
/// PROTOCOL.md: the identity is an Ed25519 signing keypair; the Stonechat ID is
/// "SC-" + base32(blake2b20(pubkey) || checksum2). Messages are encrypted
/// with per-message keys from a PQXDH + double-ratchet session
/// (session.dart) — this file provides the identity and the shared
/// primitives. The post-quantum half (ML-KEM-768 prekeys, X-Wing envelope
/// seal — notes/docs/POST_QUANTUM.md) comes from pqcore; both KEMs are always
/// hybrid alongside the classical DHs, never a replacement for them.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:sodium/sodium_sumo.dart';

import 'pqcore.dart';

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
final x3dhKdfKey = utf8.encode('stonechat-v1-pqxdh-kdf'); // 16+ bytes, generichash key
final hsealKdfKey = utf8.encode('stonechat-v1-hsealkdf'); // 16 bytes, generichash min
final hsealAd = utf8.encode('stonechat-v1-hseal');
final pqidSeedKey = utf8.encode('stonechat-v1-pqidseed'); // 16 bytes
final spkSigContext = utf8.encode('stonechat-v1-spk');
final kspkSigContext = utf8.encode('stonechat-v1-kspk');
final pqPkSigContext = utf8.encode('stonechat-v1-pqpk');
final tlsSigContext = utf8.encode('stonechat-v1-tls');
final recoverSigContext = utf8.encode('stonechat-v1-recover');
final reportSigContext = utf8.encode('stonechat-v1-report');

class CryptoService {
  final SodiumSumo sodium;
  final PqCore pq;
  final KeyPair _identity; // Ed25519
  late final SecureKey _identityXsk; // converted X25519 secret, cached
  late final Uint8List _pqSeed; // X-Wing identity seed, derived
  late final Uint8List pqPublicKey; // X-Wing identity public (directory pq_pk)

  CryptoService._(this.sodium, this._identity, {PqCore? pqCore})
      : pq = pqCore ?? PqCore() {
    _identityXsk = sodium.crypto.sign.skToCurve25519(_identity.secretKey);
    // The X-Wing identity is *derived* from the Ed25519 secret (domain-
    // separated KDF), not stored: identity export, recovery and backups
    // restore it for free, and holding the Ed25519 key already means total
    // identity compromise, so the derivation adds no new custody risk.
    final edSk = _identity.secretKey.extractBytes();
    _pqSeed = _keyedHash(edSk, Uint8List.fromList(pqidSeedKey), 32);
    edSk.fillRange(0, edSk.length, 0);
    pqPublicKey = pq.xwingPkFromSeed(_pqSeed);
  }

  static Future<SodiumSumo> loadSodium() async => SodiumSumoInit.init();

  /// Fresh identity (onboarding).
  factory CryptoService.generate(SodiumSumo sodium, {PqCore? pqCore}) =>
      CryptoService._(sodium, sodium.crypto.sign.keyPair(), pqCore: pqCore);

  /// Restore from stored key material.
  factory CryptoService.fromKeys(
    SodiumSumo sodium, {
    required Uint8List publicKey,
    required Uint8List secretKey,
    PqCore? pqCore,
  }) {
    return CryptoService._(
      sodium,
      KeyPair(
        publicKey: publicKey,
        secretKey: SecureKey.fromList(sodium, secretKey),
      ),
      pqCore: pqCore,
    );
  }

  Uint8List get publicKey => _identity.publicKey;
  String get publicKeyB64 => base64Encode(_identity.publicKey);
  String get pqPublicKeyB64 => base64Encode(pqPublicKey);
  Uint8List exportSecretKey() => _identity.secretKey.extractBytes();

  String get stonechatId => deriveStonechatId(_identity.publicKey);

  /// Own identity as X25519, for X3DH.
  SecureKey get identityXsk => _identityXsk;
  Uint8List get identityXpk =>
      sodium.crypto.sign.pkToCurve25519(_identity.publicKey);

  /// A peer's Ed25519 identity key as X25519.
  Uint8List toX25519(Uint8List edPubkey) =>
      sodium.crypto.sign.pkToCurve25519(edPubkey);

  // -- sealed envelopes (PROTOCOL.md "Envelope") --------------------------------

  /// Anonymous hybrid seal to a peer's X-Wing identity key (`pq_pk` in the
  /// directory, signature-verified against their Ed25519 key on resolve) —
  /// the wrap that hides the sender (and every other envelope field) from
  /// the recipient's mailbox. X-Wing is X25519 + ML-KEM-768 in one KEM, so
  /// a recorded envelope stays sealed against a future quantum attacker
  /// (notes/docs/POST_QUANTUM.md step 2). Wire form:
  ///
  ///   kem_ct (1120) || nonce (24) || xchacha20poly1305(inner, ad="stonechat-v1-hseal")
  ///   with key = H(kem_ss, key="stonechat-v1-hsealkdf", 32)
  ///
  /// Like crypto_box_seal, encapsulation is fresh-randomness-per-envelope and
  /// involves no sender key: nothing on the wire identifies or links senders.
  Uint8List sealTo(Uint8List recipientPqPk, Uint8List message) {
    final enc = pq.xwingEncaps(
        recipientPqPk, sodium.randombytes.buf(xwingEncapsRandomBytes));
    final key = _keyedHash(enc.ss, Uint8List.fromList(hsealKdfKey), 32);
    final sealed = aeadSeal(key, message, Uint8List.fromList(hsealAd));
    return Uint8List.fromList(
        [...enc.ct, ...sealed.nonce, ...sealed.ciphertext]);
  }

  /// Returns null when the envelope wasn't sealed to this identity (or is
  /// garbage): a wrong recipient decapsulates to a wrong shared secret and
  /// the AEAD refuses.
  Uint8List? unseal(Uint8List sealed) {
    const nonceBytes = 24;
    if (sealed.length < xwingCiphertextBytes + nonceBytes + 16) return null;
    try {
      final kemCt = Uint8List.sublistView(sealed, 0, xwingCiphertextBytes);
      final nonce = Uint8List.sublistView(
          sealed, xwingCiphertextBytes, xwingCiphertextBytes + nonceBytes);
      final box =
          Uint8List.sublistView(sealed, xwingCiphertextBytes + nonceBytes);
      final ss = pq.xwingDecaps(_pqSeed, kemCt);
      final key = _keyedHash(ss, Uint8List.fromList(hsealKdfKey), 32);
      return aeadOpen(key, nonce, box, Uint8List.fromList(hsealAd));
    } catch (_) {
      return null;
    }
  }

  /// The owner vouching for their X-Wing identity key; published beside it
  /// in the hub directory and verified by every resolver.
  String signPqPk() => base64Encode(sodium.crypto.sign.detached(
        message: Uint8List.fromList([...pqPkSigContext, ...pqPublicKey]),
        secretKey: _identity.secretKey,
      ));

  bool verifyPqPkSig(Uint8List pqPk, Uint8List sig, Uint8List identityEdPub) {
    try {
      return sodium.crypto.sign.verifyDetached(
        message: Uint8List.fromList([...pqPkSigContext, ...pqPk]),
        signature: sig,
        publicKey: identityEdPub,
      );
    } catch (_) {
      return false;
    }
  }

  // -- Stonechat ID ----------------------------------------------------------------

  String deriveStonechatId(Uint8List pubkey) {
    final hash = sodium.crypto.genericHash(message: pubkey, outLen: 20);
    final check = sodium.crypto.genericHash(message: hash, outLen: 16);
    final payload = Uint8List.fromList([...hash, check[0], check[1]]);
    final b32 = base32Encode(payload);
    final groups = <String>[];
    for (var i = 0; i < b32.length; i += 4) {
      groups.add(b32.substring(i, i + 4));
    }
    return 'SC-${groups.join('-')}';
  }

  /// Canonicalize user input; throws [FormatException] with a friendly message.
  String normalizeStonechatId(String raw) {
    final compact =
        raw.trim().toUpperCase().replaceAll(RegExp(r'[\s-]'), '');
    if (!compact.startsWith('ZC')) {
      throw const FormatException('Stonechat IDs start with SC-');
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
    return 'SC-${groups.join('-')}';
  }

  /// Any identity key we're handed (directory, x3dh block, member list) must
  /// hash back to the ID it claims to be.
  bool pubkeyMatchesId(String pubkeyB64, String stonechatId) {
    try {
      return deriveStonechatId(base64Decode(pubkeyB64)) == stonechatId;
    } catch (_) {
      return false;
    }
  }

  /// Proof of key possession for POST /v1/recover (identity restore): a
  /// signature over "stonechat-v1-recover" || the current unix time, so the hub
  /// can re-issue an account token without ever having stored one.
  String signRecovery(int unixSeconds) =>
      base64Encode(sodium.crypto.sign.detached(
        message: Uint8List.fromList(
            [...recoverSigContext, ...utf8.encode('$unixSeconds')]),
        secretKey: _identity.secretKey,
      ));

  /// Signs an abuse report (PROTOCOL.md "Reporting", hub/app/report.py).
  ///
  /// Reports are judged by the hub hosting the *reported* account, which under
  /// cross-hub resolution is often not ours — and our account token means nothing there.
  /// A signature does cross that boundary: any hub can check that this key
  /// hashes to the reporter's Stonechat ID. The body is committed to by digest
  /// rather than signed directly, because it has to survive a round trip
  /// through JSON, where field order and whitespace do not.
  String signReport({
    required String reportedId,
    required int unixSeconds,
    required String category,
    required String note,
    required String? evidence,
  }) {
    // 0x1f (unit separator) between fields: without it a note ending in what
    // looks like the next field could collide with a different report.
    final digest = sodium.crypto.genericHash(
      message: Uint8List.fromList([
        ...utf8.encode(category),
        0x1f,
        ...utf8.encode(note),
        0x1f,
        ...utf8.encode(evidence ?? ''),
      ]),
      outLen: 32,
    );
    return base64Encode(sodium.crypto.sign.detached(
      message: Uint8List.fromList([
        ...reportSigContext,
        ...utf8.encode(reportedId),
        ...utf8.encode('$unixSeconds'),
        ...digest,
      ]),
      secretKey: _identity.secretKey,
    ));
  }

  // -- prekeys -----------------------------------------------------------------

  /// New X25519 keypair (signed prekeys, one-time prekeys, ratchet keys).
  KeyPair newX25519() => sodium.crypto.box.keyPair();

  /// New ML-KEM-768 prekey (signed and one-time KEM prekeys, PQXDH). The
  /// seed is the stored secret half; the pub is what the mailbox serves.
  ({Uint8List seed, Uint8List pub}) newMlkemPrekey() {
    final seed = sodium.randombytes.buf(mlkemSeedBytes);
    return (seed: seed, pub: pq.mlkemPkFromSeed(seed));
  }

  /// Encapsulate to a peer's ML-KEM prekey (initiator side of PQXDH).
  /// Throws [StateError] on a malformed key — treat like a forged bundle.
  ({Uint8List ct, Uint8List ss}) kemEncaps(Uint8List peerKemPub) =>
      pq.mlkemEncaps(
          peerKemPub, sodium.randombytes.buf(mlkemEncapsRandomBytes));

  /// Decapsulate with a stored prekey seed (responder side of PQXDH).
  Uint8List kemDecaps(Uint8List seed, Uint8List ct) =>
      pq.mlkemDecaps(seed, ct);

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

  Uint8List signKemPrekey(Uint8List kspkPub) => sodium.crypto.sign.detached(
        message: Uint8List.fromList([...kspkSigContext, ...kspkPub]),
        secretKey: _identity.secretKey,
      );

  bool verifyKemPrekeySig(
      Uint8List kspkPub, Uint8List sig, Uint8List identityEdPub) {
    try {
      return sodium.crypto.sign.verifyDetached(
        message: Uint8List.fromList([...kspkSigContext, ...kspkPub]),
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

  /// SK = H(DH1 || DH2 || DH3 [|| DH4] || KEM_SS,
  ///        key="stonechat-v1-pqxdh-kdf", 32)
  ///
  /// PQXDH: the classical X3DH transcript plus the ML-KEM shared secret.
  /// A PQ-secure SK makes the whole ratchet chain harvest-proof — every
  /// later root key derives from it (notes/docs/POST_QUANTUM.md step 1).
  Uint8List x3dhSharedKey(List<Uint8List> dhs, Uint8List kemSs) => _keyedHash(
      Uint8List.fromList([for (final d in dhs) ...d, ...kemSs]),
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
