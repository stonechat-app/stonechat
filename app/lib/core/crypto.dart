/// Identity and the primitives built on it. Since the stonechat-core
/// cutover this file holds no cryptography of its own: it is the app's
/// view of the Rust core (core_ffi.dart), which the iOS notification
/// extension links too. That is the point — a value two processes derive
/// separately is a bug waiting, and one already shipped that way (the
/// extension hashed the 32-byte seed where the app hashed the 64-byte
/// secret key, and no sealed envelope opened).
///
/// PROTOCOL.md: the identity is an Ed25519 signing keypair; the Stonechat
/// ID is "SC-" + base32(blake2b20(pubkey) || checksum2). Messages are
/// encrypted with per-message keys from a PQXDH + double-ratchet session
/// (session.dart). The post-quantum halves — ML-KEM-768 prekeys and the
/// X-Wing envelope seal (notes/docs/POST_QUANTUM.md) — come from pqcore;
/// both KEMs are always hybrid alongside the classical DHs, never a
/// replacement for them.
library;

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'core_ffi.dart';
import 'pqcore.dart';

/// Domain-separation constants — must match core/src/primitives.rs,
/// scripts/e2e.py and PROTOCOL.md.
final spkSigContext = utf8.encode('stonechat-v1-spk');
final kspkSigContext = utf8.encode('stonechat-v1-kspk');
final tlsSigContext = utf8.encode('stonechat-v1-tls');
final recoverSigContext = utf8.encode('stonechat-v1-recover');

/// The app's CSPRNG. `Random.secure()` is the platform generator
/// (SecRandomCopyBytes / getrandom); the core deliberately draws no
/// entropy of its own, so every random input is passed in explicitly.
final _rng = Random.secure();

/// The SC- ID alphabet, kept as a top-level helper because several call
/// sites (invite links, tests) used it straight from this library.
String base32Encode(Uint8List bytes) => StonechatCore().base32Encode(bytes);

Uint8List base32Decode(String text) => StonechatCore().base32Decode(text);

Uint8List randomBytes(int n) =>
    Uint8List.fromList(List<int>.generate(n, (_) => _rng.nextInt(256)));

class CryptoService {
  final StonechatCore core;
  final PqCore pq;

  final Uint8List _secretKey; // 64 bytes: seed || public, libsodium layout
  final Uint8List publicKey;
  final Uint8List pqPublicKey; // X-Wing identity public (directory pq_pk)
  final Uint8List _pqSeed;
  final String stonechatId;
  final String _pqPkSig;

  CryptoService._(
    this.core,
    this.pq,
    this._secretKey,
    this.publicKey,
    this.pqPublicKey,
    this._pqSeed,
    this.stonechatId,
    this._pqPkSig,
  );

  factory CryptoService._from(Uint8List secretKey, {PqCore? pqCore}) {
    final core = StonechatCore();
    final id = core.identity(secretKey: secretKey);
    return CryptoService._(
      core,
      pqCore ?? PqCore(),
      id.secret,
      id.public,
      id.pqPublic,
      core.pqSeedFromEdSecret(id.secret),
      id.stonechatId,
      id.pqPublicSigB64,
    );
  }

  /// Fresh identity (onboarding).
  factory CryptoService.generate({PqCore? pqCore}) {
    final id = StonechatCore().identity(seed: randomBytes(32));
    return CryptoService._from(id.secret, pqCore: pqCore);
  }

  /// Restore from stored key material.
  factory CryptoService.fromKeys({
    required Uint8List secretKey,
    PqCore? pqCore,
  }) => CryptoService._from(secretKey, pqCore: pqCore);

  String get publicKeyB64 => base64Encode(publicKey);
  String get pqPublicKeyB64 => base64Encode(pqPublicKey);

  /// The 32-byte Ed25519 seed — the identity root.
  ///
  /// Its one remaining job is signing device certificates: since those exist,
  /// nothing else derives from it at message time, and only the primary
  /// device holds it at all (MULTIDEVICE_IMPLEMENTATION.md "How device
  /// certificates work").
  Uint8List get identitySeed => Uint8List.sublistView(_secretKey, 0, 32);
  Uint8List exportSecretKey() => Uint8List.fromList(_secretKey);

  /// The Ed25519 seed (first half of the secret key) — what the session
  /// engine expands identities from (core_ffi.dart).
  Uint8List get identityEdSeed => Uint8List.sublistView(_secretKey, 0, 32);

  // -- sealed envelopes (PROTOCOL.md "Envelope") --------------------------------

  /// Anonymous hybrid seal to a peer's X-Wing identity key (`pq_pk` in the
  /// directory, signature-verified against their Ed25519 key on resolve) —
  /// the wrap that hides the sender (and every other envelope field) from
  /// the recipient's mailbox. X-Wing is X25519 + ML-KEM-768 in one KEM, so
  /// a recorded envelope stays sealed against a future quantum attacker.
  /// Like crypto_box_seal, encapsulation is fresh-randomness-per-envelope
  /// and involves no sender key: nothing on the wire identifies or links
  /// senders.
  Uint8List sealTo(Uint8List recipientPqPk, Uint8List message) => core.sealTo(
    recipientPqPk,
    message,
    randomBytes(xwingEncapsRandomBytes),
    randomBytes(24),
  );

  /// Returns null when the envelope wasn't sealed to this identity (or is
  /// garbage): a wrong recipient decapsulates to a wrong shared secret and
  /// the AEAD refuses.
  Uint8List? unseal(Uint8List sealed) => core.unseal(_pqSeed, sealed);

  /// The owner vouching for their X-Wing identity key; published beside it
  /// in the hub directory and verified by every resolver.
  String signPqPk() => _pqPkSig;

  bool verifyPqPkSig(Uint8List pqPk, Uint8List sig, Uint8List identityEdPub) =>
      core.verify(identityEdPub, utf8.encode('stonechat-v1-pqpk'), pqPk, sig);

  // -- Stonechat ID ----------------------------------------------------------------

  String deriveStonechatId(Uint8List pubkey) => core.stonechatId(pubkey);

  /// Canonicalize user input; throws [FormatException] with a friendly
  /// message (the core reports one failure for every malformed shape).
  String normalizeStonechatId(String raw) {
    final id = core.normalizeId(raw);
    if (id == null) {
      throw const FormatException(
        "That doesn't look like a Stonechat ID — check for a typo",
      );
    }
    return id;
  }

  /// Any identity key we're handed (directory, x3dh block, member list)
  /// must hash back to the ID it claims to be.
  bool pubkeyMatchesId(String pubkeyB64, String stonechatId) {
    try {
      return deriveStonechatId(base64Decode(pubkeyB64)) == stonechatId;
    } catch (_) {
      return false;
    }
  }

  /// Proof of key possession for POST /v1/recover (identity restore): a
  /// signature over the context and the current unix time, so the hub can
  /// re-issue an account token without ever having stored one.
  String signRecovery(int unixSeconds) => base64Encode(
    core.sign(_secretKey, recoverSigContext, utf8.encode('$unixSeconds')),
  );

  /// Signs an abuse report (PROTOCOL.md "Reporting", hub/app/report.py).
  ///
  /// Reports are judged by the hub hosting the *reported* account, which
  /// under cross-hub resolution is often not ours — and our account token
  /// means nothing there. A signature does cross that boundary: any hub
  /// can check that this key hashes to the reporter's Stonechat ID.
  String signReport({
    required String reportedId,
    required int unixSeconds,
    required String category,
    required String note,
    required String? evidence,
  }) => base64Encode(
    core.signReport(
      _secretKey,
      reportedId: reportedId,
      unixSeconds: unixSeconds,
      category: category,
      note: note,
      evidence: evidence,
    ),
  );

  // -- prekeys -----------------------------------------------------------------

  /// New X25519 keypair (signed prekeys, one-time prekeys). The secret is
  /// a random scalar; the public half comes from the core.
  ({Uint8List publicKey, Uint8List secretKey}) newX25519() {
    final secret = randomBytes(32);
    return (publicKey: core.x25519Public(secret), secretKey: secret);
  }

  /// New ML-KEM-768 prekey (signed and one-time KEM prekeys, PQXDH). The
  /// seed is the stored secret half; the pub is what the mailbox serves.
  ({Uint8List seed, Uint8List pub}) newMlkemPrekey() {
    final seed = randomBytes(mlkemSeedBytes);
    return (seed: seed, pub: pq.mlkemPkFromSeed(seed));
  }

  Uint8List signPrekey(Uint8List spkPub) =>
      core.sign(_secretKey, spkSigContext, spkPub);

  bool verifyPrekeySig(
    Uint8List spkPub,
    Uint8List sig,
    Uint8List identityEdPub,
  ) => core.verify(identityEdPub, spkSigContext, spkPub, sig);

  Uint8List signKemPrekey(Uint8List kspkPub) =>
      core.sign(_secretKey, kspkSigContext, kspkPub);

  bool verifyKemPrekeySig(
    Uint8List kspkPub,
    Uint8List sig,
    Uint8List identityEdPub,
  ) => core.verify(identityEdPub, kspkSigContext, kspkPub, sig);

  // -- pinned TLS (PROTOCOL.md "Transport") --------------------------------------

  /// What clients pin: BLAKE2b-256 of the relay's DER certificate.
  String certFingerprint(Uint8List certDer) => core.tlsFingerprintB64(certDer);

  /// BLAKE2b-256 of arbitrary bytes, lowercase hex.
  ///
  /// The core exposes this under the TLS-fingerprint symbol because that was
  /// its first caller; the function is a plain keyless hash. Used to derive a
  /// link grant's parking key from the QR's lookup secret, which is why the
  /// hex form matters: the relay validates keys as 64 lowercase hex digits.
  String blake2bHex(Uint8List data) => base64Decode(core.tlsFingerprintB64(data))
      .map((b) => b.toRadixString(16).padLeft(2, '0'))
      .join();

  /// The owner vouching for their mailbox's TLS key.
  String signTlsFp(String fpB64) =>
      base64Encode(core.sign(_secretKey, tlsSigContext, base64Decode(fpB64)));

  bool verifyTlsSig(String fpB64, String sigB64, Uint8List identityEdPub) {
    try {
      return core.verify(
        identityEdPub,
        tlsSigContext,
        base64Decode(fpB64),
        base64Decode(sigB64),
      );
    } catch (_) {
      return false;
    }
  }

  // -- media blobs (one-off symmetric key per file) ------------------------------

  /// Encrypt a media file with a fresh random key. The key+nonce travel to
  /// the recipient inside the session-encrypted envelope payload; the blob
  /// itself is opaque to every server that touches it.
  ({Uint8List key, Uint8List nonce, Uint8List ciphertext}) sealBlob(
    Uint8List data,
  ) {
    final key = randomBytes(32);
    final nonce = randomBytes(24);
    return (
      key: key,
      nonce: nonce,
      ciphertext: core.blobSeal(key, nonce, data),
    );
  }

  /// Returns null on tamper/corruption.
  Uint8List? openBlob(
    Uint8List ciphertext,
    Uint8List keyBytes,
    Uint8List nonce,
  ) {
    try {
      return core.blobOpen(keyBytes, nonce, ciphertext);
    } catch (_) {
      return null;
    }
  }
}
