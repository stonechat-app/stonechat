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
/// X-Wing envelope seal (docs/POST_QUANTUM.md) — come from pqcore;
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
final deleteSigContext = utf8.encode('stonechat-v1-delete');

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

  /// 64 bytes: seed || public, libsodium layout. **Null on a linked device**,
  /// which holds no identity secret at all — see [CryptoService.publicOnly].
  final Uint8List? _secretKey;
  final Uint8List publicKey;
  /// The identity's own X-Wing key, still published in the directory as
  /// `pq_pk` and still signature-verified on resolve — but **nothing seals to
  /// it any more**. Envelopes go to a device's certified seal key instead.
  /// Its private half used to live here as `_pqSeed`; that field became
  /// unused the moment unsealing moved to the device key, which is a fair
  /// summary of what device certificates changed. Retiring the directory
  /// field itself is a separate cleanup — it touches registration and the
  /// hub schema.
  /// Null on a linked device: it is derived from the identity secret, and is
  /// only ever needed at registration, which is the primary's job.
  final Uint8List? pqPublicKey;
  final String stonechatId;
  final String? _pqPkSig;

  CryptoService._(
    this.core,
    this.pq,
    this._secretKey,
    this.publicKey,
    this.pqPublicKey,
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

  /// A device that knows **who** it is but cannot act as the root.
  ///
  /// This is what a linked device gets. It can send and receive — those run
  /// on device keys since 08-03 — but it cannot mint a certificate, sign its
  /// mailbox's TLS fingerprint, recover the account, or export the identity.
  /// Each of those throws rather than degrading, because the alternative is a
  /// linked device that appears to do them and silently does not.
  ///
  /// The public key is still checked against the Stonechat ID by the caller
  /// ([AppState.adoptLinkGrant]) — it is what the device's own certificate
  /// verifies against, so a wrong one would leave it unable to prove itself.
  factory CryptoService.publicOnly({
    required Uint8List publicKey,
    PqCore? pqCore,
  }) {
    final core = StonechatCore();
    return CryptoService._(
      core,
      pqCore ?? PqCore(),
      null,
      publicKey,
      null,
      core.stonechatId(publicKey),
      null,
    );
  }

  /// True when this device holds the identity root — i.e. it is the primary.
  bool get hasIdentitySecret => _secretKey != null;

  Uint8List get _root {
    final key = _secretKey;
    if (key == null) {
      throw StateError(
        'This device holds no identity secret — that is the primary\'s job.',
      );
    }
    return key;
  }

  String get publicKeyB64 => base64Encode(publicKey);
  /// Registration only, and registration is the primary's. Throws on a
  /// linked device rather than returning something that would be published as
  /// this identity's post-quantum key.
  String get pqPublicKeyB64 => base64Encode(
    pqPublicKey ?? (throw StateError('no identity secret: cannot derive pq_pk')),
  );

  /// The 32-byte Ed25519 seed — the identity root.
  ///
  /// Its one remaining job is signing device certificates: since those exist,
  /// nothing else derives from it at message time, and only the primary
  /// device holds it at all.
  Uint8List get identitySeed => Uint8List.sublistView(_root, 0, 32);
  Uint8List exportSecretKey() => Uint8List.fromList(_root);

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
  /// Open an envelope sealed to this **device's** key.
  ///
  /// [deviceSealSeed] is our own X-Wing seed. It used to be the identity's
  /// (`_pqSeed`), which is why every device needed the identity secret to
  /// read anything.
  Uint8List? unseal(Uint8List deviceSealSeed, Uint8List sealed) =>
      core.unseal(deviceSealSeed, sealed);

  /// The owner vouching for their X-Wing identity key; published beside it
  /// in the hub directory and verified by every resolver.
  String signPqPk() =>
      _pqPkSig ?? (throw StateError('no identity secret: cannot sign pq_pk'));

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

  /// Whether a directory's answer is an answer to the question asked.
  ///
  /// Checked against [askedFor], never [returnedId] alone: somebody else's
  /// complete record is internally consistent — its key does hash to its ID —
  /// and the only thing wrong with it is that it is not what was asked for.
  bool directoryAnswers({
    required String askedFor,
    required String returnedId,
    required String pubkeyB64,
  }) => returnedId == askedFor && pubkeyMatchesId(pubkeyB64, askedFor);

  /// Proof of key possession for POST /v1/recover (identity restore): a
  /// signature over the context and the current unix time, so the hub can
  /// re-issue an account token without ever having stored one.
  String signRecovery(int unixSeconds) => base64Encode(
    core.sign(_root, recoverSigContext, utf8.encode('$unixSeconds')),
  );

  /// Proof of key possession for POST /v1/account/delete: the bearer token
  /// alone must not be enough to erase an account, and only the primary holds
  /// the key, so a linked device cannot delete the account it belongs to.
  String signAccountDeletion(int unixSeconds) => base64Encode(
    core.sign(_root, deleteSigContext, utf8.encode('$unixSeconds')),
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
      _root,
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

  /// Prekeys are signed by the **device**, not the identity.
  ///
  /// Before device certificates, senders verified these against the identity
  /// key from the directory, which is precisely why every device needed the
  /// identity secret to be reachable at all. Now a device signs with its own
  /// key and its certificate is what ties that key to its owner.
  Uint8List signPrekey(Uint8List deviceSecret, Uint8List spkPub) =>
      core.sign(deviceSecret, spkSigContext, spkPub);

  /// [deviceSigPub] comes from the device's certificate, which the caller
  /// has already verified against the owner's identity key.
  bool verifyPrekeySig(
    Uint8List spkPub,
    Uint8List sig,
    Uint8List deviceSigPub,
  ) => core.verify(deviceSigPub, spkSigContext, spkPub, sig);

  Uint8List signKemPrekey(Uint8List deviceSecret, Uint8List kspkPub) =>
      core.sign(deviceSecret, kspkSigContext, kspkPub);

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
      base64Encode(core.sign(_root, tlsSigContext, base64Decode(fpB64)));

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
  /// itself is opaque to every mailbox that touches it.
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
