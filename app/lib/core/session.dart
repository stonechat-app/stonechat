/// Forward-secret pairwise sessions: PQXDH establishment + double ratchet
/// (PROTOCOL.md "Session crypto"). One session per peer, serialized to the
/// local DB between messages. Message keys are single-use; compromise of
/// current state cannot decrypt previously recorded ciphertext.
///
/// Since the stonechat-core cutover the ratchet math lives in Rust
/// (repo /core, reached through core_ffi.dart) — the same compiled engine
/// the iOS notification extension links, so both processes advance session
/// state identically by construction. This file is the app-facing wrapper:
/// it holds the opaque state blob, feeds the core CSPRNG bytes from
/// the platform CSPRNG, and keeps the API `chat_state.dart` always used. The retired
/// Dart implementation's behavior is pinned by the golden corpus
/// (core/tests/fixtures/dart_transcript.json) and by
/// test/golden_transcript_test.dart, which now exercises this FFI path.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'core_ffi.dart';
import 'crypto.dart';

/// A peer's prekey bundle as served by their mailbox. Parsed fields are
/// for the host's signature checks (chat_state.dart); [raw] is what the
/// core consumes verbatim. `kspk`/`kopk` are the ML-KEM-768 halves of
/// PQXDH (docs/POST_QUANTUM.md): a signed KEM prekey that is always
/// present, plus a one-time KEM prekey when the pool isn't dry.
class PrekeyBundle {
  final Map<String, dynamic> raw;
  final int spkId;
  final Uint8List spkPub;
  final Uint8List spkSig;
  final int? opkId;
  final Uint8List? opkPub;
  final int kspkId;
  final Uint8List kspkPub;
  final Uint8List kspkSig;
  final int? kopkId;
  final Uint8List? kopkPub;

  PrekeyBundle._(this.raw)
    : spkId = raw['spk']['id'] as int,
      spkPub = base64Decode(raw['spk']['pub'] as String),
      spkSig = base64Decode(raw['spk']['sig'] as String),
      opkId = raw['opk']?['id'] as int?,
      opkPub = raw['opk'] == null
          ? null
          : base64Decode(raw['opk']['pub'] as String),
      kspkId = raw['kspk']['id'] as int,
      kspkPub = base64Decode(raw['kspk']['pub'] as String),
      kspkSig = base64Decode(raw['kspk']['sig'] as String),
      kopkId = raw['kopk']?['id'] as int?,
      kopkPub = raw['kopk'] == null
          ? null
          : base64Decode(raw['kopk']['pub'] as String);

  factory PrekeyBundle.fromJson(Map<String, dynamic> j) = PrekeyBundle._;
}

/// The x3dh block attached to a session's initial envelopes. `kct` is the
/// ML-KEM ciphertext, encapsulated to the one-time KEM prekey when the
/// bundle had one (its id in `kem_id`), else to the signed KEM prekey.
class X3dhBlock {
  /// The sender's **device** Ed25519 key — not their identity key.
  ///
  /// X3DH runs device-to-device since device certificates: this key is what
  /// [cert] vouches for, and the responder checks the certificate against the
  /// sender's identity key rather than checking this against their SC- ID
  /// (a device key does not hash to its owner's ID).
  final String ikB64;
  final String ekB64; // sender's ephemeral X25519 key
  final int spkId;
  final int? opkId;
  final String kctB64; // ML-KEM-768 ciphertext (PQXDH)
  final int kemId; // id of the KEM prekey encapsulated to
  final bool kemOneTime; // whether kem_id names a one-time KEM prekey

  /// The sender's device certificate, so the responder can trust [ikB64]
  /// without a network round trip on the receive path. Self-authenticating —
  /// signed by the sender's identity key, which the responder resolves from
  /// the directory — so it needs no AEAD coverage of its own.
  ///
  /// Null only on a block from before certificates existed, which is a
  /// session that cannot be established.
  final Map<String, dynamic>? cert;

  X3dhBlock({
    required this.ikB64,
    required this.ekB64,
    required this.spkId,
    this.opkId,
    required this.kctB64,
    required this.kemId,
    required this.kemOneTime,
    this.cert,
  });

  Map<String, Object?> toJson() => {
    'ik': ikB64,
    'ek': ekB64,
    'spk_id': spkId,
    if (opkId != null) 'opk_id': opkId,
    'kct': kctB64,
    'kem_id': kemId,
    'kem_one_time': kemOneTime,
    if (cert != null) 'cert': cert,
  };

  /// The same block with our certificate attached. The core builds the
  /// cryptographic parts; the certificate is a client-layer addition, so it
  /// is merged here rather than threaded through the FFI.
  X3dhBlock withCert(Map<String, dynamic>? ours) => X3dhBlock(
    ikB64: ikB64,
    ekB64: ekB64,
    spkId: spkId,
    opkId: opkId,
    kctB64: kctB64,
    kemId: kemId,
    kemOneTime: kemOneTime,
    cert: ours,
  );

  static X3dhBlock? fromJson(Map<String, dynamic>? j) => j == null
      ? null
      : X3dhBlock(
          ikB64: j['ik'] as String,
          ekB64: j['ek'] as String,
          spkId: j['spk_id'] as int,
          opkId: j['opk_id'] as int?,
          kctB64: j['kct'] as String,
          kemId: j['kem_id'] as int,
          kemOneTime: j['kem_one_time'] as bool? ?? false,
          cert: (j['cert'] as Map?)?.cast<String, dynamic>(),
        );
}

class RatchetSession {
  final CryptoService crypto;
  final String peerId;

  /// The core's serialized session state — opaque here; persisted verbatim
  /// (same shape the retired Dart ratchet wrote, so old DB rows load).
  Map<String, dynamic> _state;

  RatchetSession._(this.crypto, this.peerId, this._state);

  static StonechatCore get _core => StonechatCore();

  Uint8List _random(int n) => randomBytes(n);

  /// PQXDH as the initiator, **device to device**.
  ///
  /// [peerEdPub] is the peer device's signing key, taken from its certificate
  /// after that certificate was verified against their identity key.
  /// [ownEdSeed] is this device's own signing seed — not the identity's,
  /// which is what lets a device run this without holding the identity
  /// secret at all.
  factory RatchetSession.initiate(
    CryptoService crypto,
    String peerId,
    Uint8List peerEdPub,
    PrekeyBundle bundle, {
    required Uint8List ownEdSeed,
  }) {
    final state = _core.sessionInitiate(
      edSeed: ownEdSeed,
      peerEdPk: peerEdPub,
      bundleJson: jsonEncode(bundle.raw),
      ekSk: randomBytes(32),
      ratchetSk: randomBytes(32),
      kemRandom: randomBytes(32),
    );
    return RatchetSession._(crypto, peerId, state);
  }

  /// PQXDH as the responder, from an initial envelope's x3dh block and our
  /// stored prekey private halves.
  ///
  /// [senderEdPub] is the sending device's key, which the caller has already
  /// checked against the certificate in the block. [kemSeed] is the stored
  /// seed of the KEM prekey named by `block.kemId`.
  factory RatchetSession.respond(
    CryptoService crypto,
    String peerId,
    Uint8List senderEdPub,
    X3dhBlock block, {
    required Uint8List ownEdSeed,
    required Uint8List spkPub,
    required Uint8List spkSec,
    Uint8List? opkSec,
    required Uint8List kemSeed,
  }) {
    final state = _core.sessionRespond(
      edSeed: ownEdSeed,
      senderEdPk: senderEdPub,
      x3dhJson: jsonEncode(block.toJson()),
      spkPub: spkPub,
      spkSec: spkSec,
      opkSec: opkSec,
      kemSeed: kemSeed,
    );
    if (state == null) {
      throw const FormatException('malformed x3dh block');
    }
    return RatchetSession._(crypto, peerId, state);
  }

  bool get canSend => _state['cks'] != null;
  bool get confirmed => _state['confirmed'] as bool;
  bool get initiatedByUs => _state['initiated_by_us'] as bool;

  X3dhBlock? get pendingX3dh => X3dhBlock.fromJson(
    (_state['pending_x3dh'] as Map?)?.cast<String, dynamic>(),
  );

  /// Encrypt one message. [adPrefix] is "stonechat/v1|from|to|type" — the
  /// cleartext routing fields get bound into the AEAD. Mutates the
  /// session; persist it before handing the envelope to the network.
  ({Map<String, Object?> ratchet, Uint8List nonce, Uint8List ciphertext})
  encrypt(String plaintext, String adPrefix) {
    final nonce = _random(24);
    final result = _core.sessionEncrypt(
      stateJson: jsonEncode(_state),
      plaintext: utf8.encode(plaintext),
      adPrefix: adPrefix,
      nonce: nonce,
    );
    _state = result.state;
    return (
      ratchet: result.header,
      nonce: nonce,
      ciphertext: result.ciphertext,
    );
  }

  /// Decrypt one message. Returns null on failure, in which case the
  /// session state is untouched. On success the state has advanced —
  /// persist it.
  String? decrypt(
    Map<String, dynamic> header,
    Uint8List nonce,
    Uint8List ciphertext,
    String adPrefix,
  ) {
    final result = _core.sessionDecrypt(
      stateJson: jsonEncode(_state),
      headerJson: jsonEncode(header),
      nonce: nonce,
      ciphertext: ciphertext,
      adPrefix: adPrefix,
      freshRatchetSk: _random(32),
      // Separate draws: the ratchet key's public half goes on the wire, and
      // the post-quantum ratchet's KEM material must not be derivable from it.
      pqRandom: _random(64),
    );
    if (result == null) return null;
    _state = result.state;
    return utf8.decode(result.plaintext);
  }

  // -- persistence ---------------------------------------------------------------

  Map<String, dynamic> toJson() => _state;

  factory RatchetSession.fromJson(
    CryptoService crypto,
    String peerId,
    Map<String, dynamic> j,
  ) = RatchetSession._;
}
