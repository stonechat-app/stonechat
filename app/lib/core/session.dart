/// Forward-secret pairwise sessions: X3DH establishment + double ratchet
/// (PROTOCOL.md "Session crypto"). One session per peer, serialized to the
/// local DB between messages. Message keys are single-use; compromise of
/// current state cannot decrypt previously recorded ciphertext.
library;

import 'dart:collection';
import 'dart:convert';
import 'dart:typed_data';

import 'package:sodium/sodium_sumo.dart';

import 'crypto.dart';

const maxSkip = 256; // per-chain gap tolerance
const maxSkippedKeys = 512; // stored per session, oldest evicted

/// A peer's prekey bundle as served by their mailbox.
class PrekeyBundle {
  final int spkId;
  final Uint8List spkPub;
  final Uint8List spkSig;
  final int? opkId;
  final Uint8List? opkPub;

  PrekeyBundle({
    required this.spkId,
    required this.spkPub,
    required this.spkSig,
    this.opkId,
    this.opkPub,
  });

  factory PrekeyBundle.fromJson(Map<String, dynamic> j) {
    final spk = j['spk'] as Map<String, dynamic>;
    final opk = j['opk'] as Map<String, dynamic>?;
    return PrekeyBundle(
      spkId: spk['id'] as int,
      spkPub: base64Decode(spk['pub'] as String),
      spkSig: base64Decode(spk['sig'] as String),
      opkId: opk?['id'] as int?,
      opkPub: opk == null ? null : base64Decode(opk['pub'] as String),
    );
  }
}

/// The x3dh block attached to a session's initial envelopes.
class X3dhBlock {
  final String ikB64; // sender's Ed25519 identity key
  final String ekB64; // sender's ephemeral X25519 key
  final int spkId;
  final int? opkId;

  X3dhBlock(
      {required this.ikB64,
      required this.ekB64,
      required this.spkId,
      this.opkId});

  Map<String, Object?> toJson() => {
        'ik': ikB64,
        'ek': ekB64,
        'spk_id': spkId,
        if (opkId != null) 'opk_id': opkId,
      };

  static X3dhBlock? fromJson(Map<String, dynamic>? j) => j == null
      ? null
      : X3dhBlock(
          ikB64: j['ik'] as String,
          ekB64: j['ek'] as String,
          spkId: j['spk_id'] as int,
          opkId: j['opk_id'] as int?,
        );
}

class RatchetSession {
  final CryptoService crypto;
  final String peerId;

  bool initiatedByUs;
  bool confirmed; // we've decrypted ≥1 message from the peer on this session
  X3dhBlock? pendingX3dh; // attached to outgoing envelopes until confirmed

  Uint8List rk;
  Uint8List dhsPub;
  Uint8List dhsSec;
  Uint8List? dhr;
  Uint8List? cks;
  Uint8List? ckr;
  int ns = 0, nr = 0, pn = 0;
  final LinkedHashMap<String, Uint8List> skipped = LinkedHashMap();

  RatchetSession._({
    required this.crypto,
    required this.peerId,
    required this.initiatedByUs,
    required this.confirmed,
    required this.rk,
    required this.dhsPub,
    required this.dhsSec,
    this.dhr,
    this.cks,
    this.pendingX3dh,
  });

  /// X3DH as the initiator. [peerEdPub] must already be commitment-verified
  /// against the peer's Zeon ID and [bundle]'s SPK signature checked.
  factory RatchetSession.initiate(
      CryptoService crypto, String peerId, Uint8List peerEdPub, PrekeyBundle bundle) {
    final peerIkx = crypto.toX25519(peerEdPub);
    final ek = crypto.newX25519();
    final dhs = [
      crypto.dh(crypto.identityXsk, bundle.spkPub), // DH1
      crypto.dh(ek.secretKey, peerIkx), // DH2
      crypto.dh(ek.secretKey, bundle.spkPub), // DH3
      if (bundle.opkPub != null) crypto.dh(ek.secretKey, bundle.opkPub!), // DH4
    ];
    final sk = crypto.x3dhSharedKey(dhs);

    // The peer's SPK doubles as their initial ratchet key.
    final ratchetKp = crypto.newX25519();
    final ratchetSec = ratchetKp.secretKey.extractBytes();
    final (rk, cks) =
        crypto.kdfRoot(sk, crypto.dh(ratchetKp.secretKey, bundle.spkPub));
    ek.secretKey.dispose();
    ratchetKp.secretKey.dispose();

    return RatchetSession._(
      crypto: crypto,
      peerId: peerId,
      initiatedByUs: true,
      confirmed: false,
      rk: rk,
      dhsPub: ratchetKp.publicKey,
      dhsSec: ratchetSec,
      dhr: bundle.spkPub,
      cks: cks,
      pendingX3dh: X3dhBlock(
        ikB64: crypto.publicKeyB64,
        ekB64: base64Encode(ek.publicKey),
        spkId: bundle.spkId,
        opkId: bundle.opkId,
      ),
    );
  }

  /// X3DH as the responder, from an initial envelope's x3dh block and our
  /// stored prekey private halves. [senderEdPub] must already be
  /// commitment-verified against the envelope's `from`.
  factory RatchetSession.respond(
    CryptoService crypto,
    String peerId,
    Uint8List senderEdPub,
    X3dhBlock block, {
    required Uint8List spkPub,
    required Uint8List spkSec,
    Uint8List? opkSec,
  }) {
    final senderIkx = crypto.toX25519(senderEdPub);
    final ek = base64Decode(block.ekB64);
    final spkKey = SecureKey.fromList(crypto.sodium, spkSec);
    final opkKey =
        opkSec == null ? null : SecureKey.fromList(crypto.sodium, opkSec);
    try {
      final dhs = [
        crypto.dh(spkKey, senderIkx), // DH1
        crypto.dh(crypto.identityXsk, ek), // DH2
        crypto.dh(spkKey, ek), // DH3
        if (opkKey != null) crypto.dh(opkKey, ek), // DH4
      ];
      final sk = crypto.x3dhSharedKey(dhs);
      // Our SPK is our initial ratchet key; the first received header
      // triggers the usual DH-ratchet step before we can send.
      return RatchetSession._(
        crypto: crypto,
        peerId: peerId,
        initiatedByUs: false,
        confirmed: true, // born from a successfully decrypted message
        rk: sk,
        dhsPub: spkPub,
        dhsSec: Uint8List.fromList(spkSec),
      );
    } finally {
      spkKey.dispose();
      opkKey?.dispose();
    }
  }

  bool get canSend => cks != null;

  String _ad(String adPrefix, String dhB64, int pn, int n) =>
      '$adPrefix|$dhB64|$pn|$n';

  /// Encrypt one message. [adPrefix] is "zeon/v1|from|to|type" — the cleartext
  /// routing fields get bound into the AEAD. Mutates the session; persist it
  /// before handing the envelope to the network.
  ({Map<String, Object?> ratchet, Uint8List nonce, Uint8List ciphertext})
      encrypt(String plaintext, String adPrefix) {
    final sendChain = cks;
    if (sendChain == null) {
      throw StateError('session not ready to send (no send chain yet)');
    }
    final (mk, ckNext) = crypto.kdfChain(sendChain);
    cks = ckNext;
    final dhB64 = base64Encode(dhsPub);
    final ad = utf8.encode(_ad(adPrefix, dhB64, pn, ns));
    final sealed = crypto.aeadSeal(mk, utf8.encode(plaintext), ad);
    final header = {'dh': dhB64, 'pn': pn, 'n': ns};
    ns += 1;
    return (ratchet: header, nonce: sealed.nonce, ciphertext: sealed.ciphertext);
  }

  /// Decrypt one message. Returns null on failure, in which case the session
  /// state is untouched. On success the state has advanced — persist it.
  String? decrypt(Map<String, dynamic> header, Uint8List nonce,
      Uint8List ciphertext, String adPrefix) {
    final dhB64 = header['dh'] as String;
    final headerPn = header['pn'] as int;
    final headerN = header['n'] as int;
    final ad = utf8.encode(_ad(adPrefix, dhB64, headerPn, headerN));

    // Skipped key from an earlier out-of-order message?
    final skippedMk = skipped.remove('$dhB64/$headerN');
    if (skippedMk != null) {
      final plain = crypto.aeadOpen(skippedMk, nonce, ciphertext, ad);
      if (plain == null) {
        skipped['$dhB64/$headerN'] = skippedMk; // not it — put it back
        return null;
      }
      confirmed = true;
      pendingX3dh = null;
      return utf8.decode(plain);
    }

    // Work on a snapshot: a failed AEAD must not burn ratchet state.
    final snapshot = toJson();
    try {
      final headerDh = base64Decode(dhB64);
      if (dhr == null || !_bytesEq(headerDh, dhr!)) {
        if (!_skipReceiveKeys(headerPn)) return _restore(snapshot);
        _dhRatchet(headerDh);
      }
      if (!_skipReceiveKeys(headerN)) return _restore(snapshot);
      final chain = ckr;
      if (chain == null) return _restore(snapshot);
      final (mk, ckNext) = crypto.kdfChain(chain);
      ckr = ckNext;
      nr += 1;
      final plain = crypto.aeadOpen(mk, nonce, ciphertext, ad);
      if (plain == null) return _restore(snapshot);
      confirmed = true;
      pendingX3dh = null;
      return utf8.decode(plain);
    } catch (_) {
      return _restore(snapshot);
    }
  }

  Null _restore(Map<String, Object?> snapshot) {
    _loadFrom(snapshot);
    return null;
  }

  /// Derive and stash message keys for messages we haven't seen yet, up to
  /// (but not including) [until] on the current receive chain.
  bool _skipReceiveKeys(int until) {
    if (nr + maxSkip < until) return false; // absurd gap — refuse
    var chain = ckr;
    if (chain == null) return nr >= until;
    final dhB64 = dhr == null ? '' : base64Encode(dhr!);
    while (nr < until) {
      final (mk, ckNext) = crypto.kdfChain(chain!);
      chain = ckNext;
      skipped['$dhB64/$nr'] = mk;
      if (skipped.length > maxSkippedKeys) {
        skipped.remove(skipped.keys.first);
      }
      nr += 1;
    }
    ckr = chain;
    return true;
  }

  void _dhRatchet(Uint8List headerDh) {
    pn = ns;
    ns = 0;
    nr = 0;
    dhr = headerDh;
    final dhsKey = SecureKey.fromList(crypto.sodium, dhsSec);
    try {
      final (rk1, ckrNew) = crypto.kdfRoot(rk, crypto.dh(dhsKey, headerDh));
      rk = rk1;
      ckr = ckrNew;
    } finally {
      dhsKey.dispose();
    }
    final fresh = crypto.newX25519();
    dhsPub = fresh.publicKey;
    dhsSec = fresh.secretKey.extractBytes();
    fresh.secretKey.dispose();
    final dhsKey2 = SecureKey.fromList(crypto.sodium, dhsSec);
    try {
      final (rk2, cksNew) = crypto.kdfRoot(rk, crypto.dh(dhsKey2, headerDh));
      rk = rk2;
      cks = cksNew;
    } finally {
      dhsKey2.dispose();
    }
  }

  static bool _bytesEq(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    var diff = 0;
    for (var i = 0; i < a.length; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff == 0;
  }

  // -- persistence ---------------------------------------------------------------

  Map<String, Object?> toJson() => {
        'initiated_by_us': initiatedByUs,
        'confirmed': confirmed,
        'rk': base64Encode(rk),
        'dhs_pub': base64Encode(dhsPub),
        'dhs_sec': base64Encode(dhsSec),
        'dhr': dhr == null ? null : base64Encode(dhr!),
        'cks': cks == null ? null : base64Encode(cks!),
        'ckr': ckr == null ? null : base64Encode(ckr!),
        'ns': ns,
        'nr': nr,
        'pn': pn,
        'pending_x3dh': pendingX3dh?.toJson(),
        'skipped': [
          for (final e in skipped.entries) {'k': e.key, 'mk': base64Encode(e.value)}
        ],
      };

  void _loadFrom(Map<String, Object?> j) {
    initiatedByUs = j['initiated_by_us'] as bool;
    confirmed = j['confirmed'] as bool;
    rk = base64Decode(j['rk'] as String);
    dhsPub = base64Decode(j['dhs_pub'] as String);
    dhsSec = base64Decode(j['dhs_sec'] as String);
    dhr = j['dhr'] == null ? null : base64Decode(j['dhr'] as String);
    cks = j['cks'] == null ? null : base64Decode(j['cks'] as String);
    ckr = j['ckr'] == null ? null : base64Decode(j['ckr'] as String);
    ns = j['ns'] as int;
    nr = j['nr'] as int;
    pn = j['pn'] as int;
    pendingX3dh =
        X3dhBlock.fromJson((j['pending_x3dh'] as Map?)?.cast<String, dynamic>());
    skipped.clear();
    for (final raw in (j['skipped'] as List? ?? const [])) {
      final entry = (raw as Map).cast<String, dynamic>();
      skipped[entry['k'] as String] = base64Decode(entry['mk'] as String);
    }
  }

  factory RatchetSession.fromJson(
      CryptoService crypto, String peerId, Map<String, dynamic> j) {
    final session = RatchetSession._(
      crypto: crypto,
      peerId: peerId,
      initiatedByUs: false,
      confirmed: false,
      rk: Uint8List(32),
      dhsPub: Uint8List(32),
      dhsSec: Uint8List(32),
    );
    session._loadFrom(j);
    return session;
  }
}
