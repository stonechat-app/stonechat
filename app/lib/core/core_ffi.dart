/// Bindings to stonechat-core (repo /core) — the protocol engine: PQXDH
/// establishment and the double ratchet, behind a C ABI. Session state is
/// an opaque JSON blob the app persists and hands back; every operation is
/// state-in/state-out, and all randomness is passed in explicitly by the
/// caller (session.dart uses libsodium's randombytes, the same CSPRNG as
/// the rest of the app).
///
/// The compiled artifact also carries pqcore's KEM symbols — one library
/// serves both this and pqcore.dart (see scripts/build_core.sh).
library;

import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

/// Resolve the shared native library for BOTH pqcore.dart and these
/// bindings. Host runs (flutter test, tooling) point STONECHAT_CORE_LIB at
/// a `cargo build` output; scripts/build_core.sh produces every platform's.
DynamicLibrary openCoreLibrary() {
  final override =
      Platform.environment['STONECHAT_CORE_LIB'] ??
      Platform.environment['STONECHAT_PQCORE_LIB']; // legacy name
  if (override != null) return DynamicLibrary.open(override);
  if (Platform.isAndroid) return DynamicLibrary.open('libstonechat_core.so');
  if (Platform.isIOS) return DynamicLibrary.process(); // static-linked
  if (Platform.isMacOS) return DynamicLibrary.open('libstonechat_core.dylib');
  return DynamicLibrary.open('libstonechat_core.so');
}

typedef _PqSeedNative = Int32 Function(Pointer<Uint8>, Pointer<Uint8>);
typedef _PqSeed = int Function(Pointer<Uint8>, Pointer<Uint8>);

typedef _TlsFpNative = Int32 Function(Pointer<Uint8>, Size, Pointer<Uint8>);
typedef _TlsFp = int Function(Pointer<Uint8>, int, Pointer<Uint8>);

typedef _FreeNative = Void Function(Pointer<Uint8>, Size);
typedef _Free = void Function(Pointer<Uint8>, int);

typedef _InitiateNative =
    Int32 Function(
      Pointer<Uint8>,
      Pointer<Uint8>,
      Pointer<Uint8>,
      Size,
      Pointer<Uint8>,
      Pointer<Uint8>,
      Pointer<Uint8>,
      Pointer<Pointer<Uint8>>,
      Pointer<Size>,
    );
typedef _Initiate =
    int Function(
      Pointer<Uint8>,
      Pointer<Uint8>,
      Pointer<Uint8>,
      int,
      Pointer<Uint8>,
      Pointer<Uint8>,
      Pointer<Uint8>,
      Pointer<Pointer<Uint8>>,
      Pointer<Size>,
    );

typedef _RespondNative =
    Int32 Function(
      Pointer<Uint8>,
      Pointer<Uint8>,
      Pointer<Uint8>,
      Size,
      Pointer<Uint8>,
      Pointer<Uint8>,
      Pointer<Uint8>,
      Pointer<Uint8>,
      Pointer<Pointer<Uint8>>,
      Pointer<Size>,
    );
typedef _Respond =
    int Function(
      Pointer<Uint8>,
      Pointer<Uint8>,
      Pointer<Uint8>,
      int,
      Pointer<Uint8>,
      Pointer<Uint8>,
      Pointer<Uint8>,
      Pointer<Uint8>,
      Pointer<Pointer<Uint8>>,
      Pointer<Size>,
    );

typedef _EncryptNative =
    Int32 Function(
      Pointer<Uint8>,
      Size,
      Pointer<Uint8>,
      Size,
      Pointer<Uint8>,
      Size,
      Pointer<Uint8>,
      Pointer<Pointer<Uint8>>,
      Pointer<Size>,
    );
typedef _Encrypt =
    int Function(
      Pointer<Uint8>,
      int,
      Pointer<Uint8>,
      int,
      Pointer<Uint8>,
      int,
      Pointer<Uint8>,
      Pointer<Pointer<Uint8>>,
      Pointer<Size>,
    );

typedef _DecryptNative =
    Int32 Function(
      Pointer<Uint8>,
      Size,
      Pointer<Uint8>,
      Size,
      Pointer<Uint8>,
      Pointer<Uint8>,
      Size,
      Pointer<Uint8>,
      Size,
      Pointer<Uint8>,
      Pointer<Pointer<Uint8>>,
      Pointer<Size>,
    );
typedef _Decrypt =
    int Function(
      Pointer<Uint8>,
      int,
      Pointer<Uint8>,
      int,
      Pointer<Uint8>,
      Pointer<Uint8>,
      int,
      Pointer<Uint8>,
      int,
      Pointer<Uint8>,
      Pointer<Pointer<Uint8>>,
      Pointer<Size>,
    );

class StonechatCore {
  final _Free _free;
  final _PqSeed _pqSeed;
  final _TlsFp _tlsFp;
  final _Initiate _initiate;
  final _Respond _respond;
  final _Encrypt _encrypt;
  final _Decrypt _decrypt;

  StonechatCore._(DynamicLibrary lib)
    : _free = lib.lookupFunction<_FreeNative, _Free>('stonechat_free'),
      _pqSeed = lib.lookupFunction<_PqSeedNative, _PqSeed>(
        'stonechat_pq_seed_from_ed_secret',
      ),
      _tlsFp = lib.lookupFunction<_TlsFpNative, _TlsFp>(
        'stonechat_tls_fingerprint',
      ),
      _initiate = lib.lookupFunction<_InitiateNative, _Initiate>(
        'stonechat_session_initiate',
      ),
      _respond = lib.lookupFunction<_RespondNative, _Respond>(
        'stonechat_session_respond',
      ),
      _encrypt = lib.lookupFunction<_EncryptNative, _Encrypt>(
        'stonechat_session_encrypt',
      ),
      _decrypt = lib.lookupFunction<_DecryptNative, _Decrypt>(
        'stonechat_session_decrypt',
      );

  static StonechatCore? _instance;

  factory StonechatCore() => _instance ??= StonechatCore._(openCoreLibrary());

  static Pointer<Uint8> _in(Uint8List bytes, String name, {int? expected}) {
    if (expected != null && bytes.length != expected) {
      throw ArgumentError('$name must be $expected bytes, got ${bytes.length}');
    }
    final p = calloc<Uint8>(bytes.length);
    p.asTypedList(bytes.length).setAll(0, bytes);
    return p;
  }

  /// Runs [body] with out-params, decodes the core-allocated JSON result,
  /// frees it. Returns null on -3 (crypto refusal — a normal outcome);
  /// throws [StateError] on -1/-2 (caller bug or core bug).
  Map<String, dynamic>? _call(
    String op,
    int Function(Pointer<Pointer<Uint8>> outPtr, Pointer<Size> outLen) body,
  ) {
    final outPtr = calloc<Pointer<Uint8>>();
    final outLen = calloc<Size>();
    try {
      final rc = body(outPtr, outLen);
      if (rc == -3) return null;
      if (rc != 0) throw StateError('stonechat-core $op failed ($rc)');
      final ptr = outPtr.value;
      final len = outLen.value;
      try {
        return jsonDecode(utf8.decode(ptr.asTypedList(len)))
            as Map<String, dynamic>;
      } finally {
        _free(ptr, len);
      }
    } finally {
      calloc.free(outPtr);
      calloc.free(outLen);
    }
  }

  /// PQXDH as the initiator. [bundleJson] is the bundle exactly as the
  /// peer's mailbox served it; signatures must already be verified.
  /// Returns the fresh session state (pending x3dh block inside).
  Map<String, dynamic> sessionInitiate({
    required Uint8List edSeed,
    required Uint8List peerEdPk,
    required String bundleJson,
    required Uint8List ekSk,
    required Uint8List ratchetSk,
    required Uint8List kemRandom,
  }) {
    final seed = _in(edSeed, 'edSeed', expected: 32);
    final peer = _in(peerEdPk, 'peerEdPk', expected: 32);
    final bundle = utf8.encode(bundleJson);
    final bundleP = _in(bundle, 'bundleJson');
    final ek = _in(ekSk, 'ekSk', expected: 32);
    final ratchet = _in(ratchetSk, 'ratchetSk', expected: 32);
    final kem = _in(kemRandom, 'kemRandom', expected: 32);
    try {
      final state = _call(
        'initiate',
        (outPtr, outLen) => _initiate(
          seed,
          peer,
          bundleP,
          bundle.length,
          ek,
          ratchet,
          kem,
          outPtr,
          outLen,
        ),
      );
      // -3 here means a forged/malformed bundle slipped past verification.
      if (state == null) throw StateError('KEM prekey does not parse');
      return state;
    } finally {
      calloc.free(seed);
      calloc.free(peer);
      calloc.free(bundleP);
      calloc.free(ek);
      calloc.free(ratchet);
      calloc.free(kem);
    }
  }

  /// PQXDH as the responder. Returns the fresh session state, or null when
  /// the block is malformed (treat like an undecryptable envelope).
  Map<String, dynamic>? sessionRespond({
    required Uint8List edSeed,
    required Uint8List senderEdPk,
    required String x3dhJson,
    required Uint8List spkPub,
    required Uint8List spkSec,
    Uint8List? opkSec,
    required Uint8List kemSeed,
  }) {
    final seed = _in(edSeed, 'edSeed', expected: 32);
    final sender = _in(senderEdPk, 'senderEdPk', expected: 32);
    final block = utf8.encode(x3dhJson);
    final blockP = _in(block, 'x3dhJson');
    final spkP = _in(spkPub, 'spkPub', expected: 32);
    final spkS = _in(spkSec, 'spkSec', expected: 32);
    final opk = opkSec == null ? nullptr : _in(opkSec, 'opkSec', expected: 32);
    final kem = _in(kemSeed, 'kemSeed', expected: 64);
    try {
      return _call(
        'respond',
        (outPtr, outLen) => _respond(
          seed,
          sender,
          blockP,
          block.length,
          spkP,
          spkS,
          opk,
          kem,
          outPtr,
          outLen,
        ),
      );
    } finally {
      calloc.free(seed);
      calloc.free(sender);
      calloc.free(blockP);
      calloc.free(spkP);
      calloc.free(spkS);
      if (opk != nullptr) calloc.free(opk);
      calloc.free(kem);
    }
  }

  /// Encrypt one message. Returns the advanced state, the ratchet header,
  /// and the ciphertext. Throws [StateError] when the session cannot send
  /// yet (responder before the first received message).
  ({
    Map<String, dynamic> state,
    Map<String, dynamic> header,
    Uint8List ciphertext,
  })
  sessionEncrypt({
    required String stateJson,
    required Uint8List plaintext,
    required String adPrefix,
    required Uint8List nonce,
  }) {
    final state = utf8.encode(stateJson);
    final stateP = _in(state, 'stateJson');
    final plainP = _in(plaintext, 'plaintext');
    final ad = utf8.encode(adPrefix);
    final adP = _in(ad, 'adPrefix');
    final nonceP = _in(nonce, 'nonce', expected: 24);
    try {
      final result = _call(
        'encrypt',
        (outPtr, outLen) => _encrypt(
          stateP,
          state.length,
          plainP,
          plaintext.length,
          adP,
          ad.length,
          nonceP,
          outPtr,
          outLen,
        ),
      );
      if (result == null) {
        throw StateError('session not ready to send (no send chain yet)');
      }
      return (
        state: (result['state'] as Map).cast<String, dynamic>(),
        header: (result['header'] as Map).cast<String, dynamic>(),
        ciphertext: base64Decode(result['ciphertext'] as String),
      );
    } finally {
      calloc.free(stateP);
      calloc.free(plainP);
      calloc.free(adP);
      calloc.free(nonceP);
    }
  }

  /// Decrypt one message. Returns null on failure — the caller's state is
  /// untouched and still valid. On success, persist the returned state.
  ({Map<String, dynamic> state, Uint8List plaintext})? sessionDecrypt({
    required String stateJson,
    required String headerJson,
    required Uint8List nonce,
    required Uint8List ciphertext,
    required String adPrefix,
    required Uint8List freshRatchetSk,
  }) {
    final state = utf8.encode(stateJson);
    final stateP = _in(state, 'stateJson');
    final header = utf8.encode(headerJson);
    final headerP = _in(header, 'headerJson');
    final nonceP = _in(nonce, 'nonce', expected: 24);
    final ctP = _in(ciphertext, 'ciphertext');
    final ad = utf8.encode(adPrefix);
    final adP = _in(ad, 'adPrefix');
    final fresh = _in(freshRatchetSk, 'freshRatchetSk', expected: 32);
    try {
      final result = _call(
        'decrypt',
        (outPtr, outLen) => _decrypt(
          stateP,
          state.length,
          headerP,
          header.length,
          nonceP,
          ctP,
          ciphertext.length,
          adP,
          ad.length,
          fresh,
          outPtr,
          outLen,
        ),
      );
      if (result == null) return null;
      return (
        state: (result['state'] as Map).cast<String, dynamic>(),
        plaintext: base64Decode(result['plaintext'] as String),
      );
    } finally {
      calloc.free(stateP);
      calloc.free(headerP);
      calloc.free(nonceP);
      calloc.free(ctP);
      calloc.free(adP);
      calloc.free(fresh);
    }
  }

  /// The X-Wing identity seed derived from the full 64-byte libsodium
  /// secret key — the same KDF crypto.dart applies. Exposed so the app
  /// and the notification extension can be proven to agree
  /// (test/core_parity_test.dart); the app itself still derives its own.
  Uint8List pqSeedFromEdSecret(Uint8List edSecret) {
    final secret = _in(edSecret, 'edSecret', expected: 64);
    final out = calloc<Uint8>(32);
    try {
      final rc = _pqSeed(secret, out);
      if (rc != 0) throw StateError('stonechat-core pq seed failed ($rc)');
      return Uint8List.fromList(out.asTypedList(32));
    } finally {
      calloc.free(secret);
      calloc.free(out);
    }
  }

  /// What clients pin: base64(BLAKE2b-256(cert DER)) — the extension's
  /// copy of api.dart's check, kept honest by test/core_parity_test.dart.
  String tlsFingerprintB64(Uint8List certDer) {
    final der = _in(certDer, 'certDer');
    final out = calloc<Uint8>(32);
    try {
      final rc = _tlsFp(der, certDer.length, out);
      if (rc != 0) {
        throw StateError('stonechat-core tls fingerprint failed ($rc)');
      }
      return base64Encode(out.asTypedList(32));
    } finally {
      calloc.free(der);
      calloc.free(out);
    }
  }
}
