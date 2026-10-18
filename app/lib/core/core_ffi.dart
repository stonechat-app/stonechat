/// Bindings to stonechat-core (repo /core) — the protocol engine: PQXDH
/// establishment and the double ratchet, behind a C ABI. Session state is
/// an opaque JSON blob the app persists and hands back; every operation is
/// state-in/state-out, and all randomness is passed in explicitly by the
/// caller (crypto.dart's `randomBytes`, which is `Random.secure()` — the
/// platform CSPRNG, and the app's only one).
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
/// bindings. STONECHAT_CORE_LIB overrides; scripts/build_core.sh produces
/// every platform's artifact.
DynamicLibrary openCoreLibrary() {
  final override =
      Platform.environment['STONECHAT_CORE_LIB'] ??
      Platform.environment['STONECHAT_PQCORE_LIB']; // legacy name
  if (override != null) return DynamicLibrary.open(override);
  if (Platform.isAndroid) return DynamicLibrary.open('libstonechat_core.so');
  if (Platform.isIOS) return DynamicLibrary.process(); // static-linked
  final name = Platform.isMacOS
      ? 'libstonechat_core.dylib'
      : 'libstonechat_core.so';
  // Host runs (flutter test, tooling): dyld has no reason to know about a
  // cargo artifact, so a bare open fails with "Failed to load dynamic
  // library" — which reads like the library was never built, and cost us a
  // long time believing exactly that. Look where build_core.sh puts it,
  // the same search scripts/pqcore.py does, before giving up.
  final built = _builtCoreLibrary(name);
  if (built != null) return DynamicLibrary.open(built);
  try {
    return DynamicLibrary.open(name);
  } on ArgumentError {
    throw StateError(
      'stonechat-core not found. Run `scripts/build_core.sh host`, or point '
      'STONECHAT_CORE_LIB at the library.',
    );
  }
}

/// `core/target/release/<name>`, searched upward from the working directory
/// — `flutter test` runs in `app/`, tooling from the repo root.
String? _builtCoreLibrary(String name) {
  var dir = Directory.current.absolute;
  for (var i = 0; i < 5; i++) {
    final candidate = File(
      '${dir.path}${Platform.pathSeparator}core'
      '${Platform.pathSeparator}target'
      '${Platform.pathSeparator}release'
      '${Platform.pathSeparator}$name',
    );
    if (candidate.existsSync()) return candidate.path;
    final parent = dir.parent;
    if (parent.path == dir.path) break;
    dir = parent;
  }
  return null;
}


typedef _TlsFpNative = Int32 Function(Pointer<Uint8>, Size, Pointer<Uint8>);
typedef _TlsFp = int Function(Pointer<Uint8>, int, Pointer<Uint8>);

typedef _IdentityNative =
    Int32 Function(
      Pointer<Uint8>,
      Int32,
      Pointer<Pointer<Uint8>>,
      Pointer<Size>,
    );
typedef _Identity =
    int Function(Pointer<Uint8>, int, Pointer<Pointer<Uint8>>, Pointer<Size>);

typedef _DevcertSignNative =
    Int32 Function(
      Pointer<Uint8>,
      Size,
      Pointer<Uint8>,
      Pointer<Pointer<Uint8>>,
      Pointer<Size>,
    );
typedef _DevcertSign =
    int Function(
      Pointer<Uint8>,
      int,
      Pointer<Uint8>,
      Pointer<Pointer<Uint8>>,
      Pointer<Size>,
    );

typedef _DevcertVerifyNative =
    Int32 Function(
      Pointer<Uint8>,
      Size,
      Pointer<Uint8>,
      Uint64,
      Pointer<Pointer<Uint8>>,
      Pointer<Size>,
    );
typedef _DevcertVerify =
    int Function(
      Pointer<Uint8>,
      int,
      Pointer<Uint8>,
      int,
      Pointer<Pointer<Uint8>>,
      Pointer<Size>,
    );

typedef _WtcertsSignNative =
    Int32 Function(
      Pointer<Uint8>,
      Size,
      Pointer<Uint8>,
      Pointer<Pointer<Uint8>>,
      Pointer<Size>,
    );
typedef _WtcertsSign =
    int Function(
      Pointer<Uint8>,
      int,
      Pointer<Uint8>,
      Pointer<Pointer<Uint8>>,
      Pointer<Size>,
    );

typedef _WtcertsVerifyNative =
    Int32 Function(Pointer<Uint8>, Size, Pointer<Uint8>, Pointer<Uint8>);
typedef _WtcertsVerify =
    int Function(Pointer<Uint8>, int, Pointer<Uint8>, Pointer<Uint8>);

// Same shapes as the schedule signing above: JSON in, base64 signature out.
typedef _DevicesSignNative = _WtcertsSignNative;
typedef _DevicesSign = _WtcertsSign;
typedef _DevicesVerifyNative = _WtcertsVerifyNative;
typedef _DevicesVerify = _WtcertsVerify;

typedef _SignNative =
    Int32 Function(
      Pointer<Uint8>,
      Pointer<Uint8>,
      Size,
      Pointer<Uint8>,
      Size,
      Pointer<Uint8>,
    );
typedef _Sign =
    int Function(
      Pointer<Uint8>,
      Pointer<Uint8>,
      int,
      Pointer<Uint8>,
      int,
      Pointer<Uint8>,
    );

typedef _VerifyNative =
    Int32 Function(
      Pointer<Uint8>,
      Pointer<Uint8>,
      Size,
      Pointer<Uint8>,
      Size,
      Pointer<Uint8>,
    );
typedef _Verify =
    int Function(
      Pointer<Uint8>,
      Pointer<Uint8>,
      int,
      Pointer<Uint8>,
      int,
      Pointer<Uint8>,
    );

typedef _SignReportNative =
    Int32 Function(
      Pointer<Uint8>,
      Pointer<Uint8>,
      Size,
      Int64,
      Pointer<Uint8>,
      Size,
      Pointer<Uint8>,
      Size,
      Pointer<Uint8>,
      Size,
      Pointer<Uint8>,
    );
typedef _SignReport =
    int Function(
      Pointer<Uint8>,
      Pointer<Uint8>,
      int,
      int,
      Pointer<Uint8>,
      int,
      Pointer<Uint8>,
      int,
      Pointer<Uint8>,
      int,
      Pointer<Uint8>,
    );

typedef _IdNative =
    Int32 Function(Pointer<Uint8>, Pointer<Pointer<Uint8>>, Pointer<Size>);
typedef _Id =
    int Function(Pointer<Uint8>, Pointer<Pointer<Uint8>>, Pointer<Size>);

typedef _NormalizeNative =
    Int32 Function(
      Pointer<Uint8>,
      Size,
      Pointer<Pointer<Uint8>>,
      Pointer<Size>,
    );
typedef _Normalize =
    int Function(Pointer<Uint8>, int, Pointer<Pointer<Uint8>>, Pointer<Size>);

typedef _SealNative =
    Int32 Function(
      Pointer<Uint8>,
      Pointer<Uint8>,
      Size,
      Pointer<Uint8>,
      Pointer<Uint8>,
      Pointer<Pointer<Uint8>>,
      Pointer<Size>,
    );
typedef _Seal =
    int Function(
      Pointer<Uint8>,
      Pointer<Uint8>,
      int,
      Pointer<Uint8>,
      Pointer<Uint8>,
      Pointer<Pointer<Uint8>>,
      Pointer<Size>,
    );

typedef _UnsealNative =
    Int32 Function(
      Pointer<Uint8>,
      Pointer<Uint8>,
      Size,
      Pointer<Pointer<Uint8>>,
      Pointer<Size>,
    );
typedef _Unseal =
    int Function(
      Pointer<Uint8>,
      Pointer<Uint8>,
      int,
      Pointer<Pointer<Uint8>>,
      Pointer<Size>,
    );

typedef _BlobNative =
    Int32 Function(
      Pointer<Uint8>,
      Pointer<Uint8>,
      Pointer<Uint8>,
      Size,
      Pointer<Pointer<Uint8>>,
      Pointer<Size>,
    );
typedef _Blob =
    int Function(
      Pointer<Uint8>,
      Pointer<Uint8>,
      Pointer<Uint8>,
      int,
      Pointer<Pointer<Uint8>>,
      Pointer<Size>,
    );

typedef _VaultSealNative =
    Int32 Function(
      Pointer<Uint8>,
      Size,
      Pointer<Uint8>,
      Size,
      Pointer<Uint8>,
      Pointer<Uint8>,
      Uint32,
      Uint32,
      Pointer<Pointer<Uint8>>,
      Pointer<Size>,
    );
typedef _VaultSeal =
    int Function(
      Pointer<Uint8>,
      int,
      Pointer<Uint8>,
      int,
      Pointer<Uint8>,
      Pointer<Uint8>,
      int,
      int,
      Pointer<Pointer<Uint8>>,
      Pointer<Size>,
    );

typedef _VaultOpenNative =
    Int32 Function(
      Pointer<Uint8>,
      Size,
      Pointer<Uint8>,
      Size,
      Pointer<Pointer<Uint8>>,
      Pointer<Size>,
    );
typedef _VaultOpen =
    int Function(
      Pointer<Uint8>,
      int,
      Pointer<Uint8>,
      int,
      Pointer<Pointer<Uint8>>,
      Pointer<Size>,
    );

typedef _X25519Native = Int32 Function(Pointer<Uint8>, Pointer<Uint8>);
typedef _X25519 = int Function(Pointer<Uint8>, Pointer<Uint8>);

typedef _B32Native =
    Int32 Function(
      Pointer<Uint8>,
      Size,
      Pointer<Pointer<Uint8>>,
      Pointer<Size>,
    );
typedef _B32 =
    int Function(Pointer<Uint8>, int, Pointer<Pointer<Uint8>>, Pointer<Size>);

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
      Pointer<Uint8>,
      Pointer<Pointer<Uint8>>,
      Pointer<Size>,
    );

/// The core ABI this binding was written against (core/src/lib.rs
/// `ABI_VERSION`). A library built from an older core takes a different
/// argument list, and calling it anyway reads garbage instead of failing.
const coreAbiVersion = 3;

class StonechatCore {
  final _Free _free;
  final _TlsFp _tlsFp;
  final _Identity _identity;
  final _DevcertSign _devcertSign;
  final _DevcertVerify _devcertVerify;
  final _WtcertsSign _wtcertsSign;
  final _WtcertsVerify _wtcertsVerify;
  final _DevicesSign _devicesSign;
  final _DevicesVerify _devicesVerify;
  final _Sign _sign;
  final _Verify _verify;
  final _SignReport _signReport;
  final _Id _id;
  final _Normalize _normalize;
  final _Seal _seal;
  final _Unseal _unseal;
  final _Blob _blobSeal;
  final _Blob _blobOpen;
  final _VaultSeal _vaultSeal;
  final _VaultOpen _vaultOpen;
  final _X25519 _x25519;
  final _B32 _b32Encode;
  final _B32 _b32Decode;
  final _Initiate _initiate;
  final _Respond _respond;
  final _Encrypt _encrypt;
  final _Decrypt _decrypt;

  StonechatCore._(DynamicLibrary lib)
    : _free = lib.lookupFunction<_FreeNative, _Free>('stonechat_free'),
      _tlsFp = lib.lookupFunction<_TlsFpNative, _TlsFp>(
        'stonechat_tls_fingerprint',
      ),
      _identity = lib.lookupFunction<_IdentityNative, _Identity>(
        'stonechat_identity',
      ),
      _devcertSign = lib.lookupFunction<_DevcertSignNative, _DevcertSign>(
        'stonechat_devcert_sign',
      ),
      _devcertVerify = lib.lookupFunction<_DevcertVerifyNative, _DevcertVerify>(
        'stonechat_devcert_verify',
      ),
      _wtcertsSign = lib.lookupFunction<_WtcertsSignNative, _WtcertsSign>(
        'stonechat_wtcerts_sign',
      ),
      _wtcertsVerify = lib.lookupFunction<_WtcertsVerifyNative, _WtcertsVerify>(
        'stonechat_wtcerts_verify',
      ),
      _devicesSign = lib.lookupFunction<_DevicesSignNative, _DevicesSign>(
        'stonechat_devices_sign',
      ),
      _devicesVerify = lib.lookupFunction<_DevicesVerifyNative, _DevicesVerify>(
        'stonechat_devices_verify',
      ),
      _sign = lib.lookupFunction<_SignNative, _Sign>('stonechat_sign'),
      _verify = lib.lookupFunction<_VerifyNative, _Verify>('stonechat_verify'),
      _signReport = lib.lookupFunction<_SignReportNative, _SignReport>(
        'stonechat_sign_report',
      ),
      _id = lib.lookupFunction<_IdNative, _Id>('stonechat_stonechat_id'),
      _normalize = lib.lookupFunction<_NormalizeNative, _Normalize>(
        'stonechat_normalize_id',
      ),
      _seal = lib.lookupFunction<_SealNative, _Seal>('stonechat_seal'),
      _unseal = lib.lookupFunction<_UnsealNative, _Unseal>('stonechat_unseal'),
      _blobSeal = lib.lookupFunction<_BlobNative, _Blob>('stonechat_blob_seal'),
      _blobOpen = lib.lookupFunction<_BlobNative, _Blob>('stonechat_blob_open'),
      _vaultSeal = lib.lookupFunction<_VaultSealNative, _VaultSeal>(
        'stonechat_vault_seal',
      ),
      _vaultOpen = lib.lookupFunction<_VaultOpenNative, _VaultOpen>(
        'stonechat_vault_open',
      ),
      _x25519 = lib.lookupFunction<_X25519Native, _X25519>(
        'stonechat_x25519_public',
      ),
      _b32Encode = lib.lookupFunction<_B32Native, _B32>(
        'stonechat_base32_encode',
      ),
      _b32Decode = lib.lookupFunction<_B32Native, _B32>(
        'stonechat_base32_decode',
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

  factory StonechatCore() => _instance ??= _checked(openCoreLibrary());

  static StonechatCore _checked(DynamicLibrary lib) {
    final abi = lib.lookupFunction<Uint32 Function(), int Function()>(
      'stonechat_core_abi_version',
    )();
    if (abi != coreAbiVersion) {
      throw StateError(
        'stonechat-core ABI $abi, this build speaks $coreAbiVersion — '
        'rebuild the core library (scripts/build_core.sh)',
      );
    }
    return StonechatCore._(lib);
  }

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
    required Uint8List pqRandom,
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
    final pq = _in(pqRandom, 'pqRandom', expected: 64);
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
          pq,
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
      calloc.free(pq);
      calloc.free(stateP);
      calloc.free(headerP);
      calloc.free(nonceP);
      calloc.free(ctP);
      calloc.free(adP);
      calloc.free(fresh);
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

  // -- identity, signatures, IDs (PROTOCOL.md "Identity") ---------------------

  /// Expand a fresh 32-byte CSPRNG seed, or re-expand a stored 64-byte
  /// secret key, into the full identity: keys and the SC- ID.
  ({Uint8List secret, Uint8List public, String stonechatId}) identity({
    Uint8List? seed,
    Uint8List? secretKey,
  }) {
    final input = secretKey ?? seed!;
    final p = _in(
      input,
      'identity input',
      expected: secretKey != null ? 64 : 32,
    );
    final outPtr = calloc<Pointer<Uint8>>();
    final outLen = calloc<Size>();
    try {
      final rc = _identity(p, secretKey != null ? 1 : 0, outPtr, outLen);
      if (rc != 0) throw StateError('stonechat-core identity failed ($rc)');
      final json =
          jsonDecode(utf8.decode(outPtr.value.asTypedList(outLen.value)))
              as Map<String, dynamic>;
      _free(outPtr.value, outLen.value);
      return (
        secret: base64Decode(json['secret'] as String),
        public: base64Decode(json['public'] as String),
        stonechatId: json['stonechat_id'] as String,
      );
    } finally {
      calloc.free(p);
      calloc.free(outPtr);
      calloc.free(outLen);
    }
  }

  // -- device certificates (core/src/devcert.rs) ------------------------------

  /// Sign a device certificate with the identity root. Only the primary
  /// device holds the seed this needs.
  ///
  /// [unsigned] is `{stonechat_id, device_id, sig_pub, seal_pub, not_after}`;
  /// the result is the same object with `sig` added.
  Map<String, dynamic> devcertSign(
    Map<String, Object?> unsigned,
    Uint8List identitySeed,
  ) {
    final json = Uint8List.fromList(utf8.encode(jsonEncode(unsigned)));
    final body = _in(json, 'cert');
    final seed = _in(identitySeed, 'identitySeed', expected: 32);
    final outPtr = calloc<Pointer<Uint8>>();
    final outLen = calloc<Size>();
    try {
      final rc = _devcertSign(body, json.length, seed, outPtr, outLen);
      if (rc != 0) throw StateError('stonechat-core devcert sign failed ($rc)');
      final signed =
          jsonDecode(utf8.decode(outPtr.value.asTypedList(outLen.value)))
              as Map<String, dynamic>;
      _free(outPtr.value, outLen.value);
      return signed;
    } finally {
      calloc.free(body);
      calloc.free(seed);
      calloc.free(outPtr);
      calloc.free(outLen);
    }
  }

  /// Check a signed certificate against its owner's identity public key.
  ///
  /// Returns `valid`, `expired`, `bad_signature` or `wrong_identity` — the
  /// distinction matters: expiry is routine and heals when the owner renews,
  /// a bad signature is someone claiming a device that is not theirs, and a
  /// wrong identity is a key the certificate's SC- ID does not commit to. [nowSeconds] is passed in
  /// because the core takes no ambient anything.
  String devcertVerify(
    Map<String, dynamic> signed,
    Uint8List identityPublic,
    int nowSeconds,
  ) {
    final json = Uint8List.fromList(utf8.encode(jsonEncode(signed)));
    final body = _in(json, 'cert');
    final pub = _in(identityPublic, 'identityPublic', expected: 32);
    final outPtr = calloc<Pointer<Uint8>>();
    final outLen = calloc<Size>();
    try {
      final rc = _devcertVerify(
        body,
        json.length,
        pub,
        nowSeconds,
        outPtr,
        outLen,
      );
      // rc is 0 for valid and -3 for a refusal; both emit a status, and only
      // a malformed input emits nothing.
      if (outPtr.value == nullptr) {
        throw StateError('stonechat-core devcert verify failed ($rc)');
      }
      final status =
          (jsonDecode(utf8.decode(outPtr.value.asTypedList(outLen.value)))
              as Map<String, dynamic>)['status'];
      _free(outPtr.value, outLen.value);
      return status as String;
    } finally {
      calloc.free(body);
      calloc.free(pub);
      calloc.free(outPtr);
      calloc.free(outLen);
    }
  }

  /// Sign a mailbox's browser-transport certificate schedule.
  ///
  /// [published] is the body the relay served at `GET /wt/certs`. The bytes
  /// actually signed are canonical and length-prefixed (core/src/wtcerts.rs),
  /// not this JSON — three implementations have to agree on them, and JSON is
  /// not a canonical form.
  String wtcertsSign(Map<String, dynamic> published, Uint8List identitySeed) {
    final json = Uint8List.fromList(utf8.encode(jsonEncode(published)));
    final body = _in(json, 'certs');
    final seed = _in(identitySeed, 'identitySeed', expected: 32);
    final outPtr = calloc<Pointer<Uint8>>();
    final outLen = calloc<Size>();
    try {
      final rc = _wtcertsSign(body, json.length, seed, outPtr, outLen);
      if (rc != 0) throw StateError('stonechat-core wtcerts sign failed ($rc)');
      final sig = utf8.decode(outPtr.value.asTypedList(outLen.value));
      _free(outPtr.value, outLen.value);
      return sig;
    } finally {
      calloc.free(body);
      calloc.free(seed);
      calloc.free(outPtr);
      calloc.free(outLen);
    }
  }

  /// True when [published] is the list its owner signed.
  ///
  /// False means the relay served a schedule nobody vouched for, and the only
  /// safe response is to pin none of it — an unverified pin is worse than no
  /// pin, because it looks like security.
  bool wtcertsVerify(
    Map<String, dynamic> published,
    Uint8List identityPublic,
    Uint8List sig,
  ) {
    final json = Uint8List.fromList(utf8.encode(jsonEncode(published)));
    final body = _in(json, 'certs');
    final pub = _in(identityPublic, 'identityPublic', expected: 32);
    final signature = _in(sig, 'sig', expected: 64);
    try {
      final rc = _wtcertsVerify(body, json.length, pub, signature);
      if (rc == 0) return true;
      if (rc == -3) return false;
      throw StateError('stonechat-core wtcerts verify failed ($rc)');
    } finally {
      calloc.free(body);
      calloc.free(pub);
      calloc.free(signature);
    }
  }

  /// Sign the identity's device manifest (PROTOCOL.md "Device manifest").
  /// [manifest] is the unsigned form; returns the base64 signature.
  String devicesSign(Map<String, dynamic> manifest, Uint8List identitySeed) {
    final json = Uint8List.fromList(utf8.encode(jsonEncode(manifest)));
    final body = _in(json, 'manifest');
    final seed = _in(identitySeed, 'identitySeed', expected: 32);
    final outPtr = calloc<Pointer<Uint8>>();
    final outLen = calloc<Size>();
    try {
      final rc = _devicesSign(body, json.length, seed, outPtr, outLen);
      if (rc != 0) throw StateError('stonechat-core devices sign failed ($rc)');
      final sig = utf8.decode(outPtr.value.asTypedList(outLen.value));
      _free(outPtr.value, outLen.value);
      return sig;
    } finally {
      calloc.free(body);
      calloc.free(seed);
      calloc.free(outPtr);
      calloc.free(outLen);
    }
  }

  /// True when [manifest] is the genuine, well-formed device list of the
  /// identity [identityPublic] — which must also be the key the manifest's
  /// Stonechat ID commits to.
  bool devicesVerify(
    Map<String, dynamic> manifest,
    Uint8List identityPublic,
    Uint8List sig,
  ) {
    final json = Uint8List.fromList(utf8.encode(jsonEncode(manifest)));
    final body = _in(json, 'manifest');
    final pub = _in(identityPublic, 'identityPublic', expected: 32);
    final signature = _in(sig, 'sig', expected: 64);
    try {
      final rc = _devicesVerify(body, json.length, pub, signature);
      if (rc == 0) return true;
      if (rc == -3) return false;
      throw StateError('stonechat-core devices verify failed ($rc)');
    } finally {
      calloc.free(body);
      calloc.free(pub);
      calloc.free(signature);
    }
  }

  /// Sign with one of the protocol's domain-separation contexts.
  Uint8List sign(Uint8List secretKey, List<int> context, List<int> message) {
    final sk = _in(secretKey, 'secretKey', expected: 64);
    final ctx = _in(Uint8List.fromList(context), 'context');
    final msg = _in(Uint8List.fromList(message), 'message');
    final out = calloc<Uint8>(64);
    try {
      final rc = _sign(sk, ctx, context.length, msg, message.length, out);
      if (rc != 0) throw StateError('stonechat-core sign failed ($rc)');
      return Uint8List.fromList(out.asTypedList(64));
    } finally {
      calloc.free(sk);
      calloc.free(ctx);
      calloc.free(msg);
      calloc.free(out);
    }
  }

  bool verify(
    Uint8List edPublic,
    List<int> context,
    List<int> message,
    Uint8List signature,
  ) {
    if (edPublic.length != 32 || signature.length != 64) return false;
    final pk = _in(edPublic, 'edPublic', expected: 32);
    final ctx = _in(Uint8List.fromList(context), 'context');
    final msg = _in(Uint8List.fromList(message), 'message');
    final sig = _in(signature, 'signature', expected: 64);
    try {
      return _verify(pk, ctx, context.length, msg, message.length, sig) == 0;
    } finally {
      calloc.free(pk);
      calloc.free(ctx);
      calloc.free(msg);
      calloc.free(sig);
    }
  }

  /// Abuse report signature — the body is committed to by digest inside
  /// the core, so field order and whitespace can change in transit.
  Uint8List signReport(
    Uint8List secretKey, {
    required String reportedId,
    required int unixSeconds,
    required String category,
    required String note,
    String? evidence,
  }) {
    final sk = _in(secretKey, 'secretKey', expected: 64);
    final id = utf8.encode(reportedId);
    final idP = _in(id, 'reportedId');
    final cat = utf8.encode(category);
    final catP = _in(cat, 'category');
    final n = utf8.encode(note);
    final nP = _in(n, 'note');
    final ev = evidence == null ? null : utf8.encode(evidence);
    final evP = ev == null ? nullptr : _in(ev, 'evidence');
    final out = calloc<Uint8>(64);
    try {
      final rc = _signReport(
        sk,
        idP,
        id.length,
        unixSeconds,
        catP,
        cat.length,
        nP,
        n.length,
        evP,
        ev?.length ?? 0,
        out,
      );
      if (rc != 0) throw StateError('stonechat-core sign_report failed ($rc)');
      return Uint8List.fromList(out.asTypedList(64));
    } finally {
      calloc.free(sk);
      calloc.free(idP);
      calloc.free(catP);
      calloc.free(nP);
      if (evP != nullptr) calloc.free(evP);
      calloc.free(out);
    }
  }

  /// The SC- ID an identity key commits to.
  String stonechatId(Uint8List edPublic) {
    final pk = _in(edPublic, 'edPublic', expected: 32);
    final outPtr = calloc<Pointer<Uint8>>();
    final outLen = calloc<Size>();
    try {
      final rc = _id(pk, outPtr, outLen);
      if (rc != 0) throw StateError('stonechat-core id failed ($rc)');
      final text = utf8.decode(outPtr.value.asTypedList(outLen.value));
      _free(outPtr.value, outLen.value);
      return text;
    } finally {
      calloc.free(pk);
      calloc.free(outPtr);
      calloc.free(outLen);
    }
  }

  /// Canonicalize typed input; null when it is not a well-formed ID.
  String? normalizeId(String raw) {
    final bytes = utf8.encode(raw);
    final p = _in(bytes, 'raw');
    final outPtr = calloc<Pointer<Uint8>>();
    final outLen = calloc<Size>();
    try {
      final rc = _normalize(p, bytes.length, outPtr, outLen);
      if (rc == -3) return null;
      if (rc != 0) throw StateError('stonechat-core normalize failed ($rc)');
      final text = utf8.decode(outPtr.value.asTypedList(outLen.value));
      _free(outPtr.value, outLen.value);
      return text;
    } finally {
      calloc.free(p);
      calloc.free(outPtr);
      calloc.free(outLen);
    }
  }

  // -- envelope seal + media blobs --------------------------------------------

  Uint8List sealTo(
    Uint8List sealPub,
    Uint8List message,
    Uint8List random,
    Uint8List nonce,
  ) {
    final pk = _in(sealPub, 'sealPub', expected: 1216);
    final msg = _in(message, 'message');
    final rnd = _in(random, 'random', expected: 64);
    final n = _in(nonce, 'nonce', expected: 24);
    final outPtr = calloc<Pointer<Uint8>>();
    final outLen = calloc<Size>();
    try {
      final rc = _seal(pk, msg, message.length, rnd, n, outPtr, outLen);
      if (rc != 0) throw StateError('stonechat-core seal failed ($rc)');
      final sealed = Uint8List.fromList(outPtr.value.asTypedList(outLen.value));
      _free(outPtr.value, outLen.value);
      return sealed;
    } finally {
      calloc.free(pk);
      calloc.free(msg);
      calloc.free(rnd);
      calloc.free(n);
      calloc.free(outPtr);
      calloc.free(outLen);
    }
  }

  /// Null when the envelope was not sealed to this device's seal key.
  Uint8List? unseal(Uint8List sealSeed, Uint8List sealed) {
    final seed = _in(sealSeed, 'sealSeed', expected: 32);
    final data = _in(sealed, 'sealed');
    final outPtr = calloc<Pointer<Uint8>>();
    final outLen = calloc<Size>();
    try {
      final rc = _unseal(seed, data, sealed.length, outPtr, outLen);
      if (rc == -3) return null;
      if (rc != 0) throw StateError('stonechat-core unseal failed ($rc)');
      final plain = Uint8List.fromList(outPtr.value.asTypedList(outLen.value));
      _free(outPtr.value, outLen.value);
      return plain;
    } finally {
      calloc.free(seed);
      calloc.free(data);
      calloc.free(outPtr);
      calloc.free(outLen);
    }
  }

  Uint8List? _blob(
    _Blob fn,
    Uint8List key,
    Uint8List nonce,
    Uint8List data,
    String op,
  ) {
    final k = _in(key, 'key', expected: 32);
    final n = _in(nonce, 'nonce', expected: 24);
    final d = _in(data, 'data');
    final outPtr = calloc<Pointer<Uint8>>();
    final outLen = calloc<Size>();
    try {
      final rc = fn(k, n, d, data.length, outPtr, outLen);
      if (rc == -3) return null;
      if (rc != 0) throw StateError('stonechat-core $op failed ($rc)');
      final out = Uint8List.fromList(outPtr.value.asTypedList(outLen.value));
      _free(outPtr.value, outLen.value);
      return out;
    } finally {
      calloc.free(k);
      calloc.free(n);
      calloc.free(d);
      calloc.free(outPtr);
      calloc.free(outLen);
    }
  }

  Uint8List blobSeal(Uint8List key, Uint8List nonce, Uint8List data) =>
      _blob(_blobSeal, key, nonce, data, 'blob_seal')!;

  /// Null on tamper/corruption.
  Uint8List? blobOpen(Uint8List key, Uint8List nonce, Uint8List data) =>
      _blob(_blobOpen, key, nonce, data, 'blob_open');

  // -- passphrase containers (backup file, identity export) -------------------

  /// Argon2id + XChaCha20-Poly1305, parameters carried inside the result.
  /// Slow by design — run it off the UI isolate.
  Uint8List vaultSeal({
    required String passphrase,
    required Uint8List plaintext,
    required Uint8List salt,
    required Uint8List nonce,
    int mCostKib = 256 * 1024,
    int tCost = 3,
  }) {
    final pw = utf8.encode(passphrase);
    final pwP = _in(pw, 'passphrase');
    final plain = _in(plaintext, 'plaintext');
    final s = _in(salt, 'salt', expected: 16);
    final n = _in(nonce, 'nonce', expected: 24);
    final outPtr = calloc<Pointer<Uint8>>();
    final outLen = calloc<Size>();
    try {
      final rc = _vaultSeal(
        pwP,
        pw.length,
        plain,
        plaintext.length,
        s,
        n,
        mCostKib,
        tCost,
        outPtr,
        outLen,
      );
      if (rc != 0) throw StateError('stonechat-core vault_seal failed ($rc)');
      final out = Uint8List.fromList(outPtr.value.asTypedList(outLen.value));
      _free(outPtr.value, outLen.value);
      return out;
    } finally {
      calloc.free(pwP);
      calloc.free(plain);
      calloc.free(s);
      calloc.free(n);
      calloc.free(outPtr);
      calloc.free(outLen);
    }
  }

  /// Outcomes the UI distinguishes: [VaultOutcome.wrongPassphrase],
  /// [VaultOutcome.newerVersion], [VaultOutcome.malformed].
  ({Uint8List? plaintext, VaultOutcome outcome}) vaultOpen({
    required String passphrase,
    required Uint8List container,
  }) {
    final pw = utf8.encode(passphrase);
    final pwP = _in(pw, 'passphrase');
    final data = _in(container, 'container');
    final outPtr = calloc<Pointer<Uint8>>();
    final outLen = calloc<Size>();
    try {
      final rc = _vaultOpen(
        pwP,
        pw.length,
        data,
        container.length,
        outPtr,
        outLen,
      );
      switch (rc) {
        case 0:
          final plain = Uint8List.fromList(
            outPtr.value.asTypedList(outLen.value),
          );
          _free(outPtr.value, outLen.value);
          return (plaintext: plain, outcome: VaultOutcome.ok);
        case -3:
          return (plaintext: null, outcome: VaultOutcome.wrongPassphrase);
        case -4:
          return (plaintext: null, outcome: VaultOutcome.newerVersion);
        default:
          return (plaintext: null, outcome: VaultOutcome.malformed);
      }
    } finally {
      calloc.free(pwP);
      calloc.free(data);
      calloc.free(outPtr);
      calloc.free(outLen);
    }
  }

  /// Public half of an X25519 secret (prekeys, ratchet keys).
  Uint8List x25519Public(Uint8List secret) {
    final sk = _in(secret, 'secret', expected: 32);
    final out = calloc<Uint8>(32);
    try {
      final rc = _x25519(sk, out);
      if (rc != 0) throw StateError('stonechat-core x25519 failed ($rc)');
      return Uint8List.fromList(out.asTypedList(32));
    } finally {
      calloc.free(sk);
      calloc.free(out);
    }
  }

  Uint8List? _b32(_B32 fn, Uint8List input, String op) {
    final p = _in(input, 'input');
    final outPtr = calloc<Pointer<Uint8>>();
    final outLen = calloc<Size>();
    try {
      final rc = fn(p, input.length, outPtr, outLen);
      if (rc == -3) return null;
      if (rc != 0) throw StateError('stonechat-core $op failed ($rc)');
      final out = Uint8List.fromList(outPtr.value.asTypedList(outLen.value));
      _free(outPtr.value, outLen.value);
      return out;
    } finally {
      calloc.free(p);
      calloc.free(outPtr);
      calloc.free(outLen);
    }
  }

  /// The SC- ID alphabet (RFC 4648 without padding), one implementation
  /// for the app and every other client.
  String base32Encode(Uint8List bytes) =>
      utf8.decode(_b32(_b32Encode, bytes, 'base32_encode')!);

  /// Throws [FormatException] on an invalid character.
  Uint8List base32Decode(String text) {
    final out = _b32(_b32Decode, utf8.encode(text), 'base32_decode');
    if (out == null) throw const FormatException('invalid base32 character');
    return out;
  }
}

enum VaultOutcome { ok, wrongPassphrase, newerVersion, malformed }
