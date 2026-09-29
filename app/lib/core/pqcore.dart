/// Bindings to the pqcore Rust crate (repo /pqcore) — ML-KEM-768 and X-Wing,
/// the post-quantum half of the protocol (docs/POST_QUANTUM.md). Pure
/// byte-in/byte-out: pqcore never draws entropy, so every random input is
/// passed in explicitly by the caller (crypto.dart's `randomBytes`, which is
/// `Random.secure()` — the platform CSPRNG, and the app's only one).
library;

import 'dart:ffi';
import 'core_ffi.dart';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

const mlkemSeedBytes = 64;
const mlkemPublicBytes = 1184;
const mlkemCiphertextBytes = 1088;
const mlkemEncapsRandomBytes = 32;
const xwingSeedBytes = 32;
const xwingPublicBytes = 1216;
const xwingCiphertextBytes = 1120;
const xwingEncapsRandomBytes = 64;
const kemSharedSecretBytes = 32;

typedef _Fn2Native = Int32 Function(Pointer<Uint8>, Pointer<Uint8>);
typedef _Fn2 = int Function(Pointer<Uint8>, Pointer<Uint8>);
typedef _Fn3Native =
    Int32 Function(Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>);
typedef _Fn3 = int Function(Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>);
typedef _Fn4Native =
    Int32 Function(
      Pointer<Uint8>,
      Pointer<Uint8>,
      Pointer<Uint8>,
      Pointer<Uint8>,
    );
typedef _Fn4 =
    int Function(
      Pointer<Uint8>,
      Pointer<Uint8>,
      Pointer<Uint8>,
      Pointer<Uint8>,
    );

class PqCore {
  final _Fn2 _mlkemPk;
  final _Fn4 _mlkemEncaps;
  final _Fn3 _mlkemDecaps;
  final _Fn2 _xwingPk;
  final _Fn4 _xwingEncaps;
  final _Fn3 _xwingDecaps;

  PqCore._(DynamicLibrary lib)
    : _mlkemPk = lib.lookupFunction<_Fn2Native, _Fn2>(
        'stonechat_mlkem_pk_from_seed',
      ),
      _mlkemEncaps = lib.lookupFunction<_Fn4Native, _Fn4>(
        'stonechat_mlkem_encaps',
      ),
      _mlkemDecaps = lib.lookupFunction<_Fn3Native, _Fn3>(
        'stonechat_mlkem_decaps',
      ),
      _xwingPk = lib.lookupFunction<_Fn2Native, _Fn2>(
        'stonechat_xwing_pk_from_seed',
      ),
      _xwingEncaps = lib.lookupFunction<_Fn4Native, _Fn4>(
        'stonechat_xwing_encaps',
      ),
      _xwingDecaps = lib.lookupFunction<_Fn3Native, _Fn3>(
        'stonechat_xwing_decaps',
      );

  static PqCore? _instance;

  // Since the stonechat-core cutover the KEM symbols ship inside the same
  // library as the session engine — one artifact, one loader.
  factory PqCore() => _instance ??= PqCore._(openCoreLibrary());

  Uint8List _call(
    int Function(Pointer<Uint8> out) body,
    int outLen,
    String op,
  ) {
    final out = calloc<Uint8>(outLen);
    try {
      final rc = body(out);
      if (rc != 0) throw StateError('pqcore $op failed ($rc)');
      return Uint8List.fromList(out.asTypedList(outLen));
    } finally {
      calloc.free(out);
    }
  }

  static Pointer<Uint8> _in(Uint8List bytes, int expected, String name) {
    if (bytes.length != expected) {
      throw ArgumentError('$name must be $expected bytes, got ${bytes.length}');
    }
    final p = calloc<Uint8>(bytes.length);
    p.asTypedList(bytes.length).setAll(0, bytes);
    return p;
  }

  Uint8List mlkemPkFromSeed(Uint8List seed) {
    final s = _in(seed, mlkemSeedBytes, 'seed');
    try {
      return _call((out) => _mlkemPk(s, out), mlkemPublicBytes, 'mlkem_pk');
    } finally {
      calloc.free(s);
    }
  }

  /// Throws [StateError] when [pk] is not a valid ML-KEM-768 key.
  ({Uint8List ct, Uint8List ss}) mlkemEncaps(Uint8List pk, Uint8List random) {
    final p = _in(pk, mlkemPublicBytes, 'pk');
    final r = _in(random, mlkemEncapsRandomBytes, 'random');
    final ss = calloc<Uint8>(kemSharedSecretBytes);
    try {
      final ct = _call(
        (out) => _mlkemEncaps(p, r, out, ss),
        mlkemCiphertextBytes,
        'mlkem_encaps',
      );
      return (
        ct: ct,
        ss: Uint8List.fromList(ss.asTypedList(kemSharedSecretBytes)),
      );
    } finally {
      calloc.free(p);
      calloc.free(r);
      calloc.free(ss);
    }
  }

  Uint8List mlkemDecaps(Uint8List seed, Uint8List ct) {
    final s = _in(seed, mlkemSeedBytes, 'seed');
    final c = _in(ct, mlkemCiphertextBytes, 'ct');
    try {
      return _call(
        (out) => _mlkemDecaps(s, c, out),
        kemSharedSecretBytes,
        'mlkem_decaps',
      );
    } finally {
      calloc.free(s);
      calloc.free(c);
    }
  }

  Uint8List xwingPkFromSeed(Uint8List seed) {
    final s = _in(seed, xwingSeedBytes, 'seed');
    try {
      return _call((out) => _xwingPk(s, out), xwingPublicBytes, 'xwing_pk');
    } finally {
      calloc.free(s);
    }
  }

  /// Throws [StateError] when [pk] does not parse as an X-Wing key.
  ({Uint8List ct, Uint8List ss}) xwingEncaps(Uint8List pk, Uint8List random) {
    final p = _in(pk, xwingPublicBytes, 'pk');
    final r = _in(random, xwingEncapsRandomBytes, 'random');
    final ss = calloc<Uint8>(kemSharedSecretBytes);
    try {
      final ct = _call(
        (out) => _xwingEncaps(p, r, out, ss),
        xwingCiphertextBytes,
        'xwing_encaps',
      );
      return (
        ct: ct,
        ss: Uint8List.fromList(ss.asTypedList(kemSharedSecretBytes)),
      );
    } finally {
      calloc.free(p);
      calloc.free(r);
      calloc.free(ss);
    }
  }

  Uint8List xwingDecaps(Uint8List seed, Uint8List ct) {
    final s = _in(seed, xwingSeedBytes, 'seed');
    final c = _in(ct, xwingCiphertextBytes, 'ct');
    try {
      return _call(
        (out) => _xwingDecaps(s, c, out),
        kemSharedSecretBytes,
        'xwing_decaps',
      );
    } finally {
      calloc.free(s);
      calloc.free(c);
    }
  }
}
