// The pqcore FFI boundary (ML-KEM-768 + X-Wing, docs/POST_QUANTUM.md).
// Needs the host library: `scripts/build_pqcore.sh host`, then
// `STONECHAT_PQCORE_LIB=$PWD/../pqcore/target/release/libpqcore.dylib flutter test`
// (auto-skips when the library isn't available). The seed→pk vectors were
// generated with scripts/pqcore.py — the same C ABI over ctypes — so a
// mismatch means the Dart marshalling is wrong, not the crypto.
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:stonechat/core/pqcore.dart';

void main() {
  late final PqCore pq;
  var available = true;
  try {
    pq = PqCore();
  } catch (_) {
    available = false;
  }

  Uint8List seq(int n) => Uint8List.fromList(List.generate(n, (i) => i));

  test('X-Wing seed→pk matches the Python/ctypes reference', () {
    if (!available) return markTestSkipped('pqcore library not built');
    final pk = pq.xwingPkFromSeed(seq(xwingSeedBytes));
    expect(pk.length, xwingPublicBytes);
    expect(pk.sublist(0, 16),
        [111, 84, 9, 138, 10, 14, 100, 17, 70, 97, 75, 105, 96, 186, 96, 216]);
    expect(pk.sublist(pk.length - 4), [79, 232, 29, 122]);
  });

  test('ML-KEM seed→pk matches the Python/ctypes reference', () {
    if (!available) return markTestSkipped('pqcore library not built');
    final pk = pq.mlkemPkFromSeed(seq(mlkemSeedBytes));
    expect(pk.length, mlkemPublicBytes);
    expect(pk.sublist(0, 16),
        [41, 138, 161, 13, 66, 60, 141, 218, 6, 157, 2, 188, 89, 230, 205, 240]);
    expect(pk.sublist(pk.length - 4), [77, 234, 5, 120]);
  });

  test('ML-KEM encaps/decaps round-trips and rejects tampering', () {
    if (!available) return markTestSkipped('pqcore library not built');
    final seed = seq(mlkemSeedBytes);
    final pk = pq.mlkemPkFromSeed(seed);
    final enc = pq.mlkemEncaps(pk, Uint8List(mlkemEncapsRandomBytes));
    expect(pq.mlkemDecaps(seed, enc.ct), enc.ss);
    final forged = Uint8List.fromList(enc.ct)..[0] ^= 1;
    expect(pq.mlkemDecaps(seed, forged), isNot(enc.ss)); // implicit rejection
  });

  test('X-Wing encaps/decaps round-trips', () {
    if (!available) return markTestSkipped('pqcore library not built');
    final seed = seq(xwingSeedBytes);
    final pk = pq.xwingPkFromSeed(seed);
    final enc = pq.xwingEncaps(pk, Uint8List(xwingEncapsRandomBytes));
    expect(pq.xwingDecaps(seed, enc.ct), enc.ss);
  });
}
