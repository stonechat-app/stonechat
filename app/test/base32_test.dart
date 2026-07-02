// Cross-implementation vectors: outputs of Python's base64.b32encode
// (padding stripped) for bytes(range(7, 7+n)). The Dart base32 codec must
// match exactly or Zeon IDs minted by the app won't validate on the
// control plane (and vice versa). The 22-byte case is the ID payload size.
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:zeon_chat/core/crypto.dart';

void main() {
  const vectors = {
    1: 'A4',
    5: 'A4EASCQL',
    20: 'A4EASCQLBQGQ4DYQCEJBGFAVCYLRQGI2',
    22: 'A4EASCQLBQGQ4DYQCEJBGFAVCYLRQGI2DMOA',
    32: 'A4EASCQLBQGQ4DYQCEJBGFAVCYLRQGI2DMOB2HQ7EAQSEIZEEUTA',
  };

  test('base32Encode matches the Python reference implementation', () {
    vectors.forEach((n, expected) {
      final bytes = Uint8List.fromList(List.generate(n, (i) => 7 + i));
      expect(base32Encode(bytes), expected, reason: 'length $n');
    });
  });

  test('base32Decode round-trips', () {
    vectors.forEach((n, encoded) {
      expect(
        base32Decode(encoded),
        List.generate(n, (i) => 7 + i),
        reason: 'length $n',
      );
    });
  });
}
