// The commitment must be byte-identical across the phone, the hub and the web
// client — three implementations of one hash over one concatenation. A drift
// here shows up as "that code has expired", which points nowhere useful.
import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:stonechat/core/core_ffi.dart';
import 'package:stonechat/core/linking.dart';

void main() {
  test('commitment matches the hub and the web client', () {
    Uint8List hash(Uint8List d) =>
        Uint8List.fromList(base64Decode(StonechatCore().tlsFingerprintB64(d)));
    final commit = offerCommitment(
      hash,
      Uint8List.fromList(List.filled(1216, 3)),
      Uint8List.fromList(List.filled(32, 4)),
    );
    expect(
      commit.map((b) => b.toRadixString(16).padLeft(2, '0')).join(),
      '7500b764f3392ffb9de621f93f0474571ce2675cae4a6420317588f8da212ae4',
    );
  });
}
