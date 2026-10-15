// A sibling device's word on where a blob of ours sits
// (lib/core/sibling_blob.dart): only our own mailbox, under its own
// certificate, with the blob's own fetch token — and never this device's
// mailbox token in its place.
import 'package:flutter_test/flutter_test.dart';
import 'package:stonechat/core/sibling_blob.dart';

const _ours = 'https://mail.example:8443';
const _ourFp = 'sha256:ours';
const _blob = '0f8fad5b-d9cb-469f-a165-70867728950e';

Map<String, dynamic> _payload({
  Object? host = _ours,
  Object? tlsFp = _ourFp,
  Object? blobId = _blob,
  Object? token = 'tok-blob',
}) => {
  'blob_host': ?host,
  'blob_tls_fp': ?tlsFp,
  'blob_id': ?blobId,
  'fetch_token': ?token,
};

void main() {
  String? why;
  SiblingBlob? check(Map<String, dynamic> p) {
    why = null;
    return siblingBlobFrom(
      p,
      mailboxAddress: _ours,
      mailboxTlsFp: _ourFp,
      reason: (r) => why = r,
    );
  }

  test('a blob on our own mailbox, with its fetch token, is fetched', () {
    final b = check(_payload());
    expect(b, (host: _ours, tlsFp: _ourFp, blobId: _blob, token: 'tok-blob'));
    expect(why, isNull);
  });

  test('another host is refused, whatever certificate it names', () {
    expect(check(_payload(host: 'https://evil.example')), isNull);
    expect(why, contains('not on our own mailbox'));
    expect(
      check(_payload(host: 'https://evil.example', tlsFp: 'sha256:evil')),
      isNull,
    );
  });

  test('our host under another certificate is refused', () {
    expect(check(_payload(tlsFp: 'sha256:evil')), isNull);
    expect(why, contains('certificate'));
  });

  test('a missing or empty fetch token is refused — nothing is substituted',
      () {
    expect(check(_payload(token: null)), isNull);
    expect(why, contains('fetch_token'));
    expect(check(_payload(token: '')), isNull);
    expect(check(_payload(token: 7)), isNull);
  });

  test('malformed coordinates are refused', () {
    expect(check(_payload(host: null)), isNull);
    expect(check(_payload(tlsFp: 3)), isNull);
    expect(check(_payload(blobId: '../etc/passwd')), isNull);
    expect(check(_payload(blobId: null)), isNull);
    expect(why, contains('malformed'));
  });
}
