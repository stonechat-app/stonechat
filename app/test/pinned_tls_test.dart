// Regression: the pin lived in badCertificateCallback, which is only asked
// about certificates the platform has already rejected — so a certificate a
// CA vouches for skipped the pin entirely, and an http:// address skipped TLS.
// The client now opens the socket itself and compares the leaf's fingerprint
// before anything is written.
//
// What is asserted throughout is that the request never REACHED the server,
// not merely that the call failed: the owner token rides in the URL, and a
// check that runs after it has been sent is not a check.
//
// The servers need a certificate, generated here with openssl. Auto-skips
// where openssl is missing (same pattern as stonechat_id_test.dart).
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:stonechat/core/api.dart';
import 'package:stonechat/models.dart';

/// Which function fingerprints a certificate is not what is under test, so
/// this is the simplest one that is collision-free.
String _fp(Uint8List der) => base64Encode(der);

String _fpOfPem(String path) => _fp(
  base64Decode(
    File(path)
        .readAsLinesSync()
        .where((l) => !l.startsWith('-----'))
        .join(),
  ),
);

class _Relay {
  final HttpServer server;
  final List<Uri> seen = [];
  int sockets = 0;
  _Relay(this.server) {
    server.listen((request) async {
      seen.add(request.uri);
      if (request.uri.path == '/ws') {
        sockets++;
        final ws = await WebSocketTransformer.upgrade(request);
        ws.add(
          jsonEncode({
            'v': 1,
            'id': 'e1',
            'to': 'SC-TEST',
            'device': 1,
            'sealed': 'AA==',
          }),
        );
        return;
      }
      request.response
        ..write('ok')
        ..close();
    });
  }
  int get port => server.port;
}

void main() {
  Directory? dir;
  String? relayFp;
  String? otherFp;
  _Relay? relay;
  _Relay? plain;

  setUpAll(() async {
    certFingerprinter = _fp;
    final tmp = await Directory.systemTemp.createTemp('stonechat-pin');
    Future<bool> mint(String name) async {
      try {
        final r = await Process.run('openssl', [
          'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
          '-keyout', '${tmp.path}/$name.key',
          '-out', '${tmp.path}/$name.pem',
          '-days', '2', '-subj', '/CN=$name',
          // An address, so the platform's own validation has nothing to
          // object to once the certificate is trusted.
          '-addext', 'subjectAltName=IP:127.0.0.1',
          '-addext', 'extendedKeyUsage=serverAuth',
        ]);
        return r.exitCode == 0;
      } catch (_) {
        return false;
      }
    }

    if (!await mint('relay') || !await mint('other')) {
      await tmp.delete(recursive: true);
      return;
    }
    dir = tmp;
    relayFp = _fpOfPem('${tmp.path}/relay.pem');
    otherFp = _fpOfPem('${tmp.path}/other.pem');
    relay = _Relay(
      await HttpServer.bindSecure(
        InternetAddress.loopbackIPv4,
        0,
        SecurityContext()
          ..useCertificateChain('${tmp.path}/relay.pem')
          ..usePrivateKey('${tmp.path}/relay.key'),
      ),
    );
    plain = _Relay(await HttpServer.bind(InternetAddress.loopbackIPv4, 0));
  });

  tearDownAll(() async {
    await relay?.server.close(force: true);
    await plain?.server.close(force: true);
    await dir?.delete(recursive: true);
  });

  setUp(() {
    relay?.seen.clear();
    plain?.seen.clear();
  });

  test('the pinned certificate is accepted', () async {
    final r = relay;
    if (r == null) return markTestSkipped('openssl unavailable');
    final client = pinnedClient(relayFp!);
    final res = await client.get(
      Uri.parse('https://127.0.0.1:${r.port}/status?token=SECRET'),
    );
    client.close();
    expect(res.statusCode, 200);
    expect(r.seen, hasLength(1));
  });

  test('any other certificate is refused before the request is sent', () async {
    final r = relay;
    if (r == null) return markTestSkipped('openssl unavailable');
    final client = pinnedClient(otherFp!);
    await expectLater(
      client.get(Uri.parse('https://127.0.0.1:${r.port}/status?token=SECRET')),
      throwsA(anything),
    );
    client.close();
    expect(r.seen, isEmpty, reason: 'the token must not have left the device');
  });

  test('a certificate the platform trusts is still held to the pin', () async {
    // The case the old code let through: the platform accepts the certificate,
    // so nobody asked about the pin. Trusting the relay's certificate stands
    // in for a CA having issued it.
    final r = relay;
    if (r == null) return markTestSkipped('openssl unavailable');
    SecurityContext.defaultContext.setTrustedCertificates(
      '${dir!.path}/relay.pem',
    );
    // The precondition, or the rest proves nothing: an ordinary client, with
    // no callback at all, now connects to this server happily.
    final ordinary = HttpClient();
    final req = await ordinary.getUrl(
      Uri.parse('https://127.0.0.1:${r.port}/health'),
    );
    expect((await req.close()).statusCode, 200);
    ordinary.close(force: true);
    r.seen.clear();

    final client = pinnedClient(otherFp!);
    await expectLater(
      client.get(Uri.parse('https://127.0.0.1:${r.port}/status?token=SECRET')),
      throwsA(anything),
    );
    client.close();
    expect(r.seen, isEmpty, reason: 'the token must not have left the device');
  });

  test('an http address is refused before the request is sent', () async {
    final p = plain;
    if (p == null) return markTestSkipped('openssl unavailable');
    final client = pinnedClient(relayFp!);
    await expectLater(
      client.get(Uri.parse('http://127.0.0.1:${p.port}/status?token=SECRET')),
      throwsA(isA<SocketException>()),
    );
    client.close();
    expect(p.seen, isEmpty, reason: 'the token must not have left the device');
  });

  test('the socket delivers over the pinned certificate', () async {
    final r = relay;
    if (r == null) return markTestSkipped('openssl unavailable');
    final got = Completer<SealedEnvelope>();
    final socket = MailboxSocket(
      address: 'https://127.0.0.1:${r.port}',
      token: 'SECRET',
      tlsFp: relayFp!,
      onEnvelope: (e) async => got.complete(e),
    )..connect();
    final envelope = await got.future.timeout(const Duration(seconds: 5));
    socket.close();
    expect(envelope.id, 'e1');
  });

  test('the socket refuses another certificate and an http address', () async {
    final r = relay, p = plain;
    if (r == null || p == null) return markTestSkipped('openssl unavailable');
    final wrongPin = MailboxSocket(
      address: 'https://127.0.0.1:${r.port}',
      token: 'SECRET',
      tlsFp: otherFp!,
      onEnvelope: (_) async => fail('delivered over an unpinned certificate'),
    )..connect();
    final cleartext = MailboxSocket(
      address: 'http://127.0.0.1:${p.port}',
      token: 'SECRET',
      tlsFp: relayFp!,
      onEnvelope: (_) async => fail('delivered in cleartext'),
    )..connect();
    await Future<void>.delayed(const Duration(milliseconds: 800));
    wrongPin.close();
    cleartext.close();
    expect(r.seen, isEmpty, reason: 'the token must not have left the device');
    expect(p.seen, isEmpty, reason: 'the token must not have left the device');
  });
}
