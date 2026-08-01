// Device linking (MULTIDEVICE.md "Linking a device"). The QR is the trust
// anchor of the whole flow — the user carries it between two screens — so
// what it encodes, and what the scanner refuses, is worth pinning.
import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:stonechat/core/linking.dart';

Uint8List bytes(int n, [int fill = 7]) =>
    Uint8List.fromList(List.filled(n, fill));

LinkOffer offer() => LinkOffer(ekPub: bytes(1216), lookup: bytes(32, 9));

void main() {
  group('LinkOffer', () {
    test('round-trips through the QR text', () {
      final back = LinkOffer.tryParse(offer().encode())!;
      expect(back.ekPub, offer().ekPub);
      expect(back.lookup, offer().lookup);
    });

    test('carries the lookup secret separately from the public key', () {
      // The whole point of the separation: the parking key must not be
      // derivable from anything a passer-by can read off the screen alone.
      final o = offer();
      expect(o.lookup, isNot(o.ekPub.sublist(0, 32)));
      final json =
          jsonDecode(
                utf8.decode(
                  base64Url.decode(o.encode().substring(linkScheme.length)),
                ),
              )
              as Map<String, dynamic>;
      expect(json.keys.toSet(), {'ek', 'lookup'});
    });

    test('refuses anything that is not one of ours', () {
      for (final junk in [
        '',
        'https://example.com',
        'stonechat:SC-SOMEONE', // the *invite* scheme, not the link one
        'stonechat-link:',
        'stonechat-link:not-base64!!',
        'stonechat-link:${base64Url.encode(utf8.encode('{"ek":"x"}'))}',
      ]) {
        expect(LinkOffer.tryParse(junk), isNull, reason: junk);
      }
    });

    test('refuses a key or lookup of the wrong size', () {
      // A short ek would fail later, inside the seal; failing at the scanner
      // is the difference between "that is not a Stonechat code" and a crash.
      String encoded(int ekLen, int lookupLen) => LinkOffer(
        ekPub: bytes(ekLen),
        lookup: bytes(lookupLen, 9),
      ).encode();
      expect(LinkOffer.tryParse(encoded(1215, 32)), isNull);
      expect(LinkOffer.tryParse(encoded(1216, 31)), isNull);
      expect(LinkOffer.tryParse(encoded(32, 32)), isNull);
      expect(LinkOffer.tryParse(encoded(1216, 32)), isNotNull);
    });

    test('tolerates the whitespace a scan or a paste can introduce', () {
      expect(LinkOffer.tryParse('  ${offer().encode()}\n'), isNotNull);
    });
  });

  group('LinkGrant', () {
    const grant = LinkGrant(
      identitySeedB64: 'c2VlZA==',
      stonechatId: 'SC-ALICE',
      displayName: 'Alice',
      hubUrl: 'https://hub.example',
      relayAddress: 'https://1.2.3.4:8080',
      relayTlsFp: 'ZnA=',
      deviceId: 3,
      deviceToken: 'tok',
      bundleToken: 'bt',
    );

    test('round-trips every field a device needs to be this user', () {
      final back = LinkGrant.fromJson(grant.toJson());
      expect(back.identitySeedB64, 'c2VlZA==');
      expect(back.stonechatId, 'SC-ALICE');
      expect(back.hubUrl, 'https://hub.example');
      expect(back.relayAddress, 'https://1.2.3.4:8080');
      expect(back.relayTlsFp, 'ZnA=');
      expect(back.deviceId, 3);
      expect(back.deviceToken, 'tok');
      expect(back.bundleToken, 'bt');
    });

    test('carries no hub account token', () {
      // Server management and billing stay with the primary: a linked device
      // must not be able to destroy the mailbox it lives on.
      final keys = grant.toJson().keys.toSet();
      expect(keys.any((k) => k.contains('account')), isFalse);
      expect(keys.any((k) => k.contains('billing')), isFalse);
      expect(keys, {
        'identity_seed',
        'stonechat_id',
        'display_name',
        'hub_url',
        'relay_address',
        'relay_tls_fp',
        'device_id',
        'device_token',
        'bundle_token',
      });
    });

    test('carries no history', () {
      // History arrives separately if at all (the backup-stream bootstrap);
      // a grant is authority, not content.
      final json = jsonEncode(grant.toJson());
      for (final word in ['message', 'history', 'text', 'contact']) {
        expect(json.contains(word), isFalse, reason: word);
      }
    });
  });

  test('the parking key is derived from the lookup secret, not the key', () {
    // Stand-in hash: only the *input* is being asserted here.
    String fakeHash(Uint8List d) => 'h${d.length}:${d.first}';
    final o = offer();
    expect(linkParkingKey(fakeHash, o.lookup), fakeHash(o.lookup));
    expect(linkParkingKey(fakeHash, o.lookup), isNot(fakeHash(o.ekPub)));
  });

  test('a minted device token is url-safe and unpadded', () {
    // It travels in a JSON body and, for the web client, potentially a URL.
    final token = newDeviceToken(bytes(32, 251));
    expect(token.contains('='), isFalse);
    expect(token.contains('+'), isFalse);
    expect(token.contains('/'), isFalse);
    // The relay requires at least 32 characters.
    expect(token.length, greaterThanOrEqualTo(32));
  });
}
