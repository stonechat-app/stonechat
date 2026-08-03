// Device linking (MULTIDEVICE.md "Linking a device"). The QR is the trust
// anchor of the whole flow — the user carries it between two screens — so
// what it encodes, and what the scanner refuses, is worth pinning.
import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:stonechat/core/core_ffi.dart';
import 'package:stonechat/core/crypto.dart';
import 'package:stonechat/core/device_keys.dart';
import 'package:stonechat/core/linking.dart';
import 'package:stonechat/core/pqcore.dart';

/// The FFI core, or null where the native library isn't present.
StonechatCore? maybeCore() {
  try {
    return StonechatCore();
  } catch (_) {
    return null;
  }
}

Uint8List bytes(int n, [int fill = 7]) =>
    Uint8List.fromList(List.filled(n, fill));

LinkOffer offer() =>
    LinkOffer(sealPub: bytes(1216), sigPub: bytes(32, 5), lookup: bytes(32, 9));

void main() {
  group('LinkOffer', () {
    test('round-trips through the QR text', () {
      final back = LinkOffer.tryParse(offer().encode())!;
      expect(back.sealPub, offer().sealPub);
      expect(back.sigPub, offer().sigPub);
      expect(back.lookup, offer().lookup);
    });

    test('offers both keys the certificate has to cover', () {
      // A certificate names a signing key and a seal key. Omitting either
      // from the QR would leave the primary unable to mint one from the scan
      // alone, which is the only information it has.
      final json = _decode(offer().encode());
      expect(json.keys.toSet(), {'seal', 'sig', 'lookup'});
    });

    test('carries the lookup secret separately from the public keys', () {
      // The whole point of the separation: the parking key must not be
      // derivable from anything a passer-by can read off the screen alone.
      final o = offer();
      expect(o.lookup, isNot(o.sealPub.sublist(0, 32)));
      expect(o.lookup, isNot(o.sigPub));
    });

    test('refuses anything that is not one of ours', () {
      for (final junk in [
        '',
        'https://example.com',
        'stonechat:SC-SOMEONE', // the *invite* scheme, not the link one
        'stonechat-link:',
        'stonechat-link:not-base64!!',
        'stonechat-link:${base64Url.encode(utf8.encode('{"seal":"x"}'))}',
      ]) {
        expect(LinkOffer.tryParse(junk), isNull, reason: junk);
      }
    });

    test('refuses a key or lookup of the wrong size', () {
      // A short seal key would fail later, inside the seal; a short signing
      // key would be signed into a certificate. Failing at the scanner is the
      // difference between "that is not a Stonechat code" and either.
      String encoded(int sealLen, int sigLen, int lookupLen) => LinkOffer(
        sealPub: bytes(sealLen),
        sigPub: bytes(sigLen, 5),
        lookup: bytes(lookupLen, 9),
      ).encode();
      expect(LinkOffer.tryParse(encoded(1215, 32, 32)), isNull);
      expect(LinkOffer.tryParse(encoded(1216, 31, 32)), isNull);
      expect(LinkOffer.tryParse(encoded(1216, 32, 31)), isNull);
      expect(LinkOffer.tryParse(encoded(32, 32, 32)), isNull);
      expect(LinkOffer.tryParse(encoded(1216, 32, 32)), isNotNull);
    });

    test('fits in a QR code', () {
      // Byte mode tops out at 2953 bytes. This is why the offer names the
      // device's real seal key instead of a separate ephemeral one: a second
      // X-Wing public key (1216 bytes, ~2160 more characters after the two
      // base64 layers) would not fit.
      expect(offer().encode().length, lessThan(2953));
    });

    test('tolerates the whitespace a scan or a paste can introduce', () {
      expect(LinkOffer.tryParse('  ${offer().encode()}\n'), isNotNull);
    });
  });

  group('LinkGrant', () {
    const grant = LinkGrant(
      identityPubB64: 'cHVi',
      cert: {'device_id': 3, 'sig': 'c2ln'},
      stonechatId: 'SC-ALICE',
      displayName: 'Alice',
      hubUrl: 'https://hub.example',
      relayAddress: 'https://1.2.3.4:8080',
      relayTlsFp: 'ZnA=',
      deviceId: 3,
      deviceToken: 'tok',
      bundleToken: 'bt',
    );

    test('round-trips every field a device needs to act as this user', () {
      final back = LinkGrant.fromJson(grant.toJson());
      expect(back.identityPubB64, 'cHVi');
      expect(back.cert['device_id'], 3);
      expect(back.stonechatId, 'SC-ALICE');
      expect(back.hubUrl, 'https://hub.example');
      expect(back.relayAddress, 'https://1.2.3.4:8080');
      expect(back.relayTlsFp, 'ZnA=');
      expect(back.deviceId, 3);
      expect(back.deviceToken, 'tok');
      expect(back.bundleToken, 'bt');
    });

    test('carries no identity secret — only the public key', () {
      // The invariant, restored: the identity secret never leaves the device
      // that generated it. What travels is a certificate, which is public.
      final json = jsonEncode(grant.toJson());
      for (final word in ['seed', 'secret', 'private']) {
        expect(json.contains(word), isFalse, reason: word);
      }
    });

    test('carries no hub account token', () {
      // Server management and billing stay with the primary: a linked device
      // must not be able to destroy the mailbox it lives on.
      final keys = grant.toJson().keys.toSet();
      expect(keys.any((k) => k.contains('account')), isFalse);
      expect(keys.any((k) => k.contains('billing')), isFalse);
      expect(keys, {
        'identity_pub',
        'cert',
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

  group('certificate lifetime by device kind', () {
    test('shorter the less the device can protect its key', () {
      expect(certLifetimeFor('primary'), primaryCertLifetime);
      expect(certLifetimeFor('linked'), linkedCertLifetime);
      expect(certLifetimeFor('web'), webCertLifetime);
      expect(webCertLifetime, lessThan(linkedCertLifetime));
      expect(linkedCertLifetime, lessThan(primaryCertLifetime));
    });

    test('an unknown kind under-grants rather than over-grants', () {
      // A typo in a kind must not hand out a year.
      expect(certLifetimeFor('typo'), webCertLifetime);
      expect(certLifetimeFor(''), webCertLifetime);
    });
  });

  test('the parking key is derived from the lookup secret, not the key', () {
    // Stand-in hash: only the *input* is being asserted here.
    String fakeHash(Uint8List d) => 'h${d.length}:${d.first}';
    final o = offer();
    expect(linkParkingKey(fakeHash, o.lookup), fakeHash(o.lookup));
    expect(linkParkingKey(fakeHash, o.lookup), isNot(fakeHash(o.sealPub)));
  });

  _sealRoundTrip();

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

Map<String, dynamic> _decode(String encoded) =>
    jsonDecode(
          utf8.decode(base64Url.decode(encoded.substring(linkScheme.length))),
        )
        as Map<String, dynamic>;

// The seal the whole link flow rests on, against the real core: the new
// device publishes its own seal key in the QR and must be able to open what
// the other device sealed to it. Asserted rather than assumed — if this
// pairing did not hold, linking would fail only on a real device.
void _sealRoundTrip() {
  test('a grant sealed to the offer key opens with that device seal seed', () {
    final core = maybeCore();
    if (core == null) return markTestSkipped('core library unavailable');
    final keys = DeviceKeys.generate();
    final grant = utf8.encode(jsonEncode({'cert': 'x'}));
    final sealed = core.sealTo(
      keys.sealPublic,
      Uint8List.fromList(grant),
      randomBytes(xwingEncapsRandomBytes),
      randomBytes(24),
    );
    expect(core.unseal(keys.sealSeed, sealed), Uint8List.fromList(grant));
    // A different seed is a different device: it must open nothing. This is
    // also what binds the grant to the device its certificate names — only
    // the holder of the certified seal key can open it.
    expect(core.unseal(randomBytes(xwingSeedBytes), sealed), isNull);
  });
}
