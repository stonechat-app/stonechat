// Device linking. The QR is the trust
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

/// BLAKE2b stand-in: only the *input* is under test in most of these, so a
/// cheap deterministic hash keeps them independent of the native core.
Uint8List fakeHash(Uint8List d) {
  final out = Uint8List(32);
  for (var i = 0; i < d.length; i++) {
    out[i % 32] = (out[i % 32] + d[i] + i) & 0xff;
  }
  return out;
}

LinkOffer offer() =>
    LinkOffer(lookup: bytes(32, 9), commitment: bytes(32, 5));

void main() {
  group('LinkOffer', () {
    test('round-trips through the QR text', () {
      final back = LinkOffer.tryParse(offer().encode())!;
      expect(back.lookup, offer().lookup);
      expect(back.commitment, offer().commitment);
    });

    test('the code is short enough to scan comfortably', () {
      // The whole point of the v2 format. v1 carried the 1216-byte X-Wing key
      // and came out at ~2360 characters — QR version 36, which phones would
      // not read. Anything over a few hundred is the old mistake returning.
      expect(offer().encode().length, lessThan(160));
    });

    test('carries a commitment, never the keys themselves', () {
      // If a key ever ends up back in here the QR silently becomes
      // unscannable again, so this is pinned as a property.
      final encoded = offer().encode();
      final body = encoded.substring(linkScheme.length);
      final padded = body + '=' * ((4 - body.length % 4) % 4);
      expect(base64Url.decode(padded).length, 65);
    });

    test('refuses anything that is not one of ours', () {
      for (final junk in [
        '',
        'https://example.com',
        'stonechat:SC-SOMEONE', // the *invite* scheme, not the link one
        'stonechat-link:',
        'stonechat-link:not-base64!!',
        // A v1 code: right scheme, wrong format. Must fail cleanly rather
        // than half-parse into a lookup that goes nowhere.
        'stonechat-link:${base64Url.encode(utf8.encode('{"seal":"x"}'))}',
      ]) {
        expect(LinkOffer.tryParse(junk), isNull, reason: junk);
      }
    });

    test('refuses a code of the wrong length or version', () {
      String encoded(List<int> raw) =>
          linkScheme + base64Url.encode(raw).replaceAll('=', '');
      expect(LinkOffer.tryParse(encoded([2, ...bytes(64)])), isNotNull);
      expect(LinkOffer.tryParse(encoded([2, ...bytes(63)])), isNull);
      expect(LinkOffer.tryParse(encoded([2, ...bytes(65)])), isNull);
      // Version 1 is the old format; refusing it is how an old code fails
      // loudly instead of being misread.
      expect(LinkOffer.tryParse(encoded([1, ...bytes(64)])), isNull);
    });

    test('tolerates the whitespace a scan or a paste can introduce', () {
      // The paste path especially: clipboards pick up trailing newlines.
      expect(LinkOffer.tryParse('  ${offer().encode()}\n'), isNotNull);
    });
  });

  group('offer commitment', () {
    test('covers both keys, and the order they appear in', () {
      final seal = bytes(1216, 3);
      final sig = bytes(32, 4);
      final base = offerCommitment(fakeHash, seal, sig);
      expect(offerCommitment(fakeHash, seal, sig), base);
      expect(offerCommitment(fakeHash, bytes(1216, 7), sig), isNot(base));
      expect(offerCommitment(fakeHash, seal, bytes(32, 8)), isNot(base));
    });

    test('is domain-separated from a bare hash of the keys', () {
      // Otherwise this commitment could be confused with — or replayed as —
      // the parking key or a TLS fingerprint, which are the same primitive
      // over different inputs.
      final seal = bytes(1216, 3);
      final sig = bytes(32, 4);
      final tagged = offerCommitment(fakeHash, seal, sig);
      final untagged = fakeHash(Uint8List.fromList([...seal, ...sig]));
      expect(tagged, isNot(untagged));
    });

    test('is 32 bytes, which is what the QR budgets for', () {
      expect(offerCommitment(fakeHash, bytes(1216, 3), bytes(32, 4)).length, 32);
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
      // Mailbox management and billing stay with the primary: a linked device
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

  test('the parking key comes from the lookup secret, not the commitment', () {
    // Both are in the QR, and only one is secret. Deriving the parking key
    // from the commitment would let anyone who glimpses the screen compute it
    // and destroy the grant with the returns-and-deletes fetch.
    String hex(Uint8List d) => 'h${d.length}:${d.first}';
    final o = offer();
    expect(linkParkingKey(hex, o.lookup), hex(o.lookup));
    expect(linkParkingKey(hex, o.lookup), isNot(hex(o.commitment)));
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
