/// Device linking (MULTIDEVICE.md "Linking a device").
///
/// The new device must end up holding: the identity secret, the hub URL, the
/// relay address + TLS fingerprint, and its freshly minted device token. The
/// transfer channel is the user's own relay; **the trust anchor is the user's
/// eyes** — the QR is carried between two screens the user is looking at.
///
/// This amends the standing invariant honestly: "the private key never leaves
/// the device" becomes "the private key never leaves the user's devices, and
/// moves between them only inside a link grant".
library;

import 'dart:convert';
import 'dart:typed_data';

const linkScheme = 'stonechat-link:';

/// What the new device shows and the existing device scans.
///
/// Two independent secrets, and the separation matters. `ek` is the X-Wing
/// public key the grant is sealed to — public by nature, since it is on
/// screen. `lookup` is what the parking key is derived from, and it is
/// *secret*: deriving the parking key from `ek` instead would let anyone who
/// merely glimpses the screen compute it and race the returns-and-deletes
/// fetch. They could not read the grant — it is sealed to a key they do not
/// hold — but they could destroy it, turning a shoulder-surf into a linking
/// denial of service.
class LinkOffer {
  final Uint8List ekPub; // X-Wing public key (the same seal the protocol uses)
  final Uint8List lookup; // 32 random bytes; the parking key is its hash

  const LinkOffer({required this.ekPub, required this.lookup});

  String encode() =>
      linkScheme +
      base64Url.encode(
        utf8.encode(
          jsonEncode({
            'ek': base64Encode(ekPub),
            'lookup': base64Encode(lookup),
          }),
        ),
      );

  /// Null for anything that isn't one of ours, or is malformed. A QR scanner
  /// sees a lot of things that are not link offers.
  static LinkOffer? tryParse(String raw) {
    final text = raw.trim();
    if (!text.startsWith(linkScheme)) return null;
    try {
      final json =
          jsonDecode(
                utf8.decode(base64Url.decode(text.substring(linkScheme.length))),
              )
              as Map<String, dynamic>;
      final ek = base64Decode(json['ek'] as String);
      final lookup = base64Decode(json['lookup'] as String);
      // Sizes are checked here rather than at use: a malformed offer should
      // fail at the scanner, not deep inside the seal.
      if (ek.length != 1216 || lookup.length != 32) return null;
      return LinkOffer(
        ekPub: Uint8List.fromList(ek),
        lookup: Uint8List.fromList(lookup),
      );
    } catch (_) {
      return null;
    }
  }
}

/// What the existing device seals to the newcomer's ephemeral key.
///
/// Everything a device needs to *be* this user, and nothing it does not: no
/// history (that arrives separately, if at all) and no hub account token —
/// server management and billing stay with the primary, so a linked device
/// cannot destroy the mailbox it lives on.
class LinkGrant {
  final String identitySeedB64; // the crown jewels
  final String stonechatId;
  final String displayName;
  final String hubUrl;
  final String relayAddress;
  final String relayTlsFp;
  final int deviceId;
  final String deviceToken;
  final String? bundleToken;

  const LinkGrant({
    required this.identitySeedB64,
    required this.stonechatId,
    required this.displayName,
    required this.hubUrl,
    required this.relayAddress,
    required this.relayTlsFp,
    required this.deviceId,
    required this.deviceToken,
    this.bundleToken,
  });

  Map<String, Object?> toJson() => {
    'identity_seed': identitySeedB64,
    'stonechat_id': stonechatId,
    'display_name': displayName,
    'hub_url': hubUrl,
    'relay_address': relayAddress,
    'relay_tls_fp': relayTlsFp,
    'device_id': deviceId,
    'device_token': deviceToken,
    if (bundleToken != null) 'bundle_token': bundleToken,
  };

  factory LinkGrant.fromJson(Map<String, dynamic> j) => LinkGrant(
    identitySeedB64: j['identity_seed'] as String,
    stonechatId: j['stonechat_id'] as String,
    displayName: (j['display_name'] as String?) ?? '',
    hubUrl: j['hub_url'] as String,
    relayAddress: j['relay_address'] as String,
    relayTlsFp: j['relay_tls_fp'] as String,
    deviceId: j['device_id'] as int,
    deviceToken: j['device_token'] as String,
    bundleToken: j['bundle_token'] as String?,
  );
}

/// Where a grant is parked: BLAKE2b-256 of the QR's *lookup secret*, hex.
///
/// Not of `ek`. `ek` is on screen and therefore public; deriving the parking
/// key from it would let a passer-by compute the key and destroy the grant
/// with the returns-and-deletes fetch.
String linkParkingKey(String Function(Uint8List) blake2bHex, Uint8List lookup) =>
    blake2bHex(lookup);

/// A device token the new device will authenticate with. Minted by the
/// *existing* device and sealed into the grant, so the secret is chosen by a
/// device the user already trusts and the relay only ever stores its hash.
String newDeviceToken(Uint8List random32) => base64Url
    .encode(random32)
    .replaceAll('=', '');
