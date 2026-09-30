/// Device linking.
///
/// The new device generates its own keys, shows their public halves, and gets
/// back a **certificate** over them plus the addressing it needs: hub URL,
/// relay address + TLS fingerprint, device id and token. The transfer channel
/// is the hub as a dead drop; **the trust anchor is the user's eyes** — the QR
/// is carried between two screens the user is looking at.
///
/// The identity secret does not travel. It used to (08-02 to 08-03), and the
/// invariant had to be softened to "the private key never leaves the user's
/// devices". Since device certificates it is back to the strong form: **the
/// identity secret never leaves the device that generated it.** A linked
/// device is bounded by a certificate it cannot extend or reissue.
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
/// Domain tag for the offer commitment. Separated so this hash can never be
/// mistaken for the parking key (BLAKE2b over the lookup secret) or the TLS
/// fingerprint (BLAKE2b over a certificate).
const offerContext = 'stonechat-link-offer';

/// Format marker. v1 carried the new device's whole 1216-byte X-Wing key in
/// the QR; at ~2360 characters that was a version-36 code and phones would not
/// read it. v2 carries a 32-byte commitment instead.
const offerVersion = 2;

/// What a scanner reads: a lookup secret and a commitment, and nothing else.
///
/// The keys themselves are fetched from the hub and checked against the
/// commitment. That sounds weaker and is not: the eyes still carry something
/// the network cannot forge. A substituted key hashes differently and is
/// refused, which is exactly what carrying the key by eye bought — for 32
/// bytes instead of 1248.
class LinkOffer {
  final Uint8List lookup; // 32 random bytes; the parking key is its hash
  final Uint8List commitment; // BLAKE2b-256 over the tag ‖ seal ‖ sig

  const LinkOffer({required this.lookup, required this.commitment});

  String encode() =>
      linkScheme +
      base64Url
          .encode([offerVersion, ...lookup, ...commitment])
          .replaceAll('=', '');

  /// Null for anything that isn't one of ours, or is malformed. A QR scanner
  /// sees a lot of things that are not link offers.
  static LinkOffer? tryParse(String raw) {
    final text = raw.trim();
    if (!text.startsWith(linkScheme)) return null;
    try {
      var body = text.substring(linkScheme.length);
      body += '=' * ((4 - body.length % 4) % 4);
      final bytes = base64Url.decode(body);
      // Length and version are checked here rather than at use: a malformed
      // code should fail at the scanner, reading as "that is not a Stonechat
      // code" rather than as a mysterious failure three steps later.
      if (bytes.length != 65 || bytes[0] != offerVersion) return null;
      return LinkOffer(
        lookup: Uint8List.fromList(bytes.sublist(1, 33)),
        commitment: Uint8List.fromList(bytes.sublist(33, 65)),
      );
    } catch (_) {
      return null;
    }
  }
}

/// The keys an offer commits to, once fetched and verified.
class OfferKeys {
  final Uint8List sealPub; // X-Wing: the grant's target, and their seal key
  final Uint8List sigPub; // Ed25519: what the certificate will vouch for

  const OfferKeys({required this.sealPub, required this.sigPub});
}

/// BLAKE2b-256 over `"stonechat-link-offer" ‖ seal ‖ sig`.
///
/// [hash] is the same keyless BLAKE2b the parking key uses. Mirrored in the
/// hub (`_offer_commitment`) and the web client (`offerCommitment`) — three
/// implementations, so the bytes are spelled out rather than implied.
Uint8List offerCommitment(
  Uint8List Function(Uint8List) hash,
  Uint8List sealPub,
  Uint8List sigPub,
) => hash(
  Uint8List.fromList([...utf8.encode(offerContext), ...sealPub, ...sigPub]),
);

/// What the existing device seals to the newcomer's ephemeral key.
///
/// Everything a device needs to *act as* this user, and nothing more.
///
/// Not in here, and each omission is a bound on what a linked device can do:
///
/// - **the identity secret** — so it cannot mint certificates (its own
///   included), sign a TLS fingerprint, or recover the account. It gets
///   `identity_pub` instead, which is what its certificate verifies against
///   and what the SC- ID commits to.
/// - **the hub account token** — mailbox management and billing stay with the
///   primary, so a linked device cannot destroy the mailbox it lives on.
/// - **history** — that arrives separately, if at all.
class LinkGrant {
  /// The identity's Ed25519 **public** key. Checked against [stonechatId] on
  /// arrival: an SC- ID is a commitment to this key, so a substituted grant
  /// cannot install a different identity under the name the user is looking at.
  final String identityPubB64;

  /// This device's certificate, signed by the primary over the public keys
  /// from the QR. The device's own secrets never left it, so this is the
  /// entire secret-bearing... nothing: the certificate is public, and the
  /// only secret in the grant is [deviceToken].
  final Map<String, dynamic> cert;

  final String stonechatId;
  final String displayName;
  final String hubUrl;
  final String relayAddress;
  final String relayTlsFp;
  final int deviceId;
  final String deviceToken;
  final String? bundleToken;

  const LinkGrant({
    required this.identityPubB64,
    required this.cert,
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
    'identity_pub': identityPubB64,
    'cert': cert,
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
    identityPubB64: j['identity_pub'] as String,
    cert: (j['cert'] as Map).cast<String, dynamic>(),
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
