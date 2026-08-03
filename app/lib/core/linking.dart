/// Device linking (MULTIDEVICE.md "Linking a device").
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
/// The two keys are this device's **long-lived** ones, not throwaways for the
/// link. That is deliberate on both counts:
///
/// - `seal` is what the grant is encapsulated to *and* what peers will seal
///   envelopes to. Making them one key binds "the device that opened the
///   grant" to "the device the certificate names" — with a separate ephemeral
///   there is nothing tying the two together. It also keeps the QR within a
///   QR's capacity: two X-Wing public keys would not fit.
/// - Reusing it costs nothing that matters. Someone who records the parked
///   ciphertext and *later* steals this device could read the grant — but a
///   stolen device already holds everything in it.
///
/// `lookup` is a third, independent secret. The parking key is its hash and
/// **not** `seal`'s: `seal` is on screen and therefore public, so deriving
/// the parking key from it would let a passer-by compute the key and destroy
/// the grant with the returns-and-deletes fetch. They still could not read it.
class LinkOffer {
  final Uint8List sealPub; // X-Wing: the grant's target, and this device's
  final Uint8List sigPub; // Ed25519: what the certificate will vouch for
  final Uint8List lookup; // 32 random bytes; the parking key is its hash

  const LinkOffer({
    required this.sealPub,
    required this.sigPub,
    required this.lookup,
  });

  String encode() =>
      linkScheme +
      base64Url.encode(
        utf8.encode(
          jsonEncode({
            'seal': base64Encode(sealPub),
            'sig': base64Encode(sigPub),
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
      final seal = base64Decode(json['seal'] as String);
      final sig = base64Decode(json['sig'] as String);
      final lookup = base64Decode(json['lookup'] as String);
      // Sizes are checked here rather than at use: a malformed offer should
      // fail at the scanner, not deep inside the seal. The sig length matters
      // most — it is about to be signed into a certificate.
      if (seal.length != 1216 || sig.length != 32 || lookup.length != 32) {
        return null;
      }
      return LinkOffer(
        sealPub: Uint8List.fromList(seal),
        sigPub: Uint8List.fromList(sig),
        lookup: Uint8List.fromList(lookup),
      );
    } catch (_) {
      return null;
    }
  }
}

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
/// - **the hub account token** — server management and billing stay with the
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
