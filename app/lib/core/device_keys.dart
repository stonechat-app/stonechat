/// This device's own keys, and the certificate that says they are ours.
///
/// See MULTIDEVICE_IMPLEMENTATION.md "How device certificates work". The
/// short version: the identity key is no longer a messaging key. It is a root
/// that signs a short public statement per device —
///
///     stonechat_id · device_id · sig_pub · seal_pub · not_after
///
/// — and each device keeps its own `sig_pub` (signs its prekeys) and
/// `seal_pub` (envelopes are sealed to it). Peers verify the statement
/// against the identity key they already hold from the directory.
///
/// The consequence that matters: a device other than the primary never needs
/// the identity secret, so a browser session — or a stolen laptop — is
/// bounded by its certificate's lifetime instead of being you forever.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'core_ffi.dart';
import 'crypto.dart';
import 'pqcore.dart';

/// How long a certificate this device mints for itself lasts.
///
/// Long, because renewing is the primary's job and it is the one device that
/// cannot be renewed *by* anything else. Linked devices get shorter lifetimes
/// chosen at link time, and a browser session shorter still.
const primaryCertLifetime = Duration(days: 365);

/// How long the primary certifies a linked device for.
///
/// Shorter than the primary's, because this is the lifetime that bounds the
/// damage from a device the user forgot they linked: revocation stops it
/// immediately, and expiry stops it eventually without anyone doing anything.
const linkedCertLifetime = Duration(days: 180);

/// A browser session. Short by design — the web client cannot protect a key
/// the way a phone keystore can, so its certificate is the mitigation, and a
/// mitigation measured in months is not one.
const webCertLifetime = Duration(days: 7);

/// A headless agent (agent_client/): a device with no screen and nobody
/// sitting at it, usually on a server rather than in a pocket.
///
/// Same as a linked device, and the reasoning runs opposite to the browser's.
/// Renewal is the primary's job, so a short lifetime here does not buy
/// vigilance — it buys an unattended process that stops receiving mail on a
/// Tuesday, months later, with the owner nowhere near it. Revocation is
/// immediate and is the control that matters; expiry is the backstop for a
/// device someone forgot, and 180 days is short enough to be that.
///
/// The key material is worse protected than a phone's (a file on a host, not
/// a keystore), which argues for shorter. What answers it is scope: an agent
/// holds no identity secret, so a stolen one is bounded by exactly this
/// certificate — the same bound a linked device gets.
const agentCertLifetime = Duration(days: 180);

/// The lifetime for a device of the given kind, matching the relay's
/// `devices.kind` column. Unknown kinds get the shortest, not the longest:
/// a typo should under-grant.
Duration certLifetimeFor(String kind) => switch (kind) {
  'primary' => primaryCertLifetime,
  'linked' => linkedCertLifetime,
  'agent' => agentCertLifetime,
  _ => webCertLifetime,
};

/// Refetch a peer's device list once the certificate we hold has less than
/// this left. Not a `devices_v` bump: that signals a device-*set* change,
/// which renewal is not, and a missed bump would silently stop delivery on
/// the day the certificate lapses. Refetching on approach is self-correcting.
const certRefreshWindow = Duration(days: 7);

/// The two keypairs a device holds. Seeds only — the public halves are
/// derived, so there is one thing to persist and one thing to lose.
class DeviceKeys {
  /// Ed25519 seed. Signs this device's prekeys.
  final Uint8List sigSeed;

  /// X-Wing seed. Envelopes to this device are sealed to its public half.
  final Uint8List sealSeed;

  const DeviceKeys({required this.sigSeed, required this.sealSeed});

  static DeviceKeys generate() => DeviceKeys(
    sigSeed: randomBytes(32),
    sealSeed: randomBytes(xwingSeedBytes),
  );

  Uint8List get sigPublic => StonechatCore().identity(seed: sigSeed).public;

  /// The 64-byte form the signing primitive wants, expanded from the seed.
  /// Derived rather than stored so it cannot drift from the seed it belongs
  /// to (see "what is persisted is seeds only").
  Uint8List get sigSecret => StonechatCore().identity(seed: sigSeed).secret;
  Uint8List get sealPublic => PqCore().xwingPkFromSeed(sealSeed);

  String encode() => jsonEncode({
    'sig': base64Encode(sigSeed),
    'seal': base64Encode(sealSeed),
  });

  static DeviceKeys decode(String stored) {
    final j = jsonDecode(stored) as Map<String, dynamic>;
    return DeviceKeys(
      sigSeed: base64Decode(j['sig'] as String),
      sealSeed: base64Decode(j['seal'] as String),
    );
  }
}

/// Build the unsigned certificate for a device. Signing is separate because
/// only the primary can do it — this is also what the primary builds for a
/// device it is linking, from the public keys in that device's QR.
Map<String, Object?> unsignedCert({
  required String stonechatId,
  required int deviceId,
  required Uint8List sigPublic,
  required Uint8List sealPublic,
  required DateTime notAfter,
}) => {
  'stonechat_id': stonechatId,
  'device_id': deviceId,
  'sig_pub': base64Encode(sigPublic),
  'seal_pub': base64Encode(sealPublic),
  'not_after': notAfter.toUtc().millisecondsSinceEpoch ~/ 1000,
};

/// When a signed certificate runs out, or null if it is malformed. Callers
/// treat unreadable as expired: a certificate we cannot parse is not one we
/// can encrypt against.
DateTime? certExpiry(Map<String, dynamic> signed) {
  final seconds = signed['not_after'];
  if (seconds is! int) return null;
  return DateTime.fromMillisecondsSinceEpoch(seconds * 1000, isUtc: true);
}

/// True once a certificate is close enough to expiry that the peer's device
/// list is worth refetching.
bool certNeedsRefresh(Map<String, dynamic> signed, {DateTime? now}) {
  final expiry = certExpiry(signed);
  if (expiry == null) return true;
  return expiry.difference(now ?? DateTime.now().toUtc()) < certRefreshWindow;
}

/// The seal key a certificate names — the target for envelopes to that
/// device. Null if the certificate does not carry a usable one; callers skip
/// the device rather than falling back to anything, because there is nothing
/// safe to fall back *to*.
Uint8List? certSealKey(Map<String, dynamic> signed) {
  final b64 = signed['seal_pub'];
  if (b64 is! String) return null;
  try {
    final bytes = base64Decode(b64);
    return bytes.length == xwingPublicBytes ? bytes : null;
  } catch (_) {
    return null;
  }
}

/// The signing key a certificate names — what that device's prekey
/// signatures verify against.
Uint8List? certSigKey(Map<String, dynamic> signed) {
  final b64 = signed['sig_pub'];
  if (b64 is! String) return null;
  try {
    final bytes = base64Decode(b64);
    return bytes.length == 32 ? bytes : null;
  } catch (_) {
    return null;
  }
}
