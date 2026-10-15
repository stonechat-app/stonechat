/// The primary's own record of the identity's devices (PROTOCOL.md "Device
/// manifest", "Publishing one").
///
/// The device manifest exists so that a contact does not have to trust a
/// relay about which devices are the identity's. That only holds if the
/// primary does not trust the relay about it either: a manifest rebuilt from
/// whatever the relay lists is a manifest the relay writes. So the primary
/// keeps its own record — every device it linked, with the keys it certified,
/// and every device it revoked — and builds the manifest from that:
///
/// - a device enters the record when the primary links it, with the keys in
///   its offer, and leaves the manifest when the primary revokes it;
/// - the relay's listing can only *remove* a device from the manifest (one
///   that revoked itself, or that the relay expired), never add one back, and
///   never changes a device's key;
/// - a certificate the relay lists is used only once it verifies as one this
///   identity signed for that slot, over the keys on record — and then only
///   to learn how far the device's renewal got.
///
/// Pure decisions, so they can be tested without a `ChatState`.
library;

/// One device of ours, as the primary recorded it.
class OwnDevice {
  final int deviceId;

  /// The relay's `devices.kind`: `linked`, `web`, `agent`.
  final String kind;

  /// The keys the primary certified, base64. Fixed for the life of the slot.
  final String sigPubB64;
  final String sealPubB64;

  /// When the certificate the primary last signed for it runs out (Unix
  /// seconds).
  final int notAfter;

  /// Unix seconds, once the primary revoked it. A revoked slot never returns
  /// to the manifest, whatever the relay lists.
  final int? revokedAt;

  const OwnDevice({
    required this.deviceId,
    required this.kind,
    required this.sigPubB64,
    required this.sealPubB64,
    required this.notAfter,
    this.revokedAt,
  });

  bool get revoked => revokedAt != null;

  OwnDevice renewed(int notAfter) => OwnDevice(
    deviceId: deviceId,
    kind: kind,
    sigPubB64: sigPubB64,
    sealPubB64: sealPubB64,
    notAfter: notAfter,
    revokedAt: revokedAt,
  );
}

/// The devices the manifest lists, in slot order, each with the key the
/// primary certified: this device, plus every recorded device that is not
/// revoked and that the relay still lists. [listed] is the set of device ids
/// the relay returned; nothing else about the listing is consulted.
Map<int, String> manifestDevices({
  required Iterable<OwnDevice> own,
  required Set<int> listed,
  required int myDeviceId,
  required String? mySigPubB64,
}) {
  final keys = <int, String>{};
  for (final d in own) {
    if (d.revoked || d.deviceId == myDeviceId) continue;
    if (!listed.contains(d.deviceId)) continue;
    keys[d.deviceId] = d.sigPubB64;
  }
  if (mySigPubB64 != null) keys[myDeviceId] = mySigPubB64;
  // Ascending by slot. The signature is over the list as given, so the
  // order is part of what every verifier must reproduce; a canonical one
  // leaves nothing for a careless parser to re-sort.
  final ids = keys.keys.toList()..sort();
  return {for (final id in ids) id: keys[id]!};
}

/// Whether a certificate the relay lists for [device] is one this identity
/// signed for that slot over the keys on record. The caller supplies the
/// signature check (the core's `devcert_verify` against our identity key);
/// this adds the binding to the slot and to the recorded keys, which the
/// signature alone does not give — an old certificate of a reused slot
/// verifies too.
bool certMatchesRecord(
  OwnDevice device,
  Map<String, dynamic> cert, {
  required bool Function(Map<String, dynamic> cert) signedByUs,
  required String stonechatId,
}) {
  if (cert['stonechat_id'] != stonechatId) return false;
  if (cert['device_id'] != device.deviceId) return false;
  if (cert['sig_pub'] != device.sigPubB64) return false;
  if (cert['seal_pub'] != device.sealPubB64) return false;
  return signedByUs(cert);
}

/// When [device]'s certificate runs out, as best the primary knows: the
/// expiry of the certificate the relay lists when that certificate is
/// verifiably ours ([certMatchesRecord]) — it says how far the device's
/// renewal actually got — and otherwise the expiry of the one the primary
/// last signed. A listing that fails the check is ignored, not trusted
/// less: it changes nothing.
int effectiveNotAfter(
  OwnDevice device,
  Map<String, dynamic>? listedCert, {
  required bool Function(Map<String, dynamic> cert) signedByUs,
  required String stonechatId,
}) {
  if (listedCert != null &&
      certMatchesRecord(
        device,
        listedCert,
        signedByUs: signedByUs,
        stonechatId: stonechatId,
      )) {
    final notAfter = listedCert['not_after'];
    if (notAfter is int) return notAfter;
  }
  return device.notAfter;
}

/// The recorded devices whose certificate the primary should renew now:
/// linked, still listed by the relay, not this device, and with less than
/// [renewWindow] (per kind) left on [effectiveNotAfter].
List<OwnDevice> renewalsDue({
  required Iterable<OwnDevice> own,
  required Map<int, Map<String, dynamic>?> listedCerts,
  required int myDeviceId,
  required int nowSeconds,
  required Duration Function(String kind) renewWindow,
  required bool Function(Map<String, dynamic> cert) signedByUs,
  required String stonechatId,
}) {
  final due = <OwnDevice>[];
  for (final d in own) {
    if (d.revoked || d.deviceId == myDeviceId) continue;
    if (!listedCerts.containsKey(d.deviceId)) continue;
    final notAfter = effectiveNotAfter(
      d,
      listedCerts[d.deviceId],
      signedByUs: signedByUs,
      stonechatId: stonechatId,
    );
    if (notAfter - nowSeconds < renewWindow(d.kind).inSeconds) due.add(d);
  }
  return due;
}

/// Seed the record from the relay's listing, once, for a primary that has
/// none: an upgrade from before the record existed, or a primary restored
/// from an identity export. A listed device is taken as ours only on the
/// strength of a certificate this identity verifiably signed for that slot
/// (the relay cannot forge one), and — when a manifest is held — only if the
/// manifest lists it with that key, so a device the previous primary had
/// dropped is not picked back up.
///
/// This is the one moment the relay's word decides who is ours, and it is
/// bounded to devices we certified at some point. The record never seeds
/// again while it holds anything.
List<OwnDevice> seedFromListing({
  required Iterable<({int deviceId, String kind, Map<String, dynamic>? cert})>
      listed,
  required Map<int, String>? heldManifest,
  required int myDeviceId,
  required String stonechatId,
  required bool Function(Map<String, dynamic> cert) signedByUs,
}) {
  final seeded = <OwnDevice>[];
  for (final d in listed) {
    if (d.deviceId == myDeviceId) continue;
    final cert = d.cert;
    if (cert == null) continue;
    final sig = cert['sig_pub'];
    final seal = cert['seal_pub'];
    final notAfter = cert['not_after'];
    if (sig is! String || seal is! String || notAfter is! int) continue;
    if (cert['stonechat_id'] != stonechatId || cert['device_id'] != d.deviceId) {
      continue;
    }
    if (heldManifest != null && heldManifest[d.deviceId] != sig) continue;
    if (!signedByUs(cert)) continue;
    seeded.add(
      OwnDevice(
        deviceId: d.deviceId,
        kind: d.kind,
        sigPubB64: sig,
        sealPubB64: seal,
        notAfter: notAfter,
      ),
    );
  }
  return seeded;
}
