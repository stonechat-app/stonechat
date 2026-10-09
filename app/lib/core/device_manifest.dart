/// The identity's signed list of its devices (PROTOCOL.md "Device manifest").
///
/// A device certificate says a device was the identity's until a date; it
/// cannot say the identity has since cut the device off. The manifest is
/// that statement, signed by the identity key, numbered so that a newer one
/// supersedes an older, and published in the directory. A peer that holds
/// it encrypts only to devices on it and accepts envelopes only from devices
/// on it, so revoking a device is a new manifest without the device — not
/// only a queue deleted on a relay the peer has to trust.
///
/// The pure parts: the wire form, what a manifest says about a device, and
/// the certificate lifetimes that make its freshness matter. The signing and
/// verification are in the core (`devices.rs`).
library;

import 'dart:convert';
import 'dart:typed_data';

import 'core_ffi.dart';

class DeviceManifest {
  final String stonechatId;
  final int version;
  final int issuedAt; // Unix seconds, informational
  /// device id → the device's signing key, base64 — its certificate's
  /// `sig_pub`. A device is "listed" only with the key it was listed with.
  final Map<int, String> devices;
  final String sigB64;

  const DeviceManifest({
    required this.stonechatId,
    required this.version,
    required this.issuedAt,
    required this.devices,
    required this.sigB64,
  });

  /// The form that is signed, stored and published; `sig` beside it.
  Map<String, dynamic> toJson() => {
    'stonechat_id': stonechatId,
    'version': version,
    'issued_at': issuedAt,
    'devices': [
      for (final e in devices.entries)
        {'device_id': e.key, 'sig_pub': e.value},
    ],
    'sig': sigB64,
  };

  /// Null for anything malformed. Verifying is separate ([verified]), so a
  /// manifest can be parsed before the identity key to check it against is
  /// known.
  static DeviceManifest? fromJson(Object? json) {
    if (json is! Map) return null;
    final id = json['stonechat_id'];
    final version = json['version'];
    final issuedAt = json['issued_at'];
    final devices = json['devices'];
    final sig = json['sig'];
    if (id is! String ||
        version is! int ||
        issuedAt is! int ||
        devices is! List ||
        sig is! String) {
      return null;
    }
    final map = <int, String>{};
    for (final d in devices) {
      if (d is! Map) return null;
      final deviceId = d['device_id'];
      final sigPub = d['sig_pub'];
      if (deviceId is! int || sigPub is! String) return null;
      map[deviceId] = sigPub;
    }
    return DeviceManifest(
      stonechatId: id,
      version: version,
      issuedAt: issuedAt,
      devices: map,
      sigB64: sig,
    );
  }

  /// Parse and verify against [identityPub] — the key the directory gave
  /// for this identity, already checked to commit to its ID. Null unless it
  /// is that identity's genuine, well-formed manifest for [stonechatId].
  static DeviceManifest? verified(
    Object? json,
    String stonechatId,
    Uint8List identityPub,
    StonechatCore core,
  ) {
    final manifest = fromJson(json);
    if (manifest == null || manifest.stonechatId != stonechatId) return null;
    final Uint8List sig;
    try {
      sig = base64Decode(manifest.sigB64);
    } catch (_) {
      return null;
    }
    if (sig.length != 64) return null;
    final unsigned = Map<String, dynamic>.from(manifest.toJson())..remove('sig');
    return core.devicesVerify(unsigned, identityPub, sig) ? manifest : null;
  }

  /// Whether [deviceId] speaks for the identity with [sigPubB64] as its key.
  bool lists(int deviceId, String? sigPubB64) =>
      sigPubB64 != null && devices[deviceId] == sigPubB64;

  /// Sign a new manifest. Only the primary can: it holds the identity seed.
  static DeviceManifest sign({
    required String stonechatId,
    required int version,
    required Map<int, String> devices,
    required Uint8List identitySeed,
    required StonechatCore core,
    DateTime? now,
  }) {
    final unsigned = DeviceManifest(
      stonechatId: stonechatId,
      version: version,
      issuedAt: (now ?? DateTime.now().toUtc()).millisecondsSinceEpoch ~/ 1000,
      devices: devices,
      sigB64: '',
    );
    final json = unsigned.toJson()..remove('sig');
    return DeviceManifest(
      stonechatId: stonechatId,
      version: version,
      issuedAt: unsigned.issuedAt,
      devices: devices,
      sigB64: core.devicesSign(json, identitySeed),
    );
  }
}

/// The version of the sender's manifest, as an envelope states it (`manifest_v`
/// in the inner envelope). Zero or absent means the sender knows of none.
int manifestVersionOf(Map<String, dynamic> inner) {
  final v = inner['manifest_v'];
  return v is int && v > 0 ? v : 0;
}
