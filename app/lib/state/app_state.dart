/// Identity + service bootstrap. Keys live in the platform keystore; if the
/// app is uninstalled they are gone, and so is the account — by design.
library;

import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import '../core/api.dart';
import '../core/crypto.dart';
import '../core/db.dart';

class AppState extends ChangeNotifier {
  static const _storage = FlutterSecureStorage();

  late final ChatDb db;
  late final ControlPlaneApi api;
  CryptoService? _crypto;
  String? zeonId;
  String? handle; // zn-word-word-word
  String? displayName;
  // Token for a self-provisioned ("external") mailbox. Lives only here —
  // the control plane never sees it. The TLS fingerprint is the one WE
  // observed at connect time (trust-on-first-use), not the control plane's.
  String? externalMailboxToken;
  String? externalMailboxTlsFp;

  bool get hasIdentity => _crypto != null && zeonId != null;
  CryptoService get crypto => _crypto!;

  // Preferences. Stored beside the keys — small values, no extra dependency.
  // Read receipts are mutual (Signal-style): turning them off also stops us
  // rendering the other side's. Delivery receipts are always sent.
  bool sendReadReceipts = true;
  bool sendTypingIndicators = true;

  Future<void> setPreference(String key, bool value) async {
    switch (key) {
      case 'read_receipts':
        sendReadReceipts = value;
      case 'typing_indicators':
        sendTypingIndicators = value;
    }
    await _storage.write(key: 'zn_pref_$key', value: value ? '1' : '0');
    notifyListeners();
  }

  Future<bool> _readPreference(String key, bool fallback) async =>
      switch (await _storage.read(key: 'zn_pref_$key')) {
        '1' => true,
        '0' => false,
        _ => fallback,
      };

  /// Two modes: by default the app uses the hosted Zeon control plane;
  /// advanced users can point it anywhere (onboarding → advanced, or
  /// --dart-define=ZEON_CP=… for development).
  static const hostedControlPlaneUrl = 'https://control.zeonchat.com';
  static const _envUrl = String.fromEnvironment('ZEON_CP');

  static String get defaultControlPlaneUrl {
    if (_envUrl.isNotEmpty) return _envUrl;
    if (kDebugMode) {
      return Platform.isAndroid
          ? 'http://10.0.2.2:8000' // Android emulator → host machine
          : 'http://127.0.0.1:8000';
    }
    return hostedControlPlaneUrl;
  }

  /// Load services and any stored identity. Called once before runApp.
  Future<void> init() async {
    db = await ChatDb.open();
    final sodium = await CryptoService.loadSodium();
    // Mailbox TLS pinning (api.dart): fingerprint = BLAKE2b-256 of DER cert.
    certFingerprinter =
        (der) => base64Encode(sodium.crypto.genericHash(message: der, outLen: 32));

    sendReadReceipts = await _readPreference('read_receipts', true);
    sendTypingIndicators = await _readPreference('typing_indicators', true);

    final secret = await _storage.read(key: 'zn_secret');
    final public = await _storage.read(key: 'zn_public');
    final storedUrl = await _storage.read(key: 'zn_cp_url');
    // Identities are Ed25519. Anything stored without the marker is a
    // dev-era X25519 key from before the protocol settled — unusable,
    // treat as no identity.
    final algo = await _storage.read(key: 'zn_algo');

    api = ControlPlaneApi(
      baseUrl: storedUrl ?? defaultControlPlaneUrl,
      accountToken: await _storage.read(key: 'zn_token'),
    );

    if (secret != null && public != null && algo == 'ed25519') {
      _crypto = CryptoService.fromKeys(
        sodium,
        publicKey: base64Decode(public),
        secretKey: base64Decode(secret),
      );
      zeonId = await _storage.read(key: 'zn_id');
      handle = await _storage.read(key: 'zn_handle');
      displayName = await _storage.read(key: 'zn_name');
      externalMailboxToken = await _storage.read(key: 'zn_ext_token');
      externalMailboxTlsFp = await _storage.read(key: 'zn_ext_tls_fp');
      if (handle == null && zeonId != null) {
        await _fetchOwnHandle(); // account predates handles — self-heal
      }
    } else {
      _sodium = sodium;
    }
  }

  Future<void> setExternalMailbox(String? token, String? tlsFp) async {
    externalMailboxToken = token;
    externalMailboxTlsFp = tlsFp;
    if (token == null) {
      await _storage.delete(key: 'zn_ext_token');
      await _storage.delete(key: 'zn_ext_tls_fp');
    } else {
      await _storage.write(key: 'zn_ext_token', value: token);
      await _storage.write(key: 'zn_ext_tls_fp', value: tlsFp);
    }
  }

  Future<void> _fetchOwnHandle() async {
    try {
      final entry = await api.directory(zeonId!);
      if (entry.handle != null) {
        handle = entry.handle;
        await _storage.write(key: 'zn_handle', value: handle);
      }
    } catch (_) {
      // offline — retry next launch
    }
  }

  // Held only between init() and createIdentity() during onboarding.
  dynamic _sodium;

  /// Onboarding: generate a keypair, register with the control plane, persist.
  Future<void> createIdentity({
    required String name,
    required String controlPlaneUrl,
  }) async {
    final crypto = CryptoService.generate(_sodium);
    api.baseUrl = controlPlaneUrl;

    final result = await api.register(crypto.publicKeyB64);
    api.accountToken = result.accountToken;

    await _storage.write(
        key: 'zn_secret', value: base64Encode(crypto.exportSecretKey()));
    await _storage.write(key: 'zn_public', value: crypto.publicKeyB64);
    await _storage.write(key: 'zn_algo', value: 'ed25519');
    await _storage.write(key: 'zn_id', value: result.zeonId);
    await _storage.write(key: 'zn_handle', value: result.handle);
    await _storage.write(key: 'zn_token', value: result.accountToken);
    await _storage.write(key: 'zn_name', value: name);
    await _storage.write(key: 'zn_cp_url', value: controlPlaneUrl);

    _crypto = crypto;
    zeonId = result.zeonId;
    handle = result.handle;
    displayName = name;
    notifyListeners();
  }
}
