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
  String? displayName;

  bool get hasIdentity => _crypto != null && zeonId != null;
  CryptoService get crypto => _crypto!;

  static String get defaultControlPlaneUrl => Platform.isAndroid
      ? 'http://10.0.2.2:8000' // Android emulator → host machine
      : 'http://127.0.0.1:8000';

  /// Load services and any stored identity. Called once before runApp.
  Future<void> init() async {
    db = await ChatDb.open();
    final sodium = await CryptoService.loadSodium();

    final secret = await _storage.read(key: 'zn_secret');
    final public = await _storage.read(key: 'zn_public');
    final storedUrl = await _storage.read(key: 'zn_cp_url');

    api = ControlPlaneApi(
      baseUrl: storedUrl ?? defaultControlPlaneUrl,
      accountToken: await _storage.read(key: 'zn_token'),
    );

    if (secret != null && public != null) {
      _crypto = CryptoService.fromKeys(
        sodium,
        publicKey: base64Decode(public),
        secretKey: base64Decode(secret),
      );
      zeonId = await _storage.read(key: 'zn_id');
      displayName = await _storage.read(key: 'zn_name');
    } else {
      _sodium = sodium;
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
    await _storage.write(key: 'zn_id', value: result.zeonId);
    await _storage.write(key: 'zn_token', value: result.accountToken);
    await _storage.write(key: 'zn_name', value: name);
    await _storage.write(key: 'zn_cp_url', value: controlPlaneUrl);

    _crypto = crypto;
    zeonId = result.zeonId;
    displayName = name;
    notifyListeners();
  }
}
