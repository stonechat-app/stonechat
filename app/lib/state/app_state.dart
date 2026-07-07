/// Identity + service bootstrap. Keys live in the platform keystore; if the
/// app is uninstalled they are gone, and so is the account — by design.
library;

import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:flutter/foundation.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:path/path.dart' as p;
import 'package:path_provider/path_provider.dart';

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
  bool appLockEnabled = false;

  Future<void> setPreference(String key, bool value) async {
    switch (key) {
      case 'read_receipts':
        sendReadReceipts = value;
      case 'typing_indicators':
        sendTypingIndicators = value;
      case 'app_lock':
        appLockEnabled = value;
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
    await _clearKeychainOnFreshInstall();
    db = await ChatDb.open(await _databaseKey());
    final sodium = await CryptoService.loadSodium();
    // Mailbox TLS pinning (api.dart): fingerprint = BLAKE2b-256 of DER cert.
    certFingerprinter =
        (der) => base64Encode(sodium.crypto.genericHash(message: der, outLen: 32));

    sendReadReceipts = await _readPreference('read_receipts', true);
    sendTypingIndicators = await _readPreference('typing_indicators', true);
    appLockEnabled = await _readPreference('app_lock', false);

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

  /// iOS keeps Keychain items after an app is deleted, so a reinstalled app
  /// silently resurrects the previous identity — including, after a directory
  /// reset, its now-dead account token (the control plane answers every
  /// authenticated call with 401 "invalid token"). The app *sandbox* is wiped
  /// on uninstall, so a marker file there distinguishes a fresh install from
  /// a normal launch. No marker ⇒ the keystore is orphaned: clear it so
  /// onboarding starts clean. This makes the real behaviour match the
  /// documented model — identity dies with the app (PROTOCOL.md), no backup.
  Future<void> _clearKeychainOnFreshInstall() async {
    try {
      final dir = await getApplicationSupportDirectory();
      final marker = File(p.join(dir.path, '.zeon_installed'));
      if (await marker.exists()) return;
      await _storage.deleteAll();
      // An in-place update keeps the sandbox: drop the DB too, since its
      // SQLCipher key just went with the keystore.
      await ChatDb.deleteDatabaseFiles();
      await marker.create(recursive: true);
    } catch (_) {
      // Best-effort: if the sandbox probe fails, fall through to a normal
      // load rather than risk wiping a valid identity.
    }
  }

  /// Manual "start over": drop the identity, its mailbox token and the local
  /// history, then the app returns to onboarding. Used when a directory reset
  /// stranded the token, or to hand the phone a clean slate.
  Future<void> resetIdentity() async {
    // Keep the DB's SQLCipher key: db.wipe() empties the tables but keeps the
    // file, so a new key here would leave it unopenable next launch.
    final dbKey = await _storage.read(key: 'zn_db_key');
    await _storage.deleteAll();
    if (dbKey != null) await _storage.write(key: 'zn_db_key', value: dbKey);
    await db.wipe();
    _crypto = null;
    zeonId = null;
    handle = null;
    displayName = null;
    externalMailboxToken = null;
    externalMailboxTlsFp = null;
    api.accountToken = null;
    notifyListeners();
  }

  /// SQLCipher key for the local history DB: 32 random bytes, minted once,
  /// kept in the platform keystore beside the identity key. Not derivable
  /// from anything — losing the keystore loses the history, same deal as
  /// the identity itself.
  Future<String> _databaseKey() async {
    final existing = await _storage.read(key: 'zn_db_key');
    if (existing != null) return existing;
    final rng = Random.secure();
    final key = base64UrlEncode(
        List<int>.generate(32, (_) => rng.nextInt(256)));
    await _storage.write(key: 'zn_db_key', value: key);
    return key;
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
