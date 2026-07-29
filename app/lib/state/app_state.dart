/// Identity + service bootstrap. Keys live in the platform keystore; if the
/// app is uninstalled they are gone, and so is the account — by design.
library;

import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:flutter/foundation.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:sodium/sodium_sumo.dart';
import 'package:path/path.dart' as p;
import 'package:path_provider/path_provider.dart';

import '../core/api.dart';
import '../core/crypto.dart';
import '../core/db.dart';
import '../core/identity_export.dart';

class AppState extends ChangeNotifier {
  // iOS: items ride the shared app-group access group so the notification
  // extension can read the DB key and identity, and first_unlock so a
  // push received while the phone is locked (post first unlock) can too —
  // the same accessibility Signal uses for its shared keychain.
  static const _storage = FlutterSecureStorage(
    iOptions: IOSOptions(
      groupId: 'group.app.stonechat.mobile',
      accessibility: KeychainAccessibility.first_unlock,
    ),
  );

  late final ChatDb db;
  late final HubApi api;
  CryptoService? _crypto;
  String? stonechatId;
  String? displayName;
  // Whether the notification soft-ask has been shown (once, on the first
  // contact request). Persisted so it never nags across launches.
  bool pushPrompted = false;
  // Own profile photo (raw image bytes, sender-scaled — see ChatState
  // maxAvatarBytes). Lives in the encrypted DB, not the keystore: too big
  // for a keychain item, and it must be ciphertext at rest like everything
  // else. Shared only with accepted contacts (PROTOCOL.md "Profiles").
  Uint8List? avatar;
  // Token for a self-provisioned ("external") mailbox. Lives only here —
  // the hub never sees it. The TLS fingerprint is the one WE
  // observed at connect time (trust-on-first-use), not the hub's.
  String? externalMailboxToken;
  String? externalMailboxTlsFp;
  // Whether the external mailbox came from a friend's invite rather than the
  // user's own server. Pure UI distinction (both are `external` records on
  // the hub) — kept locally so the mailbox screen can say which one it is.
  bool externalMailboxFriendHosted = false;
  // The user's own host agent ("host your circle"), if they run one. The
  // admin token is as sensitive as the mailbox token: keystore only, never
  // the hub. The fingerprint is trust-on-first-use, observed at connect.
  String? hostAgentAddress;
  String? hostAgentAdminToken;
  String? hostAgentTlsFp;

  bool get hasIdentity => _crypto != null && stonechatId != null;
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

  /// Two modes: by default the app uses the hosted Stonechat hub;
  /// advanced users can point it anywhere (onboarding → advanced, or
  /// --dart-define=STONECHAT_HUB=… for development).
  static const hostedHubUrl = 'https://hub.stonechat.app';
  static const _envUrl = String.fromEnvironment('STONECHAT_HUB');

  static String get defaultHubUrl {
    if (_envUrl.isNotEmpty) return _envUrl;
    if (kDebugMode) {
      return Platform.isAndroid
          ? 'http://10.0.2.2:8000' // Android emulator → host machine
          : 'http://127.0.0.1:8000';
    }
    return hostedHubUrl;
  }

  /// Load services and any stored identity. Called once before runApp.
  Future<void> init() async {
    await _clearKeychainOnFreshInstall();
    db = await ChatDb.open(await _databaseKey());
    final sodium = await CryptoService.loadSodium();
    _sodium = sodium;
    // Mailbox TLS pinning (api.dart): fingerprint = BLAKE2b-256 of DER cert.
    certFingerprinter = (der) =>
        base64Encode(sodium.crypto.genericHash(message: der, outLen: 32));

    sendReadReceipts = await _readPreference('read_receipts', true);
    sendTypingIndicators = await _readPreference('typing_indicators', true);
    appLockEnabled = await _readPreference('app_lock', false);

    final secret = await _storage.read(key: 'zn_secret');
    final public = await _storage.read(key: 'zn_public');
    final storedUrl = await _storage.read(key: 'zn_hub_url');

    api = HubApi(
      baseUrl: storedUrl ?? defaultHubUrl,
      accountToken: await _storage.read(key: 'zn_token'),
    );

    if (secret != null && public != null) {
      _crypto = CryptoService.fromKeys(
        sodium,
        publicKey: base64Decode(public),
        secretKey: base64Decode(secret),
      );
      stonechatId = await _storage.read(key: 'zn_id');
      displayName = await _storage.read(key: 'zn_name');
      pushPrompted = (await _storage.read(key: 'zn_push_prompted')) == '1';
      externalMailboxToken = await _storage.read(key: 'zn_ext_token');
      externalMailboxTlsFp = await _storage.read(key: 'zn_ext_tls_fp');
      externalMailboxFriendHosted =
          await _storage.read(key: 'zn_ext_friend') == '1';
      hostAgentAddress = await _storage.read(key: 'zn_host_agent_addr');
      hostAgentAdminToken = await _storage.read(key: 'zn_host_agent_token');
      hostAgentTlsFp = await _storage.read(key: 'zn_host_agent_tls_fp');
      avatar = await db.kvGet('own_avatar');
    }
  }

  /// iOS keeps Keychain items after an app is deleted, so a reinstalled app
  /// silently resurrects the previous identity — including, after a directory
  /// reset, its now-dead account token (the hub answers every
  /// authenticated call with 401 "invalid token"). The app *sandbox* is wiped
  /// on uninstall, so a marker file there distinguishes a fresh install from
  /// a normal launch. No marker ⇒ the keystore is orphaned: clear it so
  /// onboarding starts clean. This makes the real behaviour match the
  /// documented model — identity dies with the app (PROTOCOL.md), no backup.
  Future<void> _clearKeychainOnFreshInstall() async {
    try {
      final dir = await getApplicationSupportDirectory();
      final marker = File(p.join(dir.path, '.stonechat_installed'));
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
    // Tear down the mailbox first, while the account token still works: after
    // the wipe nobody can ever authenticate as this identity again, so a
    // mailbox left behind is unreachable forever (and on paid tiers keeps
    // billing resources alive). Best-effort — an offline reset still proceeds,
    // matching what the confirmation dialog promises either way.
    try {
      await api.deleteServer();
    } catch (_) {}
    // Keep the DB's SQLCipher key: db.wipe() empties the tables but keeps the
    // file, so a new key here would leave it unopenable next launch.
    final dbKey = await _storage.read(key: 'zn_db_key');
    await _storage.deleteAll();
    if (dbKey != null) await _storage.write(key: 'zn_db_key', value: dbKey);
    await db.wipe();
    _crypto = null;
    stonechatId = null;
    displayName = null;
    pushPrompted = false;
    avatar = null; // db.wipe() dropped the kv row
    externalMailboxToken = null;
    externalMailboxTlsFp = null;
    externalMailboxFriendHosted = false;
    hostAgentAddress = null;
    hostAgentAdminToken = null;
    hostAgentTlsFp = null;
    api.accountToken = null;
    notifyListeners();
  }

  /// Remember that we've shown the notification soft-ask, so it fires only once.
  Future<void> markPushPrompted() async {
    pushPrompted = true;
    await _storage.write(key: 'zn_push_prompted', value: '1');
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
      List<int>.generate(32, (_) => rng.nextInt(256)),
    );
    await _storage.write(key: 'zn_db_key', value: key);
    return key;
  }

  /// Persist the own profile photo (null clears it). Fan-out to contacts is
  /// ChatState's job (updateMyAvatar) — this only stores and repaints.
  Future<void> setAvatar(Uint8List? bytes) async {
    avatar = bytes;
    await db.kvPut('own_avatar', bytes);
    notifyListeners();
  }

  Future<void> setHostAgent(
    String? address,
    String? adminToken,
    String? tlsFp,
  ) async {
    hostAgentAddress = address;
    hostAgentAdminToken = adminToken;
    hostAgentTlsFp = tlsFp;
    if (address == null) {
      await _storage.delete(key: 'zn_host_agent_addr');
      await _storage.delete(key: 'zn_host_agent_token');
      await _storage.delete(key: 'zn_host_agent_tls_fp');
    } else {
      await _storage.write(key: 'zn_host_agent_addr', value: address);
      await _storage.write(key: 'zn_host_agent_token', value: adminToken);
      await _storage.write(key: 'zn_host_agent_tls_fp', value: tlsFp);
    }
    notifyListeners();
  }

  Future<void> setExternalMailbox(
    String? token,
    String? tlsFp, {
    bool friendHosted = false,
  }) async {
    externalMailboxToken = token;
    externalMailboxTlsFp = tlsFp;
    externalMailboxFriendHosted = token != null && friendHosted;
    if (token == null) {
      await _storage.delete(key: 'zn_ext_token');
      await _storage.delete(key: 'zn_ext_tls_fp');
      await _storage.delete(key: 'zn_ext_friend');
    } else {
      await _storage.write(key: 'zn_ext_token', value: token);
      await _storage.write(key: 'zn_ext_tls_fp', value: tlsFp);
      await _storage.write(
        key: 'zn_ext_friend',
        value: friendHosted ? '1' : '0',
      );
    }
  }

  // Set once by init(); createIdentity() needs it whenever onboarding is
  // (re-)entered — including via Reset identity, which does not re-run init.
  SodiumSumo? _sodium;

  /// Onboarding: generate a keypair, register with the hub, persist.
  Future<void> createIdentity({
    required String name,
    required String hubUrl,
  }) async {
    final crypto = CryptoService.generate(_sodium!);
    api.baseUrl = hubUrl;

    final result = await api.register(
      crypto.publicKeyB64,
      crypto.pqPublicKeyB64,
      crypto.signPqPk(),
    );
    api.accountToken = result.accountToken;

    await _storage.write(
      key: 'zn_secret',
      value: base64Encode(crypto.exportSecretKey()),
    );
    await _storage.write(key: 'zn_public', value: crypto.publicKeyB64);
    await _storage.write(key: 'zn_id', value: result.stonechatId);
    await _storage.write(key: 'zn_token', value: result.accountToken);
    await _storage.write(key: 'zn_name', value: name);
    await _storage.write(key: 'zn_hub_url', value: hubUrl);

    _crypto = crypto;
    stonechatId = result.stonechatId;
    displayName = name;
    notifyListeners();
  }

  /// Settings → Identity export: the passphrase-encrypted string the QR
  /// encodes (identity_export.dart). The one deliberate exception to
  /// "identity dies with the app" — created only on explicit user action.
  Future<String> exportIdentity(String passphrase) =>
      IdentityCodec(_sodium!).encode(
        secretKey: crypto.exportSecretKey(),
        passphrase: passphrase,
        name: displayName,
      );

  /// Onboarding → Restore: decrypt an identity export, prove key possession
  /// to the hub (/v1/recover) and persist exactly as createIdentity would.
  /// A hub that has never seen the key (directory reset, different hub)
  /// answers 404 — fall back to plain registration, which yields the same
  /// Stonechat ID because the ID is derived from the key.
  Future<void> restoreIdentity({
    required String export,
    required String passphrase,
    required String hubUrl,
  }) async {
    final sodium = _sodium!;
    final decoded = await IdentityCodec(sodium).decode(export, passphrase);
    // An Ed25519 secret key carries its public half in bytes 32..64.
    final crypto = CryptoService.fromKeys(
      sodium,
      publicKey: decoded.secretKey.sublist(32),
      secretKey: decoded.secretKey,
    );
    api.baseUrl = hubUrl;

    ({String stonechatId, String accountToken}) result;
    final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
    try {
      result = await api.recover(
        pubkeyB64: crypto.publicKeyB64,
        timestamp: now,
        signatureB64: crypto.signRecovery(now),
      );
    } on ApiException catch (e) {
      if (e.status != 404) rethrow;
      // The X-Wing identity is derived from the Ed25519 secret, so a
      // restored identity re-publishes the same pq_pk it always had.
      result = await api.register(
        crypto.publicKeyB64,
        crypto.pqPublicKeyB64,
        crypto.signPqPk(),
      );
    }
    api.accountToken = result.accountToken;

    final name = decoded.name ?? 'Me';
    await _storage.write(
      key: 'zn_secret',
      value: base64Encode(crypto.exportSecretKey()),
    );
    await _storage.write(key: 'zn_public', value: crypto.publicKeyB64);
    await _storage.write(key: 'zn_id', value: result.stonechatId);
    await _storage.write(key: 'zn_token', value: result.accountToken);
    await _storage.write(key: 'zn_name', value: name);
    await _storage.write(key: 'zn_hub_url', value: hubUrl);

    _crypto = crypto;
    stonechatId = result.stonechatId;
    displayName = name;
    notifyListeners();
  }
}
