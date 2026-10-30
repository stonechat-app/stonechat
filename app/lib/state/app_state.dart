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
import '../core/core_ffi.dart';
import '../core/crypto.dart';
import '../core/device_keys.dart';
import '../core/db.dart';
import '../core/identity_export.dart';
import '../core/linking.dart';
import '../core/pqcore.dart';

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
  // user's own mailbox. Pure UI distinction (both are `external` records on
  // the hub) — kept locally so the mailbox screen can say which one it is.
  bool externalMailboxFriendHosted = false;
  /// Linked devices only: this device's own token on the identity's mailbox,
  /// and where that mailbox is — the grant said, the directory keeps it
  /// current. A linked device holds no account token, so this is the only
  /// way it can know its mailbox at all.
  String? deviceToken;
  String? linkedRelayAddress;
  String? linkedRelayTlsFp;

  /// An identity without its secret: a device the primary linked.
  bool get isLinkedDevice =>
      stonechatId != null && !(_crypto?.hasIdentitySecret ?? false);
  // The user's own mailbox host ("host your circle"), if they run one. The
  // admin token is as sensitive as the mailbox token: keystore only, never
  // the hub. The fingerprint is trust-on-first-use, observed at connect.
  String? mailboxHostAddress;
  String? mailboxHostAdminToken;
  String? mailboxHostTlsFp;

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
    await _storage.write(key: 'sc_pref_$key', value: value ? '1' : '0');
    notifyListeners();
  }

  Future<bool> _readPreference(String key, bool fallback) async =>
      switch (await _storage.read(key: 'sc_pref_$key')) {
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
    // Mailbox TLS pinning (api.dart): fingerprint = BLAKE2b-256 of the DER
    // cert, computed by the core — the same function the notification
    // extension pins with.
    certFingerprinter = StonechatCore().tlsFingerprintB64;

    sendReadReceipts = await _readPreference('read_receipts', true);
    sendTypingIndicators = await _readPreference('typing_indicators', true);
    appLockEnabled = await _readPreference('app_lock', false);

    final secret = await _storage.read(key: 'sc_secret');
    final public = await _storage.read(key: 'sc_public');
    final storedUrl = await _storage.read(key: 'sc_hub_url');

    api = HubApi(
      baseUrl: storedUrl ?? defaultHubUrl,
      accountToken: await _storage.read(key: 'sc_token'),
    );

    if (public != null) {
      // A linked device stores the identity's public key and no secret. The
      // public key is the anchor either way: it is what this device's own
      // certificate verifies against and what the SC- ID commits to.
      _crypto = secret != null
          ? CryptoService.fromKeys(secretKey: base64Decode(secret))
          : CryptoService.publicOnly(publicKey: base64Decode(public));
      stonechatId = await _storage.read(key: 'sc_id');
      displayName = await _storage.read(key: 'sc_name');
      pushPrompted = (await _storage.read(key: 'sc_push_prompted')) == '1';
      externalMailboxToken = await _storage.read(key: 'sc_ext_token');
      externalMailboxTlsFp = await _storage.read(key: 'sc_ext_tls_fp');
      externalMailboxFriendHosted =
          await _storage.read(key: 'sc_ext_friend') == '1';
      deviceToken = await _storage.read(key: 'sc_device_token');
      linkedRelayAddress = await _storage.read(key: 'sc_relay_address');
      linkedRelayTlsFp = await _storage.read(key: 'sc_relay_tls_fp');
      mailboxHostAddress = await _storage.read(key: 'sc_mailbox_host_addr');
      mailboxHostAdminToken = await _storage.read(key: 'sc_mailbox_host_token');
      mailboxHostTlsFp = await _storage.read(key: 'sc_mailbox_host_tls_fp');
      avatar = await db.kvGet('own_avatar');
      await _loadOrCreateDeviceKeys();
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
      await api.deleteMailbox();
    } catch (_) {}
    await _wipeLocal();
  }

  /// Delete the account for good: the hub destroys the mailbox, releases
  /// its plan and forgets the identity (POST /v1/account/delete), then
  /// this phone wipes itself. Unlike [resetIdentity] this is not best-effort:
  /// if the hub refuses or can't be reached, nothing local is touched, because
  /// once the identity key is gone the account can never be deleted.
  ///
  /// Primary only — the hub wants a signature by the identity key.
  Future<void> deleteAccount() async {
    final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
    try {
      await api.deleteAccount(
        timestamp: now,
        signatureB64: crypto.signAccountDeletion(now),
      );
    } on ApiException catch (e) {
      // 401 on a token the hub doesn't know: the account is already gone
      // (a directory reset, or an earlier attempt that finished server-side).
      if (e.status != 401 || e.message != 'invalid token') rethrow;
    }
    await _wipeLocal();
  }

  Future<void> _wipeLocal() async {
    // Keep the DB's SQLCipher key: db.wipe() empties the tables but keeps the
    // file, so a new key here would leave it unopenable next launch.
    final dbKey = await _storage.read(key: 'sc_db_key');
    await _storage.deleteAll();
    if (dbKey != null) await _storage.write(key: 'sc_db_key', value: dbKey);
    await db.wipe();
    _crypto = null;
    stonechatId = null;
    displayName = null;
    pushPrompted = false;
    avatar = null; // db.wipe() dropped the kv row
    externalMailboxToken = null;
    externalMailboxTlsFp = null;
    externalMailboxFriendHosted = false;
    deviceToken = null;
    linkedRelayAddress = null;
    linkedRelayTlsFp = null;
    mailboxHostAddress = null;
    mailboxHostAdminToken = null;
    mailboxHostTlsFp = null;
    api.accountToken = null;
    notifyListeners();
  }

  /// Remember that we've shown the notification soft-ask, so it fires only once.
  Future<void> markPushPrompted() async {
    pushPrompted = true;
    await _storage.write(key: 'sc_push_prompted', value: '1');
  }

  /// SQLCipher key for the local history DB: 32 random bytes, minted once,
  /// kept in the platform keystore beside the identity key. Not derivable
  /// from anything — losing the keystore loses the history, same deal as
  /// the identity itself.
  Future<String> _databaseKey() async {
    final existing = await _storage.read(key: 'sc_db_key');
    if (existing != null) return existing;
    final rng = Random.secure();
    final key = base64UrlEncode(
      List<int>.generate(32, (_) => rng.nextInt(256)),
    );
    await _storage.write(key: 'sc_db_key', value: key);
    return key;
  }

  /// Persist the own profile photo (null clears it). Fan-out to contacts is
  /// ChatState's job (updateMyAvatar) — this only stores and repaints.
  Future<void> setAvatar(Uint8List? bytes) async {
    avatar = bytes;
    await db.kvPut('own_avatar', bytes);
    notifyListeners();
  }

  Future<void> setMailboxHost(
    String? address,
    String? adminToken,
    String? tlsFp,
  ) async {
    mailboxHostAddress = address;
    mailboxHostAdminToken = adminToken;
    mailboxHostTlsFp = tlsFp;
    if (address == null) {
      await _storage.delete(key: 'sc_mailbox_host_addr');
      await _storage.delete(key: 'sc_mailbox_host_token');
      await _storage.delete(key: 'sc_mailbox_host_tls_fp');
    } else {
      await _storage.write(key: 'sc_mailbox_host_addr', value: address);
      await _storage.write(key: 'sc_mailbox_host_token', value: adminToken);
      await _storage.write(key: 'sc_mailbox_host_tls_fp', value: tlsFp);
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
      await _storage.delete(key: 'sc_ext_token');
      await _storage.delete(key: 'sc_ext_tls_fp');
      await _storage.delete(key: 'sc_ext_friend');
    } else {
      await _storage.write(key: 'sc_ext_token', value: token);
      await _storage.write(key: 'sc_ext_tls_fp', value: tlsFp);
      await _storage.write(
        key: 'sc_ext_friend',
        value: friendHosted ? '1' : '0',
      );
    }
  }

  /// Onboarding: generate a keypair, register with the hub, persist.
  Future<void> createIdentity({
    required String name,
    required String hubUrl,
  }) async {
    final crypto = CryptoService.generate();
    // Ours to compute, not the hub's to assign: the ID is BLAKE2b-160 of the
    // identity key (PROTOCOL.md "Stonechat ID"), and /v1/register only
    // recomputes it. So derive it here and treat the response as a carrier for
    // the account token. A hub that answers with a different ID is wrong about
    // us, and storing its answer would leave this device advertising an ID that
    // no peer's commitment check can accept.
    final id = crypto.stonechatId;
    api.baseUrl = hubUrl;

    final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
    final result = await api.register(
      pubkeyB64: crypto.publicKeyB64,
      timestamp: now,
      signatureB64: crypto.signRegistration(now),
    );
    if (result.stonechatId != id) {
      throw ApiException.refusing(
        'This hub answered with a different Stonechat ID than your key '
        'derives — refusing to use it.',
      );
    }
    api.accountToken = result.accountToken;

    await _storage.write(
      key: 'sc_secret',
      value: base64Encode(crypto.exportSecretKey()),
    );
    await _storage.write(key: 'sc_public', value: crypto.publicKeyB64);
    await _storage.write(key: 'sc_id', value: id);
    await _storage.write(key: 'sc_token', value: result.accountToken);
    await _storage.write(key: 'sc_name', value: name);
    await _storage.write(key: 'sc_hub_url', value: hubUrl);

    _crypto = crypto;
    stonechatId = id;
    displayName = name;
    // This device needs its own keys before it can certify itself, and load()
    // only makes them when an identity is already in storage — which it was
    // not, a moment ago. Without this the whole session runs with
    // deviceKeys == null: publishPrekeys() returns early, no certificate and
    // no prekeys are ever published, and the mailbox answers every bundle
    // request with 404. Nothing looks wrong here; the identity simply cannot
    // be written to until the app is restarted.
    await _loadOrCreateDeviceKeys();
    notifyListeners();
  }

  /// Settings → Identity export: the passphrase-encrypted string the QR
  /// encodes (identity_export.dart). The one deliberate exception to
  /// "identity dies with the app" — created only on explicit user action.
  Future<String> exportIdentity(String passphrase) =>
      const IdentityCodec().encode(
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
    final decoded = await const IdentityCodec().decode(export, passphrase);
    final crypto = CryptoService.fromKeys(secretKey: decoded.secretKey);
    // Same as createIdentity: the restored key determines the ID, so neither
    // /v1/recover nor the /v1/register fallback gets to name us.
    final id = crypto.stonechatId;
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
      result = await api.register(
        pubkeyB64: crypto.publicKeyB64,
        timestamp: now,
        signatureB64: crypto.signRegistration(now),
      );
    }
    if (result.stonechatId != id) {
      throw ApiException.refusing(
        'This hub answered with a different Stonechat ID than your key '
        'derives — refusing to use it.',
      );
    }
    api.accountToken = result.accountToken;

    final name = decoded.name ?? 'Me';
    await _storage.write(
      key: 'sc_secret',
      value: base64Encode(crypto.exportSecretKey()),
    );
    await _storage.write(key: 'sc_public', value: crypto.publicKeyB64);
    await _storage.write(key: 'sc_id', value: id);
    await _storage.write(key: 'sc_token', value: result.accountToken);
    await _storage.write(key: 'sc_name', value: name);
    await _storage.write(key: 'sc_hub_url', value: hubUrl);

    _crypto = crypto;
    stonechatId = id;
    displayName = name;
    // This device needs its own keys before it can certify itself, and load()
    // only makes them when an identity is already in storage — which it was
    // not, a moment ago. Without this the whole session runs with
    // deviceKeys == null: publishPrekeys() returns early, no certificate and
    // no prekeys are ever published, and the mailbox answers every bundle
    // request with 404. Nothing looks wrong here; the identity simply cannot
    // be written to until the app is restarted.
    await _loadOrCreateDeviceKeys();
    notifyListeners();
  }

  // -- this device's own keys -------------------------------------------------

  /// This device's own signing and seal keys. Never leave this device — not
  /// in a link grant, not anywhere. What travels is the certificate over
  /// their *public* halves.
  DeviceKeys? deviceKeys;

  /// Our own signed certificate, published with our prekeys so peers know
  /// which key to seal to us with.
  Map<String, dynamic>? deviceCert;

  Future<void> _loadOrCreateDeviceKeys() async {
    final stored = await _storage.read(key: 'sc_device_keys');
    if (stored != null) {
      deviceKeys = DeviceKeys.decode(stored);
    } else {
      // First run on this device — including an upgrade from before
      // certificates existed, which is a wipe rather than a migration.
      deviceKeys = DeviceKeys.generate();
      await _storage.write(key: 'sc_device_keys', value: deviceKeys!.encode());
    }
    final storedCert = await _storage.read(key: 'sc_device_cert');
    if (storedCert != null) {
      deviceCert = jsonDecode(storedCert) as Map<String, dynamic>;
    }
  }

  /// Mint (or renew) this device's certificate.
  ///
  /// Only the primary can do this for itself — it is the device holding the
  /// identity root. A linked device receives its certificate in the link
  /// grant and cannot make its own, which is exactly the property that
  /// bounds it: it cannot extend its own life or vouch for anyone else.
  Future<void> ensureOwnCertificate(int deviceId) async {
    final keys = deviceKeys;
    if (keys == null || stonechatId == null) return;
    if (!certNeedsReminting(deviceCert, stonechatId)) return;
    if (deviceId != ChatDb.primaryDevice) {
      // Not ours to mint. If it has run out, the user must re-link; saying so
      // is better than quietly failing to publish.
      return;
    }
    final signed = crypto.core.devcertSign(
      unsignedCert(
        stonechatId: stonechatId!,
        deviceId: deviceId,
        sigPublic: keys.sigPublic,
        sealPublic: keys.sealPublic,
        notAfter: DateTime.now().toUtc().add(primaryCertLifetime),
      ),
      crypto.identitySeed,
    );
    deviceCert = signed;
    await _storage.write(key: 'sc_device_cert', value: jsonEncode(signed));
  }

  /// A certificate our primary renewed for this device, already checked by
  /// the caller to be ours (chat_state `_applySyncCert`).
  Future<void> adoptRenewedCert(Map<String, dynamic> cert) async {
    deviceCert = cert;
    await _storage.write(key: 'sc_device_cert', value: jsonEncode(cert));
  }

  // -- device linking ---------------------------------------------------------

  /// BLAKE2b-256 hex — the parking key derivation, shared by both sides.
  /// The core exposes the hash under its TLS-fingerprint symbol (its first
  /// caller); it is a plain keyless hash, and the relay validates parking
  /// keys as 64 lowercase hex digits.
  static String _hashHex(Uint8List data) => base64Decode(
    StonechatCore().tlsFingerprintB64(data),
  ).map((b) => b.toRadixString(16).padLeft(2, '0')).join();

  /// **New device.** The offer to put on screen: this device's own public
  /// keys, plus a fresh lookup secret.
  ///
  /// The keys are the ones generated on first run — the same pair peers will
  /// seal to and verify prekeys against once the certificate arrives. Showing
  /// the real keys rather than throwaways is what lets the primary certify
  /// this device from the QR alone, and it means the grant can only be opened
  /// by the device its certificate names.
  Future<LinkOffer> beginLinking(String hubUrl) async {
    final keys = deviceKeys ?? DeviceKeys.generate();
    deviceKeys = keys;
    final commitment = offerCommitment(
      _hashBytes,
      keys.sealPublic,
      keys.sigPublic,
    );
    // Parked before the code is shown: a commitment to keys nobody can fetch
    // is a QR that scans and then fails, which is worse than not showing one.
    await putLinkOffer(
      hubUrl,
      _hex(commitment),
      base64Encode(keys.sealPublic),
      base64Encode(keys.sigPublic),
    );
    return LinkOffer(lookup: randomBytes(32), commitment: commitment);
  }

  /// BLAKE2b-256, raw bytes. `_hashHex` is the same hash, hex-encoded.
  static Uint8List _hashBytes(Uint8List data) => Uint8List.fromList(
    base64Decode(StonechatCore().tlsFingerprintB64(data)),
  );

  static String _hex(Uint8List b) =>
      b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

  /// **New device.** Poll the hub for the grant the other device parked, and
  /// become this identity once it arrives.
  ///
  /// The hub is the rendezvous because it is the only address this device
  /// has: the relay it will end up using is *inside* the grant, so it cannot
  /// be the place the grant is collected from.
  Future<bool> collectLinkGrant({
    required String hubUrl,
    required LinkOffer offer,
  }) async {
    final key = linkParkingKey(_hashHex, offer.lookup);
    final sealed = await takeLinkGrant(hubUrl, key);
    if (sealed == null) return false;
    // Same hybrid seal every envelope uses, opened with this device's own
    // seal seed — the one the certificate inside is about to vouch for.
    final opened = StonechatCore().unseal(
      deviceKeys!.sealSeed,
      Uint8List.fromList(base64Decode(sealed)),
    );
    if (opened == null) return false;
    final grant = LinkGrant.fromJson(
      jsonDecode(utf8.decode(opened)) as Map<String, dynamic>,
    );
    await adoptLinkGrant(grant);
    return true;
  }

  /// **New device.** Become the identity in the grant.
  ///
  /// Three checks, and each closes a different substitution:
  ///
  /// 1. the identity key must hash to the claimed SC- ID — so a grant that
  ///    reached us by any route cannot install a *different* identity under
  ///    the name the user is looking at;
  /// 2. the certificate must verify against that identity key, unexpired, and
  ///    name the device id we were given;
  /// 3. the certificate must vouch for **our own** keys. Without this we would
  ///    happily store a valid certificate for some other device, publish it
  ///    with our prekeys, and then be unable to open a single envelope
  ///    addressed to us — a failure with no error anywhere.
  Future<void> adoptLinkGrant(LinkGrant grant) async {
    final identityPub = Uint8List.fromList(base64Decode(grant.identityPubB64));
    final crypto = CryptoService.publicOnly(publicKey: identityPub);
    if (!crypto.pubkeyMatchesId(grant.identityPubB64, grant.stonechatId)) {
      throw ApiException.refusing(
        'That code is for a different identity — refusing to link.',
      );
    }
    final keys = deviceKeys!;
    final status = crypto.core.devcertVerify(
      grant.cert,
      identityPub,
      DateTime.now().toUtc().millisecondsSinceEpoch ~/ 1000,
    );
    if (status != 'valid' ||
        grant.cert['device_id'] != grant.deviceId ||
        grant.cert['stonechat_id'] != grant.stonechatId) {
      throw ApiException.refusing(
        'That link code came with a certificate we cannot use — try again.',
      );
    }
    final certSig = certSigKey(grant.cert);
    final certSeal = certSealKey(grant.cert);
    if (certSig == null ||
        certSeal == null ||
        base64Encode(certSig) != base64Encode(keys.sigPublic) ||
        base64Encode(certSeal) != base64Encode(keys.sealPublic)) {
      throw ApiException.refusing(
        'That certificate is for a different device — refusing to link.',
      );
    }
    api.baseUrl = grant.hubUrl;
    // Deliberately no account token: mailbox management and billing stay with
    // the primary device.
    api.accountToken = null;

    // No `sc_secret`: this device never holds the identity root. Its absence
    // at startup is what makes it a linked device.
    await _storage.write(key: 'sc_public', value: grant.identityPubB64);
    deviceCert = grant.cert;
    await _storage.write(key: 'sc_device_cert', value: jsonEncode(grant.cert));
    await _storage.write(key: 'sc_id', value: grant.stonechatId);
    await _storage.write(key: 'sc_name', value: grant.displayName);
    await _storage.write(key: 'sc_hub_url', value: grant.hubUrl);
    await _storage.write(key: 'sc_device_id', value: '${grant.deviceId}');
    await _storage.write(key: 'sc_device_token', value: grant.deviceToken);
    deviceToken = grant.deviceToken;
    // The mailbox this device drains: the grant names it, and MailboxState
    // reads it from here rather than from the hub, which would want an
    // account token this device does not hold.
    await setLinkedRelay(grant.relayAddress, grant.relayTlsFp);

    _crypto = crypto;
    stonechatId = grant.stonechatId;
    displayName = grant.displayName;
    notifyListeners();
  }

  /// Where a linked device's mailbox is now. From the grant at link time;
  /// later from the directory, when the primary moves the mailbox.
  Future<void> setLinkedRelay(String address, String tlsFp) async {
    linkedRelayAddress = address;
    linkedRelayTlsFp = tlsFp;
    await _storage.write(key: 'sc_relay_address', value: address);
    await _storage.write(key: 'sc_relay_tls_fp', value: tlsFp);
  }

  /// **Existing device.** Authorise a scanned offer: mint the newcomer a
  /// device, seal it everything it needs to be us, and park that on our own
  /// mailbox where only the holder of the QR can collect it.
  Future<int> authoriseLink(
    LinkOffer offer, {
    required String relayAddress,
    required String relayTlsFp,
    required String ownerToken,
    required String hubUrl,
    String? bundleToken,
    String kind = 'linked',
    int? expiresInSeconds,
  }) async {
    final linked = await authoriseLinkDetailed(
      offer,
      relayAddress: relayAddress,
      relayTlsFp: relayTlsFp,
      ownerToken: ownerToken,
      hubUrl: hubUrl,
      bundleToken: bundleToken,
      kind: kind,
      expiresInSeconds: expiresInSeconds,
    );
    return linked.deviceId;
  }

  /// [authoriseLink], also returning the certificate it minted, so the
  /// caller can record the device as ours and list it in the device manifest
  /// before the device has published anything itself.
  Future<({int deviceId, String sigPubB64, Map<String, dynamic> cert})>
      authoriseLinkDetailed(
    LinkOffer offer, {
    required String relayAddress,
    required String relayTlsFp,
    required String ownerToken,
    required String hubUrl,
    String? bundleToken,
    String kind = 'linked',
    int? expiresInSeconds,
  }) async {
    // The QR carried a commitment, not the keys. Fetch them and check they
    // hash to what the user's eyes transported — this is the whole security of
    // the smaller code. A substituted key produces a different commitment and
    // is refused, so the hub cannot put its own key in front of ours.
    final fetched = await getLinkOffer(hubUrl, _hex(offer.commitment));
    if (fetched == null) {
      throw ApiException.refusing(
        'That code has expired — show a fresh one on the other device.',
      );
    }
    final sealPub = Uint8List.fromList(base64Decode(fetched['seal'] as String));
    final sigPub = Uint8List.fromList(base64Decode(fetched['sig'] as String));
    if (sealPub.length != xwingPublicBytes || sigPub.length != 32) {
      throw ApiException.refusing('That code points at malformed keys.');
    }
    final recomputed = offerCommitment(_hashBytes, sealPub, sigPub);
    if (_hex(recomputed) != _hex(offer.commitment)) {
      // The hub served keys other than the ones committed to. It checks this
      // itself, which is exactly why we do not take its word for it.
      throw ApiException.refusing(
        'Those keys do not match the code you scanned — refusing to link.',
      );
    }

    final deviceToken = newDeviceToken(randomBytes(32));
    final minted = await mintDevice(
      relayAddress,
      ownerToken,
      relayTlsFp,
      deviceToken,
      kind: kind,
      expiresInSeconds: expiresInSeconds,
    );
    // The certificate is minted here, from the public keys in the QR, and is
    // the only authority the new device gets. It cannot extend it: renewal
    // means coming back to this device.
    //
    // The lifetime tracks the device row's when one was set, so a device that
    // stops authenticating does not go on being a valid encryption target —
    // two clocks disagreeing is how mail ends up in a dead mailbox.
    final lifetime = expiresInSeconds != null
        ? Duration(seconds: expiresInSeconds)
        : certLifetimeFor(kind);
    final cert = crypto.core.devcertSign(
      unsignedCert(
        stonechatId: stonechatId!,
        deviceId: minted.deviceId,
        sigPublic: sigPub,
        sealPublic: sealPub,
        notAfter: DateTime.now().toUtc().add(lifetime),
      ),
      crypto.identitySeed,
    );
    final grant = LinkGrant(
      identityPubB64: crypto.publicKeyB64,
      cert: cert,
      stonechatId: stonechatId!,
      displayName: displayName ?? '',
      hubUrl: hubUrl,
      relayAddress: relayAddress,
      relayTlsFp: relayTlsFp,
      deviceId: minted.deviceId,
      deviceToken: deviceToken,
      bundleToken: bundleToken,
    );
    final sealed = crypto.sealTo(
      sealPub,
      Uint8List.fromList(utf8.encode(jsonEncode(grant.toJson()))),
    );
    await putLinkGrant(
      hubUrl,
      linkParkingKey(_hashHex, offer.lookup),
      base64Encode(sealed),
    );
    return (
      deviceId: minted.deviceId,
      sigPubB64: base64Encode(sigPub),
      cert: cert,
    );
  }
}
