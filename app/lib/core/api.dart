/// Network layer: hub client, mailbox delivery, mailbox socket.
///
/// Every mailbox connection uses **pinned TLS** (PROTOCOL.md "Transport"):
/// relay certificates are self-signed and validated by fingerprint alone —
/// never by certificate authorities.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:http/http.dart' as http;
import 'package:http/io_client.dart';
import 'package:web_socket_channel/io.dart';
import 'package:web_socket_channel/web_socket_channel.dart';

import '../models.dart';

/// Set once at startup (app_state wires it to stonechat-core, the same
/// function the notification extension pins with): BLAKE2b-256 of a DER
/// certificate.
String Function(Uint8List der)? certFingerprinter;

HttpClient _pinnedHttpClient(String expectedFpB64) =>
    HttpClient()
      ..badCertificateCallback = (X509Certificate cert, _, _) =>
          certFingerprinter!(Uint8List.fromList(cert.der)) == expectedFpB64;

/// An HTTP client that accepts exactly one mailbox certificate: the one whose
/// fingerprint the mailbox owner signed. Everything else — including
/// CA-signed certificates — is rejected.
http.Client pinnedClient(String tlsFpB64) =>
    IOClient(_pinnedHttpClient(tlsFpB64));

/// Trust-on-first-use probe for a relay the caller themself provisioned:
/// observe the certificate for pinning, and confirm the box serves the
/// expected owner by asking it to agree to our own Stonechat ID (the mailbox never
/// hands an identity back — /owner answers yes/no). Used only to bootstrap
/// self-hosted mailboxes — never for peers.
/// Returns `(tlsFp, ownerMatches)`, or null when the box is unreachable.
Future<({String tlsFp, bool ownerMatches})?> observeMailbox(
  String address,
  String expectedStonechatId,
) async {
  String? seenFp;
  final client = HttpClient()
    ..badCertificateCallback = (cert, _, _) {
      seenFp = certFingerprinter!(Uint8List.fromList(cert.der));
      return true;
    };
  try {
    final io = IOClient(client);
    final health = await io
        .get(Uri.parse('$address/health'))
        .timeout(const Duration(seconds: 8));
    if (health.statusCode != 200 || seenFp == null) return null;
    final owner = await io
        .get(
          Uri.parse(
            '$address/owner',
          ).replace(queryParameters: {'stonechat_id': expectedStonechatId}),
        )
        .timeout(const Duration(seconds: 8));
    return (tlsFp: seenFp!, ownerMatches: owner.statusCode == 200);
  } catch (_) {
    return null;
  } finally {
    client.close();
  }
}

class ApiException implements Exception {
  final String message;
  final int? status;
  final Object? detail; // parsed JSON `detail` when the mailbox sent one

  /// This send was *refused*, not merely unlucky: a directory key that doesn't
  /// hash to its ID, a prekey that doesn't verify, a peer with no usable
  /// post-quantum key. Retrying re-asks the same liar the same question, so
  /// callers fail the message immediately instead of queueing it forever.
  final bool refused;

  ApiException(this.message, [this.status, this.detail, this.refused = false]);

  /// A refusal: unusable now and unusable on every retry.
  ApiException.refusing(this.message)
    : status = null,
      detail = null,
      refused = true;

  /// Machine-readable error code (e.g. 'subscription_required'), when the
  /// hub sent a structured detail.
  String? get code => detail is Map ? (detail as Map)['code'] as String? : null;

  @override
  String toString() => message;
}

class DirectoryEntry {
  final String stonechatId;
  final String pubkeyB64;
  final String? pqPkB64; // X-Wing identity key (hybrid envelope seal)…
  final String? pqSigB64; // …signed by the Ed25519 identity key
  final String? mailboxAddress; // null → peer's mailbox is off right now
  final String? mailboxTlsFp; // pinned cert fingerprint…
  final String? mailboxTlsSig; // …vouched for by the owner's identity key

  DirectoryEntry({
    required this.stonechatId,
    required this.pubkeyB64,
    this.pqPkB64,
    this.pqSigB64,
    this.mailboxAddress,
    this.mailboxTlsFp,
    this.mailboxTlsSig,
  });
}

class MailboxRecord {
  final String status; // none | provisioning | running | error
  final String? provider;
  final String? address;
  final String? mailboxToken;
  final String? tlsFp; // observed by the hub at provision time
  final String? error;
  // Dedicated (Machine plan) VMs ship with the mailbox host pre-installed; the hub
  // hands back where it lives and the admin token it was minted with, so the
  // Invites screen connects without any manual setup.
  final String? mailboxHostAddress;
  final String? mailboxHostAdminToken;

  MailboxRecord({
    required this.status,
    this.provider,
    this.address,
    this.mailboxToken,
    this.tlsFp,
    this.error,
    this.mailboxHostAddress,
    this.mailboxHostAdminToken,
  });
}

/// One country a mailbox can live in, as the hub's catalog describes it.
///
/// Everything here is mailbox-authored on purpose: which cloud serves which
/// flag is a hub decision (hub/app/countries.py), so changing a provider — or
/// the wording of a jurisdiction line — never needs an app release.
class MailboxCountry {
  final String code; // ISO 3166-1 alpha-2; what /v1/mailbox is sent
  final String name;
  final String city;
  final String flag; // emoji
  /// What the country buys the user.
  final String jurisdiction;
  /// What it does not. Never render one without the other — a picker that
  /// shows only the flattering half is marketing, not a privacy feature.
  final String caveat;
  /// Plans that can place a mailbox here today ("machine", "mailbox").
  final List<String> plans;

  MailboxCountry({
    required this.code,
    required this.name,
    required this.city,
    required this.flag,
    required this.jurisdiction,
    required this.caveat,
    required this.plans,
  });

  factory MailboxCountry.fromJson(Map<String, dynamic> j) => MailboxCountry(
        code: j['code'] as String,
        name: j['name'] as String,
        city: j['city'] as String,
        flag: j['flag'] as String? ?? '',
        jurisdiction: j['jurisdiction'] as String? ?? '',
        caveat: j['caveat'] as String? ?? '',
        plans: ((j['plans'] as List?) ?? const []).cast<String>(),
      );

  bool allows(String? plan) => plan == null || plans.contains(plan);
}

/// Talks to the provisioner + directory. Holds the account bearer token.
class HubApi {
  String baseUrl;
  String? accountToken;

  HubApi({required this.baseUrl, this.accountToken});

  Map<String, String> get _auth => {
    if (accountToken != null) 'Authorization': 'Bearer $accountToken',
    'Content-Type': 'application/json',
  };

  Future<T> _check<T>(http.Response r, T Function(Map<String, dynamic>) parse) {
    final body = r.body.isEmpty ? <String, dynamic>{} : jsonDecode(r.body);
    if (r.statusCode >= 400) {
      final detail = body is Map ? body['detail'] : null;
      final message = detail is Map
          ? (detail['message'] as String? ?? '$detail')
          : (detail?.toString() ?? r.body);
      throw ApiException(message, r.statusCode, detail);
    }
    return Future.value(parse(body as Map<String, dynamic>));
  }

  /// [pqPkB64]/[pqSigB64]: the X-Wing identity key and its Ed25519
  /// signature, published in the directory for the hybrid envelope seal.
  Future<({String stonechatId, String accountToken})> register(
    String pubkeyB64,
    String pqPkB64,
    String pqSigB64,
  ) async {
    final r = await http.post(
      Uri.parse('$baseUrl/v1/register'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'pubkey': pubkeyB64,
        'pq_pk': pqPkB64,
        'pq_sig': pqSigB64,
      }),
    );
    return _check(
      r,
      (j) => (
        stonechatId: j['stonechat_id'] as String,
        accountToken: j['account_token'] as String,
      ),
    );
  }

  /// Identity restore: trade a proof of key possession (CryptoService
  /// .signRecovery) for a fresh account token. 404 means the hub has never
  /// seen this key — the caller falls back to register().
  Future<({String stonechatId, String accountToken})> recover({
    required String pubkeyB64,
    required int timestamp,
    required String signatureB64,
  }) async {
    final r = await http.post(
      Uri.parse('$baseUrl/v1/recover'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'pubkey': pubkeyB64,
        'timestamp': timestamp,
        'signature': signatureB64,
      }),
    );
    return _check(
      r,
      (j) => (
        stonechatId: j['stonechat_id'] as String,
        accountToken: j['account_token'] as String,
      ),
    );
  }

  /// Resolves a full SC- Stonechat ID to its directory record. Lookup is by ID
  /// only — there are no handles. [hubUrl] asks a different hub's directory
  /// (cross-hub): the answer is verified by the caller exactly like one from
  /// our own hub, so the foreign hub is trusted for availability only.
  Future<DirectoryEntry> directory(String stonechatId, {String? hubUrl}) async {
    final r = await http.get(
      Uri.parse('${hubUrl ?? baseUrl}/v1/directory/$stonechatId'),
    );
    return _check(r, (j) {
      final mailbox = j['mailbox'] as Map<String, dynamic>?;
      return DirectoryEntry(
        stonechatId: j['stonechat_id'] as String,
        pubkeyB64: j['pubkey'] as String,
        pqPkB64: j['pq_pk'] as String?,
        pqSigB64: j['pq_sig'] as String?,
        mailboxAddress: mailbox?['address'] as String?,
        mailboxTlsFp: mailbox?['tls_fp'] as String?,
        mailboxTlsSig: mailbox?['tls_sig'] as String?,
      );
    });
  }

  /// Where a mailbox may live. Unauthenticated, so the picker can render
  /// during onboarding before an account exists.
  Future<List<MailboxCountry>> getCountries() async {
    final r = await http.get(Uri.parse('$baseUrl/v1/countries'));
    return _check(r, (j) => ((j['countries'] as List?) ?? const [])
        .map((e) => MailboxCountry.fromJson(e as Map<String, dynamic>))
        .toList());
  }

  /// Create the mailbox. Pass [country] — the hub resolves it against its
  /// catalog and the account's plan. [provider]/[machineType]/[region] is the
  /// older explicit form, kept for tests and local Docker development where
  /// there is no country to speak of.
  Future<void> createMailbox({
    String? country,
    String? provider,
    String? machineType,
    String? region,
    int diskGb = 10,
  }) async {
    assert((country != null) != (provider != null),
        'pass either a country or a provider+machine, not both');
    final r = await http.post(
      Uri.parse('$baseUrl/v1/mailbox'),
      headers: _auth,
      body: jsonEncode(country != null
          ? {'country': country}
          : {
              'provider': provider,
              'machine': {
                'machine_type': machineType,
                'region': region,
                'disk_gb': diskGb,
              },
            }),
    );
    await _check(r, (_) => null);
  }

  Future<MailboxRecord> getMailbox() async {
    final r = await http.get(Uri.parse('$baseUrl/v1/mailbox'), headers: _auth);
    return _check(r, (j) {
      final mailboxHost = j['mailbox_host'] as Map<String, dynamic>?;
      return MailboxRecord(
        status: j['status'] as String,
        provider: j['provider'] as String?,
        address: j['address'] as String?,
        mailboxToken: j['mailbox_token'] as String?,
        tlsFp: j['tls_fp'] as String?,
        error: j['error'] as String?,
        mailboxHostAddress: mailboxHost?['address'] as String?,
        mailboxHostAdminToken: mailboxHost?['admin_token'] as String?,
      );
    });
  }

  /// Owner vouches for their mailbox's TLS key: publish the identity-key
  /// signature over its fingerprint so peers can pin it via the directory.
  Future<void> publishTlsSig(String tlsFp, String tlsSig) async {
    final r = await http.post(
      Uri.parse('$baseUrl/v1/mailbox/tls'),
      headers: _auth,
      body: jsonEncode({'tls_fp': tlsFp, 'tls_sig': tlsSig}),
    );
    await _check(r, (_) => null);
  }

  /// Publish the owner's signature over the mailbox's browser-transport
  /// certificate schedule. Same shape as [publishTlsSig] and for the same
  /// reason: the relay states which certificates it will present, and only the
  /// owner can vouch that the list is theirs.
  Future<void> publishWtCerts(
    List<Map<String, dynamic>> certs,
    String wtSig,
  ) async {
    final r = await http.post(
      Uri.parse('$baseUrl/v1/mailbox/wt'),
      headers: _auth,
      body: jsonEncode({'certs': certs, 'wt_sig': wtSig}),
    );
    await _check(r, (_) => null);
  }

  /// Delete the account on the hub: its mailbox, its billing and its
  /// directory entry (PROTOCOL.md "Hub API"). [signatureB64] is
  /// CryptoService.signAccountDeletion over [timestamp].
  Future<void> deleteAccount({
    required int timestamp,
    required String signatureB64,
  }) async {
    final r = await http
        .post(
          Uri.parse('$baseUrl/v1/account/delete'),
          headers: _auth,
          body: jsonEncode({'timestamp': timestamp, 'signature': signatureB64}),
        )
        .timeout(const Duration(seconds: 60)); // destroying a VM takes a while
    await _check(r, (_) => null);
  }

  Future<void> deleteMailbox() async {
    final r = await http
        .delete(
          Uri.parse('$baseUrl/v1/mailbox'),
          headers: _auth,
        )
        .timeout(const Duration(seconds: 10));
    await _check(r, (_) => null);
  }

  /// Free tier: list a self-provisioned relay in the directory. The relay's
  /// token never goes to the hub — only the address does, plus the browser
  /// transport's `host:port` when the relay has one.
  Future<void> registerExternalMailbox(String address,
      {String? wtAddress}) async {
    final r = await http.post(
      Uri.parse('$baseUrl/v1/mailbox/external'),
      headers: _auth,
      body: jsonEncode({'address': address, 'wt_address': ?wtAddress}),
    );
    await _check(r, (_) => null);
  }

  /// The account's live plan, or null (PROTOCOL.md "Billing").
  Future<({String plan, String status, String? currentPeriodEnd})?>
  getEntitlement() async {
    final r = await http.get(
      Uri.parse('$baseUrl/v1/billing/entitlement'),
      headers: _auth,
    );
    return _check(r, (j) {
      final plan = j['plan'] as String?;
      if (plan == null) return null;
      return (
        plan: plan,
        status: j['status'] as String,
        currentPeriodEnd: j['current_period_end'] as String?,
      );
    });
  }

  /// Redeem an activation code from a landing-page purchase (or a comp
  /// grant), binding its subscription to this account.
  Future<({String plan, String status})> redeemCode(String code) async {
    final r = await http.post(
      Uri.parse('$baseUrl/v1/billing/redeem'),
      headers: _auth,
      body: jsonEncode({'code': code}),
    );
    return _check(
      r,
      (j) => (plan: j['plan'] as String, status: j['status'] as String),
    );
  }
}

/// File an abuse report with the hub hosting the reported account
/// (hub/app/report.py). Returns the reference id.
///
/// Deliberately not a HubApi method: the report goes to the *reported* user's
/// home hub, which under cross-hub resolution is not the one this account belongs to,
/// and the account token would mean nothing there anyway. The Ed25519
/// signature is the whole credential.
///
/// Throws ApiException with code `not_our_account` when that hub does not host
/// them — the caller should say so rather than swallow it, because the report
/// has gone nowhere.
Future<String> fileReport({
  required String hubUrl,
  required String reportedId,
  required String reporterPubkeyB64,
  required int timestamp,
  required String category,
  required String note,
  required String? evidence,
  required String signatureB64,
}) async {
  final r = await http
      .post(
        Uri.parse('$hubUrl/v1/report'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({
          'reported_id': reportedId,
          'reporter_pubkey': reporterPubkeyB64,
          'timestamp': timestamp,
          'category': category,
          'note': note,
          'evidence': evidence,
          'signature': signatureB64,
        }),
      )
      .timeout(const Duration(seconds: 20));
  final body = r.body.isEmpty ? <String, dynamic>{} : jsonDecode(r.body);
  if (r.statusCode >= 400) {
    final detail = body is Map ? body['detail'] : null;
    final message = detail is Map
        ? (detail['message'] as String? ?? '$detail')
        : (detail?.toString() ?? r.body);
    throw ApiException(message, r.statusCode, detail);
  }
  return (body as Map<String, dynamic>)['report_id'] as String;
}

/// Fetch a mailbox's browser-transport certificate schedule.
///
/// Unauthenticated at the relay, and untrusted here: what makes the list
/// usable is the owner's signature over it, published separately to the hub.
/// Returns null when the mailbox has no browser transport, which is a normal
/// state and not an error.
Future<Map<String, dynamic>?> fetchWtCerts(
  String mailboxAddress,
  String tlsFp,
) async {
  final client = pinnedClient(tlsFp);
  try {
    final r = await client
        .get(Uri.parse('$mailboxAddress/wt/certs'))
        .timeout(const Duration(seconds: 10));
    if (r.statusCode == 404) return null; // browser transport disabled
    if (r.statusCode >= 400) {
      throw ApiException('wt certs unavailable (${r.statusCode})', r.statusCode);
    }
    return jsonDecode(r.body) as Map<String, dynamic>;
  } finally {
    client.close();
  }
}

/// Fetch a peer's prekey bundle from their mailbox (consumes a one-time
/// prekey mailbox-side). The caller must verify the SPK signature against the
/// peer's directory identity key.
Future<Map<String, dynamic>> fetchPrekeyBundle(
  String mailboxAddress,
  String tlsFp,
) async {
  final client = pinnedClient(tlsFp);
  try {
    final r = await client
        .get(Uri.parse('$mailboxAddress/prekeys/bundle'))
        .timeout(const Duration(seconds: 10));
    if (r.statusCode >= 400) {
      throw ApiException(
        'prekey bundle unavailable (${r.statusCode})',
        r.statusCode,
      );
    }
    return jsonDecode(r.body) as Map<String, dynamic>;
  } finally {
    client.close();
  }
}

/// Mint a device on our own mailbox for one being linked. The caller supplies
/// the token it is about to seal into the grant; the relay stores only its
/// hash (MULTIDEVICE.md "Device model").
///
/// [expiresInSeconds] bounds the new device's authority — set for a browser
/// session, whose whole defence is that it ends on its own.
Future<({int deviceId, String kind, String? expiresAt})> mintDevice(
  String mailboxAddress,
  String token,
  String tlsFp,
  String newDeviceToken, {
  String kind = 'linked',
  int? expiresInSeconds,
}) async {
  final client = pinnedClient(tlsFp);
  try {
    final r = await client
        .post(
          Uri.parse('$mailboxAddress/devices').replace(
            queryParameters: {'token': token},
          ),
          headers: {'Content-Type': 'application/json'},
          body: jsonEncode({
            'device_token': newDeviceToken,
            'kind': kind,
            // Omitted entirely when unbounded — the relay reads absent as
            // "lives until revoked", which is not the same as a null value.
            'expires_in_s': ?expiresInSeconds,
          }),
        )
        .timeout(const Duration(seconds: 15));
    if (r.statusCode >= 400) {
      throw ApiException('could not add the device (${r.statusCode})', r.statusCode);
    }
    final j = jsonDecode(r.body) as Map<String, dynamic>;
    return (
      deviceId: j['device_id'] as int,
      kind: j['kind'] as String? ?? kind,
      expiresAt: j['expires_at'] as String?,
    );
  } finally {
    client.close();
  }
}

/// The devices on our own mailbox, for the management screen.
Future<({int devicesV, List<Map<String, dynamic>> devices})> listDevices(
  String mailboxAddress,
  String token,
  String tlsFp,
) async {
  final client = pinnedClient(tlsFp);
  try {
    final r = await client
        .get(Uri.parse('$mailboxAddress/devices').replace(
          queryParameters: {'token': token},
        ))
        .timeout(const Duration(seconds: 10));
    if (r.statusCode >= 400) {
      throw ApiException('could not list devices (${r.statusCode})', r.statusCode);
    }
    final j = jsonDecode(r.body) as Map<String, dynamic>;
    return (
      devicesV: (j['devices_v'] as int?) ?? 0,
      devices: [
        for (final d in (j['devices'] as List? ?? const []))
          (d as Map<String, dynamic>),
      ],
    );
  } finally {
    client.close();
  }
}

/// Revoke a device. A delivery cut, not a cryptographic excision — the
/// revoked device still holds the identity secret (MULTIDEVICE.md
/// "Revocation and threat notes").
Future<void> revokeDevice(
  String mailboxAddress,
  String token,
  String tlsFp,
  int deviceId,
) async {
  final client = pinnedClient(tlsFp);
  try {
    final r = await client
        .delete(Uri.parse('$mailboxAddress/devices/$deviceId').replace(
          queryParameters: {'token': token},
        ))
        .timeout(const Duration(seconds: 10));
    if (r.statusCode >= 400) {
      throw ApiException('could not revoke (${r.statusCode})', r.statusCode);
    }
  } finally {
    client.close();
  }
}

/// Park a sealed link grant on the **hub**.
///
/// The hub, not the relay, because of who has to collect it: a device being
/// linked has no identity, no account and no way to learn which relay to
/// poll. The hub URL is the only address it has — onboarding asked for it.
/// The hub stores bytes it cannot open, filed under the hash of a secret it
/// never sees.
/// Park this device's public keys under a commitment to them.
///
/// The QR carries only the commitment — 32 bytes instead of 1248 — so the keys
/// themselves travel here. The hub recomputes the commitment and refuses a
/// mismatch; the scanning device checks again on arrival, because the hub's
/// word does not count.
Future<void> putLinkOffer(
  String hubUrl,
  String commitmentHex,
  String sealPubB64,
  String sigPubB64,
) async {
  final r = await http.post(
    Uri.parse('$hubUrl/v1/link/offer'),
    headers: {'content-type': 'application/json'},
    body: jsonEncode({
      'key': commitmentHex,
      'offer': {'seal': sealPubB64, 'sig': sigPubB64},
    }),
  );
  if (r.statusCode >= 400) {
    throw ApiException('could not publish the link code (${r.statusCode})', r.statusCode);
  }
}

/// Fetch the keys an offer commits to. Not single-use: a scan that fails
/// downstream must be retryable.
Future<Map<String, dynamic>?> getLinkOffer(
  String hubUrl,
  String commitmentHex,
) async {
  final r = await http.get(Uri.parse('$hubUrl/v1/link/offer/$commitmentHex'));
  if (r.statusCode == 404) return null;
  if (r.statusCode >= 400) {
    throw ApiException('could not read the link code (${r.statusCode})', r.statusCode);
  }
  return (jsonDecode(r.body) as Map<String, dynamic>)['offer']
      as Map<String, dynamic>;
}

Future<void> putLinkGrant(String hubUrl, String key, String sealedB64) async {
  final r = await http.post(
    Uri.parse('$hubUrl/v1/link'),
    headers: {'Content-Type': 'application/json'},
    body: jsonEncode({'key': key, 'sealed': sealedB64}),
  );
  if (r.statusCode >= 400) {
    throw ApiException('could not park the grant (${r.statusCode})', r.statusCode);
  }
}

/// Collect a parked grant. Unauthenticated — the new device has no credential
/// yet, and possession of the QR is the credential. Null while the other
/// device has not parked it, or once it has already been collected.
Future<String?> takeLinkGrant(String hubUrl, String key) async {
  try {
    final r = await http
        .get(Uri.parse('$hubUrl/v1/link/$key'))
        .timeout(const Duration(seconds: 10));
    if (r.statusCode != 200) return null;
    return (jsonDecode(r.body) as Map<String, dynamic>)['sealed'] as String?;
  } catch (_) {
    return null;
  }
}

/// A peer's device list plus their current `devices_v`, from their mailbox.
///
/// Consumes **no** one-time prekeys — listing and consuming are separate
/// calls precisely so no single request can burn a prekey per device
/// (MULTIDEVICE.md "Why the device list is gated"). Needs the peer's bundle
/// token; without it a sender can only reach their primary device, which is
/// what a stranger sending a contact request gets.
Future<({int devicesV, List<int> devices, Map<int, Map<String, dynamic>> certs})>
fetchDeviceList(
  String mailboxAddress,
  String bundleToken,
  String tlsFp,
) async {
  final client = pinnedClient(tlsFp);
  try {
    final r = await client
        .get(Uri.parse('$mailboxAddress/prekeys/devices?token=$bundleToken'))
        .timeout(const Duration(seconds: 10));
    if (r.statusCode >= 400) {
      throw ApiException(
        'device list unavailable (${r.statusCode})',
        r.statusCode,
      );
    }
    final j = jsonDecode(r.body) as Map<String, dynamic>;
    final entries = [
      for (final d in (j['devices'] as List? ?? const []))
        (d as Map<String, dynamic>),
    ];
    return (
      devicesV: (j['devices_v'] as int?) ?? 0,
      devices: [for (final d in entries) d['device_id'] as int],
      // Certificates ride the same response: the caller needs the key to
      // seal to and the key to check prekeys against, and fetching them
      // separately would be two requests for one answer.
      certs: {
        for (final d in entries)
          if (d['cert'] is Map<String, dynamic>)
            d['device_id'] as int: d['cert'] as Map<String, dynamic>,
      },
    );
  } finally {
    client.close();
  }
}

/// One device's prekey bundle. Costs exactly one OPK, for one named device.
Future<Map<String, dynamic>> fetchDeviceBundle(
  String mailboxAddress,
  int deviceId,
  String bundleToken,
  String tlsFp,
) async {
  final client = pinnedClient(tlsFp);
  try {
    final r = await client
        .get(
          Uri.parse(
            '$mailboxAddress/prekeys/bundle?device=$deviceId&token=$bundleToken',
          ),
        )
        .timeout(const Duration(seconds: 10));
    if (r.statusCode >= 400) {
      throw ApiException(
        'prekey bundle unavailable (${r.statusCode})',
        r.statusCode,
      );
    }
    return jsonDecode(r.body) as Map<String, dynamic>;
  } finally {
    client.close();
  }
}

/// Publish our public prekeys to our own mailbox (owner token required).
/// Carries both halves of PQXDH: X25519 (spk/opks) and ML-KEM-768
/// (kspk/kopks).
Future<void> uploadPrekeys(
  String mailboxAddress,
  String token,
  String tlsFp,
  Map<String, Object?> spk,
  List<Map<String, Object?>> opks,
  Map<String, Object?> kspk,
  List<Map<String, Object?>> kopks, {
  /// This device's certificate. Goes up with the prekeys because it names
  /// the key that signed them — one without the other leaves a peer unable
  /// to check either.
  Map<String, dynamic>? cert,
}) async {
  final client = pinnedClient(tlsFp);
  try {
    final r = await client
        .post(
          Uri.parse('$mailboxAddress/prekeys?token=$token'),
          headers: {'Content-Type': 'application/json'},
          body: jsonEncode({
            'spk': spk,
            'opks': opks,
            'kspk': kspk,
            'kopks': kopks,
            // Absent leaves whatever the relay holds, so a routine restock
            // never drops it.
            'cert': ?cert,
          }),
        )
        .timeout(const Duration(seconds: 10));
    if (r.statusCode >= 400) {
      throw ApiException(
        'prekey upload failed (${r.statusCode})',
        r.statusCode,
      );
    }
  } finally {
    client.close();
  }
}

/// Our own mailbox's view of *this* device: which device we are, the current
/// device-set version, our prekey inventory, and the bundle token we hand to
/// peers so they can list our devices.
///
/// The token cannot be derived client-side by anyone but device 1 (it comes
/// from the owner token), so the relay tells every authenticated device what
/// it is.
Future<MailboxStatus?> mailboxStatus(
  String address,
  String tlsFp,
  String token,
) async {
  final client = pinnedClient(tlsFp);
  try {
    final r = await client
        .get(
          Uri.parse(
            '$address/status',
          ).replace(queryParameters: {'token': token}),
        )
        .timeout(const Duration(seconds: 8));
    if (r.statusCode != 200) return null;
    final j = jsonDecode(r.body) as Map<String, dynamic>;
    final prekeys = j['prekeys'] as Map<String, dynamic>?;
    return MailboxStatus(
      deviceId: (j['device_id'] as int?) ?? 1,
      devicesV: (j['devices_v'] as int?) ?? 0,
      bundleToken: j['bundle_token'] as String?,
      prekeys: prekeys == null
          ? null
          : (
              spk: prekeys['spk'] as bool,
              opks: prekeys['opks'] as int,
              kspk: prekeys['kspk'] as bool? ?? false,
              kopks: prekeys['kopks'] as int? ?? 0,
            ),
    );
  } catch (_) {
    return null;
  } finally {
    client.close();
  }
}

class MailboxStatus {
  final int deviceId;
  final int devicesV;
  final String? bundleToken;
  final ({bool spk, int opks, bool kspk, int kopks})? prekeys;

  const MailboxStatus({
    required this.deviceId,
    required this.devicesV,
    required this.bundleToken,
    required this.prekeys,
  });
}

// -- invite-hosted mailboxes ("host your circle") -----------------------------

/// A parsed host invite: where the mailbox host is, its pinned fingerprint, and the
/// one-time token. Encoded as "stonechat-host:" + urlsafe-base64(JSON{u,f,t}).
class HostInvite {
  final String url; // mailbox host base URL (https)
  final String fp; // mailbox host TLS fingerprint to pin
  final String token; // invite token

  HostInvite(this.url, this.fp, this.token);

  static HostInvite parse(String raw) {
    final s = raw.trim();
    const prefix = 'stonechat-host:';
    if (!s.startsWith(prefix)) {
      throw const FormatException('That is not a Stonechat host invite');
    }
    var b64 = s.substring(prefix.length);
    b64 += '=' * ((4 - b64.length % 4) % 4);
    final j =
        jsonDecode(utf8.decode(base64Url.decode(b64))) as Map<String, dynamic>;
    return HostInvite(j['u'] as String, j['f'] as String, j['t'] as String);
  }
}

String _detail(http.Response r) {
  try {
    final b = jsonDecode(r.body);
    if (b is Map && b['detail'] != null) return '${b['detail']}';
  } catch (_) {}
  return 'error ${r.statusCode}';
}

/// Redeem a host invite → a mailbox for [ownerId] on that host. Pinned to the
/// mailbox host fingerprint carried in the invite (no CA, no MITM).
Future<({String address, String mailboxToken, String tlsFp})> redeemHostInvite(
  HostInvite invite,
  String ownerId,
) async {
  final client = pinnedClient(invite.fp);
  try {
    final r = await client
        .post(
          Uri.parse('${invite.url}/v1/redeem'),
          headers: {'Content-Type': 'application/json'},
          body: jsonEncode({'invite': invite.token, 'owner_id': ownerId}),
        )
        .timeout(const Duration(seconds: 90));
    if (r.statusCode >= 400) throw ApiException(_detail(r), r.statusCode);
    final j = jsonDecode(r.body) as Map<String, dynamic>;
    return (
      address: j['address'] as String,
      mailboxToken: j['mailbox_token'] as String,
      tlsFp: j['tls_fp'] as String,
    );
  } finally {
    client.close();
  }
}

/// Observe a mailbox host's TLS fingerprint (trust-on-first-use). Used by the
/// host-owner contacting their OWN mailbox host to mint invites.
Future<String?> observeCertFingerprint(String url) async {
  String? seen;
  final client = HttpClient()
    ..badCertificateCallback = (cert, _, _) {
      seen = certFingerprinter!(Uint8List.fromList(cert.der));
      return true;
    };
  try {
    final r = await IOClient(
      client,
    ).get(Uri.parse('$url/health')).timeout(const Duration(seconds: 8));
    return r.statusCode == 200 ? seen : null;
  } catch (_) {
    return null;
  } finally {
    client.close();
  }
}

/// Host-owner mints an invite through their mailbox host's admin API (pinned).
Future<String> createHostInvite(
  String agentUrl,
  String agentFp,
  String adminToken, {
  int uses = 1,
  int ttlHours = 72,
}) async {
  final client = pinnedClient(agentFp);
  try {
    final r = await client
        .post(
          Uri.parse('$agentUrl/v1/invite'),
          headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer $adminToken',
          },
          body: jsonEncode({'uses': uses, 'ttl_hours': ttlHours}),
        )
        .timeout(const Duration(seconds: 10));
    if (r.statusCode >= 400) throw ApiException(_detail(r), r.statusCode);
    return (jsonDecode(r.body) as Map<String, dynamic>)['invite'] as String;
  } finally {
    client.close();
  }
}

/// One minted invite as the mailbox host reports it: the shareable string plus
/// enough to show status (waiting / accepted / expired) in the app.
class HostInviteStatus {
  final String invite; // full "stonechat-host:..." string, re-shareable
  final int uses;
  final int usesLeft;
  final DateTime expiresAt;
  final DateTime createdAt;
  final List<String> redeemedBy; // guest Stonechat IDs, in redemption order

  HostInviteStatus({
    required this.invite,
    required this.uses,
    required this.usesLeft,
    required this.expiresAt,
    required this.createdAt,
    required this.redeemedBy,
  });

  bool get expired => expiresAt.isBefore(DateTime.now());
}

/// Host-owner lists every invite they've minted, with redemption status.
Future<List<HostInviteStatus>> listHostInvites(
  String agentUrl,
  String agentFp,
  String adminToken,
) async {
  final client = pinnedClient(agentFp);
  try {
    final r = await client
        .get(
          Uri.parse('$agentUrl/v1/invites'),
          headers: {'Authorization': 'Bearer $adminToken'},
        )
        .timeout(const Duration(seconds: 10));
    if (r.statusCode >= 400) throw ApiException(_detail(r), r.statusCode);
    final j = jsonDecode(r.body) as Map<String, dynamic>;
    return [
      for (final e in (j['invites'] as List).cast<Map<String, dynamic>>())
        HostInviteStatus(
          invite: e['invite'] as String,
          uses: e['uses'] as int,
          usesLeft: e['uses_left'] as int,
          expiresAt: DateTime.fromMillisecondsSinceEpoch(
            ((e['expires_at'] as num) * 1000).round(),
          ),
          createdAt: DateTime.parse(e['created_at'] as String).toLocal(),
          redeemedBy: (e['redeemed_by'] as List).cast<String>(),
        ),
    ];
  } finally {
    client.close();
  }
}

/// Ephemeral TURN credentials from *your own* mailbox's relay (owner token).
/// Returns null when the mailbox runs no TURN — callers fall back to
/// STUN-only.
Future<({List<String> urls, String username, String credential})?>
fetchTurnCredentials(
  String mailboxAddress,
  String ownerToken,
  String tlsFp,
) async {
  final client = pinnedClient(tlsFp);
  try {
    final r = await client
        .get(Uri.parse('$mailboxAddress/turn-credentials?token=$ownerToken'))
        .timeout(const Duration(seconds: 8));
    if (r.statusCode == 404) return null;
    if (r.statusCode >= 400) {
      throw ApiException(
        'turn credentials failed (${r.statusCode})',
        r.statusCode,
      );
    }
    final j = jsonDecode(r.body) as Map<String, dynamic>;
    return (
      urls: (j['urls'] as List).cast<String>(),
      username: j['username'] as String,
      credential: j['credential'] as String,
    );
  } catch (_) {
    return null; // TURN is an upgrade, never a blocker
  } finally {
    client.close();
  }
}

/// Register this device's push token with our OWN mailbox (owner token +
/// pinned TLS). The mailbox will ping the push gateway when we're offline.
Future<void> setPushConfig(
  String mailboxAddress,
  String ownerToken,
  String deviceToken,
  String platform,
  String tlsFp,
) async {
  final client = pinnedClient(tlsFp);
  try {
    final r = await client
        .post(
          Uri.parse('$mailboxAddress/push-config?token=$ownerToken'),
          headers: {'Content-Type': 'application/json'},
          body: jsonEncode({'device_token': deviceToken, 'platform': platform}),
        )
        .timeout(const Duration(seconds: 10));
    if (r.statusCode >= 400) {
      throw ApiException('push-config failed (${r.statusCode})', r.statusCode);
    }
  } finally {
    client.close();
  }
}

/// Upload an encrypted media blob to a peer's mailbox. Returns the blob id
/// to reference from the media envelope.
Future<String> uploadBlob(
  String mailboxAddress,
  List<int> bytes,
  String tlsFp,
) async {
  final client = pinnedClient(tlsFp);
  try {
    final r = await client
        .post(
          Uri.parse('$mailboxAddress/blob'),
          headers: {'Content-Type': 'application/octet-stream'},
          body: bytes,
        )
        .timeout(const Duration(seconds: 60));
    if (r.statusCode >= 400) {
      throw ApiException('blob upload failed (${r.statusCode})', r.statusCode);
    }
    return (jsonDecode(r.body) as Map<String, dynamic>)['blob_id'] as String;
  } finally {
    client.close();
  }
}

/// Upload one encrypted blob to *our own* mailbox and take a read capability
/// for it (PROTOCOL.md "Group media"). Group media uploads once and hands the
/// returned token to every member inside their envelope, instead of parking a
/// copy on each of their mailboxes.
Future<SharedBlobUpload> uploadSharedBlob(
  String mailboxAddress,
  List<int> bytes,
  String tlsFp,
) async {
  final client = pinnedClient(tlsFp);
  try {
    final r = await client
        .post(
          Uri.parse('$mailboxAddress/blob?shared=1'),
          headers: {'Content-Type': 'application/octet-stream'},
          body: bytes,
        )
        .timeout(const Duration(seconds: 120));
    if (r.statusCode >= 400) {
      throw ApiException('blob upload failed (${r.statusCode})', r.statusCode);
    }
    final j = jsonDecode(r.body) as Map<String, dynamic>;
    final token = j['fetch_token'];
    if (token is! String || token.isEmpty) {
      // An older relay that ignores ?shared=1 — without a token no member
      // could fetch, so fail here rather than fan out unreadable envelopes.
      throw ApiException('mailbox does not support shared blobs');
    }
    return SharedBlobUpload(j['blob_id'] as String, token);
  } finally {
    client.close();
  }
}

class SharedBlobUpload {
  final String blobId;
  final String fetchToken;
  const SharedBlobUpload(this.blobId, this.fetchToken);
}

/// Drop a blob from *your own* mailbox (owner token). Idempotent mailbox-side;
/// used to reclaim a shared group blob once every member has fetched it.
Future<void> deleteBlob(
  String mailboxAddress,
  String blobId,
  String token,
  String tlsFp,
) async {
  final client = pinnedClient(tlsFp);
  try {
    final r = await client
        .delete(Uri.parse('$mailboxAddress/blob/$blobId?token=$token'))
        .timeout(const Duration(seconds: 20));
    if (r.statusCode >= 400) {
      throw ApiException('blob delete failed (${r.statusCode})', r.statusCode);
    }
  } finally {
    client.close();
  }
}

/// Download a blob: from your own mailbox with the owner token, or from a
/// group sender's mailbox with that blob's fetch token.
Future<List<int>> downloadBlob(
  String mailboxAddress,
  String blobId,
  String token,
  String tlsFp,
) async {
  final client = pinnedClient(tlsFp);
  try {
    final r = await client
        .get(Uri.parse('$mailboxAddress/blob/$blobId?token=$token'))
        .timeout(const Duration(seconds: 60));
    if (r.statusCode >= 400) {
      throw ApiException(
        'blob download failed (${r.statusCode})',
        r.statusCode,
      );
    }
    return r.bodyBytes;
  } finally {
    client.close();
  }
}

/// Delivers a sealed envelope to a peer's mailbox. Throws on failure —
/// callers keep the message in the pending outbox and retry later.
Future<void> deliverEnvelope(
  String mailboxAddress,
  SealedEnvelope envelope,
  String tlsFp,
) async {
  final link = MailboxLink(mailboxAddress, tlsFp);
  try {
    await link.deliver(envelope);
  } finally {
    link.close();
  }
}

/// A pinned connection to one mailbox, held open across several deliveries.
///
/// Worth its own type because of what a delivery actually costs: measured at
/// ~2.6 round trips, of which roughly two are TCP+TLS setup
/// (`scripts/bench_fanout.py`). Paying that once per envelope is fine when a
/// recipient is one envelope — but a recipient's devices all live on **one**
/// mailbox, so a per-device fan-out would otherwise handshake k times to the
/// same host. Reusing the connection across a recipient's devices measured
/// 31% faster at 30ms RTT and 35% at 80ms (`scripts/bench_devices.py`).
///
/// Callers that deliver exactly once should use [deliverEnvelope], which
/// wraps this and closes it.
class MailboxLink {
  final String address;
  final http.Client _client;

  MailboxLink(this.address, String tlsFp) : _client = pinnedClient(tlsFp);

  /// Post one envelope. Returns the mailbox's current `devices_v` when it
  /// reports one, so a sender can notice a device-set change without polling
  /// (MULTIDEVICE.md "Sending: per-device envelopes"). Null from a relay that
  /// predates the device model.
  ///
  /// A 410 means the addressed device is revoked or never existed: permanent
  /// for this copy, not something a retry fixes. It is thrown with the parsed
  /// body as `detail`, so callers can read the `devices_v` that came with it
  /// and re-resolve the recipient's devices.
  Future<int?> deliver(SealedEnvelope envelope) async {
    final r = await _client
        .post(
          Uri.parse('$address/inbox'),
          headers: {'Content-Type': 'application/json'},
          body: jsonEncode(envelope.toJson()),
        )
        .timeout(const Duration(seconds: 10));
    if (r.statusCode >= 400) {
      Object? detail;
      try {
        detail = jsonDecode(r.body);
      } catch (_) {
        detail = null;
      }
      throw ApiException(
        'delivery failed (${r.statusCode})',
        r.statusCode,
        detail,
      );
    }
    try {
      return (jsonDecode(r.body) as Map<String, dynamic>)['devices_v'] as int?;
    } catch (_) {
      return null; // older relay, or a body we don't recognise
    }
  }

  void close() => _client.close();
}

/// The device this envelope was addressed to is gone (revoked, or never
/// minted). Carries the mailbox's current `devices_v` when it sent one.
int? devicesVOf(ApiException e) {
  final detail = e.detail;
  return detail is Map ? detail['devices_v'] as int? : null;
}

/// Persistent WebSocket to *your own* mailbox. Reconnects with backoff and
/// acks every envelope after [onEnvelope] completes (ack ⇒ mailbox deletes it).
class MailboxSocket {
  final String address; // https://host:port
  final String token;
  final String tlsFp; // pinned relay certificate fingerprint
  final Future<void> Function(SealedEnvelope) onEnvelope;
  final void Function(bool connected)? onStateChange;

  WebSocketChannel? _channel;
  bool _closed = false;
  int _retrySeconds = 1;

  MailboxSocket({
    required this.address,
    required this.token,
    required this.tlsFp,
    required this.onEnvelope,
    this.onStateChange,
  });

  void connect() {
    if (_closed) return;
    final wsUrl = '${address.replaceFirst('http', 'ws')}/ws?token=$token';
    try {
      final channel = IOWebSocketChannel.connect(
        Uri.parse(wsUrl),
        customClient: _pinnedHttpClient(tlsFp),
      );
      _channel = channel;
      channel.ready
          .then((_) {
            _retrySeconds = 1;
            onStateChange?.call(true);
          })
          .catchError((_) {});
      channel.stream.listen(
        (raw) async {
          try {
            final envelope = SealedEnvelope.fromJson(
              jsonDecode(raw as String) as Map<String, dynamic>,
            );
            await onEnvelope(envelope);
            channel.sink.add(jsonEncode({'ack': envelope.id}));
          } catch (_) {
            // Undecodable frame — leave it unacked; it will retry on reconnect.
          }
        },
        onDone: _scheduleReconnect,
        onError: (_) => _scheduleReconnect(),
      );
    } catch (_) {
      _scheduleReconnect();
    }
  }

  void _scheduleReconnect() {
    onStateChange?.call(false);
    if (_closed) return;
    Future.delayed(Duration(seconds: _retrySeconds), connect);
    _retrySeconds = (_retrySeconds * 2).clamp(1, 30);
  }

  void close() {
    _closed = true;
    _channel?.sink.close();
    onStateChange?.call(false);
  }
}
