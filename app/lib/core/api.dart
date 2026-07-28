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

/// Set once at startup (needs libsodium): BLAKE2b-256 of a DER certificate.
String Function(Uint8List der)? certFingerprinter;

HttpClient _pinnedHttpClient(String expectedFpB64) => HttpClient()
  ..badCertificateCallback = (X509Certificate cert, _, _) =>
      certFingerprinter!(Uint8List.fromList(cert.der)) == expectedFpB64;

/// An HTTP client that accepts exactly one server certificate: the one whose
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
    String address, String expectedStonechatId) async {
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
        .get(Uri.parse('$address/owner')
            .replace(queryParameters: {'stonechat_id': expectedStonechatId}))
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
  final Object? detail; // parsed JSON `detail` when the server sent one

  ApiException(this.message, [this.status, this.detail]);

  /// Machine-readable error code (e.g. 'subscription_required'), when the
  /// hub sent a structured detail.
  String? get code =>
      detail is Map ? (detail as Map)['code'] as String? : null;

  @override
  String toString() => message;
}

class DirectoryEntry {
  final String stonechatId;
  final String pubkeyB64;
  final String? pqPkB64; // X-Wing identity key (hybrid envelope seal)…
  final String? pqSigB64; // …signed by the Ed25519 identity key
  final String? serverAddress; // null → peer's mailbox is off right now
  final String? serverTlsFp; // pinned cert fingerprint…
  final String? serverTlsSig; // …vouched for by the owner's identity key

  DirectoryEntry(
      {required this.stonechatId,
      required this.pubkeyB64,
      this.pqPkB64,
      this.pqSigB64,
      this.serverAddress,
      this.serverTlsFp,
      this.serverTlsSig});
}

class ServerRecord {
  final String status; // none | provisioning | running | error
  final String? provider;
  final String? address;
  final String? serverToken;
  final String? tlsFp; // observed by the hub at provision time
  final String? error;
  // Dedicated (Sovereign) VMs ship with the host agent pre-installed; the hub
  // hands back where it lives and the admin token it was minted with, so the
  // Invites screen connects without any manual setup.
  final String? hostAgentAddress;
  final String? hostAgentAdminToken;

  ServerRecord(
      {required this.status,
      this.provider,
      this.address,
      this.serverToken,
      this.tlsFp,
      this.error,
      this.hostAgentAddress,
      this.hostAgentAdminToken});
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
      String pubkeyB64, String pqPkB64, String pqSigB64) async {
    final r = await http.post(Uri.parse('$baseUrl/v1/register'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode(
            {'pubkey': pubkeyB64, 'pq_pk': pqPkB64, 'pq_sig': pqSigB64}));
    return _check(r, (j) => (
          stonechatId: j['stonechat_id'] as String,
          accountToken: j['account_token'] as String,
        ));
  }

  /// Identity restore: trade a proof of key possession (CryptoService
  /// .signRecovery) for a fresh account token. 404 means the hub has never
  /// seen this key — the caller falls back to register().
  Future<({String stonechatId, String accountToken})> recover({
    required String pubkeyB64,
    required int timestamp,
    required String signatureB64,
  }) async {
    final r = await http.post(Uri.parse('$baseUrl/v1/recover'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({
          'pubkey': pubkeyB64,
          'timestamp': timestamp,
          'signature': signatureB64,
        }));
    return _check(r, (j) => (
          stonechatId: j['stonechat_id'] as String,
          accountToken: j['account_token'] as String,
        ));
  }

  /// Resolves a full SC- Stonechat ID to its directory record. Lookup is by ID
  /// only — there are no handles. [hubUrl] asks a different hub's directory
  /// (cross-hub): the answer is verified by the caller exactly like one from
  /// our own hub, so the foreign hub is trusted for availability only.
  Future<DirectoryEntry> directory(String stonechatId, {String? hubUrl}) async {
    final r =
        await http.get(Uri.parse('${hubUrl ?? baseUrl}/v1/directory/$stonechatId'));
    return _check(r, (j) {
      final server = j['server'] as Map<String, dynamic>?;
      return DirectoryEntry(
        stonechatId: j['stonechat_id'] as String,
        pubkeyB64: j['pubkey'] as String,
        pqPkB64: j['pq_pk'] as String?,
        pqSigB64: j['pq_sig'] as String?,
        serverAddress: server?['address'] as String?,
        serverTlsFp: server?['tls_fp'] as String?,
        serverTlsSig: server?['tls_sig'] as String?,
      );
    });
  }

  Future<void> createServer({
    required String provider,
    required String machineType,
    required String region,
    int diskGb = 10,
  }) async {
    final r = await http.post(Uri.parse('$baseUrl/v1/server'),
        headers: _auth,
        body: jsonEncode({
          'provider': provider,
          'machine': {
            'machine_type': machineType,
            'region': region,
            'disk_gb': diskGb,
          },
        }));
    await _check(r, (_) => null);
  }

  Future<ServerRecord> getServer() async {
    final r = await http.get(Uri.parse('$baseUrl/v1/server'), headers: _auth);
    return _check(r, (j) {
      final hostAgent = j['host_agent'] as Map<String, dynamic>?;
      return ServerRecord(
        status: j['status'] as String,
        provider: j['provider'] as String?,
        address: j['address'] as String?,
        serverToken: j['server_token'] as String?,
        tlsFp: j['tls_fp'] as String?,
        error: j['error'] as String?,
        hostAgentAddress: hostAgent?['address'] as String?,
        hostAgentAdminToken: hostAgent?['admin_token'] as String?,
      );
    });
  }

  /// Owner vouches for their mailbox's TLS key: publish the identity-key
  /// signature over its fingerprint so peers can pin it via the directory.
  Future<void> publishTlsSig(String tlsFp, String tlsSig) async {
    final r = await http.post(Uri.parse('$baseUrl/v1/server/tls'),
        headers: _auth,
        body: jsonEncode({'tls_fp': tlsFp, 'tls_sig': tlsSig}));
    await _check(r, (_) => null);
  }

  Future<void> deleteServer() async {
    final r =
        await http.delete(Uri.parse('$baseUrl/v1/server'), headers: _auth);
    await _check(r, (_) => null);
  }

  /// Free tier: list a self-provisioned relay in the directory. The relay's
  /// token never goes to the hub — only the address does.
  Future<void> registerExternalServer(String address) async {
    final r = await http.post(Uri.parse('$baseUrl/v1/server/external'),
        headers: _auth, body: jsonEncode({'address': address}));
    await _check(r, (_) => null);
  }

  /// The account's live plan, or null (PROTOCOL.md "Billing").
  Future<({String plan, String status, String? currentPeriodEnd})?>
      getEntitlement() async {
    final r = await http.get(Uri.parse('$baseUrl/v1/billing/entitlement'),
        headers: _auth);
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
    final r = await http.post(Uri.parse('$baseUrl/v1/billing/redeem'),
        headers: _auth, body: jsonEncode({'code': code}));
    return _check(r, (j) => (
          plan: j['plan'] as String,
          status: j['status'] as String,
        ));
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
      .post(Uri.parse('$hubUrl/v1/report'),
          headers: {'Content-Type': 'application/json'},
          body: jsonEncode({
            'reported_id': reportedId,
            'reporter_pubkey': reporterPubkeyB64,
            'timestamp': timestamp,
            'category': category,
            'note': note,
            'evidence': evidence,
            'signature': signatureB64,
          }))
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

/// Fetch a peer's prekey bundle from their mailbox (consumes a one-time
/// prekey server-side). The caller must verify the SPK signature against the
/// peer's directory identity key.
Future<Map<String, dynamic>> fetchPrekeyBundle(
    String serverAddress, String tlsFp) async {
  final client = pinnedClient(tlsFp);
  try {
    final r = await client
        .get(Uri.parse('$serverAddress/prekeys/bundle'))
        .timeout(const Duration(seconds: 10));
    if (r.statusCode >= 400) {
      throw ApiException('prekey bundle unavailable (${r.statusCode})', r.statusCode);
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
    String serverAddress,
    String token,
    String tlsFp,
    Map<String, Object?> spk,
    List<Map<String, Object?>> opks,
    Map<String, Object?> kspk,
    List<Map<String, Object?>> kopks) async {
  final client = pinnedClient(tlsFp);
  try {
    final r = await client
        .post(Uri.parse('$serverAddress/prekeys?token=$token'),
            headers: {'Content-Type': 'application/json'},
            body: jsonEncode(
                {'spk': spk, 'opks': opks, 'kspk': kspk, 'kopks': kopks}))
        .timeout(const Duration(seconds: 10));
    if (r.statusCode >= 400) {
      throw ApiException('prekey upload failed (${r.statusCode})', r.statusCode);
    }
  } finally {
    client.close();
  }
}

/// Our own mailbox's prekey inventory, from the owner-authenticated /status.
Future<({bool spk, int opks, bool kspk, int kopks})?> mailboxPrekeyStatus(
    String address, String tlsFp, String token) async {
  final client = pinnedClient(tlsFp);
  try {
    final r = await client
        .get(Uri.parse('$address/status')
            .replace(queryParameters: {'token': token}))
        .timeout(const Duration(seconds: 8));
    if (r.statusCode != 200) return null;
    final prekeys =
        (jsonDecode(r.body) as Map<String, dynamic>)['prekeys'] as Map<String, dynamic>?;
    if (prekeys == null) return null;
    return (
      spk: prekeys['spk'] as bool,
      opks: prekeys['opks'] as int,
      kspk: prekeys['kspk'] as bool? ?? false,
      kopks: prekeys['kopks'] as int? ?? 0,
    );
  } catch (_) {
    return null;
  } finally {
    client.close();
  }
}

// -- invite-hosted mailboxes ("host your circle") -----------------------------

/// A parsed host invite: where the host agent is, its pinned fingerprint, and the
/// one-time token. Encoded as "stonechat-host:" + urlsafe-base64(JSON{u,f,t}).
class HostInvite {
  final String url; // host agent base URL (https)
  final String fp; // host agent TLS fingerprint to pin
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
    final j = jsonDecode(utf8.decode(base64Url.decode(b64))) as Map<String, dynamic>;
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
/// host agent fingerprint carried in the invite (no CA, no MITM).
Future<({String address, String serverToken, String tlsFp})> redeemHostInvite(
    HostInvite invite, String ownerId) async {
  final client = pinnedClient(invite.fp);
  try {
    final r = await client
        .post(Uri.parse('${invite.url}/v1/redeem'),
            headers: {'Content-Type': 'application/json'},
            body: jsonEncode({'invite': invite.token, 'owner_id': ownerId}))
        .timeout(const Duration(seconds: 90));
    if (r.statusCode >= 400) throw ApiException(_detail(r), r.statusCode);
    final j = jsonDecode(r.body) as Map<String, dynamic>;
    return (
      address: j['address'] as String,
      serverToken: j['server_token'] as String,
      tlsFp: j['tls_fp'] as String,
    );
  } finally {
    client.close();
  }
}

/// Observe a host agent's TLS fingerprint (trust-on-first-use). Used by the
/// host-owner contacting their OWN host agent to mint invites.
Future<String?> observeCertFingerprint(String url) async {
  String? seen;
  final client = HttpClient()
    ..badCertificateCallback = (cert, _, _) {
      seen = certFingerprinter!(Uint8List.fromList(cert.der));
      return true;
    };
  try {
    final r = await IOClient(client)
        .get(Uri.parse('$url/health'))
        .timeout(const Duration(seconds: 8));
    return r.statusCode == 200 ? seen : null;
  } catch (_) {
    return null;
  } finally {
    client.close();
  }
}

/// Host-owner mints an invite through their host agent's admin API (pinned).
Future<String> createHostInvite(
    String agentUrl, String agentFp, String adminToken,
    {int uses = 1, int ttlHours = 72}) async {
  final client = pinnedClient(agentFp);
  try {
    final r = await client
        .post(Uri.parse('$agentUrl/v1/invite'),
            headers: {
              'Content-Type': 'application/json',
              'Authorization': 'Bearer $adminToken',
            },
            body: jsonEncode({'uses': uses, 'ttl_hours': ttlHours}))
        .timeout(const Duration(seconds: 10));
    if (r.statusCode >= 400) throw ApiException(_detail(r), r.statusCode);
    return (jsonDecode(r.body) as Map<String, dynamic>)['invite'] as String;
  } finally {
    client.close();
  }
}

/// One minted invite as the host agent reports it: the shareable string plus
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
    String agentUrl, String agentFp, String adminToken) async {
  final client = pinnedClient(agentFp);
  try {
    final r = await client.get(Uri.parse('$agentUrl/v1/invites'), headers: {
      'Authorization': 'Bearer $adminToken',
    }).timeout(const Duration(seconds: 10));
    if (r.statusCode >= 400) throw ApiException(_detail(r), r.statusCode);
    final j = jsonDecode(r.body) as Map<String, dynamic>;
    return [
      for (final e in (j['invites'] as List).cast<Map<String, dynamic>>())
        HostInviteStatus(
          invite: e['invite'] as String,
          uses: e['uses'] as int,
          usesLeft: e['uses_left'] as int,
          expiresAt: DateTime.fromMillisecondsSinceEpoch(
              ((e['expires_at'] as num) * 1000).round()),
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
        String serverAddress, String ownerToken, String tlsFp) async {
  final client = pinnedClient(tlsFp);
  try {
    final r = await client
        .get(Uri.parse('$serverAddress/turn-credentials?token=$ownerToken'))
        .timeout(const Duration(seconds: 8));
    if (r.statusCode == 404) return null;
    if (r.statusCode >= 400) {
      throw ApiException('turn credentials failed (${r.statusCode})', r.statusCode);
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
Future<void> setPushConfig(String serverAddress, String ownerToken,
    String deviceToken, String platform, String tlsFp) async {
  final client = pinnedClient(tlsFp);
  try {
    final r = await client
        .post(Uri.parse('$serverAddress/push-config?token=$ownerToken'),
            headers: {'Content-Type': 'application/json'},
            body: jsonEncode({'device_token': deviceToken, 'platform': platform}))
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
    String serverAddress, List<int> bytes, String tlsFp) async {
  final client = pinnedClient(tlsFp);
  try {
    final r = await client
        .post(Uri.parse('$serverAddress/blob'),
            headers: {'Content-Type': 'application/octet-stream'}, body: bytes)
        .timeout(const Duration(seconds: 60));
    if (r.statusCode >= 400) {
      throw ApiException('blob upload failed (${r.statusCode})', r.statusCode);
    }
    return (jsonDecode(r.body) as Map<String, dynamic>)['blob_id'] as String;
  } finally {
    client.close();
  }
}

/// Download a blob from *your own* mailbox (owner token required).
Future<List<int>> downloadBlob(
    String serverAddress, String blobId, String token, String tlsFp) async {
  final client = pinnedClient(tlsFp);
  try {
    final r = await client
        .get(Uri.parse('$serverAddress/blob/$blobId?token=$token'))
        .timeout(const Duration(seconds: 60));
    if (r.statusCode >= 400) {
      throw ApiException('blob download failed (${r.statusCode})', r.statusCode);
    }
    return r.bodyBytes;
  } finally {
    client.close();
  }
}

/// Delivers a sealed envelope to a peer's routing server. Throws on failure —
/// callers keep the message in the pending outbox and retry later.
Future<void> deliverEnvelope(
    String serverAddress, SealedEnvelope envelope, String tlsFp) async {
  final client = pinnedClient(tlsFp);
  try {
    final r = await client
        .post(Uri.parse('$serverAddress/inbox'),
            headers: {'Content-Type': 'application/json'},
            body: jsonEncode(envelope.toJson()))
        .timeout(const Duration(seconds: 10));
    if (r.statusCode >= 400) {
      throw ApiException('delivery failed (${r.statusCode})', r.statusCode);
    }
  } finally {
    client.close();
  }
}

/// Persistent WebSocket to *your own* mailbox. Reconnects with backoff and
/// acks every envelope after [onEnvelope] completes (ack ⇒ server deletes it).
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
    final wsUrl =
        '${address.replaceFirst('http', 'ws')}/ws?token=$token';
    try {
      final channel = IOWebSocketChannel.connect(
        Uri.parse(wsUrl),
        customClient: _pinnedHttpClient(tlsFp),
      );
      _channel = channel;
      channel.ready.then((_) {
        _retrySeconds = 1;
        onStateChange?.call(true);
      }).catchError((_) {});
      channel.stream.listen(
        (raw) async {
          try {
            final envelope = SealedEnvelope.fromJson(
                jsonDecode(raw as String) as Map<String, dynamic>);
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
