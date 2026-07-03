/// Network layer: control-plane client, mailbox delivery, mailbox socket.
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
/// observe the certificate, report owner + fingerprint. Used only to
/// bootstrap self-hosted mailboxes — never for peers.
Future<({String owner, String tlsFp})?> observeMailbox(String address) async {
  String? seenFp;
  final client = HttpClient()
    ..badCertificateCallback = (cert, _, _) {
      seenFp = certFingerprinter!(Uint8List.fromList(cert.der));
      return true;
    };
  try {
    final r = await IOClient(client)
        .get(Uri.parse('$address/health'))
        .timeout(const Duration(seconds: 8));
    if (r.statusCode != 200 || seenFp == null) return null;
    final owner =
        (jsonDecode(r.body) as Map<String, dynamic>)['owner'] as String?;
    return owner == null ? null : (owner: owner, tlsFp: seenFp!);
  } catch (_) {
    return null;
  } finally {
    client.close();
  }
}

class ApiException implements Exception {
  final String message;
  final int? status;
  ApiException(this.message, [this.status]);
  @override
  String toString() => message;
}

class DirectoryEntry {
  final String zeonId;
  final String? handle;
  final String pubkeyB64;
  final String? serverAddress; // null → peer's mailbox is off right now
  final String? serverTlsFp; // pinned cert fingerprint…
  final String? serverTlsSig; // …vouched for by the owner's identity key

  DirectoryEntry(
      {required this.zeonId,
      this.handle,
      required this.pubkeyB64,
      this.serverAddress,
      this.serverTlsFp,
      this.serverTlsSig});
}

class ServerRecord {
  final String status; // none | provisioning | running | error
  final String? provider;
  final String? address;
  final String? serverToken;
  final String? tlsFp; // observed by the control plane at provision time
  final String? error;

  ServerRecord(
      {required this.status,
      this.provider,
      this.address,
      this.serverToken,
      this.tlsFp,
      this.error});
}

/// Talks to the provisioner + directory. Holds the account bearer token.
class ControlPlaneApi {
  String baseUrl;
  String? accountToken;

  ControlPlaneApi({required this.baseUrl, this.accountToken});

  Map<String, String> get _auth => {
        if (accountToken != null) 'Authorization': 'Bearer $accountToken',
        'Content-Type': 'application/json',
      };

  Future<T> _check<T>(http.Response r, T Function(Map<String, dynamic>) parse) {
    final body = r.body.isEmpty ? <String, dynamic>{} : jsonDecode(r.body);
    if (r.statusCode >= 400) {
      final detail =
          body is Map && body['detail'] != null ? '${body['detail']}' : r.body;
      throw ApiException(detail, r.statusCode);
    }
    return Future.value(parse(body as Map<String, dynamic>));
  }

  Future<({String zeonId, String handle, String accountToken})> register(
      String pubkeyB64) async {
    final r = await http.post(Uri.parse('$baseUrl/v1/register'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({'pubkey': pubkeyB64}));
    return _check(r, (j) => (
          zeonId: j['zeon_id'] as String,
          handle: j['handle'] as String,
          accountToken: j['account_token'] as String,
        ));
  }

  /// Accepts either form: full ZC- ID or zn-word-word-word handle.
  Future<DirectoryEntry> directory(String idOrHandle) async {
    final r = await http.get(Uri.parse('$baseUrl/v1/directory/$idOrHandle'));
    return _check(r, (j) {
      final server = j['server'] as Map<String, dynamic>?;
      return DirectoryEntry(
        zeonId: j['zeon_id'] as String,
        handle: j['handle'] as String?,
        pubkeyB64: j['pubkey'] as String,
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
    return _check(r, (j) => ServerRecord(
          status: j['status'] as String,
          provider: j['provider'] as String?,
          address: j['address'] as String?,
          serverToken: j['server_token'] as String?,
          tlsFp: j['tls_fp'] as String?,
          error: j['error'] as String?,
        ));
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
  /// token never goes to the control plane — only the address does.
  Future<void> registerExternalServer(String address) async {
    final r = await http.post(Uri.parse('$baseUrl/v1/server/external'),
        headers: _auth, body: jsonEncode({'address': address}));
    await _check(r, (_) => null);
  }
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
Future<void> uploadPrekeys(String serverAddress, String token, String tlsFp,
    Map<String, Object?> spk, List<Map<String, Object?>> opks) async {
  final client = pinnedClient(tlsFp);
  try {
    final r = await client
        .post(Uri.parse('$serverAddress/prekeys?token=$token'),
            headers: {'Content-Type': 'application/json'},
            body: jsonEncode({'spk': spk, 'opks': opks}))
        .timeout(const Duration(seconds: 10));
    if (r.statusCode >= 400) {
      throw ApiException('prekey upload failed (${r.statusCode})', r.statusCode);
    }
  } finally {
    client.close();
  }
}

/// Our own mailbox's prekey inventory, from /health (no auth needed).
Future<({bool spk, int opks})?> mailboxPrekeyStatus(
    String address, String tlsFp) async {
  final client = pinnedClient(tlsFp);
  try {
    final r = await client
        .get(Uri.parse('$address/health'))
        .timeout(const Duration(seconds: 8));
    if (r.statusCode != 200) return null;
    final prekeys =
        (jsonDecode(r.body) as Map<String, dynamic>)['prekeys'] as Map<String, dynamic>?;
    if (prekeys == null) return null;
    return (spk: prekeys['spk'] as bool, opks: prekeys['opks'] as int);
  } catch (_) {
    return null;
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

/// Delivers an envelope to a peer's routing server. Throws on failure —
/// callers keep the message in the pending outbox and retry later.
Future<void> deliverEnvelope(
    String serverAddress, Envelope envelope, String tlsFp) async {
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
  final Future<void> Function(Envelope) onEnvelope;
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
            final envelope =
                Envelope.fromJson(jsonDecode(raw as String) as Map<String, dynamic>);
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
