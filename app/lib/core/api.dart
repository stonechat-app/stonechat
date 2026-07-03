/// Network layer: control-plane client, mailbox delivery, mailbox socket.
library;

import 'dart:async';
import 'dart:convert';

import 'package:http/http.dart' as http;
import 'package:web_socket_channel/web_socket_channel.dart';

import '../models.dart';

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

  DirectoryEntry(
      {required this.zeonId,
      this.handle,
      required this.pubkeyB64,
      this.serverAddress});
}

class ServerRecord {
  final String status; // none | provisioning | running | error
  final String? provider;
  final String? address;
  final String? serverToken;
  final String? error;

  ServerRecord(
      {required this.status,
      this.provider,
      this.address,
      this.serverToken,
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
          error: j['error'] as String?,
        ));
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

/// Ask a mailbox who it belongs to (pre-registration sanity check).
Future<String?> mailboxOwner(String address) async {
  try {
    final r = await http
        .get(Uri.parse('$address/health'))
        .timeout(const Duration(seconds: 8));
    if (r.statusCode != 200) return null;
    return (jsonDecode(r.body) as Map<String, dynamic>)['owner'] as String?;
  } catch (_) {
    return null;
  }
}

/// Fetch a peer's prekey bundle from their mailbox (consumes a one-time
/// prekey server-side). The caller must verify the SPK signature against the
/// peer's directory identity key.
Future<Map<String, dynamic>> fetchPrekeyBundle(String serverAddress) async {
  final r = await http
      .get(Uri.parse('$serverAddress/prekeys/bundle'))
      .timeout(const Duration(seconds: 10));
  if (r.statusCode >= 400) {
    throw ApiException('prekey bundle unavailable (${r.statusCode})', r.statusCode);
  }
  return jsonDecode(r.body) as Map<String, dynamic>;
}

/// Publish our public prekeys to our own mailbox (owner token required).
Future<void> uploadPrekeys(String serverAddress, String token,
    Map<String, Object?> spk, List<Map<String, Object?>> opks) async {
  final r = await http
      .post(Uri.parse('$serverAddress/prekeys?token=$token'),
          headers: {'Content-Type': 'application/json'},
          body: jsonEncode({'spk': spk, 'opks': opks}))
      .timeout(const Duration(seconds: 10));
  if (r.statusCode >= 400) {
    throw ApiException('prekey upload failed (${r.statusCode})', r.statusCode);
  }
}

/// Our own mailbox's prekey inventory, from /health (no auth needed).
Future<({bool spk, int opks})?> mailboxPrekeyStatus(String address) async {
  try {
    final r = await http
        .get(Uri.parse('$address/health'))
        .timeout(const Duration(seconds: 8));
    if (r.statusCode != 200) return null;
    final prekeys =
        (jsonDecode(r.body) as Map<String, dynamic>)['prekeys'] as Map<String, dynamic>?;
    if (prekeys == null) return null;
    return (spk: prekeys['spk'] as bool, opks: prekeys['opks'] as int);
  } catch (_) {
    return null;
  }
}

/// Upload an encrypted media blob to a peer's mailbox. Returns the blob id
/// to reference from the media envelope.
Future<String> uploadBlob(String serverAddress, List<int> bytes) async {
  final r = await http
      .post(Uri.parse('$serverAddress/blob'),
          headers: {'Content-Type': 'application/octet-stream'}, body: bytes)
      .timeout(const Duration(seconds: 60));
  if (r.statusCode >= 400) {
    throw ApiException('blob upload failed (${r.statusCode})', r.statusCode);
  }
  return (jsonDecode(r.body) as Map<String, dynamic>)['blob_id'] as String;
}

/// Download a blob from *your own* mailbox (owner token required).
Future<List<int>> downloadBlob(
    String serverAddress, String blobId, String token) async {
  final r = await http
      .get(Uri.parse('$serverAddress/blob/$blobId?token=$token'))
      .timeout(const Duration(seconds: 60));
  if (r.statusCode >= 400) {
    throw ApiException('blob download failed (${r.statusCode})', r.statusCode);
  }
  return r.bodyBytes;
}

/// Delivers an envelope to a peer's routing server. Throws on failure —
/// callers keep the message in the pending outbox and retry later.
Future<void> deliverEnvelope(String serverAddress, Envelope envelope) async {
  final r = await http
      .post(Uri.parse('$serverAddress/inbox'),
          headers: {'Content-Type': 'application/json'},
          body: jsonEncode(envelope.toJson()))
      .timeout(const Duration(seconds: 10));
  if (r.statusCode >= 400) {
    throw ApiException('delivery failed (${r.statusCode})', r.statusCode);
  }
}

/// Persistent WebSocket to *your own* mailbox. Reconnects with backoff and
/// acks every envelope after [onEnvelope] completes (ack ⇒ server deletes it).
class MailboxSocket {
  final String address; // http://host:port
  final String token;
  final Future<void> Function(Envelope) onEnvelope;
  final void Function(bool connected)? onStateChange;

  WebSocketChannel? _channel;
  bool _closed = false;
  int _retrySeconds = 1;

  MailboxSocket({
    required this.address,
    required this.token,
    required this.onEnvelope,
    this.onStateChange,
  });

  void connect() {
    if (_closed) return;
    final wsUrl =
        '${address.replaceFirst('http', 'ws')}/ws?token=$token';
    try {
      final channel = WebSocketChannel.connect(Uri.parse(wsUrl));
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
