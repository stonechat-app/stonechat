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
  final String pubkeyB64;
  final String? serverAddress; // null → peer has no running server right now

  DirectoryEntry(
      {required this.zeonId, required this.pubkeyB64, this.serverAddress});
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

  Future<({String zeonId, String accountToken})> register(
      String pubkeyB64) async {
    final r = await http.post(Uri.parse('$baseUrl/v1/register'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({'pubkey': pubkeyB64}));
    return _check(r, (j) => (
          zeonId: j['zeon_id'] as String,
          accountToken: j['account_token'] as String,
        ));
  }

  Future<DirectoryEntry> directory(String zeonId) async {
    final r = await http.get(Uri.parse('$baseUrl/v1/directory/$zeonId'));
    return _check(r, (j) {
      final server = j['server'] as Map<String, dynamic>?;
      return DirectoryEntry(
        zeonId: j['zeon_id'] as String,
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
