/// Your relay: provision/destroy lifecycle + the live mailbox connection.
library;

import 'dart:async';

import 'package:flutter/foundation.dart';

import '../core/api.dart';
import '../models.dart';
import 'app_state.dart';

class ServerState extends ChangeNotifier {
  final AppState app;
  final Future<void> Function(Envelope) onEnvelope;
  final Future<void> Function() onConnected; // e.g. retry pending outbox
  final void Function(String? address, String? token)?
      onMailbox; // own mailbox coordinates, for blob downloads

  ServerRecord record = ServerRecord(status: 'none');
  bool socketConnected = false;
  bool busy = false;

  MailboxSocket? _socket;
  Timer? _pollTimer;

  ServerState(this.app,
      {required this.onEnvelope, required this.onConnected, this.onMailbox});

  bool get isRunning => record.status == 'running';
  bool get isProvisioning => record.status == 'provisioning';

  Future<void> refresh() async {
    try {
      record = await app.api.getServer();
    } on Exception {
      return; // control plane unreachable — keep last known state
    }

    if (isProvisioning) {
      _pollTimer ??= Timer.periodic(
          const Duration(seconds: 5), (_) => refresh());
    } else {
      _pollTimer?.cancel();
      _pollTimer = null;
    }

    // External relays: the token never touched the control plane, so it
    // comes from local secure storage instead of the server record.
    final token = record.serverToken ?? app.externalMailboxToken;
    if (isRunning && record.address != null && token != null) {
      onMailbox?.call(record.address, token);
      _ensureSocket(record.address!, token);
    } else {
      onMailbox?.call(null, null);
      _dropSocket();
    }
    notifyListeners();
  }

  bool get isExternal => record.provider == 'external';

  /// Free tier: user runs their own relay; we verify it's really theirs,
  /// list its address in the directory, and keep the token on-device only.
  Future<void> connectExternal(String rawAddress, String token) async {
    final address = rawAddress.trim().replaceAll(RegExp(r'/+$'), '');
    busy = true;
    notifyListeners();
    try {
      final owner = await mailboxOwner(address);
      if (owner == null) {
        throw ApiException("Couldn't reach a Zeon mailbox at that address");
      }
      if (owner != app.zeonId) {
        throw ApiException('That mailbox belongs to a different Zeon ID');
      }
      await app.api.registerExternalServer(address);
      await app.setExternalMailboxToken(token.trim());
      await refresh();
    } finally {
      busy = false;
      notifyListeners();
    }
  }

  Future<void> create({
    required String provider,
    required String machineType,
    required String region,
    int diskGb = 10,
  }) async {
    busy = true;
    notifyListeners();
    try {
      await app.api.createServer(
        provider: provider,
        machineType: machineType,
        region: region,
        diskGb: diskGb,
      );
      await refresh();
    } finally {
      busy = false;
      notifyListeners();
    }
  }

  Future<void> destroy() async {
    busy = true;
    notifyListeners();
    try {
      await app.api.deleteServer();
      await app.setExternalMailboxToken(null);
      _dropSocket();
      await refresh();
    } finally {
      busy = false;
      notifyListeners();
    }
  }

  void _ensureSocket(String address, String token) {
    if (_socket != null) return;
    _socket = MailboxSocket(
      address: address,
      token: token,
      onEnvelope: onEnvelope,
      onStateChange: (connected) {
        final wasConnected = socketConnected;
        socketConnected = connected;
        notifyListeners();
        if (connected && !wasConnected) {
          onConnected();
        }
      },
    )..connect();
  }

  void _dropSocket() {
    _socket?.close();
    _socket = null;
    socketConnected = false;
  }

  @override
  void dispose() {
    _pollTimer?.cancel();
    _dropSocket();
    super.dispose();
  }
}
