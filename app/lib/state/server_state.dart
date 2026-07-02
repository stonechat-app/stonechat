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

  ServerRecord record = ServerRecord(status: 'none');
  bool socketConnected = false;
  bool busy = false;

  MailboxSocket? _socket;
  Timer? _pollTimer;

  ServerState(this.app, {required this.onEnvelope, required this.onConnected});

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

    if (isRunning && record.address != null && record.serverToken != null) {
      _ensureSocket(record.address!, record.serverToken!);
    } else {
      _dropSocket();
    }
    notifyListeners();
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
