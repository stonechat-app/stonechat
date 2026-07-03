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
  final void Function(String? address, String? token, String? tlsFp)?
      onMailbox; // own mailbox coordinates, for blob downloads + prekeys

  ServerRecord record = ServerRecord(status: 'none');
  bool socketConnected = false;
  bool busy = false;

  MailboxSocket? _socket;
  Timer? _pollTimer;
  String? _vouchedTlsFp; // fingerprint we already signed + published

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

    // External relays: the token — and the trust-on-first-use fingerprint —
    // never touched the control plane; they come from local secure storage.
    final token = record.serverToken ?? app.externalMailboxToken;
    final tlsFp = isExternal ? app.externalMailboxTlsFp : record.tlsFp;
    if (isRunning && record.address != null && token != null && tlsFp != null) {
      await _vouchForTls(tlsFp);
      onMailbox?.call(record.address, token, tlsFp);
      _ensureSocket(record.address!, token, tlsFp);
    } else {
      onMailbox?.call(null, null, null);
      _dropSocket();
    }
    notifyListeners();
  }

  /// The owner's half of pinned TLS (PROTOCOL.md "Transport"): sign the
  /// mailbox's certificate fingerprint with the identity key and publish it,
  /// so peers can verify the pin against our Zeon ID. Idempotent per fp;
  /// re-runs automatically when a recreated mailbox shows a new certificate.
  Future<void> _vouchForTls(String tlsFp) async {
    if (_vouchedTlsFp == tlsFp) return;
    try {
      await app.api.publishTlsSig(tlsFp, app.crypto.signTlsFp(tlsFp));
      _vouchedTlsFp = tlsFp;
    } on Exception {
      // best-effort: peers can't reach us until this lands, but the next
      // refresh() retries
    }
  }

  bool get isExternal => record.provider == 'external';

  /// Free tier: user runs their own relay; we verify it's really theirs,
  /// list its address in the directory, and keep the token on-device only.
  /// The TLS fingerprint is trust-on-first-use: this is the user's own box —
  /// they provisioned it seconds ago — so the cert we observe now IS the pin.
  Future<void> connectExternal(String rawAddress, String token) async {
    final address = rawAddress.trim().replaceAll(RegExp(r'/+$'), '');
    busy = true;
    notifyListeners();
    try {
      final probe = await observeMailbox(address);
      if (probe == null) {
        throw ApiException("Couldn't reach a Zeon mailbox at that address");
      }
      if (probe.owner != app.zeonId) {
        throw ApiException('That mailbox belongs to a different Zeon ID');
      }
      await app.api.registerExternalServer(address);
      await app.setExternalMailbox(token.trim(), probe.tlsFp);
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
      await app.setExternalMailbox(null, null);
      _vouchedTlsFp = null;
      _dropSocket();
      await refresh();
    } finally {
      busy = false;
      notifyListeners();
    }
  }

  void _ensureSocket(String address, String token, String tlsFp) {
    if (_socket != null) {
      if (_socket!.tlsFp == tlsFp && _socket!.address == address) return;
      _dropSocket(); // recreated mailbox: new address or new cert
    }
    _socket = MailboxSocket(
      address: address,
      token: token,
      tlsFp: tlsFp,
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
