/// Your relay: provision/destroy lifecycle + the live mailbox connection.
library;

import 'dart:async';

import 'package:flutter/foundation.dart';

import '../core/api.dart';
import '../models.dart';
import 'app_state.dart';

class ServerState extends ChangeNotifier {
  final AppState app;
  final Future<void> Function(SealedEnvelope) onEnvelope;
  final Future<void> Function() onConnected; // e.g. retry pending outbox
  final void Function(String? address, String? token, String? tlsFp)?
      onMailbox; // own mailbox coordinates, for blob downloads + prekeys
  final void Function(bool ok)?
      onProvisioningDone; // provisioning finished: running (true) or error

  ServerRecord record = ServerRecord(status: 'none');
  bool socketConnected = false;
  bool busy = false;

  MailboxSocket? _socket;
  Timer? _pollTimer;
  String? _vouchedTlsFp; // fingerprint we already signed + published

  ServerState(this.app,
      {required this.onEnvelope,
      required this.onConnected,
      this.onMailbox,
      this.onProvisioningDone});

  bool get isRunning => record.status == 'running';
  bool get isProvisioning => record.status == 'provisioning';

  Future<void> refresh() async {
    final wasProvisioning = isProvisioning;
    try {
      record = await app.api.getServer();
    } on Exception {
      return; // hub unreachable — keep last known state
    }

    if (wasProvisioning && (isRunning || record.status == 'error')) {
      onProvisioningDone?.call(isRunning);
    }

    if (isProvisioning) {
      _pollTimer ??= Timer.periodic(
          const Duration(seconds: 5), (_) => refresh());
    } else {
      _pollTimer?.cancel();
      _pollTimer = null;
    }

    // External relays: the token — and the trust-on-first-use fingerprint —
    // never touched the hub; they come from local secure storage.
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

  /// External mailbox that came from a friend's invite (joinHost) rather
  /// than the user's own server. Locally-stored distinction — the hub sees
  /// both as `external`.
  bool get isFriendHosted => isExternal && app.externalMailboxFriendHosted;

  /// Free tier: user runs their own relay; we verify it's really theirs,
  /// list its address in the directory, and keep the token on-device only.
  /// The TLS fingerprint is trust-on-first-use: this is the user's own box —
  /// they provisioned it seconds ago — so the cert we observe now IS the pin.
  Future<void> connectExternal(String rawAddress, String token,
      {bool friendHosted = false}) async {
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
      await app.setExternalMailbox(token.trim(), probe.tlsFp,
          friendHosted: friendHosted);
      await refresh();
    } finally {
      busy = false;
      notifyListeners();
    }
  }

  /// Guest side of "host your circle": redeem a friend's invite to get a
  /// mailbox on their host, then connect it exactly like a self-hosted relay
  /// (trust-on-first-use pin, owner-verified, token kept on-device).
  Future<void> joinHost(String rawInvite) async {
    final invite = HostInvite.parse(rawInvite); // may throw FormatException
    busy = true;
    notifyListeners();
    ({String address, String serverToken, String tlsFp}) mailbox;
    try {
      mailbox = await redeemHostInvite(invite, app.zeonId!);
    } finally {
      busy = false;
      notifyListeners();
    }
    // connectExternal manages its own busy flag + does the owner check / pin.
    await connectExternal(mailbox.address, mailbox.serverToken,
        friendHosted: true);
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

  /// Manual refresh (pull-to-refresh): tear the socket down and reconnect.
  /// The relay drains its queue to a fresh owner connection, so this is
  /// "check for mail now" — plus a server-record refresh for good measure.
  Future<void> reconnectMailbox() async {
    _dropSocket();
    notifyListeners();
    await refresh();
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
