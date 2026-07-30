/// Your relay: provision/destroy lifecycle + the live mailbox connection.
library;

import 'dart:async';
import 'dart:convert';

import 'package:flutter/foundation.dart';

import '../core/api.dart';
import '../models.dart';
import 'app_state.dart';

/// kv key holding the outage clock across launches (see [ServerState]'s
/// "unplanned outage" section).
const _outageKey = 'mailbox_outage';

/// Coarse, human "how long has this been broken" — minutes below an hour,
/// then hours, then days. Deliberately imprecise: the number is context for
/// a decision ("is this a blip or is my box gone?"), not a measurement.
String formatOutage(Duration d) {
  if (d.inMinutes < 60) return '${d.inMinutes}m';
  if (d.inHours < 48) return '${d.inHours}h';
  return '${d.inDays}d';
}

class ServerState extends ChangeNotifier {
  final AppState app;
  final Future<void> Function(SealedEnvelope) onEnvelope;
  final Future<void> Function() onConnected; // e.g. retry pending outbox
  final void Function(String? address, String? token, String? tlsFp)?
      onMailbox; // own mailbox coordinates, for blob downloads + prekeys
  final void Function(bool ok)?
      onProvisioningDone; // provisioning finished: running (true) or error

  /// The mailbox has been unreachable-though-not-turned-off for long enough
  /// to be worth interrupting the user about. Fires once per outage.
  final void Function(Duration down)? onOutage;

  ServerRecord record = ServerRecord(status: 'none');
  bool socketConnected = false;
  bool busy = false;

  MailboxSocket? _socket;
  Timer? _pollTimer;
  Timer? _unreachableTimer;
  DateTime? _downSince; // socket down continuously since — null when up
  String? _vouchedTlsFp; // fingerprint we already signed + published

  DateTime? _outageSince; // confirmed unplanned outage began — persisted
  bool _outageNotified = false; // notice already posted for THIS outage

  /// How long the socket must stay down before we stop calling it a blip.
  /// The socket's own backoff caps at 30s, so by now we've failed ~5 attempts.
  static const _unreachableAfter = Duration(seconds: 30);

  /// How long a confirmed outage must last before we interrupt the user. A
  /// rebooting VM or a provider migration is back inside a few minutes;
  /// hours means something is actually wrong and nobody but the owner can
  /// fix it — we deliberately never restart a mailbox on their behalf.
  static const outageNoticeAfter = Duration(hours: 2);

  ServerState(this.app,
      {required this.onEnvelope,
      required this.onConnected,
      this.onMailbox,
      this.onProvisioningDone,
      this.onOutage});

  bool get isRunning => record.status == 'running';
  bool get isProvisioning => record.status == 'provisioning';

  /// The mailbox is gone, whatever the hub thinks. The hub writes `external`
  /// records as `running` once at registration and never re-checks them, so a
  /// destroyed host box leaves `record.status` saying `running` forever — the
  /// socket is the only liveness signal we actually have. Distinct from
  /// `!socketConnected`, which is also true for an ordinary two-second blip.
  bool get mailboxUnreachable {
    final since = _downSince;
    if (since == null || _socket == null) return false;
    return DateTime.now().difference(since) >= _unreachableAfter;
  }

  // -- unplanned outage -------------------------------------------------------
  //
  // "Turned off" and "died" must never be confused: turning a mailbox off
  // deletes the hub row (DELETE /v1/server), so `record.status` drops to
  // 'none' and nothing below ever arms. An outage is therefore, by
  // construction, something the user did NOT ask for.
  //
  // We only ever *tell* them. Nothing here restarts or re-provisions a
  // mailbox — for a product whose whole promise is that the user owns the
  // one server their messages touch, quietly resurrecting a box they may
  // have destroyed themselves (in their own cloud console, out of band)
  // would break the promise far worse than an outage does.

  /// How long the mailbox has been confirmed down, or null when it's fine.
  /// Survives backgrounding and app restarts — unlike [mailboxUnreachable],
  /// whose 30s clock resets every time we drop the socket on the way out.
  Duration? get mailboxDownFor {
    final since = _outageSince;
    return since == null ? null : DateTime.now().difference(since);
  }

  /// Restore the outage clock from a previous launch. Call once at startup,
  /// before [refresh].
  Future<void> loadOutage() async {
    try {
      final raw = await app.db.kvGet(_outageKey);
      if (raw == null) return;
      final j = jsonDecode(utf8.decode(raw)) as Map<String, dynamic>;
      final since = j['since'] as int?;
      _outageSince =
          since == null ? null : DateTime.fromMillisecondsSinceEpoch(since);
      _outageNotified = j['notified'] as bool? ?? false;
    } catch (_) {
      // Unreadable clock is not worth failing a launch over — worst case we
      // re-detect the outage and re-notify once.
    }
  }

  Future<void> _persistOutage() async {
    try {
      final since = _outageSince;
      await app.db.kvPut(
        _outageKey,
        since == null
            ? null
            : Uint8List.fromList(utf8.encode(jsonEncode({
                'since': since.millisecondsSinceEpoch,
                'notified': _outageNotified,
              }))),
      );
    } catch (_) {
      // best-effort; the in-memory clock still works for this session
    }
  }

  /// A dead socket alone can't tell "my mailbox is down" from "my phone has
  /// no network" — both look identical from here. The hub is the oracle: if
  /// it answers, our network is fine, so the silence is the mailbox's. Only
  /// then does the outage clock start.
  Future<void> _confirmOutage() async {
    if (!isRunning || _socket == null || socketConnected) return;
    if (_outageSince != null) return; // already counting
    try {
      final probe = await app.api.getServer();
      // Turned off elsewhere, or rebuilt — either way not an outage.
      if (probe.status != 'running') return;
    } on Exception {
      return; // hub unreachable too: most likely we are the offline party
    }
    if (socketConnected || _socket == null) return; // recovered mid-probe
    _outageSince = DateTime.now();
    await _persistOutage();
    notifyListeners();
  }

  /// Post the one-shot notice once the outage has run long enough. Re-arms
  /// only after an actual recovery, so a long outage interrupts once, not
  /// on every foreground.
  Future<void> _maybeAnnounceOutage() async {
    final down = mailboxDownFor;
    if (down == null || _outageNotified || down < outageNoticeAfter) return;
    _outageNotified = true;
    await _persistOutage();
    onOutage?.call(down);
  }

  Future<void> _clearOutage() async {
    if (_outageSince == null && !_outageNotified) return;
    _outageSince = null;
    _outageNotified = false;
    await _persistOutage();
  }

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
      // Whatever the socket is doing, a persisted outage may have crossed
      // the notice threshold while the app was away.
      await _maybeAnnounceOutage();
    } else {
      // No running record = nothing to be down. Turning the mailbox off is
      // the main way here, and it must never read as an outage.
      await _clearOutage();
      onMailbox?.call(null, null, null);
      _dropSocket();
    }
    notifyListeners();
  }

  /// The owner's half of pinned TLS (PROTOCOL.md "Transport"): sign the
  /// mailbox's certificate fingerprint with the identity key and publish it,
  /// so peers can verify the pin against our Stonechat ID. Idempotent per fp;
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
      final probe = await observeMailbox(address, app.stonechatId!);
      if (probe == null) {
        throw ApiException("Couldn't reach a Stonechat mailbox at that address");
      }
      if (!probe.ownerMatches) {
        throw ApiException('That mailbox belongs to a different Stonechat ID');
      }
      await app.api.registerExternalServer(address);
      await app.setExternalMailbox(token.trim(), probe.tlsFp,
          friendHosted: friendHosted);
      await _clearOutage(); // different mailbox — the old clock is meaningless
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
      mailbox = await redeemHostInvite(invite, app.stonechatId!);
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
      await _clearOutage(); // different mailbox — the old clock is meaningless
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
      // Deliberate: from here on, silence from this address is expected.
      await _clearOutage();
      _dropSocket();
      await refresh();
    } finally {
      busy = false;
      notifyListeners();
    }
  }

  /// Identity reset: the record, socket, TLS vouch and any provisioning poll
  /// all belonged to the identity that just died. Without this, a re-onboard
  /// in the same app session inherits a ghost "running" mailbox and skips
  /// mailbox setup entirely.
  void reset() {
    _pollTimer?.cancel();
    _pollTimer = null;
    _dropSocket();
    unawaited(_clearOutage());
    record = ServerRecord(status: 'none');
    _vouchedTlsFp = null;
    busy = false;
    onMailbox?.call(null, null, null);
    notifyListeners();
  }

  /// App went to background: close the socket now, while we still have a
  /// moment of runtime, so the relay sees a clean disconnect. A suspended
  /// app keeps its TCP connection open but never reads it — the relay's
  /// live delivery "succeeds" and nothing wakes the phone.
  void onBackground() {
    _dropSocket();
    notifyListeners();
  }

  /// Back in the foreground: reconnect from the coordinates we already
  /// hold. refresh() alone isn't enough — it bails early when the hub is
  /// unreachable, and the mailbox doesn't need the hub to be up.
  void onForeground() {
    final token = record.serverToken ?? app.externalMailboxToken;
    final tlsFp = isExternal ? app.externalMailboxTlsFp : record.tlsFp;
    if (isRunning && record.address != null && token != null && tlsFp != null) {
      _ensureSocket(record.address!, token, tlsFp);
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
        _noteSocketState(connected);
        notifyListeners();
        if (connected && !wasConnected) {
          onConnected();
        }
      },
    )..connect();
  }

  /// Track how long the socket has been down. The socket retries silently on
  /// its own backoff, so without the timer nothing would notify listeners at
  /// the moment "Reconnecting…" becomes "Unreachable".
  void _noteSocketState(bool connected) {
    if (connected) {
      _downSince = null;
      _unreachableTimer?.cancel();
      _unreachableTimer = null;
      unawaited(_clearOutage()); // recovered: stop counting, re-arm the notice
    } else {
      _downSince ??= DateTime.now();
      _unreachableTimer ??= Timer(_unreachableAfter, () {
        _unreachableTimer = null;
        notifyListeners();
        // Past a blip now — ask the hub whether this is us or the mailbox.
        unawaited(_confirmOutage().then((_) => _maybeAnnounceOutage()));
      });
    }
  }

  /// Deliberate teardown (background, destroy, reset, re-pin): close first —
  /// close() reports disconnected, which would otherwise start an unreachable
  /// countdown for a socket we chose to drop — then clear the tracking.
  void _dropSocket() {
    _socket?.close();
    _socket = null;
    socketConnected = false;
    _downSince = null;
    _unreachableTimer?.cancel();
    _unreachableTimer = null;
  }

  @override
  void dispose() {
    _pollTimer?.cancel();
    _unreachableTimer?.cancel();
    _dropSocket();
    super.dispose();
  }
}
