/// Contacts + messages. Encrypts on the way out, decrypts on the way in,
/// persists everything locally, keeps a pending outbox for unreachable peers.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter/widgets.dart';
import 'package:path/path.dart' as p;
import 'package:path_provider/path_provider.dart';
import 'package:uuid/uuid.dart';

import '../core/api.dart';
import '../core/db.dart';
import '../core/device_keys.dart';
import '../core/links.dart';
import '../core/session.dart';
import '../models.dart';
import 'app_state.dart';

const _uuid = Uuid();

// -- send-retry policy (TODO.md §11 "Message reliability") --------------------
// Top-level and pure so the policy can be pinned by tests without standing up
// a ChatState: these three numbers are the difference between "still trying"
// and "gave up", and they are a product decision, not an implementation
// detail.

/// How long an undeliverable message keeps being retried before it is marked
/// `failed` and left alone. Long enough to outlast a weekend of VM trouble,
/// short enough that "sending…" never becomes a lie you live with.
const sendGiveUpAfterMs = 7 * 24 * 3600 * 1000;

const _sendRetryBaseMs = 30 * 1000;
const _sendRetryCeilingMs = 30 * 60 * 1000;

/// Backoff before attempt N+1: 30 s doubling to a 30-minute ceiling. Retries
/// are cheap, but a contact whose mailbox died should not be dialled on every
/// sweep for a week.
int sendBackoffMs(int attempts) {
  if (attempts <= 0) return 0;
  final shift = (attempts - 1).clamp(0, 20);
  return (_sendRetryBaseMs * (1 << shift)).clamp(
    _sendRetryBaseMs,
    _sendRetryCeilingMs,
  );
}

/// Coarse age for the "not sent · 3d" line. Null below five minutes — a
/// message a moment old needs no commentary, it just hasn't landed yet.
String? sendAgeLabel(int ms) {
  if (ms < 5 * 60 * 1000) return null;
  final minutes = ms ~/ 60000;
  if (minutes < 60) return '${minutes}m';
  final hours = minutes ~/ 60;
  if (hours < 24) return '${hours}h';
  return '${hours ~/ 24}d';
}

// -- fan-out concurrency ------------------------------------------------------

/// How many member deliveries may be in flight at once.
///
/// A group message is N independent HTTPS posts to N different mailboxes,
/// and they were serial: a 25-member group costs 25 round trips end to end.
/// Multi-device multiplies that by the recipient's device count
/// (MULTIDEVICE.md), which is why this had to stop being a loop before
/// per-device fan-out lands. Bounded rather than unbounded so a large group
/// can't open dozens of sockets at once on a phone radio.
const fanOutConcurrency = 6;

/// Serializes async work per key: two operations sharing a key never overlap,
/// operations on different keys run in parallel.
///
/// Exists for the ratchet. A double ratchet is mutable state — two concurrent
/// encrypts on one session derive the same message key, and two concurrent
/// loads of a cold session build two independent objects from one DB row and
/// then both encrypt from message 0. Fan-out only ever touches distinct
/// peers, but a retry sweep can overlap a live send to the same peer, and
/// that overlap became far likelier the moment fan-out stopped being serial.
class KeyedSerializer {
  final Map<String, Future<void>> _chain = {};

  /// One entry per key ever used. Bounded by the contact list here, so it is
  /// left to grow rather than reference-counted.
  int get trackedKeys => _chain.length;

  Future<T> run<T>(String key, Future<T> Function() body) {
    final prior = _chain[key] ?? Future<void>.value();
    final result = prior.then((_) => body());
    // The chain must survive a failed body, or one unreachable peer would
    // wedge every later message to them.
    _chain[key] = result.then((_) {}, onError: (_) {});
    return result;
  }
}

/// Run [tasks] with at most [limit] in flight, returning results in the
/// order the tasks were given (not the order they finished).
///
/// Tasks must not throw — a fan-out records per-recipient failures rather
/// than aborting its siblings, so callers wrap their own body in try/catch
/// and return the outcome instead.
Future<List<T>> runBounded<T>(
  int limit,
  List<Future<T> Function()> tasks,
) async {
  if (tasks.isEmpty) return <T>[];
  final results = List<T?>.filled(tasks.length, null);
  var next = 0;
  // `next++` has no await between read and increment, so the single-threaded
  // event loop makes this a safe work queue without a lock.
  Future<void> worker() async {
    while (true) {
      final i = next++;
      if (i >= tasks.length) return;
      results[i] = await tasks[i]();
    }
  }

  final workers = <Future<void>>[
    for (var w = 0; w < limit.clamp(1, tasks.length); w++) worker(),
  ];
  await Future.wait(workers);
  return results.cast<T>();
}

class ChatState extends ChangeNotifier {
  final AppState app;

  /// Posts a local notification (set by main to LocalNotices.show). Used for
  /// events worth surfacing while the app is backgrounded — e.g. a contact
  /// accepting your request.
  void Function(String title, String body)? onNotice;

  List<Contact> contacts = [];
  List<Group> groups = [];
  final Map<String, List<GroupMember>> groupMembers = {}; // by group id
  final Map<String, List<Message>> _messages = {}; // by conversation id
  final Map<String, Message?> lastMessage = {};

  // Own mailbox coordinates, set by MailboxState before the socket connects —
  // needed to download incoming media blobs and publish prekeys.
  String? mailboxAddress;
  String? mailboxToken;
  String? mailboxTlsFp;

  /// Which device *we* are on our own mailbox. The token we hold names it;
  /// the relay tells us which one it is on /status. Device 1 until a linked
  /// device learns otherwise from its grant, and it is bound into the AEAD of
  /// everything we send, so it must be right before we send anything.
  int myDeviceId = ChatDb.primaryDevice;

  /// The capability we hand peers so they can list our devices. Learned from
  /// our own mailbox's /status — a linked device cannot derive it, since that
  /// needs the owner token it deliberately does not hold.
  String? myBundleToken;

  // Forward-secret ratchet sessions, one per peer, cached over the DB copy.
  final Map<String, RatchetSession> _sessions = {};

  // The conversation currently on screen — its incoming messages are marked
  // read (and read-receipted) as they arrive.
  String? _openConversationId;

  // Call signaling hook, set by CallState: call_* envelopes from accepted
  // contacts are handed over instead of being handled here.
  Future<void> Function(
    Contact contact,
    Envelope envelope,
    Map<String, dynamic> payload,
  )?
  onCallSignal;

  // Emoji reactions: message id → (reactor Stonechat ID → emoji). Loaded per
  // conversation on open, updated live.
  final Map<String, Map<String, String>> reactionsByMessage = {};

  // Outgoing receipts, batched per peer so a drained queue costs one envelope
  // per sender instead of one per message. peer → kind → message ids.
  final Map<String, Map<String, Set<String>>> _receiptQueue = {};
  Timer? _receiptFlushTimer;

  // Who is typing where: conversation → (peer → expiry ms). Entries die on
  // expiry, on the peer's "stopped", or when their message arrives.
  final Map<String, Map<String, int>> _typing = {};
  Timer? _typingSweep;
  final Map<String, int> _typingSentAt =
      {}; // our own throttle, per conversation

  static const _typingRefreshMs =
      8 * 1000; // resend "started" at most this often
  static const _typingTtlMs = 15 * 1000; // shown this long without a refresh
  static const _editWindowMs =
      24 * 3600 * 1000; // sender-side edit/delete window
  static const _editGraceMs = 12 * 3600 * 1000; // receiver-side slack on top
  static const _replyPreviewMax = 140; // reply_to snapshot cap (chars)

  /// Mirror of the relay's MAX_BLOB_BYTES — checked before upload so a too-big
  /// video/document fails with a message instead of a 413.
  static const maxBlobBytes = 64 * 1024 * 1024;

  /// Profile photos ride inside a normal envelope (PROTOCOL.md "Profiles"),
  /// so the mailbox's 64 KB wire cap bounds them: after the payload-base64,
  /// ciphertext-base64 and seal-base64 layers, ~24 KB of raw image is the
  /// safe ceiling. Senders scale below it; receivers allow 2× for headroom.
  static const maxAvatarBytes = 24 * 1024;

  // Push wake-ups: this device's token, registered with our mailbox once both
  // exist (order of arrival between the two is not guaranteed).
  String? _pushToken;
  String? _pushPlatform;
  String? _registeredPushToken; // avoid re-POSTing an unchanged token

  ChatState(this.app);

  void setMailbox(
    String? address,
    String? token,
    String? tlsFp, {
    int? deviceId,
  }) {
    mailboxAddress = address;
    mailboxToken = token;
    mailboxTlsFp = tlsFp;
    if (deviceId != null) myDeviceId = deviceId;
    if (address != null && token != null && tlsFp != null) {
      unawaited(_learnOwnDevice(address, token, tlsFp));
    }
    _registeredPushToken = null; // new mailbox → re-register the token
    _registerPush();
    // Mirror the coordinates into the shared DB: the iOS notification
    // extension drains the mailbox from its own process and has no other
    // way to learn where it lives.
    unawaited(
      app.db.kvPut(
        'own_mailbox',
        address == null
            ? null
            : Uint8List.fromList(
                utf8.encode(
                  jsonEncode({
                    'address': address,
                    'token': token,
                    'tls_fp': tlsFp,
                    'device_id': myDeviceId,
                  }),
                ),
              ),
      ),
    );
  }

  /// Called by PushService when we obtain or refresh a device token.
  void setPushToken(String token, String platform) {
    _pushToken = token;
    _pushPlatform = platform;
    _registerPush();
  }

  Future<void> _registerPush() async {
    final address = mailboxAddress;
    final ownerToken = mailboxToken;
    final tlsFp = mailboxTlsFp;
    final deviceToken = _pushToken;
    final platform = _pushPlatform;
    if (address == null ||
        ownerToken == null ||
        tlsFp == null ||
        deviceToken == null ||
        platform == null) {
      return;
    }
    if (_registeredPushToken == deviceToken) return;
    try {
      await setPushConfig(address, ownerToken, deviceToken, platform, tlsFp);
      _registeredPushToken = deviceToken;
    } catch (_) {
      // best-effort; retried on the next mailbox connect or token refresh
    }
  }

  Future<Directory> _mediaDir() async {
    final docs = await getApplicationDocumentsDirectory();
    final dir = Directory(p.join(docs.path, 'media'));
    await dir.create(recursive: true);
    return dir;
  }

  Future<void> togglePinContact(Contact c) async {
    c.pinnedAt = c.isPinned ? null : DateTime.now().millisecondsSinceEpoch;
    await app.db.setContactPinned(c.stonechatId, c.pinnedAt);
    notifyListeners();
  }

  Future<void> togglePinGroup(Group g) async {
    g.pinnedAt = g.isPinned ? null : DateTime.now().millisecondsSinceEpoch;
    await app.db.setGroupPinned(g.id, g.pinnedAt);
    notifyListeners();
  }

  /// Block/unblock is local-only enforcement: we stop rendering their DM
  /// traffic and stop sending them anything; they are never told.
  Future<void> toggleBlock(Contact c) async {
    c.blockedAt = c.isBlocked ? null : DateTime.now().millisecondsSinceEpoch;
    await app.db.upsertContact(c);
    notifyListeners();
  }

  /// Mute until [untilMs] (null = unmute). Local-only presentation.
  Future<void> setMute(String conversationId, int? untilMs) async {
    final group = groupById(conversationId);
    final contact = group == null ? contactById(conversationId) : null;
    if (group != null) {
      group.mutedUntil = untilMs;
      await app.db.upsertGroup(group);
    } else if (contact != null) {
      contact.mutedUntil = untilMs;
      await app.db.upsertContact(contact);
    }
    notifyListeners();
  }

  Future<void> toggleArchive(String conversationId) async {
    final now = DateTime.now().millisecondsSinceEpoch;
    final group = groupById(conversationId);
    final contact = group == null ? contactById(conversationId) : null;
    if (group != null) {
      group.archivedAt = group.isArchived ? null : now;
      await app.db.upsertGroup(group);
    } else if (contact != null) {
      contact.archivedAt = contact.isArchived ? null : now;
      await app.db.upsertContact(contact);
    }
    notifyListeners();
  }

  List<Contact> get acceptedContacts =>
      contacts.where((c) => c.isAccepted).toList();
  List<Contact> get incomingRequests =>
      contacts.where((c) => c.status == ContactStatus.pendingIn).toList();
  List<Contact> get outgoingRequests =>
      contacts.where((c) => c.status == ContactStatus.pendingOut).toList();

  Future<void> load() async {
    contacts = await app.db.contacts();
    groups = await app.db.groups();
    for (final c in contacts) {
      lastMessage[c.stonechatId] = await app.db.lastMessageFor(c.stonechatId);
    }
    for (final g in groups) {
      groupMembers[g.id] = await app.db.membersOf(g.id);
      lastMessage[g.id] = await app.db.lastMessageFor(g.id);
    }
    // Partial-delivery counts before the first frame: a group message stuck
    // owing two members should say so on a cold start, not only after the
    // first retry sweep runs.
    await _reloadGroupOwed();
    notifyListeners();
    // Anything that expired while the app was closed vanishes before it can
    // be rendered (the sweep also fixes the previews it just loaded).
    unawaited(sweepExpired());
    // Whatever the last session left undelivered starts ticking again.
    if (await _hasPendingWork()) _scheduleRetrySweep();
  }

  /// Coming back to the foreground on iOS: the notification extension may
  /// have stored messages AND advanced ratchet sessions while we were
  /// suspended. Drop every cache that could now be stale — sessions above
  /// all: encrypting from a stale cached session would clobber the
  /// extension's state on save and fork the ratchet. Sessions reload
  /// lazily from the DB; the open conversation re-reads eagerly so the
  /// screen shows what the extension stored.
  Future<void> reloadAfterExtension() async {
    _sessions.clear();
    _messages.clear();
    final open = _openConversationId;
    if (open != null) await openConversation(open);
    for (final c in contacts) {
      lastMessage[c.stonechatId] = await app.db.lastMessageFor(c.stonechatId);
    }
    for (final g in groups) {
      lastMessage[g.id] = await app.db.lastMessageFor(g.id);
    }
    notifyListeners();
  }

  /// A backup restore merged rows straight into the DB underneath the
  /// per-conversation caches — drop them and reload. Not reset(): sessions,
  /// timers and push registration all belong to the live identity and must
  /// survive a restore.
  Future<void> reloadAfterRestore() async {
    _messages.clear();
    reactionsByMessage.clear();
    groupMembers.clear();
    lastMessage.clear();
    await load();
  }

  /// Identity reset: drop every in-memory trace of the dead identity. The DB
  /// is wiped separately (AppState.resetIdentity); mailbox coordinates are
  /// cleared by MailboxState.reset via setMailbox. The device push token
  /// (_pushToken/_pushPlatform) survives — it belongs to the phone, not the
  /// identity — and re-registers when the next identity gets a mailbox.
  void reset() {
    contacts = [];
    groups = [];
    groupMembers.clear();
    _messages.clear();
    lastMessage.clear();
    _sessions.clear();
    _openConversationId = null;
    reactionsByMessage.clear();
    _receiptQueue.clear();
    _receiptFlushTimer?.cancel();
    _receiptFlushTimer = null;
    _typing.clear();
    _typingSentAt.clear();
    _typingSweep?.cancel();
    _typingSweep = null;
    _expirySweep?.cancel();
    _expirySweep = null;
    _registeredPushToken = null;
    notifyListeners();
  }

  Group? groupById(String id) {
    for (final g in groups) {
      if (g.id == id) return g;
    }
    return null;
  }

  GroupMember? memberOf(String groupId, String stonechatId) {
    for (final m in groupMembers[groupId] ?? const <GroupMember>[]) {
      if (m.stonechatId == stonechatId) return m;
    }
    return null;
  }

  List<Message> messagesFor(String contactId) => _messages[contactId] ?? [];

  /// Stored history for a conversation that may never have been opened, so
  /// its messages are not in the in-memory cache. The report sheet needs this:
  /// someone can be reported straight from the chat list.
  Future<List<Message>> historyFor(String contactId) =>
      app.db.messagesFor(contactId);

  Future<void> openConversation(String contactId) async {
    _openConversationId = contactId;
    await sweepExpired(); // never render an already-expired message
    _messages[contactId] = await app.db.messagesFor(contactId);
    reactionsByMessage.addAll(await app.db.reactionsFor(contactId));
    await _markConversationRead(contactId);
    notifyListeners();
  }

  /// The chat screen is going away: stop read-receipting live arrivals and
  /// withdraw any typing indicator we advertised.
  void closeConversation(String contactId) {
    if (_openConversationId == contactId) _openConversationId = null;
    unawaited(stopTyping(contactId));
  }

  /// Everything on screen counts as read. Local state moves regardless of the
  /// privacy setting; the receipt only leaves the phone when it's on.
  Future<void> _markConversationRead(String conversationId) async {
    final read = <String>[];
    for (final m in _messages[conversationId] ?? const <Message>[]) {
      if (m.outgoing || m.status == MessageStatus.read) continue;
      m.status = MessageStatus.read;
      await app.db.setMessageStatus(m.id, MessageStatus.read);
      read.add(m.id);
      if (app.sendReadReceipts) {
        _queueReceipt(m.senderId ?? conversationId, ReceiptKind.read, m.id);
      }
    }
    if (read.isEmpty) return;
    // Read on this device is read everywhere — it is also what stops a
    // sibling notifying about a message we have already seen. Unconditional,
    // unlike the peer-facing receipt: sendReadReceipts is about what the
    // *peer* learns, not about our own devices agreeing with each other.
    unawaited(
      _syncToSiblings(EnvelopeType.syncRead, {
        if (groupById(conversationId) != null)
          'group_id': conversationId
        else
          'peer': conversationId,
        'ids': read,
      }),
    );
  }

  /// Erase one conversation's history on this device, keeping the
  /// conversation itself: the contact, its session, its device list and its
  /// display name all survive. "Clear chat" that dropped the contact would be
  /// "forget this person", which is a different button with a different
  /// consequence — the session would have to be rebuilt and the peer would see
  /// a new handshake.
  ///
  /// Local by construction. The peer keeps their copy: nothing here reaches
  /// them, and claiming otherwise would be the one lie a privacy tool must not
  /// tell. Our *own* devices do converge — see [_syncToSiblings] below, since
  /// history cleared on the phone but intact on the laptop has not been
  /// cleared in any sense the user means.
  Future<void> clearChat(String conversationId) async {
    final media = await app.db.clearConversation(conversationId);
    for (final path in media) {
      try {
        await File(path).delete();
      } catch (_) {
        // Already gone, or never written. Not worth failing the clear over.
      }
    }
    _messages[conversationId] = [];
    notifyListeners();
    unawaited(
      _syncToSiblings(EnvelopeType.syncClear, {
        if (groupById(conversationId) != null)
          'group_id': conversationId
        else
          'peer': conversationId,
      }),
    );
  }

  /// A sibling cleared this conversation; do the same here.
  ///
  /// Idempotent and order-independent: clearing an already-empty conversation
  /// is a no-op, so a redelivered envelope costs nothing. Deliberately *not*
  /// timestamped — a clear that raced with a message in flight would either
  /// need the peer's clock or ours, and both are wrong. The user asked for
  /// empty; empty is what they get, and anything that arrives afterwards is a
  /// new conversation.
  Future<void> _applySyncClear(Map<String, dynamic> payload) async {
    final conversationId =
        (payload['group_id'] ?? payload['peer']) as String? ?? '';
    if (conversationId.isEmpty) return;
    final media = await app.db.clearConversation(conversationId);
    for (final path in media) {
      try {
        await File(path).delete();
      } catch (_) {}
    }
    _messages[conversationId] = [];
    notifyListeners();
  }

  /// A sibling read these; catch up locally without re-receipting the peer —
  /// they already got a receipt from the device that did the reading.
  Future<void> _applySyncRead(Map<String, dynamic> payload) async {
    final conversationId =
        (payload['group_id'] ?? payload['peer']) as String? ?? '';
    final ids = (payload['ids'] as List?)?.whereType<String>() ?? const [];
    var touched = false;
    for (final id in ids) {
      final message = await app.db.messageById(id);
      if (message == null || message.outgoing) continue;
      if (MessageStatus.rank(MessageStatus.read) <=
          MessageStatus.rank(message.status)) {
        continue;
      }
      await _setStatusEverywhere(message, MessageStatus.read);
      touched = true;
    }
    if (touched) {
      lastMessage[conversationId] = await app.db.lastMessageFor(conversationId);
      notifyListeners();
    }
  }

  Contact? contactById(String stonechatId) {
    for (final c in contacts) {
      if (c.stonechatId == stonechatId) return c;
    }
    return null;
  }

  // -- resolving peers ---------------------------------------------------------

  /// Directory lookup with the trust-but-verify steps from PROTOCOL.md: the
  /// pubkey must hash to the ID, and any listed mailbox must carry a TLS
  /// fingerprint signed by that pubkey. A mailbox that fails the transport
  /// check is treated as absent — never connected to.
  ///
  /// Cross-hub: a peer on another hub is resolved through *their* directory —
  /// [hub] when the caller has it (fresh invite, request payload), else the
  /// contact's stored home hub. The verification below is what makes asking a
  /// foreign hub safe: it can lie only into a failed lookup.
  Future<DirectoryEntry> _resolve(String stonechatId, {String? hub}) async {
    final entry = await app.api.directory(
      stonechatId,
      hubUrl: hub ?? contactById(stonechatId)?.hub,
    );
    if (!app.crypto.pubkeyMatchesId(entry.pubkeyB64, entry.stonechatId)) {
      throw ApiException.refusing(
        'Directory returned a key that does not match this ID — refusing.',
      );
    }
    // The X-Wing identity key seals every envelope to this peer; it is only
    // trusted signed by the (commitment-verified) Ed25519 key. Absent or
    // forged → unusable entry: the protocol has no classical-seal fallback.
    final pqOk =
        entry.pqPkB64 != null &&
        entry.pqSigB64 != null &&
        app.crypto.verifyPqPkSig(
          Uint8List.fromList(base64Decode(entry.pqPkB64!)),
          Uint8List.fromList(base64Decode(entry.pqSigB64!)),
          Uint8List.fromList(base64Decode(entry.pubkeyB64)),
        );
    if (!pqOk) {
      throw ApiException.refusing(
        'Directory entry lacks a valid post-quantum key — refusing.',
      );
    }
    if (entry.mailboxAddress != null) {
      final fp = entry.mailboxTlsFp;
      final sig = entry.mailboxTlsSig;
      final vouched =
          fp != null &&
          sig != null &&
          app.crypto.verifyTlsSig(
            fp,
            sig,
            Uint8List.fromList(base64Decode(entry.pubkeyB64)),
          );
      if (!vouched) {
        return DirectoryEntry(
          stonechatId: entry.stonechatId,
          pubkeyB64: entry.pubkeyB64,
          // no owner-signed transport key yet → unreachable, not unpinned
        );
      }
    }
    return entry;
  }

  Future<String> _addressFor(Contact contact, {bool refresh = false}) async {
    if (!refresh &&
        contact.mailboxAddress != null &&
        contact.tlsFp != null &&
        contact.pqPkB64 != null) {
      return contact.mailboxAddress!;
    }
    final entry = await _resolve(contact.stonechatId);
    if (entry.mailboxAddress == null) {
      throw ApiException(
        "${contact.displayName}'s mailbox is off right now — they'll get it when it's back",
      );
    }
    contact.mailboxAddress = entry.mailboxAddress;
    contact.tlsFp = entry.mailboxTlsFp;
    contact.pqPkB64 = entry.pqPkB64; // sig-verified in _resolve
    await app.db.upsertContact(contact);
    return entry.mailboxAddress!;
  }

  /// Transport wrap (PROTOCOL.md "Envelope"): hybrid-seal the whole envelope
  /// to the recipient's X-Wing identity key (directory `pq_pk`, verified
  /// against their Ed25519 key on resolve). Their mailbox stores only
  /// {v, id, to, blob_id} plus an opaque box — it never learns who wrote to
  /// its owner. [transient] (typing, call ICE), [noPush] (receipts) and
  /// [ring] (call offers) are the delivery hints the mailbox is allowed to
  /// see.
  /// [toSealKeyB64] is the recipient **device's** X-Wing key, taken from its
  /// verified certificate — not the single identity key the directory holds.
  /// That change is what lets a device exist without the identity secret.
  SealedEnvelope _wireSeal(
    Envelope envelope,
    String toSealKeyB64, {
    bool transient = false,
    bool noPush = false,
    bool ring = false,
  }) => SealedEnvelope(
    device: envelope.device,
    id: envelope.id,
    to: envelope.to,
    sealedB64: base64Encode(
      app.crypto.sealTo(
        Uint8List.fromList(base64Decode(toSealKeyB64)),
        utf8.encode(jsonEncode(envelope.toJson())),
      ),
    ),
    blobId: envelope.blobId,
    transient: transient,
    noPush: noPush,
    ring: ring,
  );

  /// Which of a peer's devices to encrypt for.
  ///
  /// Without their bundle token we can only reach the primary — which is
  /// exactly what a stranger sending a contact request gets, and what
  /// everyone is until linking ships. Listing is an optimisation, never a
  /// precondition: if it fails we still send to the primary rather than
  /// failing the message.
  final Map<String, List<int>> _peerDevices = {};

  Future<List<int>> _devicesFor(
    String peerId,
    String? bundleToken,
    String address,
    String tlsFp,
  ) async {
    final cached = _peerDevices[peerId];
    if (cached != null) return cached;
    if (bundleToken == null) return const [ChatDb.primaryDevice];
    try {
      final listed = await fetchDeviceList(address, bundleToken, tlsFp);
      if (listed.devices.isEmpty) return const [ChatDb.primaryDevice];
      return _peerDevices[peerId] = listed.devices;
    } catch (_) {
      return const [ChatDb.primaryDevice];
    }
  }

  /// Verified device certificates, per peer, per device.
  ///
  /// In memory only: a certificate is public, cheap to refetch, and holding a
  /// stale one is worse than holding none.
  final Map<String, Map<int, Map<String, dynamic>>> _peerCerts = {};

  /// The certificate for one of a peer's devices — the thing that says which
  /// key to seal to, and which key their prekeys are signed with.
  ///
  /// Verified against the peer's identity key from the directory before it is
  /// cached, so everything downstream can treat a cached certificate as
  /// trusted. Refetched when the one we hold is nearing expiry, rather than
  /// when it has already lapsed.
  Future<Map<String, dynamic>?> _certFor(
    String peerId,
    int deviceId,
    String peerPubkeyB64,
    String? bundleToken,
    String address,
    String tlsFp,
  ) async {
    final held = _peerCerts[peerId]?[deviceId];
    if (held != null && !certNeedsRefresh(held)) return held;

    Map<String, dynamic>? fetched;
    try {
      if (bundleToken != null) {
        final listed = await fetchDeviceList(address, bundleToken, tlsFp);
        _peerDevices[peerId] = listed.devices;
        for (final entry in listed.certs.entries) {
          _recordCert(peerId, entry.key, entry.value, peerPubkeyB64);
        }
        fetched = _peerCerts[peerId]?[deviceId];
      } else if (deviceId == ChatDb.primaryDevice) {
        // No token, so no device list — but a stranger sending a first
        // contact request still gets the primary's certificate off the open
        // bundle, which is exactly the reach they are meant to have.
        final bundle = await fetchPrekeyBundle(address, tlsFp);
        final cert = bundle['cert'];
        if (cert is Map<String, dynamic>) {
          _recordCert(peerId, deviceId, cert, peerPubkeyB64);
          fetched = _peerCerts[peerId]?[deviceId];
        }
      }
    } catch (_) {
      // Unreachable mailbox — fall through to whatever we already hold.
    }
    // A stale-but-valid certificate beats refusing to send because a refresh
    // could not happen right now.
    return fetched ?? held;
  }

  /// Verify a certificate against the peer's identity key and cache it.
  ///
  /// A certificate that does not verify is dropped silently: it is either a
  /// mailbox serving something it was not given, or a device that is not this
  /// peer's. Either way there is nothing to encrypt to.
  void _recordCert(
    String peerId,
    int deviceId,
    Map<String, dynamic> cert,
    String peerPubkeyB64,
  ) {
    final now = DateTime.now().toUtc().millisecondsSinceEpoch ~/ 1000;
    final status = app.crypto.core.devcertVerify(
      cert,
      Uint8List.fromList(base64Decode(peerPubkeyB64)),
      now,
    );
    if (status != 'valid') {
      _dropLogPlain(
        'device $deviceId of $peerId: certificate $status — not encrypting to it',
      );
      _peerCerts[peerId]?.remove(deviceId);
      return;
    }
    if (cert['device_id'] != deviceId) {
      // The certificate names a different device than the slot it arrived in.
      // Signed, so not forged — but a relay shuffling certificates between
      // devices would redirect mail, and the signature covers the id exactly
      // so it can be checked.
      _dropLogPlain('device $deviceId of $peerId: certificate names another device');
      return;
    }
    (_peerCerts[peerId] ??= {})[deviceId] = cert;
  }

  static void _dropLogPlain(String reason) =>
      debugPrint('stonechat: $reason');

  /// A peer's device set changed — drop the cached list so the next send
  /// re-reads it, and remember the version we saw.
  void _noteDevicesV(Contact contact, int devicesV) {
    if (devicesV <= contact.devicesV) return;
    contact.devicesV = devicesV;
    _peerDevices.remove(contact.stonechatId);
    unawaited(app.db.upsertContact(contact));
  }

  /// Send one logical message to every device a peer has: k envelopes, each
  /// on its own ratchet with its own associated data — and all of them over
  /// **one** connection, because a peer's devices share one mailbox and the
  /// handshake is ~2 of the ~2.6 round trips a delivery costs
  /// (`scripts/bench_devices.py` measured 31–35%).
  ///
  /// Throws if no device accepted its copy; a partial fan-out counts as sent,
  /// because the devices that did take it will show the message.
  Future<void> _fanOutToDevices({
    required String peerId,
    required String pubkeyB64,
    required String pqPkB64,
    required String address,
    required String tlsFp,
    required String? bundleToken,
    required String type,
    required Map<String, Object?> payload,
    void Function(int devicesV)? onDevicesV,
    String? envelopeId,
    String? blobId,
    bool transient = false,
    bool noPush = false,
    bool ring = false,
    /// Set for real messages: the fan-out then records exactly which of this
    /// peer's devices are still owed a copy. A peer whose phone took it but
    /// whose laptop did not is *not* delivered, and only per-device rows can
    /// tell a retry the difference.
    ({String messageId, String conversationId})? outbox,
  }) async {
    final devices = await _devicesFor(peerId, bundleToken, address, tlsFp);
    final link = MailboxLink(address, tlsFp);
    final accepted = <int>{};
    final gone = <int>{}; // revoked: nobody is owed a copy for these
    Object? lastError;
    try {
      for (final device in devices) {
        try {
          // Which key this device's mail is sealed to, from its certificate.
          // No certificate, or one that does not verify, means there is
          // nothing to encrypt to — skip it rather than falling back to the
          // directory key, which is exactly what certificates replaced.
          final cert = await _certFor(
            peerId,
            device,
            pubkeyB64,
            bundleToken,
            address,
            tlsFp,
          );
          final sealKeyBytes = cert == null ? null : certSealKey(cert);
          if (sealKeyBytes == null) {
            lastError = ApiException(
              'No usable certificate for one of their devices',
            );
            continue;
          }
          final sealKey = base64Encode(sealKeyBytes);
          final envelope = await _sealFor(
            type,
            peerId,
            pubkeyB64,
            payload,
            envelopeId: envelopeId,
            mailboxAddress: address,
            mailboxTlsFp: tlsFp,
            blobId: blobId,
            deviceId: device,
            bundleToken: bundleToken,
          );
          final devicesV = await link.deliver(
            _wireSeal(
              envelope,
              sealKey,
              transient: transient,
              noPush: noPush,
              ring: ring,
            ),
          );
          accepted.add(device);
          if (devicesV != null) onDevicesV?.call(devicesV);
        } catch (e) {
          lastError = e;
          if (e is ApiException && e.status == 410) {
            // Revoked or never existed. Forget it and its ratchet; nobody is
            // owed a copy for a device that is gone.
            gone.add(device);
            _peerDevices.remove(peerId);
            await app.db.deleteSession(peerId, deviceId: device);
            final devicesV = devicesVOf(e);
            if (devicesV != null) onDevicesV?.call(devicesV);
            continue;
          }
          // One device being unreachable must not stop its siblings getting
          // their copy — the same rule groups already follow for members.
        }
      }
    } finally {
      link.close();
      if (outbox != null) {
        await app.db.setOwedDevices(
          outbox.messageId,
          outbox.conversationId,
          peerId,
          devices.where((d) => !accepted.contains(d) && !gone.contains(d)).toList(),
        );
      }
    }
    if (accepted.isEmpty) {
      throw lastError is ApiException
          ? lastError
          : ApiException('no device accepted the message');
    }
  }

  Future<void> _deliver(
    Contact contact,
    String type,
    Map<String, Object?> payload, {
    String? envelopeId,
    String? blobId,
    bool transient = false,
    bool noPush = false,
    bool ring = false,
    ({String messageId, String conversationId})? outbox,
  }) async {
    // _addressFor also backfills pq_pk for contacts saved before a resolve
    // (e.g. a pending_in row built from an x3dh block alone).
    Future<void> attempt(String address) => _fanOutToDevices(
      peerId: contact.stonechatId,
      pubkeyB64: contact.pubkeyB64,
      pqPkB64: contact.pqPkB64!,
      address: address,
      tlsFp: contact.tlsFp!,
      bundleToken: contact.bundleToken,
      onDevicesV: (v) => _noteDevicesV(contact, v),
      type: type,
      payload: payload,
      envelopeId: envelopeId,
      blobId: blobId,
      transient: transient,
      noPush: noPush,
      ring: ring,
      outbox: outbox,
    );
    try {
      await attempt(await _addressFor(contact));
    } on Exception {
      // Their mailbox may have been recreated at a new IP (or with a new TLS
      // key) — refresh everything and retry once.
      await attempt(await _addressFor(contact, refresh: true));
    }
  }

  // -- self-sync (MULTIDEVICE.md "Self-sync") ---------------------------------

  /// Our own other devices. Empty until something is linked, which is why
  /// every sync path below costs nothing today.
  Future<List<int>> _siblingDevices() async {
    final address = mailboxAddress;
    final tlsFp = mailboxTlsFp;
    final token = myBundleToken;
    if (address == null || tlsFp == null || token == null) return const [];
    try {
      final listed = await fetchDeviceList(address, token, tlsFp);
      return listed.devices.where((d) => d != myDeviceId).toList();
    } catch (_) {
      return const []; // sync is convergence, never a precondition for sending
    }
  }

  /// Mirror something to our own other devices.
  ///
  /// Siblings are peers like any other: ordinary pairwise sessions,
  /// bootstrapped from our own mailbox's per-device bundles. `push: false`
  /// throughout — our own laptop catching up is never worth lighting up our
  /// own phone.
  Future<void> _syncToSiblings(String type, Map<String, Object?> payload) async {
    final devices = await _siblingDevices();
    if (devices.isEmpty) return;
    final address = mailboxAddress!;
    final tlsFp = mailboxTlsFp!;
    for (final device in devices) {
      try {
        // Our own devices are peers like any other, including here: the wrap
        // goes to that device's certified seal key. Sealing to the identity's
        // X-Wing key — which this did until 08-03 — now produces something no
        // device can open, because that key's private half no longer exists.
        final cert = await _certFor(
          app.stonechatId!,
          device,
          app.crypto.publicKeyB64,
          myBundleToken,
          address,
          tlsFp,
        );
        final sealKey = cert == null ? null : certSealKey(cert);
        if (sealKey == null) continue;
        final envelope = await _sealFor(
          type,
          app.stonechatId!,
          app.crypto.publicKeyB64,
          payload,
          mailboxAddress: address,
          mailboxTlsFp: tlsFp,
          deviceId: device,
          bundleToken: myBundleToken,
        );
        await deliverEnvelope(
          address,
          _wireSeal(envelope, base64Encode(sealKey), noPush: true),
          tlsFp,
        );
      } catch (_) {
        // Best-effort, like receipts: a lost sync costs a stale view on one
        // device, and the next message re-converges it.
      }
    }
  }

  /// A message we just sent should appear on our other devices too. Incoming
  /// messages need no sync — every device gets its own copy from the sender.
  Future<void> _syncSent(Message message, String type, Map<String, Object?> payload) async {
    await _syncToSiblings(EnvelopeType.syncSent, {
      if (groupById(message.contactId) != null)
        'group_id': message.contactId
      else
        'peer': message.contactId,
      'type': type,
      'payload': payload,
      'id': message.id,
      'sent_at': message.sentAt,
    });
  }

  /// Media we sent, mirrored to our own devices.
  ///
  /// The payload cannot always be replayed verbatim: DM media parks its
  /// ciphertext on the *recipient's* mailbox, where a sibling holds no token
  /// at all, so every photo we sent would render as unavailable everywhere
  /// else. Group media already sits on our own mailbox behind a capability
  /// token, so that payload *is* reusable — and re-pointing the DM case at
  /// the same mechanism is the whole fix.
  Future<void> _syncSentMedia(
    Message message,
    String type,
    Map<String, Object?> payload,
  ) async {
    if ((await _siblingDevices()).isEmpty) return;
    var forSiblings = payload;
    if (message.blob == null) {
      final SharedBlob shared;
      try {
        shared = await _shareBlobFor(message);
      } catch (_) {
        return; // no sibling copy, no sync — the text of it is not worth a lie
      }
      forSiblings = {
        ...payload,
        'blob_id': shared.id,
        'key': shared.keyB64,
        'blob_nonce': shared.nonceB64,
        'fetch_token': shared.fetchToken,
        'blob_host': shared.host,
        'blob_tls_fp': shared.tlsFp,
      };
    }
    await _syncSent(message, type, forSiblings);
  }

  /// One of our own devices sent something. Render it here too.
  ///
  /// Authenticated by the session: only our own identity key could have
  /// produced this, and [handleIncoming] additionally checks `from`.
  Future<void> _applySyncSent(
    Envelope envelope,
    Map<String, dynamic> payload,
  ) async {
    final conversationId =
        (payload['group_id'] ?? payload['peer']) as String? ?? '';
    if (conversationId.isEmpty) return;
    final inner = (payload['payload'] as Map?)?.cast<String, dynamic>();
    final id = payload['id'] as String?;
    if (inner == null || id == null) return;
    final sentAt = (payload['sent_at'] as int?) ??
        DateTime.now().millisecondsSinceEpoch;
    final type = payload['type'] as String? ?? EnvelopeType.msg;

    String? mediaPath;
    final isMedia =
        type == EnvelopeType.media || type == EnvelopeType.groupMedia;
    if (isMedia) {
      // Same shared-blob path as group media, pointed at our own mailbox.
      mediaPath = await _fetchSyncedMedia(id, inner);
    }
    final (replyId, replySender, replyPreview) = _replyFrom(inner);
    final message = Message(
      id: id,
      contactId: conversationId,
      outgoing: true,
      text: isMedia ? '' : ((inner['text'] as String?) ?? ''),
      kind: isMedia ? _mediaKindOf(inner) : MessageKind.text,
      mediaPath: mediaPath,
      durationMs: inner['duration_ms'] as int?,
      fileName: _mediaNameOf(inner),
      sentAt: sentAt,
      // It left our other device; whether the peer has it is their receipt to
      // tell us, and receipts reach every device.
      status: MessageStatus.sent,
      expiresAt: _expiresAtFrom(envelope, inner),
      replyToId: replyId,
      replyToSender: replySender,
      replyToPreview: replyPreview,
    );
    await app.db.insertMessage(message);
    final cache = _messages[conversationId];
    if (cache != null && !cache.any((m) => m.id == message.id)) {
      cache.add(message);
      cache.sort((a, b) => a.sentAt.compareTo(b.sentAt));
    }
    lastMessage[conversationId] = message;
    if (message.expiresAt != null) _scheduleExpirySweep();
    notifyListeners();
  }

  /// Fetch a sibling's copy of media from our own mailbox. Null when it is
  /// gone or unreadable — the message still renders, without the file.
  Future<String?> _fetchSyncedMedia(
    String messageId,
    Map<String, dynamic> payload,
  ) async {
    final host = payload['blob_host'] as String?;
    final tlsFp = payload['blob_tls_fp'] as String?;
    final blobId = payload['blob_id'] as String?;
    final token = payload['fetch_token'] as String? ?? mailboxToken;
    if (host == null || tlsFp == null || blobId == null || token == null) {
      return null;
    }
    try {
      return await _persistMedia(
        messageId,
        await downloadBlob(host, blobId, token, tlsFp),
        payload,
      );
    } catch (_) {
      return null;
    }
  }

  /// Remember a peer's bundle token, wherever we know them from. A sender may
  /// be a contact, a fellow group member, both, or neither.
  Future<void> _noteBundleToken(String peerId, String? token) async {
    if (token == null || token.isEmpty) return;
    final contact = contactById(peerId);
    if (contact != null && contact.bundleToken != token) {
      contact.bundleToken = token;
      _peerDevices.remove(peerId); // re-list with the new capability
      await app.db.upsertContact(contact);
    }
    for (final members in groupMembers.values) {
      for (final m in members) {
        if (m.stonechatId != peerId || m.bundleToken == token) continue;
        m.bundleToken = token;
        _peerDevices.remove(peerId);
        await app.db.updateMember(m);
      }
    }
  }

  /// Ask our own mailbox which device we are and what token to hand peers.
  /// Best-effort: without it we still send, we just cannot tell anyone how to
  /// reach our siblings.
  Future<void> _learnOwnDevice(String address, String token, String tlsFp) async {
    final status = await mailboxStatus(address, tlsFp, token);
    if (status == null) return;
    myDeviceId = status.deviceId;
    myBundleToken = status.bundleToken;
  }

  // -- forward-secret sessions (PROTOCOL.md "Session crypto") --------------------

  /// One writer per ratchet — see [KeyedSerializer]. Different ratchets still
  /// encrypt in parallel, which is what makes concurrent fan-out safe. Keyed
  /// by (peer, device) now that one peer has several independent ratchets:
  /// locking a whole peer would serialize a fan-out to their own devices for
  /// no reason.
  final _peerLock = KeyedSerializer();

  /// The ratchet cache key. Sessions are per (peer, device) because a double
  /// ratchet is mutable state that advances on every message — two devices
  /// cannot share one, which is the constraint the entire multi-device design
  /// is built around (MULTIDEVICE.md).
  static String _sessionKey(String peerId, int deviceId) => '$peerId#$deviceId';

  Future<RatchetSession?> _loadSession(String peerId, int deviceId) async {
    final cached = _sessions[_sessionKey(peerId, deviceId)];
    if (cached != null) return cached;
    final stateJson = await app.db.sessionState(peerId, deviceId);
    if (stateJson == null) return null;
    final session = RatchetSession.fromJson(
      app.crypto,
      peerId,
      jsonDecode(stateJson) as Map<String, dynamic>,
    );
    _sessions[_sessionKey(peerId, deviceId)] = session;
    return session;
  }

  Future<void> _saveSession(RatchetSession session, int deviceId) async {
    _sessions[_sessionKey(session.peerId, deviceId)] = session;
    await app.db.saveSession(
      session.peerId,
      deviceId,
      jsonEncode(session.toJson()),
    );
  }

  /// The session for an outgoing message, establishing one via the peer's
  /// prekey bundle when none exists yet.
  Future<RatchetSession> _sessionFor(
    String peerId,
    String peerPubkeyB64, {
    int deviceId = ChatDb.primaryDevice,
    String? bundleToken,
    String? mailboxAddress,
    String? mailboxTlsFp,
  }) async {
    final existing = await _loadSession(peerId, deviceId);
    if (existing != null && existing.canSend) return existing;

    // X3DH must run against *that device's* prekeys. The unauthenticated
    // bundle is device 1's by design, so anything else needs the token —
    // without it we have no business claiming to reach a sibling device.
    Future<PrekeyBundle> fetchFrom(String address, String tlsFp) async {
      if (deviceId == ChatDb.primaryDevice) {
        return PrekeyBundle.fromJson(await fetchPrekeyBundle(address, tlsFp));
      }
      if (bundleToken == null) {
        throw ApiException.refusing(
          'No bundle token for device $deviceId — cannot start a session.',
        );
      }
      return PrekeyBundle.fromJson(
        await fetchDeviceBundle(address, deviceId, bundleToken, tlsFp),
      );
    }

    PrekeyBundle bundle;
    try {
      if (mailboxAddress == null || mailboxTlsFp == null) {
        throw ApiException('no cached address');
      }
      bundle = await fetchFrom(mailboxAddress, mailboxTlsFp);
    } on Exception {
      // No cached address, or their mailbox moved — ask the directory.
      final entry = await _resolve(peerId);
      if (entry.mailboxAddress == null) {
        throw ApiException(
          "Their mailbox is off right now — they'll get it when it's back",
        );
      }
      bundle = await fetchFrom(entry.mailboxAddress!, entry.mailboxTlsFp!);
    }

    // Prekeys are signed by the DEVICE, and its certificate — already
    // verified against the identity key above — is what names the key to
    // check them with. Without one there is nothing to verify against, and a
    // prekey nobody vouched for is the exact thing this check exists to
    // refuse.
    final cert = _peerCerts[peerId]?[deviceId];
    final deviceSigKey = cert == null ? null : certSigKey(cert);
    if (deviceSigKey == null) {
      throw ApiException.refusing(
        'No certificate for that device — refusing to start a session.',
      );
    }
    if (!app.crypto.verifyPrekeySig(
          bundle.spkPub,
          bundle.spkSig,
          deviceSigKey,
        ) ||
        !app.crypto.verifyKemPrekeySig(
          bundle.kspkPub,
          bundle.kspkSig,
          deviceSigKey,
        )) {
      throw ApiException.refusing(
        'Their mailbox served a forged prekey — refusing to send.',
      );
    }
    // Device to device: their signing key from the certificate we just
    // verified, ours from this device's own seed. Neither side's identity
    // secret is involved, which is the point — it is what lets a browser
    // session run this at all.
    final session = RatchetSession.initiate(
      app.crypto,
      peerId,
      deviceSigKey,
      bundle,
      ownEdSeed: app.deviceKeys!.sigSeed,
    );
    await _saveSession(session, deviceId);
    return session;
  }

  Future<Envelope> _sealFor(
    String type,
    String toStonechatId,
    String toPubkeyB64,
    Map<String, Object?> payload, {
    String? envelopeId,
    String? mailboxAddress,
    String? mailboxTlsFp,
    String? blobId,
    int deviceId = ChatDb.primaryDevice,
    String? bundleToken,
  }) {
    // Establish-then-encrypt-then-persist is one indivisible step per ratchet:
    // interleaving two of these on one session reuses a message key. Locked
    // per (peer, device) so a fan-out across one peer's devices still runs in
    // parallel.
    return _peerLock.run(_sessionKey(toStonechatId, deviceId), () async {
      final session = await _sessionFor(
        toStonechatId,
        toPubkeyB64,
        deviceId: deviceId,
        bundleToken: bundleToken,
        mailboxAddress: mailboxAddress,
        mailboxTlsFp: mailboxTlsFp,
      );
      // Both device numbers are bound, on every message, single-device or
      // not (MULTIDEVICE.md "Associated data"). One form, no conditional:
      // this is the one place where a second code path would mean silent
      // decryption failure.
      final adPrefix =
          'stonechat/v1|${app.stonechatId}|$myDeviceId'
          '|$toStonechatId|$deviceId|$type';
      final sealed = session.encrypt(jsonEncode(payload), adPrefix);
      // Our certificate travels with the handshake so the responder can
      // trust the device key inside it without fetching anything.
      final x3dh = session.pendingX3dh?.withCert(app.deviceCert).toJson();
      // Persist the advanced chain before the envelope can leave: a crash
      // after send must never reuse a message key.
      await _saveSession(session, deviceId);
      return Envelope(
        id: envelopeId ?? _uuid.v4(),
        type: type,
        from: app.stonechatId!,
        fromDevice: myDeviceId,
        to: toStonechatId,
        device: deviceId,
        sentAt: DateTime.now().toUtc().toIso8601String(),
        ratchet: sealed.ratchet,
        x3dh: x3dh,
        nonceB64: base64Encode(sealed.nonce),
        ciphertextB64: base64Encode(sealed.ciphertext),
        blobId: blobId,
        bundleToken: myBundleToken,
      );
    });
  }

  /// Decrypt an incoming envelope on the sender's session, establishing a
  /// responder session from the envelope's x3dh block when needed. Returns
  /// null (drop silently) for anything that doesn't verify.
  Future<String?> _openEnvelope(Envelope envelope) async {
    final adPrefix =
        'stonechat/v1|${envelope.from}|${envelope.fromDevice}'
        '|${envelope.to}|${envelope.device}|${envelope.type}';
    final header = envelope.ratchet.cast<String, dynamic>();
    final nonce = Uint8List.fromList(base64Decode(envelope.nonceB64));
    final ciphertext = Uint8List.fromList(base64Decode(envelope.ciphertextB64));
    final block = X3dhBlock.fromJson(envelope.x3dh?.cast<String, dynamic>());
    // Which of the sender's devices wrote this — the ratchet to open it on.
    // AEAD-bound, so a relabelled envelope simply fails to decrypt.
    final fromDevice = envelope.fromDevice;
    final session = await _loadSession(envelope.from, fromDevice);

    if (session != null) {
      // Simultaneous add: both sides initiated. The lower Stonechat ID's session
      // wins deterministically; if theirs wins, skip ours and adopt below.
      final theirsWins =
          block != null &&
          !session.confirmed &&
          session.initiatedByUs &&
          envelope.from.compareTo(app.stonechatId!) < 0;
      if (!theirsWins) {
        final plain = session.decrypt(header, nonce, ciphertext, adPrefix);
        if (plain != null) {
          await _saveSession(session, fromDevice);
          return plain;
        }
        if (block == null) {
          _dropLog(envelope, 'session decrypt failed, no x3dh block');
          return null; // forged/undecryptable — drop
        }
        // fall through: maybe a fresh prekey message replacing a stale session
      }
    }
    if (block == null) {
      _dropLog(envelope, 'no session and no x3dh block');
      return null;
    }

    // The key in the block is the sender's DEVICE key, which does not hash
    // to their SC- ID — so the check is the certificate that vouches for it,
    // against the identity key their SC- ID does commit to. The certificate
    // rides in the block precisely so this needs no network round trip on
    // the receive path.
    final senderCert = block.cert;
    if (senderCert == null) {
      _dropLog(envelope, 'x3dh block carries no device certificate');
      return null;
    }
    // Resolving the sender is the one lookup this path cannot avoid — the
    // identity key is what the certificate has to verify against, and it is
    // what their SC- ID commits to. It is also cached, so this is a network
    // call only the first time we ever hear from them.
    final senderEntry = await _resolve(envelope.from);
    _recordCert(
      envelope.from,
      envelope.fromDevice,
      senderCert,
      senderEntry.pubkeyB64,
    );
    // _recordCert caches it only if it verifies AND names this device, so
    // getting it back out is the check — and it means our reply already has
    // the certificate it needs without fetching their bundle.
    if (_peerCerts[envelope.from]?[envelope.fromDevice] == null) {
      _dropLog(envelope, 'x3dh device certificate did not verify');
      return null;
    }
    final certified = certSigKey(senderCert);
    if (certified == null || base64Encode(certified) != block.ikB64) {
      // Signed, valid, ours — but vouching for a different key than the one
      // the handshake used. Without this the certificate would be decoration.
      _dropLog(envelope, 'x3dh key is not the one its certificate vouches for');
      return null;
    }
    final spkRow = await app.db.prekeyById(block.spkId, 'spk');
    if (spkRow == null) {
      _dropLog(envelope, 'spk ${block.spkId} not held (rotated away?)');
      return null; // sender will re-encrypt
    }
    Map<String, Object?>? opkRow;
    if (block.opkId != null) {
      opkRow = await app.db.prekeyById(block.opkId!, 'opk');
      if (opkRow == null) {
        _dropLog(envelope, 'opk ${block.opkId} not held (consumed/replay?)');
        return null;
      }
    }
    final kemKind = block.kemOneTime ? 'kopk' : 'kspk';
    final kemRow = await app.db.prekeyById(block.kemId, kemKind);
    if (kemRow == null) {
      _dropLog(
        envelope,
        '$kemKind ${block.kemId} not held (rotated/consumed/replay?)',
      );
      return null; // sender will re-encrypt
    }
    final fresh = RatchetSession.respond(
      app.crypto,
      envelope.from,
      Uint8List.fromList(base64Decode(block.ikB64)),
      block,
      ownEdSeed: app.deviceKeys!.sigSeed,
      spkPub: Uint8List.fromList(base64Decode(spkRow['pub'] as String)),
      spkSec: Uint8List.fromList(base64Decode(spkRow['sec'] as String)),
      opkSec: opkRow == null
          ? null
          : Uint8List.fromList(base64Decode(opkRow['sec'] as String)),
      kemSeed: Uint8List.fromList(base64Decode(kemRow['sec'] as String)),
    );
    final plain = fresh.decrypt(header, nonce, ciphertext, adPrefix);
    if (plain == null) {
      _dropLog(envelope, 'x3dh responder decrypt failed');
      return null;
    }
    if (block.opkId != null) {
      await app.db.deletePrekey(block.opkId!); // one-time means one time
    }
    if (block.kemOneTime) {
      await app.db.deletePrekey(block.kemId); // one-time means one time
    }
    // Replaces any prior session with this peer's sending device.
    await _saveSession(fresh, fromDevice);
    return plain;
  }

  /// Dropped envelopes are invisible by design (they're acked and deleted);
  /// leave a trace so "message never arrived" is diagnosable from logs.
  static void _dropLog(Envelope envelope, String reason) {
    debugPrint(
      'stonechat: dropped ${envelope.type} from '
      '${envelope.from.substring(0, 12)}…: $reason',
    );
  }

  // -- prekey publishing -----------------------------------------------------------

  static const _opkTarget = 32;
  static const _spkRotateMs = 7 * 24 * 3600 * 1000;

  /// Keep our mailbox stocked with public prekeys so peers can start
  /// forward-secret sessions while we're offline. Called on every mailbox
  /// connect; re-seeds from scratch when the mailbox lost its store
  /// (recreated VM).
  Future<void> publishPrekeys() async {
    final address = mailboxAddress;
    final token = mailboxToken;
    final tlsFp = mailboxTlsFp;
    if (address == null || token == null || tlsFp == null) return;
    // Our certificate goes up with our prekeys: it names the key that signed
    // them, so publishing one without the other leaves peers unable to check
    // either. Minting it here also renews it when it nears expiry.
    await app.ensureOwnCertificate(myDeviceId);
    if (app.deviceKeys == null) {
      // Should be unreachable: an identity that exists has device keys, on
      // every path that can create one. It was reachable once — a freshly
      // onboarded session had none — and the cost was a mailbox that answered
      // every bundle request with 404 while the phone looked perfectly
      // healthy. Silence is what made that expensive, so it is loud now.
      debugPrint(
        'stonechat: no device keys — prekeys and certificate NOT published; '
        'this identity cannot be messaged until they exist',
      );
      return;
    }

    final now = DateTime.now().millisecondsSinceEpoch;

    var spkRow = await app.db.currentSpk();
    if (spkRow == null || now - (spkRow['created_at'] as int) > _spkRotateMs) {
      final kp = app.crypto.newX25519();
      final sec = kp.secretKey;
      final id = await app.db.insertPrekey(
        'spk',
        base64Encode(kp.publicKey),
        base64Encode(sec),
      );
      await app.db.pruneSigned('spk');
      spkRow = await app.db.prekeyById(id, 'spk');
    }

    // The ML-KEM signed prekey rotates on the same cadence as the SPK
    // (PQXDH's last-resort KEM key; docs/POST_QUANTUM.md).
    var kspkRow = await app.db.currentKspk();
    if (kspkRow == null ||
        now - (kspkRow['created_at'] as int) > _spkRotateMs) {
      final kp = app.crypto.newMlkemPrekey();
      final id = await app.db.insertPrekey(
        'kspk',
        base64Encode(kp.pub),
        base64Encode(kp.seed),
      );
      await app.db.pruneSigned('kspk');
      kspkRow = await app.db.prekeyById(id, 'kspk');
    }

    final existing = await app.db.opks();
    for (var i = existing.length; i < _opkTarget; i++) {
      final kp = app.crypto.newX25519();
      final sec = kp.secretKey;
      await app.db.insertPrekey(
        'opk',
        base64Encode(kp.publicKey),
        base64Encode(sec),
      );
    }

    final existingKem = await app.db.kopks();
    for (var i = existingKem.length; i < _opkTarget; i++) {
      final kp = app.crypto.newMlkemPrekey();
      await app.db.insertPrekey(
        'kopk',
        base64Encode(kp.pub),
        base64Encode(kp.seed),
      );
    }

    // Upload the FULL remaining stock; the mailbox replaces its store with
    // it (PROTOCOL.md "Prekeys"). Consumed OPKs are deleted locally, so what
    // we hold is exactly what we can decrypt — this heals a mailbox left
    // holding keys from a previous install.
    final toPublish = await app.db.opks();
    final kemToPublish = await app.db.kopks();
    final spkPubBytes = Uint8List.fromList(
      base64Decode(spkRow!['pub'] as String),
    );
    final kspkPubBytes = Uint8List.fromList(
      base64Decode(kspkRow!['pub'] as String),
    );
    await uploadPrekeys(
      address,
      token,
      tlsFp,
      {
        'id': spkRow['id'],
        'pub': spkRow['pub'],
        'sig': base64Encode(
          app.crypto.signPrekey(app.deviceKeys!.sigSecret, spkPubBytes),
        ),
      },
      [
        for (final o in toPublish) {'id': o['id'], 'pub': o['pub']},
      ],
      {
        'id': kspkRow['id'],
        'pub': kspkRow['pub'],
        'sig': base64Encode(
          app.crypto.signKemPrekey(app.deviceKeys!.sigSecret, kspkPubBytes),
        ),
      },
      [
        for (final o in kemToPublish) {'id': o['id'], 'pub': o['pub']},
      ],
      cert: app.deviceCert,
    );
  }

  /// Deliver to every member concurrently, swallowing per-member failures the
  /// way each of these call sites already did individually. Returns true only
  /// if every member's mailbox took its copy — the "reached everyone" answer
  /// that edit and delete-for-everyone report to the user.
  ///
  /// Everything group-shaped goes through here: a 25-member reaction used to
  /// be 25 sequential round trips, same as a message.
  Future<bool> _fanOutToMembers(
    Iterable<GroupMember> members,
    Future<void> Function(GroupMember member) send,
  ) async {
    var reachedEveryone = true;
    await runBounded(fanOutConcurrency, [
      for (final member in members)
        () async {
          try {
            await send(member);
          } catch (_) {
            reachedEveryone = false;
          }
        },
    ]);
    return reachedEveryone;
  }

  /// Every member of [groupId] except us — the fan-out target set.
  Iterable<GroupMember> _othersIn(String groupId) =>
      (groupMembers[groupId] ?? const <GroupMember>[]).where(
        (m) => m.stonechatId != app.stonechatId,
      );

  /// Resolve + deliver to a group member (same trust-but-verify as contacts),
  /// fanning out to their devices exactly as [_deliver] does.
  ///
  /// A member's bundle token is learned from anything they have sent us
  /// ([_noteBundleToken]), which is what lets a fellow member who was never a
  /// contact still be reached on all their devices. Until they have said
  /// anything we know only their primary.
  Future<void> _deliverToMember(
    GroupMember member,
    String type,
    Map<String, Object?> payload, {
    String? envelopeId,
    String? blobId,
    bool transient = false,
    bool noPush = false,
    ({String messageId, String conversationId})? outbox,
  }) async {
    Future<String> resolve() async {
      final entry = await _resolve(member.stonechatId);
      if (entry.mailboxAddress == null) {
        throw ApiException('${member.displayName} is unreachable right now');
      }
      member.mailboxAddress = entry.mailboxAddress;
      member.tlsFp = entry.mailboxTlsFp;
      member.pqPkB64 = entry.pqPkB64; // sig-verified in _resolve
      await app.db.updateMember(member);
      return entry.mailboxAddress!;
    }

    Future<void> attempt(String address) => _fanOutToDevices(
      outbox: outbox,
      peerId: member.stonechatId,
      pubkeyB64: member.pubkeyB64,
      pqPkB64: member.pqPkB64!,
      address: address,
      tlsFp: member.tlsFp!,
      bundleToken: member.bundleToken,
      type: type,
      payload: payload,
      envelopeId: envelopeId,
      blobId: blobId,
      transient: transient,
      noPush: noPush,
    );

    final known =
        member.mailboxAddress != null &&
        member.tlsFp != null &&
        member.pqPkB64 != null;
    try {
      await attempt(known ? member.mailboxAddress! : await resolve());
    } on Exception {
      await attempt(await resolve()); // their mailbox may have moved
    }
  }

  // -- profiles (PROTOCOL.md "Profiles") -------------------------------------------

  /// Our display name + current photo — what contact_request, contact_accept
  /// and profile_update carry. The avatar key is always present (null =
  /// cleared) so receivers converge on removals too. Cross-hub builds also
  /// name our home hub, so a peer on another hub can resolve us back.
  Map<String, Object?> _profilePayload() => {
    'display_name': app.displayName,
    'avatar': app.avatar == null
        ? null
        : {'data': base64Encode(app.avatar!), 'mime': 'image/jpeg'},
    if (stonechatCrossHub) 'hub': app.api.baseUrl,
  };

  /// A peer's home hub from a contact_request/accept payload: only under the
  /// cross-hub flag, only http(s), and null when it's just our own hub. The
  /// URL is routing data from an E2EE-authenticated sender — a wrong one can
  /// only make lookups fail, never redirect trust (_resolve verifies).
  String? _peerHubFrom(Map<String, dynamic> payload) {
    if (!stonechatCrossHub) return null;
    var hub = payload['hub'];
    if (hub is! String) return null;
    while (hub.endsWith('/')) {
      hub = hub.substring(0, hub.length - 1);
    }
    if (!hub.startsWith('https://') && !hub.startsWith('http://')) return null;
    return hub == app.api.baseUrl ? null : hub;
  }

  /// Set or clear our profile photo, then fan the new profile to every
  /// accepted contact. Best-effort like edits: an unreachable contact keeps
  /// the old photo until our next change reaches them.
  Future<void> updateMyAvatar(Uint8List? bytes) async {
    await app.setAvatar(bytes);
    final payload = _profilePayload();
    for (final contact in acceptedContacts.where((c) => !c.isBlocked)) {
      try {
        await _deliver(
          contact,
          EnvelopeType.profileUpdate,
          payload,
          noPush: true,
        ); // nobody's phone wakes for a photo swap
      } catch (_) {
        // unreachable — they keep the old photo, no durable retry by design
      }
    }
  }

  /// Apply a payload's optional avatar field to a contact: key absent =
  /// unchanged, null = cleared, else {"data", "mime"}. Cooperative display
  /// data — oversized or undecodable images are dropped, never trusted
  /// beyond shape. Returns whether the contact was touched.
  static bool _applyAvatar(Contact contact, Map<String, dynamic> payload) {
    if (!payload.containsKey('avatar')) return false;
    final raw = payload['avatar'];
    if (raw == null) {
      contact.avatar = null;
      return true;
    }
    if (raw is! Map) return false;
    final data = raw['data'];
    if (data is! String) return false;
    try {
      final bytes = base64Decode(data);
      if (bytes.length > 2 * maxAvatarBytes) return false;
      contact.avatar = bytes;
      return true;
    } catch (_) {
      return false; // malformed base64
    }
  }

  // -- contact lifecycle ---------------------------------------------------------

  /// Add by full SC- ID, hub-tagged `SC-…@host` code, or invite URL: resolve,
  /// verify, store, send an encrypted contact request.
  Future<Contact> addContact(String raw) async {
    final input = raw.trim();
    if (input.isEmpty) {
      throw const FormatException('Enter a Stonechat code');
    }
    // Lookup is by full SC- ID only (there are no handles). normalizeStonechatId
    // validates the checksum locally and throws FormatException on garbage.
    final invite =
        stonechatInviteFromInput(input) ?? (stonechatId: input, hub: null);
    final query = app.crypto.normalizeStonechatId(invite.stonechatId);
    final hub = invite.hub == app.api.baseUrl ? null : invite.hub;
    if (hub != null && !stonechatCrossHub) {
      throw const FormatException(
        'This invite lives on a different Stonechat hub — this build only '
        'reaches people on yours',
      );
    }

    final entry = await _resolve(query, hub: hub);
    if (entry.stonechatId == app.stonechatId) {
      throw ApiException("That's your own code");
    }
    if (contactById(entry.stonechatId) != null) {
      throw ApiException('Already in your contacts');
    }
    final contact = Contact(
      stonechatId: entry.stonechatId,
      displayName: entry.stonechatId.substring(3, 12),
      pubkeyB64: entry.pubkeyB64,
      pqPkB64: entry.pqPkB64, // sig-verified in _resolve
      status: ContactStatus.pendingOut,
      mailboxAddress: entry.mailboxAddress,
      tlsFp: entry.mailboxTlsFp,
      hub: hub,
      createdAt: DateTime.now().millisecondsSinceEpoch,
    );
    await app.db.upsertContact(contact);
    contacts.add(contact);
    notifyListeners();

    await _deliver(contact, EnvelopeType.contactRequest, _profilePayload());
    return contact;
  }

  /// Re-send a still-pending contact request (manual nudge from the
  /// Requests list; receivers dedupe by sender, so this is always safe).
  Future<void> resendRequest(Contact contact) async {
    await _deliver(contact, EnvelopeType.contactRequest, _profilePayload());
  }

  Future<void> acceptContact(Contact contact) async {
    contact.status = ContactStatus.accepted;
    await app.db.upsertContact(contact);
    notifyListeners();
    await _deliver(contact, EnvelopeType.contactAccept, _profilePayload());
  }

  Future<void> declineContact(Contact contact) async {
    await app.db.deleteContact(contact.stonechatId);
    // Drop the ratchet too: a kept session would be silently reused if this
    // peer is ever re-added, and it may be pinned to prekeys the other side
    // no longer holds (the re-add does a fresh X3DH instead).
    await app.db.deleteSession(contact.stonechatId);
    _sessions.remove(contact.stonechatId);
    contacts.removeWhere((c) => c.stonechatId == contact.stonechatId);
    _messages.remove(contact.stonechatId);
    notifyListeners();
  }

  // -- groups ----------------------------------------------------------------------

  Map<String, Object?> _membershipPayload(
    Group group,
    List<GroupMember> members,
  ) => {
    'group_id': group.id,
    'name': group.name,
    'version': group.version,
    'admin': group.adminId,
    'members': [
      for (final m in members)
        {
          'stonechat_id': m.stonechatId,
          'pubkey': m.pubkeyB64,
          'display_name': m.displayName,
        },
    ],
    // Joiners bootstrap the disappearing-messages timer from this;
    // established members ignore it (PROTOCOL.md "Disappearing messages").
    if (group.expireTimerMs > 0) 'expire_ms': group.expireTimerMs,
  };

  /// Create a group from accepted contacts. We are the admin.
  Future<Group> createGroup(String name, List<Contact> selected) async {
    final group = Group(
      id: _uuid.v4(),
      name: name,
      adminId: app.stonechatId!,
      version: 1,
      createdAt: DateTime.now().millisecondsSinceEpoch,
    );
    final members = <GroupMember>[
      GroupMember(
        groupId: group.id,
        stonechatId: app.stonechatId!,
        pubkeyB64: app.crypto.publicKeyB64,
        displayName: app.displayName ?? 'me',
      ),
      for (final c in selected)
        GroupMember(
          groupId: group.id,
          stonechatId: c.stonechatId,
          pubkeyB64: c.pubkeyB64,
          displayName: c.displayName,
          mailboxAddress: c.mailboxAddress,
          tlsFp: c.tlsFp,
        ),
    ];
    await app.db.upsertGroup(group);
    await app.db.replaceMembers(group.id, members);
    groups.add(group);
    groupMembers[group.id] = members;
    notifyListeners();

    final payload = _membershipPayload(group, members);
    // An unreachable member hears about the group via the next groupUpdate or
    // message retry; eventual delivery is accepted.
    await _fanOutToMembers(
      members.where((m) => m.stonechatId != app.stonechatId),
      (m) async => _deliverToMember(m, EnvelopeType.groupCreate, payload),
    );
    // Our own other devices are not members, so the fan-out above skips them
    // — and a linked browser was therefore never told a group existed, even
    // one created on this phone seconds earlier. It could see the messages
    // (those do sync) and not the roster, so it could read and never reply.
    // Sending the same payload to our siblings is enough: _applyMembership
    // accepts it because we are the admin that signed it.
    unawaited(_syncToSiblings(EnvelopeType.groupCreate, payload));
    return group;
  }

  /// The quoted author's Stonechat ID: us for our own messages, the group sender
  /// for group messages, the DM peer otherwise.
  String _quotedSenderOf(Message quoted) => quoted.outgoing
      ? app.stonechatId!
      : (quoted.senderId ?? quoted.contactId);

  static String _clipPreview(String s) =>
      s.length <= _replyPreviewMax ? s : '${s.substring(0, _replyPreviewMax)}…';

  /// The wire form of a message's stored reply snapshot (PROTOCOL.md
  /// "reply_to"). Built from the message's own fields so pending-outbox
  /// retries carry exactly what the original send did.
  static Map<String, Object?>? _replyPayloadOf(Message m) => m.replyToId == null
      ? null
      : {
          'id': m.replyToId,
          if (m.replyToSender != null) 'sender': m.replyToSender,
          if (m.replyToPreview != null) 'preview': m.replyToPreview,
        };

  /// Incoming reply_to block → (id, sender, preview), all null when absent
  /// or malformed. Cooperative display data — never trusted beyond shape.
  static (String?, String?, String?) _replyFrom(Map<String, dynamic> payload) {
    final r = payload['reply_to'];
    if (r is! Map) return (null, null, null);
    final id = r['id'];
    if (id is! String || id.isEmpty) return (null, null, null);
    final sender = r['sender'];
    final preview = r['preview'];
    return (
      id,
      sender is String ? sender : null,
      preview is String ? _clipPreview(preview) : null,
    );
  }

  /// Admin-only: change the member set and/or rename, bump the version, and
  /// fan the new full state to everyone — including just-removed members,
  /// whose clients clear their membership on seeing a list without them
  /// (PROTOCOL.md "Groups"). Best-effort like group_create: an unreachable
  /// member hears about it on the next update.
  Future<void> updateGroupMembership(
    Group group, {
    String? name,
    List<Contact> addContacts = const [],
    Set<String> removeIds = const {},
  }) async {
    if (group.adminId != app.stonechatId) return;
    final current = groupMembers[group.id] ?? const <GroupMember>[];
    final added = [
      for (final c in addContacts)
        if (!current.any((m) => m.stonechatId == c.stonechatId)) c,
    ];
    final removed = current
        .where((m) => removeIds.contains(m.stonechatId))
        .toList();
    final newName = name?.trim();
    final renamed =
        newName != null && newName.isNotEmpty && newName != group.name;
    if (added.isEmpty && removed.isEmpty && !renamed) return;

    final members = <GroupMember>[
      for (final m in current)
        if (!removeIds.contains(m.stonechatId)) m,
      for (final c in added)
        GroupMember(
          groupId: group.id,
          stonechatId: c.stonechatId,
          pubkeyB64: c.pubkeyB64,
          displayName: c.displayName,
          mailboxAddress: c.mailboxAddress,
          tlsFp: c.tlsFp,
        ),
    ];
    final oldName = group.name;
    if (renamed) group.name = newName;
    group.version += 1;
    await app.db.upsertGroup(group);
    await app.db.replaceMembers(group.id, members);
    groupMembers[group.id] = members;

    if (renamed) {
      await _insertNotice(group.id, 'You renamed "$oldName" to "$newName"');
    }
    for (final c in added) {
      await _insertNotice(group.id, 'You added ${c.displayName}');
    }
    for (final m in removed) {
      await _insertNotice(group.id, 'You removed ${m.displayName}');
    }
    notifyListeners();

    final payload = _membershipPayload(group, members);
    final recipients = [
      ...members.where((m) => m.stonechatId != app.stonechatId),
      ...removed,
    ];
    // An unreachable member keeps the old view until the next update.
    await _fanOutToMembers(
      recipients,
      (m) async => _deliverToMember(m, EnvelopeType.groupUpdate, payload),
    );
    // Same reasoning as create: a roster change our own devices never hear
    // about leaves them holding a membership list that is quietly wrong.
    unawaited(_syncToSiblings(EnvelopeType.groupUpdate, payload));
  }

  Future<Message> sendGroupMessage(
    Group group,
    String text, {
    Message? replyTo,
  }) async {
    _typingSentAt.remove(group.id); // the message itself says "stopped typing"
    final members = (groupMembers[group.id] ?? [])
        .where((m) => m.stonechatId != app.stonechatId)
        .toList();
    final sentAt = DateTime.now().millisecondsSinceEpoch;
    final message = Message(
      id: _uuid.v4(),
      contactId: group.id,
      outgoing: true,
      text: text,
      sentAt: sentAt,
      status: MessageStatus.pending,
      expiresAt: group.expireTimerMs > 0 ? sentAt + group.expireTimerMs : null,
      replyToId: replyTo?.id,
      replyToSender: replyTo == null ? null : _quotedSenderOf(replyTo),
      replyToPreview: replyTo == null ? null : _clipPreview(replyTo.preview),
    );
    await app.db.insertMessage(message);
    await app.db.addOutbox(message.id, group.id, [
      for (final m in members) m.stonechatId,
    ]);
    (_messages[group.id] ??= []).add(message);
    lastMessage[group.id] = message;
    if (message.expiresAt != null) _scheduleExpirySweep();
    notifyListeners();

    await _fanOut(group, message, members);
    return message;
  }

  /// Send a photo, video, voice note or document to a group. The file is
  /// encrypted and uploaded **once**, to our own mailbox, and each member is
  /// handed a read capability for that one blob (PROTOCOL.md "Group media") —
  /// so upload cost is flat in the member count, unlike the DM path, which
  /// parks a copy on the recipient's box.
  Future<Message> sendGroupMedia(
    Group group,
    String sourcePath, {
    required String kind, // MessageKind.image | audio | video | file | sticker
    required String mime,
    int? durationMs,
    String? fileName, // kind=file: the document's original name
    Message? replyTo,
  }) async {
    _typingSentAt.remove(group.id); // the message itself says "stopped typing"
    final members = (groupMembers[group.id] ?? [])
        .where((m) => m.stonechatId != app.stonechatId)
        .toList();
    final id = _uuid.v4();
    final dir = await _mediaDir();
    final localPath = p.join(dir.path, '$id${p.extension(sourcePath)}');
    await File(sourcePath).copy(localPath);

    final sentAt = DateTime.now().millisecondsSinceEpoch;
    final message = Message(
      id: id,
      contactId: group.id,
      outgoing: true,
      text: '',
      kind: kind,
      mediaPath: localPath,
      durationMs: durationMs,
      fileName: fileName,
      sentAt: sentAt,
      status: MessageStatus.pending,
      expiresAt: group.expireTimerMs > 0 ? sentAt + group.expireTimerMs : null,
      replyToId: replyTo?.id,
      replyToSender: replyTo == null ? null : _quotedSenderOf(replyTo),
      replyToPreview: replyTo == null ? null : _clipPreview(replyTo.preview),
    );
    await app.db.insertMessage(message);
    await app.db.addOutbox(message.id, group.id, [
      for (final m in members) m.stonechatId,
    ]);
    (_messages[group.id] ??= []).add(message);
    lastMessage[group.id] = message;
    if (message.expiresAt != null) _scheduleExpirySweep();
    notifyListeners();

    await _fanOut(group, message, members, mime: mime);
    return message;
  }

  Future<void> _fanOut(
    Group group,
    Message message,
    List<GroupMember> members, {
    String? mime, // first attempt only; retries re-derive it from the file
  }) async {
    // A group of one owes nobody anything — and must not park a blob on our
    // mailbox that no member will ever come to fetch.
    if (members.isEmpty) return _settleFanOut(message);
    final isMedia = message.kind != MessageKind.text;
    SharedBlob? blob;
    if (isMedia) {
      try {
        blob = await _shareBlobFor(message);
      } catch (e) {
        // Nothing was fanned out, so the outbox rows stand and retryPending
        // comes back — but the message now says why it hasn't moved.
        await _recordSendFailure(message, e);
        notifyListeners();
        return;
      }
    }
    // Expiry rides the message itself, not the current setting: a retry after
    // a timer change must still carry the TTL this message was sent under.
    final payload = {
      'group_id': group.id,
      if (!isMedia) 'text': message.text,
      if (isMedia) ...{
        'blob_id': blob!.id,
        'key': blob.keyB64,
        'blob_nonce': blob.nonceB64,
        // Where to fetch it and which pinned cert to expect — the box that
        // took the upload, not whichever is current. Our own mailbox: members
        // come to us, we don't push a copy to each of them.
        'fetch_token': blob.fetchToken,
        'blob_host': blob.host,
        'blob_tls_fp': blob.tlsFp,
        'mime': mime ?? _mimeFromPath(message.mediaPath ?? ''),
        'kind': message.kind,
        'size': blob.size,
        if (message.durationMs != null) 'duration_ms': message.durationMs,
        if (message.fileName != null) 'name': message.fileName,
      },
      if (message.expiresAt != null)
        'expire_after_ms': message.expiresAt! - message.sentAt,
      if (_replyPayloadOf(message) != null)
        'reply_to': _replyPayloadOf(message),
    };
    // The outer envelope carries no blob_id: the blob is on *our* mailbox, so
    // a member's ack must not try to garbage-collect it from theirs.
    final type = isMedia ? EnvelopeType.groupMedia : EnvelopeType.groupMsg;
    Object? lastError; // one member's failure shouldn't hide behind the others
    // Members are independent mailboxes, so their deliveries overlap. Serial
    // was one round trip per member end to end; _sealFor still serializes per
    // peer, which is the only ordering that matters.
    await runBounded(fanOutConcurrency, [
      for (final member in members)
        () async {
          try {
            // Envelope id == message id for every copy: mailboxes are
            // per-member so ids never collide, and both mailbox and receiver
            // dedupe retries.
            await _deliverToMember(
              member,
              type,
              payload,
              envelopeId: message.id,
              outbox: (messageId: message.id, conversationId: group.id),
            );
          } catch (e) {
            // stays in outbox; retryPending re-attempts this member
            lastError = e;
          }
        },
    ]);
    await _settleFanOut(message, lastError, (type: type, payload: payload));
  }

  /// A DM send is over. Sent only once no device is still owed a copy —
  /// otherwise it stays pending and the retry sweep comes back for the ones
  /// that missed out.
  Future<void> _settleSend(
    Message message,
    String type,
    Map<String, Object?> payload,
  ) async {
    if (await app.db.outboxRemaining(message.id) > 0) {
      await _recordSendFailure(
        message,
        ApiException('Some of their devices are unreachable right now'),
        mayBeTerminal: false,
      );
      return;
    }
    await _recordSendSuccess(message);
    unawaited(
      message.kind == MessageKind.text
          ? _syncSent(message, type, payload)
          : _syncSentMedia(message, type, payload),
    );
  }

  /// A fan-out pass is over. The message counts as sent once no member is
  /// still owed a copy; short of that it keeps the reason the last member
  /// gave, so the bubble can say "sent to 3 of 5" and why the other two
  /// missed out. A group is never failed by one dead mailbox — only by the
  /// give-up window, or a refusal, closing over the whole thing.
  Future<void> _settleFanOut(
    Message message, [
    Object? lastError,
    ({String type, Map<String, Object?> payload})? sync,
  ]) async {
    final owed = await app.db.outboxRemaining(message.id);
    _groupOwed[message.id] = await app.db.outboxMembersRemaining(message.id);
    if (owed == 0) {
      await _recordSendSuccess(message);
      if (sync != null) {
        unawaited(
          message.kind == MessageKind.text
              ? _syncSent(message, sync.type, sync.payload)
              : _syncSentMedia(message, sync.type, sync.payload),
        );
      }
    } else if (lastError != null) {
      await _recordSendFailure(message, lastError, mayBeTerminal: false);
    }
    notifyListeners();
  }

  /// Group messages still owed to at least one member: message id → how many
  /// members are left. Kept in memory so a bubble can render "sent to 3 of 5"
  /// without a query per frame; `group_outbox` stays the source of truth.
  final Map<String, int> _groupOwed = {};

  /// How many members still haven't been handed [messageId]. 0 means every
  /// mailbox took it — which is what "sent" means for a group.
  int owedFor(String messageId) => _groupOwed[messageId] ?? 0;

  Future<void> _reloadGroupOwed() async {
    final owed = await app.db.pendingOutbox();
    _groupOwed
      ..clear()
      ..addEntries(owed.entries.map((e) => MapEntry(e.key, e.value.length)));
  }

  /// The single shared upload behind a group-media fan-out, created on first
  /// need and reused by every retry — re-encrypting would mint a fresh key,
  /// which the ciphertext already parked on our mailbox would not match.
  ///
  /// Throws rather than returning null on failure: the caller turns that into
  /// a reason on the message. A silent null here was how "nothing happened
  /// and nobody said why" used to look.
  Future<SharedBlob> _shareBlobFor(Message message) async {
    final existing = message.blob;
    if (existing != null) return existing;
    final host = mailboxAddress;
    final tlsFp = mailboxTlsFp;
    if (host == null || tlsFp == null) {
      throw ApiException(
        "Your mailbox isn't ready — this will send once it is",
      );
    }
    final path = message.mediaPath ?? '';
    final file = File(path);
    if (!await file.exists()) {
      // Terminal: no retry brings a deleted file back.
      throw FileSystemException('media file is gone', path);
    }
    final bytes = await file.readAsBytes();
    final sealed = app.crypto.sealBlob(bytes);
    final up = await uploadSharedBlob(host, sealed.ciphertext, tlsFp);
    final blob = SharedBlob(
      id: up.blobId,
      fetchToken: up.fetchToken,
      keyB64: base64Encode(sealed.key),
      nonceB64: base64Encode(sealed.nonce),
      size: bytes.length,
      host: host,
      tlsFp: tlsFp,
    );
    message.blob = blob;
    for (final m in _cachedCopies(message)) {
      m.blob = blob;
    }
    await app.db.setMessageBlob(message.id, blob);
    return blob;
  }

  /// Everyone has the file (or the message is gone): drop the ciphertext from
  /// our mailbox rather than let it sit out the relay's 14-day TTL against our
  /// storage cap. Best-effort — that TTL is the backstop. The key is forgotten
  /// with it; it has no reason to outlive the blob it opens.
  Future<void> _releaseSharedBlob(Message message) async {
    final blob = message.blob;
    if (blob == null) return;
    final token = mailboxToken;
    if (token == null) return; // keep the record; a later cleanup can retry
    try {
      await deleteBlob(blob.host, blob.id, token, blob.tlsFp);
    } catch (_) {
      return; // unreachable, or a mailbox move left the old token behind
    }
    message.blob = null;
    for (final m in _cachedCopies(message)) {
      m.blob = null;
    }
    await app.db.setMessageBlob(message.id, null);
  }

  /// Leave: announce to everyone, then delete locally.
  Future<void> leaveGroup(Group group) async {
    // Courtesy only — removal becomes authoritative with the admin's next
    // group_update, so a member we can't reach costs nothing.
    await _fanOutToMembers(
      _othersIn(group.id),
      (m) async =>
          _deliverToMember(m, EnvelopeType.groupLeave, {'group_id': group.id}),
    );
    await app.db.deleteGroup(group.id);
    groups.removeWhere((g) => g.id == group.id);
    groupMembers.remove(group.id);
    _messages.remove(group.id);
    lastMessage.remove(group.id);
    notifyListeners();
  }

  // -- messaging -------------------------------------------------------------------

  Future<Message> sendMessage(
    Contact contact,
    String text, {
    Message? replyTo,
  }) async {
    _typingSentAt.remove(
      contact.stonechatId,
    ); // the message itself says "stopped"
    final sentAt = DateTime.now().millisecondsSinceEpoch;
    final message = Message(
      id: _uuid.v4(),
      contactId: contact.stonechatId,
      outgoing: true,
      text: text,
      sentAt: sentAt,
      status: MessageStatus.pending,
      expiresAt: contact.expireTimerMs > 0
          ? sentAt + contact.expireTimerMs
          : null,
      replyToId: replyTo?.id,
      replyToSender: replyTo == null ? null : _quotedSenderOf(replyTo),
      replyToPreview: replyTo == null ? null : _clipPreview(replyTo.preview),
    );
    await app.db.insertMessage(message);
    (_messages[contact.stonechatId] ??= []).add(message);
    lastMessage[contact.stonechatId] = message;
    if (message.expiresAt != null) _scheduleExpirySweep();
    notifyListeners();

    await _trySend(contact, message);
    return message;
  }

  /// Forward an existing message to another conversation. A forward is an
  /// ordinary new message — fresh id, own outbox lifecycle, no link back to
  /// the original. Media forwards re-copy and re-encrypt the local file, so
  /// they only work while it still exists on this device.
  Future<void> forwardMessage(
    Message m, {
    Contact? toContact,
    Group? toGroup,
  }) async {
    assert((toContact == null) != (toGroup == null));
    if (m.kind == MessageKind.text) {
      if (toGroup != null) {
        await sendGroupMessage(toGroup, m.text);
      } else {
        await sendMessage(toContact!, m.text);
      }
    } else if (toGroup != null) {
      await sendGroupMedia(
        toGroup,
        m.mediaPath!,
        kind: m.kind,
        mime: _mimeFromPath(m.mediaPath!),
        durationMs: m.durationMs,
        fileName: m.fileName,
      );
    } else {
      await sendMedia(
        toContact!,
        m.mediaPath!,
        kind: m.kind,
        mime: _mimeFromPath(m.mediaPath!),
        durationMs: m.durationMs,
        fileName: m.fileName,
      );
    }
  }

  /// Send a photo, video, voice note or document. `sourcePath` is copied into
  /// the app's media directory first — the local copy is the message history.
  Future<Message> sendMedia(
    Contact contact,
    String sourcePath, {
    required String kind, // MessageKind.image | audio | video | file
    required String mime,
    int? durationMs,
    String? fileName, // kind=file: the document's original name
    Message? replyTo,
  }) async {
    final id = _uuid.v4();
    final dir = await _mediaDir();
    final localPath = p.join(dir.path, '$id${p.extension(sourcePath)}');
    await File(sourcePath).copy(localPath);

    final sentAt = DateTime.now().millisecondsSinceEpoch;
    final message = Message(
      id: id,
      contactId: contact.stonechatId,
      outgoing: true,
      text: '',
      kind: kind,
      mediaPath: localPath,
      durationMs: durationMs,
      fileName: fileName,
      sentAt: sentAt,
      status: MessageStatus.pending,
      expiresAt: contact.expireTimerMs > 0
          ? sentAt + contact.expireTimerMs
          : null,
      replyToId: replyTo?.id,
      replyToSender: replyTo == null ? null : _quotedSenderOf(replyTo),
      replyToPreview: replyTo == null ? null : _clipPreview(replyTo.preview),
    );
    await app.db.insertMessage(message);
    (_messages[contact.stonechatId] ??= []).add(message);
    lastMessage[contact.stonechatId] = message;
    if (message.expiresAt != null) _scheduleExpirySweep();
    notifyListeners();

    await _trySend(contact, message, mime: mime);
    return message;
  }

  Future<void> _trySend(
    Contact contact,
    Message message, {
    String? mime,
  }) async {
    // A DM is a fan-out too now, so it needs the same per-device bookkeeping
    // groups have: one of the recipient's three devices accepting is not the
    // message being delivered.
    final outbox = (
      messageId: message.id,
      conversationId: contact.stonechatId,
    );
    try {
      if (message.kind == MessageKind.text) {
        // envelope id == message id → dedupe on the other side, and one id
        // names the message across every device copy.
        final payload = _textPayload(message);
        await _deliver(
          contact,
          EnvelopeType.msg,
          payload,
          envelopeId: message.id,
          outbox: outbox,
        );
        await _settleSend(message, EnvelopeType.msg, payload);
      } else {
        final media = await _sealMedia(contact, message, mime: mime);
        await _deliver(
          contact,
          EnvelopeType.media,
          media.payload,
          envelopeId: message.id,
          blobId: media.blobId,
          outbox: outbox,
        );
        await _settleSend(message, EnvelopeType.media, media.payload);
      }
    } catch (e) {
      await _recordSendFailure(message, e);
    }
    notifyListeners();
  }

  // -- send outcomes (TODO.md §11 "Message reliability") -----------------------

  Timer? _retrySweep;

  /// Reasons a peer is unreachable are their business, not the user's — the
  /// message says what happened in words, and this is the fallback when an
  /// exception carries none worth showing.
  static String _reasonFor(Object error) {
    if (error is ApiException) return error.message;
    // A media retry whose local copy is gone: no amount of network fixes it,
    // and "check your connection" would send the user down the wrong path.
    if (error is FileSystemException) {
      return 'The file is no longer on this phone';
    }
    return "Couldn't send — check your connection";
  }

  Future<void> _recordSendSuccess(Message message) async {
    message.status = MessageStatus.sent;
    message.failReason = null;
    message.lastAttemptAt = DateTime.now().millisecondsSinceEpoch;
    for (final m in _cachedCopies(message)) {
      m
        ..status = message.status
        ..failReason = null;
    }
    await app.db.saveSendAttempt(message);
  }

  /// One attempt didn't land. Refusals are terminal on the spot — a directory
  /// or prekey that doesn't verify says the same thing on every retry — and
  /// everything else keeps its place in the queue until the give-up window
  /// closes. Either way the message now carries a reason the UI can show.
  Future<void> _recordSendFailure(
    Message message,
    Object error, {

    /// False for a partly-delivered group fan-out: one member refusing must
    /// not condemn a message four others already have. Only the give-up
    /// window fails those.
    bool mayBeTerminal = true,
  }) async {
    final now = DateTime.now().millisecondsSinceEpoch;
    // Terminal on the spot: a refusal, or media whose local copy is gone —
    // both say exactly the same thing on the hundredth try as on the first.
    final terminal =
        mayBeTerminal &&
        ((error is ApiException && error.refused) ||
            error is FileSystemException);
    message
      ..attempts += 1
      ..lastAttemptAt = now
      ..failReason = _reasonFor(error);
    if (terminal || now - message.sentAt >= sendGiveUpAfterMs) {
      message.status = MessageStatus.failed;
    }
    for (final m in _cachedCopies(message)) {
      m
        ..attempts = message.attempts
        ..lastAttemptAt = message.lastAttemptAt
        ..failReason = message.failReason
        ..status = message.status;
    }
    await app.db.saveSendAttempt(message);
    _scheduleRetrySweep();
  }

  /// True while this message is inside its backoff window — the sweep skips
  /// it rather than re-dialling a mailbox that just refused to answer.
  bool _backingOff(Message message) {
    final last = message.lastAttemptAt;
    if (last == null) return false;
    final wait = sendBackoffMs(message.attempts);
    return DateTime.now().millisecondsSinceEpoch - last < wait;
  }

  /// Retrying only on connect/wake/resume left a message stuck behind an
  /// event that might never come while the user watched. This keeps a slow
  /// heartbeat going for exactly as long as something is still owed.
  void _scheduleRetrySweep() {
    if (_retrySweep != null) return;
    _retrySweep = Timer(const Duration(seconds: 60), () async {
      _retrySweep = null;
      await retryPending();
      // Still owed? Keep the heartbeat. Otherwise it stops on its own.
      if (await _hasPendingWork()) _scheduleRetrySweep();
    });
  }

  Future<bool> _hasPendingWork() async =>
      (await app.db.pendingMessages()).isNotEmpty ||
      (await app.db.pendingOutbox()).isNotEmpty ||
      contacts.any((c) => c.status == ContactStatus.pendingOut);

  /// Put a given-up message back in the queue and try it now. The user asked,
  /// so the backoff and the attempt count start over.
  Future<void> retryMessage(Message message) async {
    if (!message.outgoing || message.deleted) return;
    message
      ..status = MessageStatus.pending
      ..attempts = 0
      ..lastAttemptAt = null
      ..failReason = null;
    for (final m in _cachedCopies(message)) {
      m
        ..status = MessageStatus.pending
        ..attempts = 0
        ..lastAttemptAt = null
        ..failReason = null;
    }
    await app.db.saveSendAttempt(message);
    notifyListeners();

    final group = groupById(message.contactId);
    if (group != null) {
      final owed = await app.db.pendingOutbox();
      final ids = owed[message.id] ?? const <String>[];
      final members = (groupMembers[group.id] ?? [])
          .where((m) => ids.contains(m.stonechatId))
          .toList();
      await _fanOut(group, message, members);
      return;
    }
    final contact = contactById(message.contactId);
    if (contact == null || contact.isBlocked) return;
    await _trySend(contact, message);
  }

  /// Media path: encrypt the file with a one-off key, park the ciphertext on
  /// the recipient's mailbox, and describe it in a small normal payload.
  ///
  /// Returns the payload rather than a sealed envelope: with per-device
  /// fan-out the same payload is sealed once per device, on that device's own
  /// ratchet. The blob is uploaded once regardless — every device envelope
  /// references the same `blob_id`, and the relay refcounts.
  Future<({Map<String, Object?> payload, String blobId})> _sealMedia(
    Contact contact,
    Message message, {
    String? mime,
  }) async {
    final bytes = await File(message.mediaPath!).readAsBytes();
    final blob = app.crypto.sealBlob(bytes);
    final address = await _addressFor(contact);
    final blobId = await uploadBlob(address, blob.ciphertext, contact.tlsFp!);

    final payload = {
      'blob_id': blobId,
      'key': base64Encode(blob.key),
      'blob_nonce': base64Encode(blob.nonce),
      'mime': mime ?? _mimeFromPath(message.mediaPath!),
      'kind': message.kind,
      'size': bytes.length,
      if (message.durationMs != null) 'duration_ms': message.durationMs,
      if (message.fileName != null) 'name': message.fileName,
      if (message.expiresAt != null)
        'expire_after_ms': message.expiresAt! - message.sentAt,
      if (_replyPayloadOf(message) != null)
        'reply_to': _replyPayloadOf(message),
    };
    return (payload: payload, blobId: blobId);
  }

  static String _mimeFromPath(String path) =>
      switch (p.extension(path).toLowerCase()) {
        '.jpg' || '.jpeg' => 'image/jpeg',
        '.png' => 'image/png',
        '.heic' => 'image/heic',
        '.webp' => 'image/webp',
        '.m4a' => 'audio/mp4',
        '.mp4' => 'video/mp4',
        '.mov' => 'video/quicktime',
        '.pdf' => 'application/pdf',
        _ => 'application/octet-stream',
      };

  /// The MessageKind an incoming media payload names — anything this build
  /// doesn't know renders as an image rather than nothing.
  static String _mediaKindOf(Map<String, dynamic> payload) =>
      switch (payload['kind']) {
        MessageKind.image ||
        MessageKind.audio ||
        MessageKind.video ||
        MessageKind.file ||
        MessageKind.sticker => payload['kind'] as String,
        _ => MessageKind.image,
      };

  /// A document's original filename, stripped to its basename — PROTOCOL.md
  /// requires receivers to drop any path components the sender put there.
  static String? _mediaNameOf(Map<String, dynamic> payload) {
    final name = payload['name'] as String?;
    return name == null ? null : p.basename(name);
  }

  /// Decrypt a downloaded media blob with the key from its (already
  /// session-decrypted) payload and write it into the media directory under
  /// the message's own id. Null if it doesn't open — a tampered blob.
  Future<String?> _persistMedia(
    String messageId,
    List<int> ciphertext,
    Map<String, dynamic> payload,
  ) async {
    final data = app.crypto.openBlob(
      Uint8List.fromList(ciphertext),
      base64Decode(payload['key'] as String),
      base64Decode(payload['blob_nonce'] as String),
    );
    if (data == null) return null;
    final kind = _mediaKindOf(payload);
    final name = payload['name'] as String?;
    final dir = await _mediaDir();
    // Documents keep their original extension so the OS opens them with the
    // right app; everything else derives it from the mime type.
    final ext = kind == MessageKind.file && name != null
        ? p.extension(name)
        : _extFromMime((payload['mime'] as String?) ?? '');
    final path = p.join(dir.path, '$messageId$ext');
    await File(path).writeAsBytes(data);
    return path;
  }

  /// Group media (PROTOCOL.md "Group media"): fetch the one shared blob from
  /// the *sender's* mailbox — pinned to the fingerprint they quoted — using
  /// the per-blob capability token they put in the payload.
  ///
  /// Returns null when the media is permanently unavailable: a malformed
  /// payload, a host that isn't the sender's own mailbox, a blob the sender
  /// already reclaimed or that aged past their relay's TTL, or ciphertext that
  /// doesn't open. A transient failure (their box down, no network) throws
  /// instead, so the envelope goes un-acked and we try again on the next drain.
  Future<String?> _fetchSharedMedia(
    Envelope envelope,
    GroupMember sender,
    Map<String, dynamic> payload,
  ) async {
    final host = payload['blob_host'] as String?;
    final tlsFp = payload['blob_tls_fp'] as String?;
    final blobId = payload['blob_id'] as String?;
    final token = payload['fetch_token'] as String?;
    if (host == null || tlsFp == null || blobId == null || token == null) {
      return null;
    }
    // The blob has to be on the sender's *own* mailbox. Without this a group
    // member could name any host in the payload and have our client go fetch
    // from it — the one field in this flow that points us somewhere new. A
    // sender who moved mailboxes mid-flight fails closed (media unavailable)
    // rather than teaching us to trust an unverified address.
    if (host != sender.mailboxAddress) {
      // Their directory entry may simply be stale here; a lookup failure is
      // transient and rethrows, so only a real mismatch is fatal.
      if (host != (await _resolve(sender.stonechatId)).mailboxAddress) {
        _dropLog(envelope, "blob_host is not the sender's own mailbox");
        return null;
      }
    }
    final List<int> ciphertext;
    try {
      ciphertext = await downloadBlob(host, blobId, token, tlsFp);
    } on ApiException catch (e) {
      // 404 gone, 401 token no longer accepted: neither improves with time.
      if (e.status == 404 || e.status == 410 || e.status == 401) return null;
      rethrow;
    }
    return _persistMedia(envelope.id, ciphertext, payload);
  }

  static String _extFromMime(String mime) => switch (mime) {
    'image/jpeg' => '.jpg',
    'image/png' => '.png',
    'image/heic' => '.heic',
    'image/webp' => '.webp',
    'audio/mp4' || 'audio/aac' => '.m4a',
    'video/mp4' => '.mp4',
    'video/quicktime' => '.mov',
    'application/pdf' => '.pdf',
    _ => '.bin',
  };

  Map<String, Object?> _textPayload(Message message) => {
    'text': message.text,
    if (message.expiresAt != null)
      'expire_after_ms': message.expiresAt! - message.sentAt,
    if (_replyPayloadOf(message) != null) 'reply_to': _replyPayloadOf(message),
  };

  /// Re-attempt everything in the pending outbox (app resume, reconnect, …).
  Future<void> retryPending() async {
    // A pending message that expired while we were offline must be purged
    // (and its outbox rows cleared) before the loop below could resend it.
    await sweepExpired();
    // Contact requests that never made it out (their mailbox was off when we
    // added them). Receivers dedupe by sender, so re-sending is safe.
    for (final contact in contacts.where(
      (c) => c.status == ContactStatus.pendingOut,
    )) {
      try {
        await _deliver(contact, EnvelopeType.contactRequest, _profilePayload());
      } catch (_) {
        // still unreachable — next retry will try again
      }
    }
    for (final message in await app.db.pendingMessages()) {
      final contact = contactById(message.contactId);
      // Blocked: hold their pending sends — they resume if ever unblocked.
      if (contact == null || contact.isBlocked) continue;
      final cached = _messages[message.contactId]
          ?.where((m) => m.id == message.id)
          .firstOrNull;
      final target = cached ?? message;
      if (await _giveUpIfStale(target)) continue;
      if (_backingOff(target)) continue;
      await _trySend(contact, target);
      if (cached == null) {
        lastMessage[message.contactId] = await app.db.lastMessageFor(
          message.contactId,
        );
      }
    }
    // Group fan-outs still owed to unreachable members.
    final outbox = await app.db.pendingOutbox();
    for (final entry in outbox.entries) {
      final message = await app.db.messageById(entry.key);
      if (message == null) continue;
      final group = groupById(message.contactId);
      if (group == null) continue;
      final cached = _messages[message.contactId]
          ?.where((m) => m.id == message.id)
          .firstOrNull;
      final target = cached ?? message;
      if (await _giveUpIfStale(target)) continue;
      if (_backingOff(target)) continue;
      final owed = (groupMembers[group.id] ?? [])
          .where((m) => entry.value.contains(m.stonechatId))
          .toList();
      if (owed.isNotEmpty) {
        await _fanOut(group, message, owed);
      }
    }
    await _reloadGroupOwed();
    if (await _hasPendingWork()) _scheduleRetrySweep();
  }

  /// A message past the give-up window stops being retried, even if the last
  /// attempt was long enough ago to be due — otherwise "we're still trying"
  /// would outlive any honest claim to it. Returns true when it just failed.
  Future<bool> _giveUpIfStale(Message message) async {
    if (message.status == MessageStatus.failed) return true;
    final now = DateTime.now().millisecondsSinceEpoch;
    if (now - message.sentAt < sendGiveUpAfterMs) return false;
    message.status = MessageStatus.failed;
    message.failReason ??= "Gave up after 7 days — they never came back online";
    for (final m in _cachedCopies(message)) {
      m
        ..status = MessageStatus.failed
        ..failReason = message.failReason;
    }
    await app.db.saveSendAttempt(message);
    return true;
  }

  // -- receipts (PROTOCOL.md "receipt") ----------------------------------------------

  /// Batch a receipt for [peerId]; flushed as one envelope per (peer, kind)
  /// a couple of seconds later. Receipts are best-effort by design: a lost
  /// one costs a stale checkmark, nothing more.
  void _queueReceipt(String peerId, String kind, String messageId) {
    // A blocked peer gets nothing from us — not even checkmarks. Local read
    // state still moves; only the receipt is withheld.
    if (contactById(peerId)?.isBlocked ?? false) return;
    ((_receiptQueue[peerId] ??= {})[kind] ??= <String>{}).add(messageId);
    _receiptFlushTimer ??= Timer(const Duration(seconds: 2), () {
      _receiptFlushTimer = null;
      unawaited(_flushReceipts());
    });
  }

  Future<void> _flushReceipts() async {
    final batch = Map.of(_receiptQueue);
    _receiptQueue.clear();
    for (final peer in batch.entries) {
      for (final kinds in peer.value.entries) {
        try {
          await _sendToPeer(peer.key, EnvelopeType.receipt, {
            'kind': kinds.key,
            'ids': kinds.value.toList(),
          }, noPush: true); // never wake their phone for a checkmark
        } catch (_) {
          // unreachable mailbox — drop; the next receipt supersedes this one
        }
      }
    }
  }

  /// Deliver to a peer we know either as a contact or as a fellow group
  /// member (receipts for group messages go pairwise to the sender, who need
  /// not be a direct contact).
  Future<void> _sendToPeer(
    String stonechatId,
    String type,
    Map<String, Object?> payload, {
    bool transient = false,
    bool noPush = false,
  }) async {
    final contact = contactById(stonechatId);
    if (contact != null) {
      await _deliver(
        contact,
        type,
        payload,
        transient: transient,
        noPush: noPush,
      );
      return;
    }
    for (final members in groupMembers.values) {
      for (final m in members) {
        if (m.stonechatId != stonechatId) continue;
        await _deliverToMember(
          m,
          type,
          payload,
          transient: transient,
          noPush: noPush,
        );
        return;
      }
    }
  }

  /// A peer told us which of our messages reached their screen. Statuses only
  /// move forward; group messages advance when *every* current member is
  /// there (per-member rows in the receipts table).
  Future<void> _applyReceipt(
    Envelope envelope,
    Map<String, dynamic> payload,
  ) async {
    final kind = payload['kind'] as String?;
    if (kind != ReceiptKind.delivered && kind != ReceiptKind.read) return;
    final ids =
        (payload['ids'] as List?)?.whereType<String>() ?? const <String>[];
    final now = DateTime.now().millisecondsSinceEpoch;
    for (final id in ids) {
      final message = await app.db.messageById(id);
      if (message == null || !message.outgoing) continue;
      final group = groupById(message.contactId);
      String? next;
      if (group == null) {
        // A DM receipt is only valid from the person the message went to.
        if (message.contactId != envelope.from) continue;
        next = kind == ReceiptKind.read
            ? MessageStatus.read
            : MessageStatus.delivered;
      } else {
        if (memberOf(group.id, envelope.from) == null) continue;
        await app.db.upsertReceipt(id, envelope.from, kind!, now);
        final others = (groupMembers[group.id] ?? [])
            .where((m) => m.stonechatId != app.stonechatId)
            .length;
        if (others == 0) continue;
        final counts = await app.db.receiptCounts(id);
        if (counts.read >= others) {
          next = MessageStatus.read;
        } else if (counts.delivered >= others) {
          next = MessageStatus.delivered;
        }
      }
      if (next == null ||
          MessageStatus.rank(next) <= MessageStatus.rank(message.status)) {
        continue;
      }
      await _setStatusEverywhere(message, next);
      // Everyone has it now: the shared blob behind a group-media fan-out has
      // nothing left to serve, so reclaim the space (PROTOCOL.md "Group
      // media"). Delivered is enough — read is about eyeballs, not bytes.
      if (message.blob != null &&
          MessageStatus.rank(next) >=
              MessageStatus.rank(MessageStatus.delivered)) {
        await _releaseSharedBlob(message);
      }
    }
  }

  /// DB row + whatever cached copies the UI is holding.
  Future<void> _setStatusEverywhere(Message message, String status) async {
    await app.db.setMessageStatus(message.id, status);
    message.status = status;
    _cachedCopies(message).forEach((m) => m.status = status);
  }

  /// The list cache and lastMessage may hold instances distinct from a
  /// DB-loaded one — mutations must reach all of them.
  List<Message> _cachedCopies(Message message) => [
    ...?_messages[message.contactId]?.where((m) => m.id == message.id),
    if (lastMessage[message.contactId]?.id == message.id)
      lastMessage[message.contactId]!,
  ];

  // -- typing indicators (PROTOCOL.md "typing") ---------------------------------------

  /// Peers currently typing in a conversation (Stonechat IDs), expired on read.
  List<String> typersIn(String conversationId) {
    final now = DateTime.now().millisecondsSinceEpoch;
    final peers = _typing[conversationId];
    if (peers == null) return const [];
    peers.removeWhere((_, until) => until <= now);
    return peers.keys.toList();
  }

  /// Called on every keystroke; throttled to one "started" per ~8s. Only
  /// rides existing sessions — a typing hint is never worth an X3DH.
  Future<void> notifyTyping(String conversationId) async {
    if (!app.sendTypingIndicators) return;
    final now = DateTime.now().millisecondsSinceEpoch;
    if (now - (_typingSentAt[conversationId] ?? 0) < _typingRefreshMs) return;
    _typingSentAt[conversationId] = now;
    await _sendTypingState(conversationId, 'started');
  }

  Future<void> stopTyping(String conversationId) async {
    if (_typingSentAt.remove(conversationId) == null) return;
    await _sendTypingState(conversationId, 'stopped');
  }

  Future<void> _sendTypingState(String conversationId, String state) async {
    try {
      final group = groupById(conversationId);
      if (group == null) {
        final contact = contactById(conversationId);
        if (contact == null || !contact.isAccepted || contact.isBlocked) {
          return;
        }
        if (!((await _loadSession(
              contact.stonechatId,
              ChatDb.primaryDevice,
            ))?.canSend ??
            false)) {
          return;
        }
        await _deliver(contact, EnvelopeType.typing, {
          'state': state,
        }, transient: true);
      } else {
        final payload = {'group_id': group.id, 'state': state};
        await _fanOutToMembers(_othersIn(group.id), (m) async {
          // Only rides existing sessions — a typing hint is never worth an
          // X3DH, so members we've never spoken to are skipped.
          if (!((await _loadSession(
                m.stonechatId,
                ChatDb.primaryDevice,
              ))?.canSend ??
              false)) {
            return;
          }
          await _deliverToMember(
            m,
            EnvelopeType.typing,
            payload,
            transient: true,
          );
        });
      }
    } catch (_) {
      // fire-and-forget: a lost typing signal costs nothing
    }
  }

  void _applyTyping(Envelope envelope, Map<String, dynamic> payload) {
    final String conversationId;
    final groupId = payload['group_id'] as String?;
    if (groupId != null) {
      if (groupById(groupId) == null ||
          memberOf(groupId, envelope.from) == null) {
        return;
      }
      conversationId = groupId;
    } else {
      final contact = contactById(envelope.from);
      if (contact == null || !contact.isAccepted) return;
      conversationId = envelope.from;
    }
    final now = DateTime.now().millisecondsSinceEpoch;
    // Transient envelopes only arrive live, but guard against clock skew.
    if ((now - _sentAtMs(envelope)).abs() > 60 * 1000) return;
    if (payload['state'] == 'started') {
      (_typing[conversationId] ??= {})[envelope.from] = now + _typingTtlMs;
      _scheduleTypingSweep();
    } else {
      _typing[conversationId]?.remove(envelope.from);
    }
  }

  /// Repaint listeners when a stale "typing" entry expires without an
  /// explicit "stopped".
  void _scheduleTypingSweep() {
    _typingSweep ??= Timer(const Duration(seconds: 5), () {
      _typingSweep = null;
      final now = DateTime.now().millisecondsSinceEpoch;
      for (final peers in _typing.values) {
        peers.removeWhere((_, until) => until <= now);
      }
      if (_typing.values.any((peers) => peers.isNotEmpty)) {
        _scheduleTypingSweep();
      }
      notifyListeners();
    });
  }

  // -- edit / delete (PROTOCOL.md "msg_edit" / "msg_delete") --------------------------

  bool canEdit(Message m) =>
      m.outgoing &&
      !m.deleted &&
      m.kind == MessageKind.text &&
      DateTime.now().millisecondsSinceEpoch - m.sentAt < _editWindowMs;

  bool canDeleteForEveryone(Message m) =>
      m.outgoing &&
      !m.deleted &&
      DateTime.now().millisecondsSinceEpoch - m.sentAt < _editWindowMs;

  /// Edit an outgoing message. Returns false when some recipient could not
  /// be told (they keep the old text until their mailbox is reachable —
  /// there is no durable retry for edits, matching their best-effort tier).
  Future<bool> editMessage(Message message, String newText) async {
    final text = newText.trim();
    if (text.isEmpty || text == message.text || !canEdit(message)) return true;
    final group = groupById(message.contactId);
    final stillPending = message.status == MessageStatus.pending;
    // A message that never left the phone just gets rewritten: the pending
    // retry ships the new text, no edit envelope, no "edited" tag.
    final editedAt = (stillPending && group == null)
        ? null
        : DateTime.now().millisecondsSinceEpoch;
    message.text = text;
    message.editedAt = editedAt ?? message.editedAt;
    await app.db.setMessageText(message.id, text, editedAt);
    for (final m in _cachedCopies(message)) {
      m.text = text;
      m.editedAt = message.editedAt;
    }
    notifyListeners();
    if (stillPending && group == null) return true;

    var reachedEveryone = true;
    if (group == null) {
      final contact = contactById(message.contactId);
      if (contact == null) return false;
      try {
        await _deliver(contact, EnvelopeType.msgEdit, {
          'id': message.id,
          'text': text,
        });
      } catch (_) {
        reachedEveryone = false;
      }
    } else {
      final payload = {'group_id': group.id, 'id': message.id, 'text': text};
      reachedEveryone = await _fanOutToMembers(
        _othersIn(group.id),
        (m) async => _deliverToMember(m, EnvelopeType.groupMsgEdit, payload),
      );
    }
    return reachedEveryone;
  }

  /// Delete-for-everyone: tombstone locally, announce to recipients.
  /// Cooperative like Signal's — an honest client blanks it, that's all.
  Future<bool> deleteMessageForEveryone(Message message) async {
    if (!canDeleteForEveryone(message)) return true;
    final group = groupById(message.contactId);
    final neverLeft = message.status == MessageStatus.pending && group == null;
    await _tombstone(message);
    await app.db.clearOutboxMessage(message.id); // stop owing group copies
    notifyListeners();
    if (neverLeft) return true;

    var reachedEveryone = true;
    if (group == null) {
      final contact = contactById(message.contactId);
      if (contact == null) return false;
      try {
        await _deliver(contact, EnvelopeType.msgDelete, {'id': message.id});
      } catch (_) {
        reachedEveryone = false;
      }
    } else {
      final payload = {'group_id': group.id, 'id': message.id};
      reachedEveryone = await _fanOutToMembers(
        _othersIn(group.id),
        (m) async => _deliverToMember(m, EnvelopeType.groupMsgDelete, payload),
      );
    }
    return reachedEveryone;
  }

  /// Delete-for-me: purely local, any message.
  Future<void> deleteMessageForMe(Message message) async {
    await _removeMediaFile(message);
    await app.db.deleteMessage(message.id);
    await app.db.clearOutboxMessage(message.id);
    reactionsByMessage.remove(message.id);
    _messages[message.contactId]?.removeWhere((m) => m.id == message.id);
    if (lastMessage[message.contactId]?.id == message.id) {
      lastMessage[message.contactId] = await app.db.lastMessageFor(
        message.contactId,
      );
    }
    notifyListeners();
  }

  Future<void> _tombstone(Message message) async {
    await _removeMediaFile(message);
    await app.db.tombstoneMessage(message.id);
    await app.db.clearReactions(message.id);
    reactionsByMessage.remove(message.id);
    for (final m in [message, ..._cachedCopies(message)]) {
      m.deleted = true;
      m.text = '';
      m.mediaPath = null;
    }
  }

  /// Drop a message's local file — and, for outgoing group media, the shared
  /// copy still parked on our mailbox: once the message is gone here there is
  /// nobody left we owe it to.
  Future<void> _removeMediaFile(Message message) async {
    await _releaseSharedBlob(message);
    final path = message.mediaPath;
    if (path == null) return;
    try {
      await File(path).delete();
    } catch (_) {}
  }

  // -- disappearing messages (PROTOCOL.md "Disappearing messages") -------------------

  Timer? _expirySweep;

  /// The conversation's current timer (0 = off).
  int expireTimerFor(String conversationId) =>
      groupById(conversationId)?.expireTimerMs ??
      contactById(conversationId)?.expireTimerMs ??
      0;

  /// Set the per-conversation timer, drop a local notice, announce to the
  /// peer(s). Best-effort like edits: no durable retry, an unreachable
  /// member keeps the old timer until someone changes it again.
  Future<void> setExpireTimer(String conversationId, int expireMs) async {
    final group = groupById(conversationId);
    final contact = group == null ? contactById(conversationId) : null;
    if (group == null && contact == null) return;
    if ((group?.expireTimerMs ?? contact!.expireTimerMs) == expireMs) return;

    final now = DateTime.now().millisecondsSinceEpoch;
    if (group != null) {
      group.expireTimerMs = expireMs;
      group.expireTimerAt = now;
      await app.db.upsertGroup(group);
    } else {
      contact!.expireTimerMs = expireMs;
      contact.expireTimerAt = now;
      await app.db.upsertContact(contact);
    }
    await _insertNotice(conversationId, _timerNoticeText('You', expireMs));

    if (group != null) {
      final payload = {'group_id': group.id, 'expire_ms': expireMs};
      await _fanOutToMembers(
        _othersIn(group.id),
        (m) async =>
            _deliverToMember(m, EnvelopeType.groupTimerUpdate, payload),
      );
    } else {
      try {
        await _deliver(contact!, EnvelopeType.timerUpdate, {
          'expire_ms': expireMs,
        });
      } catch (_) {}
    }
  }

  static String _timerNoticeText(String who, int expireMs) => expireMs > 0
      ? '$who set disappearing messages to ${ExpireTimer.label(expireMs)}'
      : '$who turned off disappearing messages';

  /// A system line in the conversation. Like call epitaphs, it's local-only
  /// bookkeeping — every device writes its own — so no receipts, and it
  /// never expires. Passing the envelope id as [id] makes redelivered
  /// announcements idempotent (insertMessage ignores conflicts).
  Future<void> _insertNotice(
    String conversationId,
    String text, {
    String? id,
  }) async {
    final message = Message(
      id: id ?? _uuid.v4(),
      contactId: conversationId,
      outgoing: false,
      text: text,
      kind: MessageKind.notice,
      sentAt: DateTime.now().millisecondsSinceEpoch,
      status: MessageStatus.read,
    );
    await app.db.insertMessage(message);
    final cache = _messages[conversationId];
    if (cache != null && !cache.any((m) => m.id == message.id)) {
      cache.add(message);
    }
    lastMessage[conversationId] = message;
    notifyListeners();
  }

  /// Purge every disappearing message past its expiry — same full cleanup as
  /// delete-for-me, no tombstone residue — then re-aim at the next one.
  /// Safe to call from anywhere, any time.
  Future<void> sweepExpired() async {
    final now = DateTime.now().millisecondsSinceEpoch;
    final expired = await app.db.expiredMessages(now);
    for (final m in expired) {
      await _removeMediaFile(m);
      await app.db.deleteMessage(m.id); // row + receipts + reactions
      await app.db.clearOutboxMessage(m.id); // stop owing undelivered copies
      reactionsByMessage.remove(m.id);
      _messages[m.contactId]?.removeWhere((x) => x.id == m.id);
      if (lastMessage[m.contactId]?.id == m.id) {
        lastMessage[m.contactId] = await app.db.lastMessageFor(m.contactId);
      }
    }
    if (expired.isNotEmpty) notifyListeners();
    _scheduleExpirySweep();
  }

  /// One-shot timer aimed at the soonest expiry. Cancel-and-replace (not the
  /// typing sweep's ??=): a just-arrived 1-hour message must not wait behind
  /// an already-scheduled 7-day target. Capped at an hour so long timers
  /// re-check periodically while the app is foregrounded.
  void _scheduleExpirySweep() {
    unawaited(() async {
      final next = await app.db.nextExpiryAt();
      _expirySweep?.cancel();
      _expirySweep = null;
      if (next == null) return;
      final now = DateTime.now().millisecondsSinceEpoch;
      final delay = (next - now).clamp(1000, 3600 * 1000).toInt();
      _expirySweep = Timer(
        Duration(milliseconds: delay),
        () => unawaited(sweepExpired()),
      );
    }());
  }

  /// The peer edited one of their messages. The session already authenticated
  /// them; what's left is checking the target is really theirs.
  Future<void> _applyRemoteEdit(
    Envelope envelope,
    Map<String, dynamic> payload, {
    bool group = false,
  }) async {
    final message = await _remoteEditTarget(envelope, payload, group: group);
    final text = (payload['text'] as String?)?.trim();
    if (message == null || text == null || text.isEmpty) return;
    if (message.kind != MessageKind.text) return;
    final editedAt = _sentAtMs(envelope);
    await app.db.setMessageText(message.id, text, editedAt);
    for (final m in [message, ..._cachedCopies(message)]) {
      m.text = text;
      m.editedAt = editedAt;
    }
  }

  Future<void> _applyRemoteDelete(
    Envelope envelope,
    Map<String, dynamic> payload, {
    bool group = false,
  }) async {
    final message = await _remoteEditTarget(envelope, payload, group: group);
    if (message == null) return;
    await _tombstone(message);
  }

  /// Shared validation for msg_edit / msg_delete: the referenced message must
  /// exist, be incoming, belong to the right conversation, have been written
  /// by the envelope's (session-authenticated) sender, and still be inside
  /// the edit window plus receiver-side grace.
  Future<Message?> _remoteEditTarget(
    Envelope envelope,
    Map<String, dynamic> payload, {
    required bool group,
  }) async {
    final id = payload['id'] as String?;
    if (id == null) return null;
    final message = await app.db.messageById(id);
    if (message == null || message.outgoing || message.deleted) return null;
    if (group) {
      final groupId = payload['group_id'] as String?;
      if (groupId == null || message.contactId != groupId) return null;
      if (groupById(groupId) == null) return null;
      if (memberOf(groupId, envelope.from) == null) return null;
      if (message.senderId != envelope.from) return null;
    } else {
      if (message.contactId != envelope.from) return null;
    }
    if (_sentAtMs(envelope) - message.sentAt > _editWindowMs + _editGraceMs) {
      return null;
    }
    return message;
  }

  // -- reactions (PROTOCOL.md "reaction") ---------------------------------------------

  String? myReactionTo(Message message) =>
      reactionsByMessage[message.id]?[app.stonechatId];

  /// Set (or, when tapping the same emoji again, clear) our reaction on a
  /// message. One reaction per person per message; a new one replaces the old.
  Future<void> react(Message message, String emoji) async {
    if (message.deleted) return;
    // A blocked DM is read-only: nothing may leave for that peer.
    if (groupById(message.contactId) == null &&
        (contactById(message.contactId)?.isBlocked ?? false)) {
      return;
    }
    final applied = myReactionTo(message) == emoji ? '' : emoji;
    final now = DateTime.now().millisecondsSinceEpoch;
    await app.db.setReaction(message.id, app.stonechatId!, applied, now);
    _recordReaction(message.id, app.stonechatId!, applied);
    notifyListeners();

    final payload = {'id': message.id, 'emoji': applied};
    final group = groupById(message.contactId);
    try {
      if (group == null) {
        final contact = contactById(message.contactId);
        if (contact == null) return;
        await _deliver(contact, EnvelopeType.reaction, payload);
      } else {
        final groupPayload = {...payload, 'group_id': group.id};
        // Best-effort, like receipts.
        await _fanOutToMembers(
          _othersIn(group.id),
          (m) async =>
              _deliverToMember(m, EnvelopeType.groupReaction, groupPayload),
        );
      }
    } catch (_) {
      // unreachable peer keeps the stale (or no) reaction — best-effort tier
    }
  }

  void _recordReaction(String messageId, String peerId, String emoji) {
    if (emoji.isEmpty) {
      reactionsByMessage[messageId]?.remove(peerId);
    } else {
      (reactionsByMessage[messageId] ??= {})[peerId] = emoji;
    }
  }

  Future<void> _applyRemoteReaction(
    Envelope envelope,
    Map<String, dynamic> payload, {
    bool group = false,
  }) async {
    final id = payload['id'] as String?;
    final emoji = payload['emoji'] as String?;
    // 32 UTF-16 units of headroom: ZWJ sequences (families, skin-tone
    // couples) run well past a single code point.
    if (id == null || emoji == null || emoji.length > 32) return;
    final message = await app.db.messageById(id);
    if (message == null || message.deleted) return;
    if (group) {
      final groupId = payload['group_id'] as String?;
      if (groupId == null || message.contactId != groupId) return;
      if (groupById(groupId) == null ||
          memberOf(groupId, envelope.from) == null) {
        return;
      }
    } else {
      // Either side of a DM may react; both directions live in the
      // conversation keyed by the peer — which must be the sender.
      if (message.contactId != envelope.from) return;
    }
    await app.db.setReaction(id, envelope.from, emoji, _sentAtMs(envelope));
    _recordReaction(id, envelope.from, emoji);
  }

  // -- calls (PROTOCOL.md "Calls") ----------------------------------------------------

  /// Send one call-signaling envelope on the pairwise session. Used only by
  /// CallState; delivery failures propagate so the call fails fast.
  Future<void> sendCallSignal(
    Contact contact,
    String type,
    Map<String, Object?> payload, {
    bool transient = false,
    bool ring = false,
  }) async {
    await _deliver(contact, type, payload, transient: transient, ring: ring);
  }

  /// A call's epitaph in the conversation ("Missed voice call",
  /// "Video call · 3:42"). Local-only bookkeeping — both sides write their
  /// own — so no receipts are queued for it.
  Future<void> recordCallEvent(
    Contact contact,
    String label, {
    required bool outgoing,
  }) async {
    final message = Message(
      id: _uuid.v4(),
      contactId: contact.stonechatId,
      outgoing: outgoing,
      text: label,
      kind: MessageKind.call,
      sentAt: DateTime.now().millisecondsSinceEpoch,
      status: MessageStatus.read,
    );
    await app.db.insertMessage(message);
    final cache = _messages[contact.stonechatId];
    if (cache != null) cache.add(message);
    lastMessage[contact.stonechatId] = message;
    notifyListeners();
  }

  // -- receiving ---------------------------------------------------------------------

  /// Called by the mailbox socket for every envelope. Returning normally acks
  /// (and thus deletes) it mailbox-side, so persist before returning.
  Future<void> handleIncoming(SealedEnvelope wire) async {
    if (wire.to != app.stonechatId) return;

    // Unwrap the transport seal; anything not sealed to this identity is
    // dropped (and acked — same silent-drop rule as a failed session).
    final Envelope envelope;
    try {
      final inner = app.crypto.unseal(
        app.deviceKeys!.sealSeed,
        Uint8List.fromList(base64Decode(wire.sealedB64)),
      );
      if (inner == null) {
        debugPrint('stonechat: dropped envelope ${wire.id}: not sealed to us');
        return;
      }
      envelope = Envelope.fromJson(
        jsonDecode(utf8.decode(inner)) as Map<String, dynamic>,
      );
    } catch (_) {
      debugPrint('stonechat: dropped envelope ${wire.id}: malformed seal');
      return;
    }
    if (envelope.to != app.stonechatId) return;

    var contact = contactById(envelope.from);

    // Decryption is the authentication: the session (or the x3dh block's
    // commitment-verified identity key) proves the sender holds the `from`
    // ID's private key.
    final plaintext = await _openEnvelope(envelope);
    if (plaintext == null) return; // forged, corrupted, or no session — drop

    final payload = jsonDecode(plaintext) as Map<String, dynamic>;

    // Anything they send tells us how to list their devices. Recorded before
    // the type switch so it is learned even from traffic we go on to drop.
    await _noteBundleToken(envelope.from, envelope.bundleToken);

    // Blocked senders: their DM traffic and calls stop at the door. Decrypt
    // first (above) so the ratchet stays current for a later unblock; group
    // envelopes still flow — leaving the group is the remedy there.
    if (contact != null && contact.isBlocked) {
      switch (envelope.type) {
        case EnvelopeType.contactRequest ||
            EnvelopeType.msg ||
            EnvelopeType.media ||
            EnvelopeType.typing ||
            EnvelopeType.msgEdit ||
            EnvelopeType.msgDelete ||
            EnvelopeType.reaction ||
            EnvelopeType.profileUpdate ||
            EnvelopeType.timerUpdate ||
            EnvelopeType.callOffer ||
            EnvelopeType.callAnswer ||
            EnvelopeType.callIce ||
            EnvelopeType.callEnd:
          _dropLog(envelope, 'sender is blocked');
          return;
      }
    }

    switch (envelope.type) {
      case EnvelopeType.contactRequest:
        if (contact != null) {
          // Simultaneous add: we requested them too — two requests crossing
          // is mutual consent, so accept instead of deadlocking on
          // "duplicate". Same answer if we'd already accepted: our earlier
          // accept may have been lost (their reinstall), so re-affirm.
          if (contact.status == ContactStatus.pendingOut ||
              contact.isAccepted) {
            contact.status = ContactStatus.accepted;
            contact.hub = _peerHubFrom(payload) ?? contact.hub;
            contact.displayName =
                (payload['display_name'] as String?) ?? contact.displayName;
            if (_applyAvatar(contact, payload)) {
              contact.profileAt = _sentAtMs(envelope);
            }
            await app.db.upsertContact(contact);
            await _deliver(
              contact,
              EnvelopeType.contactAccept,
              _profilePayload(),
            );
            break;
          }
          _dropLog(
            envelope,
            'duplicate contact request (already ${contact.status})',
          );
          return;
        }
        // Identity key: the (already commitment-verified) x3dh block if this
        // was a session-opening message, else the directory (the sender's own
        // hub when the request names one), best-effort.
        final senderHub = _peerHubFrom(payload);
        final senderEntry = await _resolveOrNull(envelope.from, hub: senderHub);
        final pubkeyB64 =
            (envelope.x3dh?['ik'] as String?) ?? senderEntry?.pubkeyB64;
        if (pubkeyB64 == null) return; // unresolvable sender — drop
        contact = Contact(
          stonechatId: envelope.from,
          displayName:
              (payload['display_name'] as String?) ??
              envelope.from.substring(3, 12),
          pubkeyB64: pubkeyB64,
          // May be null when the directory was unreachable; _deliver
          // backfills it (sig-verified) before anything is sealed to them.
          pqPkB64: senderEntry?.pqPkB64,
          status: ContactStatus.pendingIn,
          mailboxAddress: senderEntry?.mailboxAddress,
          tlsFp: senderEntry?.mailboxTlsFp,
          hub: senderHub,
          createdAt: DateTime.now().millisecondsSinceEpoch,
        );
        if (_applyAvatar(contact, payload)) {
          contact.profileAt = _sentAtMs(envelope);
        }
        await app.db.upsertContact(contact);
        contacts.add(contact);

      case EnvelopeType.contactAccept:
        if (contact == null || contact.status != ContactStatus.pendingOut) {
          return;
        }
        contact.status = ContactStatus.accepted;
        contact.hub = _peerHubFrom(payload) ?? contact.hub;
        contact.displayName =
            (payload['display_name'] as String?) ?? contact.displayName;
        if (_applyAvatar(contact, payload)) {
          contact.profileAt = _sentAtMs(envelope);
        }
        await app.db.upsertContact(contact);
        // Tell the requester their invite was accepted. Only when backgrounded
        // — a foregrounded user watches the contact flip live. Best-effort, and
        // bound by the same platform limits as any local notice: iOS may be
        // suspended before we drain (see core/notices.dart).
        if (WidgetsBinding.instance.lifecycleState !=
            AppLifecycleState.resumed) {
          onNotice?.call(
            'Request accepted',
            '${contact.displayName} accepted your request',
          );
        }

      case EnvelopeType.profileUpdate:
        if (contact == null || !contact.isAccepted) {
          _dropLog(envelope, 'profile update from non-accepted contact');
          return;
        }
        // Last-writer-wins, like timer_update: a replayed or out-of-order
        // profile never regresses the one we hold.
        if (_sentAtMs(envelope) <= contact.profileAt) return;
        final name = payload['display_name'];
        if (name is String && name.trim().isNotEmpty) {
          contact.displayName = name.trim();
        }
        _applyAvatar(contact, payload);
        contact.profileAt = _sentAtMs(envelope);
        await app.db.upsertContact(contact);

      case EnvelopeType.msg:
        if (contact == null || !contact.isAccepted) {
          _dropLog(
            envelope,
            'msg from non-accepted contact — strangers cannot chat',
          );
          return;
        }
        final (replyId, replySender, replyPreview) = _replyFrom(payload);
        await _storeIncoming(
          contact,
          Message(
            id: envelope.id,
            contactId: contact.stonechatId,
            outgoing: false,
            text: (payload['text'] as String?) ?? '',
            sentAt: _sentAtMs(envelope),
            status: MessageStatus.sent,
            expiresAt: _expiresAtFrom(envelope, payload),
            replyToId: replyId,
            replyToSender: replySender,
            replyToPreview: replyPreview,
          ),
        );

      case EnvelopeType.media:
        if (contact == null || !contact.isAccepted) return;
        // Fetch + decrypt + persist BEFORE returning: returning acks the
        // envelope, which deletes the blob from our mailbox.
        if (mailboxAddress == null ||
            mailboxToken == null ||
            mailboxTlsFp == null) {
          throw StateError('mailbox info missing'); // don't ack — retry later
        }
        final ciphertext = await downloadBlob(
          mailboxAddress!,
          payload['blob_id'] as String,
          mailboxToken!,
          mailboxTlsFp!,
        );
        final path = await _persistMedia(envelope.id, ciphertext, payload);
        if (path == null) return; // tampered blob — drop
        final (replyId, replySender, replyPreview) = _replyFrom(payload);
        await _storeIncoming(
          contact,
          Message(
            id: envelope.id,
            contactId: contact.stonechatId,
            outgoing: false,
            text: '',
            kind: _mediaKindOf(payload),
            mediaPath: path,
            durationMs: payload['duration_ms'] as int?,
            fileName: _mediaNameOf(payload),
            sentAt: _sentAtMs(envelope),
            status: MessageStatus.sent,
            expiresAt: _expiresAtFrom(envelope, payload),
            replyToId: replyId,
            replyToSender: replySender,
            replyToPreview: replyPreview,
          ),
        );

      case EnvelopeType.groupCreate || EnvelopeType.groupUpdate:
        await _applyMembership(envelope, payload);

      case EnvelopeType.groupMsg:
        final group = groupById(payload['group_id'] as String? ?? '');
        if (group == null) return; // unknown group — drop (create not seen yet)
        if (memberOf(group.id, envelope.from) == null) return; // non-member
        final (replyId, replySender, replyPreview) = _replyFrom(payload);
        await _storeIncomingConversation(
          group.id,
          Message(
            id: envelope.id,
            contactId: group.id,
            senderId: envelope.from,
            outgoing: false,
            text: (payload['text'] as String?) ?? '',
            sentAt: _sentAtMs(envelope),
            status: MessageStatus.sent,
            expiresAt: _expiresAtFrom(envelope, payload),
            replyToId: replyId,
            replyToSender: replySender,
            replyToPreview: replyPreview,
          ),
        );

      case EnvelopeType.groupMedia:
        final group = groupById(payload['group_id'] as String? ?? '');
        if (group == null) return; // unknown group — drop (create not seen yet)
        final sender = memberOf(group.id, envelope.from);
        if (sender == null) return; // non-member
        // Fetch from the *sender's* mailbox with the capability token in the
        // payload, and persist BEFORE returning: returning acks the envelope.
        // A null path means the blob is provably gone — store the message
        // anyway (the bubble renders "unavailable") rather than refuse to ack
        // an envelope that can never succeed. Anything transient throws
        // instead, leaving it queued for the next drain.
        final path = await _fetchSharedMedia(envelope, sender, payload);
        final (replyId, replySender, replyPreview) = _replyFrom(payload);
        await _storeIncomingConversation(
          group.id,
          Message(
            id: envelope.id,
            contactId: group.id,
            senderId: envelope.from,
            outgoing: false,
            text: '',
            kind: _mediaKindOf(payload),
            mediaPath: path,
            durationMs: payload['duration_ms'] as int?,
            fileName: _mediaNameOf(payload),
            sentAt: _sentAtMs(envelope),
            status: MessageStatus.sent,
            expiresAt: _expiresAtFrom(envelope, payload),
            replyToId: replyId,
            replyToSender: replySender,
            replyToPreview: replyPreview,
          ),
        );

      case EnvelopeType.groupLeave:
        final group = groupById(payload['group_id'] as String? ?? '');
        if (group == null) return;
        final member = memberOf(group.id, envelope.from);
        if (member == null) {
          return; // only a member can announce their own leave
        }
        groupMembers[group.id]?.removeWhere(
          (m) => m.stonechatId == envelope.from,
        );
        await app.db.replaceMembers(
          group.id,
          groupMembers[group.id] ?? const [],
        );
        await _insertNotice(
          group.id,
          '${member.displayName} left',
          id: envelope.id,
        );

      case EnvelopeType.receipt:
        await _applyReceipt(envelope, payload);

      // Self-sync only ever comes from us. The session already proves the
      // sender holds our identity key, and every one of our devices does —
      // so this check is what keeps a *peer* from writing our history.
      case EnvelopeType.syncSent:
        if (envelope.from != app.stonechatId) {
          _dropLog(envelope, 'sync from someone else\'s identity');
          return;
        }
        await _applySyncSent(envelope, payload);

      case EnvelopeType.syncRead:
        if (envelope.from != app.stonechatId) {
          _dropLog(envelope, 'sync from someone else\'s identity');
          return;
        }
        await _applySyncRead(payload);

      case EnvelopeType.syncClear:
        if (envelope.from != app.stonechatId) {
          _dropLog(envelope, 'sync from someone else\'s identity');
          return;
        }
        await _applySyncClear(payload);

      case EnvelopeType.typing:
        _applyTyping(envelope, payload);

      case EnvelopeType.msgEdit:
        if (contact == null || !contact.isAccepted) return;
        await _applyRemoteEdit(envelope, payload);

      case EnvelopeType.msgDelete:
        if (contact == null || !contact.isAccepted) return;
        await _applyRemoteDelete(envelope, payload);

      case EnvelopeType.groupMsgEdit:
        await _applyRemoteEdit(envelope, payload, group: true);

      case EnvelopeType.groupMsgDelete:
        await _applyRemoteDelete(envelope, payload, group: true);

      case EnvelopeType.reaction:
        if (contact == null || !contact.isAccepted) return;
        await _applyRemoteReaction(envelope, payload);

      case EnvelopeType.groupReaction:
        await _applyRemoteReaction(envelope, payload, group: true);

      case EnvelopeType.timerUpdate:
        if (contact == null || !contact.isAccepted) return;
        final ms = payload['expire_ms'];
        if (ms is! int || ms < 0) return;
        // Last-writer-wins: a replayed or out-of-order update never regresses
        // the setting (the session already authenticates the sender).
        if (_sentAtMs(envelope) <= contact.expireTimerAt) return;
        contact.expireTimerMs = ms;
        contact.expireTimerAt = _sentAtMs(envelope);
        await app.db.upsertContact(contact);
        await _insertNotice(
          contact.stonechatId,
          _timerNoticeText(contact.displayName, ms),
          id: envelope.id,
        );

      case EnvelopeType.groupTimerUpdate:
        final group = groupById(payload['group_id'] as String? ?? '');
        if (group == null) return;
        final member = memberOf(group.id, envelope.from);
        if (member == null) return; // only current members set the timer
        final ms = payload['expire_ms'];
        if (ms is! int || ms < 0) return;
        if (_sentAtMs(envelope) <= group.expireTimerAt) return;
        group.expireTimerMs = ms;
        group.expireTimerAt = _sentAtMs(envelope);
        await app.db.upsertGroup(group);
        await _insertNotice(
          group.id,
          _timerNoticeText(member.displayName, ms),
          id: envelope.id,
        );

      case EnvelopeType.callOffer ||
          EnvelopeType.callAnswer ||
          EnvelopeType.callIce ||
          EnvelopeType.callEnd:
        if (contact == null || !contact.isAccepted) return;
        await onCallSignal?.call(contact, envelope, payload);
    }
    notifyListeners();
  }

  /// group_create / group_update: full-state membership replacement.
  /// Only the admin's word counts, versions only move forward, and every
  /// member key must hash to its claimed ID (offline commitment check).
  Future<void> _applyMembership(
    Envelope envelope,
    Map<String, dynamic> payload,
  ) async {
    final groupId = payload['group_id'] as String?;
    final admin = payload['admin'] as String?;
    final name = payload['name'] as String?;
    final version = payload['version'] as int?;
    final rawMembers = payload['members'] as List?;
    if (groupId == null ||
        admin == null ||
        name == null ||
        version == null ||
        rawMembers == null) {
      return;
    }
    if (envelope.from != admin) return; // only the admin defines membership

    final existing = groupById(groupId);
    if (existing != null) {
      if (envelope.from != existing.adminId) return;
      if (version <= existing.version) return; // stale or replayed
    }

    final members = <GroupMember>[];
    var includesUs = false;
    for (final raw in rawMembers) {
      if (raw is! Map) return;
      final stonechatId = raw['stonechat_id'] as String?;
      final pubkey = raw['pubkey'] as String?;
      if (stonechatId == null || pubkey == null) return;
      if (!app.crypto.pubkeyMatchesId(pubkey, stonechatId)) {
        return; // forged key
      }
      if (stonechatId == app.stonechatId) includesUs = true;
      members.add(
        GroupMember(
          groupId: groupId,
          stonechatId: stonechatId,
          pubkeyB64: pubkey,
          displayName:
              (raw['display_name'] as String?) ?? stonechatId.substring(3, 12),
        ),
      );
    }
    if (!includesUs) {
      // we were removed — drop the group locally, keep history? for now: keep
      // nothing mailbox-side to worry about; just delete membership records
      if (existing != null) {
        groupMembers[groupId] = [];
        await app.db.replaceMembers(groupId, const []);
        await _insertNotice(
          groupId,
          'You were removed from this group',
          id: envelope.id,
        );
      }
      return;
    }

    // First sight of the group: adopt its current disappearing-messages
    // timer from the payload. Established members ignore the field — an
    // admin's membership fan-out must not clobber a newer member-set timer.
    final expireMs = payload['expire_ms'];
    final bootstrapTimer = existing == null && expireMs is int && expireMs > 0;
    final group = Group(
      id: groupId,
      name: name,
      adminId: admin,
      version: version,
      createdAt: existing?.createdAt ?? DateTime.now().millisecondsSinceEpoch,
      pinnedAt: existing?.pinnedAt, // upsert REPLACEs the row — keep the pin
      expireTimerMs: existing?.expireTimerMs ?? (bootstrapTimer ? expireMs : 0),
      expireTimerAt:
          existing?.expireTimerAt ?? (bootstrapTimer ? _sentAtMs(envelope) : 0),
      mutedUntil: existing?.mutedUntil, // local settings survive the REPLACE
      archivedAt: existing?.archivedAt,
    );
    final before = groupMembers[groupId] ?? const <GroupMember>[];
    final oldName = existing?.name;
    await app.db.upsertGroup(group);
    await app.db.replaceMembers(groupId, members);
    if (existing == null) {
      groups.add(group);
    } else {
      existing.name = name;
      existing.version = version;
    }
    groupMembers[groupId] = members;

    // Surface what changed (idempotent per envelope: notice ids derive from
    // it). First sight of the group renders no diff — it just appears.
    if (existing != null) {
      if (oldName != null && oldName != name) {
        await _insertNotice(
          groupId,
          'Group renamed to "$name"',
          id: '${envelope.id}-rename',
        );
      }
      for (final m in members) {
        if (m.stonechatId != app.stonechatId &&
            !before.any((b) => b.stonechatId == m.stonechatId)) {
          await _insertNotice(
            groupId,
            '${m.displayName} was added',
            id: '${envelope.id}-add-${m.stonechatId}',
          );
        }
      }
      for (final b in before) {
        if (b.stonechatId != app.stonechatId &&
            !members.any((m) => m.stonechatId == b.stonechatId)) {
          await _insertNotice(
            groupId,
            '${b.displayName} was removed',
            id: '${envelope.id}-rm-${b.stonechatId}',
          );
        }
      }
    }
  }

  Future<void> _storeIncomingConversation(
    String conversationId,
    Message message,
  ) async {
    // Their message just landed — whatever they were typing, this is it.
    final sender = message.senderId ?? conversationId;
    _typing[conversationId]?.remove(sender);

    final onScreen = _openConversationId == conversationId;
    if (onScreen) message.status = MessageStatus.read;
    await app.db.insertMessage(message);
    final cache = _messages[conversationId];
    if (cache != null && !cache.any((m) => m.id == message.id)) {
      cache.add(message);
      cache.sort((a, b) => a.sentAt.compareTo(b.sentAt));
    }
    lastMessage[conversationId] = message;
    if (message.expiresAt != null) _scheduleExpirySweep();

    // Tell the sender it arrived — "read" straight away if it's on screen
    // (and the privacy setting allows), else "delivered". Delivery receipts
    // are unconditional, Signal-style.
    _queueReceipt(
      sender,
      onScreen && app.sendReadReceipts
          ? ReceiptKind.read
          : ReceiptKind.delivered,
      message.id,
    );
  }

  static int _sentAtMs(Envelope envelope) =>
      DateTime.tryParse(envelope.sentAt)?.toLocal().millisecondsSinceEpoch ??
      DateTime.now().millisecondsSinceEpoch;

  /// Expiry from the message's own payload — authoritative over the local
  /// setting, so ordering races and offline queues can't skew it.
  static int? _expiresAtFrom(Envelope envelope, Map<String, dynamic> payload) {
    final after = payload['expire_after_ms'];
    return (after is int && after > 0) ? _sentAtMs(envelope) + after : null;
  }

  Future<void> _storeIncoming(Contact contact, Message message) =>
      _storeIncomingConversation(contact.stonechatId, message);

  Future<DirectoryEntry?> _resolveOrNull(
    String stonechatId, {
    String? hub,
  }) async {
    try {
      return await _resolve(stonechatId, hub: hub);
    } catch (_) {
      return null;
    }
  }

  @override
  void dispose() {
    _receiptFlushTimer?.cancel();
    _typingSweep?.cancel();
    _expirySweep?.cancel();
    _retrySweep?.cancel();
    super.dispose();
  }
}
