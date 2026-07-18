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
import '../core/links.dart';
import '../core/session.dart';
import '../models.dart';
import 'app_state.dart';

const _uuid = Uuid();

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

  // Own mailbox coordinates, set by ServerState before the socket connects —
  // needed to download incoming media blobs and publish prekeys.
  String? mailboxAddress;
  String? mailboxToken;
  String? mailboxTlsFp;

  // Forward-secret ratchet sessions, one per peer, cached over the DB copy.
  final Map<String, RatchetSession> _sessions = {};

  // The conversation currently on screen — its incoming messages are marked
  // read (and read-receipted) as they arrive.
  String? _openConversationId;

  // Call signaling hook, set by CallState: call_* envelopes from accepted
  // contacts are handed over instead of being handled here.
  Future<void> Function(
      Contact contact, Envelope envelope, Map<String, dynamic> payload)?
      onCallSignal;

  // Emoji reactions: message id → (reactor Zeon ID → emoji). Loaded per
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
  final Map<String, int> _typingSentAt = {}; // our own throttle, per conversation

  static const _typingRefreshMs = 8 * 1000; // resend "started" at most this often
  static const _typingTtlMs = 15 * 1000; // shown this long without a refresh
  static const _editWindowMs = 24 * 3600 * 1000; // sender-side edit/delete window
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

  void setMailbox(String? address, String? token, String? tlsFp) {
    mailboxAddress = address;
    mailboxToken = token;
    mailboxTlsFp = tlsFp;
    _registeredPushToken = null; // new mailbox → re-register the token
    _registerPush();
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
    await app.db.setContactPinned(c.zeonId, c.pinnedAt);
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
      lastMessage[c.zeonId] = await app.db.lastMessageFor(c.zeonId);
    }
    for (final g in groups) {
      groupMembers[g.id] = await app.db.membersOf(g.id);
      lastMessage[g.id] = await app.db.lastMessageFor(g.id);
    }
    notifyListeners();
    // Anything that expired while the app was closed vanishes before it can
    // be rendered (the sweep also fixes the previews it just loaded).
    unawaited(sweepExpired());
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
  /// cleared by ServerState.reset via setMailbox. The device push token
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

  GroupMember? memberOf(String groupId, String zeonId) {
    for (final m in groupMembers[groupId] ?? const <GroupMember>[]) {
      if (m.zeonId == zeonId) return m;
    }
    return null;
  }

  List<Message> messagesFor(String contactId) => _messages[contactId] ?? [];

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
    for (final m in _messages[conversationId] ?? const <Message>[]) {
      if (m.outgoing || m.status == MessageStatus.read) continue;
      m.status = MessageStatus.read;
      await app.db.setMessageStatus(m.id, MessageStatus.read);
      if (app.sendReadReceipts) {
        _queueReceipt(m.senderId ?? conversationId, ReceiptKind.read, m.id);
      }
    }
  }

  Contact? contactById(String zeonId) {
    for (final c in contacts) {
      if (c.zeonId == zeonId) return c;
    }
    return null;
  }

  // -- resolving peers ---------------------------------------------------------

  /// Directory lookup with the trust-but-verify steps from PROTOCOL.md: the
  /// pubkey must hash to the ID, and any listed mailbox must carry a TLS
  /// fingerprint signed by that pubkey. A server that fails the transport
  /// check is treated as absent — never connected to.
  ///
  /// Federation: a peer on another hub is resolved through *their* directory —
  /// [hub] when the caller has it (fresh invite, request payload), else the
  /// contact's stored home hub. The verification below is what makes asking a
  /// foreign hub safe: it can lie only into a failed lookup.
  Future<DirectoryEntry> _resolve(String zeonId, {String? hub}) async {
    final entry = await app.api
        .directory(zeonId, hubUrl: hub ?? contactById(zeonId)?.hub);
    if (!app.crypto.pubkeyMatchesId(entry.pubkeyB64, entry.zeonId)) {
      throw ApiException(
          'Directory returned a key that does not match this ID — refusing.');
    }
    if (entry.serverAddress != null) {
      final fp = entry.serverTlsFp;
      final sig = entry.serverTlsSig;
      final vouched = fp != null &&
          sig != null &&
          app.crypto.verifyTlsSig(
              fp, sig, Uint8List.fromList(base64Decode(entry.pubkeyB64)));
      if (!vouched) {
        return DirectoryEntry(
          zeonId: entry.zeonId,
          pubkeyB64: entry.pubkeyB64,
          // no owner-signed transport key yet → unreachable, not unpinned
        );
      }
    }
    return entry;
  }

  Future<String> _addressFor(Contact contact, {bool refresh = false}) async {
    if (!refresh && contact.serverAddress != null && contact.tlsFp != null) {
      return contact.serverAddress!;
    }
    final entry = await _resolve(contact.zeonId);
    if (entry.serverAddress == null) {
      throw ApiException(
          "${contact.displayName}'s mailbox is off right now — they'll get it when it's back");
    }
    contact.serverAddress = entry.serverAddress;
    contact.tlsFp = entry.serverTlsFp;
    await app.db.upsertContact(contact);
    return entry.serverAddress!;
  }

  /// Transport wrap (PROTOCOL.md "Envelope"): seal the whole envelope to the
  /// recipient's identity key. Their mailbox stores only {v, id, to, blob_id}
  /// plus an opaque box — it never learns who wrote to its owner.
  /// [transient] (typing, call ICE), [noPush] (receipts) and [ring] (call
  /// offers) are the delivery hints the mailbox is allowed to see.
  SealedEnvelope _wireSeal(Envelope envelope, String toPubkeyB64,
          {bool transient = false, bool noPush = false, bool ring = false}) =>
      SealedEnvelope(
        id: envelope.id,
        to: envelope.to,
        sealedB64: base64Encode(app.crypto.sealTo(
            Uint8List.fromList(base64Decode(toPubkeyB64)),
            utf8.encode(jsonEncode(envelope.toJson())))),
        blobId: envelope.blobId,
        transient: transient,
        noPush: noPush,
        ring: ring,
      );

  Future<void> _deliver(Contact contact, Envelope envelope,
      {bool transient = false, bool noPush = false, bool ring = false}) async {
    final wire = _wireSeal(envelope, contact.pubkeyB64,
        transient: transient, noPush: noPush, ring: ring);
    var address = await _addressFor(contact);
    try {
      await deliverEnvelope(address, wire, contact.tlsFp!);
    } on Exception {
      // Their server may have been recreated at a new IP (or with a new TLS
      // key) — refresh both and retry once.
      address = await _addressFor(contact, refresh: true);
      await deliverEnvelope(address, wire, contact.tlsFp!);
    }
  }

  // -- forward-secret sessions (PROTOCOL.md "Session crypto") --------------------

  Future<RatchetSession?> _loadSession(String peerId) async {
    final cached = _sessions[peerId];
    if (cached != null) return cached;
    final stateJson = await app.db.sessionState(peerId);
    if (stateJson == null) return null;
    final session = RatchetSession.fromJson(
        app.crypto, peerId, jsonDecode(stateJson) as Map<String, dynamic>);
    _sessions[peerId] = session;
    return session;
  }

  Future<void> _saveSession(RatchetSession session) async {
    _sessions[session.peerId] = session;
    await app.db.saveSession(session.peerId, jsonEncode(session.toJson()));
  }

  /// The session for an outgoing message, establishing one via the peer's
  /// prekey bundle when none exists yet.
  Future<RatchetSession> _sessionFor(String peerId, String peerPubkeyB64,
      {String? serverAddress, String? serverTlsFp}) async {
    final existing = await _loadSession(peerId);
    if (existing != null && existing.canSend) return existing;

    Future<PrekeyBundle> fetchFrom(String address, String tlsFp) async =>
        PrekeyBundle.fromJson(await fetchPrekeyBundle(address, tlsFp));

    PrekeyBundle bundle;
    try {
      if (serverAddress == null || serverTlsFp == null) {
        throw ApiException('no cached address');
      }
      bundle = await fetchFrom(serverAddress, serverTlsFp);
    } on Exception {
      // No cached address, or their mailbox moved — ask the directory.
      final entry = await _resolve(peerId);
      if (entry.serverAddress == null) {
        throw ApiException(
            "Their mailbox is off right now — they'll get it when it's back");
      }
      bundle = await fetchFrom(entry.serverAddress!, entry.serverTlsFp!);
    }

    final peerEd = Uint8List.fromList(base64Decode(peerPubkeyB64));
    if (!app.crypto.verifyPrekeySig(bundle.spkPub, bundle.spkSig, peerEd)) {
      throw ApiException(
          'Their mailbox served a forged prekey — refusing to send.');
    }
    final session =
        RatchetSession.initiate(app.crypto, peerId, peerEd, bundle);
    await _saveSession(session);
    return session;
  }

  Future<Envelope> _seal(
          String type, Contact contact, Map<String, Object?> payload) =>
      _sealFor(type, contact.zeonId, contact.pubkeyB64, payload,
          serverAddress: contact.serverAddress, serverTlsFp: contact.tlsFp);

  Future<Envelope> _sealFor(
    String type,
    String toZeonId,
    String toPubkeyB64,
    Map<String, Object?> payload, {
    String? envelopeId,
    String? serverAddress,
    String? serverTlsFp,
    String? blobId,
  }) async {
    final session = await _sessionFor(toZeonId, toPubkeyB64,
        serverAddress: serverAddress, serverTlsFp: serverTlsFp);
    final adPrefix = 'zeon/v1|${app.zeonId}|$toZeonId|$type';
    final sealed = session.encrypt(jsonEncode(payload), adPrefix);
    final x3dh = session.pendingX3dh?.toJson();
    // Persist the advanced chain before the envelope can leave: a crash after
    // send must never reuse a message key.
    await _saveSession(session);
    return Envelope(
      id: envelopeId ?? _uuid.v4(),
      type: type,
      from: app.zeonId!,
      to: toZeonId,
      sentAt: DateTime.now().toUtc().toIso8601String(),
      ratchet: sealed.ratchet,
      x3dh: x3dh,
      nonceB64: base64Encode(sealed.nonce),
      ciphertextB64: base64Encode(sealed.ciphertext),
      blobId: blobId,
    );
  }

  /// Decrypt an incoming envelope on the sender's session, establishing a
  /// responder session from the envelope's x3dh block when needed. Returns
  /// null (drop silently) for anything that doesn't verify.
  Future<String?> _openEnvelope(Envelope envelope) async {
    final adPrefix =
        'zeon/v1|${envelope.from}|${envelope.to}|${envelope.type}';
    final header = envelope.ratchet.cast<String, dynamic>();
    final nonce = Uint8List.fromList(base64Decode(envelope.nonceB64));
    final ciphertext =
        Uint8List.fromList(base64Decode(envelope.ciphertextB64));
    final block =
        X3dhBlock.fromJson(envelope.x3dh?.cast<String, dynamic>());
    final session = await _loadSession(envelope.from);

    if (session != null) {
      // Simultaneous add: both sides initiated. The lower Zeon ID's session
      // wins deterministically; if theirs wins, skip ours and adopt below.
      final theirsWins = block != null &&
          !session.confirmed &&
          session.initiatedByUs &&
          envelope.from.compareTo(app.zeonId!) < 0;
      if (!theirsWins) {
        final plain = session.decrypt(header, nonce, ciphertext, adPrefix);
        if (plain != null) {
          await _saveSession(session);
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

    // The identity key in the block must commit to the claimed sender.
    if (!app.crypto.pubkeyMatchesId(block.ikB64, envelope.from)) {
      _dropLog(envelope, 'x3dh identity key does not commit to sender id');
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
    final fresh = RatchetSession.respond(
      app.crypto,
      envelope.from,
      Uint8List.fromList(base64Decode(block.ikB64)),
      block,
      spkPub: Uint8List.fromList(base64Decode(spkRow['pub'] as String)),
      spkSec: Uint8List.fromList(base64Decode(spkRow['sec'] as String)),
      opkSec: opkRow == null
          ? null
          : Uint8List.fromList(base64Decode(opkRow['sec'] as String)),
    );
    final plain = fresh.decrypt(header, nonce, ciphertext, adPrefix);
    if (plain == null) {
      _dropLog(envelope, 'x3dh responder decrypt failed');
      return null;
    }
    if (block.opkId != null) {
      await app.db.deletePrekey(block.opkId!); // one-time means one time
    }
    await _saveSession(fresh); // replaces any prior session with this peer
    return plain;
  }

  /// Dropped envelopes are invisible by design (they're acked and deleted);
  /// leave a trace so "message never arrived" is diagnosable from logs.
  static void _dropLog(Envelope envelope, String reason) {
    debugPrint('zeon: dropped ${envelope.type} from '
        '${envelope.from.substring(0, 12)}…: $reason');
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

    var spkRow = await app.db.currentSpk();
    final now = DateTime.now().millisecondsSinceEpoch;
    if (spkRow == null || now - (spkRow['created_at'] as int) > _spkRotateMs) {
      final kp = app.crypto.newX25519();
      final sec = kp.secretKey.extractBytes();
      kp.secretKey.dispose();
      final id = await app.db.insertPrekey(
          'spk', base64Encode(kp.publicKey), base64Encode(sec));
      await app.db.pruneSpks();
      spkRow = await app.db.prekeyById(id, 'spk');
    }

    final existing = await app.db.opks();
    for (var i = existing.length; i < _opkTarget; i++) {
      final kp = app.crypto.newX25519();
      final sec = kp.secretKey.extractBytes();
      kp.secretKey.dispose();
      await app.db
          .insertPrekey('opk', base64Encode(kp.publicKey), base64Encode(sec));
    }

    // Upload the FULL remaining stock; the mailbox replaces its store with
    // it (PROTOCOL.md "Prekeys"). Consumed OPKs are deleted locally, so what
    // we hold is exactly what we can decrypt — this heals a mailbox left
    // holding keys from a previous install.
    final toPublish = await app.db.opks();
    final spkPubBytes =
        Uint8List.fromList(base64Decode(spkRow!['pub'] as String));
    await uploadPrekeys(
      address,
      token,
      tlsFp,
      {
        'id': spkRow['id'],
        'pub': spkRow['pub'],
        'sig': base64Encode(app.crypto.signPrekey(spkPubBytes)),
      },
      [
        for (final o in toPublish) {'id': o['id'], 'pub': o['pub']}
      ],
    );
  }

  /// Resolve + deliver to a group member (same trust-but-verify as contacts).
  Future<void> _deliverToMember(GroupMember member, Envelope envelope,
      {bool transient = false, bool noPush = false}) async {
    Future<String> resolve() async {
      final entry = await _resolve(member.zeonId);
      if (entry.serverAddress == null) {
        throw ApiException('${member.displayName} is unreachable right now');
      }
      member.serverAddress = entry.serverAddress;
      member.tlsFp = entry.serverTlsFp;
      await app.db.updateMember(member);
      return entry.serverAddress!;
    }

    final wire =
        _wireSeal(envelope, member.pubkeyB64, transient: transient, noPush: noPush);
    var address = (member.serverAddress != null && member.tlsFp != null)
        ? member.serverAddress!
        : await resolve();
    try {
      await deliverEnvelope(address, wire, member.tlsFp!);
    } on Exception {
      address = await resolve(); // their mailbox may have moved
      await deliverEnvelope(address, wire, member.tlsFp!);
    }
  }

  // -- profiles (PROTOCOL.md "Profiles") -------------------------------------------

  /// Our display name + current photo — what contact_request, contact_accept
  /// and profile_update carry. The avatar key is always present (null =
  /// cleared) so receivers converge on removals too. Federated builds also
  /// name our home hub, so a peer on another hub can resolve us back.
  Map<String, Object?> _profilePayload() => {
        'display_name': app.displayName,
        'avatar': app.avatar == null
            ? null
            : {'data': base64Encode(app.avatar!), 'mime': 'image/jpeg'},
        if (zeonFederation) 'hub': app.api.baseUrl,
      };

  /// A peer's home hub from a contact_request/accept payload: only under the
  /// federation flag, only http(s), and null when it's just our own hub. The
  /// URL is routing data from an E2EE-authenticated sender — a wrong one can
  /// only make lookups fail, never redirect trust (_resolve verifies).
  String? _peerHubFrom(Map<String, dynamic> payload) {
    if (!zeonFederation) return null;
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
            contact, await _seal(EnvelopeType.profileUpdate, contact, payload),
            noPush: true); // nobody's phone wakes for a photo swap
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

  /// Add by full ZC- ID, hub-tagged `ZC-…@host` code, or invite URL: resolve,
  /// verify, store, send an encrypted contact request.
  Future<Contact> addContact(String raw) async {
    final input = raw.trim();
    if (input.isEmpty) {
      throw const FormatException('Enter a Zeon code');
    }
    // Lookup is by full ZC- ID only (there are no handles). normalizeZeonId
    // validates the checksum locally and throws FormatException on garbage.
    final invite = zeonInviteFromInput(input) ?? (zeonId: input, hub: null);
    final query = app.crypto.normalizeZeonId(invite.zeonId);
    final hub = invite.hub == app.api.baseUrl ? null : invite.hub;
    if (hub != null && !zeonFederation) {
      throw const FormatException(
          'This invite lives on a different Zeon hub — this build only '
          'reaches people on yours');
    }

    final entry = await _resolve(query, hub: hub);
    if (entry.zeonId == app.zeonId) {
      throw ApiException("That's your own code");
    }
    if (contactById(entry.zeonId) != null) {
      throw ApiException('Already in your contacts');
    }
    final contact = Contact(
      zeonId: entry.zeonId,
      displayName: entry.zeonId.substring(3, 12),
      pubkeyB64: entry.pubkeyB64,
      status: ContactStatus.pendingOut,
      serverAddress: entry.serverAddress,
      tlsFp: entry.serverTlsFp,
      hub: hub,
      createdAt: DateTime.now().millisecondsSinceEpoch,
    );
    await app.db.upsertContact(contact);
    contacts.add(contact);
    notifyListeners();

    await _deliver(
      contact,
      await _seal(EnvelopeType.contactRequest, contact, _profilePayload()),
    );
    return contact;
  }

  /// Re-send a still-pending contact request (manual nudge from the
  /// Requests list; receivers dedupe by sender, so this is always safe).
  Future<void> resendRequest(Contact contact) async {
    await _deliver(
      contact,
      await _seal(EnvelopeType.contactRequest, contact, _profilePayload()),
    );
  }

  Future<void> acceptContact(Contact contact) async {
    contact.status = ContactStatus.accepted;
    await app.db.upsertContact(contact);
    notifyListeners();
    await _deliver(
      contact,
      await _seal(EnvelopeType.contactAccept, contact, _profilePayload()),
    );
  }

  Future<void> declineContact(Contact contact) async {
    await app.db.deleteContact(contact.zeonId);
    // Drop the ratchet too: a kept session would be silently reused if this
    // peer is ever re-added, and it may be pinned to prekeys the other side
    // no longer holds (the re-add does a fresh X3DH instead).
    await app.db.deleteSession(contact.zeonId);
    _sessions.remove(contact.zeonId);
    contacts.removeWhere((c) => c.zeonId == contact.zeonId);
    _messages.remove(contact.zeonId);
    notifyListeners();
  }

  // -- groups ----------------------------------------------------------------------

  Map<String, Object?> _membershipPayload(Group group, List<GroupMember> members) => {
        'group_id': group.id,
        'name': group.name,
        'version': group.version,
        'admin': group.adminId,
        'members': [
          for (final m in members)
            {
              'zeon_id': m.zeonId,
              'pubkey': m.pubkeyB64,
              'display_name': m.displayName,
            }
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
      adminId: app.zeonId!,
      version: 1,
      createdAt: DateTime.now().millisecondsSinceEpoch,
    );
    final members = <GroupMember>[
      GroupMember(
        groupId: group.id,
        zeonId: app.zeonId!,
        pubkeyB64: app.crypto.publicKeyB64,
        displayName: app.displayName ?? 'me',
      ),
      for (final c in selected)
        GroupMember(
          groupId: group.id,
          zeonId: c.zeonId,
          pubkeyB64: c.pubkeyB64,
          displayName: c.displayName,
          serverAddress: c.serverAddress,
          tlsFp: c.tlsFp,
        ),
    ];
    await app.db.upsertGroup(group);
    await app.db.replaceMembers(group.id, members);
    groups.add(group);
    groupMembers[group.id] = members;
    notifyListeners();

    final payload = _membershipPayload(group, members);
    for (final m in members.where((m) => m.zeonId != app.zeonId)) {
      try {
        await _deliverToMember(
            m,
            await _sealFor(EnvelopeType.groupCreate, m.zeonId, m.pubkeyB64,
                payload,
                serverAddress: m.serverAddress, serverTlsFp: m.tlsFp));
      } catch (_) {
        // unreachable member hears about the group via the next groupUpdate
        // or message retry; eventual delivery is accepted
      }
    }
    return group;
  }

  /// The quoted author's Zeon ID: us for our own messages, the group sender
  /// for group messages, the DM peer otherwise.
  String _quotedSenderOf(Message quoted) => quoted.outgoing
      ? app.zeonId!
      : (quoted.senderId ?? quoted.contactId);

  static String _clipPreview(String s) =>
      s.length <= _replyPreviewMax ? s : '${s.substring(0, _replyPreviewMax)}…';

  /// The wire form of a message's stored reply snapshot (PROTOCOL.md
  /// "reply_to"). Built from the message's own fields so pending-outbox
  /// retries carry exactly what the original send did.
  static Map<String, Object?>? _replyPayloadOf(Message m) =>
      m.replyToId == null
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
    if (group.adminId != app.zeonId) return;
    final current = groupMembers[group.id] ?? const <GroupMember>[];
    final added = [
      for (final c in addContacts)
        if (!current.any((m) => m.zeonId == c.zeonId)) c
    ];
    final removed =
        current.where((m) => removeIds.contains(m.zeonId)).toList();
    final newName = name?.trim();
    final renamed =
        newName != null && newName.isNotEmpty && newName != group.name;
    if (added.isEmpty && removed.isEmpty && !renamed) return;

    final members = <GroupMember>[
      for (final m in current)
        if (!removeIds.contains(m.zeonId)) m,
      for (final c in added)
        GroupMember(
          groupId: group.id,
          zeonId: c.zeonId,
          pubkeyB64: c.pubkeyB64,
          displayName: c.displayName,
          serverAddress: c.serverAddress,
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
      ...members.where((m) => m.zeonId != app.zeonId),
      ...removed,
    ];
    for (final m in recipients) {
      try {
        await _deliverToMember(
            m,
            await _sealFor(EnvelopeType.groupUpdate, m.zeonId, m.pubkeyB64,
                payload,
                serverAddress: m.serverAddress, serverTlsFp: m.tlsFp));
      } catch (_) {
        // unreachable member keeps the old view until the next update
      }
    }
  }

  Future<void> sendGroupMessage(Group group, String text,
      {Message? replyTo}) async {
    _typingSentAt.remove(group.id); // the message itself says "stopped typing"
    final members = (groupMembers[group.id] ?? [])
        .where((m) => m.zeonId != app.zeonId)
        .toList();
    final sentAt = DateTime.now().millisecondsSinceEpoch;
    final message = Message(
      id: _uuid.v4(),
      contactId: group.id,
      outgoing: true,
      text: text,
      sentAt: sentAt,
      status: MessageStatus.pending,
      expiresAt:
          group.expireTimerMs > 0 ? sentAt + group.expireTimerMs : null,
      replyToId: replyTo?.id,
      replyToSender: replyTo == null ? null : _quotedSenderOf(replyTo),
      replyToPreview: replyTo == null ? null : _clipPreview(replyTo.preview),
    );
    await app.db.insertMessage(message);
    await app.db.addOutbox(message.id, group.id, [for (final m in members) m.zeonId]);
    (_messages[group.id] ??= []).add(message);
    lastMessage[group.id] = message;
    if (message.expiresAt != null) _scheduleExpirySweep();
    notifyListeners();

    await _fanOut(group, message, members);
  }

  Future<void> _fanOut(Group group, Message message, List<GroupMember> members) async {
    // Expiry rides the message itself, not the current setting: a retry after
    // a timer change must still carry the TTL this message was sent under.
    final payload = {
      'group_id': group.id,
      'text': message.text,
      if (message.expiresAt != null)
        'expire_after_ms': message.expiresAt! - message.sentAt,
      if (_replyPayloadOf(message) != null) 'reply_to': _replyPayloadOf(message),
    };
    for (final member in members) {
      try {
        // Envelope id == message id for every copy: mailboxes are per-member
        // so ids never collide, and both mailbox and receiver dedupe retries.
        await _deliverToMember(
          member,
          await _sealFor(EnvelopeType.groupMsg, member.zeonId,
              member.pubkeyB64, payload,
              envelopeId: message.id,
              serverAddress: member.serverAddress,
              serverTlsFp: member.tlsFp),
        );
        await app.db.clearOutbox(message.id, member.zeonId);
      } catch (_) {
        // stays in outbox; retryPending will re-attempt this member
      }
    }
    if (await app.db.outboxRemaining(message.id) == 0) {
      message.status = MessageStatus.sent;
      await app.db.setMessageStatus(message.id, MessageStatus.sent);
    }
    notifyListeners();
  }

  /// Leave: announce to everyone, then delete locally.
  Future<void> leaveGroup(Group group) async {
    final members = (groupMembers[group.id] ?? [])
        .where((m) => m.zeonId != app.zeonId)
        .toList();
    for (final m in members) {
      try {
        await _deliverToMember(
            m,
            await _sealFor(EnvelopeType.groupLeave, m.zeonId, m.pubkeyB64,
                {'group_id': group.id},
                serverAddress: m.serverAddress, serverTlsFp: m.tlsFp));
      } catch (_) {}
    }
    await app.db.deleteGroup(group.id);
    groups.removeWhere((g) => g.id == group.id);
    groupMembers.remove(group.id);
    _messages.remove(group.id);
    lastMessage.remove(group.id);
    notifyListeners();
  }

  // -- messaging -------------------------------------------------------------------

  Future<void> sendMessage(Contact contact, String text,
      {Message? replyTo}) async {
    _typingSentAt.remove(contact.zeonId); // the message itself says "stopped"
    final sentAt = DateTime.now().millisecondsSinceEpoch;
    final message = Message(
      id: _uuid.v4(),
      contactId: contact.zeonId,
      outgoing: true,
      text: text,
      sentAt: sentAt,
      status: MessageStatus.pending,
      expiresAt:
          contact.expireTimerMs > 0 ? sentAt + contact.expireTimerMs : null,
      replyToId: replyTo?.id,
      replyToSender: replyTo == null ? null : _quotedSenderOf(replyTo),
      replyToPreview: replyTo == null ? null : _clipPreview(replyTo.preview),
    );
    await app.db.insertMessage(message);
    (_messages[contact.zeonId] ??= []).add(message);
    lastMessage[contact.zeonId] = message;
    if (message.expiresAt != null) _scheduleExpirySweep();
    notifyListeners();

    await _trySend(contact, message);
  }

  /// Forward an existing message to another conversation. A forward is an
  /// ordinary new message — fresh id, own outbox lifecycle, no link back to
  /// the original. Media forwards re-copy and re-encrypt the local file, so
  /// they only work while it still exists on this device.
  Future<void> forwardMessage(Message m,
      {Contact? toContact, Group? toGroup}) async {
    assert((toContact == null) != (toGroup == null));
    if (toGroup != null) {
      await sendGroupMessage(toGroup, m.text);
    } else if (m.kind == MessageKind.text) {
      await sendMessage(toContact!, m.text);
    } else {
      await sendMedia(toContact!, m.mediaPath!,
          kind: m.kind,
          mime: _mimeFromPath(m.mediaPath!),
          durationMs: m.durationMs,
          fileName: m.fileName);
    }
  }

  /// Send a photo, video, voice note or document. `sourcePath` is copied into
  /// the app's media directory first — the local copy is the message history.
  Future<void> sendMedia(
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
      contactId: contact.zeonId,
      outgoing: true,
      text: '',
      kind: kind,
      mediaPath: localPath,
      durationMs: durationMs,
      fileName: fileName,
      sentAt: sentAt,
      status: MessageStatus.pending,
      expiresAt:
          contact.expireTimerMs > 0 ? sentAt + contact.expireTimerMs : null,
      replyToId: replyTo?.id,
      replyToSender: replyTo == null ? null : _quotedSenderOf(replyTo),
      replyToPreview: replyTo == null ? null : _clipPreview(replyTo.preview),
    );
    await app.db.insertMessage(message);
    (_messages[contact.zeonId] ??= []).add(message);
    lastMessage[contact.zeonId] = message;
    if (message.expiresAt != null) _scheduleExpirySweep();
    notifyListeners();

    await _trySend(contact, message, mime: mime);
  }

  Future<void> _trySend(Contact contact, Message message,
      {String? mime}) async {
    try {
      final envelope = message.kind == MessageKind.text
          ? await _sealMessage(contact, message)
          : await _sealMedia(contact, message, mime: mime);
      await _deliver(contact, envelope);
      message.status = MessageStatus.sent;
      await app.db.setMessageStatus(message.id, MessageStatus.sent);
    } catch (_) {
      // stays pending; retryPending() will pick it up
    }
    notifyListeners();
  }

  /// Media path: encrypt file with a one-off key, park the ciphertext on the
  /// recipient's mailbox, reference it from a small normal envelope.
  Future<Envelope> _sealMedia(Contact contact, Message message,
      {String? mime}) async {
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
      if (_replyPayloadOf(message) != null) 'reply_to': _replyPayloadOf(message),
    };
    return _sealFor(EnvelopeType.media, contact.zeonId, contact.pubkeyB64,
        payload,
        envelopeId: message.id,
        serverAddress: address,
        serverTlsFp: contact.tlsFp,
        blobId: blobId);
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

  Future<Envelope> _sealMessage(Contact contact, Message message) =>
      _sealFor(
          EnvelopeType.msg,
          contact.zeonId,
          contact.pubkeyB64,
          {
            'text': message.text,
            if (message.expiresAt != null)
              'expire_after_ms': message.expiresAt! - message.sentAt,
            if (_replyPayloadOf(message) != null)
              'reply_to': _replyPayloadOf(message),
          },
          // envelope id == message id → dedupe on the other side
          envelopeId: message.id,
          serverAddress: contact.serverAddress,
          serverTlsFp: contact.tlsFp);

  /// Re-attempt everything in the pending outbox (app resume, reconnect, …).
  Future<void> retryPending() async {
    // A pending message that expired while we were offline must be purged
    // (and its outbox rows cleared) before the loop below could resend it.
    await sweepExpired();
    // Contact requests that never made it out (their mailbox was off when we
    // added them). Receivers dedupe by sender, so re-sending is safe.
    for (final contact
        in contacts.where((c) => c.status == ContactStatus.pendingOut)) {
      try {
        await _deliver(
          contact,
          await _seal(EnvelopeType.contactRequest, contact, _profilePayload()),
        );
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
      await _trySend(contact, cached ?? message);
      if (cached == null) {
        lastMessage[message.contactId] =
            await app.db.lastMessageFor(message.contactId);
      }
    }
    // Group fan-outs still owed to unreachable members.
    final outbox = await app.db.pendingOutbox();
    for (final entry in outbox.entries) {
      final message = await app.db.messageById(entry.key);
      if (message == null) continue;
      final group = groupById(message.contactId);
      if (group == null) continue;
      final owed = (groupMembers[group.id] ?? [])
          .where((m) => entry.value.contains(m.zeonId))
          .toList();
      if (owed.isNotEmpty) {
        await _fanOut(group, message, owed);
      }
    }
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
          await _sendToPeer(peer.key, EnvelopeType.receipt,
              {'kind': kinds.key, 'ids': kinds.value.toList()},
              noPush: true); // never wake their phone for a checkmark
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
      String zeonId, String type, Map<String, Object?> payload,
      {bool transient = false, bool noPush = false}) async {
    final contact = contactById(zeonId);
    if (contact != null) {
      await _deliver(contact, await _seal(type, contact, payload),
          transient: transient, noPush: noPush);
      return;
    }
    for (final members in groupMembers.values) {
      for (final m in members) {
        if (m.zeonId != zeonId) continue;
        await _deliverToMember(
            m,
            await _sealFor(type, m.zeonId, m.pubkeyB64, payload,
                serverAddress: m.serverAddress, serverTlsFp: m.tlsFp),
            transient: transient,
            noPush: noPush);
        return;
      }
    }
  }

  /// A peer told us which of our messages reached their screen. Statuses only
  /// move forward; group messages advance when *every* current member is
  /// there (per-member rows in the receipts table).
  Future<void> _applyReceipt(
      Envelope envelope, Map<String, dynamic> payload) async {
    final kind = payload['kind'] as String?;
    if (kind != ReceiptKind.delivered && kind != ReceiptKind.read) return;
    final ids = (payload['ids'] as List?)?.whereType<String>() ?? const <String>[];
    final now = DateTime.now().millisecondsSinceEpoch;
    for (final id in ids) {
      final message = await app.db.messageById(id);
      if (message == null || !message.outgoing) continue;
      final group = groupById(message.contactId);
      String? next;
      if (group == null) {
        // A DM receipt is only valid from the person the message went to.
        if (message.contactId != envelope.from) continue;
        next =
            kind == ReceiptKind.read ? MessageStatus.read : MessageStatus.delivered;
      } else {
        if (memberOf(group.id, envelope.from) == null) continue;
        await app.db.upsertReceipt(id, envelope.from, kind!, now);
        final others = (groupMembers[group.id] ?? [])
            .where((m) => m.zeonId != app.zeonId)
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

  /// Peers currently typing in a conversation (Zeon IDs), expired on read.
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
        if (!((await _loadSession(contact.zeonId))?.canSend ?? false)) return;
        await _deliver(
            contact, await _seal(EnvelopeType.typing, contact, {'state': state}),
            transient: true);
      } else {
        final payload = {'group_id': group.id, 'state': state};
        for (final m in (groupMembers[group.id] ?? [])
            .where((m) => m.zeonId != app.zeonId)) {
          if (!((await _loadSession(m.zeonId))?.canSend ?? false)) continue;
          try {
            await _deliverToMember(
                m,
                await _sealFor(EnvelopeType.typing, m.zeonId, m.pubkeyB64,
                    payload,
                    serverAddress: m.serverAddress, serverTlsFp: m.tlsFp),
                transient: true);
          } catch (_) {} // per-member fire-and-forget
        }
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
        await _deliver(contact,
            await _seal(EnvelopeType.msgEdit, contact, {'id': message.id, 'text': text}));
      } catch (_) {
        reachedEveryone = false;
      }
    } else {
      final payload = {'group_id': group.id, 'id': message.id, 'text': text};
      for (final m in (groupMembers[group.id] ?? [])
          .where((m) => m.zeonId != app.zeonId)) {
        try {
          await _deliverToMember(
              m,
              await _sealFor(EnvelopeType.groupMsgEdit, m.zeonId, m.pubkeyB64,
                  payload,
                  serverAddress: m.serverAddress, serverTlsFp: m.tlsFp));
        } catch (_) {
          reachedEveryone = false;
        }
      }
    }
    return reachedEveryone;
  }

  /// Delete-for-everyone: tombstone locally, announce to recipients.
  /// Cooperative like Signal's — an honest client blanks it, that's all.
  Future<bool> deleteMessageForEveryone(Message message) async {
    if (!canDeleteForEveryone(message)) return true;
    final group = groupById(message.contactId);
    final neverLeft =
        message.status == MessageStatus.pending && group == null;
    await _tombstone(message);
    await app.db.clearOutboxMessage(message.id); // stop owing group copies
    notifyListeners();
    if (neverLeft) return true;

    var reachedEveryone = true;
    if (group == null) {
      final contact = contactById(message.contactId);
      if (contact == null) return false;
      try {
        await _deliver(contact,
            await _seal(EnvelopeType.msgDelete, contact, {'id': message.id}));
      } catch (_) {
        reachedEveryone = false;
      }
    } else {
      final payload = {'group_id': group.id, 'id': message.id};
      for (final m in (groupMembers[group.id] ?? [])
          .where((m) => m.zeonId != app.zeonId)) {
        try {
          await _deliverToMember(
              m,
              await _sealFor(EnvelopeType.groupMsgDelete, m.zeonId,
                  m.pubkeyB64, payload,
                  serverAddress: m.serverAddress, serverTlsFp: m.tlsFp));
        } catch (_) {
          reachedEveryone = false;
        }
      }
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
      lastMessage[message.contactId] =
          await app.db.lastMessageFor(message.contactId);
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

  Future<void> _removeMediaFile(Message message) async {
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
      for (final m in (groupMembers[group.id] ?? [])
          .where((m) => m.zeonId != app.zeonId)) {
        try {
          await _deliverToMember(
              m,
              await _sealFor(EnvelopeType.groupTimerUpdate, m.zeonId,
                  m.pubkeyB64, payload,
                  serverAddress: m.serverAddress, serverTlsFp: m.tlsFp));
        } catch (_) {}
      }
    } else {
      try {
        await _deliver(
            contact!,
            await _seal(EnvelopeType.timerUpdate, contact,
                {'expire_ms': expireMs}));
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
  Future<void> _insertNotice(String conversationId, String text,
      {String? id}) async {
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
      _expirySweep =
          Timer(Duration(milliseconds: delay), () => unawaited(sweepExpired()));
    }());
  }

  /// The peer edited one of their messages. The session already authenticated
  /// them; what's left is checking the target is really theirs.
  Future<void> _applyRemoteEdit(
      Envelope envelope, Map<String, dynamic> payload,
      {bool group = false}) async {
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
      Envelope envelope, Map<String, dynamic> payload,
      {bool group = false}) async {
    final message = await _remoteEditTarget(envelope, payload, group: group);
    if (message == null) return;
    await _tombstone(message);
  }

  /// Shared validation for msg_edit / msg_delete: the referenced message must
  /// exist, be incoming, belong to the right conversation, have been written
  /// by the envelope's (session-authenticated) sender, and still be inside
  /// the edit window plus receiver-side grace.
  Future<Message?> _remoteEditTarget(
      Envelope envelope, Map<String, dynamic> payload,
      {required bool group}) async {
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
      reactionsByMessage[message.id]?[app.zeonId];

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
    await app.db.setReaction(message.id, app.zeonId!, applied, now);
    _recordReaction(message.id, app.zeonId!, applied);
    notifyListeners();

    final payload = {'id': message.id, 'emoji': applied};
    final group = groupById(message.contactId);
    try {
      if (group == null) {
        final contact = contactById(message.contactId);
        if (contact == null) return;
        await _deliver(
            contact, await _seal(EnvelopeType.reaction, contact, payload));
      } else {
        final groupPayload = {...payload, 'group_id': group.id};
        for (final m in (groupMembers[group.id] ?? [])
            .where((m) => m.zeonId != app.zeonId)) {
          try {
            await _deliverToMember(
                m,
                await _sealFor(EnvelopeType.groupReaction, m.zeonId,
                    m.pubkeyB64, groupPayload,
                    serverAddress: m.serverAddress, serverTlsFp: m.tlsFp));
          } catch (_) {} // best-effort, like receipts
        }
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
      Envelope envelope, Map<String, dynamic> payload,
      {bool group = false}) async {
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
    await app.db.setReaction(
        id, envelope.from, emoji, _sentAtMs(envelope));
    _recordReaction(id, envelope.from, emoji);
  }

  // -- calls (PROTOCOL.md "Calls") ----------------------------------------------------

  /// Send one call-signaling envelope on the pairwise session. Used only by
  /// CallState; delivery failures propagate so the call fails fast.
  Future<void> sendCallSignal(
      Contact contact, String type, Map<String, Object?> payload,
      {bool transient = false, bool ring = false}) async {
    await _deliver(contact, await _seal(type, contact, payload),
        transient: transient, ring: ring);
  }

  /// A call's epitaph in the conversation ("Missed voice call",
  /// "Video call · 3:42"). Local-only bookkeeping — both sides write their
  /// own — so no receipts are queued for it.
  Future<void> recordCallEvent(Contact contact, String label,
      {required bool outgoing}) async {
    final message = Message(
      id: _uuid.v4(),
      contactId: contact.zeonId,
      outgoing: outgoing,
      text: label,
      kind: MessageKind.call,
      sentAt: DateTime.now().millisecondsSinceEpoch,
      status: MessageStatus.read,
    );
    await app.db.insertMessage(message);
    final cache = _messages[contact.zeonId];
    if (cache != null) cache.add(message);
    lastMessage[contact.zeonId] = message;
    notifyListeners();
  }

  // -- receiving ---------------------------------------------------------------------

  /// Called by the mailbox socket for every envelope. Returning normally acks
  /// (and thus deletes) it server-side, so persist before returning.
  Future<void> handleIncoming(SealedEnvelope wire) async {
    if (wire.to != app.zeonId) return;

    // Unwrap the transport seal; anything not sealed to this identity is
    // dropped (and acked — same silent-drop rule as a failed session).
    final Envelope envelope;
    try {
      final inner = app.crypto
          .unseal(Uint8List.fromList(base64Decode(wire.sealedB64)));
      if (inner == null) {
        debugPrint('zeon: dropped envelope ${wire.id}: not sealed to us');
        return;
      }
      envelope = Envelope.fromJson(
          jsonDecode(utf8.decode(inner)) as Map<String, dynamic>);
    } catch (_) {
      debugPrint('zeon: dropped envelope ${wire.id}: malformed seal');
      return;
    }
    if (envelope.to != app.zeonId) return;

    var contact = contactById(envelope.from);

    // Decryption is the authentication: the session (or the x3dh block's
    // commitment-verified identity key) proves the sender holds the `from`
    // ID's private key.
    final plaintext = await _openEnvelope(envelope);
    if (plaintext == null) return; // forged, corrupted, or no session — drop

    final payload = jsonDecode(plaintext) as Map<String, dynamic>;

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
              await _seal(
                  EnvelopeType.contactAccept, contact, _profilePayload()),
            );
            break;
          }
          _dropLog(envelope, 'duplicate contact request (already ${contact.status})');
          return;
        }
        // Identity key: the (already commitment-verified) x3dh block if this
        // was a session-opening message, else the directory (the sender's own
        // hub when the request names one), best-effort.
        final senderHub = _peerHubFrom(payload);
        final senderEntry =
            await _resolveOrNull(envelope.from, hub: senderHub);
        final pubkeyB64 =
            (envelope.x3dh?['ik'] as String?) ?? senderEntry?.pubkeyB64;
        if (pubkeyB64 == null) return; // unresolvable sender — drop
        contact = Contact(
          zeonId: envelope.from,
          displayName: (payload['display_name'] as String?) ??
              envelope.from.substring(3, 12),
          pubkeyB64: pubkeyB64,
          status: ContactStatus.pendingIn,
          serverAddress: senderEntry?.serverAddress,
          tlsFp: senderEntry?.serverTlsFp,
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
          onNotice?.call('Request accepted',
              '${contact.displayName} accepted your request');
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
          _dropLog(envelope, 'msg from non-accepted contact — strangers cannot chat');
          return;
        }
        final (replyId, replySender, replyPreview) = _replyFrom(payload);
        await _storeIncoming(
          contact,
          Message(
            id: envelope.id,
            contactId: contact.zeonId,
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
        if (mailboxAddress == null || mailboxToken == null || mailboxTlsFp == null) {
          throw StateError('mailbox info missing'); // don't ack — retry later
        }
        final ciphertext = await downloadBlob(mailboxAddress!,
            payload['blob_id'] as String, mailboxToken!, mailboxTlsFp!);
        final data = app.crypto.openBlob(
          Uint8List.fromList(ciphertext),
          base64Decode(payload['key'] as String),
          base64Decode(payload['blob_nonce'] as String),
        );
        if (data == null) return; // tampered blob — drop
        final kind = switch (payload['kind']) {
          MessageKind.image ||
          MessageKind.audio ||
          MessageKind.video ||
          MessageKind.file ||
          MessageKind.sticker =>
            payload['kind'] as String,
          _ => MessageKind.image,
        };
        final name = payload['name'] as String?;
        final dir = await _mediaDir();
        // Documents keep their original extension so the OS opens them with
        // the right app; everything else derives it from the mime type.
        final ext = kind == MessageKind.file && name != null
            ? p.extension(name)
            : _extFromMime((payload['mime'] as String?) ?? '');
        final path = p.join(dir.path, '${envelope.id}$ext');
        await File(path).writeAsBytes(data);
        final (replyId, replySender, replyPreview) = _replyFrom(payload);
        await _storeIncoming(
          contact,
          Message(
            id: envelope.id,
            contactId: contact.zeonId,
            outgoing: false,
            text: '',
            kind: kind,
            mediaPath: path,
            durationMs: payload['duration_ms'] as int?,
            fileName: name == null ? null : p.basename(name),
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

      case EnvelopeType.groupLeave:
        final group = groupById(payload['group_id'] as String? ?? '');
        if (group == null) return;
        final member = memberOf(group.id, envelope.from);
        if (member == null) return; // only a member can announce their own leave
        groupMembers[group.id]?.removeWhere((m) => m.zeonId == envelope.from);
        await app.db
            .replaceMembers(group.id, groupMembers[group.id] ?? const []);
        await _insertNotice(group.id, '${member.displayName} left',
            id: envelope.id);

      case EnvelopeType.receipt:
        await _applyReceipt(envelope, payload);

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
            contact.zeonId, _timerNoticeText(contact.displayName, ms),
            id: envelope.id);

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
            group.id, _timerNoticeText(member.displayName, ms),
            id: envelope.id);

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
      Envelope envelope, Map<String, dynamic> payload) async {
    final groupId = payload['group_id'] as String?;
    final admin = payload['admin'] as String?;
    final name = payload['name'] as String?;
    final version = payload['version'] as int?;
    final rawMembers = payload['members'] as List?;
    if (groupId == null || admin == null || name == null || version == null || rawMembers == null) {
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
      final zeonId = raw['zeon_id'] as String?;
      final pubkey = raw['pubkey'] as String?;
      if (zeonId == null || pubkey == null) return;
      if (!app.crypto.pubkeyMatchesId(pubkey, zeonId)) return; // forged key
      if (zeonId == app.zeonId) includesUs = true;
      members.add(GroupMember(
        groupId: groupId,
        zeonId: zeonId,
        pubkeyB64: pubkey,
        displayName: (raw['display_name'] as String?) ?? zeonId.substring(3, 12),
      ));
    }
    if (!includesUs) {
      // we were removed — drop the group locally, keep history? for now: keep
      // nothing server-side to worry about; just delete membership records
      if (existing != null) {
        groupMembers[groupId] = [];
        await app.db.replaceMembers(groupId, const []);
        await _insertNotice(groupId, 'You were removed from this group',
            id: envelope.id);
      }
      return;
    }

    // First sight of the group: adopt its current disappearing-messages
    // timer from the payload. Established members ignore the field — an
    // admin's membership fan-out must not clobber a newer member-set timer.
    final expireMs = payload['expire_ms'];
    final bootstrapTimer =
        existing == null && expireMs is int && expireMs > 0;
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
        await _insertNotice(groupId, 'Group renamed to "$name"',
            id: '${envelope.id}-rename');
      }
      for (final m in members) {
        if (m.zeonId != app.zeonId &&
            !before.any((b) => b.zeonId == m.zeonId)) {
          await _insertNotice(groupId, '${m.displayName} was added',
              id: '${envelope.id}-add-${m.zeonId}');
        }
      }
      for (final b in before) {
        if (b.zeonId != app.zeonId &&
            !members.any((m) => m.zeonId == b.zeonId)) {
          await _insertNotice(groupId, '${b.displayName} was removed',
              id: '${envelope.id}-rm-${b.zeonId}');
        }
      }
    }
  }

  Future<void> _storeIncomingConversation(
      String conversationId, Message message) async {
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
        onScreen && app.sendReadReceipts ? ReceiptKind.read : ReceiptKind.delivered,
        message.id);
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
      _storeIncomingConversation(contact.zeonId, message);

  Future<DirectoryEntry?> _resolveOrNull(String zeonId, {String? hub}) async {
    try {
      return await _resolve(zeonId, hub: hub);
    } catch (_) {
      return null;
    }
  }

  @override
  void dispose() {
    _receiptFlushTimer?.cancel();
    _typingSweep?.cancel();
    _expirySweep?.cancel();
    super.dispose();
  }
}
