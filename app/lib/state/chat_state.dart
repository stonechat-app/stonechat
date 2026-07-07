/// Contacts + messages. Encrypts on the way out, decrypts on the way in,
/// persists everything locally, keeps a pending outbox for unreachable peers.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:path/path.dart' as p;
import 'package:path_provider/path_provider.dart';
import 'package:uuid/uuid.dart';

import '../core/api.dart';
import '../core/session.dart';
import '../models.dart';
import 'app_state.dart';

const _uuid = Uuid();

class ChatState extends ChangeNotifier {
  final AppState app;

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
  Future<DirectoryEntry> _resolve(String zeonId) async {
    final entry = await app.api.directory(zeonId);
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
          handle: entry.handle,
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
  /// [transient] (typing) and [noPush] (receipts) are the two delivery hints
  /// the mailbox is allowed to see.
  SealedEnvelope _wireSeal(Envelope envelope, String toPubkeyB64,
          {bool transient = false, bool noPush = false}) =>
      SealedEnvelope(
        id: envelope.id,
        to: envelope.to,
        sealedB64: base64Encode(app.crypto.sealTo(
            Uint8List.fromList(base64Decode(toPubkeyB64)),
            utf8.encode(jsonEncode(envelope.toJson())))),
        blobId: envelope.blobId,
        transient: transient,
        noPush: noPush,
      );

  Future<void> _deliver(Contact contact, Envelope envelope,
      {bool transient = false, bool noPush = false}) async {
    final wire = _wireSeal(envelope, contact.pubkeyB64,
        transient: transient, noPush: noPush);
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

  // -- contact lifecycle ---------------------------------------------------------

  /// Add by Zeon code (zn-word-word-word) or full ZC- ID: resolve, verify,
  /// store, send an encrypted contact request.
  Future<Contact> addContact(String raw) async {
    final input = raw.trim();
    if (input.isEmpty) {
      throw const FormatException('Enter a Zeon code');
    }
    // Full IDs get local checksum validation; anything else is treated as a
    // handle and resolved by the directory.
    final String query;
    if (input.toUpperCase().replaceAll(RegExp(r'[\s-]'), '').startsWith('ZC')) {
      query = app.crypto.normalizeZeonId(input);
    } else {
      query = input.toLowerCase().replaceAll(RegExp(r'\s+'), '-');
    }

    final entry = await _resolve(query);
    if (entry.zeonId == app.zeonId) {
      throw ApiException("That's your own code");
    }
    if (contactById(entry.zeonId) != null) {
      throw ApiException('Already in your contacts');
    }
    final contact = Contact(
      zeonId: entry.zeonId,
      displayName: entry.handle ?? entry.zeonId.substring(3, 12),
      handle: entry.handle,
      pubkeyB64: entry.pubkeyB64,
      status: ContactStatus.pendingOut,
      serverAddress: entry.serverAddress,
      tlsFp: entry.serverTlsFp,
      createdAt: DateTime.now().millisecondsSinceEpoch,
    );
    await app.db.upsertContact(contact);
    contacts.add(contact);
    notifyListeners();

    await _deliver(
      contact,
      await _seal(EnvelopeType.contactRequest, contact,
          {'display_name': app.displayName}),
    );
    return contact;
  }

  /// Re-send a still-pending contact request (manual nudge from the
  /// Requests list; receivers dedupe by sender, so this is always safe).
  Future<void> resendRequest(Contact contact) async {
    await _deliver(
      contact,
      await _seal(EnvelopeType.contactRequest, contact,
          {'display_name': app.displayName}),
    );
  }

  Future<void> acceptContact(Contact contact) async {
    contact.status = ContactStatus.accepted;
    await app.db.upsertContact(contact);
    notifyListeners();
    await _deliver(
      contact,
      await _seal(EnvelopeType.contactAccept, contact,
          {'display_name': app.displayName}),
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

  Future<void> sendGroupMessage(Group group, String text) async {
    _typingSentAt.remove(group.id); // the message itself says "stopped typing"
    final members = (groupMembers[group.id] ?? [])
        .where((m) => m.zeonId != app.zeonId)
        .toList();
    final message = Message(
      id: _uuid.v4(),
      contactId: group.id,
      outgoing: true,
      text: text,
      sentAt: DateTime.now().millisecondsSinceEpoch,
      status: MessageStatus.pending,
    );
    await app.db.insertMessage(message);
    await app.db.addOutbox(message.id, group.id, [for (final m in members) m.zeonId]);
    (_messages[group.id] ??= []).add(message);
    lastMessage[group.id] = message;
    notifyListeners();

    await _fanOut(group, message, members);
  }

  Future<void> _fanOut(Group group, Message message, List<GroupMember> members) async {
    final payload = {'group_id': group.id, 'text': message.text};
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

  Future<void> sendMessage(Contact contact, String text) async {
    _typingSentAt.remove(contact.zeonId); // the message itself says "stopped"
    final message = Message(
      id: _uuid.v4(),
      contactId: contact.zeonId,
      outgoing: true,
      text: text,
      sentAt: DateTime.now().millisecondsSinceEpoch,
      status: MessageStatus.pending,
    );
    await app.db.insertMessage(message);
    (_messages[contact.zeonId] ??= []).add(message);
    lastMessage[contact.zeonId] = message;
    notifyListeners();

    await _trySend(contact, message);
  }

  /// Send a photo or voice note. `sourcePath` is copied into the app's media
  /// directory first — the local copy is the message history.
  Future<void> sendMedia(
    Contact contact,
    String sourcePath, {
    required String kind, // MessageKind.image | MessageKind.audio
    required String mime,
    int? durationMs,
  }) async {
    final id = _uuid.v4();
    final dir = await _mediaDir();
    final localPath = p.join(dir.path, '$id${p.extension(sourcePath)}');
    await File(sourcePath).copy(localPath);

    final message = Message(
      id: id,
      contactId: contact.zeonId,
      outgoing: true,
      text: '',
      kind: kind,
      mediaPath: localPath,
      durationMs: durationMs,
      sentAt: DateTime.now().millisecondsSinceEpoch,
      status: MessageStatus.pending,
    );
    await app.db.insertMessage(message);
    (_messages[contact.zeonId] ??= []).add(message);
    lastMessage[contact.zeonId] = message;
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
    };
    return _sealFor(EnvelopeType.media, contact.zeonId, contact.pubkeyB64,
        payload,
        envelopeId: message.id,
        serverAddress: address,
        serverTlsFp: contact.tlsFp,
        blobId: blobId);
  }

  static String _mimeFromPath(String path) => switch (p.extension(path)) {
        '.jpg' || '.jpeg' => 'image/jpeg',
        '.png' => 'image/png',
        '.heic' => 'image/heic',
        '.m4a' => 'audio/mp4',
        _ => 'application/octet-stream',
      };

  static String _extFromMime(String mime) => switch (mime) {
        'image/jpeg' => '.jpg',
        'image/png' => '.png',
        'image/heic' => '.heic',
        'audio/mp4' || 'audio/aac' => '.m4a',
        _ => '.bin',
      };

  Future<Envelope> _sealMessage(Contact contact, Message message) =>
      _sealFor(EnvelopeType.msg, contact.zeonId, contact.pubkeyB64,
          {'text': message.text},
          // envelope id == message id → dedupe on the other side
          envelopeId: message.id,
          serverAddress: contact.serverAddress,
          serverTlsFp: contact.tlsFp);

  /// Re-attempt everything in the pending outbox (app resume, reconnect, …).
  Future<void> retryPending() async {
    // Contact requests that never made it out (their mailbox was off when we
    // added them). Receivers dedupe by sender, so re-sending is safe.
    for (final contact
        in contacts.where((c) => c.status == ContactStatus.pendingOut)) {
      try {
        await _deliver(
          contact,
          await _seal(EnvelopeType.contactRequest, contact,
              {'display_name': app.displayName}),
        );
      } catch (_) {
        // still unreachable — next retry will try again
      }
    }
    for (final message in await app.db.pendingMessages()) {
      final contact = contactById(message.contactId);
      if (contact == null) continue;
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
        if (contact == null || !contact.isAccepted) return;
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
    if (id == null || emoji == null || emoji.length > 16) return;
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
            contact.displayName =
                (payload['display_name'] as String?) ?? contact.displayName;
            await app.db.upsertContact(contact);
            await _deliver(
              contact,
              await _seal(EnvelopeType.contactAccept, contact,
                  {'display_name': app.displayName}),
            );
            break;
          }
          _dropLog(envelope, 'duplicate contact request (already ${contact.status})');
          return;
        }
        // Identity key: the (already commitment-verified) x3dh block if this
        // was a session-opening message, else the directory. Handle is
        // directory-only, best-effort.
        final senderEntry = await _resolveOrNull(envelope.from);
        final pubkeyB64 =
            (envelope.x3dh?['ik'] as String?) ?? senderEntry?.pubkeyB64;
        if (pubkeyB64 == null) return; // unresolvable sender — drop
        contact = Contact(
          zeonId: envelope.from,
          displayName: (payload['display_name'] as String?) ??
              senderEntry?.handle ??
              envelope.from.substring(3, 12),
          handle: senderEntry?.handle,
          pubkeyB64: pubkeyB64,
          status: ContactStatus.pendingIn,
          serverAddress: senderEntry?.serverAddress,
          tlsFp: senderEntry?.serverTlsFp,
          createdAt: DateTime.now().millisecondsSinceEpoch,
        );
        await app.db.upsertContact(contact);
        contacts.add(contact);

      case EnvelopeType.contactAccept:
        if (contact == null || contact.status != ContactStatus.pendingOut) {
          return;
        }
        contact.status = ContactStatus.accepted;
        contact.displayName =
            (payload['display_name'] as String?) ?? contact.displayName;
        await app.db.upsertContact(contact);

      case EnvelopeType.msg:
        if (contact == null || !contact.isAccepted) {
          _dropLog(envelope, 'msg from non-accepted contact — strangers cannot chat');
          return;
        }
        await _storeIncoming(
          contact,
          Message(
            id: envelope.id,
            contactId: contact.zeonId,
            outgoing: false,
            text: (payload['text'] as String?) ?? '',
            sentAt: _sentAtMs(envelope),
            status: MessageStatus.sent,
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
        final dir = await _mediaDir();
        final ext = _extFromMime((payload['mime'] as String?) ?? '');
        final path = p.join(dir.path, '${envelope.id}$ext');
        await File(path).writeAsBytes(data);
        await _storeIncoming(
          contact,
          Message(
            id: envelope.id,
            contactId: contact.zeonId,
            outgoing: false,
            text: '',
            kind: (payload['kind'] as String?) ?? MessageKind.image,
            mediaPath: path,
            durationMs: payload['duration_ms'] as int?,
            sentAt: _sentAtMs(envelope),
            status: MessageStatus.sent,
          ),
        );

      case EnvelopeType.groupCreate || EnvelopeType.groupUpdate:
        await _applyMembership(envelope, payload);

      case EnvelopeType.groupMsg:
        final group = groupById(payload['group_id'] as String? ?? '');
        if (group == null) return; // unknown group — drop (create not seen yet)
        if (memberOf(group.id, envelope.from) == null) return; // non-member
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
      }
      return;
    }

    final group = Group(
      id: groupId,
      name: name,
      adminId: admin,
      version: version,
      createdAt: existing?.createdAt ?? DateTime.now().millisecondsSinceEpoch,
    );
    await app.db.upsertGroup(group);
    await app.db.replaceMembers(groupId, members);
    if (existing == null) {
      groups.add(group);
    } else {
      existing.name = name;
      existing.version = version;
    }
    groupMembers[groupId] = members;
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

  Future<void> _storeIncoming(Contact contact, Message message) =>
      _storeIncomingConversation(contact.zeonId, message);

  Future<DirectoryEntry?> _resolveOrNull(String zeonId) async {
    try {
      return await _resolve(zeonId);
    } catch (_) {
      return null;
    }
  }

  @override
  void dispose() {
    _receiptFlushTimer?.cancel();
    _typingSweep?.cancel();
    super.dispose();
  }
}
