/// Contacts + messages. Encrypts on the way out, decrypts on the way in,
/// persists everything locally, keeps a pending outbox for unreachable peers.
library;

import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:path/path.dart' as p;
import 'package:path_provider/path_provider.dart';
import 'package:uuid/uuid.dart';

import '../core/api.dart';
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
  // needed to download incoming media blobs.
  String? mailboxAddress;
  String? mailboxToken;

  ChatState(this.app);

  void setMailbox(String? address, String? token) {
    mailboxAddress = address;
    mailboxToken = token;
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
    _messages[contactId] = await app.db.messagesFor(contactId);
    notifyListeners();
  }

  Contact? contactById(String zeonId) {
    for (final c in contacts) {
      if (c.zeonId == zeonId) return c;
    }
    return null;
  }

  // -- resolving peers ---------------------------------------------------------

  /// Directory lookup with the trust-but-verify step from PROTOCOL.md.
  Future<DirectoryEntry> _resolve(String zeonId) async {
    final entry = await app.api.directory(zeonId);
    if (!app.crypto.pubkeyMatchesId(entry.pubkeyB64, entry.zeonId)) {
      throw ApiException(
          'Directory returned a key that does not match this ID — refusing.');
    }
    return entry;
  }

  Future<String> _addressFor(Contact contact, {bool refresh = false}) async {
    if (!refresh && contact.serverAddress != null) {
      return contact.serverAddress!;
    }
    final entry = await _resolve(contact.zeonId);
    if (entry.serverAddress == null) {
      throw ApiException(
          "${contact.displayName}'s mailbox is off right now — they'll get it when it's back");
    }
    contact.serverAddress = entry.serverAddress;
    await app.db.upsertContact(contact);
    return entry.serverAddress!;
  }

  Future<void> _deliver(Contact contact, Envelope envelope) async {
    var address = await _addressFor(contact);
    try {
      await deliverEnvelope(address, envelope);
    } on Exception {
      // Their server may have been recreated at a new IP — refresh and retry once.
      address = await _addressFor(contact, refresh: true);
      await deliverEnvelope(address, envelope);
    }
  }

  Envelope _seal(String type, Contact contact, Map<String, Object?> payload) =>
      _sealFor(type, contact.zeonId, contact.pubkeyB64, payload);

  Envelope _sealFor(
    String type,
    String toZeonId,
    String toPubkeyB64,
    Map<String, Object?> payload, {
    String? envelopeId,
  }) {
    final sealed =
        app.crypto.encrypt(jsonEncode(payload), base64Decode(toPubkeyB64));
    return Envelope(
      id: envelopeId ?? _uuid.v4(),
      type: type,
      from: app.zeonId!,
      to: toZeonId,
      sentAt: DateTime.now().toUtc().toIso8601String(),
      nonceB64: sealed.nonceB64,
      ciphertextB64: sealed.ciphertextB64,
    );
  }

  /// Resolve + deliver to a group member (same trust-but-verify as contacts).
  Future<void> _deliverToMember(GroupMember member, Envelope envelope) async {
    Future<String> resolve() async {
      final entry = await _resolve(member.zeonId);
      if (entry.serverAddress == null) {
        throw ApiException('${member.displayName} is unreachable right now');
      }
      member.serverAddress = entry.serverAddress;
      await app.db.updateMember(member);
      return entry.serverAddress!;
    }

    var address = member.serverAddress ?? await resolve();
    try {
      await deliverEnvelope(address, envelope);
    } on Exception {
      address = await resolve(); // their mailbox may have moved
      await deliverEnvelope(address, envelope);
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
      createdAt: DateTime.now().millisecondsSinceEpoch,
    );
    await app.db.upsertContact(contact);
    contacts.add(contact);
    notifyListeners();

    await _deliver(
      contact,
      _seal(EnvelopeType.contactRequest, contact,
          {'display_name': app.displayName}),
    );
    return contact;
  }

  Future<void> acceptContact(Contact contact) async {
    contact.status = ContactStatus.accepted;
    await app.db.upsertContact(contact);
    notifyListeners();
    await _deliver(
      contact,
      _seal(EnvelopeType.contactAccept, contact,
          {'display_name': app.displayName}),
    );
  }

  Future<void> declineContact(Contact contact) async {
    await app.db.deleteContact(contact.zeonId);
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
            m, _sealFor(EnvelopeType.groupCreate, m.zeonId, m.pubkeyB64, payload));
      } catch (_) {
        // unreachable member hears about the group via the next groupUpdate
        // or message retry; v1 accepts eventual delivery
      }
    }
    return group;
  }

  Future<void> sendGroupMessage(Group group, String text) async {
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
          _sealFor(EnvelopeType.groupMsg, member.zeonId, member.pubkeyB64,
              payload, envelopeId: message.id),
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
            _sealFor(EnvelopeType.groupLeave, m.zeonId, m.pubkeyB64,
                {'group_id': group.id}));
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
          ? _sealMessage(contact, message)
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
    final blobId = await uploadBlob(address, blob.ciphertext);

    final payload = {
      'blob_id': blobId,
      'key': base64Encode(blob.key),
      'blob_nonce': base64Encode(blob.nonce),
      'mime': mime ?? _mimeFromPath(message.mediaPath!),
      'kind': message.kind,
      'size': bytes.length,
      if (message.durationMs != null) 'duration_ms': message.durationMs,
    };
    final sealed = app.crypto
        .encrypt(jsonEncode(payload), base64Decode(contact.pubkeyB64));
    return Envelope(
      id: message.id,
      type: EnvelopeType.media,
      from: app.zeonId!,
      to: contact.zeonId,
      sentAt: DateTime.fromMillisecondsSinceEpoch(message.sentAt)
          .toUtc()
          .toIso8601String(),
      nonceB64: sealed.nonceB64,
      ciphertextB64: sealed.ciphertextB64,
      blobId: blobId,
    );
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

  Envelope _sealMessage(Contact contact, Message message) {
    final sealed = app.crypto
        .encrypt(jsonEncode({'text': message.text}), base64Decode(contact.pubkeyB64));
    return Envelope(
      id: message.id, // envelope id == message id → dedupe on the other side
      type: EnvelopeType.msg,
      from: app.zeonId!,
      to: contact.zeonId,
      sentAt:
          DateTime.fromMillisecondsSinceEpoch(message.sentAt, isUtc: false)
              .toUtc()
              .toIso8601String(),
      nonceB64: sealed.nonceB64,
      ciphertextB64: sealed.ciphertextB64,
    );
  }

  /// Re-attempt everything in the pending outbox (app resume, reconnect, …).
  Future<void> retryPending() async {
    // Contact requests that never made it out (their mailbox was off when we
    // added them). Receivers dedupe by sender, so re-sending is safe.
    for (final contact
        in contacts.where((c) => c.status == ContactStatus.pendingOut)) {
      try {
        await _deliver(
          contact,
          _seal(EnvelopeType.contactRequest, contact,
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

  // -- receiving ---------------------------------------------------------------------

  /// Called by the mailbox socket for every envelope. Returning normally acks
  /// (and thus deletes) it server-side, so persist before returning.
  Future<void> handleIncoming(Envelope envelope) async {
    if (envelope.to != app.zeonId) return;

    var contact = contactById(envelope.from);
    // Sender's pubkey: known contact → known group member → directory.
    String? knownPubkeyB64 = contact?.pubkeyB64;
    if (knownPubkeyB64 == null) {
      for (final members in groupMembers.values) {
        for (final m in members) {
          if (m.zeonId == envelope.from) {
            knownPubkeyB64 = m.pubkeyB64;
            break;
          }
        }
      }
    }
    final senderEntry =
        knownPubkeyB64 == null ? await _resolveOrNull(envelope.from) : null;
    knownPubkeyB64 ??= senderEntry?.pubkeyB64;
    if (knownPubkeyB64 == null) return; // unresolvable sender — drop
    final senderPubkey = Uint8List.fromList(base64Decode(knownPubkeyB64));

    final plaintext = app.crypto
        .decrypt(envelope.nonceB64, envelope.ciphertextB64, senderPubkey);
    if (plaintext == null) return; // forged or corrupted — drop silently

    final payload = jsonDecode(plaintext) as Map<String, dynamic>;

    switch (envelope.type) {
      case EnvelopeType.contactRequest:
        if (contact != null) return; // duplicate request
        contact = Contact(
          zeonId: envelope.from,
          displayName: (payload['display_name'] as String?) ??
              senderEntry?.handle ??
              envelope.from.substring(3, 12),
          handle: senderEntry?.handle,
          pubkeyB64: base64Encode(senderPubkey),
          status: ContactStatus.pendingIn,
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
        if (contact == null || !contact.isAccepted) return; // strangers can't chat
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
        if (mailboxAddress == null || mailboxToken == null) {
          throw StateError('mailbox info missing'); // don't ack — retry later
        }
        final ciphertext = await downloadBlob(
            mailboxAddress!, payload['blob_id'] as String, mailboxToken!);
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
      // we were removed — drop the group locally, keep history? v1: keep
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
    await app.db.insertMessage(message);
    final cache = _messages[conversationId];
    if (cache != null && !cache.any((m) => m.id == message.id)) {
      cache.add(message);
      cache.sort((a, b) => a.sentAt.compareTo(b.sentAt));
    }
    lastMessage[conversationId] = message;
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
}
