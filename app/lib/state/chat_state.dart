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
  final Map<String, List<Message>> _messages = {}; // by contact zeon_id
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
    for (final c in contacts) {
      lastMessage[c.zeonId] = await app.db.lastMessageFor(c.zeonId);
    }
    notifyListeners();
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

  Envelope _seal(String type, Contact contact, Map<String, Object?> payload) {
    final sealed = app.crypto
        .encrypt(jsonEncode(payload), base64Decode(contact.pubkeyB64));
    return Envelope(
      id: _uuid.v4(),
      type: type,
      from: app.zeonId!,
      to: contact.zeonId,
      sentAt: DateTime.now().toUtc().toIso8601String(),
      nonceB64: sealed.nonceB64,
      ciphertextB64: sealed.ciphertextB64,
    );
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
  }

  // -- receiving ---------------------------------------------------------------------

  /// Called by the mailbox socket for every envelope. Returning normally acks
  /// (and thus deletes) it server-side, so persist before returning.
  Future<void> handleIncoming(Envelope envelope) async {
    if (envelope.to != app.zeonId) return;

    var contact = contactById(envelope.from);
    final senderEntry =
        contact == null ? await _resolveOrNull(envelope.from) : null;
    final senderPubkey = contact != null
        ? Uint8List.fromList(base64Decode(contact.pubkeyB64))
        : senderEntry != null
            ? Uint8List.fromList(base64Decode(senderEntry.pubkeyB64))
            : null;
    if (senderPubkey == null) return; // unresolvable sender — drop

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
    }
    notifyListeners();
  }

  static int _sentAtMs(Envelope envelope) =>
      DateTime.tryParse(envelope.sentAt)?.toLocal().millisecondsSinceEpoch ??
      DateTime.now().millisecondsSinceEpoch;

  Future<void> _storeIncoming(Contact contact, Message message) async {
    await app.db.insertMessage(message);
    final cache = _messages[contact.zeonId];
    if (cache != null && !cache.any((m) => m.id == message.id)) {
      cache.add(message);
      cache.sort((a, b) => a.sentAt.compareTo(b.sentAt));
    }
    lastMessage[contact.zeonId] = message;
  }

  Future<DirectoryEntry?> _resolveOrNull(String zeonId) async {
    try {
      return await _resolve(zeonId);
    } catch (_) {
      return null;
    }
  }
}
