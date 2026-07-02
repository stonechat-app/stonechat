/// Contacts + messages. Encrypts on the way out, decrypts on the way in,
/// persists everything locally, keeps a pending outbox for unreachable peers.
library;

import 'dart:convert';

import 'package:flutter/foundation.dart';
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

  ChatState(this.app);

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
      throw ApiException('${contact.displayName} has no server online');
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

  /// Add by Zeon ID: resolve, verify, store, send an encrypted contact request.
  Future<Contact> addContact(String rawZeonId) async {
    final zeonId = app.crypto.normalizeZeonId(rawZeonId);
    if (zeonId == app.zeonId) {
      throw ApiException("That's your own ID");
    }
    if (contactById(zeonId) != null) {
      throw ApiException('Already in your contacts');
    }
    final entry = await _resolve(zeonId);
    final contact = Contact(
      zeonId: zeonId,
      displayName: zeonId.substring(3, 12), // placeholder until they accept
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

  Future<void> _trySend(Contact contact, Message message) async {
    try {
      await _deliver(contact, _sealMessage(contact, message));
      message.status = MessageStatus.sent;
      await app.db.setMessageStatus(message.id, MessageStatus.sent);
    } catch (_) {
      // stays pending; retryPending() will pick it up
    }
    notifyListeners();
  }

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
    final senderPubkey = contact != null
        ? Uint8List.fromList(base64Decode(contact.pubkeyB64))
        : await _pubkeyFromDirectory(envelope.from);
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
          displayName:
              (payload['display_name'] as String?) ?? envelope.from.substring(3, 12),
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
        final message = Message(
          id: envelope.id,
          contactId: contact.zeonId,
          outgoing: false,
          text: (payload['text'] as String?) ?? '',
          sentAt: DateTime.tryParse(envelope.sentAt)
                  ?.toLocal()
                  .millisecondsSinceEpoch ??
              DateTime.now().millisecondsSinceEpoch,
          status: MessageStatus.sent,
        );
        await app.db.insertMessage(message);
        final cache = _messages[contact.zeonId];
        if (cache != null && !cache.any((m) => m.id == message.id)) {
          cache.add(message);
          cache.sort((a, b) => a.sentAt.compareTo(b.sentAt));
        }
        lastMessage[contact.zeonId] = message;
    }
    notifyListeners();
  }

  Future<Uint8List?> _pubkeyFromDirectory(String zeonId) async {
    try {
      final entry = await _resolve(zeonId);
      return Uint8List.fromList(base64Decode(entry.pubkeyB64));
    } catch (_) {
      return null;
    }
  }
}
