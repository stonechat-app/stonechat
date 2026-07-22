/// Core data types. Mirrors PROTOCOL.md.
library;

import 'dart:typed_data';

class ContactStatus {
  static const pendingOut = 'pending_out'; // we sent a request, waiting
  static const pendingIn = 'pending_in'; // they sent us a request
  static const accepted = 'accepted';
}

class Contact {
  final String zeonId;
  String displayName;
  final String pubkeyB64;
  String status;
  String? serverAddress; // last known, refreshed from directory on demand
  String? tlsFp; // pinned relay cert fingerprint, travels with the address
  String? hub; // home hub base URL; null = the hub this app uses (cross-hub)
  final int createdAt;
  int? pinnedAt; // ms epoch when the user pinned this conversation
  int expireTimerMs; // disappearing-messages TTL, 0 = off
  int expireTimerAt; // ms epoch of the last timer change (last-writer-wins)
  int? blockedAt; // ms epoch when the user blocked this contact (local-only)
  int? mutedUntil; // ms epoch until which the conversation is muted
  int? archivedAt; // ms epoch when the user archived this conversation
  Uint8List? avatar; // their profile photo (PROTOCOL.md "Profiles")
  int profileAt; // sent_at ms of the last applied profile (last-writer-wins)

  Contact({
    required this.zeonId,
    required this.displayName,
    required this.pubkeyB64,
    required this.status,
    this.serverAddress,
    this.tlsFp,
    this.hub,
    required this.createdAt,
    this.pinnedAt,
    this.expireTimerMs = 0,
    this.expireTimerAt = 0,
    this.blockedAt,
    this.mutedUntil,
    this.archivedAt,
    this.avatar,
    this.profileAt = 0,
  });

  bool get isAccepted => status == ContactStatus.accepted;
  bool get isPinned => pinnedAt != null;
  bool get isBlocked => blockedAt != null;
  bool get isMuted =>
      (mutedUntil ?? 0) > DateTime.now().millisecondsSinceEpoch;
  bool get isArchived => archivedAt != null;

  Map<String, Object?> toRow() => {
        'zeon_id': zeonId,
        'display_name': displayName,
        'pubkey': pubkeyB64,
        'status': status,
        'server_address': serverAddress,
        'tls_fp': tlsFp,
        'hub': hub,
        'created_at': createdAt,
        'pinned_at': pinnedAt,
        'expire_timer_ms': expireTimerMs,
        'expire_timer_at': expireTimerAt,
        'blocked_at': blockedAt,
        'muted_until': mutedUntil,
        'archived_at': archivedAt,
        'avatar': avatar,
        'profile_at': profileAt,
      };

  factory Contact.fromRow(Map<String, Object?> r) => Contact(
        zeonId: r['zeon_id'] as String,
        displayName: r['display_name'] as String,
        pubkeyB64: r['pubkey'] as String,
        status: r['status'] as String,
        serverAddress: r['server_address'] as String?,
        tlsFp: r['tls_fp'] as String?,
        hub: r['hub'] as String?,
        createdAt: r['created_at'] as int,
        pinnedAt: r['pinned_at'] as int?,
        expireTimerMs: r['expire_timer_ms'] as int,
        expireTimerAt: r['expire_timer_at'] as int,
        blockedAt: r['blocked_at'] as int?,
        mutedUntil: r['muted_until'] as int?,
        archivedAt: r['archived_at'] as int?,
        avatar: r['avatar'] == null
            ? null
            : Uint8List.fromList(r['avatar'] as List<int>),
        profileAt: r['profile_at'] as int,
      );
}

/// Mute choices. Mute is local-only: it silences this device's presentation
/// of a conversation; nothing about it ever reaches the wire.
class MuteDuration {
  /// Sentinel "until I unmute" — DateTime's maximum representable ms.
  static const forever = 8640000000000000;
  static const eightHours = 8 * 3600 * 1000;
  static const oneWeek = 7 * 24 * 3600 * 1000;

  static const options = [eightHours, oneWeek, forever];

  static String label(int ms) => switch (ms) {
        eightHours => '8 hours',
        oneWeek => '1 week',
        forever => 'Until I unmute',
        _ => '${(ms / 3600000).round()} hours',
      };
}

class MessageStatus {
  static const pending = 'pending'; // queued locally, recipient unreachable
  static const sent = 'sent'; // accepted by their routing server
  static const delivered = 'delivered'; // their device persisted it
  static const read = 'read'; // displayed on their screen

  /// Receipts only move a message forward: sent → delivered → read.
  static int rank(String s) => switch (s) {
        pending => 0,
        sent => 1,
        delivered => 2,
        read => 3,
        _ => 0,
      };
}

class MessageKind {
  static const text = 'text';
  static const image = 'image';
  static const audio = 'audio';
  static const video = 'video';
  static const file = 'file'; // document / arbitrary attachment
  static const sticker = 'sticker'; // small transparent image, no frame chrome
  static const call = 'call'; // local call epitaph ("Missed voice call")
  static const notice = 'notice'; // local system line ("… set disappearing messages …")
}

/// Disappearing-messages timer choices (PROTOCOL.md "Disappearing messages").
class ExpireTimer {
  static const options = [0, 3600000, 86400000, 604800000]; // off, 1h, 24h, 7d

  static String label(int ms) => switch (ms) {
        0 => 'Off',
        3600000 => '1 hour',
        86400000 => '24 hours',
        604800000 => '7 days',
        // A peer on a newer client may pick a duration we don't offer.
        _ => ms >= 86400000
            ? '${(ms / 86400000).round()} days'
            : '${(ms / 3600000).round()} hours',
      };
}

class Message {
  final String id;
  final String contactId; // conversation id: a peer's Zeon ID, or a group id
  final String? senderId; // group messages: which member sent it (null = DM/own)
  final bool outgoing;
  String text;
  final String kind; // MessageKind
  String? mediaPath; // local file for image/audio/video/file — never leaves the phone
  final int? durationMs; // audio / video only
  final String? fileName; // kind=file: the document's original name
  final int sentAt; // ms since epoch
  String status;
  int? editedAt; // ms since epoch, set when the sender edited the text
  bool deleted; // tombstone: sender deleted it for everyone
  final int? expiresAt; // ms epoch when this copy self-deletes (null = never)
  // Reply/quote snapshot (PROTOCOL.md "reply_to"): rendered from these fields,
  // never from the referenced message — the original may be gone (expired,
  // deleted, or never held). replyToSender is the quoted author's Zeon ID.
  final String? replyToId;
  final String? replyToSender;
  final String? replyToPreview;

  Message({
    required this.id,
    required this.contactId,
    this.senderId,
    required this.outgoing,
    required this.text,
    this.kind = MessageKind.text,
    this.mediaPath,
    this.durationMs,
    this.fileName,
    required this.sentAt,
    required this.status,
    this.editedAt,
    this.deleted = false,
    this.expiresAt,
    this.replyToId,
    this.replyToSender,
    this.replyToPreview,
  });

  Map<String, Object?> toRow() => {
        'id': id,
        'contact_id': contactId,
        'sender_id': senderId,
        'outgoing': outgoing ? 1 : 0,
        'text': text,
        'kind': kind,
        'media_path': mediaPath,
        'duration_ms': durationMs,
        'file_name': fileName,
        'sent_at': sentAt,
        'status': status,
        'edited_at': editedAt,
        'deleted': deleted ? 1 : 0,
        'expires_at': expiresAt,
        'reply_to_id': replyToId,
        'reply_to_sender': replyToSender,
        'reply_to_preview': replyToPreview,
      };

  factory Message.fromRow(Map<String, Object?> r) => Message(
        id: r['id'] as String,
        contactId: r['contact_id'] as String,
        senderId: r['sender_id'] as String?,
        outgoing: (r['outgoing'] as int) == 1,
        text: r['text'] as String,
        kind: r['kind'] as String,
        mediaPath: r['media_path'] as String?,
        durationMs: r['duration_ms'] as int?,
        fileName: r['file_name'] as String?,
        sentAt: r['sent_at'] as int,
        status: r['status'] as String,
        editedAt: r['edited_at'] as int?,
        deleted: (r['deleted'] as int) == 1,
        expiresAt: r['expires_at'] as int?,
        replyToId: r['reply_to_id'] as String?,
        replyToSender: r['reply_to_sender'] as String?,
        replyToPreview: r['reply_to_preview'] as String?,
      );

  String get preview => deleted
      ? 'Message deleted'
      : switch (kind) {
          MessageKind.image => '📷 Photo',
          MessageKind.audio => '🎤 Voice note',
          MessageKind.video => '🎬 Video',
          MessageKind.file => '📎 ${fileName ?? 'Document'}',
          MessageKind.sticker => '💟 Sticker',
          _ => text,
        };
}

class EnvelopeType {
  static const msg = 'msg';
  static const media = 'media';
  static const contactRequest = 'contact_request';
  static const contactAccept = 'contact_accept';
  static const profileUpdate = 'profile_update'; // display name + avatar
  static const groupCreate = 'group_create';
  static const groupUpdate = 'group_update';
  static const groupMsg = 'group_msg';
  static const groupLeave = 'group_leave';
  static const receipt = 'receipt'; // delivered/read, batched message ids
  static const typing = 'typing'; // transient, never queued or pushed
  static const msgEdit = 'msg_edit';
  static const msgDelete = 'msg_delete';
  static const groupMsgEdit = 'group_msg_edit';
  static const groupMsgDelete = 'group_msg_delete';
  static const reaction = 'reaction'; // emoji on a message ('' clears)
  static const groupReaction = 'group_reaction';
  static const timerUpdate = 'timer_update'; // disappearing-messages setting (DM)
  static const groupTimerUpdate = 'group_timer_update'; // same, any member
  static const callOffer = 'call_offer'; // SDP; wire form rings
  static const callAnswer = 'call_answer';
  static const callIce = 'call_ice'; // transient, like typing
  static const callEnd = 'call_end';
}

class ReceiptKind {
  static const delivered = 'delivered';
  static const read = 'read';
}

/// A group lives only on members' phones — no server knows it exists.
class Group {
  final String id;
  String name;
  final String adminId;
  int version;
  final int createdAt;
  int? pinnedAt; // ms epoch when the user pinned this conversation
  int expireTimerMs; // disappearing-messages TTL, 0 = off
  int expireTimerAt; // ms epoch of the last timer change (last-writer-wins)
  int? mutedUntil; // ms epoch until which the conversation is muted
  int? archivedAt; // ms epoch when the user archived this conversation

  Group({
    required this.id,
    required this.name,
    required this.adminId,
    required this.version,
    required this.createdAt,
    this.pinnedAt,
    this.expireTimerMs = 0,
    this.expireTimerAt = 0,
    this.mutedUntil,
    this.archivedAt,
  });

  bool get isPinned => pinnedAt != null;
  bool get isMuted =>
      (mutedUntil ?? 0) > DateTime.now().millisecondsSinceEpoch;
  bool get isArchived => archivedAt != null;

  Map<String, Object?> toRow() => {
        'id': id,
        'name': name,
        'admin_id': adminId,
        'version': version,
        'created_at': createdAt,
        'pinned_at': pinnedAt,
        'expire_timer_ms': expireTimerMs,
        'expire_timer_at': expireTimerAt,
        'muted_until': mutedUntil,
        'archived_at': archivedAt,
      };

  factory Group.fromRow(Map<String, Object?> r) => Group(
        id: r['id'] as String,
        name: r['name'] as String,
        adminId: r['admin_id'] as String,
        version: r['version'] as int,
        createdAt: r['created_at'] as int,
        pinnedAt: r['pinned_at'] as int?,
        expireTimerMs: r['expire_timer_ms'] as int,
        expireTimerAt: r['expire_timer_at'] as int,
        mutedUntil: r['muted_until'] as int?,
        archivedAt: r['archived_at'] as int?,
      );
}

class GroupMember {
  final String groupId;
  final String zeonId;
  final String pubkeyB64;
  String displayName;
  String? serverAddress; // cached, refreshed on delivery failure
  String? tlsFp; // pinned relay cert fingerprint, travels with the address

  GroupMember({
    required this.groupId,
    required this.zeonId,
    required this.pubkeyB64,
    required this.displayName,
    this.serverAddress,
    this.tlsFp,
  });

  Map<String, Object?> toRow() => {
        'group_id': groupId,
        'zeon_id': zeonId,
        'pubkey': pubkeyB64,
        'display_name': displayName,
        'server_address': serverAddress,
        'tls_fp': tlsFp,
      };

  factory GroupMember.fromRow(Map<String, Object?> r) => GroupMember(
        groupId: r['group_id'] as String,
        zeonId: r['zeon_id'] as String,
        pubkeyB64: r['pubkey'] as String,
        displayName: r['display_name'] as String,
        serverAddress: r['server_address'] as String?,
        tlsFp: r['tls_fp'] as String?,
      );
}

/// The inner envelope (PROTOCOL.md "Envelope") — what the recipient sees
/// after opening the sealed wire form. `ratchet` is the double-ratchet
/// header; `x3dh` appears only on a session's initial envelopes. Never
/// travels unsealed: servers see only [SealedEnvelope].
class Envelope {
  final int v;
  final String id;
  final String type;
  final String from;
  final String to;
  final String sentAt; // ISO-8601 UTC
  final Map<String, Object?> ratchet; // {dh, pn, n}
  final Map<String, Object?>? x3dh; // {ik, ek, spk_id, opk_id?}
  final String nonceB64;
  final String ciphertextB64;
  final String? blobId;

  Envelope({
    this.v = 1,
    required this.id,
    required this.type,
    required this.from,
    required this.to,
    required this.sentAt,
    required this.ratchet,
    this.x3dh,
    required this.nonceB64,
    required this.ciphertextB64,
    this.blobId,
  });

  Map<String, Object?> toJson() => {
        'v': v,
        'id': id,
        'type': type,
        'from': from,
        'to': to,
        'sent_at': sentAt,
        'ratchet': ratchet,
        if (x3dh != null) 'x3dh': x3dh,
        'nonce': nonceB64,
        'ciphertext': ciphertextB64,
        if (blobId != null) 'blob_id': blobId,
      };

  factory Envelope.fromJson(Map<String, dynamic> j) => Envelope(
        v: j['v'] as int,
        id: j['id'] as String,
        type: j['type'] as String,
        from: j['from'] as String,
        to: j['to'] as String,
        sentAt: j['sent_at'] as String,
        ratchet: (j['ratchet'] as Map).cast<String, Object?>(),
        x3dh: (j['x3dh'] as Map?)?.cast<String, Object?>(),
        nonceB64: j['nonce'] as String,
        ciphertextB64: j['ciphertext'] as String,
        blobId: j['blob_id'] as String?,
      );
}

/// The wire format (PROTOCOL.md "Envelope"). The recipient is the only
/// cleartext routing fact; sender, type and session header ride inside
/// `sealed` — an anonymous box only the recipient's identity key opens, so
/// the mailbox never learns who wrote. `blobId` (media envelopes) is the one
/// other cleartext hint, used by the server purely to garbage-collect the
/// blob on ack. Three optional delivery hints (PROTOCOL.md "Envelope"):
/// `transient` — deliver only if the owner is connected right now, never
/// queue, never push (typing, call ICE); `push: false` — queue and deliver
/// normally but never wake the owner's phone (receipts); `ring: true` —
/// queue and wake loudly (call offers). All are server-visible by
/// necessity; none says anything an observer couldn't already infer from
/// envelope size and timing.
class SealedEnvelope {
  final int v;
  final String id;
  final String to;
  final String sealedB64;
  final String? blobId;
  final bool transient;
  final bool noPush;
  final bool ring;

  SealedEnvelope({
    this.v = 1,
    required this.id,
    required this.to,
    required this.sealedB64,
    this.blobId,
    this.transient = false,
    this.noPush = false,
    this.ring = false,
  });

  Map<String, Object?> toJson() => {
        'v': v,
        'id': id,
        'to': to,
        'sealed': sealedB64,
        if (blobId != null) 'blob_id': blobId,
        if (transient) 'transient': true,
        if (noPush) 'push': false,
        if (ring) 'ring': true,
      };

  factory SealedEnvelope.fromJson(Map<String, dynamic> j) => SealedEnvelope(
        v: j['v'] as int,
        id: j['id'] as String,
        to: j['to'] as String,
        sealedB64: j['sealed'] as String,
        blobId: j['blob_id'] as String?,
        transient: j['transient'] as bool? ?? false,
        noPush: (j['push'] as bool?) == false,
        ring: j['ring'] as bool? ?? false,
      );
}
