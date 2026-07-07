/// Core data types. Mirrors PROTOCOL.md.
library;

class ContactStatus {
  static const pendingOut = 'pending_out'; // we sent a request, waiting
  static const pendingIn = 'pending_in'; // they sent us a request
  static const accepted = 'accepted';
}

class Contact {
  final String zeonId;
  String displayName;
  final String? handle; // zn-word-word-word, from the directory
  final String pubkeyB64;
  String status;
  String? serverAddress; // last known, refreshed from directory on demand
  String? tlsFp; // pinned relay cert fingerprint, travels with the address
  final int createdAt;

  Contact({
    required this.zeonId,
    required this.displayName,
    this.handle,
    required this.pubkeyB64,
    required this.status,
    this.serverAddress,
    this.tlsFp,
    required this.createdAt,
  });

  bool get isAccepted => status == ContactStatus.accepted;

  Map<String, Object?> toRow() => {
        'zeon_id': zeonId,
        'display_name': displayName,
        'handle': handle,
        'pubkey': pubkeyB64,
        'status': status,
        'server_address': serverAddress,
        'tls_fp': tlsFp,
        'created_at': createdAt,
      };

  factory Contact.fromRow(Map<String, Object?> r) => Contact(
        zeonId: r['zeon_id'] as String,
        displayName: r['display_name'] as String,
        handle: r['handle'] as String?,
        pubkeyB64: r['pubkey'] as String,
        status: r['status'] as String,
        serverAddress: r['server_address'] as String?,
        tlsFp: r['tls_fp'] as String?,
        createdAt: r['created_at'] as int,
      );
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
}

class Message {
  final String id;
  final String contactId; // conversation id: a peer's Zeon ID, or a group id
  final String? senderId; // group messages: which member sent it (null = DM/own)
  final bool outgoing;
  String text;
  final String kind; // MessageKind
  String? mediaPath; // local file for image/audio — never leaves the phone
  final int? durationMs; // audio only
  final int sentAt; // ms since epoch
  String status;
  int? editedAt; // ms since epoch, set when the sender edited the text
  bool deleted; // tombstone: sender deleted it for everyone

  Message({
    required this.id,
    required this.contactId,
    this.senderId,
    required this.outgoing,
    required this.text,
    this.kind = MessageKind.text,
    this.mediaPath,
    this.durationMs,
    required this.sentAt,
    required this.status,
    this.editedAt,
    this.deleted = false,
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
        'sent_at': sentAt,
        'status': status,
        'edited_at': editedAt,
        'deleted': deleted ? 1 : 0,
      };

  factory Message.fromRow(Map<String, Object?> r) => Message(
        id: r['id'] as String,
        contactId: r['contact_id'] as String,
        senderId: r['sender_id'] as String?,
        outgoing: (r['outgoing'] as int) == 1,
        text: r['text'] as String,
        kind: (r['kind'] as String?) ?? MessageKind.text,
        mediaPath: r['media_path'] as String?,
        durationMs: r['duration_ms'] as int?,
        sentAt: r['sent_at'] as int,
        status: r['status'] as String,
        editedAt: r['edited_at'] as int?,
        deleted: (r['deleted'] as int? ?? 0) == 1,
      );

  String get preview => deleted
      ? 'Message deleted'
      : switch (kind) {
          MessageKind.image => '📷 Photo',
          MessageKind.audio => '🎤 Voice note',
          _ => text,
        };
}

class EnvelopeType {
  static const msg = 'msg';
  static const media = 'media';
  static const contactRequest = 'contact_request';
  static const contactAccept = 'contact_accept';
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

  Group({
    required this.id,
    required this.name,
    required this.adminId,
    required this.version,
    required this.createdAt,
  });

  Map<String, Object?> toRow() => {
        'id': id,
        'name': name,
        'admin_id': adminId,
        'version': version,
        'created_at': createdAt,
      };

  factory Group.fromRow(Map<String, Object?> r) => Group(
        id: r['id'] as String,
        name: r['name'] as String,
        adminId: r['admin_id'] as String,
        version: r['version'] as int,
        createdAt: r['created_at'] as int,
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
/// blob on ack. Two optional delivery hints (PROTOCOL.md "Envelope"):
/// `transient` — deliver only if the owner is connected right now, never
/// queue, never push (typing indicators); `push: false` — queue and deliver
/// normally but never wake the owner's phone (receipts). Both are
/// server-visible by necessity; neither says anything an observer couldn't
/// already infer from envelope size.
class SealedEnvelope {
  final int v;
  final String id;
  final String to;
  final String sealedB64;
  final String? blobId;
  final bool transient;
  final bool noPush;

  SealedEnvelope({
    this.v = 1,
    required this.id,
    required this.to,
    required this.sealedB64,
    this.blobId,
    this.transient = false,
    this.noPush = false,
  });

  Map<String, Object?> toJson() => {
        'v': v,
        'id': id,
        'to': to,
        'sealed': sealedB64,
        if (blobId != null) 'blob_id': blobId,
        if (transient) 'transient': true,
        if (noPush) 'push': false,
      };

  factory SealedEnvelope.fromJson(Map<String, dynamic> j) => SealedEnvelope(
        v: j['v'] as int,
        id: j['id'] as String,
        to: j['to'] as String,
        sealedB64: j['sealed'] as String,
        blobId: j['blob_id'] as String?,
        transient: j['transient'] as bool? ?? false,
        noPush: (j['push'] as bool?) == false,
      );
}
