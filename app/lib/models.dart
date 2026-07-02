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
  final int createdAt;

  Contact({
    required this.zeonId,
    required this.displayName,
    this.handle,
    required this.pubkeyB64,
    required this.status,
    this.serverAddress,
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
        'created_at': createdAt,
      };

  factory Contact.fromRow(Map<String, Object?> r) => Contact(
        zeonId: r['zeon_id'] as String,
        displayName: r['display_name'] as String,
        handle: r['handle'] as String?,
        pubkeyB64: r['pubkey'] as String,
        status: r['status'] as String,
        serverAddress: r['server_address'] as String?,
        createdAt: r['created_at'] as int,
      );
}

class MessageStatus {
  static const pending = 'pending'; // queued locally, recipient unreachable
  static const sent = 'sent'; // accepted by their routing server
}

class MessageKind {
  static const text = 'text';
  static const image = 'image';
  static const audio = 'audio';
}

class Message {
  final String id;
  final String contactId; // Zeon ID of the peer
  final bool outgoing;
  final String text;
  final String kind; // MessageKind
  final String? mediaPath; // local file for image/audio — never leaves the phone
  final int? durationMs; // audio only
  final int sentAt; // ms since epoch
  String status;

  Message({
    required this.id,
    required this.contactId,
    required this.outgoing,
    required this.text,
    this.kind = MessageKind.text,
    this.mediaPath,
    this.durationMs,
    required this.sentAt,
    required this.status,
  });

  Map<String, Object?> toRow() => {
        'id': id,
        'contact_id': contactId,
        'outgoing': outgoing ? 1 : 0,
        'text': text,
        'kind': kind,
        'media_path': mediaPath,
        'duration_ms': durationMs,
        'sent_at': sentAt,
        'status': status,
      };

  factory Message.fromRow(Map<String, Object?> r) => Message(
        id: r['id'] as String,
        contactId: r['contact_id'] as String,
        outgoing: (r['outgoing'] as int) == 1,
        text: r['text'] as String,
        kind: (r['kind'] as String?) ?? MessageKind.text,
        mediaPath: r['media_path'] as String?,
        durationMs: r['duration_ms'] as int?,
        sentAt: r['sent_at'] as int,
        status: r['status'] as String,
      );

  String get preview => switch (kind) {
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
}

/// The wire format. Ciphertext only — servers never see anything else.
/// `blobId` (media envelopes) is the one cleartext hint, used by the server
/// purely to garbage-collect the blob on ack.
class Envelope {
  final int v;
  final String id;
  final String type;
  final String from;
  final String to;
  final String sentAt; // ISO-8601 UTC
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
        nonceB64: j['nonce'] as String,
        ciphertextB64: j['ciphertext'] as String,
        blobId: j['blob_id'] as String?,
      );
}
