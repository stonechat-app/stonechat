/// Core data types. Mirrors PROTOCOL.md.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'core/wire_ids.dart';

class ContactStatus {
  static const pendingOut = 'pending_out'; // we sent a request, waiting
  static const pendingIn = 'pending_in'; // they sent us a request
  static const accepted = 'accepted';
}

class Contact {
  final String stonechatId;
  String displayName;
  final String pubkeyB64;
  String? pqPkB64; // directory pq_pk, sig-verified on resolve; nothing is sealed to it
  String status;
  String? mailboxAddress; // last known, refreshed from directory on demand
  String? tlsFp; // pinned relay cert fingerprint, travels with the address
  String? hub; // home hub base URL; null = the hub this app uses (cross-hub)
  final int createdAt;
  int? pinnedAt; // ms epoch when the user pinned this conversation
  int expireTimerMs; // disappearing-messages TTL, 0 = off
  int expireTimerAt; // ms epoch of the last timer change (last-writer-wins)
  int? mutedUntil; // ms epoch until which the conversation is muted
  int? archivedAt; // ms epoch when the user archived this conversation
  Uint8List? avatar; // their profile photo (PROTOCOL.md "Profiles")
  int profileAt; // sent_at ms of the last applied profile (last-writer-wins)
  /// The peer's device-set version, as last seen on an /inbox response. A bump
  /// means re-fetch their device list, X3DH to anything new, and drop sessions
  /// for anything gone.
  /// 0 = never observed, so the first send learns it.
  int devicesV;
  /// The capability that lets us list their devices at all. Handed to us in
  /// their contact_request/contact_accept; without it we can only reach their
  /// primary device, which is exactly what a stranger gets.
  String? bundleToken;

  Contact({
    required this.stonechatId,
    required this.displayName,
    required this.pubkeyB64,
    this.pqPkB64,
    required this.status,
    this.mailboxAddress,
    this.tlsFp,
    this.hub,
    required this.createdAt,
    this.pinnedAt,
    this.expireTimerMs = 0,
    this.expireTimerAt = 0,
    this.mutedUntil,
    this.archivedAt,
    this.avatar,
    this.profileAt = 0,
    this.devicesV = 0,
    this.bundleToken,
  });

  bool get isAccepted => status == ContactStatus.accepted;
  bool get isPinned => pinnedAt != null;
  bool get isMuted =>
      (mutedUntil ?? 0) > DateTime.now().millisecondsSinceEpoch;
  bool get isArchived => archivedAt != null;

  Map<String, Object?> toRow() => {
        'stonechat_id': stonechatId,
        'display_name': displayName,
        'pubkey': pubkeyB64,
        'pq_pk': pqPkB64,
        'status': status,
        'mailbox_address': mailboxAddress,
        'tls_fp': tlsFp,
        'hub': hub,
        'created_at': createdAt,
        'pinned_at': pinnedAt,
        'expire_timer_ms': expireTimerMs,
        'expire_timer_at': expireTimerAt,
        'muted_until': mutedUntil,
        'archived_at': archivedAt,
        'avatar': avatar,
        'profile_at': profileAt,
        'devices_v': devicesV,
        'bundle_token': bundleToken,
      };

  factory Contact.fromRow(Map<String, Object?> r) => Contact(
        stonechatId: r['stonechat_id'] as String,
        displayName: r['display_name'] as String,
        pubkeyB64: r['pubkey'] as String,
        pqPkB64: r['pq_pk'] as String?,
        status: r['status'] as String,
        mailboxAddress: r['mailbox_address'] as String?,
        tlsFp: r['tls_fp'] as String?,
        hub: r['hub'] as String?,
        createdAt: r['created_at'] as int,
        pinnedAt: r['pinned_at'] as int?,
        expireTimerMs: r['expire_timer_ms'] as int,
        expireTimerAt: r['expire_timer_at'] as int,
        mutedUntil: r['muted_until'] as int?,
        archivedAt: r['archived_at'] as int?,
        avatar: r['avatar'] == null
            ? null
            : Uint8List.fromList(r['avatar'] as List<int>),
        profileAt: r['profile_at'] as int,
        devicesV: (r['devices_v'] as int?) ?? 0,
        bundleToken: r['bundle_token'] as String?,
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
  static const sent = 'sent'; // accepted by their mailbox
  static const delivered = 'delivered'; // their device persisted it
  static const read = 'read'; // displayed on their screen

  /// Nobody is trying any more: either the send was *refused* (a directory or
  /// prekey that doesn't verify — retrying a lie never helps) or it stayed
  /// undeliverable past the give-up window. Only a manual retry leaves this
  /// state; an honest failure beats a spinner that never resolves.
  static const failed = 'failed';

  /// Receipts only move a message forward: sent → delivered → read.
  /// `failed` ranks with `pending` on purpose — if a receipt somehow arrives
  /// for a message we gave up on, it *did* land, and the receipt heals it.
  static int rank(String s) => switch (s) {
        pending => 0,
        failed => 0,
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
  final String contactId; // conversation id: a peer's Stonechat ID, or a group id
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
  // deleted, or never held). replyToSender is the quoted author's Stonechat ID.
  final String? replyToId;
  final String? replyToSender;
  final String? replyToPreview;
  /// Outgoing group media only: the one shared blob this message's fan-out
  /// points at (PROTOCOL.md "Group media"). Persisted because a retry to a
  /// member we couldn't reach must reference the *same* upload — re-encrypting
  /// would mint a new key that the already-parked ciphertext doesn't match —
  /// and because the sender deletes the blob once everyone has it. Cleared
  /// then; null for everything else.
  SharedBlob? blob;
  /// Why the last send attempt didn't land, in words meant for the user.
  /// Set on every failed attempt (not just terminal ones) so a still-retrying
  /// message can explain itself; cleared once it goes out.
  String? failReason;
  /// Send-attempt bookkeeping for the retry backoff: how many attempts this
  /// message has cost and when the last one was. Outgoing messages only.
  int attempts;
  int? lastAttemptAt;

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
    this.blob,
    this.failReason,
    this.attempts = 0,
    this.lastAttemptAt,
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
        'blob': blob == null ? null : jsonEncode(blob!.toJson()),
        'fail_reason': failReason,
        'attempts': attempts,
        'last_attempt_at': lastAttemptAt,
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
        blob: r['blob'] == null
            ? null
            : SharedBlob.fromJson(
                jsonDecode(r['blob'] as String) as Map<String, dynamic>,
              ),
        failReason: r['fail_reason'] as String?,
        attempts: (r['attempts'] as int?) ?? 0,
        lastAttemptAt: r['last_attempt_at'] as int?,
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

/// The sender's half of a group-media upload: one encrypted blob parked on
/// their own mailbox, plus everything a member needs to fetch and open it
/// (PROTOCOL.md "Group media"). The key lives here only until the fan-out
/// completes and the blob is deleted — it rides the ratchet to members, and
/// never reaches the mailbox holding the ciphertext.
class SharedBlob {
  final String id;
  final String fetchToken;
  final String keyB64;
  final String nonceB64;
  final int size;
  /// The mailbox that accepted the upload, and the cert to pin when talking
  /// to it. Recorded rather than read from the current mailbox settings: a
  /// retry — or a cleanup after the user moves house — must reach the box
  /// that actually holds the bytes.
  final String host;
  final String tlsFp;

  const SharedBlob({
    required this.id,
    required this.fetchToken,
    required this.keyB64,
    required this.nonceB64,
    required this.size,
    required this.host,
    required this.tlsFp,
  });

  Map<String, Object?> toJson() => {
        'id': id,
        'fetch_token': fetchToken,
        'key': keyB64,
        'nonce': nonceB64,
        'size': size,
        'host': host,
        'tls_fp': tlsFp,
      };

  factory SharedBlob.fromJson(Map<String, dynamic> j) => SharedBlob(
        id: j['id'] as String,
        fetchToken: j['fetch_token'] as String,
        keyB64: j['key'] as String,
        nonceB64: j['nonce'] as String,
        size: j['size'] as int,
        host: j['host'] as String,
        tlsFp: j['tls_fp'] as String,
      );
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
  static const groupMedia = 'group_media'; // one shared blob on the sender's box
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

  // Self-sync: state mirrored between one
  // user's own devices over ordinary pairwise sessions. Applied only when
  // `from` is our own identity, which the session already authenticates.
  static const syncSent = 'sync_sent'; // a copy of an outgoing message
  static const syncRead = 'sync_read'; // read-state convergence
  /// One conversation's history cleared. Carries no messages — the receiver
  /// drops what it holds for that peer, which is the only thing that makes
  /// "clear chat" mean anything on a user who has more than one device.
  static const syncClear = 'sync_clear';
  /// Someone blocked or unblocked — `{"peer", "blocked_at"|null}`. Blocks are
  /// local-only, so this is the only way a second device learns of one.
  static const syncBlock = 'sync_block';
}

class ReceiptKind {
  static const delivered = 'delivered';
  static const read = 'read';
}

/// A group lives only on members' phones — neither the hub nor any
/// mailbox knows it exists.
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
  final String stonechatId;
  final String pubkeyB64;
  String? pqPkB64; // directory pq_pk, sig-verified on resolve; nothing is sealed to it
  String displayName;
  String? mailboxAddress; // cached, refreshed on delivery failure
  String? tlsFp; // pinned relay cert fingerprint, travels with the address
  /// Learned from any envelope they send us — a fellow member need never
  /// have been a contact, so this is the only way we get it. Null until then,
  /// which means we can reach only their primary device.
  String? bundleToken;

  GroupMember({
    required this.groupId,
    required this.stonechatId,
    required this.pubkeyB64,
    this.pqPkB64,
    required this.displayName,
    this.mailboxAddress,
    this.tlsFp,
    this.bundleToken,
  });

  Map<String, Object?> toRow() => {
        'group_id': groupId,
        'stonechat_id': stonechatId,
        'pubkey': pubkeyB64,
        'pq_pk': pqPkB64,
        'display_name': displayName,
        'mailbox_address': mailboxAddress,
        'tls_fp': tlsFp,
        'bundle_token': bundleToken,
      };

  factory GroupMember.fromRow(Map<String, Object?> r) => GroupMember(
        groupId: r['group_id'] as String,
        stonechatId: r['stonechat_id'] as String,
        pubkeyB64: r['pubkey'] as String,
        pqPkB64: r['pq_pk'] as String?,
        displayName: r['display_name'] as String,
        mailboxAddress: r['mailbox_address'] as String?,
        tlsFp: r['tls_fp'] as String?,
        bundleToken: r['bundle_token'] as String?,
      );
}

/// The inner envelope (PROTOCOL.md "Envelope") — what the recipient sees
/// after opening the sealed wire form. `ratchet` is the double-ratchet
/// header; `x3dh` appears only on a session's initial envelopes. Never
/// travels unsealed: mailboxes see only [SealedEnvelope].
class Envelope {
  final int v;
  final String id;
  final String type;
  final String from;
  /// Which of the sender's devices wrote this. All of a user's devices
  /// send under the same SC- ID, so this number is what names the ratchet —
  /// and the device certificate — the message belongs to, which is why the
  /// AEAD binds it.
  final int fromDevice;
  final String to;
  /// Which of *our* devices it was addressed to. Also AEAD-bound: the pair
  /// names the exact ratchet, and no other ratchet can open the message.
  final int device;
  final String sentAt; // ISO-8601 UTC
  final Map<String, Object?> ratchet; // {dh, pn, n}
  final Map<String, Object?>? x3dh; // {ik, cert, ek, spk_id, opk_id?, kct, kem_id, kem_one_time}
  final String nonceB64;
  final String ciphertextB64;
  final String? blobId;
  /// Our own mailbox's bundle token, so the recipient can list our devices
  /// and encrypt to all of them.
  ///
  /// Rides every envelope rather than a dedicated announcement: it is inside
  /// the seal, so only the recipient reads it; it is ~64 bytes against a
  /// 64 KB cap; and it makes the audience exactly "people who have received
  /// something from us", which is a boundary the multi-device design already
  /// accepts. A dedicated distribution would have needed one mechanism for
  /// contacts and another for group members who were never contacts.
  final String? bundleToken;

  Envelope({
    this.v = 1,
    required this.id,
    required this.type,
    required this.from,
    required this.fromDevice,
    required this.to,
    required this.device,
    required this.sentAt,
    required this.ratchet,
    this.x3dh,
    required this.nonceB64,
    required this.ciphertextB64,
    this.blobId,
    this.bundleToken,
  });

  Map<String, Object?> toJson() => {
        'v': v,
        'id': id,
        'type': type,
        'from': from,
        'from_device': fromDevice,
        'to': to,
        'device': device,
        'sent_at': sentAt,
        'ratchet': ratchet,
        if (x3dh != null) 'x3dh': x3dh,
        'nonce': nonceB64,
        'ciphertext': ciphertextB64,
        if (blobId != null) 'blob_id': blobId,
        if (bundleToken != null) 'bundle_token': bundleToken,
      };

  /// Throws on anything malformed, ids included: `id` names the media file
  /// and `blob_id` is put in a URL, so neither is taken on trust.
  factory Envelope.fromJson(Map<String, dynamic> j) => Envelope(
        v: j['v'] as int,
        id: _wireId(j['id'], 'id'),
        type: j['type'] as String,
        from: j['from'] as String,
        fromDevice: j['from_device'] as int,
        to: j['to'] as String,
        device: j['device'] as int,
        sentAt: j['sent_at'] as String,
        ratchet: (j['ratchet'] as Map).cast<String, Object?>(),
        x3dh: (j['x3dh'] as Map?)?.cast<String, Object?>(),
        nonceB64: j['nonce'] as String,
        ciphertextB64: j['ciphertext'] as String,
        blobId: j['blob_id'] == null ? null : _wireId(j['blob_id'], 'blob_id'),
        bundleToken: j['bundle_token'] as String?,
      );

  static String _wireId(Object? value, String field) => isWireId(value)
      ? value as String
      : throw FormatException('envelope $field is not a UUID');
}

/// The wire format (PROTOCOL.md "Envelope"). The recipient and the
/// recipient device are the only cleartext routing facts; sender, type and
/// session header ride inside `sealed` — an anonymous box only the
/// addressed device's seal key opens, so the envelope names no sender (the
/// mailbox still sees the sender's network address). `blobId` (media
/// envelopes) is the one other cleartext hint, used by the mailbox purely
/// to garbage-collect the blob once no queued envelope names it. Three optional delivery hints (PROTOCOL.md "Envelope"):
/// `transient` — deliver only if the owner is connected right now, never
/// queue, never push (typing, call ICE); `push: false` — queue and deliver
/// normally but never wake the owner's phone (receipts); `ring: true` —
/// queue and wake loudly (call offers). All are mailbox-visible by
/// necessity; none says anything an observer couldn't already infer from
/// envelope size and timing.
class SealedEnvelope {
  final int v;
  final String id;
  final String to;
  /// The recipient device whose queue this belongs in — the one cleartext
  /// field the relay needs beyond `to`. It reveals nothing new: it is only
  /// meaningful to the recipient's own mailbox, which *is* the device
  /// registry. Bound into the inner AEAD, so tampering costs delivery.
  final int device;
  final String sealedB64;
  final String? blobId;
  final bool transient;
  final bool noPush;
  final bool ring;

  SealedEnvelope({
    this.v = 1,
    required this.id,
    required this.to,
    required this.device,
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
        'device': device,
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
        device: j['device'] as int,
        sealedB64: j['sealed'] as String,
        blobId: j['blob_id'] as String?,
        transient: j['transient'] as bool? ?? false,
        noPush: (j['push'] as bool?) == false,
        ring: j['ring'] as bool? ?? false,
      );
}
