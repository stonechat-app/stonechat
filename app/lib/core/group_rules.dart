/// The group rules that are decisions rather than plumbing (PROTOCOL.md
/// "Groups"): which roster a client accepts, how two members' views of the
/// roster compare, and the hashes that let members notice when what they
/// hold differs. Pure functions — chat_state.dart does the I/O around them.
library;

import 'dart:convert';
import 'dart:typed_data';

/// How many people the app lets an admin put in a group. Fan-out is
/// O(members × devices) per message.
const groupMemberCap = 25;

/// The largest roster a receiver accepts. Above the cap the app builds, so a
/// later, larger cap does not strand older clients — and bounded, so one
/// envelope cannot make a client fan out to thousands of mailboxes.
const groupRosterMax = 100;

/// How many earlier messages one group message vouches for (`seen`).
const groupSeenMax = 4;

/// Unkeyed BLAKE2b-256, base64 — `CryptoService.hashB64`.
typedef HashB64 = String Function(Uint8List data);

/// What a roster commits to: the group, its version, its admin and who is in
/// it. Names are display data and stay out. Computed over the roster **as the
/// admin issued it** — a `group_leave` applied locally does not change it —
/// so two members at the same version hold the same hash unless the admin
/// told them different things.
String rosterHash(
  HashB64 hash, {
  required String groupId,
  required int version,
  required String admin,
  required Iterable<String> memberIds,
}) {
  final ids = memberIds.toList()..sort();
  return hash(
    utf8.encode('stonechat-v1-roster|$groupId|$version|$admin|${ids.join(',')}'),
  );
}

/// The part of a group message a content hash covers: its text, or for
/// media the blob and the key that opens it. Null for a payload that is
/// neither.
String? groupMessageBody(Map<String, dynamic> payload) {
  final text = payload['text'];
  if (text is String) return 'text|$text';
  final blobId = payload['blob_id'];
  final key = payload['key'];
  final nonce = payload['blob_nonce'];
  if (blobId is String && key is String && nonce is String) {
    return 'media|$blobId|$key|$nonce';
  }
  return null;
}

/// What one member received as message [id] from [senderId]. [salt] is random
/// per message and travels inside it, so someone who was never sent the
/// message cannot test guesses of its text against the hash. The body goes
/// last: it is the only field that may contain `|`.
String groupMessageHash(
  HashB64 hash, {
  required String groupId,
  required String senderId,
  required String id,
  required String salt,
  required String body,
}) => hash(utf8.encode('stonechat-v1-gmsg|$groupId|$senderId|$id|$salt|$body'));

/// The `roster` block of a group message: the sender's view of membership.
class RosterClaim {
  final int version;
  final String? hash;
  final String? admin;
  const RosterClaim(this.version, this.hash, this.admin);

  /// Null when absent or malformed — an older client sends none, and that
  /// is not an error.
  static RosterClaim? from(Map<String, dynamic> payload) {
    final r = payload['roster'];
    if (r is! Map) return null;
    final v = r['v'];
    if (v is! int || v < 0) return null;
    final h = r['h'];
    final admin = r['admin'];
    return RosterClaim(
      v,
      h is String ? h : null,
      admin is String ? admin : null,
    );
  }
}

enum RosterView {
  /// Same version, and the same roster as far as either side can tell.
  same,

  /// The sender did not say.
  unknown,

  /// The sender holds a newer roster than we do: we missed an update.
  peerAhead,

  /// The sender holds an older one: they missed an update.
  peerBehind,

  /// Same version, different members. Only an admin (or two of its devices)
  /// issuing two rosters under one version produces this.
  diverged,
}

RosterView compareRoster({
  required int heldVersion,
  required String? heldHash,
  required RosterClaim? claim,
}) {
  if (claim == null) return RosterView.unknown;
  if (claim.version > heldVersion) return RosterView.peerAhead;
  if (claim.version < heldVersion) return RosterView.peerBehind;
  if (heldHash != null && claim.hash != null && heldHash != claim.hash) {
    return RosterView.diverged;
  }
  return RosterView.same;
}

/// The outcome of checking a `group_create` / `group_update`.
class MembershipVerdict {
  /// Why the roster is refused; null when it is accepted.
  final String? rejected;

  /// Accepted, and it names a different admin than the one we recorded.
  final bool handover;

  const MembershipVerdict.accept({this.handover = false}) : rejected = null;
  const MembershipVerdict.reject(String reason)
    : rejected = reason,
      handover = false;

  bool get accepted => rejected == null;
}

/// Whether a roster from [from] may replace what we hold.
///
/// [memberIds] are the roster's IDs, each already checked against its key.
/// [held] is the group as we hold it, null on first sight. [senderIsContact]
/// is whether [from] is an accepted contact of ours, or ourselves (one of our
/// own devices mirroring a group it administers).
MembershipVerdict checkMembership({
  required String from,
  required String payloadAdmin,
  required int version,
  required List<String> memberIds,
  required ({String adminId, int version})? held,
  required bool senderIsContact,
}) {
  if (memberIds.length > groupRosterMax) {
    return const MembershipVerdict.reject('roster is larger than a group may be');
  }
  if (memberIds.toSet().length != memberIds.length) {
    return const MembershipVerdict.reject('roster lists a member twice');
  }
  if (!memberIds.contains(payloadAdmin)) {
    return const MembershipVerdict.reject('roster names an admin who is not in it');
  }
  if (held == null) {
    // First sight. Only the admin introduces a group, and only someone we
    // have accepted as a contact may put us in one: other members can be
    // strangers, the person who adds us cannot.
    if (from != payloadAdmin) {
      return const MembershipVerdict.reject('not from the admin it names');
    }
    if (!senderIsContact) {
      return const MembershipVerdict.reject('group invite from a non-contact');
    }
    return const MembershipVerdict.accept();
  }
  // A group we hold: only the admin we recorded speaks for it. Checking
  // `from` against the payload's own `admin` instead would let any member
  // take the group by naming themselves — whereas the recorded admin naming
  // someone else is exactly how the role is handed over.
  if (from != held.adminId) {
    return const MembershipVerdict.reject('not from the admin on record');
  }
  if (version <= held.version) {
    return const MembershipVerdict.reject('stale or replayed roster');
  }
  return MembershipVerdict.accept(handover: payloadAdmin != held.adminId);
}
