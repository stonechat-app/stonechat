/// The contact list, kept in step between a user's own devices
/// (PROTOCOL.md "Self-sync", `sync_contact`).
///
/// A device that adds, accepts or declines a contact tells its siblings with
/// one envelope carrying the contact as it now holds it. The wire form and
/// its checks live here, pure; `chat_state.dart` does the I/O around them.
library;

import 'dart:convert';
import 'dart:typed_data';

import '../models.dart';

/// `status` for a contact the sending device deleted.
const contactSyncRemoved = 'removed';

const _statuses = {
  ContactStatus.pendingOut,
  ContactStatus.pendingIn,
  ContactStatus.accepted,
  contactSyncRemoved,
};

/// The payload for [contact] as this device holds it, or for its removal.
Map<String, Object?> contactSyncPayload(
  Contact contact, {
  bool removed = false,
}) => {
  'peer': contact.stonechatId,
  'pubkey': contact.pubkeyB64,
  'status': removed ? contactSyncRemoved : contact.status,
  'display_name': contact.displayName,
  // Always present: null is "no photo", so a sibling converges on removals.
  'avatar': contact.avatar == null
      ? null
      : {'data': base64Encode(contact.avatar!), 'mime': 'image/jpeg'},
  if (contact.bundleToken != null) 'bundle_token': contact.bundleToken,
  if (contact.hub != null) 'hub': contact.hub,
};

/// A parsed `sync_contact`. [avatar] is absent (unchanged), null (cleared)
/// or bytes; [avatarGiven] says which.
class ContactSync {
  final String peer;
  final String pubkeyB64;
  final String status;
  final String? displayName;
  final bool avatarGiven;
  final Uint8List? avatar;
  final String? bundleToken;
  final String? hub;

  const ContactSync({
    required this.peer,
    required this.pubkeyB64,
    required this.status,
    this.displayName,
    this.avatarGiven = false,
    this.avatar,
    this.bundleToken,
    this.hub,
  });

  bool get removed => status == contactSyncRemoved;
}

/// Null for anything malformed. [pubkeyMatchesId] is the commitment check
/// (`CryptoService.pubkeyMatchesId`): a sync naming a key its ID does not
/// commit to is dropped whole, however it was authenticated.
ContactSync? parseContactSync(
  Map<String, dynamic> payload,
  bool Function(String pubkeyB64, String stonechatId) pubkeyMatchesId,
) {
  final peer = payload['peer'];
  final pubkey = payload['pubkey'];
  final status = payload['status'];
  if (peer is! String ||
      pubkey is! String ||
      status is! String ||
      !_statuses.contains(status) ||
      !pubkeyMatchesId(pubkey, peer)) {
    return null;
  }
  final name = payload['display_name'];
  final bundleToken = payload['bundle_token'];
  final hub = payload['hub'];
  var avatarGiven = false;
  Uint8List? avatar;
  if (payload.containsKey('avatar')) {
    final raw = payload['avatar'];
    if (raw == null) {
      avatarGiven = true;
    } else if (raw is Map && raw['data'] is String) {
      try {
        final bytes = base64Decode(raw['data'] as String);
        if (bytes.length <= 2 * avatarBytesMax) {
          avatarGiven = true;
          avatar = bytes;
        }
      } catch (_) {
        // malformed base64: treated as not given
      }
    }
  }
  return ContactSync(
    peer: peer,
    pubkeyB64: pubkey,
    status: status,
    displayName: name is String && name.trim().isNotEmpty ? name.trim() : null,
    avatarGiven: avatarGiven,
    avatar: avatar,
    bundleToken: bundleToken is String && bundleToken.isNotEmpty ? bundleToken : null,
    hub: hub is String && (hub.startsWith('https://') || hub.startsWith('http://'))
        ? hub
        : null,
  );
}
