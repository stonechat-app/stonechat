/// Where a linked device's mailbox is, once the directory has answered
/// (PROTOCOL.md "Directory resolution"; CLAUDE.md: a directory answer is
/// checked against the ID that was asked for, and for a known identity with
/// the key already held).
///
/// A linked device holds its mailbox's coordinates from the link grant. The
/// directory may move them — the primary moved mailboxes — but only on the
/// identity's own word: the new fingerprint has to be signed by the identity
/// key, and *this device already holds that key*. Verifying the signature
/// with the key in the answer, as the first version did, verifies nothing: a
/// hub signs any fingerprint with a key it made up and returns both.
library;

import 'api.dart' show DirectoryEntry;

/// The coordinates to move to, or `null` to keep the held ones. [reason]
/// gets why an answer was not followed; following nothing is never an error.
({String address, String tlsFp})? linkedMailboxMove(
  DirectoryEntry entry, {
  required String askedFor,
  required String identityPubkeyB64,
  required String? heldAddress,
  required String? heldTlsFp,
  required bool Function(String fp, String sig) vouchedByIdentity,
  void Function(String reason)? reason,
}) {
  // Our own record, as the key we hold defines it. A different key cannot be
  // ours whatever it signs; a different ID is somebody else's record.
  if (entry.stonechatId != askedFor || entry.pubkeyB64 != identityPubkeyB64) {
    reason?.call('directory answered with another identity');
    return null;
  }
  final address = entry.mailboxAddress;
  final fp = entry.mailboxTlsFp;
  final sig = entry.mailboxTlsSig;
  if (address == null || fp == null || sig == null) return null;
  if (address == heldAddress && fp == heldTlsFp) return null;
  if (Uri.tryParse(address)?.scheme != 'https') {
    reason?.call('mailbox address is not https');
    return null;
  }
  if (!vouchedByIdentity(fp, sig)) {
    reason?.call('mailbox fingerprint is not signed by our identity');
    return null;
  }
  return (address: address, tlsFp: fp);
}
