/// Where a sibling device says a blob of ours is (PROTOCOL.md "Device sync":
/// `sync_sent` media and `sync_history`).
///
/// A sibling parks a blob on our own mailbox and tells the other devices
/// where to fetch it: `blob_host`, `blob_tls_fp`, `fetch_token`. Those three
/// fields would, taken as given, send this device to any server, pin any
/// certificate, and log in with any token — and a `sync_sent` without a
/// `fetch_token` used to fall back to the device's own mailbox token, which on
/// the primary is the owner token. A linked device, which holds no such token
/// by design, could name a server it ran and collect it.
///
/// So the payload does not get to say where the blob is. Our mailbox is the
/// one place a sibling can have put it, and this device already knows its
/// address and its certificate: the payload must agree with both, must carry
/// the blob's own fetch token, and nothing else is ever used.
library;

import 'wire_ids.dart';

/// Checked coordinates of a blob a sibling parked for us on our own mailbox.
typedef SiblingBlob = ({String host, String tlsFp, String blobId, String token});

/// The blob to fetch, or `null` with [reason] set when the payload does not
/// describe a blob on our own mailbox. [mailboxAddress] and [mailboxTlsFp]
/// are what this device holds for its own mailbox; the caller decides what
/// not knowing them yet means (it is transient — the envelope can wait).
SiblingBlob? siblingBlobFrom(
  Map<String, dynamic> payload, {
  required String mailboxAddress,
  required String mailboxTlsFp,
  required void Function(String reason) reason,
}) {
  final host = payload['blob_host'];
  final tlsFp = payload['blob_tls_fp'];
  final blobId = payload['blob_id'];
  final token = payload['fetch_token'];
  if (host is! String || tlsFp is! String || !isWireId(blobId)) {
    reason('malformed blob coordinates');
    return null;
  }
  if (token is! String || token.isEmpty) {
    // Never substitute this device's own mailbox token: that is a login to
    // the mailbox, not a capability on one blob.
    reason('no fetch_token for the blob');
    return null;
  }
  if (host != mailboxAddress) {
    reason('blob is not on our own mailbox');
    return null;
  }
  if (tlsFp != mailboxTlsFp) {
    reason('blob_tls_fp is not our own mailbox\'s certificate');
    return null;
  }
  return (host: host, tlsFp: tlsFp, blobId: blobId as String, token: token);
}
