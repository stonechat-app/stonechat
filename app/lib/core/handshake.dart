/// Which session survives when an initial envelope arrives over one we
/// already hold (PROTOCOL.md "PQXDH", the two collisions).
///
/// Pure, so the decision is testable without a ratchet. `chat_state.dart`
/// supplies what it knows and does what the verdict says.
library;

enum HandshakeVerdict {
  /// Decrypt on the session we hold; no handshake is involved.
  useHeld,

  /// Both sides started a session with each other and theirs wins the
  /// tie-break: skip ours and establish theirs from the block.
  adoptTheirs,

  /// Both sides started one and ours wins: drop their initial envelope. Their
  /// side adopts ours; replacing ours here would leave each holding the
  /// other's session and nothing that decrypts.
  dropTheirs,

  /// The held session no longer decrypts and the envelope carries a valid
  /// handshake: a peer who reinstalled. Establish from the block.
  replaceHeld,
}

/// Decide, before trying to decrypt. [heldDecrypts] is consulted lazily and
/// only when the answer depends on it, because a decryption attempt that
/// fails is not free of side effects for the caller's logging.
HandshakeVerdict handshakeVerdict({
  required bool hasBlock,
  required bool heldConfirmed,
  required bool heldInitiatedByUs,
  required String from,
  required int fromDevice,
  required String self,
  required int selfDevice,
  required bool Function() heldDecrypts,
}) {
  final racing = hasBlock && !heldConfirmed && heldInitiatedByUs;
  // The lower Stonechat ID wins; between two of one user's own devices the
  // IDs are equal and the lower device number does.
  final theirsWin =
      racing &&
      (from.compareTo(self) < 0 || (from == self && fromDevice < selfDevice));
  if (theirsWin) return HandshakeVerdict.adoptTheirs;
  if (heldDecrypts()) return HandshakeVerdict.useHeld;
  if (!hasBlock) return HandshakeVerdict.useHeld; // the caller drops it
  if (racing) return HandshakeVerdict.dropTheirs;
  return HandshakeVerdict.replaceHeld;
}
