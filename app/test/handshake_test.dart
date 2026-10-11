// Which session survives when an initial envelope arrives over one we hold
// (lib/core/handshake.dart): PROTOCOL.md's two collisions, decided in one
// place and without a ratchet.
import 'package:flutter_test/flutter_test.dart';
import 'package:stonechat/core/handshake.dart';

HandshakeVerdict _verdict({
  bool hasBlock = true,
  bool heldConfirmed = false,
  bool heldInitiatedByUs = true,
  String from = 'SC-B',
  int fromDevice = 1,
  String self = 'SC-A',
  int selfDevice = 1,
  bool decrypts = false,
}) => handshakeVerdict(
  hasBlock: hasBlock,
  heldConfirmed: heldConfirmed,
  heldInitiatedByUs: heldInitiatedByUs,
  from: from,
  fromDevice: fromDevice,
  self: self,
  selfDevice: selfDevice,
  heldDecrypts: () => decrypts,
);

void main() {
  test('a message that decrypts on the held session uses it', () {
    expect(_verdict(decrypts: true, hasBlock: false), HandshakeVerdict.useHeld);
    expect(_verdict(decrypts: true, heldConfirmed: true), HandshakeVerdict.useHeld);
  });

  test('no block and no decryption is a drop (reported as useHeld)', () {
    expect(_verdict(hasBlock: false), HandshakeVerdict.useHeld);
  });

  test('a fresh handshake replaces a confirmed session that no longer decrypts', () {
    // A peer who reinstalled.
    expect(_verdict(heldConfirmed: true), HandshakeVerdict.replaceHeld);
    expect(
      _verdict(heldConfirmed: false, heldInitiatedByUs: false),
      HandshakeVerdict.replaceHeld,
    );
  });

  group('simultaneous start: both hold an unconfirmed session they initiated', () {
    test('the lower Stonechat ID wins; the higher adopts', () {
      // We are SC-A (lower), they are SC-B: ours wins, theirs is dropped.
      expect(_verdict(from: 'SC-B', self: 'SC-A'), HandshakeVerdict.dropTheirs);
      // We are SC-B (higher): theirs wins, before any decryption is tried.
      var tried = false;
      final v = handshakeVerdict(
        hasBlock: true,
        heldConfirmed: false,
        heldInitiatedByUs: true,
        from: 'SC-A',
        fromDevice: 1,
        self: 'SC-B',
        selfDevice: 1,
        heldDecrypts: () {
          tried = true;
          return false;
        },
      );
      expect(v, HandshakeVerdict.adoptTheirs);
      expect(tried, isFalse);
    });

    test('between two of our own devices, the lower device number wins', () {
      // Same identity: the phone (1) against a browser (2).
      expect(
        _verdict(from: 'SC-A', fromDevice: 1, self: 'SC-A', selfDevice: 2),
        HandshakeVerdict.adoptTheirs,
      );
      expect(
        _verdict(from: 'SC-A', fromDevice: 2, self: 'SC-A', selfDevice: 1),
        HandshakeVerdict.dropTheirs,
      );
    });

    test('a block that does decrypt on ours is not a race at all', () {
      expect(_verdict(from: 'SC-B', self: 'SC-A', decrypts: true), HandshakeVerdict.useHeld);
    });
  });
}
