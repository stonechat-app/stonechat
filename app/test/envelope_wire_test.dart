// The wire format is the contract with every other client and with the relay
// (PROTOCOL.md "Envelope", MULTIDEVICE.md). These pin the parts multi-device
// added: both device numbers, and the bundle token that rides inside the seal.
import 'package:flutter_test/flutter_test.dart';
import 'package:stonechat/models.dart';

Envelope inner({
  int fromDevice = 1,
  int device = 1,
  String? bundleToken,
  String? blobId,
}) => Envelope(
  id: 'e-1',
  type: EnvelopeType.msg,
  from: 'SC-ALICE',
  fromDevice: fromDevice,
  to: 'SC-BOB',
  device: device,
  sentAt: '2026-08-01T00:00:00Z',
  ratchet: const {'dh': 'ZGg=', 'pn': 0, 'n': 3},
  nonceB64: 'bm9uY2U=',
  ciphertextB64: 'Y3Q=',
  blobId: blobId,
  bundleToken: bundleToken,
);

void main() {
  group('inner envelope', () {
    test('round-trips both device numbers', () {
      final back = Envelope.fromJson(inner(fromDevice: 2, device: 3).toJson());
      expect(back.fromDevice, 2);
      expect(back.device, 3);
    });

    test('names the device fields as the protocol spells them', () {
      // The relay and scripts/e2e.py both read these exact keys; renaming one
      // silently would break interop without failing to compile.
      final j = inner(fromDevice: 2, device: 3).toJson();
      expect(j['from_device'], 2);
      expect(j['device'], 3);
    });

    test('carries the bundle token only when there is one', () {
      expect(inner().toJson().containsKey('bundle_token'), isFalse);
      final j = inner(bundleToken: 'abc123').toJson();
      expect(j['bundle_token'], 'abc123');
      expect(Envelope.fromJson(j).bundleToken, 'abc123');
    });

    test('an envelope from a peer that sends no token is still readable', () {
      // Older/other clients may omit it; it is an optimisation, not a
      // precondition for reading their mail.
      final j = inner().toJson()..remove('bundle_token');
      expect(Envelope.fromJson(j).bundleToken, isNull);
    });
  });

  group('sealed (wire) envelope', () {
    test('routes on device and keeps everything else sealed', () {
      final wire = SealedEnvelope(
        id: 'e-1',
        to: 'SC-BOB',
        device: 4,
        sealedB64: 'c2VhbGVk',
      );
      final j = wire.toJson();
      expect(j['device'], 4);
      expect(j['to'], 'SC-BOB');
      // Sealed sender: the outer form names the recipient and which of their
      // queues, and nothing about who wrote it. from_device stays inside.
      expect(j.keys.toSet(), {'v', 'id', 'to', 'device', 'sealed'});
      expect(j.containsKey('from'), isFalse);
      expect(j.containsKey('from_device'), isFalse);
      expect(j.containsKey('type'), isFalse);
      expect(j.containsKey('bundle_token'), isFalse);
    });

    test('round-trips the routing device', () {
      final wire = SealedEnvelope(
        id: 'e-2',
        to: 'SC-BOB',
        device: 7,
        sealedB64: 'eA==',
      );
      expect(SealedEnvelope.fromJson(wire.toJson()).device, 7);
    });

    test('delivery hints stay optional and off by default', () {
      final plain = SealedEnvelope(
        id: 'e-3',
        to: 'SC-BOB',
        device: 1,
        sealedB64: 'eA==',
      ).toJson();
      for (final hint in ['transient', 'push', 'ring', 'blob_id']) {
        expect(plain.containsKey(hint), isFalse, reason: hint);
      }
    });
  });

  test('self-sync types are distinct from peer-facing ones', () {
    // A sync applied from a peer would let them write our history; the
    // handler checks `from`, and these being their own types is what makes
    // that check possible at all.
    final peerFacing = {
      EnvelopeType.msg,
      EnvelopeType.media,
      EnvelopeType.groupMsg,
      EnvelopeType.receipt,
    };
    expect(peerFacing.contains(EnvelopeType.syncSent), isFalse);
    expect(peerFacing.contains(EnvelopeType.syncRead), isFalse);
    expect(EnvelopeType.syncSent, isNot(EnvelopeType.syncRead));
  });
}
