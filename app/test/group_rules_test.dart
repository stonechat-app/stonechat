// The group rules (lib/core/group_rules.dart): which rosters a client
// accepts, how two members' views of the roster compare, and the hashes
// behind both. No ChatState here — these are the decisions it delegates.
import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:stonechat/core/crypto.dart';
import 'package:stonechat/core/group_rules.dart';

/// Stands in for BLAKE2b: any injective function shows what the hash covers.
String _hash(Uint8List data) => base64Encode(data);

const _gid = '6a1f0c1e-2b6f-4f0e-9a51-0d6b8f1c2a33';

MembershipVerdict _check({
  String from = 'SC-ADMIN',
  String admin = 'SC-ADMIN',
  int version = 2,
  List<String> members = const ['SC-ADMIN', 'SC-ME', 'SC-OTHER'],
  ({String adminId, int version})? held = (adminId: 'SC-ADMIN', version: 1),
  bool contact = true,
}) => checkMembership(
  from: from,
  payloadAdmin: admin,
  version: version,
  memberIds: members,
  held: held,
  senderIsContact: contact,
);

void main() {
  // The same inputs through scripts/e2e.py (`roster_hash`,
  // `group_message_hash`), which the echo bots and the group probe run: an
  // app and a script that disagreed here would each report the other as
  // holding a different roster, or a different message.
  test('hashes match the Python client byte for byte', () {
    final CryptoService crypto;
    try {
      crypto = CryptoService.generate();
    } catch (_) {
      return markTestSkipped('stonechat-core unavailable in test VM');
    }
    expect(
      rosterHash(
        crypto.hashB64,
        groupId: _gid,
        version: 3,
        admin: 'SC-A',
        memberIds: ['SC-C', 'SC-A', 'SC-B'],
      ),
      'bwEclWvOVRlPTPOJPAsbsRPtGUYfzsXZRYgBqEYsan4=',
    );
    String messageHash(Map<String, dynamic> payload) => groupMessageHash(
      crypto.hashB64,
      groupId: _gid,
      senderId: 'SC-A',
      id: 'm1',
      salt: 'c2FsdA==',
      body: groupMessageBody(payload)!,
    );
    expect(
      messageHash({'text': 'see you at 8 | or 9'}),
      'KFiWM0UrKbNVI2HUO9jEfLA3SQBc3Un7CZ8LLbdfbnM=',
    );
    expect(
      messageHash({'blob_id': 'b', 'key': 'k', 'blob_nonce': 'n'}),
      'n83Yradhf+fsnXrLSWrlM8Jf86qtN+5g0/95jEPJCrI=',
    );
  });

  group('rosterHash', () {
    String hashOf({
      int version = 3,
      String admin = 'SC-A',
      List<String> ids = const ['SC-A', 'SC-B', 'SC-C'],
    }) => rosterHash(
      _hash,
      groupId: _gid,
      version: version,
      admin: admin,
      memberIds: ids,
    );

    test('does not depend on the order members are listed in', () {
      expect(hashOf(ids: ['SC-C', 'SC-A', 'SC-B']), hashOf());
    });

    test('changes with the members, the version and the admin', () {
      expect(hashOf(ids: ['SC-A', 'SC-B']), isNot(hashOf()));
      expect(hashOf(ids: ['SC-A', 'SC-B', 'SC-EVE']), isNot(hashOf()));
      expect(hashOf(version: 4), isNot(hashOf()));
      expect(hashOf(admin: 'SC-B'), isNot(hashOf()));
    });
  });

  group('compareRoster', () {
    RosterView view(Map<String, dynamic> payload, {String? held = 'h1'}) =>
        compareRoster(
          heldVersion: 5,
          heldHash: held,
          claim: RosterClaim.from(payload),
        );

    test('a message without a roster block says nothing', () {
      expect(view({'text': 'hi'}), RosterView.unknown);
      expect(view({'roster': 'nonsense'}), RosterView.unknown);
      expect(view({'roster': {'v': 'five'}}), RosterView.unknown);
    });

    test('versions order the two views', () {
      expect(view({'roster': {'v': 6, 'h': 'x'}}), RosterView.peerAhead);
      expect(view({'roster': {'v': 4, 'h': 'h1'}}), RosterView.peerBehind);
      expect(view({'roster': {'v': 5, 'h': 'h1'}}), RosterView.same);
    });

    test('same version, different members is a divergence', () {
      expect(view({'roster': {'v': 5, 'h': 'h2'}}), RosterView.diverged);
    });

    test('a missing hash on either side is not a divergence', () {
      expect(view({'roster': {'v': 5}}), RosterView.same);
      expect(view({'roster': {'v': 5, 'h': 'h2'}}, held: null), RosterView.same);
    });
  });

  group('checkMembership, a group we hold', () {
    test('the admin on record moves the version forward', () {
      expect(_check().accepted, isTrue);
      expect(_check().handover, isFalse);
    });

    test('stale and replayed rosters are refused', () {
      expect(_check(version: 1).accepted, isFalse);
      expect(_check(version: 0).accepted, isFalse);
    });

    test('a member cannot take the group by naming itself admin', () {
      expect(_check(from: 'SC-OTHER', admin: 'SC-OTHER').accepted, isFalse);
    });

    test('nor by sending a roster that names the real admin', () {
      expect(_check(from: 'SC-OTHER').accepted, isFalse);
    });

    test('the admin on record can hand the role to a member', () {
      final verdict = _check(admin: 'SC-OTHER');
      expect(verdict.accepted, isTrue);
      expect(verdict.handover, isTrue);
    });

    test('but not to someone outside the roster', () {
      expect(_check(admin: 'SC-STRANGER').accepted, isFalse);
    });

    test('after a handover the old admin is no longer heard', () {
      const held = (adminId: 'SC-OTHER', version: 2);
      expect(_check(version: 3, held: held).accepted, isFalse);
      expect(
        _check(from: 'SC-OTHER', admin: 'SC-OTHER', version: 3, held: held)
            .accepted,
        isTrue,
      );
    });

    test('the sender need not be a contact once we hold the group', () {
      expect(_check(contact: false).accepted, isTrue);
    });
  });

  group('checkMembership, first sight', () {
    test('an accepted contact who is the admin may add us', () {
      expect(_check(held: null).accepted, isTrue);
    });

    test('a stranger may not', () {
      expect(_check(held: null, contact: false).accepted, isFalse);
    });

    test('nobody introduces a group on behalf of another admin', () {
      expect(_check(held: null, from: 'SC-OTHER').accepted, isFalse);
    });
  });

  group('checkMembership, the roster itself', () {
    test('is bounded', () {
      final ids = [for (var i = 0; i < groupRosterMax; i++) 'SC-$i'];
      expect(_check(admin: 'SC-0', from: 'SC-0', members: ids, held: null)
          .accepted, isTrue);
      expect(
        _check(admin: 'SC-0', from: 'SC-0', members: [...ids, 'SC-X'], held: null)
            .accepted,
        isFalse,
      );
      expect(groupMemberCap, lessThanOrEqualTo(groupRosterMax));
    });

    test('lists nobody twice', () {
      expect(_check(members: ['SC-ADMIN', 'SC-ME', 'SC-ME']).accepted, isFalse);
    });
  });

  group('groupMessageHash', () {
    String hashOf({
      String sender = 'SC-A',
      String id = 'm1',
      String salt = 'c2FsdA==',
      Map<String, dynamic> payload = const {'text': 'see you at 8'},
    }) => groupMessageHash(
      _hash,
      groupId: _gid,
      senderId: sender,
      id: id,
      salt: salt,
      body: groupMessageBody(payload)!,
    );

    test('two copies of one message agree', () {
      expect(hashOf(), hashOf());
    });

    test('different text, salt, sender or id do not', () {
      expect(hashOf(payload: {'text': 'see you at 9'}), isNot(hashOf()));
      expect(hashOf(salt: 'b3RoZXI='), isNot(hashOf()));
      expect(hashOf(sender: 'SC-B'), isNot(hashOf()));
      expect(hashOf(id: 'm2'), isNot(hashOf()));
    });

    test('media is hashed by its blob and key, and is never text', () {
      const media = {'blob_id': 'b', 'key': 'k', 'blob_nonce': 'n'};
      expect(groupMessageBody(media), 'media|b|k|n');
      expect(hashOf(payload: media), isNot(hashOf(payload: {'text': 'b|k|n'})));
      expect(
        hashOf(payload: {...media, 'key': 'k2'}),
        isNot(hashOf(payload: media)),
      );
      expect(groupMessageBody({'group_id': _gid}), isNull);
    });
  });
}
