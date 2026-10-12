// The contact list between a user's own devices (lib/core/contact_sync.dart):
// what a `sync_contact` carries, and what a receiver refuses. No ChatState
// here — these are the decisions it delegates.
import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:stonechat/core/contact_sync.dart';
import 'package:stonechat/models.dart';

/// Stands in for the commitment check: a key "commits" to an ID when the
/// two were made for each other here.
bool _matches(String pubkey, String id) => pubkey == 'pk-$id';

Contact _contact({String status = ContactStatus.accepted}) => Contact(
  stonechatId: 'SC-A',
  displayName: 'Alice',
  pubkeyB64: 'pk-SC-A',
  status: status,
  createdAt: 1,
  bundleToken: 'bt',
  hub: 'https://hub.example',
);

void main() {
  test('the payload carries the contact as held, photo included', () {
    final c = _contact()..avatar = Uint8List.fromList([1, 2, 3]);
    final p = contactSyncPayload(c);
    expect(p['peer'], 'SC-A');
    expect(p['pubkey'], 'pk-SC-A');
    expect(p['status'], 'accepted');
    expect(p['display_name'], 'Alice');
    expect(p['avatar'], {'data': base64Encode([1, 2, 3]), 'mime': 'image/jpeg'});
    expect(p['bundle_token'], 'bt');
    expect(p['hub'], 'https://hub.example');
  });

  test('no photo is said explicitly, so a sibling clears its own', () {
    expect(contactSyncPayload(_contact())['avatar'], isNull);
    expect(contactSyncPayload(_contact()).containsKey('avatar'), isTrue);
  });

  test('a removal says so, whatever the status was', () {
    expect(
      contactSyncPayload(_contact(status: ContactStatus.pendingIn), removed: true)['status'],
      contactSyncRemoved,
    );
  });

  test('a payload round-trips through the parser', () {
    final c = _contact()..avatar = Uint8List.fromList([9]);
    final parsed = parseContactSync(
      contactSyncPayload(c).cast<String, dynamic>(),
      _matches,
    )!;
    expect(parsed.peer, 'SC-A');
    expect(parsed.status, 'accepted');
    expect(parsed.displayName, 'Alice');
    expect(parsed.avatarGiven, isTrue);
    expect(parsed.avatar, [9]);
    expect(parsed.bundleToken, 'bt');
    expect(parsed.hub, 'https://hub.example');
    expect(parsed.removed, isFalse);
  });

  test('a key the ID does not commit to rejects the whole sync', () {
    // However it was authenticated: a sibling cannot be made to plant a key.
    final p = contactSyncPayload(_contact()).cast<String, dynamic>();
    p['pubkey'] = 'pk-SC-MALLORY';
    expect(parseContactSync(p, _matches), isNull);
  });

  test('an unknown status, or a missing field, is refused', () {
    final good = contactSyncPayload(_contact()).cast<String, dynamic>();
    expect(parseContactSync({...good, 'status': 'friend'}, _matches), isNull);
    expect(parseContactSync({...good}..remove('peer'), _matches), isNull);
    expect(parseContactSync({...good}..remove('pubkey'), _matches), isNull);
    expect(parseContactSync({...good, 'peer': 7}, _matches), isNull);
  });

  test('display data is taken as given, within limits', () {
    final good = contactSyncPayload(_contact()).cast<String, dynamic>();
    // Absent avatar: unchanged. Null: cleared. Oversized or junk: not given.
    expect(parseContactSync({...good}..remove('avatar'), _matches)!.avatarGiven, isFalse);
    final cleared = parseContactSync({...good, 'avatar': null}, _matches)!;
    expect(cleared.avatarGiven, isTrue);
    expect(cleared.avatar, isNull);
    final big = base64Encode(Uint8List(2 * avatarBytesMax + 1));
    expect(
      parseContactSync({...good, 'avatar': {'data': big, 'mime': 'image/jpeg'}}, _matches)!.avatarGiven,
      isFalse,
    );
    expect(
      parseContactSync({...good, 'avatar': {'data': '!!!', 'mime': 'image/jpeg'}}, _matches)!.avatarGiven,
      isFalse,
    );
    // A blank name is no name; a hub must be a URL.
    expect(parseContactSync({...good, 'display_name': '  '}, _matches)!.displayName, isNull);
    expect(parseContactSync({...good, 'hub': 'hub.example'}, _matches)!.hub, isNull);
  });

  test('verification travels, absent is unchanged, junk is unverified', () {
    expect(contactSyncPayload(_contact())['verified_at'], isNull);
    expect(contactSyncPayload(_contact()).containsKey('verified_at'), isTrue);
    expect(contactSyncPayload(_contact()..verifiedAt = 5)['verified_at'], 5);

    final base = {'peer': 'SC-A', 'pubkey': 'pk-SC-A', 'status': 'accepted'};
    final none = parseContactSync(base, _matches)!;
    expect(none.verifiedGiven, isFalse);
    final cleared = parseContactSync({...base, 'verified_at': null}, _matches)!;
    expect(cleared.verifiedGiven, isTrue);
    expect(cleared.verifiedAt, isNull);
    final set = parseContactSync({...base, 'verified_at': 1700000000000}, _matches)!;
    expect(set.verifiedAt, 1700000000000);
    final junk = parseContactSync({...base, 'verified_at': 'yes'}, _matches)!;
    expect(junk.verifiedGiven, isTrue);
    expect(junk.verifiedAt, isNull);
  });
}
