import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:zeon_chat/models.dart';

void main() {
  test('Contact row round-trips the avatar and tolerates pre-v13 rows', () {
    final photo = Uint8List.fromList(List.generate(64, (i) => i));
    final c = Contact(
      zeonId: 'ZC-X',
      displayName: 'x',
      pubkeyB64: 'k',
      status: ContactStatus.accepted,
      createdAt: 1,
      avatar: photo,
      profileAt: 42,
    );
    final back = Contact.fromRow(c.toRow());
    expect(back.avatar, photo);
    expect(back.profileAt, 42);

    // No photo stays no photo.
    final bare = Contact(
      zeonId: 'ZC-Y',
      displayName: 'y',
      pubkeyB64: 'k',
      status: ContactStatus.accepted,
      createdAt: 1,
    );
    expect(Contact.fromRow(bare.toRow()).avatar, isNull);

    // A row read before the v13 columns were added defaults cleanly.
    final oldRow = Map.of(c.toRow())
      ..remove('avatar')
      ..remove('profile_at');
    final legacy = Contact.fromRow(oldRow);
    expect(legacy.avatar, isNull);
    expect(legacy.profileAt, 0);
  });
}
