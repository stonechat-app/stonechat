import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:stonechat/models.dart';

void main() {
  test('Contact row round-trips the avatar', () {
    final photo = Uint8List.fromList(List.generate(64, (i) => i));
    final c = Contact(
      stonechatId: 'SC-X',
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
      stonechatId: 'SC-Y',
      displayName: 'y',
      pubkeyB64: 'k',
      status: ContactStatus.accepted,
      createdAt: 1,
    );
    expect(Contact.fromRow(bare.toRow()).avatar, isNull);
  });
}
