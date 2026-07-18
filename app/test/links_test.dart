import 'package:flutter_test/flutter_test.dart';
import 'package:zeon_chat/core/links.dart';

void main() {
  const id = 'ZC-K3M9-QF2X-7YT4';

  group('zeonInviteLink', () {
    test('plain invite has no hub tag', () {
      expect(zeonInviteLink(id), 'https://zeonchat.com/add#$id');
    });

    test('https hub is tagged as bare authority', () {
      expect(zeonInviteLink(id, hub: 'https://hub.example.com'),
          'https://zeonchat.com/add#$id@hub.example.com');
    });

    test('non-https hub keeps its scheme', () {
      expect(zeonInviteLink(id, hub: 'http://10.0.2.2:8000'),
          'https://zeonchat.com/add#$id@http://10.0.2.2:8000');
    });
  });

  group('zeonInviteFromInput', () {
    test('bare code', () {
      expect(zeonInviteFromInput(' $id '), (zeonId: id, hub: null));
    });

    test('tagged code defaults to https', () {
      expect(zeonInviteFromInput('$id@hub.example.com'),
          (zeonId: id, hub: 'https://hub.example.com'));
    });

    test('tagged code keeps explicit scheme and port', () {
      expect(zeonInviteFromInput('$id@http://10.0.2.2:8000'),
          (zeonId: id, hub: 'http://10.0.2.2:8000'));
    });

    test('trailing slashes on the tag are dropped', () {
      expect(zeonInviteFromInput('$id@hub.example.com/'),
          (zeonId: id, hub: 'https://hub.example.com'));
    });

    test('empty tag is rejected', () {
      expect(zeonInviteFromInput('$id@'), null);
    });

    test('non-invite input is rejected', () {
      expect(zeonInviteFromInput('hello'), null);
      expect(zeonInviteFromInput('https://example.com/add#$id'), null);
    });
  });

  group('zeonInviteFromUri', () {
    test('round-trips a plain link', () {
      expect(zeonInviteFromUri(Uri.parse(zeonInviteLink(id))),
          (zeonId: id, hub: null));
    });

    test('round-trips a tagged link', () {
      for (final hub in ['https://hub.example.com', 'http://10.0.2.2:8000']) {
        expect(zeonInviteFromUri(Uri.parse(zeonInviteLink(id, hub: hub))),
            (zeonId: id, hub: hub));
      }
    });

    test('wrong host or path is rejected', () {
      expect(zeonInviteFromUri(Uri.parse('https://evil.com/add#$id')), null);
      expect(
          zeonInviteFromUri(Uri.parse('https://zeonchat.com/join#$id')), null);
    });
  });
}
