import 'package:flutter_test/flutter_test.dart';
import 'package:stonechat/core/links.dart';

void main() {
  const id = 'SC-K3M9-QF2X-7YT4';

  group('stonechatInviteLink', () {
    test('plain invite has no hub tag', () {
      expect(stonechatInviteLink(id), 'https://stonechat.app/add#$id');
    });

    test('https hub is tagged as bare authority', () {
      expect(stonechatInviteLink(id, hub: 'https://hub.example.com'),
          'https://stonechat.app/add#$id@hub.example.com');
    });

    test('non-https hub keeps its scheme', () {
      expect(stonechatInviteLink(id, hub: 'http://10.0.2.2:8000'),
          'https://stonechat.app/add#$id@http://10.0.2.2:8000');
    });
  });

  group('stonechatInviteFromInput', () {
    test('bare code', () {
      expect(stonechatInviteFromInput(' $id '), (stonechatId: id, hub: null));
    });

    test('tagged code defaults to https', () {
      expect(stonechatInviteFromInput('$id@hub.example.com'),
          (stonechatId: id, hub: 'https://hub.example.com'));
    });

    test('tagged code keeps explicit scheme and port', () {
      expect(stonechatInviteFromInput('$id@http://10.0.2.2:8000'),
          (stonechatId: id, hub: 'http://10.0.2.2:8000'));
    });

    test('trailing slashes on the tag are dropped', () {
      expect(stonechatInviteFromInput('$id@hub.example.com/'),
          (stonechatId: id, hub: 'https://hub.example.com'));
    });

    test('empty tag is rejected', () {
      expect(stonechatInviteFromInput('$id@'), null);
    });

    test('non-invite input is rejected', () {
      expect(stonechatInviteFromInput('hello'), null);
      expect(stonechatInviteFromInput('https://example.com/add#$id'), null);
    });
  });

  group('stonechatInviteFromUri', () {
    test('round-trips a plain link', () {
      expect(stonechatInviteFromUri(Uri.parse(stonechatInviteLink(id))),
          (stonechatId: id, hub: null));
    });

    test('round-trips a tagged link', () {
      for (final hub in ['https://hub.example.com', 'http://10.0.2.2:8000']) {
        expect(stonechatInviteFromUri(Uri.parse(stonechatInviteLink(id, hub: hub))),
            (stonechatId: id, hub: hub));
      }
    });

    test('wrong host or path is rejected', () {
      expect(stonechatInviteFromUri(Uri.parse('https://evil.com/add#$id')), null);
      expect(
          stonechatInviteFromUri(Uri.parse('https://stonechat.app/join#$id')), null);
    });
  });
}
