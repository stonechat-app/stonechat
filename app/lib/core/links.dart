/// Universal-link contact invites.
///
/// A user is shared as `https://stonechat.app/add#SC-…`. The SC- ID rides in
/// the URL **fragment** (after `#`) on purpose: browsers never send a fragment
/// to the server, so an un-installed tap that falls back to the web page never
/// tells stonechat.app whose ID was being added (PROTOCOL.md "No handles").
///
/// Cross-hub builds (`--dart-define=STONECHAT_CROSS_HUB=true`) may append the
/// sender's home hub to the fragment — `#SC-…@hub.example.com` — so the
/// recipient's client knows which directory can resolve the ID. The hub tag is
/// routing information only, never trusted: resolution still verifies the
/// pubkey↔ID commitment and the owner-signed TLS fingerprint, so a lying tag
/// can at worst fail to resolve (PROTOCOL.md "Cross-hub resolution").
library;

/// Cross-hub invites and directory lookups. Off in store builds: resolving a
/// foreign ID sends your IP and the looked-up ID to a hub you didn't choose.
///
/// Not federation: hubs never talk to each other and share no namespace, so
/// this only changes *which URL the client asks* (PROTOCOL.md "Cross-hub
/// resolution").
const stonechatCrossHub = bool.fromEnvironment('STONECHAT_CROSS_HUB');

const stonechatInviteHost = 'stonechat.app';
const stonechatInvitePath = '/add';

/// A parsed invite: who, and (hub-tagged invites only) which hub resolves them.
/// [hub] is a normalized base URL (`https://…`, no trailing slash), or null
/// for "the hub this app already uses".
typedef StonechatInvite = ({String stonechatId, String? hub});

/// The shareable universal link for a Stonechat ID, optionally tagged with the
/// owner's home hub. A plain-https hub is tagged as its bare authority
/// (`@hub.example.com`); any other scheme is carried verbatim.
String stonechatInviteLink(String stonechatId, {String? hub}) {
  final tag = switch (hub) {
    null => '',
    _ when hub.startsWith('https://') => '@${hub.substring(8)}',
    _ => '@$hub',
  };
  return 'https://$stonechatInviteHost$stonechatInvitePath#$stonechatId$tag';
}

StonechatInvite? _fromFragment(String fragment) {
  if (!fragment.startsWith('SC-')) return null;
  final at = fragment.indexOf('@');
  if (at < 0) return (stonechatId: fragment, hub: null);
  var tag = fragment.substring(at + 1);
  while (tag.endsWith('/')) {
    tag = tag.substring(0, tag.length - 1);
  }
  if (tag.isEmpty) return null;
  return (
    stonechatId: fragment.substring(0, at),
    hub: tag.contains('://') ? tag : 'https://$tag',
  );
}

/// The invite inside an invite URL, or null if [uri] isn't one of ours.
StonechatInvite? stonechatInviteFromUri(Uri uri) =>
    (uri.host == stonechatInviteHost && uri.path == stonechatInvitePath)
        ? _fromFragment(uri.fragment)
        : null;

/// Accepts a bare `SC-…` code, a hub-tagged `SC-…@host` code, or a full
/// invite URL. Used for scanned QR codes and pasted input, which may carry
/// any of the three forms.
StonechatInvite? stonechatInviteFromInput(String raw) {
  final v = raw.trim();
  if (v.startsWith('SC-')) return _fromFragment(v);
  final uri = Uri.tryParse(v);
  return uri == null ? null : stonechatInviteFromUri(uri);
}
