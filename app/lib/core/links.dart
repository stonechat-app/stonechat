/// Universal-link contact invites.
///
/// A user is shared as `https://zeonchat.com/add#ZC-…`. The ZC- ID rides in
/// the URL **fragment** (after `#`) on purpose: browsers never send a fragment
/// to the server, so an un-installed tap that falls back to the web page never
/// tells zeonchat.com whose ID was being added (PROTOCOL.md "No handles").
///
/// Cross-hub builds (`--dart-define=ZEON_CROSS_HUB=true`) may append the
/// sender's home hub to the fragment — `#ZC-…@hub.example.com` — so the
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
const zeonCrossHub = bool.fromEnvironment('ZEON_CROSS_HUB');

const zeonInviteHost = 'zeonchat.com';
const zeonInvitePath = '/add';

/// A parsed invite: who, and (hub-tagged invites only) which hub resolves them.
/// [hub] is a normalized base URL (`https://…`, no trailing slash), or null
/// for "the hub this app already uses".
typedef ZeonInvite = ({String zeonId, String? hub});

/// The shareable universal link for a Zeon ID, optionally tagged with the
/// owner's home hub. A plain-https hub is tagged as its bare authority
/// (`@hub.example.com`); any other scheme is carried verbatim.
String zeonInviteLink(String zeonId, {String? hub}) {
  final tag = switch (hub) {
    null => '',
    _ when hub.startsWith('https://') => '@${hub.substring(8)}',
    _ => '@$hub',
  };
  return 'https://$zeonInviteHost$zeonInvitePath#$zeonId$tag';
}

ZeonInvite? _fromFragment(String fragment) {
  if (!fragment.startsWith('ZC-')) return null;
  final at = fragment.indexOf('@');
  if (at < 0) return (zeonId: fragment, hub: null);
  var tag = fragment.substring(at + 1);
  while (tag.endsWith('/')) {
    tag = tag.substring(0, tag.length - 1);
  }
  if (tag.isEmpty) return null;
  return (
    zeonId: fragment.substring(0, at),
    hub: tag.contains('://') ? tag : 'https://$tag',
  );
}

/// The invite inside an invite URL, or null if [uri] isn't one of ours.
ZeonInvite? zeonInviteFromUri(Uri uri) =>
    (uri.host == zeonInviteHost && uri.path == zeonInvitePath)
        ? _fromFragment(uri.fragment)
        : null;

/// Accepts a bare `ZC-…` code, a hub-tagged `ZC-…@host` code, or a full
/// invite URL. Used for scanned QR codes and pasted input, which may carry
/// any of the three forms.
ZeonInvite? zeonInviteFromInput(String raw) {
  final v = raw.trim();
  if (v.startsWith('ZC-')) return _fromFragment(v);
  final uri = Uri.tryParse(v);
  return uri == null ? null : zeonInviteFromUri(uri);
}
