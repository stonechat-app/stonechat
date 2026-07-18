/// Universal-link contact invites.
///
/// A user is shared as `https://zeonchat.com/add#ZC-…`. The ZC- ID rides in
/// the URL **fragment** (after `#`) on purpose: browsers never send a fragment
/// to the server, so an un-installed tap that falls back to the web page never
/// tells zeonchat.com whose ID was being added (PROTOCOL.md "No handles").
library;

const zeonInviteHost = 'zeonchat.com';
const zeonInvitePath = '/add';

/// The shareable universal link for a Zeon ID.
String zeonInviteLink(String zeonId) =>
    'https://$zeonInviteHost$zeonInvitePath#$zeonId';

/// The ZC- ID inside an invite URL, or null if [uri] isn't one of ours.
String? zeonIdFromUri(Uri uri) {
  if (uri.host == zeonInviteHost &&
      uri.path == zeonInvitePath &&
      uri.fragment.startsWith('ZC-')) {
    return uri.fragment;
  }
  return null;
}

/// Accepts either a bare `ZC-…` code or a full invite URL, and returns the
/// ZC- ID. Used for scanned QR codes, which may carry either form.
String? zeonIdFromInput(String raw) {
  final v = raw.trim();
  if (v.startsWith('ZC-')) return v;
  final uri = Uri.tryParse(v);
  return uri == null ? null : zeonIdFromUri(uri);
}
