/// Identifiers that arrive from someone else and end up in a file path or a
/// URL. Both are UUIDs by construction — every client mints them with a UUID
/// generator — so anything that is not one was not written by a client, and
/// is refused where it enters rather than escaped where it is used.
library;

import 'package:path/path.dart' as p;

final _uuid = RegExp(
  r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
  caseSensitive: false,
);

/// Whether [value] is a UUID in its canonical 36-character form: hex and
/// hyphens, nothing a path or a URL could read as structure.
bool isWireId(Object? value) => value is String && _uuid.hasMatch(value);

final _extension = RegExp(r'^\.[A-Za-z0-9]{1,10}$');

/// A file extension safe to append to a name we chose: a dot and a few
/// alphanumerics, else `.bin`. The sender picks it (it is what lets the OS
/// open a document with the right app), so it is held to a shape too.
String safeExtension(String? extension) =>
    extension != null && _extension.hasMatch(extension) ? extension : '.bin';

/// Where a message's media file lives: `<dir>/<messageId><extension>`.
///
/// Throws [FormatException] unless [messageId] is a UUID and the result is
/// directly inside [dir]. The second check cannot fail once the first has
/// passed; it is here so that the property that matters — nothing is ever
/// written outside the media directory — is stated where the path is built
/// and does not depend on what the validation above it happens to allow.
String mediaFilePath(String dir, String messageId, String? extension) {
  if (!isWireId(messageId)) {
    throw const FormatException('message id is not a UUID');
  }
  final path = p.join(dir, '${messageId.toLowerCase()}${safeExtension(extension)}');
  if (p.dirname(p.normalize(path)) != p.normalize(dir)) {
    throw const FormatException('media path escapes the media directory');
  }
  return path;
}
