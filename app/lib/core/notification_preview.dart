/// How much of a message a notification may show. The user's choice, kept
/// in the shared kv store so the iOS notification extension (which writes
/// the alert in its own process) and the Android push drain read the same
/// value. Absent → [NotificationPreview.full].
library;

import 'dart:convert';

import 'db.dart';

const notificationPreviewKey = 'notification_preview';

enum NotificationPreview {
  /// "Maria: see you at 8"
  full,

  /// "Maria: New message"
  sender,

  /// "Stonechat: You have new messages"
  none;

  String get label => switch (this) {
    full => 'Name and message',
    sender => 'Name only',
    none => 'Nothing',
  };

  static NotificationPreview parse(String? raw) => values.firstWhere(
    (v) => v.name == raw,
    orElse: () => full,
  );

  static Future<NotificationPreview> load(ChatDb db) async {
    final raw = await db.kvGet(notificationPreviewKey);
    return parse(raw == null ? null : utf8.decode(raw));
  }

  Future<void> save(ChatDb db) =>
      db.kvPut(notificationPreviewKey, utf8.encode(name));
}
