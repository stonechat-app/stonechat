/// The Android push drain — what the iOS notification extension is on iOS.
///
/// Android has no extension that can rewrite a notification, but it will
/// run Dart in the background: FCM hands a *data* message (the gateway
/// sends nothing displayable, push_gateway/main.py) to [pushBackgroundHandler]
/// in its own isolate, with the app in the background or not running at all.
/// The handler stands up the app's own state headless — same DB, same
/// keystore, same ChatState — attaches to the mailbox once, lets
/// `ChatState.handleIncoming` persist every queued envelope exactly as the
/// foreground app would, and posts one local notification per conversation
/// that received a message, carrying the conversation id so a tap lands
/// there (core/push.dart `onOpen`).
///
/// Two isolates, one database. The foreground isolate may still be alive in
/// the background with cached sessions; it closes its socket on pause
/// (MailboxState.onBackground) and its retry sweep stands down while paused
/// (ChatState._scheduleRetrySweep), so nothing in it encrypts while this
/// runs. On resume it drops its caches (ChatState.reloadAfterExtension)
/// before reconnecting, the same reconciliation iOS does after the
/// extension. What this handler stores is therefore what the app shows.
library;

import 'dart:convert';

import 'package:firebase_messaging/firebase_messaging.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_local_notifications/flutter_local_notifications.dart'
    hide Message;

import '../models.dart';
import 'notification_preview.dart';
import '../state/app_state.dart';
import '../state/chat_state.dart';
import 'api.dart';

/// The notification channel for messages. Created on first use by the
/// plugin; the user's per-channel settings (sound, importance) stick to it.
const messagesChannelId = 'messages';

/// Registered with FirebaseMessaging.onBackgroundMessage (core/push.dart).
/// Must be a top-level function: the plugin starts a fresh isolate and
/// looks it up by name, which is what the pragma preserves through tree
/// shaking.
@pragma('vm:entry-point')
Future<void> pushBackgroundHandler(RemoteMessage message) async {
  WidgetsFlutterBinding.ensureInitialized();
  final app = AppState();
  await app.init();
  if (!app.hasIdentity) return;

  // Where the mailbox lives, as the foreground app last mirrored it for
  // exactly this purpose (ChatState.setMailbox). No mailbox yet → nothing
  // to drain.
  final raw = await app.db.kvGet('own_mailbox');
  if (raw == null) return;
  final coords = jsonDecode(utf8.decode(raw)) as Map<String, dynamic>;
  final address = coords['address'] as String?;
  final token = coords['token'] as String?;
  final tlsFp = coords['tls_fp'] as String?;
  if (address == null || token == null || tlsFp == null) return;

  final chat = ChatState(app);
  await chat.load();

  // What landed, per conversation, in arrival order. One notification per
  // conversation: a second message replaces the first's rather than
  // stacking, and says how many.
  final landed = <String, List<Message>>{};
  chat.onStoredIncoming = (conversationId, m) =>
      (landed[conversationId] ??= []).add(m);

  try {
    await drainMailboxOnce(
      address: address,
      token: token,
      tlsFp: tlsFp,
      onEnvelope: chat.handleIncoming,
    );
  } catch (e) {
    debugPrint('push drain: mailbox unreachable: $e');
    // The envelopes stay queued; the app drains them on open.
  }

  if (landed.isEmpty) return;
  final preview = await NotificationPreview.load(app.db);
  final notices = FlutterLocalNotificationsPlugin();
  await notices.initialize(
    settings: const InitializationSettings(
      android: AndroidInitializationSettings('@mipmap/ic_launcher'),
    ),
  );
  for (final entry in landed.entries) {
    final conversationId = entry.key;
    final messages = entry.value;
    final last = messages.last;
    final group = chat.groupById(conversationId);
    // Mute is honoured here, where the notification is made (the mailbox
    // cannot know: sealed sender). A group message that names us cuts
    // through (PROTOCOL.md "group_msg" mentions).
    final muted =
        group?.isMuted ?? chat.contactById(conversationId)?.isMuted ?? false;
    final me = app.stonechatId;
    if (muted && !messages.any((m) => me != null && m.mentions.contains(me))) {
      continue;
    }
    final sender = chat.contactById(last.senderId ?? conversationId);
    final senderName = sender?.displayName ?? 'Someone';
    // What the user allowed on the lock screen (Settings › Notifications).
    final title = switch (preview) {
      NotificationPreview.none => 'Stonechat',
      _ => group != null ? '${group.name} · $senderName' : senderName,
    };
    final body = switch (preview) {
      NotificationPreview.none => 'You have new messages',
      _ when messages.length > 1 => '${messages.length} new messages',
      NotificationPreview.sender => 'New message',
      NotificationPreview.full => _preview(last),
    };
    await notices.show(
      id: conversationId.hashCode,
      title: title,
      body: body,
      payload: conversationId,
      notificationDetails: const NotificationDetails(
        android: AndroidNotificationDetails(
          messagesChannelId,
          'Messages',
          channelDescription: 'New messages',
          importance: Importance.high,
          priority: Priority.high,
          category: AndroidNotificationCategory.message,
        ),
      ),
    );
  }
}

/// What a message reads as on the lock screen. Text is the text — it is
/// decrypted on this phone, for this user, the same as on screen; the
/// Android notification privacy setting is what hides it from the lock
/// screen if they want that. Media gets a label, not the file.
String _preview(Message m) => switch (m.kind) {
  MessageKind.text => m.text,
  MessageKind.image => '📷 Photo',
  MessageKind.sticker => 'Sticker',
  MessageKind.audio => '🎤 Voice message',
  MessageKind.video => '🎥 Video',
  MessageKind.file => '📎 ${m.fileName ?? 'File'}',
  _ => 'New message',
};
