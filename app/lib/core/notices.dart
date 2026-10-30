/// One-shot local notifications for app-internal events (e.g. "your mailbox
/// is ready"). Unlike core/push.dart these never touch the network — they are
/// posted by the running app itself, so nothing here has privacy weight.
///
/// Platform reality: on Android the Dart isolate keeps running in the
/// background, so a poll loop can post these after the user leaves the app.
/// On iOS the app is suspended seconds after backgrounding — the notice only
/// fires if the event lands inside that grace window; otherwise the user just
/// sees the new state on return. Acceptable for a nice-to-have.
library;

import 'dart:ui' show Color;

import 'package:flutter_local_notifications/flutter_local_notifications.dart';

/// Android status-bar icon: the bird as a white silhouette
/// (res/drawable-*/ic_notification.png). Android draws small icons from
/// their alpha alone, so the full-colour launcher icon came out as a square.
/// Kept from resource shrinking by res/raw/keep.xml.
const androidNotificationIcon = 'ic_notification';

/// Tints the icon and app name in the notification shade (theme.dart Zn.orange).
const androidNotificationColor = Color(0xFFFF4D00);

class LocalNotices {
  final _plugin = FlutterLocalNotificationsPlugin();
  bool _ready = false;

  /// [onTap] receives the payload of a tapped notification — the message
  /// notifications the Android push drain posts carry the conversation id
  /// (core/push_drain.dart). Fires for a tap while running and for the one
  /// that launched the app.
  Future<void> init({void Function(String payload)? onTap}) async {
    try {
      _ready =
          await _plugin.initialize(
            settings: const InitializationSettings(
              android: AndroidInitializationSettings(androidNotificationIcon),
              // Never prompt from here: notification permission is requested
              // once, deferred, by PushService (see core/push.dart). These
              // notices simply ride whatever grant that produced.
              iOS: DarwinInitializationSettings(
                requestAlertPermission: false,
                requestBadgePermission: false,
                requestSoundPermission: false,
              ),
            ),
            onDidReceiveNotificationResponse: (response) {
              final payload = response.payload;
              if (payload != null && payload.isNotEmpty) onTap?.call(payload);
            },
          ) ??
          false;
      final launch = await _plugin.getNotificationAppLaunchDetails();
      final payload = launch?.notificationResponse?.payload;
      if ((launch?.didNotificationLaunchApp ?? false) &&
          payload != null &&
          payload.isNotEmpty) {
        onTap?.call(payload);
      }
    } catch (_) {
      // Notifications unavailable — non-fatal, everything else works.
    }
  }

  /// [id] separates notice kinds: posting the same id replaces the previous
  /// notification, so an outage warning must not reuse the setup channel's
  /// slot (and re-posting an outage update should replace, not stack).
  Future<void> show(String title, String body, {int id = 0}) async {
    if (!_ready) return;
    try {
      await _plugin.show(
        id: id,
        title: title,
        body: body,
        notificationDetails: const NotificationDetails(
          android: AndroidNotificationDetails(
            'mailbox',
            'Mailbox status',
            channelDescription: 'Mailbox setup and status updates',
            color: androidNotificationColor,
            importance: Importance.high,
            priority: Priority.high,
          ),
        ),
      );
    } catch (_) {
      // best-effort
    }
  }
}
