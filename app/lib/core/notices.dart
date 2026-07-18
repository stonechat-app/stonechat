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

import 'package:flutter_local_notifications/flutter_local_notifications.dart';

class LocalNotices {
  final _plugin = FlutterLocalNotificationsPlugin();
  bool _ready = false;

  Future<void> init() async {
    try {
      _ready = await _plugin.initialize(
            settings: const InitializationSettings(
              android: AndroidInitializationSettings('@mipmap/ic_launcher'),
              // Never prompt from here: notification permission is requested
              // once, deferred, by PushService (see core/push.dart). These
              // notices simply ride whatever grant that produced.
              iOS: DarwinInitializationSettings(
                requestAlertPermission: false,
                requestBadgePermission: false,
                requestSoundPermission: false,
              ),
            ),
          ) ??
          false;
    } catch (_) {
      // Notifications unavailable — non-fatal, everything else works.
    }
  }

  Future<void> show(String title, String body) async {
    if (!_ready) return;
    try {
      await _plugin.show(
        id: 0,
        title: title,
        body: body,
        notificationDetails: const NotificationDetails(
          android: AndroidNotificationDetails(
            'mailbox',
            'Mailbox status',
            channelDescription: 'Mailbox setup and status updates',
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
