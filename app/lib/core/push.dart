/// Content-free push wake-ups (PROTOCOL.md "Push gateway").
///
/// The device token is the ONLY thing that leaves the phone here, and it goes
/// to the user's OWN mailbox (see ChatState.registerPush) — never to us
/// directly. The mailbox pings the push gateway when the owner is offline; the
/// gateway sends a generic "you have new messages" alert with no content. The
/// woken phone drains its own mailbox over the normal encrypted path.
///
/// Entirely optional: without a Firebase configuration on the device this
/// stays disabled and the app behaves exactly as before (live-socket delivery
/// while foregrounded / on resume).
library;

import 'dart:io' show Platform;

import 'package:firebase_core/firebase_core.dart';
import 'package:firebase_messaging/firebase_messaging.dart';
import 'package:flutter/foundation.dart';

class PushService {
  bool available = false;
  String? token;
  String? platform; // 'ios' | 'android'

  /// [onToken] fires whenever we obtain or refresh a device token (register it
  /// with the mailbox). [onWake] fires when a push is received or tapped —
  /// drain the mailbox.
  Future<void> init({
    required void Function(String token, String platform) onToken,
    required void Function() onWake,
  }) async {
    try {
      await Firebase.initializeApp();
    } catch (e) {
      // No Firebase config bundled → push simply off. Not an error.
      debugPrint('push disabled (no Firebase config): $e');
      return;
    }

    final messaging = FirebaseMessaging.instance;
    final settings = await messaging.requestPermission();
    if (settings.authorizationStatus == AuthorizationStatus.denied) {
      debugPrint('push disabled (permission denied)');
      return;
    }
    available = true;

    // A content-free wake-up: foreground arrival or the user tapping the
    // notification both just mean "go check your mailbox".
    FirebaseMessaging.onMessage.listen((_) => onWake());
    FirebaseMessaging.onMessageOpenedApp.listen((_) => onWake());

    // FCM token rotation (Android). APNs tokens are re-read each launch.
    messaging.onTokenRefresh.listen((t) {
      if (Platform.isAndroid) {
        token = t;
        platform = 'android';
        onToken(t, 'android');
      }
    });

    await _emitToken(messaging, onToken);
  }

  Future<void> _emitToken(
      FirebaseMessaging messaging, void Function(String, String) onToken) async {
    try {
      // iOS: the raw APNs token (our gateway pushes APNs-direct). Android: the
      // FCM registration token.
      final String? t;
      final String p;
      if (Platform.isIOS) {
        t = await messaging.getAPNSToken();
        p = 'ios';
      } else {
        t = await messaging.getToken();
        p = 'android';
      }
      if (t != null) {
        token = t;
        platform = p;
        onToken(t, p);
      }
    } catch (e) {
      debugPrint('push token unavailable: $e');
    }
  }
}
