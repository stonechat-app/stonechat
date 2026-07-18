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

  bool _firebaseReady = false;
  void Function(String token, String platform)? _onToken;

  /// Sets up Firebase and the message listeners **without** prompting for
  /// permission. A returning user who already granted gets their token wired
  /// up silently; a new user is left untouched until [requestPermission] is
  /// called at a smart moment (see ui/push_prompt.dart). Without a bundled
  /// Firebase config this stays disabled and the app relies on live-socket /
  /// on-resume delivery, exactly as before.
  ///
  /// [onToken] fires whenever we obtain or refresh a device token (register it
  /// with the mailbox). [onWake] fires when a push is received or tapped —
  /// drain the mailbox.
  Future<void> init({
    required void Function(String token, String platform) onToken,
    required void Function() onWake,
  }) async {
    _onToken = onToken;
    try {
      await Firebase.initializeApp();
    } catch (e) {
      // No Firebase config bundled → push simply off. Not an error.
      debugPrint('push disabled (no Firebase config): $e');
      return;
    }
    _firebaseReady = true;
    final messaging = FirebaseMessaging.instance;

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

    // Returning user who already granted: acquire the token now, no prompt.
    final settings = await messaging.getNotificationSettings();
    if (_granted(settings.authorizationStatus)) {
      available = true;
      await _emitToken(messaging, onToken);
    }
  }

  /// True only while the OS permission has never been asked — i.e. we may still
  /// show a soft ask and then prompt. False once granted or denied, or when
  /// push isn't configured at all.
  Future<bool> get isUndetermined async {
    if (!_firebaseReady) return false;
    final s = await FirebaseMessaging.instance.getNotificationSettings();
    return s.authorizationStatus == AuthorizationStatus.notDetermined;
  }

  /// Fires the OS permission dialog and, on grant, registers the device token.
  /// Call this ONLY after the user opts in through your own soft-ask UI — that
  /// keeps iOS's single system prompt for someone who already said yes.
  /// Returns whether notifications ended up authorized.
  Future<bool> requestPermission() async {
    if (!_firebaseReady) return false;
    final messaging = FirebaseMessaging.instance;
    final settings = await messaging.requestPermission();
    if (!_granted(settings.authorizationStatus)) {
      debugPrint('push not authorized: ${settings.authorizationStatus}');
      return false;
    }
    available = true;
    final cb = _onToken;
    if (cb != null) await _emitToken(messaging, cb);
    return true;
  }

  bool _granted(AuthorizationStatus s) =>
      s == AuthorizationStatus.authorized ||
      s == AuthorizationStatus.provisional;

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
