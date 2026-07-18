import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../core/push.dart';
import '../state/app_state.dart';
import 'theme.dart';

/// Pre-permission "soft ask". Shown at a moment the value is concrete — right
/// after the user sends their first contact request, when they're waiting to
/// hear back. We only fire the OS permission dialog if the user opts in here,
/// which preserves iOS's single system prompt for someone who already agreed.
///
/// No-ops (and marks itself done) when we've asked before, when the OS decision
/// is already made, or when push isn't configured — so it never nags.
Future<void> maybeAskForPush(BuildContext context) async {
  final app = context.read<AppState>();
  final push = context.read<PushService>();

  if (app.pushPrompted) return;
  if (!await push.isUndetermined) {
    await app.markPushPrompted();
    return;
  }
  if (!context.mounted) return;

  final wantsIt = await showModalBottomSheet<bool>(
    context: context,
    backgroundColor: Zn.surface,
    shape: const RoundedRectangleBorder(
      borderRadius: BorderRadius.vertical(top: Radius.circular(Zn.radius)),
    ),
    builder: (sheetCtx) => SafeArea(
      child: Padding(
        padding: const EdgeInsets.fromLTRB(24, 24, 24, 16),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text('Get notified when they reply',
                style: TextStyle(
                    color: Zn.text,
                    fontSize: 17,
                    fontWeight: FontWeight.w700)),
            const SizedBox(height: 10),
            const Text(
              'We\'ll let you know when your request is accepted and when '
              'messages arrive. Zeon notifications are content-free — the '
              'alert never carries who wrote or what they said.',
              style: TextStyle(color: Zn.muted, fontSize: 13, height: 1.45),
            ),
            const SizedBox(height: 20),
            SizedBox(
              width: double.infinity,
              height: 48,
              child: FilledButton(
                onPressed: () => Navigator.pop(sheetCtx, true),
                child: const Text('Turn on notifications'),
              ),
            ),
            const SizedBox(height: 4),
            SizedBox(
              width: double.infinity,
              child: TextButton(
                onPressed: () => Navigator.pop(sheetCtx, false),
                child: const Text('Not now',
                    style: TextStyle(color: Zn.muted)),
              ),
            ),
          ],
        ),
      ),
    ),
  );

  await app.markPushPrompted();
  if (wantsIt == true) {
    await push.requestPermission();
  }
}
