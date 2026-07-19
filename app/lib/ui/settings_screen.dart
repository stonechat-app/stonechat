/// Preferences: receipt/typing privacy and the app lock. Everything here is
/// device-local — none of it is visible to the hub or any mailbox.
library;

import 'package:flutter/material.dart';
import 'package:local_auth/local_auth.dart';
import 'package:provider/provider.dart';

import '../core/push.dart';
import '../state/app_state.dart';
import '../state/call_state.dart';
import '../state/chat_state.dart';
import '../state/server_state.dart';
import 'redeem_sheet.dart';
import 'theme.dart';
import 'widgets.dart';

class SettingsScreen extends StatelessWidget {
  const SettingsScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final app = context.watch<AppState>();

    return Scaffold(
      appBar: AppBar(title: const Text('Settings')),
      body: ListView(
        children: [
          const _SectionLabel('Privacy'),
          SwitchListTile(
            value: app.sendReadReceipts,
            onChanged: (v) => app.setPreference('read_receipts', v),
            activeThumbColor: Zn.orange,
            title: const Text('Read receipts'),
            subtitle: const Text(
                'Tell contacts when you have read their messages. '
                'Delivery receipts are always sent.',
                style: TextStyle(color: Zn.muted, fontSize: 12)),
          ),
          SwitchListTile(
            value: app.sendTypingIndicators,
            onChanged: (v) => app.setPreference('typing_indicators', v),
            activeThumbColor: Zn.orange,
            title: const Text('Typing indicators'),
            subtitle: const Text('Show contacts when you are typing.',
                style: TextStyle(color: Zn.muted, fontSize: 12)),
          ),
          const _NotificationsSection(),
          const _SectionLabel('Security'),
          SwitchListTile(
            value: app.appLockEnabled,
            onChanged: (v) => _toggleAppLock(context, app, v),
            activeThumbColor: Zn.orange,
            title: const Text('App lock'),
            subtitle: const Text(
                'Require Face ID, fingerprint or the device passcode to open Zeon.',
                style: TextStyle(color: Zn.muted, fontSize: 12)),
          ),
          ListTile(
            title: const Text('Message history'),
            subtitle: const Text(
                'Stored only on this phone, in an encrypted database. '
                'There is no cloud copy — losing the phone loses the history '
                'unless you export a backup.',
                style: TextStyle(color: Zn.muted, fontSize: 12)),
            leading: const Icon(Icons.enhanced_encryption_outlined,
                color: Zn.muted, size: 20),
          ),
          ListTile(
            title: const Text('Chat backup'),
            subtitle: const Text(
                'Export an encrypted file of your text messages, '
                'or restore one.',
                style: TextStyle(color: Zn.muted, fontSize: 12)),
            leading: const Icon(Icons.save_alt, color: Zn.muted, size: 20),
            onTap: () => Navigator.pushNamed(context, '/backup'),
          ),
          ListTile(
            title: const Text('Identity export'),
            subtitle: const Text(
                'Save an encrypted QR of your identity key — the only way '
                'to keep your Zeon ID if this phone is lost.',
                style: TextStyle(color: Zn.muted, fontSize: 12)),
            leading: const Icon(Icons.qr_code_2, color: Zn.muted, size: 20),
            onTap: () => Navigator.pushNamed(context, '/identity-export'),
          ),
          const _SectionLabel('Subscription'),
          const _SubscriptionSection(),
          const _SectionLabel('Account'),
          ListTile(
            leading: const Icon(Icons.restart_alt, color: Zn.danger, size: 20),
            title: const Text('Reset identity',
                style: TextStyle(color: Zn.danger)),
            subtitle: const Text(
                'Delete this identity, its mailbox and all local history, and '
                'start over. This cannot be undone.',
                style: TextStyle(color: Zn.muted, fontSize: 12)),
            onTap: () => _resetIdentity(context, app),
          ),
        ],
      ),
    );
  }

  Future<void> _resetIdentity(BuildContext context, AppState app) async {
    // Grab the sibling states up front — the dialog await may outlive us.
    final call = context.read<CallState>();
    final server = context.read<ServerState>();
    final chat = context.read<ChatState>();
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        backgroundColor: Zn.surface,
        title: const Text('Reset identity?'),
        content: const Text(
            'Your Zeon ID, mailbox and entire message history on this phone '
            'are erased. Contacts keep only what they already received. '
            'There is no way back unless you saved an identity export.'),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(dialogContext, false),
            child: const Text('Cancel'),
          ),
          TextButton(
            onPressed: () => Navigator.pop(dialogContext, true),
            child: const Text('Reset', style: TextStyle(color: Zn.danger)),
          ),
        ],
      ),
    );
    if (confirmed != true) return;
    await call.reset(); // release camera/mic before the identity dies
    await app.resetIdentity(); // needs the account token (deleteServer)
    server.reset();
    chat.reset();
    // The identity is gone; drop every screen and land back on onboarding.
    if (context.mounted) {
      Navigator.of(context).pushNamedAndRemoveUntil('/onboarding', (_) => false);
    }
  }

  /// Both directions require passing the device auth once — enabling proves
  /// it works, disabling proves it's you.
  Future<void> _toggleAppLock(
      BuildContext context, AppState app, bool value) async {
    final auth = LocalAuthentication();
    try {
      if (value && !await auth.isDeviceSupported()) {
        if (context.mounted) {
          showZnSnack(
              context, 'Set up a screen lock on this device first',
              error: true);
        }
        return;
      }
      final ok = await auth.authenticate(
        localizedReason:
            value ? 'Confirm to enable app lock' : 'Confirm to disable app lock',
      );
      if (ok) await app.setPreference('app_lock', value);
    } on Exception {
      if (context.mounted) {
        showZnSnack(context, "Couldn't verify device authentication",
            error: true);
      }
    }
  }
}

/// Current plan (fetched from the hub) + the redeem entry point.
class _SubscriptionSection extends StatefulWidget {
  const _SubscriptionSection();

  @override
  State<_SubscriptionSection> createState() => _SubscriptionSectionState();
}

class _SubscriptionSectionState extends State<_SubscriptionSection> {
  late Future<({String plan, String status, String? currentPeriodEnd})?>
      _entitlement;

  @override
  void initState() {
    super.initState();
    _entitlement = context.read<AppState>().api.getEntitlement();
  }

  void _refresh() {
    setState(() {
      _entitlement = context.read<AppState>().api.getEntitlement();
    });
  }

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        FutureBuilder(
          future: _entitlement,
          builder: (context, snap) {
            final (label, color, sub) = switch (snap) {
              AsyncSnapshot(connectionState: ConnectionState.waiting) => (
                  '···',
                  Zn.muted,
                  'Checking your plan',
                ),
              AsyncSnapshot(hasError: true) => (
                  'Unavailable',
                  Zn.muted,
                  "Couldn't reach the server",
                ),
              AsyncSnapshot(data: final e?) => (
                  e.plan == 'sovereign' ? 'Sovereign' : 'Private',
                  e.status == 'grace' ? Zn.danger : Zn.ok,
                  e.status == 'grace'
                      ? 'Payment issue — check your card with Stripe'
                      : 'Active',
                ),
              _ => (
                  'No plan',
                  Zn.muted,
                  'Plans unlock a managed mailbox — see zeonchat.com/pricing',
                ),
            };
            return ListTile(
              leading:
                  const Icon(Icons.workspace_premium_outlined, color: Zn.muted, size: 20),
              title: Text(label, style: TextStyle(color: color)),
              subtitle: Text(sub,
                  style: const TextStyle(color: Zn.muted, fontSize: 12)),
            );
          },
        ),
        ListTile(
          leading: const Icon(Icons.confirmation_number_outlined,
              color: Zn.orange, size: 20),
          title: const Text('Redeem activation code'),
          subtitle: const Text('From a purchase on zeonchat.com',
              style: TextStyle(color: Zn.muted, fontSize: 12)),
          onTap: () async {
            final activated = await showRedeemSheet(context);
            if (activated) _refresh();
          },
        ),
      ],
    );
  }
}

/// Notification permission, with a way back for anyone who dismissed the
/// soft-ask. The OS is the source of truth: we can prompt once (when it was
/// never asked), but can't revoke or re-prompt after that — those states point
/// the user at the system Settings app. Hidden entirely when push isn't
/// configured on this build.
class _NotificationsSection extends StatefulWidget {
  const _NotificationsSection();

  @override
  State<_NotificationsSection> createState() => _NotificationsSectionState();
}

class _NotificationsSectionState extends State<_NotificationsSection> {
  late Future<NotificationPermission> _state;

  @override
  void initState() {
    super.initState();
    _state = context.read<PushService>().permissionState();
  }

  void _refresh() {
    setState(() {
      _state = context.read<PushService>().permissionState();
    });
  }

  Future<void> _onChanged(bool wantOn, NotificationPermission current) async {
    if (current == NotificationPermission.notDetermined && wantOn) {
      // Never asked (e.g. tapped "Not now" earlier) — the one moment we can
      // legitimately show the OS dialog. Capture providers before the awaits.
      final app = context.read<AppState>();
      final push = context.read<PushService>();
      await app.markPushPrompted();
      await push.requestPermission();
      if (mounted) _refresh();
      return;
    }
    // Granted→off or denied→on: the OS won't let us change it from inside the
    // app; send the user to system Settings.
    if (!mounted) return;
    _guideToSettings(context, blocked: current == NotificationPermission.denied);
  }

  @override
  Widget build(BuildContext context) {
    return FutureBuilder<NotificationPermission>(
      future: _state,
      builder: (context, snap) {
        final state = snap.data;
        if (state == NotificationPermission.unavailable) {
          return const SizedBox.shrink();
        }
        final on = state == NotificationPermission.granted;
        final subtitle = switch (state) {
          NotificationPermission.granted =>
            'On. Content-free wake-ups when messages arrive or a request is accepted.',
          NotificationPermission.denied =>
            "Blocked. Turn them on in your phone's Settings › Zeon.",
          _ => 'Get notified when messages arrive or a request is accepted.',
        };
        return Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const _SectionLabel('Notifications'),
            SwitchListTile(
              value: on,
              onChanged:
                  state == null ? null : (v) => _onChanged(v, state),
              activeThumbColor: Zn.orange,
              title: const Text('Notifications'),
              subtitle: Text(subtitle,
                  style: const TextStyle(color: Zn.muted, fontSize: 12)),
            ),
          ],
        );
      },
    );
  }
}

void _guideToSettings(BuildContext context, {required bool blocked}) {
  showDialog<void>(
    context: context,
    builder: (ctx) => AlertDialog(
      backgroundColor: Zn.surface,
      title: const Text('Manage in Settings'),
      content: Text(blocked
          ? 'Notifications are turned off for Zeon at the system level. Open '
              "your phone's Settings › Zeon › Notifications to turn them on."
          : "To turn notifications off, open your phone's Settings › Zeon › "
              'Notifications.'),
      actions: [
        TextButton(
          onPressed: () => Navigator.pop(ctx),
          child: const Text('OK'),
        ),
      ],
    ),
  );
}

class _SectionLabel extends StatelessWidget {
  final String text;
  const _SectionLabel(this.text);

  @override
  Widget build(BuildContext context) => Padding(
        padding: const EdgeInsets.fromLTRB(16, 18, 16, 8),
        child: Text(text.toUpperCase(),
            style: Zn.mono(size: 10, letterSpacing: 2)),
      );
}
