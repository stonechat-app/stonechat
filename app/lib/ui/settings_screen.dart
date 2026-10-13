/// Preferences: receipt/typing privacy and the app lock. Everything here is
/// device-local — none of it is visible to the hub or any mailbox.
library;

import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:local_auth/local_auth.dart';
import 'package:package_info_plus/package_info_plus.dart';
import 'package:provider/provider.dart';

import '../core/api.dart';
import '../core/push.dart';
import '../state/app_state.dart';
import '../state/call_state.dart';
import '../state/chat_state.dart';
import '../state/mailbox_state.dart';
import 'blocked_screen.dart';
import 'bookmarks_screen.dart';
import 'devices_screen.dart';
import 'redeem_sheet.dart';
import 'theme.dart';
import 'widgets.dart';

/// Where this app's source lives — the AGPL §13 offer to everyone using it.
const sourceUrl = 'https://github.com/stonechat-app/stonechat';

class SettingsScreen extends StatelessWidget {
  const SettingsScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final app = context.watch<AppState>();

    return Scaffold(
      appBar: AppBar(title: const Text('Settings')),
      body: ListView(
        children: [
          const _SectionLabel('You'),
          ListTile(
            title: const Text('My code'),
            subtitle: const Text(
                'Your Stonechat ID and QR code — share it to be added.',
                style: TextStyle(color: Zn.muted, fontSize: 12)),
            leading: const Icon(Icons.qr_code_2, color: Zn.muted, size: 20),
            onTap: () => Navigator.pushNamed(context, '/my-id'),
          ),
          ListTile(
            title: const Text('My mailbox'),
            subtitle: const Text(
                'Where your messages wait while your phone is offline.',
                style: TextStyle(color: Zn.muted, fontSize: 12)),
            leading: const Icon(Icons.markunread_mailbox_outlined,
                color: Zn.muted, size: 20),
            onTap: () => Navigator.pushNamed(context, '/mailbox'),
          ),
          ListTile(
            title: const Text('My bookmarked messages'),
            subtitle: const Text(
                'Messages you bookmarked, by chat. Kept on this device only.',
                style: TextStyle(color: Zn.muted, fontSize: 12)),
            leading:
                const Icon(Icons.bookmark_outline, color: Zn.muted, size: 20),
            onTap: () => Navigator.push(
              context,
              MaterialPageRoute(builder: (_) => const BookmarksScreen()),
            ),
          ),
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
          ListTile(
            title: const Text('Blocked people'),
            subtitle: Text(
                switch (context.watch<ChatState>().blocked.length) {
                  0 => 'Nobody',
                  1 => '1 person',
                  final n => '$n people',
                },
                style: const TextStyle(color: Zn.muted, fontSize: 12)),
            leading: const Icon(Icons.block, color: Zn.muted, size: 20),
            onTap: () => Navigator.push(
              context,
              MaterialPageRoute(builder: (_) => const BlockedScreen()),
            ),
          ),
          const _NotificationsSection(),
          const _SectionLabel('Security'),
          SwitchListTile(
            value: app.appLockEnabled,
            onChanged: (v) => _toggleAppLock(context, app, v),
            activeThumbColor: Zn.orange,
            title: const Text('App lock'),
            subtitle: const Text(
                'Require Face ID, fingerprint or the device passcode to open Stonechat.',
                style: TextStyle(color: Zn.muted, fontSize: 12)),
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
            title: const Text('Linked devices'),
            subtitle: const Text(
                'Use Stonechat on more than one device. Each one sends and '
                'receives on its own; a removed device stops receiving, but '
                'still holds a copy of your identity key.',
                style: TextStyle(color: Zn.muted, fontSize: 12)),
            leading: const Icon(Icons.devices_other, color: Zn.muted, size: 20),
            onTap: () => Navigator.push(
              context,
              MaterialPageRoute(builder: (_) => const DevicesScreen()),
            ),
          ),
          ListTile(
            title: const Text('Identity export'),
            subtitle: const Text(
                'Save an encrypted QR of your identity key — the only way '
                'to keep your Stonechat ID if this phone is lost.',
                style: TextStyle(color: Zn.muted, fontSize: 12)),
            leading: const Icon(Icons.qr_code_2, color: Zn.muted, size: 20),
            onTap: () => Navigator.pushNamed(context, '/identity-export'),
          ),
          const _AccessSection(),
          const _SectionLabel('Account'),
          // The primary deletes the account itself; a linked device holds no
          // identity key, so all it can do is forget itself locally.
          if (app.crypto.hasIdentitySecret)
            ListTile(
              leading:
                  const Icon(Icons.delete_forever, color: Zn.danger, size: 20),
              title: const Text('Delete account',
                  style: TextStyle(color: Zn.danger)),
              subtitle: const Text(
                  'Permanently delete your Stonechat ID and your mailbox, and '
                  'erase everything on this phone.',
                  style: TextStyle(color: Zn.muted, fontSize: 12)),
              onTap: () => _deleteAccount(context, app),
            )
          else
            ListTile(
              leading:
                  const Icon(Icons.restart_alt, color: Zn.danger, size: 20),
              title: const Text('Reset identity',
                  style: TextStyle(color: Zn.danger)),
              subtitle: const Text(
                  'Delete this identity, its mailbox and all local history, and '
                  'start over. This cannot be undone.',
                  style: TextStyle(color: Zn.muted, fontSize: 12)),
              onTap: () => _resetIdentity(context, app),
            ),
          const _SectionLabel('About'),
          ListTile(
            leading: const Icon(Icons.code, color: Zn.muted, size: 20),
            title: const Text('Source code'),
            subtitle: const Text(
                '$sourceUrl — free software under the AGPL-3.0. Tap to copy.',
                style: TextStyle(color: Zn.muted, fontSize: 12)),
            onTap: () async {
              await Clipboard.setData(const ClipboardData(text: sourceUrl));
              if (context.mounted) {
                showZnSnack(context, 'Source code link copied');
              }
            },
          ),
          const _VersionFooter(),
        ],
      ),
    );
  }

  Future<void> _deleteAccount(BuildContext context, AppState app) async {
    // Grab the sibling states up front — the dialog await may outlive us.
    final call = context.read<CallState>();
    final mailbox = context.read<MailboxState>();
    final chat = context.read<ChatState>();
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        backgroundColor: Zn.surface,
        title: const Text('Delete your account?'),
        content: const Text(
            'Your Stonechat ID is removed from the directory, your mailbox is '
            'destroyed along with any messages waiting in it. Everything on '
            'this phone is erased, including your message history.\n\n'
            'Contacts keep only what they already received. This cannot be '
            'undone.'),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(dialogContext, false),
            child: const Text('Cancel'),
          ),
          TextButton(
            onPressed: () => Navigator.pop(dialogContext, true),
            child: const Text('Delete account',
                style: TextStyle(color: Zn.danger)),
          ),
        ],
      ),
    );
    if (confirmed != true || !context.mounted) return;
    final navigator = Navigator.of(context, rootNavigator: true);
    unawaited(showDialog<void>(
      context: context,
      barrierDismissible: false,
      builder: (_) => const _BusyDialog('Deleting your account…'),
    ));
    try {
      await call.reset(); // release camera/mic before the identity dies
      await app.deleteAccount();
      mailbox.reset();
      chat.reset();
    } catch (e) {
      navigator.pop(); // dismiss the spinner
      // Nothing local was touched: the account is intact and can be retried.
      if (context.mounted) {
        final reason = e is ApiException
            ? e.message
            : "Couldn't reach Stonechat. Check your connection and try again.";
        showZnSnack(context, "Your account wasn't deleted. $reason",
            error: true);
      }
      return;
    }
    navigator.pop(); // dismiss the spinner
    // The account is gone; drop every screen and land back on onboarding.
    navigator.pushNamedAndRemoveUntil('/onboarding', (_) => false);
  }

  Future<void> _resetIdentity(BuildContext context, AppState app) async {
    // Grab the sibling states up front — the dialog await may outlive us.
    final call = context.read<CallState>();
    final mailbox = context.read<MailboxState>();
    final chat = context.read<ChatState>();
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        backgroundColor: Zn.surface,
        title: const Text('Reset identity?'),
        content: const Text(
            'Your Stonechat ID, mailbox and entire message history on this phone '
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
    if (confirmed != true || !context.mounted) return;
    // The wipe tears the mailbox down over the network before it touches
    // anything local, so it can sit for a few seconds — hold the screen with a
    // spinner instead of leaving the tap looking ignored. Captured up front:
    // the dialog and the onboarding jump both run after awaits.
    final navigator = Navigator.of(context, rootNavigator: true);
    unawaited(showDialog<void>(
      context: context,
      barrierDismissible: false,
      builder: (_) => const _BusyDialog('Erasing this identity…'),
    ));
    try {
      await call.reset(); // release camera/mic before the identity dies
      await app.resetIdentity(); // needs the account token (deleteMailbox)
      mailbox.reset();
      chat.reset();
    } finally {
      navigator.pop(); // dismiss the spinner
    }
    // The identity is gone; drop every screen and land back on onboarding.
    navigator.pushNamedAndRemoveUntil('/onboarding', (_) => false);
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

/// Modal "this is running" spinner. Not dismissible in any way — the caller
/// pops it when the work finishes, and there is nothing sane to do with a
/// half-erased identity in the meantime.
class _BusyDialog extends StatelessWidget {
  final String message;
  const _BusyDialog(this.message);

  @override
  Widget build(BuildContext context) => PopScope(
        canPop: false,
        child: AlertDialog(
          backgroundColor: Zn.surface,
          content: Row(
            children: [
              const SizedBox(
                width: 20,
                height: 20,
                child: CircularProgressIndicator(
                    strokeWidth: 2, color: Zn.orange),
              ),
              const SizedBox(width: 16),
              Expanded(child: Text(message)),
            ],
          ),
        ),
      );
}

/// Current plan (fetched from the hub) + the redeem entry point. Absent on
/// an open hub — one without a gate has no plans, so there is nothing to show
/// and nothing to redeem (PROTOCOL.md "Gate").
class _AccessSection extends StatefulWidget {
  const _AccessSection();

  @override
  State<_AccessSection> createState() => _AccessSectionState();
}

class _AccessSectionState extends State<_AccessSection> {
  late Future<HubAccess> _entitlement;

  @override
  void initState() {
    super.initState();
    _entitlement = context.read<AppState>().api.getAccess();
  }

  void _refresh() {
    setState(() {
      _entitlement = context.read<AppState>().api.getAccess();
    });
  }

  @override
  Widget build(BuildContext context) {
    return FutureBuilder(
      future: _entitlement,
      builder: (context, snap) {
        if (snap.data?.gated == false) return const SizedBox.shrink();
        return Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            const _SectionLabel('Access'),
            _planTile(snap),
            ListTile(
              leading: const Icon(Icons.confirmation_number_outlined,
                  color: Zn.orange, size: 20),
              title: const Text('Enter invite code'),
              subtitle: const Text('If you were given one',
                  style: TextStyle(color: Zn.muted, fontSize: 12)),
              onTap: () async {
                final activated = await showRedeemSheet(context);
                if (activated) _refresh();
              },
            ),
          ],
        );
      },
    );
  }

  Widget _planTile(AsyncSnapshot<HubAccess> snap) {
    final (label, color, sub) = switch (snap) {
      AsyncSnapshot(connectionState: ConnectionState.waiting) => (
          '···',
          Zn.muted,
          'Checking your access',
        ),
      AsyncSnapshot(hasError: true) => (
          'Unavailable',
          Zn.muted,
          "Couldn't reach the mailbox",
        ),
      AsyncSnapshot(data: HubAccess(plan: final String plan) && final e) => (
          plan == 'machine' ? 'Machine' : 'Mailbox',
          e.status == 'grace' ? Zn.danger : Zn.ok,
          e.notice ?? 'Active',
        ),
      _ => (
          'Not invited yet',
          Zn.muted,
          'An invite code unlocks a managed mailbox',
        ),
    };
    return ListTile(
      leading:
          const Icon(Icons.workspace_premium_outlined, color: Zn.muted, size: 20),
      title: Text(label, style: TextStyle(color: color)),
      subtitle: Text(sub,
          style: const TextStyle(color: Zn.muted, fontSize: 12)),
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
            "Blocked. Turn them on in your phone's Settings › Stonechat.",
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
          ? 'Notifications are turned off for Stonechat at the system level. Open '
              "your phone's Settings › Stonechat › Notifications to turn them on."
          : "To turn notifications off, open your phone's Settings › Stonechat › "
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

/// Which build is on this phone — pubspec `version` (version+build) as the
/// list footer, so testers can name what they are running.
class _VersionFooter extends StatelessWidget {
  const _VersionFooter();

  @override
  Widget build(BuildContext context) => FutureBuilder<PackageInfo>(
        future: PackageInfo.fromPlatform(),
        builder: (context, snap) {
          final info = snap.data;
          return Padding(
            padding: const EdgeInsets.fromLTRB(16, 28, 16, 24),
            child: Center(
              child: Text(
                info == null
                    ? ''
                    : 'Stonechat ${info.version} (${info.buildNumber})',
                style: Zn.mono(size: 11, letterSpacing: 1),
              ),
            ),
          );
        },
      );
}
