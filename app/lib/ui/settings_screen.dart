/// Preferences: receipt/typing privacy and the app lock. Everything here is
/// device-local — none of it is visible to the control plane or any mailbox.
library;

import 'package:flutter/material.dart';
import 'package:local_auth/local_auth.dart';
import 'package:provider/provider.dart';

import '../state/app_state.dart';
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
            activeThumbColor: Zn.ion,
            title: const Text('Read receipts'),
            subtitle: const Text(
                'Tell contacts when you have read their messages. '
                'Delivery receipts are always sent.',
                style: TextStyle(color: Zn.muted, fontSize: 12)),
          ),
          SwitchListTile(
            value: app.sendTypingIndicators,
            onChanged: (v) => app.setPreference('typing_indicators', v),
            activeThumbColor: Zn.ion,
            title: const Text('Typing indicators'),
            subtitle: const Text('Show contacts when you are typing.',
                style: TextStyle(color: Zn.muted, fontSize: 12)),
          ),
          const _SectionLabel('Security'),
          SwitchListTile(
            value: app.appLockEnabled,
            onChanged: (v) => _toggleAppLock(context, app, v),
            activeThumbColor: Zn.ion,
            title: const Text('App lock'),
            subtitle: const Text(
                'Require Face ID, fingerprint or the device passcode to open Zeon.',
                style: TextStyle(color: Zn.muted, fontSize: 12)),
          ),
          ListTile(
            title: const Text('Message history'),
            subtitle: const Text(
                'Stored only on this phone, in an encrypted database. '
                'There is no cloud copy — losing the phone loses the history.',
                style: TextStyle(color: Zn.muted, fontSize: 12)),
            leading: const Icon(Icons.enhanced_encryption_outlined,
                color: Zn.muted, size: 20),
          ),
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
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        backgroundColor: Zn.surface,
        title: const Text('Reset identity?'),
        content: const Text(
            'Your Zeon ID, mailbox and entire message history on this phone '
            'are erased. Contacts keep only what they already received. '
            'There is no way back.'),
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
    await app.resetIdentity();
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
