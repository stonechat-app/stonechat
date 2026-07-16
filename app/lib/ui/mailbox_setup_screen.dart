/// Step 2 of onboarding: get the user a mailbox without them ever hearing
/// the words "VM", "provider", or "region". The three hosting choices are
/// presented with the same cards as the mailbox screen; Zeon Cloud is
/// pre-selected with sensible defaults.
library;

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../core/api.dart';
import '../state/app_state.dart';
import '../state/server_state.dart';
import 'redeem_sheet.dart';
import 'theme.dart';
import 'widgets.dart';

/// The three ways to get a mailbox.
enum _Choice { cloud, friend, selfHost }

class MailboxSetupScreen extends StatefulWidget {
  const MailboxSetupScreen({super.key});

  @override
  State<MailboxSetupScreen> createState() => _MailboxSetupScreenState();
}

class _MailboxSetupScreenState extends State<MailboxSetupScreen> {
  _Choice _choice = _Choice.cloud;
  // Which card's action is in flight. Drives that button's spinner and
  // freezes the other cards — switching options mid-provision would fire a
  // second mailbox request on top of the running one.
  _Choice? _pending;
  final _inviteInput = TextEditingController();
  final _extAddress = TextEditingController();
  final _extToken = TextEditingController();

  // In debug builds default to a local Docker mailbox so development never
  // needs a cloud account; release builds pick the provider the account's
  // plan entitles it to (PROTOCOL.md "Billing"): private → fleet,
  // sovereign → gcp. --dart-define=ZEON_PROVIDER overrides everything
  // (e.g. testing the gcp provider from a debug build in the simulator).
  static const _envProvider = String.fromEnvironment('ZEON_PROVIDER');
  static const _defaults = {
    'gcp': (machineType: 'e2-micro', region: 'us-central1-a'),
    'aws': (machineType: 't3.micro', region: 'us-east-1'),
    'digitalocean': (machineType: 's-1vcpu-1gb', region: 'fra1'),
    'fleet': (machineType: 'container', region: 'shared'),
    'local': (machineType: 'container', region: 'localhost'),
  };

  @override
  void dispose() {
    _inviteInput.dispose();
    _extAddress.dispose();
    _extToken.dispose();
    super.dispose();
  }

  /// null → no plan on this account yet (caller offers the redeem sheet).
  Future<String?> _resolveProvider() async {
    if (_envProvider != '') return _envProvider;
    if (kDebugMode) return 'local';
    final entitlement =
        await context.read<AppState>().api.getEntitlement();
    if (entitlement == null) return null;
    return entitlement.plan == 'sovereign' ? 'gcp' : 'fleet';
  }

  Future<void> _setupCloud() async {
    final server = context.read<ServerState>();
    setState(() => _pending = _Choice.cloud);
    try {
      var provider = await _resolveProvider();
      if (provider == null) {
        if (!mounted) return;
        final activated = await showRedeemSheet(context);
        provider = activated && mounted ? await _resolveProvider() : null;
        if (provider == null) return;
      }
      final d = _defaults[provider] ?? _defaults['gcp']!;
      await server.create(
        provider: provider,
        machineType: d.machineType,
        region: d.region,
      );
    } on ApiException catch (e) {
      if (!mounted) return;
      if (e.code == 'subscription_required') {
        // Belt and braces: the server re-checks the entitlement (it may have
        // lapsed since we looked). Offer the code path and retry.
        setState(() => _pending = null);
        final activated = await showRedeemSheet(context);
        if (activated && mounted) await _setupCloud();
      } else {
        showZnSnack(context, "Couldn't start setup: $e", error: true);
      }
    } catch (e) {
      if (mounted) showZnSnack(context, "Couldn't start setup: $e", error: true);
    } finally {
      if (mounted) setState(() => _pending = null);
    }
  }

  Future<void> _joinHost() async {
    final invite = _inviteInput.text.trim();
    if (invite.isEmpty) {
      showZnSnack(context, 'Paste the invite first', error: true);
      return;
    }
    final server = context.read<ServerState>();
    setState(() => _pending = _Choice.friend);
    try {
      await server.joinHost(invite);
    } catch (e) {
      if (mounted) showZnSnack(context, '$e', error: true);
    } finally {
      if (mounted) setState(() => _pending = null);
    }
  }

  Future<void> _connectExternal() async {
    final address = _extAddress.text.trim();
    final token = _extToken.text.trim();
    if (address.isEmpty || token.isEmpty) {
      showZnSnack(context, 'Enter your mailbox address and token', error: true);
      return;
    }
    final server = context.read<ServerState>();
    setState(() => _pending = _Choice.selfHost);
    try {
      await server.connectExternal(address, token);
    } catch (e) {
      if (mounted) showZnSnack(context, '$e', error: true);
    } finally {
      if (mounted) setState(() => _pending = null);
    }
  }

  VoidCallback? _select(_Choice choice) =>
      _pending != null ? null : () => setState(() => _choice = choice);

  Widget _spinnerOr(String pendingLabel, String label, _Choice choice) =>
      _pending == choice
          ? Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                const SizedBox(
                    width: 16,
                    height: 16,
                    child: CircularProgressIndicator(strokeWidth: 2)),
                const SizedBox(width: 10),
                Flexible(
                    child: Text(pendingLabel,
                        maxLines: 1, overflow: TextOverflow.ellipsis)),
              ],
            )
          : Text(label);

  @override
  Widget build(BuildContext context) {
    final server = context.watch<ServerState>();
    final ready = server.isRunning;

    return Scaffold(
      body: SafeArea(
        child: ready ? _readyView(context) : _chooseView(server),
      ),
    );
  }

  Widget _chooseView(ServerState server) {
    final settingUpCloud = _pending == _Choice.cloud || server.isProvisioning;
    return ListView(
      padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 32),
      children: [
        Text('⌂', style: Zn.mono(size: 40, color: Zn.orange)),
        const SizedBox(height: 16),
        const Text('Your mailbox',
            style: TextStyle(
                color: Zn.text, fontSize: 22, fontWeight: FontWeight.w700)),
        const SizedBox(height: 12),
        const Text(
          'Messages sent to you arrive at your mailbox and wait there, '
          'encrypted, until your phone picks them up. When you write to '
          'friends, you deliver to theirs.',
          style: TextStyle(color: Zn.muted, height: 1.5),
        ),
        const SizedBox(height: 8),
        const Text(
          'Where should your mailbox live?',
          style: TextStyle(
              color: Zn.text, fontSize: 15, fontWeight: FontWeight.w600),
        ),
        const SizedBox(height: 16),
        ZnOptionCard(
          title: 'Zeon Cloud',
          subtitle: 'An isolated container on our servers that only you can '
              'use — destroy it and start fresh whenever you want.',
          selected: _choice == _Choice.cloud,
          onTap: _select(_Choice.cloud),
          children: [
            SizedBox(
              width: double.infinity,
              height: 48,
              child: FilledButton(
                onPressed: settingUpCloud ? null : _setupCloud,
                child: settingUpCloud
                    ? Row(
                        mainAxisAlignment: MainAxisAlignment.center,
                        children: [
                          const SizedBox(
                              width: 16,
                              height: 16,
                              child: CircularProgressIndicator(strokeWidth: 2)),
                          const SizedBox(width: 12),
                          Text('Setting up — about 2 minutes',
                              style: TextStyle(
                                  color: Zn.bg.withValues(alpha: 0.7))),
                        ],
                      )
                    : const Text('Set up my mailbox'),
              ),
            ),
          ],
        ),
        const SizedBox(height: 10),
        ZnOptionCard(
          title: "A friend's machine",
          subtitle: 'Your mailbox lives on the server of someone you trust. '
              'All you need is their invite.',
          selected: _choice == _Choice.friend,
          onTap: _select(_Choice.friend),
          children: [
            const Text(
              'Your messages stay end-to-end encrypted — but your host can '
              'see that your mailbox is there and its traffic timing. Only '
              'accept from someone you trust with that.',
              style: TextStyle(color: Zn.muted, fontSize: 12.5, height: 1.45),
            ),
            const SizedBox(height: 12),
            ZnLabeledField(label: 'Paste the invite here', controller: _inviteInput),
            const SizedBox(height: 12),
            SizedBox(
              width: double.infinity,
              height: 44,
              child: FilledButton(
                onPressed: server.busy ? null : _joinHost,
                child: _spinnerOr("Setting up on your friend's server…",
                    'Join with invite', _Choice.friend),
              ),
            ),
          ],
        ),
        const SizedBox(height: 10),
        ZnOptionCard(
          title: 'Self-host',
          subtitle: 'Your mailbox runs on your own server. Free, forever.',
          selected: _choice == _Choice.selfHost,
          onTap: _select(_Choice.selfHost),
          children: [
            const Text(
              'Run the Zeon mailbox anywhere you like, then connect it here. '
              'Its access token stays on this phone — we only list the '
              'address so friends can find you.',
              style: TextStyle(color: Zn.muted, fontSize: 12.5, height: 1.45),
            ),
            const SizedBox(height: 12),
            ZnLabeledField(label: 'Address', controller: _extAddress),
            const SizedBox(height: 12),
            ZnLabeledField(label: 'Mailbox token', controller: _extToken),
            const SizedBox(height: 12),
            SizedBox(
              width: double.infinity,
              height: 44,
              child: FilledButton(
                onPressed: server.busy ? null : _connectExternal,
                child: _spinnerOr(
                    'Connecting…', 'Connect my mailbox', _Choice.selfHost),
              ),
            ),
          ],
        ),
        const SizedBox(height: 16),
        if (server.isProvisioning)
          const Padding(
            padding: EdgeInsets.only(bottom: 8),
            child: Text(
              "You can continue without waiting — we'll notify you when your "
              'mailbox is ready.',
              textAlign: TextAlign.center,
              style: TextStyle(color: Zn.muted, fontSize: 12.5, height: 1.4),
            ),
          ),
        Center(
          child: TextButton(
            onPressed: () => Navigator.pushReplacementNamed(context, '/home'),
            child: Text(server.isProvisioning ? 'Continue' : 'Skip for now',
                style: const TextStyle(color: Zn.muted)),
          ),
        ),
      ],
    );
  }

  Widget _readyView(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 28),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Spacer(),
          Text('✓', style: Zn.mono(size: 40, color: Zn.ok)),
          const SizedBox(height: 16),
          const Text("You're all set",
              style: TextStyle(
                  color: Zn.text, fontSize: 22, fontWeight: FontWeight.w700)),
          const SizedBox(height: 12),
          const Text(
            'Your mailbox is running. Friends can reach you now — messages '
            'wait there, encrypted, until your phone picks them up.',
            style: TextStyle(color: Zn.muted, height: 1.5),
          ),
          const SizedBox(height: 32),
          SizedBox(
            width: double.infinity,
            height: 48,
            child: FilledButton(
              onPressed: () => Navigator.pushReplacementNamed(context, '/home'),
              child: const Text('Start chatting'),
            ),
          ),
          const Spacer(flex: 2),
        ],
      ),
    );
  }
}
