/// Step 2 of onboarding: get the user a mailbox without them ever hearing
/// the words "VM", "provider", or "region". One button, sensible defaults;
/// the advanced screen is a tap away for people who care.
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

class MailboxSetupScreen extends StatefulWidget {
  const MailboxSetupScreen({super.key});

  @override
  State<MailboxSetupScreen> createState() => _MailboxSetupScreenState();
}

class _MailboxSetupScreenState extends State<MailboxSetupScreen> {
  bool _requested = false;

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

  /// null → no plan on this account yet (caller offers the redeem sheet).
  Future<String?> _resolveProvider() async {
    if (_envProvider != '') return _envProvider;
    if (kDebugMode) return 'local';
    final entitlement =
        await context.read<AppState>().api.getEntitlement();
    if (entitlement == null) return null;
    return entitlement.plan == 'sovereign' ? 'gcp' : 'fleet';
  }

  Future<void> _setup() async {
    setState(() => _requested = true);
    final server = context.read<ServerState>();
    try {
      var provider = await _resolveProvider();
      if (provider == null) {
        if (!mounted) return;
        final activated = await showRedeemSheet(context);
        provider = activated && mounted ? await _resolveProvider() : null;
        if (provider == null) {
          if (mounted) setState(() => _requested = false);
          return;
        }
      }
      final d = _defaults[provider] ?? _defaults['gcp']!;
      await server.create(
        provider: provider,
        machineType: d.machineType,
        region: d.region,
      );
    } on ApiException catch (e) {
      if (!mounted) return;
      setState(() => _requested = false);
      if (e.code == 'subscription_required') {
        // Belt and braces: the server re-checks the entitlement (it may have
        // lapsed since we looked). Offer the code path and retry.
        final activated = await showRedeemSheet(context);
        if (activated && mounted) await _setup();
      } else {
        showZnSnack(context, "Couldn't start setup: $e", error: true);
      }
    } catch (e) {
      if (mounted) {
        showZnSnack(context, "Couldn't start setup: $e", error: true);
        setState(() => _requested = false);
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final server = context.watch<ServerState>();
    final ready = server.isRunning;

    return Scaffold(
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 28),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Spacer(),
              Text(ready ? '✓' : '⌂',
                  style: Zn.mono(size: 40, color: ready ? Zn.ok : Zn.orange)),
              const SizedBox(height: 16),
              Text(ready ? "You're all set" : 'One last thing: your mailbox',
                  style: const TextStyle(
                      color: Zn.text, fontSize: 22, fontWeight: FontWeight.w700)),
              const SizedBox(height: 12),
              Text(
                ready
                    ? 'Your mailbox is running. Friends can reach you now — '
                        'messages wait there, encrypted, until your phone picks '
                        'them up.'
                    : 'Your mailbox receives messages for you when your phone '
                        'is offline. It runs in the cloud, holds only encrypted '
                        'envelopes, and no one but you can use it.',
                style: const TextStyle(color: Zn.muted, height: 1.5),
              ),
              const SizedBox(height: 32),
              if (!ready)
                SizedBox(
                  width: double.infinity,
                  height: 48,
                  child: FilledButton(
                    onPressed:
                        (_requested || server.isProvisioning) ? null : _setup,
                    child: server.isProvisioning || _requested
                        ? Row(
                            mainAxisAlignment: MainAxisAlignment.center,
                            children: [
                              const SizedBox(
                                  width: 16,
                                  height: 16,
                                  child: CircularProgressIndicator(
                                      strokeWidth: 2)),
                              const SizedBox(width: 12),
                              Text('Setting up — about 2 minutes',
                                  style: TextStyle(
                                      color: Zn.bg.withValues(alpha: 0.7))),
                            ],
                          )
                        : const Text('Set up my mailbox'),
                  ),
                )
              else
                SizedBox(
                  width: double.infinity,
                  height: 48,
                  child: FilledButton(
                    onPressed: () =>
                        Navigator.pushReplacementNamed(context, '/home'),
                    child: const Text('Start chatting'),
                  ),
                ),
              const SizedBox(height: 16),
              if (!ready)
                Center(
                  child: TextButton(
                    onPressed: () =>
                        Navigator.pushReplacementNamed(context, '/home'),
                    child: const Text('Skip for now',
                        style: TextStyle(color: Zn.muted)),
                  ),
                ),
              if (!ready)
                Center(
                  child: TextButton(
                    onPressed: () => Navigator.pushNamed(context, '/server'),
                    child: Text('Advanced options',
                        style: Zn.mono(size: 10, letterSpacing: 2)),
                  ),
                ),
              const Spacer(flex: 2),
            ],
          ),
        ),
      ),
    );
  }
}
