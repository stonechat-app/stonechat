/// Step 2 of onboarding: get the user a mailbox without them ever hearing
/// the words "VM", "provider", or "region". The three hosting choices are
/// presented with the same cards as the mailbox screen; Stonechat Cloud is
/// pre-selected with sensible defaults.
library;

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../core/api.dart';
import '../state/app_state.dart';
import '../state/server_state.dart';
import 'country_picker.dart';
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
  // needs a cloud account (and never a country — there is only one localhost).
  // --dart-define=STONECHAT_PROVIDER overrides everything, e.g. to drive a real
  // cloud provider from a debug build in the simulator.
  //
  // Release builds send a *country* instead and let the hub resolve the cloud
  // (hub/app/countries.py), which is why the provider defaults below only
  // cover the escape hatches.
  static const _envProvider = String.fromEnvironment('STONECHAT_PROVIDER');

  // Debug builds provision into local Docker, where "which country" has no
  // meaning — so the picker is hidden and, without this, could only ever be
  // looked at in a release build. That makes the one piece of UI whose wording
  // matters most the hardest to iterate on. Force it visible with:
  //
  //   flutter run --dart-define=STONECHAT_COUNTRY_PICKER=true
  //
  // It only affects *display*: the mailbox is still created on the local
  // provider, so picking Brazil in a debug build does not send anything to
  // São Paulo.
  static const _forcePicker = bool.fromEnvironment('STONECHAT_COUNTRY_PICKER');
  static const _defaults = {
    'gcp': (machineType: 'e2-micro', region: 'us-central1-a'),
    'aws': (machineType: 't3.micro', region: 'us-east-1'),
    'digitalocean': (machineType: 's-1vcpu-1gb', region: 'fra1'),
    'fleet': (machineType: 'container', region: 'shared'),
    'local': (machineType: 'container', region: 'localhost'),
  };

  /// Country catalog, fetched once. null while loading; empty if the hub is
  /// unreachable or too old to know about countries — in which case the card
  /// falls back to the pre-picker behaviour rather than blocking setup.
  List<MailboxCountry>? _countries;
  String? _country; // deliberately null: we never choose a jurisdiction for you
  String? _plan; // "private" | "sovereign" | null (unknown / no plan yet)

  bool get _usesLocalProvider => _envProvider != '' || kDebugMode;

  /// Whether to render the picker at all — a superset of "we will act on it",
  /// so a debug build can display it without pretending to place a mailbox
  /// abroad.
  bool get _showsCountries => !_usesLocalProvider || _forcePicker;

  @override
  void initState() {
    super.initState();
    if (_showsCountries) _loadCountries();
  }

  Future<void> _loadCountries() async {
    final api = context.read<AppState>().api;
    try {
      final list = await api.getCountries();
      if (mounted) setState(() => _countries = list);
    } catch (_) {
      // Non-fatal: onboarding must survive a hub that cannot answer.
      if (mounted) setState(() => _countries = const []);
    }
    try {
      final entitlement = await api.getEntitlement();
      if (mounted) setState(() => _plan = entitlement?.plan);
    } catch (_) {/* plan stays null → nothing is greyed out */}
  }

  @override
  void dispose() {
    _inviteInput.dispose();
    _extAddress.dispose();
    _extToken.dispose();
    super.dispose();
  }

  /// The escape-hatch provider for debug/dart-define builds. Release builds
  /// send a country and never reach this.
  String? _localProvider() {
    if (_envProvider != '') return _envProvider;
    if (kDebugMode) return 'local';
    return null;
  }

  /// True once the account has a plan. Countries are placeable per plan, so
  /// the picker needs this before it can grey anything out.
  Future<bool> _ensurePlan() async {
    if (_plan != null) return true;
    final entitlement = await context.read<AppState>().api.getEntitlement();
    if (!mounted) return false;
    setState(() => _plan = entitlement?.plan);
    return entitlement != null;
  }

  Future<void> _setupCloud() async {
    final server = context.read<ServerState>();
    setState(() => _pending = _Choice.cloud);
    try {
      final local = _localProvider();
      if (local != null) {
        final d = _defaults[local] ?? _defaults['gcp']!;
        await server.create(
          provider: local,
          machineType: d.machineType,
          region: d.region,
        );
        return;
      }
      if (!await _ensurePlan()) {
        if (!mounted) return;
        final activated = await showRedeemSheet(context);
        if (!activated || !mounted || !await _ensurePlan()) return;
      }
      if (_countries == null) {
        // Catalog still in flight. Refusing beats falling through to the
        // fallback below, which would place the mailbox without a choice.
        if (mounted) showZnSnack(context, 'Still loading locations…');
        return;
      }
      if (_countries!.isEmpty) {
        // Hub unreachable or older than the catalog: fall back to the plan →
        // provider mapping this screen used before the picker existed, so a
        // stale hub degrades to "no country choice" instead of "no mailbox".
        final provider = _plan == 'sovereign' ? 'gcp' : 'fleet';
        final d = _defaults[provider]!;
        await server.create(
          provider: provider,
          machineType: d.machineType,
          region: d.region,
        );
        return;
      }
      // The hub knows the countries but the user has not picked one — say so
      // rather than quietly placing the mailbox somewhere of our choosing.
      if (_country == null) {
        if (mounted) {
          showZnSnack(context, 'Choose where your mailbox should live first');
        }
        return;
      }
      await server.create(country: _country);
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

  /// The country block inside the Stonechat Cloud card. Empty in debug/local
  /// builds and when the hub has no catalog to offer — in both cases there is
  /// genuinely no choice to make, and an empty picker would imply otherwise.
  List<Widget> _countryChooser(bool busy) {
    if (!_showsCountries) return const [];
    final countries = _countries;
    if (countries == null) {
      return [
        Row(
          children: [
            const SizedBox(
                width: 12,
                height: 12,
                child: CircularProgressIndicator(strokeWidth: 1.5)),
            const SizedBox(width: 10),
            Text('Loading locations…', style: Zn.mono(size: 11.5)),
          ],
        ),
        const SizedBox(height: 14),
      ];
    }
    if (countries.isEmpty) return const [];
    return [
      const Text(
        'Which country?',
        style: TextStyle(
            color: Zn.text, fontSize: 13.5, fontWeight: FontWeight.w600),
      ),
      const SizedBox(height: 6),
      // The honest frame, stated once rather than repeated per country: the
      // mailbox only ever holds sealed ciphertext, so what the jurisdiction
      // governs is metadata and physical seizure — not your messages.
      const Text(
        'Your mailbox only ever holds encrypted messages, so this choice '
        "doesn't decide who can read them — nobody can. It decides whose "
        'laws apply to the machine, and who could seize it.',
        style: TextStyle(color: Zn.muted, fontSize: 12.5, height: 1.45),
      ),
      const SizedBox(height: 12),
      CountryPicker(
        countries: countries,
        selected: _country,
        plan: _plan,
        enabled: !busy,
        onSelect: (code) => setState(() => _country = code),
      ),
      const SizedBox(height: 6),
      Text('You can move your mailbox later by destroying it and setting up '
          'a new one.',
          style: Zn.mono(size: 11, color: Zn.muted)),
      const SizedBox(height: 14),
    ];
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
          title: 'Stonechat Cloud',
          subtitle: 'An isolated container on our servers that only you can '
              'use — destroy it and start fresh whenever you want.',
          selected: _choice == _Choice.cloud,
          onTap: _select(_Choice.cloud),
          children: [
            ..._countryChooser(settingUpCloud),
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
              'Run the Stonechat mailbox anywhere you like, then connect it here. '
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
