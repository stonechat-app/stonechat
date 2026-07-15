import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../core/api.dart';
import '../state/app_state.dart';
import '../state/server_state.dart';
import 'redeem_sheet.dart';
import 'theme.dart';
import 'widgets.dart';

/// Machine settings are an implementation detail now: each provider gets its
/// fixed sensible default, nothing is user-editable.
const _providerDefaults = {
  'gcp': (machineType: 'e2-micro', region: 'us-central1-a'),
  'aws': (machineType: 't3.micro', region: 'us-east-1'),
  'digitalocean': (machineType: 's-1vcpu-1gb', region: 'fra1'),
  'fleet': (machineType: 'container', region: 'shared'),
  'local': (machineType: 'container', region: 'localhost'),
};

const _providerLabels = {
  'gcp': 'Zeon Cloud · dedicated',
  'aws': 'Zeon Cloud · dedicated',
  'fleet': 'Zeon Cloud',
  'local': 'This computer',
  'external': 'Self-hosted',
};

/// The three ways to get a mailbox.
enum _Choice { cloud, friend, selfHost }

class ServerScreen extends StatefulWidget {
  const ServerScreen({super.key});

  @override
  State<ServerScreen> createState() => _ServerScreenState();
}

class _ServerScreenState extends State<ServerScreen> {
  _Choice _choice = _Choice.cloud;
  // Which card's action is in flight. Drives that button's spinner and
  // freezes the other cards — switching options mid-provision would fire a
  // second mailbox request on top of the running one.
  _Choice? _pending;
  final _inviteInput = TextEditingController();
  final _extAddress = TextEditingController();
  final _extToken = TextEditingController();
  String? _plan; // live entitlement plan, for the invites entry

  @override
  void initState() {
    super.initState();
    _loadPlan();
  }

  Future<void> _loadPlan() async {
    try {
      final e = await context.read<AppState>().api.getEntitlement();
      if (mounted) setState(() => _plan = e?.plan);
    } on Exception {
      // best-effort; the invites entry also keys off the provider
    }
  }

  /// Sovereign plans and self-hosters can host friends' mailboxes.
  bool _canHostFriends(ServerState server) {
    if (!server.isRunning) return false;
    final p = server.record.provider;
    return server.isExternal ||
        p == 'gcp' ||
        p == 'aws' ||
        _plan == 'sovereign' ||
        (kDebugMode && p == 'local');
  }

  /// Which card a live mailbox record lights up. Friend-hosted and self-hosted
  /// mailboxes are both `external` records on the hub; the locally-stored
  /// friend-hosted flag (AppState) tells them apart.
  _Choice _activeChoice(ServerState server) => server.isFriendHosted
      ? _Choice.friend
      : server.isExternal
          ? _Choice.selfHost
          : _Choice.cloud;

  void _lockedNotice() {
    showZnSnack(
        context, 'Turn off your current mailbox before starting a new one.');
  }

  @override
  Widget build(BuildContext context) {
    final server = context.watch<ServerState>();
    // A mailbox exists (running, setting up, or errored): the choice cards
    // stay visible so the other options are discoverable, but they're locked —
    // the live one is marked, the rest are dimmed and tapping them explains.
    final locked = server.record.status != 'none';
    final active = locked ? _activeChoice(server) : null;

    return Scaffold(
      appBar: AppBar(
        title: const Text('Your mailbox',
            style: TextStyle(fontSize: 17, fontWeight: FontWeight.w600)),
      ),
      body: ListView(
        padding: const EdgeInsets.all(20),
        children: [
          _StatusCard(server: server),
          const SizedBox(height: 20),
          if (!locked) ...[
            const Text(
              'Your mailbox receives messages when your phone is offline. '
              'It holds only encrypted envelopes — each one is deleted the '
              'moment your phone picks it up.',
              style: TextStyle(color: Zn.muted, fontSize: 13, height: 1.45),
            ),
            const SizedBox(height: 20),
          ],
          _OptionCard(
            title: 'Zeon Cloud',
            subtitle: 'We run it for you. Nothing to set up — '
                'ready in about two minutes.',
            selected: !locked && _choice == _Choice.cloud,
            active: active == _Choice.cloud,
            dimmed: locked && active != _Choice.cloud,
            onTap: locked
                ? (active == _Choice.cloud ? null : _lockedNotice)
                : (_pending != null
                    ? null
                    : () => setState(() => _choice = _Choice.cloud)),
            children: [
              SizedBox(
                width: double.infinity,
                height: 48,
                child: FilledButton(
                  onPressed: server.busy ? null : () => _createCloud(server),
                  child: _pending == _Choice.cloud
                      ? const SizedBox(
                          width: 18,
                          height: 18,
                          child: CircularProgressIndicator(strokeWidth: 2))
                      : const Text('Turn on my mailbox'),
                ),
              ),
            ],
          ),
          const SizedBox(height: 10),
          _OptionCard(
            title: "A friend's machine",
            subtitle: 'Someone you trust hosts your mailbox on their '
                'server. You just need their invite.',
            selected: !locked && _choice == _Choice.friend,
            active: active == _Choice.friend,
            dimmed: locked && active != _Choice.friend,
            onTap: locked
                ? (active == _Choice.friend ? null : _lockedNotice)
                : (_pending != null
                    ? null
                    : () => setState(() => _choice = _Choice.friend)),
            children: [
              const Text(
                'Your messages stay end-to-end encrypted — but your host '
                'can see that your mailbox is there and its traffic '
                'timing. Only accept from someone you trust with that.',
                style:
                    TextStyle(color: Zn.muted, fontSize: 12.5, height: 1.45),
              ),
              const SizedBox(height: 12),
              _LabeledField(
                  label: 'Paste the invite here',
                  controller: _inviteInput),
              const SizedBox(height: 12),
              SizedBox(
                width: double.infinity,
                height: 44,
                child: FilledButton(
                  onPressed: server.busy ? null : () => _joinHost(server),
                  child: _pending == _Choice.friend
                      ? const Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            SizedBox(
                                width: 18,
                                height: 18,
                                child:
                                    CircularProgressIndicator(strokeWidth: 2)),
                            SizedBox(width: 10),
                            Text('Setting up on your friend\'s server…'),
                          ],
                        )
                      : const Text('Join with invite'),
                ),
              ),
            ],
          ),
          const SizedBox(height: 10),
          _OptionCard(
            title: 'Self-host',
            subtitle: 'Run the mailbox on your own server. '
                'Free, forever.',
            selected: !locked && _choice == _Choice.selfHost,
            active: active == _Choice.selfHost,
            dimmed: locked && active != _Choice.selfHost,
            onTap: locked
                ? (active == _Choice.selfHost ? null : _lockedNotice)
                : (_pending != null
                    ? null
                    : () => setState(() => _choice = _Choice.selfHost)),
            children: [
              const Text(
                'Run the Zeon mailbox anywhere you like, then connect it '
                'here. Its access token stays on this phone — we only list '
                'the address so friends can find you.',
                style:
                    TextStyle(color: Zn.muted, fontSize: 12.5, height: 1.45),
              ),
              const SizedBox(height: 12),
              _LabeledField(label: 'Address', controller: _extAddress),
              const SizedBox(height: 12),
              _LabeledField(label: 'Mailbox token', controller: _extToken),
              const SizedBox(height: 12),
              SizedBox(
                width: double.infinity,
                height: 44,
                child: FilledButton(
                  onPressed:
                      server.busy ? null : () => _connectExternal(server),
                  child: _pending == _Choice.selfHost
                      ? const SizedBox(
                          width: 18,
                          height: 18,
                          child: CircularProgressIndicator(strokeWidth: 2))
                      : const Text('Connect my mailbox'),
                ),
              ),
            ],
          ),
          const SizedBox(height: 10),
          if (server.isProvisioning)
            const Padding(
              padding: EdgeInsets.only(top: 8),
              child: Text(
                'Setting up your mailbox — this takes about 2 minutes the '
                "first time. You can leave this screen; we'll notify you "
                "when it's ready.",
                style: TextStyle(color: Zn.muted, fontSize: 12.5, height: 1.4),
              ),
            ),
          if (_canHostFriends(server)) ...[
            _InvitesEntry(
                onTap: () => Navigator.pushNamed(context, '/invites')),
            const SizedBox(height: 12),
          ],
          if (server.isRunning || server.record.status == 'error') ...[
            const SizedBox(height: 8),
            SizedBox(
              width: double.infinity,
              height: 48,
              child: OutlinedButton(
                style: OutlinedButton.styleFrom(
                  foregroundColor: Zn.danger,
                  side: const BorderSide(color: Zn.danger),
                ),
                onPressed: server.busy ? null : () => _destroy(server),
                child: server.busy
                    ? Row(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          const SizedBox(
                            width: 16,
                            height: 16,
                            child: CircularProgressIndicator(
                                strokeWidth: 2, color: Zn.danger),
                          ),
                          const SizedBox(width: 10),
                          Text(server.isExternal
                              ? 'Disconnecting…'
                              : 'Turning off…'),
                        ],
                      )
                    : Text(server.isExternal
                        ? 'Disconnect mailbox'
                        : 'Turn off mailbox'),
              ),
            ),
            const SizedBox(height: 8),
            Text(
              server.isExternal
                  ? 'Disconnecting removes your address from the directory — '
                      'your server keeps running and is yours to stop. Your '
                      'chat history on this phone is never affected.'
                  : 'While your mailbox is off you won\'t receive messages — '
                      'they\'ll wait on your friends\' phones and arrive once '
                      'you turn it back on. Your chat history on this phone '
                      'is never affected.',
              style: const TextStyle(color: Zn.muted, fontSize: 12.5, height: 1.4),
            ),
          ],
        ],
      ),
    );
  }

  // In debug builds default to a local Docker mailbox so development never
  // needs a cloud account; release builds pick the provider the account's
  // plan entitles it to (PROTOCOL.md "Billing"): private → fleet,
  // sovereign → gcp. --dart-define=ZEON_PROVIDER overrides everything.
  static const _envProvider = String.fromEnvironment('ZEON_PROVIDER');

  /// null → no plan on this account yet (caller offers the redeem sheet).
  Future<String?> _resolveProvider() async {
    if (_envProvider != '') return _envProvider;
    if (kDebugMode) return 'local';
    final entitlement = await context.read<AppState>().api.getEntitlement();
    if (entitlement == null) return null;
    return entitlement.plan == 'sovereign' ? 'gcp' : 'fleet';
  }

  Future<void> _createCloud(ServerState server) async {
    setState(() => _pending = _Choice.cloud);
    try {
      var provider = await _resolveProvider();
      if (provider == null) {
        if (!mounted) return;
        final activated = await showRedeemSheet(context);
        provider = activated && mounted ? await _resolveProvider() : null;
        if (provider == null) return;
      }
      final d = _providerDefaults[provider] ?? _providerDefaults['gcp']!;
      await server.create(
        provider: provider,
        machineType: d.machineType,
        region: d.region,
      );
      _loadPlan();
    } on ApiException catch (e) {
      if (!mounted) return;
      if (e.code == 'subscription_required') {
        // Belt and braces: the server re-checks the entitlement (it may have
        // lapsed since we looked). Offer the code path and retry.
        final activated = await showRedeemSheet(context);
        if (activated && mounted) await _createCloud(server);
      } else {
        showZnSnack(context, '$e', error: true);
      }
    } catch (e) {
      if (mounted) showZnSnack(context, '$e', error: true);
    } finally {
      if (mounted) setState(() => _pending = null);
    }
  }

  Future<void> _connectExternal(ServerState server) async {
    final address = _extAddress.text.trim();
    final token = _extToken.text.trim();
    if (address.isEmpty || token.isEmpty) {
      showZnSnack(context, 'Enter your mailbox address and token', error: true);
      return;
    }
    setState(() => _pending = _Choice.selfHost);
    try {
      await server.connectExternal(address, token);
      if (mounted) showZnSnack(context, 'Connected — friends can reach you now');
    } catch (e) {
      if (mounted) showZnSnack(context, '$e', error: true);
    } finally {
      if (mounted) setState(() => _pending = null);
    }
  }

  Future<void> _joinHost(ServerState server) async {
    final invite = _inviteInput.text.trim();
    if (invite.isEmpty) {
      showZnSnack(context, 'Paste the invite first', error: true);
      return;
    }
    setState(() => _pending = _Choice.friend);
    try {
      await server.joinHost(invite);
      if (mounted) {
        showZnSnack(context, 'Joined — your mailbox is live on your friend\'s host');
      }
    } catch (e) {
      if (mounted) showZnSnack(context, '$e', error: true);
    } finally {
      if (mounted) setState(() => _pending = null);
    }
  }

  Future<void> _destroy(ServerState server) async {
    final external = server.isExternal;
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: Zn.surface,
        title: Text(external
            ? 'Disconnect your mailbox?'
            : 'Turn off your mailbox?'),
        content: Text(
            external
                ? 'Your address is removed from the directory; the server '
                    'itself keeps running and stays yours. Your chat history '
                    'stays on this phone.'
                : 'You\'ll stop receiving messages until you turn it back on. '
                    'New messages will wait on your friends\' phones. Your '
                    'chat history stays on this phone.',
            style: const TextStyle(color: Zn.muted, height: 1.4)),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(context, false),
              child: Text(external ? 'Stay connected' : 'Keep it on')),
          TextButton(
              onPressed: () => Navigator.pop(context, true),
              child: Text(external ? 'Disconnect' : 'Turn off',
                  style: const TextStyle(color: Zn.danger))),
        ],
      ),
    );
    if (confirmed != true) return;
    try {
      await server.destroy();
      if (mounted) {
        showZnSnack(context,
            external ? 'Mailbox disconnected' : 'Mailbox turned off');
      }
    } catch (e) {
      if (mounted) showZnSnack(context, '$e', error: true);
    }
  }
}

class _StatusCard extends StatelessWidget {
  final ServerState server;
  const _StatusCard({required this.server});

  @override
  Widget build(BuildContext context) {
    final r = server.record;
    final (color, headline) = switch (r.status) {
      // busy while running can only be the teardown call — surface it.
      'running' when server.busy => (
          Zn.amber,
          server.isExternal ? 'Disconnecting…' : 'Turning off…'
        ),
      'running' => (Zn.ok, 'Running'),
      'provisioning' => (Zn.amber, 'Setting up…'),
      'error' => (Zn.danger, 'Something went wrong'),
      _ => (Zn.muted, 'Off'),
    };

    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: Zn.surface,
        borderRadius: BorderRadius.circular(Zn.radius),
        border: Border.all(color: Zn.line),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Container(
                width: 8,
                height: 8,
                decoration: BoxDecoration(color: color, shape: BoxShape.circle),
              ),
              const SizedBox(width: 10),
              Text(headline,
                  style: TextStyle(
                      fontSize: 15, color: color, fontWeight: FontWeight.w700)),
            ],
          ),
          if (r.status != 'none') ...[
            const SizedBox(height: 12),
            if (r.provider != null)
              _kv(
                  'Runs on',
                  server.isFriendHosted
                      ? "A friend's machine"
                      : _providerLabels[r.provider] ?? r.provider!),
            if (r.address != null) _kv('Address', r.address!),
            if (r.status == 'running')
              _kv('Phone link',
                  server.socketConnected ? 'Connected' : 'Reconnecting…'),
            if (r.error != null) _kv('Details', r.error!),
          ],
        ],
      ),
    );
  }

  Widget _kv(String k, String v) => Padding(
        padding: const EdgeInsets.only(top: 4),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            SizedBox(
                width: 84,
                child: Text(k,
                    style: const TextStyle(color: Zn.muted, fontSize: 12))),
            Expanded(
                child: Text(v, style: Zn.mono(size: 11, color: Zn.text))),
          ],
        ),
      );
}

/// One of the three big choices: a tappable card with a radio dot; the
/// selected one expands to show its form and action button. Once a mailbox
/// exists the cards lock: [active] marks where it lives (check instead of
/// radio), [dimmed] grays out the alternatives — kept visible so users know
/// they exist; their onTap explains how to switch.
class _OptionCard extends StatelessWidget {
  final String title;
  final String subtitle;
  final bool selected;
  final bool active;
  final bool dimmed;
  final VoidCallback? onTap;
  final List<Widget> children;

  const _OptionCard({
    required this.title,
    required this.subtitle,
    required this.selected,
    this.active = false,
    this.dimmed = false,
    required this.onTap,
    required this.children,
  });

  @override
  Widget build(BuildContext context) {
    final Widget marker = active
        ? const Icon(Icons.check_circle, color: Zn.ok, size: 18)
        : Container(
            width: 16,
            height: 16,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              border: Border.all(
                  color: selected ? Zn.orange : Zn.line, width: 1.5),
            ),
            child: selected
                ? Center(
                    child: Container(
                      width: 8,
                      height: 8,
                      decoration: const BoxDecoration(
                          color: Zn.orange, shape: BoxShape.circle),
                    ),
                  )
                : null,
          );

    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(Zn.radius),
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 150),
        padding: const EdgeInsets.all(16),
        decoration: BoxDecoration(
          color: active
              ? Zn.ok.withValues(alpha: 0.05)
              : selected
                  ? Zn.orange.withValues(alpha: 0.06)
                  : Zn.surface,
          borderRadius: BorderRadius.circular(Zn.radius),
          border: Border.all(
              color: active
                  ? Zn.ok
                  : selected
                      ? Zn.orange
                      : Zn.line),
        ),
        child: Opacity(
          opacity: dimmed ? 0.45 : 1,
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Padding(
                    padding: const EdgeInsets.only(top: 2),
                    child: marker,
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(title,
                            style: TextStyle(
                                fontSize: 15,
                                fontWeight: FontWeight.w600,
                                color: selected || active
                                    ? Zn.text
                                    : Zn.muted)),
                        const SizedBox(height: 3),
                        Text(subtitle,
                            style: const TextStyle(
                                color: Zn.muted, fontSize: 12.5, height: 1.4)),
                      ],
                    ),
                  ),
                ],
              ),
              if (selected && children.isNotEmpty) ...[
                const SizedBox(height: 16),
                ...children,
              ],
            ],
          ),
        ),
      ),
    );
  }
}

/// Entry point to the invites screen — hosts (self-host or Sovereign) can
/// invite friends onto their machine and track who accepted.
class _InvitesEntry extends StatelessWidget {
  final VoidCallback onTap;
  const _InvitesEntry({required this.onTap});

  @override
  Widget build(BuildContext context) {
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(Zn.radius),
      child: Container(
        padding: const EdgeInsets.all(16),
        decoration: BoxDecoration(
          color: Zn.surface,
          borderRadius: BorderRadius.circular(Zn.radius),
          border: Border.all(color: Zn.line),
        ),
        child: Row(
          children: [
            const Icon(Icons.group_add_outlined, color: Zn.orange, size: 20),
            const SizedBox(width: 12),
            const Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text('Invites',
                      style: TextStyle(
                          fontSize: 14,
                          fontWeight: FontWeight.w600,
                          color: Zn.text)),
                  SizedBox(height: 2),
                  Text('Host friends on your machine — send invites and '
                      'see who accepted',
                      style: TextStyle(
                          color: Zn.muted, fontSize: 12, height: 1.35)),
                ],
              ),
            ),
            const Icon(Icons.chevron_right, color: Zn.muted, size: 20),
          ],
        ),
      ),
    );
  }
}

class _LabeledField extends StatelessWidget {
  final String label;
  final TextEditingController controller;

  const _LabeledField({required this.label, required this.controller});

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(label, style: const TextStyle(color: Zn.muted, fontSize: 12)),
        const SizedBox(height: 6),
        TextField(
          controller: controller,
          style: Zn.mono(size: 13, color: Zn.text),
        ),
      ],
    );
  }
}
