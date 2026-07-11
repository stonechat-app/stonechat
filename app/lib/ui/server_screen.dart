import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';

import '../state/server_state.dart';
import 'theme.dart';
import 'widgets.dart';

/// Per-provider sensible defaults; everything stays editable under Advanced.
const _providerDefaults = {
  'gcp': (machineType: 'e2-micro', region: 'us-central1-a'),
  'aws': (machineType: 't3.micro', region: 'us-east-1'),
  'fleet': (machineType: 'container', region: 'shared'),
  'local': (machineType: 'container', region: 'localhost'),
};

// 'local' puts the mailbox on the machine running the hub —
// forbidden in production topology, so it's offered in dev builds only.
const _providerChoices =
    kDebugMode ? ['gcp', 'aws', 'fleet', 'local'] : ['gcp', 'aws', 'fleet'];

const _providerLabels = {
  'gcp': 'Google Cloud',
  'aws': 'Amazon',
  'fleet': 'Zeon cloud',
  'local': 'This computer',
  'external': 'Your own server',
};

class ServerScreen extends StatefulWidget {
  const ServerScreen({super.key});

  @override
  State<ServerScreen> createState() => _ServerScreenState();
}

class _ServerScreenState extends State<ServerScreen> {
  // --dart-define=ZEON_PROVIDER overrides the default selection (must be one
  // of _providerDefaults' keys), same as on the onboarding setup screen.
  static const _envProvider = String.fromEnvironment('ZEON_PROVIDER');
  String _provider = _envProvider != ''
      ? _envProvider
      : (kDebugMode ? 'local' : 'gcp');
  late final _machineType =
      TextEditingController(text: _providerDefaults[_provider]!.machineType);
  late final _region =
      TextEditingController(text: _providerDefaults[_provider]!.region);
  double _diskGb = 10;
  bool _showAdvanced = false;
  bool _showExternal = false;
  bool _showJoin = false;
  bool _showHost = false;
  final _extAddress = TextEditingController();
  final _extToken = TextEditingController();
  final _inviteInput = TextEditingController();
  final _agentAddress = TextEditingController();
  final _agentAdminToken = TextEditingController();
  String? _mintedInvite;

  void _applyProviderDefaults(String provider) {
    setState(() {
      _provider = provider;
      _machineType.text = _providerDefaults[provider]!.machineType;
      _region.text = _providerDefaults[provider]!.region;
    });
  }

  @override
  Widget build(BuildContext context) {
    final server = context.watch<ServerState>();

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
          if (server.record.status == 'none') ...[
            const Text(
              'Your mailbox receives messages when your phone is offline. '
              'It holds only encrypted envelopes — each one is deleted the '
              'moment your phone picks it up.',
              style: TextStyle(color: Zn.muted, fontSize: 13, height: 1.45),
            ),
            const SizedBox(height: 16),
            const Text('Where should it run?',
                style: TextStyle(
                    color: Zn.text, fontSize: 13, fontWeight: FontWeight.w600)),
            const SizedBox(height: 10),
            Row(
              children: [
                for (final p in _providerChoices) ...[
                  Expanded(
                    child: _ProviderChip(
                      name: _providerLabels[p]!,
                      selected: _provider == p,
                      onTap: () => _applyProviderDefaults(p),
                    ),
                  ),
                  if (p != _providerChoices.last) const SizedBox(width: 8),
                ],
              ],
            ),
            const SizedBox(height: 16),
            GestureDetector(
              onTap: () => setState(() => _showAdvanced = !_showAdvanced),
              child: Text(
                _showAdvanced ? '▾ Advanced' : '▸ Advanced',
                style: Zn.mono(size: 10, letterSpacing: 2),
              ),
            ),
            if (_showAdvanced) ...[
              const SizedBox(height: 12),
              _LabeledField(label: 'Machine type', controller: _machineType),
              const SizedBox(height: 12),
              _LabeledField(label: 'Region / zone', controller: _region),
              const SizedBox(height: 12),
              Text('Disk · ${_diskGb.round()} GB',
                  style: Zn.mono(size: 10, letterSpacing: 2)),
              Slider(
                value: _diskGb,
                min: 10,
                max: 50,
                divisions: 8,
                activeColor: Zn.ion,
                onChanged: (v) => setState(() => _diskGb = v),
              ),
            ],
            const SizedBox(height: 12),
            SizedBox(
              width: double.infinity,
              height: 48,
              child: FilledButton(
                onPressed: server.busy ? null : () => _create(server),
                child: server.busy
                    ? const SizedBox(
                        width: 18,
                        height: 18,
                        child: CircularProgressIndicator(strokeWidth: 2))
                    : const Text('Turn on my mailbox'),
              ),
            ),
            const SizedBox(height: 24),
            const Divider(),
            const SizedBox(height: 8),
            GestureDetector(
              onTap: () => setState(() => _showExternal = !_showExternal),
              child: Text(
                _showExternal
                    ? '▾ I already run a mailbox'
                    : '▸ I already run a mailbox',
                style: Zn.mono(size: 10, letterSpacing: 2),
              ),
            ),
            if (_showExternal) ...[
              const SizedBox(height: 8),
              const Text(
                'Run the Zeon mailbox on any server you like, then connect it '
                'here. Its access token stays on this phone — we only list '
                'the address so friends can find you. Free, forever.',
                style: TextStyle(color: Zn.muted, fontSize: 12.5, height: 1.45),
              ),
              const SizedBox(height: 12),
              _LabeledField(label: 'Address', controller: _extAddress),
              const SizedBox(height: 12),
              _LabeledField(label: 'Mailbox token', controller: _extToken),
              const SizedBox(height: 12),
              SizedBox(
                width: double.infinity,
                height: 44,
                child: OutlinedButton(
                  onPressed: server.busy ? null : () => _connectExternal(server),
                  child: const Text('Connect my mailbox'),
                ),
              ),
            ],
            const SizedBox(height: 16),
            GestureDetector(
              onTap: () => setState(() => _showJoin = !_showJoin),
              child: Text(
                _showJoin ? '▾ Join a friend\'s host' : '▸ Join a friend\'s host',
                style: Zn.mono(size: 10, letterSpacing: 2),
              ),
            ),
            if (_showJoin) ...[
              const SizedBox(height: 8),
              const Text(
                'A friend can host your mailbox on their own server. Paste the '
                'invite they sent you. Your messages stay end-to-end encrypted — '
                'but your host can see that you have a mailbox there and its '
                'traffic timing. Only accept from someone you trust with that.',
                style: TextStyle(color: Zn.muted, fontSize: 12.5, height: 1.45),
              ),
              const SizedBox(height: 12),
              _LabeledField(label: 'Invite', controller: _inviteInput),
              const SizedBox(height: 12),
              SizedBox(
                width: double.infinity,
                height: 44,
                child: OutlinedButton(
                  onPressed: server.busy ? null : () => _joinHost(server),
                  child: const Text('Join with invite'),
                ),
              ),
            ],
            const SizedBox(height: 16),
            GestureDetector(
              onTap: () => setState(() => _showHost = !_showHost),
              child: Text(
                _showHost
                    ? '▾ Host friends on my server'
                    : '▸ Host friends on my server',
                style: Zn.mono(size: 10, letterSpacing: 2),
              ),
            ),
            if (_showHost) ...[
              const SizedBox(height: 8),
              const Text(
                'Running the Zeon host agent on your server? Create an invite for '
                'a friend — their mailbox lives on your box alongside yours. You '
                'can see that they host with you, never their messages.',
                style: TextStyle(color: Zn.muted, fontSize: 12.5, height: 1.45),
              ),
              const SizedBox(height: 12),
              _LabeledField(label: 'Agent address', controller: _agentAddress),
              const SizedBox(height: 12),
              _LabeledField(label: 'Admin token', controller: _agentAdminToken),
              const SizedBox(height: 12),
              SizedBox(
                width: double.infinity,
                height: 44,
                child: OutlinedButton(
                  onPressed: server.busy ? null : () => _mintInvite(server),
                  child: const Text('Create an invite'),
                ),
              ),
              if (_mintedInvite != null) ...[
                const SizedBox(height: 12),
                _InviteResult(invite: _mintedInvite!),
              ],
            ],
          ],
          if (server.isProvisioning)
            const Padding(
              padding: EdgeInsets.only(top: 8),
              child: Text(
                'Setting up your mailbox — this takes about 2 minutes the '
                'first time. You can leave this screen.',
                style: TextStyle(color: Zn.muted, fontSize: 12.5, height: 1.4),
              ),
            ),
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
                child: Text(server.isExternal
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

  Future<void> _create(ServerState server) async {
    try {
      await server.create(
        provider: _provider,
        machineType: _machineType.text.trim(),
        region: _region.text.trim(),
        diskGb: _diskGb.round(),
      );
    } catch (e) {
      if (mounted) showZnSnack(context, '$e', error: true);
    }
  }

  Future<void> _connectExternal(ServerState server) async {
    final address = _extAddress.text.trim();
    final token = _extToken.text.trim();
    if (address.isEmpty || token.isEmpty) {
      showZnSnack(context, 'Enter your mailbox address and token', error: true);
      return;
    }
    try {
      await server.connectExternal(address, token);
      if (mounted) showZnSnack(context, 'Connected — friends can reach you now');
    } catch (e) {
      if (mounted) showZnSnack(context, '$e', error: true);
    }
  }

  Future<void> _joinHost(ServerState server) async {
    final invite = _inviteInput.text.trim();
    if (invite.isEmpty) {
      showZnSnack(context, 'Paste the invite first', error: true);
      return;
    }
    try {
      await server.joinHost(invite);
      if (mounted) {
        showZnSnack(context, 'Joined — your mailbox is live on your friend\'s host');
      }
    } catch (e) {
      if (mounted) showZnSnack(context, '$e', error: true);
    }
  }

  Future<void> _mintInvite(ServerState server) async {
    final addr = _agentAddress.text.trim();
    final token = _agentAdminToken.text.trim();
    if (addr.isEmpty || token.isEmpty) {
      showZnSnack(context, 'Enter your agent address and admin token', error: true);
      return;
    }
    try {
      final invite = await server.mintInvite(addr, token);
      if (mounted) setState(() => _mintedInvite = invite);
    } catch (e) {
      if (mounted) showZnSnack(context, '$e', error: true);
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
      'running' => (Zn.ok, 'Running'),
      'provisioning' => (Zn.cyan, 'Setting up…'),
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
              _kv('Runs on', _providerLabels[r.provider] ?? r.provider!),
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

class _ProviderChip extends StatelessWidget {
  final String name;
  final bool selected;
  final VoidCallback onTap;

  const _ProviderChip(
      {required this.name, required this.selected, required this.onTap});

  @override
  Widget build(BuildContext context) {
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(Zn.radius),
      child: Container(
        padding: const EdgeInsets.symmetric(vertical: 12, horizontal: 4),
        alignment: Alignment.center,
        decoration: BoxDecoration(
          color: selected ? Zn.ion.withValues(alpha: 0.12) : Zn.surface,
          borderRadius: BorderRadius.circular(Zn.radius),
          border: Border.all(color: selected ? Zn.ion : Zn.line),
        ),
        child: Text(
          name,
          textAlign: TextAlign.center,
          style: TextStyle(
              fontSize: 12,
              color: selected ? Zn.ion : Zn.muted,
              fontWeight: FontWeight.w600),
        ),
      ),
    );
  }
}

class _InviteResult extends StatelessWidget {
  final String invite;
  const _InviteResult({required this.invite});

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: Zn.surface,
        borderRadius: BorderRadius.circular(Zn.radius),
        border: Border.all(color: Zn.ion),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('Share this with your friend',
              style: Zn.mono(size: 10, letterSpacing: 2, color: Zn.ion)),
          const SizedBox(height: 8),
          SelectableText(invite, style: Zn.mono(size: 11, color: Zn.text)),
          const SizedBox(height: 8),
          Align(
            alignment: Alignment.centerRight,
            child: TextButton.icon(
              onPressed: () async {
                await Clipboard.setData(ClipboardData(text: invite));
                if (context.mounted) showZnSnack(context, 'Invite copied');
              },
              icon: const Icon(Icons.copy, size: 16),
              label: const Text('Copy'),
            ),
          ),
        ],
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
