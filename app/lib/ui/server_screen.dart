import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../state/server_state.dart';
import 'theme.dart';
import 'widgets.dart';

/// Per-provider sensible defaults; everything stays editable under Advanced.
const _providerDefaults = {
  'gcp': (machineType: 'e2-micro', region: 'us-central1-a'),
  'aws': (machineType: 't3.micro', region: 'us-east-1'),
  'local': (machineType: 'container', region: 'localhost'),
};

const _providerLabels = {
  'gcp': 'Google Cloud',
  'aws': 'Amazon',
  'local': 'This computer',
};

class ServerScreen extends StatefulWidget {
  const ServerScreen({super.key});

  @override
  State<ServerScreen> createState() => _ServerScreenState();
}

class _ServerScreenState extends State<ServerScreen> {
  String _provider = kDebugMode ? 'local' : 'gcp';
  late final _machineType =
      TextEditingController(text: _providerDefaults[_provider]!.machineType);
  late final _region =
      TextEditingController(text: _providerDefaults[_provider]!.region);
  double _diskGb = 10;
  bool _showAdvanced = false;

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
                for (final p in _providerDefaults.keys) ...[
                  Expanded(
                    child: _ProviderChip(
                      name: _providerLabels[p]!,
                      selected: _provider == p,
                      onTap: () => _applyProviderDefaults(p),
                    ),
                  ),
                  if (p != _providerDefaults.keys.last) const SizedBox(width: 8),
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
                child: const Text('Turn off mailbox'),
              ),
            ),
            const SizedBox(height: 8),
            const Text(
              'While your mailbox is off you won\'t receive messages — '
              'they\'ll wait on your friends\' phones and arrive once you '
              'turn it back on. Your chat history on this phone is never '
              'affected.',
              style: TextStyle(color: Zn.muted, fontSize: 12.5, height: 1.4),
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

  Future<void> _destroy(ServerState server) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: Zn.surface,
        title: const Text('Turn off your mailbox?'),
        content: const Text(
            'You\'ll stop receiving messages until you turn it back on. '
            'New messages will wait on your friends\' phones. Your chat '
            'history stays on this phone.',
            style: TextStyle(color: Zn.muted, height: 1.4)),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(context, false),
              child: const Text('Keep it on')),
          TextButton(
              onPressed: () => Navigator.pop(context, true),
              child: const Text('Turn off',
                  style: TextStyle(color: Zn.danger))),
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
