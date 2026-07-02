import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../state/server_state.dart';
import 'theme.dart';
import 'widgets.dart';

/// Per-provider sensible defaults; everything stays editable.
const _providerDefaults = {
  'gcp': (machineType: 'e2-micro', region: 'us-central1-a'),
  'aws': (machineType: 't3.micro', region: 'us-east-1'),
  'local': (machineType: 'container', region: 'localhost'),
};

class ServerScreen extends StatefulWidget {
  const ServerScreen({super.key});

  @override
  State<ServerScreen> createState() => _ServerScreenState();
}

class _ServerScreenState extends State<ServerScreen> {
  String _provider = 'gcp';
  late final _machineType =
      TextEditingController(text: _providerDefaults['gcp']!.machineType);
  late final _region =
      TextEditingController(text: _providerDefaults['gcp']!.region);
  double _diskGb = 10;

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
        title: Text('RELAY', style: Zn.mono(size: 13, letterSpacing: 3, color: Zn.text)),
      ),
      body: ListView(
        padding: const EdgeInsets.all(20),
        children: [
          _StatusCard(server: server),
          const SizedBox(height: 24),
          if (server.record.status == 'none') ...[
            Text('IGNITE A RELAY', style: Zn.mono(size: 10, letterSpacing: 2)),
            const SizedBox(height: 6),
            const Text(
              'A tiny virtual machine, in a cloud account, whose only job is '
              'to hold encrypted envelopes until your phone picks them up.',
              style: TextStyle(color: Zn.muted, fontSize: 12, height: 1.4),
            ),
            const SizedBox(height: 16),
            Row(
              children: [
                for (final p in _providerDefaults.keys) ...[
                  Expanded(
                    child: _ProviderChip(
                      name: p,
                      selected: _provider == p,
                      onTap: () => _applyProviderDefaults(p),
                    ),
                  ),
                  if (p != _providerDefaults.keys.last) const SizedBox(width: 8),
                ],
              ],
            ),
            const SizedBox(height: 16),
            _LabeledField(label: 'MACHINE TYPE', controller: _machineType),
            const SizedBox(height: 12),
            _LabeledField(label: 'REGION / ZONE', controller: _region),
            const SizedBox(height: 12),
            Text('DISK · ${_diskGb.round()} GB',
                style: Zn.mono(size: 10, letterSpacing: 2)),
            Slider(
              value: _diskGb,
              min: 10,
              max: 50,
              divisions: 8,
              activeColor: Zn.ion,
              onChanged: (v) => setState(() => _diskGb = v),
            ),
            const SizedBox(height: 8),
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
                    : const Text('IGNITE'),
              ),
            ),
          ],
          if (server.isProvisioning)
            const Padding(
              padding: EdgeInsets.only(top: 8),
              child: Text(
                'Booting the VM and installing your relay. First boot takes a '
                'couple of minutes — you can leave this screen.',
                style: TextStyle(color: Zn.muted, fontSize: 12, height: 1.4),
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
                child: const Text('DESTROY RELAY'),
              ),
            ),
            const SizedBox(height: 8),
            const Text(
              'Destroying the relay deletes the VM and any undelivered '
              'envelopes on it. Your local history is untouched. You can '
              'ignite a new one anytime — contacts find it automatically.',
              style: TextStyle(color: Zn.muted, fontSize: 12, height: 1.4),
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
        title: const Text('Destroy relay?'),
        content: const Text(
            'The VM and any undelivered envelopes on it are deleted.',
            style: TextStyle(color: Zn.muted)),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(context, false),
              child: const Text('KEEP')),
          TextButton(
              onPressed: () => Navigator.pop(context, true),
              child: const Text('DESTROY',
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
      'running' => (Zn.ok, 'ONLINE'),
      'provisioning' => (Zn.cyan, 'IGNITING…'),
      'error' => (Zn.danger, 'FAILED'),
      _ => (Zn.muted, 'NO RELAY'),
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
                  style: Zn.mono(
                      size: 14, color: color, weight: FontWeight.w700, letterSpacing: 2)),
            ],
          ),
          if (r.status != 'none') ...[
            const SizedBox(height: 12),
            if (r.provider != null)
              _kv('PROVIDER', r.provider!.toUpperCase()),
            if (r.address != null) _kv('ADDRESS', r.address!),
            if (r.status == 'running')
              _kv('LINK', server.socketConnected ? 'CONNECTED' : 'RECONNECTING…'),
            if (r.error != null) _kv('ERROR', r.error!),
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
            SizedBox(width: 84, child: Text(k, style: Zn.mono(size: 10))),
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
        padding: const EdgeInsets.symmetric(vertical: 12),
        alignment: Alignment.center,
        decoration: BoxDecoration(
          color: selected ? Zn.ion.withValues(alpha: 0.12) : Zn.surface,
          borderRadius: BorderRadius.circular(Zn.radius),
          border: Border.all(color: selected ? Zn.ion : Zn.line),
        ),
        child: Text(
          name.toUpperCase(),
          style: Zn.mono(
              size: 11,
              color: selected ? Zn.ion : Zn.muted,
              weight: FontWeight.w700,
              letterSpacing: 1),
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
        Text(label, style: Zn.mono(size: 10, letterSpacing: 2)),
        const SizedBox(height: 6),
        TextField(
          controller: controller,
          style: Zn.mono(size: 13, color: Zn.text),
        ),
      ],
    );
  }
}
