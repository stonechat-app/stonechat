/// Linked devices: what is attached to this mailbox, and how to add or
/// remove one (MULTIDEVICE.md "Device model", "Revocation and threat notes").
library;

import 'package:flutter/material.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
import 'dart:async';

import 'package:provider/provider.dart';

import '../core/api.dart';
import '../core/linking.dart';
import '../state/app_state.dart';
import '../state/chat_state.dart';
import 'theme.dart';
import 'widgets.dart';

class DevicesScreen extends StatefulWidget {
  const DevicesScreen({super.key});

  @override
  State<DevicesScreen> createState() => _DevicesScreenState();
}

class _DevicesScreenState extends State<DevicesScreen> {
  List<Map<String, dynamic>>? _devices;
  String? _error;
  bool _busy = false;

  @override
  void initState() {
    super.initState();
    unawaited(_load());
  }

  ({String address, String token, String tlsFp})? get _mailbox {
    final chat = context.read<ChatState>();
    final address = chat.mailboxAddress;
    final token = chat.mailboxToken;
    final tlsFp = chat.mailboxTlsFp;
    if (address == null || token == null || tlsFp == null) return null;
    return (address: address, token: token, tlsFp: tlsFp);
  }

  Future<void> _load() async {
    final mailbox = _mailbox;
    if (mailbox == null) {
      setState(() => _error = 'Your mailbox is still starting up.');
      return;
    }
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final listed = await listDevices(
        mailbox.address,
        mailbox.token,
        mailbox.tlsFp,
      );
      if (mounted) setState(() => _devices = listed.devices);
    } on ApiException catch (e) {
      if (mounted) setState(() => _error = e.message);
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _revoke(int deviceId) async {
    final mailbox = _mailbox;
    if (mailbox == null) return;
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        backgroundColor: Zn.surface,
        title: const Text('Remove this device?'),
        // The honest statement, not a comforting one. MULTIDEVICE.md is
        // explicit that revocation is a delivery cut, not a cryptographic
        // excision, and the UI is where that stops being a footnote.
        content: const Text(
          'It stops receiving messages immediately and contacts stop '
          'encrypting to it.\n\n'
          'It still holds a copy of your identity key. If the device was '
          'stolen rather than simply retired, removing it here limits what '
          'arrives next — it does not take back what already did.',
          style: TextStyle(color: Zn.muted, fontSize: 13, height: 1.4),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(dialogContext, false),
            child: const Text('Cancel'),
          ),
          TextButton(
            onPressed: () => Navigator.pop(dialogContext, true),
            child: const Text('Remove', style: TextStyle(color: Zn.danger)),
          ),
        ],
      ),
    );
    if (confirmed != true) return;
    try {
      await revokeDevice(
        mailbox.address,
        mailbox.token,
        mailbox.tlsFp,
        deviceId,
      );
      await _load();
    } on ApiException catch (e) {
      if (mounted) showZnSnack(context, e.message, error: true);
    }
  }

  Future<void> _scanToLink() async {
    final mailbox = _mailbox;
    if (mailbox == null) return;
    final offer = await Navigator.push<LinkOffer>(
      context,
      MaterialPageRoute(builder: (_) => const _LinkScannerScreen()),
    );
    if (offer == null || !mounted) return;

    final app = context.read<AppState>();
    setState(() => _busy = true);
    try {
      await app.authoriseLink(
        offer,
        relayAddress: mailbox.address,
        relayTlsFp: mailbox.tlsFp,
        ownerToken: mailbox.token,
        hubUrl: app.api.baseUrl,
        bundleToken: context.read<ChatState>().myBundleToken,
      );
      if (mounted) {
        showZnSnack(context, 'Authorised — finish on the other device');
      }
      await _load();
    } on ApiException catch (e) {
      if (mounted) showZnSnack(context, e.message, error: true);
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Zn.bg,
      appBar: AppBar(
        title: const Text('Linked devices'),
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh, color: Zn.muted),
            onPressed: _busy ? null : _load,
          ),
        ],
      ),
      body: ListView(
        padding: const EdgeInsets.all(20),
        children: [
          if (_error != null)
            Text(_error!, style: const TextStyle(color: Zn.danger)),
          if (_devices != null)
            for (final device in _devices!) _tile(device),
          const SizedBox(height: 20),
          OutlinedButton.icon(
            onPressed: _busy ? null : _scanToLink,
            icon: const Icon(Icons.qr_code_scanner, size: 18),
            label: const Text('Link a device'),
          ),
          const SizedBox(height: 16),
          const Text(
            'On the new device, choose "Link to a device I already have" and '
            'scan the code it shows.\n\n'
            'Every linked device receives and sends independently — none is a '
            'proxy for another. They share your identity, so a linked device '
            'can do anything this one can.',
            style: TextStyle(color: Zn.muted, fontSize: 12, height: 1.4),
          ),
        ],
      ),
    );
  }

  Widget _tile(Map<String, dynamic> device) {
    final id = device['device_id'] as int;
    final kind = device['kind'] as String? ?? 'linked';
    final isThisDevice = id == context.read<ChatState>().myDeviceId;
    final expires = device['expires_at'] as String?;
    final lastSeen = device['last_seen'] as String?;
    return ListTile(
      contentPadding: EdgeInsets.zero,
      leading: Icon(switch (kind) {
        'web' => Icons.language,
        'primary' => Icons.smartphone,
        _ => Icons.devices_other,
      }, color: Zn.muted),
      title: Text(
        isThisDevice ? 'This device' : 'Device $id',
        style: const TextStyle(color: Zn.text),
      ),
      subtitle: Text(
        [
          kind,
          if (lastSeen != null) 'last seen ${_short(lastSeen)}',
          if (expires != null) 'expires ${_short(expires)}',
        ].join(' · '),
        style: Zn.mono(size: 10),
      ),
      trailing: isThisDevice
          ? null
          : IconButton(
              icon: const Icon(Icons.close, size: 18, color: Zn.danger),
              onPressed: () => _revoke(id),
            ),
    );
  }

  static String _short(String isoTimestamp) =>
      isoTimestamp.length >= 16 ? isoTimestamp.substring(0, 16) : isoTimestamp;
}

/// Scan the code the new device is showing. Returns the parsed offer.
class _LinkScannerScreen extends StatelessWidget {
  const _LinkScannerScreen();

  @override
  Widget build(BuildContext context) {
    var handled = false;
    return Scaffold(
      backgroundColor: Zn.bg,
      appBar: AppBar(title: const Text('Scan the new device')),
      body: Stack(
        children: [
          MobileScanner(
            onDetect: (capture) {
              if (handled) return;
              final raw = capture.barcodes.firstOrNull?.rawValue;
              final offer = raw == null ? null : LinkOffer.tryParse(raw);
              if (offer == null) return; // a scanner sees a lot of other things
              handled = true;
              Navigator.pop(context, offer);
            },
          ),
          const Positioned(
            bottom: 32,
            left: 24,
            right: 24,
            child: Text(
              'Point at the code on the device you are adding',
              textAlign: TextAlign.center,
              style: TextStyle(fontSize: 13, color: Zn.text),
            ),
          ),
        ],
      ),
    );
  }
}
