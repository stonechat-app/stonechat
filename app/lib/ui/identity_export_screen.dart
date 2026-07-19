import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
import 'package:provider/provider.dart';
import 'package:qr_flutter/qr_flutter.dart';

import '../core/identity_export.dart';
import '../state/app_state.dart';
import '../state/chat_state.dart';
import '../state/server_state.dart';
import 'theme.dart';
import 'widgets.dart';

/// Settings → Identity export: encrypt the identity key under a passphrase
/// and show it as a QR (rendered live, never written to disk or Photos)
/// plus a copyable string. The companion restore flow lives below.
class IdentityExportScreen extends StatefulWidget {
  const IdentityExportScreen({super.key});

  @override
  State<IdentityExportScreen> createState() => _IdentityExportScreenState();
}

class _IdentityExportScreenState extends State<IdentityExportScreen> {
  final _passphrase = TextEditingController();
  final _confirm = TextEditingController();
  String? _code;
  bool _busy = false;

  Future<void> _create() async {
    final passphrase = _passphrase.text;
    if (passphrase.length < IdentityCodec.minPassphraseChars) {
      showZnSnack(context,
          'Use at least ${IdentityCodec.minPassphraseChars} characters',
          error: true);
      return;
    }
    if (passphrase != _confirm.text) {
      showZnSnack(context, "The passphrases don't match", error: true);
      return;
    }
    setState(() => _busy = true);
    try {
      final code = await context.read<AppState>().exportIdentity(passphrase);
      if (mounted) setState(() => _code = code);
    } catch (_) {
      if (mounted) showZnSnack(context, 'Export failed.', error: true);
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Identity export',
            style: TextStyle(fontSize: 17, fontWeight: FontWeight.w600)),
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(24),
        child: _code == null ? _buildForm() : _buildCode(_code!),
      ),
    );
  }

  Widget _buildForm() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Text(
          'Your Zeon ID is an encryption key that normally lives and dies '
          'with this phone. An identity export is the one way to outlive it: '
          'an encrypted code you can print or store somewhere safe, and use '
          'to restore this same Zeon ID on a new phone.\n\n'
          'It contains your identity key — not your messages. For those, '
          'use Chat backup.',
          style: TextStyle(color: Zn.muted, fontSize: 13, height: 1.5),
        ),
        const SizedBox(height: 24),
        const Text('Passphrase',
            style: TextStyle(
                color: Zn.text, fontSize: 13, fontWeight: FontWeight.w600)),
        const SizedBox(height: 8),
        TextField(
          controller: _passphrase,
          obscureText: true,
          decoration: const InputDecoration(
              hintText: 'At least 8 characters — longer is safer'),
        ),
        const SizedBox(height: 12),
        TextField(
          controller: _confirm,
          obscureText: true,
          decoration: const InputDecoration(hintText: 'Repeat the passphrase'),
        ),
        const SizedBox(height: 20),
        SizedBox(
          width: double.infinity,
          height: 48,
          child: FilledButton(
            onPressed: _busy ? null : _create,
            child: _busy
                ? const SizedBox(
                    width: 18,
                    height: 18,
                    child: CircularProgressIndicator(strokeWidth: 2))
                : const Text('Create export code'),
          ),
        ),
        const SizedBox(height: 12),
        const Text(
          'Anyone who has this code and its passphrase is you: they can '
          'restore your Zeon ID and receive messages meant for you. Treat '
          'the printed code like a house key, and the passphrase like the '
          'alarm code — keep them apart.',
          style: TextStyle(color: Zn.muted, fontSize: 12, height: 1.4),
        ),
      ],
    );
  }

  Widget _buildCode(String code) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.center,
      children: [
        Container(
          padding: const EdgeInsets.all(16),
          decoration: BoxDecoration(
            color: Colors.white,
            borderRadius: BorderRadius.circular(Zn.radius),
          ),
          child: QrImageView(
            data: code,
            size: 260,
            backgroundColor: Colors.white,
          ),
        ),
        const SizedBox(height: 18),
        OutlinedButton.icon(
          onPressed: () {
            Clipboard.setData(ClipboardData(text: code));
            showZnSnack(context, 'Export code copied');
          },
          icon: const Icon(Icons.copy, size: 16),
          label: const Text('Copy as text'),
        ),
        const SizedBox(height: 16),
        const Text(
          'Print this QR or write the text copy down, and store it offline. '
          'Avoid screenshots — your photo library is usually synced to a '
          'cloud you don\'t control. To use it: reinstall Zeon, choose '
          '"Restore identity" and scan this code.\n\n'
          'Restoring keeps your Zeon ID and contactability. Messages are '
          'not included — restore a chat backup for those.',
          textAlign: TextAlign.center,
          style: TextStyle(color: Zn.muted, fontSize: 12, height: 1.4),
        ),
      ],
    );
  }
}

/// Onboarding → Restore identity: scan or paste an export code, decrypt it
/// and take over the Zeon ID it holds.
class IdentityRestoreScreen extends StatefulWidget {
  final String hubUrl;
  const IdentityRestoreScreen({super.key, required this.hubUrl});

  @override
  State<IdentityRestoreScreen> createState() => _IdentityRestoreScreenState();
}

class _IdentityRestoreScreenState extends State<IdentityRestoreScreen> {
  final _code = TextEditingController();
  final _passphrase = TextEditingController();
  bool _scanning = true;
  bool _busy = false;

  Future<void> _restore() async {
    final code = _code.text.trim();
    if (code.isEmpty) {
      showZnSnack(context, 'Scan or paste your export code first', error: true);
      return;
    }
    setState(() => _busy = true);
    final app = context.read<AppState>();
    final chat = context.read<ChatState>();
    final server = context.read<ServerState>();
    try {
      await app.restoreIdentity(
        export: code,
        passphrase: _passphrase.text,
        hubUrl: widget.hubUrl,
      );
      // Same boot sequence main.dart runs for an existing identity: history
      // first (empty here), then the server record — a mailbox that survived
      // the old phone reconnects right away.
      await chat.load();
      await server.refresh();
      if (!mounted) return;
      final hasMailbox = server.isRunning || server.isProvisioning;
      Navigator.of(context).pushNamedAndRemoveUntil(
          hasMailbox ? '/home' : '/mailbox-setup', (_) => false);
    } on IdentityExportException catch (e) {
      if (mounted) showZnSnack(context, e.message, error: true);
    } catch (e) {
      if (mounted) {
        showZnSnack(context, "Couldn't restore: $e", error: true);
      }
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Restore identity',
            style: TextStyle(fontSize: 17, fontWeight: FontWeight.w600)),
        actions: [
          IconButton(
            icon: Icon(_scanning ? Icons.keyboard : Icons.qr_code_scanner,
                color: Zn.muted),
            onPressed: () => setState(() => _scanning = !_scanning),
          ),
        ],
      ),
      body: _scanning ? _buildScanner() : _buildManual(),
    );
  }

  Widget _buildScanner() {
    return Stack(
      children: [
        MobileScanner(
          onDetect: (capture) {
            final raw = capture.barcodes.firstOrNull?.rawValue;
            if (raw != null && raw.startsWith(IdentityCodec.prefix)) {
              setState(() {
                _code.text = raw;
                _scanning = false;
              });
            }
          },
        ),
        const Positioned(
          bottom: 32,
          left: 0,
          right: 0,
          child: Center(
            child: Text('Point at your identity export QR',
                style: TextStyle(fontSize: 13, color: Zn.text)),
          ),
        ),
      ],
    );
  }

  Widget _buildManual() {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text('Export code',
              style: TextStyle(
                  color: Zn.text, fontSize: 13, fontWeight: FontWeight.w600)),
          const SizedBox(height: 8),
          TextField(
            controller: _code,
            maxLines: 4,
            style: Zn.mono(size: 12, color: Zn.text),
            decoration: const InputDecoration(hintText: 'ZID1.…'),
          ),
          const SizedBox(height: 16),
          const Text('Passphrase',
              style: TextStyle(
                  color: Zn.text, fontSize: 13, fontWeight: FontWeight.w600)),
          const SizedBox(height: 8),
          TextField(
            controller: _passphrase,
            obscureText: true,
            decoration:
                const InputDecoration(hintText: 'The passphrase you chose'),
          ),
          const SizedBox(height: 20),
          SizedBox(
            width: double.infinity,
            height: 48,
            child: FilledButton(
              onPressed: _busy ? null : _restore,
              child: _busy
                  ? const SizedBox(
                      width: 18,
                      height: 18,
                      child: CircularProgressIndicator(strokeWidth: 2))
                  : const Text('Restore'),
            ),
          ),
          const SizedBox(height: 12),
          const Text(
            'This brings back your Zeon ID and mailbox, so contacts can '
            'reach you as before. Message history is separate — restore a '
            'chat backup from Settings afterwards.',
            style: TextStyle(color: Zn.muted, fontSize: 12, height: 1.4),
          ),
        ],
      ),
    );
  }
}
