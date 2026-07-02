import 'package:flutter/material.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
import 'package:provider/provider.dart';

import '../state/chat_state.dart';
import 'theme.dart';
import 'widgets.dart';

class AddContactScreen extends StatefulWidget {
  const AddContactScreen({super.key});

  @override
  State<AddContactScreen> createState() => _AddContactScreenState();
}

class _AddContactScreenState extends State<AddContactScreen> {
  final _id = TextEditingController();
  bool _working = false;
  bool _scanning = false;
  bool _scanHandled = false;

  Future<void> _add(String rawId) async {
    if (_working) return;
    setState(() => _working = true);
    try {
      await context.read<ChatState>().addContact(rawId);
      if (mounted) {
        Navigator.pop(context);
        showZnSnack(context, 'Request sent — waiting for them to accept');
      }
    } on FormatException catch (e) {
      if (mounted) showZnSnack(context, e.message, error: true);
    } catch (e) {
      if (mounted) showZnSnack(context, '$e', error: true);
    } finally {
      if (mounted) setState(() => _working = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Add a friend',
            style: TextStyle(fontSize: 17, fontWeight: FontWeight.w600)),
        actions: [
          IconButton(
            icon: Icon(_scanning ? Icons.keyboard : Icons.qr_code_scanner,
                color: Zn.muted),
            onPressed: () => setState(() {
              _scanning = !_scanning;
              _scanHandled = false;
            }),
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
            if (_scanHandled) return;
            final value = capture.barcodes.firstOrNull?.rawValue;
            if (value != null &&
                (value.startsWith('ZC-') || value.startsWith('zn-'))) {
              _scanHandled = true;
              _add(value);
            }
          },
        ),
        Positioned(
          bottom: 32,
          left: 0,
          right: 0,
          child: Center(
            child: Text('Point at a friend\'s Zeon code',
                style: TextStyle(fontSize: 13, color: Zn.text)),
          ),
        ),
      ],
    );
  }

  Widget _buildManual() {
    return Padding(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text('Their Zeon code',
              style: TextStyle(
                  color: Zn.text, fontSize: 13, fontWeight: FontWeight.w600)),
          const SizedBox(height: 6),
          const Text(
            'Ask them for their three words — or scan their QR code with the '
            'camera button above.',
            style: TextStyle(color: Zn.muted, fontSize: 12.5, height: 1.4),
          ),
          const SizedBox(height: 12),
          TextField(
            controller: _id,
            style: Zn.mono(size: 14, color: Zn.text),
            autocorrect: false,
            decoration: const InputDecoration(hintText: 'zn-palm-dog-cherry'),
          ),
          const SizedBox(height: 20),
          SizedBox(
            width: double.infinity,
            height: 48,
            child: FilledButton(
              onPressed: _working ? null : () => _add(_id.text),
              child: _working
                  ? const SizedBox(
                      width: 18,
                      height: 18,
                      child: CircularProgressIndicator(strokeWidth: 2))
                  : const Text('Send request'),
            ),
          ),
          const SizedBox(height: 16),
          const Text(
            'They\'ll get a private request, and you can chat once they '
            'accept. Codes carry no personal information.',
            style: TextStyle(color: Zn.muted, fontSize: 12, height: 1.4),
          ),
        ],
      ),
    );
  }
}
