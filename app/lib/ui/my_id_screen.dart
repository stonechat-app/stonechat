import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';
import 'package:qr_flutter/qr_flutter.dart';

import '../state/app_state.dart';
import 'theme.dart';
import 'widgets.dart';

class MyIdScreen extends StatelessWidget {
  const MyIdScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final app = context.watch<AppState>();
    final zeonId = app.zeonId ?? '';

    return Scaffold(
      appBar: AppBar(
        title: Text('MY ID', style: Zn.mono(size: 13, letterSpacing: 3, color: Zn.text)),
      ),
      body: Center(
        child: Padding(
          padding: const EdgeInsets.all(28),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Container(
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: Colors.white,
                  borderRadius: BorderRadius.circular(Zn.radius),
                ),
                child: QrImageView(
                  data: zeonId,
                  size: 220,
                  backgroundColor: Colors.white,
                ),
              ),
              const SizedBox(height: 28),
              Text(app.displayName ?? '',
                  style: const TextStyle(
                      color: Zn.text, fontSize: 18, fontWeight: FontWeight.w600)),
              const SizedBox(height: 12),
              SelectableText(
                zeonId,
                textAlign: TextAlign.center,
                style: Zn.mono(size: 13, color: Zn.ion, weight: FontWeight.w600),
              ),
              const SizedBox(height: 24),
              OutlinedButton.icon(
                onPressed: () {
                  Clipboard.setData(ClipboardData(text: zeonId));
                  showZnSnack(context, 'ID copied');
                },
                icon: const Icon(Icons.copy, size: 16),
                label: const Text('COPY ID'),
              ),
              const SizedBox(height: 16),
              const Text(
                'Anyone with this ID can send you a contact request — and '
                'nothing else. It contains no phone number, email, or name.',
                textAlign: TextAlign.center,
                style: TextStyle(color: Zn.muted, fontSize: 12, height: 1.4),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
