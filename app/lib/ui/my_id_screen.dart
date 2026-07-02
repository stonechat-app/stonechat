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
    final handle = app.handle ?? '';

    return Scaffold(
      appBar: AppBar(
        title: const Text('My code',
            style: TextStyle(fontSize: 17, fontWeight: FontWeight.w600)),
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
              const SizedBox(height: 10),
              SelectableText(
                handle,
                textAlign: TextAlign.center,
                style: Zn.mono(size: 19, color: Zn.ion, weight: FontWeight.w700),
              ),
              const SizedBox(height: 20),
              OutlinedButton.icon(
                onPressed: () {
                  Clipboard.setData(ClipboardData(text: handle));
                  showZnSnack(context, 'Code copied');
                },
                icon: const Icon(Icons.copy, size: 16),
                label: const Text('Copy my code'),
              ),
              const SizedBox(height: 16),
              const Text(
                'Friends add you with these three words, or by scanning the '
                'QR. Anyone with your code can send you a request — and '
                'nothing else. It contains no phone number, email, or name.',
                textAlign: TextAlign.center,
                style: TextStyle(color: Zn.muted, fontSize: 12, height: 1.4),
              ),
              const SizedBox(height: 14),
              SelectableText(
                zeonId,
                textAlign: TextAlign.center,
                style: Zn.mono(size: 9, color: Zn.muted),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
