import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';

import '../state/app_state.dart';
import 'theme.dart';
import 'widgets.dart';

class OnboardingScreen extends StatefulWidget {
  const OnboardingScreen({super.key});

  @override
  State<OnboardingScreen> createState() => _OnboardingScreenState();
}

class _OnboardingScreenState extends State<OnboardingScreen> {
  final _name = TextEditingController();
  late final _url =
      TextEditingController(text: AppState.defaultControlPlaneUrl);
  bool _showAdvanced = false;
  bool _working = false;

  Future<void> _forge() async {
    final name = _name.text.trim();
    if (name.isEmpty) {
      showZnSnack(context, 'Pick a name your contacts will see', error: true);
      return;
    }
    setState(() => _working = true);
    final app = context.read<AppState>();
    try {
      await app.createIdentity(name: name, controlPlaneUrl: _url.text.trim());
      if (!mounted) return;
      await showDialog<void>(
        context: context,
        builder: (_) => _IdentityRevealDialog(zeonId: app.zeonId!),
      );
      if (mounted) {
        Navigator.pushReplacementNamed(context, '/home');
      }
    } catch (e) {
      if (mounted) showZnSnack(context, 'Could not register: $e', error: true);
    } finally {
      if (mounted) setState(() => _working = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 28),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Spacer(),
              Text('ZEON',
                  style: Zn.mono(
                      size: 42,
                      color: Zn.ion,
                      weight: FontWeight.w700,
                      letterSpacing: 10)),
              const SizedBox(height: 8),
              const Text(
                'Messaging that routes through a server you own.\n'
                'No phone number. No cloud inbox. History lives here.',
                style: TextStyle(color: Zn.muted, height: 1.5),
              ),
              const SizedBox(height: 40),
              Text('DISPLAY NAME', style: Zn.mono(size: 10, letterSpacing: 2)),
              const SizedBox(height: 8),
              TextField(
                controller: _name,
                maxLength: 32,
                decoration: const InputDecoration(
                    hintText: 'shown only to accepted contacts',
                    counterText: ''),
              ),
              const SizedBox(height: 12),
              GestureDetector(
                onTap: () => setState(() => _showAdvanced = !_showAdvanced),
                child: Text(
                  _showAdvanced ? '▾ CONTROL PLANE' : '▸ CONTROL PLANE',
                  style: Zn.mono(size: 10, letterSpacing: 2),
                ),
              ),
              if (_showAdvanced) ...[
                const SizedBox(height: 8),
                TextField(
                  controller: _url,
                  style: Zn.mono(size: 13, color: Zn.text),
                  decoration:
                      const InputDecoration(hintText: 'http://host:8000'),
                ),
              ],
              const SizedBox(height: 28),
              SizedBox(
                width: double.infinity,
                height: 48,
                child: FilledButton(
                  onPressed: _working ? null : _forge,
                  child: _working
                      ? const SizedBox(
                          width: 18,
                          height: 18,
                          child: CircularProgressIndicator(strokeWidth: 2))
                      : const Text('FORGE IDENTITY'),
                ),
              ),
              const SizedBox(height: 12),
              const Text(
                'Forging generates an encryption keypair on this device. '
                'Your Zeon ID is derived from it — nothing else identifies you.',
                style: TextStyle(color: Zn.muted, fontSize: 12, height: 1.4),
              ),
              const Spacer(flex: 2),
            ],
          ),
        ),
      ),
    );
  }
}

class _IdentityRevealDialog extends StatelessWidget {
  final String zeonId;
  const _IdentityRevealDialog({required this.zeonId});

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      backgroundColor: Zn.surface,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(Zn.radius),
        side: const BorderSide(color: Zn.line),
      ),
      title: Text('YOUR ZEON ID',
          style: Zn.mono(size: 12, letterSpacing: 2, color: Zn.ion)),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SelectableText(zeonId,
              style: Zn.mono(size: 14, color: Zn.text, weight: FontWeight.w600)),
          const SizedBox(height: 12),
          const Text(
            'This is how people reach you. Share it freely — it reveals '
            'nothing about you.',
            style: TextStyle(color: Zn.muted, fontSize: 12, height: 1.4),
          ),
        ],
      ),
      actions: [
        TextButton(
          onPressed: () {
            Clipboard.setData(ClipboardData(text: zeonId));
            showZnSnack(context, 'Copied');
          },
          child: const Text('COPY'),
        ),
        FilledButton(
          onPressed: () => Navigator.pop(context),
          child: const Text('ENTER'),
        ),
      ],
    );
  }
}
