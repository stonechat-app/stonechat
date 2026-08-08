import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';

import '../state/app_state.dart';
import 'identity_export_screen.dart';
import 'link_device_screen.dart';
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
      TextEditingController(text: AppState.defaultHubUrl);
  bool _showAdvanced = false;
  bool _working = false;

  Future<void> _createAccount() async {
    final name = _name.text.trim();
    if (name.isEmpty) {
      showZnSnack(context, 'Pick a name your friends will see', error: true);
      return;
    }
    setState(() => _working = true);
    final app = context.read<AppState>();
    try {
      await app.createIdentity(name: name, hubUrl: _url.text.trim());
      if (!mounted) return;
      await showDialog<void>(
        context: context,
        barrierDismissible: false,
        builder: (_) => _CodeRevealDialog(stonechatId: app.stonechatId ?? ''),
      );
      if (mounted) {
        Navigator.pushReplacementNamed(context, '/mailbox-setup');
      }
    } catch (e) {
      if (mounted) {
        showZnSnack(context, "Couldn't create your account: $e", error: true);
      }
    } finally {
      if (mounted) setState(() => _working = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: SafeArea(
        // Scrollable, but still full-height so the Spacers place the wordmark
        // and the footer links as designed when there is room. Without it the
        // keyboard shrinks the viewport and the fixed Column overflows.
        child: LayoutBuilder(
          builder: (context, constraints) => SingleChildScrollView(
            padding: const EdgeInsets.symmetric(horizontal: 28),
            child: ConstrainedBox(
              constraints: BoxConstraints(minHeight: constraints.maxHeight),
              child: IntrinsicHeight(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Spacer(),
                    Text('STONECHAT',
                        style: Zn.mono(
                            size: 42,
                            color: Zn.orange,
                            weight: FontWeight.w700,
                            letterSpacing: 10)),
                    const SizedBox(height: 8),
                    const Text(
                      'Private messaging through a mailbox only you own.\n'
                      'No phone number. No email. Your messages stay on your phone.',
                      style: TextStyle(color: Zn.muted, height: 1.5),
                    ),
                    const SizedBox(height: 40),
                    const Text('Your name',
                        style: TextStyle(
                            color: Zn.text, fontSize: 13, fontWeight: FontWeight.w600)),
                    const SizedBox(height: 8),
                    TextField(
                      controller: _name,
                      maxLength: 32,
                      decoration: const InputDecoration(
                          hintText: 'Only your friends will ever see it',
                          counterText: ''),
                    ),
                    const SizedBox(height: 28),
                    SizedBox(
                      width: double.infinity,
                      height: 48,
                      child: FilledButton(
                        onPressed: _working ? null : _createAccount,
                        child: _working
                            ? const SizedBox(
                                width: 18,
                                height: 18,
                                child: CircularProgressIndicator(strokeWidth: 2))
                            : const Text('Create account'),
                      ),
                    ),
                    const SizedBox(height: 12),
                    const Text(
                      'No sign-up form. Your account is an encryption key created '
                      'on this phone — we never learn who you are.',
                      style: TextStyle(color: Zn.muted, fontSize: 12, height: 1.4),
                    ),
                    const Spacer(flex: 2),
                    Center(
                      child: TextButton(
                        onPressed: _working
                            ? null
                            : () => Navigator.push(
                                  context,
                                  MaterialPageRoute(
                                    builder: (_) => LinkDeviceScreen(
                                        hubUrl: _url.text.trim()),
                                  ),
                                ),
                        child: const Text('Link to a device I already have',
                            style: TextStyle(color: Zn.muted, fontSize: 12)),
                      ),
                    ),
                    Center(
                      child: TextButton(
                        onPressed: _working
                            ? null
                            : () => Navigator.push(
                                  context,
                                  MaterialPageRoute(
                                    builder: (_) => IdentityRestoreScreen(
                                        hubUrl: _url.text.trim()),
                                  ),
                                ),
                        child: const Text('Restore an exported identity',
                            style: TextStyle(color: Zn.muted, fontSize: 12)),
                      ),
                    ),
                    Center(
                      child: TextButton(
                        onPressed: () => setState(() => _showAdvanced = !_showAdvanced),
                        child: Text('Advanced',
                            style: Zn.mono(size: 10, letterSpacing: 2)),
                      ),
                    ),
                    if (_showAdvanced) ...[
                      Text('Service address (self-hosters only)',
                          style: Zn.mono(size: 10, letterSpacing: 1)),
                      const SizedBox(height: 6),
                      TextField(
                        controller: _url,
                        style: Zn.mono(size: 13, color: Zn.text),
                        decoration: InputDecoration(
                            hintText: AppState.hostedHubUrl),
                      ),
                      const SizedBox(height: 12),
                    ],
                    const SizedBox(height: 8),
                  ],
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }
}

class _CodeRevealDialog extends StatelessWidget {
  final String stonechatId;
  const _CodeRevealDialog({required this.stonechatId});

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      backgroundColor: Zn.surface,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(Zn.radius),
        side: const BorderSide(color: Zn.line),
      ),
      title: const Text('Your Stonechat code',
          style: TextStyle(fontSize: 16, fontWeight: FontWeight.w600)),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SelectableText(stonechatId,
              style:
                  Zn.mono(size: 14, color: Zn.orange, weight: FontWeight.w700)),
          const SizedBox(height: 12),
          const Text(
            'This is your code — friends add you by scanning your QR or '
            'tapping your invite link. Share it freely: it says nothing '
            'about who you are.',
            style: TextStyle(color: Zn.muted, fontSize: 12.5, height: 1.4),
          ),
        ],
      ),
      actions: [
        TextButton(
          onPressed: () {
            Clipboard.setData(ClipboardData(text: stonechatId));
            showZnSnack(context, 'Copied');
          },
          child: const Text('Copy'),
        ),
        FilledButton(
          onPressed: () => Navigator.pop(context),
          child: const Text('Continue'),
        ),
      ],
    );
  }
}
