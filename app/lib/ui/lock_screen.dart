/// App lock: a full-screen gate over the whole app, opened with the device's
/// biometrics or passcode (local_auth). Locks on cold start and whenever the
/// app leaves the foreground. Purely a screen gate — the DB key never
/// depends on it; SQLCipher already protects the bytes at rest.
library;

import 'package:flutter/material.dart';
import 'package:local_auth/local_auth.dart';
import 'package:provider/provider.dart';

import '../state/app_state.dart';
import 'theme.dart';

class LockGate extends StatefulWidget {
  final Widget child;
  const LockGate({super.key, required this.child});

  @override
  State<LockGate> createState() => _LockGateState();
}

class _LockGateState extends State<LockGate> with WidgetsBindingObserver {
  final _auth = LocalAuthentication();
  bool _locked = false;
  bool _authInFlight = false;

  bool get _enabled {
    final app = context.read<AppState>();
    return app.appLockEnabled && app.hasIdentity;
  }

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _locked = _enabled;
    if (_locked) {
      // Prompt as soon as the first frame is up.
      WidgetsBinding.instance.addPostFrameCallback((_) => _unlock());
    }
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (!_enabled) return;
    // The biometric sheet itself backgrounds the activity on Android —
    // don't re-lock underneath our own prompt.
    if (state == AppLifecycleState.paused && !_authInFlight && !_locked) {
      setState(() => _locked = true);
    }
  }

  Future<void> _unlock() async {
    if (_authInFlight) return;
    _authInFlight = true;
    try {
      final ok = await _auth.authenticate(
        localizedReason: 'Unlock Zeon',
        persistAcrossBackgrounding: true,
      );
      if (ok && mounted) setState(() => _locked = false);
    } on Exception {
      // No biometrics enrolled / canceled / hardware odd — stay locked,
      // the button retries.
    } finally {
      _authInFlight = false;
    }
  }

  @override
  Widget build(BuildContext context) {
    return Stack(
      children: [
        widget.child,
        if (_locked)
          Positioned.fill(
            child: Scaffold(
              backgroundColor: Zn.bg,
              body: Center(
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Text('ZEON',
                        style: Zn.mono(
                            size: 24,
                            color: Zn.ion,
                            weight: FontWeight.w700,
                            letterSpacing: 8)),
                    const SizedBox(height: 12),
                    Text('LOCKED', style: Zn.mono(size: 10, letterSpacing: 4)),
                    const SizedBox(height: 32),
                    OutlinedButton.icon(
                      onPressed: _unlock,
                      icon: const Icon(Icons.lock_open, size: 18),
                      label: const Text('Unlock'),
                    ),
                  ],
                ),
              ),
            ),
          ),
      ],
    );
  }
}
