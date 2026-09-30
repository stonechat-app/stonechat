/// The new device's side of linking: show a code, wait to be authorised.
///
/// Reached from onboarding, because this runs on a device with no identity
/// yet — that is the whole point.
library;

import 'dart:async';

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:qr_flutter/qr_flutter.dart';

import '../core/api.dart';
import '../core/linking.dart';
import '../state/app_state.dart';
import 'theme.dart';

class LinkDeviceScreen extends StatefulWidget {
  final String hubUrl;
  const LinkDeviceScreen({super.key, required this.hubUrl});

  @override
  State<LinkDeviceScreen> createState() => _LinkDeviceScreenState();
}

class _LinkDeviceScreenState extends State<LinkDeviceScreen> {
  LinkOffer? _offer;
  Timer? _poll;
  String? _error;
  bool _linked = false;

  @override
  void initState() {
    super.initState();
    // The offer is parked on the hub before it can be shown, so this is
    // async: a code committing to keys nobody can fetch would scan and then
    // fail.
    final app = context.read<AppState>();
    app.beginLinking(widget.hubUrl).then((offer) {
      if (!mounted) return;
      setState(() => _offer = offer);
    }).catchError((Object e) {
      if (mounted) setState(() => _error = '$e');
    });
    // The grant is single-use and expires in ten minutes; polling is the
    // whole of the new device's side, since it has no socket to be notified
    // on until it has an identity.
    _poll = Timer.periodic(const Duration(seconds: 2), (_) => _tryCollect());
  }

  @override
  void dispose() {
    _poll?.cancel();
    super.dispose();
  }

  Future<void> _tryCollect() async {
    if (_linked) return;
    final offer = _offer;
    if (offer == null) return;
    try {
      final ok = await context.read<AppState>().collectLinkGrant(
        hubUrl: widget.hubUrl,
        offer: offer,
      );
      if (!ok || !mounted) return;
      _linked = true;
      _poll?.cancel();
      // main.dart swaps to the home screen once an identity exists.
      Navigator.of(context).popUntil((route) => route.isFirst);
    } on ApiException catch (e) {
      // A refusal is terminal — the commitment check failed, which means the
      // grant was for a different identity than the one being claimed.
      _poll?.cancel();
      if (mounted) setState(() => _error = e.message);
    } catch (_) {
      // Network hiccup: the next tick tries again.
    }
  }

  @override
  Widget build(BuildContext context) {
    final offer = _offer;
    return Scaffold(
      backgroundColor: Zn.bg,
      appBar: AppBar(title: const Text('Link this device')),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(24),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.center,
          children: [
            if (_error != null) ...[
              Text(
                _error!,
                textAlign: TextAlign.center,
                style: const TextStyle(color: Zn.danger, height: 1.4),
              ),
              const SizedBox(height: 16),
              OutlinedButton(
                onPressed: () => Navigator.pop(context),
                child: const Text('Back'),
              ),
            ] else if (offer != null) ...[
              Container(
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: Colors.white,
                  borderRadius: BorderRadius.circular(Zn.radius),
                ),
                child: QrImageView(
                  data: offer.encode(),
                  size: 260,
                  backgroundColor: Colors.white,
                ),
              ),
              const SizedBox(height: 24),
              const Row(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  SizedBox(
                    width: 14,
                    height: 14,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  ),
                  SizedBox(width: 10),
                  Text(
                    'Waiting to be approved…',
                    style: TextStyle(color: Zn.muted, fontSize: 13),
                  ),
                ],
              ),
              const SizedBox(height: 20),
              const Text(
                'On a device you already use, open Settings → Linked devices '
                '→ Link a device, and scan this code.',
                textAlign: TextAlign.center,
                style: TextStyle(color: Zn.text, fontSize: 13, height: 1.5),
              ),
              const SizedBox(height: 16),
              const Text(
                'The code is only useful for the next few minutes, and only '
                'once. It carries no secret of yours — what comes back is '
                'sealed so that only this device can open it.\n\n'
                'Your message history stays where it is; this device starts '
                'from now.',
                textAlign: TextAlign.center,
                style: TextStyle(color: Zn.muted, fontSize: 12, height: 1.4),
              ),
            ],
          ],
        ),
      ),
    );
  }
}
