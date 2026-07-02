/// Shared Zeon UI pieces: the relay status strip and ID-derived avatars.
library;

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../state/server_state.dart';
import 'theme.dart';

/// The signature element: a thin status line that always tells you whether
/// you can receive messages. Tapping it opens the mailbox screen.
class RelayStrip extends StatelessWidget {
  const RelayStrip({super.key});

  @override
  Widget build(BuildContext context) {
    final server = context.watch<ServerState>();

    final (dot, label, color) = switch ((server.record.status, server.socketConnected)) {
      ('running', true) => ('●', "You're reachable", Zn.ok),
      ('running', false) => ('◐', 'Connecting to your mailbox…', Zn.cyan),
      ('provisioning', _) => ('◌', 'Setting up your mailbox…', Zn.cyan),
      ('error', _) => ('✕', "Mailbox setup didn't work — tap to see why", Zn.danger),
      _ => ('○', 'No mailbox yet — tap to set up', Zn.muted),
    };

    return InkWell(
      onTap: () => Navigator.pushNamed(context, '/server'),
      child: Container(
        width: double.infinity,
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 7),
        decoration: const BoxDecoration(
          color: Zn.surface,
          border: Border(
            top: BorderSide(color: Zn.line),
            bottom: BorderSide(color: Zn.line),
          ),
        ),
        child: Row(
          children: [
            Text(dot, style: Zn.mono(size: 11, color: color)),
            const SizedBox(width: 8),
            Text(label,
                style: TextStyle(
                    fontSize: 12.5, color: color, fontWeight: FontWeight.w500)),
          ],
        ),
      ),
    );
  }
}

/// Square avatar with a color derived from the contact's ID — no photos,
/// nothing to upload, nothing to leak.
class ZeonAvatar extends StatelessWidget {
  final String zeonId;
  final String name;
  final double size;

  const ZeonAvatar({
    super.key,
    required this.zeonId,
    required this.name,
    this.size = 42,
  });

  @override
  Widget build(BuildContext context) {
    final color = Zn.idColor(zeonId);
    final initials = name.isEmpty
        ? '?'
        : name.trim().split(RegExp(r'\s+')).take(2).map((w) => w[0]).join().toUpperCase();
    return Container(
      width: size,
      height: size,
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.14),
        borderRadius: BorderRadius.circular(Zn.radius),
        border: Border.all(color: color.withValues(alpha: 0.55)),
      ),
      alignment: Alignment.center,
      child: Text(initials, style: Zn.mono(size: size * 0.33, color: color, weight: FontWeight.w700)),
    );
  }
}

void showZnSnack(BuildContext context, String message, {bool error = false}) {
  ScaffoldMessenger.of(context).showSnackBar(
    SnackBar(
      content: Text(message,
          style: TextStyle(color: error ? Zn.danger : Zn.text)),
    ),
  );
}
