/// Shared Zeon UI pieces: the relay status strip and ID-derived avatars.
library;

import 'dart:typed_data';

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
      ('running', false) => ('◐', 'Connecting to your mailbox…', Zn.amber),
      ('provisioning', _) => ('◌', 'Setting up your mailbox…', Zn.amber),
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

/// Square avatar: the contact's profile photo when we hold one (E2EE-shared,
/// PROTOCOL.md "Profiles"), else initials on a color derived from their ID.
class ZeonAvatar extends StatelessWidget {
  final String zeonId;
  final String name;
  final double size;
  final Uint8List? image; // profile photo bytes, straight from the DB

  const ZeonAvatar({
    super.key,
    required this.zeonId,
    required this.name,
    this.size = 42,
    this.image,
  });

  @override
  Widget build(BuildContext context) {
    final color = Zn.idColor(zeonId);
    final photo = image;
    if (photo != null) {
      return Container(
        width: size,
        height: size,
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(Zn.radius),
          border: Border.all(color: color.withValues(alpha: 0.55)),
        ),
        clipBehavior: Clip.antiAlias,
        child: Image.memory(
          photo,
          fit: BoxFit.cover,
          gaplessPlayback: true, // no flicker when a profile refresh repaints
          errorBuilder: (_, _, _) => _initials(color),
        ),
      );
    }
    return Container(
      width: size,
      height: size,
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.14),
        borderRadius: BorderRadius.circular(Zn.radius),
        border: Border.all(color: color.withValues(alpha: 0.55)),
      ),
      alignment: Alignment.center,
      child: _initials(color),
    );
  }

  Widget _initials(Color color) {
    final initials = name.isEmpty
        ? '?'
        : name.trim().split(RegExp(r'\s+')).take(2).map((w) => w[0]).join().toUpperCase();
    return Center(
      child: Text(initials,
          style: Zn.mono(size: size * 0.33, color: color, weight: FontWeight.w700)),
    );
  }
}

/// A bottom tab in [ZnTabBar]. `dot` marks the tab with a small ion dot —
/// used so pending contact requests are never invisible from another tab.
class ZnTab {
  final String label;
  final bool dot;
  const ZnTab(this.label, {this.dot = false});
}

/// Slim bottom tab bar in the ledger idiom: hairline top border, uppercase
/// mono labels, a 2px ion indicator segment instead of a Material pill.
class ZnTabBar extends StatelessWidget {
  final int index;
  final ValueChanged<int> onChanged;
  final List<ZnTab> tabs;

  const ZnTabBar({
    super.key,
    required this.index,
    required this.onChanged,
    required this.tabs,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      decoration: const BoxDecoration(
        color: Zn.bg,
        border: Border(top: BorderSide(color: Zn.line)),
      ),
      child: SafeArea(
        top: false,
        child: SizedBox(
          height: 52,
          child: Row(
            children: [
              for (var i = 0; i < tabs.length; i++)
                Expanded(
                  child: InkWell(
                    onTap: () => onChanged(i),
                    child: Stack(
                      children: [
                        if (i == index)
                          Align(
                            alignment: Alignment.topCenter,
                            child: Container(
                                width: 56, height: 2, color: Zn.orange),
                          ),
                        Center(
                          child: Row(
                            mainAxisSize: MainAxisSize.min,
                            children: [
                              Text(
                                tabs[i].label.toUpperCase(),
                                style: Zn.mono(
                                    size: 10,
                                    letterSpacing: 2,
                                    weight: FontWeight.w700,
                                    color: i == index ? Zn.orange : Zn.muted),
                              ),
                              if (tabs[i].dot) ...[
                                const SizedBox(width: 6),
                                Container(
                                  width: 6,
                                  height: 6,
                                  decoration: const BoxDecoration(
                                      color: Zn.orange, shape: BoxShape.circle),
                                ),
                              ],
                            ],
                          ),
                        ),
                      ],
                    ),
                  ),
                ),
            ],
          ),
        ),
      ),
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
