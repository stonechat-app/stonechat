/// Shared Stonechat UI pieces: the relay status strip and ID-derived avatars.
library;

import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../state/mailbox_state.dart';
import 'theme.dart';

/// The signature element: a thin status line that always tells you whether
/// you can receive messages. Tapping it opens the mailbox screen.
class RelayStrip extends StatelessWidget {
  const RelayStrip({super.key});

  @override
  Widget build(BuildContext context) {
    final mailbox = context.watch<MailboxState>();

    // A confirmed outage outranks "connecting…": we've already checked with
    // the hub that the network is fine and the mailbox simply isn't there.
    final down = mailbox.mailboxDownFor;

    final (dot, label, color) = switch ((mailbox.record.status, mailbox.socketConnected)) {
      ('running', true) => ('●', "You're reachable", Zn.ok),
      ('running', false) when down != null => (
          '✕',
          "Your mailbox isn't answering · ${formatOutage(down)} — tap to check",
          Zn.danger
        ),
      ('running', false) => ('◐', 'Connecting to your mailbox…', Zn.amber),
      ('provisioning', _) => ('◌', 'Setting up your mailbox…', Zn.amber),
      ('error', _) => ('✕', "Mailbox setup didn't work — tap to see why", Zn.danger),
      _ => ('○', 'No mailbox yet — tap to set up', Zn.muted),
    };

    return InkWell(
      onTap: () => Navigator.pushNamed(context, '/mailbox'),
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
class StonechatAvatar extends StatelessWidget {
  final String stonechatId;
  final String name;
  final double size;
  final Uint8List? image; // profile photo bytes, straight from the DB

  const StonechatAvatar({
    super.key,
    required this.stonechatId,
    required this.name,
    this.size = 42,
    this.image,
  });

  @override
  Widget build(BuildContext context) {
    final color = Zn.idColor(stonechatId);
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

/// A selectable "where does your mailbox live" card: radio-style marker,
/// title + subtitle, and an expandable body shown while selected. Used by
/// the mailbox screen and onboarding so the two stay visually identical.
class ZnOptionCard extends StatelessWidget {
  final String title;
  final String subtitle;
  final bool selected;
  final bool active;
  final bool dimmed;
  final VoidCallback? onTap;
  final List<Widget> children;

  const ZnOptionCard({
    super.key,
    required this.title,
    required this.subtitle,
    required this.selected,
    this.active = false,
    this.dimmed = false,
    required this.onTap,
    required this.children,
  });

  @override
  Widget build(BuildContext context) {
    final Widget marker = active
        ? const Icon(Icons.check_circle, color: Zn.ok, size: 18)
        : Container(
            width: 16,
            height: 16,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              border: Border.all(
                  color: selected ? Zn.orange : Zn.line, width: 1.5),
            ),
            child: selected
                ? Center(
                    child: Container(
                      width: 8,
                      height: 8,
                      decoration: const BoxDecoration(
                          color: Zn.orange, shape: BoxShape.circle),
                    ),
                  )
                : null,
          );

    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(Zn.radius),
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 150),
        padding: const EdgeInsets.all(16),
        decoration: BoxDecoration(
          color: active
              ? Zn.ok.withValues(alpha: 0.05)
              : selected
                  ? Zn.orange.withValues(alpha: 0.06)
                  : Zn.surface,
          borderRadius: BorderRadius.circular(Zn.radius),
          border: Border.all(
              color: active
                  ? Zn.ok
                  : selected
                      ? Zn.orange
                      : Zn.line),
        ),
        child: Opacity(
          opacity: dimmed ? 0.45 : 1,
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Padding(
                    padding: const EdgeInsets.only(top: 2),
                    child: marker,
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(title,
                            style: TextStyle(
                                fontSize: 15,
                                fontWeight: FontWeight.w600,
                                color: selected || active
                                    ? Zn.text
                                    : Zn.muted)),
                        const SizedBox(height: 3),
                        Text(subtitle,
                            style: const TextStyle(
                                color: Zn.muted, fontSize: 12.5, height: 1.4)),
                      ],
                    ),
                  ),
                ],
              ),
              if (selected && children.isNotEmpty) ...[
                const SizedBox(height: 16),
                ...children,
              ],
            ],
          ),
        ),
      ),
    );
  }
}

class ZnLabeledField extends StatelessWidget {
  final String label;
  final TextEditingController controller;

  const ZnLabeledField({super.key, required this.label, required this.controller});

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(label, style: const TextStyle(color: Zn.muted, fontSize: 12)),
        const SizedBox(height: 6),
        TextField(
          controller: controller,
          style: Zn.mono(size: 13, color: Zn.text),
        ),
      ],
    );
  }
}
