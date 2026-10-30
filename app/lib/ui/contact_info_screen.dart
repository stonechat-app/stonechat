/// A contact's identity, and whether the user has verified it.
///
/// Verifying is comparing codes in person (PROTOCOL.md "Verification"): the
/// Stonechat ID commits to the identity key, so confirming the ID is theirs
/// confirms the key. Scan their code, or read the two IDs side by side. The
/// result is this user's own trust: stored, mirrored to their other devices,
/// never sent to the contact.
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:intl/intl.dart';
import 'package:provider/provider.dart';

import '../core/links.dart';
import '../models.dart';
import '../state/chat_state.dart';
import 'theme.dart';
import 'widgets.dart';

class ContactInfoScreen extends StatelessWidget {
  final Contact contact;
  const ContactInfoScreen({super.key, required this.contact});

  @override
  Widget build(BuildContext context) {
    final chat = context.watch<ChatState>();
    // The live row: verification flips underneath this screen.
    final c = chat.contactById(contact.stonechatId) ?? contact;

    return Scaffold(
      appBar: AppBar(title: const Text('Contact info')),
      body: ListView(
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 20, 16, 8),
            child: Row(
              children: [
                StonechatAvatar(
                    stonechatId: c.stonechatId,
                    name: c.displayName,
                    size: 54,
                    image: c.avatar),
                const SizedBox(width: 14),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Row(
                        children: [
                          Flexible(
                            child: Text(c.displayName,
                                maxLines: 1,
                                overflow: TextOverflow.ellipsis,
                                style: const TextStyle(
                                    fontSize: 18, fontWeight: FontWeight.w600)),
                          ),
                          if (c.isVerified)
                            const Padding(
                              padding: EdgeInsets.only(left: 6),
                              child: Icon(Icons.verified_user,
                                  size: 16, color: Zn.ok),
                            ),
                        ],
                      ),
                      const SizedBox(height: 3),
                      Text(c.stonechatId.substring(0, 12),
                          style: Zn.mono(size: 10, letterSpacing: 1)),
                    ],
                  ),
                ),
              ],
            ),
          ),
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 18, 16, 4),
            child: Text('STONECHAT ID', style: Zn.mono(size: 10, letterSpacing: 2)),
          ),
          ListTile(
            title: SelectableText(c.stonechatId,
                style: Zn.mono(size: 12, color: Zn.text)),
            trailing: IconButton(
              icon: const Icon(Icons.copy, size: 18, color: Zn.muted),
              tooltip: 'Copy',
              onPressed: () {
                Clipboard.setData(ClipboardData(text: c.stonechatId));
                showZnSnack(context, 'Copied');
              },
            ),
          ),
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 18, 16, 4),
            child: Text('VERIFICATION', style: Zn.mono(size: 10, letterSpacing: 2)),
          ),
          if (c.isVerified) ...[
            ListTile(
              leading: const Icon(Icons.verified_user, color: Zn.ok),
              title: const Text('Verified in person'),
              subtitle: Text(
                  'You compared codes on '
                  '${DateFormat.yMMMd().format(DateTime.fromMillisecondsSinceEpoch(c.verifiedAt!))}. '
                  'Their ID is their key, so this can only be undone by a device '
                  'joining their set — you will be told in the chat if that happens.',
                  style: const TextStyle(color: Zn.muted, fontSize: 12)),
            ),
            TextButton(
              onPressed: () => chat.setVerified(c, false),
              child: const Text('Remove verification',
                  style: TextStyle(color: Zn.danger)),
            ),
          ] else ...[
            const ListTile(
              leading: Icon(Icons.shield_outlined, color: Zn.muted),
              title: Text('Not verified'),
              subtitle: Text(
                  'Messages are end-to-end encrypted either way. Verifying confirms '
                  'that this ID really is this person: scan their code from their '
                  'phone, or read the two IDs to each other.',
                  style: TextStyle(color: Zn.muted, fontSize: 12)),
            ),
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 4, 16, 8),
              child: Row(
                children: [
                  Expanded(
                    child: FilledButton.icon(
                      onPressed: () => _scan(context, chat, c),
                      icon: const Icon(Icons.qr_code_scanner, size: 18),
                      label: const Text('Scan their code'),
                    ),
                  ),
                  const SizedBox(width: 10),
                  Expanded(
                    child: OutlinedButton(
                      onPressed: () => _compare(context, chat, c),
                      child: const Text('Compare codes'),
                    ),
                  ),
                ],
              ),
            ),
          ],
        ],
      ),
    );
  }

  /// Their QR, from their phone: the same code a contact request scans.
  Future<void> _scan(BuildContext context, ChatState chat, Contact c) async {
    final scanned = await Navigator.push<String>(
      context,
      MaterialPageRoute(builder: (_) => const _ScanScreen()),
    );
    if (scanned == null || !context.mounted) return;
    final invite = stonechatInviteFromInput(scanned);
    if (invite?.stonechatId == c.stonechatId) {
      await chat.setVerified(c, true);
      if (context.mounted) showZnSnack(context, '${c.displayName} is verified');
    } else {
      showZnSnack(context, "That's not ${c.displayName}'s code", error: true);
    }
  }

  /// Both IDs on one screen, to read aloud or hold side by side.
  Future<void> _compare(BuildContext context, ChatState chat, Contact c) async {
    final mine = chat.app.stonechatId ?? '';
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        backgroundColor: Zn.surface,
        title: const Text('Compare codes'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('THEIRS — ${c.displayName.toUpperCase()}',
                style: Zn.mono(size: 10, letterSpacing: 2)),
            const SizedBox(height: 4),
            Text(c.stonechatId, style: Zn.mono(size: 12, color: Zn.text)),
            const SizedBox(height: 14),
            Text('YOURS', style: Zn.mono(size: 10, letterSpacing: 2)),
            const SizedBox(height: 4),
            Text(mine, style: Zn.mono(size: 12, color: Zn.text)),
            const SizedBox(height: 14),
            const Text(
                'Have them open their own Contact info for you and check both '
                'codes match what you each see.',
                style: TextStyle(color: Zn.muted, fontSize: 12)),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(dialogContext, false),
            child: const Text('Not now'),
          ),
          TextButton(
            onPressed: () => Navigator.pop(dialogContext, true),
            child: const Text('They match'),
          ),
        ],
      ),
    );
    if (confirmed == true && context.mounted) {
      await chat.setVerified(c, true);
      if (context.mounted) showZnSnack(context, '${c.displayName} is verified');
    }
  }
}

class _ScanScreen extends StatefulWidget {
  const _ScanScreen();

  @override
  State<_ScanScreen> createState() => _ScanScreenState();
}

class _ScanScreenState extends State<_ScanScreen> {
  bool _handled = false;

  @override
  Widget build(BuildContext context) => Scaffold(
        appBar: AppBar(title: const Text('Scan their code')),
        body: Stack(
          children: [
            QrScanView(
              onCode: (raw) {
                if (_handled) return;
                if (stonechatInviteFromInput(raw) == null) return;
                _handled = true;
                Navigator.pop(context, raw);
              },
            ),
            const Positioned(
              bottom: 32,
              left: 0,
              right: 0,
              child: Center(
                child: Text('Point at the code on their phone',
                    style: TextStyle(fontSize: 13, color: Zn.text)),
              ),
            ),
          ],
        ),
      );
}
