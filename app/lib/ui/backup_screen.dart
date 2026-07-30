/// Chat backup: create an encrypted, text-only export of the local history
/// and hand it to the OS share sheet — or restore such a file into this
/// account. The heavy lifting (format, crypto, merge) lives in core/backup.dart.
library;

import 'dart:io';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:share_plus/share_plus.dart';

import '../core/backup.dart';
import '../state/app_state.dart';
import '../state/chat_state.dart';
import 'theme.dart';
import 'widgets.dart';

class BackupScreen extends StatefulWidget {
  const BackupScreen({super.key});

  @override
  State<BackupScreen> createState() => _BackupScreenState();
}

class _BackupScreenState extends State<BackupScreen> {
  bool _busy = false;
  String _busyLabel = '';

  BackupService get _service {
    final app = context.read<AppState>();
    return BackupService(app.db);
  }

  @override
  void initState() {
    super.initState();
    // Sweep exports orphaned by a crash or an abandoned share sheet.
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (mounted) _service.cleanupTempBackups();
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Chat backup')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: Zn.surface,
              borderRadius: BorderRadius.circular(Zn.radius),
              border: Border.all(color: Zn.line),
            ),
            child: const Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('Included: your text messages, contacts and groups, '
                    'as one encrypted file.',
                    style: TextStyle(
                        color: Zn.text, fontSize: 13, height: 1.45)),
                SizedBox(height: 8),
                Text('Not included: photos, videos, voice notes and files — '
                    'and never your identity keys.',
                    style: TextStyle(
                        color: Zn.muted, fontSize: 12.5, height: 1.45)),
                SizedBox(height: 8),
                Text('The file only opens with the passphrase you choose. '
                    'A forgotten passphrase cannot be recovered — by anyone.',
                    style: TextStyle(
                        color: Zn.muted, fontSize: 12.5, height: 1.45)),
              ],
            ),
          ),
          const SizedBox(height: 24),
          SizedBox(
            width: double.infinity,
            height: 46,
            child: FilledButton(
              onPressed: _busy ? null : _create,
              child: _busy
                  ? const SizedBox(
                      width: 16,
                      height: 16,
                      child: CircularProgressIndicator(strokeWidth: 2))
                  : const Text('Create backup'),
            ),
          ),
          const SizedBox(height: 12),
          SizedBox(
            width: double.infinity,
            height: 46,
            child: OutlinedButton(
              onPressed: _busy ? null : _restore,
              child: const Text('Restore from backup'),
            ),
          ),
          if (_busy) ...[
            const SizedBox(height: 12),
            Center(
              child: Text(_busyLabel, style: Zn.mono(size: 11, color: Zn.muted)),
            ),
          ],
          const SizedBox(height: 12),
          const Text(
              'Restoring merges a backup into this account: existing chats '
              'are kept, and messages you already have are not duplicated.',
              style: TextStyle(color: Zn.muted, fontSize: 12, height: 1.45)),
        ],
      ),
    );
  }

  Future<void> _create() async {
    final passphrase = await _askPassphrase(create: true);
    if (passphrase == null || !mounted) return;
    setState(() {
      _busy = true;
      _busyLabel = 'Encrypting…';
    });
    File? file;
    try {
      final service = _service;
      file = await service.createBackup(passphrase);
      if (!mounted) return;
      // iPad's share popover needs an anchor rect.
      final box = context.findRenderObject() as RenderBox?;
      await SharePlus.instance.share(ShareParams(
        files: [XFile(file.path, mimeType: 'application/octet-stream')],
        subject: 'Stonechat backup',
        sharePositionOrigin:
            box == null ? null : box.localToGlobal(Offset.zero) & box.size,
      ));
    } on BackupException catch (e) {
      if (mounted) showZnSnack(context, e.message, error: true);
    } catch (_) {
      if (mounted) showZnSnack(context, 'Backup failed.', error: true);
    } finally {
      // The share target got its copy (or the user bailed) — the plaintext-
      // named ciphertext has no business staying in the temp dir.
      try {
        await file?.delete();
      } catch (_) {}
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _restore() async {
    // FileType.any: iOS can't filter on an unregistered extension, and the
    // magic-bytes check rejects anything that isn't a backup.
    final picked = await FilePicker.pickFiles();
    final path = picked?.files.single.path;
    if (path == null || !mounted) return;

    final passphrase = await _askPassphrase(create: false);
    if (passphrase == null || !mounted) return;

    final confirmed = await showDialog<bool>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        backgroundColor: Zn.surface,
        title: const Text('Restore into this account?'),
        content: const Text(
            'Existing chats are kept; messages, contacts and groups from the '
            'backup merge in.'),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(dialogContext, false),
            child: const Text('Cancel'),
          ),
          TextButton(
            onPressed: () => Navigator.pop(dialogContext, true),
            child: const Text('Restore'),
          ),
        ],
      ),
    );
    if (confirmed != true || !mounted) return;

    setState(() {
      _busy = true;
      _busyLabel = 'Decrypting…';
    });
    try {
      final summary = await _service.restoreBackup(File(path), passphrase);
      if (!mounted) return;
      await context.read<ChatState>().reloadAfterRestore();
      if (!mounted) return;
      final skipped = summary.messagesSkipped;
      showZnSnack(
          context,
          'Restored ${summary.messagesAdded} messages and '
          '${summary.contactsAdded} contacts'
          '${skipped > 0 ? ' ($skipped already present or expired)' : ''}.');
    } on BackupException catch (e) {
      if (mounted) showZnSnack(context, e.message, error: true);
    } catch (_) {
      if (mounted) showZnSnack(context, 'Restore failed.', error: true);
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<String?> _askPassphrase({required bool create}) {
    final pass = TextEditingController();
    final repeat = TextEditingController();
    String? error;
    return showDialog<String>(
      context: context,
      builder: (dialogContext) => StatefulBuilder(
        builder: (dialogContext, setState) {
          void submit() {
            if (create &&
                pass.text.length < BackupService.minPassphraseChars) {
              setState(() => error =
                  'Use at least ${BackupService.minPassphraseChars} characters.');
              return;
            }
            if (create && repeat.text != pass.text) {
              setState(() => error = 'Passphrases do not match.');
              return;
            }
            if (pass.text.isEmpty) return;
            Navigator.pop(dialogContext, pass.text);
          }

          return AlertDialog(
            backgroundColor: Zn.surface,
            title: Text(create ? 'Backup passphrase' : 'Enter passphrase'),
            content: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                if (create)
                  const Padding(
                    padding: EdgeInsets.only(bottom: 12),
                    child: Text(
                        'Anyone with the file and this passphrase can read '
                        'your messages. There is no recovery.',
                        style: TextStyle(
                            color: Zn.muted, fontSize: 12, height: 1.4)),
                  ),
                _ObscuredField(
                  label: 'Passphrase',
                  controller: pass,
                  autofocus: true,
                  onSubmitted: create ? null : submit,
                ),
                if (create) ...[
                  const SizedBox(height: 12),
                  _ObscuredField(
                    label: 'Repeat passphrase',
                    controller: repeat,
                    onSubmitted: submit,
                  ),
                ],
                if (error != null)
                  Padding(
                    padding: const EdgeInsets.only(top: 10),
                    child: Text(error!,
                        style:
                            const TextStyle(color: Zn.danger, fontSize: 12)),
                  ),
              ],
            ),
            actions: [
              TextButton(
                onPressed: () => Navigator.pop(dialogContext),
                child: const Text('Cancel'),
              ),
              TextButton(
                onPressed: submit,
                child: Text(create ? 'Create' : 'Restore'),
              ),
            ],
          );
        },
      ),
    );
  }
}

class _ObscuredField extends StatelessWidget {
  final String label;
  final TextEditingController controller;
  final bool autofocus;
  final VoidCallback? onSubmitted;

  const _ObscuredField({
    required this.label,
    required this.controller,
    this.autofocus = false,
    this.onSubmitted,
  });

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(label, style: const TextStyle(color: Zn.muted, fontSize: 12)),
        const SizedBox(height: 6),
        TextField(
          controller: controller,
          autofocus: autofocus,
          obscureText: true,
          autocorrect: false,
          enableSuggestions: false,
          style: Zn.mono(size: 13, color: Zn.text),
          onSubmitted: onSubmitted == null ? null : (_) => onSubmitted!(),
        ),
      ],
    );
  }
}
