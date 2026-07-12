import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:image_picker/image_picker.dart';
import 'package:provider/provider.dart';
import 'package:qr_flutter/qr_flutter.dart';

import '../state/app_state.dart';
import '../state/chat_state.dart';
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
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(28),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              _AvatarEditor(app: app),
              const SizedBox(height: 10),
              Text(app.displayName ?? '',
                  style: const TextStyle(
                      color: Zn.text, fontSize: 18, fontWeight: FontWeight.w600)),
              const SizedBox(height: 20),
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
              const SizedBox(height: 18),
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
                'nothing else. It contains no phone number, email, or name. '
                'Your photo is end-to-end encrypted and shared only with '
                'your contacts.',
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

/// Own profile photo with a tap-to-edit affordance. The photo never touches
/// the hub or any mailbox in the clear: it fans out to accepted contacts
/// over the normal encrypted sessions (PROTOCOL.md "Profiles").
class _AvatarEditor extends StatelessWidget {
  final AppState app;
  const _AvatarEditor({required this.app});

  @override
  Widget build(BuildContext context) {
    return InkWell(
      borderRadius: BorderRadius.circular(Zn.radius),
      onTap: () => _showOptions(context),
      child: Stack(
        clipBehavior: Clip.none,
        children: [
          ZeonAvatar(
            zeonId: app.zeonId ?? '',
            name: app.displayName ?? '',
            size: 96,
            image: app.avatar,
          ),
          Positioned(
            right: -4,
            bottom: -4,
            child: Container(
              padding: const EdgeInsets.all(5),
              decoration: BoxDecoration(
                color: Zn.surface,
                borderRadius: BorderRadius.circular(Zn.radius),
                border: Border.all(color: Zn.line),
              ),
              child: const Icon(Icons.photo_camera_outlined,
                  size: 15, color: Zn.ion),
            ),
          ),
        ],
      ),
    );
  }

  Future<void> _showOptions(BuildContext context) async {
    final chat = context.read<ChatState>();
    await showModalBottomSheet<void>(
      context: context,
      backgroundColor: Zn.surface,
      builder: (sheetContext) => SafeArea(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            ListTile(
              leading: const Icon(Icons.photo_library_outlined,
                  color: Zn.ion, size: 20),
              title: Text(app.avatar == null ? 'Choose photo' : 'Change photo'),
              subtitle: const Text('Only your contacts ever see it',
                  style: TextStyle(color: Zn.muted, fontSize: 12)),
              onTap: () {
                Navigator.pop(sheetContext);
                _pick(context, chat);
              },
            ),
            if (app.avatar != null)
              ListTile(
                leading: const Icon(Icons.delete_outline,
                    color: Zn.danger, size: 20),
                title:
                    const Text('Remove photo', style: TextStyle(color: Zn.danger)),
                onTap: () {
                  Navigator.pop(sheetContext);
                  chat.updateMyAvatar(null);
                },
              ),
          ],
        ),
      ),
    );
  }

  Future<void> _pick(BuildContext context, ChatState chat) async {
    // The picker downscales and re-encodes to JPEG, which keeps the result
    // well under the envelope budget (ChatState.maxAvatarBytes) — the size
    // check is a backstop for pathological images.
    final picked = await ImagePicker().pickImage(
      source: ImageSource.gallery,
      maxWidth: 256,
      maxHeight: 256,
      imageQuality: 70,
    );
    if (picked == null) return;
    final bytes = await picked.readAsBytes();
    if (bytes.length > ChatState.maxAvatarBytes) {
      if (context.mounted) {
        showZnSnack(context, "That image didn't compress small enough — try another",
            error: true);
      }
      return;
    }
    await chat.updateMyAvatar(bytes);
    if (context.mounted) {
      showZnSnack(context, 'Photo updated — your contacts will see it');
    }
  }
}
