/// Everyone this user has blocked — contacts, group members, strangers — and
/// the one place a block on someone who is not a contact can be undone.
library;

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../state/chat_state.dart';
import 'theme.dart';
import 'widgets.dart';

class BlockedScreen extends StatelessWidget {
  const BlockedScreen({super.key});

  /// Best name we know: a contact's, else what a shared group calls them,
  /// else a slice of the ID — a blocked stranger may be nothing more.
  static String nameFor(ChatState chat, String stonechatId) {
    final contact = chat.contactById(stonechatId);
    if (contact != null) return contact.displayName;
    for (final members in chat.groupMembers.values) {
      for (final m in members) {
        if (m.stonechatId == stonechatId) return m.displayName;
      }
    }
    return stonechatId.length > 12 ? stonechatId.substring(0, 12) : stonechatId;
  }

  @override
  Widget build(BuildContext context) {
    final chat = context.watch<ChatState>();
    final ids = chat.blocked.keys.toList()
      ..sort((a, b) => chat.blocked[b]!.compareTo(chat.blocked[a]!));

    return Scaffold(
      appBar: AppBar(title: const Text('Blocked people')),
      body: ids.isEmpty
          ? Center(
              child: Padding(
                padding: const EdgeInsets.all(32),
                child: Text(
                  'Nobody is blocked.\nBlock someone from a chat, or by '
                  'long-pressing them in a group.',
                  textAlign: TextAlign.center,
                  style: Zn.mono(size: 11, color: Zn.muted),
                ),
              ),
            )
          : ListView(
              children: [
                Padding(
                  padding: const EdgeInsets.fromLTRB(16, 16, 16, 8),
                  child: Text(
                    "Blocked people can't message or call you, and their group "
                    'messages show collapsed. They are not told. This list '
                    'stays on your devices.',
                    style: const TextStyle(color: Zn.muted, fontSize: 12),
                  ),
                ),
                for (final id in ids)
                  ListTile(
                    leading: StonechatAvatar(
                      stonechatId: id,
                      name: nameFor(chat, id),
                      size: 38,
                      image: chat.contactById(id)?.avatar,
                    ),
                    title: Text(nameFor(chat, id)),
                    subtitle: Text(id, style: Zn.mono(size: 9, color: Zn.muted)),
                    trailing: TextButton(
                      onPressed: () async {
                        await chat.setBlocked(id, false);
                        if (context.mounted) {
                          showZnSnack(context, '${nameFor(chat, id)} unblocked');
                        }
                      },
                      child: const Text('Unblock'),
                    ),
                  ),
              ],
            ),
    );
  }
}
