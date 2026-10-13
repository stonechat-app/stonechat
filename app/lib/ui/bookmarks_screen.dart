/// Bookmarked messages: first the chats that hold any, then one chat's
/// bookmarks, each opening the chat at that message. Bookmarks are a local
/// mark — they never leave this device.
library;

import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:intl/intl.dart';
import 'package:provider/provider.dart';

import '../models.dart';
import '../state/chat_state.dart';
import 'chat_screen.dart';
import 'theme.dart';
import 'widgets.dart';

/// Every chat with at least one bookmark, the most recently bookmarked first.
class BookmarksScreen extends StatefulWidget {
  const BookmarksScreen({super.key});

  @override
  State<BookmarksScreen> createState() => _BookmarksScreenState();
}

class _BookmarksScreenState extends State<BookmarksScreen> {
  List<Message>? _bookmarks;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    final all = await context.read<ChatState>().bookmarkedMessages();
    if (mounted) setState(() => _bookmarks = all);
  }

  @override
  Widget build(BuildContext context) {
    final chat = context.watch<ChatState>();
    final bookmarks = _bookmarks;
    // Newest-first already, so a chat's first appearance is its latest one.
    final byChat = <String, List<Message>>{};
    for (final m in bookmarks ?? const <Message>[]) {
      if (chat.conversationLabel(m.contactId) == null) continue;
      (byChat[m.contactId] ??= []).add(m);
    }

    return Scaffold(
      appBar: AppBar(title: const Text('My bookmarked messages')),
      body: bookmarks == null
          ? const SizedBox.shrink()
          : byChat.isEmpty
          ? const _Empty(
              'No bookmarks yet.\nLong-press a message in any chat and '
              'choose Bookmark to keep it here.',
            )
          : ListView(
              children: [
                for (final MapEntry(key: id, value: messages)
                    in byChat.entries)
                  _chatTile(chat, id, messages),
              ],
            ),
    );
  }

  Widget _chatTile(ChatState chat, String id, List<Message> messages) {
    final label = chat.conversationLabel(id)!;
    return ListTile(
      leading: _ChatAvatar(id: id, label: label),
      title: Text(
        label.name,
        maxLines: 1,
        overflow: TextOverflow.ellipsis,
        style: const TextStyle(fontWeight: FontWeight.w600),
      ),
      subtitle: Text(
        messages.first.preview,
        maxLines: 1,
        overflow: TextOverflow.ellipsis,
        style: const TextStyle(color: Zn.muted, fontSize: 13),
      ),
      trailing: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Text('${messages.length}', style: Zn.mono(size: 11)),
          const SizedBox(width: 4),
          const Icon(Icons.bookmark, size: 14, color: Zn.amber),
        ],
      ),
      onTap: () async {
        await Navigator.push(
          context,
          MaterialPageRoute(
            builder: (_) => ChatBookmarksScreen(conversationId: id),
          ),
        );
        _load(); // bookmarks may have been removed in there
      },
    );
  }
}

/// One chat's bookmarked messages, the most recently bookmarked first.
class ChatBookmarksScreen extends StatefulWidget {
  final String conversationId;
  const ChatBookmarksScreen({super.key, required this.conversationId});

  @override
  State<ChatBookmarksScreen> createState() => _ChatBookmarksScreenState();
}

class _ChatBookmarksScreenState extends State<ChatBookmarksScreen> {
  List<Message>? _bookmarks;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    final all = await context.read<ChatState>().bookmarkedMessages();
    if (!mounted) return;
    setState(
      () => _bookmarks = [
        for (final m in all)
          if (m.contactId == widget.conversationId) m,
      ],
    );
  }

  String _sender(ChatState chat, Message m, String chatName) {
    if (m.outgoing) return 'You';
    final senderId = m.senderId;
    if (senderId == null) return chatName;
    return chat.memberOf(m.contactId, senderId)?.displayName ??
        chat.contactById(senderId)?.displayName ??
        'Unknown member';
  }

  Future<void> _open(ChatState chat, Message m) async {
    final id = widget.conversationId;
    final group = chat.groupById(id);
    final contact = chat.isNotesToSelf(id)
        ? chat.notesToSelf
        : chat.contactById(id);
    final Widget screen;
    if (group != null) {
      screen = ChatScreen.group(group: group, focusMessageId: m.id);
    } else if (contact != null) {
      screen = ChatScreen(contact: contact, focusMessageId: m.id);
    } else {
      return;
    }
    await Navigator.push(context, MaterialPageRoute(builder: (_) => screen));
    _load();
  }

  Future<void> _remove(ChatState chat, Message m) async {
    await chat.toggleBookmark(m);
    if (!mounted) return;
    setState(() => _bookmarks?.removeWhere((b) => b.id == m.id));
    showZnSnack(context, 'Bookmark removed');
  }

  @override
  Widget build(BuildContext context) {
    final chat = context.watch<ChatState>();
    final label = chat.conversationLabel(widget.conversationId);
    final name = label?.name ?? 'Chat';
    final bookmarks = _bookmarks;

    return Scaffold(
      appBar: AppBar(
        titleSpacing: 0,
        title: Row(
          children: [
            if (label != null) ...[
              _ChatAvatar(id: widget.conversationId, label: label, size: 32),
              const SizedBox(width: 10),
            ],
            Expanded(
              child: Text(
                name,
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                style: const TextStyle(fontSize: 16),
              ),
            ),
          ],
        ),
      ),
      body: bookmarks == null
          ? const SizedBox.shrink()
          : bookmarks.isEmpty
          ? const _Empty('No bookmarks left in this chat.')
          : ListView.separated(
              itemCount: bookmarks.length,
              separatorBuilder: (_, _) => const Divider(height: 1),
              itemBuilder: (context, i) {
                final m = bookmarks[i];
                return ListTile(
                  title: Row(
                    children: [
                      Expanded(
                        child: Text(
                          _sender(chat, m, name),
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                          style: const TextStyle(
                            fontWeight: FontWeight.w600,
                            fontSize: 13,
                          ),
                        ),
                      ),
                      Text(
                        DateFormat('dd MMM yyyy, HH:mm').format(
                          DateTime.fromMillisecondsSinceEpoch(m.sentAt),
                        ),
                        style: Zn.mono(size: 9),
                      ),
                    ],
                  ),
                  subtitle: Padding(
                    padding: const EdgeInsets.only(top: 4),
                    child: Text(
                      m.preview,
                      maxLines: 4,
                      overflow: TextOverflow.ellipsis,
                      style: const TextStyle(color: Zn.text, fontSize: 14),
                    ),
                  ),
                  trailing: IconButton(
                    tooltip: 'Remove bookmark',
                    icon: const Icon(
                      Icons.bookmark_remove_outlined,
                      color: Zn.muted,
                      size: 20,
                    ),
                    onPressed: () => _remove(chat, m),
                  ),
                  onTap: () => _open(chat, m),
                );
              },
            ),
    );
  }
}

class _ChatAvatar extends StatelessWidget {
  final String id;
  final ({String name, Uint8List? image, bool notes}) label;
  final double size;
  const _ChatAvatar({required this.id, required this.label, this.size = 42});

  @override
  Widget build(BuildContext context) => label.notes
      ? NotesAvatar(size: size)
      : StonechatAvatar(
          stonechatId: id,
          name: label.name,
          size: size,
          image: label.image,
        );
}

class _Empty extends StatelessWidget {
  final String text;
  const _Empty(this.text);

  @override
  Widget build(BuildContext context) => Center(
    child: Padding(
      padding: const EdgeInsets.all(32),
      child: Text(
        text,
        textAlign: TextAlign.center,
        style: Zn.mono(size: 11, color: Zn.muted),
      ),
    ),
  );
}
