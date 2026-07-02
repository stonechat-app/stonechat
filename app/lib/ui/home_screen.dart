import 'package:flutter/material.dart';
import 'package:intl/intl.dart';
import 'package:provider/provider.dart';

import '../models.dart';
import '../state/chat_state.dart';
import 'chat_screen.dart';
import 'theme.dart';
import 'widgets.dart';

class HomeScreen extends StatelessWidget {
  const HomeScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final chat = context.watch<ChatState>();
    final requests = chat.incomingRequests;
    final conversations = chat.acceptedContacts;

    return Scaffold(
      appBar: AppBar(
        title: Text('ZEON',
            style: Zn.mono(
                size: 20, color: Zn.ion, weight: FontWeight.w700, letterSpacing: 6)),
        actions: [
          IconButton(
            icon: const Icon(Icons.qr_code_2, color: Zn.muted),
            tooltip: 'My ID',
            onPressed: () => Navigator.pushNamed(context, '/my-id'),
          ),
          IconButton(
            icon: const Icon(Icons.dns_outlined, color: Zn.muted),
            tooltip: 'Relay',
            onPressed: () => Navigator.pushNamed(context, '/server'),
          ),
        ],
      ),
      body: Column(
        children: [
          const RelayStrip(),
          Expanded(
            child: (requests.isEmpty && conversations.isEmpty)
                ? const _EmptyState()
                : ListView(
                    children: [
                      if (requests.isNotEmpty) ...[
                        _SectionLabel('REQUESTS · ${requests.length}'),
                        ...requests.map((c) => _RequestTile(contact: c)),
                      ],
                      if (conversations.isNotEmpty) ...[
                        const _SectionLabel('CONVERSATIONS'),
                        ...conversations.map((c) => _ConversationTile(contact: c)),
                      ],
                    ],
                  ),
          ),
        ],
      ),
      floatingActionButton: FloatingActionButton(
        backgroundColor: Zn.ion,
        foregroundColor: const Color(0xFF15200A),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(Zn.radius)),
        onPressed: () => Navigator.pushNamed(context, '/add-contact'),
        child: const Icon(Icons.person_add_alt),
      ),
    );
  }
}

class _SectionLabel extends StatelessWidget {
  final String text;
  const _SectionLabel(this.text);

  @override
  Widget build(BuildContext context) => Padding(
        padding: const EdgeInsets.fromLTRB(16, 18, 16, 8),
        child: Text(text, style: Zn.mono(size: 10, letterSpacing: 2)),
      );
}

class _RequestTile extends StatelessWidget {
  final Contact contact;
  const _RequestTile({required this.contact});

  @override
  Widget build(BuildContext context) {
    final chat = context.read<ChatState>();
    return ListTile(
      leading: ZeonAvatar(zeonId: contact.zeonId, name: contact.displayName),
      title: Text(contact.displayName,
          style: const TextStyle(fontWeight: FontWeight.w600)),
      subtitle: Text('wants to connect', style: Zn.mono(size: 11)),
      trailing: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          IconButton(
            icon: const Icon(Icons.close, color: Zn.danger, size: 20),
            onPressed: () => chat.declineContact(contact),
          ),
          IconButton(
            icon: const Icon(Icons.check, color: Zn.ok, size: 20),
            onPressed: () async {
              try {
                await chat.acceptContact(contact);
              } catch (e) {
                if (context.mounted) {
                  showZnSnack(context, 'Accepted — will notify them when reachable');
                }
              }
            },
          ),
        ],
      ),
    );
  }
}

class _ConversationTile extends StatelessWidget {
  final Contact contact;
  const _ConversationTile({required this.contact});

  @override
  Widget build(BuildContext context) {
    final chat = context.watch<ChatState>();
    final last = chat.lastMessage[contact.zeonId];

    return ListTile(
      leading: ZeonAvatar(zeonId: contact.zeonId, name: contact.displayName),
      title: Text(contact.displayName,
          style: const TextStyle(fontWeight: FontWeight.w600)),
      subtitle: last == null
          ? Text('say hello', style: Zn.mono(size: 11))
          : Text(
              '${last.outgoing ? '› ' : ''}${last.text}',
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: const TextStyle(color: Zn.muted, fontSize: 13),
            ),
      trailing: last == null
          ? null
          : Text(_when(last.sentAt), style: Zn.mono(size: 10)),
      onTap: () => Navigator.push(
        context,
        MaterialPageRoute(builder: (_) => ChatScreen(contact: contact)),
      ),
    );
  }

  String _when(int ms) {
    final t = DateTime.fromMillisecondsSinceEpoch(ms);
    final now = DateTime.now();
    if (t.year == now.year && t.month == now.month && t.day == now.day) {
      return DateFormat('HH:mm').format(t);
    }
    return DateFormat('dd MMM').format(t);
  }
}

class _EmptyState extends StatelessWidget {
  const _EmptyState();

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Text('◇', style: Zn.mono(size: 40, color: Zn.line)),
          const SizedBox(height: 16),
          const Text('No conversations yet',
              style: TextStyle(color: Zn.muted)),
          const SizedBox(height: 6),
          Text('share your ID or add a contact',
              style: Zn.mono(size: 11)),
        ],
      ),
    );
  }
}
