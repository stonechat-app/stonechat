import 'package:flutter/material.dart';
import 'package:intl/intl.dart';
import 'package:provider/provider.dart';

import '../models.dart';
import '../state/chat_state.dart';
import '../state/server_state.dart';
import 'chat_screen.dart';
import 'theme.dart';
import 'widgets.dart';

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  int _tab = 0; // 0 = direct chats, 1 = groups

  @override
  Widget build(BuildContext context) {
    final chat = context.watch<ChatState>();
    final requests = chat.incomingRequests;
    final sent = chat.outgoingRequests;

    // Pinned first (most recently pinned on top), then most recent activity.
    int activity(String id, int fallback) =>
        chat.lastMessage[id]?.sentAt ?? fallback;
    int compare(int? pinA, int? pinB, int activityA, int activityB) {
      if ((pinA != null) != (pinB != null)) return pinA != null ? -1 : 1;
      if (pinA != null && pinB != null && pinA != pinB) {
        return pinB.compareTo(pinA);
      }
      return activityB.compareTo(activityA);
    }

    final contacts = [...chat.acceptedContacts]..sort((a, b) => compare(
        a.pinnedAt,
        b.pinnedAt,
        activity(a.zeonId, a.createdAt),
        activity(b.zeonId, b.createdAt)));
    final groups = [...chat.groups]..sort((a, b) => compare(a.pinnedAt,
        b.pinnedAt, activity(a.id, a.createdAt), activity(b.id, b.createdAt)));

    final chatsEmpty = requests.isEmpty && sent.isEmpty && contacts.isEmpty;
    final tabEmpty = _tab == 0 ? chatsEmpty : groups.isEmpty;

    return Scaffold(
      appBar: AppBar(
        title: Text('ZEON',
            style: Zn.mono(
                size: 20, color: Zn.ion, weight: FontWeight.w700, letterSpacing: 6)),
        actions: [
          IconButton(
            icon: const Icon(Icons.qr_code_2, color: Zn.muted),
            tooltip: 'My code',
            onPressed: () => Navigator.pushNamed(context, '/my-id'),
          ),
          IconButton(
            icon: const Icon(Icons.markunread_mailbox_outlined, color: Zn.muted),
            tooltip: 'Mailbox',
            onPressed: () => Navigator.pushNamed(context, '/server'),
          ),
          IconButton(
            icon: const Icon(Icons.settings_outlined, color: Zn.muted),
            tooltip: 'Settings',
            onPressed: () => Navigator.pushNamed(context, '/settings'),
          ),
        ],
      ),
      body: Column(
        children: [
          const RelayStrip(),
          Expanded(
            // Pull down = "check for mail now": reconnect the mailbox socket
            // (the relay re-drains its queue to a fresh connection) and
            // retry anything still pending in our outbox.
            child: RefreshIndicator(
              color: Zn.ion,
              onRefresh: () async {
                final server = context.read<ServerState>();
                await server.reconnectMailbox();
                await chat.retryPending();
              },
              child: tabEmpty
                  ? LayoutBuilder(
                      builder: (context, constraints) => ListView(
                        physics: const AlwaysScrollableScrollPhysics(),
                        children: [
                          SizedBox(
                            height: constraints.maxHeight,
                            child: _tab == 0
                                ? const _EmptyState()
                                : const _EmptyState(
                                    title: 'No groups yet',
                                    hint: 'Start one with + · New group',
                                  ),
                          ),
                        ],
                      ),
                    )
                  : ListView(
                      physics: const AlwaysScrollableScrollPhysics(),
                      children: _tab == 0
                          ? [
                              if (requests.isNotEmpty || sent.isNotEmpty) ...[
                                _SectionLabel(
                                    'Requests · ${requests.length + sent.length}'),
                                ...requests
                                    .map((c) => _RequestTile(contact: c)),
                                ...sent
                                    .map((c) => _SentRequestTile(contact: c)),
                              ],
                              if (contacts.isNotEmpty) ...[
                                const _SectionLabel('Chats'),
                                ...contacts.map(
                                    (c) => _ConversationTile(contact: c)),
                              ],
                            ]
                          : [
                              const _SectionLabel('Groups'),
                              ...groups.map((g) => _GroupTile(group: g)),
                            ],
                    ),
            ),
          ),
        ],
      ),
      bottomNavigationBar: ZnTabBar(
        index: _tab,
        onChanged: (i) => setState(() => _tab = i),
        tabs: [
          // The dot keeps pending handshakes visible from the Groups tab.
          ZnTab('Chats', dot: requests.isNotEmpty),
          const ZnTab('Groups'),
        ],
      ),
      floatingActionButton: FloatingActionButton(
        backgroundColor: Zn.ion,
        foregroundColor: const Color(0xFF15200A),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(Zn.radius)),
        onPressed: () => _showNewMenu(context),
        child: const Icon(Icons.add),
      ),
    );
  }

  void _showNewMenu(BuildContext context) {
    showModalBottomSheet<void>(
      context: context,
      backgroundColor: Zn.surface,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(8)),
      ),
      builder: (sheetContext) => SafeArea(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            ListTile(
              leading: const Icon(Icons.person_add_alt, color: Zn.ion),
              title: const Text('Add a friend'),
              onTap: () {
                Navigator.pop(sheetContext);
                Navigator.pushNamed(context, '/add-contact');
              },
            ),
            ListTile(
              leading: const Icon(Icons.group_add_outlined, color: Zn.cyan),
              title: const Text('New group'),
              onTap: () {
                Navigator.pop(sheetContext);
                Navigator.pushNamed(context, '/create-group');
              },
            ),
          ],
        ),
      ),
    );
  }
}

String _when(int ms) {
  final t = DateTime.fromMillisecondsSinceEpoch(ms);
  final now = DateTime.now();
  if (t.year == now.year && t.month == now.month && t.day == now.day) {
    return DateFormat('HH:mm').format(t);
  }
  return DateFormat('dd MMM').format(t);
}

Widget? _tileTrailing(Message? last, bool pinned) {
  if (last == null && !pinned) return null;
  return Row(
    mainAxisSize: MainAxisSize.min,
    children: [
      if (pinned)
        Padding(
          padding: EdgeInsets.only(right: last == null ? 0 : 6),
          child: const Icon(Icons.push_pin, size: 12, color: Zn.muted),
        ),
      if (last != null) Text(_when(last.sentAt), style: Zn.mono(size: 10)),
    ],
  );
}

/// Long-press menu for a conversation tile. One action today (pin/unpin);
/// mute/archive would slot in here.
void _showConversationSheet(BuildContext context,
    {required bool pinned, required Future<void> Function() onTogglePin}) {
  showModalBottomSheet<void>(
    context: context,
    backgroundColor: Zn.surface,
    shape: const RoundedRectangleBorder(
      borderRadius: BorderRadius.vertical(top: Radius.circular(8)),
    ),
    builder: (sheetContext) => SafeArea(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          ListTile(
            leading: Icon(
                pinned ? Icons.push_pin_outlined : Icons.push_pin,
                color: Zn.muted),
            title: Text(pinned ? 'Unpin' : 'Pin to top'),
            onTap: () {
              Navigator.pop(sheetContext);
              onTogglePin();
            },
          ),
        ],
      ),
    ),
  );
}

class _GroupTile extends StatelessWidget {
  final Group group;
  const _GroupTile({required this.group});

  @override
  Widget build(BuildContext context) {
    final chat = context.watch<ChatState>();
    final last = chat.lastMessage[group.id];
    final memberCount = chat.groupMembers[group.id]?.length ?? 0;

    return ListTile(
      leading: ZeonAvatar(zeonId: group.id, name: '◈', size: 42),
      title: Text(group.name,
          style: const TextStyle(fontWeight: FontWeight.w600)),
      subtitle: last == null
          ? Text('$memberCount members', style: Zn.mono(size: 11))
          : Text(
              '${last.outgoing ? '› ' : ''}${last.preview}',
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: const TextStyle(color: Zn.muted, fontSize: 13),
            ),
      trailing: _tileTrailing(last, group.isPinned),
      onTap: () => Navigator.push(
        context,
        MaterialPageRoute(builder: (_) => ChatScreen.group(group: group)),
      ),
      onLongPress: () => _showConversationSheet(context,
          pinned: group.isPinned,
          onTogglePin: () => chat.togglePinGroup(group)),
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
      subtitle: Text(
          contact.handle == null
              ? 'wants to connect'
              : '${contact.handle} · wants to connect',
          style: const TextStyle(color: Zn.muted, fontSize: 12)),
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

/// A contact request WE sent that the other side hasn't accepted yet.
/// Kept visible so a stuck handshake is never invisible; the arrow re-sends
/// (receivers dedupe by sender) and the cross withdraws it locally.
class _SentRequestTile extends StatelessWidget {
  final Contact contact;
  const _SentRequestTile({required this.contact});

  @override
  Widget build(BuildContext context) {
    final chat = context.read<ChatState>();
    return ListTile(
      leading: ZeonAvatar(zeonId: contact.zeonId, name: contact.displayName),
      title: Text(contact.displayName,
          style: const TextStyle(fontWeight: FontWeight.w600)),
      subtitle: Text(
          contact.handle == null
              ? 'request sent · waiting'
              : '${contact.handle} · request sent · waiting',
          style: const TextStyle(color: Zn.muted, fontSize: 12)),
      trailing: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          IconButton(
            icon: const Icon(Icons.close, color: Zn.danger, size: 20),
            tooltip: 'Withdraw',
            onPressed: () => chat.declineContact(contact),
          ),
          IconButton(
            icon: const Icon(Icons.arrow_upward, color: Zn.ion, size: 20),
            tooltip: 'Send again',
            onPressed: () async {
              try {
                await chat.resendRequest(contact);
                if (context.mounted) {
                  showZnSnack(context, 'Request sent again');
                }
              } catch (e) {
                if (context.mounted) {
                  showZnSnack(context, "Couldn't reach their mailbox: $e",
                      error: true);
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
              '${last.outgoing ? '› ' : ''}${last.preview}',
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: const TextStyle(color: Zn.muted, fontSize: 13),
            ),
      trailing: _tileTrailing(last, contact.isPinned),
      onTap: () => Navigator.push(
        context,
        MaterialPageRoute(builder: (_) => ChatScreen(contact: contact)),
      ),
      onLongPress: () => _showConversationSheet(context,
          pinned: contact.isPinned,
          onTogglePin: () => chat.togglePinContact(contact)),
    );
  }
}

class _EmptyState extends StatelessWidget {
  final String title;
  final String hint;

  const _EmptyState({
    this.title = 'No chats yet',
    this.hint = 'Share your code, or add a friend with theirs',
  });

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Text('◇', style: Zn.mono(size: 40, color: Zn.line)),
          const SizedBox(height: 16),
          Text(title, style: const TextStyle(color: Zn.muted)),
          const SizedBox(height: 6),
          Text(hint, style: const TextStyle(color: Zn.muted, fontSize: 12)),
        ],
      ),
    );
  }
}
