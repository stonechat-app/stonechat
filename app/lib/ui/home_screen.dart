import 'package:flutter/material.dart';
import 'package:intl/intl.dart';
import 'package:provider/provider.dart';

import '../models.dart';
import '../state/chat_state.dart';
import '../state/mailbox_state.dart';
import 'chat_screen.dart';
import 'report_sheet.dart';
import 'theme.dart';
import 'widgets.dart';

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  int _tab = 0; // 0 = direct chats, 1 = groups
  bool _showArchived = false; // the Archived section is collapsed by default

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

    final allContacts = [...chat.acceptedContacts, ?chat.notesToSelf]
      ..sort(
        (a, b) => compare(
          a.pinnedAt,
          b.pinnedAt,
          activity(a.stonechatId, a.createdAt),
          activity(b.stonechatId, b.createdAt),
        ),
      );
    final allGroups = [...chat.groups]
      ..sort(
        (a, b) => compare(
          a.pinnedAt,
          b.pinnedAt,
          activity(a.id, a.createdAt),
          activity(b.id, b.createdAt),
        ),
      );

    // Archived conversations live in their own collapsed section.
    final contacts = allContacts.where((c) => !c.isArchived).toList();
    final archivedContacts = allContacts.where((c) => c.isArchived).toList();
    final groups = allGroups.where((g) => !g.isArchived).toList();
    final archivedGroups = allGroups.where((g) => g.isArchived).toList();

    final chatsEmpty =
        requests.isEmpty &&
        sent.isEmpty &&
        contacts.isEmpty &&
        archivedContacts.isEmpty;
    final tabEmpty = _tab == 0
        ? chatsEmpty
        : groups.isEmpty && archivedGroups.isEmpty;

    return Scaffold(
      appBar: AppBar(
        title: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Image.asset('assets/logo/bird.png', height: 22),
            const SizedBox(width: 8),
            // Three action buttons leave a 360dp phone a pixel short of
            // this at full size: scale rather than clip the last letter.
            Flexible(
              child: FittedBox(
                fit: BoxFit.scaleDown,
                alignment: Alignment.centerLeft,
                child: Text(
                  'STONECHAT',
                  maxLines: 1,
                  style: Zn.mono(
                    size: 20,
                    color: Zn.orange,
                    weight: FontWeight.w700,
                    letterSpacing: 6,
                  ),
                ),
              ),
            ),
          ],
        ),
        // My code and the mailbox live at the top of Settings; the status
        // strip below still opens the mailbox screen on tap.
        actions: [
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
              color: Zn.orange,
              onRefresh: () async {
                final mailbox = context.read<MailboxState>();
                await mailbox.reconnectMailbox();
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
                                  'Requests · ${requests.length + sent.length}',
                                ),
                                ...requests.map(
                                  (c) => _RequestTile(contact: c),
                                ),
                                ...sent.map(
                                  (c) => _SentRequestTile(contact: c),
                                ),
                              ],
                              if (contacts.isNotEmpty) ...[
                                const _SectionLabel('Chats'),
                                ...contacts.map(
                                  (c) => _ConversationTile(contact: c),
                                ),
                              ],
                              if (archivedContacts.isNotEmpty) ...[
                                _archivedHeader(archivedContacts.length),
                                if (_showArchived)
                                  ...archivedContacts.map(
                                    (c) => _ConversationTile(contact: c),
                                  ),
                              ],
                            ]
                          : [
                              if (groups.isNotEmpty) ...[
                                const _SectionLabel('Groups'),
                                ...groups.map((g) => _GroupTile(group: g)),
                              ],
                              if (archivedGroups.isNotEmpty) ...[
                                _archivedHeader(archivedGroups.length),
                                if (_showArchived)
                                  ...archivedGroups.map(
                                    (g) => _GroupTile(group: g),
                                  ),
                              ],
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
        backgroundColor: Zn.orange,
        foregroundColor: Zn.onAccent,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(Zn.radius),
        ),
        onPressed: () => _showNewMenu(context),
        child: const Icon(Icons.add),
      ),
    );
  }

  /// Collapsed "Archived · n" row; tap toggles the section open.
  Widget _archivedHeader(int count) => InkWell(
    onTap: () => setState(() => _showArchived = !_showArchived),
    child: Padding(
      padding: const EdgeInsets.fromLTRB(16, 18, 16, 8),
      child: Row(
        children: [
          const Icon(Icons.archive_outlined, size: 13, color: Zn.muted),
          const SizedBox(width: 8),
          Text('Archived · $count', style: Zn.mono(size: 10, letterSpacing: 2)),
          const Spacer(),
          Icon(
            _showArchived ? Icons.expand_less : Icons.expand_more,
            size: 16,
            color: Zn.muted,
          ),
        ],
      ),
    ),
  );

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
              leading: const Icon(Icons.person_add_alt, color: Zn.orange),
              title: const Text('Add a friend'),
              onTap: () {
                Navigator.pop(sheetContext);
                Navigator.pushNamed(context, '/add-contact');
              },
            ),
            ListTile(
              leading: const Icon(Icons.group_add_outlined, color: Zn.amber),
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

/// A conversation's unsent text, in place of its last message.
Widget _draftLine(String draft) => Text.rich(
  TextSpan(
    children: [
      const TextSpan(
        text: 'Draft: ',
        style: TextStyle(color: Zn.orange, fontWeight: FontWeight.w600),
      ),
      TextSpan(text: draft.replaceAll('\n', ' ')),
    ],
  ),
  maxLines: 1,
  overflow: TextOverflow.ellipsis,
  style: const TextStyle(color: Zn.muted, fontSize: 13),
);

String _when(int ms) {
  final t = DateTime.fromMillisecondsSinceEpoch(ms);
  final now = DateTime.now();
  if (t.year == now.year && t.month == now.month && t.day == now.day) {
    return DateFormat('HH:mm').format(t);
  }
  return DateFormat('dd MMM').format(t);
}

Widget? _tileTrailing(
  Message? last,
  bool pinned, {
  bool muted = false,
  bool blocked = false,
}) {
  if (last == null && !pinned && !muted && !blocked) return null;
  return Row(
    mainAxisSize: MainAxisSize.min,
    children: [
      if (blocked)
        const Padding(
          padding: EdgeInsets.only(right: 6),
          child: Icon(Icons.block, size: 12, color: Zn.danger),
        ),
      if (muted)
        const Padding(
          padding: EdgeInsets.only(right: 6),
          child: Icon(
            Icons.notifications_off_outlined,
            size: 12,
            color: Zn.muted,
          ),
        ),
      if (pinned)
        Padding(
          padding: EdgeInsets.only(right: last == null ? 0 : 6),
          child: const Icon(Icons.push_pin, size: 12, color: Zn.muted),
        ),
      // A conversation whose newest message never went out says so from the
      // list — otherwise the user has to open every chat to find out.
      if (last != null && last.status == MessageStatus.failed)
        const Padding(
          padding: EdgeInsets.only(right: 6),
          child: Icon(Icons.error_outline, size: 12, color: Zn.danger),
        ),
      if (last != null) Text(_when(last.sentAt), style: Zn.mono(size: 10)),
    ],
  );
}

/// Long-press menu for a conversation tile: pin, mute, archive — and for
/// direct chats, block and report. Everything here except report is a
/// local-only setting; report is the one entry that leaves the device, which
/// is why it sits last and behind its own sheet.
void _showConversationSheet(
  BuildContext context, {
  required bool pinned,
  required bool muted,
  required bool archived,
  required Future<void> Function() onTogglePin,
  required Future<void> Function(int? untilMs)? onMute, // null: notes to self
  required Future<void> Function() onToggleArchive,
  bool blocked = false,
  Future<void> Function()? onToggleBlock, // null for groups
  VoidCallback? onReport, // null for groups
}) {
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
              color: Zn.muted,
            ),
            title: Text(pinned ? 'Unpin' : 'Pin to top'),
            onTap: () {
              Navigator.pop(sheetContext);
              onTogglePin();
            },
          ),
          if (onMute != null)
            ListTile(
              leading: Icon(
                muted
                    ? Icons.notifications_active_outlined
                    : Icons.notifications_off_outlined,
                color: Zn.muted,
              ),
              title: Text(muted ? 'Unmute' : 'Mute'),
              onTap: () {
                Navigator.pop(sheetContext);
                if (muted) {
                  onMute(null);
                } else {
                  _showMuteSheet(context, onMute);
                }
              },
            ),
          ListTile(
            leading: Icon(
              archived ? Icons.unarchive_outlined : Icons.archive_outlined,
              color: Zn.muted,
            ),
            title: Text(archived ? 'Unarchive' : 'Archive'),
            onTap: () {
              Navigator.pop(sheetContext);
              onToggleArchive();
            },
          ),
          if (onToggleBlock != null)
            ListTile(
              leading: Icon(Icons.block, color: blocked ? Zn.muted : Zn.danger),
              title: Text(
                blocked ? 'Unblock' : 'Block',
                style: TextStyle(color: blocked ? Zn.text : Zn.danger),
              ),
              onTap: () {
                Navigator.pop(sheetContext);
                onToggleBlock();
              },
            ),
          if (onReport != null)
            ListTile(
              leading: const Icon(Icons.flag_outlined, color: Zn.danger),
              title: const Text('Report', style: TextStyle(color: Zn.danger)),
              onTap: () {
                Navigator.pop(sheetContext);
                onReport();
              },
            ),
        ],
      ),
    ),
  );
}

void _showMuteSheet(
  BuildContext context,
  Future<void> Function(int? untilMs) onMute,
) {
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
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 14, 16, 6),
            child: Align(
              alignment: Alignment.centerLeft,
              child: Text(
                'MUTE FOR',
                style: Zn.mono(size: 10, letterSpacing: 2),
              ),
            ),
          ),
          for (final ms in MuteDuration.options)
            ListTile(
              title: Text(MuteDuration.label(ms)),
              onTap: () {
                Navigator.pop(sheetContext);
                onMute(
                  ms == MuteDuration.forever
                      ? MuteDuration.forever
                      : DateTime.now().millisecondsSinceEpoch + ms,
                );
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
      leading: StonechatAvatar(
          stonechatId: group.id, name: '◈', size: 42, image: group.avatar),
      title: Text(
        group.name,
        style: const TextStyle(fontWeight: FontWeight.w600),
      ),
      subtitle: chat.drafts[group.id] != null
          ? _draftLine(chat.drafts[group.id]!)
          : last == null
          ? Text('$memberCount members', style: Zn.mono(size: 11))
          : Text(
              !last.outgoing && chat.isBlocked(last.senderId ?? '')
                  ? 'Message from a blocked member'
                  : '${last.outgoing ? '› ' : ''}${last.preview}',
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: const TextStyle(color: Zn.muted, fontSize: 13),
            ),
      trailing: _tileTrailing(last, group.isPinned, muted: group.isMuted),
      onTap: () => Navigator.push(
        context,
        MaterialPageRoute(builder: (_) => ChatScreen.group(group: group)),
      ),
      onLongPress: () => _showConversationSheet(
        context,
        pinned: group.isPinned,
        muted: group.isMuted,
        archived: group.isArchived,
        onTogglePin: () => chat.togglePinGroup(group),
        onMute: (until) => chat.setMute(group.id, until),
        onToggleArchive: () => chat.toggleArchive(group.id),
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
      leading: StonechatAvatar(
        stonechatId: contact.stonechatId,
        name: contact.displayName,
        image: contact.avatar,
      ),
      title: Text(
        contact.displayName,
        style: const TextStyle(fontWeight: FontWeight.w600),
      ),
      subtitle: Text(
        '${contact.stonechatId.substring(0, 12)} · wants to connect',
        style: const TextStyle(color: Zn.muted, fontSize: 12),
      ),
      // An unsolicited request from a stranger is the one abuse that arrives
      // before there is any conversation to report from, so the report path
      // has to exist here too — decline alone only makes it stop for you.
      onLongPress: () => _reportContact(context, chat, contact),
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
                  showZnSnack(
                    context,
                    'Accepted — will notify them when reachable',
                  );
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
      leading: StonechatAvatar(
        stonechatId: contact.stonechatId,
        name: contact.displayName,
        image: contact.avatar,
      ),
      title: Text(
        contact.displayName,
        style: const TextStyle(fontWeight: FontWeight.w600),
      ),
      subtitle: Text(
        '${contact.stonechatId.substring(0, 12)} · request sent · waiting',
        style: const TextStyle(color: Zn.muted, fontSize: 12),
      ),
      trailing: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          IconButton(
            icon: const Icon(Icons.close, color: Zn.danger, size: 20),
            tooltip: 'Withdraw',
            onPressed: () => chat.declineContact(contact),
          ),
          IconButton(
            icon: const Icon(Icons.arrow_upward, color: Zn.orange, size: 20),
            tooltip: 'Send again',
            onPressed: () async {
              try {
                await chat.resendRequest(contact);
                if (context.mounted) {
                  showZnSnack(context, 'Request sent again');
                }
              } catch (e) {
                if (context.mounted) {
                  showZnSnack(
                    context,
                    "Couldn't reach their mailbox: $e",
                    error: true,
                  );
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
    final last = chat.lastMessage[contact.stonechatId];
    final notes = chat.isNotesToSelf(contact.stonechatId);

    return ListTile(
      leading: notes
          ? const NotesAvatar()
          : StonechatAvatar(
              stonechatId: contact.stonechatId,
              name: contact.displayName,
              image: contact.avatar,
            ),
      title: Text(
        contact.displayName,
        style: const TextStyle(fontWeight: FontWeight.w600),
      ),
      subtitle: chat.drafts[contact.stonechatId] != null
          ? _draftLine(chat.drafts[contact.stonechatId]!)
          : last == null
          ? Text(
              notes ? 'only you can see this' : 'say hello',
              style: Zn.mono(size: 11),
            )
          : Text(
              '${last.outgoing ? '› ' : ''}${last.preview}',
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: const TextStyle(color: Zn.muted, fontSize: 13),
            ),
      trailing: _tileTrailing(
        last,
        contact.isPinned,
        muted: contact.isMuted,
        blocked: chat.isBlocked(contact.stonechatId),
      ),
      onTap: () => Navigator.push(
        context,
        MaterialPageRoute(builder: (_) => ChatScreen(contact: contact)),
      ),
      // Notes to self: pin and archive only. Nothing arrives there to mute,
      // there is nobody to block or report, and it cannot be deleted.
      onLongPress: () => _showConversationSheet(
        context,
        pinned: contact.isPinned,
        muted: contact.isMuted,
        archived: contact.isArchived,
        blocked: chat.isBlocked(contact.stonechatId),
        onTogglePin: () => chat.togglePinContact(contact),
        onMute: notes
            ? null
            : (until) => chat.setMute(contact.stonechatId, until),
        onToggleArchive: () => chat.toggleArchive(contact.stonechatId),
        onToggleBlock: notes ? null : () => chat.toggleBlock(contact),
        onReport: notes ? null : () => _reportContact(context, chat, contact),
      ),
    );
  }
}

/// Report a contact from the conversation list, honouring the sheet's
/// "block them as well" choice.
Future<void> _reportContact(
  BuildContext context,
  ChatState chat,
  Contact contact,
) async {
  // From the list, the conversation may never have been opened — read the
  // stored history rather than the in-memory cache, which would be empty and
  // silently offer nothing to attach.
  final history = await chat.historyFor(contact.stonechatId);
  if (!context.mounted) return;
  final outcome = await showReportSheet(
    context,
    stonechatId: contact.stonechatId,
    displayName: contact.displayName,
    hub: contact.hub,
    conversation: history,
    canBlock: !chat.isBlocked(contact.stonechatId),
  );
  if (outcome.alsoBlock && !chat.isBlocked(contact.stonechatId)) {
    await chat.toggleBlock(contact);
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
