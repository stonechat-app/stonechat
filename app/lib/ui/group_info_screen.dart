/// Group details: the member ledger, and — for the admin — the levers the
/// protocol already grants them: add, remove, rename (PROTOCOL.md "Groups";
/// every change fans a full-state group_update to all members).
library;

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../models.dart';
import '../state/chat_state.dart';
import 'report_sheet.dart';
import 'theme.dart';
import 'widgets.dart';

class GroupInfoScreen extends StatefulWidget {
  final Group group;
  const GroupInfoScreen({super.key, required this.group});

  @override
  State<GroupInfoScreen> createState() => _GroupInfoScreenState();
}

class _GroupInfoScreenState extends State<GroupInfoScreen> {
  // Fan-out is O(N) per message — PROTOCOL.md's practical group cap.
  static const _memberCap = 25;

  @override
  Widget build(BuildContext context) {
    final chat = context.watch<ChatState>();
    final group = widget.group;
    final members = chat.groupMembers[group.id] ?? const <GroupMember>[];
    final isAdmin = group.adminId == chat.app.stonechatId;

    return Scaffold(
      appBar: AppBar(
        title: const Text('Group info'),
        actions: [
          if (isAdmin)
            IconButton(
              icon: const Icon(Icons.edit_outlined, color: Zn.muted, size: 20),
              tooltip: 'Rename group',
              onPressed: () => _rename(chat),
            ),
        ],
      ),
      body: ListView(
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 20, 16, 8),
            child: Row(
              children: [
                StonechatAvatar(stonechatId: group.id, name: '◈ ${group.name}', size: 54),
                const SizedBox(width: 14),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(group.name,
                          style: const TextStyle(
                              fontSize: 18, fontWeight: FontWeight.w600)),
                      const SizedBox(height: 3),
                      Text('${members.length} members',
                          style: Zn.mono(size: 10, letterSpacing: 1)),
                    ],
                  ),
                ),
              ],
            ),
          ),
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 18, 16, 4),
            child: Text('MEMBERS', style: Zn.mono(size: 10, letterSpacing: 2)),
          ),
          for (final m in members)
            ListTile(
              leading: StonechatAvatar(
                  stonechatId: m.stonechatId,
                  name: m.displayName,
                  size: 38,
                  image: chat.contactById(m.stonechatId)?.avatar),
              title: Text(m.stonechatId == chat.app.stonechatId
                  ? '${m.displayName} (you)'
                  : m.displayName),
              subtitle: m.stonechatId == group.adminId ||
                      chat.isBlocked(m.stonechatId)
                  ? Text(
                      [
                        if (m.stonechatId == group.adminId) 'ADMIN',
                        if (chat.isBlocked(m.stonechatId)) 'BLOCKED',
                      ].join(' · '),
                      style: Zn.mono(
                          size: 8,
                          color: chat.isBlocked(m.stonechatId)
                              ? Zn.danger
                              : Zn.orange,
                          letterSpacing: 2))
                  : null,
              onLongPress: m.stonechatId == chat.app.stonechatId
                  ? null
                  : () => _memberActions(chat, m),
              trailing: isAdmin && m.stonechatId != chat.app.stonechatId
                  ? IconButton(
                      icon: const Icon(Icons.person_remove_outlined,
                          color: Zn.danger, size: 20),
                      tooltip: 'Remove from group',
                      onPressed: () => _confirmRemove(chat, m),
                    )
                  : null,
            ),
          if (isAdmin)
            ListTile(
              leading: const Icon(Icons.person_add_alt, color: Zn.orange),
              title: const Text('Add members'),
              onTap: () => _showAddSheet(chat, members),
            ),
          if (!isAdmin)
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 14, 16, 0),
              child: Text('Only the group admin can change members',
                  style: Zn.mono(size: 9, color: Zn.muted)),
            ),
        ],
      ),
    );
  }

  Future<void> _rename(ChatState chat) async {
    final controller = TextEditingController(text: widget.group.name);
    final name = await showDialog<String>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        backgroundColor: Zn.surface,
        title: const Text('Rename group'),
        content: TextField(
          controller: controller,
          autofocus: true,
          maxLength: 48,
          style: const TextStyle(color: Zn.text),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(dialogContext),
            child: const Text('Cancel'),
          ),
          TextButton(
            onPressed: () =>
                Navigator.pop(dialogContext, controller.text.trim()),
            child: const Text('Save'),
          ),
        ],
      ),
    );
    if (name == null || name.isEmpty || !mounted) return;
    await chat.updateGroupMembership(widget.group, name: name);
  }

  Future<void> _confirmRemove(ChatState chat, GroupMember m) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        backgroundColor: Zn.surface,
        title: Text('Remove ${m.displayName}?'),
        content: const Text(
            "They'll stop receiving group messages. Their copy of the history stays on their device."),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(dialogContext, false),
            child: const Text('Cancel'),
          ),
          TextButton(
            onPressed: () => Navigator.pop(dialogContext, true),
            child: const Text('Remove', style: TextStyle(color: Zn.danger)),
          ),
        ],
      ),
    );
    if (confirmed != true || !mounted) return;
    await chat.updateGroupMembership(widget.group, removeIds: {m.stonechatId});
  }

  /// Long-press on a member: block/unblock and report. Any member can be
  /// blocked, contact or not — the block is keyed by Stonechat ID.
  void _memberActions(ChatState chat, GroupMember m) {
    final blocked = chat.isBlocked(m.stonechatId);
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
                blocked ? Icons.lock_open_outlined : Icons.block,
                color: blocked ? Zn.muted : Zn.danger,
              ),
              title: Text(
                blocked ? 'Unblock ${m.displayName}' : 'Block ${m.displayName}',
                style: TextStyle(color: blocked ? null : Zn.danger),
              ),
              subtitle: blocked
                  ? null
                  : const Text(
                      'Their group messages stay here, collapsed. They are not told.',
                      style: TextStyle(color: Zn.muted, fontSize: 12),
                    ),
              onTap: () {
                Navigator.pop(sheetContext);
                chat.setBlocked(m.stonechatId, !blocked);
              },
            ),
            ListTile(
              leading: const Icon(Icons.flag_outlined, color: Zn.muted),
              title: const Text('Report'),
              onTap: () {
                Navigator.pop(sheetContext);
                _reportMember(chat, m);
              },
            ),
          ],
        ),
      ),
    );
  }

  /// Report a group member. Evidence comes from the *group* conversation,
  /// filtered to this member — what they said in the room is the whole
  /// complaint.
  Future<void> _reportMember(ChatState chat, GroupMember m) async {
    final history = await chat.historyFor(widget.group.id);
    if (!mounted) return;
    final contact = chat.contactById(m.stonechatId);
    final outcome = await showReportSheet(
      context,
      stonechatId: m.stonechatId,
      displayName: m.displayName,
      hub: contact?.hub,
      conversation: history.where((msg) => msg.senderId == m.stonechatId).toList(),
      canBlock: !chat.isBlocked(m.stonechatId),
    );
    if (outcome.alsoBlock) await chat.setBlocked(m.stonechatId, true);
  }

  void _showAddSheet(ChatState chat, List<GroupMember> members) {
    final candidates = chat.acceptedContacts
        .where((c) =>
            !chat.isBlocked(c.stonechatId) && !members.any((m) => m.stonechatId == c.stonechatId))
        .toList();
    if (candidates.isEmpty) {
      showZnSnack(context, 'Everyone you know is already in this group');
      return;
    }
    final selected = <Contact>{};
    showModalBottomSheet<void>(
      context: context,
      backgroundColor: Zn.surface,
      isScrollControlled: true,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(8)),
      ),
      builder: (sheetContext) => StatefulBuilder(
        builder: (sheetContext, setSheetState) => SafeArea(
          child: ConstrainedBox(
            constraints: BoxConstraints(
                maxHeight: MediaQuery.of(sheetContext).size.height * 0.7),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Padding(
                  padding: const EdgeInsets.fromLTRB(16, 14, 16, 6),
                  child: Align(
                    alignment: Alignment.centerLeft,
                    child: Text('ADD MEMBERS',
                        style: Zn.mono(size: 10, letterSpacing: 2)),
                  ),
                ),
                Flexible(
                  child: ListView(
                    shrinkWrap: true,
                    children: [
                      for (final c in candidates)
                        CheckboxListTile(
                          value: selected.contains(c),
                          activeColor: Zn.orange,
                          controlAffinity: ListTileControlAffinity.trailing,
                          secondary: StonechatAvatar(
                              stonechatId: c.stonechatId,
                              name: c.displayName,
                              size: 34,
                              image: c.avatar),
                          title: Text(c.displayName),
                          onChanged: (checked) {
                            if (checked == true &&
                                members.length + selected.length >=
                                    _memberCap) {
                              showZnSnack(sheetContext,
                                  'Groups top out around $_memberCap people',
                                  error: true);
                              return;
                            }
                            setSheetState(() => checked == true
                                ? selected.add(c)
                                : selected.remove(c));
                          },
                        ),
                    ],
                  ),
                ),
                Padding(
                  padding: const EdgeInsets.all(12),
                  child: SizedBox(
                    width: double.infinity,
                    child: FilledButton(
                      style: FilledButton.styleFrom(
                        backgroundColor: Zn.orange,
                        foregroundColor: Zn.onAccent,
                        shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(Zn.radius)),
                      ),
                      onPressed: selected.isEmpty
                          ? null
                          : () async {
                              Navigator.pop(sheetContext);
                              await chat.updateGroupMembership(widget.group,
                                  addContacts: selected.toList());
                              if (mounted) {
                                showZnSnack(context,
                                    'Added ${selected.length} ${selected.length == 1 ? 'member' : 'members'}');
                              }
                            },
                      child: Text(selected.isEmpty
                          ? 'Add members'
                          : 'Add ${selected.length}'),
                    ),
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
