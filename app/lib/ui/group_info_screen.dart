/// Group details: the member ledger, and — for the admin — the levers the
/// protocol already grants them: add, remove, rename (PROTOCOL.md "Groups";
/// every change fans a full-state group_update to all members).
library;

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../models.dart';
import '../state/chat_state.dart';
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
    final isAdmin = group.adminId == chat.app.zeonId;

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
                ZeonAvatar(zeonId: group.id, name: '◈ ${group.name}', size: 54),
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
              leading:
                  ZeonAvatar(zeonId: m.zeonId, name: m.displayName, size: 38),
              title: Text(m.zeonId == chat.app.zeonId
                  ? '${m.displayName} (you)'
                  : m.displayName),
              subtitle: m.zeonId == group.adminId
                  ? Text('ADMIN',
                      style: Zn.mono(size: 8, color: Zn.ion, letterSpacing: 2))
                  : null,
              trailing: isAdmin && m.zeonId != chat.app.zeonId
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
              leading: const Icon(Icons.person_add_alt, color: Zn.ion),
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
    await chat.updateGroupMembership(widget.group, removeIds: {m.zeonId});
  }

  void _showAddSheet(ChatState chat, List<GroupMember> members) {
    final candidates = chat.acceptedContacts
        .where((c) =>
            !c.isBlocked && !members.any((m) => m.zeonId == c.zeonId))
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
                          activeColor: Zn.ion,
                          controlAffinity: ListTileControlAffinity.trailing,
                          secondary: ZeonAvatar(
                              zeonId: c.zeonId,
                              name: c.displayName,
                              size: 34),
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
                        backgroundColor: Zn.ion,
                        foregroundColor: const Color(0xFF15200A),
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
