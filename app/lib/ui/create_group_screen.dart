import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../state/chat_state.dart';
import 'chat_screen.dart';
import 'theme.dart';
import 'widgets.dart';

class CreateGroupScreen extends StatefulWidget {
  const CreateGroupScreen({super.key});

  @override
  State<CreateGroupScreen> createState() => _CreateGroupScreenState();
}

class _CreateGroupScreenState extends State<CreateGroupScreen> {
  final _name = TextEditingController();
  final _selected = <String>{};
  bool _working = false;

  Future<void> _create() async {
    final chat = context.read<ChatState>();
    final name = _name.text.trim();
    if (name.isEmpty) {
      showZnSnack(context, 'Give the group a name', error: true);
      return;
    }
    if (_selected.isEmpty) {
      showZnSnack(context, 'Pick at least one friend', error: true);
      return;
    }
    setState(() => _working = true);
    try {
      final members = chat.acceptedContacts
          .where((c) => _selected.contains(c.zeonId))
          .toList();
      final group = await chat.createGroup(name, members);
      if (!mounted) return;
      Navigator.pushReplacement(
        context,
        MaterialPageRoute(builder: (_) => ChatScreen.group(group: group)),
      );
    } catch (e) {
      if (mounted) {
        showZnSnack(context, '$e', error: true);
        setState(() => _working = false);
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final contacts = context.watch<ChatState>().acceptedContacts;

    return Scaffold(
      appBar: AppBar(
        title: const Text('New group',
            style: TextStyle(fontSize: 17, fontWeight: FontWeight.w600)),
      ),
      body: Column(
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(20, 12, 20, 4),
            child: TextField(
              controller: _name,
              maxLength: 40,
              decoration: const InputDecoration(
                  hintText: 'Group name', counterText: ''),
            ),
          ),
          Padding(
            padding: const EdgeInsets.fromLTRB(20, 8, 20, 4),
            child: Align(
              alignment: Alignment.centerLeft,
              child: Text(
                'Members · ${_selected.length} selected',
                style: Zn.mono(size: 10, letterSpacing: 2),
              ),
            ),
          ),
          Expanded(
            child: contacts.isEmpty
                ? const Center(
                    child: Text('Add some friends first',
                        style: TextStyle(color: Zn.muted)),
                  )
                : ListView(
                    children: [
                      for (final c in contacts)
                        CheckboxListTile(
                          value: _selected.contains(c.zeonId),
                          activeColor: Zn.ion,
                          checkColor: const Color(0xFF15200A),
                          onChanged: (v) => setState(() {
                            v == true
                                ? _selected.add(c.zeonId)
                                : _selected.remove(c.zeonId);
                          }),
                          secondary: ZeonAvatar(
                              zeonId: c.zeonId, name: c.displayName, size: 36),
                          title: Text(c.displayName,
                              style:
                                  const TextStyle(fontWeight: FontWeight.w600)),
                          subtitle: c.handle == null
                              ? null
                              : Text(c.handle!, style: Zn.mono(size: 10)),
                        ),
                    ],
                  ),
          ),
          SafeArea(
            child: Padding(
              padding: const EdgeInsets.fromLTRB(20, 8, 20, 12),
              child: SizedBox(
                width: double.infinity,
                height: 48,
                child: FilledButton(
                  onPressed: _working ? null : _create,
                  child: _working
                      ? const SizedBox(
                          width: 18,
                          height: 18,
                          child: CircularProgressIndicator(strokeWidth: 2))
                      : const Text('Create group'),
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }
}
