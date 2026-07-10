/// The Zeon conversation view: a left-aligned ledger, not bubbles.
///
/// Every message is a full-width entry with a colored rail — ion for you,
/// the contact's derived color for them. Long silences render as actual
/// vertical space with a small gap marker, so a conversation's rhythm is
/// visible at a glance.
library;

import 'dart:async';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:image_picker/image_picker.dart';
import 'package:intl/intl.dart';
import 'package:just_audio/just_audio.dart';
import 'package:path_provider/path_provider.dart';
import 'package:provider/provider.dart';
import 'package:record/record.dart';

import '../models.dart';
import '../state/call_state.dart';
import '../state/chat_state.dart';
import 'theme.dart';
import 'widgets.dart';

class ChatScreen extends StatefulWidget {
  final Contact? contact;
  final Group? group;

  const ChatScreen({super.key, required Contact this.contact}) : group = null;
  const ChatScreen.group({super.key, required Group this.group})
      : contact = null;

  @override
  State<ChatScreen> createState() => _ChatScreenState();
}

class _ChatScreenState extends State<ChatScreen> {
  final _input = TextEditingController();
  final _scroll = ScrollController();
  late final ChatState _chat;
  Message? _editing; // composer is rewriting this message instead of sending

  bool get isGroup => widget.group != null;
  String get conversationId => widget.contact?.zeonId ?? widget.group!.id;

  @override
  void initState() {
    super.initState();
    _chat = context.read<ChatState>();
    _chat.openConversation(conversationId);
  }

  @override
  void dispose() {
    _chat.closeConversation(conversationId);
    super.dispose();
  }

  Future<void> _send() async {
    final text = _input.text.trim();
    if (text.isEmpty) return;
    _input.clear();
    final chat = context.read<ChatState>();
    final editing = _editing;
    if (editing != null) {
      setState(() => _editing = null);
      final reachedEveryone = await chat.editMessage(editing, text);
      if (!reachedEveryone && mounted) {
        showZnSnack(context, "Edit couldn't reach everyone — they still see the old text",
            error: true);
      }
      return;
    }
    if (isGroup) {
      await chat.sendGroupMessage(widget.group!, text);
    } else {
      await chat.sendMessage(widget.contact!, text);
    }
    _scrollToEnd();
  }

  void _startEdit(Message m) {
    setState(() => _editing = m);
    _input.text = m.text;
    _input.selection = TextSelection.collapsed(offset: m.text.length);
  }

  static const _quickReactions = ['👍', '❤️', '😂', '😮', '😢', '🔥'];

  void _showMessageSheet(Message m) {
    final chat = context.read<ChatState>();
    if (m.deleted) return;
    // Local rows (call epitaphs, system notices): delete-for-me only.
    final isLocalRow =
        m.kind == MessageKind.call || m.kind == MessageKind.notice;
    final myEmoji = chat.myReactionTo(m);
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
            if (!isLocalRow)
            Padding(
              padding: const EdgeInsets.symmetric(vertical: 10, horizontal: 16),
              child: Row(
                mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                children: [
                  for (final emoji in _quickReactions)
                    GestureDetector(
                      onTap: () {
                        Navigator.pop(sheetContext);
                        chat.react(m, emoji);
                      },
                      child: Container(
                        padding: const EdgeInsets.all(6),
                        decoration: BoxDecoration(
                          color: myEmoji == emoji ? Zn.raised : null,
                          borderRadius: BorderRadius.circular(Zn.radius),
                          border: myEmoji == emoji
                              ? Border.all(color: Zn.ion)
                              : null,
                        ),
                        child: Text(emoji,
                            style: const TextStyle(fontSize: 24)),
                      ),
                    ),
                ],
              ),
            ),
            if (!isLocalRow) const Divider(height: 1),
            if (m.kind == MessageKind.text)
              ListTile(
                leading: const Icon(Icons.copy_outlined, color: Zn.muted),
                title: const Text('Copy'),
                onTap: () {
                  Clipboard.setData(ClipboardData(text: m.text));
                  Navigator.pop(sheetContext);
                },
              ),
            if (!isLocalRow)
              ListTile(
                leading: const Icon(Icons.shortcut_outlined, color: Zn.muted),
                title: const Text('Forward'),
                onTap: () {
                  Navigator.pop(sheetContext);
                  _showForwardPicker(m);
                },
              ),
            if (chat.canEdit(m))
              ListTile(
                leading: const Icon(Icons.edit_outlined, color: Zn.ion),
                title: const Text('Edit'),
                onTap: () {
                  Navigator.pop(sheetContext);
                  _startEdit(m);
                },
              ),
            if (chat.canDeleteForEveryone(m) && !isLocalRow)
              ListTile(
                leading: const Icon(Icons.delete_outline, color: Zn.danger),
                title: const Text('Delete for everyone',
                    style: TextStyle(color: Zn.danger)),
                onTap: () async {
                  Navigator.pop(sheetContext);
                  final reachedEveryone =
                      await chat.deleteMessageForEveryone(m);
                  if (!reachedEveryone && mounted) {
                    showZnSnack(context,
                        "Couldn't reach everyone — some may still see it",
                        error: true);
                  }
                },
              ),
            ListTile(
              leading: const Icon(Icons.delete_sweep_outlined, color: Zn.muted),
              title: const Text('Delete for me'),
              onTap: () {
                Navigator.pop(sheetContext);
                chat.deleteMessageForMe(m);
              },
            ),
          ],
        ),
      ),
    );
  }

  /// Pick a destination and re-send `m` there. Media can only go to direct
  /// chats — groups don't carry media yet (see PROTOCOL.md).
  void _showForwardPicker(Message m) {
    final chat = context.read<ChatState>();
    final isMedia = m.kind != MessageKind.text;
    if (isMedia && !File(m.mediaPath ?? '').existsSync()) {
      showZnSnack(context, 'That file is no longer on this device',
          error: true);
      return;
    }
    final contacts = chat.acceptedContacts;
    final groups = isMedia ? const <Group>[] : chat.groups;
    if (contacts.isEmpty && groups.isEmpty) {
      showZnSnack(context, 'No one to forward to yet');
      return;
    }

    Future<void> forward(
        {Contact? toContact, Group? toGroup, required String name}) async {
      await chat.forwardMessage(m, toContact: toContact, toGroup: toGroup);
      if (mounted) showZnSnack(context, 'Forwarded to $name');
    }

    showModalBottomSheet<void>(
      context: context,
      backgroundColor: Zn.surface,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(8)),
      ),
      builder: (sheetContext) => SafeArea(
        child: ConstrainedBox(
          constraints: BoxConstraints(
              maxHeight: MediaQuery.of(sheetContext).size.height * 0.6),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Padding(
                padding: const EdgeInsets.fromLTRB(16, 14, 16, 6),
                child: Align(
                  alignment: Alignment.centerLeft,
                  child: Text('FORWARD TO',
                      style: Zn.mono(size: 10, letterSpacing: 2)),
                ),
              ),
              if (isMedia)
                Padding(
                  padding: const EdgeInsets.fromLTRB(16, 0, 16, 6),
                  child: Align(
                    alignment: Alignment.centerLeft,
                    child: Text(
                        'Photos and voice notes can only go to direct chats',
                        style: Zn.mono(size: 9, color: Zn.muted)),
                  ),
                ),
              Flexible(
                child: ListView(
                  shrinkWrap: true,
                  children: [
                    for (final c in contacts)
                      ListTile(
                        leading: ZeonAvatar(
                            zeonId: c.zeonId, name: c.displayName, size: 34),
                        title: Text(c.displayName),
                        onTap: () {
                          Navigator.pop(sheetContext);
                          forward(toContact: c, name: c.displayName);
                        },
                      ),
                    for (final g in groups)
                      ListTile(
                        leading: ZeonAvatar(
                            zeonId: g.id, name: '◈ ${g.name}', size: 34),
                        title: Text(g.name),
                        onTap: () {
                          Navigator.pop(sheetContext);
                          forward(toGroup: g, name: g.name);
                        },
                      ),
                  ],
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  void _showTimerSheet() {
    final chat = context.read<ChatState>();
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
              padding: const EdgeInsets.fromLTRB(16, 14, 16, 2),
              child: Align(
                alignment: Alignment.centerLeft,
                child: Text('DISAPPEARING MESSAGES',
                    style: Zn.mono(size: 10, letterSpacing: 2)),
              ),
            ),
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 0, 16, 6),
              child: Align(
                alignment: Alignment.centerLeft,
                child: Text(
                    'New messages will vanish for everyone after the selected time',
                    style: Zn.mono(size: 9, color: Zn.muted)),
              ),
            ),
            RadioGroup<int>(
              groupValue: chat.expireTimerFor(conversationId),
              onChanged: (value) {
                Navigator.pop(sheetContext);
                if (value != null) chat.setExpireTimer(conversationId, value);
              },
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  for (final ms in ExpireTimer.options)
                    RadioListTile<int>(
                      value: ms,
                      activeColor: Zn.ion,
                      title: Text(ExpireTimer.label(ms)),
                    ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  String _typingLabel(ChatState chat) {
    final typers = chat.typersIn(conversationId);
    if (typers.isEmpty) return '';
    if (!isGroup) return 'typing ···';
    final names = typers
        .map((id) =>
            chat.memberOf(conversationId, id)?.displayName ?? 'someone')
        .toList();
    return '${names.join(', ')} ${names.length == 1 ? 'is' : 'are'} typing ···';
  }

  Future<void> _sendPhoto() async {
    final picked = await ImagePicker().pickImage(
      source: ImageSource.gallery,
      maxWidth: 1600,
      imageQuality: 82,
    );
    if (picked == null || !mounted) return;
    await context.read<ChatState>().sendMedia(
          widget.contact!,
          picked.path,
          kind: MessageKind.image,
          mime: 'image/jpeg',
        );
    _scrollToEnd();
  }

  Future<void> _sendVoice(String path, int durationMs) async {
    await context.read<ChatState>().sendMedia(
          widget.contact!,
          path,
          kind: MessageKind.audio,
          mime: 'audio/mp4',
          durationMs: durationMs,
        );
    _scrollToEnd();
  }

  void _scrollToEnd() {
    if (_scroll.hasClients) {
      _scroll.animateTo(_scroll.position.maxScrollExtent + 120,
          duration: const Duration(milliseconds: 200), curve: Curves.easeOut);
    }
  }

  @override
  Widget build(BuildContext context) {
    final chat = context.watch<ChatState>();
    final messages = chat.messagesFor(conversationId);
    final title = widget.contact?.displayName ?? widget.group!.name;
    final memberCount = isGroup ? chat.groupMembers[conversationId]?.length : null;

    return Scaffold(
      appBar: AppBar(
        titleSpacing: 0,
        title: Row(
          children: [
            ZeonAvatar(
                zeonId: conversationId,
                name: isGroup ? '◈ ${widget.group!.name}' : title,
                size: 32),
            const SizedBox(width: 10),
            Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(title, style: const TextStyle(fontSize: 16)),
                Row(
                  children: [
                    if (chat.expireTimerFor(conversationId) > 0)
                      const Padding(
                        padding: EdgeInsets.only(right: 3),
                        child: Icon(Icons.timer_outlined,
                            size: 11, color: Zn.muted),
                      ),
                    Text(
                        isGroup
                            ? '$memberCount members'
                            : (widget.contact!.handle ??
                                widget.contact!.zeonId.substring(0, 12)),
                        style: Zn.mono(size: 9, letterSpacing: 1)),
                  ],
                ),
              ],
            ),
          ],
        ),
        actions: [
          if (!isGroup) ...[
            IconButton(
              icon: const Icon(Icons.call_outlined, color: Zn.muted, size: 22),
              tooltip: 'Voice call',
              onPressed: () => context
                  .read<CallState>()
                  .startCall(widget.contact!, video: false),
            ),
            IconButton(
              icon: const Icon(Icons.videocam_outlined,
                  color: Zn.muted, size: 22),
              tooltip: 'Video call',
              onPressed: () => context
                  .read<CallState>()
                  .startCall(widget.contact!, video: true),
            ),
          ],
          PopupMenuButton<String>(
            color: Zn.raised,
            icon: const Icon(Icons.more_vert, color: Zn.muted),
            onSelected: (value) async {
              if (value == 'timer') {
                _showTimerSheet();
                return;
              }
              if (value == 'leave') {
                await chat.leaveGroup(widget.group!);
                if (context.mounted) Navigator.pop(context);
              }
            },
            itemBuilder: (_) => [
              const PopupMenuItem(
                value: 'timer',
                child: Text('Disappearing messages'),
              ),
              if (isGroup)
                const PopupMenuItem(
                  value: 'leave',
                  child: Text('Leave group',
                      style: TextStyle(color: Zn.danger)),
                ),
            ],
          ),
        ],
      ),
      body: Column(
        children: [
          Expanded(
            child: ListView.builder(
              controller: _scroll,
              padding: const EdgeInsets.symmetric(vertical: 12),
              itemCount: messages.length,
              itemBuilder: (context, i) {
                final m = messages[i];
                final previous = i > 0 ? messages[i - 1] : null;
                final senderName = m.outgoing
                    ? 'YOU'
                    : isGroup
                        ? (chat
                                .memberOf(conversationId, m.senderId ?? '')
                                ?.displayName ??
                            'former member')
                        : title;
                final railColor = m.outgoing
                    ? Zn.ion
                    : Zn.idColor(isGroup ? (m.senderId ?? '') : conversationId);
                if (m.kind == MessageKind.notice) {
                  return GestureDetector(
                    onLongPress: () => _showMessageSheet(m),
                    behavior: HitTestBehavior.opaque,
                    child: Padding(
                      padding: const EdgeInsets.symmetric(vertical: 10),
                      child: Row(
                        mainAxisAlignment: MainAxisAlignment.center,
                        children: [
                          const Icon(Icons.timer_outlined,
                              size: 11, color: Zn.muted),
                          const SizedBox(width: 5),
                          Flexible(
                            child: Text(m.text,
                                textAlign: TextAlign.center,
                                style: Zn.mono(size: 10, color: Zn.muted)),
                          ),
                        ],
                      ),
                    ),
                  );
                }
                return Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    if (previous != null) _GapMarker.between(previous, m),
                    GestureDetector(
                      onLongPress: () => _showMessageSheet(m),
                      behavior: HitTestBehavior.opaque,
                      child: _LedgerEntry(
                        message: m,
                        peerName: senderName,
                        peerColor: railColor,
                        // A notice breaks the run: re-show the sender after it.
                        showSender: previous == null ||
                            previous.kind == MessageKind.notice ||
                            previous.outgoing != m.outgoing ||
                            previous.senderId != m.senderId,
                        reactions:
                            chat.reactionsByMessage[m.id] ?? const {},
                        myEmoji: chat.myReactionTo(m),
                        onReact: (emoji) => chat.react(m, emoji),
                      ),
                    ),
                  ],
                );
              },
            ),
          ),
          if (_typingLabel(chat).isNotEmpty)
            Container(
              alignment: Alignment.centerLeft,
              padding: const EdgeInsets.fromLTRB(16, 0, 16, 6),
              child: Text(_typingLabel(chat),
                  style: Zn.mono(size: 10, color: Zn.cyan, letterSpacing: 1)),
            ),
          if (_editing != null)
            Container(
              color: Zn.surface,
              padding: const EdgeInsets.fromLTRB(16, 6, 4, 0),
              child: Row(
                children: [
                  const Icon(Icons.edit_outlined, size: 14, color: Zn.ion),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text('Editing message',
                        style: Zn.mono(size: 10, color: Zn.ion, letterSpacing: 1)),
                  ),
                  IconButton(
                    icon: const Icon(Icons.close, size: 16, color: Zn.muted),
                    onPressed: () {
                      _input.clear();
                      setState(() => _editing = null);
                    },
                  ),
                ],
              ),
            ),
          _Composer(
            controller: _input,
            onSend: _send,
            onTyping: _editing == null
                ? () => context.read<ChatState>().notifyTyping(conversationId)
                : null,
            // Media in groups is deferred (see PROTOCOL.md) — DM-only for now.
            onPickPhoto: isGroup ? null : _sendPhoto,
            onVoiceRecorded: isGroup ? null : _sendVoice,
          ),
        ],
      ),
    );
  }
}

class _LedgerEntry extends StatelessWidget {
  final Message message;
  final String peerName;
  final Color peerColor;
  final bool showSender;
  final Map<String, String> reactions; // reactor Zeon ID → emoji
  final String? myEmoji;
  final void Function(String emoji)? onReact;

  const _LedgerEntry({
    required this.message,
    required this.peerName,
    required this.peerColor,
    required this.showSender,
    this.reactions = const {},
    this.myEmoji,
    this.onReact,
  });

  /// emoji → how many people picked it, insertion-ordered.
  Map<String, int> _aggregated() {
    final counts = <String, int>{};
    for (final emoji in reactions.values) {
      counts[emoji] = (counts[emoji] ?? 0) + 1;
    }
    return counts;
  }

  @override
  Widget build(BuildContext context) {
    final color = message.outgoing ? Zn.ion : peerColor;
    final sender = message.outgoing ? 'YOU' : peerName.toUpperCase();

    return Padding(
      padding: EdgeInsets.fromLTRB(16, showSender ? 10 : 2, 16, 2),
      child: IntrinsicHeight(
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Container(
              width: 2.5,
              decoration: BoxDecoration(
                color: color.withValues(alpha: 0.8),
                borderRadius: BorderRadius.circular(2),
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  if (showSender)
                    Padding(
                      padding: const EdgeInsets.only(bottom: 3),
                      child: Text(sender,
                          style: Zn.mono(
                              size: 9,
                              color: color,
                              weight: FontWeight.w700,
                              letterSpacing: 2)),
                    ),
                  if (message.deleted)
                    Text('message deleted',
                        style: Zn.mono(size: 12).copyWith(
                            fontStyle: FontStyle.italic, color: Zn.muted))
                  else
                    switch (message.kind) {
                      MessageKind.image => _ImageEntry(message: message),
                      MessageKind.audio =>
                        _AudioEntry(message: message, color: color),
                      MessageKind.call => Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            Icon(
                                message.text.startsWith('Missed')
                                    ? Icons.phone_missed
                                    : message.text.contains('ideo')
                                        ? Icons.videocam_outlined
                                        : Icons.call_outlined,
                                size: 14,
                                color: message.text.startsWith('Missed')
                                    ? Zn.danger
                                    : Zn.muted),
                            const SizedBox(width: 6),
                            Text(message.text, style: Zn.mono(size: 12)),
                          ],
                        ),
                      _ => Text.rich(
                          TextSpan(
                            text: message.text,
                            children: [
                              if (message.editedAt != null)
                                TextSpan(
                                    text: '  · edited', style: Zn.mono(size: 9)),
                            ],
                          ),
                          style: const TextStyle(
                              color: Zn.text, fontSize: 15, height: 1.35)),
                    },
                  if (reactions.isNotEmpty)
                    Padding(
                      padding: const EdgeInsets.only(top: 4),
                      child: Wrap(
                        spacing: 6,
                        runSpacing: 4,
                        children: [
                          for (final entry in _aggregated().entries)
                            GestureDetector(
                              onTap: () => onReact?.call(entry.key),
                              child: Container(
                                padding: const EdgeInsets.symmetric(
                                    horizontal: 8, vertical: 2),
                                decoration: BoxDecoration(
                                  color: Zn.raised,
                                  borderRadius:
                                      BorderRadius.circular(Zn.radius),
                                  border: Border.all(
                                      color: myEmoji == entry.key
                                          ? Zn.ion
                                          : Zn.line),
                                ),
                                child: Text(
                                  entry.value > 1
                                      ? '${entry.key} ${entry.value}'
                                      : entry.key,
                                  style: const TextStyle(
                                      fontSize: 13, color: Zn.text),
                                ),
                              ),
                            ),
                        ],
                      ),
                    ),
                ],
              ),
            ),
            const SizedBox(width: 12),
            Column(
              mainAxisAlignment: MainAxisAlignment.end,
              children: [
                Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Text(
                      DateFormat('HH:mm').format(
                          DateTime.fromMillisecondsSinceEpoch(message.sentAt)),
                      style: Zn.mono(size: 9),
                    ),
                    if (message.outgoing) ...[
                      const SizedBox(width: 4),
                      Text(
                        switch (message.status) {
                          MessageStatus.pending => '◌',
                          MessageStatus.sent => '●',
                          _ => '●●', // delivered / read, read lights up
                        },
                        style: Zn.mono(
                            size: 9,
                            color: message.status == MessageStatus.read
                                ? Zn.cyan
                                : Zn.muted),
                      ),
                    ],
                  ],
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}

/// Silence made visible: >20 min between messages renders as space.
class _GapMarker extends StatelessWidget {
  final Duration gap;
  const _GapMarker({required this.gap});

  static Widget between(Message a, Message b) {
    final gap = Duration(milliseconds: b.sentAt - a.sentAt);
    if (gap.inMinutes < 20) return const SizedBox.shrink();
    return _GapMarker(gap: gap);
  }

  @override
  Widget build(BuildContext context) {
    final label = gap.inDays >= 1
        ? '${gap.inDays}D'
        : gap.inHours >= 1
            ? '${gap.inHours}H'
            : '${gap.inMinutes}M';
    return Padding(
      padding: EdgeInsets.symmetric(
          vertical: (12 + gap.inHours.clamp(0, 10) * 2).toDouble()),
      child: Row(
        children: [
          const Expanded(child: Divider(indent: 16, endIndent: 12)),
          Text('· $label ·', style: Zn.mono(size: 9, letterSpacing: 1)),
          const Expanded(child: Divider(indent: 12, endIndent: 16)),
        ],
      ),
    );
  }
}

class _ImageEntry extends StatelessWidget {
  final Message message;
  const _ImageEntry({required this.message});

  @override
  Widget build(BuildContext context) {
    final file = File(message.mediaPath ?? '');
    if (!file.existsSync()) {
      return Text('📷 photo unavailable', style: Zn.mono(size: 12));
    }
    return Padding(
      padding: const EdgeInsets.only(top: 2),
      child: GestureDetector(
        onTap: () => showDialog<void>(
          context: context,
          builder: (_) => Dialog(
            backgroundColor: Colors.black,
            insetPadding: const EdgeInsets.all(12),
            child: InteractiveViewer(child: Image.file(file)),
          ),
        ),
        child: ClipRRect(
          borderRadius: BorderRadius.circular(Zn.radius),
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxHeight: 260, maxWidth: 260),
            child: Image.file(file, fit: BoxFit.cover),
          ),
        ),
      ),
    );
  }
}

class _AudioEntry extends StatefulWidget {
  final Message message;
  final Color color;
  const _AudioEntry({required this.message, required this.color});

  @override
  State<_AudioEntry> createState() => _AudioEntryState();
}

class _AudioEntryState extends State<_AudioEntry> {
  final _player = AudioPlayer();
  bool _loaded = false;

  @override
  void dispose() {
    _player.dispose();
    super.dispose();
  }

  Future<void> _toggle() async {
    if (!_loaded) {
      await _player.setFilePath(widget.message.mediaPath!);
      _loaded = true;
    }
    if (_player.playing) {
      await _player.pause();
    } else {
      if (_player.processingState == ProcessingState.completed) {
        await _player.seek(Duration.zero);
      }
      unawaited(_player.play());
    }
  }

  String _fmt(Duration d) =>
      '${d.inMinutes}:${(d.inSeconds % 60).toString().padLeft(2, '0')}';

  @override
  Widget build(BuildContext context) {
    final total = Duration(milliseconds: widget.message.durationMs ?? 0);
    return Padding(
      padding: const EdgeInsets.only(top: 2),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          StreamBuilder<PlayerState>(
            stream: _player.playerStateStream,
            builder: (context, snap) {
              final playing = snap.data?.playing ?? false;
              return GestureDetector(
                onTap: _toggle,
                child: Container(
                  width: 34,
                  height: 34,
                  decoration: BoxDecoration(
                    color: widget.color.withValues(alpha: 0.15),
                    borderRadius: BorderRadius.circular(Zn.radius),
                    border:
                        Border.all(color: widget.color.withValues(alpha: 0.5)),
                  ),
                  child: Icon(playing ? Icons.pause : Icons.play_arrow,
                      size: 20, color: widget.color),
                ),
              );
            },
          ),
          const SizedBox(width: 10),
          SizedBox(
            width: 130,
            child: StreamBuilder<Duration>(
              stream: _player.positionStream,
              builder: (context, snap) {
                final pos = snap.data ?? Duration.zero;
                final progress = total.inMilliseconds > 0
                    ? (pos.inMilliseconds / total.inMilliseconds).clamp(0.0, 1.0)
                    : 0.0;
                return ClipRRect(
                  borderRadius: BorderRadius.circular(2),
                  child: LinearProgressIndicator(
                    value: progress,
                    minHeight: 3,
                    backgroundColor: Zn.line,
                    valueColor: AlwaysStoppedAnimation(widget.color),
                  ),
                );
              },
            ),
          ),
          const SizedBox(width: 10),
          Text(_fmt(total), style: Zn.mono(size: 10)),
        ],
      ),
    );
  }
}

class _Composer extends StatefulWidget {
  final TextEditingController controller;
  final VoidCallback onSend;
  final VoidCallback? onTyping; // keystroke → typing indicator (throttled upstream)
  final VoidCallback? onPickPhoto; // null → media disabled (groups, deferred)
  final void Function(String path, int durationMs)? onVoiceRecorded;

  const _Composer({
    required this.controller,
    required this.onSend,
    this.onTyping,
    required this.onPickPhoto,
    required this.onVoiceRecorded,
  });

  @override
  State<_Composer> createState() => _ComposerState();
}

class _ComposerState extends State<_Composer> {
  final _recorder = AudioRecorder();
  DateTime? _recordingStarted;
  Timer? _ticker;

  bool get _recording => _recordingStarted != null;

  @override
  void dispose() {
    _ticker?.cancel();
    _recorder.dispose();
    super.dispose();
  }

  Future<void> _toggleRecording() async {
    if (_recording) {
      final path = await _recorder.stop();
      final started = _recordingStarted!;
      _ticker?.cancel();
      setState(() => _recordingStarted = null);
      if (path != null) {
        final duration = DateTime.now().difference(started);
        if (duration.inMilliseconds > 500) {
          widget.onVoiceRecorded?.call(path, duration.inMilliseconds);
        }
      }
      return;
    }
    if (!await _recorder.hasPermission()) {
      if (mounted) {
        showZnSnack(context, 'Microphone access is needed for voice notes',
            error: true);
      }
      return;
    }
    final dir = await getTemporaryDirectory();
    await _recorder.start(
      const RecordConfig(encoder: AudioEncoder.aacLc, bitRate: 48000),
      path:
          '${dir.path}/zeon-voice-${DateTime.now().millisecondsSinceEpoch}.m4a',
    );
    setState(() => _recordingStarted = DateTime.now());
    _ticker =
        Timer.periodic(const Duration(seconds: 1), (_) => setState(() {}));
  }

  @override
  Widget build(BuildContext context) {
    final elapsed = _recording
        ? DateTime.now().difference(_recordingStarted!)
        : Duration.zero;

    return Container(
      decoration: const BoxDecoration(
        color: Zn.surface,
        border: Border(top: BorderSide(color: Zn.line)),
      ),
      padding: EdgeInsets.only(
        left: 4,
        right: 8,
        top: 8,
        bottom: 8 + MediaQuery.of(context).padding.bottom,
      ),
      child: Row(
        children: [
          if (widget.onPickPhoto != null)
            IconButton(
              onPressed: _recording ? null : widget.onPickPhoto,
              icon: const Icon(Icons.photo_outlined, color: Zn.muted, size: 22),
            )
          else
            const SizedBox(width: 12),
          Expanded(
            child: _recording
                ? Row(
                    children: [
                      Container(
                        width: 8,
                        height: 8,
                        decoration: const BoxDecoration(
                            color: Zn.danger, shape: BoxShape.circle),
                      ),
                      const SizedBox(width: 10),
                      Text(
                        'Recording · ${elapsed.inMinutes}:${(elapsed.inSeconds % 60).toString().padLeft(2, '0')}',
                        style: Zn.mono(size: 13, color: Zn.text),
                      ),
                    ],
                  )
                : TextField(
                    controller: widget.controller,
                    minLines: 1,
                    maxLines: 5,
                    textInputAction: TextInputAction.send,
                    onChanged: (text) {
                      if (text.trim().isNotEmpty) widget.onTyping?.call();
                    },
                    onSubmitted: (_) => widget.onSend(),
                    style: const TextStyle(color: Zn.text, fontSize: 15),
                    decoration: InputDecoration(
                      hintText: 'message ›',
                      hintStyle: Zn.mono(size: 13),
                      border: InputBorder.none,
                      enabledBorder: InputBorder.none,
                      focusedBorder: InputBorder.none,
                      filled: false,
                    ),
                  ),
          ),
          if (widget.onVoiceRecorded != null)
            IconButton(
              onPressed: _toggleRecording,
              icon: Icon(
                _recording ? Icons.stop_circle_outlined : Icons.mic_none,
                color: _recording ? Zn.danger : Zn.muted,
                size: 22,
              ),
            ),
          IconButton(
            onPressed: _recording ? null : widget.onSend,
            icon: Container(
              width: 36,
              height: 36,
              decoration: BoxDecoration(
                color: _recording ? Zn.line : Zn.ion,
                borderRadius: BorderRadius.circular(Zn.radius),
              ),
              child: const Icon(Icons.arrow_upward,
                  size: 20, color: Color(0xFF15200A)),
            ),
          ),
        ],
      ),
    );
  }
}
