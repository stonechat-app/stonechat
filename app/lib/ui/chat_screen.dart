/// The Stonechat conversation view: a left-aligned ledger, not bubbles.
///
/// Every message is a full-width entry with a colored rail — ion for you,
/// the contact's derived color for them. Long silences render as actual
/// vertical space with a small gap marker, so a conversation's rhythm is
/// visible at a glance.
library;

import 'dart:async';
import 'dart:io';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter/services.dart';
import 'package:image_picker/image_picker.dart';
import 'package:intl/intl.dart';
import 'package:just_audio/just_audio.dart';
import 'package:open_filex/open_filex.dart';
import 'package:path/path.dart' as p;
import 'package:path_provider/path_provider.dart';
import 'package:provider/provider.dart';
import 'package:record/record.dart';
import 'package:scrollable_positioned_list/scrollable_positioned_list.dart';
import 'package:video_player/video_player.dart';

import 'package:emoji_picker_flutter/emoji_picker_flutter.dart';

import '../core/stickers.dart';
import '../models.dart';
import '../state/call_state.dart';
import '../state/chat_state.dart';
import 'group_info_screen.dart';
import 'report_sheet.dart';
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
  final _itemScroll = ItemScrollController();
  final _itemPositions = ItemPositionsListener.create();
  final _scrollOffset = ScrollOffsetController();
  final _listKey = GlobalKey(); // measures the viewport for _scrollToEnd
  late final ChatState _chat;
  Message? _editing; // composer is rewriting this message instead of sending
  Message? _replyingTo; // composer sends the next message as a reply to this
  bool _jumpedToEnd = false; // first non-empty build lands on the last message
  // Group messages from blocked members the user chose to look at anyway.
  // Per screen visit: leaving and coming back collapses them again.
  final _revealed = <String>{};

  // In-chat search: null query = closed. Matches are message ids; the
  // current one is scrolled to and every hit is highlighted in place.
  final _searchInput = TextEditingController();
  bool _searching = false;
  int _searchPos = 0; // index into the match list (newest first)
  String? _flashId; // briefly tinted row after a jump (reply tap, search)
  Timer? _flashTimer;

  // Arrival animation: only messages sent after the screen opened, and each
  // only once — scrolling back through history never replays it.
  final _openedAt = DateTime.now().millisecondsSinceEpoch;
  final _arrived = <String>{};

  Widget _arrive(Message m, Widget child) {
    final animate = _arrived.add(m.id) && m.sentAt >= _openedAt - 2000;
    // Always the same wrapper, so a rebuild mid-animation (pending → sent is
    // quick) lets it finish instead of snapping.
    return TweenAnimationBuilder<double>(
      tween: Tween(begin: animate ? 0 : 1, end: 1),
      duration: Zn.dur(context, Zn.medium),
      curve: Zn.ease,
      builder: (context, t, child) => Opacity(
        opacity: t,
        child: Transform.translate(
          offset: Offset(0, 6 * (1 - t)),
          child: child,
        ),
      ),
      child: child,
    );
  }

  bool get isGroup => widget.group != null;
  String get conversationId => widget.contact?.stonechatId ?? widget.group!.id;

  /// Notes to self: a direct chat with nobody on the other end, so everything
  /// that would reach a peer — calls, block, report, the disappearing timer,
  /// delete-for-everyone — is left out.
  bool get isNotes => !isGroup && _chat.isNotesToSelf(conversationId);

  @override
  void initState() {
    super.initState();
    _chat = context.read<ChatState>();
    _chat.openConversation(conversationId);
  }

  @override
  void dispose() {
    _flashTimer?.cancel();
    _searchInput.dispose();
    _chat.closeConversation(conversationId);
    super.dispose();
  }

  Future<void> _send() async {
    final text = _input.text.trim();
    if (text.isEmpty) return;
    HapticFeedback.lightImpact();
    _input.clear();
    final chat = context.read<ChatState>();
    final editing = _editing;
    if (editing != null) {
      setState(() => _editing = null);
      final reachedEveryone = await chat.editMessage(editing, text);
      if (!reachedEveryone && mounted) {
        showZnSnack(
          context,
          "Edit couldn't reach everyone — they still see the old text",
          error: true,
        );
      }
      return;
    }
    final replyTo = _replyingTo;
    if (replyTo != null) setState(() => _replyingTo = null);
    final sent = isGroup
        ? await chat.sendGroupMessage(widget.group!, text, replyTo: replyTo)
        : await chat.sendMessage(widget.contact!, text, replyTo: replyTo);
    _reportSendTrouble(sent);
    _scrollToEnd();
  }

  /// The first attempt just failed and the user is still looking at the
  /// screen — this is the moment the friendly copy in ChatState is worth
  /// something. The bubble carries the same reason afterwards, so this is a
  /// nudge, not the only telling.
  void _reportSendTrouble(Message m) {
    final reason = m.failReason;
    if (reason == null || !mounted) return;
    showZnSnack(context, reason, error: m.status == MessageStatus.failed);
  }

  void _startEdit(Message m) {
    setState(() {
      _editing = m;
      _replyingTo = null;
    });
    _input.text = m.text;
    _input.selection = TextSelection.collapsed(offset: m.text.length);
  }

  void _startReply(Message m) {
    setState(() {
      _replyingTo = m;
      _editing = null;
    });
  }

  /// Consume the composer's reply context for an outgoing attachment —
  /// replies ride photos, videos, voice notes and documents too.
  Message? _takeReply() {
    final r = _replyingTo;
    if (r != null) setState(() => _replyingTo = null);
    return r;
  }

  /// Briefly tint a row after a jump so the eye lands on it.
  void _flash(String id) {
    _flashTimer?.cancel();
    setState(() => _flashId = id);
    _flashTimer = Timer(const Duration(milliseconds: 1400), () {
      if (mounted) setState(() => _flashId = null);
    });
  }

  void _jumpToMessage(String id) {
    final messages = _chat.messagesFor(conversationId);
    final index = messages.indexWhere((m) => m.id == id);
    if (index < 0) {
      showZnSnack(context, 'Original message is no longer on this device');
      return;
    }
    _flash(id);
    if (_itemScroll.isAttached) {
      _itemScroll.scrollTo(
        index: index,
        alignment: 0.3,
        duration: const Duration(milliseconds: 250),
        curve: Curves.easeOut,
      );
    }
  }

  // -- in-chat search -------------------------------------------------------

  /// Indices of messages matching the query (text and document names).
  List<int> _searchMatches(List<Message> messages) {
    final q = _searchInput.text.trim().toLowerCase();
    if (q.isEmpty) return const [];
    return [
      for (var i = 0; i < messages.length; i++)
        if (!messages[i].deleted &&
            (messages[i].text.toLowerCase().contains(q) ||
                (messages[i].fileName?.toLowerCase().contains(q) ?? false)))
          i,
    ];
  }

  void _onSearchChanged() {
    final messages = _chat.messagesFor(conversationId);
    final matches = _searchMatches(messages);
    // Start at the newest match, WhatsApp-style, and work backwards.
    setState(() => _searchPos = matches.isEmpty ? 0 : matches.length - 1);
    if (matches.isNotEmpty) _goToMatch(messages, matches, matches.length - 1);
  }

  void _stepSearch(int delta) {
    final messages = _chat.messagesFor(conversationId);
    final matches = _searchMatches(messages);
    if (matches.isEmpty) return;
    final pos = (_searchPos + delta).clamp(0, matches.length - 1);
    setState(() => _searchPos = pos);
    _goToMatch(messages, matches, pos);
  }

  void _goToMatch(List<Message> messages, List<int> matches, int pos) {
    final index = matches[pos];
    _flash(messages[index].id);
    if (_itemScroll.isAttached) {
      _itemScroll.scrollTo(
        index: index,
        alignment: 0.3,
        duration: const Duration(milliseconds: 200),
        curve: Curves.easeOut,
      );
    }
  }

  void _closeSearch() {
    _searchInput.clear();
    setState(() {
      _searching = false;
      _searchPos = 0;
    });
  }

  static const _quickReactions = ['👍', '❤️', '😂', '😮', '😢', '🔥'];

  void _showMessageSheet(Message m) {
    final chat = context.read<ChatState>();
    if (m.deleted) return;
    HapticFeedback.mediumImpact();
    // Local rows (call epitaphs, system notices): delete-for-me only.
    final isLocalRow =
        m.kind == MessageKind.call || m.kind == MessageKind.notice;
    // A blocked DM is read-only: anything that would send to the blocked
    // peer is withheld (forwarding elsewhere and delete-for-me stay).
    final blocked = !isGroup && chat.isBlocked(widget.contact!.stonechatId);
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
            if (!isLocalRow && !blocked)
              Padding(
                padding: const EdgeInsets.symmetric(
                  vertical: 10,
                  horizontal: 16,
                ),
                child: Row(
                  mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                  children: [
                    for (final emoji in _quickReactions)
                      GestureDetector(
                        onTap: () {
                          Navigator.pop(sheetContext);
                          HapticFeedback.selectionClick();
                          chat.react(m, emoji);
                        },
                        child: Container(
                          padding: const EdgeInsets.all(6),
                          decoration: BoxDecoration(
                            color: myEmoji == emoji ? Zn.raised : null,
                            borderRadius: BorderRadius.circular(Zn.radius),
                            border: myEmoji == emoji
                                ? Border.all(color: Zn.orange)
                                : null,
                          ),
                          child: Text(
                            emoji,
                            style: const TextStyle(fontSize: 24),
                          ),
                        ),
                      ),
                    // The full collection lives one tap further.
                    GestureDetector(
                      onTap: () {
                        Navigator.pop(sheetContext);
                        _showEmojiPicker(m);
                      },
                      child: Container(
                        width: 36,
                        height: 36,
                        decoration: BoxDecoration(
                          color: Zn.raised,
                          borderRadius: BorderRadius.circular(Zn.radius),
                          border: Border.all(color: Zn.line),
                        ),
                        child: const Icon(Icons.add, size: 20, color: Zn.muted),
                      ),
                    ),
                  ],
                ),
              ),
            if (!isLocalRow && !blocked) const Divider(height: 1),
            if (!isLocalRow && !blocked)
              ListTile(
                leading: const Icon(Icons.reply_outlined, color: Zn.muted),
                title: const Text('Reply'),
                onTap: () {
                  Navigator.pop(sheetContext);
                  _startReply(m);
                },
              ),
            if (m.kind == MessageKind.text)
              ListTile(
                leading: const Icon(Icons.copy_outlined, color: Zn.muted),
                title: const Text('Copy'),
                onTap: () {
                  Clipboard.setData(ClipboardData(text: m.text));
                  Navigator.pop(sheetContext);
                },
              ),
            if (m.status == MessageStatus.failed)
              ListTile(
                leading: const Icon(Icons.refresh, color: Zn.orange),
                title: const Text('Try again'),
                subtitle: m.failReason == null
                    ? null
                    : Text(m.failReason!, style: Zn.mono(size: 10)),
                onTap: () {
                  Navigator.pop(sheetContext);
                  chat.retryMessage(m);
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
            if (chat.canEdit(m) && !blocked)
              ListTile(
                leading: const Icon(Icons.edit_outlined, color: Zn.orange),
                title: const Text('Edit'),
                onTap: () {
                  Navigator.pop(sheetContext);
                  _startEdit(m);
                },
              ),
            if (chat.canDeleteForEveryone(m) &&
                !isLocalRow &&
                !blocked &&
                !isNotes)
              ListTile(
                leading: const Icon(Icons.delete_outline, color: Zn.danger),
                title: const Text(
                  'Delete for everyone',
                  style: TextStyle(color: Zn.danger),
                ),
                onTap: () async {
                  Navigator.pop(sheetContext);
                  final reachedEveryone = await chat.deleteMessageForEveryone(
                    m,
                  );
                  if (!reachedEveryone && mounted) {
                    showZnSnack(
                      context,
                      "Couldn't reach everyone — some may still see it",
                      error: true,
                    );
                  }
                },
              ),
            if (isGroup && !m.outgoing && !isLocalRow && m.senderId != null)
              _blockSenderTile(chat, m, sheetContext),
            ListTile(
              leading: const Icon(Icons.delete_sweep_outlined, color: Zn.muted),
              title: Text(isNotes ? 'Delete' : 'Delete for me'),
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

  /// Block (or unblock) whoever sent [m] in a group — contact or not. Their
  /// messages stay in the room, collapsed; see ChatState.setBlocked.
  Widget _blockSenderTile(
    ChatState chat,
    Message m,
    BuildContext sheetContext,
  ) {
    final senderId = m.senderId!;
    final name =
        chat.memberOf(m.contactId, senderId)?.displayName ?? 'this member';
    final blocked = chat.isBlocked(senderId);
    return ListTile(
      leading: Icon(
        blocked ? Icons.lock_open_outlined : Icons.block,
        color: blocked ? Zn.muted : Zn.danger,
      ),
      title: Text(
        blocked ? 'Unblock $name' : 'Block $name',
        style: TextStyle(color: blocked ? null : Zn.danger),
      ),
      onTap: () {
        Navigator.pop(sheetContext);
        chat.setBlocked(senderId, !blocked);
      },
    );
  }

  /// React with anything: the full categorized emoji collection, with
  /// search and recents, WhatsApp-style.
  void _showEmojiPicker(Message m) {
    final chat = context.read<ChatState>();
    showModalBottomSheet<void>(
      context: context,
      backgroundColor: Zn.surface,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(8)),
      ),
      builder: (sheetContext) => SafeArea(
        child: EmojiPicker(
          onEmojiSelected: (category, emoji) {
            Navigator.pop(sheetContext);
            HapticFeedback.selectionClick();
            chat.react(m, emoji.emoji);
          },
          config: const Config(
            height: 320,
            checkPlatformCompatibility: true,
            emojiViewConfig: EmojiViewConfig(
              backgroundColor: Zn.surface,
              emojiSizeMax: 28,
            ),
            categoryViewConfig: CategoryViewConfig(
              backgroundColor: Zn.surface,
              indicatorColor: Zn.orange,
              iconColorSelected: Zn.orange,
              dividerColor: Zn.line,
            ),
            bottomActionBarConfig: BottomActionBarConfig(enabled: false),
            searchViewConfig: SearchViewConfig(
              backgroundColor: Zn.surface,
              buttonIconColor: Zn.muted,
            ),
          ),
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
      showZnSnack(
        context,
        'That file is no longer on this device',
        error: true,
      );
      return;
    }
    // No forwarding to blocked contacts — the composer is closed to them too.
    final contacts = [
      // Saving something to your own notes is the most common forward there
      // is, so it leads — except from inside the notes themselves.
      if (!isNotes) ?chat.notesToSelf,
      ...chat.acceptedContacts.where((c) => !chat.isBlocked(c.stonechatId)),
    ];
    final groups = isMedia ? const <Group>[] : chat.groups;
    if (contacts.isEmpty && groups.isEmpty) {
      showZnSnack(context, 'No one to forward to yet');
      return;
    }

    Future<void> forward({
      Contact? toContact,
      Group? toGroup,
      required String name,
    }) async {
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
            maxHeight: MediaQuery.of(sheetContext).size.height * 0.6,
          ),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Padding(
                padding: const EdgeInsets.fromLTRB(16, 14, 16, 6),
                child: Align(
                  alignment: Alignment.centerLeft,
                  child: Text(
                    'FORWARD TO',
                    style: Zn.mono(size: 10, letterSpacing: 2),
                  ),
                ),
              ),
              if (isMedia)
                Padding(
                  padding: const EdgeInsets.fromLTRB(16, 0, 16, 6),
                  child: Align(
                    alignment: Alignment.centerLeft,
                    child: Text(
                      'Photos, videos, documents and voice notes can only go to direct chats',
                      style: Zn.mono(size: 9, color: Zn.muted),
                    ),
                  ),
                ),
              Flexible(
                child: ListView(
                  shrinkWrap: true,
                  children: [
                    for (final c in contacts)
                      ListTile(
                        leading: chat.isNotesToSelf(c.stonechatId)
                            ? const NotesAvatar(size: 34)
                            : StonechatAvatar(
                                stonechatId: c.stonechatId,
                                name: c.displayName,
                                size: 34,
                                image: c.avatar,
                              ),
                        title: Text(c.displayName),
                        onTap: () {
                          Navigator.pop(sheetContext);
                          forward(toContact: c, name: c.displayName);
                        },
                      ),
                    for (final g in groups)
                      ListTile(
                        leading: StonechatAvatar(
                          stonechatId: g.id,
                          name: '◈ ${g.name}',
                          size: 34,
                        ),
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

  /// Wipe this conversation's history here, keeping the conversation.
  ///
  /// The dialog says what it does *and* what it does not: people expect
  /// "clear" to reach the other person, and it never can — their copy is
  /// theirs. Saying so up front is cheaper than the support conversation
  /// after, and honest about what a local history actually means.
  Future<void> _clearChat() async {
    final chat = context.read<ChatState>();
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        backgroundColor: Zn.surface,
        title: Text(isNotes ? 'Clear your notes?' : 'Clear this chat?'),
        content: Text(
          isNotes
              ? 'Every note and attachment here is deleted from your devices. '
                    'Notes to self stays, ready for the next one.'
              : 'Every message and attachment here is deleted from your devices. '
                    'The conversation and the contact stay, so you can keep '
                    'talking.\n\n'
                    "The other person keeps their copy — nothing here can reach it.",
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(dialogContext, false),
            child: const Text('Cancel'),
          ),
          TextButton(
            onPressed: () => Navigator.pop(dialogContext, true),
            child: const Text('Clear', style: TextStyle(color: Zn.danger)),
          ),
        ],
      ),
    );
    if (confirmed != true) return;
    await chat.clearChat(conversationId);
    if (mounted) showZnSnack(context, 'Chat cleared');
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
                child: Text(
                  'DISAPPEARING MESSAGES',
                  style: Zn.mono(size: 10, letterSpacing: 2),
                ),
              ),
            ),
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 0, 16, 6),
              child: Align(
                alignment: Alignment.centerLeft,
                child: Text(
                  'New messages will vanish for everyone after the selected time',
                  style: Zn.mono(size: 9, color: Zn.muted),
                ),
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
                      activeColor: Zn.orange,
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
        .map(
          (id) => chat.memberOf(conversationId, id)?.displayName ?? 'someone',
        )
        .toList();
    return '${names.join(', ')} ${names.length == 1 ? 'is' : 'are'} typing ···';
  }

  void _showAttachSheet() {
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
              leading: const Icon(Icons.photo_camera_outlined, color: Zn.muted),
              title: const Text('Camera'),
              onTap: () {
                Navigator.pop(sheetContext);
                _sendPhoto(ImageSource.camera);
              },
            ),
            ListTile(
              leading: const Icon(Icons.photo_outlined, color: Zn.muted),
              title: const Text('Photo'),
              onTap: () {
                Navigator.pop(sheetContext);
                _sendPhoto(ImageSource.gallery);
              },
            ),
            ListTile(
              leading: const Icon(Icons.videocam_outlined, color: Zn.muted),
              title: const Text('Video'),
              onTap: () {
                Navigator.pop(sheetContext);
                _sendVideo();
              },
            ),
            ListTile(
              leading: const Icon(Icons.description_outlined, color: Zn.muted),
              title: const Text('Document'),
              onTap: () {
                Navigator.pop(sheetContext);
                _sendFile();
              },
            ),
          ],
        ),
      ),
    );
  }

  /// The one outgoing-attachment path for both conversation kinds: a DM parks
  /// its ciphertext on the recipient's mailbox, a group parks one copy on ours
  /// and hands every member a token for it (PROTOCOL.md "Group media").
  Future<void> _sendAttachment(
    String path, {
    required String kind,
    required String mime,
    int? durationMs,
    String? fileName,
  }) async {
    final chat = context.read<ChatState>();
    final replyTo = _takeReply();
    final sent = isGroup
        ? await chat.sendGroupMedia(
            widget.group!,
            path,
            kind: kind,
            mime: mime,
            durationMs: durationMs,
            fileName: fileName,
            replyTo: replyTo,
          )
        : await chat.sendMedia(
            widget.contact!,
            path,
            kind: kind,
            mime: mime,
            durationMs: durationMs,
            fileName: fileName,
            replyTo: replyTo,
          );
    _reportSendTrouble(sent);
    _scrollToEnd();
  }

  Future<void> _sendPhoto(ImageSource source) async {
    final picked = await ImagePicker().pickImage(
      source: source,
      maxWidth: 1600,
      imageQuality: 82,
    );
    if (picked == null || !mounted) return;
    await _sendAttachment(
      picked.path,
      kind: MessageKind.image,
      mime: 'image/jpeg',
    );
  }

  Future<void> _sendVideo() async {
    final picked = await ImagePicker().pickVideo(source: ImageSource.gallery);
    if (picked == null || !mounted) return;
    if (!await _fitsBlobCap(picked.path)) return;
    // Probe the duration for the bubble label — best-effort, the video
    // still sends without it.
    int? durationMs;
    try {
      final probe = VideoPlayerController.file(File(picked.path));
      await probe.initialize();
      durationMs = probe.value.duration.inMilliseconds;
      await probe.dispose();
    } catch (_) {}
    if (!mounted) return;
    await _sendAttachment(
      picked.path,
      kind: MessageKind.video,
      mime: picked.path.toLowerCase().endsWith('.mov')
          ? 'video/quicktime'
          : 'video/mp4',
      durationMs: durationMs,
    );
  }

  Future<void> _sendFile() async {
    final result = await FilePicker.pickFiles();
    final file = result?.files.single;
    if (file?.path == null || !mounted) return;
    if (!await _fitsBlobCap(file!.path!)) return;
    if (!mounted) return;
    await _sendAttachment(
      file.path!,
      kind: MessageKind.file,
      mime: 'application/octet-stream',
      fileName: file.name,
    );
  }

  /// The relay caps blobs (PROTOCOL.md) — fail with words, not a 413.
  Future<bool> _fitsBlobCap(String path) async {
    final size = await File(path).length();
    if (size <= ChatState.maxBlobBytes) return true;
    if (mounted) {
      showZnSnack(
        context,
        'Too big — attachments can be at most ${ChatState.maxBlobBytes ~/ (1024 * 1024)} MB',
        error: true,
      );
    }
    return false;
  }

  void _showStickerPicker() {
    final store = StickerStore.instance;
    unawaited(store.load());
    showModalBottomSheet<void>(
      context: context,
      backgroundColor: Zn.surface,
      isScrollControlled: true,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(8)),
      ),
      builder: (sheetContext) => SafeArea(
        child: SizedBox(
          height: 400,
          child: ListenableBuilder(
            listenable: store,
            builder: (context, _) {
              final packs = [
                if (store.recents.isNotEmpty)
                  StickerPack(
                    name: 'Recent',
                    bundled: true,
                    refs: store.recents,
                  ),
                ...store.packs,
              ];
              if (packs.isEmpty) {
                return Center(
                  child: Text(
                    'No stickers yet — import some below',
                    style: Zn.mono(size: 11, color: Zn.muted),
                  ),
                );
              }
              return DefaultTabController(
                length: packs.length,
                child: Column(
                  children: [
                    Row(
                      children: [
                        Expanded(
                          child: TabBar(
                            isScrollable: true,
                            tabAlignment: TabAlignment.start,
                            indicatorColor: Zn.orange,
                            labelColor: Zn.orange,
                            unselectedLabelColor: Zn.muted,
                            labelStyle: Zn.mono(size: 10, letterSpacing: 1),
                            dividerColor: Zn.line,
                            tabs: [
                              for (final pack in packs)
                                Tab(text: pack.name.toUpperCase(), height: 40),
                            ],
                          ),
                        ),
                        IconButton(
                          icon: const Icon(
                            Icons.add_photo_alternate_outlined,
                            color: Zn.muted,
                            size: 20,
                          ),
                          tooltip: 'Import stickers (transparent WebP/PNG)',
                          onPressed: () => _importStickers(sheetContext),
                        ),
                      ],
                    ),
                    Expanded(
                      child: TabBarView(
                        children: [
                          for (final pack in packs)
                            GridView.builder(
                              padding: const EdgeInsets.all(12),
                              gridDelegate:
                                  const SliverGridDelegateWithFixedCrossAxisCount(
                                    crossAxisCount: 4,
                                    mainAxisSpacing: 10,
                                    crossAxisSpacing: 10,
                                  ),
                              itemCount: pack.refs.length,
                              itemBuilder: (context, i) => GestureDetector(
                                onTap: () {
                                  Navigator.pop(sheetContext);
                                  _sendSticker(pack.refs[i]);
                                },
                                child: Image(
                                  image: store.imageFor(pack.refs[i]),
                                  fit: BoxFit.contain,
                                ),
                              ),
                            ),
                        ],
                      ),
                    ),
                  ],
                ),
              );
            },
          ),
        ),
      ),
    );
  }

  Future<void> _importStickers(BuildContext sheetContext) async {
    final result = await FilePicker.pickFiles(
      allowMultiple: true,
      type: FileType.custom,
      allowedExtensions: ['webp', 'png', 'jpg', 'jpeg'],
    );
    final paths =
        result?.files.map((f) => f.path).whereType<String>().toList() ?? [];
    if (paths.isEmpty) return;
    await StickerStore.instance.importFiles(paths);
    if (sheetContext.mounted) {
      showZnSnack(
        sheetContext,
        'Imported ${paths.length} ${paths.length == 1 ? 'sticker' : 'stickers'}',
      );
    }
  }

  Future<void> _sendSticker(String ref) async {
    final store = StickerStore.instance;
    final file = await store.materialize(ref);
    await store.recordRecent(ref);
    if (!mounted) return;
    final mime = switch (p.extension(file.path).toLowerCase()) {
      '.png' => 'image/png',
      '.jpg' || '.jpeg' => 'image/jpeg',
      _ => 'image/webp',
    };
    await _sendAttachment(file.path, kind: MessageKind.sticker, mime: mime);
  }

  Future<void> _sendVoice(String path, int durationMs) async {
    await _sendAttachment(
      path,
      kind: MessageKind.audio,
      mime: 'audio/mp4',
      durationMs: durationMs,
    );
  }

  void _scrollToEnd() {
    // Post-frame: a just-sent message is in state but not yet in the list.
    WidgetsBinding.instance.addPostFrameCallback((_) {
      final count = _chat.messagesFor(conversationId).length;
      if (count == 0 || !_itemScroll.isAttached) return;
      // scrollTo(index) aims the item's TOP edge at the viewport top — for
      // the last message that offset lies past the end of the list, so the
      // animation overshoots and bounces back. When the newest message is
      // already laid out (the normal case: we were at the bottom and it
      // appeared just below the fold), scroll by the exact distance that
      // puts its bottom edge flush with the end instead.
      ItemPosition? last;
      for (final pos in _itemPositions.itemPositions.value) {
        if (pos.index == count - 1) {
          last = pos;
          break;
        }
      }
      final viewport = _listKey.currentContext?.size?.height;
      if (last != null && viewport != null) {
        // +12 covers the list's bottom padding, landing on the true end.
        final delta = (last.itemTrailingEdge - 1) * viewport + 12;
        if (delta > 0) {
          _scrollOffset.animateScroll(
            offset: delta,
            duration: const Duration(milliseconds: 200),
            curve: Curves.easeOut,
          );
        }
        return;
      }
      // Sent from far up in history: fall back to the index-based scroll.
      _itemScroll.scrollTo(
        index: count - 1,
        duration: const Duration(milliseconds: 200),
        curve: Curves.easeOut,
      );
    });
  }

  /// Who wrote [stonechatId]'s messages, for quote headers: "You", a member's
  /// name, or the DM peer.
  String _senderName(String? stonechatId, ChatState chat) {
    if (stonechatId == null) {
      return isGroup ? 'someone' : widget.contact!.displayName;
    }
    if (stonechatId == chat.app.stonechatId) return 'You';
    if (isGroup) {
      return chat.memberOf(conversationId, stonechatId)?.displayName ??
          'former member';
    }
    return widget.contact!.displayName;
  }

  /// The search-mode app bar: query field, match counter, older/newer.
  PreferredSizeWidget _searchAppBar(List<Message> messages) {
    final matches = _searchMatches(messages);
    final pos = matches.isEmpty ? 0 : _searchPos.clamp(0, matches.length - 1);
    return AppBar(
      leading: IconButton(
        icon: const Icon(Icons.arrow_back, color: Zn.muted),
        onPressed: _closeSearch,
      ),
      titleSpacing: 0,
      title: TextField(
        controller: _searchInput,
        autofocus: true,
        onChanged: (_) => _onSearchChanged(),
        style: const TextStyle(color: Zn.text, fontSize: 15),
        decoration: InputDecoration(
          hintText: 'search ›',
          hintStyle: Zn.mono(size: 13),
          border: InputBorder.none,
          enabledBorder: InputBorder.none,
          focusedBorder: InputBorder.none,
          filled: false,
        ),
      ),
      actions: [
        if (_searchInput.text.trim().isNotEmpty)
          Padding(
            padding: const EdgeInsets.only(right: 2),
            child: Center(
              child: Text(
                matches.isEmpty ? '0/0' : '${pos + 1}/${matches.length}',
                style: Zn.mono(size: 11, color: Zn.muted),
              ),
            ),
          ),
        IconButton(
          icon: const Icon(Icons.keyboard_arrow_up, color: Zn.muted),
          tooltip: 'Older match',
          onPressed: () => _stepSearch(-1),
        ),
        IconButton(
          icon: const Icon(Icons.keyboard_arrow_down, color: Zn.muted),
          tooltip: 'Newer match',
          onPressed: () => _stepSearch(1),
        ),
      ],
    );
  }

  @override
  Widget build(BuildContext context) {
    final chat = context.watch<ChatState>();
    final messages = chat.messagesFor(conversationId);
    final title = widget.contact?.displayName ?? widget.group!.name;
    final memberCount = isGroup
        ? chat.groupMembers[conversationId]?.length
        : null;
    final searchQuery = _searching ? _searchInput.text.trim() : '';

    // First frame with content: land on the newest message.
    if (!_jumpedToEnd && messages.isNotEmpty) {
      _jumpedToEnd = true;
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (mounted && _itemScroll.isAttached) {
          _itemScroll.jumpTo(index: messages.length - 1);
        }
      });
    }

    return Scaffold(
      appBar: _searching
          ? _searchAppBar(messages)
          : AppBar(
              titleSpacing: 0,
              title: GestureDetector(
                // Group header opens the member ledger, WhatsApp-style.
                onTap: isGroup
                    ? () => Navigator.push(
                        context,
                        MaterialPageRoute(
                          builder: (_) => GroupInfoScreen(group: widget.group!),
                        ),
                      )
                    : null,
                child: Row(
                  children: [
                    if (isNotes)
                      const NotesAvatar(size: 32)
                    else
                      StonechatAvatar(
                        stonechatId: conversationId,
                        name: isGroup ? '◈ ${widget.group!.name}' : title,
                        size: 32,
                        image: widget.contact?.avatar,
                      ),
                    const SizedBox(width: 10),
                    // A name is the contact's own choice and any length;
                    // the action buttons are not. Ellipsis beats overflow.
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            title,
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                            style: const TextStyle(fontSize: 16),
                          ),
                          Row(
                            children: [
                              if (chat.expireTimerFor(conversationId) > 0)
                                const Padding(
                                  padding: EdgeInsets.only(right: 3),
                                  child: Icon(
                                    Icons.timer_outlined,
                                    size: 11,
                                    color: Zn.muted,
                                  ),
                                ),
                              Text(
                                isGroup
                                    ? '$memberCount members'
                                    : isNotes
                                    ? 'ONLY YOU'
                                    : widget.contact!.stonechatId.substring(
                                        0,
                                        12,
                                      ),
                                style: Zn.mono(size: 9, letterSpacing: 1),
                              ),
                            ],
                          ),
                        ],
                      ),
                    ),
                  ],
                ),
              ),
              actions: [
                if (!isGroup &&
                    !isNotes &&
                    !chat.isBlocked(widget.contact!.stonechatId)) ...[
                  IconButton(
                    icon: const Icon(
                      Icons.call_outlined,
                      color: Zn.muted,
                      size: 22,
                    ),
                    tooltip: 'Voice call',
                    onPressed: () => context.read<CallState>().startCall(
                      widget.contact!,
                      video: false,
                    ),
                  ),
                  IconButton(
                    icon: const Icon(
                      Icons.videocam_outlined,
                      color: Zn.muted,
                      size: 22,
                    ),
                    tooltip: 'Video call',
                    onPressed: () => context.read<CallState>().startCall(
                      widget.contact!,
                      video: true,
                    ),
                  ),
                ],
                PopupMenuButton<String>(
                  color: Zn.raised,
                  icon: const Icon(Icons.more_vert, color: Zn.muted),
                  onSelected: (value) async {
                    if (value == 'search') {
                      setState(() => _searching = true);
                      return;
                    }
                    if (value == 'timer') {
                      _showTimerSheet();
                      return;
                    }
                    if (value == 'clear') {
                      await _clearChat();
                      return;
                    }
                    if (value == 'info') {
                      await Navigator.push(
                        context,
                        MaterialPageRoute(
                          builder: (_) => GroupInfoScreen(group: widget.group!),
                        ),
                      );
                      return;
                    }
                    if (value == 'block') {
                      await chat.toggleBlock(widget.contact!);
                      return;
                    }
                    if (value == 'report') {
                      final contact = widget.contact!;
                      final outcome = await showReportSheet(
                        context,
                        stonechatId: contact.stonechatId,
                        displayName: contact.displayName,
                        hub: contact.hub,
                        conversation: chat.messagesFor(contact.stonechatId),
                        canBlock: !chat.isBlocked(contact.stonechatId),
                      );
                      if (outcome.alsoBlock &&
                          !chat.isBlocked(contact.stonechatId)) {
                        await chat.toggleBlock(contact);
                      }
                      return;
                    }
                    if (value == 'leave') {
                      await chat.leaveGroup(widget.group!);
                      if (context.mounted) Navigator.pop(context);
                    }
                  },
                  itemBuilder: (_) => [
                    if (isGroup)
                      const PopupMenuItem(
                        value: 'info',
                        child: Text('Group info'),
                      ),
                    const PopupMenuItem(value: 'search', child: Text('Search')),
                    if (!isNotes)
                      const PopupMenuItem(
                        value: 'timer',
                        child: Text('Disappearing messages'),
                      ),
                    const PopupMenuItem(
                      value: 'clear',
                      child: Text('Clear chat'),
                    ),
                    if (!isGroup && !isNotes)
                      PopupMenuItem(
                        value: 'block',
                        child: chat.isBlocked(widget.contact!.stonechatId)
                            ? const Text('Unblock')
                            : const Text(
                                'Block',
                                style: TextStyle(color: Zn.danger),
                              ),
                      ),
                    if (!isGroup && !isNotes)
                      const PopupMenuItem(
                        value: 'report',
                        child: Text(
                          'Report',
                          style: TextStyle(color: Zn.danger),
                        ),
                      ),
                    if (isGroup)
                      const PopupMenuItem(
                        value: 'leave',
                        child: Text(
                          'Leave group',
                          style: TextStyle(color: Zn.danger),
                        ),
                      ),
                  ],
                ),
              ],
            ),
      body: Column(
        children: [
          Expanded(
            // Starting to drag the history tucks the keyboard away.
            child: NotificationListener<ScrollStartNotification>(
              onNotification: (notification) {
                if (notification.dragDetails != null) {
                  FocusManager.instance.primaryFocus?.unfocus();
                }
                return false;
              },
              child: ScrollablePositionedList.builder(
                key: _listKey,
                itemScrollController: _itemScroll,
                itemPositionsListener: _itemPositions,
                scrollOffsetController: _scrollOffset,
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
                      ? Zn.orange
                      : Zn.idColor(
                          isGroup ? (m.senderId ?? '') : conversationId,
                        );
                  if (m.kind == MessageKind.notice) {
                    return _arrive(
                      m,
                      GestureDetector(
                        onLongPress: () => _showMessageSheet(m),
                        behavior: HitTestBehavior.opaque,
                        child: Padding(
                          padding: const EdgeInsets.symmetric(vertical: 10),
                          child: Row(
                            mainAxisAlignment: MainAxisAlignment.center,
                            children: [
                              Icon(
                                m.text.contains('disappearing messages')
                                    ? Icons.timer_outlined
                                    : Icons.info_outline,
                                size: 11,
                                color: Zn.muted,
                              ),
                              const SizedBox(width: 5),
                              Flexible(
                                child: Text(
                                  m.text,
                                  textAlign: TextAlign.center,
                                  style: Zn.mono(size: 10, color: Zn.muted),
                                ),
                              ),
                            ],
                          ),
                        ),
                      ),
                    );
                  }
                  if (isGroup &&
                      !m.outgoing &&
                      chat.isBlocked(m.senderId ?? '') &&
                      !_revealed.contains(m.id)) {
                    return _arrive(
                      m,
                      _BlockedMessage(
                        onReveal: () => setState(() => _revealed.add(m.id)),
                      ),
                    );
                  }
                  return _arrive(
                    m,
                    Column(
                      crossAxisAlignment: CrossAxisAlignment.stretch,
                      children: [
                        if (previous != null) _GapMarker.between(previous, m),
                        GestureDetector(
                          onLongPress: () => _showMessageSheet(m),
                          behavior: HitTestBehavior.opaque,
                          child: AnimatedContainer(
                            duration: const Duration(milliseconds: 300),
                            color: _flashId == m.id
                                ? Zn.orange.withValues(alpha: 0.08)
                                : Colors.transparent,
                            child: _LedgerEntry(
                              message: m,
                              peerName: senderName,
                              peerColor: railColor,
                              // A notice breaks the run: re-show the sender after it.
                              showSender:
                                  previous == null ||
                                  previous.kind == MessageKind.notice ||
                                  previous.outgoing != m.outgoing ||
                                  previous.senderId != m.senderId,
                              reactions:
                                  chat.reactionsByMessage[m.id] ?? const {},
                              myEmoji: chat.myReactionTo(m),
                              onReact: (emoji) {
                                HapticFeedback.selectionClick();
                                chat.react(m, emoji);
                              },
                              quoteSender: m.replyToId == null
                                  ? null
                                  : _senderName(m.replyToSender, chat),
                              onQuoteTap: m.replyToId == null
                                  ? null
                                  : () => _jumpToMessage(m.replyToId!),
                              searchQuery: searchQuery,
                              owed: isGroup ? chat.owedFor(m.id) : 0,
                              // Fan-out targets, so everyone but us.
                              memberCount: isGroup ? (memberCount ?? 1) - 1 : 0,
                              onRetry: m.status == MessageStatus.failed
                                  ? () => chat.retryMessage(m)
                                  : null,
                            ),
                          ),
                        ),
                      ],
                    ),
                  );
                },
              ),
            ),
          ),
          if (_typingLabel(chat).isNotEmpty)
            Container(
              alignment: Alignment.centerLeft,
              padding: const EdgeInsets.fromLTRB(16, 0, 16, 6),
              child: Text(
                _typingLabel(chat),
                style: Zn.mono(size: 10, color: Zn.amber, letterSpacing: 1),
              ),
            ),
          if (_editing != null)
            Container(
              color: Zn.surface,
              padding: const EdgeInsets.fromLTRB(16, 6, 4, 0),
              child: Row(
                children: [
                  const Icon(Icons.edit_outlined, size: 14, color: Zn.orange),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      'Editing message',
                      style: Zn.mono(
                        size: 10,
                        color: Zn.orange,
                        letterSpacing: 1,
                      ),
                    ),
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
          if (_replyingTo != null)
            Container(
              color: Zn.surface,
              padding: const EdgeInsets.fromLTRB(16, 6, 4, 0),
              child: Row(
                children: [
                  const Icon(Icons.reply_outlined, size: 14, color: Zn.orange),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          _senderName(
                            _replyingTo!.outgoing
                                ? chat.app.stonechatId
                                : (_replyingTo!.senderId ??
                                      _replyingTo!.contactId),
                            chat,
                          ).toUpperCase(),
                          style: Zn.mono(
                            size: 9,
                            color: Zn.orange,
                            letterSpacing: 1,
                          ),
                        ),
                        Text(
                          _replyingTo!.preview,
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                          style: const TextStyle(fontSize: 12, color: Zn.muted),
                        ),
                      ],
                    ),
                  ),
                  IconButton(
                    icon: const Icon(Icons.close, size: 16, color: Zn.muted),
                    onPressed: () => setState(() => _replyingTo = null),
                  ),
                ],
              ),
            ),
          if (!isGroup && chat.isBlocked(widget.contact!.stonechatId))
            Container(
              decoration: const BoxDecoration(
                color: Zn.surface,
                border: Border(top: BorderSide(color: Zn.line)),
              ),
              padding: EdgeInsets.only(
                left: 16,
                right: 8,
                top: 6,
                bottom: 6 + MediaQuery.of(context).padding.bottom,
              ),
              child: Row(
                children: [
                  const Icon(Icons.block, size: 14, color: Zn.danger),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      'You blocked $title',
                      style: Zn.mono(size: 10, color: Zn.muted),
                    ),
                  ),
                  TextButton(
                    onPressed: () => chat.toggleBlock(widget.contact!),
                    child: Text(
                      'UNBLOCK',
                      style: Zn.mono(
                        size: 10,
                        color: Zn.orange,
                        letterSpacing: 1,
                      ),
                    ),
                  ),
                ],
              ),
            )
          else
            _Composer(
              controller: _input,
              onSend: _send,
              onTyping: _editing == null
                  ? () => context.read<ChatState>().notifyTyping(conversationId)
                  : null,
              onAttach: _showAttachSheet,
              onSticker: _showStickerPicker,
              onVoiceRecorded: _sendVoice,
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
  final Map<String, String> reactions; // reactor Stonechat ID → emoji
  final String? myEmoji;
  final void Function(String emoji)? onReact;
  final String? quoteSender; // display name for the reply_to header
  final VoidCallback? onQuoteTap;
  final String searchQuery; // non-empty → highlight matches in the text
  /// Groups: members whose mailboxes haven't taken this message yet, and how
  /// many there are in total. 0 owed → it reached everyone.
  final int owed;
  final int memberCount;
  final VoidCallback? onRetry; // failed messages only

  const _LedgerEntry({
    required this.message,
    required this.peerName,
    required this.peerColor,
    required this.showSender,
    this.reactions = const {},
    this.myEmoji,
    this.onReact,
    this.quoteSender,
    this.onQuoteTap,
    this.searchQuery = '',
    this.owed = 0,
    this.memberCount = 0,
    this.onRetry,
  });

  /// The line under an outgoing message that hasn't landed cleanly. Null while
  /// everything is normal — a message on its way needs no commentary, and the
  /// glyph already carries "sent" and "read".
  ///
  /// Silence here was the whole complaint: a mailbox off for an hour and one
  /// gone for six months both rendered as `◌` forever.
  String? get _troubleLine {
    if (!message.outgoing || message.deleted) return null;
    final age = sendAgeLabel(
      DateTime.now().millisecondsSinceEpoch - message.sentAt,
    );
    final why = message.failReason;

    if (message.status == MessageStatus.failed) {
      final head = age == null ? 'not sent' : 'not sent · $age';
      return why == null ? head : '$head — $why';
    }
    // A group is never failed by one dead mailbox out of five — say what
    // actually happened instead of condemning the whole message.
    if (owed > 0 && memberCount > 0) {
      final progress = 'sent to ${memberCount - owed} of $memberCount';
      return age == null ? progress : '$progress · $age';
    }
    // Still queued after a real wait. Below five minutes sendAgeLabel returns
    // null and we stay quiet: a blip that the next sweep clears is not worth
    // a line of its own.
    if (message.status == MessageStatus.pending &&
        message.attempts > 0 &&
        age != null) {
      return why == null ? 'sending · $age' : 'sending · $age — $why';
    }
    return null;
  }

  /// The message text as spans, query matches tinted.
  List<TextSpan> _highlighted(String text) {
    if (searchQuery.isEmpty) return [TextSpan(text: text)];
    final lower = text.toLowerCase();
    final q = searchQuery.toLowerCase();
    final spans = <TextSpan>[];
    var start = 0;
    while (start < text.length) {
      final i = lower.indexOf(q, start);
      if (i < 0) {
        spans.add(TextSpan(text: text.substring(start)));
        break;
      }
      if (i > start) spans.add(TextSpan(text: text.substring(start, i)));
      spans.add(
        TextSpan(
          text: text.substring(i, i + q.length),
          style: TextStyle(
            backgroundColor: Zn.orange.withValues(alpha: 0.35),
            color: Zn.text,
          ),
        ),
      );
      start = i + q.length;
    }
    return spans;
  }

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
    final color = message.outgoing ? Zn.orange : peerColor;
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
                      child: Text(
                        sender,
                        style: Zn.mono(
                          size: 9,
                          color: color,
                          weight: FontWeight.w700,
                          letterSpacing: 2,
                        ),
                      ),
                    ),
                  if (!message.deleted && message.replyToId != null)
                    GestureDetector(
                      onTap: onQuoteTap,
                      child: Container(
                        margin: const EdgeInsets.only(bottom: 4),
                        padding: const EdgeInsets.fromLTRB(8, 5, 10, 5),
                        decoration: BoxDecoration(
                          color: Zn.raised,
                          borderRadius: BorderRadius.circular(Zn.radius),
                          border: Border(
                            left: BorderSide(
                              color: color.withValues(alpha: 0.7),
                              width: 2,
                            ),
                          ),
                        ),
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              (quoteSender ?? '').toUpperCase(),
                              style: Zn.mono(
                                size: 8,
                                color: color,
                                weight: FontWeight.w700,
                                letterSpacing: 1,
                              ),
                            ),
                            const SizedBox(height: 1),
                            Text(
                              message.replyToPreview ?? 'Message',
                              maxLines: 2,
                              overflow: TextOverflow.ellipsis,
                              style: const TextStyle(
                                fontSize: 12,
                                color: Zn.muted,
                              ),
                            ),
                          ],
                        ),
                      ),
                    ),
                  if (message.deleted)
                    Text(
                      'message deleted',
                      style: Zn.mono(
                        size: 12,
                      ).copyWith(fontStyle: FontStyle.italic, color: Zn.muted),
                    )
                  else
                    switch (message.kind) {
                      MessageKind.image => _ImageEntry(message: message),
                      MessageKind.audio => _AudioEntry(
                        message: message,
                        color: color,
                      ),
                      MessageKind.video => _VideoEntry(
                        message: message,
                        color: color,
                      ),
                      MessageKind.sticker => _StickerEntry(message: message),
                      MessageKind.file => _FileEntry(
                        message: message,
                        color: color,
                        searchQuery: searchQuery,
                      ),
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
                                : Zn.muted,
                          ),
                          const SizedBox(width: 6),
                          Text(message.text, style: Zn.mono(size: 12)),
                        ],
                      ),
                      _ => Text.rich(
                        TextSpan(
                          children: [
                            ..._highlighted(message.text),
                            if (message.editedAt != null)
                              TextSpan(
                                text: '  · edited',
                                style: Zn.mono(size: 9),
                              ),
                          ],
                        ),
                        style: const TextStyle(
                          color: Zn.text,
                          fontSize: 15,
                          height: 1.35,
                        ),
                      ),
                    },
                  if (_troubleLine case final trouble?)
                    Padding(
                      padding: const EdgeInsets.only(top: 3),
                      child: GestureDetector(
                        onTap: onRetry,
                        child: Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            Icon(
                              message.status == MessageStatus.failed
                                  ? Icons.error_outline
                                  : Icons.schedule,
                              size: 11,
                              color: message.status == MessageStatus.failed
                                  ? Zn.danger
                                  : Zn.muted,
                            ),
                            const SizedBox(width: 4),
                            Flexible(
                              child: Text(
                                onRetry == null
                                    ? trouble
                                    : '$trouble · tap to retry',
                                style: Zn.mono(
                                  size: 9,
                                  color: message.status == MessageStatus.failed
                                      ? Zn.danger
                                      : Zn.muted,
                                ),
                              ),
                            ),
                          ],
                        ),
                      ),
                    ),
                  // Always mounted, even empty: the row tells a reaction that
                  // just arrived from one that was there when it scrolled in.
                  _ReactionRow(
                    counts: _aggregated(),
                    myEmoji: myEmoji,
                    onReact: onReact,
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
                        DateTime.fromMillisecondsSinceEpoch(message.sentAt),
                      ),
                      style: Zn.mono(size: 9),
                    ),
                    if (message.outgoing) ...[
                      const SizedBox(width: 4),
                      // Cross-fade so "it landed" is a moment, not a swap.
                      AnimatedSwitcher(
                        duration: Zn.dur(context, Zn.fast),
                        switchInCurve: Zn.ease,
                        child: Text(
                          switch (message.status) {
                            MessageStatus.pending => '◌',
                            MessageStatus.failed => '✕',
                            MessageStatus.sent => '●',
                            _ => '●●', // delivered / read, read lights up
                          },
                          key: ValueKey(message.status),
                          style: Zn.mono(
                            size: 9,
                            color: switch (message.status) {
                              MessageStatus.read => Zn.amber,
                              MessageStatus.failed => Zn.danger,
                              _ => Zn.muted,
                            },
                          ),
                        ),
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

/// Reaction chips under a message. A chip that is new, or whose count went
/// up, pops once; everything present when the row mounted stays still.
class _ReactionRow extends StatefulWidget {
  final Map<String, int> counts; // emoji → how many reacted with it
  final String? myEmoji;
  final void Function(String emoji)? onReact;

  const _ReactionRow({required this.counts, this.myEmoji, this.onReact});

  @override
  State<_ReactionRow> createState() => _ReactionRowState();
}

class _ReactionRowState extends State<_ReactionRow> {
  final _generation = <String, int>{}; // bumped per pop: a new key restarts it
  final _popping = <String>{};

  @override
  void didUpdateWidget(_ReactionRow old) {
    super.didUpdateWidget(old);
    _popping.clear();
    for (final entry in widget.counts.entries) {
      if (entry.value > (old.counts[entry.key] ?? 0)) {
        _generation[entry.key] = (_generation[entry.key] ?? 0) + 1;
        _popping.add(entry.key);
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    if (widget.counts.isEmpty) return const SizedBox.shrink();
    return Padding(
      padding: const EdgeInsets.only(top: 4),
      child: Wrap(
        spacing: 6,
        runSpacing: 4,
        children: [
          for (final entry in widget.counts.entries)
            TweenAnimationBuilder<double>(
              key: ValueKey('${entry.key}#${_generation[entry.key] ?? 0}'),
              tween: Tween(
                begin: _popping.contains(entry.key) ? 0.85 : 1,
                end: 1,
              ),
              duration: Zn.dur(context, Zn.fast),
              curve: Zn.ease,
              builder: (context, scale, child) =>
                  Transform.scale(scale: scale, child: child),
              child: GestureDetector(
                onTap: () => widget.onReact?.call(entry.key),
                child: Container(
                  padding: const EdgeInsets.symmetric(
                    horizontal: 8,
                    vertical: 2,
                  ),
                  decoration: BoxDecoration(
                    color: Zn.raised,
                    borderRadius: BorderRadius.circular(Zn.radius),
                    border: Border.all(
                      color: widget.myEmoji == entry.key ? Zn.orange : Zn.line,
                    ),
                  ),
                  child: Text(
                    entry.value > 1 ? '${entry.key} ${entry.value}' : entry.key,
                    style: const TextStyle(fontSize: 13, color: Zn.text),
                  ),
                ),
              ),
            ),
        ],
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
        vertical: (12 + gap.inHours.clamp(0, 10) * 2).toDouble(),
      ),
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

/// A sticker: rendered plain at a fixed size — no frame, no background,
/// no zoom dialog. The transparency is the point.
class _StickerEntry extends StatelessWidget {
  final Message message;
  const _StickerEntry({required this.message});

  @override
  Widget build(BuildContext context) {
    final file = File(message.mediaPath ?? '');
    if (!file.existsSync()) {
      return Text('💟 sticker unavailable', style: Zn.mono(size: 12));
    }
    return Padding(
      padding: const EdgeInsets.only(top: 2),
      child: Image.file(
        file,
        width: 160,
        height: 160,
        fit: BoxFit.contain,
        alignment: Alignment.centerLeft,
      ),
    );
  }
}

class _VideoEntry extends StatelessWidget {
  final Message message;
  final Color color;
  const _VideoEntry({required this.message, required this.color});

  static String _fmt(Duration d) =>
      '${d.inMinutes}:${(d.inSeconds % 60).toString().padLeft(2, '0')}';

  @override
  Widget build(BuildContext context) {
    final path = message.mediaPath;
    if (path == null || !File(path).existsSync()) {
      return Text('🎬 video unavailable', style: Zn.mono(size: 12));
    }
    return Padding(
      padding: const EdgeInsets.only(top: 2),
      child: GestureDetector(
        onTap: () => Navigator.of(context).push(
          MaterialPageRoute<void>(builder: (_) => _VideoPlayerPage(path: path)),
        ),
        child: ClipRRect(
          borderRadius: BorderRadius.circular(Zn.radius),
          child: Container(
            width: 240,
            height: 150,
            color: Colors.black,
            child: Stack(
              alignment: Alignment.center,
              children: [
                Container(
                  width: 44,
                  height: 44,
                  decoration: BoxDecoration(
                    color: color.withValues(alpha: 0.15),
                    borderRadius: BorderRadius.circular(Zn.radius),
                    border: Border.all(color: color.withValues(alpha: 0.5)),
                  ),
                  child: Icon(Icons.play_arrow, size: 26, color: color),
                ),
                if (message.durationMs != null)
                  Positioned(
                    right: 8,
                    bottom: 6,
                    child: Text(
                      _fmt(Duration(milliseconds: message.durationMs!)),
                      style: Zn.mono(size: 10, color: Zn.text),
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

/// Full-screen playback; tap toggles play/pause.
class _VideoPlayerPage extends StatefulWidget {
  final String path;
  const _VideoPlayerPage({required this.path});

  @override
  State<_VideoPlayerPage> createState() => _VideoPlayerPageState();
}

class _VideoPlayerPageState extends State<_VideoPlayerPage> {
  late final VideoPlayerController _controller;

  @override
  void initState() {
    super.initState();
    _controller = VideoPlayerController.file(File(widget.path))
      ..initialize().then((_) {
        if (mounted) {
          setState(() {});
          _controller.play();
        }
      });
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.black,
      appBar: AppBar(
        backgroundColor: Colors.black,
        leading: IconButton(
          icon: const Icon(Icons.close, color: Zn.text),
          onPressed: () => Navigator.pop(context),
        ),
      ),
      body: _controller.value.isInitialized
          ? GestureDetector(
              onTap: () => setState(
                () => _controller.value.isPlaying
                    ? _controller.pause()
                    : _controller.play(),
              ),
              child: Column(
                children: [
                  Expanded(
                    child: Center(
                      child: AspectRatio(
                        aspectRatio: _controller.value.aspectRatio,
                        child: VideoPlayer(_controller),
                      ),
                    ),
                  ),
                  SafeArea(
                    top: false,
                    child: VideoProgressIndicator(
                      _controller,
                      allowScrubbing: true,
                      padding: const EdgeInsets.all(12),
                      colors: const VideoProgressColors(
                        playedColor: Zn.orange,
                        backgroundColor: Zn.line,
                      ),
                    ),
                  ),
                ],
              ),
            )
          : const Center(child: CircularProgressIndicator(color: Zn.orange)),
    );
  }
}

/// A document row: icon, name, size — tap opens it with the OS handler.
class _FileEntry extends StatelessWidget {
  final Message message;
  final Color color;
  final String searchQuery;
  const _FileEntry({
    required this.message,
    required this.color,
    this.searchQuery = '',
  });

  static String _sizeLabel(int bytes) => bytes >= 1024 * 1024
      ? '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MB'
      : '${(bytes / 1024).ceil()} KB';

  @override
  Widget build(BuildContext context) {
    final path = message.mediaPath;
    final exists = path != null && File(path).existsSync();
    final name = message.fileName ?? 'Document';
    return Padding(
      padding: const EdgeInsets.only(top: 2),
      child: GestureDetector(
        onTap: !exists
            ? null
            : () async {
                final result = await OpenFilex.open(path);
                if (result.type != ResultType.done && context.mounted) {
                  showZnSnack(
                    context,
                    "Couldn't open ${message.fileName}",
                    error: true,
                  );
                }
              },
        child: _MaxWidth(
          260,
          child: Container(
            padding: const EdgeInsets.all(8),
            decoration: BoxDecoration(
              color: Zn.raised,
              borderRadius: BorderRadius.circular(Zn.radius),
              border: Border.all(color: Zn.line),
            ),
            child: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                Container(
                  width: 34,
                  height: 34,
                  decoration: BoxDecoration(
                    color: color.withValues(alpha: 0.15),
                    borderRadius: BorderRadius.circular(Zn.radius),
                    border: Border.all(color: color.withValues(alpha: 0.5)),
                  ),
                  child: Icon(
                    Icons.description_outlined,
                    size: 18,
                    color: color,
                  ),
                ),
                const SizedBox(width: 10),
                Flexible(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        name,
                        maxLines: 2,
                        overflow: TextOverflow.ellipsis,
                        style: const TextStyle(fontSize: 13, color: Zn.text),
                      ),
                      const SizedBox(height: 2),
                      Text(
                        exists
                            ? _sizeLabel(File(path).lengthSync())
                            : 'no longer on this device',
                        style: Zn.mono(size: 9, color: Zn.muted),
                      ),
                    ],
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

/// A max-width box that also caps the width it reports intrinsics at.
/// `Container(constraints:)` doesn't: under the ledger's IntrinsicHeight the
/// card was measured at full row width (name on one line), then laid out at
/// 260 (name on two), and overflowed into the next message.
class _MaxWidth extends SingleChildRenderObjectWidget {
  final double maxWidth;
  const _MaxWidth(this.maxWidth, {super.child});

  @override
  RenderObject createRenderObject(BuildContext context) =>
      _RenderMaxWidth(maxWidth);

  @override
  void updateRenderObject(BuildContext context, _RenderMaxWidth renderObject) =>
      renderObject.additionalConstraints = BoxConstraints(maxWidth: maxWidth);
}

class _RenderMaxWidth extends RenderConstrainedBox {
  _RenderMaxWidth(double maxWidth)
    : super(additionalConstraints: BoxConstraints(maxWidth: maxWidth));

  double _cap(double width) => width < additionalConstraints.maxWidth
      ? width
      : additionalConstraints.maxWidth;

  @override
  double computeMinIntrinsicHeight(double width) =>
      super.computeMinIntrinsicHeight(_cap(width));

  @override
  double computeMaxIntrinsicHeight(double width) =>
      super.computeMaxIntrinsicHeight(_cap(width));
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
                    border: Border.all(
                      color: widget.color.withValues(alpha: 0.5),
                    ),
                  ),
                  child: Icon(
                    playing ? Icons.pause : Icons.play_arrow,
                    size: 20,
                    color: widget.color,
                  ),
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
                    ? (pos.inMilliseconds / total.inMilliseconds).clamp(
                        0.0,
                        1.0,
                      )
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
  final VoidCallback?
  onTyping; // keystroke → typing indicator (throttled upstream)
  final VoidCallback? onAttach; // null → no attachment button at all
  final VoidCallback?
  onSticker; // opens the sticker picker (DM-only, like media)
  final void Function(String path, int durationMs)? onVoiceRecorded;

  const _Composer({
    required this.controller,
    required this.onSend,
    this.onTyping,
    required this.onAttach,
    required this.onSticker,
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
      HapticFeedback.mediumImpact();
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
        showZnSnack(
          context,
          'Microphone access is needed for voice notes',
          error: true,
        );
      }
      return;
    }
    final dir = await getTemporaryDirectory();
    await _recorder.start(
      const RecordConfig(encoder: AudioEncoder.aacLc, bitRate: 48000),
      path:
          '${dir.path}/stonechat-voice-${DateTime.now().millisecondsSinceEpoch}.m4a',
    );
    HapticFeedback.mediumImpact();
    setState(() => _recordingStarted = DateTime.now());
    _ticker = Timer.periodic(
      const Duration(seconds: 1),
      (_) => setState(() {}),
    );
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
          if (widget.onAttach != null)
            IconButton(
              onPressed: _recording ? null : widget.onAttach,
              icon: const Icon(
                Icons.add_circle_outline,
                color: Zn.muted,
                size: 22,
              ),
            )
          else
            const SizedBox(width: 12),
          if (widget.onSticker != null)
            IconButton(
              onPressed: _recording ? null : widget.onSticker,
              icon: const Icon(
                Icons.emoji_emotions_outlined,
                color: Zn.muted,
                size: 22,
              ),
            ),
          Expanded(
            child: _recording
                ? Row(
                    children: [
                      Container(
                        width: 8,
                        height: 8,
                        decoration: const BoxDecoration(
                          color: Zn.danger,
                          shape: BoxShape.circle,
                        ),
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
              icon: AnimatedSwitcher(
                duration: Zn.dur(context, Zn.fast),
                switchInCurve: Zn.ease,
                transitionBuilder: (child, animation) => FadeTransition(
                  opacity: animation,
                  child: ScaleTransition(
                    scale: Tween(begin: 0.8, end: 1.0).animate(animation),
                    child: child,
                  ),
                ),
                child: Icon(
                  _recording ? Icons.stop_circle_outlined : Icons.mic_none,
                  key: ValueKey(_recording),
                  color: _recording ? Zn.danger : Zn.muted,
                  size: 22,
                ),
              ),
            ),
          // Lights up once there is something to send.
          ValueListenableBuilder(
            valueListenable: widget.controller,
            builder: (context, value, _) {
              final armed = !_recording && value.text.trim().isNotEmpty;
              return IconButton(
                onPressed: _recording ? null : widget.onSend,
                icon: AnimatedContainer(
                  duration: Zn.dur(context, Zn.fast),
                  curve: Zn.ease,
                  width: 36,
                  height: 36,
                  decoration: BoxDecoration(
                    color: armed ? Zn.orange : Zn.line,
                    borderRadius: BorderRadius.circular(Zn.radius),
                  ),
                  child: Icon(
                    Icons.arrow_upward,
                    size: 20,
                    color: armed ? Zn.onAccent : Zn.muted,
                  ),
                ),
              );
            },
          ),
        ],
      ),
    );
  }
}

/// A group message from someone the user blocked: present, so the room
/// still makes sense, but closed until tapped.
class _BlockedMessage extends StatelessWidget {
  final VoidCallback onReveal;

  const _BlockedMessage({required this.onReveal});

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: onReveal,
      behavior: HitTestBehavior.opaque,
      child: Padding(
        padding: const EdgeInsets.symmetric(vertical: 8, horizontal: 16),
        child: Row(
          children: [
            const Icon(Icons.block, size: 12, color: Zn.muted),
            const SizedBox(width: 6),
            Flexible(
              child: Text(
                'Message from a blocked member · tap to show',
                style: Zn.mono(size: 10, color: Zn.muted),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
