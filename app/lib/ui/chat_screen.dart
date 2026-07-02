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
import 'package:image_picker/image_picker.dart';
import 'package:intl/intl.dart';
import 'package:just_audio/just_audio.dart';
import 'package:path_provider/path_provider.dart';
import 'package:provider/provider.dart';
import 'package:record/record.dart';

import '../models.dart';
import '../state/chat_state.dart';
import 'theme.dart';
import 'widgets.dart';

class ChatScreen extends StatefulWidget {
  final Contact contact;
  const ChatScreen({super.key, required this.contact});

  @override
  State<ChatScreen> createState() => _ChatScreenState();
}

class _ChatScreenState extends State<ChatScreen> {
  final _input = TextEditingController();
  final _scroll = ScrollController();

  @override
  void initState() {
    super.initState();
    context.read<ChatState>().openConversation(widget.contact.zeonId);
  }

  Future<void> _send() async {
    final text = _input.text.trim();
    if (text.isEmpty) return;
    _input.clear();
    await context.read<ChatState>().sendMessage(widget.contact, text);
    _scrollToEnd();
  }

  Future<void> _sendPhoto() async {
    final picked = await ImagePicker().pickImage(
      source: ImageSource.gallery,
      maxWidth: 1600,
      imageQuality: 82,
    );
    if (picked == null || !mounted) return;
    await context.read<ChatState>().sendMedia(
          widget.contact,
          picked.path,
          kind: MessageKind.image,
          mime: 'image/jpeg',
        );
    _scrollToEnd();
  }

  Future<void> _sendVoice(String path, int durationMs) async {
    await context.read<ChatState>().sendMedia(
          widget.contact,
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
    final messages = chat.messagesFor(widget.contact.zeonId);
    final peerColor = Zn.idColor(widget.contact.zeonId);

    return Scaffold(
      appBar: AppBar(
        titleSpacing: 0,
        title: Row(
          children: [
            ZeonAvatar(
                zeonId: widget.contact.zeonId,
                name: widget.contact.displayName,
                size: 32),
            const SizedBox(width: 10),
            Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(widget.contact.displayName,
                    style: const TextStyle(fontSize: 16)),
                Text(
                    widget.contact.handle ??
                        widget.contact.zeonId.substring(0, 12),
                    style: Zn.mono(size: 9, letterSpacing: 1)),
              ],
            ),
          ],
        ),
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
                return Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    if (previous != null) _GapMarker.between(previous, m),
                    _LedgerEntry(
                      message: m,
                      peerName: widget.contact.displayName,
                      peerColor: peerColor,
                      showSender:
                          previous == null || previous.outgoing != m.outgoing,
                    ),
                  ],
                );
              },
            ),
          ),
          _Composer(
            controller: _input,
            onSend: _send,
            onPickPhoto: _sendPhoto,
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

  const _LedgerEntry({
    required this.message,
    required this.peerName,
    required this.peerColor,
    required this.showSender,
  });

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
                  switch (message.kind) {
                    MessageKind.image => _ImageEntry(message: message),
                    MessageKind.audio =>
                      _AudioEntry(message: message, color: color),
                    _ => Text(message.text,
                        style: const TextStyle(
                            color: Zn.text, fontSize: 15, height: 1.35)),
                  },
                ],
              ),
            ),
            const SizedBox(width: 12),
            Column(
              mainAxisAlignment: MainAxisAlignment.end,
              children: [
                Text(
                  '${DateFormat('HH:mm').format(DateTime.fromMillisecondsSinceEpoch(message.sentAt))}'
                  '${message.outgoing ? (message.status == MessageStatus.pending ? ' ◌' : ' ●') : ''}',
                  style: Zn.mono(size: 9),
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
  final VoidCallback onPickPhoto;
  final void Function(String path, int durationMs) onVoiceRecorded;

  const _Composer({
    required this.controller,
    required this.onSend,
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
          widget.onVoiceRecorded(path, duration.inMilliseconds);
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
          IconButton(
            onPressed: _recording ? null : widget.onPickPhoto,
            icon: const Icon(Icons.photo_outlined, color: Zn.muted, size: 22),
          ),
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
