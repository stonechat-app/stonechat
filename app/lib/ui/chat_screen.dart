/// The Zeon conversation view: a left-aligned ledger, not bubbles.
///
/// Every message is a full-width entry with a colored rail — ion for you,
/// the contact's derived color for them. Long silences render as actual
/// vertical space with a small gap marker, so a conversation's rhythm is
/// visible at a glance.
library;

import 'package:flutter/material.dart';
import 'package:intl/intl.dart';
import 'package:provider/provider.dart';

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
    if (_scroll.hasClients) {
      _scroll.animateTo(_scroll.position.maxScrollExtent + 80,
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
                Text(widget.contact.zeonId.substring(0, 12),
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
          _Composer(controller: _input, onSend: _send),
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
                  Text(message.text,
                      style: const TextStyle(
                          color: Zn.text, fontSize: 15, height: 1.35)),
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

class _Composer extends StatelessWidget {
  final TextEditingController controller;
  final VoidCallback onSend;

  const _Composer({required this.controller, required this.onSend});

  @override
  Widget build(BuildContext context) {
    return Container(
      decoration: const BoxDecoration(
        color: Zn.surface,
        border: Border(top: BorderSide(color: Zn.line)),
      ),
      padding: EdgeInsets.only(
        left: 16,
        right: 8,
        top: 8,
        bottom: 8 + MediaQuery.of(context).padding.bottom,
      ),
      child: Row(
        children: [
          Expanded(
            child: TextField(
              controller: controller,
              minLines: 1,
              maxLines: 5,
              textInputAction: TextInputAction.send,
              onSubmitted: (_) => onSend(),
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
            onPressed: onSend,
            icon: Container(
              width: 36,
              height: 36,
              decoration: BoxDecoration(
                color: Zn.ion,
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
