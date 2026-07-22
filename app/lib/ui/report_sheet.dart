/// Reporting someone to the hub that hosts them.
///
/// The sheet's job is not to collect a report — that part is three fields. It
/// is to make the privacy trade legible at the moment it is made. Everywhere
/// else in this app, message content cannot leave the device; here it can, if
/// the reporter decides it should. So the attach control is off by default,
/// the exact lines that would be transmitted are shown before sending and not
/// merely summarised, and the copy says plainly which of the two things is
/// about to happen.
///
/// Composition and wire format: core/report.dart.
library;

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../core/api.dart';
import '../core/report.dart';
import '../models.dart';
import '../state/app_state.dart';
import 'theme.dart';
import 'widgets.dart';

/// What the reporter decided. [alsoBlock] is a request, not something the
/// sheet acts on: only the caller knows what blocking means where it was
/// opened from, and in a group it may mean nothing at all.
class ReportOutcome {
  final bool filed;
  final bool alsoBlock;

  const ReportOutcome({required this.filed, this.alsoBlock = false});
}

/// Report [zeonId]. [hub] is their home hub (Contact.hub — null means ours);
/// [conversation] is the local history with them, from which the reporter may
/// attach received messages. Pass an empty list where there is no history
/// (a contact request from a stranger) and the attach control disappears.
///
/// [canBlock] shows the "block them too" option, which is on by default —
/// nearly everyone reporting someone also wants them gone, and making that
/// one tap instead of two is the difference between a blocked contact and a
/// user who files a report and keeps receiving messages. Pass false where the
/// caller cannot block (a group member who is not a contact).
Future<ReportOutcome> showReportSheet(
  BuildContext context, {
  required String zeonId,
  required String displayName,
  String? hub,
  List<Message> conversation = const [],
  bool canBlock = true,
}) async {
  final outcome = await showModalBottomSheet<ReportOutcome>(
    context: context,
    backgroundColor: Zn.surface,
    isScrollControlled: true,
    shape: const RoundedRectangleBorder(
      borderRadius: BorderRadius.vertical(top: Radius.circular(8)),
    ),
    builder: (_) => _ReportSheet(
      zeonId: zeonId,
      displayName: displayName,
      hub: hub,
      conversation: conversation,
      canBlock: canBlock,
    ),
  );
  return outcome ?? const ReportOutcome(filed: false);
}

class _ReportSheet extends StatefulWidget {
  final String zeonId;
  final String displayName;
  final String? hub;
  final List<Message> conversation;
  final bool canBlock;

  const _ReportSheet({
    required this.zeonId,
    required this.displayName,
    required this.hub,
    required this.conversation,
    required this.canBlock,
  });

  @override
  State<_ReportSheet> createState() => _ReportSheetState();
}

class _ReportSheetState extends State<_ReportSheet> {
  final _note = TextEditingController();
  late final List<Message> _attachable = evidenceCandidates(widget.conversation);
  String? _category;
  bool _attach = false; // opt-in, always
  bool _showPreview = false;
  late bool _block = widget.canBlock;
  bool _busy = false;
  String? _error;

  @override
  void dispose() {
    _note.dispose();
    super.dispose();
  }

  Future<void> _submit() async {
    if (_category == null) return;
    setState(() {
      _busy = true;
      _error = null;
    });
    final app = context.read<AppState>();
    try {
      final reference = await submitReport(
        crypto: app.crypto,
        // Their hub, not ours — see core/report.dart.
        hubUrl: widget.hub ?? app.api.baseUrl,
        reportedId: widget.zeonId,
        category: _category!,
        note: _note.text.trim(),
        evidence: _attach && _attachable.isNotEmpty
            ? buildEvidence(_attachable)
            : null,
      );
      if (!mounted) return;
      Navigator.pop(
          context,
          ReportOutcome(
              filed: true, alsoBlock: widget.canBlock && _block));
      showZnSnack(context, 'Report filed — reference ${reference.substring(0, 8)}');
    } on ApiException catch (e) {
      setState(() {
        _busy = false;
        // `not_our_account` is the cross-hub case and needs the honest
        // version: we did not file this anywhere.
        _error = e.code == 'not_our_account'
            ? "This person isn't hosted by your hub, so it can't act on a "
                "report about them. Write to abuse@zeonchat.com instead."
            : e.message;
      });
    } catch (_) {
      setState(() {
        _busy = false;
        _error = "Couldn't reach the hub — try again";
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: EdgeInsets.only(
        left: 24,
        right: 24,
        top: 20,
        bottom: 20 + MediaQuery.of(context).viewInsets.bottom,
      ),
      child: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('REPORT ${widget.displayName.toUpperCase()}',
                style: Zn.mono(size: 10, letterSpacing: 2)),
            const SizedBox(height: 12),
            const Text(
              'Reports go to the hub that hosts this person. A hub can take '
              'their mailbox away and refuse them another one — it cannot '
              'read your messages or delete anything on their phone.',
              style: TextStyle(color: Zn.muted, fontSize: 13, height: 1.4),
            ),
            const SizedBox(height: 20),
            Text('WHAT HAPPENED', style: Zn.mono(size: 10, letterSpacing: 2)),
            const SizedBox(height: 8),
            for (final category in ReportCategory.options)
              _CategoryRow(
                label: ReportCategory.label(category),
                selected: _category == category,
                onTap: _busy ? null : () => setState(() => _category = category),
              ),
            const SizedBox(height: 16),
            TextField(
              controller: _note,
              enabled: !_busy,
              maxLines: 3,
              maxLength: 2000,
              style: const TextStyle(color: Zn.text, fontSize: 14),
              decoration: const InputDecoration(
                hintText: 'Anything else the hub should know (optional)',
                hintStyle: TextStyle(color: Zn.muted, fontSize: 13),
              ),
            ),
            if (_attachable.isNotEmpty) ...[
              const SizedBox(height: 8),
              _AttachControl(
                count: _attachable.length,
                attach: _attach,
                showPreview: _showPreview,
                lines: describeEvidence(_attachable),
                onToggle: _busy
                    ? null
                    : (v) => setState(() {
                          _attach = v;
                          if (!v) _showPreview = false;
                        }),
                onTogglePreview: () =>
                    setState(() => _showPreview = !_showPreview),
              ),
            ],
            if (widget.canBlock) ...[
              const SizedBox(height: 4),
              InkWell(
                onTap: _busy ? null : () => setState(() => _block = !_block),
                borderRadius: BorderRadius.circular(Zn.radius),
                child: Padding(
                  padding: const EdgeInsets.symmetric(vertical: 8),
                  child: Row(
                    children: [
                      Icon(
                          _block
                              ? Icons.check_box
                              : Icons.check_box_outline_blank,
                          size: 18,
                          color: _block ? Zn.orange : Zn.muted),
                      const SizedBox(width: 12),
                      const Expanded(
                        child: Text('Block them as well',
                            style: TextStyle(color: Zn.text, fontSize: 13)),
                      ),
                    ],
                  ),
                ),
              ),
            ],
            const SizedBox(height: 16),
            if (_error != null) ...[
              Text(_error!,
                  style: const TextStyle(
                      color: Zn.danger, fontSize: 12, height: 1.4)),
              const SizedBox(height: 12),
            ],
            SizedBox(
              width: double.infinity,
              height: 46,
              child: FilledButton(
                onPressed: _busy || _category == null ? null : _submit,
                child: _busy
                    ? const SizedBox(
                        width: 16,
                        height: 16,
                        child: CircularProgressIndicator(strokeWidth: 2))
                    : const Text('Send report'),
              ),
            ),
            const SizedBox(height: 8),
            // The one line that has to be true and has to be read. It changes
            // with the switch because the promise changes with the switch.
            Text(
              _attach
                  ? 'Your report, and the ${_attachable.length} received '
                      'messages shown above, will be sent to the hub.'
                  : 'No message content will be sent — only your report.',
              style: TextStyle(
                  color: _attach ? Zn.amber : Zn.muted,
                  fontSize: 11,
                  height: 1.4),
            ),
          ],
        ),
      ),
    );
  }
}

class _CategoryRow extends StatelessWidget {
  final String label;
  final bool selected;
  final VoidCallback? onTap;

  const _CategoryRow({
    required this.label,
    required this.selected,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(Zn.radius),
      child: Padding(
        padding: const EdgeInsets.symmetric(vertical: 9),
        child: Row(
          children: [
            Container(
              width: 16,
              height: 16,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                border: Border.all(
                    color: selected ? Zn.orange : Zn.line, width: 1.5),
              ),
              child: selected
                  ? Center(
                      child: Container(
                        width: 8,
                        height: 8,
                        decoration: const BoxDecoration(
                            color: Zn.orange, shape: BoxShape.circle),
                      ),
                    )
                  : null,
            ),
            const SizedBox(width: 12),
            Expanded(
              child: Text(label,
                  style: TextStyle(
                      color: selected ? Zn.text : Zn.muted, fontSize: 14)),
            ),
          ],
        ),
      ),
    );
  }
}

/// The attach switch and its preview. Kept as one widget because the preview
/// is the only thing that makes the switch honest — a reporter who cannot see
/// what they are attaching has not really opted in to attaching it.
class _AttachControl extends StatelessWidget {
  final int count;
  final bool attach;
  final bool showPreview;
  final List<String> lines;
  final ValueChanged<bool>? onToggle;
  final VoidCallback onTogglePreview;

  const _AttachControl({
    required this.count,
    required this.attach,
    required this.showPreview,
    required this.lines,
    required this.onToggle,
    required this.onTogglePreview,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      decoration: BoxDecoration(
        border: Border.all(color: attach ? Zn.amber : Zn.line),
        borderRadius: BorderRadius.circular(Zn.radius),
      ),
      padding: const EdgeInsets.fromLTRB(12, 4, 8, 8),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Expanded(
                child: Text(
                  'Attach the last $count message${count == 1 ? '' : 's'} '
                  'they sent you',
                  style: const TextStyle(color: Zn.text, fontSize: 13),
                ),
              ),
              Switch(
                value: attach,
                onChanged: onToggle,
                activeThumbColor: Zn.amber,
              ),
            ],
          ),
          const Text(
            'Photos, files and voice messages are never uploaded — only a note '
            'that one was sent.',
            style: TextStyle(color: Zn.muted, fontSize: 11, height: 1.4),
          ),
          if (attach) ...[
            const SizedBox(height: 4),
            GestureDetector(
              onTap: onTogglePreview,
              child: Text(
                showPreview ? 'Hide what will be sent' : 'See what will be sent',
                style: const TextStyle(
                    color: Zn.amber,
                    fontSize: 12,
                    decoration: TextDecoration.underline,
                    decorationColor: Zn.amber),
              ),
            ),
            if (showPreview) ...[
              const SizedBox(height: 8),
              ConstrainedBox(
                constraints: const BoxConstraints(maxHeight: 160),
                child: SingleChildScrollView(
                  child: Container(
                    width: double.infinity,
                    padding: const EdgeInsets.all(8),
                    color: Zn.bg,
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        for (final line in lines)
                          Padding(
                            padding: const EdgeInsets.only(bottom: 6),
                            child: Text(line,
                                style: Zn.mono(size: 11, color: Zn.muted)),
                          ),
                      ],
                    ),
                  ),
                ),
              ),
            ],
          ],
        ],
      ),
    );
  }
}
