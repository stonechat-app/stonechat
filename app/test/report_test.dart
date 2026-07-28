import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:stonechat/core/report.dart';
import 'package:stonechat/models.dart';

Message _msg(String id, int sentAt,
        {bool outgoing = false,
        String text = 'hi',
        String kind = MessageKind.text,
        bool deleted = false,
        String? fileName}) =>
    Message(
      id: id,
      contactId: 'SC-PEER',
      outgoing: outgoing,
      text: text,
      kind: kind,
      fileName: fileName,
      deleted: deleted,
      sentAt: sentAt,
      status: MessageStatus.delivered,
    );

void main() {
  test('evidence carries only what they sent', () {
    final candidates = evidenceCandidates([
      _msg('a', 1, text: 'theirs'),
      _msg('b', 2, outgoing: true, text: 'mine'),
      _msg('c', 3, text: 'theirs again'),
    ]);
    expect(candidates.map((m) => m.text), ['theirs', 'theirs again']);
  });

  test('deleted messages are not attachable', () {
    final candidates = evidenceCandidates([
      _msg('a', 1, text: 'retracted', deleted: true),
      _msg('b', 2, text: 'kept'),
    ]);
    expect(candidates.map((m) => m.text), ['kept']);
  });

  test('keeps the newest N, still oldest-first', () {
    final many = [
      for (var i = 0; i < evidenceMessageLimit + 10; i++)
        _msg('m$i', i, text: 'msg$i')
    ];
    final candidates = evidenceCandidates(many);
    expect(candidates.length, evidenceMessageLimit);
    // The newest window, in reading order.
    expect(candidates.first.text, 'msg10');
    expect(candidates.last.text, 'msg${evidenceMessageLimit + 9}');
  });

  test('media is described, never uploaded', () {
    final lines = describeEvidence([
      _msg('a', 1, kind: MessageKind.image),
      _msg('b', 2, kind: MessageKind.file, fileName: 'invoice.pdf'),
      _msg('c', 3, kind: MessageKind.audio),
      _msg('d', 4, text: 'plain words'),
    ]);
    expect(lines[0], '[photo — not uploaded]');
    expect(lines[1], '[file: invoice.pdf — not uploaded]');
    expect(lines[2], '[voice message — not uploaded]');
    expect(lines[3], 'plain words');

    // Nothing in the serialised payload should reference a local file path.
    final payload = buildEvidence([_msg('a', 1, kind: MessageKind.image)]);
    expect(payload.contains('mediaPath'), isFalse);
    expect(payload.contains('/'), isFalse);
  });

  test('what the preview shows is what the payload sends', () {
    final messages = [
      _msg('a', 1, text: 'first'),
      _msg('b', 2, kind: MessageKind.image),
    ];
    final shown = describeEvidence(messages);
    final sent = (jsonDecode(buildEvidence(messages))['messages'] as List)
        .map((m) => m['text'] as String)
        .toList();
    expect(sent, shown);
  });

  test('every category has a label and matches the hub vocabulary', () {
    for (final c in ReportCategory.options) {
      expect(ReportCategory.label(c), isNot(c));
    }
    // Must stay in step with CATEGORIES in hub/app/report.py.
    expect(ReportCategory.options.toSet(), {
      'spam',
      'harassment',
      'impersonation',
      'illegal_content',
      'csam',
      'other',
    });
  });
}
