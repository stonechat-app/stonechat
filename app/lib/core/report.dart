/// Abuse reports: composing one, and what a reporter may choose to attach.
///
/// The hub side is `hub/app/report.py`; the wire format and signature are in
/// PROTOCOL.md "Reporting". This file owns the two decisions that belong on
/// the device.
///
/// **Which hub hears it.** A report is only useful to the party that can
/// destroy a mailbox or ban an account, and that is the hub hosting the
/// *reported* user — `Contact.hub` when cross-hub, ours otherwise. It is not
/// necessarily the reporter's own hub, which is why the report is signed
/// rather than authenticated with an account token.
///
/// **What leaves the phone.** By default: an ID, a category, and whatever the
/// reporter typed. Nothing else — which is what keeps the privacy policy's
/// "we never receive message content" true for anyone who does not choose
/// otherwise. Attaching a transcript is an explicit, separate act, it is
/// capped and composed here, and [describeEvidence] exists so the UI can show
/// the reporter exactly what they are about to hand over. Media is never
/// uploaded: an attachment appears as a placeholder line, because shipping the
/// bytes would turn a report into a file transfer we cannot un-send.
library;

import 'dart:convert';

import '../models.dart';
import 'api.dart';
import 'crypto.dart';

/// Must match CATEGORIES in hub/app/report.py.
class ReportCategory {
  static const spam = 'spam';
  static const harassment = 'harassment';
  static const impersonation = 'impersonation';
  static const csam = 'csam';
  static const illegalContent = 'illegal_content';
  static const other = 'other';

  /// Ordered for the picker: most-reported first, `other` last.
  static const options = [
    spam,
    harassment,
    impersonation,
    illegalContent,
    csam,
    other,
  ];

  static String label(String c) => switch (c) {
        spam => 'Spam or scams',
        harassment => 'Harassment or threats',
        impersonation => 'Pretending to be someone else',
        illegalContent => 'Illegal content',
        csam => 'Child sexual abuse material',
        other => 'Something else',
        _ => c,
      };
}

/// How many received messages an attached transcript may carry.
const evidenceMessageLimit = 20;

/// Per-message text cap, so one enormous message cannot eat the whole budget.
const _evidenceTextLimit = 2000;

/// The most recent messages *received from* [contactId], oldest first.
///
/// Outgoing messages are excluded on purpose. A report should not be able to
/// carry words the reported person never said, and a transcript the reporter
/// half-wrote is worth less to whoever has to judge it, not more.
List<Message> evidenceCandidates(List<Message> conversation) => conversation
    .where((m) => !m.outgoing && !m.deleted)
    .toList()
    .reversed
    .take(evidenceMessageLimit)
    .toList()
    .reversed
    .toList();

/// One human-readable line per message, for the confirmation screen. What the
/// UI shows here and what [buildEvidence] transmits must stay the same set —
/// a reporter who was shown five lines must not send six.
List<String> describeEvidence(List<Message> messages) =>
    messages.map(_describe).toList();

String _describe(Message m) => switch (m.kind) {
      MessageKind.text => m.text,
      MessageKind.image => '[photo — not uploaded]',
      MessageKind.video => '[video — not uploaded]',
      MessageKind.audio => '[voice message — not uploaded]',
      MessageKind.sticker => '[sticker — not uploaded]',
      MessageKind.file => '[file: ${m.fileName ?? 'attachment'} — not uploaded]',
      _ => '[${m.kind}]',
    };

/// Serialise the attached messages. The hub stores this verbatim and never
/// parses it (report.py), so the shape only has to be readable by whoever
/// triages it — and stable, because its exact bytes are signed.
String buildEvidence(List<Message> messages) => jsonEncode({
      'v': 1,
      'messages': [
        for (final m in messages)
          {
            'sent_at': m.sentAt,
            'kind': m.kind,
            'text': _describe(m).length > _evidenceTextLimit
                ? _describe(m).substring(0, _evidenceTextLimit)
                : _describe(m),
          }
      ],
    });

/// Sign and file a report. Returns the hub's reference id.
///
/// [hubUrl] must be the reported user's home hub — see the library docstring.
/// [evidence] is the output of [buildEvidence], or null for the default
/// content-free report.
Future<String> submitReport({
  required CryptoService crypto,
  required String hubUrl,
  required String reportedId,
  required String category,
  required String note,
  required String? evidence,
}) async {
  final timestamp = DateTime.now().millisecondsSinceEpoch ~/ 1000;
  return fileReport(
    hubUrl: hubUrl,
    reportedId: reportedId,
    reporterPubkeyB64: crypto.publicKeyB64,
    timestamp: timestamp,
    category: category,
    note: note,
    evidence: evidence,
    signatureB64: crypto.signReport(
      reportedId: reportedId,
      unixSeconds: timestamp,
      category: category,
      note: note,
      evidence: evidence,
    ),
  );
}
