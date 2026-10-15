/// What becomes of an envelope whose handling threw (PROTOCOL.md "Receiving
/// an envelope": a dropped envelope is still acked; one that fails
/// *transiently* is left queued).
///
/// The mailbox socket acks an envelope when the handler returns and leaves
/// it queued when the handler throws. That made every exception a "try
/// again later", including the ones a sender can cause on purpose: a field
/// of the wrong type, an id too short to abbreviate, a payload that is not
/// an object. Such an envelope was never acked, so the mailbox sent it
/// again on every connect, forever, and it sat in the queue against the
/// inbox cap. Nothing about it improves with time.
///
/// So the rule is inverted: an envelope is kept only for a failure that is
/// ours or the network's, named here. Everything else is the envelope's own
/// fault and it is dropped — logged and acked, like any other drop.
library;

import 'dart:async' show TimeoutException;
import 'dart:io' show IOException;

import 'package:sqflite_sqlcipher/sqflite.dart' show DatabaseException;

import 'api.dart' show ApiException;

/// Thrown by the handler to leave the envelope queued for a reason it names:
/// something this device needs is not here yet (its own mailbox's
/// coordinates, say) and will be.
class EnvelopeDeferred implements Exception {
  final String reason;
  const EnvelopeDeferred(this.reason);
  @override
  String toString() => 'envelope deferred: $reason';
}

/// Whether [error], thrown while handling an envelope, means the envelope
/// should stay queued and be delivered again later.
///
/// True for an explicit [EnvelopeDeferred]; for network and I/O failures
/// ([IOException] covers sockets, TLS and files; [TimeoutException]); for a
/// mailbox or directory call that failed but was not a *refusal*
/// ([ApiException.refused] means the answer is bad, not late); and for a
/// local database failure, which is this device's problem, not the
/// sender's. False for everything else: type and range errors, format
/// errors, argument and state errors — the shapes a malformed envelope
/// produces.
bool leavesQueued(Object error) => switch (error) {
  EnvelopeDeferred() => true,
  ApiException(refused: final refused) => !refused,
  IOException() => true,
  TimeoutException() => true,
  DatabaseException() => true,
  _ => false,
};

/// A short, safe form of a peer id for a log line: the first characters,
/// never a throw on a short or odd one.
String abbreviateId(String id, [int length = 12]) =>
    id.length <= length ? id : '${id.substring(0, length)}…';
