/// 1:1 E2EE calls (PROTOCOL.md "Calls").
///
/// The ratchet-encrypted envelope layer is the signaling channel: SDP and
/// ICE candidates travel as ordinary sealed envelopes, so signaling is
/// authenticated end-to-end — which in turn authenticates the DTLS-SRTP
/// fingerprints inside the SDP. Media itself flows peer-to-peer (or via the
/// caller's/callee's own mailbox TURN relay), never through a mailbox.
library;

import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter_webrtc/flutter_webrtc.dart';
import 'package:uuid/uuid.dart';

import '../core/api.dart';
import '../models.dart';
import 'app_state.dart';
import 'chat_state.dart';

const _uuid = Uuid();

enum CallPhase {
  idle,
  dialing, // we sent an offer, waiting for their answer
  ringing, // their offer is on our screen, waiting for the user
  connecting, // answered, ICE still working
  active,
  ended, // terminal flash before returning to idle
}

class CallEndReason {
  static const hangup = 'hangup';
  static const decline = 'decline';
  static const busy = 'busy';
  static const timeout = 'timeout';
}

class CallState extends ChangeNotifier {
  final AppState app;
  final ChatState chat;

  CallState(this.app, this.chat) {
    chat.onCallSignal = _onSignal;
  }

  CallPhase phase = CallPhase.idle;
  Contact? peer;
  String? callId;
  bool withVideo = false;
  bool outgoing = false;
  bool muted = false;
  bool speakerOn = false;
  bool cameraOff = false;
  String? endNote; // one-line epitaph shown on the ended flash
  DateTime? connectedAt;

  RTCPeerConnection? _pc;
  MediaStream? _localStream;
  final localRenderer = RTCVideoRenderer();
  final remoteRenderer = RTCVideoRenderer();
  bool _renderersReady = false;

  Timer? _ringTimer;
  Timer? _iceFlushTimer;
  final List<Map<String, Object?>> _iceOutbox = [];
  final List<RTCIceCandidate> _pendingRemoteCandidates = [];
  bool _remoteDescriptionSet = false;
  Map<String, dynamic>? _pendingOffer; // callee: held until the user accepts

  bool get inCall => phase != CallPhase.idle;

  static const _ringTimeoutS = 45;
  static const _offerFreshnessS = 60;

  // -- placing / answering ------------------------------------------------------

  Future<void> startCall(Contact contact, {required bool video}) async {
    if (inCall) return;
    peer = contact;
    callId = _uuid.v4();
    withVideo = video;
    outgoing = true;
    _setPhase(CallPhase.dialing);
    try {
      await _setupMediaAndPc();
      final offer = await _pc!.createOffer();
      await _pc!.setLocalDescription(offer);
      await chat.sendCallSignal(
        contact,
        EnvelopeType.callOffer,
        {
          'call_id': callId,
          'media': video ? 'video' : 'audio',
          'sdp': offer.sdp,
        },
        ring: true,
      );
      _armRingTimer(() async {
        await _sendEnd(CallEndReason.timeout);
        await _recordAndClose('No answer',
            note: 'No answer');
      });
    } catch (e) {
      await _recordAndClose('Call failed', note: 'Call failed: $e');
    }
  }

  Future<void> acceptCall() async {
    final offer = _pendingOffer;
    final contact = peer;
    if (phase != CallPhase.ringing || offer == null || contact == null) return;
    _ringTimer?.cancel();
    _setPhase(CallPhase.connecting);
    try {
      await _setupMediaAndPc();
      await _pc!.setRemoteDescription(
          RTCSessionDescription(offer['sdp'] as String, 'offer'));
      _remoteDescriptionSet = true;
      await _drainRemoteCandidates();
      final answer = await _pc!.createAnswer();
      await _pc!.setLocalDescription(answer);
      await chat.sendCallSignal(contact, EnvelopeType.callAnswer,
          {'call_id': callId, 'sdp': answer.sdp});
    } catch (e) {
      await _sendEnd(CallEndReason.hangup);
      await _recordAndClose('Call failed', note: 'Call failed: $e');
    }
  }

  Future<void> declineCall() async {
    if (phase != CallPhase.ringing) return;
    await _sendEnd(CallEndReason.decline);
    await _recordAndClose(_label('Declined'), note: null, silent: true);
  }

  Future<void> hangUp() async {
    if (!inCall) return;
    await _sendEnd(CallEndReason.hangup);
    await _recordAndClose(_endedLabel(), note: null, silent: true);
  }

  void toggleMute() {
    muted = !muted;
    for (final t in _localStream?.getAudioTracks() ?? const []) {
      t.enabled = !muted;
    }
    notifyListeners();
  }

  void toggleSpeaker() {
    speakerOn = !speakerOn;
    Helper.setSpeakerphoneOn(speakerOn);
    notifyListeners();
  }

  void toggleCamera() {
    if (!withVideo) return;
    cameraOff = !cameraOff;
    for (final t in _localStream?.getVideoTracks() ?? const []) {
      t.enabled = !cameraOff;
    }
    notifyListeners();
  }

  Future<void> switchCamera() async {
    final tracks = _localStream?.getVideoTracks();
    if (tracks == null || tracks.isEmpty) return;
    await Helper.switchCamera(tracks.first);
  }

  // -- incoming signaling (from ChatState.handleIncoming) ------------------------

  Future<void> _onSignal(
      Contact contact, Envelope envelope, Map<String, dynamic> payload) async {
    final id = payload['call_id'] as String?;
    if (id == null) return;
    switch (envelope.type) {
      case EnvelopeType.callOffer:
        await _onOffer(contact, envelope, payload, id);
      case EnvelopeType.callAnswer:
        await _onAnswer(contact, payload, id);
      case EnvelopeType.callIce:
        await _onIce(contact, payload, id);
      case EnvelopeType.callEnd:
        await _onEnd(contact, payload, id);
    }
    notifyListeners();
  }

  Future<void> _onOffer(Contact contact, Envelope envelope,
      Map<String, dynamic> payload, String id) async {
    final sentAt = DateTime.tryParse(envelope.sentAt)?.toLocal() ??
        DateTime.now();
    final stale =
        DateTime.now().difference(sentAt).inSeconds > _offerFreshnessS;
    if (stale) {
      // They gave up long ago — a missed call, not a ring.
      await chat.recordCallEvent(contact,
          _missedLabel(payload['media'] == 'video'),
          outgoing: false);
      return;
    }
    if (inCall) {
      final glare = phase == CallPhase.dialing &&
          peer?.stonechatId == contact.stonechatId;
      if (glare && contact.stonechatId.compareTo(app.stonechatId!) < 0) {
        // Simultaneous call, their (lower) ID wins: drop our attempt and
        // ring with theirs. They do the reciprocal and ignore ours.
        await _teardownRtc();
      } else if (!glare) {
        await chat.sendCallSignal(contact, EnvelopeType.callEnd,
            {'call_id': id, 'reason': CallEndReason.busy});
        await chat.recordCallEvent(
            contact, _missedLabel(payload['media'] == 'video'),
            outgoing: false);
        return;
      } else {
        return; // glare, our ID wins: they will adopt our offer
      }
    }
    peer = contact;
    callId = id;
    withVideo = payload['media'] == 'video';
    outgoing = false;
    _pendingOffer = payload;
    _setPhase(CallPhase.ringing);
    _armRingTimer(() async {
      await chat.recordCallEvent(contact, _missedLabel(withVideo),
          outgoing: false);
      await _close(silent: true);
    });
  }

  Future<void> _onAnswer(
      Contact contact, Map<String, dynamic> payload, String id) async {
    if (phase != CallPhase.dialing || id != callId || _pc == null) return;
    _ringTimer?.cancel();
    _setPhase(CallPhase.connecting);
    await _pc!.setRemoteDescription(
        RTCSessionDescription(payload['sdp'] as String, 'answer'));
    _remoteDescriptionSet = true;
    await _drainRemoteCandidates();
  }

  Future<void> _onIce(
      Contact contact, Map<String, dynamic> payload, String id) async {
    if (id != callId || contact.stonechatId != peer?.stonechatId) return;
    for (final raw in (payload['candidates'] as List? ?? const [])) {
      if (raw is! Map) continue;
      final candidate = RTCIceCandidate(
        raw['candidate'] as String?,
        raw['sdp_mid'] as String?,
        raw['sdp_mline_index'] as int?,
      );
      if (_remoteDescriptionSet && _pc != null) {
        await _pc!.addCandidate(candidate);
      } else {
        _pendingRemoteCandidates.add(candidate);
      }
    }
  }

  Future<void> _onEnd(
      Contact contact, Map<String, dynamic> payload, String id) async {
    if (id != callId || contact.stonechatId != peer?.stonechatId) return;
    final reason = payload['reason'] as String? ?? CallEndReason.hangup;
    final label = switch (reason) {
      CallEndReason.decline => _label('Declined'),
      CallEndReason.busy => _label('Busy'),
      CallEndReason.timeout => _missedLabel(withVideo),
      _ => phase == CallPhase.active ? _endedLabel() : _label('Canceled'),
    };
    await _recordAndClose(label,
        note: switch (reason) {
          CallEndReason.decline => 'Declined',
          CallEndReason.busy => 'Busy',
          _ => null,
        });
  }

  // -- WebRTC plumbing ------------------------------------------------------------

  Future<void> _setupMediaAndPc() async {
    if (!_renderersReady) {
      await localRenderer.initialize();
      await remoteRenderer.initialize();
      _renderersReady = true;
    }
    _localStream = await navigator.mediaDevices.getUserMedia({
      'audio': true,
      'video': withVideo
          ? {'facingMode': 'user', 'width': 1280, 'height': 720}
          : false,
    });
    localRenderer.srcObject = _localStream;

    _pc = await createPeerConnection({'iceServers': await _iceServers()});
    for (final track in _localStream!.getTracks()) {
      await _pc!.addTrack(track, _localStream!);
    }
    _pc!.onTrack = (event) {
      if (event.streams.isNotEmpty) {
        remoteRenderer.srcObject = event.streams.first;
        notifyListeners();
      }
    };
    _pc!.onIceCandidate = _queueLocalCandidate;
    _pc!.onConnectionState = (state) {
      switch (state) {
        case RTCPeerConnectionState.RTCPeerConnectionStateConnected:
          if (phase == CallPhase.connecting || phase == CallPhase.dialing) {
            connectedAt = DateTime.now();
            Helper.setSpeakerphoneOn(speakerOn || withVideo);
            speakerOn = speakerOn || withVideo;
            _setPhase(CallPhase.active);
          }
        case RTCPeerConnectionState.RTCPeerConnectionStateFailed:
          _recordAndClose(_endedLabel(), note: 'Connection lost');
        default:
          break;
      }
    };
  }

  /// Own mailbox's TURN (when it runs one) + public STUN. Either side's
  /// relay candidates can carry the call, so we only need our own.
  Future<List<Map<String, Object?>>> _iceServers() async {
    final servers = <Map<String, Object?>>[
      {'urls': 'stun:stun.l.google.com:19302'},
    ];
    final address = chat.mailboxAddress;
    final token = chat.mailboxToken;
    final tlsFp = chat.mailboxTlsFp;
    if (address != null && token != null && tlsFp != null) {
      final turn = await fetchTurnCredentials(address, token, tlsFp);
      if (turn != null) {
        servers.add({
          'urls': turn.urls,
          'username': turn.username,
          'credential': turn.credential,
        });
      }
    }
    return servers;
  }

  /// Trickle ICE, batched: one envelope per ~300 ms burst instead of one
  /// per candidate (each envelope is a ratchet step + an HTTP POST).
  void _queueLocalCandidate(RTCIceCandidate candidate) {
    if (candidate.candidate == null) return;
    _iceOutbox.add({
      'candidate': candidate.candidate,
      'sdp_mid': candidate.sdpMid,
      'sdp_mline_index': candidate.sdpMLineIndex,
    });
    _iceFlushTimer ??= Timer(const Duration(milliseconds: 300), () {
      _iceFlushTimer = null;
      final contact = peer;
      final id = callId;
      if (contact == null || id == null || _iceOutbox.isEmpty) return;
      final batch = List.of(_iceOutbox);
      _iceOutbox.clear();
      unawaited(chat
          .sendCallSignal(contact, EnvelopeType.callIce,
              {'call_id': id, 'candidates': batch}, transient: true)
          .catchError((_) {})); // late/lost candidates are self-healing
    });
  }

  Future<void> _drainRemoteCandidates() async {
    for (final c in _pendingRemoteCandidates) {
      await _pc!.addCandidate(c);
    }
    _pendingRemoteCandidates.clear();
  }

  // -- teardown -------------------------------------------------------------------

  void _armRingTimer(Future<void> Function() onTimeout) {
    _ringTimer?.cancel();
    _ringTimer = Timer(const Duration(seconds: _ringTimeoutS), () {
      unawaited(onTimeout());
    });
  }

  Future<void> _sendEnd(String reason) async {
    final contact = peer;
    final id = callId;
    if (contact == null || id == null) return;
    try {
      await chat.sendCallSignal(contact, EnvelopeType.callEnd,
          {'call_id': id, 'reason': reason});
    } catch (_) {
      // their ring timer ends the call for them
    }
  }

  String _label(String what) =>
      '$what ${withVideo ? 'video' : 'voice'} call';

  String _missedLabel(bool video) =>
      'Missed ${video ? 'video' : 'voice'} call';

  String _endedLabel() {
    final started = connectedAt;
    if (started == null) return _label('Canceled');
    final d = DateTime.now().difference(started);
    final mm = d.inMinutes.toString();
    final ss = (d.inSeconds % 60).toString().padLeft(2, '0');
    return '${withVideo ? 'Video' : 'Voice'} call · $mm:$ss';
  }

  /// Write the call's epitaph into the conversation, then tear down.
  Future<void> _recordAndClose(String label,
      {String? note, bool silent = false}) async {
    final contact = peer;
    if (contact != null) {
      await chat.recordCallEvent(contact, label, outgoing: outgoing);
    }
    endNote = note;
    await _close(silent: silent || note == null);
  }

  Future<void> _close({required bool silent}) async {
    await _teardownRtc();
    if (!silent) {
      _setPhase(CallPhase.ended); // brief flash with endNote
      Timer(const Duration(seconds: 2), () {
        if (phase == CallPhase.ended) _resetToIdle();
      });
    } else {
      _resetToIdle();
    }
  }

  Future<void> _teardownRtc() async {
    _ringTimer?.cancel();
    _iceFlushTimer?.cancel();
    _iceFlushTimer = null;
    _iceOutbox.clear();
    _pendingRemoteCandidates.clear();
    _remoteDescriptionSet = false;
    _pendingOffer = null;
    localRenderer.srcObject = null;
    remoteRenderer.srcObject = null;
    final stream = _localStream;
    _localStream = null;
    if (stream != null) {
      for (final t in stream.getTracks()) {
        await t.stop();
      }
      await stream.dispose();
    }
    final pc = _pc;
    _pc = null;
    await pc?.close();
  }

  void _resetToIdle() {
    peer = null;
    callId = null;
    withVideo = false;
    outgoing = false;
    muted = false;
    speakerOn = false;
    cameraOff = false;
    endNote = null;
    connectedAt = null;
    _setPhase(CallPhase.idle);
  }

  /// Identity reset: kill any call in progress without signaling — the
  /// identity that could seal a hangup envelope is being erased anyway.
  Future<void> reset() async {
    if (!inCall) return;
    await _teardownRtc();
    _resetToIdle();
  }

  void _setPhase(CallPhase next) {
    phase = next;
    notifyListeners();
  }

  @override
  void dispose() {
    _teardownRtc();
    localRenderer.dispose();
    remoteRenderer.dispose();
    super.dispose();
  }
}
