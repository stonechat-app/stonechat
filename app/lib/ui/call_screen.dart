/// The call surface: incoming ring, dialing, and the live call.
/// Video calls render the peer full-bleed with a local picture-in-picture;
/// voice calls get the ledger aesthetic — avatar, mono status line, rail
/// colors. Pushed over everything by ZeonApp whenever CallState leaves idle.
library;

import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_webrtc/flutter_webrtc.dart';
import 'package:provider/provider.dart';

import '../models.dart';
import '../state/call_state.dart';
import 'theme.dart';
import 'widgets.dart';

class CallScreen extends StatefulWidget {
  const CallScreen({super.key});

  @override
  State<CallScreen> createState() => _CallScreenState();
}

class _CallScreenState extends State<CallScreen> {
  Timer? _ticker; // repaint the duration once a second while active

  @override
  void initState() {
    super.initState();
    _ticker = Timer.periodic(
        const Duration(seconds: 1), (_) => setState(() {}));
  }

  @override
  void dispose() {
    _ticker?.cancel();
    super.dispose();
  }

  String _status(CallState call) => switch (call.phase) {
        CallPhase.dialing => 'CALLING ···',
        CallPhase.ringing =>
          call.withVideo ? 'INCOMING VIDEO CALL' : 'INCOMING VOICE CALL',
        CallPhase.connecting => 'CONNECTING ···',
        CallPhase.active => _elapsed(call),
        CallPhase.ended => (call.endNote ?? 'CALL ENDED').toUpperCase(),
        CallPhase.idle => '',
      };

  String _elapsed(CallState call) {
    final started = call.connectedAt;
    if (started == null) return '';
    final d = DateTime.now().difference(started);
    return '${d.inMinutes.toString().padLeft(2, '0')}:'
        '${(d.inSeconds % 60).toString().padLeft(2, '0')}';
  }

  @override
  Widget build(BuildContext context) {
    final call = context.watch<CallState>();
    final peer = call.peer;
    if (peer == null) return const Scaffold(backgroundColor: Zn.bg);

    final showVideo = call.withVideo &&
        (call.phase == CallPhase.active || call.phase == CallPhase.connecting);

    // The route is pushed/popped by ZeonApp in lockstep with CallState —
    // a back gesture would desync them, so it's disabled.
    return PopScope(
      canPop: false,
      child: _body(call, peer, showVideo),
    );
  }

  Widget _body(CallState call, Contact peer, bool showVideo) {
    return Scaffold(
      backgroundColor: Zn.bg,
      body: Stack(
        children: [
          if (showVideo)
            Positioned.fill(
              child: RTCVideoView(call.remoteRenderer,
                  objectFit:
                      RTCVideoViewObjectFit.RTCVideoViewObjectFitCover),
            ),
          if (showVideo && !call.cameraOff)
            Positioned(
              right: 16,
              top: MediaQuery.of(context).padding.top + 16,
              width: 96,
              height: 144,
              child: ClipRRect(
                borderRadius: BorderRadius.circular(Zn.radius),
                child: RTCVideoView(call.localRenderer,
                    mirror: true,
                    objectFit:
                        RTCVideoViewObjectFit.RTCVideoViewObjectFitCover),
              ),
            ),
          SafeArea(
            child: Column(
              children: [
                const Spacer(flex: 2),
                if (!showVideo) ...[
                  ZeonAvatar(
                      zeonId: peer.zeonId,
                      name: peer.displayName,
                      size: 96,
                      image: peer.avatar),
                  const SizedBox(height: 24),
                  Text(peer.displayName,
                      style: const TextStyle(
                          color: Zn.text,
                          fontSize: 24,
                          fontWeight: FontWeight.w600)),
                  const SizedBox(height: 8),
                ],
                Container(
                  padding:
                      const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
                  decoration: showVideo
                      ? BoxDecoration(
                          color: Zn.bg.withValues(alpha: 0.6),
                          borderRadius: BorderRadius.circular(Zn.radius))
                      : null,
                  child: Text(
                    showVideo
                        ? '${peer.displayName} · ${_status(call)}'
                        : _status(call),
                    style: Zn.mono(
                        size: 12,
                        color: call.phase == CallPhase.active
                            ? Zn.orange
                            : Zn.muted,
                        letterSpacing: 2),
                  ),
                ),
                const Spacer(flex: 3),
                _controls(call),
                const SizedBox(height: 32),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _controls(CallState call) {
    if (call.phase == CallPhase.ringing) {
      return Row(
        mainAxisAlignment: MainAxisAlignment.spaceEvenly,
        children: [
          _RoundButton(
            icon: Icons.call_end,
            color: Zn.danger,
            label: 'Decline',
            onTap: call.declineCall,
          ),
          _RoundButton(
            icon: call.withVideo ? Icons.videocam : Icons.call,
            color: Zn.ok,
            label: 'Accept',
            onTap: call.acceptCall,
          ),
        ],
      );
    }
    if (call.phase == CallPhase.ended) return const SizedBox(height: 64);
    return Row(
      mainAxisAlignment: MainAxisAlignment.spaceEvenly,
      children: [
        _RoundButton(
          icon: call.muted ? Icons.mic_off : Icons.mic,
          color: call.muted ? Zn.orange : Zn.raised,
          label: 'Mute',
          onTap: call.toggleMute,
        ),
        if (call.withVideo) ...[
          _RoundButton(
            icon: call.cameraOff ? Icons.videocam_off : Icons.videocam,
            color: call.cameraOff ? Zn.orange : Zn.raised,
            label: 'Camera',
            onTap: call.toggleCamera,
          ),
          _RoundButton(
            icon: Icons.cameraswitch,
            color: Zn.raised,
            label: 'Flip',
            onTap: call.switchCamera,
          ),
        ] else
          _RoundButton(
            icon: call.speakerOn ? Icons.volume_up : Icons.volume_down,
            color: call.speakerOn ? Zn.orange : Zn.raised,
            label: 'Speaker',
            onTap: call.toggleSpeaker,
          ),
        _RoundButton(
          icon: Icons.call_end,
          color: Zn.danger,
          label: 'End',
          onTap: call.hangUp,
        ),
      ],
    );
  }
}

class _RoundButton extends StatelessWidget {
  final IconData icon;
  final Color color;
  final String label;
  final VoidCallback onTap;

  const _RoundButton({
    required this.icon,
    required this.color,
    required this.label,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    final bright = color != Zn.raised;
    return Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        GestureDetector(
          onTap: onTap,
          child: Container(
            width: 60,
            height: 60,
            decoration: BoxDecoration(
              color: color,
              borderRadius: BorderRadius.circular(Zn.radius * 2),
            ),
            child: Icon(icon,
                size: 26, color: bright ? Zn.onAccent : Zn.text),
          ),
        ),
        const SizedBox(height: 6),
        Text(label.toUpperCase(), style: Zn.mono(size: 9, letterSpacing: 1)),
      ],
    );
  }
}
