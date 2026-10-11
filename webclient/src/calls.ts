/**
 * 1:1 E2EE calls (PROTOCOL.md "Calls").
 *
 * Counterpart of `app/lib/state/call_state.dart`. The ratchet-encrypted
 * envelope layer is the signaling channel: SDP and ICE candidates travel as
 * ordinary sealed envelopes, so signaling is authenticated end-to-end —
 * which in turn authenticates the DTLS-SRTP fingerprints inside the SDP.
 * Media itself flows peer-to-peer (or via the caller's or callee's own
 * mailbox TURN relay), never through a mailbox.
 *
 * WebRTC is reached through [Rtc], an interface the page fills with the
 * browser's `RTCPeerConnection` and `getUserMedia`, and the tests with a
 * fake: what needs proving here is the signaling state machine — who rings,
 * who wins a glare, what each `call_end` reason means — and that should be
 * provable without a camera.
 */
import type { Protocol } from './protocol.js';
import { sentAtMs } from './wire.js';

export type CallPhase =
  | 'idle'
  /** We sent an offer, waiting for their answer. */
  | 'dialing'
  /** Their offer is on our screen, waiting for the user. */
  | 'ringing'
  /** Answered, ICE still working. */
  | 'connecting'
  | 'active'
  /** Terminal flash before returning to idle. */
  | 'ended';

export type CallEndReason = 'hangup' | 'decline' | 'busy' | 'timeout';

// -- the slice of WebRTC this needs, as an interface ------------------------

export interface TrackLike {
  kind: string;
  enabled: boolean;
  stop(): void;
}

export interface MediaStreamLike {
  getTracks(): TrackLike[];
  getAudioTracks(): TrackLike[];
  getVideoTracks(): TrackLike[];
}

export interface IceCandidateLike {
  candidate: string;
  sdpMid: string | null;
  sdpMLineIndex: number | null;
}

export interface PeerConnectionLike {
  connectionState: string;
  onicecandidate: ((e: { candidate: IceCandidateLike | null }) => void) | null;
  ontrack: ((e: { streams: MediaStreamLike[] }) => void) | null;
  onconnectionstatechange: (() => void) | null;
  createOffer(): Promise<{ sdp?: string }>;
  createAnswer(): Promise<{ sdp?: string }>;
  setLocalDescription(d: { type: 'offer' | 'answer'; sdp?: string }): Promise<void>;
  setRemoteDescription(d: { type: 'offer' | 'answer'; sdp: string }): Promise<void>;
  addIceCandidate(c: IceCandidateLike): Promise<void>;
  addTrack(track: TrackLike, stream: MediaStreamLike): unknown;
  close(): void;
}

export interface IceServer {
  urls: string | string[];
  username?: string;
  credential?: string;
}

export interface Rtc {
  peerConnection(iceServers: IceServer[]): PeerConnectionLike;
  userMedia(video: boolean): Promise<MediaStreamLike>;
}

/** The browser's own WebRTC. */
export const browserRtc: Rtc = {
  peerConnection: (iceServers) =>
    new RTCPeerConnection({ iceServers }) as unknown as PeerConnectionLike,
  userMedia: (video) =>
    navigator.mediaDevices.getUserMedia({
      audio: true,
      video: video ? { facingMode: 'user', width: { ideal: 1280 }, height: { ideal: 720 } } : false,
    }) as unknown as Promise<MediaStreamLike>,
};

export interface CallOptions {
  /** Both sides give up ringing after this. */
  ringTimeoutMs?: number;
  /** An offer older than this is a missed call, not a ring. */
  offerFreshnessMs?: number;
  /** Trickle ICE is batched into one envelope per burst of this length.
   * Null: only when [CallManager.flushIce] is called (tests). */
  iceFlushMs?: number | null;
  /** How long the "ended" flash stays. */
  endedFlashMs?: number;
  now?: () => number;
}

interface Offer {
  sdp: string;
  media: string;
}

export class CallManager {
  /** Anything about the call changed: phase, streams, mute. */
  onChange?: () => void;

  phase: CallPhase = 'idle';
  peerId: string | null = null;
  callId: string | null = null;
  withVideo = false;
  outgoing = false;
  muted = false;
  cameraOff = false;
  /** One-line epitaph shown on the ended flash. */
  endNote: string | null = null;
  connectedAt: number | null = null;
  localStream: MediaStreamLike | null = null;
  remoteStream: MediaStreamLike | null = null;

  private pc: PeerConnectionLike | null = null;
  private ringTimer: ReturnType<typeof setTimeout> | null = null;
  private iceFlushTimer: ReturnType<typeof setTimeout> | null = null;
  private endedTimer: ReturnType<typeof setTimeout> | null = null;
  private readonly iceOutbox: Array<Record<string, unknown>> = [];
  private readonly pendingRemoteCandidates: IceCandidateLike[] = [];
  private remoteDescriptionSet = false;
  /** Callee: the offer, held until the user accepts. */
  private pendingOffer: Offer | null = null;
  /** The in-flight signaling send, so a test can wait for it. */
  private signaling: Promise<void> = Promise.resolve();

  private readonly ringTimeoutMs: number;
  private readonly offerFreshnessMs: number;
  private readonly iceFlushMs: number | null;
  private readonly endedFlashMs: number;
  private readonly now: () => number;

  constructor(
    private readonly protocol: Protocol,
    private readonly rtc: Rtc = browserRtc,
    opts: CallOptions = {},
  ) {
    this.ringTimeoutMs = opts.ringTimeoutMs ?? 45_000;
    this.offerFreshnessMs = opts.offerFreshnessMs ?? 60_000;
    this.iceFlushMs = opts.iceFlushMs ?? 300;
    this.endedFlashMs = opts.endedFlashMs ?? 2000;
    this.now = opts.now ?? (() => Date.now());
    protocol.onCallSignal = (from, type, payload, sentAt) => this.onSignal(from, type, payload, sentAt);
  }

  get inCall(): boolean {
    return this.phase !== 'idle';
  }

  /** Resolves once the last signaling envelope has gone (tests). */
  whenSignaled(): Promise<void> {
    return this.signaling;
  }

  // -- placing / answering --------------------------------------------------------

  async startCall(peerId: string, video: boolean): Promise<void> {
    if (this.inCall) return;
    this.peerId = peerId;
    this.callId = crypto.randomUUID();
    this.withVideo = video;
    this.outgoing = true;
    this.setPhase('dialing');
    try {
      await this.setupMediaAndPc();
      const offer = await this.pc!.createOffer();
      await this.pc!.setLocalDescription({ type: 'offer', ...(offer.sdp !== undefined ? { sdp: offer.sdp } : {}) });
      await this.signal('call_offer', {
        call_id: this.callId,
        media: video ? 'video' : 'audio',
        sdp: offer.sdp ?? '',
      }, { ring: true });
      this.armRingTimer(async () => {
        await this.sendEnd('timeout');
        await this.recordAndClose('No answer', 'No answer');
      });
    } catch (e) {
      await this.recordAndClose('Call failed', `Call failed: ${(e as Error).message}`);
    }
  }

  async acceptCall(): Promise<void> {
    const offer = this.pendingOffer;
    const peerId = this.peerId;
    if (this.phase !== 'ringing' || offer === null || peerId === null) return;
    this.clearRingTimer();
    this.setPhase('connecting');
    try {
      await this.setupMediaAndPc();
      await this.pc!.setRemoteDescription({ type: 'offer', sdp: offer.sdp });
      this.remoteDescriptionSet = true;
      await this.drainRemoteCandidates();
      const answer = await this.pc!.createAnswer();
      await this.pc!.setLocalDescription({ type: 'answer', ...(answer.sdp !== undefined ? { sdp: answer.sdp } : {}) });
      await this.signal('call_answer', { call_id: this.callId, sdp: answer.sdp ?? '' });
    } catch (e) {
      await this.sendEnd('hangup');
      await this.recordAndClose('Call failed', `Call failed: ${(e as Error).message}`);
    }
  }

  async declineCall(): Promise<void> {
    if (this.phase !== 'ringing') return;
    await this.sendEnd('decline');
    await this.recordAndClose(this.label('Declined'), null, true);
  }

  async hangUp(): Promise<void> {
    if (!this.inCall) return;
    await this.sendEnd('hangup');
    await this.recordAndClose(this.endedLabel(), null, true);
  }

  toggleMute(): void {
    this.muted = !this.muted;
    for (const t of this.localStream?.getAudioTracks() ?? []) t.enabled = !this.muted;
    this.onChange?.();
  }

  toggleCamera(): void {
    if (!this.withVideo) return;
    this.cameraOff = !this.cameraOff;
    for (const t of this.localStream?.getVideoTracks() ?? []) t.enabled = !this.cameraOff;
    this.onChange?.();
  }

  // -- incoming signaling (from Protocol) -------------------------------------------

  private async onSignal(
    from: string,
    type: string,
    payload: Record<string, unknown>,
    sentAt: string,
  ): Promise<void> {
    const id = payload['call_id'];
    if (typeof id !== 'string' || id === '') return;
    switch (type) {
      case 'call_offer':
        await this.onOffer(from, payload, id, sentAt);
        break;
      case 'call_answer':
        await this.onAnswer(from, payload, id);
        break;
      case 'call_ice':
        await this.onIce(from, payload, id);
        break;
      case 'call_end':
        await this.onEnd(from, payload, id);
        break;
    }
    this.onChange?.();
  }

  private async onOffer(
    from: string,
    payload: Record<string, unknown>,
    id: string,
    sentAt: string,
  ): Promise<void> {
    const video = payload['media'] === 'video';
    const sdp = payload['sdp'];
    if (typeof sdp !== 'string') return;
    if (this.now() - sentAtMs(sentAt) > this.offerFreshnessMs) {
      // They gave up long ago — a missed call, not a ring.
      this.protocol.recordCallEvent(from, this.missedLabel(video), false);
      return;
    }
    if (this.inCall) {
      const glare = this.phase === 'dialing' && this.peerId === from;
      if (glare && from < this.protocol.stonechatId) {
        // Simultaneous call, their (lower) ID wins: drop our attempt and
        // ring with theirs. They do the reciprocal and ignore ours.
        this.teardownRtc();
      } else if (!glare) {
        await this.protocol
          .sendCallSignal(from, 'call_end', { call_id: id, reason: 'busy' })
          .catch(() => {});
        this.protocol.recordCallEvent(from, this.missedLabel(video), false);
        return;
      } else {
        return; // glare, our ID wins: they will adopt our offer
      }
    }
    this.peerId = from;
    this.callId = id;
    this.withVideo = video;
    this.outgoing = false;
    this.pendingOffer = { sdp, media: video ? 'video' : 'audio' };
    this.setPhase('ringing');
    this.armRingTimer(async () => {
      this.protocol.recordCallEvent(from, this.missedLabel(this.withVideo), false);
      this.close(true);
    });
  }

  private async onAnswer(from: string, payload: Record<string, unknown>, id: string): Promise<void> {
    if (this.phase !== 'dialing' || id !== this.callId || from !== this.peerId || this.pc === null) return;
    const sdp = payload['sdp'];
    if (typeof sdp !== 'string') return;
    this.clearRingTimer();
    this.setPhase('connecting');
    await this.pc.setRemoteDescription({ type: 'answer', sdp });
    this.remoteDescriptionSet = true;
    await this.drainRemoteCandidates();
  }

  private async onIce(from: string, payload: Record<string, unknown>, id: string): Promise<void> {
    if (id !== this.callId || from !== this.peerId) return;
    const list = Array.isArray(payload['candidates']) ? payload['candidates'] : [];
    for (const raw of list) {
      if (typeof raw !== 'object' || raw === null) continue;
      const r = raw as Record<string, unknown>;
      if (typeof r['candidate'] !== 'string') continue;
      const candidate: IceCandidateLike = {
        candidate: r['candidate'],
        sdpMid: typeof r['sdp_mid'] === 'string' ? r['sdp_mid'] : null,
        sdpMLineIndex: typeof r['sdp_mline_index'] === 'number' ? r['sdp_mline_index'] : null,
      };
      if (this.remoteDescriptionSet && this.pc !== null) {
        await this.pc.addIceCandidate(candidate).catch(() => {});
      } else {
        this.pendingRemoteCandidates.push(candidate);
      }
    }
  }

  private async onEnd(from: string, payload: Record<string, unknown>, id: string): Promise<void> {
    if (id !== this.callId || from !== this.peerId) return;
    const reason = typeof payload['reason'] === 'string' ? payload['reason'] : 'hangup';
    const label =
      reason === 'decline' ? this.label('Declined')
        : reason === 'busy' ? this.label('Busy')
          : reason === 'timeout' ? this.missedLabel(this.withVideo)
            : this.phase === 'active' ? this.endedLabel() : this.label('Canceled');
    await this.recordAndClose(
      label,
      reason === 'decline' ? 'Declined' : reason === 'busy' ? 'Busy' : null,
    );
  }

  // -- WebRTC plumbing -------------------------------------------------------------

  private async setupMediaAndPc(): Promise<void> {
    this.localStream = await this.rtc.userMedia(this.withVideo);
    const pc = this.rtc.peerConnection(await this.iceServers());
    this.pc = pc;
    for (const track of this.localStream.getTracks()) pc.addTrack(track, this.localStream);
    pc.ontrack = (event) => {
      if (event.streams.length > 0) {
        this.remoteStream = event.streams[0]!;
        this.onChange?.();
      }
    };
    pc.onicecandidate = (event) => {
      if (event.candidate) this.queueLocalCandidate(event.candidate);
    };
    pc.onconnectionstatechange = () => {
      if (this.pc !== pc) return;
      switch (pc.connectionState) {
        case 'connected':
          if (this.phase === 'connecting' || this.phase === 'dialing') {
            this.connectedAt = this.now();
            this.setPhase('active');
          }
          break;
        case 'failed':
          void this.recordAndClose(this.endedLabel(), 'Connection lost');
          break;
        default:
          break;
      }
    };
  }

  /** Own mailbox's TURN (when it runs one) + public STUN. Either side's
   * relay candidates can carry the call, so we only need our own. */
  private async iceServers(): Promise<IceServer[]> {
    const servers: IceServer[] = [{ urls: 'stun:stun.l.google.com:19302' }];
    const turn = await this.protocol.turnCredentials();
    if (turn) servers.push({ urls: turn.urls, username: turn.username, credential: turn.credential });
    return servers;
  }

  /** Trickle ICE, batched: one envelope per burst instead of one per
   * candidate (each envelope is a ratchet step and a deposit). */
  private queueLocalCandidate(candidate: IceCandidateLike): void {
    this.iceOutbox.push({
      candidate: candidate.candidate,
      sdp_mid: candidate.sdpMid,
      sdp_mline_index: candidate.sdpMLineIndex,
    });
    if (this.iceFlushMs === null) return;
    this.iceFlushTimer ??= setTimeout(() => {
      this.iceFlushTimer = null;
      void this.flushIce();
    }, this.iceFlushMs);
  }

  /** Send the candidates gathered so far, in one transient envelope. */
  async flushIce(): Promise<void> {
    const peerId = this.peerId;
    const id = this.callId;
    if (peerId === null || id === null || this.iceOutbox.length === 0) return;
    const batch = this.iceOutbox.splice(0);
    // Late or lost candidates are self-healing: transient, never queued.
    await this.signal('call_ice', { call_id: id, candidates: batch }, { transient: true }).catch(() => {});
  }

  private async drainRemoteCandidates(): Promise<void> {
    const pending = this.pendingRemoteCandidates.splice(0);
    for (const c of pending) await this.pc?.addIceCandidate(c).catch(() => {});
  }

  private signal(
    type: string,
    payload: Record<string, unknown>,
    opts: { transient?: boolean; ring?: boolean } = {},
  ): Promise<void> {
    const peerId = this.peerId;
    if (peerId === null) return Promise.resolve();
    const p = this.protocol.sendCallSignal(peerId, type, payload, opts);
    this.signaling = this.signaling.then(() => p).catch(() => {});
    return p;
  }

  // -- teardown ---------------------------------------------------------------------

  private armRingTimer(onTimeout: () => Promise<void>): void {
    this.clearRingTimer();
    this.ringTimer = setTimeout(() => {
      this.ringTimer = null;
      void onTimeout();
    }, this.ringTimeoutMs);
  }

  private clearRingTimer(): void {
    if (this.ringTimer) clearTimeout(this.ringTimer);
    this.ringTimer = null;
  }

  private async sendEnd(reason: CallEndReason): Promise<void> {
    if (this.peerId === null || this.callId === null) return;
    try {
      await this.signal('call_end', { call_id: this.callId, reason });
    } catch {
      // their ring timer ends the call for them
    }
  }

  private label(what: string): string {
    return `${what} ${this.withVideo ? 'video' : 'voice'} call`;
  }

  private missedLabel(video: boolean): string {
    return `Missed ${video ? 'video' : 'voice'} call`;
  }

  private endedLabel(): string {
    const started = this.connectedAt;
    if (started === null) return this.label('Canceled');
    const seconds = Math.max(0, Math.floor((this.now() - started) / 1000));
    const mm = String(Math.floor(seconds / 60));
    const ss = String(seconds % 60).padStart(2, '0');
    return `${this.withVideo ? 'Video' : 'Voice'} call · ${mm}:${ss}`;
  }

  /** Write the call's epitaph into the conversation, then tear down. */
  private async recordAndClose(label: string, note: string | null, silent = false): Promise<void> {
    if (this.peerId !== null) this.protocol.recordCallEvent(this.peerId, label, this.outgoing);
    this.endNote = note;
    this.close(silent || note === null);
  }

  private close(silent: boolean): void {
    this.teardownRtc();
    if (!silent) {
      this.setPhase('ended'); // brief flash with endNote
      this.endedTimer = setTimeout(() => {
        this.endedTimer = null;
        if (this.phase === 'ended') this.resetToIdle();
      }, this.endedFlashMs);
    } else {
      this.resetToIdle();
    }
  }

  private teardownRtc(): void {
    this.clearRingTimer();
    if (this.iceFlushTimer) clearTimeout(this.iceFlushTimer);
    this.iceFlushTimer = null;
    this.iceOutbox.length = 0;
    this.pendingRemoteCandidates.length = 0;
    this.remoteDescriptionSet = false;
    this.pendingOffer = null;
    this.remoteStream = null;
    const stream = this.localStream;
    this.localStream = null;
    if (stream) for (const t of stream.getTracks()) t.stop();
    const pc = this.pc;
    this.pc = null;
    pc?.close();
  }

  private resetToIdle(): void {
    if (this.endedTimer) clearTimeout(this.endedTimer);
    this.endedTimer = null;
    this.peerId = null;
    this.callId = null;
    this.withVideo = false;
    this.outgoing = false;
    this.muted = false;
    this.cameraOff = false;
    this.endNote = null;
    this.connectedAt = null;
    this.setPhase('idle');
  }

  private setPhase(next: CallPhase): void {
    this.phase = next;
    this.onChange?.();
  }
}
