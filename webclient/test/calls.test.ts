/**
 * Calls, with WebRTC faked.
 *
 * What is pinned is the signaling (PROTOCOL.md "Calls"): the offer rings,
 * ICE is transient and batched, both sides record the same outcome, busy and
 * stale offers, the glare tie-break, timeouts. The fake peer connection
 * produces one candidate per local description and connects when told to.
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  CallManager,
  type IceCandidateLike,
  type IceServer,
  type MediaStreamLike,
  type PeerConnectionLike,
  type Rtc,
  type TrackLike,
} from '../src/calls.js';
import { store } from '../src/store.js';
import { drainAll, raw, world } from './fixtures.js';

class FakeTrack implements TrackLike {
  enabled = true;
  stopped = false;
  constructor(readonly kind: string) {}
  stop() {
    this.stopped = true;
  }
}

class FakeStream implements MediaStreamLike {
  constructor(readonly tracks: FakeTrack[]) {}
  getTracks() {
    return this.tracks;
  }
  getAudioTracks() {
    return this.tracks.filter((t) => t.kind === 'audio');
  }
  getVideoTracks() {
    return this.tracks.filter((t) => t.kind === 'video');
  }
}

class FakePc implements PeerConnectionLike {
  connectionState = 'new';
  onicecandidate: PeerConnectionLike['onicecandidate'] = null;
  ontrack: PeerConnectionLike['ontrack'] = null;
  onconnectionstatechange: PeerConnectionLike['onconnectionstatechange'] = null;
  local: { type: string; sdp?: string } | null = null;
  remote: { type: string; sdp: string } | null = null;
  added: IceCandidateLike[] = [];
  tracks = 0;
  closed = false;
  constructor(readonly iceServers: IceServer[]) {}
  async createOffer() {
    return { sdp: 'v=0 offer' };
  }
  async createAnswer() {
    return { sdp: 'v=0 answer' };
  }
  async setLocalDescription(d: { type: 'offer' | 'answer'; sdp?: string }) {
    this.local = d;
    // Trickle: one candidate, soon after.
    setTimeout(() => this.onicecandidate?.({ candidate: { candidate: `cand-${d.type}`, sdpMid: '0', sdpMLineIndex: 0 } }), 1);
  }
  async setRemoteDescription(d: { type: 'offer' | 'answer'; sdp: string }) {
    this.remote = d;
  }
  async addIceCandidate(c: IceCandidateLike) {
    this.added.push(c);
  }
  addTrack() {
    this.tracks += 1;
  }
  close() {
    this.closed = true;
  }
  connect() {
    this.connectionState = 'connected';
    this.onconnectionstatechange?.();
    this.ontrack?.({ streams: [new FakeStream([new FakeTrack('audio')])] });
  }
  fail() {
    this.connectionState = 'failed';
    this.onconnectionstatechange?.();
  }
}

function fakeRtc() {
  const pcs: FakePc[] = [];
  const streams: FakeStream[] = [];
  const rtc: Rtc = {
    peerConnection: (iceServers) => {
      const pc = new FakePc(iceServers);
      pcs.push(pc);
      return pc;
    },
    userMedia: async (video) => {
      const s = new FakeStream(video ? [new FakeTrack('audio'), new FakeTrack('video')] : [new FakeTrack('audio')]);
      streams.push(s);
      return s;
    },
  };
  return { rtc, pcs, streams };
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Two people who can call each other, with fast timers. */
async function callers(opts: { ringTimeoutMs?: Record<string, number> } = {}) {
  const { who, as, time } = await world('alice', 'bob', 'carol');
  // ICE is flushed by hand and ring timers are per side: a timer that fires
  // while the test is "being" the other side would write the sender's
  // ratchet into the wrong storage (the fakes share one localStorage).
  const make = (name: 'alice' | 'bob' | 'carol') => {
    const f = fakeRtc();
    const calls = new CallManager(who[name].protocol, f.rtc, {
      ringTimeoutMs: opts.ringTimeoutMs?.[name] ?? 10_000, iceFlushMs: null, endedFlashMs: 5, now: time.now,
    });
    return { ...f, calls };
  };
  const a = make('alice');
  const b = make('bob');
  const c = make('carol');
  const callEvents = (name: 'alice' | 'bob' | 'carol', peer: string) =>
    as(name, async () => (store.messages()[peer] ?? []).filter((m) => m.call).map((m) => [m.text, m.mine]));
  return { who, as, time, a, b, c, callEvents };
}

test('a call rings, connects, and ends with the same record on both sides', async () => {
  const { who, as, time, a, b, callEvents } = await callers();
  const { alice, bob } = who;

  await as('alice', () => a.calls.startCall(bob.id, false));
  assert.equal(a.calls.phase, 'dialing');
  const offer = bob.relay.deposits[bob.relay.deposits.length - 1]!;
  assert.equal(offer['ring'], true, 'the offer rings');

  await as('bob', () => drainAll(bob.protocol));
  assert.equal(b.calls.phase, 'ringing');
  assert.equal(b.calls.peerId, alice.id);
  assert.equal(b.calls.withVideo, false);

  await as('bob', async () => {
    await b.calls.acceptCall();
    await b.calls.whenSignaled();
  });
  assert.equal(b.calls.phase, 'connecting');
  assert.equal(b.pcs[0]!.remote?.sdp, 'v=0 offer');
  await as('alice', () => drainAll(alice.protocol));
  assert.equal(a.calls.phase, 'connecting');
  assert.equal(a.pcs[0]!.remote?.sdp, 'v=0 answer');

  // Trickle ICE: batched, queued without a push, applied on the other side.
  await sleep(5); // the fake peer connections have produced a candidate each
  await as('alice', () => a.calls.flushIce());
  await as('bob', () => b.calls.flushIce());
  const ice = bob.relay.deposits.filter((d) => d['push'] === false);
  assert.ok(ice.length >= 1, 'candidates went as queued, push-free envelopes');
  assert.equal(bob.relay.deposits.filter((d) => d['transient'] === true).length, 0, 'never transient');
  await as('bob', () => drainAll(bob.protocol));
  await as('alice', () => drainAll(alice.protocol));
  assert.deepEqual(b.pcs[0]!.added.map((c) => c.candidate), ['cand-offer']);
  assert.deepEqual(a.pcs[0]!.added.map((c) => c.candidate), ['cand-answer']);

  a.pcs[0]!.connect();
  b.pcs[0]!.connect();
  assert.equal(a.calls.phase, 'active');
  assert.equal(b.calls.phase, 'active');
  assert.ok(a.calls.remoteStream);

  time.advance(65_000);
  await as('alice', () => a.calls.hangUp());
  assert.equal(a.calls.phase, 'idle');
  assert.equal(a.pcs[0]!.closed, true);
  assert.equal(a.streams[0]!.tracks[0]!.stopped, true, 'the microphone is released');
  await as('bob', () => drainAll(bob.protocol));
  // A hang-up needs no epitaph on screen: straight back to idle, as on the
  // phone; the record in the conversation says what happened.
  assert.equal(b.calls.phase, 'idle');
  assert.equal(b.pcs[0]!.closed, true);
  assert.deepEqual(await callEvents('alice', bob.id), [['Voice call · 1:05', true]]);
  assert.deepEqual(await callEvents('bob', alice.id), [['Voice call · 1:05', false]]);
});

test('declining tells the caller why', async () => {
  const { who, as, a, b, callEvents } = await callers();
  const { alice, bob } = who;
  await as('alice', () => a.calls.startCall(bob.id, true));
  await as('bob', () => drainAll(bob.protocol));
  assert.equal(b.calls.withVideo, true);
  await as('bob', () => b.calls.declineCall());
  assert.equal(b.calls.phase, 'idle');
  await as('alice', () => drainAll(alice.protocol));
  assert.equal(a.calls.phase, 'ended');
  assert.equal(a.calls.endNote, 'Declined');
  assert.deepEqual(await callEvents('alice', bob.id), [['Declined video call', true]]);
  assert.deepEqual(await callEvents('bob', alice.id), [['Declined video call', false]]);
});

test('a second caller is answered busy', async () => {
  const { who, as, a, b, c, callEvents } = await callers();
  const { alice, bob, carol } = who;
  await as('alice', () => a.calls.startCall(bob.id, false));
  await as('bob', () => drainAll(bob.protocol));
  await as('carol', () => c.calls.startCall(bob.id, false));
  await as('bob', async () => {
    await drainAll(bob.protocol);
    await b.calls.whenSignaled();
  });
  assert.equal(b.calls.phase, 'ringing', 'still ringing with alice');
  assert.equal(b.calls.peerId, alice.id);
  await as('carol', () => drainAll(carol.protocol));
  assert.equal(c.calls.phase, 'ended');
  assert.equal(c.calls.endNote, 'Busy');
  assert.deepEqual(await callEvents('bob', carol.id), [['Missed voice call', false]]);
  assert.deepEqual(await callEvents('carol', bob.id), [['Busy voice call', true]]);
});

test('an old offer is a missed call, not a ring', async () => {
  const { who, as, b, callEvents } = await callers();
  const { alice, bob } = who;
  await as('alice', () =>
    raw(alice.protocol, bob.id, 'call_offer', { call_id: crypto.randomUUID(), media: 'video', sdp: 'v=0' }, 1, {
      sentAt: new Date(Date.now() - 120_000).toISOString(),
    }));
  await as('bob', () => drainAll(bob.protocol));
  assert.equal(b.calls.phase, 'idle');
  assert.deepEqual(await callEvents('bob', alice.id), [['Missed video call', false]]);
});

test('when both call at once, the lower ID\'s offer wins', async () => {
  const { who, as, a, b } = await callers();
  const { alice, bob } = who;
  const [lower, higher] = alice.id < bob.id ? [a, b] : [b, a];
  const lowerName = alice.id < bob.id ? 'alice' : 'bob';
  const higherName = lowerName === 'alice' ? 'bob' : 'alice';
  const lowerId = who[lowerName].id;
  const higherId = who[higherName].id;

  await as(lowerName, () => lower.calls.startCall(higherId, false));
  await as(higherName, () => higher.calls.startCall(lowerId, false));
  await as(lowerName, () => drainAll(who[lowerName].protocol));
  await as(higherName, () => drainAll(who[higherName].protocol));
  assert.equal(lower.calls.phase, 'dialing', 'ours wins: their offer is ignored');
  assert.equal(higher.calls.phase, 'ringing', 'theirs wins: we drop ours and ring');
  assert.equal(higher.calls.callId, lower.calls.callId);
  assert.equal(higher.pcs[0]!.closed, true, 'the dropped attempt is torn down');
});

test('nobody answering is a timeout on both sides', async () => {
  const { who, as, a, b, callEvents } = await callers({ ringTimeoutMs: { alice: 80, bob: 20 } });
  const { alice, bob } = who;
  await as('alice', () => a.calls.startCall(bob.id, false));
  await as('bob', () => drainAll(bob.protocol));
  assert.equal(b.calls.phase, 'ringing');
  // Bob's ring runs out first, then Alice's; each under its own storage.
  await as('bob', () => sleep(35));
  assert.equal(b.calls.phase, 'idle');
  await as('alice', async () => {
    await sleep(60);
    await a.calls.whenSignaled();
  });
  assert.equal(a.calls.phase, 'idle', 'flashed "No answer" and returned');
  assert.deepEqual(await callEvents('alice', bob.id), [['No answer', true]]);
  assert.equal(bob.relay.deposits.filter((d) => d['transient'] !== true).length, 2, 'the offer, then the timeout');
  // The caller's timeout arrives for a call Bob no longer has, and is ignored.
  await as('bob', () => drainAll(bob.protocol));
  assert.equal(b.calls.phase, 'idle');
  assert.deepEqual(await callEvents('bob', alice.id), [['Missed voice call', false]]);
});

test('signals for another call, or from someone else, are ignored', async () => {
  const { who, as, a, b, c } = await callers();
  const { alice, bob, carol } = who;
  await as('alice', () => a.calls.startCall(bob.id, false));
  await as('bob', () => drainAll(bob.protocol));
  const id = b.calls.callId!;
  await as('carol', async () => {
    await raw(carol.protocol, bob.id, 'call_end', { call_id: id, reason: 'hangup' });
    await raw(carol.protocol, bob.id, 'call_ice', { call_id: id, candidates: [{ candidate: 'x' }] });
  });
  await as('alice', () => raw(alice.protocol, bob.id, 'call_end', { call_id: crypto.randomUUID(), reason: 'hangup' }));
  await as('bob', () => drainAll(bob.protocol));
  assert.equal(b.calls.phase, 'ringing', 'still ringing');
  void c;
});

test('the mailbox\'s call relay is the only ICE server; without one the call fails and says so', async () => {
  const { who, as, a, b } = await callers();
  const { alice, bob } = who;
  alice.relay.turn = { urls: ['turn:1.2.3.4:3478?transport=udp'], username: '1:stonechat', credential: 'c' };
  await as('alice', () => a.calls.startCall(bob.id, false));
  assert.deepEqual(a.pcs[0]!.iceServers, [
    { urls: ['turn:1.2.3.4:3478?transport=udp'], username: '1:stonechat', credential: 'c' },
  ], 'no third-party STUN');
  await as('bob', () => drainAll(bob.protocol));
  bob.relay.turn = null;
  await as('bob', () => b.calls.acceptCall());
  assert.equal(b.pcs.length, 0, 'no peer connection without a relay');
  assert.equal(b.calls.phase, 'ended');
  assert.match(b.calls.endNote ?? '', /no call relay/);
});

test('a lost connection ends the call with a note', async () => {
  const { who, as, a, b } = await callers();
  const { bob } = who;
  await as('alice', () => a.calls.startCall(bob.id, false));
  await as('bob', () => drainAll(bob.protocol));
  await as('bob', () => b.calls.acceptCall());
  b.pcs[0]!.connect();
  assert.equal(b.calls.phase, 'active');
  b.pcs[0]!.fail();
  await sleep(1);
  assert.equal(b.calls.phase, 'ended');
  assert.equal(b.calls.endNote, 'Connection lost');
});

test('without a call manager, an offer is a notice to answer on the phone', async () => {
  const { who, as } = await world('alice', 'bob');
  const { alice, bob } = who;
  await as('alice', () => raw(alice.protocol, bob.id, 'call_offer', { call_id: crypto.randomUUID(), media: 'audio', sdp: 'v=0' }));
  const got = await as('bob', () => drainAll(bob.protocol));
  assert.equal(got.length, 1);
  assert.equal(got[0]!.call, true);
  assert.match(got[0]!.text, /answer on your phone/);
});
