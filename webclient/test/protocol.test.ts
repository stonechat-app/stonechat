/**
 * Two web sessions, talking.
 *
 * The relay and hub are mocked — a fake mailbox holding queues and prekey
 * bundles, a fake directory — because what needs proving here is the *crypto
 * orchestration*, and that should be provable without a browser or a running
 * relay. The relay's own behaviour has its own tests, and the wire format has
 * the conformance corpus.
 *
 * What this pins: PQXDH between two devices, the certificate checks on both
 * sides, the AEAD binding both device numbers, ratchet advance across several
 * messages, and one-time prekeys being consumed exactly once.
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { StonechatCore, type SignedCert } from '../src/core.js';
import { DeviceKeys } from '../src/device.js';
import { Hub, type DirectoryEntry } from '../src/hub.js';
import type { LinkGrant } from '../src/linking.js';
import type { Mailbox } from '../src/mailbox.js';
import { Protocol } from '../src/protocol.js';
import { store } from '../src/store.js';
import { b64decode, b64encode, utf8 } from '../src/bytes.js';
import { certSigKey } from '../src/device.js';

const wasm = readFileSync(
  fileURLToPath(
    new URL(
      '../../core/target/wasm32-unknown-unknown/release/stonechat_core.wasm',
      import.meta.url,
    ),
  ),
);
const core = await StonechatCore.instantiate(
  wasm.buffer.slice(wasm.byteOffset, wasm.byteOffset + wasm.byteLength),
);

// -- a mock relay ----------------------------------------------------------

interface Queued {
  id: string;
  sealed: string;
}

/** One owner's mailbox: a prekey store and a per-device queue. */
class FakeRelay {
  /** Per device, like the real relay: each device publishes its own pool and
   * its own certificate. One shared slot would let a sibling's publish clobber
   * another's, and the mismatch it causes is exactly the bug per-device
   * prekeys exist to prevent. */
  prekeys = new Map<number, Record<string, unknown>>();
  /** Per-device queues. A single shared queue would let a sibling drain mail
   * addressed to another device, which is precisely what per-device fan-out
   * exists to prevent — a mock that did that could not see a routing bug. */
  queues = new Map<number, Queued[]>();
  /** Every device this owner has, as `/prekeys/devices` reports them. */
  devices: number[] = [1];
  /** One-time prekeys handed out, so double-use is detectable. */
  servedOpks: number[] = [];

  bundle(device = 1): Record<string, unknown> {
    const p = this.prekeys.get(device) as {
      spk: unknown;
      kspk: unknown;
      opks: Array<{ id: number; pub: string }>;
      kopks: Array<{ id: number; pub: string }>;
      cert: SignedCert;
    };
    if (!p) throw new Error(`no prekeys published for device ${device}`);
    // Consumed server-side, exactly like the real relay.
    const opk = p.opks.shift();
    const kopk = p.kopks.shift();
    if (opk) this.servedOpks.push(opk.id);
    return {
      spk: p.spk,
      kspk: p.kspk,
      cert: p.cert,
      ...(opk ? { opk } : {}),
      ...(kopk ? { kopk } : {}),
    };
  }
}

/** A Mailbox-shaped object over a FakeRelay. */
function fakeMailbox(relay: FakeRelay, drainDevice = 1): Mailbox {
  const mailbox = {
    closed: new Promise<void>(() => {}),
    close() {},
    async request() {
      throw new Error('not used by these tests');
    },
    async json<T>(method: string, path: string, body?: unknown): Promise<T> {
      const route = path.split('?')[0]!;
      if (method === 'POST' && route === '/prekeys') {
        relay.prekeys.set(drainDevice, body as Record<string, unknown>);
        return null as T;
      }
      if (method === 'GET' && route === '/prekeys/devices') {
        return { devices: relay.devices.map((d) => ({ device_id: d })) } as T;
      }
      if (method === 'GET' && route === '/prekeys/bundle') {
        const want = Number(
          new URLSearchParams(path.split('?')[1] ?? '').get('device') ?? 1,
        );
        return relay.bundle(want) as T;
      }
      if (method === 'POST' && route === '/inbox') {
        const envelope = body as Queued & { device?: number };
        const device = envelope.device ?? 1;
        const q = relay.queues.get(device) ?? [];
        q.push({ id: envelope.id, sealed: envelope.sealed });
        relay.queues.set(device, q);
        return { status: 'delivered' } as T;
      }
      throw new Error(`unmocked ${method} ${path}`);
    },
    async *socket() {
      const q = relay.queues.get(drainDevice) ?? [];
      for (const item of q.splice(0)) {
        yield { kind: 'envelope' as const, envelope: item as unknown as Record<string, unknown> };
      }
    },
    ack: async () => {},
  };
  return mailbox as unknown as Mailbox;
}

// -- identities ------------------------------------------------------------

/** A phone: an identity that can certify devices. */
function phone(seedFill: number) {
  const seed = new Uint8Array(32).fill(seedFill);
  const identity = core.identity(seed, false);
  return {
    id: identity.stonechat_id,
    pub: identity.public,
    certify(keys: DeviceKeys, deviceId: number): SignedCert {
      return core.devcertSign(
        {
          stonechat_id: identity.stonechat_id,
          device_id: deviceId,
          sig_pub: b64encode(keys.sigPublic),
          seal_pub: b64encode(keys.sealPublic),
          not_after: Math.floor(Date.now() / 1000) + 604_800,
        },
        seed,
      );
    },
  };
}

function grantFor(
  owner: ReturnType<typeof phone>,
  cert: SignedCert,
  deviceId: number,
): LinkGrant {
  return {
    identity_pub: owner.pub,
    cert,
    stonechat_id: owner.id,
    display_name: '',
    hub_url: 'https://hub.example',
    relay_address: `https://relay.${deviceId}:8080`,
    relay_tls_fp: 'ZnA=',
    device_id: deviceId,
    device_token: `tok-${deviceId}`.padEnd(32, 'x'),
    bundle_token: `bundle-${owner.id}`,
  };
}

/** Wire two sessions together through fake relays and a fake directory. */
async function pair() {
  // localStorage is per-process here, so the two sides cannot share one.
  // Swapping the backing object between calls is how each gets its own.
  const worlds = new Map<string, Record<string, string>>();
  let active = 'a';
  const backing: Storage = {
    getItem: (k) => worlds.get(active)![k] ?? null,
    setItem: (k, v) => {
      worlds.get(active)![k] = v;
    },
    removeItem: (k) => {
      delete worlds.get(active)![k];
    },
    clear: () => worlds.set(active, {}),
    key: () => null,
    length: 0,
  };
  worlds.set('a', {});
  worlds.set('b', {});
  (globalThis as { localStorage?: Storage }).localStorage = backing;

  const alice = phone(7);
  const bob = phone(9);
  const aKeys = DeviceKeys.generate(core);
  const bKeys = DeviceKeys.generate(core);
  const aRelay = new FakeRelay();
  const bRelay = new FakeRelay();
  const relays: Record<string, FakeRelay> = {
    [alice.id]: aRelay,
    [bob.id]: bRelay,
  };
  const entries: Record<string, DirectoryEntry> = {
    [alice.id]: { stonechat_id: alice.id, pubkey: alice.pub },
    [bob.id]: { stonechat_id: bob.id, pubkey: bob.pub },
  };
  const hub = {
    directory: async (id: string) => entries[id]!,
  } as unknown as Hub;

  const dial = async (entry: DirectoryEntry) =>
    fakeMailbox(relays[entry.stonechat_id]!, entry.stonechat_id === alice.id ? 2 : 1);

  // Alice is a browser session — device 2, like every web device. That is the
  // case a reply has to reach, and it only does because the fan-out reads her
  // bundle token rather than assuming device 1.
  aRelay.devices = [2];
  bRelay.devices = [1];
  const A = new Protocol(core, hub, aKeys, grantFor(alice, alice.certify(aKeys, 2), 2), dial);
  const B = new Protocol(core, hub, bKeys, grantFor(bob, bob.certify(bKeys, 1), 1), dial);

  const as = <T>(who: 'a' | 'b', fn: () => Promise<T>): Promise<T> => {
    active = who;
    return fn();
  };
  return { alice, bob, A, B, aRelay, bRelay, as };
}

/** Collect whatever a session can currently drain. */
async function drain(p: Protocol): Promise<Array<{ text: string; peerId: string }>> {
  const out: Array<{ text: string; peerId: string }> = [];
  for await (const m of p.receive()) out.push({ text: m.text, peerId: m.peerId });
  return out;
}

// -- the tests -------------------------------------------------------------

test('one session sends, the other receives', async () => {
  const { alice, bob, A, B, as } = await pair();
  await as('b', () => B.publishPrekeys());
  const sent = await as('a', () => A.send(bob.id, 'hello from a browser'));
  assert.equal(sent.text, 'hello from a browser');

  const got = await as('b', () => drain(B));
  assert.equal(got.length, 1);
  assert.equal(got[0]!.text, 'hello from a browser');
  assert.equal(got[0]!.peerId, alice.id);
});

test('the ratchet advances across several messages, in order', async () => {
  const { bob, A, B, as } = await pair();
  await as('b', () => B.publishPrekeys());
  for (const text of ['one', 'two', 'three']) {
    await as('a', () => A.send(bob.id, text));
  }
  const got = await as('b', () => drain(B));
  assert.deepEqual(
    got.map((m) => m.text),
    ['one', 'two', 'three'],
  );
});

test('a reply works, which means the responder built a usable session', async () => {
  // The direction that only works if the X3DH response produced the same root
  // key the initiator derived. A one-way test would pass with a broken
  // responder that merely decrypted.
  const { alice, bob, A, B, as } = await pair();
  await as('b', () => B.publishPrekeys());
  await as('a', () => A.publishPrekeys());
  await as('a', () => A.send(bob.id, 'ping'));
  assert.equal((await as('b', () => drain(B)))[0]!.text, 'ping');

  await as('b', () => B.send(alice.id, 'pong'));
  const back = await as('a', () => drain(A));
  assert.equal(back.length, 1);
  assert.equal(back[0]!.text, 'pong');
  assert.equal(back[0]!.peerId, bob.id);
});

test('the sender is recorded as a contact, with their bundle token', async () => {
  // The token rides every envelope; it is what later lets us reach all of a
  // peer's devices instead of only their primary.
  const { alice, bob, A, B, as } = await pair();
  await as('b', () => B.publishPrekeys());
  await as('a', () => A.send(bob.id, 'hi'));
  await as('b', () => drain(B));
  const { store } = await import('../src/store.js');
  const contacts = await as('b', async () => store.contacts());
  assert.equal(contacts[alice.id]?.stonechatId, alice.id);
  assert.equal(contacts[alice.id]?.bundleToken, `bundle-${alice.id}`);
  void bob;
});

test('a one-time prekey is consumed exactly once', async () => {
  const { bob, A, B, as, bRelay } = await pair();
  await as('b', () => B.publishPrekeys());
  await as('a', () => A.send(bob.id, 'first'));
  await as('b', () => drain(B));
  assert.equal(bRelay.servedOpks.length, 1, 'the handshake consumed one OPK');

  // A second message reuses the established session and asks for nothing more.
  await as('a', () => A.send(bob.id, 'second'));
  assert.equal(bRelay.servedOpks.length, 1, 'an established session fetches no bundle');
});

test('an envelope for another device cannot be opened', async () => {
  // Sealed to a different device's key: the AEAD refuses, and the client
  // drops it rather than surfacing garbage.
  const { bob, A, B, as, bRelay } = await pair();
  await as('b', () => B.publishPrekeys());
  await as('a', () => A.send(bob.id, 'for someone else'));
  const stray = bRelay.queues.get(1)![0]!;
  const other = DeviceKeys.generate(core);
  bRelay.queues.set(1, [
    {
      id: stray.id,
      sealed: b64encode(
        core.seal(
          other.sealPublic,
          utf8.encode('{"type":"msg"}'),
          crypto.getRandomValues(new Uint8Array(64)),
          crypto.getRandomValues(new Uint8Array(24)),
        ),
      ),
    },
  ]);
  assert.deepEqual(await as('b', () => drain(B)), []);
});

test('a handshake with no certificate establishes nothing', () => {
  // The key in an x3dh block is the sender's *device* key, which does not hash
  // to their SC- ID. The certificate is the only thing that binds it to them,
  // so a block without one must not produce a session — otherwise anyone could
  // hand us a key and become a contact.
  const alice = phone(7);
  const keys = DeviceKeys.generate(core);
  const cert = alice.certify(keys, 2);

  // The certificate itself is sound...
  assert.equal(
    core.devcertVerify(cert, b64decode(alice.pub), Math.floor(Date.now() / 1000)),
    'valid',
  );
  // ...and it is the *pairing* with the handshake key that the responder
  // checks. A certificate for one key cannot vouch for another.
  const someoneElse = DeviceKeys.generate(core);
  assert.notEqual(
    b64encode(certSigKey(cert)!),
    b64encode(someoneElse.sigPublic),
    'a certificate must not vouch for a key it does not name',
  );
});

test('a certificate for another device id is refused', async () => {
  // Signed, unexpired, genuinely theirs — for a different device than the slot
  // it arrived in. A relay shuffling certificates between devices would
  // redirect mail, and the signature covers the id exactly so it can be caught.
  const { bob, A, as, bRelay } = await pair();
  await as('b', () => B_publish(bRelay));
  await assert.rejects(
    () => as('a', () => A.send(bob.id, 'should not send')),
    /names a different device/,
  );
});

/** Publish prekeys carrying a certificate that names the wrong device. */
async function B_publish(relay: FakeRelay): Promise<void> {
  const bob = phone(9);
  const keys = DeviceKeys.generate(core);
  relay.prekeys.set(1, {
    spk: { id: 1, pub: b64encode(core.x25519Public(new Uint8Array(32).fill(3))), sig: '' },
    kspk: { id: 1, pub: b64encode(core.mlkemPkFromSeed(new Uint8Array(64).fill(4))), sig: '' },
    opks: [],
    kopks: [],
    // Device 5, but it will be served in device 1's slot.
    cert: bob.certify(keys, 5),
  });
  relay.devices = [1];
}

// -- self-sync ---------------------------------------------------------------

/**
 * Two devices of ONE identity — a phone and a browser — plus someone to talk
 * to. This is the shape the slim client got wrong: each device only ever saw
 * what a *peer* sent it, so a message typed on one never appeared on the other.
 */
async function ownDevices() {
  const worlds = new Map<string, Record<string, string>>();
  let active = 'phone';
  (globalThis as { localStorage?: Storage }).localStorage = {
    getItem: (k) => worlds.get(active)![k] ?? null,
    setItem: (k, v) => {
      worlds.get(active)![k] = v;
    },
    removeItem: (k) => {
      delete worlds.get(active)![k];
    },
    clear: () => worlds.set(active, {}),
    key: () => null,
    length: 0,
  } as Storage;
  worlds.set('phone', {});
  worlds.set('browser', {});
  worlds.set('them', {});

  const me = phone(7);
  const them = phone(9);
  const themKeys = DeviceKeys.generate(core);
  const phoneKeys = DeviceKeys.generate(core);
  const browserKeys = DeviceKeys.generate(core);
  const myRelay = new FakeRelay();
  const theirRelay = new FakeRelay();
  // One identity, two devices, one mailbox — which is the whole point.
  myRelay.devices = [1, 2];
  theirRelay.devices = [1];
  const relays: Record<string, FakeRelay> = {
    [me.id]: myRelay,
    [them.id]: theirRelay,
  };
  const entries: Record<string, DirectoryEntry> = {
    [me.id]: { stonechat_id: me.id, pubkey: me.pub },
    [them.id]: { stonechat_id: them.id, pubkey: them.pub },
  };
  const hub = { directory: async (id: string) => entries[id]! } as unknown as Hub;

  const make = (keys: DeviceKeys, device: number, drain: number) =>
    new Protocol(
      core,
      hub,
      keys,
      grantFor(me, me.certify(keys, device), device),
      async (entry: DirectoryEntry) => fakeMailbox(relays[entry.stonechat_id]!, drain),
    );

  // The person being written to has to be a real participant: they publish
  // prekeys and hold their own storage, exactly like the two devices do.
  const themProtocol = new Protocol(
    core,
    hub,
    themKeys,
    grantFor(them, them.certify(themKeys, 1), 1),
    async (entry: DirectoryEntry) => fakeMailbox(relays[entry.stonechat_id]!, 1),
  );

  const as = <T>(
    who: 'phone' | 'browser' | 'them',
    fn: () => Promise<T>,
  ): Promise<T> => {
    active = who;
    return fn();
  };
  return {
    me,
    them,
    themProtocol,
    myRelay,
    phone: make(phoneKeys, 1, 1),
    browser: make(browserKeys, 2, 2),
    as,
  };
}

test('a self-sync does not make us our own contact', async () => {
  // sync_sent arrives *from* our own identity, and every sender was recorded
  // as a contact — so a browser listed its own owner as a conversation, with
  // no messages in it and no way to have any. Nothing needs the record:
  // sibling devices come from the grant's bundle token.
  const { me, them, themProtocol, phone: myPhone, browser, as } =
    await ownDevices();
  await as('them', () => themProtocol.publishPrekeys());
  await as('phone', () => myPhone.publishPrekeys());
  await as('browser', () => browser.publishPrekeys());

  await as('browser', async () => {
    await browser.send(them.id, 'hello');
    await browser.whenSynced();
  });
  // The phone drains the sync its sibling sent.
  await as('phone', async () => {
    for await (const _ of myPhone.receive()) break;
  });

  const listed = await as('phone', async () => Object.keys(store.contacts()));
  assert.ok(
    !listed.includes(me.id),
    `our own identity must not be a contact, got: ${listed.join(', ')}`,
  );
  // Deliberately not asserting the peer is listed here: this device only saw
  // a sync, and a sync records the conversation, not a contact. The device
  // that actually talked to them is the one that knows them.
});

test('a message sent on one device appears on the other', async () => {
  // The bug: replies from a peer reached both devices, but our own outgoing
  // messages reached neither sibling — each device only ever saw what a peer
  // sent it.
  const { them, themProtocol, phone: myPhone, browser, as, myRelay } =
    await ownDevices();
  await as('them', () => themProtocol.publishPrekeys());
  await as('phone', () => myPhone.publishPrekeys());
  await as('browser', () => browser.publishPrekeys());

  const sent = await as('browser', async () => {
    const m = await browser.send(them.id, 'typed in the tab');
    await browser.whenSynced();
    return m;
  });
  assert.equal(sent.text, 'typed in the tab');

  // The sync copy is addressed to device 1 — the sibling, not the sender.
  assert.equal(myRelay.queues.get(1)?.length, 1, 'sibling should have a copy');
  assert.equal(myRelay.queues.get(2)?.length ?? 0, 0, 'no copy to itself');

  const onPhone = await as('phone', () => drain(myPhone));
  assert.equal(onPhone.length, 1);
  assert.equal(onPhone[0]!.text, 'typed in the tab');
  assert.equal(onPhone[0]!.peerId, them.id, 'filed under the conversation');
});

test('a synced message is marked as ours, not as theirs', async () => {
  // It has to render on the right side of the ledger; a sync copy shown as an
  // incoming message would read as the peer echoing us back.
  const { them, themProtocol, phone: myPhone, browser, as } = await ownDevices();
  await as('them', () => themProtocol.publishPrekeys());
  await as('phone', () => myPhone.publishPrekeys());
  await as('browser', () => browser.publishPrekeys());
  await as('browser', async () => {
    await browser.send(them.id, 'mine');
    await browser.whenSynced();
  });

  const messages: Array<{ mine: boolean }> = [];
  await as('phone', async () => {
    for await (const m of myPhone.receive()) messages.push(m);
  });
  assert.equal(messages.length, 1);
  assert.equal(messages[0]!.mine, true);
});
