/**
 * What the protocol tests run against: a fake relay, a fake directory, and
 * identities that can certify devices and sign manifests.
 *
 * The relay and hub are mocked — a fake mailbox holding queues, prekey
 * bundles and blobs, a fake directory — because what needs proving is the
 * *crypto orchestration*, and that should be provable without a browser or a
 * running relay. The relay's own behaviour has its own tests, and the wire
 * format has the conformance corpus. Where the fake has rules, they are the
 * real relay's: a bundle for a device other than 1 needs the bundle token,
 * a deposit for a device that does not exist is 410, a blob is served to
 * whoever holds its fetch token.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { StonechatCore, type SignedCert } from '../src/core.js';
import { DeviceKeys } from '../src/device.js';
import type { Hub, DirectoryEntry } from '../src/hub.js';
import type { LinkGrant } from '../src/linking.js';
import { MailboxError, type Mailbox } from '../src/mailbox.js';
import type { Message } from '../src/model.js';
import { Protocol } from '../src/protocol.js';
import { b64encode, fromUtf8, utf8 } from '../src/bytes.js';
import { store } from '../src/store.js';

const wasm = readFileSync(
  fileURLToPath(
    new URL(
      '../../core/target/wasm32-unknown-unknown/release/stonechat_core.wasm',
      import.meta.url,
    ),
  ),
);
export const core = await StonechatCore.instantiate(
  wasm.buffer.slice(wasm.byteOffset, wasm.byteOffset + wasm.byteLength),
);

// -- a mock relay ----------------------------------------------------------

export interface Queued {
  id: string;
  sealed: string;
  [field: string]: unknown;
}

/** One owner's mailbox: a prekey store, a per-device queue, a blob store. */
export class FakeRelay {
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
  devicesV = 1;
  /** One-time prekeys handed out, so double-use is detectable. */
  servedOpks: number[] = [];
  /** Blobs, with the fetch token each was given when shared. */
  blobs = new Map<string, { bytes: Uint8Array; token: string | null }>();
  /** Every deposit, in order, with its delivery hints. */
  deposits: Array<Record<string, unknown>> = [];
  /** Set to make every request fail, as an unreachable mailbox does. */
  down = false;
  /** Devices whose bundle request fails with 503, for now. */
  failBundleFor = new Set<number>();
  /** Devices whose deposits fail with 503, for now. */
  failInboxFor = new Set<number>();
  /** What `/turn-credentials` answers; null is a mailbox without a call
   * relay (404), which no 0.3.0+ relay is — so one is the default. */
  turn: { urls: string[]; username: string; credential: string } | null = {
    urls: ['turn:relay.test:3478?transport=udp'], username: '1:stonechat', credential: 'c',
  };

  bundle(device = 1): Record<string, unknown> {
    if (this.failBundleFor.has(device)) throw new MailboxError('{"detail":"try later"}', 503);
    const p = this.prekeys.get(device) as {
      spk: unknown;
      kspk: unknown;
      opks: Array<{ id: number; pub: string }>;
      kopks: Array<{ id: number; pub: string }>;
      cert: SignedCert;
    };
    if (!p) throw new MailboxError('{"detail":"no prekeys"}', 404);
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

  /** Revoke a device: its queue, prekeys and listing go; deposits are 410. */
  revoke(device: number): void {
    this.devices = this.devices.filter((d) => d !== device);
    this.queues.delete(device);
    this.prekeys.delete(device);
    this.devicesV += 1;
  }
}

/** A Mailbox-shaped object over a FakeRelay. */
export function fakeMailbox(relay: FakeRelay, drainDevice = 1): Mailbox {
  const unreachable = () => new Error('mailbox unreachable');
  const mailbox = {
    closed: new Promise<void>(() => {}),
    close() {},
    async request(method: string, path: string, body: Uint8Array = new Uint8Array(0)) {
      if (relay.down) throw unreachable();
      const [route, query] = path.split('?');
      const q = new URLSearchParams(query ?? '');
      if (method === 'POST' && route === '/blob') {
        if (body.length === 0) return { status: 400, headers: {}, body: utf8.encode('{"detail":"empty"}') };
        const id = crypto.randomUUID();
        const shared = q.get('shared') === '1' || q.get('shared') === 'true';
        const token = shared ? `fetch-${id}` : null;
        relay.blobs.set(id, { bytes: body, token });
        return {
          status: 200,
          headers: {},
          body: utf8.encode(JSON.stringify({ blob_id: id, ...(token ? { fetch_token: token } : {}) })),
        };
      }
      if (method === 'GET' && route === '/turn-credentials') {
        if (!(q.get('token') ?? '').startsWith('tok-')) {
          return { status: 401, headers: {}, body: utf8.encode('{"detail":"owner only"}') };
        }
        if (relay.turn === null) return { status: 404, headers: {}, body: utf8.encode('{"detail":"no turn"}') };
        return { status: 200, headers: {}, body: utf8.encode(JSON.stringify({ ...relay.turn, ttl: 21600 })) };
      }
      if (method === 'GET' && route?.startsWith('/blob/')) {
        const id = route.slice('/blob/'.length);
        const held = relay.blobs.get(id);
        const token = q.get('token') ?? '';
        if (!held) return { status: 404, headers: {}, body: utf8.encode('{"detail":"no such blob"}') };
        // A device token, or that blob's fetch token.
        if (!token.startsWith('tok-') && token !== held.token) {
          return { status: 401, headers: {}, body: utf8.encode('{"detail":"owner only"}') };
        }
        return { status: 200, headers: {}, body: held.bytes };
      }
      throw new Error(`unmocked ${method} ${path}`);
    },
    async json<T>(method: string, path: string, body?: unknown): Promise<T> {
      if (relay.down) throw unreachable();
      const route = path.split('?')[0]!;
      if (method === 'POST' && route === '/prekeys') {
        relay.prekeys.set(drainDevice, body as Record<string, unknown>);
        return null as T;
      }
      if (method === 'GET' && route === '/prekeys/devices') {
        const token = new URLSearchParams(path.split('?')[1] ?? '').get('token') ?? '';
        if (!token.startsWith('bundle-')) throw new MailboxError('{"detail":"owner only"}', 401);
        return {
          devices_v: relay.devicesV,
          devices: relay.devices
            .filter((d) => relay.prekeys.has(d))
            .map((d) => ({
              device_id: d,
              ...(relay.prekeys.get(d)?.['cert'] ? { cert: relay.prekeys.get(d)!['cert'] } : {}),
            })),
        } as T;
      }
      if (method === 'GET' && route === '/prekeys/bundle') {
        const q = new URLSearchParams(path.split('?')[1] ?? '');
        const want = Number(q.get('device') ?? 1);
        // Without `device`: device 1, to anyone. With it: the bundle token
        // (or a device token), else 401 — exactly the real relay's rule.
        if (q.has('device') && !(q.get('token') ?? '').startsWith('bundle-')) {
          throw new MailboxError('{"detail":"owner only"}', 401);
        }
        return relay.bundle(want) as T;
      }
      if (method === 'POST' && route === '/inbox') {
        const envelope = body as Queued & { device?: number };
        const device = envelope.device ?? 1;
        relay.deposits.push(envelope);
        if (relay.failInboxFor.has(device)) throw new MailboxError('{"detail":"mailbox full"}', 503);
        if (!relay.devices.includes(device)) {
          // Revoked, expired or never existed: permanent for that copy.
          throw new MailboxError(
            JSON.stringify({ detail: 'no such device', devices_v: relay.devicesV }),
            410,
          );
        }
        // A transient envelope goes to the live socket or nowhere. The fake
        // has no live socket; the queue stands in for one, so a test can see
        // what would have been delivered live.
        const q = relay.queues.get(device) ?? [];
        // The whole wire envelope, as the real relay stores and redelivers
        // it: the receiver checks `to` and `id` on it before unsealing.
        if (!q.some((e) => e.id === envelope.id)) q.push(envelope);
        relay.queues.set(device, q);
        return { status: 'queued', devices_v: relay.devicesV } as T;
      }
      throw new Error(`unmocked ${method} ${path}`);
    },
    async *socket() {
      if (relay.down) throw unreachable();
      const q = relay.queues.get(drainDevice) ?? [];
      for (const item of q.splice(0)) {
        yield { kind: 'envelope' as const, envelope: item as unknown as Record<string, unknown> };
      }
    },
    acked: [] as string[],
    async ack(id: string) {
      mailbox.acked.push(id);
    },
  };
  return mailbox as unknown as Mailbox;
}

// -- identities ------------------------------------------------------------

export type Phone = ReturnType<typeof phone>;

/** A phone: an identity that can certify devices and sign manifests. */
export function phone(seedFill: number) {
  const seed = new Uint8Array(32).fill(seedFill);
  const identity = core.identity(seed, false);
  return {
    id: identity.stonechat_id,
    pub: identity.public,
    seed,
    certify(keys: DeviceKeys, deviceId: number, lifetimeS = 604_800): SignedCert {
      return core.devcertSign(
        {
          stonechat_id: identity.stonechat_id,
          device_id: deviceId,
          sig_pub: b64encode(keys.sigPublic),
          seal_pub: b64encode(keys.sealPublic),
          not_after: Math.floor(Date.now() / 1000) + lifetimeS,
        },
        seed,
      );
    },
    /** The signed device manifest listing these devices by their keys. */
    manifest(version: number, devices: Array<[number, DeviceKeys]>): Record<string, unknown> {
      const unsigned = {
        stonechat_id: identity.stonechat_id,
        version,
        issued_at: Math.floor(Date.now() / 1000),
        devices: devices.map(([device_id, keys]) => ({ device_id, sig_pub: b64encode(keys.sigPublic) })),
      };
      return { ...unsigned, sig: core.devicesSign(unsigned, seed) };
    },
  };
}

export function grantFor(
  owner: Phone,
  cert: SignedCert,
  deviceId: number,
): LinkGrant {
  return {
    identity_pub: owner.pub,
    cert,
    stonechat_id: owner.id,
    display_name: '',
    hub_url: 'https://hub.example',
    // One mailbox per identity: every device of it is handed the same address.
    relay_address: `https://relay.${owner.id.slice(3, 11).toLowerCase()}:8080`,
    relay_tls_fp: 'ZnA=',
    device_id: deviceId,
    device_token: `tok-${deviceId}`.padEnd(32, 'x'),
    bundle_token: `bundle-${owner.id}`,
  };
}

/** localStorage is per-process here, so sessions cannot share one. Swapping
 * the backing object between calls is how each gets its own. */
export function storages(...names: string[]) {
  const worlds = new Map<string, Record<string, string>>();
  let active = names[0]!;
  const backing: Storage = {
    getItem: (k) => worlds.get(active)![k] ?? null,
    setItem: (k, v) => {
      worlds.get(active)![k] = v;
    },
    removeItem: (k) => {
      delete worlds.get(active)![k];
    },
    clear: () => worlds.set(active, {}),
    key: (i) => Object.keys(worlds.get(active)!)[i] ?? null,
    get length() {
      return Object.keys(worlds.get(active)!).length;
    },
  };
  for (const name of names) worlds.set(name, {});
  (globalThis as { localStorage?: Storage }).localStorage = backing;
  return <T>(who: string, fn: () => Promise<T>): Promise<T> => {
    active = who;
    return fn();
  };
}

/**
 * Record `others` as accepted contacts in the current storage — what a
 * phone's contact list says, and what reaches a browser over `sync_history`
 * and `sync_contact`. Nothing is rendered from a non-contact, as on the
 * phone, so most tests start from here.
 */
export function befriend(...others: Array<{ id: string; pub: string }>): void {
  for (const o of others) {
    store.setContact({ ...(store.contact(o.id) ?? { stonechatId: o.id }), stonechatId: o.id, pubkey: o.pub, status: 'accepted' });
  }
}

/** A clock the tests can move. */
export function clock(start = Date.now()) {
  let at = start;
  return {
    now: () => at,
    advance(ms: number) {
      at += ms;
    },
  };
}

/** Wire two sessions together through fake relays and a fake directory. */
export async function pair() {
  const as = storages('a', 'b');
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
  const time = clock();
  const A = new Protocol(core, hub, aKeys, grantFor(alice, alice.certify(aKeys, 2), 2), dial, time.now, null);
  const B = new Protocol(core, hub, bKeys, grantFor(bob, bob.certify(bKeys, 1), 1), dial, time.now, null);
  await as('a', async () => befriend(bob));
  await as('b', async () => befriend(alice));

  return { alice, bob, aKeys, bKeys, A, B, aRelay, bRelay, as: as as <T>(who: 'a' | 'b', fn: () => Promise<T>) => Promise<T>, entries, time };
}

/** Collect whatever a session can currently drain. */
export async function drain(p: Protocol): Promise<Array<{ text: string; peerId: string }>> {
  const out: Array<{ text: string; peerId: string }> = [];
  for await (const m of p.receive()) out.push({ text: m.text, peerId: m.peerId });
  return out;
}

export async function drainAll(p: Protocol): Promise<Message[]> {
  const out: Message[] = [];
  for await (const m of p.receive()) out.push(m);
  return out;
}

/**
 * Two devices of ONE identity — a phone and a browser — plus someone to talk
 * to.
 */
export async function ownDevices() {
  const as = storages('phone', 'browser', 'them');
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
  const time = clock();

  const make = (keys: DeviceKeys, device: number, drainDevice: number) =>
    new Protocol(
      core,
      hub,
      keys,
      grantFor(me, me.certify(keys, device), device),
      async (entry: DirectoryEntry) => fakeMailbox(relays[entry.stonechat_id]!, drainDevice),
      time.now,
      null,
    );

  // The person being written to has to be a real participant: they publish
  // prekeys and hold their own storage, exactly like the two devices do.
  const themProtocol = new Protocol(
    core,
    hub,
    themKeys,
    grantFor(them, them.certify(themKeys, 1), 1),
    async (entry: DirectoryEntry) => fakeMailbox(relays[entry.stonechat_id]!, 1),
    time.now,
    null,
  );

  await as('phone', async () => befriend(them));
  await as('browser', async () => befriend(them));
  await as('them', async () => befriend(me));
  return {
    me,
    them,
    themProtocol,
    themKeys,
    phoneKeys,
    browserKeys,
    myRelay,
    theirRelay,
    entries,
    time,
    phone: make(phoneKeys, 1, 1),
    browser: make(browserKeys, 2, 2),
    as: as as <T>(who: 'phone' | 'browser' | 'them', fn: () => Promise<T>) => Promise<T>,
  };
}

/**
 * Any number of identities, one device each, each with its own storage.
 *
 * Groups need at least three people to say anything: an admin, a member, and
 * somebody who is neither.
 */
export async function world<N extends string>(...names: N[]) {
  const as = storages(...names);
  const relays: Record<string, FakeRelay> = {};
  const entries: Record<string, DirectoryEntry> = {};
  const hub = { directory: async (id: string) => entries[id]! } as unknown as Hub;
  const time = clock();
  const who = {} as Record<
    N,
    { id: string; pub: string; keys: DeviceKeys; owner: Phone; relay: FakeRelay; protocol: Protocol }
  >;
  names.forEach((name, i) => {
    const owner = phone(21 + i);
    const keys = DeviceKeys.generate(core);
    const relay = new FakeRelay();
    relays[owner.id] = relay;
    entries[owner.id] = { stonechat_id: owner.id, pubkey: owner.pub };
    who[name] = {
      id: owner.id,
      pub: owner.pub,
      keys,
      owner,
      relay,
      protocol: new Protocol(
        core,
        hub,
        keys,
        grantFor(owner, owner.certify(keys, 1), 1),
        async (entry: DirectoryEntry) => fakeMailbox(relays[entry.stonechat_id]!, 1),
        time.now,
        null,
      ),
    };
  });
  // Everyone has everyone as an accepted contact — except a "mallory", who
  // is a stranger to all and holds everyone, which is what an attacker has.
  const stranger = (n: string) => n.startsWith('mallory');
  for (const name of names) {
    await as(name, async () => {
      befriend(...names.filter((o) => o !== name && (stranger(name) || !stranger(o))).map((o) => who[o]));
      await who[name].protocol.publishPrekeys();
    });
  }
  return { who, as: as as <T>(name: N, fn: () => Promise<T>) => Promise<T>, entries, relays, time };
}

/**
 * Send an envelope of any type, with any payload.
 *
 * `sendTo` is private because the client only ever sends what it means to. An
 * attacker is not so limited, and neither is the phone, which sends types this
 * client has no send path for — so the tests reach past the visibility.
 */
export function raw(
  from: Protocol,
  to: string,
  type: string,
  payload: Record<string, unknown>,
  device = 1,
  opts: { id?: string; sentAt?: string; transient?: boolean } = {},
): Promise<void> {
  return (
    from as unknown as {
      sendTo(
        peer: string, device: number, id: string, sentAt: string,
        type: string, payload: Record<string, unknown>, o?: { transient?: boolean },
      ): Promise<void>;
    }
  ).sendTo(
    to, device, opts.id ?? crypto.randomUUID(), opts.sentAt ?? new Date().toISOString(),
    type, payload, opts.transient ? { transient: true } : {},
  );
}

export const entryOf = (p: { id: string; pub: string }, name?: string) => ({
  stonechat_id: p.id,
  pubkey: p.pub,
  ...(name ? { display_name: name } : {}),
});

export const GROUP = '3f0e6c1a-8f7e-4a53-9b6e-0d6f2f6f5a11';

/** The last deposit's wire form, decoded as JSON where it is text. */
export function lastDeposit(relay: FakeRelay): Record<string, unknown> {
  return relay.deposits[relay.deposits.length - 1]!;
}

export const text = (bytes: Uint8Array): string => fromUtf8.decode(bytes);
