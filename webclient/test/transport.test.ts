/**
 * Deciding what to pin.
 *
 * The relay publishes which short-lived WebTransport certificates it will
 * present; the owner signs that list; this client refuses to pin anything the
 * owner did not sign. Skipping that check is the interesting failure — it
 * looks like it works, against whatever certificate the network chose.
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { StonechatCore, type WtCert } from '../src/core.js';
import type { DirectoryEntry } from '../src/hub.js';
import { PinRefused, pinsFor, pinsNeedRefresh, routeFor } from '../src/transport.js';
import { b64decode, b64encode } from '../src/bytes.js';

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

const NOW = new Date(1_800_000_000_000);
const T = Math.floor(NOW.getTime() / 1000);
const DAY = 86_400;

const owner = core.identity(new Uint8Array(32).fill(7), false);
const stranger = core.identity(new Uint8Array(32).fill(9), false);

function schedule(): WtCert[] {
  return [
    { sha256: b64encode(new Uint8Array(32).fill(1)), not_before: T - DAY, not_after: T + 12 * DAY },
    { sha256: b64encode(new Uint8Array(32).fill(2)), not_before: T + 11 * DAY, not_after: T + 24 * DAY },
    { sha256: b64encode(new Uint8Array(32).fill(3)), not_before: T + 23 * DAY, not_after: T + 36 * DAY },
  ];
}

/**
 * The canonical signing bytes, built here rather than asked of the core.
 *
 * Deliberate: the client never *signs* a schedule — only the owner's phone
 * does, and shipping a signer in a browser would be dead code in the one place
 * dead code is most expensive. Reimplementing the encoding for the test also
 * makes this a fourth independent implementation of it (Rust, the hub's
 * Python, the e2e's, and this), so a drift in any of them shows up as a
 * failure here rather than as "the signature does not verify".
 */
function signingBytes(certs: WtCert[]): Uint8Array {
  const out: number[] = [];
  const u32 = (n: number) => out.push((n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255);
  const i64 = (n: number) => {
    const v = BigInt(n);
    for (let i = 7; i >= 0; i--) out.push(Number((v >> BigInt(i * 8)) & 0xffn));
  };
  // The count first: without it a truncated list is a valid prefix.
  u32(certs.length);
  for (const c of certs) {
    const hash = new TextEncoder().encode(c.sha256);
    u32(hash.length);
    out.push(...hash);
    u32(8);
    i64(c.not_before);
    u32(8);
    i64(c.not_after);
  }
  return new Uint8Array(out);
}

/** Sign a schedule the way the owner's phone does. */
function signed(certs: WtCert[], seedFill = 7): string {
  const identity = core.identity(new Uint8Array(32).fill(seedFill), false);
  return b64encode(
    core.sign(
      b64decode(identity.secret),
      new TextEncoder().encode('stonechat-v1-wtcerts'),
      signingBytes(certs),
    ),
  );
}

function entry(overrides: Partial<DirectoryEntry['server']> = {}): DirectoryEntry {
  const certs = schedule();
  return {
    stonechat_id: owner.stonechat_id,
    pubkey: owner.public,
    server: {
      address: 'https://1.2.3.4:8080',
      tls_fp: 'ZnA=',
      wt_certs: certs,
      wt_sig: signed(certs),
      wt_address: '1.2.3.4:8443',
      ...overrides,
    },
  };
}

test('a signed schedule yields every unexpired pin', () => {
  const pins = pinsFor(core, entry(), NOW);
  // All three, including the two not yet live: the relay may rotate at any
  // moment and the client cannot know which it is serving. Passing the whole
  // set is what makes rotation silent.
  assert.equal(pins.length, 3);
  assert.equal(pins[0]!.length, 32);
});

test('an unsigned schedule is refused', () => {
  // The one that matters. Without this check everything appears to work,
  // against whatever certificate the network chose to serve.
  assert.throws(
    () => pinsFor(core, entry({ wt_sig: null }), NOW),
    PinRefused,
  );
  assert.throws(
    () => pinsFor(core, entry({ wt_certs: null }), NOW),
    PinRefused,
  );
});

test('a schedule signed by someone else is refused', () => {
  const certs = schedule();
  const e = entry({ wt_certs: certs, wt_sig: signed(certs, 9) });
  assert.throws(() => pinsFor(core, e, NOW), /not the one its owner signed/);
});

test('a tampered hash is refused', () => {
  const certs = schedule();
  const sig = signed(certs);
  const swapped = certs.map((c, i) =>
    i === 0 ? { ...c, sha256: b64encode(new Uint8Array(32).fill(200)) } : c,
  );
  assert.throws(
    () => pinsFor(core, entry({ wt_certs: swapped, wt_sig: sig }), NOW),
    /not the one its owner signed/,
  );
});

test('a truncated schedule is refused', () => {
  // The attack the length prefix in the signing bytes exists for: strip the
  // future certificates and a client is stranded on the current one — which
  // is the one an attacker who holds it wants them stuck with.
  const certs = schedule();
  const sig = signed(certs);
  assert.throws(
    () => pinsFor(core, entry({ wt_certs: certs.slice(0, 2), wt_sig: sig }), NOW),
    /not the one its owner signed/,
  );
});

test('a reordered schedule is refused', () => {
  const certs = schedule();
  const sig = signed(certs);
  const shuffled = [certs[2]!, certs[1]!, certs[0]!];
  assert.throws(
    () => pinsFor(core, entry({ wt_certs: shuffled, wt_sig: sig }), NOW),
    /not the one its owner signed/,
  );
});

test('a directory key that does not commit to the ID is refused', () => {
  // The directory is untrusted. A lying hub can only produce a *failed*
  // lookup, and only if somebody actually checks the hash.
  const e = entry();
  e.pubkey = stranger.public;
  assert.throws(() => pinsFor(core, e, NOW), /does not commit/);
});

test('an all-expired schedule is refused rather than pinned empty', () => {
  // Connecting with no pins would mean connecting with no pinning. Saying so
  // is better: the owner's device has not been online to re-vouch.
  const stale = schedule().map((c) => ({
    ...c,
    not_before: c.not_before - 400 * DAY,
    not_after: c.not_after - 400 * DAY,
  }));
  assert.throws(
    () => pinsFor(core, entry({ wt_certs: stale, wt_sig: signed(stale) }), NOW),
    /expired/,
  );
});

test('expired entries are dropped from a still-usable schedule', () => {
  const mixed = [
    { sha256: b64encode(new Uint8Array(32).fill(9)), not_before: T - 30 * DAY, not_after: T - DAY },
    ...schedule(),
  ];
  const pins = pinsFor(core, entry({ wt_certs: mixed, wt_sig: signed(mixed) }), NOW);
  assert.equal(pins.length, 3);
  for (const pin of pins) {
    assert.ok(!pin.every((b) => b === 9), 'an expired pin survived');
  }
});

test('refresh is driven by the LAST pin, not the current one', () => {
  // The whole point of publishing months ahead. Refreshing when the live
  // certificate is about to lapse would put the client back on a fortnightly
  // network dependency.
  const certs = schedule();
  assert.equal(pinsNeedRefresh(certs, NOW), false);
  const nearlyOut = certs.map((c) => ({ ...c, not_after: T + 5 * DAY }));
  assert.equal(pinsNeedRefresh(nearlyOut, NOW), true);
  assert.equal(pinsNeedRefresh([], NOW), true);
});

test('the pins are the bytes the relay published', () => {
  const certs = schedule();
  const pins = pinsFor(core, entry({ wt_certs: certs, wt_sig: signed(certs) }), NOW);
  assert.deepEqual(Array.from(pins[0]!), Array.from(b64decode(certs[0]!.sha256)));
});

// -- where to send them ----------------------------------------------------

test('a route needs an address as well as pins', () => {
  const route = routeFor(core, entry(), NOW);
  assert.equal(route.origin, 'https://1.2.3.4:8443');
  assert.equal(route.pins.length, 3);
});

test('signed certificates with nowhere to send them are refused', () => {
  // A real state, not a broken one: a provider that has not been taught to
  // map the UDP port, or a host that blocks it. Saying so beats constructing
  // a URL out of nothing.
  assert.throws(
    () => routeFor(core, entry({ wt_address: null }), NOW),
    /no browser-transport address/,
  );
});

test('a malformed address is refused rather than dialled', () => {
  // This value ends up inside a URL handed to `new WebTransport`. It arrives
  // over the network, unsigned, so it is the one field an attacker can freely
  // choose — and the check is cheap.
  for (const bad of [
    'not-a-host',
    '1.2.3.4',
    '1.2.3.4:8443/evil',
    'evil.example:8443?x=1',
    '1.2.3.4:8443 ',
    'javascript:alert(1)',
    '1.2.3.4:999999',
  ]) {
    assert.throws(
      () => routeFor(core, entry({ wt_address: bad }), NOW),
      /malformed address/,
      bad,
    );
  }
});

test('an address is accepted for hostnames and IPv6 too', () => {
  for (const good of ['relay.example.com:8443', '[2001:db8::1]:8443', '1.2.3.4:65535']) {
    assert.equal(
      routeFor(core, entry({ wt_address: good }), NOW).origin,
      `https://${good}`,
    );
  }
});

test('the address is checked AFTER the signature', () => {
  // Order matters for what the user is told. An unsigned schedule is a
  // security failure; a missing address is a mailbox without a browser
  // transport. Reporting the wrong one sends someone debugging the wrong
  // thing.
  assert.throws(
    () => routeFor(core, entry({ wt_sig: null, wt_address: null }), NOW),
    /no signed browser-transport certificates/,
  );
});
