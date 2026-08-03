/**
 * The bridge between JavaScript and stonechat-core.
 *
 * Not a test of the crypto — core/ owns that, and `core/tests` plus the golden
 * transcript corpus are where it is checked. This checks the *binding*: that
 * bytes cross linear memory intact, that a WASM-derived identity is
 * byte-identical to the native core's, and above all that the fixed-size
 * contract is enforced here, because the core cannot enforce it itself.
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { fixed, StonechatCore, XWING_PUBLIC } from '../src/core.js';
import { b64decode, b64encode, equalBytes } from '../src/bytes.js';

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

/** The all-0x07 seed, and the Ed25519 public key the *native* core derives
 * from it. A WASM build that quietly disagreed would produce an identity no
 * peer could resolve, so this is pinned rather than computed. */
const SEED_07 = new Uint8Array(32).fill(7);
const PUBLIC_07 =
  'ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c';

test('identity from a seed matches the native core byte for byte', () => {
  const id = core.identity(SEED_07, false);
  assert.equal(Buffer.from(b64decode(id.public)).toString('hex'), PUBLIC_07);
  assert.match(id.stonechat_id, /^SC-/);
});

test('the 64-byte secret form derives the same identity', () => {
  const fromSeed = core.identity(SEED_07, false);
  const fromSecret = core.identity(b64decode(fromSeed.secret), true);
  assert.equal(fromSecret.public, fromSeed.public);
  assert.equal(fromSecret.stonechat_id, fromSeed.stonechat_id);
});

test('an SC- ID commits to the public key it was derived from', () => {
  const id = core.identity(SEED_07, false);
  assert.equal(core.stonechatId(b64decode(id.public)), id.stonechat_id);
});

test('fixed-size inputs are refused here, because the core cannot', () => {
  // The single most important property in the binding. A short buffer is not
  // detectable by the core: it reads past the end and returns a confident
  // wrong answer. Native callers get this from their FFI signatures; JS does
  // not, so it has to be here or nowhere.
  assert.throws(() => core.identity(new Uint8Array(31), false), TypeError);
  assert.throws(() => core.identity(new Uint8Array(32), true), TypeError);
  assert.throws(() => core.stonechatId(new Uint8Array(31)), TypeError);
  assert.throws(() => core.xwingPkFromSeed(new Uint8Array(16)), TypeError);
  assert.throws(
    () => fixed(new Uint8Array(3), 4, 'thing'),
    /must be exactly 4 bytes, got 3/,
  );
});

test('a too-LONG buffer is refused as well', () => {
  // Over-length is the quieter half: it does not read past anything, it just
  // silently ignores the tail, so the caller believes they used a key they
  // did not.
  assert.throws(() => core.identity(new Uint8Array(33), false), TypeError);
});

test('normalizeId canonicalises, and refuses what is not an ID', () => {
  const id = core.identity(SEED_07, false).stonechat_id;
  assert.equal(core.normalizeId(id.toLowerCase()), id);
  assert.equal(core.normalizeId('not an id'), null);
  assert.equal(core.normalizeId(''), null);
});

test('signatures round-trip, and a wrong key does not verify', () => {
  const id = core.identity(SEED_07, false);
  const ctx = new TextEncoder().encode('stonechat-v1-test');
  const msg = new TextEncoder().encode('the message');
  const sig = core.sign(b64decode(id.secret), ctx, msg);
  assert.equal(sig.length, 64);
  assert.equal(core.verify(b64decode(id.public), ctx, msg, sig), true);

  const other = core.identity(new Uint8Array(32).fill(9), false);
  assert.equal(core.verify(b64decode(other.public), ctx, msg, sig), false);
  // A different context is a different statement, even over the same bytes.
  const otherCtx = new TextEncoder().encode('stonechat-v1-other');
  assert.equal(core.verify(b64decode(id.public), otherCtx, msg, sig), false);
});

test('the hybrid seal round-trips, and only for the right seed', () => {
  const seed = crypto.getRandomValues(new Uint8Array(32));
  const pk = core.xwingPkFromSeed(seed);
  assert.equal(pk.length, XWING_PUBLIC);
  const message = new TextEncoder().encode('{"cert":"x"}');
  const sealed = core.seal(
    pk,
    message,
    crypto.getRandomValues(new Uint8Array(64)),
    crypto.getRandomValues(new Uint8Array(24)),
  );
  assert.ok(equalBytes(core.unseal(seed, sealed)!, message));
  // A different seed is a different device: it must open nothing.
  assert.equal(core.unseal(crypto.getRandomValues(new Uint8Array(32)), sealed), null);
});

test('device certificates verify, expire, and detect tampering', () => {
  const identity = core.identity(SEED_07, false);
  const now = 1_800_000_000;
  const keys = {
    sig: core.identity(new Uint8Array(32).fill(3), false).public,
    seal: b64encode(core.xwingPkFromSeed(new Uint8Array(32).fill(4))),
  };
  const signed = core.devcertSign(
    {
      stonechat_id: identity.stonechat_id,
      device_id: 2,
      sig_pub: keys.sig,
      seal_pub: keys.seal,
      not_after: now + 3600,
    },
    SEED_07,
  );
  const identityPub = b64decode(identity.public);
  assert.equal(core.devcertVerify(signed, identityPub, now), 'valid');
  assert.equal(core.devcertVerify(signed, identityPub, now + 7200), 'expired');

  // Every field is covered by the signature, so moving the certificate to
  // another device id breaks it — that is what stops a relay shuffling
  // certificates between devices to redirect mail.
  assert.equal(
    core.devcertVerify({ ...signed, device_id: 3 }, identityPub, now),
    'bad_signature',
  );
  assert.equal(
    core.devcertVerify({ ...signed, not_after: now + 999_999 }, identityPub, now),
    'bad_signature',
  );
  // And a different identity did not sign it.
  const other = core.identity(new Uint8Array(32).fill(9), false);
  assert.equal(
    core.devcertVerify(signed, b64decode(other.public), now),
    'bad_signature',
  );
});

test('base32 round-trips', () => {
  const data = crypto.getRandomValues(new Uint8Array(20));
  assert.ok(equalBytes(core.base32Decode(core.base32Encode(data)), data));
});

test('repeated calls do not leak or corrupt linear memory', () => {
  // Allocation is manual on both sides of this boundary. A leak in a tab the
  // user leaves open all day is a leak that grows all day, and a double-free
  // would surface as garbage rather than a crash — so churn it and check the
  // answers stay right.
  const expect = core.identity(SEED_07, false).stonechat_id;
  for (let i = 0; i < 500; i++) {
    core.seal(
      core.xwingPkFromSeed(new Uint8Array(32).fill(i % 251)),
      new Uint8Array(256).fill(i % 251),
      crypto.getRandomValues(new Uint8Array(64)),
      crypto.getRandomValues(new Uint8Array(24)),
    );
  }
  assert.equal(core.identity(SEED_07, false).stonechat_id, expect);
});

test('a throwing call still frees what it allocated', () => {
  // The failure path is the one that leaks, and it is the one nobody
  // exercises. Fixed() throws before any allocation; a core-level refusal
  // throws after several.
  const before = core.identity(SEED_07, false).stonechat_id;
  for (let i = 0; i < 200; i++) {
    assert.throws(() => core.identity(new Uint8Array(31), false));
  }
  assert.equal(core.identity(SEED_07, false).stonechat_id, before);
});
