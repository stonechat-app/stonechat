/**
 * What arrives on the wire is checked where it enters (PROTOCOL.md "What a
 * recipient checks"). These are the shape checks that run before any
 * cryptography, so they are tested without any.
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';

import { isWireId, parseInner } from '../src/wire.js';

const ME = 'SC-ME';
const ID = '3f0e6c1a-8f7e-4a53-9b6e-0d6f2f6f5a11';

const inner = (patch: Record<string, unknown> = {}) => ({
  v: 1,
  id: ID,
  type: 'msg',
  from: 'SC-THEM',
  from_device: 1,
  to: ME,
  device: 2,
  sent_at: '2026-10-11T10:00:00.000Z',
  ratchet: { dh: 'x', pn: 0, n: 0 },
  nonce: 'AA==',
  ciphertext: 'AA==',
  ...patch,
});

test('a UUID is a UUID; nothing else is', () => {
  assert.equal(isWireId(ID), true);
  assert.equal(isWireId(ID.toUpperCase()), true);
  for (const bad of [
    '', 'x', ID.slice(1), `${ID}a`, '../../etc/passwd', ID.replace('-', '_'),
    42, null, undefined, { id: ID },
  ]) {
    assert.equal(isWireId(bad), false, String(bad));
  }
});

test('a well-formed inner envelope parses', () => {
  const r = parseInner({ id: ID, to: ME }, inner({ bundle_token: 'bt', manifest_v: 3 }), ME, 2);
  assert.equal(r.reason, undefined);
  assert.equal(r.inner!.id, ID);
  assert.equal(r.inner!.fromDevice, 1);
  assert.equal(r.inner!.device, 2);
  assert.equal(r.inner!.bundleToken, 'bt');
  assert.equal(r.inner!.manifestV, 3);
  assert.equal(r.inner!.blobId, null);
});

test('the inner id must be a UUID and equal the id on the wire', () => {
  // One id names a message everywhere — acked, stored, receipted. An inner
  // id that disagrees is a sender trying to be filed under a name the
  // mailbox never saw.
  const other = '9a1c0b52-5d0e-4a0b-8a54-0f6f0c1d2e3f';
  assert.match(parseInner({ id: other, to: ME }, inner(), ME, 2).reason!, /differs/);
  assert.match(parseInner({ id: 'not-a-uuid', to: ME }, inner({ id: 'not-a-uuid' }), ME, 2).reason!, /not a UUID/);
  assert.match(parseInner({ id: ID, to: ME }, inner({ id: 'not-a-uuid' }), ME, 2).reason!, /not a UUID/);
});

test('the inner envelope must be addressed to us, and to this device', () => {
  assert.match(parseInner({ id: ID, to: ME }, inner({ to: 'SC-SOMEONE' }), ME, 2).reason!, /someone else/);
  assert.match(parseInner({ id: ID, to: ME }, inner({ device: 3 }), ME, 2).reason!, /another of our devices/);
});

test('both device numbers are required — nothing defaults to 1', () => {
  // The associated data binds both; an implicit value would make sender and
  // receiver agree on what "absent" meant.
  assert.match(parseInner({ id: ID, to: ME }, inner({ from_device: undefined }), ME, 2).reason!, /from_device/);
  assert.match(parseInner({ id: ID, to: ME }, inner({ from_device: '1' }), ME, 2).reason!, /from_device/);
  assert.match(parseInner({ id: ID, to: ME }, inner({ from_device: 0 }), ME, 2).reason!, /from_device/);
  assert.match(parseInner({ id: ID, to: ME }, inner({ device: undefined }), ME, 2).reason!, /bad device/);
});

test('a blob id, when present, must be a UUID', () => {
  // It goes into a URL on our own mailbox with our own token beside it.
  assert.match(parseInner({ id: ID, to: ME }, inner({ blob_id: '../x' }), ME, 2).reason!, /blob_id/);
  assert.equal(parseInner({ id: ID, to: ME }, inner({ blob_id: null }), ME, 2).reason, undefined);
  const ok = parseInner({ id: ID, to: ME }, inner({ blob_id: ID }), ME, 2);
  assert.equal(ok.inner!.blobId, ID);
});

test('garbage is refused rather than guessed at', () => {
  for (const junk of [null, 'string', 42, [], { id: ID }]) {
    assert.notEqual(parseInner({ id: ID, to: ME }, junk, ME, 2).reason, undefined);
  }
  assert.match(parseInner({ id: ID, to: ME }, inner({ ratchet: 'x' }), ME, 2).reason!, /ratchet/);
  assert.match(parseInner({ id: ID, to: ME }, inner({ ciphertext: 7 }), ME, 2).reason!, /ciphertext/);
  assert.match(parseInner({ id: ID, to: ME }, inner({ type: '' }), ME, 2).reason!, /type/);
});
