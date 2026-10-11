/**
 * The group rules (`src/groups.ts`): which rosters a client accepts, how two
 * members' views compare, and the hashes behind both.
 *
 * The hash vectors are the ones `app/test/group_rules_test.dart` pins against
 * `scripts/e2e.py`: an app, a script and a browser that disagreed here would
 * each report the others as holding a different roster, or a different
 * message.
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';

import { b64encode } from '../src/bytes.js';
import {
  checkMembership,
  compareRoster,
  groupMessageBody,
  groupMessageHash,
  rosterClaim,
  rosterHash,
} from '../src/groups.js';
import { core } from './fixtures.js';

const hash = (data: Uint8Array) => b64encode(core.tlsFingerprint(data));
const GID = '6a1f0c1e-2b6f-4f0e-9a51-0d6b8f1c2a33';

test('hashes match the app and the Python client byte for byte', () => {
  assert.equal(
    rosterHash(hash, { groupId: GID, version: 3, admin: 'SC-A', memberIds: ['SC-C', 'SC-A', 'SC-B'] }),
    'bwEclWvOVRlPTPOJPAsbsRPtGUYfzsXZRYgBqEYsan4=',
  );
  const messageHash = (payload: Record<string, unknown>) =>
    groupMessageHash(hash, {
      groupId: GID, senderId: 'SC-A', id: 'm1', salt: 'c2FsdA==', body: groupMessageBody(payload)!,
    });
  assert.equal(messageHash({ text: 'see you at 8 | or 9' }), 'KFiWM0UrKbNVI2HUO9jEfLA3SQBc3Un7CZ8LLbdfbnM=');
  assert.equal(
    messageHash({ blob_id: 'b', key: 'k', blob_nonce: 'n' }),
    'n83Yradhf+fsnXrLSWrlM8Jf86qtN+5g0/95jEPJCrI=',
  );
});

test('the roster hash does not depend on the order members are listed in', () => {
  const a = rosterHash(hash, { groupId: GID, version: 1, admin: 'SC-A', memberIds: ['SC-A', 'SC-B'] });
  const b = rosterHash(hash, { groupId: GID, version: 1, admin: 'SC-A', memberIds: ['SC-B', 'SC-A'] });
  assert.equal(a, b);
  assert.notEqual(a, rosterHash(hash, { groupId: GID, version: 2, admin: 'SC-A', memberIds: ['SC-A', 'SC-B'] }));
  assert.notEqual(a, rosterHash(hash, { groupId: GID, version: 1, admin: 'SC-B', memberIds: ['SC-A', 'SC-B'] }));
});

test('a message body is its text, or its blob and key; nothing else', () => {
  assert.equal(groupMessageBody({ text: 'hi' }), 'text|hi');
  assert.equal(groupMessageBody({ blob_id: 'b', key: 'k', blob_nonce: 'n' }), 'media|b|k|n');
  assert.equal(groupMessageBody({ blob_id: 'b' }), null);
  assert.equal(groupMessageBody({}), null);
});

const check = (patch: Partial<Parameters<typeof checkMembership>[0]> = {}) =>
  checkMembership({
    from: 'SC-ADMIN',
    payloadAdmin: 'SC-ADMIN',
    version: 2,
    memberIds: ['SC-ADMIN', 'SC-ME', 'SC-OTHER'],
    held: { adminId: 'SC-ADMIN', version: 1 },
    senderIsContact: true,
    ...patch,
  });

test('a held group listens to its admin on record, and only forward', () => {
  assert.deepEqual(check(), { accepted: true, handover: false });
  assert.deepEqual(check({ version: 1 }), { accepted: false, rejected: 'stale or replayed roster' });
  assert.deepEqual(check({ from: 'SC-OTHER', payloadAdmin: 'SC-OTHER' }), {
    accepted: false, rejected: 'not from the admin on record',
  });
  // The admin on record naming someone else is how the role is handed over.
  assert.deepEqual(check({ payloadAdmin: 'SC-OTHER' }), { accepted: true, handover: true });
});

test('first sight: only the admin it names, and only a contact', () => {
  assert.deepEqual(check({ held: null }), { accepted: true, handover: false });
  assert.deepEqual(check({ held: null, from: 'SC-OTHER' }), {
    accepted: false, rejected: 'not from the admin it names',
  });
  assert.deepEqual(check({ held: null, senderIsContact: false }), {
    accepted: false, rejected: 'group invite from a non-contact',
  });
});

test('a roster is bounded, lists nobody twice, and contains its admin', () => {
  assert.match(check({ memberIds: Array.from({ length: 101 }, (_, i) => `SC-${i}`) }).rejected!, /larger/);
  assert.match(check({ memberIds: ['SC-ADMIN', 'SC-ME', 'SC-ME'] }).rejected!, /twice/);
  assert.match(check({ memberIds: ['SC-ME', 'SC-OTHER'] }).rejected!, /admin who is not in it/);
});

test('a roster claim is read as the sender sent it, and compared to ours', () => {
  assert.equal(rosterClaim({}), null);
  assert.equal(rosterClaim({ roster: { v: -1 } }), null);
  const claim = rosterClaim({ roster: { v: 3, h: 'H', admin: 'SC-A' } })!;
  assert.deepEqual(claim, { version: 3, hash: 'H', admin: 'SC-A' });
  assert.equal(compareRoster({ heldVersion: 3, heldHash: 'H', claim }), 'same');
  assert.equal(compareRoster({ heldVersion: 3, heldHash: 'X', claim }), 'diverged');
  assert.equal(compareRoster({ heldVersion: 3, heldHash: null, claim }), 'same');
  assert.equal(compareRoster({ heldVersion: 2, heldHash: 'H', claim }), 'peerAhead');
  assert.equal(compareRoster({ heldVersion: 4, heldHash: 'H', claim }), 'peerBehind');
  assert.equal(compareRoster({ heldVersion: 4, heldHash: 'H', claim: null }), 'unknown');
});
