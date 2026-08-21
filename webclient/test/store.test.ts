/**
 * What a browser keeps, and how much of it.
 *
 * History persisting at all is a reversal of the original design, so the bound
 * on it is the part that matters: it is the blast radius of a compromised
 * session, and it is the only thing bounding one — the certificate limits what
 * a session can *do*, not what is sitting on disk.
 */
import assert from 'node:assert/strict';
import { beforeEach, test } from 'node:test';

import { MAX_MESSAGES_PER_CONVERSATION, store } from '../src/store.js';
import type { Message } from '../src/protocol.js';

function memoryStorage(): Storage {
  const box: Record<string, string> = {};
  return {
    getItem: (k) => box[k] ?? null,
    setItem: (k, v) => {
      box[k] = v;
    },
    removeItem: (k) => {
      delete box[k];
    },
    clear: () => {
      for (const k of Object.keys(box)) delete box[k];
    },
    key: () => null,
    length: 0,
  } as Storage;
}

const message = (id: string, peerId = 'SC-PEER', mine = false): Message => ({
  id,
  peerId,
  mine,
  text: `body ${id}`,
  sentAt: '2026-08-04T12:00:00.000Z',
});

beforeEach(() => {
  (globalThis as { localStorage?: Storage }).localStorage = memoryStorage();
});

test('messages survive being written and read back', () => {
  store.appendMessage(message('a'));
  store.appendMessage(message('b', 'SC-PEER', true));
  const thread = store.messages()['SC-PEER']!;
  assert.deepEqual(thread.map((m) => m.id), ['a', 'b']);
  assert.equal(thread[1]!.mine, true, 'who sent it must survive too');
});

test('the same message twice is stored once', () => {
  // Redelivery is normal, not exceptional: the relay re-sends anything unacked
  // when a socket reconnects, so a refresh mid-conversation replays the tail.
  // Without dedup every recent message doubles on each refresh.
  store.appendMessage(message('a'));
  store.appendMessage(message('a'));
  store.appendMessage(message('a'));
  assert.equal(store.messages()['SC-PEER']!.length, 1);
});

test('a conversation is capped, oldest first', () => {
  for (let i = 0; i < MAX_MESSAGES_PER_CONVERSATION + 25; i++) {
    store.appendMessage(message(`m${i}`));
  }
  const thread = store.messages()['SC-PEER']!;
  assert.equal(thread.length, MAX_MESSAGES_PER_CONVERSATION);
  // The newest survive and the oldest are the ones dropped — a cap that kept
  // the *first* 200 would freeze the conversation at its beginning.
  assert.equal(thread[thread.length - 1]!.id, `m${MAX_MESSAGES_PER_CONVERSATION + 24}`);
  assert.equal(thread[0]!.id, 'm25');
});

test('the cap is per conversation, so one busy chat evicts nobody', () => {
  store.appendMessage(message('keep', 'SC-QUIET'));
  for (let i = 0; i < MAX_MESSAGES_PER_CONVERSATION + 50; i++) {
    store.appendMessage(message(`m${i}`, 'SC-BUSY'));
  }
  assert.equal(store.messages()['SC-QUIET']!.length, 1);
  assert.equal(store.messages()['SC-BUSY']!.length, MAX_MESSAGES_PER_CONVERSATION);
});

test('unlinking erases the history as well as the keys', () => {
  // The whole reason a bound is acceptable: there is a way to get to zero, and
  // it is one button rather than a DevTools incantation.
  store.appendMessage(message('a'));
  store.setDeviceKeys('{"sig":"x","seal":"y"}');
  store.clear();
  assert.deepEqual(store.messages(), {});
  assert.equal(store.deviceKeys(), null);
});

test('corrupt history reads as empty rather than throwing', () => {
  // A half-written value must not brick the client on load — an empty
  // conversation is recoverable, a page that will not start is not.
  localStorage.setItem('stonechat.messages', '{not json');
  assert.deepEqual(store.messages(), {});
});


test('clearing a conversation keeps the contact and the session', () => {
  // The whole point of "clear chat" rather than "forget this person": drop
  // the history and keep talking. A clear that took the ratchet with it would
  // force a handshake the peer can see, which is a different thing entirely.
  store.setContact({ stonechatId: 'SC-PEER', pubkey: 'AA==' });
  store.appendMessage({
    id: 'm1', peerId: 'SC-PEER', mine: true, text: 'one',
    sentAt: new Date(0).toISOString(),
  });
  store.appendMessage({
    id: 'm2', peerId: 'SC-OTHER', mine: false, text: 'two',
    sentAt: new Date(0).toISOString(),
  });

  store.clearConversation('SC-PEER');

  assert.equal(store.messages()['SC-PEER'], undefined, 'history is gone');
  assert.equal(store.messages()['SC-OTHER']?.length, 1, 'other chats untouched');
  assert.ok(store.contacts()['SC-PEER'], 'the contact survives');
});

test('clearing an unknown conversation is a no-op', () => {
  // Redelivery is normal, so the same sync_clear can arrive twice.
  store.clearConversation('SC-NOBODY');
  assert.ok(true);
});
