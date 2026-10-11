/**
 * The contact list, between a user's own devices and from the phone to a
 * freshly linked browser (PROTOCOL.md "Self-sync": `sync_contact`,
 * `sync_history`), and the gate it enables: nothing is rendered from a
 * stranger, as on the phone.
 */
import assert from 'node:assert/strict';
import { gzipSync } from 'node:zlib';
import { test } from 'node:test';

import { b64encode, utf8 } from '../src/bytes.js';
import { store, threadKey } from '../src/store.js';
import { core, drainAll, GROUP, ownDevices, raw, world } from './fixtures.js';

test('a stranger\'s message is not shown; an accepted contact\'s is', async () => {
  const { who, as } = await world('alice', 'mallory');
  const { alice, mallory } = who;
  await as('mallory', () => raw(mallory.protocol, alice.id, 'msg', { text: 'psst' }));
  assert.deepEqual(await as('alice', () => drainAll(alice.protocol)), []);
  // Nor typing, reactions, timers or calls.
  await as('mallory', async () => {
    await raw(mallory.protocol, alice.id, 'timer_update', { expire_ms: 1000 });
    await raw(mallory.protocol, alice.id, 'call_offer', { call_id: crypto.randomUUID(), media: 'audio', sdp: 'v=0' });
  });
  assert.deepEqual(await as('alice', () => drainAll(alice.protocol)), []);
  assert.equal(await as('alice', async () => alice.protocol.expireTimerOf(mallory.id, false)), 0);
});

test('a request from the browser reaches the peer and the phone; the accept comes back to both', async () => {
  const { me, them, themProtocol, phone: myPhone, browser, as } = await ownDevices();
  // Start as strangers.
  for (const w of ['phone', 'browser'] as const) await as(w, async () => store.deleteContact(them.id));
  await as('them', async () => store.deleteContact(me.id));
  await as('phone', () => myPhone.publishPrekeys());
  await as('browser', () => browser.publishPrekeys());
  await as('them', () => themProtocol.publishPrekeys());

  await as('browser', async () => {
    const c = await browser.addContact(them.id);
    assert.equal(c.status, 'pendingOut');
    await browser.whenSynced();
  });
  // They see a request; the phone learns the browser sent one.
  const theirs = await as('them', () => drainAll(themProtocol));
  assert.equal(theirs[0]?.request, true);
  assert.equal(await as('them', async () => store.contact(me.id)?.status), 'pendingIn');
  await as('phone', () => drainAll(myPhone));
  assert.equal(await as('phone', async () => store.contact(them.id)?.status), 'pendingOut');

  // They accept: the browser's contact flips, and it tells the phone.
  await as('them', async () => {
    await themProtocol.acceptContact(me.id);
    await themProtocol.whenSynced();
  });
  const got = await as('browser', async () => {
    const m = await drainAll(browser);
    await browser.whenSynced();
    return m;
  });
  assert.match(got[0]?.text ?? '', /accepted your request/);
  assert.equal(await as('browser', async () => store.contact(them.id)?.status), 'accepted');
  await as('phone', () => drainAll(myPhone));
  assert.equal(await as('phone', async () => store.contact(them.id)?.status), 'accepted');

  // And now a message gets through.
  await as('them', () => themProtocol.send(me.id, 'hello'));
  assert.deepEqual((await as('browser', () => drainAll(browser))).map((m) => m.text), ['hello']);
});

test('a sync_contact from a sibling creates, updates and removes; a wrong key is refused', async () => {
  const { me, them, phone: myPhone, browser, as } = await ownDevices();
  await as('browser', async () => store.deleteContact(them.id));
  await as('phone', () => myPhone.publishPrekeys());
  await as('browser', () => browser.publishPrekeys());
  const stranger = { id: 'SC-K3M9-QF2X-V8D4-HTPR-26LN-AQ7B-ZZC4-J5WE-M2KA', pub: them.pub };
  await as('phone', async () => {
    await raw(myPhone, me.id, 'sync_contact', { peer: them.id, pubkey: them.pub, status: 'pending_in', display_name: 'Them', avatar: null }, 2);
    // Somebody else's key under this ID: refused whole.
    await raw(myPhone, me.id, 'sync_contact', { peer: stranger.id, pubkey: stranger.pub, status: 'accepted' }, 2);
  });
  await as('browser', () => drainAll(browser));
  const held = await as('browser', async () => store.contact(them.id));
  assert.equal(held?.status, 'pendingIn');
  assert.equal(held?.displayName, 'Them');
  assert.equal(await as('browser', async () => store.contact(stranger.id)), null);

  await as('phone', () => raw(myPhone, me.id, 'sync_contact', { peer: them.id, pubkey: them.pub, status: 'accepted', bundle_token: `bundle-${them.id}` }, 2));
  await as('browser', () => drainAll(browser));
  assert.equal(await as('browser', async () => store.contact(them.id)?.status), 'accepted');
  assert.equal(await as('browser', async () => store.contact(them.id)?.bundleToken), `bundle-${them.id}`);

  await as('phone', () => raw(myPhone, me.id, 'sync_contact', { peer: them.id, pubkey: them.pub, status: 'removed' }, 2));
  await as('browser', () => drainAll(browser));
  assert.equal(await as('browser', async () => store.contact(them.id)), null);
});

test('sync_history fills a fresh browser in from the phone\'s export', async () => {
  const { me, them, phone: myPhone, browser, as, myRelay } = await ownDevices();
  await as('browser', async () => store.deleteContact(them.id));
  await as('phone', () => myPhone.publishPrekeys());
  await as('browser', () => browser.publishPrekeys());
  const carol = core.identity(new Uint8Array(32).fill(31), false);
  const payload = {
    format: 'stonechat-backup', version: 1, created_at: 1,
    contacts: [
      { stonechat_id: them.id, display_name: 'Them', pubkey: them.pub, status: 'accepted', created_at: 1, expire_timer_ms: 3600000, expire_timer_at: 5 },
      { stonechat_id: carol.stonechat_id, display_name: 'Carol', pubkey: carol.public, status: 'pending_out', created_at: 2 },
      // A key that does not hash to its ID: skipped, not fatal.
      { stonechat_id: 'SC-K3M9-QF2X-V8D4-HTPR-26LN-AQ7B-ZZC4-J5WE-M2KA', display_name: 'X', pubkey: them.pub, status: 'accepted', created_at: 3 },
    ],
    blocked: [{ stonechat_id: carol.stonechat_id, blocked_at: 99 }],
    groups: [{ id: GROUP, name: 'Trip', admin_id: me.id, version: 3, roster_hash: 'h', created_at: 1 }],
    group_members: [
      { group_id: GROUP, stonechat_id: me.id, pubkey: me.pub, display_name: 'Me' },
      { group_id: GROUP, stonechat_id: them.id, pubkey: them.pub, display_name: 'Them' },
    ],
    messages: [
      { id: '0e6f1c2a-1111-4a53-9b6e-0d6f2f6f5a11', contact_id: them.id, outgoing: 0, text: 'old hello', kind: 'text', sent_at: 1000, status: 'read' },
      { id: '0e6f1c2a-2222-4a53-9b6e-0d6f2f6f5a11', contact_id: them.id, outgoing: 1, text: 'old reply', kind: 'text', sent_at: 2000, status: 'delivered' },
      { id: '0e6f1c2a-3333-4a53-9b6e-0d6f2f6f5a11', contact_id: GROUP, sender_id: them.id, outgoing: 0, text: 'in the group', kind: 'text', sent_at: 3000, status: 'read' },
      { id: '0e6f1c2a-4444-4a53-9b6e-0d6f2f6f5a11', contact_id: them.id, outgoing: 0, text: '', kind: 'image', sent_at: 4000, status: 'read' },
      { id: 'not-a-uuid', contact_id: them.id, outgoing: 0, text: 'junk', kind: 'text', sent_at: 5000, status: 'read' },
    ],
    reactions: [{ message_id: '0e6f1c2a-2222-4a53-9b6e-0d6f2f6f5a11', peer_id: them.id, emoji: '👍', at: 2500 }],
  };
  // The phone's half, done by hand: seal the gzip'd payload like a blob and
  // park it on our own mailbox as a shared blob.
  const key = crypto.getRandomValues(new Uint8Array(32));
  const nonce = crypto.getRandomValues(new Uint8Array(24));
  const plain = new Uint8Array(gzipSync(Buffer.from(JSON.stringify(payload))));
  const ciphertext = core.blobSeal(key, nonce, plain);
  const blobId = crypto.randomUUID();
  myRelay.blobs.set(blobId, { bytes: ciphertext, token: `fetch-${blobId}` });
  const history = (host: string) => ({
    blob_id: blobId, key: b64encode(key), blob_nonce: b64encode(nonce), fetch_token: `fetch-${blobId}`,
    blob_host: host, blob_tls_fp: 'ZnA=',
  });
  await as('phone', async () => {
    // Pointing anywhere but our own mailbox is refused.
    await raw(myPhone, me.id, 'sync_history', history('https://evil.example:8080'), 2);
    await raw(myPhone, me.id, 'sync_history', history(browser.grant.relay_address), 2);
  });
  let groupsChanged = 0;
  browser.onGroupsChanged = () => groupsChanged++;
  await as('browser', () => drainAll(browser));
  assert.equal(groupsChanged, 1);

  await as('browser', async () => {
    assert.equal(store.contact(them.id)?.status, 'accepted');
    assert.equal(store.contact(them.id)?.displayName, 'Them');
    assert.equal(store.contact(them.id)?.expireTimerMs, 3600000);
    assert.equal(store.contact(carol.stonechat_id)?.status, 'pendingOut');
    assert.equal(store.contact(carol.stonechat_id)?.blockedAt, 99);
    assert.equal(Object.keys(store.contacts()).length, 2, 'the forged row is skipped');
    const group = store.group(GROUP)!;
    assert.equal(group.name, 'Trip');
    assert.equal(group.version, 3);
    assert.deepEqual(group.members.map((m) => m.displayName), ['Me', 'Them']);
    const dm = store.messages()[them.id] ?? [];
    assert.deepEqual(dm.map((m) => [m.text, m.mine, m.status]), [
      ['old hello', false, 'read'], ['old reply', true, 'delivered'], ['', false, 'read'],
    ]);
    assert.deepEqual(dm[1]!.reactions, { [them.id]: '👍' });
    assert.equal(dm[2]!.media?.kind, 'image');
    assert.equal(dm[2]!.media?.url, undefined);
    assert.deepEqual((store.messages()[threadKey(GROUP, true)] ?? []).map((m) => [m.text, m.sender]), [['in the group', them.id]]);
  });

  // Held rows win: a second bootstrap changes nothing already there.
  await as('browser', async () => {
    store.setContact({ ...store.contact(them.id)!, displayName: 'Renamed here' });
  });
  await as('phone', () => raw(myPhone, me.id, 'sync_history', history(browser.grant.relay_address), 2));
  await as('browser', () => drainAll(browser));
  assert.equal(await as('browser', async () => store.contact(them.id)?.displayName), 'Renamed here');
  assert.equal((await as('browser', async () => store.messages()[them.id]))?.length, 3);
});

test('a first-sight group invitation needs an accepted admin', async () => {
  const { who, as } = await world('alice', 'bob');
  const { alice, bob } = who;
  await as('alice', async () => store.setContact({ ...store.contact(bob.id)!, status: 'pendingIn' }));
  await as('bob', () =>
    raw(bob.protocol, alice.id, 'group_create', {
      group_id: GROUP, name: 'T', version: 1, admin: bob.id,
      members: [{ stonechat_id: bob.id, pubkey: bob.pub }, { stonechat_id: alice.id, pubkey: alice.pub }],
    }));
  await as('alice', () => drainAll(alice.protocol));
  assert.equal(await as('alice', async () => store.group(GROUP)), null);
  await as('alice', () => alice.protocol.acceptContact(bob.id));
  await as('bob', () => drainAll(bob.protocol));
  await as('bob', () =>
    raw(bob.protocol, alice.id, 'group_create', {
      group_id: GROUP, name: 'T', version: 2, admin: bob.id,
      members: [{ stonechat_id: bob.id, pubkey: bob.pub }, { stonechat_id: alice.id, pubkey: alice.pub }],
    }));
  await as('alice', () => drainAll(alice.protocol));
  assert.equal(await as('alice', async () => store.group(GROUP)?.name), 'T');
});
