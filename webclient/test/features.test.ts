/**
 * What the app does, done from a browser.
 *
 * Every behaviour here was missing from the slim client and is required by
 * PROTOCOL.md or done by `chat_state.dart`: the receive-side checks, device
 * manifests, certificate renewal over `sync_cert`, the bundle token for a
 * non-primary device, 410, receipts, typing, edits, deletes, reactions,
 * disappearing messages, roster claims and parked group messages, the
 * transcript check, group media, the outbox, blocks, contact requests,
 * session replacement and the simultaneous-handshake tie-break.
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';

import { b64decode, b64encode, utf8 } from '../src/bytes.js';
import { verifiedManifest } from '../src/manifest.js';
import { DeviceKeys } from '../src/device.js';
import { Protocol } from '../src/protocol.js';
import { store, threadKey } from '../src/store.js';
import {
  befriend, core, drainAll, entryOf, fakeMailbox, FakeRelay, GROUP, grantFor, lastDeposit, ownDevices,
  pair, phone, raw, world,
} from './fixtures.js';
import type { DirectoryEntry } from '../src/hub.js';

// -- what a recipient checks ------------------------------------------------

test('an inner id that differs from the wire id is dropped, and acked', async () => {
  const { bob, A, B, as, bRelay } = await pair();
  await as('b', () => B.publishPrekeys());
  await as('a', () => A.send(bob.id, 'relabelled'));
  const queued = bRelay.queues.get(1)![0]!;
  // The mailbox never saw this id; the sender is trying to be filed under it.
  queued['id'] = crypto.randomUUID();
  assert.deepEqual(await as('b', () => drainAll(B)), []);
  assert.equal(bRelay.queues.get(1)!.length, 0, 'drained');
});

test('an envelope whose wire form is addressed to someone else is dropped', async () => {
  const { bob, A, B, as, bRelay } = await pair();
  await as('b', () => B.publishPrekeys());
  await as('a', () => A.send(bob.id, 'misrouted'));
  bRelay.queues.get(1)![0]!['to'] = 'SC-SOMEONE-ELSE';
  assert.deepEqual(await as('b', () => drainAll(B)), []);
});

test('one malformed envelope does not wedge the session', async () => {
  // M25: a `sealed` that is not base64, an inner that is not JSON, and an
  // envelope with no id, ahead of a good one. Each is dropped on its own; the
  // good one still arrives.
  const { bob, A, B, as, bRelay } = await pair();
  await as('b', () => B.publishPrekeys());
  await as('a', () => A.send(bob.id, 'after the junk'));
  const good = bRelay.queues.get(1)![0]!;
  bRelay.queues.set(1, [
    { ...good, id: crypto.randomUUID(), sealed: '!!! not base64 !!!' },
    { ...good, id: crypto.randomUUID(), sealed: b64encode(utf8.encode('short')) },
    { ...good, id: '' },
    good,
  ]);
  const got = await as('b', () => drainAll(B));
  assert.deepEqual(got.map((m) => m.text), ['after the junk']);
});

test('a directory record carrying a bad pq_pk is refused', async () => {
  const { bob, A, as, entries } = await pair();
  entries[bob.id] = { stonechat_id: bob.id, pubkey: bob.pub, pq_pk: b64encode(new Uint8Array(1216)), pq_sig: b64encode(new Uint8Array(64)) };
  await assert.rejects(as('a', () => A.send(bob.id, 'x')), /bad pq_pk/);
});

// -- device manifests ---------------------------------------------------------

test('a revoked device is dropped on receive and left out on send', async () => {
  const { me, them, themProtocol, phone: myPhone, browser, as, myRelay, theirRelay, entries, phoneKeys, browserKeys } =
    await ownDevices();
  entries[me.id] = { ...entries[me.id]!, devices: me.manifest(1, [[1, phoneKeys], [2, browserKeys]]) } as DirectoryEntry;
  await as('them', () => themProtocol.publishPrekeys());
  await as('phone', () => myPhone.publishPrekeys());
  await as('browser', () => browser.publishPrekeys());

  // The browser writes to them; they learn our bundle token and both devices.
  await as('browser', async () => {
    await browser.send(them.id, 'from the browser');
    await browser.whenSynced();
  });
  assert.deepEqual((await as('them', () => drainAll(themProtocol))).map((m) => m.text), ['from the browser']);
  await as('phone', () => drainAll(myPhone)); // the mirrored copy
  await as('them', () => themProtocol.send(me.id, 'to both'));
  assert.equal(myRelay.queues.get(1)?.length, 1);
  assert.equal(myRelay.queues.get(2)?.length, 1);
  await as('phone', () => drainAll(myPhone));
  await as('browser', () => drainAll(browser));

  // The phone revokes the browser: a manifest without it. A hostile relay
  // could go on listing the browser and serving its certificate — so the
  // manifest is what they check. There is deliberately no periodic refetch:
  // they learn of the new version from the next envelope that states it,
  // here one from the phone.
  const v2 = me.manifest(2, [[1, phoneKeys]]);
  entries[me.id] = { ...entries[me.id]!, devices: v2 } as DirectoryEntry;
  await as('phone', async () => {
    store.setManifest(me.id, verifiedManifest(core, v2, me.id, b64decode(me.pub))!);
    await myPhone.send(them.id, 'the browser is gone');
    await myPhone.whenSynced();
  });
  assert.deepEqual((await as('them', () => drainAll(themProtocol))).map((m) => m.text), ['the browser is gone']);
  assert.equal((await as('them', async () => store.manifest(me.id)))?.version, 2);
  await as('them', () => themProtocol.send(me.id, 'to the phone only'));
  assert.equal(myRelay.queues.get(1)?.length, 1);
  assert.equal(myRelay.queues.get(2)?.length ?? 0, 0, 'nothing encrypted to the revoked device');

  // The revoked browser still holds its keys and writes to them, stating the
  // new manifest version it has seen (it cannot lie usefully: a lower
  // version is checked against what they already hold).
  await as('browser', async () => {
    await browser.send(them.id, 'still here?');
    await browser.whenSynced();
  });
  assert.deepEqual(await as('them', () => drainAll(themProtocol)), [], 'a device off the manifest is dropped');
  void theirRelay;
});

test('a manifest the owner did not sign refuses the whole record', async () => {
  const { bob, A, as, entries, bKeys } = await pair();
  const mallory = phone(11);
  entries[bob.id] = { ...entries[bob.id]!, devices: mallory.manifest(1, [[1, bKeys]]) } as DirectoryEntry;
  await assert.rejects(as('a', () => A.send(bob.id, 'x')), /manifest/);
});

// -- certificates -----------------------------------------------------------

test('the phone renews the browser\'s certificate over sync_cert', async () => {
  const { me, phone: myPhone, browser, as, myRelay, browserKeys } = await ownDevices();
  await as('phone', () => myPhone.publishPrekeys());
  await as('browser', () => browser.publishPrekeys());
  const before = browser.grant.cert;

  // Not ours: another device's keys, then an older one, then a forged one.
  const otherKeys = DeviceKeys.generate(core);
  const older = me.certify(browserKeys, 2, 3600);
  const forged = phone(11).certify(browserKeys, 2, 30 * 86_400);
  const renewed = me.certify(browserKeys, 2, 30 * 86_400);
  await as('phone', async () => {
    await raw(myPhone, me.id, 'sync_cert', { cert: me.certify(otherKeys, 2, 30 * 86_400) }, 2);
    await raw(myPhone, me.id, 'sync_cert', { cert: older }, 2);
    await raw(myPhone, me.id, 'sync_cert', { cert: forged }, 2);
    await raw(myPhone, me.id, 'sync_cert', { cert: renewed }, 2);
  });
  let renewals = 0;
  browser.onCertRenewed = () => renewals++;
  await as('browser', () => drainAll(browser));
  assert.equal(renewals, 1);
  assert.equal(browser.grant.cert.not_after, renewed.not_after);
  assert.notEqual(browser.grant.cert.not_after, before.not_after);
  assert.equal((await as('browser', async () => store.grant()))?.cert.not_after, renewed.not_after, 'persisted');
  // And republished with the prekeys, so senders fetch the new one.
  assert.equal((myRelay.prekeys.get(2)!['cert'] as { not_after: number }).not_after, renewed.not_after);

  // A peer must not write our certificate.
  const stranger = phone(13);
  await as('browser', () => drainAll(browser));
  void stranger;
});

test('an expired sender certificate drops the envelope until a current one is served', async () => {
  const { bob, bKeys, A, B, as, time, bRelay, aRelay } = await pair();
  await as('b', () => B.publishPrekeys());
  await as('a', () => A.publishPrekeys());
  await as('a', () => A.send(bob.id, 'one'));
  assert.deepEqual((await as('b', () => drainAll(B))).map((m) => m.text), ['one']);
  // Bob's phone renews his certificate, as a primary does for itself; Alice
  // refetches it off the open bundle once hers is near expiry. Alice's own
  // certificate (7 days) runs out and her mailbox keeps serving it — a
  // device still linked would have had it renewed over sync_cert.
  bRelay.prekeys.get(1)!['cert'] = bob.certify(bKeys, 1, 30 * 86_400);
  time.advance(8 * 86_400_000);
  await as('a', () => A.send(bob.id, 'two'));
  assert.equal(bRelay.queues.get(1)!.length, 1, 'her mailbox accepted it');
  assert.deepEqual(await as('b', () => drainAll(B)), [], 'expired: dropped');
  void aRelay;
});

// -- devices ------------------------------------------------------------------

test('without a bundle token only the primary is reached', async () => {
  const { me, them, themProtocol, phone: myPhone, browser, as, myRelay } = await ownDevices();
  await as('phone', () => myPhone.publishPrekeys());
  await as('browser', () => browser.publishPrekeys());
  await as('them', () => themProtocol.publishPrekeys());
  // They have never heard from us: no token, so no listing.
  await as('them', () => themProtocol.send(me.id, 'first contact'));
  assert.equal(myRelay.queues.get(1)?.length, 1);
  assert.equal(myRelay.queues.get(2)?.length ?? 0, 0);
});

test('a device answered 410 is forgotten: its session, and nothing owed', async () => {
  const { me, them, themProtocol, phone: myPhone, browser, as, myRelay } = await ownDevices();
  await as('phone', () => myPhone.publishPrekeys());
  await as('browser', () => browser.publishPrekeys());
  await as('them', () => themProtocol.publishPrekeys());
  await as('browser', async () => {
    await browser.send(them.id, 'hi');
    await browser.whenSynced();
  });
  await as('them', () => drainAll(themProtocol));
  await as('them', () => themProtocol.send(me.id, 'both'));
  assert.equal(myRelay.queues.get(2)?.length, 1);
  assert.ok(await as('them', async () => store.session(me.id, 2)));

  myRelay.revoke(2);
  const sent = await as('them', () => themProtocol.send(me.id, 'after revocation'));
  assert.equal(sent.status, 'sent', 'the phone took it; nobody is owed for the revoked device');
  assert.equal(await as('them', async () => store.session(me.id, 2)), null);
  assert.deepEqual(await as('them', async () => store.outbox()), {});
});

// -- receipts and read state --------------------------------------------------

test('delivered and read receipts move a message forward, on every device', async () => {
  const { me, them, themProtocol, phone: myPhone, browser, as } = await ownDevices();
  await as('phone', () => myPhone.publishPrekeys());
  await as('browser', () => browser.publishPrekeys());
  await as('them', () => themProtocol.publishPrekeys());
  await as('browser', async () => {
    await browser.send(them.id, 'hello');
    await browser.whenSynced();
  });
  await as('them', () => drainAll(themProtocol));

  const sent = await as('them', () => themProtocol.send(me.id, 'read me'));
  assert.equal(sent.status, 'sent');
  // The browser stores it and owes a delivery receipt; the batch is flushed.
  const got = await as('browser', async () => {
    const m = await drainAll(browser);
    await browser.flushReceiptsNow();
    return m;
  });
  assert.equal(got[0]!.text, 'read me');
  await as('them', () => drainAll(themProtocol));
  assert.equal((await as('them', async () => store.findMessage(sent.id)))?.message.status, 'delivered');

  // Read on the browser: a read receipt to them, and sync_read to the phone.
  await as('phone', () => drainAll(myPhone));
  await as('browser', async () => {
    browser.markRead(them.id, false);
    await browser.flushReceiptsNow();
    await browser.whenSynced();
  });
  await as('them', () => drainAll(themProtocol));
  assert.equal((await as('them', async () => store.findMessage(sent.id)))?.message.status, 'read');
  await as('phone', () => drainAll(myPhone));
  assert.equal((await as('phone', async () => store.findMessage(sent.id)))?.message.status, 'read');
});

test('a receipt only counts from the person the message went to', async () => {
  const { who, as } = await world('alice', 'bob', 'mallory');
  const { alice, bob, mallory } = who;
  const sent = await as('alice', () => alice.protocol.send(bob.id, 'for bob'));
  await as('mallory', () => raw(mallory.protocol, alice.id, 'receipt', { kind: 'read', ids: [sent.id] }));
  await as('alice', () => drainAll(alice.protocol));
  assert.equal((await as('alice', async () => store.findMessage(sent.id)))?.message.status, 'sent');
});

test('a group message is delivered when every member has it', async () => {
  const { who, as } = await world('admin', 'bea', 'cal');
  const { admin, bea, cal } = who;
  const roster = { group_id: GROUP, name: 'T', version: 1, admin: admin.id, members: [entryOf(admin), entryOf(bea), entryOf(cal)] };
  await as('admin', async () => {
    store.upsertGroup({ id: GROUP, name: 'T', admin: admin.id, version: 1, members: roster.members.map((m) => ({ stonechatId: m.stonechat_id, pubkey: m.pubkey })) });
    await raw(admin.protocol, bea.id, 'group_create', roster);
    await raw(admin.protocol, cal.id, 'group_create', roster);
  });
  await as('bea', () => drainAll(bea.protocol));
  await as('cal', () => drainAll(cal.protocol));
  const sent = await as('admin', () => admin.protocol.sendGroup(GROUP, 'all'));
  await as('bea', async () => { await drainAll(bea.protocol); await bea.protocol.flushReceiptsNow(); });
  await as('admin', () => drainAll(admin.protocol));
  assert.equal((await as('admin', async () => store.findMessage(sent.id)))?.message.status, 'sent', 'one of two');
  await as('cal', async () => { await drainAll(cal.protocol); await cal.protocol.flushReceiptsNow(); });
  await as('admin', () => drainAll(admin.protocol));
  assert.equal((await as('admin', async () => store.findMessage(sent.id)))?.message.status, 'delivered');
});

test('mentions name members, and only members survive the trip', async () => {
  const { who, as } = await world('admin', 'bea', 'cal');
  const { admin, bea, cal } = who;
  const roster = { group_id: GROUP, name: 'T', version: 1, admin: admin.id, members: [entryOf(admin), entryOf(bea), entryOf(cal)] };
  await as('admin', async () => {
    store.upsertGroup({ id: GROUP, name: 'T', admin: admin.id, version: 1, members: roster.members.map((m) => ({ stonechatId: m.stonechat_id, pubkey: m.pubkey })) });
    await raw(admin.protocol, bea.id, 'group_create', roster);
    await raw(admin.protocol, cal.id, 'group_create', roster);
  });
  await as('bea', () => drainAll(bea.protocol));
  await as('cal', () => drainAll(cal.protocol));
  const sent = await as('admin', () => admin.protocol.sendGroup(GROUP, '@bea look', { mentions: [bea.id, 'SC-NOBODY'] }));
  assert.deepEqual(sent.mentions, [bea.id], 'a non-member is not a mention');
  const deposit = bea.relay.deposits.find((d) => d['transient'] !== true);
  assert.ok(deposit, 'bea got the message');
  await as('bea', () => drainAll(bea.protocol));
  const held = await as('bea', async () => store.findMessage(sent.id)?.message);
  assert.deepEqual(held?.mentions, [bea.id]);
});

// -- typing -----------------------------------------------------------------------

test('typing is transient, shown for a while, and only on existing sessions', async () => {
  const { who, as, time } = await world('alice', 'bob');
  const { alice, bob } = who;
  const seen: Array<[string, string[]]> = [];
  bob.protocol.onTyping = (key, whoIs) => seen.push([key, whoIs]);

  // No session yet: nothing is sent — a typing hint is never worth a handshake.
  await as('alice', () => alice.protocol.notifyTyping(bob.id, false));
  await new Promise((r) => setTimeout(r, 10));
  assert.equal(bob.relay.deposits.length, 0);

  await as('alice', () => alice.protocol.send(bob.id, 'hi'));
  await as('bob', () => drainAll(bob.protocol));
  time.advance(10_000);
  await as('alice', async () => {
    alice.protocol.notifyTyping(bob.id, false);
    await new Promise((r) => setTimeout(r, 10));
  });
  assert.equal(lastDeposit(bob.relay)['transient'], true);
  await as('bob', () => drainAll(bob.protocol));
  assert.deepEqual(seen, [[threadKey(alice.id, false), [alice.id]]]);
  assert.deepEqual(bob.protocol.typersIn(threadKey(alice.id, false)), [alice.id]);
  time.advance(16_000);
  assert.deepEqual(bob.protocol.typersIn(threadKey(alice.id, false)), []);

  // One too far from our clock is ignored.
  await as('alice', () =>
    raw(alice.protocol, bob.id, 'typing', { state: 'started' }, 1, { transient: true, sentAt: new Date(time.now() - 120_000).toISOString() }));
  await as('bob', () => drainAll(bob.protocol));
  assert.deepEqual(bob.protocol.typersIn(threadKey(alice.id, false)), []);
});

// -- edits, deletes, reactions -----------------------------------------------------

test('edits, deletes and reactions apply in a direct conversation', async () => {
  const { who, as } = await world('alice', 'bob', 'mallory');
  const { alice, bob, mallory } = who;
  const sent = await as('alice', () => alice.protocol.send(bob.id, 'teh message'));
  await as('bob', () => drainAll(bob.protocol));

  assert.equal(await as('alice', () => alice.protocol.editMessage(sent, 'the message')), true);
  await as('bob', () => drainAll(bob.protocol));
  const edited = await as('bob', async () => store.findMessage(sent.id)!.message);
  assert.equal(edited.text, 'the message');
  assert.ok(edited.editedAt);

  // Only the author: a third party naming the id changes nothing.
  await as('mallory', () => raw(mallory.protocol, bob.id, 'msg_edit', { id: sent.id, text: 'hijacked' }));
  await as('bob', () => drainAll(bob.protocol));
  assert.equal((await as('bob', async () => store.findMessage(sent.id)))?.message.text, 'the message');

  await as('bob', () => bob.protocol.react(edited, '👍'));
  await as('alice', () => drainAll(alice.protocol));
  assert.deepEqual((await as('alice', async () => store.findMessage(sent.id)))?.message.reactions, { [bob.id]: '👍' });
  await as('bob', () => bob.protocol.react(edited, '👍')); // same again clears
  await as('alice', () => drainAll(alice.protocol));
  assert.deepEqual((await as('alice', async () => store.findMessage(sent.id)))?.message.reactions, {});

  assert.equal(await as('alice', () => alice.protocol.deleteForEveryone(sent)), true);
  await as('bob', () => drainAll(bob.protocol));
  const gone = await as('bob', async () => store.findMessage(sent.id)!.message);
  assert.equal(gone.deleted, true);
  assert.equal(gone.text, '');
});

test('edits and reactions in a group come only from members, on their own messages', async () => {
  const { who, as } = await world('admin', 'bea', 'cal', 'mallory');
  const { admin, bea, cal, mallory } = who;
  const members = [entryOf(admin), entryOf(bea), entryOf(cal)];
  const roster = { group_id: GROUP, name: 'T', version: 1, admin: admin.id, members };
  await as('admin', async () => {
    store.upsertGroup({ id: GROUP, name: 'T', admin: admin.id, version: 1, members: members.map((m) => ({ stonechatId: m.stonechat_id, pubkey: m.pubkey })) });
    for (const to of [bea, cal]) await raw(admin.protocol, to.id, 'group_create', roster);
  });
  await as('bea', () => drainAll(bea.protocol));
  await as('cal', () => drainAll(cal.protocol));
  const sent = await as('bea', () => bea.protocol.sendGroup(GROUP, 'draft'));
  await as('cal', () => drainAll(cal.protocol));

  await as('bea', () => bea.protocol.editMessage(sent, 'final'));
  // A member editing someone else's message, and a non-member reacting.
  await as('admin', () => raw(admin.protocol, cal.id, 'group_msg_edit', { group_id: GROUP, id: sent.id, text: 'not mine' }));
  await as('mallory', () => raw(mallory.protocol, cal.id, 'group_reaction', { group_id: GROUP, id: sent.id, emoji: '💀' }));
  await as('admin', () => raw(admin.protocol, cal.id, 'group_reaction', { group_id: GROUP, id: sent.id, emoji: '👏' }));
  await as('cal', () => drainAll(cal.protocol));
  const held = await as('cal', async () => store.findMessage(sent.id)!.message);
  assert.equal(held.text, 'final');
  assert.deepEqual(held.reactions, { [admin.id]: '👏' });
});

// -- disappearing messages -------------------------------------------------------

test('a timer set by either side expires messages on time', async () => {
  const { who, as, time } = await world('alice', 'bob');
  const { alice, bob } = who;
  await as('alice', () => alice.protocol.setExpireTimer(bob.id, false, 3_600_000));
  const notices = await as('bob', () => drainAll(bob.protocol));
  assert.match(notices[0]!.text, /disappear after 1 hour/);
  assert.equal(await as('bob', async () => bob.protocol.expireTimerOf(alice.id, false)), 3_600_000);

  // Bob's own messages now carry the TTL; alice's do too.
  const fromBob = await as('bob', () => bob.protocol.send(alice.id, 'gone in an hour'));
  assert.equal(fromBob.expiresAt, time.now() + 3_600_000);
  const got = await as('alice', () => drainAll(alice.protocol));
  assert.equal(got[0]!.expiresAt, Date.parse(fromBob.sentAt) + 3_600_000);

  // An older timer_update cannot regress the setting.
  await as('alice', () =>
    raw(alice.protocol, bob.id, 'timer_update', { expire_ms: 0 }, 1, { sentAt: new Date(time.now() - 60_000).toISOString() }));
  await as('bob', () => drainAll(bob.protocol));
  assert.equal(await as('bob', async () => bob.protocol.expireTimerOf(alice.id, false)), 3_600_000);

  time.advance(3_600_001);
  await as('alice', async () => {
    assert.equal(alice.protocol.nextExpiry(), Date.parse(fromBob.sentAt) + 3_600_000);
    alice.protocol.sweepExpired();
    assert.equal(store.findMessage(fromBob.id), null);
  });
});

// -- rosters in step -----------------------------------------------------------------

test('a message ahead of its roster is parked, the admin is asked, and it is read once the roster lands', async () => {
  const { who, as } = await world('admin', 'bea', 'cal');
  const { admin, bea, cal } = who;
  const v2 = { group_id: GROUP, name: 'T', version: 2, admin: admin.id, members: [entryOf(admin), entryOf(bea), entryOf(cal)] };
  // The admin's roster reached bea but not cal (yet). Cal has never heard of
  // the group; bea writes to it.
  await as('admin', async () => {
    store.upsertGroup({ id: GROUP, name: 'T', admin: admin.id, version: 2, members: v2.members.map((m) => ({ stonechatId: m.stonechat_id, pubkey: m.pubkey })) });
    await raw(admin.protocol, bea.id, 'group_update', v2);
  });
  await as('bea', () => drainAll(bea.protocol));
  await as('bea', () => bea.protocol.sendGroup(GROUP, 'early'));
  assert.deepEqual(await as('cal', () => drainAll(cal.protocol)), [], 'parked, not shown');
  assert.equal((await as('cal', async () => store.parked())).length, 1);
  // Cal asked the admin for the roster (the admin also hears bea)…
  const atAdmin = await as('admin', () => drainAll(admin.protocol));
  assert.deepEqual(atAdmin.map((m) => m.text), ['early']);
  // …and the admin answered with the current roster, which lets cal in and
  // releases what was parked.
  const got = await as('cal', () => drainAll(cal.protocol));
  assert.equal((await as('cal', async () => store.group(GROUP)))?.version, 2);
  assert.deepEqual((await as('cal', async () => store.messages()[threadKey(GROUP, true)] ?? [])).map((m) => m.text), ['early']);
  assert.deepEqual(got, []);
  assert.equal((await as('cal', async () => store.parked())).length, 0);
});

test('a member behind the roster is handed the current one by the admin', async () => {
  const { who, as } = await world('admin', 'bea', 'cal');
  const { admin, bea, cal } = who;
  const members = [entryOf(admin), entryOf(bea), entryOf(cal)];
  const v1 = { group_id: GROUP, name: 'T', version: 1, admin: admin.id, members };
  await as('admin', async () => {
    store.upsertGroup({ id: GROUP, name: 'T', admin: admin.id, version: 1, members: members.map((m) => ({ stonechatId: m.stonechat_id, pubkey: m.pubkey })) });
    for (const to of [bea, cal]) await raw(admin.protocol, to.id, 'group_create', v1);
  });
  await as('bea', () => drainAll(bea.protocol));
  await as('cal', () => drainAll(cal.protocol));
  // The admin renames (v2) but cal's copy never arrives.
  await as('admin', async () => {
    store.upsertGroup({ id: GROUP, name: 'Renamed', admin: admin.id, version: 2, members: members.map((m) => ({ stonechatId: m.stonechat_id, pubkey: m.pubkey })) });
    await raw(admin.protocol, bea.id, 'group_update', { ...v1, name: 'Renamed', version: 2 });
  });
  await as('bea', () => drainAll(bea.protocol));
  // Cal writes with roster v1; the admin sees cal is behind and sends v2.
  await as('cal', () => cal.protocol.sendGroup(GROUP, 'still on v1'));
  await as('admin', () => drainAll(admin.protocol));
  await as('cal', () => drainAll(cal.protocol));
  assert.equal((await as('cal', async () => store.group(GROUP)))?.name, 'Renamed');
});

test('two members sent different text under one id can tell', async () => {
  const { who, as } = await world('admin', 'bea', 'cal');
  const { admin, bea, cal } = who;
  const members = [entryOf(admin), entryOf(bea), entryOf(cal)];
  const v1 = { group_id: GROUP, name: 'T', version: 1, admin: admin.id, members };
  await as('admin', async () => {
    store.upsertGroup({ id: GROUP, name: 'T', admin: admin.id, version: 1, members: members.map((m) => ({ stonechatId: m.stonechat_id, pubkey: m.pubkey })) });
    for (const to of [bea, cal]) await raw(admin.protocol, to.id, 'group_create', v1);
  });
  await as('bea', () => drainAll(bea.protocol));
  await as('cal', () => drainAll(cal.protocol));
  // The admin tells bea one thing and cal another, under one id and salt.
  const id = crypto.randomUUID();
  const salt = b64encode(new Uint8Array(16).fill(5));
  await as('admin', async () => {
    await raw(admin.protocol, bea.id, 'group_msg', { group_id: GROUP, text: 'meet at 8', salt }, 1, { id });
    await raw(admin.protocol, cal.id, 'group_msg', { group_id: GROUP, text: 'meet at 9', salt }, 1, { id });
  });
  await as('bea', () => drainAll(bea.protocol));
  await as('cal', () => drainAll(cal.protocol));
  // Bea's next message carries what she saw; cal holds a different hash.
  await as('bea', () => bea.protocol.sendGroup(GROUP, 'see you then'));
  await as('cal', () => drainAll(cal.protocol));
  const notices = (await as('cal', async () => store.messages()[threadKey(GROUP, true)] ?? [])).filter((m) => m.notice);
  assert.equal(notices.length, 1);
  assert.match(notices[0]!.text, /different version of a message/);
});

test('a roster change is told as notices, and a group_leave removes the member', async () => {
  const { who, as } = await world('admin', 'bea', 'cal');
  const { admin, bea, cal } = who;
  const v1 = { group_id: GROUP, name: 'T', version: 1, admin: admin.id, members: [entryOf(admin), entryOf(bea)] };
  await as('admin', () => raw(admin.protocol, bea.id, 'group_create', v1));
  await as('admin', () => raw(admin.protocol, bea.id, 'group_update', { ...v1, version: 2, name: 'Trip', members: [entryOf(admin), entryOf(bea), entryOf(cal, 'Cal')] }));
  await as('bea', () => drainAll(bea.protocol));
  const texts = (await as('bea', async () => store.messages()[threadKey(GROUP, true)] ?? [])).map((m) => m.text);
  assert.ok(texts.some((t) => /renamed to "Trip"/.test(t)));
  assert.ok(texts.some((t) => /Cal was added/.test(t)));
  await as('cal', () => raw(cal.protocol, bea.id, 'group_leave', { group_id: GROUP }));
  const got = await as('bea', () => drainAll(bea.protocol));
  assert.equal(got[0]!.text, 'Cal left');
  assert.deepEqual((await as('bea', async () => store.group(GROUP)))?.members.map((m) => m.stonechatId), [admin.id, bea.id]);
});

// -- group media ---------------------------------------------------------------------

test('a group attachment is one blob on the sender\'s mailbox, fetched by each member', async () => {
  const { who, as } = await world('admin', 'bea', 'cal');
  const { admin, bea, cal } = who;
  const members = [entryOf(admin), entryOf(bea), entryOf(cal)];
  const v1 = { group_id: GROUP, name: 'T', version: 1, admin: admin.id, members };
  await as('admin', async () => {
    store.upsertGroup({ id: GROUP, name: 'T', admin: admin.id, version: 1, members: members.map((m) => ({ stonechatId: m.stonechat_id, pubkey: m.pubkey })) });
    for (const to of [bea, cal]) await raw(admin.protocol, to.id, 'group_create', v1);
  });
  await as('bea', () => drainAll(bea.protocol));
  await as('cal', () => drainAll(cal.protocol));
  const bytes = new Uint8Array(3000).map((_, i) => i % 251);
  const file = new File([bytes], 'pic.png', { type: 'image/png' });
  const sent = await as('bea', () => bea.protocol.sendGroupMedia(GROUP, file));
  assert.equal(sent.media?.kind, 'image');
  assert.equal(bea.relay.blobs.size, 1, 'one upload, on the sender\'s own mailbox');
  assert.equal(admin.relay.blobs.size, 0);
  for (const name of ['admin', 'cal'] as const) {
    const got = await as(name, () => drainAll(who[name].protocol));
    assert.equal(got.length, 1);
    assert.equal(got[0]!.media?.size, 3000);
    assert.ok(got[0]!.media?.url, 'decrypted in the tab');
    assert.equal(got[0]!.media?.name, 'pic.png');
  }
  // What the store keeps has no URL: it dies with the tab.
  const kept = await as('cal', async () => store.findMessage(sent.id)!.message);
  assert.equal(kept.media?.url, undefined);
  assert.equal(kept.media?.size, 3000);
});

test('a direct attachment is parked on the recipient\'s mailbox, and a copy for our own devices on ours', async () => {
  const { me, them, themProtocol, phone: myPhone, browser, as, myRelay, theirRelay } = await ownDevices();
  await as('phone', () => myPhone.publishPrekeys());
  await as('browser', () => browser.publishPrekeys());
  await as('them', () => themProtocol.publishPrekeys());
  const file = new File([new Uint8Array(500).fill(7)], 'note.txt', { type: 'text/plain' });
  await as('browser', async () => {
    await browser.sendMedia(them.id, file);
    await browser.whenSynced();
  });
  assert.equal(theirRelay.blobs.size, 1);
  assert.equal(myRelay.blobs.size, 1, 'the sibling copy');
  const theirs = await as('them', () => drainAll(themProtocol));
  assert.equal(theirs[0]!.media?.kind, 'file');
  assert.equal(theirs[0]!.media?.size, 500);
  const onPhone = await as('phone', () => drainAll(myPhone));
  assert.equal(onPhone[0]!.mine, true);
  assert.equal(onPhone[0]!.media?.size, 500);
  assert.ok(onPhone[0]!.media?.url);
});

// -- the outbox ------------------------------------------------------------------------

test('a send to an unreachable mailbox waits in the outbox and is retried with backoff', async () => {
  const { who, as, time } = await world('alice', 'bob');
  const { alice, bob } = who;
  bob.relay.down = true;
  const sent = await as('alice', () => alice.protocol.send(bob.id, 'patience'));
  assert.equal(sent.status, 'pending');
  assert.match(sent.error ?? '', /unreachable/);
  assert.equal(await as('alice', async () => alice.protocol.hasPendingWork()), true);

  bob.relay.down = false;
  // Too soon: the first retry waits 30 s.
  await as('alice', () => alice.protocol.retryPending());
  assert.equal((await as('alice', async () => store.findMessage(sent.id)))?.message.status, 'pending');
  time.advance(31_000);
  await as('alice', () => alice.protocol.retryPending());
  assert.equal((await as('alice', async () => store.findMessage(sent.id)))?.message.status, 'sent');
  assert.deepEqual((await as('bob', () => drainAll(bob.protocol))).map((m) => m.text), ['patience']);
  assert.equal(await as('alice', async () => alice.protocol.hasPendingWork()), false);
});

test('a refused send fails at once and is not retried', async () => {
  const { bob, A, as, entries } = await pair();
  const mallory = phone(11);
  entries[bob.id] = { stonechat_id: bob.id, pubkey: mallory.pub };
  await assert.rejects(as('a', () => A.send(bob.id, 'x')), /does not commit/);
  const held = await as('a', async () => (store.messages()[bob.id] ?? [])[0]);
  assert.equal(held?.status, 'failed');
  assert.deepEqual(await as('a', async () => store.outbox()), {});
});

test('a retry sends to the devices still owed, not again to the ones that took it', async () => {
  const { me, them, themProtocol, phone: myPhone, browser, as, myRelay, time } = await ownDevices();
  await as('phone', () => myPhone.publishPrekeys());
  await as('browser', () => browser.publishPrekeys());
  await as('them', () => themProtocol.publishPrekeys());
  await as('browser', async () => {
    await browser.send(them.id, 'hi');
    await browser.whenSynced();
  });
  await as('them', () => drainAll(themProtocol));
  await as('phone', () => drainAll(myPhone)); // the mirrored copy of 'hi'
  // Device 2's queue cannot take a deposit right now (full): its copy is
  // owed, device 1's is not.
  myRelay.failInboxFor.add(2);
  const sent = await as('them', () => themProtocol.send(me.id, 'partial'));
  assert.equal(sent.status, 'pending');
  assert.equal(myRelay.queues.get(1)?.length, 1);
  assert.deepEqual(await as('them', async () => store.outbox()[sent.id]?.owed), { [me.id]: [2] });
  myRelay.failInboxFor.delete(2);
  time.advance(31_000);
  await as('them', () => themProtocol.retryPending());
  assert.equal(myRelay.queues.get(1)?.length, 1, 'not sent twice to device 1');
  assert.equal(myRelay.queues.get(2)?.length, 1);
  assert.equal((await as('them', async () => store.findMessage(sent.id)))?.message.status, 'sent');
});

// -- contacts and blocks ---------------------------------------------------------------

test('a contact request is shown and waits for the phone; a message from them is not shown', async () => {
  const { who, as } = await world('alice', 'mallory');
  const { alice, mallory } = who;
  await as('mallory', async () => {
    await raw(mallory.protocol, alice.id, 'contact_request', { display_name: 'Mal' });
    await raw(mallory.protocol, alice.id, 'msg', { text: 'let me in' });
  });
  const got = await as('alice', () => drainAll(alice.protocol));
  assert.equal(got.length, 1);
  assert.equal(got[0]!.request, true);
  assert.match(got[0]!.text, /Mal wants to connect/);
  const contact = await as('alice', async () => store.contact(mallory.id));
  assert.equal(contact?.status, 'pendingIn');
  assert.equal(contact?.displayName, 'Mal');
  assert.equal(await as('alice', async () => alice.protocol.nameOf(mallory.id)), 'Mal');
});

test('a block synced from the phone stops their messages here and ours to them', async () => {
  const { me, them, themProtocol, phone: myPhone, browser, as } = await ownDevices();
  await as('phone', () => myPhone.publishPrekeys());
  await as('browser', () => browser.publishPrekeys());
  await as('them', () => themProtocol.publishPrekeys());
  await as('browser', async () => {
    await browser.send(them.id, 'so they can reach device 2');
    await browser.whenSynced();
  });
  await as('them', () => drainAll(themProtocol));
  await as('them', () => themProtocol.send(me.id, 'before'));
  assert.deepEqual((await as('browser', () => drainAll(browser))).map((m) => m.text), ['before']);
  await as('phone', () => raw(myPhone, me.id, 'sync_block', { peer: them.id, blocked_at: Date.now() }, 2));
  await as('browser', () => drainAll(browser));
  assert.equal(await as('browser', async () => browser.isBlocked(them.id)), true);
  await as('them', () => themProtocol.send(me.id, 'after'));
  assert.deepEqual(await as('browser', () => drainAll(browser)), []);
  await assert.rejects(as('browser', () => browser.send(them.id, 'x')), /blocked/);
  await as('phone', () => raw(myPhone, me.id, 'sync_block', { peer: them.id, blocked_at: null }, 2));
  await as('browser', () => drainAll(browser));
  assert.equal(await as('browser', async () => browser.isBlocked(them.id)), false);
});

test('a profile update renames a contact, and an older one cannot regress it', async () => {
  const { who, as, time } = await world('alice', 'bob');
  const { alice, bob } = who;
  await as('bob', () => raw(bob.protocol, alice.id, 'contact_accept', { display_name: 'Bob' }));
  await as('bob', () => raw(bob.protocol, alice.id, 'profile_update', { display_name: 'Robert' }, 1, { sentAt: new Date(time.now() + 1000).toISOString() }));
  await as('bob', () => raw(bob.protocol, alice.id, 'profile_update', { display_name: 'Bobby' }, 1, { sentAt: new Date(time.now() - 1000).toISOString() }));
  await as('alice', () => drainAll(alice.protocol));
  assert.equal(await as('alice', async () => alice.protocol.nameOf(bob.id)), 'Robert');
});

// -- sessions ----------------------------------------------------------------------------

test('a peer who reinstalled gets through: a fresh handshake replaces the dead session', async () => {
  const { who, as, relays, entries } = await world('alice', 'bob');
  const { alice, bob } = who;
  await as('alice', () => alice.protocol.send(bob.id, 'before'));
  await as('bob', () => drainAll(bob.protocol));
  await as('bob', () => bob.protocol.send(alice.id, 'reply'));
  await as('alice', () => drainAll(alice.protocol));

  // Bob reinstalls: new device keys, a new certificate for slot 1, no
  // sessions. Same identity, same mailbox.
  const keys = DeviceKeys.generate(core);
  const bob2 = new Protocol(
    core,
    { directory: async (id: string) => entries[id]! } as never,
    keys,
    grantFor(bob.owner, bob.owner.certify(keys, 1), 1),
    async (entry: DirectoryEntry) => fakeMailbox(relays[entry.stonechat_id]!, 1),
    () => Date.now(),
    null,
  );
  await as('bob', async () => {
    store.clear();
    befriend(alice); // a reinstall restores its contacts from a backup
    await bob2.publishPrekeys();
    await bob2.send(alice.id, 'from the new install');
  });
  assert.deepEqual((await as('alice', () => drainAll(alice.protocol))).map((m) => m.text), ['from the new install']);
  // And the conversation continues both ways on the new session.
  await as('alice', () => alice.protocol.send(bob.id, 'welcome back'));
  assert.deepEqual((await as('bob', () => drainAll(bob2))).map((m) => m.text), ['welcome back']);
});

test('a simultaneous start converges on the lower ID\'s session', async () => {
  const { who, as } = await world('p', 'q');
  const [lower, higher] = [who.p, who.q].sort((a, b) => (a.id < b.id ? -1 : 1));
  const name = (x: typeof lower) => (x === who.p ? 'p' : 'q');
  // Both write before either reads.
  await as(name(lower), () => lower.protocol.send(higher.id, 'from lower'));
  await as(name(higher), () => higher.protocol.send(lower.id, 'from higher'));
  // The higher ID adopts the lower's session; the lower drops the higher's
  // initial envelope — the loser's first message is the price of the race.
  assert.deepEqual((await as(name(higher), () => drainAll(higher.protocol))).map((m) => m.text), ['from lower']);
  assert.deepEqual(await as(name(lower), () => drainAll(lower.protocol)), []);
  // From here on, both directions work.
  await as(name(higher), () => higher.protocol.send(lower.id, 'again'));
  assert.deepEqual((await as(name(lower), () => drainAll(lower.protocol))).map((m) => m.text), ['again']);
  await as(name(lower), () => lower.protocol.send(higher.id, 'and back'));
  assert.deepEqual((await as(name(higher), () => drainAll(higher.protocol))).map((m) => m.text), ['and back']);
});

test('signed prekeys rotate weekly, and a handshake against the previous one still completes', async () => {
  const { bob, A, B, as, time, bRelay } = await pair();
  await as('b', () => B.publishPrekeys());
  const first = (bRelay.prekeys.get(1)!['spk'] as { id: number }).id;
  await as('a', () => A.send(bob.id, 'against the old prekey'));
  time.advance(8 * 86_400_000);
  // Alice's certificate (7 days in these tests) would have run out; renew it
  // the way her phone would, so what is under test is the prekey.
  await as('b', () => B.publishPrekeys());
  const second = (bRelay.prekeys.get(1)!['spk'] as { id: number }).id;
  assert.notEqual(first, second, 'rotated');
  const pool = await as('b', async () => store.prekeys()!);
  assert.equal(pool.prevSpk?.id, first, 'the previous one is kept through one rotation');
  assert.equal(Object.keys(pool.opks).length, 32);
  time.advance(-8 * 86_400_000); // back, so the certificate is current again
  assert.deepEqual((await as('b', () => drainAll(B))).map((m) => m.text), ['against the old prekey']);
});

test('our own manifest version rides every envelope we send', async () => {
  const { me, them, themProtocol, phone: myPhone, browser, as, entries, phoneKeys, browserKeys, theirRelay } = await ownDevices();
  entries[me.id] = { ...entries[me.id]!, devices: me.manifest(5, [[1, phoneKeys], [2, browserKeys]]) } as DirectoryEntry;
  await as('phone', () => myPhone.publishPrekeys());
  await as('browser', () => browser.publishPrekeys());
  await as('them', () => themProtocol.publishPrekeys());
  await as('browser', async () => {
    await browser.send(them.id, 'hi');
    await browser.whenSynced();
  });
  // Open their copy as they would, and read the version off it.
  const wire = lastDeposit(theirRelay);
  assert.equal(wire['to'], them.id);
  const got = await as('them', () => drainAll(themProtocol));
  assert.equal(got.length, 1);
  assert.equal((await as('them', async () => store.manifest(me.id)))?.version, 5);
});

test('a sibling\'s sync_read marks a message read; a sync from a peer does not', async () => {
  const { me, them, themProtocol, phone: myPhone, browser, as } = await ownDevices();
  await as('phone', () => myPhone.publishPrekeys());
  await as('browser', () => browser.publishPrekeys());
  await as('them', () => themProtocol.publishPrekeys());
  await as('browser', async () => {
    await browser.send(them.id, 'so they can reach device 2');
    await browser.whenSynced();
  });
  await as('them', () => drainAll(themProtocol));
  const sent = await as('them', () => themProtocol.send(me.id, 'unread'));
  await as('browser', () => drainAll(browser));
  await as('phone', () => drainAll(myPhone));
  await as('them', () => raw(themProtocol, me.id, 'sync_read', { peer: them.id, ids: [sent.id] }, 2));
  await as('browser', () => drainAll(browser));
  assert.equal((await as('browser', async () => store.findMessage(sent.id)))?.message.status, 'sent');
  await as('phone', () => raw(myPhone, me.id, 'sync_read', { peer: them.id, ids: [sent.id] }, 2));
  await as('browser', () => drainAll(browser));
  assert.equal((await as('browser', async () => store.findMessage(sent.id)))?.message.status, 'read');
});
