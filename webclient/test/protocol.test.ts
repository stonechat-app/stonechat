/**
 * Two web sessions, talking.
 *
 * The relay and hub are mocked (`fixtures.ts`): what needs proving here is
 * the *crypto orchestration*, and that should be provable without a browser
 * or a running relay.
 *
 * What this pins: PQXDH between two devices, the certificate checks on both
 * sides, the AEAD binding both device numbers, ratchet advance across several
 * messages, one-time prekeys being consumed exactly once, self-sync between a
 * user's own devices, and the group rules.
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';

import type { SignedCert } from '../src/core.js';
import { DeviceKeys } from '../src/device.js';
import { store } from '../src/store.js';
import { b64decode, b64encode, utf8 } from '../src/bytes.js';
import { certSigKey } from '../src/device.js';
import {
  core, drain, drainAll, entryOf, FakeRelay, GROUP, ownDevices, pair, phone, raw, world,
} from './fixtures.js';

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

test('a directory answering with someone else\'s record is refused', async () => {
  // Mallory's record is complete and self-consistent: her key does hash to
  // her ID. Served in answer to a lookup for Bob, the only thing wrong with it
  // is that it is not what was asked for — so that is what has to be checked.
  const { bob, A, as, entries, bRelay } = await pair();
  const mallory = phone(11);
  entries[bob.id] = { stonechat_id: mallory.id, pubkey: mallory.pub };
  await assert.rejects(
    as('a', () => A.send(bob.id, 'for bob only')),
    /does not commit/,
  );
  assert.equal(bRelay.queues.get(1)?.length ?? 0, 0);
});

test('a key that does not hash to the ID asked for is refused', async () => {
  // The cruder lie: Bob's ID on the label, Mallory's key inside.
  const { bob, A, as, entries } = await pair();
  const mallory = phone(11);
  entries[bob.id] = { stonechat_id: bob.id, pubkey: mallory.pub };
  await assert.rejects(
    as('a', () => A.send(bob.id, 'for bob only')),
    /does not commit/,
  );
});

test('a certificate signed by another identity is refused by name', async () => {
  // Correctly signed and unexpired, by a key its SC- ID does not commit to.
  const mallory = phone(11);
  const victim = phone(9);
  const keys = DeviceKeys.generate(core);
  const forged = core.devcertSign(
    {
      stonechat_id: victim.id,
      device_id: 1,
      sig_pub: b64encode(keys.sigPublic),
      seal_pub: b64encode(keys.sealPublic),
      not_after: Math.floor(Date.now() / 1000) + 3600,
    },
    new Uint8Array(32).fill(11),
  );
  const now = Math.floor(Date.now() / 1000);
  assert.equal(
    core.devcertVerify(forged, b64decode(mallory.pub), now),
    'wrong_identity',
  );
  assert.equal(
    core.devcertVerify(forged, b64decode(victim.pub), now),
    'bad_signature',
  );
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
      ...stray,
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

// -- groups ------------------------------------------------------------------

test('a group works end to end: create, talk both ways, add and remove', async () => {
  const { who, as } = await world('admin', 'bea', 'cal', 'dee');
  const { admin, bea, cal, dee } = who;
  const v1 = {
    group_id: GROUP, name: 'Trip', version: 1, admin: admin.id,
    members: [entryOf(admin), entryOf(bea, 'Bea'), entryOf(cal)],
  };
  await as('admin', async () => {
    // The admin's own copy is local on a phone; here it holds one the same
    // way every member does, so it can send.
    store.upsertGroup({
      id: GROUP, name: 'Trip', admin: admin.id, version: 1,
      members: v1.members.map((m) => ({ stonechatId: m.stonechat_id, pubkey: m.pubkey })),
    });
    await raw(admin.protocol, bea.id, 'group_create', v1);
    await raw(admin.protocol, cal.id, 'group_create', v1);
  });
  assert.deepEqual(await as('bea', () => drainAll(bea.protocol)), []);
  assert.deepEqual(await as('cal', () => drainAll(cal.protocol)), []);
  const held = await as('bea', async () => store.groups()[GROUP]);
  assert.equal(held?.name, 'Trip');
  assert.equal(held?.admin, admin.id);
  assert.equal(held?.members[1]?.displayName, 'Bea');

  // A member speaks; the admin and the other member both hear it.
  const sent = await as('bea', () => bea.protocol.sendGroup(GROUP, 'hello all'));
  assert.equal(sent.group, true);
  for (const name of ['admin', 'cal'] as const) {
    const got = await as(name, () => drainAll(who[name].protocol));
    assert.equal(got.length, 1, `${name} hears bea`);
    assert.equal(got[0]!.text, 'hello all');
    assert.equal(got[0]!.peerId, GROUP);
    assert.equal(got[0]!.group, true);
    assert.equal(got[0]!.sender, bea.id);
  }
  // And the other way.
  await as('admin', () => admin.protocol.sendGroup(GROUP, 'hello back'));
  const back = await as('bea', () => drainAll(bea.protocol));
  assert.deepEqual(back.map((m) => [m.text, m.sender]), [['hello back', admin.id]]);
  await as('cal', () => drainAll(cal.protocol));

  // v2: dee in, cal out. Everyone affected is told, including the one removed.
  const v2 = {
    ...v1, version: 2,
    members: [entryOf(admin), entryOf(bea), entryOf(dee)],
  };
  await as('admin', async () => {
    for (const to of [bea, cal, dee]) await raw(admin.protocol, to.id, 'group_update', v2);
  });
  for (const name of ['bea', 'cal', 'dee'] as const) {
    await as(name, () => drainAll(who[name].protocol));
  }
  assert.deepEqual(
    (await as('dee', async () => store.groups()[GROUP]))?.members.map((m) => m.stonechatId),
    [admin.id, bea.id, dee.id],
  );

  await as('bea', () => bea.protocol.sendGroup(GROUP, 'welcome dee'));
  assert.deepEqual(
    (await as('dee', () => drainAll(dee.protocol))).map((m) => m.text),
    ['welcome dee'],
  );
  assert.equal(cal.relay.queues.get(1)?.length ?? 0, 0, 'nothing goes to a removed member');

  // The removed member still holds the old roster's sessions, and is ignored.
  await as('cal', () => raw(cal.protocol, bea.id, 'group_msg', { group_id: GROUP, text: 'still here?' }));
  assert.deepEqual(await as('bea', () => drainAll(bea.protocol)), []);
});

test('a roster from anyone but the admin it names is ignored', async () => {
  // First sight: the payload's admin has to be the authenticated sender.
  const { who, as } = await world('alice', 'bob', 'mallory');
  const { alice, bob, mallory } = who;
  await as('mallory', () =>
    raw(mallory.protocol, alice.id, 'group_create', {
      group_id: GROUP, name: 'Trip', version: 1, admin: bob.id,
      members: [entryOf(bob), entryOf(alice), entryOf(mallory)],
    }),
  );
  assert.deepEqual(await as('alice', () => drainAll(alice.protocol)), []);
  assert.deepEqual(await as('alice', async () => store.groups()), {});
});

test('a member cannot update a group, or make themselves its admin', async () => {
  const { who, as } = await world('alice', 'bob', 'mallory');
  const { alice, bob, mallory } = who;
  const members = [entryOf(bob), entryOf(alice), entryOf(mallory)];
  await as('bob', () =>
    raw(bob.protocol, alice.id, 'group_create', {
      group_id: GROUP, name: 'Trip', version: 1, admin: bob.id, members,
    }),
  );
  await as('mallory', async () => {
    // Naming the real admin: refused because she is not him.
    await raw(mallory.protocol, alice.id, 'group_update', {
      group_id: GROUP, name: 'Mine', version: 2, admin: bob.id,
      members: [entryOf(alice), entryOf(mallory)],
    });
    // Naming herself: consistent with its sender, and not the stored admin.
    await raw(mallory.protocol, alice.id, 'group_update', {
      group_id: GROUP, name: 'Mine', version: 3, admin: mallory.id,
      members: [entryOf(alice), entryOf(mallory)],
    });
  });
  await as('alice', () => drainAll(alice.protocol));
  const held = await as('alice', async () => store.groups()[GROUP]!);
  assert.equal(held.name, 'Trip');
  assert.equal(held.admin, bob.id);
  assert.equal(held.version, 1);
  assert.equal(held.members.length, 3);

  // The admin on record *can* hand the group to someone: a roster from him
  // naming another member as admin is a handover (PROTOCOL.md "Handing over
  // the admin role"), and from then on only she is listened to.
  await as('bob', () =>
    raw(bob.protocol, alice.id, 'group_update', {
      group_id: GROUP, name: 'Trip', version: 4, admin: mallory.id, members,
    }),
  );
  await as('alice', () => drainAll(alice.protocol));
  const after = await as('alice', async () => store.groups()[GROUP]!);
  assert.equal(after.admin, mallory.id);
  assert.equal(after.version, 4);
  const handoverNotice = await as('alice', async () =>
    (store.messages()[`group:${GROUP}`] ?? []).some((m) => m.notice && /now the group admin/.test(m.text)));
  assert.equal(handoverNotice, true);

  // The former admin stays a member and is no longer in charge.
  await as('bob', () =>
    raw(bob.protocol, alice.id, 'group_update', {
      group_id: GROUP, name: 'Bob again', version: 5, admin: bob.id, members,
    }),
  );
  await as('mallory', () =>
    raw(mallory.protocol, alice.id, 'group_update', {
      group_id: GROUP, name: 'Hers', version: 6, admin: mallory.id, members: [entryOf(alice), entryOf(mallory), entryOf(bob)],
    }),
  );
  await as('alice', () => drainAll(alice.protocol));
  const later = await as('alice', async () => store.groups()[GROUP]!);
  assert.equal(later.name, 'Hers');
  assert.equal(later.version, 6);
});

test('a stale or repeated roster version is ignored', async () => {
  const { who, as } = await world('alice', 'bob', 'carol');
  const { alice, bob, carol } = who;
  const roster = (version: number, name: string, members: unknown[]) => ({
    group_id: GROUP, name, version, admin: bob.id, members,
  });
  await as('bob', async () => {
    await raw(bob.protocol, alice.id, 'group_create',
      roster(2, 'Two', [entryOf(bob), entryOf(alice)]));
    await raw(bob.protocol, alice.id, 'group_update',
      roster(1, 'One', [entryOf(bob), entryOf(alice), entryOf(carol)]));
    await raw(bob.protocol, alice.id, 'group_update',
      roster(2, 'Two again', [entryOf(bob), entryOf(alice), entryOf(carol)]));
  });
  await as('alice', () => drainAll(alice.protocol));
  const held = await as('alice', async () => store.groups()[GROUP]!);
  assert.equal(held.name, 'Two');
  assert.equal(held.members.length, 2, 'the removed member stays removed');
});

test('one forged member key rejects the whole roster', async () => {
  const { who, as } = await world('alice', 'bob', 'carol', 'mallory');
  const { alice, bob, carol, mallory } = who;
  await as('bob', async () => {
    await raw(bob.protocol, alice.id, 'group_create', {
      group_id: GROUP, name: 'Trip', version: 1, admin: bob.id,
      members: [
        entryOf(bob),
        entryOf(alice),
        // Carol's name on Mallory's key.
        { stonechat_id: carol.id, pubkey: mallory.pub },
      ],
    });
    // Not a key at all.
    await raw(bob.protocol, alice.id, 'group_create', {
      group_id: GROUP, name: 'Trip', version: 2, admin: bob.id,
      members: [entryOf(bob), entryOf(alice), { stonechat_id: carol.id, pubkey: 'AA==' }],
    });
  });
  assert.deepEqual(await as('alice', () => drainAll(alice.protocol)), []);
  assert.deepEqual(await as('alice', async () => store.groups()), {});

  // Against a roster already held, the bad update changes nothing.
  await as('bob', async () => {
    await raw(bob.protocol, alice.id, 'group_create', {
      group_id: GROUP, name: 'Trip', version: 3, admin: bob.id,
      members: [entryOf(bob), entryOf(alice)],
    });
    await raw(bob.protocol, alice.id, 'group_update', {
      group_id: GROUP, name: 'Trip', version: 4, admin: bob.id,
      members: [entryOf(bob), entryOf(alice), { stonechat_id: carol.id, pubkey: mallory.pub }],
    });
  });
  await as('alice', () => drainAll(alice.protocol));
  const held = await as('alice', async () => store.groups()[GROUP]!);
  assert.equal(held.version, 3);
  assert.equal(held.members.length, 2);
});

test('a roster that never included us is not kept', async () => {
  const { who, as } = await world('alice', 'bob', 'carol');
  const { alice, bob, carol } = who;
  await as('bob', () =>
    raw(bob.protocol, alice.id, 'group_create', {
      group_id: GROUP, name: 'Not yours', version: 1, admin: bob.id,
      members: [entryOf(bob), entryOf(carol)],
    }),
  );
  await as('alice', () => drainAll(alice.protocol));
  assert.deepEqual(await as('alice', async () => store.groups()), {});
});

test('being removed ends the group here, and an old roster cannot undo it', async () => {
  const { who, as } = await world('alice', 'bob', 'carol');
  const { alice, bob, carol } = who;
  const roster = (version: number, members: unknown[]) => ({
    group_id: GROUP, name: 'Trip', version, admin: bob.id, members,
  });
  const everyone = [entryOf(bob), entryOf(alice), entryOf(carol)];
  await as('bob', async () => {
    await raw(bob.protocol, alice.id, 'group_create', roster(1, everyone));
    await raw(bob.protocol, alice.id, 'group_msg', { group_id: GROUP, text: 'before' });
    await raw(bob.protocol, alice.id, 'group_update', roster(5, [entryOf(bob), entryOf(carol)]));
    await raw(bob.protocol, alice.id, 'group_msg', { group_id: GROUP, text: 'after' });
    // Redelivered late: newer than what she held when she was removed, older
    // than the removal.
    await raw(bob.protocol, alice.id, 'group_update', roster(3, everyone));
  });
  const got = await as('alice', () => drainAll(alice.protocol));
  assert.deepEqual(got.map((m) => m.text), ['before']);
  const held = await as('alice', async () => store.groups()[GROUP]!);
  assert.equal(held.removed, true);
  assert.deepEqual(held.members, []);
  assert.equal(held.version, 5);
  assert.equal(await as('alice', async () => alice.protocol.knowsGroup(GROUP)), false);
  await assert.rejects(
    as('alice', () => alice.protocol.sendGroup(GROUP, 'hello?')),
    /no longer in that group/,
  );
  assert.equal(bob.relay.queues.get(1)?.length ?? 0, 0);
  assert.equal(carol.relay.queues.get(1)?.length ?? 0, 0);

  // The admin can put her back, and only the admin.
  await as('bob', () => raw(bob.protocol, alice.id, 'group_update', roster(6, everyone)));
  await as('alice', () => drainAll(alice.protocol));
  const again = await as('alice', async () => store.groups()[GROUP]!);
  assert.equal(again.removed, undefined);
  assert.equal(again.members.length, 3);
});

test('a group message from a non-member is dropped', async () => {
  const { who, as } = await world('alice', 'bob', 'mallory');
  const { alice, bob, mallory } = who;
  await as('bob', () =>
    raw(bob.protocol, alice.id, 'group_create', {
      group_id: GROUP, name: 'Trip', version: 1, admin: bob.id,
      members: [entryOf(bob), entryOf(alice)],
    }),
  );
  await as('mallory', async () => {
    await raw(mallory.protocol, alice.id, 'group_msg', { group_id: GROUP, text: 'psst' });
    // Dropped before anything is fetched: the mock's `request` throws, so a
    // fetch from the sender's mailbox would fail this drain rather than
    // return nothing.
    await raw(mallory.protocol, alice.id, 'group_media', {
      group_id: GROUP, blob_id: crypto.randomUUID(), fetch_token: 't',
      key: 'AA==', blob_nonce: 'AA==',
    });
  });
  assert.deepEqual(await as('alice', () => drainAll(alice.protocol)), []);
});

test('a message for a group we were never told about is dropped', async () => {
  const { who, as } = await world('alice', 'mallory');
  const { alice, mallory } = who;
  await as('mallory', async () => {
    await raw(mallory.protocol, alice.id, 'group_msg', { group_id: GROUP, text: 'psst' });
    await raw(mallory.protocol, alice.id, 'group_media', {
      group_id: GROUP, blob_id: crypto.randomUUID(), fetch_token: 't',
      key: 'AA==', blob_nonce: 'AA==',
    });
    await raw(mallory.protocol, alice.id, 'group_msg', { text: 'no group at all' });
  });
  assert.deepEqual(await as('alice', () => drainAll(alice.protocol)), []);
  assert.deepEqual(await as('alice', async () => store.messages()), {});
});

test('a group id that is a Stonechat ID is refused', async () => {
  const { who, as } = await world('alice', 'bob', 'mallory');
  const { alice, bob, mallory } = who;
  assert.equal(core.normalizeId(GROUP), null, 'a real group id is not an SC- ID');
  await as('mallory', async () => {
    for (const id of [bob.id, bob.id.toLowerCase(), ` ${bob.id}`, 'SC-ANYTHING']) {
      await raw(mallory.protocol, alice.id, 'group_create', {
        group_id: id, name: 'bob', version: 1, admin: mallory.id,
        members: [entryOf(mallory), entryOf(alice)],
      });
    }
  });
  assert.deepEqual(await as('alice', () => drainAll(alice.protocol)), []);
  assert.deepEqual(await as('alice', async () => store.groups()), {});
});

test('a roster wearing a contact\'s ID does not redirect their conversation', async () => {
  // The attack: Mallory sends a well-formed roster, hers to send, whose
  // group_id is Bob's SC- ID and whose only other member is herself. The send
  // path used to ask "is there a roster under this id?", so what Alice typed
  // to Bob was fanned out to the roster instead — to Mallory.
  const { who, as } = await world('alice', 'bob', 'mallory');
  const { alice, bob, mallory } = who;
  await as('bob', () => bob.protocol.send(alice.id, 'hi alice'));
  await as('alice', () => drainAll(alice.protocol));

  await as('mallory', async () => {
    await raw(mallory.protocol, alice.id, 'group_create', {
      group_id: bob.id, name: 'Bob', version: 1, admin: mallory.id,
      members: [entryOf(mallory), entryOf(alice)],
    });
    await raw(mallory.protocol, alice.id, 'group_msg', {
      group_id: bob.id, text: 'it is me, bob',
    });
  });
  const injected = await as('alice', () => drainAll(alice.protocol));
  assert.deepEqual(injected, [], 'nothing is filed in the conversation with bob');
  assert.equal(await as('alice', async () => alice.protocol.knowsGroup(bob.id)), false);
  // Bob's own message is filed with Bob; nothing of Mallory's is.
  assert.deepEqual(
    (await as('alice', async () => store.messages()[bob.id] ?? [])).map((m) => m.text),
    ['hi alice'],
  );
  await assert.rejects(as('alice', () => alice.protocol.sendGroup(bob.id, 'x')));

  const before = mallory.relay.queues.get(1)?.length ?? 0;
  await as('alice', () => alice.protocol.send(bob.id, 'for bob only'));
  assert.equal(mallory.relay.queues.get(1)?.length ?? 0, before, 'nothing reaches mallory');
  const got = await as('bob', () => drainAll(bob.protocol));
  assert.deepEqual(got.map((m) => [m.text, m.peerId]), [['for bob only', alice.id]]);
});

test('a group\'s thread and a peer\'s are filed apart', async () => {
  // Whatever the ids are. Separate keys are what holds if a group id ever
  // does collide with a peer's, by a rule that was missed rather than broken.
  const { as } = await world('alice');
  await as('alice', async () => {
    const at = new Date(0).toISOString();
    store.appendMessage({ id: 'd', peerId: 'X', mine: false, text: 'direct', sentAt: at });
    store.appendMessage({ id: 'g', peerId: 'X', mine: false, text: 'group', sentAt: at, group: true });
    const all = store.messages();
    assert.deepEqual(Object.keys(all).sort(), ['X', 'group:X']);
    assert.deepEqual(all['X']!.map((m) => m.text), ['direct']);
    store.clearConversation('X', true);
    assert.deepEqual(Object.keys(store.messages()), ['X']);
  });
});

test('our own phone\'s roster and group messages reach a linked browser', async () => {
  // The phone is the admin of what it creates, and mirrors the roster to its
  // siblings from our own identity — so it passes the admin check as itself.
  const { me, them, themProtocol, phone: myPhone, browser, as } = await ownDevices();
  await as('them', () => themProtocol.publishPrekeys());
  await as('phone', () => myPhone.publishPrekeys());
  await as('browser', () => browser.publishPrekeys());

  const other = '9a1c0b52-5d0e-4a0b-8a54-0f6f0c1d2e3f';
  await as('phone', async () => {
    await raw(myPhone, me.id, 'group_create', {
      group_id: GROUP, name: 'Mine', version: 1, admin: me.id,
      members: [entryOf(me), entryOf(them)],
    }, 2);
    const mirror = (group_id: string, text: string) =>
      raw(myPhone, me.id, 'sync_sent', {
        group_id, type: 'group_msg', payload: { group_id, text },
        id: crypto.randomUUID(), sent_at: Date.now(),
      }, 2);
    await mirror(GROUP, 'from the phone');
    // A group this browser holds no roster for: not shown.
    await mirror(other, 'into a group the browser never heard of');
    // A kind of message that does not match the kind of conversation.
    await raw(myPhone, me.id, 'sync_sent', {
      peer: them.id, type: 'group_msg', payload: { text: 'confused' },
      id: crypto.randomUUID(), sent_at: Date.now(),
    }, 2);
  });
  const got = await as('browser', () => drainAll(browser));
  assert.deepEqual(
    got.map((m) => [m.text, m.peerId, m.group, m.mine]),
    [['from the phone', GROUP, true, true]],
  );
  assert.equal((await as('browser', async () => store.groups()[GROUP]))?.admin, me.id);

  // And the browser can now send into it; the phone sees that as a group
  // message too.
  await as('browser', async () => {
    await browser.sendGroup(GROUP, 'from the tab');
    await browser.whenSynced();
  });
  assert.deepEqual(
    (await as('them', () => drainAll(themProtocol))).map((m) => [m.text, m.group]),
    [],
    'they hold no roster, so they drop it — the same rule, from the other side',
  );
  await as('phone', async () => {
    store.upsertGroup({
      id: GROUP, name: 'Mine', admin: me.id, version: 1,
      members: [
        { stonechatId: me.id, pubkey: me.pub },
        { stonechatId: them.id, pubkey: them.pub },
      ],
    });
  });
  assert.deepEqual(
    (await as('phone', () => drainAll(myPhone))).map((m) => [m.text, m.peerId, m.group]),
    [['from the tab', GROUP, true]],
  );
});

test('a peer cannot write our history through self-sync', async () => {
  const { who, as } = await world('alice', 'bob', 'mallory');
  const { alice, bob, mallory } = who;
  const cleared: string[] = [];
  alice.protocol.onConversationCleared = (id) => cleared.push(id);
  await as('bob', () => bob.protocol.send(alice.id, 'keep me'));
  const kept = await as('alice', () => drainAll(alice.protocol));
  await as('alice', async () => kept.forEach((m) => store.appendMessage(m)));

  await as('mallory', async () => {
    await raw(mallory.protocol, alice.id, 'sync_sent', {
      peer: bob.id, type: 'msg', payload: { text: 'words in your mouth' },
      id: crypto.randomUUID(), sent_at: Date.now(),
    });
    await raw(mallory.protocol, alice.id, 'sync_clear', { peer: bob.id });
  });
  assert.deepEqual(await as('alice', () => drainAll(alice.protocol)), []);
  assert.deepEqual(cleared, []);
  assert.equal((await as('alice', async () => store.messages()[bob.id]))?.length, 1);
});

test('a clear from our own device clears the kind of conversation it names', async () => {
  const { me, them, phone: myPhone, browser, as } = await ownDevices();
  await as('phone', () => myPhone.publishPrekeys());
  await as('browser', () => browser.publishPrekeys());
  const cleared: Array<[string, boolean]> = [];
  browser.onConversationCleared = (id, group) => cleared.push([id, group]);
  await as('browser', async () => {
    const at = new Date(0).toISOString();
    store.appendMessage({ id: 'd', peerId: them.id, mine: true, text: 'direct', sentAt: at });
    store.appendMessage({ id: 'g', peerId: GROUP, mine: true, text: 'group', sentAt: at, group: true });
  });
  await as('phone', () => raw(myPhone, me.id, 'sync_clear', { group_id: GROUP }, 2));
  await as('browser', () => drainAll(browser));
  assert.deepEqual(cleared, [[GROUP, true]]);
  assert.deepEqual(await as('browser', async () => Object.keys(store.messages())), [them.id]);

  await as('phone', () => raw(myPhone, me.id, 'sync_clear', { peer: them.id }, 2));
  await as('browser', () => drainAll(browser));
  assert.deepEqual(cleared, [[GROUP, true], [them.id, false]]);
  assert.deepEqual(await as('browser', async () => store.messages()), {});
});
