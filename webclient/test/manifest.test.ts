/**
 * Device manifests (PROTOCOL.md "Device manifest"): the identity's signed
 * list of the devices that speak for it. The signing bytes are the core's;
 * this checks the binding and the wire form around it.
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';

import { b64decode, b64encode } from '../src/bytes.js';
import { DeviceKeys } from '../src/device.js';
import { manifestLists, parseManifest, verifiedManifest } from '../src/manifest.js';
import { core, phone } from './fixtures.js';

test('a manifest the identity signed verifies, for that identity only', () => {
  const owner = phone(7);
  const d1 = DeviceKeys.generate(core);
  const d2 = DeviceKeys.generate(core);
  const json = owner.manifest(4, [[1, d1], [2, d2]]);
  const m = verifiedManifest(core, json, owner.id, b64decode(owner.pub));
  assert.ok(m);
  assert.equal(m.version, 4);
  assert.equal(manifestLists(m, 1, b64encode(d1.sigPublic)), true);
  assert.equal(manifestLists(m, 2, b64encode(d2.sigPublic)), true);
  // Listed, but with another key: a relay that moved a certificate between
  // slots, or kept one from before a re-key, is caught by the pair.
  assert.equal(manifestLists(m, 2, b64encode(d1.sigPublic)), false);
  assert.equal(manifestLists(m, 3, b64encode(d1.sigPublic)), false);
  assert.equal(manifestLists(m, 1, null), false);

  // Somebody else's key, or somebody else's name.
  const other = phone(9);
  assert.equal(verifiedManifest(core, json, owner.id, b64decode(other.pub)), null);
  assert.equal(verifiedManifest(core, json, other.id, b64decode(owner.pub)), null);
});

test('a manifest listed out of order verifies as signed', () => {
  // A phone that just linked device 3 lists it first; the signature is
  // over that order, and an object keyed by number must not re-sort it.
  const owner = phone(7);
  const d1 = DeviceKeys.generate(core);
  const d3 = DeviceKeys.generate(core);
  const json = owner.manifest(5, [[3, d3], [1, d1]]);
  assert.deepEqual(json.devices.map((d) => d.device_id), [3, 1]);
  const m = verifiedManifest(core, json, owner.id, b64decode(owner.pub));
  assert.ok(m, 'verifies in the order it was signed');
  assert.deepEqual(m.order, [3, 1]);
  assert.equal(manifestLists(m, 3, b64encode(d3.sigPublic)), true);
});

test('tampering with the list breaks the signature', () => {
  const owner = phone(7);
  const d1 = DeviceKeys.generate(core);
  const d2 = DeviceKeys.generate(core);
  const json = owner.manifest(4, [[1, d1], [2, d2]]) as { devices: unknown[]; version: number };
  const pub = b64decode(owner.pub);
  assert.ok(verifiedManifest(core, json, owner.id, pub));
  // Dropping a device (how an attacker would strand a client on one it
  // holds), adding one, or bumping the version.
  assert.equal(verifiedManifest(core, { ...json, devices: json.devices.slice(0, 1) }, owner.id, pub), null);
  assert.equal(
    verifiedManifest(core, { ...json, devices: [...json.devices, { device_id: 3, sig_pub: b64encode(d1.sigPublic) }] }, owner.id, pub),
    null,
  );
  assert.equal(verifiedManifest(core, { ...json, version: 5 }, owner.id, pub), null);
});

test('malformed manifests parse to nothing', () => {
  const owner = phone(7);
  const good = owner.manifest(1, [[1, DeviceKeys.generate(core)]]);
  assert.ok(parseManifest(good));
  for (const bad of [
    null, 'x', [], {},
    { ...good, version: '1' },
    { ...good, devices: 'none' },
    { ...good, devices: [{ device_id: '1', sig_pub: 'x' }] },
    { ...good, sig: 7 },
  ]) {
    assert.equal(parseManifest(bad), null);
  }
  // Parses, but the signature is not 64 bytes.
  assert.equal(verifiedManifest(core, { ...good, sig: 'AA==' }, owner.id, b64decode(owner.pub)), null);
});

test('the core refuses an empty list and a slot listed twice', () => {
  const owner = phone(7);
  const d1 = DeviceKeys.generate(core);
  const pub = b64decode(owner.pub);
  assert.equal(verifiedManifest(core, owner.manifest(1, []), owner.id, pub), null);
  assert.equal(verifiedManifest(core, owner.manifest(1, [[1, d1], [1, d1]]), owner.id, pub), null);
});
