/**
 * Getting linked, from the browser's side.
 *
 * The QR is the trust anchor of the whole flow — the user carries it between
 * two screens — and the three checks on the grant are what stand between "a
 * phone authorised this browser" and "something authorised this browser".
 * Both are pinned here.
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { StonechatCore, type SignedCert } from '../src/core.js';
import { DeviceKeys, randomBytes } from '../src/device.js';
import {
  encodeOffer,
  LINK_SCHEME,
  LinkRefused,
  openGrant,
  parkingKey,
  parseOffer,
  type LinkGrant,
} from '../src/linking.js';
import { b64decode, b64encode, equalBytes, utf8 } from '../src/bytes.js';

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

/** Stand in for the phone: an identity that can sign certificates. */
function primary(seedFill = 7) {
  const identity = core.identity(new Uint8Array(32).fill(seedFill), false);
  return {
    identity,
    pub: b64decode(identity.public),
    seed: new Uint8Array(32).fill(seedFill),
    certify(
      keys: DeviceKeys,
      deviceId: number,
      { stonechatId = identity.stonechat_id, lifetimeSeconds = 604_800 } = {},
    ): SignedCert {
      return core.devcertSign(
        {
          stonechat_id: stonechatId,
          device_id: deviceId,
          sig_pub: b64encode(keys.sigPublic),
          seal_pub: b64encode(keys.sealPublic),
          not_after: Math.floor(Date.now() / 1000) + lifetimeSeconds,
        },
        this.seed,
      );
    },
  };
}

/** Seal a grant to a device exactly as the phone does. */
function park(keys: DeviceKeys, grant: LinkGrant): string {
  return b64encode(
    core.seal(
      keys.sealPublic,
      utf8.encode(JSON.stringify(grant)),
      randomBytes(64),
      randomBytes(24),
    ),
  );
}

function grantFor(
  phone: ReturnType<typeof primary>,
  cert: SignedCert,
  deviceId = 2,
  overrides: Partial<LinkGrant> = {},
): LinkGrant {
  return {
    identity_pub: phone.identity.public,
    cert,
    stonechat_id: phone.identity.stonechat_id,
    display_name: 'Alice',
    hub_url: 'https://hub.example',
    relay_address: 'https://1.2.3.4:8080',
    relay_tls_fp: 'ZnA=',
    device_id: deviceId,
    device_token: 'tok'.padEnd(32, 'x'),
    bundle_token: 'bt',
    ...overrides,
  };
}

// -- the offer -------------------------------------------------------------

test('the offer round-trips through the QR text', () => {
  const keys = DeviceKeys.generate(core);
  const offer = { sealPub: keys.sealPublic, sigPub: keys.sigPublic, lookup: randomBytes(32) };
  const back = parseOffer(encodeOffer(offer))!;
  assert.ok(equalBytes(back.sealPub, offer.sealPub));
  assert.ok(equalBytes(back.sigPub, offer.sigPub));
  assert.ok(equalBytes(back.lookup, offer.lookup));
});

test('the offer fits in a QR code', () => {
  // Byte mode tops out at 2953 bytes. This is why the offer names the
  // device's real seal key instead of a separate ephemeral one: a second
  // X-Wing public key would not fit.
  const keys = DeviceKeys.generate(core);
  const encoded = encodeOffer({
    sealPub: keys.sealPublic,
    sigPub: keys.sigPublic,
    lookup: randomBytes(32),
  });
  assert.ok(encoded.length < 2953, `offer is ${encoded.length} chars`);
});

test('the scanner refuses anything that is not one of ours', () => {
  for (const junk of [
    '',
    'https://example.com',
    'stonechat:SC-SOMEONE', // the *invite* scheme, not the link one
    LINK_SCHEME,
    `${LINK_SCHEME}not-base64!!`,
    LINK_SCHEME + Buffer.from('{"seal":"x"}').toString('base64url'),
  ]) {
    assert.equal(parseOffer(junk), null, junk);
  }
});

test('the scanner refuses a key of the wrong size', () => {
  const encode = (seal: number, sig: number, lookup: number) =>
    encodeOffer({
      sealPub: new Uint8Array(seal),
      sigPub: new Uint8Array(sig),
      lookup: new Uint8Array(lookup),
    });
  assert.equal(parseOffer(encode(1215, 32, 32)), null);
  assert.equal(parseOffer(encode(1216, 31, 32)), null);
  assert.equal(parseOffer(encode(1216, 32, 31)), null);
  assert.notEqual(parseOffer(encode(1216, 32, 32)), null);
});

test('whitespace from a scan or a paste is tolerated', () => {
  const keys = DeviceKeys.generate(core);
  const encoded = encodeOffer({
    sealPub: keys.sealPublic,
    sigPub: keys.sigPublic,
    lookup: randomBytes(32),
  });
  assert.notEqual(parseOffer(`  ${encoded}\n`), null);
});

test('the parking key comes from the lookup secret, not the visible key', () => {
  // Deriving it from `seal` — which is on screen — would let a passer-by
  // compute it and destroy the grant with the returns-and-deletes fetch.
  const keys = DeviceKeys.generate(core);
  const lookup = randomBytes(32);
  assert.equal(parkingKey(core, lookup), parkingKey(core, lookup));
  assert.notEqual(parkingKey(core, lookup), parkingKey(core, keys.sealPublic.slice(0, 32)));
  assert.match(parkingKey(core, lookup), /^[0-9a-f]{64}$/);
});

// -- the grant -------------------------------------------------------------

test('a well-formed grant is accepted', () => {
  const phone = primary();
  const keys = DeviceKeys.generate(core);
  const grant = grantFor(phone, phone.certify(keys, 2));
  const opened = openGrant(core, keys, park(keys, grant));
  assert.equal(opened.stonechat_id, phone.identity.stonechat_id);
  assert.equal(opened.device_id, 2);
});

test('a grant sealed to another device cannot be opened', () => {
  const phone = primary();
  const ours = DeviceKeys.generate(core);
  const theirs = DeviceKeys.generate(core);
  const grant = grantFor(phone, phone.certify(theirs, 2));
  assert.throws(
    () => openGrant(core, ours, park(theirs, grant)),
    (e: Error) => e instanceof LinkRefused && /not sealed to this/.test(e.message),
  );
});

test('check 1: the identity key must commit to the claimed SC- ID', () => {
  // Otherwise a substituted grant installs a different identity under the
  // name the user is looking at.
  const phone = primary();
  const impostor = primary(9);
  const keys = DeviceKeys.generate(core);
  const grant = grantFor(phone, phone.certify(keys, 2), 2, {
    identity_pub: impostor.identity.public,
  });
  assert.throws(
    () => openGrant(core, keys, park(keys, grant)),
    /different identity/,
  );
});

test('check 2: the certificate must be signed by that identity', () => {
  const phone = primary();
  const mallory = primary(9);
  const keys = DeviceKeys.generate(core);
  // Mallory certifies our keys, under Alice's SC- ID, and claims to be her.
  const forged = mallory.certify(keys, 2, {
    stonechatId: phone.identity.stonechat_id,
  });
  assert.throws(
    () => openGrant(core, keys, park(keys, grantFor(phone, forged))),
    /certificate we cannot use \(bad_signature\)/,
  );
});

test('check 2: an expired certificate is refused', () => {
  const phone = primary();
  const keys = DeviceKeys.generate(core);
  const stale = phone.certify(keys, 2, { lifetimeSeconds: -60 });
  assert.throws(
    () => openGrant(core, keys, park(keys, grantFor(phone, stale))),
    /certificate we cannot use \(expired\)/,
  );
});

test('check 2: the certificate must name the device id we were given', () => {
  const phone = primary();
  const keys = DeviceKeys.generate(core);
  const cert = phone.certify(keys, 3); // signed, valid — for device 3
  assert.throws(
    () => openGrant(core, keys, park(keys, grantFor(phone, cert, 2))),
    /certificate we cannot use/,
  );
});

test('check 3: the certificate must vouch for OUR keys', () => {
  // The interesting one. Without it we would store a perfectly valid
  // certificate for someone else's device, publish it with our prekeys, and
  // then be unable to open a single envelope addressed to us — with no error
  // anywhere.
  const phone = primary();
  const ours = DeviceKeys.generate(core);
  const someoneElse = DeviceKeys.generate(core);
  const cert = phone.certify(someoneElse, 2); // signed, valid, right device
  assert.throws(
    () => openGrant(core, ours, park(ours, grantFor(phone, cert))),
    /different device/,
  );
});

test('a grant carries no identity secret', () => {
  // The invariant device certificates bought back: the identity secret never
  // leaves the device that generated it.
  const phone = primary();
  const keys = DeviceKeys.generate(core);
  const json = JSON.stringify(grantFor(phone, phone.certify(keys, 2)));
  for (const word of ['seed', 'secret', 'private', 'account']) {
    assert.ok(!json.includes(word), `grant mentions "${word}"`);
  }
});

test('device keys persist as seeds only, and round-trip', () => {
  const keys = DeviceKeys.generate(core);
  const stored = JSON.parse(keys.encode()) as Record<string, string>;
  assert.deepEqual(Object.keys(stored).sort(), ['seal', 'sig']);
  const back = DeviceKeys.decode(core, keys.encode());
  assert.ok(equalBytes(back.sigPublic, keys.sigPublic));
  assert.ok(equalBytes(back.sealPublic, keys.sealPublic));
});
