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
  offerCommitment,
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
  const offer = {
    sealPub: keys.sealPublic,
    sigPub: keys.sigPublic,
    lookup: randomBytes(32),
  };
  const back = parseOffer(encodeOffer(core, offer))!;
  assert.ok(equalBytes(back.lookup, offer.lookup));
  assert.equal(
    back.commitment,
    offerCommitment(core, offer.sealPub, offer.sigPub),
  );
});

test('the code is short enough to scan comfortably', () => {
  // The whole point of v2. v1 carried the 1216-byte X-Wing key and came out
  // at ~2360 characters — QR version 36, which phones would not read.
  const keys = DeviceKeys.generate(core);
  const encoded = encodeOffer(core, {
    sealPub: keys.sealPublic,
    sigPub: keys.sigPublic,
    lookup: randomBytes(32),
  });
  assert.ok(encoded.length < 160, `offer is ${encoded.length} chars`);
});

test('the commitment covers both keys and their order', () => {
  const a = DeviceKeys.generate(core);
  const b = DeviceKeys.generate(core);
  const base = offerCommitment(core, a.sealPublic, a.sigPublic);
  assert.equal(offerCommitment(core, a.sealPublic, a.sigPublic), base);
  assert.notEqual(offerCommitment(core, b.sealPublic, a.sigPublic), base);
  assert.notEqual(offerCommitment(core, a.sealPublic, b.sigPublic), base);
  assert.match(base, /^[0-9a-f]{64}$/);
});

test('the commitment matches the phone and the hub, byte for byte', () => {
  // Three implementations hash one concatenation: this, the hub's
  // `_offer_commitment`, and the app's `offerCommitment`. A drift surfaces as
  // "that code has expired", which points nowhere useful — so the bytes are
  // pinned rather than merely agreed upon.
  assert.equal(
    offerCommitment(core, new Uint8Array(1216).fill(3), new Uint8Array(32).fill(4)),
    '7500b764f3392ffb9de621f93f0474571ce2675cae4a6420317588f8da212ae4',
  );
});

test('the scanner refuses anything that is not one of ours', () => {
  for (const junk of [
    '',
    'https://example.com',
    'stonechat:SC-SOMEONE', // the *invite* scheme, not the link one
    LINK_SCHEME,
    `${LINK_SCHEME}not-base64!!`,
    // A v1 code: right scheme, wrong format. Must fail cleanly rather than
    // half-parse into a lookup that goes nowhere.
    LINK_SCHEME + Buffer.from('{"seal":"x"}').toString('base64url'),
  ]) {
    assert.equal(parseOffer(junk), null, junk);
  }
});

test('the scanner refuses a code of the wrong length or version', () => {
  const encode = (raw: number[]) =>
    LINK_SCHEME + Buffer.from(raw).toString('base64url');
  assert.notEqual(parseOffer(encode([2, ...new Array(64).fill(1)])), null);
  assert.equal(parseOffer(encode([2, ...new Array(63).fill(1)])), null);
  assert.equal(parseOffer(encode([2, ...new Array(65).fill(1)])), null);
  // Version 1 is the old format. Refusing it makes an old code fail loudly
  // rather than be misread as a lookup plus garbage.
  assert.equal(parseOffer(encode([1, ...new Array(64).fill(1)])), null);
});

test('whitespace from a scan or a paste is tolerated', () => {
  const keys = DeviceKeys.generate(core);
  const encoded = encodeOffer(core, {
    sealPub: keys.sealPublic,
    sigPub: keys.sigPublic,
    lookup: randomBytes(32),
  });
  assert.notEqual(parseOffer(`  ${encoded}\n`), null);
});

test('the parking key comes from the lookup, not the commitment', () => {
  // Both are in the QR and only one is secret. Deriving the parking key from
  // the commitment would let anyone who glimpses the screen compute it and
  // destroy the grant with the returns-and-deletes fetch.
  const keys = DeviceKeys.generate(core);
  const lookup = randomBytes(32);
  const commitment = offerCommitment(core, keys.sealPublic, keys.sigPublic);
  assert.equal(parkingKey(core, lookup), parkingKey(core, lookup));
  assert.notEqual(parkingKey(core, lookup), commitment);
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
