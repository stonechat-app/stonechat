// Device certificates through the WASM boundary (core/src/devcert.rs).
//
// The web client's entire security argument rests on this: its keys are its
// own, and a certificate signed by the identity root — which stays on the
// phone — is what tells a sender those keys are really its owner's.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const wasm = fileURLToPath(
  new URL('../../core/target/wasm32-unknown-unknown/release/stonechat_core.wasm', import.meta.url),
);
const { instance } = await WebAssembly.instantiate(readFileSync(wasm), {});
const ex = instance.exports;
const bytes = () => new Uint8Array(ex.memory.buffer);
const view = () => new DataView(ex.memory.buffer);

const put = (b) => { const p = ex.stonechat_alloc(b.length); bytes().set(b, p); return p; };
const putStr = (s) => put(new TextEncoder().encode(s));
function take(outPtr, outLenPtr) {
  const p = view().getUint32(outPtr, true), n = view().getUint32(outLenPtr, true);
  const copy = bytes().slice(p, p + n);
  ex.stonechat_free(p, n);
  return JSON.parse(new TextDecoder().decode(copy));
}

let failures = 0;
const check = (name, ok, detail = '') => {
  console.log(`  ${ok ? 'ok  ' : 'FAIL'} ${name}${detail ? ': ' + detail : ''}`);
  if (!ok) failures++;
};

// An identity root, and a device that is NOT it.
const rootSeed = new Uint8Array(32).fill(11);
const o = () => ex.stonechat_alloc(4);
let a = o(), b = o();
ex.stonechat_identity(put(rootSeed), 0, a, b);
const root = take(a, b);

const unsigned = {
  stonechat_id: root.stonechat_id,
  device_id: 3,
  sig_pub: Buffer.from(new Uint8Array(32).fill(5)).toString('base64'),
  seal_pub: Buffer.from(new Uint8Array(1216).fill(6)).toString('base64'),
  not_after: 2000,
};

a = o(); b = o();
const signRc = ex.stonechat_devcert_sign(
  putStr(JSON.stringify(unsigned)), JSON.stringify(unsigned).length,
  put(rootSeed), a, b,
);
check('sign returns 0', signRc === 0, `rc=${signRc}`);
const signed = take(a, b);
check('the certificate gains a signature', typeof signed.sig === 'string');

function verify(cert, identityPubB64, now) {
  const json = JSON.stringify(cert);
  const x = o(), y = o();
  const rc = ex.stonechat_devcert_verify(
    putStr(json), json.length,
    put(Uint8Array.from(Buffer.from(identityPubB64, 'base64'))), BigInt(now), x, y,
  );
  return { rc, body: take(x, y) };
}

let r = verify(signed, root.public, 1999);
check('valid before expiry', r.rc === 0 && r.body.status === 'valid', r.body.status);

r = verify(signed, root.public, 2000);
check('expired at not_after', r.rc !== 0 && r.body.status === 'expired', r.body.status);

// Someone else's root must not be able to vouch for this device.
a = o(); b = o();
ex.stonechat_identity(put(new Uint8Array(32).fill(12)), 0, a, b);
const stranger = take(a, b);
r = verify(signed, stranger.public, 1);
check('another identity cannot vouch', r.body.status === 'bad_signature', r.body.status);

// Editing the device id must invalidate it — a cert is not transferable.
r = verify({ ...signed, device_id: 4 }, root.public, 1);
check('not replayable onto another device id', r.body.status === 'bad_signature', r.body.status);

// The seal key is the field that would redirect every envelope.
r = verify(
  { ...signed, seal_pub: Buffer.from(new Uint8Array(1216).fill(7)).toString('base64') },
  root.public, 1,
);
check('a swapped seal key is rejected', r.body.status === 'bad_signature', r.body.status);

console.log(failures === 0 ? '\nPASS' : `\nFAIL (${failures})`);
process.exit(failures ? 1 : 0);
