// Does stonechat-core actually work from JavaScript? This is the question the
// whole web client rests on: the protocol is Rust behind a C ABI, and a
// browser can only reach it through WebAssembly's linear memory.
//
// Not a unit test of the crypto — core/ owns that. This checks the *bridge*:
// allocate, write, call, read a core-allocated result, free.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const wasmPath = fileURLToPath(
  new URL('../../core/target/wasm32-unknown-unknown/release/stonechat_core.wasm', import.meta.url),
);
const { instance } = await WebAssembly.instantiate(readFileSync(wasmPath), {});
const ex = instance.exports;
const mem = () => new Uint8Array(ex.memory.buffer);

/** Copy bytes into core-owned memory. */
function put(bytes) {
  const ptr = ex.stonechat_alloc(bytes.length);
  if (ptr === 0) throw new Error('stonechat_alloc returned null');
  mem().set(bytes, ptr);
  return ptr;
}

/** Read a core-allocated (ptr,len) result and release it. */
function takeOut(outPtr, outLenPtr) {
  const view = new DataView(ex.memory.buffer);
  const ptr = view.getUint32(outPtr, true);
  const len = view.getUint32(outLenPtr, true);
  const copy = mem().slice(ptr, ptr + len);
  ex.stonechat_free(ptr, len);
  return copy;
}

let failures = 0;
function check(name, ok, detail = '') {
  console.log(`  ${ok ? 'ok  ' : 'FAIL'} ${name}${detail ? ': ' + detail : ''}`);
  if (!ok) failures++;
}

// 1. The bridge itself.
const scratch = ex.stonechat_alloc(64);
check('alloc returns a usable pointer', scratch !== 0);
ex.stonechat_free(scratch, 64);

// 2. A real protocol call with a known answer. The secret key is libsodium's
//    layout — seed || public — so it has to be a genuine pair, not 64 filler
//    bytes: the core reads the public half rather than re-deriving it, and
//    filler would yield a confident, meaningless ID. Ed25519 public key for
//    the all-0x07 seed, cross-checked against the native core.
const secret = new Uint8Array([
  ...new Uint8Array(32).fill(7),
  ...Uint8Array.from(Buffer.from('ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c', 'hex')),
]);
const skPtr = put(secret);
const outPtr = ex.stonechat_alloc(4);
const outLenPtr = ex.stonechat_alloc(4);
// (input, from_secret, out_ptr, out_len) — from_secret=1 means the 64-byte
// secret key rather than a 32-byte seed.
const rc = ex.stonechat_identity(skPtr, 1, outPtr, outLenPtr);
check('stonechat_identity returns 0', rc === 0, `rc=${rc}`);
const identity = JSON.parse(new TextDecoder().decode(takeOut(outPtr, outLenPtr)));
// Cross-check against the native core: same algorithm, different target.
// A WASM build that quietly disagreed would produce an identity no peer
// could resolve, which is the worst possible way to find out.
const EXPECTED = 'SC-HER2-J2IU-IIA7-7TB5-JLEJ-DUKK-CTPU-HDCS-P4IQ';
check('SC- id matches the native core', identity.stonechat_id === EXPECTED,
  identity.stonechat_id);
check('derives an X-Wing public key', typeof identity.pq_pk === 'string' && identity.pq_pk.length > 100);

// 3. Determinism — the same secret must give the same identity, since every
//    peer resolves this ID from the same key.
const skPtr2 = put(secret);
const o2 = ex.stonechat_alloc(4), l2 = ex.stonechat_alloc(4);
ex.stonechat_identity(skPtr2, 1, o2, l2);
const again = JSON.parse(new TextDecoder().decode(takeOut(o2, l2)));
check('identity is deterministic', again.stonechat_id === identity.stonechat_id);

// 4. The contract the binding layer must enforce, written down because it
//    surprised me: fixed-size inputs carry no length, so the core CANNOT
//    detect a short buffer — it reads whatever follows in linear memory and
//    returns a confident wrong answer. Native callers get this for free from
//    their FFI type signatures; JavaScript does not, so the binding is the
//    only place it can be checked.
const short = put(new Uint8Array(3));
const o3 = ex.stonechat_alloc(4), l3 = ex.stonechat_alloc(4);
const shortRc = ex.stonechat_identity(short, 1, o3, l3);
check(
  'a short fixed-size input is NOT caught by the core (bindings must check)',
  shortRc === 0,
  'reads past the buffer by design — see the FFI contract in core/src/ffi.rs',
);
if (shortRc === 0) {
  const v = new DataView(ex.memory.buffer);
  ex.stonechat_free(v.getUint32(o3, true), v.getUint32(l3, true));
}

// 5. Variable-length inputs DO carry a length, and those are validated.
const badJson = put(new TextEncoder().encode('{not json'));
const o4 = ex.stonechat_alloc(4), l4 = ex.stonechat_alloc(4);
const jsonRc = ex.stonechat_session_encrypt(
  badJson, 9, badJson, 9, badJson, 9, badJson, 24, o4, l4,
);
check('malformed JSON is refused with a nonzero code', jsonRc !== 0, `rc=${jsonRc}`);

console.log(failures === 0 ? '\nPASS' : `\nFAIL (${failures})`);
process.exit(failures === 0 ? 0 : 1);
