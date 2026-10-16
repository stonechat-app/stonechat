/**
 * stonechat-core, from JavaScript.
 *
 * This is the web counterpart of `app/lib/core/core_ffi.dart`. It exists as a
 * separate implementation for a reason that is worth being clear about: Dart's
 * `dart:ffi` does not exist on the web, so *no* framework choice lets the app's
 * binding be reused here. Two bindings to one core is the floor, not a cost of
 * having picked TypeScript.
 *
 * ## The contract this layer owes the core
 *
 * Fixed-size inputs — a 64-byte secret key, a 32-byte seed, a 1216-byte X-Wing
 * public key — are passed as a bare pointer and **carry no length**. The core
 * cannot detect a short buffer: it reads whatever follows in linear memory and
 * returns a confident, wrong answer. Native callers get this check for free
 * from their FFI type signatures; JavaScript does not.
 *
 * So every fixed-size argument goes through {@link fixed}, which throws. This
 * is the single most important thing in this file. A missing check here is not
 * a crash — it is a valid-looking identity nobody can resolve, or an envelope
 * sealed to nothing.
 *
 * Variable-length inputs do carry a length and are validated by the core
 * itself (`rc = ERR_INPUT`).
 *
 * ## Memory
 *
 * WASM linear memory can grow, which detaches every existing `ArrayBuffer`
 * view. Never hold a view across a call into the core — take a fresh one each
 * time, which is what {@link bytes} and {@link view} are for.
 */

/** Return codes, mirroring core/src/ffi.rs. */
export const OK = 0;
export const ERR_INPUT = -1;
export const ERR_PANIC = -2;
export const ERR_REFUSED = -3;

/** Key and ciphertext sizes, mirroring app/lib/core/pqcore.dart. */
export const MLKEM_SEED = 64;
export const MLKEM_PUBLIC = 1184;
export const MLKEM_CIPHERTEXT = 1088;
export const MLKEM_ENCAPS_RANDOM = 32;
export const XWING_SEED = 32;
export const XWING_PUBLIC = 1216;
export const XWING_CIPHERTEXT = 1120;
export const XWING_ENCAPS_RANDOM = 64;
export const KEM_SHARED_SECRET = 32;
export const ED_SEED = 32;
export const ED_PUBLIC = 32;
export const ED_SECRET = 64;
export const ED_SIGNATURE = 64;
export const SHA256 = 32;

/** The ABI this binding was written against. */
export const EXPECTED_ABI = 3;

interface CoreExports {
  memory: WebAssembly.Memory;
  stonechat_alloc(len: number): number;
  stonechat_free(ptr: number, len: number): void;
  stonechat_core_abi_version(): number;
  [name: string]: unknown;
}

/** What a WASM32 export accepts: i32/u32 as number, i64/u64 as bigint. */
type Arg = number | bigint;

export class CoreError extends Error {
  constructor(
    readonly fn: string,
    readonly rc: number,
  ) {
    super(`stonechat-core ${fn} failed (${rc})`);
    this.name = 'CoreError';
  }
}

/**
 * Check a fixed-size buffer, or throw.
 *
 * Named and exported because it is a security property, not a convenience:
 * see the note at the top of this file.
 */
export function fixed(
  value: Uint8Array,
  expected: number,
  what: string,
): Uint8Array {
  if (value.length !== expected) {
    throw new TypeError(
      `${what} must be exactly ${expected} bytes, got ${value.length} — ` +
        'the core cannot detect this and would read past the buffer',
    );
  }
  return value;
}

const enc = new TextEncoder();
const dec = new TextDecoder();

export class StonechatCore {
  private constructor(private readonly ex: CoreExports) {}

  /**
   * Instantiate from a fetched module.
   *
   * `WebAssembly.instantiateStreaming` with an `integrity`-checked Response is
   * the intended browser path: the hash of this module is part of the release
   * hash root (see build.mjs).
   */
  static async instantiate(
    source: BufferSource | Response | PromiseLike<Response>,
  ): Promise<StonechatCore> {
    const result =
      source instanceof ArrayBuffer || ArrayBuffer.isView(source)
        ? await WebAssembly.instantiate(source as BufferSource, {})
        : await WebAssembly.instantiateStreaming(source as Response, {});
    const core = new StonechatCore(
      result.instance.exports as unknown as CoreExports,
    );
    const abi = core.ex.stonechat_core_abi_version();
    if (abi !== EXPECTED_ABI) {
      // A core with a different ABI is not a core this binding can drive, and
      // the failure mode without this check is silent corruption rather than
      // an error.
      throw new Error(
        `stonechat-core ABI ${abi}, this binding speaks ${EXPECTED_ABI}`,
      );
    }
    return core;
  }

  // -- linear memory ------------------------------------------------------

  /** A fresh byte view. Never cache: growth detaches the old buffer. */
  private bytes(): Uint8Array {
    return new Uint8Array(this.ex.memory.buffer);
  }

  private view(): DataView {
    return new DataView(this.ex.memory.buffer);
  }

  private alloc(len: number): number {
    // Zero-length allocations are legal in Rust but give a dangling pointer;
    // one byte keeps every pointer we hand the core dereferenceable.
    const ptr = this.ex.stonechat_alloc(Math.max(len, 1));
    if (ptr === 0) throw new Error('stonechat_alloc returned null');
    return ptr;
  }

  /** Copy bytes into core-owned memory. */
  private put(data: Uint8Array): number {
    const ptr = this.alloc(data.length);
    this.bytes().set(data, ptr);
    return ptr;
  }

  /** Read a core-allocated `(ptr, len)` out-parameter pair and free it. */
  private take(outPtr: number, outLenPtr: number): Uint8Array {
    const v = this.view();
    const ptr = v.getUint32(outPtr, true);
    const len = v.getUint32(outLenPtr, true);
    if (ptr === 0) throw new Error('core returned a null out pointer');
    const copy = this.bytes().slice(ptr, ptr + len);
    this.ex.stonechat_free(ptr, len);
    return copy;
  }

  /** Args are `number` except where the Rust signature says `u64`/`i64`,
   * which WASM32 surfaces to JavaScript as `BigInt` — passing a plain number
   * there is a TypeError at the call boundary, not a silent coercion. */
  private fn(name: string): (...args: Arg[]) => number {
    const f = this.ex[name];
    if (typeof f !== 'function') {
      throw new Error(`stonechat-core does not export ${name}`);
    }
    return f as (...args: Arg[]) => number;
  }

  /**
   * Call a core function that returns bytes through `(out_ptr, out_len)`.
   *
   * `ERR_REFUSED` means two different things depending on the function, and
   * conflating them is a live trap:
   *
   * - `allowRefused` — the refusal *is* the answer and there is no output.
   *   An envelope that was not sealed to us, an ID that does not parse.
   *   Returns null.
   * - `refusalHasOutput` — the call refused *and still wrote a result*.
   *   `devcert_verify` is the one that does this: `expired` and
   *   `bad_signature` are refusals, but the label is what the caller wants.
   *   Discarding it yields a null where a status was expected, which fails
   *   somewhere else entirely.
   *
   * Everything allocated is freed on every path, including the throwing one —
   * a leak in a long-lived browser tab is a leak that grows all day.
   */
  private callOut(
    name: string,
    args: (alloc: (data: Uint8Array) => number) => Arg[],
    { allowRefused = false, refusalHasOutput = false } = {},
  ): Uint8Array | null {
    const owned: Array<[number, number]> = [];
    const alloc = (data: Uint8Array): number => {
      const ptr = this.put(data);
      owned.push([ptr, Math.max(data.length, 1)]);
      return ptr;
    };
    const outPtr = this.alloc(4);
    const outLenPtr = this.alloc(4);
    owned.push([outPtr, 4], [outLenPtr, 4]);
    try {
      const rc = this.fn(name)(...args(alloc), outPtr, outLenPtr);
      if (rc === ERR_REFUSED && refusalHasOutput) return this.take(outPtr, outLenPtr);
      if (rc === ERR_REFUSED && allowRefused) return null;
      if (rc !== OK) throw new CoreError(name, rc);
      return this.take(outPtr, outLenPtr);
    } finally {
      for (const [ptr, len] of owned) this.ex.stonechat_free(ptr, len);
    }
  }

  /** Call a core function that writes into a caller-sized out buffer. */
  private callInto(
    name: string,
    outLen: number,
    args: (alloc: (data: Uint8Array) => number) => Arg[],
    { allowRefused = false } = {},
  ): Uint8Array | null {
    const owned: Array<[number, number]> = [];
    const alloc = (data: Uint8Array): number => {
      const ptr = this.put(data);
      owned.push([ptr, Math.max(data.length, 1)]);
      return ptr;
    };
    const out = this.alloc(outLen);
    owned.push([out, outLen]);
    try {
      const rc = this.fn(name)(...args(alloc), out);
      if (rc === ERR_REFUSED && allowRefused) return null;
      if (rc !== OK) throw new CoreError(name, rc);
      return this.bytes().slice(out, out + outLen);
    } finally {
      for (const [ptr, len] of owned) this.ex.stonechat_free(ptr, len);
    }
  }

  private json<T>(out: Uint8Array): T {
    return JSON.parse(dec.decode(out)) as T;
  }

  // -- identity -----------------------------------------------------------

  /**
   * Derive an identity from a 32-byte seed or a 64-byte secret key.
   *
   * `fromSecret` is the argument that is easy to drop, and dropping it does
   * not fail — the call still returns `OK` while every subsequent byte is
   * read from the wrong offset.
   */
  identity(input: Uint8Array, fromSecret: boolean): Identity {
    fixed(input, fromSecret ? ED_SECRET : ED_SEED, 'identity input');
    const out = this.callOut('stonechat_identity', (a) => [
      a(input),
      fromSecret ? 1 : 0,
    ]);
    return this.json<Identity>(out!);
  }

  /** The SC- ID a public key commits to. */
  stonechatId(edPublic: Uint8Array): string {
    fixed(edPublic, ED_PUBLIC, 'ed public key');
    return dec.decode(
      this.callOut('stonechat_stonechat_id', (a) => [a(edPublic)])!,
    );
  }

  /** Canonicalise user input, or null if it is not an SC- ID at all. */
  normalizeId(raw: string): string | null {
    const text = enc.encode(raw);
    const out = this.callOut(
      'stonechat_normalize_id',
      (a) => [a(text), text.length],
      { allowRefused: true },
    );
    return out === null ? null : dec.decode(out);
  }

  // -- signatures ---------------------------------------------------------

  sign(
    edSecret: Uint8Array,
    context: Uint8Array,
    message: Uint8Array,
  ): Uint8Array {
    fixed(edSecret, ED_SECRET, 'ed secret key');
    return this.callInto('stonechat_sign', ED_SIGNATURE, (a) => [
      a(edSecret),
      a(context),
      context.length,
      a(message),
      message.length,
    ])!;
  }

  verify(
    edPublic: Uint8Array,
    context: Uint8Array,
    message: Uint8Array,
    sig: Uint8Array,
  ): boolean {
    fixed(edPublic, ED_PUBLIC, 'ed public key');
    fixed(sig, ED_SIGNATURE, 'signature');
    const owned: Array<[number, number]> = [];
    const put = (d: Uint8Array): number => {
      const p = this.put(d);
      owned.push([p, Math.max(d.length, 1)]);
      return p;
    };
    try {
      const rc = this.fn('stonechat_verify')(
        put(edPublic),
        put(context),
        context.length,
        put(message),
        message.length,
        put(sig),
      );
      if (rc === OK) return true;
      if (rc === ERR_REFUSED) return false;
      throw new CoreError('stonechat_verify', rc);
    } finally {
      for (const [ptr, len] of owned) this.ex.stonechat_free(ptr, len);
    }
  }

  // -- device certificates ------------------------------------------------

  /** Sign a certificate with the identity root. Primary only, by design. */
  devcertSign(
    unsigned: Record<string, unknown>,
    identitySeed: Uint8Array,
  ): SignedCert {
    fixed(identitySeed, ED_SEED, 'identity seed');
    const json = enc.encode(JSON.stringify(unsigned));
    const out = this.callOut('stonechat_devcert_sign', (a) => [
      a(json),
      json.length,
      a(identitySeed),
    ]);
    return this.json<SignedCert>(out!);
  }

  /**
   * Check a certificate against its owner's identity key.
   *
   * Returns `valid`, `expired`, `bad_signature` or `wrong_identity` — the
   * distinction matters: expiry is routine and heals when the owner renews, a
   * bad signature is someone claiming a device that is not theirs, and a
   * wrong identity is a key the certificate's SC- ID does not commit to. `now`
   * is passed in because the core takes no ambient anything.
   */
  devcertVerify(
    signed: SignedCert,
    identityPublic: Uint8Array,
    nowSeconds: number,
  ): CertStatus {
    fixed(identityPublic, ED_PUBLIC, 'identity public key');
    const json = enc.encode(JSON.stringify(signed));
    const out = this.callOut(
      'stonechat_devcert_verify',
      // `now` is a u64: BigInt, not number.
      (a) => [a(json), json.length, a(identityPublic), BigInt(nowSeconds)],
      // Expired and bad_signature come back as refusals *with* a status. The
      // whole value of this call is telling those two apart.
      { refusalHasOutput: true },
    );
    // The core answers `{"status": "..."}` rather than a bare string — same
    // shape core_ffi.dart unwraps.
    return this.json<{ status: CertStatus }>(out!).status;
  }

  // -- device manifests ---------------------------------------------------

  /** Sign a device manifest with the identity root — primary only, by
   * design. Here for the tests, which play the phone; this client has
   * nothing to call it with. Returns the base64 signature. */
  devicesSign(unsigned: Record<string, unknown>, identitySeed: Uint8Array): string {
    fixed(identitySeed, ED_SEED, 'identity seed');
    const json = enc.encode(JSON.stringify(unsigned));
    const out = this.callOut('stonechat_devices_sign', (a) => [
      a(json),
      json.length,
      a(identitySeed),
    ]);
    return dec.decode(out!);
  }

  /**
   * Is this the identity's genuine, well-formed device manifest?
   *
   * `unsigned` is the manifest without its `sig`. True only when the
   * signature verifies under `identityPublic`, that key is the one the
   * manifest's Stonechat ID commits to, it lists 1–64 devices and no slot
   * twice — the core refuses the rest (PROTOCOL.md "Device manifest").
   */
  devicesVerify(
    unsigned: Record<string, unknown>,
    identityPublic: Uint8Array,
    sig: Uint8Array,
  ): boolean {
    fixed(identityPublic, ED_PUBLIC, 'identity public key');
    fixed(sig, ED_SIGNATURE, 'signature');
    const json = enc.encode(JSON.stringify(unsigned));
    const owned: Array<[number, number]> = [];
    const put = (d: Uint8Array): number => {
      const p = this.put(d);
      owned.push([p, Math.max(d.length, 1)]);
      return p;
    };
    try {
      const rc = this.fn('stonechat_devices_verify')(
        put(json),
        json.length,
        put(identityPublic),
        put(sig),
      );
      if (rc === OK) return true;
      if (rc === ERR_REFUSED) return false;
      throw new CoreError('stonechat_devices_verify', rc);
    } finally {
      for (const [ptr, len] of owned) this.ex.stonechat_free(ptr, len);
    }
  }

  /**
   * Is this the certificate schedule its owner signed?
   *
   * A relay's `/wt/certs` states which short-lived WebTransport certificates
   * it will present; it cannot vouch for them, being the thing under
   * authentication. Pinning an unverified list is worse than not pinning at
   * all — it looks like security and is not.
   *
   * The bytes actually signed are canonical and length-prefixed
   * (core/src/wtcerts.rs), because four implementations build them and JSON is
   * not a canonical form.
   */
  wtcertsVerify(
    published: WtCertSchedule,
    identityPublic: Uint8Array,
    sig: Uint8Array,
  ): boolean {
    fixed(identityPublic, ED_PUBLIC, 'identity public key');
    fixed(sig, ED_SIGNATURE, 'signature');
    const json = enc.encode(JSON.stringify(published));
    const owned: Array<[number, number]> = [];
    const put = (d: Uint8Array): number => {
      const p = this.put(d);
      owned.push([p, Math.max(d.length, 1)]);
      return p;
    };
    try {
      const rc = this.fn('stonechat_wtcerts_verify')(
        put(json),
        json.length,
        put(identityPublic),
        put(sig),
      );
      if (rc === OK) return true;
      if (rc === ERR_REFUSED) return false;
      throw new CoreError('stonechat_wtcerts_verify', rc);
    } finally {
      for (const [ptr, len] of owned) this.ex.stonechat_free(ptr, len);
    }
  }

  // -- sealed envelopes ---------------------------------------------------

  seal(
    recipientPqPk: Uint8Array,
    message: Uint8Array,
    random: Uint8Array,
    nonce: Uint8Array,
  ): Uint8Array {
    fixed(recipientPqPk, XWING_PUBLIC, 'x-wing public key');
    fixed(random, XWING_ENCAPS_RANDOM, 'encapsulation randomness');
    fixed(nonce, 24, 'nonce');
    return this.callOut('stonechat_seal', (a) => [
      a(recipientPqPk),
      a(message),
      message.length,
      a(random),
      a(nonce),
    ])!;
  }

  // -- media blobs --------------------------------------------------------

  /**
   * Encrypt a media blob under a fresh symmetric key.
   *
   * The key and nonce travel inside the (already end-to-end encrypted)
   * envelope, never with the blob — so the mailbox holding the ciphertext
   * cannot read it, which is what lets the sender park it on the *recipient's*
   * box without trusting that box with anything.
   */
  blobSeal(key: Uint8Array, nonce: Uint8Array, data: Uint8Array): Uint8Array {
    fixed(key, 32, 'blob key');
    fixed(nonce, 24, 'blob nonce');
    return this.callOut('stonechat_blob_seal', (a) => [
      a(key),
      a(nonce),
      a(data),
      data.length,
    ])!;
  }

  /** Null on tamper or corruption — a blob that does not open is not shown. */
  blobOpen(
    key: Uint8Array,
    nonce: Uint8Array,
    data: Uint8Array,
  ): Uint8Array | null {
    fixed(key, 32, 'blob key');
    fixed(nonce, 24, 'blob nonce');
    return this.callOut(
      'stonechat_blob_open',
      (a) => [a(key), a(nonce), a(data), data.length],
      { allowRefused: true },
    );
  }

  /** Null when the envelope was not sealed to this device (or is garbage). */
  unseal(deviceSealSeed: Uint8Array, sealed: Uint8Array): Uint8Array | null {
    fixed(deviceSealSeed, XWING_SEED, 'x-wing seed');
    return this.callOut(
      'stonechat_unseal',
      (a) => [a(deviceSealSeed), a(sealed), sealed.length],
      { allowRefused: true },
    );
  }

  // -- sessions -----------------------------------------------------------

  /**
   * PQXDH as the initiator, device to device.
   *
   * `edSeed` is this device's signing seed and `peerEdPk` the peer device's
   * signing key from its certificate — neither is an identity key.
   */
  sessionInitiate(args: {
    edSeed: Uint8Array;
    peerEdPk: Uint8Array;
    bundleJson: string;
    ekSk: Uint8Array;
    ratchetSk: Uint8Array;
    kemRandom: Uint8Array;
  }): SessionState {
    fixed(args.edSeed, ED_SEED, 'ed seed');
    fixed(args.peerEdPk, ED_PUBLIC, 'peer ed public key');
    fixed(args.ekSk, 32, 'ephemeral secret');
    fixed(args.ratchetSk, 32, 'ratchet secret');
    fixed(args.kemRandom, MLKEM_ENCAPS_RANDOM, 'kem randomness');
    const bundle = enc.encode(args.bundleJson);
    const out = this.callOut('stonechat_session_initiate', (a) => [
      a(args.edSeed),
      a(args.peerEdPk),
      a(bundle),
      bundle.length,
      a(args.ekSk),
      a(args.ratchetSk),
      a(args.kemRandom),
    ]);
    return this.json<SessionState>(out!);
  }

  sessionRespond(args: {
    edSeed: Uint8Array;
    senderEdPk: Uint8Array;
    x3dhJson: string;
    spkPub: Uint8Array;
    spkSec: Uint8Array;
    opkSec: Uint8Array | null;
    kemSeed: Uint8Array;
  }): SessionState {
    fixed(args.edSeed, ED_SEED, 'ed seed');
    fixed(args.senderEdPk, ED_PUBLIC, 'sender ed public key');
    fixed(args.spkPub, 32, 'spk public');
    fixed(args.spkSec, 32, 'spk secret');
    if (args.opkSec) fixed(args.opkSec, 32, 'opk secret');
    fixed(args.kemSeed, MLKEM_SEED, 'kem seed');
    const x3dh = enc.encode(args.x3dhJson);
    const out = this.callOut('stonechat_session_respond', (a) => [
      a(args.edSeed),
      a(args.senderEdPk),
      a(x3dh),
      x3dh.length,
      a(args.spkPub),
      a(args.spkSec),
      // A null pointer is how "no one-time prekey" is expressed; passing a
      // zeroed 32-byte buffer instead would be a *different* handshake.
      args.opkSec ? a(args.opkSec) : 0,
      a(args.kemSeed),
    ]);
    return this.json<SessionState>(out!);
  }

  sessionEncrypt(
    state: SessionState,
    plaintext: Uint8Array,
    ad: Uint8Array,
    nonce: Uint8Array,
  ): EncryptResult {
    fixed(nonce, 24, 'nonce');
    const stateJson = enc.encode(JSON.stringify(state));
    const out = this.callOut('stonechat_session_encrypt', (a) => [
      a(stateJson),
      stateJson.length,
      a(plaintext),
      plaintext.length,
      a(ad),
      ad.length,
      a(nonce),
    ]);
    return this.json<EncryptResult>(out!);
  }

  /** Null when this message is not for us — a wrong key, or a replay. */
  sessionDecrypt(args: {
    state: SessionState;
    header: unknown;
    nonce: Uint8Array;
    ciphertext: Uint8Array;
    ad: Uint8Array;
    freshRatchetSk: Uint8Array;
    /** 64 fresh bytes for the post-quantum ratchet, drawn separately. */
    pqRandom: Uint8Array;
  }): DecryptResult | null {
    fixed(args.nonce, 24, 'nonce');
    fixed(args.freshRatchetSk, 32, 'fresh ratchet secret');
    fixed(args.pqRandom, 64, 'post-quantum ratchet randomness');
    const stateJson = enc.encode(JSON.stringify(args.state));
    const headerJson = enc.encode(JSON.stringify(args.header));
    const out = this.callOut(
      'stonechat_session_decrypt',
      (a) => [
        a(stateJson),
        stateJson.length,
        a(headerJson),
        headerJson.length,
        a(args.nonce),
        a(args.ciphertext),
        args.ciphertext.length,
        a(args.ad),
        args.ad.length,
        a(args.freshRatchetSk),
        a(args.pqRandom),
      ],
      { allowRefused: true },
    );
    return out === null ? null : this.json<DecryptResult>(out);
  }

  // -- KEM ----------------------------------------------------------------

  /** The X25519 public half of a 32-byte secret — the DH prekeys' keypair. */
  x25519Public(secret: Uint8Array): Uint8Array {
    fixed(secret, 32, 'x25519 secret');
    return this.callInto('stonechat_x25519_public', 32, (a) => [a(secret)])!;
  }

  xwingPkFromSeed(seed: Uint8Array): Uint8Array {
    fixed(seed, XWING_SEED, 'x-wing seed');
    return this.callInto('stonechat_xwing_pk_from_seed', XWING_PUBLIC, (a) => [
      a(seed),
    ])!;
  }

  mlkemPkFromSeed(seed: Uint8Array): Uint8Array {
    fixed(seed, MLKEM_SEED, 'ml-kem seed');
    return this.callInto('stonechat_mlkem_pk_from_seed', MLKEM_PUBLIC, (a) => [
      a(seed),
    ])!;
  }

  mlkemEncaps(
    pk: Uint8Array,
    random: Uint8Array,
  ): { ct: Uint8Array; ss: Uint8Array } {
    fixed(pk, MLKEM_PUBLIC, 'ml-kem public key');
    fixed(random, MLKEM_ENCAPS_RANDOM, 'encapsulation randomness');
    // Two out buffers, so this one is written longhand rather than through
    // callInto.
    const owned: Array<[number, number]> = [];
    const put = (d: Uint8Array): number => {
      const p = this.put(d);
      owned.push([p, d.length]);
      return p;
    };
    const ctPtr = this.alloc(MLKEM_CIPHERTEXT);
    const ssPtr = this.alloc(KEM_SHARED_SECRET);
    owned.push([ctPtr, MLKEM_CIPHERTEXT], [ssPtr, KEM_SHARED_SECRET]);
    try {
      const rc = this.fn('stonechat_mlkem_encaps')(
        put(pk),
        put(random),
        ctPtr,
        ssPtr,
      );
      if (rc !== OK) throw new CoreError('stonechat_mlkem_encaps', rc);
      const m = this.bytes();
      return {
        ct: m.slice(ctPtr, ctPtr + MLKEM_CIPHERTEXT),
        ss: m.slice(ssPtr, ssPtr + KEM_SHARED_SECRET),
      };
    } finally {
      for (const [ptr, len] of owned) this.ex.stonechat_free(ptr, len);
    }
  }

  mlkemDecaps(seed: Uint8Array, ct: Uint8Array): Uint8Array {
    fixed(seed, MLKEM_SEED, 'ml-kem seed');
    fixed(ct, MLKEM_CIPHERTEXT, 'ml-kem ciphertext');
    return this.callInto('stonechat_mlkem_decaps', KEM_SHARED_SECRET, (a) => [
      a(seed),
      a(ct),
    ])!;
  }

  // -- misc ---------------------------------------------------------------

  /** BLAKE2b-256 of a DER certificate — also the plain hash the link flow
   * derives its parking key with (app_state.dart `_hashHex`). */
  tlsFingerprint(der: Uint8Array): Uint8Array {
    return this.callInto('stonechat_tls_fingerprint', SHA256, (a) => [
      a(der),
      der.length,
    ])!;
  }

  base32Encode(data: Uint8Array): string {
    return dec.decode(
      this.callOut('stonechat_base32_encode', (a) => [a(data), data.length])!,
    );
  }

  base32Decode(text: string): Uint8Array {
    const raw = enc.encode(text);
    return this.callOut('stonechat_base32_decode', (a) => [a(raw), raw.length])!;
  }
}

// -- shapes the core returns ----------------------------------------------

export interface Identity {
  secret: string;
  public: string;
  pq_public: string;
  stonechat_id: string;
  pq_public_sig: string;
}

export interface SignedCert {
  stonechat_id: string;
  device_id: number;
  sig_pub: string;
  seal_pub: string;
  not_after: number;
  sig: string;
}

export type CertStatus =
  | 'valid'
  | 'expired'
  | 'bad_signature'
  | 'wrong_identity';

/** Mostly opaque — the core owns the ratchet's shape. `pending_x3dh` is the
 * one field a caller reads: it is the handshake block that must ride the first
 * envelope, and it clears itself once the peer replies. */
export type SessionState = Record<string, unknown> & {
  pending_x3dh?: Record<string, unknown> | null;
};

export interface EncryptResult {
  state: SessionState;
  /** The ratchet header — `{dh, pn, n}`. Called `header` by the core and
   * `ratchet` on the wire; the two names are for the same object, and
   * conflating them silently produces an envelope nobody can decrypt. */
  header: Record<string, unknown>;
  ciphertext: string;
}

/** One published WebTransport certificate: its SHA-256 and its window. */
export interface WtCert {
  sha256: string;
  not_before: number;
  not_after: number;
}

export interface WtCertSchedule {
  certs: WtCert[];
  refresh_after?: number | null;
}

export interface DecryptResult {
  state: SessionState;
  /** **Base64**, not text. The core emits JSON, and a plaintext containing a
   * quote or a newline could not ride in a JSON string unescaped — so it is
   * encoded, and callers decode. Treating it as text yields a confident
   * `SyntaxError` on the first message. */
  plaintext: string;
}
