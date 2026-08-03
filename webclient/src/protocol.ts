/**
 * Sending and receiving text, and nothing else.
 *
 * The slim counterpart of `app/lib/state/chat_state.dart`. That file is 4,000
 * lines because it handles groups, media, receipts, edits, reactions, calls,
 * self-sync, retry and disappearing messages. This handles `msg`, so it is
 * about 300 — but the *protocol* parts are the same and must stay the same:
 *
 * - envelopes are sealed to a **device's certified key**, never the identity's;
 * - the AEAD binds both device numbers, one form, always;
 * - a peer's certificate is checked against the identity key their SC- ID
 *   commits to, before anything is encrypted to it;
 * - prekeys are signed by this device and published with its certificate.
 *
 * ## What is deliberately missing
 *
 * Fan-out to a peer's *other* devices. Reaching them needs their bundle token,
 * which rides every envelope they send us — so a first outbound message goes to
 * their primary only, exactly as a stranger's contact request does. Once they
 * reply, the token is stored and the gap closes for that contact. Groups,
 * media, receipts and self-sync are simply not here.
 */
import {
  type SessionState,
  type SignedCert,
  type StonechatCore,
  MLKEM_ENCAPS_RANDOM,
  XWING_ENCAPS_RANDOM,
} from './core.js';
import { b64decode, b64encode, fromUtf8, utf8 } from './bytes.js';
import { certSealKey, certSigKey, DeviceKeys, randomBytes } from './device.js';
import { Hub, type DirectoryEntry } from './hub.js';
import type { LinkGrant } from './linking.js';
import { Mailbox } from './mailbox.js';
import { routeFor } from './transport.js';
import { store, type Contact } from './store.js';

const PRIMARY_DEVICE = 1;
const OPK_TARGET = 20;

export interface Message {
  id: string;
  peerId: string;
  mine: boolean;
  text: string;
  sentAt: string;
}

/** How many prekeys to keep published. */
export class Protocol {
  private readonly directory = new Map<string, DirectoryEntry>();
  /** One mailbox connection per relay address — a peer's relay is reached the
   * same way our own is, and reusing the session across sends is most of the
   * cost of delivery. */
  private readonly mailboxes = new Map<string, Promise<Mailbox>>();

  constructor(
    private readonly core: StonechatCore,
    private readonly hub: Hub,
    private readonly keys: DeviceKeys,
    readonly grant: LinkGrant,
    /** How to reach a relay. Overridden by the tests, which have no
     * WebTransport: the crypto is what needs proving, and it should be
     * provable without a browser. */
    private readonly dial: (entry: DirectoryEntry) => Promise<Mailbox> = async (
      entry,
    ) => Mailbox.open(routeFor(this.core, entry), ''),
  ) {}

  get stonechatId(): string {
    return this.grant.stonechat_id;
  }
  get deviceId(): number {
    return this.grant.device_id;
  }

  // -- our own mailbox ----------------------------------------------------

  private async ownMailbox(): Promise<Mailbox> {
    return this.connect(this.stonechatId);
  }

  /**
   * Open (or reuse) a WebTransport session to whoever's relay.
   *
   * The pins come from the directory and are verified against the owner's
   * identity key before anything is dialled (`transport.ts`). A peer's relay
   * is reached exactly like our own: there is no privileged path.
   */
  private connect(ownerId: string): Promise<Mailbox> {
    const existing = this.mailboxes.get(ownerId);
    if (existing) return existing;
    const opening = (async () => {
      const entry = await this.resolve(ownerId);
      // No token: a peer's relay gets none, and the routes it exposes to a
      // stranger are exactly the ones that take none. Our own mailbox's token
      // rides on the individual requests that need it.
      const mailbox = await this.dial(entry);
      void mailbox.closed.then(() => this.mailboxes.delete(ownerId));
      return mailbox;
    })();
    this.mailboxes.set(ownerId, opening);
    return opening;
  }

  /** A directory entry, checked to commit to the ID we asked for. Cached: a
   * lying hub can only produce a *failed* lookup, and only if someone checks. */
  private async resolve(stonechatId: string): Promise<DirectoryEntry> {
    const held = this.directory.get(stonechatId);
    if (held) return held;
    const entry = await this.hub.directory(stonechatId);
    if (this.core.stonechatId(b64decode(entry.pubkey)) !== entry.stonechat_id) {
      throw new Error(`the directory's key does not commit to ${stonechatId}`);
    }
    this.directory.set(stonechatId, entry);
    return entry;
  }

  // -- prekeys ------------------------------------------------------------

  /**
   * Publish this device's prekeys, so peers can start sessions with it.
   *
   * Signed by the **device** key and published with the certificate that names
   * it — one without the other leaves a sender unable to check either.
   */
  async publishPrekeys(): Promise<void> {
    let pool = store.prekeys();
    if (pool === null) {
      const spkPair = this.newX25519();
      const kspkSeed = randomBytes(64);
      pool = {
        spk: { id: 1, pub: spkPair.pub, sec: spkPair.sec },
        kspk: {
          id: 1,
          pub: b64encode(this.core.mlkemPkFromSeed(kspkSeed)),
          seed: b64encode(kspkSeed),
        },
        opks: {},
        kopks: {},
        nextId: 2,
      };
    }
    while (Object.keys(pool.opks).length < OPK_TARGET) {
      const pair = this.newX25519();
      pool.opks[pool.nextId++] = { pub: pair.pub, sec: pair.sec };
    }
    while (Object.keys(pool.kopks).length < OPK_TARGET) {
      const seed = randomBytes(64);
      pool.kopks[pool.nextId++] = {
        pub: b64encode(this.core.mlkemPkFromSeed(seed)),
        seed: b64encode(seed),
      };
    }
    store.setPrekeys(pool);

    const sig = this.core.sign(
      this.keys.sigSecret,
      utf8.encode('stonechat-v1-spk'),
      b64decode(pool.spk.pub),
    );
    const ksig = this.core.sign(
      this.keys.sigSecret,
      utf8.encode('stonechat-v1-kspk'),
      b64decode(pool.kspk.pub),
    );
    const mailbox = await this.ownMailbox();
    await mailbox.json('POST', `/prekeys?token=${this.grant.device_token}`, {
      spk: { id: pool.spk.id, pub: pool.spk.pub, sig: b64encode(sig) },
      opks: Object.entries(pool.opks).map(([id, o]) => ({
        id: Number(id),
        pub: o.pub,
      })),
      kspk: { id: pool.kspk.id, pub: pool.kspk.pub, sig: b64encode(ksig) },
      kopks: Object.entries(pool.kopks).map(([id, o]) => ({
        id: Number(id),
        pub: o.pub,
      })),
      cert: this.grant.cert,
    });
  }

  /** An X25519 pair, via the core's scalar-mult helper. */
  private newX25519(): { pub: string; sec: string } {
    const sec = randomBytes(32);
    return { pub: b64encode(this.core.x25519Public(sec)), sec: b64encode(sec) };
  }

  // -- sessions -----------------------------------------------------------

  /**
   * Establish (or load) the ratchet for one of a peer's devices.
   *
   * The order is the security argument, same as the app's: their certificate
   * is checked against the identity key their SC- ID commits to, and their
   * prekeys are then checked against the key that certificate names. A prekey
   * nobody vouched for is exactly what this refuses.
   */
  private async sessionFor(
    peerId: string,
    device: number,
  ): Promise<SessionState> {
    const held = store.session(peerId, device);
    if (held) return held;

    const entry = await this.resolve(peerId);
    const mailbox = await this.connect(peerId);
    const bundle = await mailbox.json<Record<string, never>>(
      'GET',
      device === PRIMARY_DEVICE
        ? '/prekeys/bundle'
        : `/prekeys/bundle?device=${device}`,
    );
    const cert = (bundle as Record<string, unknown>)['cert'] as
      | SignedCert
      | undefined;
    if (!cert) {
      throw new Error('No certificate for that device — refusing to send.');
    }
    const identityPub = b64decode(entry.pubkey);
    const status = this.core.devcertVerify(
      cert,
      identityPub,
      Math.floor(Date.now() / 1000),
    );
    if (status !== 'valid') {
      throw new Error(`Their certificate is ${status} — refusing to send.`);
    }
    if (cert.device_id !== device) {
      // Signed and unexpired, but for a different device than the slot it
      // arrived in. A relay shuffling certificates between devices would
      // redirect mail, and the signature covers the id exactly so it can be
      // checked.
      throw new Error('Their certificate names a different device.');
    }
    const deviceSigKey = certSigKey(cert);
    if (!deviceSigKey) throw new Error('Their certificate names no signing key.');
    store.setPeerCert(peerId, device, cert);

    const b = bundle as unknown as {
      spk: { pub: string; sig: string };
      kspk: { pub: string; sig: string };
    };
    if (
      !this.core.verify(
        deviceSigKey,
        utf8.encode('stonechat-v1-spk'),
        b64decode(b.spk.pub),
        b64decode(b.spk.sig),
      ) ||
      !this.core.verify(
        deviceSigKey,
        utf8.encode('stonechat-v1-kspk'),
        b64decode(b.kspk.pub),
        b64decode(b.kspk.sig),
      )
    ) {
      throw new Error('Their mailbox served a forged prekey — refusing to send.');
    }

    // Device to device: their signing key from the certificate we just
    // verified, ours from this session's own seed. No identity secret is
    // involved on either side, which is what lets a browser do this at all.
    const state = this.core.sessionInitiate({
      edSeed: this.keys.sigSeed,
      peerEdPk: deviceSigKey,
      bundleJson: JSON.stringify(bundle),
      ekSk: randomBytes(32),
      ratchetSk: randomBytes(32),
      kemRandom: randomBytes(MLKEM_ENCAPS_RANDOM),
    });
    store.setSession(peerId, device, state);
    return state;
  }

  // -- sending ------------------------------------------------------------

  /**
   * Send text to a peer — one envelope per device they have.
   *
   * Fan-out is not optional even in a slim client: a web session is device 2
   * or later, so a reply that only ever went to device 1 would never reach the
   * browser it was answering. Which devices exist comes from their bundle
   * token, which rides every envelope they send us; without one we can reach
   * only their primary, which is exactly what a stranger's first message gets.
   *
   * A partial fan-out counts as sent: the devices that took it will show the
   * message, and refusing on one dead device would lose it for the rest.
   */
  async send(peerId: string, text: string): Promise<Message> {
    const devices = await this.devicesOf(peerId);
    const id = crypto.randomUUID();
    const sentAt = new Date().toISOString();
    let delivered = 0;
    let lastError: unknown = null;
    for (const device of devices) {
      try {
        await this.sendTo(peerId, device, id, sentAt, text);
        delivered++;
      } catch (e) {
        lastError = e;
      }
    }
    if (delivered === 0) {
      throw lastError instanceof Error
        ? lastError
        : new Error('Could not reach any of their devices.');
    }
    return { id, peerId, mine: true, text, sentAt };
  }

  /** Which of a peer's devices to encrypt for. */
  private async devicesOf(peerId: string): Promise<number[]> {
    const token = store.contacts()[peerId]?.bundleToken;
    if (!token) return [PRIMARY_DEVICE];
    try {
      const mailbox = await this.connect(peerId);
      const listed = await mailbox.json<{ devices: Array<{ device_id: number }> }>(
        'GET',
        `/prekeys/devices?token=${encodeURIComponent(token)}`,
      );
      const ids = listed.devices.map((d) => d.device_id).filter((d) => d > 0);
      return ids.length ? ids : [PRIMARY_DEVICE];
    } catch {
      // A listing we cannot fetch is not a reason to send nothing.
      return [PRIMARY_DEVICE];
    }
  }

  private async sendTo(
    peerId: string,
    device: number,
    id: string,
    sentAt: string,
    text: string,
  ): Promise<void> {
    const state = await this.sessionFor(peerId, device);
    // Held from whichever way the session was established: fetched with their
    // bundle if we started it, or taken from the handshake block if they did.
    const cert = store.peerCert(peerId, device);
    const sealKey = cert ? certSealKey(cert) : null;
    if (!sealKey) throw new Error('No usable certificate for that device.');

    const type = 'msg';
    // Both device numbers are bound, on every message. One form, no
    // conditional: this is the one place a second code path would mean silent
    // decryption failure.
    const ad = utf8.encode(
      `stonechat/v1|${this.stonechatId}|${this.deviceId}|${peerId}|${device}|${type}`,
    );
    // The nonce is ours, not the core's: it takes one and binds it, and it
    // has to travel beside the ciphertext.
    const nonce = randomBytes(24);
    const result = this.core.sessionEncrypt(
      state,
      utf8.encode(JSON.stringify({ text })),
      ad,
      nonce,
    );
    store.setSession(peerId, device, result.state);
    // The handshake block lives in the *state*, not the encrypt result, and
    // clears itself once the peer replies.
    const pending = result.state.pending_x3dh;

    const inner: Record<string, unknown> = {
      v: 1,
      id,
      type,
      from: this.stonechatId,
      from_device: this.deviceId,
      to: peerId,
      device,
      sent_at: sentAt,
      ratchet: result.header,
      nonce: b64encode(nonce),
      ciphertext: result.ciphertext,
      // So they can reach all of our devices, not just this one.
      bundle_token: this.grant.bundle_token,
    };
    if (pending) {
      // Our certificate travels with the handshake so the responder can trust
      // the device key inside it without fetching anything.
      inner['x3dh'] = { ...pending, cert: this.grant.cert };
    }

    const sealed = this.core.seal(
      sealKey,
      utf8.encode(JSON.stringify(inner)),
      randomBytes(XWING_ENCAPS_RANDOM),
      randomBytes(24),
    );
    const mailbox = await this.connect(peerId);
    await mailbox.json('POST', '/inbox', {
      v: 1,
      id,
      to: peerId,
      device,
      sealed: b64encode(sealed),
    });
  }

  // -- receiving ----------------------------------------------------------

  /**
   * Drain and stay connected. Yields decrypted text messages.
   *
   * Anything that is not a `msg` is acked and dropped: a slim client that
   * left receipts and typing indicators queued would grow its own mailbox
   * forever.
   */
  async *receive(): AsyncGenerator<Message, void, void> {
    const mailbox = await this.ownMailbox();
    for await (const item of mailbox.socket()) {
      if (item.kind === 'closed') {
        throw new Error(
          item.code === 4001
            ? 'This device was revoked from your phone.'
            : 'Another session took over this device.',
        );
      }
      const message = await this.open(item.envelope);
      // Ack after it is decrypted and handed over, never before: the relay's
      // promise is "accepted for write", and an ack is what deletes the row.
      await mailbox.ack(String(item.envelope['id']));
      if (message) yield message;
    }
  }

  private async open(
    wire: Record<string, unknown>,
  ): Promise<Message | null> {
    const sealed = wire['sealed'];
    if (typeof sealed !== 'string') return null;
    const opened = this.core.unseal(this.keys.sealSeed, b64decode(sealed));
    if (opened === null) return null; // not sealed to this device
    const inner = JSON.parse(fromUtf8.decode(opened)) as Record<string, unknown>;

    const from = String(inner['from']);
    const fromDevice = Number(inner['from_device'] ?? PRIMARY_DEVICE);
    const type = String(inner['type']);

    const entry = await this.resolve(from);
    const contact: Contact = { stonechatId: from, pubkey: entry.pubkey };
    if (typeof inner['bundle_token'] === 'string') {
      contact.bundleToken = inner['bundle_token'];
    }
    store.setContact(contact);

    const ad = utf8.encode(
      `stonechat/v1|${from}|${fromDevice}|${this.stonechatId}|${this.deviceId}|${type}`,
    );
    const x3dh = inner['x3dh'] as Record<string, unknown> | undefined;
    let state = store.session(from, fromDevice);

    if (!state && x3dh) {
      state = this.respond(from, fromDevice, x3dh, entry);
    }
    if (!state) return null;

    const result = this.core.sessionDecrypt({
      state,
      header: inner['ratchet'],
      nonce: b64decode(String(inner['nonce'])),
      ciphertext: b64decode(String(inner['ciphertext'])),
      ad,
      freshRatchetSk: randomBytes(32),
    });
    if (result === null) return null;
    store.setSession(from, fromDevice, result.state);

    if (type !== 'msg') return null; // slim: text only
    const payload = JSON.parse(
      fromUtf8.decode(b64decode(result.plaintext)),
    ) as { text?: string };
    if (typeof payload.text !== 'string') return null;
    return {
      id: String(inner['id']),
      peerId: from,
      mine: false,
      text: payload.text,
      sentAt: String(inner['sent_at'] ?? new Date().toISOString()),
    };
  }

  /**
   * Answer an initial handshake.
   *
   * The key in the block is the sender's **device** key, which does not hash
   * to their SC- ID — so the check is the certificate that vouches for it,
   * against the identity key their SC- ID does commit to, and then that the
   * certificate vouches for *this* key. Without the second, the certificate
   * would be decoration.
   */
  private respond(
    from: string,
    fromDevice: number,
    x3dh: Record<string, unknown>,
    entry: DirectoryEntry,
  ): SessionState | null {
    const cert = x3dh['cert'] as SignedCert | undefined;
    if (!cert) return null;
    const identityPub = b64decode(entry.pubkey);
    if (
      this.core.devcertVerify(cert, identityPub, Math.floor(Date.now() / 1000)) !==
        'valid' ||
      cert.device_id !== fromDevice
    ) {
      return null;
    }
    const certified = certSigKey(cert);
    if (!certified || b64encode(certified) !== String(x3dh['ik'])) return null;
    // Keep it: it names the key to seal back to, so a reply needs no fetch.
    store.setPeerCert(from, fromDevice, cert);

    const pool = store.prekeys();
    if (!pool) return null;
    const opkId = x3dh['opk_id'] as number | undefined;
    const kemOneTime = Boolean(x3dh['kem_one_time']);
    const kemId = Number(x3dh['kem_id']);
    const kemSeed = kemOneTime ? pool.kopks[kemId]?.seed : pool.kspk.seed;
    if (!kemSeed) return null;
    const opkSec = opkId === undefined ? null : pool.opks[opkId]?.sec;
    if (opkId !== undefined && !opkSec) return null;

    const state = this.core.sessionRespond({
      edSeed: this.keys.sigSeed,
      senderEdPk: b64decode(String(x3dh['ik'])),
      x3dhJson: JSON.stringify(x3dh),
      spkPub: b64decode(pool.spk.pub),
      spkSec: b64decode(pool.spk.sec),
      opkSec: opkSec ? b64decode(opkSec) : null,
      kemSeed: b64decode(kemSeed),
    });

    // One-time means one time: what we hold is exactly what we can decrypt.
    if (opkId !== undefined) delete pool.opks[opkId];
    if (kemOneTime) delete pool.kopks[kemId];
    store.setPrekeys(pool);
    return state;
  }
}
