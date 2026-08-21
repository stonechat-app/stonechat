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
import { PinRefused, routeFor } from './transport.js';
import { store, type Contact } from './store.js';

const PRIMARY_DEVICE = 1;
const OPK_TARGET = 20;

export interface Message {
  id: string;
  /** The conversation this belongs to: a peer's SC- ID, or a group's id. */
  peerId: string;
  mine: boolean;
  text: string;
  sentAt: string;
  media?: MediaAttachment;
  /**
   * Who actually sent it, when that is not the same as the conversation.
   *
   * In a group the conversation is the group and the sender is a member, so a
   * thread that labelled everything with the conversation id would credit
   * every message to the group itself.
   */
  sender?: string;
}

/**
 * A decrypted attachment, ready to render.
 *
 * `url` is an object URL over bytes this tab decrypted — it never points at
 * the mailbox, which only ever held ciphertext it had no key for. Revoke it
 * when the message leaves the view; nothing here does that yet, which is
 * fine while the cap on kept messages is what bounds it.
 */
export interface MediaAttachment {
  url: string;
  mime: string;
  kind: string;
  size: number;
  name?: string;
}

/**
 * The MessageKind the phone uses for this mime type.
 *
 * Kept in step with the app's `_mimeFromPath`/`_mediaKindOf` so a photo sent
 * from a browser arrives on a phone as an image rather than a file.
 */
function kindForMime(mime: string): string {
  if (mime.startsWith('image/')) return 'image';
  if (mime.startsWith('video/')) return 'video';
  if (mime.startsWith('audio/')) return 'audio';
  return 'file';
}

/** How many prekeys to keep published. */
export class Protocol {
  /**
   * A conversation was cleared on another of our devices.
   *
   * A cleared conversation is not a message, so it cannot come back through
   * `receive()` — this is how the view learns to drop what it is showing.
   */
  onConversationCleared?: (peerId: string) => void;

  /** A roster arrived or changed — the conversation list has new names. */
  onGroupsChanged?: () => void;

  private readonly directory = new Map<string, DirectoryEntry>();
  /** One mailbox connection per relay address — a peer's relay is reached the
   * same way our own is, and reusing the session across sends is most of the
   * cost of delivery. */
  private readonly mailboxes = new Map<string, Promise<Mailbox>>();

  /** The in-flight self-sync, if any. Exposed through [whenSynced] because
   * fire-and-forget work is invisible to a test otherwise. */
  private syncing: Promise<void> = Promise.resolve();

  /** Resolves once the last send's mirror to our own devices has finished. */
  whenSynced(): Promise<void> {
    return this.syncing;
  }

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
      //
      // Entries are cached for the session, so one resolved in the gap between
      // a mailbox igniting and its owner publishing a certificate schedule
      // would keep this session broken until the tab was reloaded — reporting
      // a mailbox problem that had already fixed itself. Re-read once when the
      // refusal says the answer can change, and only then: a bad signature is
      // not a race, and retrying it would hide it.
      const mailbox = await this.dial(entry).catch(async (e: unknown) => {
        if (!(e instanceof PinRefused) || !e.transient) throw e;
        return this.dial(await this.resolve(ownerId, { refresh: true }));
      });
      void mailbox.closed.then(() => this.mailboxes.delete(ownerId));
      return mailbox;
    })();
    this.mailboxes.set(ownerId, opening);
    return opening;
  }

  /** A directory entry, checked to commit to the ID we asked for. Cached: a
   * lying hub can only produce a *failed* lookup, and only if someone checks. */
  private async resolve(
    stonechatId: string,
    { refresh = false }: { refresh?: boolean } = {},
  ): Promise<DirectoryEntry> {
    const held = refresh ? undefined : this.directory.get(stonechatId);
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
        await this.sendTo(peerId, device, id, sentAt, 'msg', { text });
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
    // Mirror it to our own other devices. Without this a message typed in the
    // browser never appears on the phone and vice versa: each device only sees
    // what a *peer* sent it, and our own outgoing messages have no other route.
    //
    // Not awaited: the message has already reached the person it was for, and
    // making the composer wait on a sibling that may be offline would be the
    // wrong trade. The promise is kept so tests can wait for it.
    this.syncing = this.syncSent(peerId, id, sentAt, text);
    return { id, peerId, mine: true, text, sentAt };
  }

  /**
   * Send to a group.
   *
   * There is no group mailbox: a group message is N pairwise messages, one per
   * member per device, each sealed to that device exactly as a DM is. That is
   * what makes a group cost nothing server-side and also why a member we
   * cannot reach is an ordinary partial failure rather than a broken send.
   *
   * Needs the roster, so it only works for a group we have been told about —
   * see `sendableGroup`.
   */
  async sendGroup(groupId: string, text: string): Promise<Message> {
    const group = store.groups()[groupId];
    if (!group) {
      throw new Error(
        'This browser has not been told who is in that group — send from your phone.',
      );
    }
    const id = crypto.randomUUID();
    const sentAt = new Date().toISOString();
    const payload = { group_id: groupId, text };

    let delivered = 0;
    let lastError: unknown = null;
    for (const member of group.members) {
      if (member.stonechatId === this.stonechatId) continue;
      for (const device of await this.devicesOf(member.stonechatId)) {
        try {
          await this.sendTo(
            member.stonechatId, device, id, sentAt, 'group_msg', payload,
          );
          delivered++;
        } catch (e) {
          lastError = e;
        }
      }
    }
    // A group of one is a legitimate state — everyone else left — so an empty
    // fan-out is not a failure. Nobody *reachable* is.
    const others = group.members.filter((m) => m.stonechatId !== this.stonechatId);
    if (delivered === 0 && others.length > 0) {
      throw lastError instanceof Error
        ? lastError
        : new Error('Could not reach anyone in that group.');
    }
    // Our own devices see it as a group message, keyed by group rather than
    // peer — the same shape the phone's _applySyncSent reads.
    this.syncing = this.syncSentGroup(groupId, id, sentAt, payload);
    return { id, peerId: groupId, mine: true, text, sentAt };
  }

  private async syncSentGroup(
    groupId: string,
    id: string,
    sentAt: string,
    payload: Record<string, unknown>,
  ): Promise<void> {
    for (const device of await this.siblingDevices()) {
      try {
        await this.sendTo(this.stonechatId, device, id, sentAt, 'sync_sent', {
          group_id: groupId,
          type: 'group_msg',
          payload,
          id,
          sent_at: Date.parse(sentAt),
        });
      } catch {
        // A sibling that is gone is not this send's problem.
      }
    }
  }

  /** Whether this browser knows enough about a group to send into it. */
  knowsGroup(groupId: string): boolean {
    return groupId in store.groups();
  }

  /**
   * Send an attachment.
   *
   * The blob is encrypted under a fresh key and parked on the *recipient's*
   * mailbox, exactly as the phone does it: one upload, then one envelope per
   * device carrying the key. The mailbox holds ciphertext it has no key for,
   * so parking it there costs the recipient storage and tells them nothing.
   *
   * Uploaded once rather than per device — the envelopes all name the same
   * blob, and the relay refcounts it, so a two-device peer does not pay twice.
   */
  async sendMedia(peerId: string, file: File): Promise<Message> {
    const bytes = new Uint8Array(await file.arrayBuffer());
    const key = randomBytes(32);
    const nonce = randomBytes(24);
    const ciphertext = this.core.blobSeal(key, nonce, bytes);

    const mailbox = await this.connect(peerId);
    const uploaded = await mailbox.request('POST', '/blob', ciphertext);
    if (uploaded.status < 200 || uploaded.status >= 300) {
      throw new Error(
        uploaded.status === 413
          ? 'That file is too large for a mailbox.'
          : `Could not upload the attachment (${uploaded.status}).`,
      );
    }
    const blobId = String(
      (JSON.parse(fromUtf8.decode(uploaded.body)) as Record<string, unknown>)[
        'blob_id'
      ],
    );

    const id = crypto.randomUUID();
    const sentAt = new Date().toISOString();
    const payload: Record<string, unknown> = {
      blob_id: blobId,
      key: b64encode(key),
      blob_nonce: b64encode(nonce),
      mime: file.type || 'application/octet-stream',
      kind: kindForMime(file.type),
      size: bytes.length,
      name: file.name,
    };

    let delivered = 0;
    let lastError: unknown = null;
    for (const device of await this.devicesOf(peerId)) {
      try {
        await this.sendTo(peerId, device, id, sentAt, 'media', payload, blobId);
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
    // Mirror it to our own other devices, exactly as text is mirrored — but a
    // sibling cannot read the copy we just uploaded: that one lives on the
    // *recipient's* mailbox and we hold no token for it. So a second copy goes
    // on our own mailbox with a fetch token beside it, which is the same
    // shared-blob path group media uses (chat_state.dart `_syncSentMedia`).
    // Without this a photo sent from the browser simply never appears on the
    // phone, while the text beside it does.
    this.syncing = this.syncSentMedia(peerId, id, sentAt, payload, bytes);
    return {
      id,
      peerId,
      mine: true,
      text: '',
      sentAt,
      media: {
        // Our own copy comes from the bytes we just read, not from a fetch:
        // the blob we uploaded is on *their* mailbox and we hold no token for
        // it. This is also why an attachment we sent survives only as long as
        // this tab does.
        url: URL.createObjectURL(new Blob([bytes], { type: file.type })),
        mime: file.type || 'application/octet-stream',
        kind: kindForMime(file.type),
        size: bytes.length,
        name: file.name,
      },
    };
  }

  /**
   * Mirror an outgoing attachment to our own other devices.
   *
   * Best-effort, like every other sync: the message has already reached the
   * person it was for, and a sibling that is offline must never make the send
   * look failed. A sibling copy that cannot be parked means no sync at all —
   * the phone's rule too, since a sync naming a blob nobody can fetch renders
   * as an attachment that never loads.
   */
  private async syncSentMedia(
    peerId: string,
    id: string,
    sentAt: string,
    payload: Record<string, unknown>,
    bytes: Uint8Array,
  ): Promise<void> {
    const siblings = await this.siblingDevices();
    if (siblings.length === 0) return;

    const entry = await this.resolve(this.stonechatId);
    const host = entry.mailbox?.address;
    const tlsFp = entry.mailbox?.tls_fp;
    if (!host || !tlsFp) return;

    // `?shared=1` is what returns a fetch token: the sibling holds no owner
    // token for this mailbox, and a per-blob capability is all it needs.
    const own = await this.connect(this.stonechatId);
    const key = randomBytes(32);
    const nonce = randomBytes(24);
    const parked = await own.request(
      'POST',
      '/blob?shared=1',
      this.core.blobSeal(key, nonce, bytes),
    );
    if (parked.status < 200 || parked.status >= 300) return;
    const body = JSON.parse(fromUtf8.decode(parked.body)) as Record<string, unknown>;

    const forSiblings = {
      ...payload,
      blob_id: String(body['blob_id']),
      key: b64encode(key),
      blob_nonce: b64encode(nonce),
      fetch_token: String(body['fetch_token'] ?? ''),
      blob_host: host,
      blob_tls_fp: tlsFp,
    };
    for (const device of siblings) {
      try {
        await this.sendTo(this.stonechatId, device, id, sentAt, 'sync_sent', {
          peer: peerId,
          type: 'media',
          payload: forSiblings,
          id,
          sent_at: Date.parse(sentAt),
        });
      } catch {
        // A device that is gone or unreachable is not this send's problem.
      }
    }
  }

  /**
   * Mirror one of our own outgoing messages to our other devices.
   *
   * Best-effort, like receipts: a lost sync costs a stale view on one device,
   * and it must never make the send itself look failed — the message did go to
   * the person it was for.
   */
  private async syncSent(
    peerId: string,
    id: string,
    sentAt: string,
    text: string,
  ): Promise<void> {
    const payload = {
      peer: peerId,
      type: 'msg',
      payload: { text },
      id,
      // Milliseconds, matching what the app's `_applySyncSent` reads. The
      // outer envelope carries ISO; this inner field does not.
      sent_at: Date.parse(sentAt),
    };
    for (const device of await this.siblingDevices()) {
      try {
        await this.sendTo(this.stonechatId, device, id, sentAt, 'sync_sent', payload);
      } catch {
        // A device that is gone or unreachable is not this send's problem.
      }
    }
  }

  /**
   * Fetch and decrypt an attachment someone sent us.
   *
   * The blob sits on *our* mailbox — the sender parked it there — so this
   * fetches with our own device token. A blob that does not open is dropped
   * rather than shown: the key came from inside the session ciphertext, so a
   * failure means the bytes were tampered with, and rendering "something" for
   * a message whose contents we could not authenticate is how a chat client
   * lies to its user.
   */
  private async openMedia(
    inner: Record<string, unknown>,
    body: Record<string, unknown>,
    from: string,
  ): Promise<Message | null> {
    const blobId = body['blob_id'];
    const keyB64 = body['key'];
    const nonceB64 = body['blob_nonce'];
    if (
      typeof blobId !== 'string' ||
      typeof keyB64 !== 'string' ||
      typeof nonceB64 !== 'string'
    ) {
      return null;
    }
    const mailbox = await this.ownMailbox();
    const got = await mailbox.request(
      'GET',
      `/blob/${blobId}?token=${encodeURIComponent(this.grant.device_token)}`,
    );
    // 404 is ordinary, not an error: the blob is deleted once every device has
    // acked, so a second device draining later finds it gone.
    if (got.status !== 200) return null;

    const plain = this.core.blobOpen(
      b64decode(keyB64),
      b64decode(nonceB64),
      got.body,
    );
    if (plain === null) return null;

    const mime =
      typeof body['mime'] === 'string' ? body['mime'] : 'application/octet-stream';
    // The sender chose this name; a path in it must not survive into a
    // download attribute (PROTOCOL.md requires receivers to strip one).
    const name =
      typeof body['name'] === 'string'
        ? body['name'].split(/[\\/]/).pop() || undefined
        : undefined;
    return {
      id: String(inner['id']),
      peerId: from,
      mine: false,
      text: '',
      sentAt: String(inner['sent_at'] ?? new Date().toISOString()),
      media: {
        // `.slice()` copies into a buffer the Blob constructor will accept:
        // what the core hands back is backed by wasm memory, which TypeScript
        // types as possibly shared.
        url: URL.createObjectURL(
          new Blob([plain.slice().buffer as ArrayBuffer], { type: mime }),
        ),
        mime,
        kind: typeof body['kind'] === 'string' ? body['kind'] : kindForMime(mime),
        size: plain.length,
        ...(name ? { name } : {}),
      },
    };
  }

  /**
   * Fetch a group attachment from wherever the sender parked it.
   *
   * Unlike a DM, the blob is not on our mailbox: the sender uploads **one**
   * copy to their own box and hands every member a per-blob capability, so N
   * members cost one upload rather than N. That means dialling a mailbox we do
   * not own, with a token that opens exactly this blob and nothing else
   * (`fetch_token`, PROTOCOL.md "Group media").
   */
  private async fetchGroupMedia(
    body: Record<string, unknown>,
    sender: string,
  ): Promise<MediaAttachment | undefined> {
    const blobId = body['blob_id'];
    const token = body['fetch_token'];
    const keyB64 = body['key'];
    const nonceB64 = body['blob_nonce'];
    if (
      typeof blobId !== 'string' || typeof token !== 'string' ||
      typeof keyB64 !== 'string' || typeof nonceB64 !== 'string'
    ) {
      return undefined;
    }
    // Dialled by *owner*, not by the `blob_host` address the payload also
    // carries: this transport pins against the owner's signed certificate
    // schedule from the directory, so an address on its own is not something
    // it can safely connect to. The sender is the owner — they park one copy
    // on their own mailbox and hand every member a token for it.
    const mailbox = await this.connect(sender);
    const got = await mailbox.request(
      'GET',
      `/blob/${blobId}?token=${encodeURIComponent(token)}`,
    );
    if (got.status !== 200) return undefined;
    const plain = this.core.blobOpen(b64decode(keyB64), b64decode(nonceB64), got.body);
    if (plain === null) return undefined;
    const mime =
      typeof body['mime'] === 'string' ? body['mime'] : 'application/octet-stream';
    const name =
      typeof body['name'] === 'string'
        ? body['name'].split(/[\\/]/).pop() || undefined
        : undefined;
    return {
      url: URL.createObjectURL(
        new Blob([plain.slice().buffer as ArrayBuffer], { type: mime }),
      ),
      mime,
      kind: typeof body['kind'] === 'string' ? body['kind'] : kindForMime(mime),
      size: plain.length,
      ...(name ? { name } : {}),
    };
  }

  /** Our own devices, excluding this one. */
  private async siblingDevices(): Promise<number[]> {
    const token = this.grant.bundle_token;
    if (!token) return [];
    try {
      const mailbox = await this.ownMailbox();
      const listed = await mailbox.json<{ devices: Array<{ device_id: number }> }>(
        'GET',
        `/prekeys/devices?token=${encodeURIComponent(token)}`,
      );
      return listed.devices
        .map((d) => d.device_id)
        .filter((d) => d !== this.deviceId);
    } catch {
      return [];
    }
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
    type: string,
    payload: Record<string, unknown>,
    blobId?: string,
  ): Promise<void> {
    const state = await this.sessionFor(peerId, device);
    // Held from whichever way the session was established: fetched with their
    // bundle if we started it, or taken from the handshake block if they did.
    const cert = store.peerCert(peerId, device);
    const sealKey = cert ? certSealKey(cert) : null;
    if (!sealKey) throw new Error('No usable certificate for that device.');

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
      utf8.encode(JSON.stringify(payload)),
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
      // Outside the ciphertext on purpose: the relay cannot read the payload,
      // so this is how it knows the blob is still referenced. It drops the
      // blob when the last envelope naming it is acked (blob_refcount).
      ...(blobId ? { blob_id: blobId } : {}),
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
    for await (const item of mailbox.socket(this.grant.device_token)) {
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
    // Not for ourselves. Self-sync envelopes arrive *from* our own identity,
    // so recording every sender as a contact listed us in our own chat list —
    // a conversation with yourself, which is not a thing this client has.
    // Nothing needs the record either: sibling devices come from the grant's
    // bundle token, not from a contact.
    if (from !== this.stonechatId) {
      const contact: Contact = { stonechatId: from, pubkey: entry.pubkey };
      if (typeof inner['bundle_token'] === 'string') {
        contact.bundleToken = inner['bundle_token'];
      }
      store.setContact(contact);
    }

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

    const body = JSON.parse(fromUtf8.decode(b64decode(result.plaintext))) as
      Record<string, unknown>;

    if (type === 'sync_sent') {
      // One of *our* devices telling us what it sent. Applied only when the
      // sender is our own identity — which the session already authenticates,
      // since only our own devices hold a ratchet under our SC- ID.
      if (from !== this.stonechatId) return null;
      return await this.fromSyncSent(body);
    }
    if (type === 'group_create' || type === 'group_update') {
      // The only way this browser ever learns a roster: nothing server-side
      // knows groups exist, so there is nothing to ask.
      const id = body['group_id'];
      if (typeof id !== 'string') return null;
      const members = Array.isArray(body['members']) ? body['members'] : [];
      const changed = store.upsertGroup({
        id,
        name: typeof body['name'] === 'string' ? body['name'] : id.slice(0, 8),
        admin: typeof body['admin'] === 'string' ? body['admin'] : '',
        version: Number(body['version'] ?? 0),
        members: members.map((m: Record<string, unknown>) => ({
          stonechatId: String(m['stonechat_id']),
          pubkey: String(m['pubkey']),
          ...(typeof m['display_name'] === 'string'
            ? { displayName: m['display_name'] }
            : {}),
        })),
      });
      if (changed) this.onGroupsChanged?.();
      return null;
    }
    if (type === 'group_msg' || type === 'group_media') {
      const groupId = body['group_id'];
      if (typeof groupId !== 'string') return null;
      // A group we have never been told about: still worth showing. The
      // alternative is silently dropping messages because we were linked after
      // the group was formed, which looks exactly like delivery being broken.
      const media =
        type === 'group_media' ? await this.fetchGroupMedia(body, from) : undefined;
      if (type === 'group_media' && !media) return null;
      return {
        id: String(inner['id']),
        peerId: groupId,
        mine: false,
        text: typeof body['text'] === 'string' ? body['text'] : '',
        sentAt: String(inner['sent_at'] ?? new Date().toISOString()),
        sender: from,
        ...(media ? { media } : {}),
      };
    }
    if (type === 'sync_clear') {
      // Only ever from ourselves — the session already authenticates that, and
      // a peer must never be able to erase our history.
      if (from !== this.stonechatId) return null;
      const peer = (body['group_id'] ?? body['peer']) as string | undefined;
      if (peer) {
        store.clearConversation(peer);
        this.onConversationCleared?.(peer);
      }
      return null;
    }
    if (type === 'media') return await this.openMedia(inner, body, from);
    if (type !== 'msg') return null; // slim: text and media only
    if (typeof body['text'] !== 'string') return null;
    return {
      id: String(inner['id']),
      peerId: from,
      mine: false,
      text: body['text'],
      sentAt: String(inner['sent_at'] ?? new Date().toISOString()),
    };
  }

  /** A message one of our own devices sent, mirrored to us. */
  private async fromSyncSent(
    payload: Record<string, unknown>,
  ): Promise<Message | null> {
    // A group conversation is keyed by its group id, a DM by the peer's. Both
    // are ours to render: this used to drop anything with a group_id, from
    // when groups were not implemented here, which silently threw away every
    // group message sent from the phone.
    const peerId = (payload['group_id'] ?? payload['peer']) as string | undefined;
    const inner = payload['payload'] as Record<string, unknown> | undefined;
    const id = payload['id'] as string | undefined;
    if (!peerId || !inner || !id) return null;
    const type = String(payload['type'] ?? 'msg');
    const sentAt =
      typeof payload['sent_at'] === 'number'
        ? new Date(payload['sent_at']).toISOString()
        : new Date().toISOString();

    if (type === 'media' || type === 'group_media') {
      // The sending device parked a copy on *our own* mailbox precisely so a
      // sibling could fetch it — that is what the fetch token in the payload
      // opens (chat_state.dart `_syncSentMedia`).
      const media = await this.fetchGroupMedia(inner, this.stonechatId);
      if (!media) return null;
      return { id, peerId, mine: true, text: '', sentAt, media };
    }
    if (type !== 'msg' && type !== 'group_msg') return null;
    if (typeof inner['text'] !== 'string') return null;
    return { id, peerId, mine: true, text: inner['text'], sentAt };
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
