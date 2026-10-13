/**
 * Sending and receiving.
 *
 * The browser counterpart of `app/lib/state/chat_state.dart`. Smaller than it
 * — no calls, no backups, no contact management, no group administration —
 * but the *protocol* parts are the same and must stay the same:
 *
 * - envelopes are sealed to a **device's certified key**, never the identity's;
 * - the AEAD binds both device numbers, one form, always;
 * - a peer's certificate is checked against the identity key their SC- ID
 *   commits to, before anything is encrypted to it and on every envelope
 *   from it; the identity's device manifest, when it has one, decides which
 *   devices count (PROTOCOL.md "Device manifest");
 * - prekeys are signed by this device and published with its certificate;
 * - what arrives is checked where it enters (`wire.ts`), and a sender's
 *   initial handshake can replace a session that no longer decrypts, with
 *   the lower Stonechat ID winning a simultaneous start.
 *
 * What it handles: `msg`, `media`, `group_msg`, `group_media`, rosters and
 * `group_sync`/`group_leave`, receipts, typing, edits, deletes, reactions,
 * replies, disappearing messages, contact requests/accepts and profiles
 * (recorded, not answered), and every self-sync type including `sync_cert`.
 * Calls are shown and must be answered on the phone. A send that cannot be
 * delivered now waits in an outbox and is retried with the app's backoff.
 */
import {
  type SessionState,
  type SignedCert,
  type StonechatCore,
  MLKEM_ENCAPS_RANDOM,
  XWING_ENCAPS_RANDOM,
} from './core.js';
import { b64decode, b64encode, fromUtf8, utf8 } from './bytes.js';
import {
  certExpiry,
  certNeedsRefresh,
  certSealKey,
  certSigKey,
  DeviceKeys,
  randomBytes,
} from './device.js';
import {
  checkMembership,
  compareRoster,
  GROUP_SEEN_MAX,
  groupMessageBody,
  groupMessageHash,
  rosterClaim,
  rosterHash,
  type RosterClaim,
} from './groups.js';
import { Hub, type DirectoryEntry } from './hub.js';
import type { LinkGrant } from './linking.js';
import { Mailbox, MailboxError } from './mailbox.js';
import { manifestLists, verifiedManifest, type DeviceManifest } from './manifest.js';
import type {
  Contact,
  Group,
  GroupMember,
  MediaAttachment,
  Message,
  OutboxEntry,
  Parked,
} from './model.js';
import { statusRank } from './model.js';
import {
  EDIT_GRACE_MS,
  EDIT_WINDOW_MS,
  OPK_TARGET,
  PARKED_MAX,
  PARKED_TTL_MS,
  REPLY_PREVIEW_MAX,
  ROSTER_ANSWER_EVERY_MS,
  ROSTER_ASK_EVERY_MS,
  SEND_GIVE_UP_AFTER_MS,
  sendBackoffMs,
  SPK_ROTATE_MS,
  TYPING_REFRESH_MS,
  TYPING_TTL_MS,
} from './retry.js';
import { store, threadKey } from './store.js';
import { PinRefused, routeFor } from './transport.js';
import { isWireId, parseInner, sentAtMs, type Inner } from './wire.js';

export type { MediaAttachment, Message } from './model.js';

const PRIMARY_DEVICE = 1;

/**
 * An envelope whose processing failed for a reason that may pass — a blob
 * that cannot be fetched right now. Left un-acked, so the mailbox delivers
 * it again on the next connection, rather than dropped.
 */
export class TransientFailure extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TransientFailure';
  }
}

/** A send refused on grounds that retrying cannot change: a certificate or
 * prekey that does not verify, a directory answer that is not the owner's,
 * a device that is gone. */
export class Refused extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'Refused';
  }
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

function clipPreview(s: string): string {
  return s.length <= REPLY_PREVIEW_MAX ? s : `${s.slice(0, REPLY_PREVIEW_MAX)}…`;
}

/** Incoming `reply_to` → a display snapshot, or nothing. Cooperative display
 * data — never trusted beyond shape, and the preview is clipped again here. */
function replyFrom(payload: Record<string, unknown>): Message['replyTo'] | undefined {
  const r = payload['reply_to'];
  if (typeof r !== 'object' || r === null) return undefined;
  const id = (r as Record<string, unknown>)['id'];
  if (typeof id !== 'string' || id === '') return undefined;
  const sender = (r as Record<string, unknown>)['sender'];
  const preview = (r as Record<string, unknown>)['preview'];
  return {
    id,
    ...(typeof sender === 'string' ? { sender } : {}),
    ...(typeof preview === 'string' ? { preview: clipPreview(preview) } : {}),
  };
}

/** Expiry from the message's own payload — authoritative over the local
 * setting, so ordering races and offline queues cannot skew it. */
function expiresAtFrom(sentAt: string, payload: Record<string, unknown>): number | undefined {
  const after = payload['expire_after_ms'];
  return typeof after === 'number' && Number.isInteger(after) && after > 0
    ? sentAtMs(sentAt) + after
    : undefined;
}

/** The sender's avatar from a profile-bearing payload: absent means
 * unchanged, null cleared, else `{data, mime}` within the size receivers
 * accept (twice the 24 KiB senders scale to). */
function avatarFrom(
  payload: Record<string, unknown>,
): { data: string; mime: string } | null | undefined {
  if (!('avatar' in payload)) return undefined;
  const a = payload['avatar'];
  if (a === null) return null;
  if (typeof a !== 'object') return undefined;
  const data = (a as Record<string, unknown>)['data'];
  const mime = (a as Record<string, unknown>)['mime'];
  if (typeof data !== 'string' || typeof mime !== 'string' || !mime.startsWith('image/')) {
    return undefined;
  }
  if (data.length > 2 * 24 * 1024 * (4 / 3) + 4) return undefined;
  return { data, mime };
}

const log = (what: string): void => console.warn(`stonechat: ${what}`);

/** Envelope types that are a direct conversation with their sender. */
const DM_TYPES = new Set([
  'msg', 'media', 'contact_request', 'contact_accept', 'profile_update', 'receipt',
  'typing', 'msg_edit', 'msg_delete', 'reaction', 'timer_update',
  'call_offer', 'call_answer', 'call_ice', 'call_end',
]);

export class Protocol {
  /** Something rendered from the store changed: a message's status, a
   * contact's name, a group's roster, an expiry. The view re-reads. */
  onChange?: () => void;

  /**
   * A conversation was cleared on another of our devices.
   *
   * A cleared conversation is not a message, so it cannot come back through
   * `receive()` — this is how the view learns to drop what it is showing.
   */
  onConversationCleared?: (peerId: string, group: boolean) => void;

  /** A roster arrived or changed — the conversation list has new names. */
  onGroupsChanged?: () => void;

  /** Who is typing in a conversation (thread key → senders), after a change. */
  onTyping?: (key: string, who: string[]) => void;

  /** The phone renewed this session's certificate. */
  onCertRenewed?: () => void;

  /**
   * Call signaling from an accepted peer: `call_offer`, `call_answer`,
   * `call_ice`, `call_end`, with the envelope's `sent_at`. Set by
   * `calls.ts`; without it an offer is shown as a notice to answer on the
   * phone.
   */
  onCallSignal?: (
    from: string,
    type: string,
    payload: Record<string, unknown>,
    sentAt: string,
  ) => void | Promise<void>;

  private readonly directory = new Map<string, DirectoryEntry>();
  /** One mailbox connection per relay address — a peer's relay is reached the
   * same way our own is, and reusing the session across sends is most of the
   * cost of delivery. */
  private readonly mailboxes = new Map<string, Promise<Mailbox>>();
  /** A peer's device list, for this run. Dropped on a `devices_v` bump, a
   * 410, or a bundle token change. */
  private readonly deviceLists = new Map<string, number[]>();
  /** Identities whose directory record was read this run and carried no
   * manifest, so a stream of envelopes does not become a stream of lookups. */
  private readonly noManifestThisRun = new Set<string>();
  /** Peers whose manifest was refetched this run because their mailbox
   * listed a device the manifest did not. */
  private readonly manifestRefetched = new Set<string>();

  private readonly typing = new Map<string, Map<string, number>>();
  private readonly typingSentAt = new Map<string, number>();
  private typingSweep: ReturnType<typeof setTimeout> | null = null;
  private readonly rosterAsked = new Map<string, { version: number; at: number }>();
  private readonly rosterAnswered = new Map<string, number>();
  private readonly receiptQueue = new Map<string, Map<'delivered' | 'read', Set<string>>>();
  private receiptTimer: ReturnType<typeof setTimeout> | null = null;

  /** The in-flight self-sync, if any. Exposed through [whenSynced] because
   * fire-and-forget work is invisible to a test otherwise. */
  private syncing: Promise<void> = Promise.resolve();
  /** Receipts in flight, likewise. */
  private flushing: Promise<void> = Promise.resolve();

  private _grant: LinkGrant;

  /** Resolves once the last send's mirror to our own devices has finished. */
  whenSynced(): Promise<void> {
    return this.syncing.then(() => this.flushing);
  }

  constructor(
    private readonly core: StonechatCore,
    private readonly hub: Hub,
    private readonly keys: DeviceKeys,
    grant: LinkGrant,
    /** How to reach a relay. Overridden by the tests, which have no
     * WebTransport: the crypto is what needs proving, and it should be
     * provable without a browser. */
    private readonly dial: (entry: DirectoryEntry) => Promise<Mailbox> = async (
      entry,
    ) => Mailbox.open(routeFor(this.core, entry), ''),
    /** The clock, for tests of anything timed. */
    private readonly now: () => number = () => Date.now(),
    /** How long receipts are batched before they go. Null: only when asked
     * ([flushReceiptsNow]) — for tests, where a timer that fires later runs
     * against whatever storage is current by then. */
    private readonly receiptDelayMs: number | null = 2000,
  ) {
    this._grant = grant;
  }

  get grant(): LinkGrant {
    return this._grant;
  }
  get stonechatId(): string {
    return this._grant.stonechat_id;
  }
  get deviceId(): number {
    return this._grant.device_id;
  }

  private changed(): void {
    this.onChange?.();
  }

  // -- names ----------------------------------------------------------------

  /** How to label an identity: a name they told us, else the short ID. */
  nameOf(stonechatId: string): string {
    if (stonechatId === this.stonechatId) return 'you';
    const contact = store.contact(stonechatId);
    if (contact?.displayName) return contact.displayName;
    for (const group of Object.values(store.groups())) {
      const m = group.members.find((x) => x.stonechatId === stonechatId);
      if (m?.displayName) return m.displayName;
    }
    return stonechatId.replace(/^SC-/, '').slice(0, 9);
  }

  isBlocked(stonechatId: string): boolean {
    const at = store.contact(stonechatId)?.blockedAt;
    return typeof at === 'number';
  }

  /** An accepted contact: the only kind of person a message is rendered
   * from, a group invitation taken from, or a call answered from — as on
   * the phone, whose contact list reaches this browser over `sync_history`
   * at link time and `sync_contact` afterwards. */
  isContact(stonechatId: string): boolean {
    return store.contact(stonechatId)?.status === 'accepted';
  }

  // -- the contact list ---------------------------------------------------------

  /**
   * Add someone by ID: resolve them, record the request, send it, and tell
   * our other devices. Nothing is rendered from them until they accept.
   */
  async addContact(raw: string): Promise<Contact> {
    const id = this.core.normalizeId(raw);
    if (id === null) throw new Refused('That is not a Stonechat ID.');
    if (id === this.stonechatId) throw new Refused('That is your own ID.');
    const held = store.contact(id);
    if (held?.status === 'accepted') return held;
    if (held?.status === 'pendingIn') {
      await this.acceptContact(id);
      return store.contact(id)!;
    }
    const entry = await this.resolve(id);
    const contact: Contact = {
      ...(held ?? {}),
      stonechatId: id,
      pubkey: entry.pubkey,
      status: 'pendingOut',
    };
    store.setContact(contact);
    this.changed();
    void this.sync('sync_contact', this.contactSyncPayload(contact));
    await this.sendToPeer(id, 'contact_request', this.profilePayload());
    return contact;
  }

  /** Accept a request: tell them, and our other devices. */
  async acceptContact(stonechatId: string): Promise<void> {
    const held = store.contact(stonechatId);
    if (!held || held.status !== 'pendingIn') return;
    const contact: Contact = { ...held, status: 'accepted' };
    store.setContact(contact);
    this.changed();
    void this.sync('sync_contact', this.contactSyncPayload(contact));
    await this.sendToPeer(stonechatId, 'contact_accept', this.profilePayload()).catch(() => false);
  }

  /** Decline a request, or drop a contact: forgotten here and on our other
   * devices, with its sessions — a re-add does a fresh handshake. */
  async declineContact(stonechatId: string): Promise<void> {
    const held = store.contact(stonechatId);
    if (!held) return;
    void this.sync('sync_contact', this.contactSyncPayload(held, true));
    store.deleteContact(stonechatId);
    for (const d of this.deviceLists.get(stonechatId) ?? [1, 2, 3, 4]) {
      store.deleteSession(stonechatId, d);
    }
    this.deviceLists.delete(stonechatId);
    this.changed();
  }

  /** The contact as this browser holds it, for `sync_contact`. */
  private contactSyncPayload(contact: Contact, removed = false): Record<string, unknown> {
    return {
      peer: contact.stonechatId,
      pubkey: contact.pubkey,
      status: removed ? 'removed' : wireStatus(contact.status),
      ...(contact.displayName ? { display_name: contact.displayName } : {}),
      avatar: contact.avatar ?? null,
      ...(contact.bundleToken ? { bundle_token: contact.bundleToken } : {}),
    };
  }

  /** A sibling changed its contact list: do the same here. The key is
   * still checked against the ID, so a sibling cannot be made to plant one. */
  private applySyncContact(body: Record<string, unknown>): void {
    const peer = body['peer'];
    const pubkey = body['pubkey'];
    const status = body['status'];
    if (typeof peer !== 'string' || typeof pubkey !== 'string' || typeof status !== 'string') return;
    if (peer === this.stonechatId || !this.hashesTo(pubkey, peer)) return;
    const held = store.contact(peer);
    if (status === 'removed') {
      if (!held) return;
      store.deleteContact(peer);
      for (const d of this.deviceLists.get(peer) ?? [1, 2, 3, 4]) store.deleteSession(peer, d);
      this.deviceLists.delete(peer);
      this.changed();
      return;
    }
    const local = localStatus(status);
    if (local === null) return;
    const name = body['display_name'];
    const avatar = avatarFrom(body);
    const token = body['bundle_token'];
    const { status: _s, ...rest } = held ?? { stonechatId: peer, pubkey };
    void _s;
    store.setContact({
      ...rest,
      stonechatId: peer,
      pubkey,
      status: local,
      ...(typeof name === 'string' && name.trim() ? { displayName: name.trim() } : {}),
      ...(avatar !== undefined ? { avatar } : {}),
      ...(typeof token === 'string' && token ? { bundleToken: token } : {}),
    });
    if (typeof token === 'string' && token !== held?.bundleToken) this.deviceLists.delete(peer);
    this.changed();
  }

  /**
   * Our primary's export, for this freshly linked browser: contacts, blocks,
   * groups and text history, as the backup carries them (PROTOCOL.md
   * "History bootstrap"). Fetched from our own mailbox — and nowhere else —
   * with the capability in the payload, opened with the key beside it, and
   * merged under the backup's rule: what we already hold wins.
   */
  private async applySyncHistory(body: Record<string, unknown>): Promise<void> {
    const host = body['blob_host'];
    if (typeof host !== 'string' || host !== this._grant.relay_address) {
      log('sync_history blob is not on our own mailbox');
      return;
    }
    const bytes = await this.fetchSharedBytes(body, this.stonechatId);
    if (bytes === null) return; // gone, or tampered
    let payload: unknown;
    try {
      payload = JSON.parse(fromUtf8.decode(await gunzip(bytes)));
    } catch {
      log('sync_history payload does not parse');
      return;
    }
    if (typeof payload !== 'object' || payload === null) return;
    const p = payload as Record<string, unknown>;
    if (p['format'] !== 'stonechat-backup') return;
    const rows = (key: string): Array<Record<string, unknown>> =>
      Array.isArray(p[key]) ? p[key].filter((r): r is Record<string, unknown> => typeof r === 'object' && r !== null) : [];
    const merged = mergeBackup(
      {
        contacts: rows('contacts'),
        blocked: rows('blocked'),
        groups: rows('groups'),
        groupMembers: rows('group_members'),
        messages: rows('messages'),
        reactions: rows('reactions'),
      },
      this.stonechatId,
      (pubkey, id) => this.hashesTo(pubkey, id),
    );
    log(`bootstrapped from our primary: ${merged.contacts} contacts, ${merged.groups} groups, ${merged.messages} messages`);
    this.deviceLists.clear();
    this.onGroupsChanged?.();
    this.changed();
  }

  // -- our own mailbox ----------------------------------------------------

  private ownMailbox(): Promise<Mailbox> {
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
    opening.catch(() => this.mailboxes.delete(ownerId));
    return opening;
  }

  /** Drop a connection so the next request re-dials. */
  private forgetMailbox(ownerId: string): void {
    const held = this.mailboxes.get(ownerId);
    this.mailboxes.delete(ownerId);
    void held?.then((m) => m.close()).catch(() => {});
  }

  // -- resolving --------------------------------------------------------------

  /**
   * The identity key we hold for a peer, if any — a contact's, a group
   * member's (every roster entry was checked against its ID), or our own
   * from the grant. An ID commits to exactly one key, so for a peer we know
   * the directory is never asked for it again.
   */
  private heldIdentityKey(stonechatId: string): string | null {
    if (stonechatId === this.stonechatId) return this._grant.identity_pub;
    const held = store.contact(stonechatId)?.pubkey;
    if (held) return held;
    for (const group of Object.values(store.groups())) {
      const m = group.members.find((x) => x.stonechatId === stonechatId);
      if (m) return m.pubkey;
    }
    return null;
  }

  private hashesTo(pubkeyB64: string, stonechatId: string): boolean {
    try {
      return this.core.stonechatId(b64decode(pubkeyB64)) === stonechatId;
    } catch {
      return false;
    }
  }

  /** The identity key for a peer: what we hold, else the directory's. */
  private async identityKeyFor(stonechatId: string): Promise<Uint8Array> {
    const held = this.heldIdentityKey(stonechatId);
    if (held && this.hashesTo(held, stonechatId)) return b64decode(held);
    return b64decode((await this.resolve(stonechatId)).pubkey);
  }

  /**
   * A directory entry, checked to commit to the ID we asked for. Cached: a
   * lying hub can only produce a *failed* lookup, and only if someone checks.
   *
   * Also where the identity's device manifest is learned: a record whose
   * manifest does not verify is not the owner's record and is refused whole.
   */
  private async resolve(
    stonechatId: string,
    { refresh = false }: { refresh?: boolean } = {},
  ): Promise<DirectoryEntry> {
    const held = refresh ? undefined : this.directory.get(stonechatId);
    if (held) return held;
    const entry = await this.hub.directory(stonechatId);
    // Against the ID that was asked for, never the one in the answer: a hub
    // returning somebody else's complete record is internally consistent.
    if (
      entry.stonechat_id !== stonechatId ||
      !this.hashesTo(entry.pubkey, stonechatId)
    ) {
      throw new Refused(`the directory's key does not commit to ${stonechatId}`);
    }
    // For a peer we know, the key we hold is the key. A directory answering
    // with a different one for the same ID is lying — an ID commits to
    // exactly one key — and the check above would already have caught that,
    // but say so plainly rather than by accident.
    const known = this.heldIdentityKey(stonechatId);
    if (known && known !== entry.pubkey && this.hashesTo(known, stonechatId)) {
      throw new Refused(`the directory's key for ${stonechatId} is not the one held`);
    }
    const identityPub = b64decode(entry.pubkey);
    // The identity's X-Wing key is checked when present, as the app does.
    // Nothing is sealed to it, so a bad one costs the record, not a message.
    if (typeof entry.pq_pk === 'string' && typeof entry.pq_sig === 'string') {
      let ok = false;
      try {
        const pq = b64decode(entry.pq_pk);
        const sig = b64decode(entry.pq_sig);
        ok =
          pq.length === 1216 && sig.length === 64 &&
          this.core.verify(identityPub, utf8.encode('stonechat-v1-pqpk'), pq, sig);
      } catch {
        ok = false;
      }
      if (!ok) throw new Refused(`the directory's record for ${stonechatId} carries a bad pq_pk`);
    }
    const devices = (entry as unknown as Record<string, unknown>)['devices'];
    if (devices !== undefined && devices !== null) {
      const manifest = verifiedManifest(this.core, devices, stonechatId, identityPub);
      if (manifest === null) {
        throw new Refused(`the directory serves a device manifest ${stonechatId} did not sign`);
      }
      // Only forward: a directory serving an older manifest than the one we
      // hold is serving a stale one, and we keep ours.
      if (store.setManifest(stonechatId, manifest)) this.deviceLists.delete(stonechatId);
    } else {
      this.noManifestThisRun.add(stonechatId);
    }
    this.directory.set(stonechatId, entry);
    return entry;
  }

  // -- device manifests -------------------------------------------------------

  /**
   * The manifest we hold for an identity, fetching from the directory when
   * we hold none, or when `wanted` is a version above the one we hold. Null
   * when the identity has published none, or it cannot be fetched now.
   */
  private async manifestFor(stonechatId: string, wanted = 0): Promise<DeviceManifest | null> {
    const held = store.manifest(stonechatId);
    if (held && held.version >= wanted) return held;
    if (!held && this.noManifestThisRun.has(stonechatId)) return null;
    try {
      await this.resolve(stonechatId, { refresh: true });
    } catch {
      // Directory unreachable, or lying: judge by what we hold.
    }
    return store.manifest(stonechatId);
  }

  /** Our own manifest's version, as every envelope we send states it. */
  private get manifestV(): number {
    return store.manifest(this.stonechatId)?.version ?? 0;
  }

  /**
   * The devices of a peer we may encrypt to: those listed, narrowed to the
   * identity's manifest when it has one. A listed device that is not on the
   * manifest we hold has the manifest refetched once — it may have just been
   * linked — and is left out if it is still not there: a relay that keeps
   * serving a revoked device's certificate must not get that device a copy.
   */
  private async allowedDevices(peerId: string, listed: number[]): Promise<number[]> {
    let manifest = await this.manifestFor(peerId);
    if (manifest === null) return listed;
    const unlisted = (d: number): boolean => !(d in manifest!.devices);
    if (listed.some(unlisted) && !this.manifestRefetched.has(peerId)) {
      this.manifestRefetched.add(peerId);
      manifest = await this.manifestFor(peerId, manifest.version + 1);
      if (manifest === null) return listed;
    }
    const allowed: number[] = [];
    for (const d of listed) {
      const cert = store.peerCert(peerId, d);
      // Without a certificate the fan-out skips the device anyway; with one,
      // the key must be the listed one.
      if (!unlisted(d) && (cert === null || manifestLists(manifest, d, cert.sig_pub))) {
        allowed.push(d);
      } else {
        log(`device ${d} of ${peerId} is not in their manifest — not encrypting to it`);
      }
    }
    return allowed;
  }

  // -- certificates -----------------------------------------------------------

  /**
   * Verify a certificate against the peer's identity key and keep it.
   *
   * A certificate that does not verify is dropped silently: it is either a
   * mailbox serving something it was not given, or a device that is not this
   * peer's. Either way there is nothing to encrypt to.
   */
  private recordCert(
    peerId: string,
    device: number,
    cert: unknown,
    identityPub: Uint8Array,
  ): SignedCert | null {
    return this.checkCert(peerId, device, cert, identityPub).cert;
  }

  /** As [recordCert], saying why when it refuses. */
  private checkCert(
    peerId: string,
    device: number,
    cert: unknown,
    identityPub: Uint8Array,
  ): { cert: SignedCert | null; reason: string } {
    if (typeof cert !== 'object' || cert === null) {
      return { cert: null, reason: 'No certificate for that device — refusing to send.' };
    }
    const signed = cert as SignedCert;
    let status: string;
    try {
      status = this.core.devcertVerify(signed, identityPub, Math.floor(this.now() / 1000));
    } catch {
      status = 'malformed';
    }
    if (status !== 'valid') {
      log(`device ${device} of ${peerId}: certificate ${status} — not encrypting to it`);
      store.deletePeerCert(peerId, device);
      return { cert: null, reason: `Their certificate is ${status} — refusing to send.` };
    }
    if (signed.stonechat_id !== peerId) {
      // Genuine, and somebody else's. The signature only says an identity
      // vouched for this device; this is what says it was this peer's.
      log(`device ${device} of ${peerId}: certificate names another owner`);
      store.deletePeerCert(peerId, device);
      return { cert: null, reason: 'Their certificate names a different owner.' };
    }
    if (signed.device_id !== device) {
      // Signed and unexpired, but for a different device than the slot it
      // arrived in. A relay shuffling certificates between devices would
      // redirect mail, and the signature covers the id exactly so it can be
      // checked.
      log(`device ${device} of ${peerId}: certificate names another device`);
      return { cert: null, reason: 'Their certificate names a different device.' };
    }
    if (certSigKey(signed) === null || certSealKey(signed) === null) {
      return { cert: null, reason: 'Their certificate names no usable keys.' };
    }
    store.setPeerCert(peerId, device, signed);
    return { cert: signed, reason: '' };
  }

  /** The verified certificate we hold for a peer's device — null if none,
   * or if it has expired. */
  private heldCert(peerId: string, device: number): SignedCert | null {
    const cert = store.peerCert(peerId, device);
    if (cert === null) return null;
    const expiry = certExpiry(cert);
    if (expiry === null || expiry.getTime() <= this.now()) {
      store.deletePeerCert(peerId, device);
      return null;
    }
    return cert;
  }

  /** Which token lets us list a peer's devices: a contact's, a fellow
   * member's, or our own grant's for our siblings. */
  private bundleTokenFor(peerId: string): string | null {
    if (peerId === this.stonechatId) return this._grant.bundle_token ?? null;
    const contact = store.contact(peerId);
    if (contact?.bundleToken) return contact.bundleToken;
    for (const group of Object.values(store.groups())) {
      const m = group.members.find((x) => x.stonechatId === peerId);
      if (m?.bundleToken) return m.bundleToken;
    }
    return null;
  }

  /**
   * List a peer's devices with their certificates — one request, cached for
   * the run. Without a bundle token only the primary is reachable, which is
   * what a stranger sending a first message gets. Listing is an
   * optimisation, never a precondition: if it fails we still send to device 1.
   */
  private async listDevices(peerId: string, identityPub: Uint8Array): Promise<number[]> {
    const cached = this.deviceLists.get(peerId);
    if (cached) return cached;
    const token = this.bundleTokenFor(peerId);
    if (token === null) return [PRIMARY_DEVICE];
    try {
      const mailbox = await this.connect(peerId);
      const listed = await mailbox.json<{
        devices_v?: number;
        devices: Array<{ device_id: number; cert?: unknown }>;
      }>('GET', `/prekeys/devices?token=${encodeURIComponent(token)}`);
      const ids: number[] = [];
      for (const d of listed.devices) {
        if (!Number.isInteger(d.device_id) || d.device_id < 1) continue;
        ids.push(d.device_id);
        if (d.cert) this.recordCert(peerId, d.device_id, d.cert, identityPub);
      }
      if (typeof listed.devices_v === 'number') this.noteDevicesV(peerId, listed.devices_v);
      const result = ids.length ? ids : [PRIMARY_DEVICE];
      this.deviceLists.set(peerId, result);
      return result;
    } catch {
      // A listing we cannot fetch is not a reason to send nothing.
      return [PRIMARY_DEVICE];
    }
  }

  /** A peer's device set changed — drop the cached list so the next send
   * re-reads it, and remember the version we saw. */
  private noteDevicesV(peerId: string, devicesV: number): void {
    if (peerId === this.stonechatId) return;
    const contact = store.contact(peerId);
    const held = contact?.devicesV ?? 0;
    if (devicesV <= held) return;
    this.deviceLists.delete(peerId);
    if (contact) store.setContact({ ...contact, devicesV });
  }

  /**
   * The certificate for one of a peer's devices — the thing that says which
   * key to seal to, and which key their prekeys are signed with.
   *
   * Refetched when the one we hold is nearing expiry, rather than when it has
   * already lapsed. A stale-but-valid certificate beats refusing to send
   * because a refresh could not happen right now; an expired one is not
   * valid: a device whose certificate has run out is not encrypted to,
   * whatever its mailbox still lists.
   */
  private async certFor(
    peerId: string,
    device: number,
    identityPub: Uint8Array,
  ): Promise<SignedCert | null> {
    const held = store.peerCert(peerId, device);
    if (held !== null && !certNeedsRefresh(held, new Date(this.now()))) return held;
    const token = this.bundleTokenFor(peerId);
    try {
      if (token !== null) {
        this.deviceLists.delete(peerId);
        await this.listDevices(peerId, identityPub);
      } else if (device === PRIMARY_DEVICE) {
        // No token, so no device list — but a stranger sending a first
        // contact request still gets the primary's certificate off the open
        // bundle, which is exactly the reach they are meant to have.
        const mailbox = await this.connect(peerId);
        const bundle = await mailbox.json<{ cert?: unknown }>('GET', '/prekeys/bundle');
        if (bundle?.cert) this.recordCert(peerId, device, bundle.cert, identityPub);
      }
    } catch {
      // Unreachable mailbox — fall through to whatever we already hold.
    }
    return this.heldCert(peerId, device);
  }

  // -- prekeys ------------------------------------------------------------

  /**
   * Publish this device's prekeys, so peers can start sessions with it.
   *
   * Signed by the **device** key and published with the certificate that names
   * it — one without the other leaves a sender unable to check either. Signed
   * prekeys are replaced once a week, keeping the previous one so a handshake
   * in flight against it still completes; one-time pools are topped up to 32
   * of each kind, and the mailbox's store is **replaced** with what we hold.
   */
  async publishPrekeys(): Promise<void> {
    const now = this.now();
    let pool = store.prekeys();
    if (pool === null) {
      const spkPair = this.newX25519();
      const kspkSeed = randomBytes(64);
      pool = {
        spk: { id: 1, pub: spkPair.pub, sec: spkPair.sec, createdAt: now },
        kspk: {
          id: 2,
          pub: b64encode(this.core.mlkemPkFromSeed(kspkSeed)),
          seed: b64encode(kspkSeed),
          createdAt: now,
        },
        opks: {},
        kopks: {},
        nextId: 3,
      };
    }
    if (now - (pool.spk.createdAt ?? 0) > SPK_ROTATE_MS) {
      const { createdAt: _c, ...previous } = pool.spk;
      void _c;
      const pair = this.newX25519();
      pool.prevSpk = previous;
      pool.spk = { id: pool.nextId++, pub: pair.pub, sec: pair.sec, createdAt: now };
    }
    if (now - (pool.kspk.createdAt ?? 0) > SPK_ROTATE_MS) {
      const { createdAt: _c, ...previous } = pool.kspk;
      void _c;
      const seed = randomBytes(64);
      pool.prevKspk = previous;
      pool.kspk = {
        id: pool.nextId++,
        pub: b64encode(this.core.mlkemPkFromSeed(seed)),
        seed: b64encode(seed),
        createdAt: now,
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
    await mailbox.json('POST', `/prekeys?token=${encodeURIComponent(this._grant.device_token)}`, {
      spk: { id: pool.spk.id, pub: pool.spk.pub, sig: b64encode(sig) },
      opks: Object.entries(pool.opks).map(([id, o]) => ({ id: Number(id), pub: o.pub })),
      kspk: { id: pool.kspk.id, pub: pool.kspk.pub, sig: b64encode(ksig) },
      kopks: Object.entries(pool.kopks).map(([id, o]) => ({ id: Number(id), pub: o.pub })),
      cert: this._grant.cert,
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
   *
   * X3DH must run against *that device's* prekeys. The unauthenticated
   * bundle is device 1's by design, so anything else needs the bundle token.
   */
  private async sessionFor(
    peerId: string,
    device: number,
    identityPub: Uint8Array,
  ): Promise<SessionState> {
    const held = store.session(peerId, device);
    if (held && held['cks'] != null) return held;

    const mailbox = await this.connect(peerId);
    let path = '/prekeys/bundle';
    if (device !== PRIMARY_DEVICE) {
      const token = this.bundleTokenFor(peerId);
      if (token === null) {
        throw new Refused(`No bundle token for device ${device} — cannot start a session.`);
      }
      path = `/prekeys/bundle?device=${device}&token=${encodeURIComponent(token)}`;
    }
    const bundle = await mailbox.json<Record<string, unknown>>('GET', path);
    const { cert, reason } = this.checkCert(peerId, device, bundle['cert'], identityPub);
    if (cert === null) throw new Refused(reason);
    const deviceSigKey = certSigKey(cert)!;

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
      throw new Refused('Their mailbox served a forged prekey — refusing to send.');
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

  // -- sending: one envelope -----------------------------------------------

  /**
   * Encrypt, seal and deposit one envelope for one device.
   *
   * Throws `Refused` for what no retry fixes, `MailboxError` (410 included)
   * for what the mailbox said, and anything else for the network.
   */
  private async sendTo(
    peerId: string,
    device: number,
    id: string,
    sentAt: string,
    type: string,
    payload: Record<string, unknown>,
    opts: { blobId?: string; transient?: boolean; noPush?: boolean; ring?: boolean } = {},
  ): Promise<void> {
    const identityPub = await this.identityKeyFor(peerId);
    // Which key this device's mail is sealed to, from its certificate. No
    // certificate, or one that does not verify, means there is nothing to
    // encrypt to — skip it rather than falling back to the directory key,
    // which is exactly what certificates replaced.
    const state = await this.sessionFor(peerId, device, identityPub);
    const cert = await this.certFor(peerId, device, identityPub);
    const sealKey = cert ? certSealKey(cert) : null;
    if (!sealKey) throw new Refused('No usable certificate for that device.');

    // Both device numbers are bound, on every message. One form, no
    // conditional: this is the one place a second code path would mean silent
    // decryption failure. The core appends the ratchet header's fields.
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
    // Persist the advanced chain before the envelope can leave: a failure
    // after send must never reuse a message key.
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
      ...(this._grant.bundle_token ? { bundle_token: this._grant.bundle_token } : {}),
      manifest_v: this.manifestV,
    };
    if (opts.blobId) inner['blob_id'] = opts.blobId;
    if (pending) {
      // Our certificate travels with the handshake so the responder can trust
      // the device key inside it without fetching anything.
      inner['x3dh'] = { ...pending, cert: this._grant.cert };
    }

    const sealed = this.core.seal(
      sealKey,
      utf8.encode(JSON.stringify(inner)),
      randomBytes(XWING_ENCAPS_RANDOM),
      randomBytes(24),
    );
    const mailbox = await this.connect(peerId);
    try {
      const answer = await mailbox.json<{ devices_v?: number } | null>('POST', '/inbox', {
        v: 1,
        id,
        to: peerId,
        device,
        sealed: b64encode(sealed),
        // Outside the ciphertext on purpose: the relay cannot read the
        // payload, so this is how it knows the blob is still referenced. It
        // drops the blob when the last envelope naming it is acked.
        ...(opts.blobId ? { blob_id: opts.blobId } : {}),
        ...(opts.transient ? { transient: true } : {}),
        ...(opts.noPush ? { push: false } : {}),
        ...(opts.ring ? { ring: true } : {}),
      });
      if (answer && typeof answer.devices_v === 'number') {
        this.noteDevicesV(peerId, answer.devices_v);
      }
    } catch (e) {
      if (e instanceof MailboxError && e.status === 410) {
        // Revoked or never existed. Forget it and its ratchet; nobody is owed
        // a copy for a device that is gone.
        store.deleteSession(peerId, device);
        store.deletePeerCert(peerId, device);
        this.deviceLists.delete(peerId);
      }
      throw e;
    }
  }

  /**
   * Send one logical message to every device a peer has: k envelopes, each
   * on its own ratchet with its own associated data. Returns which devices
   * took it and which are still owed; throws only if nothing was reachable
   * at all, so a partial fan-out counts as sent — the devices that did take
   * it will show the message.
   */
  private async fanOut(
    peerId: string,
    id: string,
    sentAt: string,
    type: string,
    payload: Record<string, unknown>,
    opts: {
      blobId?: string;
      transient?: boolean;
      noPush?: boolean;
      ring?: boolean;
      /** Only devices we already hold a session with (typing). */
      existingOnly?: boolean;
      /** Narrow to these devices — a retry of what is still owed. */
      only?: number[];
    } = {},
  ): Promise<{ accepted: number[]; owed: number[]; error: unknown }> {
    const identityPub = await this.identityKeyFor(peerId);
    const listed = await this.listDevices(peerId, identityPub);
    const allowed = await this.allowedDevices(peerId, listed);
    const devices = opts.only ? allowed.filter((d) => opts.only!.includes(d)) : allowed;
    const accepted: number[] = [];
    const gone = new Set<number>();
    let error: unknown = null;
    for (const device of devices) {
      if (opts.existingOnly && store.session(peerId, device)?.['cks'] == null) continue;
      try {
        await this.sendTo(peerId, device, id, sentAt, type, payload, opts);
        accepted.push(device);
      } catch (e) {
        error = e;
        if (e instanceof MailboxError && e.status === 410) gone.add(device);
        // One device being unreachable must not stop its siblings getting
        // their copy — the same rule groups already follow for members.
      }
    }
    const owed = devices.filter((d) => !accepted.includes(d) && !gone.has(d));
    if (accepted.length === 0 && devices.length > 0 && !opts.existingOnly) {
      // Their mailbox may have moved, or its certificate schedule changed:
      // the next attempt re-reads the directory.
      this.directory.delete(peerId);
      this.forgetMailbox(peerId);
    }
    return { accepted, owed, error };
  }

  /** Deliver to a peer we know — contact or fellow member — on every device,
   * best-effort. Nothing is owed afterwards. */
  private async sendToPeer(
    peerId: string,
    type: string,
    payload: Record<string, unknown>,
    opts: { transient?: boolean; noPush?: boolean; ring?: boolean; existingOnly?: boolean } = {},
  ): Promise<boolean> {
    const r = await this.fanOut(
      peerId, crypto.randomUUID(), new Date(this.now()).toISOString(), type, payload, opts,
    );
    return r.accepted.length > 0 || r.owed.length === 0;
  }

  // -- sending: messages ------------------------------------------------------

  /** Who a conversation's message goes to: the peer, or every other member. */
  private recipientsOf(conversationId: string, group: boolean): string[] {
    if (!group) return [conversationId];
    const held = store.group(conversationId);
    if (!held || held.removed) return [];
    return held.members.map((m) => m.stonechatId).filter((id) => id !== this.stonechatId);
  }

  /**
   * Record a message as ours and start delivering it.
   *
   * The message is in the store, pending, before anything touches the
   * network: a send that fails is then a message that says so and is retried,
   * rather than text handed back to the composer to be lost on a reload.
   */
  private async startSend(
    message: Message,
    type: string,
    payload: Record<string, unknown>,
    blobId?: string,
  ): Promise<Message> {
    const group = message.group === true;
    const recipients = this.recipientsOf(message.peerId, group);
    store.appendMessage(message);
    const entry: OutboxEntry = {
      messageId: message.id,
      conversationId: message.peerId,
      group,
      type,
      payload,
      ...(blobId ? { blobId } : {}),
      owed: Object.fromEntries(recipients.map((r) => [r, []])),
      attempts: 0,
      lastAt: 0,
      since: this.now(),
    };
    store.setOutbox(entry);
    this.changed();
    const refused = await this.trySend(entry);
    // Nothing took it and nothing will: the message is in the ledger, marked
    // failed with the reason, and the caller hears it too.
    if (refused) throw refused;
    return store.findMessage(message.id)?.message ?? message;
  }

  /**
   * One attempt at everything still owed on an outbox entry. Settles the
   * message as sent once nobody is owed a copy; leaves it pending (with the
   * reason) otherwise, or failed when retrying could never help.
   */
  private async trySend(entry: OutboxEntry): Promise<Refused | null> {
    let lastError: unknown = null;
    let refused = false;
    let delivered = 0;
    for (const [peerId, devices] of Object.entries(entry.owed)) {
      if (this.isBlocked(peerId) && !entry.group) {
        delete entry.owed[peerId];
        continue;
      }
      try {
        const r = await this.fanOut(
          peerId, entry.messageId, this.sentAtOf(entry), entry.type, entry.payload,
          {
            ...(entry.blobId ? { blobId: entry.blobId } : {}),
            ...(devices.length ? { only: devices } : {}),
          },
        );
        delivered += r.accepted.length;
        if (r.owed.length === 0) delete entry.owed[peerId];
        else entry.owed[peerId] = r.owed;
        if (r.error) lastError = r.error;
        if (r.error instanceof Refused && r.accepted.length === 0) refused = true;
      } catch (e) {
        lastError = e;
        if (e instanceof Refused) refused = true;
      }
    }
    entry.attempts += 1;
    entry.lastAt = this.now();
    const done = Object.keys(entry.owed).length === 0;
    if (done) {
      store.deleteOutbox(entry.messageId);
      store.updateMessage(entry.messageId, (m) => {
        const { error: _e, ...rest } = m;
        void _e;
        return { ...rest, status: statusRank(m.status) > 1 ? (m.status ?? 'sent') : 'sent' };
      });
      this.changed();
      return null;
    }
    const reason = lastError instanceof Error ? lastError.message : 'unreachable';
    log(`send ${entry.messageId} still owed: ${reason}`);
    const terminal = refused || this.now() - entry.since >= SEND_GIVE_UP_AFTER_MS;
    if (terminal) store.deleteOutbox(entry.messageId);
    else store.setOutbox(entry);
    store.updateMessage(entry.messageId, (m) => ({
      ...m,
      // Some took it: it is sent as far as they are concerned, and still
      // pending for the rest — the ledger shows the worse of the two.
      status: terminal ? 'failed' : 'pending',
      error: reason,
    }));
    this.changed();
    return refused && delivered === 0 && lastError instanceof Refused ? lastError : null;
  }

  private sentAtOf(entry: OutboxEntry): string {
    return store.findMessage(entry.messageId)?.message.sentAt ?? new Date(entry.since).toISOString();
  }

  /** Whether anything is waiting to be retried. */
  hasPendingWork(): boolean {
    return Object.keys(store.outbox()).length > 0;
  }

  /**
   * Retry what is owed, with the app's backoff (30 s doubling to 30 min,
   * giving up after seven days). Called by the sweep and on reconnect.
   */
  async retryPending(): Promise<void> {
    const now = this.now();
    for (const entry of Object.values(store.outbox())) {
      if (now - entry.since >= SEND_GIVE_UP_AFTER_MS) {
        store.deleteOutbox(entry.messageId);
        store.updateMessage(entry.messageId, (m) => ({ ...m, status: 'failed', error: 'gave up after 7 days' }));
        this.changed();
        continue;
      }
      if (now - entry.lastAt < sendBackoffMs(entry.attempts)) continue;
      await this.trySend(entry);
    }
  }

  /** A manual retry of one message: the backoff is reset. */
  async retryMessage(messageId: string): Promise<void> {
    const found = store.findMessage(messageId);
    if (!found || !found.message.mine) return;
    let entry = store.outbox()[messageId];
    if (!entry) {
      // Gave up, or was refused: rebuild what the first attempt sent.
      const m = found.message;
      const group = m.group === true;
      const payload = m.media ? null : this.textPayload(m, group);
      if (payload === null) return; // media cannot be rebuilt: the bytes are gone
      entry = {
        messageId,
        conversationId: m.peerId,
        group,
        type: group ? 'group_msg' : 'msg',
        payload,
        owed: Object.fromEntries(this.recipientsOf(m.peerId, group).map((r) => [r, []])),
        attempts: 0,
        lastAt: 0,
        since: this.now(),
      };
    }
    entry.attempts = 0;
    entry.lastAt = 0;
    store.setOutbox(entry);
    store.updateMessage(messageId, (m) => ({ ...m, status: 'pending' }));
    this.changed();
    await this.trySend(entry);
  }

  // (a refused retry shows on the message; nothing to throw to)

  private textPayload(m: Message, group: boolean): Record<string, unknown> {
    const payload: Record<string, unknown> = group
      ? { group_id: m.peerId, text: m.text, ...this.groupExtras(m.peerId, m) }
      : { text: m.text };
    if (m.expiresAt) payload['expire_after_ms'] = m.expiresAt - sentAtMs(m.sentAt);
    if (m.replyTo) payload['reply_to'] = m.replyTo;
    return payload;
  }

  /** The `roster`, `salt` and `seen` fields of a group message. */
  private groupExtras(groupId: string, message: Message): Record<string, unknown> {
    const group = store.group(groupId);
    if (!group) return {};
    const salt = message.salt ?? b64encode(randomBytes(16));
    // What we have seen the others say since we last spoke here, so anyone
    // who was shown something else can tell (PROTOCOL.md "Transcript
    // consistency").
    const thread = store.messages()[threadKey(groupId, true)] ?? [];
    const seen: Array<{ id: string; h: string }> = [];
    for (let i = thread.length - 1; i >= 0 && seen.length < GROUP_SEEN_MAX; i--) {
      const m = thread[i]!;
      if (m.id === message.id) continue;
      if (m.mine && !m.notice) break;
      if (!m.mine && m.contentHash) seen.push({ id: m.id, h: m.contentHash });
    }
    return {
      roster: {
        v: group.version,
        ...(group.rosterHash ? { h: group.rosterHash } : {}),
        admin: group.admin,
      },
      salt,
      ...(seen.length ? { seen } : {}),
    };
  }

  private expiryFor(conversationId: string, group: boolean, sentAt: string): number | undefined {
    const ms = group
      ? store.group(conversationId)?.expireTimerMs
      : store.contact(conversationId)?.expireTimerMs;
    return ms && ms > 0 ? sentAtMs(sentAt) + ms : undefined;
  }

  private quoteOf(replyTo: Message | undefined): Message['replyTo'] | undefined {
    if (!replyTo) return undefined;
    const preview = replyTo.deleted
      ? 'message deleted'
      : replyTo.media
        ? replyTo.media.name ?? replyTo.media.kind
        : replyTo.text;
    return {
      id: replyTo.id,
      sender: replyTo.mine ? this.stonechatId : replyTo.sender ?? replyTo.peerId,
      preview: clipPreview(preview),
    };
  }

  /**
   * Send text to a peer — one envelope per device they have.
   *
   * Fan-out is not optional even here: a web session is device 2 or later,
   * so a reply that only ever went to device 1 would never reach the browser
   * it was answering. Which devices exist comes from their bundle token,
   * which rides every envelope they send us; without one we can reach only
   * their primary, which is exactly what a stranger's first message gets.
   */
  async send(peerId: string, text: string, opts: { replyTo?: Message } = {}): Promise<Message> {
    if (this.isBlocked(peerId)) throw new Refused('You have blocked this person.');
    this.typingSentAt.delete(threadKey(peerId, false));
    const id = crypto.randomUUID();
    const sentAt = new Date(this.now()).toISOString();
    const expiresAt = this.expiryFor(peerId, false, sentAt);
    const replyTo = this.quoteOf(opts.replyTo);
    const message: Message = {
      id, peerId, mine: true, text, sentAt, status: 'pending',
      ...(expiresAt ? { expiresAt } : {}),
      ...(replyTo ? { replyTo } : {}),
    };
    const payload = this.textPayload(message, false);
    const sent = await this.startSend(message, 'msg', payload);
    // Mirror it to our own other devices. Without this a message typed in the
    // browser never appears on the phone and vice versa: each device only sees
    // what a *peer* sent it, and our own outgoing messages have no other route.
    //
    // Not awaited: the message has already reached the person it was for, and
    // making the composer wait on a sibling that may be offline would be the
    // wrong trade. The promise is kept so tests can wait for it.
    void this.chain(() => this.syncSent(message, 'msg', payload));
    return sent;
  }

  /**
   * Send to a group.
   *
   * There is no group mailbox: a group message is N pairwise messages, one per
   * member per device, each sealed to that device exactly as a DM is. That is
   * what makes a group cost nothing server-side and also why a member we
   * cannot reach is an ordinary partial failure rather than a broken send.
   *
   * Needs the roster, so it only works for a group we have been told about.
   */
  async sendGroup(groupId: string, text: string, opts: { replyTo?: Message } = {}): Promise<Message> {
    const group = store.group(groupId);
    if (!group) {
      throw new Refused(
        'This browser has not been told who is in that group — send from your phone.',
      );
    }
    if (group.removed) throw new Refused('You are no longer in that group.');
    this.typingSentAt.delete(threadKey(groupId, true));
    const id = crypto.randomUUID();
    const sentAt = new Date(this.now()).toISOString();
    const expiresAt = this.expiryFor(groupId, true, sentAt);
    const replyTo = this.quoteOf(opts.replyTo);
    const message: Message = {
      id, peerId: groupId, mine: true, text, sentAt, group: true, status: 'pending',
      salt: b64encode(randomBytes(16)),
      ...(expiresAt ? { expiresAt } : {}),
      ...(replyTo ? { replyTo } : {}),
    };
    const payload = this.textPayload(message, true);
    const sent = await this.startSend(message, 'group_msg', payload);
    // Our own devices see it as a group message, keyed by group rather than
    // peer — the same shape the phone's _applySyncSent reads.
    void this.chain(() => this.syncSent(message, 'group_msg', payload));
    return sent;
  }

  /** Whether this browser knows enough about a group to send into it. Says
   * nothing about what kind of conversation an id names — that is the
   * conversation's own type, never a lookup. */
  knowsGroup(groupId: string): boolean {
    const group = store.group(groupId);
    return group !== null && !group.removed;
  }

  /**
   * Send an attachment to a peer.
   *
   * The blob is encrypted under a fresh key and parked on the *recipient's*
   * mailbox, exactly as the phone does it: one upload, then one envelope per
   * device carrying the key. The mailbox holds ciphertext it has no key for,
   * so parking it there costs the recipient storage and tells them nothing.
   */
  async sendMedia(peerId: string, file: File, opts: { replyTo?: Message } = {}): Promise<Message> {
    if (this.isBlocked(peerId)) throw new Refused('You have blocked this person.');
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
      (JSON.parse(fromUtf8.decode(uploaded.body)) as Record<string, unknown>)['blob_id'],
    );
    if (!isWireId(blobId)) throw new Error('Their mailbox returned a malformed blob id.');

    const id = crypto.randomUUID();
    const sentAt = new Date(this.now()).toISOString();
    const mime = file.type || 'application/octet-stream';
    const expiresAt = this.expiryFor(peerId, false, sentAt);
    const replyTo = this.quoteOf(opts.replyTo);
    const payload: Record<string, unknown> = {
      blob_id: blobId,
      key: b64encode(key),
      blob_nonce: b64encode(nonce),
      mime,
      kind: kindForMime(mime),
      size: bytes.length,
      name: file.name,
      ...(expiresAt ? { expire_after_ms: expiresAt - sentAtMs(sentAt) } : {}),
      ...(replyTo ? { reply_to: replyTo } : {}),
    };
    const message: Message = {
      id, peerId, mine: true, text: '', sentAt, status: 'pending',
      media: {
        // Our own copy comes from the bytes we just read, not from a fetch:
        // the blob we uploaded is on *their* mailbox and we hold no token for
        // it. This is also why an attachment we sent survives only as long as
        // this tab does.
        url: URL.createObjectURL(new Blob([bytes], { type: mime })),
        mime, kind: kindForMime(mime), size: bytes.length, name: file.name,
      },
      ...(expiresAt ? { expiresAt } : {}),
      ...(replyTo ? { replyTo } : {}),
    };
    const sent = await this.startSend(message, 'media', payload, blobId);
    // Mirror it to our own other devices, exactly as text is mirrored — but a
    // sibling cannot read the copy we just uploaded: that one lives on the
    // *recipient's* mailbox and we hold no token for it. So a second copy goes
    // on our own mailbox with a fetch token beside it, which is the same
    // shared-blob path group media uses (chat_state.dart `_syncSentMedia`).
    void this.chain(() => this.syncSentMedia(message, 'media', payload, bytes));
    return sent;
  }

  /**
   * Send an attachment to a group: **one blob, on our own mailbox, N
   * capability tokens' worth of reads** (PROTOCOL.md "Group media"), so the
   * upload is O(1) in members instead of O(N).
   */
  async sendGroupMedia(groupId: string, file: File, opts: { replyTo?: Message } = {}): Promise<Message> {
    const group = store.group(groupId);
    if (!group) throw new Refused('This browser has not been told who is in that group.');
    if (group.removed) throw new Refused('You are no longer in that group.');
    const bytes = new Uint8Array(await file.arrayBuffer());
    const shared = await this.shareBlob(bytes);

    const id = crypto.randomUUID();
    const sentAt = new Date(this.now()).toISOString();
    const mime = file.type || 'application/octet-stream';
    const expiresAt = this.expiryFor(groupId, true, sentAt);
    const replyTo = this.quoteOf(opts.replyTo);
    const message: Message = {
      id, peerId: groupId, mine: true, text: '', sentAt, group: true, status: 'pending',
      salt: b64encode(randomBytes(16)),
      media: {
        url: URL.createObjectURL(new Blob([bytes], { type: mime })),
        mime, kind: kindForMime(mime), size: bytes.length, name: file.name,
      },
      ...(expiresAt ? { expiresAt } : {}),
      ...(replyTo ? { replyTo } : {}),
    };
    const payload: Record<string, unknown> = {
      group_id: groupId,
      ...this.groupExtras(groupId, message),
      ...shared,
      mime,
      kind: kindForMime(mime),
      size: bytes.length,
      name: file.name,
      ...(expiresAt ? { expire_after_ms: expiresAt - sentAtMs(sentAt) } : {}),
      ...(replyTo ? { reply_to: replyTo } : {}),
    };
    // The outer envelope carries no blob_id: the blob is on *our* mailbox, so
    // a member's ack must not try to garbage-collect it from theirs.
    const sent = await this.startSend(message, 'group_media', payload);
    // Group media already sits on our own mailbox behind a capability token,
    // so the same payload is what our siblings fetch from.
    void this.chain(() => this.syncSent(message, 'group_media', payload));
    return sent;
  }

  /** Park an encrypted copy on our own mailbox with a fetch token: the
   * fields a `group_media` (or a synced DM media) payload carries. */
  private async shareBlob(bytes: Uint8Array): Promise<Record<string, string>> {
    const key = randomBytes(32);
    const nonce = randomBytes(24);
    const own = await this.ownMailbox();
    // `?shared=1` is what returns a fetch token: a member or sibling holds no
    // owner token for this mailbox, and a per-blob capability is all it needs.
    const parked = await own.request('POST', '/blob?shared=1', this.core.blobSeal(key, nonce, bytes));
    if (parked.status < 200 || parked.status >= 300) {
      throw new Error(
        parked.status === 413
          ? 'That file is too large for a mailbox.'
          : `Could not upload the attachment (${parked.status}).`,
      );
    }
    const body = JSON.parse(fromUtf8.decode(parked.body)) as Record<string, unknown>;
    const blobId = String(body['blob_id']);
    if (!isWireId(blobId)) throw new Error('Our mailbox returned a malformed blob id.');
    return {
      blob_id: blobId,
      key: b64encode(key),
      blob_nonce: b64encode(nonce),
      fetch_token: String(body['fetch_token'] ?? ''),
      // Where to fetch it and which pinned certificate to expect — our own
      // mailbox, as the grant names it.
      blob_host: this._grant.relay_address,
      blob_tls_fp: this._grant.relay_tls_fp,
    };
  }

  // -- calls (PROTOCOL.md "Calls") -----------------------------------------------

  /** One call-signaling envelope on the pairwise session, to every device
   * of the peer. Used only by `calls.ts`; delivery failures propagate so the
   * call fails fast. */
  async sendCallSignal(
    peerId: string,
    type: string,
    payload: Record<string, unknown>,
    opts: { transient?: boolean; noPush?: boolean; ring?: boolean } = {},
  ): Promise<void> {
    if (this.isBlocked(peerId)) throw new Refused('You have blocked this person.');
    const r = await this.fanOut(
      peerId, crypto.randomUUID(), new Date(this.now()).toISOString(), type, payload, opts,
    );
    if (r.accepted.length === 0 && !opts.transient) {
      throw r.error instanceof Error ? r.error : new Error('Could not reach any of their devices.');
    }
  }

  /** A call's epitaph in the conversation. Local-only bookkeeping — both
   * sides write their own — so no receipt is queued for it. */
  recordCallEvent(peerId: string, label: string, mine: boolean): void {
    const added = store.appendMessage({
      id: crypto.randomUUID(), peerId, mine, text: label, notice: true, call: true,
      sentAt: new Date(this.now()).toISOString(), status: 'read',
    });
    if (added) this.changed();
  }

  /**
   * Our own mailbox's TURN credentials, when it runs a relay — plus nothing
   * else: either side's relay candidates can carry the call, so a client
   * only needs its own. Null when the mailbox serves no TURN (404) or
   * cannot be asked right now: TURN is an upgrade, never a blocker.
   */
  async turnCredentials(): Promise<{ urls: string[]; username: string; credential: string } | null> {
    try {
      const mailbox = await this.ownMailbox();
      const got = await mailbox.request(
        'GET',
        `/turn-credentials?token=${encodeURIComponent(this._grant.device_token)}`,
      );
      if (got.status !== 200) return null;
      const j = JSON.parse(fromUtf8.decode(got.body)) as Record<string, unknown>;
      const urls = Array.isArray(j['urls']) ? j['urls'].filter((u): u is string => typeof u === 'string') : [];
      if (!urls.length || typeof j['username'] !== 'string' || typeof j['credential'] !== 'string') return null;
      return { urls, username: j['username'], credential: j['credential'] };
    } catch {
      return null;
    }
  }

  // -- edits, deletes, reactions, timers ------------------------------------------

  canEdit(m: Message): boolean {
    return m.mine && !m.deleted && !m.media && !m.notice &&
      this.now() - sentAtMs(m.sentAt) < EDIT_WINDOW_MS;
  }

  canDeleteForEveryone(m: Message): boolean {
    return m.mine && !m.deleted && !m.notice && this.now() - sentAtMs(m.sentAt) < EDIT_WINDOW_MS;
  }

  /** Edit one of our text messages. Returns false when some recipient could
   * not be told — they keep the old text (best-effort tier, like the app). */
  async editMessage(message: Message, newText: string): Promise<boolean> {
    const text = newText.trim();
    if (!this.canEdit(message) || text === '' || text === message.text) return false;
    const group = message.group === true;
    const editedAt = this.now();
    store.updateMessage(message.id, (m) => ({ ...m, text, editedAt }));
    // A message still in the outbox is rewritten before first delivery.
    const pending = store.outbox()[message.id];
    if (pending) {
      pending.payload = { ...pending.payload, text };
      store.setOutbox(pending);
    }
    this.changed();
    const payload = group
      ? { group_id: message.peerId, id: message.id, text }
      : { id: message.id, text };
    const type = group ? 'group_msg_edit' : 'msg_edit';
    let everyone = true;
    for (const peer of this.recipientsOf(message.peerId, group)) {
      if (!(await this.sendToPeer(peer, type, payload).catch(() => false))) everyone = false;
    }
    void this.sync('sync_sent', {
      ...(group ? { group_id: message.peerId } : { peer: message.peerId }),
      type, payload, id: crypto.randomUUID(), sent_at: editedAt,
    });
    return everyone;
  }

  /** Delete for everyone: a tombstone here, a `msg_delete` to each
   * recipient. Cooperative, not cryptographic. */
  async deleteForEveryone(message: Message): Promise<boolean> {
    if (!this.canDeleteForEveryone(message)) return false;
    const group = message.group === true;
    store.deleteOutbox(message.id);
    this.tombstone(message.id);
    const payload = group ? { group_id: message.peerId, id: message.id } : { id: message.id };
    const type = group ? 'group_msg_delete' : 'msg_delete';
    let everyone = true;
    for (const peer of this.recipientsOf(message.peerId, group)) {
      if (!(await this.sendToPeer(peer, type, payload).catch(() => false))) everyone = false;
    }
    return everyone;
  }

  /** Delete here only. The store forgets it; nobody is told. */
  deleteForMe(message: Message): void {
    store.deleteOutbox(message.id);
    store.removeMessages(new Set([message.id]));
    this.changed();
  }

  private tombstone(id: string): void {
    store.updateMessage(id, (m) => {
      const { media: _media, replyTo: _r, reactions: _x, ...rest } = m;
      void _media; void _r; void _x;
      return { ...rest, text: '', deleted: true };
    });
    this.changed();
  }

  myReactionTo(message: Message): string {
    const live = store.findMessage(message.id)?.message ?? message;
    return live.reactions?.[this.stonechatId] ?? '';
  }

  /** Set (or, with the same emoji again, clear) our reaction. One per
   * person per message; a new one replaces the old. */
  async react(message: Message, emoji: string): Promise<void> {
    if (message.deleted || message.notice) return;
    const group = message.group === true;
    if (!group && this.isBlocked(message.peerId)) return;
    if (emoji.length > 32) return;
    const applied = this.myReactionTo(message) === emoji ? '' : emoji;
    this.recordReaction(message.id, this.stonechatId, applied);
    const payload = group
      ? { group_id: message.peerId, id: message.id, emoji: applied }
      : { id: message.id, emoji: applied };
    const type = group ? 'group_reaction' : 'reaction';
    for (const peer of this.recipientsOf(message.peerId, group)) {
      await this.sendToPeer(peer, type, payload).catch(() => false);
    }
  }

  private recordReaction(messageId: string, who: string, emoji: string): void {
    store.updateMessage(messageId, (m) => {
      const reactions = { ...(m.reactions ?? {}) };
      if (emoji === '') delete reactions[who];
      else reactions[who] = emoji;
      return { ...m, reactions };
    });
    this.changed();
  }

  /** The disappearing-messages timer of a conversation (0 = off). */
  expireTimerOf(conversationId: string, group: boolean): number {
    return (group ? store.group(conversationId)?.expireTimerMs : store.contact(conversationId)?.expireTimerMs) ?? 0;
  }

  /** Set a conversation's timer: ours to set in a DM, any member's in a
   * group. The other side learns over `timer_update` / `group_timer_update`. */
  async setExpireTimer(conversationId: string, group: boolean, expireMs: number): Promise<void> {
    if (!Number.isInteger(expireMs) || expireMs < 0) return;
    const at = this.now();
    if (group) {
      if (!store.group(conversationId)) return;
      store.patchGroup(conversationId, { expireTimerMs: expireMs, expireTimerAt: at });
    } else {
      const contact = store.contact(conversationId) ?? { stonechatId: conversationId, pubkey: '' };
      store.setContact({ ...contact, expireTimerMs: expireMs, expireTimerAt: at });
    }
    this.notice(conversationId, group, timerNoticeText('You', expireMs), `timer-${at}`);
    const payload = group
      ? { group_id: conversationId, expire_ms: expireMs }
      : { expire_ms: expireMs };
    for (const peer of this.recipientsOf(conversationId, group)) {
      await this.sendToPeer(peer, group ? 'group_timer_update' : 'timer_update', payload).catch(() => false);
    }
  }

  /** Delete every message whose time has come. Called by the sweep. */
  sweepExpired(): void {
    const now = this.now();
    const gone = new Set<string>();
    for (const thread of Object.values(store.messages())) {
      for (const m of thread) if (m.expiresAt !== undefined && m.expiresAt <= now) gone.add(m.id);
    }
    if (gone.size === 0) return;
    for (const id of gone) store.deleteOutbox(id);
    store.removeMessages(gone);
    this.changed();
  }

  /** The soonest expiry held, or null. */
  nextExpiry(): number | null {
    let next: number | null = null;
    for (const thread of Object.values(store.messages())) {
      for (const m of thread) {
        if (m.expiresAt !== undefined && (next === null || m.expiresAt < next)) next = m.expiresAt;
      }
    }
    return next;
  }

  // -- read state and receipts --------------------------------------------------

  /**
   * The conversation is on screen: mark its incoming messages read, tell the
   * sender (when the setting allows), and tell our own devices.
   *
   * Read on this device is read everywhere — it is also what stops a sibling
   * notifying about a message we have already seen. Unconditional, unlike
   * the peer-facing receipt: the setting is about what the *peer* learns.
   */
  markRead(conversationId: string, group: boolean): void {
    const thread = store.messages()[threadKey(conversationId, group)] ?? [];
    const read: string[] = [];
    const sendRead = store.settings().sendReadReceipts !== false;
    for (const m of thread) {
      if (m.mine || m.notice || m.status === 'read') continue;
      store.updateMessage(m.id, (x) => ({ ...x, status: 'read' }));
      read.push(m.id);
      if (sendRead) this.queueReceipt(m.sender ?? conversationId, 'read', m.id);
    }
    if (read.length === 0) return;
    this.changed();
    void this.sync('sync_read', {
      ...(group ? { group_id: conversationId } : { peer: conversationId }),
      ids: read,
    });
  }

  private queueReceipt(peerId: string, kind: 'delivered' | 'read', messageId: string): void {
    // A blocked peer gets nothing from us — not even checkmarks.
    if (this.isBlocked(peerId) || peerId === this.stonechatId) return;
    const byKind = this.receiptQueue.get(peerId) ?? new Map();
    const ids = byKind.get(kind) ?? new Set<string>();
    ids.add(messageId);
    byKind.set(kind, ids);
    this.receiptQueue.set(peerId, byKind);
    if (this.receiptDelayMs === null) return;
    this.receiptTimer ??= setTimeout(() => {
      this.receiptTimer = null;
      this.flushing = this.flushReceipts();
    }, this.receiptDelayMs);
  }

  private async flushReceipts(): Promise<void> {
    const batch = new Map(this.receiptQueue);
    this.receiptQueue.clear();
    for (const [peer, byKind] of batch) {
      for (const [kind, ids] of byKind) {
        // Never wake their phone for a checkmark.
        await this.sendToPeer(peer, 'receipt', { kind, ids: [...ids] }, { noPush: true })
          .catch(() => false);
      }
    }
  }

  /** Flush receipts now rather than after the batching delay (tests). */
  async flushReceiptsNow(): Promise<void> {
    if (this.receiptTimer) {
      clearTimeout(this.receiptTimer);
      this.receiptTimer = null;
    }
    await this.flushReceipts();
  }

  /**
   * A peer told us which of our messages reached their screen. Statuses only
   * move forward; group messages advance when *every* current member is
   * there.
   */
  private applyReceipt(from: string, payload: Record<string, unknown>): void {
    const kind = payload['kind'];
    if (kind !== 'delivered' && kind !== 'read') return;
    const ids = Array.isArray(payload['ids']) ? payload['ids'].filter((x): x is string => typeof x === 'string') : [];
    let touched = false;
    for (const id of ids) {
      const found = store.findMessage(id);
      if (!found || !found.message.mine) continue;
      const m = found.message;
      let next: Message['status'] | null = null;
      if (!m.group) {
        // A DM receipt is only valid from the person the message went to.
        if (m.peerId !== from) continue;
        next = kind;
      } else {
        const group = store.group(m.peerId);
        if (!group || !group.members.some((x) => x.stonechatId === from)) continue;
        store.setReceipt(id, from, kind);
        const others = group.members.filter((x) => x.stonechatId !== this.stonechatId).map((x) => x.stonechatId);
        if (others.length === 0) continue;
        const receipts = store.receipts(id);
        if (others.every((o) => receipts[o] === 'read')) next = 'read';
        else if (others.every((o) => receipts[o] !== undefined)) next = 'delivered';
      }
      if (next === null || statusRank(next) <= statusRank(m.status)) continue;
      store.updateMessage(id, (x) => ({ ...x, status: next! }));
      touched = true;
    }
    if (touched) this.changed();
  }

  // -- typing ---------------------------------------------------------------------

  /** Who is typing in a conversation right now. */
  typersIn(key: string): string[] {
    const now = this.now();
    return [...(this.typing.get(key) ?? new Map())].filter(([, until]) => until > now).map(([who]) => who);
  }

  /** The user is typing: say so, at most once per ~8 s, on sessions that
   * already exist — a typing hint is never worth a handshake. */
  notifyTyping(conversationId: string, group: boolean): void {
    const key = threadKey(conversationId, group);
    const last = this.typingSentAt.get(key) ?? 0;
    if (this.now() - last < TYPING_REFRESH_MS) return;
    this.typingSentAt.set(key, this.now());
    void this.sendTypingState(conversationId, group, 'started');
  }

  stopTyping(conversationId: string, group: boolean): void {
    const key = threadKey(conversationId, group);
    if (!this.typingSentAt.has(key)) return;
    this.typingSentAt.delete(key);
    void this.sendTypingState(conversationId, group, 'stopped');
  }

  private async sendTypingState(conversationId: string, group: boolean, state: 'started' | 'stopped'): Promise<void> {
    const payload = group ? { group_id: conversationId, state } : { state };
    for (const peer of this.recipientsOf(conversationId, group)) {
      if (this.isBlocked(peer)) continue;
      // fire-and-forget: a lost typing signal costs nothing
      await this.sendToPeer(peer, 'typing', payload, { transient: true, existingOnly: true }).catch(() => false);
    }
  }

  private applyTyping(inner: Inner, payload: Record<string, unknown>): void {
    const groupId = payload['group_id'];
    let key: string;
    if (typeof groupId === 'string') {
      const group = store.group(groupId);
      if (!group || !group.members.some((m) => m.stonechatId === inner.from)) return;
      key = threadKey(groupId, true);
    } else {
      if (!this.isContact(inner.from)) return;
      key = threadKey(inner.from, false);
    }
    const now = this.now();
    // Transient envelopes only arrive live, but guard against clock skew.
    if (Math.abs(now - sentAtMs(inner.sentAt)) > 60 * 1000) return;
    const who = this.typing.get(key) ?? new Map<string, number>();
    if (payload['state'] === 'started') {
      who.set(inner.from, now + TYPING_TTL_MS);
      this.scheduleTypingSweep();
    } else {
      who.delete(inner.from);
    }
    this.typing.set(key, who);
    this.onTyping?.(key, this.typersIn(key));
  }

  private scheduleTypingSweep(): void {
    this.typingSweep ??= setTimeout(() => {
      this.typingSweep = null;
      const now = this.now();
      let more = false;
      for (const [key, who] of this.typing) {
        let changed = false;
        for (const [id, until] of who) {
          if (until <= now) {
            who.delete(id);
            changed = true;
          }
        }
        if (changed) this.onTyping?.(key, this.typersIn(key));
        if (who.size > 0) more = true;
      }
      if (more) this.scheduleTypingSweep();
    }, 5000);
  }

  // -- self-sync ----------------------------------------------------------------

  /** Our own devices, excluding this one. */
  private async siblingDevices(): Promise<number[]> {
    const token = this._grant.bundle_token;
    if (!token) return [];
    try {
      const listed = await this.listDevices(this.stonechatId, b64decode(this._grant.identity_pub));
      return listed.filter((d) => d !== this.deviceId);
    } catch {
      return [];
    }
  }

  /** Run a mirror to our own devices behind whatever is already being
   * mirrored, so [whenSynced] covers it. Never called from inside one: a
   * mirror queued behind itself never runs. */
  private chain(work: () => Promise<void>): Promise<void> {
    this.syncing = this.syncing.then(work).catch(() => {});
    return this.syncing;
  }

  private sync(type: string, payload: Record<string, unknown>): Promise<void> {
    return this.chain(() => this.syncToSiblings(type, payload));
  }

  /** Mirror something to our own other devices. Best-effort, `push: false`
   * throughout — our own laptop catching up is never worth lighting up our
   * own phone. */
  private async syncToSiblings(type: string, payload: Record<string, unknown>): Promise<void> {
    const siblings = await this.siblingDevices();
    if (siblings.length === 0) return;
    const allowed = await this.allowedDevices(this.stonechatId, siblings);
    const id = crypto.randomUUID();
    const sentAt = new Date(this.now()).toISOString();
    for (const device of allowed) {
      try {
        await this.sendTo(this.stonechatId, device, id, sentAt, type, payload, { noPush: true });
      } catch {
        // A device that is gone or unreachable is not this send's problem.
      }
    }
  }

  /** A message we just sent should appear on our other devices too. */
  private syncSent(message: Message, type: string, payload: Record<string, unknown>): Promise<void> {
    return this.syncToSiblings('sync_sent', {
      ...(message.group ? { group_id: message.peerId } : { peer: message.peerId }),
      type,
      payload,
      id: message.id,
      // Milliseconds, matching what the app's `_applySyncSent` reads. The
      // outer envelope carries ISO; this inner field does not.
      sent_at: sentAtMs(message.sentAt),
    });
  }

  /**
   * Mirror an outgoing DM attachment to our own other devices.
   *
   * A sibling copy that cannot be parked means no sync at all — the phone's
   * rule too, since a sync naming a blob nobody can fetch renders as an
   * attachment that never loads.
   */
  private async syncSentMedia(
    message: Message,
    type: string,
    payload: Record<string, unknown>,
    bytes: Uint8Array,
  ): Promise<void> {
    if ((await this.siblingDevices()).length === 0) return;
    let shared: Record<string, string>;
    try {
      shared = await this.shareBlob(bytes);
    } catch {
      return;
    }
    await this.syncSent(message, type, { ...payload, ...shared });
  }

  /** A message one of our own devices sent, mirrored to us. */
  private async fromSyncSent(inner: Inner, payload: Record<string, unknown>): Promise<Message | null> {
    const groupId = payload['group_id'];
    const inGroup = groupId !== undefined && groupId !== null;
    const peerId = inGroup ? groupId : payload['peer'];
    const body = payload['payload'] as Record<string, unknown> | undefined;
    const id = payload['id'];
    if (typeof peerId !== 'string' || !peerId || !body || typeof id !== 'string') return null;
    const type = String(payload['type'] ?? 'msg');
    const sentAt =
      typeof payload['sent_at'] === 'number'
        ? new Date(payload['sent_at']).toISOString()
        : inner.sentAt;

    // Edits, deletes and reactions made on another of our devices.
    if (type === 'msg_edit' || type === 'group_msg_edit') {
      const target = body['id'];
      const text = body['text'];
      if (typeof target === 'string' && typeof text === 'string' && text.trim() !== '') {
        store.updateMessage(target, (m) => (m.mine && !m.deleted ? { ...m, text, editedAt: sentAtMs(sentAt) } : m));
        this.changed();
      }
      return null;
    }
    if (type === 'msg_delete' || type === 'group_msg_delete') {
      if (typeof body['id'] === 'string') this.tombstone(body['id']);
      return null;
    }

    // The kind of conversation and the kind of message have to agree, and a
    // group has to be one we hold a roster for — the same rule a member's
    // message meets, so a thread never exists for a group the list cannot
    // show.
    const groupType = type === 'group_msg' || type === 'group_media';
    if (groupType !== inGroup) return null;
    if (inGroup && !this.groupFor(peerId, this.stonechatId)) return null;
    if (!isWireId(id)) return null;
    const kind = inGroup ? { group: true as const } : {};
    const expiresAt = expiresAtFrom(sentAt, body);
    const replyTo = replyFrom(body);
    const base = {
      id, peerId, mine: true as const, sentAt, status: 'sent' as const, ...kind,
      ...(expiresAt ? { expiresAt } : {}),
      ...(replyTo ? { replyTo } : {}),
    };
    if (type === 'media' || type === 'group_media') {
      // The sending device parked a copy on *our own* mailbox precisely so a
      // sibling could fetch it — that is what the fetch token in the payload
      // opens (chat_state.dart `_syncSentMedia`). Gone or unreadable: the
      // message still renders, without the file.
      const media = await this.fetchSharedMedia(body, this.stonechatId).catch(() => undefined);
      return { ...base, text: '', media: media ?? describeMedia(body) };
    }
    if (type !== 'msg' && type !== 'group_msg') return null;
    if (typeof body['text'] !== 'string') return null;
    return { ...base, text: body['text'] };
  }

  /** The primary renewed this device's certificate: adopt it if it is ours,
   * later than the one held, and republish prekeys under it. */
  private async applySyncCert(payload: Record<string, unknown>): Promise<void> {
    const cert = payload['cert'];
    if (typeof cert !== 'object' || cert === null) return;
    const signed = cert as SignedCert;
    const identityPub = b64decode(this._grant.identity_pub);
    let status: string;
    try {
      status = this.core.devcertVerify(signed, identityPub, Math.floor(this.now() / 1000));
    } catch {
      return;
    }
    if (status !== 'valid' || signed.stonechat_id !== this.stonechatId || signed.device_id !== this.deviceId) {
      log('renewed certificate is not for this device');
      return;
    }
    const sig = certSigKey(signed);
    const seal = certSealKey(signed);
    if (
      sig === null || seal === null ||
      b64encode(sig) !== b64encode(this.keys.sigPublic) ||
      b64encode(seal) !== b64encode(this.keys.sealPublic)
    ) {
      log('renewed certificate names other keys');
      return;
    }
    const held = certExpiry(this._grant.cert);
    const renewed = certExpiry(signed);
    if (renewed === null || (held !== null && renewed.getTime() <= held.getTime())) return;
    this._grant = { ...this._grant, cert: signed };
    store.setGrant(this._grant);
    this.onCertRenewed?.();
    try {
      await this.publishPrekeys();
    } catch {
      // Republished on the next connect.
    }
  }

  // -- groups -----------------------------------------------------------------

  /**
   * The group a group-scoped envelope may be applied to, or null.
   *
   * One rule for every group type: the group is one we hold a roster for, and
   * the authenticated sender is in that roster now (PROTOCOL.md "Groups").
   */
  private groupFor(groupId: unknown, from: string): Group | null {
    if (typeof groupId !== 'string') return null;
    const group = store.group(groupId);
    if (!group || group.removed) return null;
    return group.members.some((m) => m.stonechatId === from) ? group : null;
  }

  private memberOf(group: Group, stonechatId: string): GroupMember | null {
    return group.members.find((m) => m.stonechatId === stonechatId) ?? null;
  }

  private hashB64 = (data: Uint8Array): string => b64encode(this.core.tlsFingerprint(data));

  /** Whether we would take a group invitation from this sender: our own
   * identity (a device mirroring a group it administers) or an accepted
   * contact, as on the phone. Other members may be strangers; the person
   * who adds us may not. */
  private senderIsContact(from: string): boolean {
    if (from === this.stonechatId) return true;
    if (this.isBlocked(from)) return false;
    return this.isContact(from);
  }

  /**
   * `group_create` / `group_update`: full-state replacement of a roster.
   *
   * Only the admin's word counts — the admin on record for a group we hold,
   * the one it names on first sight, and from an accepted contact — versions
   * only move forward, and every member key must hash to the ID it is listed
   * under. One that does not rejects the roster whole, since a roster applied
   * in part is one nobody sent. A roster from the admin on record naming
   * another member as admin is a handover.
   */
  private async applyMembership(inner: Inner, body: Record<string, unknown>): Promise<void> {
    const from = inner.from;
    const id = body['group_id'];
    const admin = body['admin'];
    const name = body['name'];
    const version = body['version'];
    const members = body['members'];
    if (
      typeof id !== 'string' || typeof admin !== 'string' || typeof name !== 'string' ||
      typeof version !== 'number' || !Number.isSafeInteger(version) || !Array.isArray(members)
    ) {
      return;
    }
    // The id becomes a conversation key beside contacts' Stonechat IDs: a
    // "group" named after a contact would capture what is typed to them.
    if (!isWireId(id)) return;
    if (members.length > 100) return; // before any key work

    const held = store.group(id);
    const roster: GroupMember[] = [];
    let includesUs = false;
    for (const raw of members as unknown[]) {
      if (typeof raw !== 'object' || raw === null) return;
      const m = raw as Record<string, unknown>;
      const stonechatId = m['stonechat_id'];
      const pubkey = m['pubkey'];
      if (typeof stonechatId !== 'string' || typeof pubkey !== 'string') return;
      if (!this.hashesTo(pubkey, stonechatId)) return; // forged key
      if (stonechatId === this.stonechatId) includesUs = true;
      const previous = held?.members.find((x) => x.stonechatId === stonechatId);
      roster.push({
        stonechatId,
        pubkey,
        ...(typeof m['display_name'] === 'string' ? { displayName: m['display_name'] } : {}),
        ...(previous?.bundleToken ? { bundleToken: previous.bundleToken } : {}),
      });
    }
    const verdict = checkMembership({
      from,
      payloadAdmin: admin,
      version,
      memberIds: roster.map((m) => m.stonechatId),
      // A group we were removed from is still one we hold: its admin on
      // record is the only one who can put us back, past the version that
      // removed us.
      held: held ? { adminId: held.admin, version: held.version } : null,
      senderIsContact: this.senderIsContact(from),
    });
    if (!verdict.accepted) {
      log(`roster refused: ${verdict.rejected}`);
      return;
    }
    const hash = rosterHash(this.hashB64, {
      groupId: id, version, admin, memberIds: roster.map((m) => m.stonechatId),
    });

    if (!includesUs) {
      // A roster without us is either a group we were never in, which is
      // nothing to us, or our removal. Removal keeps the record and empties
      // it: the history stays readable, nothing more is accepted or sent, and
      // the version moves on so an older roster cannot put us back.
      if (!held) return;
      store.upsertGroup({ ...held, version, admin, rosterHash: hash, members: [], removed: true });
      this.notice(id, true, 'You were removed from this group', inner.id);
      this.onGroupsChanged?.();
      return;
    }

    // First sight of the group: adopt its current disappearing-messages
    // timer from the payload. Established members ignore the field.
    const expireMs = body['expire_ms'];
    const bootstrapTimer = !held && typeof expireMs === 'number' && Number.isInteger(expireMs) && expireMs > 0;
    const before = held?.removed ? [] : held?.members ?? [];
    // The group photo is display data in the profile-photo shape; oversized
    // or undecodable reads as none, never as a reason to refuse the roster.
    const avatar = avatarFrom(body) ?? null;
    const next: Group = {
      id,
      name,
      ...(avatar ? { avatar } : {}),
      admin,
      version,
      members: roster,
      rosterHash: hash,
      ...(held?.seenVersion ? { seenVersion: held.seenVersion } : {}),
      ...(held?.expireTimerMs !== undefined
        ? { expireTimerMs: held.expireTimerMs, expireTimerAt: held.expireTimerAt ?? 0 }
        : bootstrapTimer
          ? { expireTimerMs: expireMs, expireTimerAt: sentAtMs(inner.sentAt) }
          : {}),
    };
    if (!store.upsertGroup(next)) return;
    this.onGroupsChanged?.();

    // Surface what changed (idempotent per envelope: notice ids derive from
    // it). First sight of the group renders no diff — it just appears.
    if (verdict.handover) {
      this.notice(
        id, true,
        admin === this.stonechatId
          ? 'You are now the group admin'
          : `${this.nameOf(admin)} is now the group admin`,
        `${inner.id}-admin`,
      );
    }
    if (held && !held.removed) {
      if (held.name !== name) this.notice(id, true, `Group renamed to "${name}"`, `${inner.id}-rename`);
      for (const m of roster) {
        if (m.stonechatId !== this.stonechatId && !before.some((b) => b.stonechatId === m.stonechatId)) {
          this.notice(id, true, `${this.nameOf(m.stonechatId)} was added`, `${inner.id}-add-${m.stonechatId}`);
        }
      }
      for (const b of before) {
        if (b.stonechatId !== this.stonechatId && !roster.some((m) => m.stonechatId === b.stonechatId)) {
          this.notice(id, true, `${this.nameOf(b.stonechatId)} was removed`, `${inner.id}-rm-${b.stonechatId}`);
        }
      }
    }

    // Messages that arrived ahead of this roster can be read now.
    const parked = store.parked();
    const mine = parked.filter((p) => p.groupId === id);
    if (mine.length) {
      store.setParked(parked.filter((p) => p.groupId !== id));
      for (const p of mine) {
        const fake: Inner = {
          id: p.id, type: p.type, from: p.from, fromDevice: p.fromDevice, to: this.stonechatId,
          device: this.deviceId, sentAt: p.sentAt, ratchet: {}, x3dh: null, nonce: '', ciphertext: '',
          blobId: null, bundleToken: null, manifestV: 0,
        };
        try {
          const m = await this.receiveGroupMessage(fake, p.payload, true);
          if (m) this.deliverLocally(m);
        } catch {
          // Its media could not be fetched just now: wait for the next
          // roster rather than lose it.
          store.setParked([...store.parked(), p]);
        }
      }
    }
  }

  /** A system row in a conversation, idempotent per id. */
  private notice(conversationId: string, group: boolean, text: string, id: string): void {
    const added = store.appendMessage({
      id, peerId: conversationId, mine: false, text, notice: true,
      sentAt: new Date(this.now()).toISOString(), ...(group ? { group: true } : {}),
    });
    if (added) this.changed();
  }

  /**
   * `group_msg` / `group_media`: rendered only from a current member of a
   * group we hold. What the sender says about the roster and about the
   * messages it has seen is checked against our own on the way.
   */
  private async receiveGroupMessage(
    inner: Inner,
    payload: Record<string, unknown>,
    replayed = false,
  ): Promise<Message | null> {
    const groupId = payload['group_id'];
    const group = typeof groupId === 'string' ? store.group(groupId) : null;
    const claim = rosterClaim(payload);
    const sender = group && !group.removed ? this.memberOf(group, inner.from) : null;
    if (!group || !sender) {
      if (!replayed) await this.parkIfAhead(inner, payload, group, claim);
      return null;
    }
    await this.noteRosterView(group, sender, claim);

    const isMedia = inner.type === 'group_media';
    // Fetch from the *sender's* mailbox with the capability token in the
    // payload, before returning: returning acks the envelope. Gone for good
    // renders as unavailable; a mailbox that cannot be reached right now
    // throws, which leaves the envelope queued for the next drain. A blocked
    // sender's blob is not fetched: fetching would tell their mailbox we
    // are still reading.
    const media = !isMedia
      ? undefined
      : this.isBlocked(inner.from)
        ? describeMedia(payload)
        : (await this.fetchSharedMedia(payload, inner.from)) ?? describeMedia(payload);
    const salt = payload['salt'];
    const body = groupMessageBody(payload);
    const expiresAt = expiresAtFrom(inner.sentAt, payload);
    const replyTo = replyFrom(payload);
    const message: Message = {
      id: inner.id,
      peerId: group.id,
      mine: false,
      text: isMedia ? '' : typeof payload['text'] === 'string' ? payload['text'] : '',
      sentAt: inner.sentAt,
      group: true,
      sender: inner.from,
      status: 'sent',
      ...(media ? { media } : {}),
      ...(expiresAt ? { expiresAt } : {}),
      ...(replyTo ? { replyTo } : {}),
      ...(typeof salt === 'string' && body !== null
        ? {
            contentHash: groupMessageHash(this.hashB64, {
              groupId: group.id, senderId: inner.from, id: inner.id, salt, body,
            }),
          }
        : {}),
    };
    this.checkSeen(group, sender, payload);
    this.queueReceipt(inner.from, 'delivered', inner.id);
    return message;
  }

  /**
   * A group message we cannot place: for a group we do not hold, or from
   * someone not in the roster we hold. If it says the sender is on a newer
   * roster than ours, it is early rather than wrong — keep it and ask the
   * admin for the roster. Otherwise it is dropped, as it always was.
   */
  private async parkIfAhead(
    inner: Inner,
    payload: Record<string, unknown>,
    group: Group | null,
    claim: RosterClaim | null,
  ): Promise<void> {
    const groupId = payload['group_id'];
    if (claim === null || !isWireId(groupId)) return;
    let adminId: string;
    if (group === null || group.removed) {
      // Never heard of it (or left it). Worth waiting only if the admin it
      // names is someone whose invitation we would accept.
      const named = claim.admin;
      if (named === null || named === this.stonechatId || !this.senderIsContact(named)) return;
      if (group?.removed && claim.version <= group.version) return;
      adminId = named;
    } else {
      if (claim.version <= group.version) return; // not news: not a member
      // We issue this group's rosters: there is nobody to ask.
      if (group.admin === this.stonechatId) return;
      adminId = group.admin;
    }
    const now = this.now();
    const parked = store.parked().filter((p) => now - p.parkedAt < PARKED_TTL_MS && p.id !== inner.id);
    if (parked.length >= PARKED_MAX) return;
    parked.push({
      id: inner.id, groupId, from: inner.from, fromDevice: inner.fromDevice,
      type: inner.type, sentAt: inner.sentAt, payload, parkedAt: now,
    });
    store.setParked(parked);
    await this.askForRoster(groupId, adminId, group?.version ?? 0, claim.version);
  }

  /** Compare a member's stated view of the roster with ours and act on a
   * difference: catch up, help them catch up, or say that the lists differ. */
  private async noteRosterView(group: Group, sender: GroupMember, claim: RosterClaim | null): Promise<void> {
    const weAreAdmin = group.admin === this.stonechatId;
    switch (compareRoster({ heldVersion: group.version, heldHash: group.rosterHash ?? null, claim })) {
      case 'same':
      case 'unknown':
        return;
      case 'peerAhead':
        if (!weAreAdmin) {
          await this.askForRoster(group.id, group.admin, group.version, claim!.version);
        } else if (claim!.version > (group.seenVersion ?? 0)) {
          // Only we issue rosters, yet a member holds a newer one: this
          // device is behind the group it administers — our phone issued it.
          store.patchGroup(group.id, { seenVersion: claim!.version });
          void this.sync('group_sync', { group_id: group.id, version: group.version });
        }
        return;
      case 'peerBehind':
        // They missed an update. Ours to repair if we issued it; otherwise
        // the admin's own retry is already on its way to them.
        if (weAreAdmin) await this.answerRosterRequest(group, sender);
        return;
      case 'diverged':
        this.notice(
          group.id, true,
          `${this.nameOf(sender.stonechatId)} holds a different member list for this group than this device does. Ask the admin to send the list again.`,
          `roster-differs-${group.id}-${group.version}`,
        );
        return;
    }
  }

  /** Ask `adminId` for the roster of a group we are behind on. At most once
   * per version every ten minutes; best-effort. */
  private async askForRoster(groupId: string, adminId: string, held: number, wanted: number): Promise<void> {
    const now = this.now();
    const asked = this.rosterAsked.get(groupId);
    if (asked && asked.version >= wanted && now - asked.at < ROSTER_ASK_EVERY_MS) return;
    this.rosterAsked.set(groupId, { version: wanted, at: now });
    const ok = await this.sendToPeer(adminId, 'group_sync', { group_id: groupId, version: held }, { noPush: true })
      .catch(() => false);
    if (!ok) this.rosterAsked.delete(groupId);
  }

  /** Hand `member` the current roster because they asked, or because their
   * own message showed they hold an older one. */
  private async answerRosterRequest(group: Group, member: GroupMember): Promise<void> {
    const now = this.now();
    const key = `${group.id}|${member.stonechatId}`;
    if (now - (this.rosterAnswered.get(key) ?? 0) < ROSTER_ANSWER_EVERY_MS) return;
    this.rosterAnswered.set(key, now);
    await this.sendToPeer(member.stonechatId, 'group_update', this.membershipPayload(group)).catch(() => false);
  }

  private membershipPayload(group: Group): Record<string, unknown> {
    return {
      group_id: group.id,
      name: group.name,
      // Every roster carries the photo (null = none): a member restored
      // from a backup gets it back with the next one. An admin device that
      // dropped the field would read as "photo removed" on every phone.
      avatar: group.avatar ?? null,
      version: group.version,
      admin: group.admin,
      members: group.members.map((m) => ({
        stonechat_id: m.stonechatId,
        pubkey: m.pubkey,
        display_name: m.displayName ?? m.stonechatId.slice(3, 12),
      })),
      ...(group.expireTimerMs ? { expire_ms: group.expireTimerMs } : {}),
    };
  }

  /** `seen`: where we hold the same message with a different hash, the two
   * of us were sent different things under one id. */
  private checkSeen(group: Group, sender: GroupMember, payload: Record<string, unknown>): void {
    const seen = payload['seen'];
    if (!Array.isArray(seen)) return;
    for (const entry of seen.slice(0, GROUP_SEEN_MAX * 4)) {
      if (typeof entry !== 'object' || entry === null) continue;
      const id = (entry as Record<string, unknown>)['id'];
      const theirs = (entry as Record<string, unknown>)['h'];
      if (typeof id !== 'string' || typeof theirs !== 'string') continue;
      const ours = store.findMessage(id)?.message;
      if (
        !ours || ours.mine || ours.peerId !== group.id || !ours.group ||
        !ours.contentHash || ours.contentHash === theirs || ours.sender === sender.stonechatId
      ) {
        continue;
      }
      this.notice(
        group.id, true,
        `${this.nameOf(sender.stonechatId)} received a different version of a message from ${this.nameOf(ours.sender ?? '')} than this device did.`,
        `${id}-differs-${sender.stonechatId}`,
      );
    }
  }

  // -- media --------------------------------------------------------------------

  /**
   * Fetch and decrypt a DM attachment someone sent us.
   *
   * The blob sits on *our* mailbox — the sender parked it there — so this
   * fetches with our own device token. A blob that does not open is dropped
   * rather than shown: the key came from inside the session ciphertext, so a
   * failure means the bytes were tampered with. 404 is ordinary: the blob is
   * deleted once every device has acked, so a second device draining later
   * finds it gone. A mailbox that cannot be reached right now is transient —
   * the envelope stays queued.
   */
  private async openMedia(body: Record<string, unknown>): Promise<MediaAttachment | null> {
    const blobId = body['blob_id'];
    const keyB64 = body['key'];
    const nonceB64 = body['blob_nonce'];
    if (!isWireId(blobId) || typeof keyB64 !== 'string' || typeof nonceB64 !== 'string') return null;
    let got;
    try {
      const mailbox = await this.ownMailbox();
      got = await mailbox.request(
        'GET',
        `/blob/${blobId}?token=${encodeURIComponent(this._grant.device_token)}`,
      );
    } catch (e) {
      throw new TransientFailure(`attachment not fetched: ${(e as Error).message}`);
    }
    if (got.status !== 200) return null;
    return decryptedMedia(this.core, body, keyB64, nonceB64, got.body);
  }

  /**
   * Fetch a group attachment, or a sibling's synced copy, from wherever its
   * owner parked it — the sender's own mailbox, reached by *owner*, not by
   * the `blob_host` address the payload also carries: this transport pins
   * against the owner's signed certificate schedule from the directory, so
   * an address on its own is not something it can safely connect to. That
   * is also the check PROTOCOL.md asks for, made structural.
   */
  private async fetchSharedMedia(
    body: Record<string, unknown>,
    owner: string,
  ): Promise<MediaAttachment | undefined> {
    const keyB64 = body['key'];
    const nonceB64 = body['blob_nonce'];
    if (typeof keyB64 !== 'string' || typeof nonceB64 !== 'string') return undefined;
    const got = await this.fetchSharedRaw(body, owner);
    if (got === null) return undefined;
    return decryptedMedia(this.core, body, keyB64, nonceB64, got) ?? undefined;
  }

  /** The ciphertext of a shared blob, or null when it is gone for good. A
   * mailbox that cannot be reached right now is transient. */
  private async fetchSharedRaw(body: Record<string, unknown>, owner: string): Promise<Uint8Array | null> {
    const blobId = body['blob_id'];
    const token = body['fetch_token'];
    if (!isWireId(blobId) || typeof token !== 'string') return null;
    let got;
    try {
      const mailbox = await this.connect(owner);
      got = await mailbox.request('GET', `/blob/${blobId}?token=${encodeURIComponent(token)}`);
    } catch (e) {
      throw new TransientFailure(`blob not fetched: ${(e as Error).message}`);
    }
    return got.status === 200 ? got.body : null;
  }

  /** A shared blob, fetched and opened. Null when gone or tampered. */
  private async fetchSharedBytes(body: Record<string, unknown>, owner: string): Promise<Uint8Array | null> {
    const keyB64 = body['key'];
    const nonceB64 = body['blob_nonce'];
    if (typeof keyB64 !== 'string' || typeof nonceB64 !== 'string') return null;
    const got = await this.fetchSharedRaw(body, owner);
    if (got === null) return null;
    try {
      return this.core.blobOpen(b64decode(keyB64), b64decode(nonceB64), got);
    } catch {
      return null;
    }
  }

  // -- receiving ----------------------------------------------------------

  /**
   * Drain and stay connected. Yields messages to show.
   *
   * Everything this client handles is applied; anything it does not is
   * acked and dropped — a client that left receipts and typing indicators
   * queued would grow its own mailbox forever. An envelope whose processing
   * fails *transiently* (a blob that cannot be fetched right now) is left
   * un-acked and redelivered on the next connection. One malformed envelope
   * is dropped, never the connection.
   */
  async *receive(): AsyncGenerator<Message, void, void> {
    const mailbox = await this.ownMailbox();
    for await (const item of mailbox.socket(this._grant.device_token)) {
      if (item.kind === 'closed') {
        throw new Error(
          item.code === 4001
            ? 'This device was revoked from your phone.'
            : 'Another session took over this device.',
        );
      }
      const id = item.envelope['id'];
      if (typeof id !== 'string' || id === '') continue;
      let message: Message | null = null;
      try {
        message = await this.open(item.envelope);
      } catch (e) {
        if (e instanceof TransientFailure) {
          log(`left queued: ${e.message}`);
          continue;
        }
        log(`dropped envelope ${id}: ${(e as Error).message}`);
      }
      // Persisted, then acked, never the other way round: the relay's
      // promise is "accepted for write", and an ack is what deletes the row.
      if (message) this.deliverLocally(message);
      await mailbox.ack(id);
      if (message) yield message;
    }
  }

  /** File a message that arrived (or was replayed) and tell the view. */
  private deliverLocally(message: Message): void {
    if (message.media?.url) this.mediaUrls.set(message.id, message.media.url);
    if (store.appendMessage(message)) this.changed();
  }

  /** Object URLs for attachments decrypted in this run, by message id. The
   * store does not keep them — they die with the tab. */
  readonly mediaUrls = new Map<string, string>();

  /**
   * Keep receiving, reconnecting with backoff, and run the sweeps. For the
   * page; the tests drive `receive()` directly.
   */
  async start(onMessage: (m: Message) => void, onStatus: (kind: 'live' | 'warn' | 'down', text: string) => void): Promise<void> {
    let delay = 1000;
    for (;;) {
      try {
        await this.publishPrekeys();
        onStatus('live', 'connected');
        delay = 1000;
        void this.retryPending();
        for await (const message of this.receive()) onMessage(message);
        onStatus('warn', 'disconnected — reconnecting');
      } catch (e) {
        const text = (e as Error).message;
        // 4001 is the relay saying this device is gone. Nothing here recovers
        // from that, so say what to do rather than retrying forever.
        if (/revoked/i.test(text) || (e instanceof MailboxError && (e.status === 410 || e.status === 403))) {
          onStatus('down', 'This browser is no longer linked — open Settings and Unlink.');
          return;
        }
        if (/took over/i.test(text)) {
          onStatus('down', 'Another tab or window took over this session. Close this one.');
          return;
        }
        onStatus('down', `${text} — reconnecting`);
      }
      this.forgetMailbox(this.stonechatId);
      await new Promise((r) => setTimeout(r, delay));
      delay = Math.min(delay * 2, 30_000);
    }
  }

  private async open(wire: Record<string, unknown>): Promise<Message | null> {
    if (wire['to'] !== this.stonechatId) {
      log(`dropped envelope ${String(wire['id'])}: addressed to someone else`);
      return null;
    }
    const sealed = wire['sealed'];
    if (typeof sealed !== 'string') return null;
    const opened = this.core.unseal(this.keys.sealSeed, b64decode(sealed));
    if (opened === null) return null; // not sealed to this device
    let json: unknown;
    try {
      json = JSON.parse(fromUtf8.decode(opened));
    } catch {
      log(`dropped envelope ${String(wire['id'])}: malformed seal`);
      return null;
    }
    const parsed = parseInner(wire, json, this.stonechatId, this.deviceId);
    if (parsed.reason !== undefined) {
      log(`dropped envelope ${String(wire['id'])}: ${parsed.reason}`);
      return null;
    }
    const inner = parsed.inner;

    // Decryption is the authentication: the session (or the x3dh block's
    // device key, vouched for by a certificate the `from` ID's identity key
    // signed) proves the sender is a device that identity certified.
    const plaintext = await this.openSession(inner);
    if (plaintext === null) return null;
    let body: Record<string, unknown>;
    try {
      body = JSON.parse(plaintext) as Record<string, unknown>;
      if (typeof body !== 'object' || body === null) return null;
    } catch {
      return null;
    }

    if (inner.from !== this.stonechatId) {
      // Someone writing to us directly is a conversation, whoever they are to
      // the phone; a group member speaking in a group is not, and is recorded
      // on the roster instead.
      if (DM_TYPES.has(inner.type)) {
        this.ensureContact(inner.from, b64encode(await this.identityKeyFor(inner.from)));
      }
      // Anything they send tells us how to list their devices. Recorded before
      // the type switch so it is learned even from traffic we go on to drop —
      // and only now, after the envelope decrypted.
      this.noteBundleToken(inner.from, inner.bundleToken);
    }

    // The device that wrote this must still speak for the sender: its
    // certificate unexpired, and listed in the sender's device manifest when
    // the sender has one. A session that was fine when it started does not
    // settle this — the device may have been revoked since.
    if (!(await this.senderDeviceTrusted(inner))) return null;

    return this.dispatch(inner, body);
  }

  /**
   * Decrypt on the sender's session, establishing a responder session from
   * the envelope's x3dh block when needed (PROTOCOL.md "PQXDH"). Null for
   * anything that does not verify.
   */
  private async openSession(inner: Inner): Promise<string | null> {
    const { from, fromDevice } = inner;
    const ad = utf8.encode(
      `stonechat/v1|${from}|${fromDevice}|${inner.to}|${inner.device}|${inner.type}`,
    );
    const block = inner.x3dh;
    const decrypt = (state: SessionState): { state: SessionState; plaintext: string } | null =>
      this.core.sessionDecrypt({
        state,
        header: inner.ratchet,
        nonce: b64decode(inner.nonce),
        ciphertext: b64decode(inner.ciphertext),
        ad,
        freshRatchetSk: randomBytes(32),
        pqRandom: randomBytes(64),
      });

    const session = store.session(from, fromDevice);
    if (session) {
      // Simultaneous initiation: both sides started a session with each
      // other, and each holds an unconfirmed one it initiated. The lower
      // Stonechat ID's wins (PROTOCOL.md "PQXDH"): if theirs does, ours is
      // skipped and theirs adopted below; if ours does, their initial
      // envelope is dropped rather than allowed to replace a session they
      // are about to adopt — replacing it would leave the two sides holding
      // each other's session and nothing that decrypts.
      const racing =
        block !== null && session['confirmed'] === false && session['initiated_by_us'] === true;
      // Between two of our own devices the IDs are equal: the lower device
      // number decides, so the phone (device 1) always wins against a
      // browser. (The app replaces here instead — see README "Still missing".)
      const theirsWins =
        racing &&
        (from < this.stonechatId || (from === this.stonechatId && fromDevice < this.deviceId));
      if (!theirsWins) {
        let result: { state: SessionState; plaintext: string } | null = null;
        try {
          result = decrypt(session);
        } catch {
          result = null;
        }
        if (result !== null) {
          store.setSession(from, fromDevice, result.state);
          return fromUtf8.decode(b64decode(result.plaintext));
        }
        if (block === null) {
          log(`dropped ${inner.type} from ${from.slice(0, 12)}…: session decrypt failed, no x3dh block`);
          return null;
        }
        if (racing) {
          log(`dropped ${inner.type} from ${from.slice(0, 12)}…: simultaneous handshake, ours wins`);
          return null;
        }
        // Fall through: a fresh handshake replacing a session that no longer
        // decrypts — a peer who reinstalled.
      }
    }
    if (block === null) {
      log(`dropped ${inner.type} from ${from.slice(0, 12)}…: no session and no x3dh block`);
      return null;
    }

    // The key in the block is the sender's DEVICE key, which does not hash
    // to their SC- ID — so the check is the certificate that vouches for it,
    // against the identity key their SC- ID does commit to, and then that
    // the certificate vouches for *this* key. Without the second, the
    // certificate would be decoration. The identity key is what we hold for
    // someone we know; the directory is asked only the first time we hear
    // from a stranger.
    let identityPub: Uint8Array;
    try {
      identityPub = await this.identityKeyFor(from);
    } catch {
      log(`dropped ${inner.type} from ${from.slice(0, 12)}…: no identity key that commits to their ID`);
      return null;
    }
    const cert = this.recordCert(from, fromDevice, block['cert'], identityPub);
    if (cert === null) {
      log(`dropped ${inner.type} from ${from.slice(0, 12)}…: x3dh device certificate did not verify`);
      return null;
    }
    const certified = certSigKey(cert);
    if (!certified || b64encode(certified) !== String(block['ik'])) {
      log(`dropped ${inner.type} from ${from.slice(0, 12)}…: x3dh key is not the one its certificate vouches for`);
      return null;
    }

    const pool = store.prekeys();
    if (!pool) return null;
    const spkId = block['spk_id'];
    const spk =
      pool.spk.id === spkId ? pool.spk : pool.prevSpk?.id === spkId ? pool.prevSpk : null;
    if (!spk) {
      log(`dropped ${inner.type} from ${from.slice(0, 12)}…: spk ${String(spkId)} not held (rotated away?)`);
      return null; // sender will re-encrypt
    }
    const opkId = block['opk_id'] as number | undefined;
    const opkSec = opkId === undefined || opkId === null ? null : pool.opks[opkId]?.sec ?? null;
    if (opkId !== undefined && opkId !== null && opkSec === null) {
      log(`dropped ${inner.type} from ${from.slice(0, 12)}…: opk ${String(opkId)} not held (consumed/replay?)`);
      return null;
    }
    const kemOneTime = Boolean(block['kem_one_time']);
    const kemId = Number(block['kem_id']);
    const kemSeed = kemOneTime
      ? pool.kopks[kemId]?.seed ?? null
      : pool.kspk.id === kemId
        ? pool.kspk.seed
        : pool.prevKspk?.id === kemId
          ? pool.prevKspk.seed
          : null;
    if (kemSeed === null) {
      log(`dropped ${inner.type} from ${from.slice(0, 12)}…: kem prekey ${kemId} not held`);
      return null;
    }
    let fresh: SessionState;
    try {
      fresh = this.core.sessionRespond({
        edSeed: this.keys.sigSeed,
        senderEdPk: b64decode(String(block['ik'])),
        x3dhJson: JSON.stringify(block),
        spkPub: b64decode(spk.pub),
        spkSec: b64decode(spk.sec),
        opkSec: opkSec ? b64decode(opkSec) : null,
        kemSeed: b64decode(kemSeed),
      });
    } catch {
      return null;
    }
    let result: { state: SessionState; plaintext: string } | null = null;
    try {
      result = decrypt(fresh);
    } catch {
      result = null;
    }
    if (result === null) {
      // A responder session whose first decryption fails is discarded:
      // nothing about it has been authenticated.
      log(`dropped ${inner.type} from ${from.slice(0, 12)}…: x3dh responder decrypt failed`);
      return null;
    }
    // One-time means one time: what we hold is exactly what we can decrypt.
    if (opkId !== undefined && opkId !== null) delete pool.opks[opkId];
    if (kemOneTime) delete pool.kopks[kemId];
    store.setPrekeys(pool);
    // Replaces any prior session with this peer's sending device.
    store.setSession(from, fromDevice, result.state);
    return fromUtf8.decode(b64decode(result.plaintext));
  }

  /** A conversation exists with this peer: make sure a record does, with the
   * identity key that was checked to commit to their ID. */
  private ensureContact(peerId: string, pubkey: string): void {
    const held = store.contact(peerId);
    if (held && held.pubkey === pubkey) return;
    store.setContact({ ...(held ?? { stonechatId: peerId }), pubkey });
    this.changed();
  }

  /** Remember a peer's bundle token, wherever we know them from. */
  private noteBundleToken(peerId: string, token: string | null): void {
    if (token === null || peerId === this.stonechatId) return;
    const contact = store.contact(peerId);
    if (contact && contact.bundleToken !== token) {
      store.setContact({ ...contact, bundleToken: token });
      this.deviceLists.delete(peerId);
    }
    for (const group of Object.values(store.groups())) {
      const m = group.members.find((x) => x.stonechatId === peerId);
      if (!m || m.bundleToken === token) continue;
      store.patchGroup(group.id, {
        members: group.members.map((x) => (x.stonechatId === peerId ? { ...x, bundleToken: token } : x)),
      });
      this.deviceLists.delete(peerId);
    }
  }

  /**
   * Whether the device an envelope came from still speaks for its sender.
   *
   * Its certificate, verified when its session began and kept, must not have
   * expired — and if it has, the sender's mailbox is asked for a renewed one,
   * which a device still linked has and a revoked one does not. And when the
   * sender's identity has published a device manifest, the device must be on
   * it with the key its certificate carries; an envelope claiming a newer
   * manifest than we hold has the manifest refetched first.
   */
  private async senderDeviceTrusted(inner: Inner): Promise<boolean> {
    const { from, fromDevice } = inner;
    let cert = this.heldCert(from, fromDevice);
    if (cert === null) {
      try {
        const identityPub = await this.identityKeyFor(from);
        store.deletePeerCert(from, fromDevice);
        cert = await this.certFor(from, fromDevice, identityPub);
      } catch {
        cert = null;
      }
      if (cert === null) {
        log(`dropped ${inner.type} from ${from.slice(0, 12)}…: sender device ${fromDevice}: certificate expired or unknown`);
        return false;
      }
    }
    const manifest = await this.manifestFor(from, inner.manifestV);
    if (manifest === null) return true; // nothing published: certificates decide
    if (manifestLists(manifest, fromDevice, cert.sig_pub)) return true;
    log(`dropped ${inner.type} from ${from.slice(0, 12)}…: sender device ${fromDevice} is not in their device manifest (version ${manifest.version})`);
    return false;
  }

  /** Apply one decrypted, trusted envelope by type. */
  private async dispatch(inner: Inner, body: Record<string, unknown>): Promise<Message | null> {
    const { from, type } = inner;
    const self = from === this.stonechatId;

    // Self-sync only ever comes from us. The session already proves the
    // sender is a device the `from` identity certified — so this check, that
    // `from` is *our* identity, is what keeps a peer from writing our history.
    if (type.startsWith('sync_')) {
      if (!self) {
        log(`dropped ${type}: sync from someone else's identity`);
        return null;
      }
      switch (type) {
        case 'sync_sent':
          return this.fromSyncSent(inner, body);
        case 'sync_read': {
          const ids = Array.isArray(body['ids']) ? body['ids'].filter((x): x is string => typeof x === 'string') : [];
          let touched = false;
          for (const id of ids) {
            const held = store.findMessage(id)?.message;
            if (!held || held.mine || held.status === 'read') continue;
            store.updateMessage(id, (m) => ({ ...m, status: 'read' }));
            touched = true;
          }
          if (touched) this.changed();
          return null;
        }
        case 'sync_clear': {
          // Which field names the conversation is what says which kind it is.
          const groupId = body['group_id'];
          const peer = groupId ?? body['peer'];
          if (typeof peer === 'string' && peer !== '') {
            const group = groupId !== undefined && groupId !== null;
            store.clearConversation(peer, group);
            this.onConversationCleared?.(peer, group);
            this.changed();
          }
          return null;
        }
        case 'sync_block': {
          const peer = body['peer'];
          if (typeof peer !== 'string' || peer === '') return null;
          const at = body['blocked_at'];
          const contact = store.contact(peer) ?? { stonechatId: peer, pubkey: '' };
          store.setContact({ ...contact, blockedAt: typeof at === 'number' ? at : null });
          this.changed();
          return null;
        }
        case 'sync_cert':
          await this.applySyncCert(body);
          return null;
        case 'sync_contact':
          this.applySyncContact(body);
          return null;
        case 'sync_history':
          await this.applySyncHistory(body);
          return null;
        default:
          return null;
      }
    }

    const contact = store.contact(from);
    // Blocked senders — contacts or not: their DM traffic, calls and contact
    // requests stop at the door. Decrypted first (above) so the ratchet stays
    // current for a later unblock. In groups, messages still arrive and
    // render collapsed, so the room stays coherent.
    if (this.isBlocked(from)) {
      switch (type) {
        case 'group_reaction':
          return null;
        case 'group_create':
        case 'group_update':
          if (typeof body['group_id'] !== 'string' || !store.group(body['group_id'])) return null;
          break;
        case 'contact_request': case 'msg': case 'media': case 'typing': case 'msg_edit':
        case 'msg_delete': case 'reaction': case 'profile_update': case 'timer_update':
        case 'call_offer': case 'call_answer': case 'call_ice': case 'call_end':
          return null;
      }
    }

    switch (type) {
      case 'contact_request': {
        const name = body['display_name'];
        const avatar = avatarFrom(body);
        const held = contact ?? { stonechatId: from, pubkey: '' };
        const pubkey = held.pubkey || b64encode(await this.identityKeyFor(from));
        // We asked them too: two requests crossing is mutual consent. Else it
        // waits for the phone — accepting is a decision this browser does not
        // make for the user (README "Still missing").
        const mutual = held.status === 'pendingOut' || held.status === 'accepted';
        const recorded: Contact = {
          ...held, pubkey,
          status: mutual ? 'accepted' : 'pendingIn',
          ...(typeof name === 'string' && name.trim() ? { displayName: name.trim() } : {}),
          ...(avatar !== undefined ? { avatar, profileAt: sentAtMs(inner.sentAt) } : {}),
        };
        store.setContact(recorded);
        this.changed();
        // Every device receives the request itself; the sync is what keeps
        // them agreeing once one of them answers it.
        void this.sync('sync_contact', this.contactSyncPayload(recorded));
        if (mutual) {
          await this.sendToPeer(from, 'contact_accept', this.profilePayload()).catch(() => false);
          return null;
        }
        return {
          id: inner.id, peerId: from, mine: false, sentAt: inner.sentAt, notice: true, request: true,
          text: `${this.nameOf(from)} wants to connect — accept or decline on your phone`,
        };
      }
      case 'contact_accept': {
        if (!contact || contact.status !== 'pendingOut') return null;
        const name = body['display_name'];
        const avatar = avatarFrom(body);
        const accepted: Contact = {
          ...contact, status: 'accepted',
          ...(typeof name === 'string' && name.trim() ? { displayName: name.trim() } : {}),
          ...(avatar !== undefined ? { avatar, profileAt: sentAtMs(inner.sentAt) } : {}),
        };
        store.setContact(accepted);
        this.changed();
        void this.sync('sync_contact', this.contactSyncPayload(accepted));
        return {
          id: inner.id, peerId: from, mine: false, sentAt: inner.sentAt, notice: true,
          text: `${this.nameOf(from)} accepted your request`,
        };
      }
      case 'profile_update': {
        if (!contact || !this.isContact(from)) return null;
        // Last-writer-wins: a replayed or out-of-order profile never
        // regresses the one we hold.
        const at = sentAtMs(inner.sentAt);
        if (at <= (contact.profileAt ?? 0)) return null;
        const name = body['display_name'];
        const avatar = avatarFrom(body);
        store.setContact({
          ...contact, profileAt: at,
          ...(typeof name === 'string' && name.trim() ? { displayName: name.trim() } : {}),
          ...(avatar !== undefined ? { avatar } : {}),
        });
        this.changed();
        return null;
      }
      case 'msg': {
        // Strangers cannot chat: only an accepted contact's message is shown.
        if (!this.isContact(from)) return null;
        if (typeof body['text'] !== 'string') return null;
        this.queueReceipt(from, 'delivered', inner.id);
        const expiresAt = expiresAtFrom(inner.sentAt, body);
        const replyTo = replyFrom(body);
        return {
          id: inner.id, peerId: from, mine: false, text: body['text'], sentAt: inner.sentAt, status: 'sent',
          ...(expiresAt ? { expiresAt } : {}),
          ...(replyTo ? { replyTo } : {}),
        };
      }
      case 'media': {
        if (!this.isContact(from)) return null;
        // Blob ids go into a URL on our own mailbox with our own token
        // beside them: dropped, not retried, when not a UUID — no later
        // attempt makes it one.
        if (!isWireId(body['blob_id'])) return null;
        const media = await this.openMedia(body);
        this.queueReceipt(from, 'delivered', inner.id);
        const expiresAt = expiresAtFrom(inner.sentAt, body);
        const replyTo = replyFrom(body);
        return {
          id: inner.id, peerId: from, mine: false, text: '', sentAt: inner.sentAt, status: 'sent',
          media: media ?? describeMedia(body),
          ...(expiresAt ? { expiresAt } : {}),
          ...(replyTo ? { replyTo } : {}),
        };
      }
      case 'group_create':
      case 'group_update':
        await this.applyMembership(inner, body);
        return null;
      case 'group_msg':
      case 'group_media':
        return this.receiveGroupMessage(inner, body);
      case 'group_sync': {
        const group = typeof body['group_id'] === 'string' ? store.group(body['group_id']) : null;
        if (!group || group.removed) return null;
        const held = body['version'];
        if (typeof held === 'number' && held >= group.version) return null; // nothing newer
        if (self) {
          // One of our own devices is behind on a group we administer.
          await this.syncToSiblings('group_update', this.membershipPayload(group));
          return null;
        }
        // Whoever asks us holds us as the admin on record — true of the admin,
        // and of a former one for members who missed the handover.
        const member = this.memberOf(group, from);
        if (member) await this.answerRosterRequest(group, member);
        return null;
      }
      case 'group_leave': {
        const group = typeof body['group_id'] === 'string' ? store.group(body['group_id']) : null;
        if (!group || group.removed || !this.memberOf(group, from)) return null;
        const left = this.nameOf(from); // before the roster forgets the name
        store.patchGroup(group.id, { members: group.members.filter((m) => m.stonechatId !== from) });
        this.onGroupsChanged?.();
        return {
          id: inner.id, peerId: group.id, mine: false, group: true, notice: true, sentAt: inner.sentAt,
          text: `${left} left`,
        };
      }
      case 'receipt':
        this.applyReceipt(from, body);
        return null;
      case 'typing':
        this.applyTyping(inner, body);
        return null;
      case 'msg_edit':
      case 'group_msg_edit': {
        const target = this.remoteEditTarget(inner, body, type === 'group_msg_edit');
        const text = typeof body['text'] === 'string' ? body['text'].trim() : '';
        if (!target || text === '' || target.media) return null;
        store.updateMessage(target.id, (m) => ({ ...m, text, editedAt: sentAtMs(inner.sentAt) }));
        this.changed();
        return null;
      }
      case 'msg_delete':
      case 'group_msg_delete': {
        const target = this.remoteEditTarget(inner, body, type === 'group_msg_delete');
        if (target) this.tombstone(target.id);
        return null;
      }
      case 'reaction':
      case 'group_reaction': {
        const id = body['id'];
        const emoji = body['emoji'];
        // 32 UTF-16 units of headroom: ZWJ sequences run well past one code point.
        if (typeof id !== 'string' || typeof emoji !== 'string' || emoji.length > 32) return null;
        const held = store.findMessage(id)?.message;
        if (!held || held.deleted || held.notice) return null;
        if (type === 'group_reaction') {
          const group = typeof body['group_id'] === 'string' ? store.group(body['group_id']) : null;
          if (!group || held.peerId !== group.id || !held.group || !this.memberOf(group, from)) return null;
        } else if (held.group || held.peerId !== from || !this.isContact(from)) {
          return null;
        }
        this.recordReaction(id, from, emoji);
        return null;
      }
      case 'timer_update': {
        if (!this.isContact(from)) return null;
        const ms = body['expire_ms'];
        if (typeof ms !== 'number' || !Number.isInteger(ms) || ms < 0) return null;
        const at = sentAtMs(inner.sentAt);
        const held = contact ?? { stonechatId: from, pubkey: '' };
        if (at <= (held.expireTimerAt ?? 0)) return null;
        store.setContact({ ...held, expireTimerMs: ms, expireTimerAt: at });
        return {
          id: inner.id, peerId: from, mine: false, notice: true, sentAt: inner.sentAt,
          text: timerNoticeText(this.nameOf(from), ms),
        };
      }
      case 'group_timer_update': {
        const group = typeof body['group_id'] === 'string' ? store.group(body['group_id']) : null;
        if (!group || group.removed || !this.memberOf(group, from)) return null;
        const ms = body['expire_ms'];
        if (typeof ms !== 'number' || !Number.isInteger(ms) || ms < 0) return null;
        const at = sentAtMs(inner.sentAt);
        if (at <= (group.expireTimerAt ?? 0)) return null;
        store.patchGroup(group.id, { expireTimerMs: ms, expireTimerAt: at });
        return {
          id: inner.id, peerId: group.id, mine: false, group: true, notice: true, sentAt: inner.sentAt,
          text: timerNoticeText(this.nameOf(from), ms),
        };
      }
      case 'call_offer':
      case 'call_answer':
      case 'call_ice':
      case 'call_end': {
        // Calls are between accepted contacts only.
        if (!this.isContact(from)) return null;
        if (this.onCallSignal) {
          await this.onCallSignal(from, type, body, inner.sentAt);
          return null;
        }
        if (type !== 'call_offer') return null;
        // No call support wired in: the phone gets its own copy of this
        // offer. Say so, or a ringing phone and a silent tab look unrelated.
        const missed = this.now() - sentAtMs(inner.sentAt) > 60 * 1000;
        const media = body['media'] === 'video' ? 'Video call' : 'Call';
        return {
          id: inner.id, peerId: from, mine: false, notice: true, call: true, sentAt: inner.sentAt,
          text: missed
            ? `Missed ${media.toLowerCase()} from ${this.nameOf(from)}`
            : `${media} from ${this.nameOf(from)} — answer on your phone`,
        };
      }
      default:
        // Anything newer: decrypted to keep the ratchet current, and dropped.
        return null;
    }
  }

  /** Shared validation for edits and deletes: the referenced message must be
   * held, incoming, in the right conversation, written by the sender, and
   * inside the window plus receiver-side grace. */
  private remoteEditTarget(inner: Inner, body: Record<string, unknown>, group: boolean): Message | null {
    const id = body['id'];
    if (typeof id !== 'string') return null;
    const held = store.findMessage(id)?.message;
    if (!held || held.mine || held.deleted || held.notice) return null;
    if (group) {
      const groupId = body['group_id'];
      if (typeof groupId !== 'string' || held.peerId !== groupId || !held.group) return null;
      const g = store.group(groupId);
      if (!g || g.removed || !this.memberOf(g, inner.from)) return null;
      if (held.sender !== inner.from) return null;
    } else if (held.group || held.peerId !== inner.from || !this.isContact(inner.from)) {
      return null;
    }
    if (sentAtMs(inner.sentAt) - sentAtMs(held.sentAt) > EDIT_WINDOW_MS + EDIT_GRACE_MS) return null;
    return held;
  }

  /** What our contact accepts carry: the name the grant gave us. A photo
   * would have to be synced from the phone, which nothing does. */
  private profilePayload(): Record<string, unknown> {
    return { display_name: this._grant.display_name || this.stonechatId.slice(3, 12) };
  }
}

/** The phone's contact statuses on the wire, and ours. */
function wireStatus(status: Contact['status']): string {
  switch (status) {
    case 'pendingOut':
      return 'pending_out';
    case 'pendingIn':
      return 'pending_in';
    case 'accepted':
      return 'accepted';
    default:
      return 'pending_out';
  }
}

function localStatus(wire: string): NonNullable<Contact['status']> | null {
  switch (wire) {
    case 'pending_out':
      return 'pendingOut';
    case 'pending_in':
      return 'pendingIn';
    case 'accepted':
      return 'accepted';
    default:
      return null;
  }
}

/** gzip, as the backup payload is compressed. */
async function gunzip(bytes: Uint8Array): Promise<Uint8Array> {
  const stream = new Blob([bytes.slice().buffer as ArrayBuffer]).stream().pipeThrough(new DecompressionStream('gzip'));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

const num = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) ? v : null);
const str = (v: unknown): string | null => (typeof v === 'string' ? v : null);

/**
 * Merge a backup payload — the phone's rows — into the store, under the
 * backup's rule: what is already held wins. Rows that fail the checks every
 * other path makes (keys that do not hash to their IDs, ids that are not
 * UUIDs) are skipped, not fatal.
 */
export function mergeBackup(
  rows: {
    contacts: Array<Record<string, unknown>>;
    blocked: Array<Record<string, unknown>>;
    groups: Array<Record<string, unknown>>;
    groupMembers: Array<Record<string, unknown>>;
    messages: Array<Record<string, unknown>>;
    reactions: Array<Record<string, unknown>>;
  },
  self: string,
  hashesTo: (pubkey: string, id: string) => boolean,
): { contacts: number; groups: number; messages: number } {
  let contacts = 0;
  for (const r of rows.contacts) {
    const id = str(r['stonechat_id']);
    const pubkey = str(r['pubkey']);
    const status = localStatus(str(r['status']) ?? '');
    if (!id || !pubkey || status === null || id === self || !hashesTo(pubkey, id)) continue;
    const held = store.contact(id);
    if (held?.status) continue; // held wins
    const name = str(r['display_name']);
    const timer = num(r['expire_timer_ms']);
    const { status: _s, ...rest } = held ?? { stonechatId: id, pubkey };
    void _s;
    store.setContact({
      ...rest,
      stonechatId: id,
      pubkey,
      status,
      ...(name && !held?.displayName ? { displayName: name } : {}),
      ...(timer && !held?.expireTimerMs ? { expireTimerMs: timer, expireTimerAt: num(r['expire_timer_at']) ?? 0 } : {}),
    });
    contacts++;
  }
  for (const r of rows.blocked) {
    const id = str(r['stonechat_id']);
    const at = num(r['blocked_at']);
    if (!id || at === null) continue;
    const held = store.contact(id);
    if (held?.blockedAt !== undefined) continue;
    store.setContact({ ...(held ?? { stonechatId: id, pubkey: '' }), blockedAt: at });
  }

  let groups = 0;
  const groupIds = new Set<string>();
  for (const g of rows.groups) {
    const id = str(g['id']);
    const name = str(g['name']);
    const admin = str(g['admin_id']);
    const version = num(g['version']);
    if (!id || !isWireId(id) || !name || !admin || version === null) continue;
    groupIds.add(id);
    const members = [];
    let bad = false;
    for (const m of rows.groupMembers) {
      if (m['group_id'] !== id) continue;
      const sid = str(m['stonechat_id']);
      const pubkey = str(m['pubkey']);
      if (!sid || !pubkey || !hashesTo(pubkey, sid)) {
        bad = true;
        break;
      }
      const dn = str(m['display_name']);
      members.push({ stonechatId: sid, pubkey, ...(dn ? { displayName: dn } : {}) });
    }
    if (bad || members.length === 0 || !members.some((m) => m.stonechatId === admin)) continue;
    const hash = str(g['roster_hash']);
    const timer = num(g['expire_timer_ms']);
    const added = store.upsertGroup({
      id, name, admin, version, members,
      ...(hash ? { rosterHash: hash } : {}),
      ...(timer ? { expireTimerMs: timer, expireTimerAt: num(g['expire_timer_at']) ?? 0 } : {}),
      ...(members.some((m) => m.stonechatId === self) ? {} : { removed: true as const }),
    });
    if (added) groups++;
  }

  const reactions = new Map<string, Record<string, string>>();
  for (const r of rows.reactions) {
    const mid = str(r['message_id']);
    const who = str(r['peer_id']);
    const emoji = str(r['emoji']);
    if (!mid || !who || !emoji) continue;
    reactions.set(mid, { ...(reactions.get(mid) ?? {}), [who]: emoji });
  }
  let messages = 0;
  for (const m of rows.messages) {
    const id = str(m['id']);
    const conversation = str(m['contact_id']);
    const sentAt = num(m['sent_at']);
    const kind = str(m['kind']) ?? 'text';
    if (!id || !isWireId(id) || !conversation || sentAt === null) continue;
    const group = groupIds.has(conversation) || store.group(conversation) !== null;
    if (!group && conversation === self) continue; // notes to self: not a thing here
    const mine = m['outgoing'] === 1 || m['outgoing'] === true;
    const sender = str(m['sender_id']);
    const text = str(m['text']) ?? '';
    const status = str(m['status']);
    const edited = num(m['edited_at']);
    const expires = num(m['expires_at']);
    const replyId = str(m['reply_to_id']);
    const message: Message = {
      id,
      peerId: conversation,
      mine,
      text,
      sentAt: new Date(sentAt).toISOString(),
      ...(group ? { group: true as const } : {}),
      ...(group && sender && !mine ? { sender } : {}),
      ...(status === 'read' || status === 'delivered' || status === 'sent' || status === 'pending' || status === 'failed'
        ? { status }
        : {}),
      ...(edited ? { editedAt: edited } : {}),
      ...(expires ? { expiresAt: expires } : {}),
      ...(replyId
        ? { replyTo: { id: replyId, ...(str(m['reply_to_sender']) ? { sender: str(m['reply_to_sender'])! } : {}), ...(str(m['reply_to_preview']) ? { preview: str(m['reply_to_preview'])! } : {}) } }
        : {}),
      ...(kind === 'call' || kind === 'notice' ? { notice: true as const } : {}),
      ...(kind === 'call' ? { call: true as const } : {}),
      ...(kind !== 'text' && kind !== 'call' && kind !== 'notice'
        ? { media: { kind, mime: 'application/octet-stream', size: 0, ...(str(m['file_name']) ? { name: str(m['file_name'])! } : {}) } }
        : {}),
      ...(reactions.has(id) ? { reactions: reactions.get(id)! } : {}),
    };
    if (store.appendMessage(message)) messages++;
  }
  return { contacts, groups, messages };
}

function timerNoticeText(who: string, ms: number): string {
  if (ms <= 0) return `${who} turned off disappearing messages`;
  const hours = ms / 3_600_000;
  const span =
    hours < 1 ? `${Math.round(ms / 60_000)} minutes`
      : hours < 24 ? `${Math.round(hours)} hour${Math.round(hours) === 1 ? '' : 's'}`
        : `${Math.round(hours / 24)} day${Math.round(hours / 24) === 1 ? '' : 's'}`;
  return `${who} set messages to disappear after ${span}`;
}

/** The description of an attachment we do not hold the bytes of. */
function describeMedia(body: Record<string, unknown>): MediaAttachment {
  const mime = typeof body['mime'] === 'string' ? body['mime'] : 'application/octet-stream';
  const name = typeof body['name'] === 'string' ? body['name'].split(/[\\/]/).pop() || undefined : undefined;
  const size = typeof body['size'] === 'number' ? body['size'] : 0;
  return {
    mime,
    kind: typeof body['kind'] === 'string' ? body['kind'] : kindForMime(mime),
    size,
    ...(name ? { name } : {}),
    ...(typeof body['duration_ms'] === 'number' ? { durationMs: body['duration_ms'] } : {}),
  };
}

/** Decrypt fetched blob bytes into something the page can show. Null on
 * tamper: the key came from inside the session, so a failure means the
 * bytes are not what was sent, and rendering "something" would be a lie. */
function decryptedMedia(
  core: StonechatCore,
  body: Record<string, unknown>,
  keyB64: string,
  nonceB64: string,
  bytes: Uint8Array,
): MediaAttachment | null {
  let plain: Uint8Array | null;
  try {
    plain = core.blobOpen(b64decode(keyB64), b64decode(nonceB64), bytes);
  } catch {
    plain = null;
  }
  if (plain === null) return null;
  const described = describeMedia(body);
  return {
    ...described,
    // `.slice()` copies into a buffer the Blob constructor will accept: what
    // the core hands back is backed by wasm memory, which TypeScript types
    // as possibly shared.
    url: URL.createObjectURL(new Blob([plain.slice().buffer as ArrayBuffer], { type: described.mime })),
    size: plain.length,
  };
}
