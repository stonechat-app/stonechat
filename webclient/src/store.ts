/**
 * What a browser session keeps, and what it deliberately does not.
 *
 * A browser is a bad place for long-lived secrets.
 * `localStorage` is readable by any XSS, any extension, anyone at the keyboard,
 * and WebCrypto non-extractable keys do not help because the ratchet runs in
 * WASM and needs raw bytes. That is not fixable here — it is why the web device
 * is a **bounded** device: its certificate is short-lived, it cannot renew
 * itself, and the phone can revoke it.
 *
 * So the rule is: keep what the session cannot function without, and nothing
 * else.
 *
 * **Kept** — device keys, the link grant, ratchet state, peer certificates
 * and device manifests, prekey private halves, and the outbox. The ratchet is
 * the one people are tempted to leave in memory: it must survive a reload,
 * because a peer who has advanced their chain cannot rewind it. Losing it does
 * not lose a message, it breaks the conversation permanently.
 *
 * **Kept, with a bound** — message history. This reverses the original
 * decision, and the reversal is worth stating rather than burying: the
 * tethered shape said history stays on the phone, so a reload showed an empty
 * conversation. That is defensible and it is also unusable — a client that
 * forgets the conversation every refresh is not one anyone will test with,
 * let alone use.
 *
 * What it costs: a compromised browser session used to yield *messages during
 * that session*. Now it yields what this browser has seen, up to the cap. The
 * certificate bounds what the session can **do**, not what is sitting on disk,
 * so the cap is the only thing bounding this — hence
 * [MAX_MESSAGES_PER_CONVERSATION], and hence Unlink wiping it.
 *
 * **Not kept** — decrypted media. An object URL dies with the tab and
 * `localStorage` is far too small for files, so an attachment survives only
 * as a description after a reload. The phone keeps the file.
 *
 * No encryption-at-rest theatre: any key the page could use to decrypt this
 * would have to live in the same storage, readable by exactly the same
 * attacker. It would look like protection and be none.
 */
import type { SessionState, SignedCert } from './core.js';
import type { LinkGrant } from './linking.js';
import type { DeviceManifest } from './manifest.js';
import type {
  Contact,
  Group,
  Message,
  OutboxEntry,
  Parked,
} from './model.js';

export type { Contact, Group, GroupMember, Message, OutboxEntry, Parked } from './model.js';

/// Every key this module owns starts with this, which is what lets [clear]
/// find them all without being told.
const NAMESPACE = 'stonechat.';
const KEYS = 'stonechat.device_keys';
const GRANT = 'stonechat.grant';
const SESSIONS = 'stonechat.sessions';
const PEER_CERTS = 'stonechat.peer_certs';
const MANIFESTS = 'stonechat.manifests';
const CONTACTS = 'stonechat.contacts';
const PREKEYS = 'stonechat.prekeys';
const MESSAGES = 'stonechat.messages';
const GROUPS = 'stonechat.groups';
const OUTBOX = 'stonechat.outbox';
const PARKED = 'stonechat.parked';
const RECEIPTS = 'stonechat.receipts';
const SETTINGS = 'stonechat.settings';

/**
 * How much of a conversation a browser keeps.
 *
 * A bound rather than a number pulled from nowhere: this is the blast radius
 * of a compromised session, and "everything, forever" is the wrong answer for
 * a device whose whole justification is being disposable. Enough to scroll
 * back through a conversation; not enough to be an archive. The phone is the
 * archive.
 */
export const MAX_MESSAGES_PER_CONVERSATION = 200;

/**
 * Where a conversation's messages are filed.
 *
 * A direct conversation is keyed by the peer's SC- ID and a group by its id
 * behind a prefix no SC- ID can carry, so the two can never name the same
 * thread whatever a sender puts in `group_id`. Sharing one key space is what
 * let a roster whose id was a contact's SC- ID take over that contact's
 * conversation.
 */
export function threadKey(id: string, group: boolean): string {
  return group ? `group:${id}` : id;
}

/** Our own prekey private halves, by id. Consumed one-time keys are deleted:
 * what we hold is exactly what we can decrypt. The previous signed prekey of
 * each kind is kept through one rotation, as the app does, so a handshake
 * that used the old one still completes. */
export interface PrekeyStore {
  spk: { id: number; pub: string; sec: string; createdAt?: number };
  prevSpk?: { id: number; pub: string; sec: string };
  kspk: { id: number; pub: string; seed: string; createdAt?: number };
  prevKspk?: { id: number; pub: string; seed: string };
  opks: Record<number, { pub: string; sec: string }>;
  kopks: Record<number, { pub: string; seed: string }>;
  nextId: number;
}

export interface Settings {
  /** Whether a peer learns we have read their message. Delivery receipts
   * are unconditional. */
  sendReadReceipts?: boolean;
}

function read<T>(key: string): T | null {
  const raw = localStorage.getItem(key);
  if (raw === null) return null;
  try {
    return JSON.parse(raw) as T;
  } catch {
    // Corrupt is treated as absent. A half-parsed ratchet is worse than none:
    // it would encrypt with a key the peer cannot derive.
    localStorage.removeItem(key);
    return null;
  }
}

function write(key: string, value: unknown): void {
  localStorage.setItem(key, JSON.stringify(value));
}

/** The stored form of a message: without the object URL, which dies with
 * the tab and would read back as a broken image. */
function storable(message: Message): Message {
  if (!message.media || message.media.url === undefined) return message;
  const { url: _url, ...media } = message.media;
  void _url;
  return { ...message, media };
}

export const store = {
  deviceKeys: () => localStorage.getItem(KEYS),
  setDeviceKeys: (encoded: string) => localStorage.setItem(KEYS, encoded),

  grant: () => read<LinkGrant>(GRANT),
  setGrant: (grant: LinkGrant) => write(GRANT, grant),

  settings: () => read<Settings>(SETTINGS) ?? {},
  setSettings: (patch: Settings) => write(SETTINGS, { ...store.settings(), ...patch }),

  /** Ratchet state, keyed `peerId/device`. */
  session(peerId: string, device: number): SessionState | null {
    const all = read<Record<string, SessionState>>(SESSIONS) ?? {};
    return all[`${peerId}/${device}`] ?? null;
  },
  setSession(peerId: string, device: number, state: SessionState): void {
    const all = read<Record<string, SessionState>>(SESSIONS) ?? {};
    all[`${peerId}/${device}`] = state;
    write(SESSIONS, all);
  },
  /** A device that is gone (410) or re-keyed: nothing is owed on its ratchet. */
  deleteSession(peerId: string, device: number): void {
    const all = read<Record<string, SessionState>>(SESSIONS) ?? {};
    delete all[`${peerId}/${device}`];
    write(SESSIONS, all);
  },

  /** A peer device's verified certificate, keyed `peerId/device`.
   *
   * Persisted beside the session because it is needed for exactly as long: it
   * names the key to seal to, and it is checked on every envelope from that
   * device — expired means the device is refetched, and dropped if nothing
   * current is served. */
  peerCert(peerId: string, device: number): SignedCert | null {
    const all = read<Record<string, SignedCert>>(PEER_CERTS) ?? {};
    return all[`${peerId}/${device}`] ?? null;
  },
  setPeerCert(peerId: string, device: number, cert: SignedCert): void {
    const all = read<Record<string, SignedCert>>(PEER_CERTS) ?? {};
    all[`${peerId}/${device}`] = cert;
    write(PEER_CERTS, all);
  },
  deletePeerCert(peerId: string, device: number): void {
    const all = read<Record<string, SignedCert>>(PEER_CERTS) ?? {};
    delete all[`${peerId}/${device}`];
    write(PEER_CERTS, all);
  },

  /** The newest verified device manifest held per identity. Only ever moves
   * forward: a directory serving an older one is serving a stale one. */
  manifest(stonechatId: string): DeviceManifest | null {
    const all = read<Record<string, DeviceManifest>>(MANIFESTS) ?? {};
    return all[stonechatId] ?? null;
  },
  setManifest(stonechatId: string, manifest: DeviceManifest): boolean {
    const all = read<Record<string, DeviceManifest>>(MANIFESTS) ?? {};
    const held = all[stonechatId];
    if (held && held.version >= manifest.version) return false;
    all[stonechatId] = manifest;
    write(MANIFESTS, all);
    return true;
  },

  contacts: () => read<Record<string, Contact>>(CONTACTS) ?? {},
  contact: (stonechatId: string): Contact | null => store.contacts()[stonechatId] ?? null,
  setContact(contact: Contact): void {
    const all = store.contacts();
    // Merge rather than replace: a bundle token learned from an incoming
    // envelope must not be lost when the contact is next touched.
    all[contact.stonechatId] = { ...all[contact.stonechatId], ...contact };
    write(CONTACTS, all);
  },
  deleteContact(stonechatId: string): void {
    const all = store.contacts();
    delete all[stonechatId];
    write(CONTACTS, all);
  },

  prekeys: () => read<PrekeyStore>(PREKEYS),
  setPrekeys: (value: PrekeyStore) => write(PREKEYS, value),

  /** Every conversation this browser has kept, newest last. */
  messages: () => read<Record<string, Message[]>>(MESSAGES) ?? {},

  /**
   * Record one message, or ignore it if we already have it.
   *
   * Deduplicated by id because redelivery is normal, not exceptional: the
   * relay re-sends anything unacked when a socket reconnects, so a refresh
   * mid-conversation would otherwise double every recent message. Returns
   * whether it was new.
   */
  appendMessage(message: Message): boolean {
    const all = store.messages();
    const key = threadKey(message.peerId, message.group === true);
    const thread = all[key] ?? [];
    if (thread.some((m) => m.id === message.id)) return false;
    thread.push(storable(message));
    // By time, so a sync copy that arrives late sits where it was sent.
    thread.sort((a, b) => Date.parse(a.sentAt) - Date.parse(b.sentAt));
    // Trim from the front: the oldest go first, and the cap is per
    // conversation so one busy chat cannot evict every other.
    if (thread.length > MAX_MESSAGES_PER_CONVERSATION) {
      thread.splice(0, thread.length - MAX_MESSAGES_PER_CONVERSATION);
    }
    all[key] = thread;
    write(MESSAGES, all);
    return true;
  },

  /** One message by id, wherever it is filed. Ids are UUIDs, so a collision
   * across conversations is not a thing that happens. */
  findMessage(id: string): { key: string; message: Message } | null {
    for (const [key, thread] of Object.entries(store.messages())) {
      const message = thread.find((m) => m.id === id);
      if (message) return { key, message };
    }
    return null;
  },

  /** Change a stored message in place. Returns the updated message, or null
   * when it is not held. */
  updateMessage(id: string, patch: (m: Message) => Message | null): Message | null {
    const all = store.messages();
    for (const thread of Object.values(all)) {
      const at = thread.findIndex((m) => m.id === id);
      if (at === -1) continue;
      const next = patch(thread[at]!);
      if (next === null) return null;
      thread[at] = storable(next);
      write(MESSAGES, all);
      return next;
    }
    return null;
  },

  /** Drop single messages (expired, deleted for me). */
  removeMessages(ids: Set<string>): boolean {
    const all = store.messages();
    let touched = false;
    for (const [key, thread] of Object.entries(all)) {
      const kept = thread.filter((m) => !ids.has(m.id));
      if (kept.length !== thread.length) {
        all[key] = kept;
        touched = true;
      }
    }
    if (touched) write(MESSAGES, all);
    return touched;
  },

  groups: () => read<Record<string, Group>>(GROUPS) ?? {},
  group: (id: string): Group | null => store.groups()[id] ?? null,

  /**
   * Record a roster, unless we already hold a newer one.
   *
   * Returns whether anything changed, so the view only re-renders on real
   * news. A same-version repeat is ordinary: `group_create` goes to every
   * device independently and any of them can be redelivered.
   *
   * Versions only: *whose* roster this is, and whether its keys are genuine,
   * is decided by the protocol layer before anything reaches here.
   */
  upsertGroup(group: Group): boolean {
    // An SC- ID is never a group id. The protocol layer refuses these with the
    // core's normaliser; this is the same rule at the last door, for a caller
    // that forgot.
    if (/^\s*SC-/i.test(group.id)) return false;
    const all = store.groups();
    const held = all[group.id];
    if (held && held.version >= group.version) return false;
    all[group.id] = group;
    write(GROUPS, all);
    return true;
  },

  /** Change a held group in place without a new roster version: a member's
   * bundle token learned, a `group_leave` applied, a timer set. */
  patchGroup(id: string, patch: Partial<Group>): void {
    const all = store.groups();
    const held = all[id];
    if (!held) return;
    all[id] = { ...held, ...patch };
    write(GROUPS, all);
  },

  outbox: () => read<Record<string, OutboxEntry>>(OUTBOX) ?? {},
  setOutbox(entry: OutboxEntry): void {
    const all = store.outbox();
    all[entry.messageId] = entry;
    write(OUTBOX, all);
  },
  deleteOutbox(messageId: string): void {
    const all = store.outbox();
    if (!(messageId in all)) return;
    delete all[messageId];
    write(OUTBOX, all);
  },

  parked: () => read<Parked[]>(PARKED) ?? [],
  setParked: (list: Parked[]) => write(PARKED, list),

  /** Per group message: which members have receipted it, and how far. */
  receipts: (messageId: string): Record<string, 'delivered' | 'read'> =>
    (read<Record<string, Record<string, 'delivered' | 'read'>>>(RECEIPTS) ?? {})[messageId] ?? {},
  setReceipt(messageId: string, from: string, kind: 'delivered' | 'read'): void {
    const all = read<Record<string, Record<string, 'delivered' | 'read'>>>(RECEIPTS) ?? {};
    const held = all[messageId] ?? {};
    if (held[from] === 'read') return; // only forward
    held[from] = kind;
    all[messageId] = held;
    write(RECEIPTS, all);
  },

  /**
   * Drop one conversation's messages, keeping the contact and its session.
   *
   * Deliberately narrower than [clear]: the ratchet, the peer's certificates
   * and its display name all survive, so the next message continues the
   * conversation instead of starting a handshake. Clearing history must not
   * cost the relationship.
   */
  clearConversation(peerId: string, group = false): void {
    const all = store.messages();
    const key = threadKey(peerId, group);
    if (!(key in all)) return;
    delete all[key];
    write(MESSAGES, all);
  },

  /** Forget everything. Used when a link is refused or a device is revoked —
   * leaving a dead ratchet behind would make the next link fail confusingly. */
  clear(): void {
    // By prefix, not by list. The list had to be updated every time storage
    // grew, and the first time it was not, Unlink left group rosters — names,
    // member IDs and their keys — on a browser somebody had just
    // disconnected. A forgotten key is silent, survives the one action whose
    // whole job is to forget, and is only ever found by looking in devtools.
    // Collected first, then removed: removing during the walk shifts every
    // later index and silently skips half of them.
    const ours: string[] = [];
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (key?.startsWith(NAMESPACE)) ours.push(key);
    }
    for (const key of ours) localStorage.removeItem(key);
  },
};
