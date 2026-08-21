/**
 * What a browser session keeps, and what it deliberately does not.
 *
 * WEB_CLIENT.md blocker 3: a browser is a bad place for long-lived secrets.
 * `localStorage` is readable by any XSS, any extension, anyone at the keyboard,
 * and WebCrypto non-extractable keys do not help because the ratchet runs in
 * WASM and needs raw bytes. That is not fixable here — it is why the web device
 * is a **bounded** device: its certificate is short-lived, it cannot renew
 * itself, and the phone can revoke it.
 *
 * So the rule is: keep what the session cannot function without, and nothing
 * else.
 *
 * **Kept** — device keys, the link grant, and ratchet state. The ratchet is the
 * one people are tempted to leave in memory: it must survive a reload, because
 * a peer who has advanced their chain cannot rewind it. Losing it does not lose
 * a message, it breaks the conversation permanently.
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
 * No encryption-at-rest theatre: any key the page could use to decrypt this
 * would have to live in the same storage, readable by exactly the same
 * attacker. It would look like protection and be none.
 */
import type { SessionState, SignedCert } from './core.js';
// Type-only, so this does not create a runtime cycle with protocol.ts.
import type { Message } from './protocol.js';
import type { LinkGrant } from './linking.js';

const KEYS = 'stonechat.device_keys';
const GRANT = 'stonechat.grant';
const SESSIONS = 'stonechat.sessions';
const PEER_CERTS = 'stonechat.peer_certs';
const CONTACTS = 'stonechat.contacts';
const PREKEYS = 'stonechat.prekeys';
const MESSAGES = 'stonechat.messages';
const GROUPS = 'stonechat.groups';

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

/** A peer we have exchanged something with. */
/**
 * A group, as this browser understands it.
 *
 * Groups exist only on members' devices — no hub row, no mailbox row, nothing
 * server-side to fetch. Everything here arrives in a `group_create` or
 * `group_update` envelope, which is also why a browser linked *after* a group
 * was formed knows nothing about it until the roster changes: there is no
 * request that asks.
 *
 * `version` is what makes an out-of-order update safe to drop. Envelopes are
 * per-device and retried independently, so an older roster can arrive after a
 * newer one and would otherwise resurrect a removed member.
 */
export interface Group {
  id: string;
  name: string;
  admin: string;
  version: number;
  members: { stonechatId: string; pubkey: string; displayName?: string }[];
}

export interface Contact {
  stonechatId: string;
  /** Their identity key, verified to commit to their SC- ID. */
  pubkey: string;
  /** Their mailbox's bundle token, if they have sent us anything — it rides
   * every envelope. Without it we can only reach their primary device, which
   * is exactly what a stranger sending a first message gets. */
  bundleToken?: string;
}

/** Our own prekey private halves, by id. Consumed one-time keys are deleted:
 * what we hold is exactly what we can decrypt. */
export interface PrekeyStore {
  spk: { id: number; pub: string; sec: string };
  kspk: { id: number; pub: string; seed: string };
  opks: Record<number, { pub: string; sec: string }>;
  kopks: Record<number, { pub: string; seed: string }>;
  nextId: number;
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

export const store = {
  deviceKeys: () => localStorage.getItem(KEYS),
  setDeviceKeys: (encoded: string) => localStorage.setItem(KEYS, encoded),

  grant: () => read<LinkGrant>(GRANT),
  setGrant: (grant: LinkGrant) => write(GRANT, grant),

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

  /** A peer device's verified certificate, keyed `peerId/device`.
   *
   * Persisted beside the session because it is needed for exactly as long: it
   * names the key to seal to. Without it, replying to someone who wrote to us
   * first would have to re-fetch their bundle — and the handshake they sent
   * already contained it. */
  peerCert(peerId: string, device: number): SignedCert | null {
    const all = read<Record<string, SignedCert>>(PEER_CERTS) ?? {};
    return all[`${peerId}/${device}`] ?? null;
  },
  setPeerCert(peerId: string, device: number, cert: SignedCert): void {
    const all = read<Record<string, SignedCert>>(PEER_CERTS) ?? {};
    all[`${peerId}/${device}`] = cert;
    write(PEER_CERTS, all);
  },

  contacts: () => read<Record<string, Contact>>(CONTACTS) ?? {},
  setContact(contact: Contact): void {
    const all = store.contacts();
    // Merge rather than replace: a bundle token learned from an incoming
    // envelope must not be lost when the contact is next touched.
    all[contact.stonechatId] = { ...all[contact.stonechatId], ...contact };
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
   * mid-conversation would otherwise double every recent message.
   */
  appendMessage(message: Message): void {
    const all = store.messages();
    const thread = all[message.peerId] ?? [];
    if (thread.some((m) => m.id === message.id)) return;
    thread.push(message);
    // Trim from the front: the oldest go first, and the cap is per
    // conversation so one busy chat cannot evict every other.
    if (thread.length > MAX_MESSAGES_PER_CONVERSATION) {
      thread.splice(0, thread.length - MAX_MESSAGES_PER_CONVERSATION);
    }
    all[message.peerId] = thread;
    write(MESSAGES, all);
  },

  groups: () => read<Record<string, Group>>(GROUPS) ?? {},

  /**
   * Record a roster, unless we already hold a newer one.
   *
   * Returns whether anything changed, so the view only re-renders on real
   * news. A same-version repeat is ordinary: `group_create` goes to every
   * device independently and any of them can be redelivered.
   */
  upsertGroup(group: Group): boolean {
    const all = store.groups();
    const held = all[group.id];
    if (held && held.version >= group.version) return false;
    all[group.id] = group;
    write(GROUPS, all);
    return true;
  },

  /**
   * Drop one conversation's messages, keeping the contact and its session.
   *
   * Deliberately narrower than [clear]: the ratchet, the peer's certificates
   * and its display name all survive, so the next message continues the
   * conversation instead of starting a handshake. Clearing history must not
   * cost the relationship.
   */
  clearConversation(peerId: string): void {
    const all = store.messages();
    if (!(peerId in all)) return;
    delete all[peerId];
    write(MESSAGES, all);
  },

  /** Forget everything. Used when a link is refused or a device is revoked —
   * leaving a dead ratchet behind would make the next link fail confusingly. */
  clear(): void {
    for (const key of [
      KEYS,
      GRANT,
      SESSIONS,
      PEER_CERTS,
      CONTACTS,
      PREKEYS,
      MESSAGES,
    ]) {
      localStorage.removeItem(key);
    }
  },
};
