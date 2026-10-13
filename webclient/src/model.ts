/**
 * What a conversation is made of, as this browser holds it.
 *
 * The shapes `store.ts` persists and `ui.ts` renders. Kept apart from the
 * protocol so the store, which the protocol writes to, does not import the
 * protocol at runtime.
 */

/** Delivery state of a message. Mirrors the app's `MessageStatus`: receipts
 * only ever move a message forward, and `failed` ranks with `pending` so a
 * receipt that arrives for a message we gave up on still heals it. */
export type MessageStatus = 'pending' | 'sent' | 'delivered' | 'read' | 'failed';

export function statusRank(s: MessageStatus | undefined): number {
  switch (s) {
    case 'sent':
      return 1;
    case 'delivered':
      return 2;
    case 'read':
      return 3;
    default:
      return 0;
  }
}

/**
 * A decrypted attachment, ready to render.
 *
 * `url` is an object URL over bytes this tab decrypted — it never points at
 * the mailbox, which only ever held ciphertext it had no key for. It lives
 * as long as the tab: the store drops it on write, and a message read back
 * after a reload has `media` without a `url`, which renders as an attachment
 * this browser no longer holds. The phone keeps the file.
 */
export interface MediaAttachment {
  url?: string;
  mime: string;
  kind: string;
  size: number;
  name?: string;
  durationMs?: number;
}

/** A quote of an earlier message: a display snapshot, never resolved. */
export interface ReplyTo {
  id: string;
  sender?: string;
  preview?: string;
}

export interface Message {
  id: string;
  /** The conversation this belongs to: a peer's SC- ID, or a group's id. */
  peerId: string;
  mine: boolean;
  text: string;
  /** ISO-8601. */
  sentAt: string;
  media?: MediaAttachment;
  /**
   * Set when `peerId` is a group's id rather than a peer's.
   *
   * The conversation's type travels with the message instead of being guessed
   * from the id: the id is whatever the sender wrote, and a thread chosen by
   * looking it up is a thread the sender chose.
   */
  group?: true;
  /**
   * Who actually sent it, when that is not the same as the conversation.
   *
   * In a group the conversation is the group and the sender is a member, so a
   * thread that labelled everything with the conversation id would credit
   * every message to the group itself.
   */
  sender?: string;
  /** Ours: pending → sent → delivered → read, or failed. Theirs: whether we
   * have shown it (`read`) — what `sync_read` carries between our devices. */
  status?: MessageStatus;
  /** Why a send is pending or failed, for the ledger to say so. */
  error?: string;
  /** Milliseconds; set by a remote edit. */
  editedAt?: number;
  /** Tombstoned by its author. The text is gone. */
  deleted?: true;
  /** Reactor's SC- ID → emoji. One per person; the empty string clears. */
  reactions?: Record<string, string>;
  replyTo?: ReplyTo;
  /** Milliseconds. Deleted on every device once passed, read or not. */
  expiresAt?: number;
  /** A system row ("X was added"), not something anyone typed. */
  notice?: true;
  /** Incoming group messages: BLAKE2b over the content as it first arrived,
   * so a `seen` entry from another member can be compared against it. */
  contentHash?: string;
  /** Our own group messages: the salt we sent, so a retry carries the same. */
  salt?: string;
  /** A pending contact request we have not answered here. */
  request?: true;
  /** A call's epitaph ("Missed voice call", "Video call · 3:42"): a notice
   * that is also local bookkeeping, written by each side for itself. */
  call?: true;
}

export interface Contact {
  stonechatId: string;
  /** Their identity key, verified to commit to their SC- ID. Empty until
   * the directory has been asked. */
  pubkey: string;
  /** Their mailbox's bundle token, if they have sent us anything — it rides
   * every envelope. Without it we can only reach their primary device, which
   * is exactly what a stranger sending a first message gets. */
  bundleToken?: string;
  /** From a contact request, accept, profile update or roster. */
  displayName?: string;
  /** `{data, mime}` is a photo; null is cleared; absent is never told. */
  avatar?: { data: string; mime: string } | null;
  /** When the profile we hold was sent, so an older one cannot regress it. */
  profileAt?: number;
  /**
   * What this browser knows of the relationship. A browser is linked after
   * most contacts were accepted and there is no contact sync, so this is
   * usually unknown — see README "Still missing".
   */
  status?: 'accepted' | 'pendingIn' | 'pendingOut';
  /** Blocked at (ms), null or absent when not. Learned over `sync_block`. */
  blockedAt?: number | null;
  /** Disappearing-messages timer for the DM, and when it was last set. */
  expireTimerMs?: number;
  expireTimerAt?: number;
  /** The mailbox's `devices_v` as last reported; a bump drops the cached
   * device list. */
  devicesV?: number;
}

export interface GroupMember {
  stonechatId: string;
  pubkey: string;
  displayName?: string;
  /** Learned from anything they send; lets us reach all their devices. */
  bundleToken?: string;
}

/**
 * A group, as this browser understands it.
 *
 * Groups exist only on members' devices — no hub row, no mailbox row, nothing
 * server-side to fetch. Everything here arrives in a `group_create` or
 * `group_update` envelope, which is also why a browser linked *after* a group
 * was formed knows nothing about it until the roster changes or a member's
 * message says it is behind and the admin answers a `group_sync`.
 */
export interface Group {
  id: string;
  name: string;
  /** The group's photo, set by the admin and carried by every roster. */
  avatar?: { data: string; mime: string };
  /** The admin on record. Only this identity's rosters are applied, and a
   * roster from it naming another member is a handover. */
  admin: string;
  version: number;
  members: GroupMember[];
  /** BLAKE2b over the roster as the admin issued it. Absent for a roster
   * held from before this was recorded. */
  rosterHash?: string;
  /** The highest roster version a member has claimed above ours while we
   * are the admin — a device behind the group it administers. */
  seenVersion?: number;
  expireTimerMs?: number;
  expireTimerAt?: number;
  /**
   * The admin's latest roster no longer includes us.
   *
   * Kept rather than deleted so the history stays readable and so the version
   * we were removed at is remembered — deleting the record would let a replay
   * of any older roster look like first sight and put us back.
   */
  removed?: true;
}

/** A send still owed to someone. The retry sweep works through these. */
export interface OutboxEntry {
  messageId: string;
  conversationId: string;
  group: boolean;
  type: string;
  payload: Record<string, unknown>;
  /** DM media only: the blob on the recipient's mailbox, so the outer
   * envelope can name it. */
  blobId?: string;
  /** Peer → devices still owed a copy. Empty list: every device of that
   * peer is still to be determined (the fan-out never ran). */
  owed: Record<string, number[]>;
  attempts: number;
  lastAt: number;
  since: number;
}

/** A group message that arrived ahead of its roster. */
export interface Parked {
  id: string;
  groupId: string;
  from: string;
  fromDevice: number;
  type: string;
  sentAt: string;
  payload: Record<string, unknown>;
  parkedAt: number;
}
