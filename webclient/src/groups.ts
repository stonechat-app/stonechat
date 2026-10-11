/**
 * The group rules that are decisions rather than plumbing (PROTOCOL.md
 * "Groups"): which roster a client accepts, how two members' views of the
 * roster compare, and the hashes that let members notice when what they
 * hold differs. Pure functions — `protocol.ts` does the I/O around them.
 *
 * Counterpart of `app/lib/core/group_rules.dart`, and checked against the
 * same vectors, so the app and the browser agree byte for byte on what a
 * roster hashes to — two clients that disagreed here would each report the
 * other as holding a different roster.
 */
import { utf8 } from './bytes.js';

/** The largest roster a receiver accepts. Above the cap the app builds (25),
 * so a later, larger cap does not strand older clients — and bounded, so one
 * envelope cannot make a client fan out to thousands of mailboxes. */
export const GROUP_ROSTER_MAX = 100;

/** How many earlier messages one group message vouches for (`seen`). */
export const GROUP_SEEN_MAX = 4;

/** Unkeyed BLAKE2b-256, base64. */
export type HashB64 = (data: Uint8Array) => string;

/**
 * What a roster commits to: the group, its version, its admin and who is in
 * it. Names are display data and stay out. Computed over the roster **as the
 * admin issued it** — a `group_leave` applied locally does not change it —
 * so two members at the same version hold the same hash unless the admin
 * told them different things.
 */
export function rosterHash(
  hash: HashB64,
  args: { groupId: string; version: number; admin: string; memberIds: Iterable<string> },
): string {
  const ids = [...args.memberIds].sort();
  return hash(
    utf8.encode(
      `stonechat-v1-roster|${args.groupId}|${args.version}|${args.admin}|${ids.join(',')}`,
    ),
  );
}

/** The part of a group message a content hash covers: its text, or for
 * media the blob and the key that opens it. Null for a payload that is
 * neither. */
export function groupMessageBody(payload: Record<string, unknown>): string | null {
  const text = payload['text'];
  if (typeof text === 'string') return `text|${text}`;
  const blobId = payload['blob_id'];
  const key = payload['key'];
  const nonce = payload['blob_nonce'];
  if (typeof blobId === 'string' && typeof key === 'string' && typeof nonce === 'string') {
    return `media|${blobId}|${key}|${nonce}`;
  }
  return null;
}

/** What one member received as message `id` from `senderId`. `salt` is
 * random per message and travels inside it, so someone who was never sent
 * the message cannot test guesses of its text against the hash. The body
 * goes last: it is the only field that may contain `|`. */
export function groupMessageHash(
  hash: HashB64,
  args: { groupId: string; senderId: string; id: string; salt: string; body: string },
): string {
  return hash(
    utf8.encode(
      `stonechat-v1-gmsg|${args.groupId}|${args.senderId}|${args.id}|${args.salt}|${args.body}`,
    ),
  );
}

/** The `roster` block of a group message: the sender's view of membership. */
export interface RosterClaim {
  version: number;
  hash: string | null;
  admin: string | null;
}

/** Null when absent or malformed — an older client sends none, and that is
 * not an error. */
export function rosterClaim(payload: Record<string, unknown>): RosterClaim | null {
  const r = payload['roster'];
  if (typeof r !== 'object' || r === null) return null;
  const v = (r as Record<string, unknown>)['v'];
  if (typeof v !== 'number' || !Number.isInteger(v) || v < 0) return null;
  const h = (r as Record<string, unknown>)['h'];
  const admin = (r as Record<string, unknown>)['admin'];
  return {
    version: v,
    hash: typeof h === 'string' ? h : null,
    admin: typeof admin === 'string' ? admin : null,
  };
}

export type RosterView =
  /** Same version, and the same roster as far as either side can tell. */
  | 'same'
  /** The sender did not say. */
  | 'unknown'
  /** The sender holds a newer roster than we do: we missed an update. */
  | 'peerAhead'
  /** The sender holds an older one: they missed an update. */
  | 'peerBehind'
  /** Same version, different members. Only an admin (or two of its devices)
   * issuing two rosters under one version produces this. */
  | 'diverged';

export function compareRoster(args: {
  heldVersion: number;
  heldHash: string | null;
  claim: RosterClaim | null;
}): RosterView {
  const { heldVersion, heldHash, claim } = args;
  if (claim === null) return 'unknown';
  if (claim.version > heldVersion) return 'peerAhead';
  if (claim.version < heldVersion) return 'peerBehind';
  if (heldHash !== null && claim.hash !== null && heldHash !== claim.hash) return 'diverged';
  return 'same';
}

/** The outcome of checking a `group_create` / `group_update`. */
export type MembershipVerdict =
  | { accepted: true; handover: boolean }
  | { accepted: false; rejected: string };

/**
 * Whether a roster from `from` may replace what we hold.
 *
 * `memberIds` are the roster's IDs, each already checked against its key.
 * `held` is the group as we hold it, null on first sight. `senderIsContact`
 * is whether `from` is an accepted contact of ours, or ourselves (one of our
 * own devices mirroring a group it administers).
 */
export function checkMembership(args: {
  from: string;
  payloadAdmin: string;
  version: number;
  memberIds: string[];
  held: { adminId: string; version: number } | null;
  senderIsContact: boolean;
}): MembershipVerdict {
  const { from, payloadAdmin, version, memberIds, held, senderIsContact } = args;
  if (memberIds.length > GROUP_ROSTER_MAX) {
    return { accepted: false, rejected: 'roster is larger than a group may be' };
  }
  if (new Set(memberIds).size !== memberIds.length) {
    return { accepted: false, rejected: 'roster lists a member twice' };
  }
  if (!memberIds.includes(payloadAdmin)) {
    return { accepted: false, rejected: 'roster names an admin who is not in it' };
  }
  if (held === null) {
    // First sight. Only the admin introduces a group, and only someone we
    // have accepted as a contact may put us in one: other members can be
    // strangers, the person who adds us cannot.
    if (from !== payloadAdmin) return { accepted: false, rejected: 'not from the admin it names' };
    if (!senderIsContact) return { accepted: false, rejected: 'group invite from a non-contact' };
    return { accepted: true, handover: false };
  }
  // A group we hold: only the admin we recorded speaks for it. Checking
  // `from` against the payload's own `admin` instead would let any member
  // take the group by naming themselves — whereas the recorded admin naming
  // someone else is exactly how the role is handed over.
  if (from !== held.adminId) return { accepted: false, rejected: 'not from the admin on record' };
  if (version <= held.version) return { accepted: false, rejected: 'stale or replayed roster' };
  return { accepted: true, handover: payloadAdmin !== held.adminId };
}
