/**
 * What arrives on the wire, checked where it enters.
 *
 * Counterpart of `app/lib/core/wire_ids.dart` and the top of the app's
 * `handleIncoming`: the shape checks PROTOCOL.md "What a recipient checks"
 * requires *before* any cryptography is attempted on an envelope. They are
 * cheap, they are the same on every client, and an envelope that fails one
 * is dropped silently — and acked, because it can never succeed.
 */

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Whether a value is a UUID in its canonical 36-character form.
 *
 * Envelope and blob ids are UUIDs by construction — every client mints them
 * with a UUID generator — so anything else was not written by a client. They
 * end up in URLs (`/blob/{id}`) and in storage keys, so the shape is refused
 * here rather than escaped at every use.
 */
export function isWireId(value: unknown): value is string {
  return typeof value === 'string' && UUID.test(value);
}

/** The inner envelope, after the checks below. */
export interface Inner {
  id: string;
  type: string;
  from: string;
  fromDevice: number;
  to: string;
  device: number;
  sentAt: string;
  ratchet: Record<string, unknown>;
  x3dh: Record<string, unknown> | null;
  nonce: string;
  ciphertext: string;
  blobId: string | null;
  bundleToken: string | null;
  manifestV: number;
}

const isInt = (v: unknown): v is number => typeof v === 'number' && Number.isInteger(v);

/**
 * Parse and check an unsealed inner envelope against the wire envelope it
 * arrived in, for the recipient `self` on device `selfDevice`.
 *
 * Returns the reason it is refused, or the parsed envelope. The checks, in
 * PROTOCOL.md's order:
 *
 *  - it parses, with `id` (and `blob_id` when present) a UUID;
 *  - the inner `to` is us;
 *  - the inner `id` equals the id on the wire — one id names a message
 *    everywhere, and an inner id that disagrees is a sender trying to be
 *    filed under a name the mailbox never saw;
 *  - `from_device` and `device` are present and integers: both are bound
 *    into the AEAD, and a default for either would make sender and receiver
 *    agree on what "absent" meant.
 */
export function parseInner(
  wire: Record<string, unknown>,
  opened: unknown,
  self: string,
  selfDevice: number,
): { inner: Inner; reason?: undefined } | { inner?: undefined; reason: string } {
  if (typeof opened !== 'object' || opened === null || Array.isArray(opened)) {
    return { reason: 'inner envelope is not an object' };
  }
  const j = opened as Record<string, unknown>;
  const id = j['id'];
  if (!isWireId(id)) return { reason: 'inner id is not a UUID' };
  if (id !== wire['id']) return { reason: 'inner id differs from the wire id' };
  if (j['to'] !== self) return { reason: 'inner envelope is addressed to someone else' };
  const type = j['type'];
  const from = j['from'];
  if (typeof type !== 'string' || type === '') return { reason: 'no type' };
  if (typeof from !== 'string' || from === '') return { reason: 'no sender' };
  const fromDevice = j['from_device'];
  const device = j['device'];
  if (!isInt(fromDevice) || fromDevice < 1) return { reason: 'bad from_device' };
  if (!isInt(device) || device < 1) return { reason: 'bad device' };
  if (device !== selfDevice) return { reason: 'addressed to another of our devices' };
  const ratchet = j['ratchet'];
  if (typeof ratchet !== 'object' || ratchet === null) return { reason: 'no ratchet header' };
  const nonce = j['nonce'];
  const ciphertext = j['ciphertext'];
  if (typeof nonce !== 'string' || typeof ciphertext !== 'string') {
    return { reason: 'no ciphertext' };
  }
  const blobId = j['blob_id'];
  if (blobId !== undefined && blobId !== null && !isWireId(blobId)) {
    return { reason: 'blob_id is not a UUID' };
  }
  const x3dh = j['x3dh'];
  const bundleToken = j['bundle_token'];
  const manifestV = j['manifest_v'];
  return {
    inner: {
      id,
      type,
      from,
      fromDevice,
      to: self,
      device,
      sentAt: typeof j['sent_at'] === 'string' ? j['sent_at'] : new Date().toISOString(),
      ratchet: ratchet as Record<string, unknown>,
      x3dh:
        typeof x3dh === 'object' && x3dh !== null ? (x3dh as Record<string, unknown>) : null,
      nonce,
      ciphertext,
      blobId: typeof blobId === 'string' ? blobId : null,
      bundleToken: typeof bundleToken === 'string' && bundleToken !== '' ? bundleToken : null,
      manifestV: isInt(manifestV) && manifestV > 0 ? manifestV : 0,
    },
  };
}

/** The envelope's `sent_at` as milliseconds, or now when it is unreadable. */
export function sentAtMs(iso: string): number {
  const t = Date.parse(iso);
  return Number.isNaN(t) ? Date.now() : t;
}
