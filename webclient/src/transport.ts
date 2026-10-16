/**
 * Reaching the mailbox from a browser.
 *
 * A relay is a self-signed certificate on a bare IP. `fetch` and `WebSocket`
 * refuse that outright, with no API to accept it.
 * WebTransport's `serverCertificateHashes` is the one exception, and it is the
 * *same* trust model Stonechat already has: pin the certificate, ignore CAs.
 *
 * Two differences, neither ours to negotiate: the pin is SHA-256 of the DER
 * (native clients pin BLAKE2b), and the certificate may be valid for at most
 * 14 days. The relay answers the cap by publishing a **schedule** months ahead
 * (`relay/src/wtcert.rs`); this file's job is to refuse to use it unless the
 * owner signed it.
 */
import type { StonechatCore, WtCert, WtCertSchedule } from './core.js';
import { b64decode } from './bytes.js';
import type { DirectoryEntry } from './hub.js';

export class PinRefused extends Error {
  /**
   * Whether re-reading the directory could change the answer.
   *
   * A schedule that has not been published yet appears the moment the owner's
   * phone vouches for one — but the entry that said so is cached, so without
   * this the session stays broken until the tab is reloaded. A refused
   * signature or a wrong key is not transient: that entry is wrong, and
   * fetching it again would only refuse it again.
   */
  readonly transient: boolean;

  constructor(message: string, options?: { transient?: boolean }) {
    super(message);
    this.name = 'PinRefused';
    this.transient = options?.transient ?? false;
  }
}

export interface MailboxRoute {
  /** The URL to dial, path and token appended by the caller. */
  origin: string;
  /** Every unexpired pin, including ones not yet live. */
  pins: Uint8Array[];
  /** The schedule these came from, so the caller can decide when to refresh. */
  certs: WtCert[];
}

/**
 * Turn a directory entry into somewhere to dial and hashes to pin, or throw.
 *
 * The order of checks is the security argument:
 *
 * 1. the identity key must hash to the SC- ID the entry carries — which makes
 *    the entry self-consistent and nothing more. That it is the ID that was
 *    *asked for* is `Protocol.resolve`'s check, the only place the question
 *    is known; every entry that reaches here must have come through it;
 * 2. the schedule must be signed by that key;
 * 3. only then are the still-valid entries pinnable;
 * 4. and there has to be an address to send them to.
 *
 * Skipping (2) is the interesting failure: everything would appear to work,
 * against whatever certificate the network chose to serve. (4) is checked last
 * because an unsigned schedule is a security problem and a missing address is
 * merely a mailbox without a browser transport.
 */
export function routeFor(
  core: StonechatCore,
  entry: DirectoryEntry,
  now = new Date(),
): MailboxRoute {
  const mailbox = entry.mailbox;
  // Two different situations, and blaming the certificates for both sends
  // whoever reads it to look at the relay when the relay is fine.
  if (!mailbox) {
    // The identity is in the directory but owns no mailbox: switched off,
    // destroyed, or never set up. Nothing about this browser is wrong.
    throw new PinRefused(
      'That mailbox is switched off — its owner needs to turn it back on.',
    );
  }
  if (!mailbox.wt_certs || !mailbox.wt_sig) {
    // A mailbox exists but its owner has not vouched for a browser-transport
    // schedule yet. Ordinary and temporary: the phone publishes one shortly
    // after ignite, so this resolves itself once it is opened.
    throw new PinRefused(
      'That mailbox has no browser-transport certificates yet — its owner ' +
        'needs to open Stonechat.',
      { transient: true },
    );
  }
  const identityPub = b64decode(entry.pubkey);
  if (core.stonechatId(identityPub) !== entry.stonechat_id) {
    throw new PinRefused('Directory key does not commit to that Stonechat ID.');
  }
  // The signature covers the list exactly as published: same fields, same
  // order, same count. Reconstructing it here rather than trusting a
  // server-side re-serialization is what makes that true.
  const published: WtCertSchedule = { certs: mailbox.wt_certs };
  if (!core.wtcertsVerify(published, identityPub, b64decode(mailbox.wt_sig))) {
    throw new PinRefused(
      'That certificate schedule is not the one its owner signed.',
    );
  }

  const seconds = Math.floor(now.getTime() / 1000);
  const usable = mailbox.wt_certs.filter((c: WtCert) => c.not_after > seconds);
  if (usable.length === 0) {
    // Every published certificate has expired. The owner's device has not
    // been online to re-vouch, and connecting anyway would mean pinning
    // nothing.
    throw new PinRefused(
      'Their published certificates have all expired — the owner needs to open Stonechat.',
    );
  }
  const address = mailbox.wt_address;
  if (!address) {
    // Signed certificates but nowhere to send them. A real state — a provider
    // that has not been taught to map the UDP port, or a host that blocks it.
    throw new PinRefused(
      'That mailbox publishes no browser-transport address.',
    );
  }
  // Refused rather than passed to `new WebTransport`, where a crafted value
  // would be a URL the client did not intend to construct. This field arrives
  // over the network and is unsigned, so it is the one an attacker can freely
  // choose.
  //
  // The bracketed alternative is not decoration: an IPv6 literal is full of
  // colons, so a host pattern that excludes them rejects every IPv6 mailbox.
  const match = /^(?:\[[0-9A-Fa-f:.]+\]|[a-zA-Z0-9.-]+):(\d{1,5})$/.exec(address);
  if (!match || Number(match[1]) > 65535 || Number(match[1]) === 0) {
    throw new PinRefused('That mailbox published a malformed address.');
  }
  // Every unexpired hash, including ones not yet live: the relay may rotate
  // at any moment and the client has no way to know which it is serving.
  // Passing the whole set is what makes rotation silent.
  return {
    origin: `https://${address}`,
    pins: usable.map((c: WtCert) => b64decode(c.sha256)),
    certs: usable,
  };
}

/** Just the pins, for callers that only need to know what is trusted. */
export function pinsFor(
  core: StonechatCore,
  entry: DirectoryEntry,
  now = new Date(),
): Uint8Array[] {
  return routeFor(core, entry, now).pins;
}

/**
 * When the pins we hold need refreshing: shortly before the last one lapses.
 *
 * Not before the *current* one lapses — that is the mistake the schedule
 * exists to avoid. As long as one future pin is still valid, a rotation is
 * survivable without touching the network.
 */
export function pinsNeedRefresh(
  certs: WtCert[],
  now = new Date(),
  marginDays = 14,
): boolean {
  const seconds = Math.floor(now.getTime() / 1000);
  const last = certs.reduce((max, c) => Math.max(max, c.not_after), 0);
  return last - seconds < marginDays * 86_400;
}

/** The subset of the WebTransport API this client uses. Declared rather than
 * imported: `WebTransport` is a browser global with no Node typing, and this
 * keeps the surface honest about what is actually relied on. */
interface WebTransportLike {
  ready: Promise<void>;
  closed: Promise<unknown>;
  createBidirectionalStream(): Promise<{
    readable: ReadableStream<Uint8Array>;
    writable: WritableStream<Uint8Array>;
  }>;
  close(info?: { closeCode?: number; reason?: string }): void;
}

type WebTransportCtor = new (
  url: string,
  options: {
    serverCertificateHashes: Array<{ algorithm: string; value: Uint8Array }>;
  },
) => WebTransportLike;

/**
 * Open the mailbox socket over WebTransport.
 *
 * `serverCertificateHashes` is the whole reason this is possible: the browser
 * accepts a self-signed certificate whose SHA-256 we supply, which is the
 * pinning Stonechat already does everywhere else. **No CA is consulted**, and
 * every hash passed here came from a schedule its owner signed.
 *
 * All unexpired pins are passed, not just the live one: the relay rotates on
 * its own schedule and the client has no way to know which certificate it is
 * currently serving. That is what makes rotation silent.
 */
export async function connectMailbox(
  route: MailboxRoute,
  deviceToken: string,
): Promise<WebTransportLike> {
  const ctor = (globalThis as { WebTransport?: WebTransportCtor }).WebTransport;
  if (!ctor) {
    throw new Error('This browser has no WebTransport; Stonechat needs it.');
  }
  const transport = new ctor(
    `${route.origin}/wt?token=${encodeURIComponent(deviceToken)}`,
    {
      serverCertificateHashes: route.pins.map((value) => ({
        algorithm: 'sha-256',
        value,
      })),
    },
  );
  await transport.ready;
  return transport;
}
