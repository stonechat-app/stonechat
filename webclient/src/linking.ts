/**
 * Getting linked.
 *
 * Counterpart of `app/lib/core/linking.dart`, but only the **new device's**
 * half: a browser can be linked, and can never link anything else, because
 * authorising a link means signing a certificate and that needs the identity
 * root.
 *
 * The flow, from this side:
 *
 *   1. show `{seal, sig, lookup}` — this session's own public keys plus a
 *      lookup secret;
 *   2. the phone scans it, mints a device, signs a certificate over those
 *      keys, seals the grant to `seal`, parks it on the hub under `H(lookup)`;
 *   3. poll `GET /v1/link/{H(lookup)}`, unseal with our own seal seed, and
 *      make the three checks below before believing any of it.
 *
 * Why the hub and not the relay: a device being linked has no identity, no
 * account, and no way to learn which relay to poll — the relay address is
 * *inside* the grant it is trying to collect. The hub URL is the only address
 * it has. The hub sees ciphertext.
 */
import type { SignedCert, StonechatCore } from './core.js';
import { certSealKey, certSigKey, type DeviceKeys } from './device.js';
import {
  b64decode,
  b64urlDecode,
  b64urlEncode,
  equalBytes,
  fromUtf8,
  toHex,
  utf8,
} from './bytes.js';

export const LINK_SCHEME = 'stonechat-link:';

/** Domain tag for the commitment. Separated so this hash can never be
 * mistaken for the parking key (blake2b over the lookup secret) or the TLS
 * fingerprint (blake2b over a certificate). */
const OFFER_CONTEXT = 'stonechat-link-offer';

/** Format marker. The first version put the whole 1216-byte X-Wing key in the
 * QR; this one puts a commitment to it. Carried so a future change is a
 * different byte rather than a mystery. */
const OFFER_V2 = 0x02;

/**
 * What this session holds. The public halves go to the hub; only a 32-byte
 * commitment to them travels by eye.
 *
 * `seal` and `sig` are this device's **long-lived** keys, not throwaways: they
 * are what the certificate must vouch for, and `seal` is also the key the
 * grant is encapsulated to — which binds "the device that opened the grant" to
 * "the device the certificate names".
 *
 * `lookup` is a third, independent secret and stays out of the offer entirely.
 * The parking key is its hash, and deriving that from anything on screen would
 * let a passer-by compute it and destroy the grant with the returns-and-deletes
 * fetch.
 */
export interface LinkOffer {
  sealPub: Uint8Array;
  sigPub: Uint8Array;
  lookup: Uint8Array;
}

/** What a scanner reads: a lookup secret and a commitment, and nothing else. */
export interface ScannedOffer {
  lookup: Uint8Array;
  /** blake2b-256 over the two public keys. Hex, because it is also the key the
   * offer is parked under. */
  commitment: string;
}

/**
 * blake2b-256 over `"stonechat-link-offer" ‖ seal ‖ sig`.
 *
 * This is the whole trick. The keys themselves are 1248 bytes and put the QR
 * at version 36 — dense enough that phones would not read it. A commitment is
 * 32 bytes and says exactly as much as the eyes need to say: *the key you
 * fetch must be this one*. A substituted key hashes differently and is refused,
 * so the network still cannot swap it.
 */
export function offerCommitment(
  core: StonechatCore,
  sealPub: Uint8Array,
  sigPub: Uint8Array,
): string {
  const tag = utf8.encode(OFFER_CONTEXT);
  const buf = new Uint8Array(tag.length + sealPub.length + sigPub.length);
  buf.set(tag);
  buf.set(sealPub, tag.length);
  buf.set(sigPub, tag.length + sealPub.length);
  return toHex(core.tlsFingerprint(buf));
}

/** The QR payload: 65 bytes — a version marker, the lookup secret and the
 * commitment — which is ~102 characters and a QR a phone reads at a glance. */
export function encodeOffer(core: StonechatCore, offer: LinkOffer): string {
  const commitment = offerCommitment(core, offer.sealPub, offer.sigPub);
  const raw = new Uint8Array(1 + 32 + 32);
  raw[0] = OFFER_V2;
  raw.set(offer.lookup, 1);
  raw.set(hexToBytes(commitment), 33);
  return LINK_SCHEME + b64urlEncode(raw);
}

/** Null for anything that is not one of ours, or is malformed. */
export function parseOffer(raw: string): ScannedOffer | null {
  const text = raw.trim();
  if (!text.startsWith(LINK_SCHEME)) return null;
  try {
    const bytes = b64urlDecode(text.slice(LINK_SCHEME.length));
    // Length and version are checked at the scanner, not deep inside the
    // seal: a malformed code should read as "that is not a Stonechat code".
    if (bytes.length !== 65 || bytes[0] !== OFFER_V2) return null;
    return {
      lookup: bytes.slice(1, 33),
      commitment: toHex(bytes.slice(33, 65)),
    };
  } catch {
    return null;
  }
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** What the phone seals back. The only secret in it is `device_token`. */
export interface LinkGrant {
  identity_pub: string;
  cert: SignedCert;
  stonechat_id: string;
  display_name: string;
  hub_url: string;
  relay_address: string;
  relay_tls_fp: string;
  device_id: number;
  device_token: string;
  bundle_token?: string;
}

/** Where a grant is parked: BLAKE2b-256 of the *lookup secret*, hex. */
export function parkingKey(core: StonechatCore, lookup: Uint8Array): string {
  // The core exposes this hash under its TLS-fingerprint symbol (its first
  // caller); it is a plain keyless hash, and the hub validates parking keys as
  // 64 lowercase hex digits.
  return toHex(core.tlsFingerprint(lookup));
}

export class LinkRefused extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'LinkRefused';
  }
}

/**
 * Open a collected grant and check it, or throw.
 *
 * Three checks, and each closes a different substitution:
 *
 *  1. the identity key must hash to the claimed SC- ID — so a grant that
 *     reached us by any route cannot install a *different* identity under the
 *     name the user is looking at;
 *  2. the certificate must verify against that key, unexpired, and name both
 *     this device id and this SC- ID;
 *  3. the certificate must vouch for **our own** keys. Skipping this is the
 *     interesting failure: we would store a perfectly valid certificate for
 *     someone else's device, publish it with our prekeys, and then be unable
 *     to open a single envelope addressed to us — with no error anywhere.
 */
export function openGrant(
  core: StonechatCore,
  keys: DeviceKeys,
  sealedB64: string,
  now = new Date(),
): LinkGrant {
  const opened = core.unseal(keys.sealSeed, b64decode(sealedB64));
  if (opened === null) {
    // Sealed to a different key: not for this session. Under polling this is
    // indistinguishable from someone else's grant landing on our parking key,
    // which is why it is an error and not a retry.
    throw new LinkRefused('That grant was not sealed to this browser session.');
  }
  const grant = JSON.parse(fromUtf8.decode(opened)) as LinkGrant;

  const identityPub = b64decode(grant.identity_pub);
  if (core.stonechatId(identityPub) !== grant.stonechat_id) {
    throw new LinkRefused(
      'That code is for a different identity — refusing to link.',
    );
  }

  const status = core.devcertVerify(
    grant.cert,
    identityPub,
    Math.floor(now.getTime() / 1000),
  );
  if (
    status !== 'valid' ||
    grant.cert.device_id !== grant.device_id ||
    grant.cert.stonechat_id !== grant.stonechat_id
  ) {
    throw new LinkRefused(
      `That link code came with a certificate we cannot use (${status}).`,
    );
  }

  const sig = certSigKey(grant.cert);
  const seal = certSealKey(grant.cert);
  if (
    sig === null ||
    seal === null ||
    !equalBytes(sig, keys.sigPublic) ||
    !equalBytes(seal, keys.sealPublic)
  ) {
    throw new LinkRefused(
      'That certificate is for a different device — refusing to link.',
    );
  }
  return grant;
}
