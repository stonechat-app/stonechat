/**
 * Getting linked (MULTIDEVICE.md "Linking a device").
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
  b64encode,
  b64urlDecode,
  b64urlEncode,
  equalBytes,
  fromUtf8,
  toHex,
  utf8,
} from './bytes.js';

export const LINK_SCHEME = 'stonechat-link:';

/**
 * What this session shows and the phone scans.
 *
 * `seal` and `sig` are this device's **long-lived** keys, not throwaways for
 * the link: they are what the certificate must vouch for, and the phone has
 * nothing but this to mint it from. `seal` is therefore also the key the grant
 * is encapsulated to, which binds "the device that opened the grant" to "the
 * device the certificate names".
 *
 * `lookup` is a third, independent secret. The parking key is its hash and
 * **not** `seal`'s: `seal` is on screen and therefore public, so deriving the
 * parking key from it would let anyone who glimpses the screen compute it and
 * win the returns-and-deletes race. They could not read the grant — it is
 * sealed to a key they do not hold — but they could destroy it, turning a
 * shoulder-surf into a linking denial of service.
 */
export interface LinkOffer {
  sealPub: Uint8Array;
  sigPub: Uint8Array;
  lookup: Uint8Array;
}

export function encodeOffer(offer: LinkOffer): string {
  return (
    LINK_SCHEME +
    b64urlEncode(
      utf8.encode(
        JSON.stringify({
          seal: b64encode(offer.sealPub),
          sig: b64encode(offer.sigPub),
          lookup: b64encode(offer.lookup),
        }),
      ),
    )
  );
}

/** Null for anything that is not one of ours, or is malformed. */
export function parseOffer(raw: string): LinkOffer | null {
  const text = raw.trim();
  if (!text.startsWith(LINK_SCHEME)) return null;
  try {
    const json = JSON.parse(
      fromUtf8.decode(b64urlDecode(text.slice(LINK_SCHEME.length))),
    ) as Record<string, unknown>;
    const seal = b64decode(json['seal'] as string);
    const sig = b64decode(json['sig'] as string);
    const lookup = b64decode(json['lookup'] as string);
    // Sizes checked here rather than at use: a malformed offer should fail at
    // the scanner, not deep inside the seal. The sig length matters most — it
    // is about to be signed into a certificate.
    if (seal.length !== 1216 || sig.length !== 32 || lookup.length !== 32) {
      return null;
    }
    return { sealPub: seal, sigPub: sig, lookup };
  } catch {
    return null;
  }
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
