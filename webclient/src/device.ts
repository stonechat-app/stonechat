/**
 * This browser session's own keys, and the certificate that says they are ours.
 *
 * Counterpart of `app/lib/core/device_keys.dart`. The short version: the
 * identity key is not a messaging key. It is a root that signs a
 * short public statement per device —
 *
 *     stonechat_id · device_id · sig_pub · seal_pub · not_after
 *
 * — and each device keeps its own `sig_pub` (signs its prekeys) and `seal_pub`
 * (envelopes are sealed to it). That is the entire reason a web client is
 * defensible: **this session never holds the identity secret**, so a coerced
 * origin gets a bounded, revocable, expiring device rather than the user
 * forever.
 */
import type { SignedCert, StonechatCore } from './core.js';
import { ED_PUBLIC, XWING_PUBLIC, XWING_SEED } from './core.js';
import { b64decode, b64encode } from './bytes.js';

/**
 * How long the primary certifies a browser session for — mirrors
 * `linkedCertLifetime` in device_keys.dart.
 *
 * Short by design. A browser cannot protect a key the way a phone keystore
 * can, so the certificate's lifetime *is* the mitigation, and a mitigation
 * measured in months is not one. The phone decides the real value (its link
 * dialog mints a `linked` device, 14 days, renewed over `sync_cert` while the
 * device is still listed); this constant is only what the UI counts down
 * against when it has nothing else.
 */
export const WEB_CERT_LIFETIME_MS = 14 * 24 * 60 * 60 * 1000;

/**
 * Refetch a peer's certificate once the one we hold has less than this left
 * — 3 days, as the app (`certRefreshWindow`): after the primary would have
 * renewed it, so a device still linked has a newer one to serve.
 */
export const CERT_REFRESH_WINDOW_MS = 3 * 24 * 60 * 60 * 1000;

/**
 * The two keypairs a device holds. Seeds only — public halves are derived, so
 * there is one thing to persist and one thing to lose, and they cannot drift
 * out of step with the secrets.
 */
export class DeviceKeys {
  private constructor(
    readonly sigSeed: Uint8Array,
    readonly sealSeed: Uint8Array,
    private readonly core: StonechatCore,
  ) {}

  static generate(core: StonechatCore): DeviceKeys {
    return new DeviceKeys(randomBytes(32), randomBytes(XWING_SEED), core);
  }

  static decode(core: StonechatCore, stored: string): DeviceKeys {
    const j = JSON.parse(stored) as { sig: string; seal: string };
    return new DeviceKeys(b64decode(j.sig), b64decode(j.seal), core);
  }

  encode(): string {
    return JSON.stringify({
      sig: b64encode(this.sigSeed),
      seal: b64encode(this.sealSeed),
    });
  }

  /** Ed25519 public half. Signs this device's prekeys. */
  get sigPublic(): Uint8Array {
    return b64decode(this.core.identity(this.sigSeed, false).public);
  }

  /** The 64-byte signing key the primitive wants, expanded from the seed. */
  get sigSecret(): Uint8Array {
    return b64decode(this.core.identity(this.sigSeed, false).secret);
  }

  /** X-Wing public half. Envelopes to this device are sealed to it. */
  get sealPublic(): Uint8Array {
    return this.core.xwingPkFromSeed(this.sealSeed);
  }
}

/** Cryptographically strong bytes. `crypto.getRandomValues` is the only
 * source used anywhere in this client — the core takes randomness as an
 * argument precisely so there is one place to audit. */
export function randomBytes(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

/** The unsigned certificate body. Signing is separate because only the
 * primary can do it — this client never calls it, and has nothing to call it
 * with. Present so both sides of the format live in one file. */
export function unsignedCert(fields: {
  stonechatId: string;
  deviceId: number;
  sigPublic: Uint8Array;
  sealPublic: Uint8Array;
  notAfter: Date;
}): Record<string, unknown> {
  return {
    stonechat_id: fields.stonechatId,
    device_id: fields.deviceId,
    sig_pub: b64encode(fields.sigPublic),
    seal_pub: b64encode(fields.sealPublic),
    not_after: Math.floor(fields.notAfter.getTime() / 1000),
  };
}

/** When a signed certificate runs out, or null if it is malformed. Callers
 * treat unreadable as expired: one we cannot parse is not one we can encrypt
 * against. */
export function certExpiry(signed: SignedCert): Date | null {
  const seconds = signed.not_after;
  return typeof seconds === 'number' ? new Date(seconds * 1000) : null;
}

export function certNeedsRefresh(signed: SignedCert, now = new Date()): boolean {
  const expiry = certExpiry(signed);
  if (expiry === null) return true;
  return expiry.getTime() - now.getTime() < CERT_REFRESH_WINDOW_MS;
}

/** The seal key a certificate names — the target for envelopes to that
 * device. Null if it does not carry a usable one; callers skip the device
 * rather than falling back, because there is nothing safe to fall back *to*. */
export function certSealKey(signed: SignedCert): Uint8Array | null {
  return sizedKey(signed.seal_pub, XWING_PUBLIC);
}

/** The signing key a certificate names — what that device's prekey
 * signatures verify against. */
export function certSigKey(signed: SignedCert): Uint8Array | null {
  return sizedKey(signed.sig_pub, ED_PUBLIC);
}

function sizedKey(b64: unknown, expected: number): Uint8Array | null {
  if (typeof b64 !== 'string') return null;
  try {
    const bytes = b64decode(b64);
    return bytes.length === expected ? bytes : null;
  } catch {
    return null;
  }
}
