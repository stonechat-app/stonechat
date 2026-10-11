/**
 * The identity's signed list of its devices (PROTOCOL.md "Device manifest").
 *
 * Counterpart of `app/lib/core/device_manifest.dart`. A device certificate
 * says a device *was* the identity's, until a date; it cannot say the
 * identity has since cut the device off. The manifest is that statement:
 * the primary signs the set of devices that currently speak for the
 * identity, numbered so a newer one supersedes an older, and the directory
 * serves it. A client that holds it encrypts only to listed devices and
 * accepts envelopes only from listed devices — so revoking a device is a new
 * manifest without it, which a contact can check, not only a queue deleted
 * on a relay the contact has to trust.
 *
 * The signing and verification are the core's (`devices.rs`); this file is
 * the wire form and what a manifest says about a device.
 */
import type { StonechatCore } from './core.js';
import { b64decode } from './bytes.js';

export interface DeviceManifest {
  stonechat_id: string;
  version: number;
  /** Unix seconds. Informational: nothing expires a manifest. */
  issued_at: number;
  /** Device slot → the device's signing key (its certificate's `sig_pub`),
   * base64. A device is "listed" only with the key it was listed with. */
  devices: Record<number, string>;
  sig: string;
}

const isInt = (v: unknown): v is number => typeof v === 'number' && Number.isInteger(v);

/** Null for anything malformed. Verifying is separate so a manifest can be
 * parsed before the key to check it against is known. */
export function parseManifest(json: unknown): DeviceManifest | null {
  if (typeof json !== 'object' || json === null) return null;
  const j = json as Record<string, unknown>;
  const id = j['stonechat_id'];
  const version = j['version'];
  const issuedAt = j['issued_at'];
  const devices = j['devices'];
  const sig = j['sig'];
  if (
    typeof id !== 'string' || !isInt(version) || !isInt(issuedAt) ||
    !Array.isArray(devices) || typeof sig !== 'string'
  ) {
    return null;
  }
  const map: Record<number, string> = {};
  for (const d of devices as unknown[]) {
    if (typeof d !== 'object' || d === null) return null;
    const deviceId = (d as Record<string, unknown>)['device_id'];
    const sigPub = (d as Record<string, unknown>)['sig_pub'];
    if (!isInt(deviceId) || typeof sigPub !== 'string') return null;
    map[deviceId] = sigPub;
  }
  return { stonechat_id: id, version, issued_at: issuedAt, devices: map, sig };
}

/** The form that is signed and published: `sig` beside it. */
export function manifestJson(m: DeviceManifest): Record<string, unknown> {
  return {
    stonechat_id: m.stonechat_id,
    version: m.version,
    issued_at: m.issued_at,
    devices: Object.entries(m.devices).map(([id, sig_pub]) => ({
      device_id: Number(id),
      sig_pub,
    })),
    sig: m.sig,
  };
}

/**
 * Parse and verify a manifest against `identityPub` — the key the directory
 * gave for this identity, already checked to commit to its ID. Null unless it
 * is that identity's genuine, well-formed manifest *for `stonechatId`*: a
 * valid manifest for somebody else is as useless as a forged one.
 */
export function verifiedManifest(
  core: StonechatCore,
  json: unknown,
  stonechatId: string,
  identityPub: Uint8Array,
): DeviceManifest | null {
  const manifest = parseManifest(json);
  if (manifest === null || manifest.stonechat_id !== stonechatId) return null;
  let sig: Uint8Array;
  try {
    sig = b64decode(manifest.sig);
  } catch {
    return null;
  }
  if (sig.length !== 64) return null;
  const unsigned = manifestJson(manifest);
  delete unsigned['sig'];
  return core.devicesVerify(unsigned, identityPub, sig) ? manifest : null;
}

/** Whether `deviceId` speaks for the identity with `sigPub` as its key. */
export function manifestLists(
  m: DeviceManifest,
  deviceId: number,
  sigPub: string | null | undefined,
): boolean {
  return typeof sigPub === 'string' && m.devices[deviceId] === sigPub;
}
