/** Byte plumbing. Small on purpose — every line here is on the audit path. */

export function b64encode(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

export function b64decode(text: string): Uint8Array {
  const s = atob(text);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

/** base64url without padding — what link offers and device tokens travel as. */
export function b64urlEncode(bytes: Uint8Array): string {
  return b64encode(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function b64urlDecode(text: string): Uint8Array {
  const padded = text.replace(/-/g, '+').replace(/_/g, '/');
  return b64decode(padded + '='.repeat((4 - (padded.length % 4)) % 4));
}

export const utf8 = new TextEncoder();
export const fromUtf8 = new TextDecoder();

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Constant-time-ish equality for secrets and key material.
 *
 * `a === b` on base64 strings short-circuits on the first differing character.
 * Nothing here is currently a remote-timing target, but comparing keys is
 * exactly the place that assumption stops holding quietly.
 */
export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}
