/**
 * The hub, over ordinary HTTPS.
 *
 * The hub is the *only* Stonechat service a browser can currently reach: it
 * has a domain and a CA certificate. Relays do not — they are self-signed
 * certs on bare IPs, validated by fingerprint against the directory, and no
 * browser API can accept that (WEB_CLIENT.md blocker 1). Reaching a relay
 * needs WebTransport with `serverCertificateHashes`, which is not built.
 *
 * So this file is the whole of the client's network surface today, and it is
 * enough to *get linked* — which is the half of the flow that runs against
 * the hub by design.
 */

import type { WtCert } from './core.js';

export class HubError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = 'HubError';
  }
}

export class Hub {
  constructor(readonly baseUrl: string) {}

  /**
   * Collect a parked link grant. Returns null while nothing has been parked
   * yet — the normal case on every poll before the user scans.
   *
   * Unauthenticated: possession of the parking key *is* the capability, and
   * it is derived from a secret only the two devices hold. Returns and
   * deletes, so a poll that succeeds is the only one that will.
   */
  async takeLinkGrant(key: string): Promise<string | null> {
    const r = await fetch(`${this.baseUrl}/v1/link/${key}`, {
      // No credentials, no cookies: nothing about this request should be
      // ambiently authenticated, and the response is opaque ciphertext.
      credentials: 'omit',
      cache: 'no-store',
    });
    if (r.status === 404) return null;
    if (!r.ok) throw new HubError(`hub returned ${r.status}`, r.status);
    const body = (await r.json()) as { sealed?: string };
    return typeof body.sealed === 'string' ? body.sealed : null;
  }

  /**
   * A directory entry, so a certificate can be checked against the identity
   * key its SC- ID commits to.
   *
   * The commitment check is the caller's job and is not optional: a lying hub
   * can only produce a *failed* lookup, never a substituted key, but only if
   * someone actually checks the hash.
   */
  async directory(stonechatId: string): Promise<DirectoryEntry> {
    const r = await fetch(
      `${this.baseUrl}/v1/directory/${encodeURIComponent(stonechatId)}`,
      { credentials: 'omit' },
    );
    if (!r.ok) throw new HubError(`directory lookup ${r.status}`, r.status);
    return (await r.json()) as DirectoryEntry;
  }
}

export interface DirectoryEntry {
  stonechat_id: string;
  pubkey: string;
  pq_pk?: string;
  pq_sig?: string;
  server?: {
    address?: string;
    tls_fp?: string;
    tls_sig?: string;
    /// The browser transport's certificate schedule, and the owner's
    /// signature over it. Both null, or both present — the hub stores them
    /// together, because a list nobody vouched for must not be pinnable.
    wt_certs?: WtCert[] | null;
    wt_sig?: string | null;
    /// `host:port` of the browser transport (UDP). Not derivable from
    /// `address`: container providers map a random host port for each, so a
    /// mailbox at 1.2.3.4:49173 says nothing about where its QUIC listener
    /// landed. Null means the mailbox has no browser transport.
    wt_address?: string | null;
  };
}
