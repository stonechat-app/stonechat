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
   * Park this session's public keys under a commitment to them.
   *
   * The QR carries only the commitment — 32 bytes instead of 1248 — so the
   * keys themselves have to reach the phone some other way. The hub recomputes
   * the commitment and refuses a mismatch, and the phone checks again on
   * arrival: a substituted key hashes differently and is rejected, which is
   * exactly the property the eyes used to provide by carrying the key itself.
   */
  async putLinkOffer(
    commitment: string,
    sealPub: string,
    sigPub: string,
  ): Promise<void> {
    let r: Response;
    try {
      r = await fetch(`${this.baseUrl}/v1/link/offer`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        credentials: 'omit',
        body: JSON.stringify({
          key: commitment,
          offer: { seal: sealPub, sig: sigPub },
        }),
      });
    } catch (e) {
      // A blocked fetch and an unreachable host are the same `TypeError` here
      // — the browser deliberately tells a page nothing about why. The CSP is
      // by far the likelier cause when the hub is on plain HTTP, and the fix
      // is not guessable, so name it.
      throw new HubError(
        `cannot reach ${this.baseUrl}. If the page's Content-Security-Policy ` +
          'does not allow that origin, rebuild with ' +
          `STONECHAT_CONNECT="${this.baseUrl}" npm run build`,
        0,
      );
    }
    if (!r.ok) throw new HubError(`could not park the offer (${r.status})`, r.status);
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
  mailbox?: {
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
