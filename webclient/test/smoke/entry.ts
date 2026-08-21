/**
 * What runs *inside the browser* during the smoke test.
 *
 * Everything else in this repo's test suite runs in Node, which is
 * structurally blind to browser policy. On 2026-08-04 that let four bugs reach
 * a live deployment in one day: two Content-Security-Policy failures, a CORS
 * failure, and a certificate with no subjectAltName. Not one was visible to a
 * Node test, and the last one passed *three* end-to-end WebTransport tests
 * because Rust QUIC clients skip name checks when handed certificate hashes.
 *
 * So this file asserts the things only a browser can tell us, against the real
 * modules and under the real CSP:
 *
 *   1. the WASM core compiles           — CSP `wasm-unsafe-eval`
 *   2. a cross-origin hub call succeeds — CSP `connect-src`, and hub CORS
 *   3. a WebTransport session opens     — pins, certificate SAN, UDP reachability
 *   4. a request round-trips on it      — the stream framing
 *
 * Results go to the console as `SMOKE <name> <PASS|FAIL> [detail]`; the runner
 * reads them from Chrome's stderr.
 */
import { StonechatCore } from '../../src/core.js';
import { Mailbox } from '../../src/mailbox.js';
import { routeFor } from '../../src/transport.js';
import type { DirectoryEntry } from '../../src/hub.js';

declare const __WASM_INTEGRITY__: string;

/** Injected by the runner: where the stub hub and relay are. */
interface SmokeConfig {
  hub: string;
  stonechatId: string;
  deviceToken: string;
}

function report(name: string, ok: boolean, detail = ''): void {
  console.log(`SMOKE ${name} ${ok ? 'PASS' : 'FAIL'} ${detail}`.trim());
}

async function main(): Promise<void> {
  const config = JSON.parse(
    document.getElementById('smoke-config')!.textContent!,
  ) as SmokeConfig;

  // 1. The core. Fetched with the integrity the build computed, so this also
  //    proves the hash chain holds for the file actually served.
  let core: StonechatCore;
  try {
    core = await StonechatCore.instantiate(
      fetch('/stonechat_core.wasm', { integrity: __WASM_INTEGRITY__ }),
    );
    report('core-instantiates', true);
  } catch (e) {
    report('core-instantiates', false, String((e as Error).message));
    report('done', false);
    return;
  }

  // 1b. A decrypted attachment renders. Media arrives as ciphertext and
  //     becomes an object URL, so `img-src` has to allow `blob:` — and when it
  //     does not, the bytes are perfectly fine and the browser simply refuses
  //     to display them. That failure is invisible to every other check here:
  //     the core loads, the transport connects, the message arrives, and the
  //     user sees a broken-image icon. Checked under the page's real policy,
  //     which is the only place it can be caught.
  try {
    const png = Uint8Array.from(atob(
      'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==',
    ), (c) => c.charCodeAt(0));
    const url = URL.createObjectURL(new Blob([png], { type: 'image/png' }));
    await new Promise<void>((resolve, reject) => {
      const img = new Image();
      img.onload = () => resolve();
      img.onerror = () => reject(new Error('blocked — img-src must allow blob:'));
      img.src = url;
    });
    URL.revokeObjectURL(url);
    report('blob-image-renders', true);
  } catch (e) {
    report('blob-image-renders', false, String((e as Error).message));
  }

  // 2. A cross-origin call to the hub. Blocked by `connect-src` or by missing
  //    CORS headers, and a browser reports both identically as a bare
  //    TypeError — which is why this is checked separately from anything else.
  let entry: DirectoryEntry;
  try {
    const r = await fetch(`${config.hub}/v1/directory/${config.stonechatId}`, {
      credentials: 'omit',
    });
    if (!r.ok) throw new Error(`status ${r.status}`);
    entry = (await r.json()) as DirectoryEntry;
    report('hub-reachable', true);
  } catch (e) {
    report('hub-reachable', false, String((e as Error).message));
    report('done', false);
    return;
  }

  // 3. The transport. `routeFor` verifies the schedule's signature against the
  //    identity key before handing back a single pin, so a failure here is
  //    either that check or the connection itself.
  let mailbox: Mailbox;
  try {
    const route = routeFor(core, entry);
    report('pins-verify', true, `${route.pins.length} pins`);
    mailbox = await Mailbox.open(route, '');
    report('webtransport-connects', true);
  } catch (e) {
    report('webtransport-connects', false, String((e as Error).message));
    report('done', false);
    return;
  }

  // 4. A request over it, end to end through the framing.
  try {
    const status = await mailbox.json<{ queued: number }>(
      'GET',
      `/status?token=${encodeURIComponent(config.deviceToken)}`,
    );
    report('request-round-trips', typeof status.queued === 'number',
      `queued=${status.queued}`);
  } catch (e) {
    report('request-round-trips', false, String((e as Error).message));
  }

  report('done', true);
}

void main().catch((e: unknown) => {
  report('unhandled', false, String((e as Error)?.message ?? e));
  report('done', false);
});
