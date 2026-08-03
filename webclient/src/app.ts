/**
 * Entry point: link if we are not linked, otherwise chat.
 *
 * The link is persisted, so a reload does not send the user back to the QR.
 * Message *history* is not — it stays on the phone (WEB_CLIENT.md "the
 * defensible shape"), and `store.ts` says which is which and why.
 */
import { b64decode, b64encode } from './bytes.js';
import { StonechatCore } from './core.js';
import { DeviceKeys, randomBytes, WEB_CERT_LIFETIME_MS } from './device.js';
import { Hub } from './hub.js';
import { Protocol } from './protocol.js';
import { qrVersion, renderQr } from './qr.js';
import { store } from './store.js';
import { App } from './ui.js';
import {
  encodeOffer,
  LinkRefused,
  offerCommitment,
  openGrant,
  parkingKey,
  type LinkGrant,
  type LinkOffer,
} from './linking.js';

/** Injected by build.mjs so the client can integrity-check its own core. */
declare const __WASM_INTEGRITY__: string;
declare const __BUILD_VERSION__: string;

const el = <K extends keyof HTMLElementTagNameMap>(
  tag: K,
  className?: string,
  text?: string,
): HTMLElementTagNameMap[K] => {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
};

async function loadCore(): Promise<StonechatCore> {
  // The integrity string was compiled in at build time and the hash of *this
  // file* is pinned by index.html. That is the chain: one small human-readable
  // file at the root covers everything below it.
  return StonechatCore.instantiate(
    fetch('/stonechat_core.wasm', { integrity: __WASM_INTEGRITY__ }),
  );
}

class LinkScreen {
  private readonly root = el('div', 'app');
  private readonly status = el('div', 'banner');
  private readonly dot = el('span', 'dot');
  private readonly statusText = el('span');
  private poll: number | undefined;

  constructor(
    private readonly core: StonechatCore,
    private readonly keys: DeviceKeys,
    private readonly hub: Hub,
    private readonly offer: LinkOffer,
  ) {}

  mount(into: HTMLElement): void {
    const bar = el('header', 'appbar');
    bar.append(el('span', 'appbar__title', 'Stonechat'));
    const build = el('span', 'mono');
    build.textContent = `web ${__BUILD_VERSION__}`;
    build.style.marginLeft = 'auto';
    bar.append(build);

    this.dot.classList.add('dot--warn');
    this.statusText.textContent = 'not linked — waiting for a phone to authorise';
    this.status.append(this.dot, this.statusText);

    const body = el('main');
    body.style.padding = 'var(--gutter)';
    body.style.overflowY = 'auto';
    body.style.flex = '1';

    const card = el('div', 'card');
    card.style.padding = '16px';
    card.style.maxWidth = '640px';

    card.append(el('h1', undefined, 'Link this browser'));
    const h1 = card.querySelector('h1')!;
    h1.style.fontSize = '17px';
    h1.style.marginBottom = '8px';

    const lede = el(
      'p',
      undefined,
      'Open Stonechat on your phone, go to Devices, and scan or paste this ' +
        'code. Your phone signs a certificate for this browser; it never ' +
        'sends its identity key.',
    );
    lede.style.color = 'var(--muted)';
    lede.style.marginBottom = '16px';
    card.append(lede);

    const offerText = encodeOffer(this.core, this.offer);

    // The QR, on white with a quiet zone — the phone's Devices screen scans,
    // it has no paste path, so this is the flow rather than a convenience.
    const qrWrap = el('div');
    qrWrap.style.background = '#fff';
    qrWrap.style.padding = '12px';
    qrWrap.style.borderRadius = 'var(--radius)';
    qrWrap.style.display = 'flex';
    qrWrap.style.justifyContent = 'center';
    qrWrap.append(renderQr(offerText));
    card.append(qrWrap);

    const hint = el('div', 'mono');
    hint.style.marginTop = '8px';
    hint.style.color = 'var(--faint)';
    hint.textContent =
      `QR version ${qrVersion(offerText)} · your phone fetches this session's ` +
      'keys and checks them against the code you scanned';
    card.append(hint);

    // Kept for debugging and for anything that cannot scan. Collapsed, so it
    // does not compete with the QR.
    const details = el('details');
    details.style.marginTop = '12px';
    const summary = el('summary', 'mono', 'show the raw code');
    summary.style.cursor = 'pointer';
    summary.style.color = 'var(--muted)';
    const code = el('textarea', 'mono');
    code.value = offerText;
    code.readOnly = true;
    code.rows = 5;
    code.style.width = '100%';
    code.style.marginTop = '8px';
    code.style.wordBreak = 'break-all';
    code.addEventListener('focus', () => code.select());
    details.append(summary, code);
    card.append(details);

    const facts = el('div', 'mono');
    facts.style.marginTop = '16px';
    facts.style.display = 'grid';
    facts.style.gap = '4px';
    for (const [k, v] of [
      ['session keys', 'generated here, never sent'],
      ['grant target', 'this session’s seal key'],
      ['certificate', `${WEB_CERT_LIFETIME_MS / 86_400_000} days, not renewable here`],
      ['parking key', parkingKey(this.core, this.offer.lookup).slice(0, 16) + '…'],
    ]) {
      const row = el('div');
      row.style.display = 'flex';
      row.style.gap = '12px';
      const label = el('span', undefined, k!);
      label.style.color = 'var(--faint)';
      label.style.minWidth = '110px';
      row.append(label, el('span', undefined, v!));
      facts.append(row);
    }
    card.append(facts);
    body.append(card);

    const caveat = el('div', 'card');
    caveat.style.padding = '16px';
    caveat.style.maxWidth = '640px';
    caveat.style.marginTop = '16px';
    const caveatTitle = el('div', 'mono', 'WHAT THIS SESSION CAN DO');
    caveatTitle.style.color = 'var(--amber)';
    caveatTitle.style.marginBottom = '6px';
    const caveatBody = el(
      'p',
      undefined,
      'Send and receive text. No groups, media, calls or receipts yet — and ' +
        'no history: past messages stay on your phone, and this session only ' +
        'shows what arrives while it is open.',
    );
    caveatBody.style.color = 'var(--muted)';
    caveat.append(caveatTitle, caveatBody);
    body.append(caveat);

    this.root.append(bar, this.status, body);
    into.replaceChildren(this.root);
    // Park the keys before anything can be scanned. If this fails the QR is
    // useless — the phone would scan a commitment to keys it cannot fetch — so
    // it is reported rather than left to fail later and less clearly.
    void this.publishOffer().then(() => this.startPolling());
  }

  private setStatus(kind: 'live' | 'warn' | 'down', text: string): void {
    this.dot.className = `dot dot--${kind}`;
    this.statusText.textContent = text;
  }

  private async publishOffer(): Promise<void> {
    try {
      await this.hub.putLinkOffer(
        offerCommitment(this.core, this.offer.sealPub, this.offer.sigPub),
        b64encode(this.offer.sealPub),
        b64encode(this.offer.sigPub),
      );
    } catch (e) {
      this.setStatus('down', `could not publish this session's keys — ${(e as Error).message}`);
      throw e;
    }
  }

  private startPolling(): void {
    const key = parkingKey(this.core, this.offer.lookup);
    // Two seconds: the grant is single-use and expires in ten minutes, and
    // polling is the whole of this side — there is no socket to be notified on
    // until there is an identity.
    this.poll = window.setInterval(() => void this.tryCollect(key), 2000);
    void this.tryCollect(key);
  }

  private async tryCollect(key: string): Promise<void> {
    let sealed: string | null;
    try {
      sealed = await this.hub.takeLinkGrant(key);
    } catch (e) {
      this.setStatus('down', `hub unreachable — ${(e as Error).message}`);
      return;
    }
    if (sealed === null) return;
    window.clearInterval(this.poll);
    try {
      const grant = openGrant(this.core, this.keys, sealed);
      this.onLinked(grant);
    } catch (e) {
      // A refusal is terminal: one of the three checks failed, and the grant
      // has already been consumed by the fetch. Starting over is the only
      // move, and saying so is better than silently polling forever.
      this.setStatus(
        'down',
        e instanceof LinkRefused
          ? e.message
          : `could not open the grant — ${(e as Error).message}`,
      );
    }
  }

  private onLinked(grant: LinkGrant): void {
    // Persisted so a reload does not start over. The device keys were already
    // stored when they were generated; the grant is what says who they belong
    // to and where the mailbox is.
    store.setDeviceKeys(this.keys.encode());
    store.setGrant(grant);
    this.setStatus(
      'live',
      `linked as ${grant.stonechat_id} · device ${grant.device_id}`,
    );
    const done = el('div', 'card');
    done.style.padding = '16px';
    done.style.maxWidth = '640px';
    done.style.margin = 'var(--gutter)';
    done.append(el('h1', undefined, 'Linked'));
    const list = el('div', 'mono');
    list.style.marginTop = '12px';
    list.style.display = 'grid';
    list.style.gap = '4px';
    for (const [k, v] of [
      ['identity', grant.stonechat_id],
      ['device', String(grant.device_id)],
      ['mailbox', grant.relay_address],
      ['certificate', `expires ${new Date(grant.cert.not_after * 1000).toISOString().slice(0, 10)}`],
    ]) {
      const row = el('div');
      row.style.display = 'flex';
      row.style.gap = '12px';
      const label = el('span', undefined, k!);
      label.style.color = 'var(--faint)';
      label.style.minWidth = '110px';
      row.append(label, el('span', 'mono--id', v!));
      list.append(row);
    }
    done.append(list);
    const next = el('p', undefined, 'Opening your conversations…');
    next.style.color = 'var(--muted)';
    next.style.marginTop = '12px';
    done.append(next);
    this.root.querySelector('main')!.replaceChildren(done);
    // Straight into the app: the certificate checks out, the keys are ours,
    // and the mailbox is reachable.
    setTimeout(() => void main(), 600);
  }
}

function fail(mount: HTMLElement, message: string): void {
  const err = el('div', 'card');
  err.style.margin = 'var(--gutter)';
  err.style.padding = '16px';
  err.style.borderColor = 'var(--danger)';
  err.append(el('div', 'mono', message));
  mount.replaceChildren(err);
}

async function main(): Promise<void> {
  const mount = document.getElementById('app')!;
  let core: StonechatCore;
  try {
    core = await loadCore();
  } catch (e) {
    // An integrity failure lands here. It is worth naming plainly: it means
    // the served core did not match the release this page was built from.
    fail(mount, `core failed to load: ${(e as Error).message}`);
    return;
  }

  // The hub is same-origin only if this page is served from it; in
  // development it is passed on the query string. There is no default that
  // would be safe to guess.
  const hubUrl =
    new URLSearchParams(location.search).get('hub') ?? location.origin;
  const hub = new Hub(hubUrl);

  const stored = store.grant();
  const storedKeys = store.deviceKeys();
  if (stored && storedKeys) {
    // Already linked. The certificate is checked again on every start: it is
    // short-lived by design, and using an expired one would fail later and
    // less clearly.
    const keys = DeviceKeys.decode(core, storedKeys);
    const status = core.devcertVerify(
      stored.cert,
      b64decode(stored.identity_pub),
      Math.floor(Date.now() / 1000),
    );
    if (status !== 'valid') {
      store.clear();
      fail(
        mount,
        `this session's certificate is ${status} — link again from your phone`,
      );
      return;
    }
    new App(new Protocol(core, hub, keys, stored)).mount(mount);
    return;
  }

  const keys = DeviceKeys.generate(core);
  store.setDeviceKeys(keys.encode());
  const offer: LinkOffer = {
    sealPub: keys.sealPublic,
    sigPub: keys.sigPublic,
    lookup: randomBytes(32),
  };
  new LinkScreen(core, keys, hub, offer).mount(mount);
}

void main();
