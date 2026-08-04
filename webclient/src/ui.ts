/**
 * The slim client: a conversations list and a chat screen.
 *
 * Style is `theme.css`, lifted value-for-value from `app/lib/ui/theme.dart`:
 * warm near-black surfaces, 4px corners, burnt-orange accent, monospace for
 * anything machine-made. Messages render as a left-aligned ledger with coloured
 * rails, not bubbles.
 *
 * **Messages persist, up to a cap.** They used to live in memory only, which
 * meant a refresh emptied every conversation — defensible on paper and
 * unusable in practice. `store.ts` holds the reasoning and the bound.
 */
import type { Message, Protocol } from './protocol.js';
import { certExpiry } from './device.js';
import {
  MAX_MESSAGES_PER_CONVERSATION,
  store,
  type Contact,
} from './store.js';

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

/** The per-contact colour, by the same hash the app uses (`Zn.idColor`), so a
 * contact is the same colour on both clients. */
function idColor(stonechatId: string): string {
  let h = 0;
  for (const c of stonechatId) h = (h * 31 + c.charCodeAt(0)) & 0x7fffffff;
  return `var(--id-${h % 6})`;
}

const shortId = (id: string) => id.replace(/^SC-/, '').slice(0, 9);

export class App {
  private readonly root = el('div', 'app');
  private readonly banner = el('div', 'banner');
  private readonly dot = el('span', 'dot');
  private readonly bannerText = el('span');
  private readonly body = el('main');
  /** Loaded from storage on mount and written through on every change, so a
   * refresh resumes rather than forgetting. */
  private readonly threads = new Map<string, Message[]>();
  private open: string | null = null;

  constructor(private readonly protocol: Protocol) {}

  mount(into: HTMLElement): void {
    for (const [peerId, messages] of Object.entries(store.messages())) {
      this.threads.set(peerId, messages);
    }
    const bar = el('header', 'appbar');
    const back = el('button', 'secondary', '‹');
    back.style.display = 'none';
    back.addEventListener('click', () => {
      this.open = null;
      this.render();
    });
    const title = el('span', 'appbar__title', 'Stonechat');
    const who = el('span', 'mono mono--id', shortId(this.protocol.stonechatId));
    who.style.marginLeft = 'auto';
    // Unlinking needs an affordance. A browser session is meant to be
    // disposable, and "clear localStorage in DevTools" is not a way to
    // dispose of one — it is also the only recovery when a link dies with
    // the mailbox it was registered on, which happens.
    const reset = el('button', 'secondary', 'Unlink');
    reset.style.marginLeft = '12px';
    reset.addEventListener('click', () => {
      if (!confirm('Unlink this browser? Its keys and messages are forgotten.')) {
        return;
      }
      store.clear();
      location.reload();
    });
    bar.append(back, title, who, reset);
    this.backButton = back;
    this.title = title;

    this.dot.classList.add('dot--warn');
    this.bannerText.textContent = 'connecting…';
    this.banner.append(this.dot, this.bannerText);

    this.body.className = 'ledger';
    this.root.append(bar, this.banner, this.body, this.composerRow());
    into.replaceChildren(this.root);
    this.render();
    void this.run();
  }

  private backButton!: HTMLButtonElement;
  private title!: HTMLSpanElement;
  private input!: HTMLInputElement;
  private composer!: HTMLDivElement;

  private composerRow(): HTMLElement {
    const row = el('div', 'composer');
    const input = el('input');
    input.type = 'text';
    input.placeholder = 'Message';
    const send = el('button', undefined, 'Send');
    const submit = async () => {
      const text = input.value.trim();
      if (!text || !this.open) return;
      input.value = '';
      send.disabled = true;
      try {
        const message = await this.protocol.send(this.open, text);
        this.push(message);
      } catch (e) {
        this.setStatus('down', (e as Error).message);
        // Put it back rather than losing what they typed.
        input.value = text;
      } finally {
        send.disabled = false;
        input.focus();
      }
    };
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') void submit();
    });
    send.addEventListener('click', () => void submit());
    row.append(input, send);
    this.input = input;
    this.composer = row;
    return row;
  }

  private setStatus(kind: 'live' | 'warn' | 'down', text: string): void {
    this.dot.className = `dot dot--${kind}`;
    this.bannerText.textContent = text;
  }

  private push(message: Message): void {
    const thread = this.threads.get(message.peerId) ?? [];
    // Redelivery is normal — the relay re-sends anything unacked when a socket
    // reconnects — so the same message can arrive twice across a refresh.
    if (thread.some((m) => m.id === message.id)) return;
    thread.push(message);
    this.threads.set(message.peerId, thread);
    store.appendMessage(message);
    this.render();
  }

  /** Drain, publish prekeys, and stay connected. */
  private async run(): Promise<void> {
    try {
      await this.protocol.publishPrekeys();
      const expiry = certExpiry(this.protocol.grant.cert);
      const days = expiry
        ? Math.max(0, Math.round((expiry.getTime() - Date.now()) / 86_400_000))
        : 0;
      this.setStatus(
        'live',
        `connected · device ${this.protocol.deviceId} · session ends in ${days}d`,
      );
      for await (const message of this.protocol.receive()) {
        this.push(message);
      }
      // The generator ending means the socket closed cleanly.
      this.setStatus('warn', 'disconnected — reload to reconnect');
    } catch (e) {
      const message = (e as Error).message;
      // 410 is the relay saying this device is gone — revoked, or its mailbox
      // was replaced. Nothing here recovers from that, so say what to do
      // rather than showing a network error forever.
      const dead =
        /\b410\b/.test(message) || /revoked/i.test(message);
      this.setStatus(
        'down',
        dead
          ? 'This browser is no longer linked — press Unlink and link again.'
          : message,
      );
    }
  }

  // -- rendering ----------------------------------------------------------

  private render(): void {
    if (this.open === null) {
      this.backButton.style.display = 'none';
      this.title.textContent = 'Stonechat';
      this.composer.style.display = 'none';
      this.renderList();
    } else {
      this.backButton.style.display = '';
      this.title.textContent = shortId(this.open);
      this.composer.style.display = '';
      this.renderThread(this.open);
      this.input.focus();
    }
  }

  private renderList(): void {
    const contacts = Object.values(store.contacts());
    this.body.replaceChildren();

    const starter = el('div');
    starter.style.padding = 'var(--gutter)';
    starter.style.borderBottom = '1px solid var(--line)';
    const row = el('div');
    row.style.display = 'flex';
    row.style.gap = '8px';
    const idInput = el('input');
    idInput.type = 'text';
    idInput.placeholder = 'SC-…  start a conversation';
    const go = el('button', undefined, 'Open');
    const start = () => {
      const id = idInput.value.trim().toUpperCase();
      if (!id.startsWith('SC-')) {
        this.setStatus('down', "That doesn't look like a Stonechat ID.");
        return;
      }
      // Recorded on open so the conversation exists before the first send —
      // the pubkey is filled in when the directory is resolved.
      store.setContact({ stonechatId: id, pubkey: '' });
      idInput.value = '';
      this.open = id;
      this.render();
    };
    idInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') start();
    });
    go.addEventListener('click', start);
    row.append(idInput, go);
    starter.append(row);
    this.body.append(starter);

    if (contacts.length === 0) {
      const empty = el('div');
      empty.style.padding = 'var(--gutter)';
      empty.style.color = 'var(--muted)';
      empty.textContent =
        'No conversations yet. Paste someone’s Stonechat ID above, or wait for a message to arrive.';
      this.body.append(empty);
      return;
    }

    for (const contact of contacts) {
      this.body.append(this.contactRow(contact));
    }

    const note = el('div', 'mono');
    note.style.padding = 'var(--gutter)';
    note.style.color = 'var(--faint)';
    note.textContent =
      `this browser keeps the last ${MAX_MESSAGES_PER_CONVERSATION} messages ` +
      'per conversation — Unlink erases them';
    this.body.append(note);
  }

  private contactRow(contact: Contact): HTMLElement {
    const thread = this.threads.get(contact.stonechatId) ?? [];
    const last = thread[thread.length - 1];
    const row = el('div', 'row');
    row.style.cursor = 'pointer';
    row.style.borderBottom = '1px solid var(--line)';
    const rail = el('div', 'row__rail');
    rail.style.background = idColor(contact.stonechatId);
    const main = el('div');
    const meta = el('div', 'row__meta');
    const who = el('span', 'row__who mono--id', shortId(contact.stonechatId));
    who.style.color = idColor(contact.stonechatId);
    meta.append(who);
    if (last) meta.append(el('span', undefined, time(last.sentAt)));
    const preview = el(
      'div',
      'row__body',
      last ? last.text : 'no messages yet',
    );
    if (!last) preview.style.color = 'var(--faint)';
    main.append(meta, preview);
    row.append(rail, main);
    row.addEventListener('click', () => {
      this.open = contact.stonechatId;
      this.render();
    });
    return row;
  }

  private renderThread(peerId: string): void {
    const thread = this.threads.get(peerId) ?? [];
    this.body.replaceChildren();
    if (thread.length === 0) {
      const empty = el('div', 'mono');
      empty.style.padding = 'var(--gutter)';
      empty.style.color = 'var(--faint)';
      empty.textContent = 'nothing here yet';
      this.body.append(empty);
    }
    for (const message of thread) {
      const row = el('div', message.mine ? 'row row--mine' : 'row');
      const rail = el('div', 'row__rail');
      if (!message.mine) rail.style.background = idColor(message.peerId);
      const main = el('div');
      const meta = el('div', 'row__meta');
      const who = el(
        'span',
        'row__who',
        message.mine ? 'you' : shortId(message.peerId),
      );
      if (!message.mine) who.style.color = idColor(message.peerId);
      meta.append(who, el('span', undefined, time(message.sentAt)));
      main.append(meta, el('div', 'row__body', message.text));
      row.append(rail, main);
      this.body.append(row);
    }
    this.body.scrollTop = this.body.scrollHeight;
  }
}

function time(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime())
    ? ''
    : `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
}
