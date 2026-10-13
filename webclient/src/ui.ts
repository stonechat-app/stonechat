/**
 * The client: a rail, a conversation list, and a conversation.
 *
 * Style is `theme.css`, lifted value-for-value from `app/lib/ui/theme.dart`:
 * warm near-black surfaces, 4px corners, burnt-orange accent, monospace for
 * anything machine-made. Messages render as a left-aligned ledger with coloured
 * rails, not bubbles — the *layout* is desktop-shaped, the visual language is
 * still ours.
 *
 * Everything shown is read back from `store.ts` on every change; the only
 * state this file keeps is what cannot be stored — decrypted media URLs,
 * which die with the tab, and what is open.
 */
import birdMark from './bird.png';
import type { CallManager } from './calls.js';
import type { MediaAttachment, Message, Protocol } from './protocol.js';
import { certExpiry } from './device.js';
import {
  MAX_MESSAGES_PER_CONVERSATION,
  store,
  threadKey,
  type Contact,
  type Group,
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

/** Inline SVG rather than an icon font or emoji: nothing to fetch — every
 * external request is one the hash root does not cover — and it inherits
 * `currentColor`, so the rail's selected state needs no second asset. */
function icon(path: string, size = 20): SVGSVGElement {
  const NS = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(NS, 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('width', String(size));
  svg.setAttribute('height', String(size));
  svg.setAttribute('fill', 'none');
  svg.setAttribute('stroke', 'currentColor');
  svg.setAttribute('stroke-width', '1.7');
  svg.setAttribute('stroke-linecap', 'round');
  svg.setAttribute('stroke-linejoin', 'round');
  const p = document.createElementNS(NS, 'path');
  p.setAttribute('d', path);
  svg.appendChild(p);
  return svg;
}

const ICON = {
  chats:
    'M21 11.5a8.4 8.4 0 0 1-9 8.4 9 9 0 0 1-4-.9L3 21l1.9-4.9A8.4 8.4 0 0 1 4 11.5a8.5 8.5 0 0 1 17 0z',
  groups:
    'M17 20v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2M9.5 7.5a3.5 3.5 0 1 1-7 0 3.5 3.5 0 0 1 7 0zM22 20v-2a4 4 0 0 0-3-3.9M16 3.6a4 4 0 0 1 0 7.8',
  settings:
    'M12 15.5a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7zM19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-2.9 1.2 2 2 0 1 1-4 0 1.7 1.7 0 0 0-2.9-1.2l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1A1.7 1.7 0 0 0 3 15a2 2 0 1 1 0-4 1.7 1.7 0 0 0 1.2-2.9l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1A1.7 1.7 0 0 0 10 4a2 2 0 1 1 4 0 1.7 1.7 0 0 0 2.9 1.2l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1A1.7 1.7 0 0 0 21 11a2 2 0 1 1 0 4z',
  compose: 'M12 5v14M5 12h14',
  back: 'M15 18l-6-6 6-6',
  more: 'M5 12h.01M12 12h.01M19 12h.01',
  close: 'M18 6L6 18M6 6l12 12',
  phone:
    'M22 16.9v3a2 2 0 0 1-2.2 2 19.8 19.8 0 0 1-8.6-3.1 19.5 19.5 0 0 1-6-6A19.8 19.8 0 0 1 2.1 4.2 2 2 0 0 1 4.1 2h3a2 2 0 0 1 2 1.7c.1.9.4 1.8.7 2.7a2 2 0 0 1-.5 2.1L8 9.8a16 16 0 0 0 6 6l1.3-1.3a2 2 0 0 1 2.1-.4c.9.3 1.8.6 2.7.7a2 2 0 0 1 1.7 2z',
  video: 'M23 7l-7 5 7 5V7zM14 5H3a2 2 0 0 0-2 2v10a2 2 0 0 0 2 2h11a2 2 0 0 0 2-2V7a2 2 0 0 0-2-2z',
  hangup: 'M10.7 13.3a16 16 0 0 1-2.7-3.5l1.3-1.3a2 2 0 0 0 .5-2.1c-.3-.9-.6-1.8-.7-2.7A2 2 0 0 0 7.1 2h-3A2 2 0 0 0 2.1 4.2a19.8 19.8 0 0 0 3.1 8.6M22 16.9v3a2 2 0 0 1-2.2 2 19.8 19.8 0 0 1-8.6-3.1M2 2l20 20',
  mic: 'M12 1a3 3 0 0 0-3 3v8a3 3 0 0 0 6 0V4a3 3 0 0 0-3-3zM19 10v2a7 7 0 0 1-14 0v-2M12 19v4M8 23h8',
};

/** The per-contact colour, by the same hash the app uses (`Zn.idColor`), so a
 * contact is the same colour on both clients. */
function idColor(stonechatId: string): string {
  let h = 0;
  for (const c of stonechatId) h = (h * 31 + c.charCodeAt(0)) & 0x7fffffff;
  return `var(--id-${h % 6})`;
}

/** The quick reactions the app offers. */
const QUICK_REACTIONS = ['👍', '❤️', '😂', '😮', '😢', '🙏'];

/** The disappearing-message timers the app offers. */
const TIMERS: Array<[number, string]> = [
  [0, 'off'],
  [3_600_000, '1 hour'],
  [86_400_000, '24 hours'],
  [7 * 86_400_000, '7 days'],
];

/**
 * The top bar: the mark and wordmark on the left, connection status on the
 * right. One bar rather than two.
 */
function brandBar(status: HTMLElement): HTMLElement {
  const bar = el('header', 'brand');
  const mark = el('img', 'brand__mark');
  mark.src = birdMark;
  mark.alt = '';
  mark.width = 22;
  mark.height = 22;
  const word = el('span', 'brand__word', 'STONECHAT');
  bar.append(mark, word, status);
  return bar;
}

type Section = 'chats' | 'groups';

/**
 * The conversation on screen: its type, then its id.
 *
 * The type is set by which list the row was clicked in and decides everything
 * downstream — the thread shown, the title, the send path. It is never worked
 * out from the id, which for a group is a string somebody else chose.
 */
interface Open {
  group: boolean;
  id: string;
}

export class App {
  private readonly shell = el('div', 'shell');
  private readonly listBody = el('div', 'sidebar__list');
  private readonly sidebarTitle = el('span', 'sidebar__title', 'Chats');
  private readonly pane = el('div', 'pane');
  private readonly banner = el('div', 'banner');
  private readonly dot = el('span', 'dot');
  private readonly bannerText = el('span');

  private open: Open | null = null;
  private section: Section = 'chats';
  private replyingTo: Message | null = null;
  private readonly railButtons = new Map<string, HTMLButtonElement>();
  private menu: HTMLElement | null = null;
  private expirySweep: ReturnType<typeof setTimeout> | null = null;

  private readonly callLayer = el('div', 'call');

  constructor(
    private readonly protocol: Protocol,
    private readonly calls: CallManager,
  ) {}

  mount(into: HTMLElement): void {
    this.shell.append(this.railEl(), this.sidebarEl(), this.pane);

    this.dot.classList.add('dot--warn');
    this.bannerText.textContent = 'connecting…';
    this.banner.append(this.dot, this.bannerText);

    const root = el('div', 'app');
    root.append(brandBar(this.banner), this.shell);
    into.replaceChildren(root);

    this.render();
    void this.run();
  }

  // -- chrome -------------------------------------------------------------

  private railEl(): HTMLElement {
    const rail = el('nav', 'rail');
    const add = (key: string, path: string, label: string, onClick: () => void) => {
      const b = el('button', 'rail__btn');
      b.title = label;
      b.setAttribute('aria-label', label);
      b.append(icon(path));
      b.addEventListener('click', onClick);
      this.railButtons.set(key, b);
      rail.append(b);
    };
    add('chats', ICON.chats, 'Direct messages', () => this.setSection('chats'));
    add('groups', ICON.groups, 'Groups', () => this.setSection('groups'));
    rail.append(el('div', 'rail__spacer'));
    add('settings', ICON.settings, 'Settings', () => this.openSettings());
    return rail;
  }

  private sidebarEl(): HTMLElement {
    const sidebar = el('aside', 'sidebar');
    const head = el('div', 'sidebar__head');
    const compose = el('button', 'icon-btn');
    compose.title = 'New conversation';
    compose.setAttribute('aria-label', 'New conversation');
    compose.append(icon(ICON.compose, 18));
    compose.style.marginLeft = 'auto';
    compose.addEventListener('click', () => {
      if (this.section === 'groups') {
        // Creating one means choosing contacts and owing a roster to every
        // member's every device until it lands. The phone does that.
        this.setStatus('warn', 'Groups are created on your phone.');
        return;
      }
      this.openCompose();
    });
    head.append(this.sidebarTitle, compose);

    const note = el('div', 'sidebar__note');
    note.textContent = `keeps the last ${MAX_MESSAGES_PER_CONVERSATION} per conversation`;

    sidebar.append(head, this.listBody, note);
    return sidebar;
  }

  private setSection(section: Section): void {
    this.section = section;
    this.sidebarTitle.textContent = section === 'chats' ? 'Chats' : 'Groups';
    // Close whatever is open only if it does not belong to the section being
    // shown — otherwise entering Groups would close the group you just picked.
    if (this.open !== null && (section === 'groups') !== this.open.group) {
      this.setOpen(null);
    }
    this.render();
  }

  private setStatus(kind: 'live' | 'warn' | 'down', text: string): void {
    this.dot.className = `dot dot--${kind}`;
    this.bannerText.textContent = text;
  }

  private setOpen(open: Open | null): void {
    if (this.open && (!open || open.id !== this.open.id || open.group !== this.open.group)) {
      this.protocol.stopTyping(this.open.id, this.open.group);
    }
    this.open = open;
    this.replyingTo = null;
    this.closeMenu();
    if (open) this.protocol.markRead(open.id, open.group);
  }

  // -- modals -------------------------------------------------------------

  /** A modal with the two exits people reach for: Escape, and the backdrop. */
  private modal(build: (close: () => void) => HTMLElement): void {
    const backdrop = el('div', 'backdrop');
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') close();
    };
    const close = () => {
      backdrop.remove();
      document.removeEventListener('keydown', onKey);
    };
    document.addEventListener('keydown', onKey);
    backdrop.addEventListener('click', (e) => {
      if (e.target === backdrop) close();
    });
    backdrop.append(build(close));
    document.body.append(backdrop);
  }

  private openCompose(): void {
    this.modal((close) => {
      const card = el('div', 'modal');
      card.append(el('h2', undefined, 'Add a contact'));
      const lede = el(
        'p',
        'mono',
        'Paste their Stonechat ID. There is nothing to search — an ID is a ' +
          'commitment to a key, not a name in a directory. They get a request; ' +
          'the conversation opens once they accept.',
      );
      lede.style.marginBottom = '14px';
      card.append(lede);

      const input = el('input');
      input.type = 'text';
      input.placeholder = 'SC-XXXX-XXXX-…';
      input.style.width = '100%';
      const error = el('div', 'mono');
      error.style.color = 'var(--danger)';
      error.style.marginTop = '8px';
      error.style.minHeight = '16px';

      const submit = async () => {
        const id = input.value.trim().toUpperCase();
        if (!id.startsWith('SC-') || id.length < 10) {
          error.textContent = "that doesn't look like a Stonechat ID";
          return;
        }
        go.disabled = true;
        try {
          const contact = await this.protocol.addContact(id);
          this.section = 'chats';
          this.setOpen({ group: false, id: contact.stonechatId });
          close();
          this.render();
        } catch (e) {
          error.textContent = (e as Error).message;
          go.disabled = false;
        }
      };
      input.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') void submit();
      });

      const cancel = el('button', 'secondary', 'Cancel');
      cancel.addEventListener('click', close);
      const go = el('button', undefined, 'Send request');
      go.addEventListener('click', () => void submit());
      const actions = el('div', 'modal__actions');
      actions.append(cancel, go);

      card.append(input, error, actions);
      setTimeout(() => input.focus(), 0);
      return card;
    });
  }

  private openSettings(): void {
    this.modal((close) => {
      const card = el('div', 'modal');
      card.append(el('h2', undefined, 'This browser'));

      const expiry = certExpiry(this.protocol.grant.cert);
      const days = expiry
        ? Math.max(0, Math.round((expiry.getTime() - Date.now()) / 86_400_000))
        : 0;
      const facts = el('div', 'mono');
      facts.style.display = 'grid';
      facts.style.gap = '6px';
      facts.style.margin = '14px 0';
      for (const [k, v] of [
        ['your ID', this.protocol.stonechatId],
        ['device', String(this.protocol.deviceId)],
        [
          'certificate',
          expiry
            ? `${expiry.toISOString().slice(0, 10)} · ${days}d · renewed by your phone`
            : 'unknown',
        ],
        ['messages kept', `${MAX_MESSAGES_PER_CONVERSATION} per conversation`],
      ]) {
        const row = el('div');
        row.style.display = 'flex';
        row.style.gap = '12px';
        const label = el('span', undefined, k!);
        label.style.color = 'var(--faint)';
        label.style.minWidth = '104px';
        label.style.flex = 'none';
        const value = el('span', 'mono--id', v!);
        value.style.wordBreak = 'break-all';
        row.append(label, value);
        facts.append(row);
      }
      card.append(facts);

      // Read receipts: what the *peer* learns. Delivery receipts are
      // unconditional, as on the phone.
      const receipts = el('label', 'mono');
      receipts.style.display = 'flex';
      receipts.style.gap = '8px';
      receipts.style.alignItems = 'center';
      receipts.style.margin = '0 0 14px';
      const box = el('input');
      box.type = 'checkbox';
      box.checked = store.settings().sendReadReceipts !== false;
      box.addEventListener('change', () => store.setSettings({ sendReadReceipts: box.checked }));
      receipts.append(box, el('span', undefined, 'send read receipts from this browser'));
      card.append(receipts);

      const warn = el(
        'p',
        'mono',
        'Unlinking forgets this session’s keys and every message it holds. ' +
          'Your phone keeps everything.',
      );
      warn.style.color = 'var(--faint)';
      card.append(warn);

      const cancel = el('button', 'secondary', 'Close');
      cancel.addEventListener('click', close);
      const unlink = el('button', undefined, 'Unlink');
      unlink.style.background = 'var(--danger)';
      unlink.addEventListener('click', () => {
        if (!confirm('Unlink this browser? Its keys and messages are forgotten.')) {
          return;
        }
        store.clear();
        location.reload();
      });
      const actions = el('div', 'modal__actions');
      actions.append(cancel, unlink);
      card.append(actions);
      return card;
    });
  }

  // -- running ------------------------------------------------------------

  private async run(): Promise<void> {
    this.protocol.onChange = () => this.render();
    this.protocol.onGroupsChanged = () => this.render();
    this.protocol.onConversationCleared = () => this.render();
    this.protocol.onTyping = () => this.renderTyping();
    this.protocol.onCertRenewed = () => this.setStatus('live', 'connected · certificate renewed');
    this.calls.onChange = () => {
      this.renderCall();
      this.render();
    };
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'visible' && this.open) {
        this.protocol.markRead(this.open.id, this.open.group);
      }
    });
    // The retry sweep: what could not be delivered is tried again with the
    // app's backoff. Cheap when nothing is owed.
    setInterval(() => void this.protocol.retryPending(), 30_000);
    this.scheduleExpirySweep();

    await this.protocol.start(
      (message) => {
        if (
          this.open && document.visibilityState === 'visible' &&
          message.peerId === this.open.id && (message.group === true) === this.open.group
        ) {
          this.protocol.markRead(this.open.id, this.open.group);
        }
        if (message.expiresAt) this.scheduleExpirySweep();
        this.render();
      },
      (kind, text) => {
        if (kind === 'live') {
          const expiry = certExpiry(this.protocol.grant.cert);
          const days = expiry
            ? Math.max(0, Math.round((expiry.getTime() - Date.now()) / 86_400_000))
            : 0;
          this.setStatus('live', `${text} · device ${this.protocol.deviceId} · certificate ${days}d`);
        } else {
          this.setStatus(kind, text);
        }
      },
    );
  }

  private scheduleExpirySweep(): void {
    if (this.expirySweep) clearTimeout(this.expirySweep);
    const next = this.protocol.nextExpiry();
    if (next === null) return;
    this.expirySweep = setTimeout(() => {
      this.expirySweep = null;
      this.protocol.sweepExpired();
      this.scheduleExpirySweep();
    }, Math.max(1000, Math.min(next - Date.now(), 3_600_000)));
  }

  // -- rendering ----------------------------------------------------------

  private render(): void {
    for (const [key, button] of this.railButtons) {
      button.setAttribute('aria-selected', String(key === this.section));
    }
    // Drives the one-pane-at-a-time layout on narrow screens; ignored above
    // 760px, where both panes are visible at once.
    this.shell.dataset['view'] = this.open === null ? 'list' : 'chat';
    this.renderList();
    this.renderPane();
  }

  private renderList(): void {
    this.listBody.replaceChildren();
    const messages = store.messages();

    if (this.section === 'groups') {
      // Only groups we hold a roster for. One we were linked too late to hear
      // about has no row and no messages until its admin next changes it or
      // a member's message shows we are behind.
      const known = Object.values(store.groups());
      if (known.length === 0) {
        const note = el('div', 'mono');
        note.style.padding = 'var(--gutter)';
        note.style.color = 'var(--faint)';
        note.textContent = 'no groups yet — create one on your phone';
        this.listBody.append(note);
        return;
      }
      const lastOf = (g: Group) => {
        const thread = messages[threadKey(g.id, true)];
        return thread?.[thread.length - 1];
      };
      known.sort((a, b) => (Date.parse(lastOf(b)?.sentAt ?? '') || 0) - (Date.parse(lastOf(a)?.sentAt ?? '') || 0));
      for (const group of known) this.listBody.append(this.groupRow(group, lastOf(group)));
      return;
    }

    // Sessions from before this was fixed hold a contact for our own
    // identity; filtering here heals them on reload rather than needing an
    // unlink to clear.
    const contacts = Object.values(store.contacts()).filter(
      (c) => c.stonechatId !== this.protocol.stonechatId,
    );
    if (contacts.length === 0) {
      const empty = el('div', 'mono');
      empty.style.padding = 'var(--gutter)';
      empty.style.color = 'var(--faint)';
      empty.textContent = 'no conversations yet — use + to start one';
      this.listBody.append(empty);
      return;
    }
    const lastAt = (c: Contact) => {
      const thread = messages[c.stonechatId];
      const last = thread?.[thread.length - 1];
      return last ? Date.parse(last.sentAt) || 0 : 0;
    };
    // Most recent first, so a reply moves a conversation up the list.
    for (const contact of contacts.sort((a, b) => lastAt(b) - lastAt(a))) {
      const thread = messages[contact.stonechatId] ?? [];
      this.listBody.append(this.contactRow(contact, thread[thread.length - 1]));
    }
  }

  /** The text, with every `@name` the sender meant set off. */
  private textBody(message: Message): HTMLElement {
    const body = el('div', 'row__body');
    const names = (message.mentions ?? [])
      .map((id) => this.protocol.nameOf(id))
      .filter((n) => n.length > 0)
      .sort((a, b) => b.length - a.length); // longest first: "Ann Lee" before "Ann"
    if (names.length === 0) {
      body.textContent = message.text;
      return body;
    }
    const text = message.text;
    let start = 0;
    while (start < text.length) {
      let at = -1;
      let hit = '';
      for (const n of names) {
        const i = text.indexOf(`@${n}`, start);
        if (i >= 0 && (at < 0 || i < at)) { at = i; hit = n; }
      }
      if (at < 0) { body.append(text.slice(start)); break; }
      if (at > start) body.append(text.slice(start, at));
      const span = el('span', 'mention', `@${hit}`);
      if (hit === this.protocol.nameOf(this.protocol.stonechatId)) span.classList.add('mention--me');
      body.append(span);
      start = at + hit.length + 1;
    }
    return body;
  }

  /** A group's photo, or a lettered square in its colour. */
  private groupAvatar(group: Group, size = 26): HTMLElement {
    if (group.avatar) {
      const img = el('img', 'avatar');
      img.src = `data:${group.avatar.mime};base64,${group.avatar.data}`;
      img.alt = '';
      img.width = size;
      img.height = size;
      return img;
    }
    const dot = el('div', 'avatar avatar--letter', group.name.slice(0, 1).toUpperCase());
    dot.style.background = idColor(group.id);
    dot.style.width = `${size}px`;
    dot.style.height = `${size}px`;
    dot.style.lineHeight = `${size}px`;
    return dot;
  }

  private avatar(contact: Contact | null, id: string, size = 26): HTMLElement {
    if (contact?.avatar) {
      const img = el('img', 'avatar');
      img.src = `data:${contact.avatar.mime};base64,${contact.avatar.data}`;
      img.alt = '';
      img.width = size;
      img.height = size;
      return img;
    }
    const dot = el('div', 'avatar avatar--letter', this.protocol.nameOf(id).slice(0, 1).toUpperCase());
    dot.style.background = idColor(id);
    dot.style.width = `${size}px`;
    dot.style.height = `${size}px`;
    dot.style.lineHeight = `${size}px`;
    return dot;
  }

  private contactRow(contact: Contact, last: Message | undefined): HTMLElement {
    const id = contact.stonechatId;
    const row = el(
      'div',
      this.open !== null && !this.open.group && id === this.open.id ? 'row row--active' : 'row',
    );
    row.style.cursor = 'pointer';
    row.style.borderBottom = '1px solid var(--line)';
    const rail = el('div', 'row__rail');
    rail.style.background = idColor(id);
    const main = el('div');
    main.style.minWidth = '0';
    const meta = el('div', 'row__meta');
    const who = el('span', 'row__who', this.protocol.nameOf(id));
    who.style.color = idColor(id);
    meta.append(who);
    if (contact.status === 'pendingIn') meta.append(el('span', 'tag', 'request'));
    if (contact.status === 'pendingOut') meta.append(el('span', 'tag', 'invited'));
    if (typeof contact.blockedAt === 'number') meta.append(el('span', 'tag tag--danger', 'blocked'));
    if (last) meta.append(el('span', undefined, time(last.sentAt)));
    const preview = el('div', 'row__body', last ? previewOf(last) : 'no messages yet');
    preview.style.whiteSpace = 'nowrap';
    preview.style.overflow = 'hidden';
    preview.style.textOverflow = 'ellipsis';
    if (!last) preview.style.color = 'var(--faint)';
    const unread = (store.messages()[id] ?? []).filter((m) => !m.mine && !m.notice && m.status !== 'read').length;
    if (unread > 0) meta.append(el('span', 'badge', String(unread)));
    main.append(meta, preview);
    row.append(rail, main);
    row.addEventListener('click', () => {
      this.setOpen({ group: false, id });
      this.render();
    });
    return row;
  }

  /**
   * One group in the list.
   *
   * A group we were `removed` from stays listed: what was said while we were
   * in it is still ours to read. It is readable and not sendable, and the
   * label says so.
   */
  private groupRow(group: Group, last: Message | undefined): HTMLElement {
    const row = el('div', this.open?.group && group.id === this.open.id ? 'row row--active' : 'row');
    row.style.cursor = 'pointer';
    row.style.borderBottom = '1px solid var(--line)';
    const rail = el('div', 'row__rail');
    rail.style.background = idColor(group.id);
    const main = el('div');
    main.style.minWidth = '0';
    const meta = el('div', 'row__meta');
    const name = el('span', 'row__who', group.name);
    name.style.color = 'var(--text)';
    meta.append(name);
    if (group.removed) {
      const hint = el('span', 'tag', 'read-only');
      hint.title = 'You were removed from this group.';
      meta.append(hint);
    }
    if (last) meta.append(el('span', undefined, time(last.sentAt)));
    const unread = (store.messages()[threadKey(group.id, true)] ?? [])
      .filter((m) => !m.mine && !m.notice && m.status !== 'read').length;
    if (unread > 0) meta.append(el('span', 'badge', String(unread)));
    const preview = el('div', 'row__body', last ? previewOf(last, this.protocol) : `${group.members.length} members`);
    preview.style.whiteSpace = 'nowrap';
    preview.style.overflow = 'hidden';
    preview.style.textOverflow = 'ellipsis';
    if (!last) preview.style.color = 'var(--faint)';
    main.append(meta, preview);
    row.append(rail, this.groupAvatar(group), main);
    row.addEventListener('click', () => {
      this.setOpen({ group: true, id: group.id });
      this.render();
    });
    return row;
  }

  private renderPane(): void {
    this.pane.replaceChildren();
    if (this.open === null) {
      const empty = el('div', 'pane__empty');
      empty.textContent =
        this.section === 'groups' ? 'select a group' : 'select a conversation';
      this.pane.append(empty);
      return;
    }

    const open = this.open;
    const head = el('div', 'pane__head');
    const back = el('button', 'icon-btn pane__back');
    back.setAttribute('aria-label', 'Back');
    back.append(icon(ICON.back, 18));
    back.addEventListener('click', () => {
      this.setOpen(null);
      this.render();
    });
    const openGroup = open.group ? store.group(open.id) : null;
    const contact = open.group ? null : store.contact(open.id);
    const title = el('span', 'pane__title', openGroup ? openGroup.name : this.protocol.nameOf(open.id));
    if (!openGroup) title.style.color = idColor(open.id);
    const sub = el('span', 'mono pane__sub');
    sub.textContent = openGroup
      ? openGroup.removed
        ? 'you were removed'
        : openGroup.members.map((m) => this.protocol.nameOf(m.stonechatId)).join(', ')
      : open.id;
    const titles = el('div', 'pane__titles');
    titles.append(title, sub);
    head.append(back, openGroup ? this.groupAvatar(openGroup) : this.avatar(contact, open.id), titles);

    // Calls are 1:1, between accepted contacts. This browser refuses what it
    // knows is not one; the rest it offers.
    if (!open.group && contact?.status === 'accepted' && typeof contact?.blockedAt !== 'number') {
      const spacer = el('span');
      spacer.style.marginLeft = 'auto';
      head.append(spacer);
      for (const [path, label, video] of [
        [ICON.phone, 'Voice call', false],
        [ICON.video, 'Video call', true],
      ] as const) {
        const b = el('button', 'icon-btn');
        b.title = label;
        b.setAttribute('aria-label', label);
        b.append(icon(path, 16));
        b.disabled = this.calls.inCall;
        b.addEventListener('click', () => void this.calls.startCall(open.id, video));
        head.append(b);
      }
    }

    // The disappearing-messages timer: ours to set in a DM, any member's in
    // a group. The other side learns over timer_update.
    if (!openGroup?.removed && !(contact && typeof contact.blockedAt === 'number')) {
      const timer = el('select', 'timer');
      timer.title = 'Disappearing messages';
      const current = this.protocol.expireTimerOf(open.id, open.group);
      for (const [ms, label] of TIMERS) {
        const option = el('option', undefined, ms === 0 ? 'disappear: off' : `disappear: ${label}`);
        option.value = String(ms);
        if (ms === current) option.selected = true;
        timer.append(option);
      }
      if (!TIMERS.some(([ms]) => ms === current)) {
        const option = el('option', undefined, `disappear: ${Math.round(current / 60_000)} min`);
        option.value = String(current);
        option.selected = true;
        timer.append(option);
      }
      timer.addEventListener('change', () => {
        void this.protocol.setExpireTimer(open.id, open.group, Number(timer.value));
      });
      if (open.group) timer.style.marginLeft = 'auto';
      head.append(timer);
    }

    const ledger = el('div', 'ledger');
    const thread = store.messages()[threadKey(open.id, open.group)] ?? [];
    if (thread.length === 0) {
      const empty = el('div', 'mono');
      empty.style.padding = 'var(--gutter)';
      empty.style.color = 'var(--faint)';
      empty.textContent = 'nothing here yet';
      ledger.append(empty);
    }
    for (const message of thread) ledger.append(this.messageRow(message, thread));

    this.pane.append(head, ledger, this.typingRow(), this.composerRow(open, openGroup, contact));
    ledger.scrollTop = ledger.scrollHeight;
  }

  private readonly typingLine = el('div', 'typing mono');

  private typingRow(): HTMLElement {
    this.renderTyping();
    return this.typingLine;
  }

  private renderTyping(): void {
    if (!this.open) return;
    const who = this.protocol.typersIn(threadKey(this.open.id, this.open.group));
    this.typingLine.textContent =
      who.length === 0 ? '' : `${who.map((w) => this.protocol.nameOf(w)).join(', ')} typing…`;
    this.typingLine.hidden = who.length === 0;
  }

  private messageRow(message: Message, thread: Message[]): HTMLElement {
    if (message.notice) {
      const row = el('div', 'notice mono', message.text);
      if (message.request) row.classList.add('notice--request');
      if (message.call) row.classList.add('notice--call');
      return row;
    }
    const row = el('div', message.mine ? 'row row--mine' : 'row');
    const rail = el('div', 'row__rail');
    if (!message.mine) rail.style.background = idColor(message.sender ?? message.peerId);
    const main = el('div');
    main.style.minWidth = '0';
    const meta = el('div', 'row__meta');
    const who = el('span', 'row__who', this.protocol.nameOf(message.mine ? this.protocol.stonechatId : message.sender ?? message.peerId));
    if (!message.mine) who.style.color = idColor(message.sender ?? message.peerId);
    meta.append(who, el('span', undefined, time(message.sentAt)));
    if (message.editedAt) meta.append(el('span', undefined, 'edited'));
    if (message.expiresAt) {
      const left = el('span', undefined, `⌛ ${remaining(message.expiresAt)}`);
      left.title = 'disappears';
      meta.append(left);
    }
    if (message.mine) meta.append(stateLabel(message));
    const more = el('button', 'icon-btn row__more');
    more.setAttribute('aria-label', 'Message actions');
    more.append(icon(ICON.more, 14));
    more.addEventListener('click', (e) => {
      e.stopPropagation();
      this.openMenu(message, more);
    });
    meta.append(more);
    main.append(meta);

    if (message.replyTo) {
      const quote = el('div', 'quote');
      const quoted = thread.find((m) => m.id === message.replyTo!.id);
      const by = el('span', 'quote__who', this.protocol.nameOf(message.replyTo.sender ?? ''));
      const text = el('span', 'quote__text', message.replyTo.preview ?? '');
      quote.append(by, text);
      if (quoted) {
        quote.style.cursor = 'pointer';
        quote.title = 'Jump to the original';
        quote.addEventListener('click', () => {
          const target = this.pane.querySelector<HTMLElement>(`[data-id="${CSS.escape(quoted.id)}"]`);
          target?.scrollIntoView({ block: 'center' });
          target?.classList.add('row--flash');
          setTimeout(() => target?.classList.remove('row--flash'), 1200);
        });
      }
      main.append(quote);
    }

    if (message.deleted) {
      const gone = el('div', 'row__body mono', 'message deleted');
      gone.style.color = 'var(--faint)';
      main.append(gone);
    } else if (message.media) {
      main.append(this.mediaBody(message.id, message.media));
    } else {
      main.append(this.textBody(message));
    }

    if (message.reactions && Object.keys(message.reactions).length) {
      const line = el('div', 'reactions');
      const byEmoji = new Map<string, string[]>();
      for (const [who, emoji] of Object.entries(message.reactions)) {
        byEmoji.set(emoji, [...(byEmoji.get(emoji) ?? []), who]);
      }
      for (const [emoji, whos] of byEmoji) {
        const chip = el('button', 'reaction', whos.length > 1 ? `${emoji} ${whos.length}` : emoji);
        if (whos.includes(this.protocol.stonechatId)) chip.classList.add('reaction--mine');
        chip.title = whos.map((w) => this.protocol.nameOf(w)).join(', ');
        chip.addEventListener('click', () => void this.protocol.react(message, emoji));
        line.append(chip);
      }
      main.append(line);
    }
    if (message.status === 'failed' || (message.status === 'pending' && message.error)) {
      const why = el('div', 'row__state row__state--failed mono', message.error ?? 'not sent');
      main.append(why);
    }
    row.append(rail, main);
    row.dataset['id'] = message.id;
    return row;
  }

  /**
   * Render a decrypted attachment.
   *
   * Images render inline; everything else becomes a download link, because a
   * browser asked to inline an arbitrary mime type from a stranger is a
   * decision better left to the person receiving it. The name is whatever the
   * sender chose, already stripped of any path by the protocol layer. An
   * attachment this tab never decrypted — one from before a reload — shows
   * what it was; the phone holds the file.
   */
  private mediaBody(id: string, media: MediaAttachment): HTMLElement {
    const wrap = el('div', 'row__body');
    // Decrypted in this tab, or from before a reload — in which case the
    // bytes are gone and the phone holds the file.
    const url = media.url ?? this.protocol.mediaUrls.get(id);
    if (!url) {
      const gone = el('span', 'mono', `${media.kind}${media.name ? ` · ${media.name}` : ''} · ${sizeLabel(media.size)} · not kept in this browser`);
      gone.style.color = 'var(--faint)';
      wrap.append(gone);
      return wrap;
    }
    if (media.kind === 'image' || media.kind === 'sticker' || media.mime.startsWith('image/')) {
      const img = el('img') as HTMLImageElement;
      img.src = url;
      img.alt = media.name ?? 'attachment';
      img.style.maxWidth = media.kind === 'sticker' ? '160px' : '320px';
      img.style.maxHeight = media.kind === 'sticker' ? '160px' : '320px';
      img.style.borderRadius = '8px';
      img.style.display = 'block';
      wrap.append(img);
      return wrap;
    }
    if (media.kind === 'video' || media.mime.startsWith('video/')) {
      const video = el('video') as HTMLVideoElement;
      video.src = url;
      video.controls = true;
      video.style.maxWidth = '320px';
      video.style.display = 'block';
      wrap.append(video);
      return wrap;
    }
    if (media.kind === 'audio' || media.mime.startsWith('audio/')) {
      const audio = el('audio') as HTMLAudioElement;
      audio.src = url;
      audio.controls = true;
      wrap.append(audio);
      return wrap;
    }
    const link = el('a', undefined, media.name ?? 'attachment') as HTMLAnchorElement;
    link.href = url;
    link.download = media.name ?? 'attachment';
    wrap.append(link, el('span', undefined, ` · ${sizeLabel(media.size)}`));
    return wrap;
  }

  // -- calls --------------------------------------------------------------------

  /**
   * The call, over everything else while there is one.
   *
   * One layer for every phase: ringing shows accept and decline, dialing and
   * connecting show the peer and a status line, active shows the streams
   * and the controls, ended flashes the epitaph.
   */
  private renderCall(): void {
    const call = this.calls;
    if (call.phase === 'idle') {
      this.callLayer.remove();
      this.callLayer.replaceChildren();
      return;
    }
    const peer = call.peerId ?? '';
    this.callLayer.replaceChildren();

    const stage = el('div', 'call__stage');
    if (call.withVideo && call.remoteStream) {
      const remote = el('video', 'call__remote') as HTMLVideoElement;
      remote.autoplay = true;
      remote.playsInline = true;
      remote.srcObject = call.remoteStream as unknown as MediaStream;
      stage.append(remote);
    } else if (call.remoteStream) {
      // Audio only: the element plays, nothing shows.
      const audio = el('audio') as HTMLAudioElement;
      audio.autoplay = true;
      audio.srcObject = call.remoteStream as unknown as MediaStream;
      stage.append(audio);
      stage.append(this.avatar(store.contact(peer), peer, 88));
    } else {
      stage.append(this.avatar(store.contact(peer), peer, 88));
    }
    if (call.withVideo && call.localStream && !call.cameraOff) {
      const local = el('video', 'call__local') as HTMLVideoElement;
      local.autoplay = true;
      local.playsInline = true;
      local.muted = true;
      local.srcObject = call.localStream as unknown as MediaStream;
      stage.append(local);
    }

    const who = el('div', 'call__who', this.protocol.nameOf(peer));
    const status = el('div', 'call__status mono');
    status.textContent =
      call.phase === 'dialing' ? 'calling…'
        : call.phase === 'ringing' ? `incoming ${call.withVideo ? 'video' : 'voice'} call`
          : call.phase === 'connecting' ? 'connecting…'
            : call.phase === 'active' ? 'connected'
              : call.endNote ?? 'ended';
    if (call.phase === 'active' && call.connectedAt !== null) {
      const tick = () => {
        if (call.phase !== 'active' || call.connectedAt === null) return;
        const s = Math.floor((Date.now() - call.connectedAt) / 1000);
        status.textContent = `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;
        setTimeout(tick, 1000);
      };
      tick();
    }

    const controls = el('div', 'call__controls');
    const control = (path: string, label: string, onClick: () => void, danger = false, on = false) => {
      const b = el('button', 'call__btn');
      if (danger) b.classList.add('call__btn--danger');
      if (on) b.classList.add('call__btn--on');
      b.title = label;
      b.setAttribute('aria-label', label);
      b.append(icon(path, 22), el('span', 'mono', label));
      b.addEventListener('click', onClick);
      controls.append(b);
    };
    if (call.phase === 'ringing') {
      control(ICON.hangup, 'Decline', () => void call.declineCall(), true);
      control(call.withVideo ? ICON.video : ICON.phone, 'Accept', () => void call.acceptCall());
    } else if (call.phase !== 'ended') {
      control(ICON.mic, call.muted ? 'Unmute' : 'Mute', () => call.toggleMute(), false, call.muted);
      if (call.withVideo) {
        control(ICON.video, call.cameraOff ? 'Camera on' : 'Camera off', () => call.toggleCamera(), false, call.cameraOff);
      }
      control(ICON.hangup, 'End', () => void call.hangUp(), true);
    }

    this.callLayer.append(stage, who, status, controls);
    if (!this.callLayer.isConnected) document.body.append(this.callLayer);
  }

  // -- message actions -------------------------------------------------------

  private closeMenu(): void {
    this.menu?.remove();
    this.menu = null;
  }

  private openMenu(message: Message, anchor: HTMLElement): void {
    this.closeMenu();
    const menu = el('div', 'menu');
    const add = (label: string, onClick: () => void, danger = false) => {
      const b = el('button', 'menu__item', label);
      if (danger) b.classList.add('menu__item--danger');
      b.addEventListener('click', () => {
        this.closeMenu();
        onClick();
      });
      menu.append(b);
    };
    if (!message.deleted) {
      const quick = el('div', 'menu__reactions');
      for (const emoji of QUICK_REACTIONS) {
        const b = el('button', 'reaction', emoji);
        if (this.protocol.myReactionTo(message) === emoji) b.classList.add('reaction--mine');
        b.addEventListener('click', () => {
          this.closeMenu();
          void this.protocol.react(message, emoji);
        });
        quick.append(b);
      }
      menu.append(quick);
      add('Reply', () => {
        this.replyingTo = message;
        this.renderPane();
      });
    }
    if (message.status === 'failed') add('Retry', () => void this.protocol.retryMessage(message.id));
    if (this.protocol.canEdit(message)) {
      add('Edit', () => {
        const text = prompt('Edit message', message.text);
        if (text !== null) void this.protocol.editMessage(message, text);
      });
    }
    if (this.protocol.canDeleteForEveryone(message)) {
      add('Delete for everyone', () => void this.protocol.deleteForEveryone(message), true);
    }
    add('Delete for me', () => this.protocol.deleteForMe(message), true);

    const rect = anchor.getBoundingClientRect();
    menu.style.top = `${rect.bottom + 4}px`;
    menu.style.left = `${Math.min(rect.left, window.innerWidth - 240)}px`;
    document.body.append(menu);
    this.menu = menu;
    const onAway = (e: MouseEvent) => {
      if (!menu.contains(e.target as Node)) {
        this.closeMenu();
        document.removeEventListener('mousedown', onAway);
      }
    };
    setTimeout(() => document.addEventListener('mousedown', onAway), 0);
  }

  private composerRow(open: Open, group: Group | null, contact: Contact | null): HTMLElement {
    const box = el('div', 'composer__box');
    if (group?.removed) {
      const note = el('div', 'mono composer__note', 'You were removed from this group. You can read what was said; nothing more is sent.');
      box.append(note);
      return box;
    }
    if (contact && typeof contact.blockedAt === 'number') {
      const note = el('div', 'mono composer__note', 'You blocked this person on your phone. Nothing is sent or shown from them here.');
      box.append(note);
      return box;
    }
    if (contact?.status === 'pendingIn') {
      const note = el('div', 'composer__note');
      note.append(el('span', 'mono', `${this.protocol.nameOf(open.id)} asked to connect.`));
      const decline = el('button', 'secondary', 'Decline');
      decline.addEventListener('click', () => void this.protocol.declineContact(open.id).then(() => {
        this.setOpen(null);
        this.render();
      }));
      const accept = el('button', undefined, 'Accept');
      accept.addEventListener('click', () => void this.protocol.acceptContact(open.id));
      const actions = el('div', 'modal__actions');
      actions.style.marginTop = '8px';
      actions.append(decline, accept);
      note.append(actions);
      box.append(note);
      return box;
    }
    if (contact?.status === 'pendingOut') {
      const note = el('div', 'mono composer__note', 'Request sent — the conversation opens once they accept.');
      box.append(note);
      return box;
    }
    if (!contact || contact.status !== 'accepted') {
      const note = el('div', 'mono composer__note', 'Not a contact. Use + to send them a request.');
      box.append(note);
      return box;
    }

    if (this.replyingTo) {
      const strip = el('div', 'composer__reply');
      const label = el('span', 'mono', `replying to ${this.protocol.nameOf(this.replyingTo.mine ? this.protocol.stonechatId : this.replyingTo.sender ?? this.replyingTo.peerId)}`);
      const text = el('span', 'quote__text', previewOf(this.replyingTo));
      const cancel = el('button', 'icon-btn');
      cancel.setAttribute('aria-label', 'Cancel reply');
      cancel.append(icon(ICON.close, 14));
      cancel.addEventListener('click', () => {
        this.replyingTo = null;
        this.renderPane();
      });
      strip.append(label, text, cancel);
      box.append(strip);
    }

    const row = el('div', 'composer');
    const input = el('input');
    input.type = 'text';
    input.placeholder = 'Message';
    const send = el('button', undefined, 'Send');
    // A hidden input rather than a drop zone: one control, no drag-and-drop
    // state machine, and it is the affordance people already expect.
    const picker = el('input');
    picker.type = 'file';
    picker.style.display = 'none';
    const attach = el('button', 'secondary', 'Attach');
    attach.title = 'Send a photo or file';
    attach.addEventListener('click', () => picker.click());
    picker.addEventListener('change', async () => {
      const file = picker.files?.[0];
      picker.value = ''; // so the same file can be picked twice in a row
      if (!file) return;
      attach.disabled = true;
      const previous = attach.textContent;
      // Encrypting and uploading a photo is slow enough to look broken
      // without this.
      attach.textContent = 'Sending…';
      const replyTo = this.replyingTo ?? undefined;
      this.replyingTo = null;
      try {
        const sent = open.group
          ? await this.protocol.sendGroupMedia(open.id, file, replyTo ? { replyTo } : {})
          : await this.protocol.sendMedia(open.id, file, replyTo ? { replyTo } : {});
        if (sent.media?.url) this.protocol.mediaUrls.set(sent.id, sent.media.url);
        this.render();
      } catch (e) {
        this.setStatus('down', (e as Error).message);
      } finally {
        attach.disabled = false;
        attach.textContent = previous;
      }
    });
    // Group @mentions: a trailing `@name` at the cursor fills the strip with
    // matching members; a pick completes the name and remembers its ID. On
    // send, only names still in the text count.
    const picked = new Map<string, string>(); // display name → SC- ID
    const strip = el('div', 'mention-strip');
    strip.hidden = true;
    const refreshStrip = () => {
      if (!group || group.removed) return;
      const cursor = input.selectionStart ?? input.value.length;
      const head = input.value.slice(0, cursor);
      const m = /(?:^|\s)@([^\s@]*)$/.exec(head);
      strip.replaceChildren();
      if (!m) { strip.hidden = true; return; }
      const q = m[1]!.toLowerCase();
      const matches = group.members
        .filter((mem) => mem.stonechatId !== this.protocol.stonechatId)
        .map((mem) => ({ id: mem.stonechatId, name: this.protocol.nameOf(mem.stonechatId) }))
        .filter((mem) => mem.name.toLowerCase().includes(q))
        .slice(0, 6);
      strip.hidden = matches.length === 0;
      for (const mem of matches) {
        const chip = el('button', 'mention-strip__chip', `@${mem.name}`);
        chip.type = 'button';
        chip.addEventListener('mousedown', (e) => e.preventDefault()); // keep focus
        chip.addEventListener('click', () => {
          const at = head.lastIndexOf('@');
          const replaced = `${head.slice(0, at)}@${mem.name} `;
          input.value = replaced + input.value.slice(cursor);
          input.setSelectionRange(replaced.length, replaced.length);
          picked.set(mem.name, mem.id);
          strip.hidden = true;
          strip.replaceChildren();
          input.focus();
        });
        strip.append(chip);
      }
    };
    const submit = async () => {
      const text = input.value.trim();
      if (!text) return;
      const mentions = [...picked.entries()].filter(([name]) => text.includes(`@${name}`)).map(([, id]) => id);
      picked.clear();
      strip.hidden = true;
      input.value = '';
      send.disabled = true;
      const replyTo = this.replyingTo ?? undefined;
      this.replyingTo = null;
      try {
        // By the conversation's type, never by whether a roster happens to
        // exist under its id: that lookup is what let a roster carrying a
        // contact's SC- ID redirect what was typed to them.
        // The message is in the ledger, pending, before anything is sent;
        // a failure shows on it and is retried rather than handed back.
        if (open.group) await this.protocol.sendGroup(open.id, text, { ...(replyTo ? { replyTo } : {}), ...(mentions.length ? { mentions } : {}) });
        else await this.protocol.send(open.id, text, replyTo ? { replyTo } : {});
      } catch (e) {
        this.setStatus('down', (e as Error).message);
      } finally {
        send.disabled = false;
        this.render();
        this.pane.querySelector<HTMLInputElement>('.composer input[type=text]')?.focus();
      }
    };
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') void submit();
    });
    input.addEventListener('input', () => {
      if (input.value) this.protocol.notifyTyping(open.id, open.group);
      else this.protocol.stopTyping(open.id, open.group);
      refreshStrip();
    });
    input.addEventListener('keyup', (e) => {
      if (e.key === 'ArrowLeft' || e.key === 'ArrowRight') refreshStrip();
    });
    send.addEventListener('click', () => void submit());
    row.append(picker, attach, input, send);
    box.append(strip, row);
    setTimeout(() => input.focus(), 0);
    return box;
  }
}

/** The delivery state of one of our messages, in the machine voice. */
function stateLabel(message: Message): HTMLElement {
  const label = el('span', 'row__state mono');
  switch (message.status) {
    case 'pending':
      label.textContent = '…';
      label.classList.add('row__state--pending');
      label.title = 'not delivered yet';
      break;
    case 'failed':
      label.textContent = 'failed';
      label.classList.add('row__state--failed');
      break;
    case 'delivered':
      label.textContent = '✓✓';
      label.title = 'delivered';
      break;
    case 'read':
      label.textContent = '✓✓';
      label.classList.add('row__state--read');
      label.title = 'read';
      break;
    default:
      label.textContent = '✓';
      label.title = 'sent';
  }
  return label;
}

function previewOf(message: Message, protocol?: Protocol): string {
  const by = protocol && message.group && !message.mine && message.sender
    ? `${protocol.nameOf(message.sender)}: `
    : message.mine ? 'you: ' : '';
  if (message.deleted) return `${by}message deleted`;
  if (message.media) return `${by}${message.media.kind}${message.media.name ? ` · ${message.media.name}` : ''}`;
  return `${by}${message.text}`;
}

function sizeLabel(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function remaining(at: number): string {
  const ms = Math.max(0, at - Date.now());
  if (ms < 60_000) return `${Math.round(ms / 1000)}s`;
  if (ms < 3_600_000) return `${Math.round(ms / 60_000)}m`;
  if (ms < 86_400_000) return `${Math.round(ms / 3_600_000)}h`;
  return `${Math.round(ms / 86_400_000)}d`;
}

function time(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime())
    ? ''
    : `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
}
