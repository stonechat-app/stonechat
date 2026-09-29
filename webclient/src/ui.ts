/**
 * The client: a rail, a conversation list, and a conversation.
 *
 * Style is `theme.css`, lifted value-for-value from `app/lib/ui/theme.dart`:
 * warm near-black surfaces, 4px corners, burnt-orange accent, monospace for
 * anything machine-made. Messages render as a left-aligned ledger with coloured
 * rails, not bubbles — the *layout* is desktop-shaped, the visual language is
 * still ours.
 *
 * **Messages persist, up to a cap.** They used to live in memory only, which
 * meant a refresh emptied every conversation — defensible on paper and
 * unusable in practice. `store.ts` holds the reasoning and the bound.
 */
import birdMark from './bird.png';
import type { MediaAttachment, Message, Protocol } from './protocol.js';
import { certExpiry } from './device.js';
import {
  MAX_MESSAGES_PER_CONVERSATION,
  store,
  threadKey,
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
};

/** The per-contact colour, by the same hash the app uses (`Zn.idColor`), so a
 * contact is the same colour on both clients. */
function idColor(stonechatId: string): string {
  let h = 0;
  for (const c of stonechatId) h = (h * 31 + c.charCodeAt(0)) & 0x7fffffff;
  return `var(--id-${h % 6})`;
}

const shortId = (id: string) => id.replace(/^SC-/, '').slice(0, 9);

/**
 * The top bar: the mark and wordmark on the left, connection status on the
 * right.
 *
 * One bar rather than two. The status used to sit in a strip of its own above
 * the app, which spent a whole row saying "connected" — folding it in beside
 * the brand costs nothing and reads as one piece of chrome.
 *
 * The mark is the same bird as the phone app and the landing page
 * (`app/assets/logo/bird.png`), and the wordmark is set in the monospace face
 * with the landing site's letter-spacing, so the three surfaces still look
 * like one product.
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

  /** Loaded from storage on mount and written through on every change, so a
   * refresh resumes rather than forgetting. */
  private readonly threads = new Map<string, Message[]>();
  private open: Open | null = null;
  private section: Section = 'chats';
  private readonly railButtons = new Map<string, HTMLButtonElement>();

  constructor(private readonly protocol: Protocol) {}

  mount(into: HTMLElement): void {
    // Keyed as stored (`threadKey`), so a group's thread and a peer's stay
    // apart in memory exactly as they do on disk.
    for (const [key, messages] of Object.entries(store.messages())) {
      this.threads.set(key, messages);
    }
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
        // Creating one means choosing contacts and fanning a roster out to
        // every member's every device. Reading and replying is the useful
        // half; making that claim without the fan-out would be worse.
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
      this.open = null;
    }
    this.render();
  }

  private setStatus(kind: 'live' | 'warn' | 'down', text: string): void {
    this.dot.className = `dot dot--${kind}`;
    this.bannerText.textContent = text;
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
      card.append(el('h2', undefined, 'New conversation'));
      const lede = el(
        'p',
        'mono',
        'Paste their Stonechat ID. There is nothing to search — an ID is a ' +
          'commitment to a key, not a name in a directory.',
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

      const submit = () => {
        const id = input.value.trim().toUpperCase();
        if (!id.startsWith('SC-') || id.length < 10) {
          error.textContent = "that doesn't look like a Stonechat ID";
          return;
        }
        if (id === this.protocol.stonechatId) {
          // Your devices share your ID; a conversation with yourself is not a
          // thing this protocol has.
          error.textContent = 'that is your own ID';
          return;
        }
        // Recorded on open so the conversation exists before the first send —
        // the public key is filled in when the directory is resolved.
        store.setContact({ stonechatId: id, pubkey: '' });
        this.section = 'chats';
        this.open = { group: false, id };
        close();
        this.render();
      };
      input.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') submit();
      });

      const cancel = el('button', 'secondary', 'Cancel');
      cancel.addEventListener('click', close);
      const go = el('button', undefined, 'Open');
      go.addEventListener('click', submit);
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
          'session ends',
          expiry ? `${expiry.toISOString().slice(0, 10)} · ${days}d` : 'unknown',
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

  private push(message: Message): void {
    const key = threadKey(message.peerId, message.group === true);
    const thread = this.threads.get(key) ?? [];
    // Redelivery is normal — the relay re-sends anything unacked when a socket
    // reconnects — so the same message can arrive twice across a refresh.
    if (thread.some((m) => m.id === message.id)) return;
    thread.push(message);
    this.threads.set(key, thread);
    store.appendMessage(message);
    this.render();
  }

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
      // A clear performed on the phone has to empty the view here too, or the
      // browser goes on showing history the user believes they deleted — the
      // one outcome that makes "clear chat" untrustworthy.
      // A roster arriving is what makes a group exist here at all, and one
      // changing can rename it or end our part in it.
      this.protocol.onGroupsChanged = () => this.render();
      this.protocol.onConversationCleared = (peerId, group) => {
        this.threads.set(threadKey(peerId, group), []);
        this.render();
      };
      for await (const message of this.protocol.receive()) {
        this.push(message);
      }
      this.setStatus('warn', 'disconnected — reload to reconnect');
    } catch (e) {
      const message = (e as Error).message;
      // 410 is the relay saying this device is gone — revoked, or its mailbox
      // was replaced. Nothing here recovers from that, so say what to do
      // rather than showing a network error forever.
      const dead = /\b410\b/.test(message) || /revoked/i.test(message);
      this.setStatus(
        'down',
        dead
          ? 'This browser is no longer linked — open Settings and Unlink.'
          : message,
      );
    }
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

    if (this.section === 'groups') {
      // Only groups we hold a roster for. One we were linked too late to hear
      // about has no row and no messages until its admin next changes it:
      // without a roster there is no telling a member from anyone else.
      const known = store.groups();
      if (Object.keys(known).length === 0) {
        const note = el('div', 'mono');
        note.style.padding = 'var(--gutter)';
        note.style.color = 'var(--faint)';
        note.textContent = 'no groups yet — create one on your phone';
        this.listBody.append(note);
        return;
      }
      for (const group of Object.values(known)) {
        this.listBody.append(
          this.groupRow(group.id, group.name, group.removed === true),
        );
      }
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
    // Most recent first, so a reply moves a conversation up the list.
    for (const contact of contacts.sort((a, b) => this.lastAt(b) - this.lastAt(a))) {
      this.listBody.append(this.contactRow(contact));
    }
  }

  private lastAt(contact: Contact): number {
    const thread = this.threads.get(contact.stonechatId);
    const last = thread?.[thread.length - 1];
    return last ? Date.parse(last.sentAt) || 0 : 0;
  }

  private contactRow(contact: Contact): HTMLElement {
    const thread = this.threads.get(contact.stonechatId) ?? [];
    const last = thread[thread.length - 1];
    const row = el(
      'div',
      this.open !== null && !this.open.group && contact.stonechatId === this.open.id
        ? 'row row--active'
        : 'row',
    );
    row.style.cursor = 'pointer';
    row.style.borderBottom = '1px solid var(--line)';
    const rail = el('div', 'row__rail');
    rail.style.background = idColor(contact.stonechatId);
    const main = el('div');
    main.style.minWidth = '0';
    const meta = el('div', 'row__meta');
    // Always the ID. A contact row is never named from a roster: a group's
    // name is its admin's choice, and this row is somebody else.
    const who = el('span', 'row__who mono--id', shortId(contact.stonechatId));
    who.style.color = idColor(contact.stonechatId);
    meta.append(who);
    if (last) meta.append(el('span', undefined, time(last.sentAt)));
    const preview = el('div', 'row__body', last ? last.text : 'no messages yet');
    preview.style.whiteSpace = 'nowrap';
    preview.style.overflow = 'hidden';
    preview.style.textOverflow = 'ellipsis';
    if (!last) preview.style.color = 'var(--faint)';
    main.append(meta, preview);
    row.append(rail, main);
    row.addEventListener('click', () => {
      this.open = { group: false, id: contact.stonechatId };
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
  private groupRow(id: string, label: string, removed: boolean): HTMLElement {
    const row = el('button', 'conv');
    if (this.open?.group && id === this.open.id) row.classList.add('conv--open');
    const name = el('span', 'row__who', label);
    row.append(name);
    if (removed) {
      const hint = el('span', 'mono', ' · read-only');
      hint.style.color = 'var(--faint)';
      hint.title = 'You were removed from this group.';
      row.append(hint);
    }
    row.addEventListener('click', () => {
      this.open = { group: true, id };
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

    const head = el('div', 'pane__head');
    const back = el('button', 'icon-btn pane__back');
    back.setAttribute('aria-label', 'Back');
    back.append(icon(ICON.back, 18));
    back.addEventListener('click', () => {
      this.open = null;
      this.render();
    });
    const open = this.open;
    const openGroup = open.group ? store.groups()[open.id] : undefined;
    const title = openGroup
      ? el('span', undefined, openGroup.name)
      : el('span', 'mono mono--id', shortId(open.id));
    title.style.color = idColor(open.id);
    title.style.fontSize = '13px';
    const full = el('span', 'mono', open.id);
    full.style.color = 'var(--faint)';
    full.style.marginLeft = 'auto';
    full.style.overflow = 'hidden';
    full.style.textOverflow = 'ellipsis';
    full.style.whiteSpace = 'nowrap';
    head.append(back, title, full);

    const ledger = el('div', 'ledger');
    const thread = this.threads.get(threadKey(open.id, open.group)) ?? [];
    if (thread.length === 0) {
      const empty = el('div', 'mono');
      empty.style.padding = 'var(--gutter)';
      empty.style.color = 'var(--faint)';
      empty.textContent = 'nothing here yet';
      ledger.append(empty);
    }
    for (const message of thread) ledger.append(this.messageRow(message));

    this.pane.append(head, ledger, this.composerRow(open));
    ledger.scrollTop = ledger.scrollHeight;
  }

  private messageRow(message: Message): HTMLElement {
    const row = el('div', message.mine ? 'row row--mine' : 'row');
    const rail = el('div', 'row__rail');
    if (!message.mine) rail.style.background = idColor(message.peerId);
    const main = el('div');
    const meta = el('div', 'row__meta');
    const who = el(
      'span',
      'row__who',
      message.mine ? 'you' : shortId(message.sender ?? message.peerId),
    );
    if (!message.mine) who.style.color = idColor(message.peerId);
    meta.append(who, el('span', undefined, time(message.sentAt)));
    main.append(meta, message.media ? mediaBody(message.media) : el('div', 'row__body', message.text));
    row.append(rail, main);
    return row;
  }

  private composerRow(open: Open): HTMLElement {
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
    const attach = el('button', undefined, 'Attach');
    attach.title = 'Send a photo or file';
    attach.addEventListener('click', () => picker.click());
    picker.addEventListener('change', async () => {
      const file = picker.files?.[0];
      picker.value = ''; // so the same file can be picked twice in a row
      if (!file) return;
      if (open.group) {
        // There is no group media send here, and the DM one must not be
        // handed a group's id as if it were a person.
        this.setStatus('warn', 'Attachments to a group are sent from your phone.');
        return;
      }
      attach.disabled = true;
      const previous = attach.textContent;
      // Encrypting and uploading a photo is slow enough to look broken
      // without this, and there is no outbox to show progress anywhere else.
      attach.textContent = 'Sending…';
      try {
        this.push(await this.protocol.sendMedia(open.id, file));
      } catch (e) {
        this.setStatus('down', (e as Error).message);
      } finally {
        attach.disabled = false;
        attach.textContent = previous;
      }
    });
    const submit = async () => {
      const text = input.value.trim();
      if (!text) return;
      input.value = '';
      send.disabled = true;
      try {
        // By the conversation's type, never by whether a roster happens to
        // exist under its id: that lookup is what let a roster carrying a
        // contact's SC- ID redirect what was typed to them.
        this.push(
          open.group
            ? await this.protocol.sendGroup(open.id, text)
            : await this.protocol.send(open.id, text),
        );
      } catch (e) {
        this.setStatus('down', (e as Error).message);
        // Put it back rather than losing what they typed — there is no outbox
        // and no retry, so the composer is the only place it survives.
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
    row.append(picker, attach, input, send);
    setTimeout(() => input.focus(), 0);
    return row;
  }
}

/**
 * Render a decrypted attachment.
 *
 * Images render inline; everything else becomes a download link, because a
 * browser asked to inline an arbitrary mime type from a stranger is a
 * decision better left to the person receiving it. The name is whatever the
 * sender chose, already stripped of any path by the protocol layer.
 */
function mediaBody(media: MediaAttachment): HTMLElement {
  const wrap = el('div', 'row__body');
  if (media.kind === 'image' || media.mime.startsWith('image/')) {
    const img = el('img') as HTMLImageElement;
    img.src = media.url;
    img.alt = media.name ?? 'attachment';
    img.style.maxWidth = '320px';
    img.style.maxHeight = '320px';
    img.style.borderRadius = '8px';
    img.style.display = 'block';
    wrap.append(img);
    return wrap;
  }
  const link = el('a', undefined, media.name ?? 'attachment') as HTMLAnchorElement;
  link.href = media.url;
  link.download = media.name ?? 'attachment';
  wrap.append(link, el('span', undefined, ` · ${sizeLabel(media.size)}`));
  return wrap;
}

function sizeLabel(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function time(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime())
    ? ''
    : `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
}
