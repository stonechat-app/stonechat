/**
 * Talking to a mailbox over WebTransport.
 *
 * The relay carries its whole HTTP surface on this transport, one bidirectional
 * stream per request (`relay/src/wt.rs`). Each stream is a JSON header line and
 * an optional body:
 *
 * ```text
 * {"method":"POST","path":"/inbox","len":1234}\n<1234 bytes>
 * ```
 *
 * and the reply comes back the same shape. `/ws` is the exception, and it is
 * the HTTP one: the relay answers `{"status":101}` and the stream then carries
 * the owner socket — newline-delimited envelopes down, `{"ack": id}` up.
 *
 * The session is authenticated **once**, at CONNECT, by the device token in
 * the URL. A stream carries no token of its own, so opening many is cheap and
 * they run concurrently.
 */
import { fromUtf8, utf8 } from './bytes.js';
import type { MailboxRoute } from './transport.js';
import { connectMailbox } from './transport.js';

export interface MailboxResponse {
  status: number;
  headers: Record<string, string>;
  body: Uint8Array;
}

export class MailboxError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = 'MailboxError';
  }
}

/** What a drained envelope looks like on the wire, plus the close frames the
 * relay sends in place of a WebSocket close code. */
export type SocketMessage =
  | { kind: 'envelope'; envelope: Record<string, unknown> }
  | { kind: 'closed'; code: number; reason: string };

export interface Session {
  createBidirectionalStream(): Promise<{
    readable: ReadableStream<Uint8Array>;
    writable: WritableStream<Uint8Array>;
  }>;
  closed: Promise<unknown>;
  close(info?: { closeCode?: number; reason?: string }): void;
}

/** Split a byte stream into newline-delimited lines. */
async function* lines(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  seed: Uint8Array,
): AsyncGenerator<string> {
  let acc = seed;
  for (;;) {
    let idx = acc.indexOf(10);
    while (idx !== -1) {
      yield fromUtf8.decode(acc.subarray(0, idx));
      acc = acc.subarray(idx + 1);
      idx = acc.indexOf(10);
    }
    const { value, done } = await reader.read();
    if (done) return;
    const next = new Uint8Array(acc.length + value.length);
    next.set(acc);
    next.set(value, acc.length);
    acc = next;
  }
}

export class Mailbox {
  private constructor(private readonly session: Session) {}

  static async open(route: MailboxRoute, deviceToken: string): Promise<Mailbox> {
    return new Mailbox((await connectMailbox(route, deviceToken)) as Session);
  }

  /** Drive an already-open session. The framing is what is worth testing and
   * a real WebTransport is not available off a browser, so this is how the
   * tests reach it. */
  static overSession(session: Session): Mailbox {
    return new Mailbox(session);
  }

  /** Closed by the relay or by us. Resolves either way; the caller decides
   * whether to reconnect. */
  get closed(): Promise<unknown> {
    return this.session.closed;
  }

  close(): void {
    this.session.close();
  }

  /**
   * One request on its own stream.
   *
   * The body is bytes, not text: blobs are arbitrary binary and large enough
   * to span many reads, and treating them as strings is how a round trip gets
   * silently corrupted rather than loudly broken.
   */
  async request(
    method: string,
    path: string,
    body: Uint8Array = new Uint8Array(0),
  ): Promise<MailboxResponse> {
    const stream = await this.session.createBidirectionalStream();
    const writer = stream.writable.getWriter();
    const header = utf8.encode(
      JSON.stringify({ method, path, len: body.length }) + '\n',
    );
    await writer.write(header);
    if (body.length > 0) await writer.write(body);
    await writer.close();

    const reader = stream.readable.getReader();
    // The header line, then exactly `len` more bytes. Reading to end-of-stream
    // instead would work here and break the moment anything is pipelined.
    let acc = new Uint8Array(0);
    let head: { status: number; headers?: Record<string, string>; len: number } | null =
      null;
    for (;;) {
      const idx = acc.indexOf(10);
      if (idx !== -1) {
        head = JSON.parse(fromUtf8.decode(acc.subarray(0, idx)));
        acc = acc.subarray(idx + 1);
        break;
      }
      const { value, done } = await reader.read();
      if (done) throw new MailboxError('mailbox closed the stream', 0);
      const next = new Uint8Array(acc.length + value.length);
      next.set(acc);
      next.set(value, acc.length);
      acc = next;
    }
    const wanted = head!.len;
    const parts: Uint8Array[] = [acc];
    let have = acc.length;
    while (have < wanted) {
      const { value, done } = await reader.read();
      if (done) break;
      parts.push(value);
      have += value.length;
    }
    const out = new Uint8Array(Math.min(have, wanted));
    let at = 0;
    for (const part of parts) {
      if (at >= out.length) break;
      out.set(part.subarray(0, out.length - at), at);
      at += part.length;
    }
    return {
      status: head!.status,
      headers: head!.headers ?? {},
      body: out,
    };
  }

  /** A request whose body is JSON, and whose reply is expected to be. Throws
   * on any non-2xx, carrying the status so callers can tell 410 (device gone)
   * from 401 (token dead) — the app shows different things for those. */
  async json<T>(method: string, path: string, body?: unknown): Promise<T> {
    const r = await this.request(
      method,
      path,
      body === undefined ? undefined : utf8.encode(JSON.stringify(body)),
    );
    if (r.status < 200 || r.status >= 300) {
      throw new MailboxError(
        fromUtf8.decode(r.body) || `mailbox returned ${r.status}`,
        r.status,
      );
    }
    return (r.body.length ? JSON.parse(fromUtf8.decode(r.body)) : null) as T;
  }

  /**
   * The owner socket: drains the queue, then stays open for live delivery.
   *
   * [deviceToken] authorises it — the socket names the device, and the device
   * names the queue.
   *
   * `ack` deletes the row — only this device's copy, so a sibling still owed
   * the same envelope keeps its own. Ack after the envelope is stored, never
   * before: the relay's promise is "accepted for write", not "read".
   */
  async *socket(deviceToken: string): AsyncGenerator<SocketMessage, void, void> {
    const stream = await this.session.createBidirectionalStream();
    const writer = stream.writable.getWriter();
    // The token rides on the *request*, not the session. The session is
    // deliberately unauthenticated — sealed sender means a stranger has to be
    // able to deliver — so every route that needs authorisation carries its
    // own, exactly as over HTTP. Omitting it here gets a 403 that looks like
    // a transport failure and is not.
    await writer.write(
      utf8.encode(
        JSON.stringify({
          method: 'GET',
          path: `/ws?token=${encodeURIComponent(deviceToken)}`,
          len: 0,
        }) + '\n',
      ),
    );
    this.ack = async (id: string) => {
      await writer.write(utf8.encode(JSON.stringify({ ack: id }) + '\n'));
    };

    const reader = stream.readable.getReader();
    let first = true;
    for await (const line of lines(reader, new Uint8Array(0))) {
      if (!line) continue;
      const value = JSON.parse(line) as Record<string, unknown>;
      if (first) {
        first = false;
        if (value['status'] !== 101) {
          throw new MailboxError(
            `mailbox refused the socket (${String(value['status'])})`,
            Number(value['status']) || 0,
          );
        }
        continue;
      }
      if (typeof value['close'] === 'number') {
        // 4000 replaced by a newer connection, 4001 revoked. The distinction
        // matters: one means another tab took over, the other means this
        // device is finished.
        yield {
          kind: 'closed',
          code: value['close'],
          reason: String(value['reason'] ?? ''),
        };
        return;
      }
      yield { kind: 'envelope', envelope: value };
    }
  }

  /** Set once [socket] is running. Acking before then is a programming error,
   * not a network one, so it throws rather than silently dropping. */
  ack: (id: string) => Promise<void> = async () => {
    throw new Error('ack before the socket was opened');
  };
}
