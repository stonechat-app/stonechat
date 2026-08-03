/**
 * The client half of the WebTransport framing.
 *
 * Driven against a mock session that behaves like `relay/src/wt.rs`: a JSON
 * header line, then exactly the declared number of body bytes. The relay side
 * has its own end-to-end tests against a real process; this pins the *client*
 * against the same contract, including the parts that only go wrong under
 * fragmentation.
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';

import { Mailbox, MailboxError, type Session } from '../src/mailbox.js';
import { fromUtf8, utf8 } from '../src/bytes.js';

/** How a mock relay answers one request. */
type Handler = (
  method: string,
  path: string,
  body: Uint8Array,
) => { status: number; headers?: Record<string, string>; body?: Uint8Array };

interface MockOptions {
  /** Bytes per chunk on the way back. Small values fragment every frame,
   * which is where length handling actually breaks. */
  chunk?: number;
  /** Lines the `/ws` stream emits after the upgrade reply. */
  socketLines?: unknown[];
  /** What the relay answers to `/ws`. Anything but 101 is a refusal. */
  socketStatus?: number;
}

function mockRelay(handler: Handler, options: MockOptions = {}): {
  session: Session;
  acks: string[];
} {
  const chunk = options.chunk ?? 1 << 20;
  const acks: string[] = [];

  const session: Session = {
    closed: new Promise(() => {}),
    close() {},
    async createBidirectionalStream() {
      let outbound = new Uint8Array(0);
      let deliver: ((chunk: Uint8Array | null) => void) | null = null;
      const queue: Array<Uint8Array | null> = [];
      const push = (data: Uint8Array | null) => {
        if (deliver) {
          const fn = deliver;
          deliver = null;
          fn(data);
        } else queue.push(data);
      };
      const sendChunked = (data: Uint8Array) => {
        for (let i = 0; i < data.length; i += chunk) {
          push(data.subarray(i, Math.min(i + chunk, data.length)));
        }
      };

      let head: { method: string; path: string; len: number } | null = null;
      let isSocket = false;

      const writable = new WritableStream<Uint8Array>({
        write(data) {
          const next = new Uint8Array(outbound.length + data.length);
          next.set(outbound);
          next.set(data, outbound.length);
          outbound = next;

          for (;;) {
            if (head === null) {
              const idx = outbound.indexOf(10);
              if (idx === -1) return;
              head = JSON.parse(fromUtf8.decode(outbound.subarray(0, idx)));
              outbound = outbound.subarray(idx + 1);
              if (head!.path.split('?')[0] === '/ws') {
                isSocket = true;
                push(
                  utf8.encode(
                    JSON.stringify({ status: options.socketStatus ?? 101 }) + '\n',
                  ),
                );
                for (const line of options.socketLines ?? []) {
                  push(utf8.encode(JSON.stringify(line) + '\n'));
                }
                // End the stream, so a consumer that is waiting for more
                // terminates instead of hanging — a real relay closes too.
                push(null);
                continue;
              }
            }
            if (isSocket) {
              // Acks, newline-delimited.
              let idx = outbound.indexOf(10);
              while (idx !== -1) {
                const line = fromUtf8.decode(outbound.subarray(0, idx));
                if (line) acks.push((JSON.parse(line) as { ack: string }).ack);
                outbound = outbound.subarray(idx + 1);
                idx = outbound.indexOf(10);
              }
              return;
            }
            if (outbound.length < head!.len) return;
            const body = outbound.subarray(0, head!.len);
            const reply = handler(head!.method, head!.path, body);
            const replyBody = reply.body ?? new Uint8Array(0);
            sendChunked(
              utf8.encode(
                JSON.stringify({
                  status: reply.status,
                  headers: reply.headers ?? {},
                  len: replyBody.length,
                }) + '\n',
              ),
            );
            sendChunked(replyBody);
            push(null);
            return;
          }
        },
        close() {},
      });

      const readable = new ReadableStream<Uint8Array>({
        async pull(controller) {
          const next =
            queue.length > 0
              ? queue.shift()!
              : await new Promise<Uint8Array | null>((r) => (deliver = r));
          if (next === null) controller.close();
          else controller.enqueue(next);
        },
      });
      return { readable, writable };
    },
  };
  return { session, acks };
}

const okJson = (value: unknown): ReturnType<Handler> => ({
  status: 200,
  headers: { 'content-type': 'application/json' },
  body: utf8.encode(JSON.stringify(value)),
});

test('a request round-trips through the framing', async () => {
  const seen: Array<[string, string, string]> = [];
  const { session } = mockRelay((method, path, body) => {
    seen.push([method, path, fromUtf8.decode(body)]);
    return okJson({ queued: 3 });
  });
  const mailbox = Mailbox.overSession(session);
  const status = await mailbox.json<{ queued: number }>('GET', '/status?token=t');
  assert.equal(status.queued, 3);
  assert.deepEqual(seen[0], ['GET', '/status?token=t', '']);
});

test('a JSON body reaches the relay intact', async () => {
  let received = '';
  const { session } = mockRelay((_m, _p, body) => {
    received = fromUtf8.decode(body);
    return okJson({ status: 'delivered' });
  });
  const mailbox = Mailbox.overSession(session);
  await mailbox.json('POST', '/inbox', { id: 'e-1', sealed: 'AAAA' });
  assert.deepEqual(JSON.parse(received), { id: 'e-1', sealed: 'AAAA' });
});

test('binary bodies survive in both directions, fragmented', async () => {
  // The case JSON-header framing has to get right: arbitrary bytes, big
  // enough to span many reads. A length mistake corrupts silently rather than
  // failing, so this fragments hard on purpose.
  const blob = new Uint8Array(300_000);
  for (let i = 0; i < blob.length; i++) blob[i] = i % 256;
  let uploaded: Uint8Array | null = null;
  const { session } = mockRelay(
    (_m, _p, body) => {
      uploaded = body.slice();
      return { status: 200, body: body.slice() };
    },
    { chunk: 1337 }, // a size that lines up with nothing
  );
  const mailbox = Mailbox.overSession(session);
  const r = await mailbox.request('POST', '/blob?token=t', blob);
  assert.equal(r.status, 200);
  assert.equal(uploaded!.length, blob.length, 'upload length');
  assert.deepEqual(uploaded, blob, 'upload bytes');
  assert.equal(r.body.length, blob.length, 'download length');
  assert.deepEqual(r.body, blob, 'download bytes');
});

test('a one-byte-at-a-time relay is still parsed correctly', async () => {
  // Nothing guarantees a chunk boundary lines up with a frame boundary. The
  // pathological case is cheap to test and the one that bites in production.
  const { session } = mockRelay(() => okJson({ ok: true, note: 'x'.repeat(50) }), {
    chunk: 1,
  });
  const mailbox = Mailbox.overSession(session);
  const value = await mailbox.json<{ ok: boolean }>('GET', '/status');
  assert.equal(value.ok, true);
});

test('response headers survive', async () => {
  const { session } = mockRelay(() => ({
    status: 200,
    headers: { 'content-type': 'application/octet-stream' },
    body: new Uint8Array([1, 2, 3]),
  }));
  const r = await Mailbox.overSession(session).request('GET', '/blob/x');
  assert.equal(r.headers['content-type'], 'application/octet-stream');
});

test('a non-2xx throws with its status, not a generic failure', async () => {
  // 410 (device revoked) and 401 (token dead) mean different things to the
  // user, so the status has to survive.
  for (const status of [401, 404, 410, 500]) {
    const { session } = mockRelay(() => ({
      status,
      body: utf8.encode('nope'),
    }));
    await assert.rejects(
      () => Mailbox.overSession(session).json('GET', '/status'),
      (e: MailboxError) => e instanceof MailboxError && e.status === status,
    );
  }
});

test('the socket drains, acks, and reports a close code', async () => {
  const { session, acks } = mockRelay(() => okJson({}), {
    socketLines: [
      { id: 'e-1', sealed: 'AAAA' },
      { id: 'e-2', sealed: 'BBBB' },
      { close: 4001, reason: 'device revoked' },
    ],
  });
  const mailbox = Mailbox.overSession(session);
  const seen: string[] = [];
  let closed: { code: number; reason: string } | null = null;
  for await (const message of mailbox.socket()) {
    if (message.kind === 'envelope') {
      seen.push(String(message.envelope['id']));
      await mailbox.ack(String(message.envelope['id']));
    } else {
      closed = { code: message.code, reason: message.reason };
    }
  }
  assert.deepEqual(seen, ['e-1', 'e-2']);
  assert.deepEqual(acks, ['e-1', 'e-2']);
  // 4000 replaced vs 4001 revoked: one means another tab took over, the other
  // means this device is finished. The app shows different things.
  assert.deepEqual(closed, { code: 4001, reason: 'device revoked' });
});

test('the upgrade reply is consumed, not yielded as an envelope', async () => {
  const { session } = mockRelay(() => okJson({}), {
    socketLines: [{ id: 'e-1' }],
  });
  const messages = [];
  for await (const m of Mailbox.overSession(session).socket()) messages.push(m);
  // One envelope, not two: the `{"status":101}` frame is the upgrade, and
  // treating it as an envelope would hand the app a message with no id.
  assert.equal(messages.length, 1);
  assert.equal(messages[0]!.kind, 'envelope');
});

test('a refused upgrade throws instead of pretending to be connected', async () => {
  // 403 here means the token stopped authenticating between CONNECT and the
  // socket — a revoked device. Silently yielding nothing would look exactly
  // like an empty queue.
  const { session } = mockRelay(() => okJson({}), { socketStatus: 403 });
  await assert.rejects(async () => {
    for await (const _ of Mailbox.overSession(session).socket()) {
      // no messages expected
    }
  }, (e: MailboxError) => e instanceof MailboxError && e.status === 403);
});

test('acking before the socket is open is a programming error', async () => {
  const { session } = mockRelay(() => okJson({}));
  await assert.rejects(
    () => Mailbox.overSession(session).ack('e-1'),
    /before the socket was opened/,
  );
});
