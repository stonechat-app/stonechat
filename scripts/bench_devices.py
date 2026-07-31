"""Phase 2 question: a per-device fan-out sends k envelopes per recipient, and
all k of a recipient's devices live on ONE mailbox. Does reusing the TLS
connection across a recipient's devices pay for itself?

Compares, for 25 recipients x 3 devices = 75 envelopes:
  fresh   — 75 connections, one per envelope (what the code does today)
  reused  — 25 connections, three requests each (keep-alive per recipient)

Same delay proxy as bench_fanout.py so handshakes pay real round trips.
"""
import asyncio
import json
import ssl
import sys
import time

from bench_fanout import CTX, DelayProxy, CONCURRENCY

RECIPIENTS = 25
DEVICES = 3
RTTS_MS = [30, 80]

BODY = json.dumps({
    "v": 1, "id": "dev-0000", "to": "SC-TEST-OWNER", "sealed": "aGVsbG8=",
}).encode()


def request(i, last):
    body = BODY.replace(b"dev-0000", f"dev-{i:05d}".encode())
    conn = b"close" if last else b"keep-alive"
    return (b"POST /inbox HTTP/1.1\r\nHost: relay\r\n"
            b"Content-Type: application/json\r\n"
            + f"Content-Length: {len(body)}\r\n".encode()
            + b"Connection: " + conn + b"\r\n\r\n" + body)


async def send_fresh(port, i):
    r, w = await asyncio.open_connection("127.0.0.1", port, ssl=CTX)
    w.write(request(i, True))
    await w.drain()
    await r.read(65536)
    w.close()
    try:
        await w.wait_closed()
    except (ssl.SSLError, OSError):
        pass


async def send_reused(port, base, k):
    """One connection, k requests — a recipient's k devices."""
    r, w = await asyncio.open_connection("127.0.0.1", port, ssl=CTX)
    for j in range(k):
        w.write(request(base + j, j == k - 1))
        await w.drain()
        await r.readuntil(b"\r\n\r\n")
    w.close()
    try:
        await w.wait_closed()
    except (ssl.SSLError, OSError):
        pass


async def bounded(tasks, limit):
    sem = asyncio.Semaphore(limit)

    async def one(t):
        async with sem:
            await t()

    await asyncio.gather(*(one(t) for t in tasks))


async def main():
    host, target = sys.argv[1], int(sys.argv[2])
    total = RECIPIENTS * DEVICES
    print(f"{RECIPIENTS} recipients x {DEVICES} devices = {total} envelopes, "
          f"bounded at {CONCURRENCY}\n")
    print(f"{'rtt':>6} {'fresh conns':>13} {'reused/recipient':>18} {'saving':>8}")
    print("-" * 50)
    base = 100000
    for rtt in RTTS_MS:
        proxy = DelayProxy(host, target, rtt)
        port = await proxy.start()
        fresh_runs, reuse_runs = [], []
        for _ in range(3):
            t = time.perf_counter()
            await bounded([lambda i=base + i: send_fresh(port, i)
                           for i in range(total)], CONCURRENCY)
            fresh_runs.append(time.perf_counter() - t)
            base += total

            t = time.perf_counter()
            await bounded([lambda b=base + r * DEVICES: send_reused(port, b, DEVICES)
                           for r in range(RECIPIENTS)], CONCURRENCY)
            reuse_runs.append(time.perf_counter() - t)
            base += total
        f, u = min(fresh_runs), min(reuse_runs)
        print(f"{rtt:>4}ms {f*1000:>12.0f}ms {u*1000:>17.0f}ms "
              f"{(1 - u / f) * 100:>7.0f}%")
        await proxy.stop()


if __name__ == "__main__":
    asyncio.run(main())
