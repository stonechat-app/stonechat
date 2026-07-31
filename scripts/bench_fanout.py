"""Measure what a group fan-out actually costs: N envelope deliveries, serial
vs bounded-concurrent, against a real relay over TLS.

The app opens a FRESH pinned TLS client per delivery (api.dart pinnedClient →
close), so every member costs a full handshake plus the POST. That is the cost
being measured here, not a bare request.

Real network latency is simulated with an in-process TCP delay proxy rather
than assumed, so the TLS handshake's multiple round trips are paid for the way
they would be on a phone.

Usage: python3 bench_fanout.py <relay_host> <relay_port>
"""
import asyncio
import json
import ssl
import statistics
import sys
import time

CONCURRENCY = 6          # fanOutConcurrency in chat_state.dart
MEMBERS = [5, 25, 75]    # 75 = 25 members x 3 devices, the multi-device case
RTTS_MS = [0, 30, 80]    # localhost, good wifi, mobile

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

ENVELOPE = json.dumps({
    "v": 1, "id": "bench-0000", "to": "SC-TEST-OWNER", "sealed": "aGVsbG8=",
}).encode()


class DelayProxy:
    """TCP proxy adding `delay_ms` in each direction — one RTT per round trip,
    so a TLS handshake pays it as many times as it really would."""

    def __init__(self, target_host, target_port, delay_ms):
        self.target = (target_host, target_port)
        self.delay = delay_ms / 2000.0  # half an RTT per direction
        self.server = None

    async def start(self):
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        return self.server.sockets[0].getsockname()[1]

    async def _pump(self, reader, writer):
        try:
            while chunk := await reader.read(65536):
                if self.delay:
                    await asyncio.sleep(self.delay)
                writer.write(chunk)
                await writer.drain()
        except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()

    async def _handle(self, cr, cw):
        try:
            sr, sw = await asyncio.open_connection(*self.target)
        except OSError:
            cw.close()
            return
        await asyncio.gather(self._pump(cr, sw), self._pump(sr, cw),
                             return_exceptions=True)

    async def stop(self):
        self.server.close()
        await self.server.wait_closed()


async def deliver(port, i):
    """One member delivery: fresh TLS connection + POST /inbox, like the app."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port, ssl=CTX)
    body = ENVELOPE.replace(b"bench-0000", f"bench-{i:04d}".encode())
    writer.write(
        b"POST /inbox HTTP/1.1\r\nHost: relay\r\n"
        b"Content-Type: application/json\r\n"
        + f"Content-Length: {len(body)}\r\n".encode()
        + b"Connection: close\r\n\r\n" + body
    )
    await writer.drain()
    await reader.read(65536)
    writer.close()
    try:
        await writer.wait_closed()
    except (ssl.SSLError, OSError):
        pass


async def run_serial(port, n, base):
    for i in range(n):
        await deliver(port, base + i)


async def run_bounded(port, n, base, limit):
    sem = asyncio.Semaphore(limit)

    async def one(i):
        async with sem:
            await deliver(port, base + i)

    await asyncio.gather(*(one(i) for i in range(n)))


async def main():
    host, target_port = sys.argv[1], int(sys.argv[2])
    print(f"{'members':>8} {'rtt':>6} {'serial':>10} {'bounded/6':>10} {'speedup':>8}")
    print("-" * 48)
    base = 0
    for rtt in RTTS_MS:
        proxy = DelayProxy(host, target_port, rtt)
        port = await proxy.start()
        for n in MEMBERS:
            # Best of 3 — one slow run should not decide a design question.
            serial, bounded = [], []
            for _ in range(3):
                t = time.perf_counter()
                await run_serial(port, n, base)
                serial.append(time.perf_counter() - t)
                base += n
                t = time.perf_counter()
                await run_bounded(port, n, base, CONCURRENCY)
                bounded.append(time.perf_counter() - t)
                base += n
            s, b = min(serial), min(bounded)
            print(f"{n:>8} {rtt:>4}ms {s*1000:>9.0f}ms {b*1000:>9.0f}ms "
                  f"{s/b:>7.1f}x")
        await proxy.stop()


if __name__ == "__main__":
    asyncio.run(main())
