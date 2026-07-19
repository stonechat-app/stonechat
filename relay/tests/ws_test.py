"""WS conformance: drain order, ack-delete (incl. blob), bad-token reject,
connection replacement. Usage: python ws_test.py <base_url>"""
import asyncio
import json
import ssl
import sys
import urllib.request

import websockets

BASE = sys.argv[1]
WS = BASE.replace("https", "wss") + "/ws?token=tok-secret"
TOKEN = "tok-secret"

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


def http(method, path, body=None):
    r = urllib.request.Request(BASE + path, method=method,
                               data=body if body is None or isinstance(body, bytes)
                               else json.dumps(body).encode())
    try:
        with urllib.request.urlopen(r, context=CTX, timeout=10) as resp:
            return resp.status, json.loads(resp.read() or b"null")
    except urllib.error.HTTPError as e:
        return e.code, None


async def main():
    ok = True

    # bad token → handshake rejected
    try:
        async with websockets.connect(WS + "WRONG", ssl=CTX, open_timeout=5):
            print("  FAIL bad-token: connected"); ok = False
    except Exception:
        print("  ok   bad-token rejected")

    # queue: one plain, one media envelope w/ real blob
    st, blob = http("POST", "/blob", b"cipherbytes")
    assert st == 200
    blob_id = blob["blob_id"]
    http("POST", "/inbox", {"v": 1, "id": "w-1", "to": "ZC-TEST-OWNER", "sealed": "YQ=="})
    http("POST", "/inbox", {"v": 1, "id": "w-2", "to": "ZC-TEST-OWNER",
                            "sealed": "Yg==", "blob_id": blob_id})

    async with websockets.connect(WS, ssl=CTX, open_timeout=5) as ws:
        drained = []
        # existing queue from the HTTP corpus (e-0001, e-0002) may drain first
        while True:
            env = json.loads(await asyncio.wait_for(ws.recv(), 5))
            drained.append(env["id"])
            await ws.send(json.dumps({"ack": env["id"]}))
            if env["id"] == "w-2":
                break
        pos = [d for d in drained if d.startswith("w-")]
        print(f"  {'ok  ' if pos == ['w-1', 'w-2'] else 'FAIL'} drain order: {drained}")
        ok = ok and pos == ["w-1", "w-2"]

        # malformed ack frames must be ignored silently
        await ws.send("garbage{")
        await ws.send(json.dumps({"ack": 42}))

        # live push while connected
        http("POST", "/inbox", {"v": 1, "id": "w-3", "to": "ZC-TEST-OWNER", "sealed": "Yw=="})
        env = json.loads(await asyncio.wait_for(ws.recv(), 5))
        print(f"  {'ok  ' if env['id'] == 'w-3' else 'FAIL'} live push: {env['id']}")
        ok = ok and env["id"] == "w-3"

        # transient while connected → delivered, not queued
        st, r = http("POST", "/inbox", {"v": 1, "id": "w-4", "to": "ZC-TEST-OWNER",
                                        "sealed": "ZA==", "transient": True})
        env = json.loads(await asyncio.wait_for(ws.recv(), 5))
        good = r == {"status": "delivered"} and env["id"] == "w-4"
        print(f"  {'ok  ' if good else 'FAIL'} transient live: {r}")
        ok = ok and good
        await ws.send(json.dumps({"ack": "w-3"}))

        # replacement: second connection closes the first with 4000
        ws2 = await websockets.connect(WS, ssl=CTX, open_timeout=5)
        try:
            await asyncio.wait_for(ws.recv(), 5)
            print("  FAIL replacement: first socket still open"); ok = False
        except websockets.ConnectionClosed as e:
            good = e.rcvd and e.rcvd.code == 4000
            print(f"  {'ok  ' if good else 'FAIL'} replacement close: "
                  f"{e.rcvd.code if e.rcvd else '?'} {e.rcvd.reason if e.rcvd else ''}")
            ok = ok and good
        await ws2.close()

    await asyncio.sleep(0.3)
    st, s = http("GET", f"/status?token={TOKEN}")
    # acked blob envelope must have deleted its blob
    st_blob, _ = http("GET", f"/blob/{blob_id}?token={TOKEN}")
    good = s["queued"] == 0 and st_blob == 404
    print(f"  {'ok  ' if good else 'FAIL'} after acks: queued={s['queued']}, blob GET={st_blob}")
    ok = ok and good

    print("PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)


asyncio.run(main())
