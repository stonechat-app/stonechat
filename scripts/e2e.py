"""End-to-end test of the Zeon stack, no Flutter needed.

Simulates two phones (Alice, Bob) with PyNaCl (same libsodium primitives the
app uses): register → provision local-Docker relays → contact handshake →
message → ack → verify the relay queue is empty → destroy relays.
"""

import asyncio
import base64
import json
import sys
import time
import uuid
from datetime import datetime, timezone

import httpx
import websockets
from nacl.public import Box, PrivateKey, PublicKey
from nacl.secret import SecretBox
from nacl.utils import random as nacl_random

import os
CP = os.environ.get("ZEON_CP", "http://127.0.0.1:8477")

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1] / "control-plane"))
from app.identity import zeon_id_from_pubkey  # noqa: E402


class Phone:
    def __init__(self, name):
        self.name = name
        self.key = PrivateKey.generate()
        self.pubkey_b64 = base64.b64encode(bytes(self.key.public_key)).decode()
        self.zeon_id = None
        self.token = None
        self.server = None

    def register(self):
        r = httpx.post(f"{CP}/v1/register", json={"pubkey": self.pubkey_b64})
        r.raise_for_status()
        data = r.json()
        self.zeon_id, self.token = data["zeon_id"], data["account_token"]
        self.handle = data["handle"]
        expected = zeon_id_from_pubkey(bytes(self.key.public_key))
        assert self.zeon_id == expected, "server-derived ID != client-derived ID"
        assert self.handle.startswith("zn-"), f"bad handle: {self.handle}"
        print(f"  {self.name}: {self.zeon_id} ({self.handle})")

    @property
    def auth(self):
        return {"Authorization": f"Bearer {self.token}"}

    def provision(self):
        r = httpx.post(
            f"{CP}/v1/server",
            headers=self.auth,
            json={
                "provider": "local",
                "machine": {"machine_type": "container", "region": "localhost"},
            },
        )
        r.raise_for_status()

    def wait_running(self, timeout=300):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            r = httpx.get(f"{CP}/v1/server", headers=self.auth)
            r.raise_for_status()
            s = r.json()
            if s["status"] == "running":
                self.server = s
                print(f"  {self.name} relay: {s['address']}")
                return
            if s["status"] == "error":
                raise RuntimeError(f"provisioning failed: {s['error']}")
            time.sleep(2)
        raise TimeoutError("relay never became running")

    def seal(self, to: "Phone", type_: str, payload: dict, envelope_id=None) -> dict:
        box = Box(self.key, PublicKey(bytes(to.key.public_key)))
        sealed = box.encrypt(json.dumps(payload).encode())
        return {
            "v": 1,
            "id": envelope_id or str(uuid.uuid4()),
            "type": type_,
            "from": self.zeon_id,
            "to": to.zeon_id,
            "sent_at": datetime.now(timezone.utc).isoformat(),
            "nonce": base64.b64encode(sealed.nonce).decode(),
            "ciphertext": base64.b64encode(sealed.ciphertext).decode(),
        }

    def open_envelope(self, envelope: dict, sender: "Phone") -> dict:
        box = Box(self.key, PublicKey(bytes(sender.key.public_key)))
        plain = box.decrypt(
            base64.b64decode(envelope["ciphertext"]),
            base64.b64decode(envelope["nonce"]),
        )
        return json.loads(plain)

    def deliver_to(self, to: "Phone", envelope: dict):
        r = httpx.post(f"{to.server['address']}/inbox", json=envelope, timeout=10)
        r.raise_for_status()

    async def receive_one(self, timeout=15, process=None) -> dict:
        """Receive one envelope, run `process(envelope)` BEFORE acking (the
        app does the same: persist/download first, ack last), then ack."""
        url = self.server["address"].replace("http", "ws") + f"/ws?token={self.server['server_token']}"
        async with websockets.connect(url) as ws:
            raw = await asyncio.wait_for(ws.recv(), timeout)
            envelope = json.loads(raw)
            if process:
                process(envelope)
            await ws.send(json.dumps({"ack": envelope["id"]}))
            await asyncio.sleep(0.3)  # let the ack land before closing
            return envelope

    def queue_depth(self):
        return httpx.get(f"{self.server['address']}/health").json()["queued"]

    def destroy(self):
        r = httpx.delete(f"{CP}/v1/server", headers=self.auth, timeout=30)
        r.raise_for_status()


def main():
    alice, bob = Phone("alice"), Phone("bob")

    print("1) register")
    alice.register()
    bob.register()

    print("2) directory lookup + commitment check")
    entry = httpx.get(f"{CP}/v1/directory/{bob.zeon_id}").json()
    assert entry["pubkey"] == bob.pubkey_b64
    assert zeon_id_from_pubkey(base64.b64decode(entry["pubkey"])) == bob.zeon_id
    assert entry["server"] is None
    lower = bob.zeon_id.lower().replace("-", "")
    assert httpx.get(f"{CP}/v1/directory/{lower}").status_code == 200, "sloppy input should normalize"

    print("2b) handle lookup resolves to the same record")
    by_handle = httpx.get(f"{CP}/v1/directory/{bob.handle.upper()}").json()
    assert by_handle["zeon_id"] == bob.zeon_id
    assert by_handle["pubkey"] == bob.pubkey_b64
    assert by_handle["handle"] == bob.handle
    assert httpx.get(f"{CP}/v1/directory/zn-no-such-handle").status_code == 404

    print("3) provision relays (local docker)")
    alice.provision()
    bob.provision()
    alice.wait_running()
    bob.wait_running()

    print("3b) fleet provider: container-per-user on a shared host")
    carol = Phone("carol")
    carol.register()
    r = httpx.post(
        f"{CP}/v1/server", headers=carol.auth,
        json={"provider": "fleet",
              "machine": {"machine_type": "container", "region": "fleet"}},
    )
    r.raise_for_status()
    carol.wait_running()
    health = httpx.get(f"{carol.server['address']}/health").json()
    assert health["owner"] == carol.zeon_id
    carol.destroy()
    assert httpx.get(f"{CP}/v1/server", headers=carol.auth).json()["status"] == "none"

    print("4) one-server-per-user enforced")
    r = httpx.post(
        f"{CP}/v1/server", headers=alice.auth,
        json={"provider": "local", "machine": {"machine_type": "x", "region": "y"}},
    )
    assert r.status_code == 409, f"expected 409, got {r.status_code}"

    print("5) contact handshake")
    alice.deliver_to(bob, alice.seal(bob, "contact_request", {"display_name": "Alice"}))
    req = asyncio.run(bob.receive_one())
    assert req["type"] == "contact_request"
    assert bob.open_envelope(req, alice) == {"display_name": "Alice"}

    bob.deliver_to(alice, bob.seal(alice, "contact_accept", {"display_name": "Bob"}))
    acc = asyncio.run(alice.receive_one())
    assert alice.open_envelope(acc, bob) == {"display_name": "Bob"}

    print("6) message + delete-on-ack")
    alice.deliver_to(bob, alice.seal(bob, "msg", {"text": "hello from my own relay"}))
    msg = asyncio.run(bob.receive_one())
    assert bob.open_envelope(msg, alice) == {"text": "hello from my own relay"}
    time.sleep(0.5)
    assert bob.queue_depth() == 0, "envelope should be deleted after ack"

    print("6b) media blob: upload → envelope → download → decrypt → ack-deletes")
    photo = nacl_random(200_000)  # stand-in for an encrypted JPEG
    blob_key, blob_nonce = nacl_random(32), nacl_random(24)
    sealed_blob = SecretBox(blob_key).encrypt(photo, blob_nonce).ciphertext
    r = httpx.post(f"{bob.server['address']}/blob", content=sealed_blob, timeout=30)
    r.raise_for_status()
    blob_id = r.json()["blob_id"]

    media_env = alice.seal(bob, "media", {
        "blob_id": blob_id,
        "key": base64.b64encode(blob_key).decode(),
        "blob_nonce": base64.b64encode(blob_nonce).decode(),
        "mime": "image/jpeg", "kind": "image", "size": len(photo),
    })
    media_env["blob_id"] = blob_id
    alice.deliver_to(bob, media_env)

    recovered_holder = {}

    def fetch_and_decrypt(envelope):
        payload = bob.open_envelope(envelope, alice)
        dl = httpx.get(
            f"{bob.server['address']}/blob/{payload['blob_id']}",
            params={"token": bob.server["server_token"]}, timeout=30,
        )
        dl.raise_for_status()
        recovered_holder["data"] = SecretBox(
            base64.b64decode(payload["key"])
        ).decrypt(dl.content, base64.b64decode(payload["blob_nonce"]))

    asyncio.run(bob.receive_one(process=fetch_and_decrypt))
    assert recovered_holder["data"] == photo, "media round-trip corrupted"
    # unauthenticated download must fail; after ack the blob must be gone
    assert httpx.get(f"{bob.server['address']}/blob/{blob_id}").status_code == 401
    time.sleep(0.5)
    gone = httpx.get(f"{bob.server['address']}/blob/{blob_id}",
                     params={"token": bob.server["server_token"]})
    assert gone.status_code == 404, "blob should be deleted after ack"

    print("7) wrong recipient rejected by mailbox")
    r = httpx.post(
        f"{bob.server['address']}/inbox",
        json=alice.seal(alice, "msg", {"text": "misrouted"}),
    )
    assert r.status_code == 403, f"expected 403, got {r.status_code}"

    print("8) offline queueing (no ws connected)")
    alice.deliver_to(bob, alice.seal(bob, "msg", {"text": "while you were out"}))
    assert bob.queue_depth() == 1
    queued = asyncio.run(bob.receive_one())  # drains on connect
    assert bob.open_envelope(queued, alice)["text"] == "while you were out"
    time.sleep(0.5)
    assert bob.queue_depth() == 0

    push_gateway = os.environ.get("ZEON_TEST_PUSH_GATEWAY")
    if push_gateway:
        print("8b) offline owner triggers a content-free gateway ping")
        r = httpx.post(
            f"{bob.server['address']}/push-config",
            params={"token": bob.server["server_token"]},
            json={"device_token": "e2e-test-token-bob", "platform": "ios"},
        )
        r.raise_for_status()
        alice.deliver_to(bob, alice.seal(bob, "msg", {"text": "wake up"}))
        deadline = time.monotonic() + 10
        seen = False
        while time.monotonic() < deadline and not seen:
            pings = httpx.get(f"{push_gateway}/v1/debug/pings").json()
            seen = any(p["device_token"] == "e2e-test-token-bob" for p in pings)
            time.sleep(0.5)
        assert seen, "gateway never received the wake-up ping"
        asyncio.run(bob.receive_one())  # drain before teardown

    print("9) destroy relays")
    alice.destroy()
    bob.destroy()
    assert httpx.get(f"{CP}/v1/server", headers=alice.auth).json()["status"] == "none"
    entry = httpx.get(f"{CP}/v1/directory/{bob.zeon_id}").json()
    assert entry["server"] is None

    print("\nALL E2E CHECKS PASSED")


if __name__ == "__main__":
    main()
