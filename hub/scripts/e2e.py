"""End-to-end test of the Stonechat stack, no Flutter needed.

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

import os
HUB = os.environ.get("STONECHAT_HUB", "http://127.0.0.1:8477")

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1] / "hub"))
from app.identity import stonechat_id_from_pubkey  # noqa: E402


class Phone:
    def __init__(self, name):
        self.name = name
        self.key = PrivateKey.generate()
        self.pubkey_b64 = base64.b64encode(bytes(self.key.public_key)).decode()
        self.stonechat_id = None
        self.token = None
        self.mailbox = None

    def register(self):
        r = httpx.post(f"{HUB}/v1/register", json={"pubkey": self.pubkey_b64})
        r.raise_for_status()
        data = r.json()
        self.stonechat_id, self.token = data["stonechat_id"], data["account_token"]
        expected = stonechat_id_from_pubkey(bytes(self.key.public_key))
        assert self.stonechat_id == expected, "mailbox-derived ID != client-derived ID"
        print(f"  {self.name}: {self.stonechat_id}")

    @property
    def auth(self):
        return {"Authorization": f"Bearer {self.token}"}

    def provision(self):
        r = httpx.post(
            f"{HUB}/v1/mailbox",
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
            r = httpx.get(f"{HUB}/v1/mailbox", headers=self.auth)
            r.raise_for_status()
            s = r.json()
            if s["status"] == "running":
                self.mailbox = s
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
            "from": self.stonechat_id,
            "to": to.stonechat_id,
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
        r = httpx.post(f"{to.mailbox['address']}/inbox", json=envelope, timeout=10)
        r.raise_for_status()

    async def receive_one(self, timeout=15) -> dict:
        url = self.mailbox["address"].replace("http", "ws") + f"/ws?token={self.mailbox['mailbox_token']}"
        async with websockets.connect(url) as ws:
            raw = await asyncio.wait_for(ws.recv(), timeout)
            envelope = json.loads(raw)
            await ws.send(json.dumps({"ack": envelope["id"]}))
            await asyncio.sleep(0.3)  # let the ack land before closing
            return envelope

    def queue_depth(self):
        return httpx.get(f"{self.mailbox['address']}/status",
                         params={"token": self.mailbox["mailbox_token"]}).json()["queued"]

    def destroy(self):
        r = httpx.delete(f"{HUB}/v1/mailbox", headers=self.auth, timeout=30)
        r.raise_for_status()


def main():
    alice, bob = Phone("alice"), Phone("bob")

    print("1) register")
    alice.register()
    bob.register()

    print("2) directory lookup + commitment check")
    entry = httpx.get(f"{HUB}/v1/directory/{bob.stonechat_id}").json()
    assert entry["pubkey"] == bob.pubkey_b64
    assert stonechat_id_from_pubkey(base64.b64decode(entry["pubkey"])) == bob.stonechat_id
    assert entry["mailbox"] is None
    lower = bob.stonechat_id.lower().replace("-", "")
    assert httpx.get(f"{HUB}/v1/directory/{lower}").status_code == 200, "sloppy input should normalize"
    assert "handle" not in entry, "directory must not return a handle"
    assert httpx.get(f"{HUB}/v1/directory/zn-palm-dog-cherry").status_code == 400, \
        "handle-form lookups must be rejected, not resolved"

    print("3) provision relays (local docker)")
    alice.provision()
    bob.provision()
    alice.wait_running()
    bob.wait_running()

    print("4) one-mailbox-per-user enforced")
    r = httpx.post(
        f"{HUB}/v1/mailbox", headers=alice.auth,
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

    print("7) wrong recipient rejected by mailbox")
    r = httpx.post(
        f"{bob.mailbox['address']}/inbox",
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

    print("9) destroy relays")
    alice.destroy()
    bob.destroy()
    assert httpx.get(f"{HUB}/v1/mailbox", headers=alice.auth).json()["status"] == "none"
    entry = httpx.get(f"{HUB}/v1/directory/{bob.stonechat_id}").json()
    assert entry["mailbox"] is None

    print("\nALL E2E CHECKS PASSED")


if __name__ == "__main__":
    main()
