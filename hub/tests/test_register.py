"""POST /v1/register: proof of possession of the identity key."""

import base64
import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ["STONECHAT_HUB_DB"] = os.path.join(tempfile.mkdtemp(), "hub.db")

from fastapi.testclient import TestClient  # noqa: E402
from nacl.signing import SigningKey  # noqa: E402

from app.main import app  # noqa: E402


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def signed(identity: SigningKey, ts: int) -> str:
    return b64(identity.sign(b"stonechat-v1-register" + str(ts).encode()).signature)


class Register(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def register(self, identity, ts=None, signature=None, pubkey=None):
        ts = int(time.time()) if ts is None else ts
        return self.client.post("/v1/register", json={
            "pubkey": pubkey or b64(bytes(identity.verify_key)),
            "timestamp": ts,
            "signature": signature or signed(identity, ts),
        })

    def test_signed_registration_succeeds_once(self):
        identity = SigningKey.generate()
        r = self.register(identity)
        self.assertEqual(r.status_code, 201, r.text)
        self.assertTrue(r.json()["stonechat_id"].startswith("SC-"))
        self.assertEqual(self.register(identity).status_code, 409)

    def test_directory_record_carries_no_identity_kem_key(self):
        identity = SigningKey.generate()
        sid = self.register(identity).json()["stonechat_id"]
        entry = self.client.get(f"/v1/directory/{sid}").json()
        self.assertEqual(entry["pubkey"], b64(bytes(identity.verify_key)))
        self.assertNotIn("pq_pk", entry)
        self.assertNotIn("pq_sig", entry)

    def test_rejects_signature_by_another_key(self):
        victim, attacker = SigningKey.generate(), SigningKey.generate()
        ts = int(time.time())
        r = self.register(victim, ts=ts, signature=signed(attacker, ts))
        self.assertEqual(r.status_code, 401)

    def test_rejects_stale_timestamp(self):
        identity = SigningKey.generate()
        r = self.register(identity, ts=int(time.time()) - 600)
        self.assertEqual(r.status_code, 400)

    def test_rejects_signature_over_a_different_timestamp(self):
        identity = SigningKey.generate()
        ts = int(time.time())
        r = self.register(identity, ts=ts, signature=signed(identity, ts - 1))
        self.assertEqual(r.status_code, 401)


if __name__ == "__main__":
    unittest.main()
