"""The signed device manifest (PROTOCOL.md "Device manifest"): the hub checks
the signature and the version on the way in, and serves the manifest verbatim
in the directory record."""

import base64
import time
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ["STONECHAT_HUB_DB"] = os.path.join(tempfile.mkdtemp(), "hub.db")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient  # noqa: E402
from nacl.signing import SigningKey  # noqa: E402

from app.main import _devices_signing_bytes, app  # noqa: E402

def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


class Devices(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.identity = SigningKey.generate()
        now = int(time.time())
        r = cls.client.post("/v1/register", json={
            "pubkey": b64(bytes(cls.identity.verify_key)),
            "timestamp": now,
            "signature": b64(cls.identity.sign(b"stonechat-v1-register" + str(now).encode()).signature),
        })
        assert r.status_code == 201, r.text
        cls.stonechat_id = r.json()["stonechat_id"]
        cls.auth = {"Authorization": f"Bearer {r.json()['account_token']}"}

    def manifest(self, version, devices=((1, bytes(32)),), signer=None, stonechat_id=None):
        m = {
            "stonechat_id": stonechat_id or self.stonechat_id,
            "version": version,
            "issued_at": 1_790_000_000,
            "devices": [{"device_id": i, "sig_pub": b64(k)} for i, k in devices],
        }
        sig = (signer or self.identity).sign(
            b"stonechat-v1-devices" + _devices_signing_bytes(m)).signature
        return {**m, "sig": b64(sig)}

    def test_publish_serve_and_supersede(self):
        r = self.client.post("/v1/devices", json=self.manifest(1), headers=self.auth)
        self.assertEqual(r.status_code, 200, r.text)
        served = self.client.get(f"/v1/directory/{self.stonechat_id}").json()["devices"]
        self.assertEqual(served["version"], 1)
        self.assertEqual(served["devices"][0]["device_id"], 1)
        self.assertIn("sig", served)

        two = self.manifest(2, devices=((1, bytes(32)), (3, bytes([3]) * 32)))
        self.assertEqual(self.client.post("/v1/devices", json=two, headers=self.auth).status_code, 200)
        served = self.client.get(f"/v1/directory/{self.stonechat_id}").json()["devices"]
        self.assertEqual(served, two, "served exactly as published")

        # Not newer: a replay, or a restored device that is behind.
        r = self.client.post("/v1/devices", json=self.manifest(2), headers=self.auth)
        self.assertEqual(r.status_code, 409)
        self.assertEqual(r.json()["detail"]["current"], 2)
        r = self.client.post("/v1/devices", json=self.manifest(1), headers=self.auth)
        self.assertEqual(r.status_code, 409)

    def test_refusals(self):
        other = SigningKey.generate()
        cases = {
            "another identity's signature": self.manifest(9, signer=other),
            "names another identity": self.manifest(9, stonechat_id="SC-SOMEONE-ELSE"),
            "a device twice": self.manifest(9, devices=((1, bytes(32)), (1, bytes(32)))),
            "a short key": self.manifest(9, devices=((1, bytes(31)),)),
        }
        for name, body in cases.items():
            r = self.client.post("/v1/devices", json=body, headers=self.auth)
            self.assertEqual(r.status_code, 400, name)
        empty = self.manifest(9, devices=())
        self.assertEqual(self.client.post("/v1/devices", json=empty, headers=self.auth).status_code, 422)
        self.assertEqual(self.client.post("/v1/devices", json=self.manifest(9)).status_code, 401)

    def test_tampering_after_signing_is_caught(self):
        m = self.manifest(9, devices=((1, bytes(32)), (2, bytes([2]) * 32)))
        m["devices"].pop()  # truncate: the count is signed
        self.assertEqual(self.client.post("/v1/devices", json=m, headers=self.auth).status_code, 400)
        m = self.manifest(9)
        m["issued_at"] += 1
        self.assertEqual(self.client.post("/v1/devices", json=m, headers=self.auth).status_code, 400)


if __name__ == "__main__":
    unittest.main()
