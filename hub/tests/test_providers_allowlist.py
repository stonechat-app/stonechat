"""STONECHAT_PROVIDERS: which providers a request may land on, and the
machine shapes the explicit provider+machine form is held to."""

import base64
import time
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ["STONECHAT_HUB_DB"] = os.path.join(tempfile.mkdtemp(), "hub.db")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient  # noqa: E402
from nacl.signing import SigningKey  # noqa: E402

from app import countries  # noqa: E402
from app.main import app, enabled_providers  # noqa: E402

def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


class Allowlist(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        identity = SigningKey.generate()
        now = int(time.time())
        r = cls.client.post("/v1/register", json={
            "pubkey": b64(bytes(identity.verify_key)),
            "timestamp": now,
            "signature": b64(identity.sign(b"stonechat-v1-register" + str(now).encode()).signature),
        })
        assert r.status_code == 201, r.text
        cls.auth = {"Authorization": f"Bearer {r.json()['account_token']}"}

    def create(self, **body):
        return self.client.post("/v1/mailbox", json=body, headers=self.auth)

    def test_unset_means_every_registered_provider(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("STONECHAT_PROVIDERS", None)
            self.assertIn("local", enabled_providers())
            self.assertIn("gcp", enabled_providers())

    def test_set_narrows_and_ignores_unknown_names(self):
        with mock.patch.dict(os.environ, {"STONECHAT_PROVIDERS": " mailbox_host, gcp ,nope"}):
            self.assertEqual(enabled_providers(), ["gcp", "mailbox_host"])
            self.assertEqual(self.client.get("/health").json()["providers"],
                             ["gcp", "mailbox_host"])

    def test_a_client_cannot_name_a_provider_the_hub_does_not_run(self):
        # The hosted hub's case: a debug build defaulting to `local` must be
        # told no, not make the hub try Docker on itself.
        with mock.patch.dict(os.environ, {"STONECHAT_PROVIDERS": "mailbox_host,gcp"}):
            r = self.create(provider="local",
                            machine={"machine_type": "container", "region": "localhost"})
        self.assertEqual(r.status_code, 400, r.text)
        self.assertEqual(r.json()["detail"]["code"], "provider_unavailable")

    def test_no_entitlement_is_answered_before_availability(self):
        # The hosted hub again: an account with no code picks a country,
        # resolves to the dedicated plan, and must hear "redeem a code" — the
        # 402 the app turns into the invite sheet — not that gcp is off here.
        from app import gate, main
        with mock.patch.dict(os.environ, {"STONECHAT_PROVIDERS": "mailbox_host"}), \
                mock.patch.object(gate, "GATED", True), \
                mock.patch.object(main, "GATED_PROVIDERS",
                                  {"mailbox_host": "mailbox", "gcp": "machine"}), \
                mock.patch.object(gate, "access", return_value={"tier": None}), \
                mock.patch.object(main, "shared_host_countries", return_value=set()):
            r = self.create(country="DE")
        self.assertEqual(r.status_code, 402, r.text)
        self.assertEqual(r.json()["detail"]["code"], "access_required")

    def test_the_explicit_form_is_held_to_catalog_shapes(self):
        with mock.patch.dict(os.environ, {"STONECHAT_PROVIDERS": "gcp"}):
            r = self.create(provider="gcp",
                            machine={"machine_type": "n2-highmem-96",
                                     "region": "us-central1-a"})
        self.assertEqual(r.status_code, 400, r.text)
        self.assertEqual(r.json()["detail"]["code"], "machine_unavailable")

    def test_catalog_shapes_are_what_resolve_hands_out(self):
        for c in countries.CATALOG:
            provider, machine = countries.resolve(c.code, "machine")
            self.assertIn((machine["region"], machine["machine_type"]),
                          countries.known_shapes(provider))
        self.assertEqual(countries.known_shapes("nope"), set())


if __name__ == "__main__":
    unittest.main()
