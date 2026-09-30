"""The mailbox host's admin door, and what an upload is held to.

Regression: an empty STONECHAT_MAILBOX_HOST_ADMIN_TOKEN — which is what
.env.example ships — started fine, and every request with no Authorization
header then presented exactly that token.

    hub/.venv/bin/python -m unittest discover -s mailbox_host/tests -v

main.py reads its configuration at import and mints a TLS certificate, so each
case imports it fresh into a temp state directory. Needs the `openssl` CLI.
"""

import importlib.util
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]

ADMIN = "an-admin-token-of-reasonable-length"
ELF = b"\x7fELF" + b"relay" * 64


def load(state: Path, **env: str):
    """mailbox_host/main.py, imported under `env` with its state in `state`."""
    base = {
        "STONECHAT_MAILBOX_HOST_ADMIN_TOKEN": ADMIN,
        "STONECHAT_MAILBOX_HOST_ADVERTISE_HOST": "127.0.0.1",
        "STONECHAT_MAILBOX_HOST_MANAGED": "1",
        "STONECHAT_MAILBOX_HOST_DB": str(state / "mailbox_host.db"),
        "STONECHAT_MAILBOX_HOST_TLS_DIR": str(state),
        "STONECHAT_MAILBOX_HOST_RELAY_DIR": str(state),
        "STONECHAT_MAILBOX_HOST_IMAGE": "stonechat-relay@sha256:" + "0" * 64,
    }
    base.update(env)
    clean = {k: v for k, v in os.environ.items() if not k.startswith("STONECHAT_")}
    with mock.patch.dict(os.environ, {**clean, **base}, clear=True):
        spec = importlib.util.spec_from_file_location(
            "mailbox_host_under_test", ROOT / "mailbox_host" / "main.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    return module


@unittest.skipUnless(shutil.which("openssl"), "openssl unavailable")
class Case(unittest.TestCase):
    def setUp(self):
        self.state = Path(tempfile.mkdtemp(prefix="stonechat-host-test-"))
        self.addCleanup(shutil.rmtree, self.state, ignore_errors=True)

    def host(self, **env):
        module = load(self.state, **env)
        # Wrapping the binary in an image is Docker's job and not what is under
        # test; what is, is whether the upload got that far.
        self.built = []
        module._build_relay_image = lambda path, build: self.built.append(build)
        return module, TestClient(module.app)


class AdminToken(Case):
    def test_an_empty_token_refuses_to_start(self):
        for value in ("", "   "):
            with self.assertRaises(SystemExit) as stop:
                load(self.state, STONECHAT_MAILBOX_HOST_ADMIN_TOKEN=value)
            self.assertIn("STONECHAT_MAILBOX_HOST_ADMIN_TOKEN", str(stop.exception))

    def test_a_short_token_refuses_to_start(self):
        with self.assertRaises(SystemExit):
            load(self.state, STONECHAT_MAILBOX_HOST_ADMIN_TOKEN="changeme")

    def test_no_advertise_host_refuses_to_start(self):
        with self.assertRaises(SystemExit):
            load(self.state, STONECHAT_MAILBOX_HOST_ADVERTISE_HOST="")

    def test_the_example_env_file_does_not_start_a_host(self):
        # The file people copy. Whatever it ships must not be a working config.
        env = {}
        for line in (ROOT / "mailbox_host" / ".env.example").read_text().splitlines():
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                env[key] = value
        with self.assertRaises(SystemExit):
            load(self.state, **env)

    def test_only_the_token_opens_an_admin_route(self):
        _, client = self.host()
        self.assertEqual(client.get("/v1/guests").status_code, 401)
        for presented in ("", "Bearer", "Bearer ", "Bearer wrong", "Bearer " + ADMIN[:-1],
                          ADMIN[:-1]):
            r = client.get("/v1/guests", headers={"Authorization": presented})
            self.assertEqual(r.status_code, 401, presented)
        ok = client.get("/v1/guests", headers={"Authorization": f"Bearer {ADMIN}"})
        self.assertEqual(ok.status_code, 200)

    def test_a_token_that_is_not_ascii_is_a_401_not_a_500(self):
        _, client = self.host()
        r = client.get("/v1/guests",
                       headers={"Authorization": "Bearer tøken".encode("latin-1")})
        self.assertEqual(r.status_code, 401)


class RelayUpload(Case):
    def setUp(self):
        super().setUp()
        self.auth = {"Authorization": f"Bearer {ADMIN}",
                     "Content-Type": "application/octet-stream"}

    def upload(self, client, data=ELF):
        return client.post("/v1/relay", content=data, headers=self.auth)

    def installed(self):
        return sorted(p.name for p in self.state.glob("stonechat-relay-*"))

    def test_an_upload_is_installed(self):
        _, client = self.host()
        r = self.upload(client)
        self.assertEqual(r.status_code, 200, r.text)
        build = r.json()["build"]
        self.assertEqual(self.built, [build])
        self.assertEqual(self.installed(), [f"stonechat-relay-{build}"])

    def test_the_upload_is_admin_only(self):
        _, client = self.host()
        r = client.post("/v1/relay", content=ELF,
                        headers={"Content-Type": "application/octet-stream"})
        self.assertEqual(r.status_code, 401)
        self.assertEqual(self.installed(), [])

    def test_a_binary_changed_on_disk_is_not_rolled(self):
        _, client = self.host()
        build = self.upload(client).json()["build"]
        roll = {"Authorization": f"Bearer {ADMIN}"}
        self.assertEqual(
            client.post("/v1/relay/roll", json={"dry_run": True}, headers=roll).status_code,
            200)
        (self.state / f"stonechat-relay-{build}").write_bytes(ELF + b"tampered")
        r = client.post("/v1/relay/roll", json={"dry_run": True}, headers=roll)
        self.assertEqual(r.status_code, 409, r.text)

    def test_an_oversized_upload_is_cut_off(self):
        module, client = self.host()
        module.MAX_RELAY_BYTES = 1024
        self.assertEqual(self.upload(client, data=ELF + b"x" * 2048).status_code, 413)


if __name__ == "__main__":
    unittest.main()
