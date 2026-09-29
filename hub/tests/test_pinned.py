"""The pin is checked on the connection that carries the token.

Regression: the fingerprint used to be observed on one connection and the
request sent on another, so anyone on the path could pass the first through and
answer the second — the one with the admin token on it.

    cd hub && .venv/bin/python -m unittest discover -s tests -v

Needs the `openssl` CLI to mint test certificates; skipped without it.
"""

import http.server
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.providers.base import ProviderError  # noqa: E402
from app.providers.mailbox_host import MailboxHost, MailboxHostProvider  # noqa: E402
from app.providers.pinned import (  # noqa: E402
    INSECURE, PinMismatch, fingerprint, pinned_request,
)


def _mint(directory: Path, name: str) -> tuple[Path, Path, str]:
    key, cert = directory / f"{name}.key", directory / f"{name}.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "ec",
         "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
         "-keyout", str(key), "-out", str(cert), "-days", "2",
         "-subj", f"/CN={name}"],
        check=True, capture_output=True)
    der = ssl.PEM_cert_to_DER_cert(cert.read_text())
    return key, cert, fingerprint(der)


class _Server:
    """An HTTPS server that records what reached it, and can present a
    different certificate to each connection it accepts."""

    def __init__(self, certs: list[tuple[Path, Path]]):
        self.requests: list[tuple[str, str, str | None]] = []
        self.connections = 0
        contexts = []
        for key, cert in certs:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert, key)
            contexts.append(ctx)
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def _answer(self):
                length = int(self.headers.get("Content-Length") or 0)
                self.rfile.read(length)
                outer.requests.append(
                    (self.command, self.path, self.headers.get("Authorization")))
                body = b'{"count": 1, "capacity": 4}'
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_GET = do_POST = do_DELETE = _answer

            def log_message(self, *a):
                pass

        class Httpd(http.server.ThreadingHTTPServer):
            def get_request(self):
                sock, addr = super().get_request()
                ctx = contexts[min(outer.connections, len(contexts) - 1)]
                outer.connections += 1
                try:
                    return ctx.wrap_socket(sock, server_side=True), addr
                except (ssl.SSLError, OSError):
                    sock.close()
                    raise OSError("handshake failed")

        self.httpd = Httpd(("127.0.0.1", 0), Handler)
        self.url = f"https://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@unittest.skipUnless(shutil.which("openssl"), "openssl unavailable")
class PinnedRequest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = Path(tempfile.mkdtemp(prefix="stonechat-pin-"))
        cls.host_key, cls.host_cert, cls.host_fp = _mint(cls.dir, "host")
        cls.evil_key, cls.evil_cert, cls.evil_fp = _mint(cls.dir, "evil")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.dir, ignore_errors=True)

    def serve(self, *certs):
        server = _Server(list(certs))
        self.addCleanup(server.close)
        return server

    def test_the_pinned_certificate_is_accepted(self):
        s = self.serve((self.host_key, self.host_cert))
        r = pinned_request(s.url, self.host_fp, "GET", "/v1/guests",
                           headers={"Authorization": "Bearer SECRET"}, timeout=5)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["capacity"], 4)
        self.assertEqual(s.requests, [("GET", "/v1/guests", "Bearer SECRET")])

    def test_another_certificate_is_refused_and_nothing_is_sent(self):
        s = self.serve((self.evil_key, self.evil_cert))
        with self.assertRaises(PinMismatch):
            pinned_request(s.url, self.host_fp, "POST", "/v1/guest",
                           headers={"Authorization": "Bearer SECRET"},
                           json_body={"owner_token": "ALSO-SECRET"}, timeout=5)
        self.assertEqual(s.requests, [], "the token must not have been sent")

    def test_the_request_rides_the_connection_that_was_checked(self):
        # The attack: show the real certificate to the first connection and
        # answer every later one yourself. Checking on one connection and
        # sending on the next hands the second the token.
        s = self.serve((self.host_key, self.host_cert),
                       (self.evil_key, self.evil_cert))
        first = pinned_request(s.url, self.host_fp, "GET", "/v1/guests",
                               headers={"Authorization": "Bearer SECRET"}, timeout=5)
        self.assertEqual(first.status_code, 200)
        self.assertEqual(s.connections, 1, "one request, one connection")
        with self.assertRaises(PinMismatch):
            pinned_request(s.url, self.host_fp, "GET", "/v1/guests",
                           headers={"Authorization": "Bearer SECRET"}, timeout=5)
        self.assertEqual(len(s.requests), 1, "the second token must not have been sent")

    def test_the_provider_sends_its_token_only_to_the_pinned_host(self):
        s = self.serve((self.host_key, self.host_cert),
                       (self.evil_key, self.evil_cert))
        provider = MailboxHostProvider.__new__(MailboxHostProvider)
        host = MailboxHost("de1", s.url, "DE", "ADMIN-TOKEN", self.host_fp)
        provider.hosts = [host]
        self.assertEqual(provider._occupancy(host), (1, 4))
        with self.assertRaises(ProviderError) as refused:
            provider._occupancy(host)
        self.assertIn("refusing to send it an admin token", str(refused.exception))
        self.assertEqual([a for _, _, a in s.requests], ["Bearer ADMIN-TOKEN"])

    def test_insecure_is_explicit_and_skips_the_pin(self):
        s = self.serve((self.evil_key, self.evil_cert))
        r = pinned_request(s.url, INSECURE, "GET", "/v1/guests", timeout=5)
        self.assertEqual(r.status_code, 200)

    def test_plain_http_is_refused(self):
        with self.assertRaises(ProviderError):
            pinned_request("http://127.0.0.1:1", self.host_fp, "GET", "/", timeout=1)

    def test_an_unreachable_host_is_a_provider_error(self):
        with self.assertRaises(ProviderError):
            pinned_request("https://127.0.0.1:1", self.host_fp, "GET", "/", timeout=1)


if __name__ == "__main__":
    unittest.main()
