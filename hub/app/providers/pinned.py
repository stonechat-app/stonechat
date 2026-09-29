"""One HTTPS request to a box that self-signs, pinned by certificate fingerprint.

Mailbox hosts are not public web servers: there is no CA to check their
certificate against, so the fingerprint in the operator's config is the whole
trust anchor. What matters is *which connection* it is checked on. Observing
the certificate on one connection and then sending the request on another
checks nothing — whoever sits on the path passes the first through untouched
and answers the second themselves, and the second is the one carrying the admin
token.

So the check lives inside the connection: after the handshake, before a single
byte of the request is written. httpx offers no hook at that point, which is
why this is http.client.
"""

import base64
import hashlib
import http.client
import json
import socket
import ssl
from dataclasses import dataclass
from urllib.parse import urlsplit

from .base import ProviderError

INSECURE = "insecure"


def fingerprint(der: bytes) -> str:
    """BLAKE2b-256 of a DER certificate, base64 — the same function the
    mailbox host reports on /health and the app pins a mailbox with."""
    return base64.b64encode(hashlib.blake2b(der, digest_size=32).digest()).decode()


class PinMismatch(ProviderError):
    """The box answered with a certificate other than the pinned one."""


@dataclass
class PinnedResponse:
    status_code: int
    content: bytes

    @property
    def text(self) -> str:
        return self.content.decode("utf-8", "replace")

    def json(self):
        return json.loads(self.content)


class _PinnedConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, tls_fp: str, timeout: float):
        # The chain is not validated because there is none: a bare self-signed
        # leaf, on an address rather than a name. The fingerprint below is the
        # verification, not an addition to one.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        super().__init__(host, port, timeout=timeout, context=context)
        self._tls_fp = tls_fp

    def connect(self) -> None:
        super().connect()
        if self._tls_fp == INSECURE:
            return
        der = self.sock.getpeercert(binary_form=True)
        observed = fingerprint(der) if der else ""
        if observed != self._tls_fp:
            self.close()
            raise PinMismatch(
                "certificate does not match its pin (expected "
                f"{self._tls_fp[:12]}…, got {observed[:12] or 'none'}…); "
                "nothing was sent"
            )


def pinned_request(url: str, tls_fp: str, method: str, path: str, *,
                   headers: dict[str, str] | None = None,
                   json_body: dict | None = None,
                   content: bytes | None = None,
                   timeout: float) -> PinnedResponse:
    """`method path` against `url`, on a connection whose certificate hashes to
    `tls_fp`. Raises PinMismatch before anything is written if it does not, and
    ProviderError if the box cannot be reached.

    `tls_fp` may be the literal ``insecure`` (laptop dev), which skips the pin
    and says so in the config rather than in the code.
    """
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise ProviderError(f"{url!r} must be https:// — the admin token travels "
                            "on this connection")
    body = content
    sending = dict(headers or {})
    if json_body is not None:
        body = json.dumps(json_body).encode()
        sending["Content-Type"] = "application/json"
    conn = _PinnedConnection(parts.hostname, parts.port or 443, tls_fp, timeout)
    try:
        conn.request(method, path, body=body, headers=sending)
        resp = conn.getresponse()
        return PinnedResponse(resp.status, resp.read())
    except PinMismatch:
        raise
    except (OSError, http.client.HTTPException, socket.timeout) as e:
        raise ProviderError(f"unreachable: {e}") from e
    finally:
        conn.close()
