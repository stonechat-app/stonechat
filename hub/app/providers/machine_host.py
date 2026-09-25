"""Machine-host provider — the shared-host tier.

One mailbox container per customer, packed onto a pool of boxes the hub
operator runs. Each box runs the **machine host** (machine_host/main.py) in
managed mode, and this provider places mailboxes on it over that HTTPS API:
``POST /v1/guest`` to create, ``DELETE /v1/guest/{owner_id}`` to destroy,
``GET /v1/guests`` to see how full it is. Placement is least-loaded **within
the requested country**.

This replaced the `fleet` provider, which ran `docker -H ssh://…` against a
bare daemon on each host. Same containers in the end, but the authority is
different, and that was the point: the hub held a key into the `docker` group
on every mailbox host, which is root there in all but name, so a compromised
hub owned the whole fleet. Now it holds a bearer token for an API that can do
four things, none of them "run this container".

Host pool config (env, REQUIRED)::

    STONECHAT_MACHINE_HOSTS="berlin=https://10.0.0.5:8200|DE|<admin token>|<tls fp>"

Comma-separated ``name=url|COUNTRY|admin_token|tls_fp``, where:

* **COUNTRY** is an ISO 3166-1 alpha-2 code, required and never defaulted. It
  is both where mailboxes land and the country list the Mailbox plan offers
  (countries.py reads it from here).
* **admin_token** is that host's ``STONECHAT_MACHINE_HOST_ADMIN_TOKEN``.
* **tls_fp** is the host's certificate fingerprint, as ``GET /health`` reports
  it — ``curl -sk https://<host>:8200/health`` on first boot. The machine host
  self-signs (it is not a public web server), so there is no CA to check it
  against and the fingerprint is the whole trust anchor: without it, anything
  on the path between hub and host can collect an admin token that provisions
  mailboxes. The literal ``insecure`` skips the check and is for laptop dev
  only, the way the fleet provider's empty endpoint meant "local daemon".

The address a mailbox is reachable at is decided by the host, not here: it
knows its own advertise address and which port it published.
"""

import base64
import hashlib
import os
import socket
import ssl
from dataclasses import dataclass

import httpx

from ..pushkey import mint_push_key
from .base import CloudProvider, ProviderError, ProvisionRequest, ProvisionResult

# Provisioning waits for a container to start and a relay to open its database
# and mint a certificate schedule; the host polls for that before answering.
PROVISION_TIMEOUT_S = 120
CONTROL_TIMEOUT_S = 15

INSECURE = "insecure"


@dataclass
class MachineHost:
    name: str
    url: str  # https://host:8200, no trailing slash
    country: str  # ISO 3166-1 alpha-2 — the jurisdiction this host sells
    admin_token: str
    tls_fp: str  # BLAKE2b-256 of the DER cert, base64; or INSECURE


def parse_machine_hosts(raw: str) -> list[MachineHost]:
    """`name=url|COUNTRY|admin_token|tls_fp, …` → hosts.

    Every field is required. A defaulted country places a mailbox in the wrong
    jurisdiction — invisibly, because the mailbox works perfectly, it is simply
    somewhere the user did not choose. A defaulted fingerprint hands the admin
    token to whoever answers on that address.
    """
    hosts = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            name, rest = part.split("=", 1)
            url, country, admin_token, tls_fp = rest.split("|", 3)
        except ValueError:
            raise ProviderError(
                f"bad STONECHAT_MACHINE_HOSTS entry {part!r}; expected "
                "name=url|COUNTRY|admin_token|tls_fp"
            )
        country = country.strip().upper()
        if len(country) != 2 or not country.isalpha():
            raise ProviderError(
                f"bad country {country!r} in STONECHAT_MACHINE_HOSTS entry {part!r}; "
                "expected an ISO 3166-1 alpha-2 code such as DE"
            )
        url = url.strip().rstrip("/")
        if not url.startswith("https://"):
            raise ProviderError(
                f"machine host {name.strip()!r} must be https:// — the admin token "
                "travels on this connection"
            )
        if not admin_token.strip():
            raise ProviderError(f"machine host {name.strip()!r} has no admin token")
        if not tls_fp.strip():
            raise ProviderError(
                f"machine host {name.strip()!r} has no tls_fp; read it from "
                f"`curl -sk {url}/health`, or use the literal {INSECURE!r} for "
                "laptop dev"
            )
        hosts.append(MachineHost(name=name.strip(), url=url, country=country,
                                 admin_token=admin_token.strip(),
                                 tls_fp=tls_fp.strip()))
    return hosts


def _parse_hosts() -> list[MachineHost]:
    raw = os.environ.get("STONECHAT_MACHINE_HOSTS", "").strip()
    if not raw:
        # No silent local fallback: mailboxes must never land on the hub box
        # (the hub holds the directory and every provider credential). Dev opts
        # into localhost explicitly.
        raise ProviderError(
            "STONECHAT_MACHINE_HOSTS is not set; the machine-host provider never "
            "provisions on the hub box itself. For laptop dev use "
            f'"local=https://127.0.0.1:8201|DE|<token>|{INSECURE}".'
        )
    return parse_machine_hosts(raw)


def configured_countries() -> set[str]:
    """Countries this pool can place into, read off the host list.

    Derived, never configured alongside: a second copy of this fact is what once
    let the hub advertise five countries while every container landed on the one
    host it had. If it isn't in STONECHAT_MACHINE_HOSTS, it isn't sold.
    """
    raw = os.environ.get("STONECHAT_MACHINE_HOSTS", "").strip()
    return {h.country for h in parse_machine_hosts(raw)} if raw else set()


def _observed_fingerprint(url: str) -> str:
    """BLAKE2b-256 of the host's DER certificate, base64 — the same function the
    machine host reports on /health and the app pins a mailbox with.

    Taken from a bare TLS handshake rather than from the HTTP response, because
    a fingerprint the peer *tells* us is not a pin. httpx offers no hook onto
    the peer certificate of a verify=False connection, so the handshake happens
    here and the request below rides on the trust this established.
    """
    host, _, port = url.removeprefix("https://").partition(":")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, int(port or 443)),
                                      timeout=CONTROL_TIMEOUT_S) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
    except OSError as e:
        raise ProviderError(f"machine host {url} unreachable: {e}") from e
    if not der:
        raise ProviderError(f"machine host {url} presented no certificate")
    return base64.b64encode(hashlib.blake2b(der, digest_size=32).digest()).decode()


class MachineHostProvider(CloudProvider):
    name = "machine_host"

    def __init__(self):
        self.hosts = _parse_hosts()

    # -- talking to a host --------------------------------------------------------

    def _check_pin(self, host: MachineHost) -> None:
        if host.tls_fp == INSECURE:
            return
        observed = _observed_fingerprint(host.url)
        if observed != host.tls_fp:
            raise ProviderError(
                f"machine host {host.name} certificate does not match its pin "
                f"(expected {host.tls_fp[:12]}…, got {observed[:12]}…); refusing to "
                "send it an admin token"
            )

    def _request(self, host: MachineHost, method: str, path: str,
                 json_body: dict | None = None, timeout: float = CONTROL_TIMEOUT_S):
        """One authenticated call, pin checked first.

        verify=False is not "unverified": _check_pin has just confirmed the
        certificate by fingerprint, which is the trust anchor everywhere in this
        system — a self-signed cert has no CA chain to validate and the hostname
        is an IP. Skipping the pin (dev) is the only unverified case, and it says
        so in the config.
        """
        self._check_pin(host)
        try:
            resp = httpx.request(
                method, f"{host.url}{path}",
                headers={"Authorization": f"Bearer {host.admin_token}"},
                json=json_body, timeout=timeout, verify=False,
            )
        except httpx.HTTPError as e:
            raise ProviderError(f"machine host {host.name} unreachable: {e}") from e
        if resp.status_code == 401:
            raise ProviderError(
                f"machine host {host.name} rejected the admin token in "
                "STONECHAT_MACHINE_HOSTS"
            )
        if resp.status_code >= 400:
            raise ProviderError(
                f"machine host {host.name} said {resp.status_code}: {resp.text[:300]}"
            )
        return resp

    def _host_by_name(self, name: str) -> MachineHost | None:
        return next((h for h in self.hosts if h.name == name), None)

    def _occupancy(self, host: MachineHost) -> tuple[int, int]:
        body = self._request(host, "GET", "/v1/guests").json()
        return int(body.get("count", 0)), int(body.get("capacity", 0))

    # -- provider interface -------------------------------------------------------

    def _pick_host(self, country: str) -> MachineHost:
        """Emptiest host **in the requested country**, skipping full ones.

        Never falls back to another country. `countries.resolve()` already
        refuses a country we cannot place into, so reaching here with no
        candidate means the catalog and the host list disagree — a config bug,
        and one that must not be papered over by shipping the user's mailbox to
        whichever host happened to be emptiest.
        """
        want = (country or "").strip().upper()
        candidates = [h for h in self.hosts if h.country == want]
        if not candidates:
            have = ", ".join(sorted({h.country for h in self.hosts})) or "none"
            raise ProviderError(
                f"no machine host in {want!r}; configured countries: {have}"
            )
        # Occupancy is read per host, so an unreachable one must not take the
        # whole placement down with it while its neighbours have room.
        best: tuple[int, MachineHost] | None = None
        errors = []
        for host in candidates:
            try:
                count, capacity = self._occupancy(host)
            except ProviderError as e:
                errors.append(str(e))
                continue
            if capacity and count >= capacity:
                errors.append(f"{host.name} is full ({count}/{capacity})")
                continue
            if best is None or count < best[0]:
                best = (count, host)
        if best is None:
            raise ProviderError(
                f"no machine host in {want} can take a mailbox: " + "; ".join(errors)
            )
        return best[1]

    def provision(self, req: ProvisionRequest) -> ProvisionResult:
        host = self._pick_host(req.spec.region)
        body = self._request(
            host, "POST", "/v1/guest",
            json_body={
                "owner_id": req.owner_id,
                # The hub's own token, not one the host invents: it has already
                # been stored as the mailbox token this user's app will present.
                "owner_token": req.owner_token,
                # Only the hub holds the mint secret, so the key is minted here
                # and passed. "" when push is not configured, which the relay
                # reads as "ping without a key".
                "push_key": mint_push_key(),
                # And the gateway's address, for the same reason: this hub knows
                # where its own gateway is, so the host does not have to be told
                # separately and cannot drift from it.
                "push_gateway": os.environ.get("STONECHAT_PUSH_GATEWAY", ""),
            },
            timeout=PROVISION_TIMEOUT_S,
        ).json()
        address = body.get("address")
        if not address:
            raise ProviderError(
                f"machine host {host.name} returned no address for the mailbox")
        return ProvisionResult(
            resource_id=req.owner_id,  # how this host addresses the guest
            address=address,
            wt_address=body.get("wt_address"),
            meta={"host": host.name},
        )

    def destroy(self, resource_id: str, meta: dict) -> None:
        host = self._host_by_name(meta.get("host", ""))
        # The pool may have been re-listed since this mailbox was created, so a
        # missing `host` means "ask everyone" rather than "give up". Eviction is
        # idempotent on the host side, so asking one that never had it is free.
        candidates = [host] if host else self.hosts
        errors = []
        for candidate in candidates:
            try:
                self._request(candidate, "DELETE", f"/v1/guest/{resource_id}")
                return
            except ProviderError as e:
                errors.append(str(e))
        raise ProviderError(
            "could not destroy the mailbox on any machine host: " + "; ".join(errors)
        )
