"""Provider abstraction.

A provider knows how to do exactly three things: boot a VM that runs the Stonechat
routing server, destroy it, and nothing else. Every provider receives the same
bootstrap script (see bootstrap.py), so the routing server is byte-identical
regardless of cloud — an adapter is only "create machine, pass script, return
the public address".

To add a provider: subclass CloudProvider, implement provision()/destroy(),
and register the module in providers/__init__.py. Nothing else changes.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class MachineSpec:
    """Provider-native machine description, passed through from the API.

    machine_type and region use each provider's own vocabulary
    (e.g. GCP: "e2-micro" / "us-central1-a"; AWS: "t3.micro" / "us-east-1").
    """

    machine_type: str
    region: str
    disk_gb: int = 10


@dataclass
class ProvisionRequest:
    owner_id: str          # Stonechat ID of the user this mailbox belongs to
    owner_token: str       # secret the owner's device presents on /ws
    spec: MachineSpec
    # Dedicated VMs only: pre-install the machine host with this admin token
    # so the owner can mint invites from the app (None → no agent).
    machine_host_token: str | None = None


@dataclass
class ProvisionResult:
    resource_id: str       # provider-side handle (instance name, id, container id)
    address: str           # base URL of the routing server, e.g. "http://34.1.2.3:8080"
    meta: dict = field(default_factory=dict)  # whatever destroy() will need (zone, region, …)
    # Where the browser transport listens: "host:port", UDP (relay/src/wt.rs).
    #
    # Published rather than derived from `address` because it is not derivable:
    # container providers map a *random* host port for each, so a mailbox at
    # 1.2.3.4:49173 says nothing about where its QUIC listener landed. VM
    # providers could derive it — the port is fixed there — but one rule that
    # holds everywhere beats two that each hold somewhere.
    #
    # None means "no browser transport", which is a normal state: a host that
    # blocks UDP, or a provider that has not been taught to map it.
    #
    # Unsigned, and safe to be: an attacker who rewrites this sends the client
    # to a server whose certificate is not in the owner-signed schedule, so the
    # connection is refused. Denial of service, not compromise — the same
    # property `address` already has behind the signed `tls_fp`.
    wt_address: str | None = None


class CloudProvider(ABC):
    """One instance per configured provider; must be stateless between calls."""

    name: str = "abstract"

    @abstractmethod
    def provision(self, req: ProvisionRequest) -> ProvisionResult:
        """Create the VM and return once it has a public address.

        Blocking/synchronous by design — the API layer runs this in a worker
        thread. Implementations should raise ProviderError with a readable
        message on failure.
        """

    @abstractmethod
    def destroy(self, resource_id: str, meta: dict) -> None:
        """Tear down the VM. Must be idempotent (gone already == success)."""


class ProviderError(RuntimeError):
    pass
