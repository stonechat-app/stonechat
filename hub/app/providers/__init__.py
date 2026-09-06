"""Provider registry.

Providers are imported lazily so that a missing optional dependency (boto3,
google-cloud-compute) only breaks the provider that needs it, not the app.
"""

from importlib import import_module

from .base import CloudProvider, MachineSpec, ProviderError, ProvisionRequest, ProvisionResult

__all__ = [
    "CloudProvider",
    "MachineSpec",
    "ProviderError",
    "ProvisionRequest",
    "ProvisionResult",
    "available_providers",
    "get_provider",
]

_REGISTRY: dict[str, tuple[str, str]] = {
    # name -> (module, class)
    "gcp": ("app.providers.gcp", "GCPProvider"),
    "aws": ("app.providers.aws", "AWSProvider"),
    "digitalocean": ("app.providers.digitalocean", "DOProvider"),
    "hetzner": ("app.providers.hetzner", "HetznerProvider"),
    "vultr": ("app.providers.vultr", "VultrProvider"),
    "local": ("app.providers.local", "LocalDockerProvider"),
    "fleet": ("app.providers.fleet", "FleetProvider"),
    # To add another cloud: create <name>.py implementing CloudProvider and
    # register it here; gate it in main.py if the plan requires it.
}


def available_providers() -> list[str]:
    return sorted(_REGISTRY)


def get_provider(name: str) -> CloudProvider:
    try:
        module_name, class_name = _REGISTRY[name]
    except KeyError:
        raise ProviderError(
            f"unknown provider {name!r}; available: {', '.join(available_providers())}"
        )
    module = import_module(module_name)
    return getattr(module, class_name)()
