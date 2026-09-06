"""Country catalog — the only place that knows which cloud serves which flag.

The app asks for a **country**. It never names a provider, a region or a
machine type: those are our vocabulary, they change when prices change, and
baking them into a shipped binary means every provider swap waits on an App
Store review. So the mapping lives here and the client sends `{"country":
"CH"}`.

That indirection is the point. Moving Switzerland from GCP Zurich to Exoscale,
or Germany from GCP to Hetzner once that adapter lands, is an edit to this file
and a hub restart — no app release, and existing mailboxes are untouched
because a running server row already holds its own resolved provider.

**What the picker actually sells.** A mailbox holds sealed ciphertext, so
jurisdiction does not govern message content — it governs metadata (that a box
exists, its address, connection timing) and who can seize the hardware. Every
country below therefore ships with a `caveat` as well as a `jurisdiction`
line, and the UI is required to show both. A country picker that prints only
the flattering half is marketing, and this product does not get to do that:
`SG` is on the list for reach and says so.

Opening set is deliberately five (BUSINESS.md): each country is one idle fleet
host until it fills, so coverage is added when demand proves it, not upfront.

All five currently resolve to **GCP**, the one adapter that has ever
provisioned for real. `hetzner`, `vultr` and `digitalocean` all exist and are
mock-tested only (`hub/scripts/check_providers.py`); `aws` is dead code on
hairpin NAT. Each `Hosting(...)` below therefore names the cheaper home it
should move to and what that move is still waiting on — one live provision per
provider, per TODO.md §20 — because a country picker that places a mailbox
somewhere untested is the one failure this file exists to prevent.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

log = logging.getLogger("stonechat.hub.countries")


@dataclass(frozen=True)
class Hosting:
    """Where a dedicated (Machine plan) mailbox for this country actually boots."""

    provider: str
    region: str          # provider-native: GCP wants a *zone*
    machine_type: str


@dataclass(frozen=True)
class Country:
    code: str            # ISO 3166-1 alpha-2, and the picker's wire value
    name: str
    city: str
    flag: str
    # Shown together in the picker. `jurisdiction` is what the country buys the
    # user; `caveat` is what it does not. Never show one without the other.
    jurisdiction: str
    caveat: str
    hosting: Hosting


# Ordered as the picker shows them: Europe first (the strongest privacy story
# and the cheapest hosting), then the regional anchors.
CATALOG: tuple[Country, ...] = (
    Country(
        code="DE",
        name="Germany",
        city="Frankfurt",
        flag="🇩🇪",
        jurisdiction="EU data protection law (GDPR). Germany's courts struck "
                     "down blanket data retention in 2022.",
        caveat="Germany takes part in the 'Fourteen Eyes' intelligence-sharing "
               "arrangement.",
        # Roughly a fifth of the cost on Hetzner Falkenstein, same country:
        #   hosting=Hosting("hetzner", "fsn1", "cx22")
        # is the whole change, once one live provision has proved the adapter.
        hosting=Hosting("gcp", "europe-west3-a", "e2-micro"),
    ),
    Country(
        code="FI",
        name="Finland",
        city="Hamina",
        flag="🇫🇮",
        jurisdiction="EU data protection law (GDPR), and Finland sits outside "
                     "the Fourteen Eyes intelligence-sharing group.",
        caveat="Finnish law has permitted state network surveillance since the "
               "2019 intelligence acts.",
        # Hetzner Helsinki is the cheapest RAM in the industry — this is the
        # country where the Mailbox tier's margin is actually decided:
        #   hosting=Hosting("hetzner", "hel1", "cx22")
        hosting=Hosting("gcp", "europe-north1-a", "e2-micro"),
    ),
    Country(
        code="CH",
        name="Switzerland",
        city="Zurich",
        flag="🇨🇭",
        jurisdiction="Swiss federal data protection law, outside the EU and "
                     "outside every major intelligence-sharing bloc.",
        caveat="Swiss surveillance law can oblige telecoms operators to retain "
               "metadata; how far that reaches hosting customers has been "
               "fought over in court.",
        hosting=Hosting("gcp", "europe-west6-a", "e2-micro"),
    ),
    Country(
        code="BR",
        name="Brazil",
        city="São Paulo",
        flag="🇧🇷",
        jurisdiction="Brazilian data protection law (LGPD), which is modelled "
                     "on the GDPR.",
        caveat="Brazil's Marco Civil requires application providers to keep "
               "access logs for six months.",
        # Vultr São Paulo (`Hosting("vultr", "sao", "vc2-1c-1gb")`) is the
        # cheaper home; GCP already reaches São Paulo, so this one is price,
        # not coverage.
        hosting=Hosting("gcp", "southamerica-east1-a", "e2-micro"),
    ),
    Country(
        code="SG",
        name="Singapore",
        city="Singapore",
        flag="🇸🇬",
        jurisdiction="Political stability and the best connectivity in "
                     "Southeast Asia.",
        caveat="Singapore law grants broad state access powers, including "
               "compelling assistance with decryption. It is on this list for "
               "reach, not for privacy.",
        # Two cheaper homes, both untested: Hetzner `sin` (cpx11 — the Intel
        # CX line is EU-only) or Vultr `sgp`.
        hosting=Hosting("gcp", "asia-southeast1-a", "e2-micro"),
    ),
)

_BY_CODE = {c.code: c for c in CATALOG}


# Which countries the Mailbox tier can actually place a container in — read
# straight off the configured fleet hosts, intersected with this catalog.
#
# Derived on purpose. This used to be its own env var (STONECHAT_FLEET_COUNTRIES)
# maintained beside the host list, and the two drifted: the hub advertised five
# countries while every container landed on the single host it had. A fact about
# deployed infrastructure has exactly one home, and it is the host list.
def fleet_countries() -> set[str]:
    from .providers import ProviderError
    from .providers.fleet import configured_countries  # local: keeps hub start cheap

    try:
        return configured_countries() & set(_BY_CODE)
    except ProviderError:
        # Malformed STONECHAT_FLEET_HOSTS. This feeds the public picker, so it
        # fails *closed* — offer no Mailbox country — rather than 500ing
        # onboarding. Provisioning still raises loudly (FleetProvider), and the
        # only unsafe direction is over-claiming, which an empty set cannot do.
        log.exception("STONECHAT_FLEET_HOSTS is unparseable — Mailbox plan offered nowhere")
        return set()


def plans_for(country: Country, fleet: set[str]) -> list[str]:
    """Which plans can place a mailbox in this country right now."""
    plans = ["machine"]
    if country.code in fleet:
        plans.append("mailbox")
    return plans


def catalog() -> list[dict]:
    """The picker's payload. Ordered; `plans` is what the client gates on."""
    fleet = fleet_countries()
    return [
        {
            "code": c.code,
            "name": c.name,
            "city": c.city,
            "flag": c.flag,
            "jurisdiction": c.jurisdiction,
            "caveat": c.caveat,
            "plans": plans_for(c, fleet),
        }
        for c in CATALOG
    ]


class UnavailableCountry(ValueError):
    """Country is unknown, or known but not placeable on the caller's plan."""


def resolve(code: str, plan: str) -> tuple[str, dict]:
    """(country, plan) -> (provider name, MachineIn-shaped dict).

    Raises UnavailableCountry rather than falling back to some other country:
    silently placing a mailbox somewhere the user did not pick is the one
    failure mode this whole feature exists to prevent.
    """
    country = _BY_CODE.get(code.upper())
    if country is None:
        raise UnavailableCountry(
            f"unknown country {code!r}; available: "
            f"{', '.join(c.code for c in CATALOG)}"
        )
    if plan == "mailbox":
        if country.code not in fleet_countries():
            raise UnavailableCountry(
                f"{country.name} is not available on the Mailbox plan yet"
            )
        # The fleet provider places by pool name, not by cloud region.
        return "fleet", {"machine_type": "container", "region": country.code}
    h = country.hosting
    return h.provider, {
        "machine_type": h.machine_type,
        "region": h.region,
        "disk_gb": 10,
    }
