#!/usr/bin/env python3
"""Push the App Store listing metadata to App Store Connect.

Companion to upload_to_testflight.sh, which ships the *binary* and leaves the
product page blank. This ships the page: name, subtitle, description, keywords,
URLs, categories and the age-rating questionnaire — and the rest of what a
submission needs that is data rather than judgement: the price (free), the
storefronts it is offered in, and the notes App Review reads.

    scripts/appstore_listing.py --dry-run   # show what would change
    scripts/appstore_listing.py             # apply it

Copy lives in ../store/listing.en-US.toml, next to the checkout and outside the
repository (--listing to point elsewhere) — edit there, not in the ASC web UI,
or the next push overwrites the edit. Credentials come from .env.appstore (the
same file upload_to_testflight.sh reads). So does everything about App Review
that must not sit in a public repository: the reviewer's invite codes, the
test contact, and the phone number and address Apple may call or write to —
REVIEW_INVITE_CODES, REVIEW_TEST_CONTACT, REVIEW_CONTACT_FIRST_NAME,
REVIEW_CONTACT_LAST_NAME, REVIEW_CONTACT_PHONE, REVIEW_CONTACT_EMAIL.

Two things this deliberately does not do, because neither can be done honestly
without a human: take screenshots (they must depict the real app — once taken,
appstore_screenshots.py uploads them) and set the privacy "nutrition labels"
(that questionnaire has no public API and must be answered in the web UI —
src/pages/privacy.astro in the stonechat-app/landing repo is the source text).

Requires: pip install 'pyjwt[crypto]' httpx
"""

from __future__ import annotations

import argparse
import os
import sys
import time
import tomllib
from pathlib import Path
from typing import Any

try:
    import httpx
    import jwt
except ImportError as exc:  # pragma: no cover - dependency hint
    sys.exit(f"missing dependency ({exc.name}): pip install 'pyjwt[crypto]' httpx")

ROOT = Path(__file__).resolve().parent.parent
API = "https://api.appstoreconnect.apple.com/v1"

# Apple truncates silently in some fields and rejects in others; failing here
# means a bad edit never reaches the network.
LIMITS = {
    "name": 30,
    "subtitle": 30,
    "promotional_text": 170,
    "keywords": 100,
    "description": 4000,
    "whats_new": 4000,
}

# States in which a version's copy is still editable. Anything else (IN_REVIEW,
# PENDING_DEVELOPER_RELEASE, …) means Apple owns the record right now.
EDITABLE = {
    "PREPARE_FOR_SUBMISSION",
    "DEVELOPER_REJECTED",
    "REJECTED",
    "METADATA_REJECTED",
    "INVALID_BINARY",
}


class Fatal(Exception):
    """Anything that should stop the push with a readable message."""


# --------------------------------------------------------------------------
# credentials
# --------------------------------------------------------------------------


def load_env() -> dict[str, str]:
    path = ROOT / ".env.appstore"
    if not path.exists():
        raise Fatal(f"{path} not found — see upload_to_testflight.sh for its shape")
    env: dict[str, str] = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            env[key.strip()] = value.strip()
    for required in ("API_KEY_ID", "API_ISSUER_ID"):
        if not env.get(required):
            raise Fatal(f"{required} must be set in .env.appstore")
    return env


def token_for(env: dict[str, str]) -> str:
    key_id = env["API_KEY_ID"]
    key_dir = ROOT / Path(env.get("API_KEY_PATH", "credentials/AuthKey.p8")).parent
    key_file = key_dir / f"AuthKey_{key_id}.p8"
    if not key_file.exists():
        raise Fatal(f"API key file not found at {key_file}")
    now = int(time.time())
    return jwt.encode(
        {
            "iss": env["API_ISSUER_ID"],
            "iat": now,
            "exp": now + 900,  # Apple rejects anything over 20 minutes
            "aud": "appstoreconnect-v1",
        },
        key_file.read_text(),
        algorithm="ES256",
        headers={"kid": key_id, "typ": "JWT"},
    )


# --------------------------------------------------------------------------
# API plumbing
# --------------------------------------------------------------------------


class Client:
    def __init__(self, bearer: str, dry_run: bool) -> None:
        self._http = httpx.Client(
            base_url=API,
            headers={"Authorization": f"Bearer {bearer}"},
            timeout=30.0,
        )
        self.dry_run = dry_run

    def get(self, path: str, **params: Any) -> dict:
        response = self._http.get(path, params=params)
        self._check(response, "GET", path)
        return response.json()

    def patch(self, path: str, kind: str, ident: str, attributes: dict) -> None:
        if self.dry_run:
            return
        payload = {"data": {"type": kind, "id": ident, "attributes": attributes}}
        response = self._http.patch(path, json=payload)
        self._check(response, "PATCH", path)

    def post(self, url: str, payload: dict) -> None:
        """Create a resource. `url` may be absolute: some resources live
        under /v2 while the client's base is /v1."""
        if self.dry_run:
            return
        response = self._http.post(url, json=payload)
        self._check(response, "POST", url)

    def get_or_none(self, url: str, **params: Any) -> dict | None:
        """GET, with "there is no such resource yet" as None, not an error."""
        response = self._http.get(url, params=params)
        if response.status_code == 404:
            return None
        self._check(response, "GET", url)
        return response.json()

    def patch_relationships(self, path: str, kind: str, ident: str, rels: dict) -> None:
        """Set to-one relationships on the resource itself.

        The /relationships/<name> sub-resource is GET-only for appInfos, so
        categories have to ride along on a PATCH of the parent.
        """
        if self.dry_run:
            return
        payload = {"data": {"type": kind, "id": ident, "relationships": rels}}
        response = self._http.patch(path, json=payload)
        self._check(response, "PATCH", path)

    @staticmethod
    def _check(response: httpx.Response, verb: str, path: str) -> None:
        if response.is_success:
            return
        detail = response.text
        try:  # Apple's errors are genuinely informative — surface them verbatim
            errors = response.json().get("errors", [])
            detail = "\n".join(
                f"  {e.get('title')}: {e.get('detail')}" for e in errors
            ) or detail
        except ValueError:
            pass
        raise Fatal(f"{verb} {path} → {response.status_code}\n{detail}")


# --------------------------------------------------------------------------
# resolution
# --------------------------------------------------------------------------


def resolve_app(client: Client, env: dict[str, str], bundle_id: str) -> str:
    """Return the ASC app id, preferring APP_ID but falling back to the bundle."""
    if env.get("APP_ID"):
        return env["APP_ID"]
    apps = client.get("apps", **{"filter[bundleId]": bundle_id, "limit": 10})["data"]
    if not apps:
        raise Fatal(f"no app in App Store Connect with bundle id {bundle_id}")
    app_id = apps[0]["id"]
    print(f"  note: APP_ID is unset in .env.appstore — resolved {app_id} from {bundle_id}")
    print(f"        add 'APP_ID={app_id}' to skip this lookup")
    return app_id


def editable_version(client: Client, app_id: str) -> dict:
    versions = client.get(
        f"apps/{app_id}/appStoreVersions", **{"limit": 10, "filter[platform]": "IOS"}
    )["data"]
    for version in versions:
        if version["attributes"].get("appStoreState") in EDITABLE:
            return version
    states = ", ".join(
        f"{v['attributes'].get('versionString')}={v['attributes'].get('appStoreState')}"
        for v in versions
    ) or "none"
    raise Fatal(f"no editable iOS version — Apple currently owns these: {states}")


def localization(client: Client, parent: str, parent_id: str, locale: str) -> dict:
    """Find the localization for `locale`, which must already exist."""
    child = (
        "appInfoLocalizations"
        if parent == "appInfos"
        else "appStoreVersionLocalizations"
    )
    for loc in client.get(f"{parent}/{parent_id}/{child}", limit=50)["data"]:
        if loc["attributes"].get("locale") == locale:
            return loc
    raise Fatal(f"no {locale} localization on {parent}/{parent_id}")


# --------------------------------------------------------------------------
# push
# --------------------------------------------------------------------------


def validate(listing: dict) -> None:
    values = {**listing["app_info"], **listing["version"]}
    for field, limit in LIMITS.items():
        text = (values.get(field) or "").strip()
        if len(text) > limit:
            raise Fatal(
                f"{field} is {len(text)} characters; Apple's limit is {limit}"
            )
    if not values.get("description"):
        raise Fatal("description is required and empty")


def diff(current: dict, desired: dict) -> dict:
    """Only send fields that actually differ — a no-op PATCH still burns a write."""
    return {k: v for k, v in desired.items() if (current.get(k) or "") != (v or "")}


def report(label: str, changes: dict, current: dict) -> None:
    if not changes:
        print(f"  {label}: already current")
        return
    for field, value in changes.items():
        before = current.get(field)
        before_text = "(empty)" if not before else _clip(str(before))
        print(f"  {label}.{field}")
        print(f"      - {before_text}")
        print(f"      + {_clip(str(value))}")


# --------------------------------------------------------------------------
# pricing and availability
# --------------------------------------------------------------------------

API_V2 = "https://api.appstoreconnect.apple.com/v2"


def push_free_price(client: Client, app_id: str, base_territory: str) -> None:
    """A free app still needs a price schedule: until one exists the version
    cannot be submitted."""
    # 404 while the app has never had a schedule.
    current = client.get_or_none(f"appPriceSchedules/{app_id}/manualPrices", limit=1)
    if current and current["data"]:
        print("  price: a schedule is already set — left alone")
        return
    points = client.get(
        f"apps/{app_id}/appPricePoints",
        **{"filter[territory]": base_territory, "limit": 200},
    )["data"]
    free = next(
        (p for p in points if float(p["attributes"]["customerPrice"]) == 0.0), None
    )
    if free is None:
        raise Fatal(f"no free price point for {base_territory}")
    print(f"  price\n      - (unset)\n      + free, base territory {base_territory}")
    client.post(
        "appPriceSchedules",
        {
            "data": {
                "type": "appPriceSchedules",
                "relationships": {
                    "app": {"data": {"type": "apps", "id": app_id}},
                    "baseTerritory": {
                        "data": {"type": "territories", "id": base_territory}
                    },
                    "manualPrices": {"data": [{"type": "appPrices", "id": "${free}"}]},
                },
            },
            "included": [
                {
                    "type": "appPrices",
                    "id": "${free}",
                    "attributes": {"startDate": None},
                    "relationships": {
                        "appPricePoint": {
                            "data": {"type": "appPricePoints", "id": free["id"]}
                        }
                    },
                }
            ],
        },
    )


def push_availability(client: Client, app_id: str, excluded: list[str]) -> None:
    """Offer the app everywhere except `excluded` (territory ids, e.g. FRA).

    Created once if the app has no availability yet; after that each
    territory is compared and only the ones that differ are changed."""
    excluded_set = set(excluded)
    existing = client.get_or_none(
        f"{API_V2}/appAvailabilities/{app_id}/territoryAvailabilities",
        **{"limit": 200, "include": "territory"},
    )
    if existing is None:
        territories = [t["id"] for t in client.get("territories", limit=200)["data"]]
        unknown = excluded_set - set(territories)
        if unknown:
            raise Fatal(f"not territories Apple knows: {', '.join(sorted(unknown))}")
        print(
            f"  availability\n      - (unset)\n      + {len(territories) - len(excluded_set)}"
            f" territories, and new ones as Apple adds them; not {', '.join(sorted(excluded_set)) or '(none)'}"
        )
        client.post(
            f"{API_V2}/appAvailabilities",
            {
                "data": {
                    "type": "appAvailabilities",
                    "attributes": {"availableInNewTerritories": True},
                    "relationships": {
                        "app": {"data": {"type": "apps", "id": app_id}},
                        "territoryAvailabilities": {
                            "data": [
                                {"type": "territoryAvailabilities", "id": f"${{{t}}}"}
                                for t in territories
                            ]
                        },
                    },
                },
                "included": [
                    {
                        "type": "territoryAvailabilities",
                        "id": f"${{{t}}}",
                        "attributes": {"available": t not in excluded_set},
                        "relationships": {
                            "territory": {"data": {"type": "territories", "id": t}}
                        },
                    }
                    for t in territories
                ],
            },
        )
        return
    changed = False
    for row in existing["data"]:
        territory = row["relationships"]["territory"]["data"]["id"]
        wanted = territory not in excluded_set
        if row["attributes"]["available"] != wanted:
            changed = True
            print(f"  availability.{territory}\n      - {not wanted}\n      + {wanted}")
            client.patch(
                f"territoryAvailabilities/{row['id']}",
                "territoryAvailabilities",
                row["id"],
                {"available": wanted},
            )
    if not changed:
        print("  availability: already current")


# --------------------------------------------------------------------------
# App Review
# --------------------------------------------------------------------------


def push_review_detail(
    client: Client, version_id: str, review: dict, env: dict[str, str]
) -> None:
    """The notes and contact App Review sees. The notes template lives with
    the listing; what fills it in, and the contact, come from .env.appstore."""
    codes = [c.strip() for c in env.get("REVIEW_INVITE_CODES", "").split(",") if c.strip()]
    contact = env.get("REVIEW_TEST_CONTACT", "")
    if not codes or not contact:
        print(
            "  review: skipped — set REVIEW_INVITE_CODES and REVIEW_TEST_CONTACT"
            " in .env.appstore"
        )
        return
    notes = review["notes"].strip().format(
        invite_codes="\n".join(f"    {c}" for c in codes), test_contact=contact
    )
    if len(notes) > 4000:
        raise Fatal(f"review.notes is {len(notes)} chars, limit 4000")
    desired: dict[str, Any] = {"notes": notes, "demoAccountRequired": False}
    fields = {
        "contactFirstName": "REVIEW_CONTACT_FIRST_NAME",
        "contactLastName": "REVIEW_CONTACT_LAST_NAME",
        "contactPhone": "REVIEW_CONTACT_PHONE",
        "contactEmail": "REVIEW_CONTACT_EMAIL",
    }
    missing = [name for name in fields.values() if not env.get(name)]
    for attribute, name in fields.items():
        if env.get(name):
            desired[attribute] = env[name]

    current = client.get(f"appStoreVersions/{version_id}/appStoreReviewDetail").get("data")
    if current is None:
        print(f"  review\n      - (none)\n      + notes ({len(notes)} chars)"
              + ("" if missing else ", contact"))
        client.post(
            "appStoreReviewDetails",
            {
                "data": {
                    "type": "appStoreReviewDetails",
                    "attributes": desired,
                    "relationships": {
                        "appStoreVersion": {
                            "data": {"type": "appStoreVersions", "id": version_id}
                        }
                    },
                }
            },
        )
    else:
        changes = diff(current["attributes"], desired)
        report("review", changes, current["attributes"])
        if changes:
            client.patch(
                f"appStoreReviewDetails/{current['id']}",
                "appStoreReviewDetails",
                current["id"],
                changes,
            )
    if missing:
        print(f"      still needed before submitting: {', '.join(missing)}")


def _clip(text: str, width: int = 88) -> str:
    flat = " ".join(text.split())
    return flat if len(flat) <= width else flat[: width - 1] + "…"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dry-run", action="store_true", help="show the changes without sending them"
    )
    parser.add_argument(
        "--listing",
        # The listing copy is the owner's, not the project's: it lives beside
        # the checkout rather than in it, like .env.appstore's contents.
        default=str(ROOT.parent / "store" / "listing.en-US.toml"),
        help="path to the listing copy (default: ../store/listing.en-US.toml)",
    )
    parser.add_argument(
        "--bundle-id",
        default="app.stonechat.mobile",
        help="fallback used when APP_ID is unset in .env.appstore",
    )
    args = parser.parse_args()

    listing = tomllib.loads(Path(args.listing).read_text())
    validate(listing)
    locale = listing["locale"]

    env = load_env()
    client = Client(token_for(env), args.dry_run)

    if args.dry_run:
        print("DRY RUN — nothing will be sent\n")

    app_id = resolve_app(client, env, args.bundle_id)
    app = client.get(f"apps/{app_id}")["data"]
    print(f"app {app_id} · {app['attributes'].get('bundleId')}")

    # `include` matters: without it the relationships come back as bare links
    # and every category reads as unset, so the script would re-PATCH forever.
    info = client.get(
        f"apps/{app_id}/appInfos",
        limit=10,
        include="primaryCategory,secondaryCategory",
    )["data"][0]
    version = editable_version(client, app_id)
    print(
        f"version {version['attributes'].get('versionString')} "
        f"({version['attributes'].get('appStoreState')})\n"
    )

    # -- app-level copy: name, subtitle, privacy policy -------------------
    app_info = listing["app_info"]
    info_loc = localization(client, "appInfos", info["id"], locale)
    changes = diff(
        info_loc["attributes"],
        {
            "name": app_info["name"],
            "subtitle": app_info["subtitle"],
            "privacyPolicyUrl": app_info["privacy_policy_url"],
        },
    )
    report("appInfo", changes, info_loc["attributes"])
    if changes:
        client.patch(
            f"appInfoLocalizations/{info_loc['id']}",
            "appInfoLocalizations",
            info_loc["id"],
            changes,
        )

    # -- categories -------------------------------------------------------
    rels: dict[str, Any] = {}
    for slot, key in (("primaryCategory", "primary_category"),
                      ("secondaryCategory", "secondary_category")):
        wanted = app_info.get(key)
        if not wanted:
            continue
        existing = (info.get("relationships", {}).get(slot, {}) or {}).get("data")
        if existing and existing.get("id") == wanted:
            print(f"  category.{slot}: already {wanted}")
            continue
        print(f"  category.{slot}")
        print(f"      - {existing['id'] if existing else '(unset)'}")
        print(f"      + {wanted}")
        rels[slot] = {"data": {"type": "appCategories", "id": wanted}}
    if rels:
        client.patch_relationships(
            f"appInfos/{info['id']}", "appInfos", info["id"], rels
        )

    # -- content rights: an app-level yes/no Apple asks once ----------------
    rights = app_info.get("content_rights")
    if rights:
        app = client.get(f"apps/{app_id}")["data"]
        current_rights = app["attributes"].get("contentRightsDeclaration")
        if current_rights == rights:
            print(f"  contentRights: already {rights}")
        else:
            print(f"  contentRights\n      - {current_rights or '(unset)'}\n      + {rights}")
            client.patch(f"apps/{app_id}", "apps", app_id,
                         {"contentRightsDeclaration": rights})

    # -- version copy: description, keywords, URLs ------------------------
    ver = listing["version"]
    # Copyright lives on the version itself, not its localization, and the
    # version cannot be added for review without it.
    if ver.get("copyright"):
        changes = diff(version["attributes"], {"copyright": ver["copyright"].strip()})
        report("version", changes, version["attributes"])
        if changes:
            client.patch(f"appStoreVersions/{version['id']}", "appStoreVersions",
                         version["id"], changes)
    ver_loc = localization(client, "appStoreVersions", version["id"], locale)
    desired = {
        "description": ver["description"].strip(),
        "keywords": ver["keywords"].strip(),
        "promotionalText": ver["promotional_text"].strip(),
        "supportUrl": ver["support_url"],
        "marketingUrl": ver["marketing_url"],
    }
    # Apple rejects "what's new" on a version that has never been released.
    whats_new = (ver.get("whats_new") or "").strip()
    if whats_new:
        desired["whatsNew"] = whats_new
    changes = diff(ver_loc["attributes"], desired)
    report("version", changes, ver_loc["attributes"])
    if changes:
        client.patch(
            f"appStoreVersionLocalizations/{ver_loc['id']}",
            "appStoreVersionLocalizations",
            ver_loc["id"],
            changes,
        )

    # -- age rating -------------------------------------------------------
    # Apple validates this as one questionnaire: a partial PATCH is rejected
    # with "you must provide a value for ...", so the whole block goes every
    # time and the diff is only used to decide whether to send at all.
    if listing.get("age_rating"):
        answers = listing["age_rating"]
        declaration = client.get(f"appInfos/{info['id']}/ageRatingDeclaration")["data"]
        changed = {
            k: v for k, v in answers.items() if declaration["attributes"].get(k) != v
        }
        if changed:
            for field, value in sorted(changed.items()):
                was = declaration["attributes"].get(field)
                print(f"  ageRating.{field}")
                print(f"      - {'(unanswered)' if was is None else was}")
                print(f"      + {value}")
            client.patch(
                f"ageRatingDeclarations/{declaration['id']}",
                "ageRatingDeclarations",
                declaration["id"],
                answers,
            )
        else:
            print("  ageRating: already current")

    # -- price, storefronts, App Review -------------------------------------
    if listing.get("availability"):
        availability = listing["availability"]
        push_free_price(client, app_id, availability.get("base_territory", "USA"))
        push_availability(client, app_id, availability.get("excluded", []))
    if listing.get("review"):
        push_review_detail(client, version["id"], listing["review"], env)

    # -- what a script cannot do --------------------------------------------
    print()
    screenshots = client.get(
        f"appStoreVersionLocalizations/{ver_loc['id']}/appScreenshotSets", limit=10
    )["data"]
    if not screenshots:
        print("STILL MISSING — screenshots: none uploaded; take them, then run "
              "scripts/appstore_screenshots.py")
    print("STILL MANUAL — privacy nutrition labels: no public API; answer in the web UI")
    print(f"               https://appstoreconnect.apple.com/apps/{app_id}/distribution")

    if args.dry_run:
        print("\nDry run — re-run without --dry-run to apply.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Fatal as err:
        sys.exit(f"error: {err}")
