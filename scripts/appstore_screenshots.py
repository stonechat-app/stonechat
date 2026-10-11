#!/usr/bin/env python3
"""Upload App Store screenshots to the editable version's listing.

Companion to appstore_listing.py, which ships the copy and deliberately leaves
screenshots alone: they must depict the real app, so a human takes them. Once
taken, this pushes them — the upload protocol (reserve, PUT the bytes in the
chunks Apple asks for, commit with a checksum, wait for processing) is the part
nobody should do by hand.

    scripts/appstore_screenshots.py ../store/screenshots            # upload
    scripts/appstore_screenshots.py ../store/screenshots --dry-run  # plan only
    scripts/appstore_screenshots.py ../store/screenshots --replace  # wipe each
                                                 # set first, then upload

The directory holds one sub-directory per display size, named after the
simulator it was shot on; files upload in name order, which becomes the order
on the product page:

    iphone-6.9/   1320×2868 or 1290×2796   → APP_IPHONE_67  (6.9"/6.7" set)
    ipad-13/      2064×2752 or 2048×2732   → APP_IPAD_PRO_3GEN_129 (13" set)

A file already present in the set (same name) is skipped unless --replace, so
re-running after adding one shot uploads one shot. Credentials and the app
come from .env.appstore exactly as for appstore_listing.py; the locale from
../store/listing.en-US.toml (--locale to override).

Requires: pip install 'pyjwt[crypto]' httpx
"""

from __future__ import annotations

import argparse
import hashlib
import sys
import time
import tomllib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import httpx  # noqa: E402

from appstore_listing import (  # noqa: E402
    ROOT,
    Client,
    Fatal,
    editable_version,
    load_env,
    localization,
    resolve_app,
    token_for,
)

# Directory name → (Apple display type, accepted pixel sizes). Sizes are the
# ones App Store Connect lists for each display, portrait only.
DISPLAYS: dict[str, tuple[str, set[tuple[int, int]]]] = {
    "iphone-6.9": ("APP_IPHONE_67", {(1320, 2868), (1290, 2796)}),
    "iphone-6.5": ("APP_IPHONE_65", {(1284, 2778), (1242, 2688)}),
    "ipad-13": ("APP_IPAD_PRO_3GEN_129", {(2064, 2752), (2048, 2732)}),
    "ipad-12.9": ("APP_IPAD_PRO_129", {(2048, 2732)}),
}
MAX_PER_SET = 10


def png_size(path: Path) -> tuple[int, int]:
    """Width and height from the PNG header — no image library needed."""
    with path.open("rb") as f:
        head = f.read(24)
    if head[:8] != b"\x89PNG\r\n\x1a\n" or head[12:16] != b"IHDR":
        raise Fatal(f"{path.name} is not a PNG")
    return int.from_bytes(head[16:20], "big"), int.from_bytes(head[20:24], "big")


def plan(root: Path) -> dict[str, list[Path]]:
    """Which files go in which set, validated before anything is sent."""
    if not root.is_dir():
        raise Fatal(f"{root} is not a directory")
    sets: dict[str, list[Path]] = {}
    for sub in sorted(p for p in root.iterdir() if p.is_dir()):
        if sub.name not in DISPLAYS:
            if not sub.name.startswith("_"):
                print(f"  skipping {sub.name}/ — not a known display "
                      f"({', '.join(DISPLAYS)})")
            continue
        display, sizes = DISPLAYS[sub.name]
        files = sorted(sub.glob("*.png"))
        if not files:
            continue
        if len(files) > MAX_PER_SET:
            raise Fatal(f"{sub.name}/ has {len(files)} PNGs; Apple takes at most {MAX_PER_SET}")
        for f in files:
            size = png_size(f)
            if size not in sizes:
                want = " or ".join(f"{w}×{h}" for w, h in sorted(sizes))
                raise Fatal(f"{sub.name}/{f.name} is {size[0]}×{size[1]}; "
                            f"the {display} set wants {want}")
        sets[display] = files
    if not sets:
        raise Fatal(f"nothing to upload under {root}")
    return sets


# --------------------------------------------------------------------------
# App Store Connect
# --------------------------------------------------------------------------


def screenshot_set(client: Client, loc_id: str, display: str) -> dict | None:
    sets = client.get(
        f"appStoreVersionLocalizations/{loc_id}/appScreenshotSets", limit=50
    )["data"]
    return next(
        (s for s in sets if s["attributes"].get("screenshotDisplayType") == display),
        None,
    )


def create_set(client: Client, loc_id: str, display: str) -> dict:
    response = client._http.post(
        "appScreenshotSets",
        json={
            "data": {
                "type": "appScreenshotSets",
                "attributes": {"screenshotDisplayType": display},
                "relationships": {
                    "appStoreVersionLocalization": {
                        "data": {"type": "appStoreVersionLocalizations", "id": loc_id}
                    }
                },
            }
        },
    )
    client._check(response, "POST", "appScreenshotSets")
    return response.json()["data"]


def set_screenshots(client: Client, set_id: str) -> list[dict]:
    return client.get(f"appScreenshotSets/{set_id}/appScreenshots", limit=50)["data"]


def delete_screenshot(client: Client, shot_id: str) -> None:
    response = client._http.delete(f"appScreenshots/{shot_id}")
    client._check(response, "DELETE", f"appScreenshots/{shot_id}")


def upload(client: Client, set_id: str, path: Path) -> str:
    """Reserve, upload, commit, and wait for Apple to accept one file."""
    data = path.read_bytes()
    response = client._http.post(
        "appScreenshots",
        json={
            "data": {
                "type": "appScreenshots",
                "attributes": {"fileName": path.name, "fileSize": len(data)},
                "relationships": {
                    "appScreenshotSet": {
                        "data": {"type": "appScreenshotSets", "id": set_id}
                    }
                },
            }
        },
    )
    client._check(response, "POST", "appScreenshots")
    shot = response.json()["data"]
    shot_id = shot["id"]
    # Apple hands back the exact PUTs it wants: URL, byte range and headers.
    # The upload hosts are not under the API base, so a bare client is used.
    with httpx.Client(timeout=120.0) as raw:
        for op in shot["attributes"]["uploadOperations"]:
            start, length = op["offset"], op["length"]
            headers = {h["name"]: h["value"] for h in op.get("requestHeaders", [])}
            put = raw.request(op["method"], op["url"],
                              content=data[start:start + length], headers=headers)
            if not put.is_success:
                raise Fatal(f"upload chunk of {path.name} → {put.status_code}: {put.text[:300]}")
    client.patch(
        f"appScreenshots/{shot_id}",
        "appScreenshots",
        shot_id,
        {"uploaded": True, "sourceFileChecksum": hashlib.md5(data).hexdigest()},
    )
    # Processing is asynchronous; a FAILED state carries the reason (wrong
    # size, alpha channel, …) and is worth surfacing per file.
    for _ in range(60):
        state = client.get(f"appScreenshots/{shot_id}")["data"]["attributes"][
            "assetDeliveryState"
        ]
        if state["state"] == "COMPLETE":
            return shot_id
        if state["state"] == "FAILED":
            errors = "; ".join(e.get("description", "") for e in state.get("errors", []))
            raise Fatal(f"Apple rejected {path.name}: {errors or state}")
        time.sleep(2)
    raise Fatal(f"{path.name} is still processing after two minutes — check App Store Connect")


def order(client: Client, set_id: str, shot_ids: list[str]) -> None:
    response = client._http.patch(
        f"appScreenshotSets/{set_id}/relationships/appScreenshots",
        json={"data": [{"type": "appScreenshots", "id": i} for i in shot_ids]},
    )
    client._check(response, "PATCH", f"appScreenshotSets/{set_id}/relationships/appScreenshots")


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("directory", help="folder of <display>/ sub-directories of PNGs")
    parser.add_argument("--dry-run", action="store_true",
                        help="show what would be uploaded without sending it")
    parser.add_argument("--replace", action="store_true",
                        help="delete what is in each set before uploading")
    parser.add_argument("--locale", default=None,
                        help="listing locale (default: from ../store/listing.en-US.toml)")
    parser.add_argument("--bundle-id", default="app.stonechat.mobile")
    args = parser.parse_args()

    sets = plan(Path(args.directory).resolve())
    locale = args.locale
    if locale is None:
        listing = ROOT.parent / "store" / "listing.en-US.toml"
        locale = tomllib.loads(listing.read_text())["locale"] if listing.exists() else "en-US"

    env = load_env()
    client = Client(token_for(env), args.dry_run)
    app_id = resolve_app(client, env, args.bundle_id)
    version = editable_version(client, app_id)
    print(f"version {version['attributes']['versionString']} "
          f"({version['attributes']['appStoreState']}), locale {locale}"
          + (" — DRY RUN" if args.dry_run else ""))
    loc = localization(client, "appStoreVersions", version["id"], locale)

    for display, files in sets.items():
        existing_set = screenshot_set(client, loc["id"], display)
        existing = set_screenshots(client, existing_set["id"]) if existing_set else []
        by_name = {s["attributes"].get("fileName"): s["id"] for s in existing}
        print(f"\n{display}: {len(existing)} on the listing, {len(files)} local")

        if args.replace and existing:
            for s in existing:
                print(f"  - {s['attributes'].get('fileName')}")
                if not args.dry_run:
                    delete_screenshot(client, s["id"])
            by_name = {}

        if existing_set is None:
            print("  + new screenshot set")
            if not args.dry_run:
                existing_set = create_set(client, loc["id"], display)

        final_ids: list[str] = []
        for f in files:
            if f.name in by_name:
                print(f"  = {f.name} (already there)")
                final_ids.append(by_name[f.name])
                continue
            print(f"  + {f.name} ({f.stat().st_size // 1024} KB)")
            if not args.dry_run:
                final_ids.append(upload(client, existing_set["id"], f))

        if not args.dry_run and len(final_ids) == len(files):
            order(client, existing_set["id"], final_ids)
            print(f"  ordered {len(final_ids)} screenshots")

    print("\ndone" + (" (nothing sent)" if args.dry_run else ""))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Fatal as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)
