# Licensing

**Stonechat is licensed under the GNU Affero General Public License v3.0**
(AGPL-3.0-only). Every component — the clients, the protocol core, the relay,
the hub, the push gateway — is under that one license. The full text is in
[`LICENSE`](LICENSE).

Two things are carved out, and they are the only two: the **specification**
and the **brand assets**. Both are described below.

## Why AGPL

Section 13 is the part that matters for a hosted service: **anyone who runs a
modified version of this software and lets people interact with it over a
network must offer those users the source of their modifications.**

You cannot build a closed fork, and you cannot sell a proprietary Stonechat to
companies.

This is the same license Signal and SimpleX use, chosen for the same reason: a
messenger that asks you to trust it with your private conversations has no
business being unreadable.

## What this means for you

**Running it.** Host it, run it inside your company, host it for your family, for your friends: no
permission needed. If you run a _modified_ version as a network service, §13
requires you to offer your users the corresponding source of your version.

**Self-hosting your own mailbox.** Nothing is triggered by running the
software for yourself. The obligation attaches when other people interact with
your modified version over a network.

**Forking.** Fork freely. Your fork stays AGPL, it must publish its
modifications, and it must not use the Stonechat name or marks — see below.

Note one practical wrinkle if you fork the mobile client: the Android build
links a proprietary Google component (Play Services, for push) that is not
AGPL-compatible. A distributable fork strips or replaces it, the way
de-Googled builds of other AGPL messengers do.

**Implementing the protocol instead.** Read [`PROTOCOL.md`](PROTOCOL.md) and
build your own client from scratch. That imposes no obligation at all, and the
spec is licensed to make it easy.

**Contributing.** Contributions are accepted under the AGPL-3.0, certified
with a `Signed-off-by` line, and you keep your copyright. See
[`CONTRIBUTING.md`](CONTRIBUTING.md), which also covers whether a contributor
licence agreement is required.

## Carve-out 1: the specification

[`PROTOCOL.md`](PROTOCOL.md) is licensed **CC-BY-4.0**, not AGPL.

## Carve-out 2: brand assets

The **name "Stonechat", the logo, and the bird mark are trademarks of
GazelleLabs LLC**, and no license in this repository grants any right to use
them. This explicitly includes the image files in the repository:

- `app/assets/logo/`
- `app/assets/icon/`
- `app/android/app/src/main/res/mipmap-*/ic_launcher.png` and `launch_image.png`
- `app/ios/Runner/Assets.xcassets/AppIcon.appiconset/` and `LaunchImage.imageset/`

These are present so the official app builds from a clean checkout. They are
**not** covered by the AGPL and are not yours to redistribute.

You may state accurately that your software is derived from, based on, or
compatible with Stonechat. You may not name your fork, service, or application
"Stonechat", brand it with these marks, or present it as the official
Stonechat client, service, or network. **Rename your fork and use your own
icon.**

## Third-party dependencies

No dependency in any component is GPL, LGPL or AGPL licensed — the graphs are
permissive throughout, predominantly MIT, BSD-3-Clause and Apache-2.0. Those
licenses impose attribution obligations that survive into the shipped
binaries; [`NOTICE`](NOTICE) records them and names the tooling that generates
complete listings.

The shipped mobile apps additionally link native SDKs that are **not** open
source, notably Google Play Services, governed by its own terms.
