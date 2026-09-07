# Licensing

**Stonechat is licensed under the GNU Affero General Public License v3.0**
(AGPL-3.0-only). Every component — the clients, the protocol core, the relay,
the hub, the gateway — is under that one license. The full text is in
[`LICENSE`](LICENSE).

Two things are carved out, and they are the only two: the **specification**
and the **brand assets**. Both are described below.

## Why AGPL

The AGPL is the strongest guarantee available that Stonechat stays open.

Section 13 is the part that matters for a hosted service: **anyone who runs a
modified version of this software and lets people interact with it over a
network must offer those users the source of their modifications.** An
ordinary GPL lets a competitor take the code, improve it in secret, and sell
the result as a service, because they never "distribute" a binary. The AGPL
closes that.

So you can compete with Stonechat, and you can charge for it. What you cannot
do is build a closed fork, and you cannot sell a proprietary Stonechat to
companies. Improvements come back.

This is the same license Signal and SimpleX use, chosen for the same reason: a
messenger that asks you to trust it with your private conversations has no
business being unreadable.

## What this means for you

**Running it, including commercially.** The AGPL permits commercial use
without exception. Host it, sell hosting, run it inside your company — no
permission needed. If you run a *modified* version as a network service, §13
requires you to offer your users the corresponding source of your version.

**Self-hosting your own mailbox.** Nothing is triggered by running the
software for yourself. The obligation attaches when other people interact with
your modified version over a network.

**Forking.** Fork freely. Your fork stays AGPL, it must publish its
modifications, and it must not use the Stonechat name or marks — see below.

Note one practical wrinkle if you fork the mobile client: the Android build
links proprietary Google components (ML Kit for barcode scanning, Play
Services for push) that are not AGPL-compatible. A distributable fork strips
or replaces them, the way de-Googled builds of other AGPL messengers do.

**Implementing the protocol instead.** Read [`PROTOCOL.md`](PROTOCOL.md) and
build your own client from scratch. That imposes no obligation at all, and the
spec is licensed to make it easy.

**Contributing.** Contributions are accepted under the AGPL-3.0, certified
with a `Signed-off-by` line, and you keep your copyright. See
[`CONTRIBUTING.md`](CONTRIBUTING.md), which also covers whether a contributor
licence agreement is required.

## Carve-out 1: the specification

[`PROTOCOL.md`](PROTOCOL.md) is licensed **CC-BY-4.0**, not AGPL.

A copyleft software license applied to a specification document is a category
error — its terms are about source and object code — and more importantly, an
independent implementation of this protocol is something we *want*. Every
client that speaks it reaches the same directory and the same users, and a
protocol nobody else can implement is a protocol nobody can check. Build one
and attribute the spec.

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

This is the ordinary arrangement for an open source project with a hosted
service behind it, and it is what makes the AGPL safe to grant: the code is
yours to use, the name stays ours so users can tell which network they are
joining.

## Third-party dependencies

No dependency in any component is GPL, LGPL or AGPL licensed — the graphs are
permissive throughout, predominantly MIT, BSD-3-Clause and Apache-2.0. Those
licenses impose attribution obligations that survive into the shipped
binaries; [`NOTICE`](NOTICE) records them and names the tooling that generates
complete listings.

The shipped mobile apps additionally link native SDKs that are **not** open
source, notably Google ML Kit and Play Services, governed by their own terms.
