# Stonechat web client

Design and threat analysis: WEB_CLIENT.md (the private design notes). This
README is the build record and the open decisions.

Status: **a working second device, served at https://webapp.stonechat.app** (a
static site block in the main hub's Caddy, filled by `deploy.sh --webapp`
from `dist/`; verify a deployment with the hash root below). A browser
session can be linked — generate its own keys, show the offer, collect the
grant, verify the certificate, be filled in by the phone — and then talks to
relays over WebTransport.
It sends and receives text and attachments in direct conversations and in
groups it has been told about, with receipts, typing, edits, deletes,
reactions, replies and disappearing messages, and makes voice and video
calls over WebRTC; its own outgoing messages are
mirrored to and from the user's other devices, and the phone renews its
certificate over `sync_cert`. It makes the receive-side checks PROTOCOL.md
requires and the Flutter app makes, device manifests included. What it does
not do is listed under "Still missing".

```bash
cd ../core && cargo build --release --target wasm32-unknown-unknown
cd ../webclient && npm ci && npm run check     # typecheck, tests, build, smoke
```

## Layout

| | |
|---|---|
| `src/core.ts` | the WASM binding — counterpart of `app/lib/core/core_ffi.dart` |
| `src/device.ts` | this session's keys and certificate — counterpart of `device_keys.dart` |
| `src/linking.ts` | the new device's half of the link flow — counterpart of `linking.dart` |
| `src/hub.ts` | the hub over ordinary HTTPS: the link dead drop and the directory |
| `src/transport.ts` | the owner-signed certificate schedule → WebTransport pins; refuses anything unsigned |
| `src/mailbox.ts` | a relay's HTTP surface and owner socket over WebTransport streams |
| `src/wire.ts` | what arrives on the wire, checked where it enters — counterpart of `wire_ids.dart` and the top of `handleIncoming` |
| `src/manifest.ts` | device manifests — counterpart of `device_manifest.dart` |
| `src/groups.ts` | the group rules that are decisions: which roster to accept, roster and message hashes — counterpart of `group_rules.dart`, checked against its vectors |
| `src/protocol.ts` | sessions, per-device fan-out, the outbox, sending and receiving every type this client handles — the counterpart of `chat_state.dart` |
| `src/model.ts`, `src/store.ts` | what the browser keeps: device keys, grant, ratchets, peer certificates and manifests, prekeys, outbox, capped history |
| `src/calls.ts` | 1:1 calls: the signaling state machine over the envelope layer, WebRTC behind an interface — counterpart of `call_state.dart` |
| `src/retry.ts` | the timings shared with the app: backoff, windows, caps |
| `src/ui.ts`, `src/app.ts` | the screens |
| `src/theme.css` | the visual identity, lifted value-for-value from `app/lib/ui/theme.dart` |
| `build.mjs` | bundle → hash → SRI-pinned index.html → **hash root** |

## Why a second implementation exists at all

Worth stating plainly, because it is the main cost of the TypeScript decision
and it is smaller than it looks: **`dart:ffi` does not exist on the web.** No
framework choice lets `core_ffi.dart` be reused here. Two bindings to one core
is the floor, not something TypeScript introduced.

What genuinely does get duplicated is orchestration — the fan-out, outbox and
certificate-cache logic that is `chat_state.dart`'s 4,000 lines. Both
implementations are checked against the same reference (`relay/tests/`,
`scripts/e2e.py`) rather than against each other, which is what makes a second
client tractable.

## The build produces a hash root

This is the entire argument for hand-writing the client rather than compiling
Flutter to the web. WEB_CLIENT.md: a coerced origin can serve one targeted
user a modified client, and *nothing in-page fixes that* — "a signature only
helps if the verifier lives outside the delivery channel being attacked". What
is achievable is making the attack **detectable**:

```
  index.html            0.8 KB      ← the whole root of trust, readable by eye
  app.js              132.5 KB      ← pinned by SRI from the HTML
  theme.css             7.5 KB      ← pinned by SRI from the HTML
  stonechat_core.wasm  562.7 KB     ← integrity-fetched, hash compiled into app.js
  favicon.png           1.5 KB      ← hashed in release.json, not browser-enforced

  hash root  55e17010f349673bcf6eaf0ef24359948bdc55d5ac795e5ebb23efa11c1522d9
```

Every *executable* resource is covered: `<link rel=icon>` takes no `integrity`
attribute, so the favicon is the one served file outside the enforced chain.
Inlining it would close that, at the cost of putting 2 KB of base64 in the one
file whose entire value is being readable by eye — a bad trade for something
that cannot run. Its hash is published either way, so a verifier checking a
deployment against a release still catches a swap.

Verifying a deployment is `curl -s https://<origin>/ | shasum -a 256` against
a published release. That is what makes a transparency log meaningful, and it
is what a megabyte of compiled Dart plus a CanvasKit blob cannot offer.

No service worker, deliberately: service worker scripts cannot carry SRI, so
one would put uncoverable code in the delivery path. The client is live-only
anyway.

Three dependencies total (`esbuild`, `typescript`, and esbuild's platform
binary), both dev-only. Nothing is fetched at runtime — no CDN, no webfonts.
The landing site's Bricolage Grotesque and IBM Plex Mono are deliberately *not*
used here: every external request is one the hash root does not cover.

### The contract the binding must enforce

Fixed-size inputs (a 64-byte secret key, a 32-byte seed) carry **no length**,
so the core cannot detect a short buffer — it reads whatever follows in
linear memory and returns a confident wrong answer. Native callers get this
free from their FFI type signatures. JavaScript does not, so `fixed()` in
`core.ts` is the only place it can be checked.

Variable-length inputs do carry a length and are validated (`rc = -1`).

`stonechat_alloc` was added for this host: native callers allocate with their
own runtime, but a JS host can read and write the exported `memory` and has no
way to know which of it is free.

**`ERR_REFUSED` means two different things** and conflating them cost an
afternoon: for `unseal`, `normalize_id` and `session_decrypt` the refusal *is*
the answer and there is no output; for `devcert_verify` the call refuses **and
still writes a result**, because `expired` and `bad_signature` are refusals
whose label is the whole point. `callOut` takes `allowRefused` or
`refusalHasOutput` accordingly — never both.

## Blocked on

**The relay half landed 2026-08-03** — `relay/src/wt.rs` carries the owner
socket over WebTransport, `relay/src/wtcert.rs` runs the certificate schedule
the 14-day cap forces, and `relay/tests/webtransport.rs` proves a client with
*only* a pinned SHA-256 drains a real queue. What is left before this client
can use it:

1. ~~The owner must sign the certificate schedule.~~ **Done.** `src/transport.ts`
   refuses to pin anything the owner did not sign: identity key must commit to
   the SC- ID, schedule must verify against it, and only then are the
   unexpired entries pinnable. Truncation, reordering and tampering are all
   caught — see `test/transport.test.ts`, which rebuilds the canonical signing
   bytes independently rather than asking the core for them, so a drift
   between the four implementations fails here rather than as "the signature
   does not verify".
2. ~~Address discovery.~~ **Done.** `mailbox.wt_address` in the directory;
   `routeFor()` returns somewhere to dial alongside the pins, and
   `connectMailbox()` opens the WebTransport session with
   `serverCertificateHashes`. The address is validated before it reaches a URL
   — it arrives over the network and is unsigned, so it is the one field an
   attacker can freely choose.
3. ~~The HTTP routes.~~ **Done.** `src/mailbox.ts` carries the whole surface
   over WebTransport — one stream per request, `/ws` as an upgrade — against a
   relay that dispatches into its existing `axum::Router` rather than
   reimplementing anything.

**The transport is finished**, and a slim application runs on it.

## The client

`src/protocol.ts` + `src/ui.ts`: a conversations list and a chat screen.
Smaller than `chat_state.dart` — no calls, no backups, no contact
management, no group administration — but the *protocol* parts are the
same and have to stay the same: envelopes sealed to a device's certified
key, the AEAD binding both device numbers in one form, a peer's certificate
checked against the identity key their SC- ID commits to and again on every
envelope, the identity's device manifest deciding which devices count,
prekeys signed by the device and published with its certificate, and what
arrives checked where it enters (`wire.ts`: UUID ids, inner id equal to the
wire id, inner `to`, both device numbers present).

**What it handles.** `msg`, `media`, `group_msg`, `group_media`,
`group_create` / `group_update` (rosters, including handover),
`group_sync` and `group_leave`, `receipt`, `typing`, `msg_edit` /
`msg_delete` and their group forms, `reaction` / `group_reaction`,
`reply_to`, `timer_update` / `group_timer_update` with expiry, `contact_request`
/ `contact_accept` / `profile_update` (recorded for names and photos, not
answered), `call_offer` / `call_answer` / `call_ice` / `call_end`, and every
self-sync type: `sync_sent`, `sync_read`, `sync_clear`, `sync_block`,
`sync_cert`. Anything else is decrypted (to keep the ratchet current), acked
and dropped.

**Fan-out is not optional even here.** A web session is device 2 or later, so a
reply that only went to device 1 would never reach the browser it was
answering. Which devices exist comes from the peer's bundle token, which rides
every envelope; without one we reach their primary only, exactly as a
stranger's first message does. A bundle for a device other than 1 is fetched
with that token, as the relay requires. A device answered `410` is forgotten
along with its session.

**Retry.** A message is in the ledger, pending, before anything touches the
network. What no device accepted waits in an outbox and is retried with the
app's backoff (30 s doubling to 30 min, giving up after seven days), per
device still owed; a refusal that no retry can fix — a certificate or prekey
that does not verify, a directory answer that is not the owner's — fails at
once and says why. A manual retry resets the backoff.

**Certificates and manifests.** The certificate held for a sending device is
checked on every envelope, refetched from the sender's mailbox when it has
expired, and the envelope dropped if nothing current is served. When the
sender's identity has published a device manifest, the device must be on it
with the certificate's key; an envelope stating a newer manifest version has
it refetched first, and a mailbox listing an unlisted device has it refetched
once per run. There is no periodic refetch, as PROTOCOL.md says. This
session's own certificate is renewed by the phone over `sync_cert`: adopted
only if it verifies against the identity key, names this ID, slot and both
keys, and is later than the one held; then republished with the prekeys.

**Calls** (`src/calls.ts`) are the app's state machine, in a browser: the
offer rides a `ring` envelope to every device of the peer, the answer and
hang-up are ordinary envelopes, ICE candidates are batched into `transient`
ones; both sides give up ringing after 45 s, an offer older than 60 s is a
missed call, a second offer is answered `busy`, and when two people call each
other at once the lower Stonechat ID's offer wins. ICE servers are a public
STUN plus this mailbox's own TURN when it runs one (`/turn-credentials`,
fetched with the device token), as on the phone; either side's relay can
carry the call. Media never touches a mailbox. A call rings on every device
of the callee, this browser included; whichever answers takes it, and the
caller's eventual `call_end` quiets the rest. `getUserMedia` needs a secure
context, which the deploy target is anyway.

**Prekeys** follow the app's policy: signed prekeys rotate weekly (the
previous one is kept through one rotation so a handshake in flight against
it still completes), one-time pools of 32, the mailbox's store replaced with
what is held.

**Sessions.** A handshake that arrives over a session that no longer decrypts
replaces it (a peer who reinstalled). Two sides that start a session with
each other at once converge on the lower Stonechat ID's, and between two of
our own devices on the lower device number's; the loser's initial envelope is
dropped, as PROTOCOL.md says and as the app's `core/handshake.dart` decides.

**Contacts.** The phone's contact list reaches the browser twice over: once
at link time, in the `sync_history` the primary sends when it next finds the
new device listed with prekeys (contacts, blocks, groups and text history —
the backup payload, sealed like a media blob and parked on our own mailbox),
and then on every change, as `sync_contact` from whichever device made it. A
request can be sent, accepted or declined from here, and the phone follows.
With that list, the browser applies the phone's gates: nothing is rendered
from anyone but an accepted contact, and a group invitation is taken only
from one.

**What is stored** (`src/store.ts`): device keys, the grant, ratchet state,
peer certificates and device manifests, prekey private halves, the outbox —
the ratchet especially, because a peer who has advanced their chain cannot
rewind it, and losing it breaks the conversation permanently rather than
losing one message.

**Message history too, capped** (2026-08-04). This reverses WEB_CLIENT.md's
"no history sync; history stays on the phone", and the reversal is a real
tradeoff rather than an oversight. Before: a compromised browser session
yielded *messages during that session*. Now: what the browser has seen, up to
`MAX_MESSAGES_PER_CONVERSATION` (200). The certificate bounds what a session
can **do**, not what is sitting on disk, so the cap and the Unlink button are
the only things bounding this. Decrypted media is not kept: an object URL
dies with the tab and `localStorage` is far too small for files, so after a
reload an attachment shows as what it was; the phone holds the file.

Deliberately no encryption at rest: any key the page could decrypt with would
live in the same storage, readable by exactly the same attacker. It would look
like protection and be none.

The reason history changed is worth recording too — a client that forgets
every conversation on refresh is defensible on paper and unusable in practice,
which makes it untestable, which makes it undeployable.

## Still missing

**History bootstrap, media.** `sync_history` carries contacts, blocks,
groups and text history; attachments are not carried, and show as what they
were. The phone holds the files.

**Group administration.** Creating a group, changing its roster and handing
over admin stay on the phone: the admin owes the roster to every member's
every device until it lands, and the phone has that outbox. The browser does
answer a `group_sync` for a group it holds as admin (its phone mirrored the
roster to it), and mirrors `group_sync` to its siblings when a member shows
it is behind.

**Profile.** The browser sends the display name the grant gave it with a
contact request or accept, and no photo: the phone's profile is not synced
to it.

**`?hub=`.** Whoever writes this page's URL can choose the hub the offer is
parked on (M26). The link screen names it; a hub that is not the phone's is
a link that fails, not a compromise.

## Decisions

### 1. Does the web device hold the shared identity key? — **settled 08-03: no**

Resolved by building it. Device certificates landed across the core, relay and
client, and all three roles the identity used to play (unsealing, prekey
signing, PQXDH) now run on per-device keys. Linking hands over a certificate,
not the root. A browser session is meant to be a `web`-kind device with a
**7-day** certificate it cannot renew (see "Certificate renewal" for where
that stands).

Everything below is the reasoning as it stood before, kept because the
argument is what made the cost worth paying. The last paragraph turned out to
be the decisive one — see MULTIDEVICE.md "Revocation and threat notes", now
rewritten.

<details><summary>The original tension</summary>

The multi-device design has **every device share one identity key** — that is
what lets the outer envelope seal (to the user's single `pq_pk` in the
directory) be opened by any of them.

WEB_CLIENT.md's defensible shape says the opposite: *"The identity key never
leaves the phone"*, *"the web device's keys are its own, authorized by an
identity-signed grant"* — while also calling the web device *"a real device in
the MULTIDEVICE.md sense"*. Those cannot both hold.

- **Shared identity** — everything built works unchanged, and the web client
  is a few weeks of UI. But a coerced origin steals the identity *permanently*,
  which destroys the entire argument that a browser client is defensible. The
  doc's own threat analysis exists to avoid exactly this.
- **Per-device keys + an identity-signed certificate** — matches the threat
  model. Costs a protocol extension: per-device seal keys in the bundle, and
  peers verifying a device certificate chain.

The second is more work and strictly better, and it would also fix a
limitation flagged throughout the docs: revocation is currently *"a delivery
cut, not a cryptographic excision"*. With expiring per-device certificates,
revoking a device would actually mean something cryptographically.

</details>

### 2. Flutter web, or a purpose-built bundle? — **open**

WEB_CLIENT.md's attestation story rests on a tiny root of trust: *"tiny
index.html → SRI-pinned JS → integrity-fetched WASM means the entire attack
surface is one human-readable file"*, enabling reproducible builds and a
public transparency log of release hashes.

Flutter web emits a large opaque bundle (`main.dart.js` plus a renderer),
which fights that story badly — nobody audits a megabyte of compiled Dart,
and the hash root stops being meaningful. It also cannot reach WebTransport
or the WASM core without JS interop anyway, so the "share code with the app"
benefit is thin.

A small hand-written TypeScript app costs a UI rewrite and serves the
security argument that justifies the whole project.

## Not started

- **A transparency log** of release hash roots, which is what makes the hash
  root checkable by someone other than us.
- **Moving `?token=` out of the query string.** A WebTransport request
  carries no headers a client can set, so tokens ride in the framed `path`.

## The browser smoke test

`npm run smoke` — part of `npm run check`.

It starts a real relay, a stub hub whose CORS mirrors the real one, and a
static server, then drives headless Chrome at a page served under the
**identical CSP as the release** (`csp.mjs`, shared with the build — a smoke
test with its own relaxed policy would pass while the real page failed). In the
page it asserts, against the real modules:

| assertion | catches |
|---|---|
| `core-instantiates` | CSP `wasm-unsafe-eval`, and the WASM integrity hash |
| `hub-reachable` | CSP `connect-src`, and the hub's CORS |
| `pins-verify` | the schedule's owner signature |
| `webtransport-connects` | certificate SAN, pins, UDP reachability |
| `request-round-trips` | the stream framing |

Each was checked by reintroducing the corresponding bug and watching it fail —
including rebuilding the relay to mint SAN-less certificates again, since that
is the one no other test in this repo can see.

It skips (exit 0, loudly) without Chrome or a built relay, so it can sit in the
default check without becoming machine-specific.

### Why it exists

Every other test here runs in Node, which is structurally blind to browser
policy. On 2026-08-04 that let four bugs reach a live deployment in one day:

| bug | found by |
|---|---|
| CSP blocked WebAssembly compilation | loading the page |
| CSP blocked the hub's origin | loading the page |
| Hub CORS was GET-only from the landing origin | the hub's access log |
| WebTransport certificates had no `subjectAltName` | Chrome's DevTools, then headless Chrome |

The last is the instructive one. Rust QUIC clients skip name checks when handed
certificate hashes, so a certificate with no SAN passed the unit tests, all
three end-to-end WebTransport tests, and a live connection against production.
The tests were not weak; they could not see it.

All four are now covered by `npm run smoke`.
