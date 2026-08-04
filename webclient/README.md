# Stonechat web client

Design and threat analysis: `notes/docs/WEB_CLIENT.md` (internal). This
README is the build record and the open decisions.

Status: **linking works; messaging does not.** A browser session can be
linked — generate its own keys, show the offer, collect the grant, verify the
certificate. It cannot talk to a relay yet (see "Blocked on").

```bash
cd ../core && cargo build --release --target wasm32-unknown-unknown
cd ../webclient && npm ci && npm run check     # typecheck, 27 tests, build
```

## Layout

| | |
|---|---|
| `src/core.ts` | the WASM binding — counterpart of `app/lib/core/core_ffi.dart` |
| `src/device.ts` | this session's keys and certificate — counterpart of `device_keys.dart` |
| `src/linking.ts` | the new device's half of the link flow — counterpart of `linking.dart` |
| `src/hub.ts` | the hub over ordinary HTTPS: the only Stonechat service a browser can reach |
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
  index.html            0.7 KB      ← the whole root of trust, readable by eye
  app.js               26.9 KB      ← pinned by SRI from the HTML
  theme.css             5.9 KB      ← pinned by SRI from the HTML
  stonechat_core.wasm  558.5 KB     ← integrity-fetched, hash compiled into app.js

  hash root  550a2261790521ef147e72a679fd732d25e33125623da2a7a8f855d245a90567
```

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
2. ~~Address discovery.~~ **Done.** `server.wt_address` in the directory;
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

## The slim client

`src/protocol.ts` + `src/ui.ts`: a conversations list, a chat screen, and text
messages in both directions. Nothing else — no groups, media, receipts, calls,
edits or self-sync. About 400 lines against `chat_state.dart`'s 4,000, but the
protocol parts are identical and have to stay identical: envelopes sealed to a
device's certified key, the AEAD binding both device numbers in one form, a
peer's certificate checked against the identity key their SC- ID commits to,
prekeys signed by the device and published with its certificate.

**Fan-out is not optional even here.** A web session is device 2 or later, so a
reply that only went to device 1 would never reach the browser it was
answering. Which devices exist comes from the peer's bundle token, which rides
every envelope; without one we reach their primary only, exactly as a
stranger's first message does.

**What is stored** (`src/store.ts`): device keys, the grant, ratchet state and
peer certificates — the ratchet especially, because a peer who has advanced
their chain cannot rewind it, and losing it breaks the conversation permanently
rather than losing one message.

**Message history too, capped** (2026-08-04). This reverses WEB_CLIENT.md's
"no history sync; history stays on the phone", and the reversal is a real
tradeoff rather than an oversight. Before: a compromised browser session
yielded *messages during that session*. Now: what the browser has seen, up to
`MAX_MESSAGES_PER_CONVERSATION` (200). The certificate bounds what a session
can **do**, not what is sitting on disk, so the cap and the Unlink button are
the only things bounding this.

Deliberately no encryption at rest: any key the page could decrypt with would
live in the same storage, readable by exactly the same attacker. It would look
like protection and be none.

The reason it changed is worth recording too — a client that forgets every
conversation on refresh is defensible on paper and unusable in practice, which
makes it untestable, which makes it undeployable.

## Still missing

Groups, media, receipts, typing, calls, edits, reactions, disappearing
messages, self-sync, history bootstrap, QR *rendering* (the offer is a paste
string), and retry — a send that fails reports the error and puts the text
back in the composer rather than queueing.

Also unbuilt: QR *rendering* (the offer is shown as a paste string, which
MULTIDEVICE.md allows as the fallback), and storage — there is no SQLCipher in
a browser, and the tethered shape says no history at all, which makes that
smaller than it looks.

## Decisions

### 1. Does the web device hold the shared identity key? — **settled 08-03: no**

Resolved by building it. Device certificates landed across the core, relay and
client, and all three roles the identity used to play (unsealing, prekey
signing, PQXDH) now run on per-device keys. Linking hands over a certificate,
not the root. A browser session is a `web`-kind device with a **7-day**
certificate it cannot renew.

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

- **WebTransport endpoint on the relay** (`serverCertificateHashes`, option B
  in WEB_CLIENT.md) — the largest remaining unknown, and relay work rather
  than client work.
- **Silent cert rotation** — WebTransport caps certificate validity at 14
  days, which makes the batch pre-signing scheme load-bearing rather than
  optional.
- **Storage** — no SQLCipher in a browser. The tethered shape says no history
  at all, which makes this smaller than it looks.
- **CORS on the relay** (there is none) and moving `?token=` out of the query
  string.
