# Web client (assessment)

Status: **chosen (2026-08-01), ahead of a desktop port.** This began as an
assessment of whether a browser client was defensible at all; the analysis
below stands unchanged and is now the plan. Browser reach is the
differentiator — Signal has no web client — and the cost is accepted with
eyes open: everything in the "three blockers" and "code-delivery problem"
sections is still true, which is exactly why the shape is a tethered,
ephemeral, revocable device rather than a full peer.

Sequencing: multi-device phase 2 (per-device client) → linking → this.

Bottom line: a web client is buildable, but three deliberate Stonechat
design choices are hostile to browsers, and the web's code-delivery model
is a trust regression that no amount of signing can paper over. The
defensible version is a **tethered, ephemeral device** — identity key
stays on the phone, sessions are QR-granted and revocable via the user's
own mailbox. Desktop (native Flutter) needs the same multi-device work and pays none of
these costs — it was the safer first target and was deliberately deferred
behind this one.

## The three blockers

1. ~~**The TLS model cannot exist in a browser.**~~ **Solved relay-side
   2026-08-03** — see `relay/src/wt.rs`, `relay/src/wtcert.rs`, and the
   end-to-end test in `relay/tests/webtransport.rs`, where a client holding
   *only* a SHA-256 from `/wt/certs` — no CA, no trust store — drains a real
   queue. WebTransport's `serverCertificateHashes` turned out to be the same
   trust model Stonechat already had, with a different hash (SHA-256 of the
   DER, not BLAKE2b) and a 14-day validity cap. The cap is answered by running
   ahead: a schedule of twelve certificates covering ~5 months, all hashes
   published, rotation in place via `reload_config` so live sessions survive.
   The **owner signs the schedule** (`stonechat-v1-wtcerts` over a canonical
   length-prefixed form; hub `POST /v1/mailbox/wt`; directory serves list and
   signature together or neither), the web client refuses to pin anything
   unsigned, and the **address is published** as `server.wt_address` — not
   derivable, because container providers map a random host port per mailbox.
   The **whole HTTP surface** is carried too — one bidirectional stream per
   request, dispatched into the relay's existing `axum::Router` so no route is
   implemented twice. Nothing about the transport is outstanding; what remains
   is the client application itself. The original analysis follows.

   **The TLS model cannot exist in a browser.** Every relay connection
   uses a self-signed cert on a bare IP, validated by fingerprint against
   the hub directory (api.dart `badCertificateCallback`, PROTOCOL.md
   "Transport": clients MUST NOT use CA validation). Browsers expose no
   API to accept a self-signed cert or pin a fingerprint — `fetch()` and
   `WebSocket` simply refuse. This is a platform limit, not a code gap.
   Fixing it means either per-relay hostnames + CA-issued certs
   (abandoning the "no CAs, no domains" stance) or a CA-free browser
   transport — see "Keeping relays CA-free and domain-free" below.
   Note: E2EE survives that change — envelopes are sealed to the identity
   key from the directory, so a MITM'd relay connection leaks metadata and
   can drop messages but cannot read content. Pinning is defense-in-depth;
   it is also the part the web physically cannot honor.

2. **A web client is a second device, and multi-device doesn't exist.**
   `OwnerLink` allows one live owner WS (a second kicks the first), rows
   die on ack, sessions are keyed by `peer_id` only. Everything in
   MULTIDEVICE.md (per-device queues, prekey pools, tokens, link grants)
   is a prerequisite. That is the bulk of the work — and it is the same
   work desktop needs.

3. **The browser is a bad place for long-lived secrets.** Today: identity
   key in Keychain/Keystore, history in SQLCipher. Web equivalents are
   IndexedDB/localStorage — readable by any XSS, any extension, anyone at
   the keyboard. WebCrypto non-extractable keys don't help: the
   Ed25519/X25519 ratchet math runs in WASM and needs raw key bytes.

Smaller, fixable items: the Dart `sodium` package has a web backend; relay
has no CORS at all and the hub allows GET-only from the landing origin;
the `?token=` query param should move to a header/subprotocol for any
browser story.

## The code-delivery problem (why Signal has no web client)

An installed app is a signed artifact obtained once. A web app is
re-fetched from its origin on every load — so whoever controls the origin
(or coerces its operator) can serve *one targeted user* a modified client
that exfiltrates keys: one page load, invisible to everyone else. That
silently converts E2EE into "encryption until the server decides
otherwise." No user can verify the JS they just received is the JS
everyone else got.

Signal's answer is Signal Desktop (Electron): installed, signed, updated
through an auditable channel. Meta's answer for WhatsApp Web is the Code
Verify browser *extension*, which attests the served JS against a
published hash from outside the page — heavy machinery to partially
recover what installed apps get for free.

**"Download once" is not enforceable on the web.** A PWA's service worker
is re-fetched from the origin on the browser's schedule (≤24h stale, per
spec, ignoring caches) and whatever the origin serves replaces the
installed code. There is no web API for "pin this version" or "only
accept updates signed by key X." Trust-wise, every day is a fresh install.

**Phone-signed bundles don't close the loop.** Tempting scheme: the phone
signs a known-good web bundle, parks it in the user's mailbox, and a
loader page fetches + verifies + executes it. But the loader itself comes
from an origin — the very party being defended against — which can serve
a targeted loader that skips the check (or passes it, then also
exfiltrates). The general law: **a signature only helps if the verifier
lives outside the delivery channel being attacked.** Every purely-in-page
scheme reduces, after a hop or two, to "trust the origin on every load."
Only an installed verifier (extension, native app) breaks the loop.
Serving the bundle from the mailbox instead of a central origin changes
nothing — and is blocked outright today by blocker 1.

**Subresource Integrity: use it, but know what it buys.** SRI
(`integrity` attrs on `<script>`/`<link>`, plus `fetch(url,
{integrity})` for the WASM) makes the browser refuse any resource whose
hash doesn't match. Its designed threat is a compromised CDN/third-party
host — MDN is explicit it does NOT protect against a compromised
first-party origin, and it never covers the HTML document itself. Same
verifier-inside-the-channel law: the hashes ride in the HTML, and the
HTML comes from the origin, so a coerced origin serves modified HTML
with matching hashes and every check passes. Still worth doing, for two
reasons: (1) it shrinks the root of trust to one small file — tiny
index.html → SRI-pinned JS → integrity-fetched WASM means the entire
attack surface is one human-readable file; (2) that makes external
attestation practical — reproducible builds + a single hash-root file
lets anyone (monitoring, a future Code-Verify-style extension, curl)
verify the served app by checking one tiny file against the published
release. Targeted attacks stay possible but become far more detectable.
Caveat: service-worker scripts are not SRI-coverable — skip the service
worker entirely (the web client is live-only anyway) so the HTML+SRI
chain is the whole delivery story.

**"What about a signed WASM binary?"** Doesn't change the trust
position. Browsers have no code-signing for web content — a signature
on the .wasm is bytes the browser ignores, and whoever would check it
in-page arrives over the attacked channel (the law, again). Nor does an
attacker need to patch the binary: WASM can't reach DOM/network/storage
directly, so every key and plaintext crosses a JS import boundary — a
ten-line hook on the untampered module's imports exfiltrates
everything. Compiled opacity helps auditors less than it helps anyone.
What IS real in the idea: a **public append-only registry of release
hashes** (sigstore/binary-transparency pattern). It turns verification
into "is my hash the one the whole world sees?" — spot-checkable with
curl, makes targeted serving publicly provable if caught, and is the
missing half of the attestation extension (extension checks served hash
against the log; that combination does close the loop for those who
install it). Rust→WASM helps only as build hygiene: one reproducible
artifact strengthens the single-hash-root story above.

**"Can the phone replace the extension as verifier?"** No — and the
reason refines the law. A working verifier needs BOTH: (1) delivery
outside the attacked channel, and (2) read access to what actually
runs. The in-page checker fails (1); the phone fails (2). The extension
uniquely has both (store-delivered + privileged visibility into loaded
scripts). Any "browser sends an attestation to the mailbox with each
message" scheme is self-attestation from the very code under suspicion:
malicious code replays the honest report (embed the clean bundle's hash
as a constant). No protocol fixes this without hardware-measured
execution, which browsers don't expose to pages. What the phone CAN do:
- **Out-of-band probing**: periodically fetch the webapp origin and
  compare the hash-root HTML against the transparency log. Catches
  broad compromise immediately; squeezes targeted serving (phone often
  probes from the same IP as the laptop — attacker must distinguish
  clients behind one NAT, and getting caught is publicly provable via
  the log). Detection + deterrence, not prevention.
- **Authority monitoring**: the relay sees the web device's real
  activity (queue drains, prekey fetches, blob pulls) — evidence
  generated by owned infrastructure, not self-reported, so malicious
  code can't forge it. Phone surfaces it ("web: 14 msgs today, last
  active 2 h ago") and alarms on anomalies (bulk prekey fetches,
  activity while the laptop should be closed). Option for send-side
  visibility: route web-device outbound through the own relay as a
  forwarder (costs a hop, enables outbound display and caps).

Hierarchy: **the phone detects and contains; only an installed verifier
prevents.** Probing + transparency log + bounded sessions make the
extension a later nice-to-have, not a launch requirement.

(Edge case for completeness: a single-file HTML build the user downloads
once and opens from disk really is delivered once — but that's an
installed app with worse storage, worse UX, and CORS headaches. The
exception proves the rule: the fix for web code delivery is to stop being
the web.)

## The defensible shape: tethered, ephemeral device

If the browser code can't be made trustworthy, make it **not worth
attacking**. Original-WhatsApp-Web model, and the per-user mailbox is a
better substrate for it than a central session broker:

- The identity key never leaves the phone.
- The browser generates an *ephemeral* keypair and shows a QR; the phone
  scans and authorizes it via a link-grant envelope parked on the user's
  own mailbox (close kin to MULTIDEVICE.md's link flow) — as a
  short-lived, limited device: own relay queue, own token, an expiry, a
  kill switch on the phone.
- The web session ratchets with its own ephemeral keys via per-device
  fan-out (or, stricter, the phone proxies and the browser is a display).
- No history sync; history stays on the phone. **Amended 2026-08-04**: the
  browser now keeps the last 200 messages per conversation, because a client
  that empties every conversation on refresh is unusable and therefore
  untested. The exposure grows from "messages during this session" to "what
  this browser has seen, capped" — bounded by the cap and erased by Unlink.
  History *sync* is still absent: the browser only keeps what passed through
  it, and never fetches the phone's backlog.

Attack walkthrough: a coerced webapp origin serves malicious JS. It gets
the ephemeral session key — messages *during that session, until
revoked*. It cannot steal the identity, impersonate durably, or read
history, and the phone shows "web session active" throughout. This
converts "one page load = total permanent compromise" into "one page
load = bounded, revocable, visible compromise."

The mailbox's real contribution is delivering **authority**, not code:
link grants, session revocation, per-device queues.

## Keeping relays CA-free and domain-free

If we refuse CA certs and domains on relays, the browser TLS blocker has
real workarounds — change the *transport*, keep the trust model:

- **A. WebRTC DataChannel to the relay** (works in every browser today).
  WebRTC never uses CAs: DTLS verifies the peer cert against the
  fingerprint exchanged in signaling — natively the Stonechat model.
  Browser sends an SDP offer via a signaling path (the hub is natural:
  real cert, already the directory); relay answers with its fingerprint;
  result is an encrypted, fingerprint-pinned channel to a bare IP. To
  keep the hub un-MITM-able, the relay signs its SDP/fingerprint with
  the owner-published key — same anchor as today. The relay already
  mints TURN creds and the app already ships WebRTC for calls; relay
  side needs aiortc (Python) / webrtc-rs or str0m (Rust). Public relay
  IPs mean NAT is a non-issue.
- **B. WebTransport `serverCertificateHashes`** (purpose-built for
  this). The page says "accept the cert whose SHA-256 hash is X" — no
  CA, no domain, no SAN. WebTransport is Baseline as of Safari 26.4
  (March 2026) — current Chromium, Firefox, and Safari all ship it;
  the gap is only not-yet-updated devices. Spec constraints: SHA-256
  hash, cert validity ≤14 days (rotation — solvable silently, see
  below), ECDSA P-256 key (the relay's rcgen cert already is one).
  No fallback when UDP is blocked.
- **C. Blind tunnel gateway + TLS-in-WASM.** A dumb forwarder
  (gw.stonechat.app, real cert) shovels bytes between a browser WebSocket
  and the relay's TCP port; the page runs a WASM TLS client doing the
  exact pinned handshake inside the tunnel. Gateway sees only TLS
  ciphertext — can drop, cannot read or impersonate. Preserves current
  TLS byte-for-byte; costs a heavy WASM stack and a central
  availability chokepoint.
- **D. Terminating gateway.** Same gateway but it terminates the pinned
  TLS and re-serves under its CA cert. Simplest; sealed E2EE keeps
  content safe, but the gateway sees ciphertext, timing, and
  who-talks-to-which-relay, and is MITM-capable. Only acceptable with
  eyes open about the metadata regression.
- **Half-option: Let's Encrypt IP certs** (short-lived, ~6-day profile)
  — kills the domain requirement while keeping a CA. Helps only if the
  objection is to domains, not CAs.

**Cert rotation without user interaction (for B).** What rotation needs
every ≤14 days: relay makes a new cert, the owner identity key signs its
fingerprint, hub directory updates. The user is not inherently in that
loop — only the phone is. Design: the relay pre-generates its next cert
and hands the fingerprint to the phone over the authenticated owner
channel; the phone signs it *silently* — domain-separated and
context-bound (`"stonechat-v1-relay-cert" || relay_addr || fingerprint ||
not_after`) so the signature can't be repurposed — and pushes it to the
hub. Safe without a prompt: only the owner's relay can ask, a
compromised relay already controls that transport endpoint, and E2EE
means transport compromise never reads content. Offline-phone gap:
**batch pre-signing** — relay pre-generates a chain of future certs
(~6 months' worth), phone signs all fingerprints in one session, relay
publishes each as its window opens. `serverCertificateHashes` takes an
*array*, so the client passes current + next and rollover is seamless.
Do NOT solve rotation with a recurring "yes, rotate" push or QR — it
trains reflexive approval and breaks when missed. Reserve user presence
for what deserves consent: linking a web session (QR grant) and
revocation.

Ranking: **B is the front-runner** (Baseline browser support since
March 2026, silent rotation per above, no signaling middleman, cleaner
pinning, simpler server stack); A is the fallback for UDP-blocked
networks (TURN/TCP-443) and stale browsers; C/D only to avoid touching
the relay. All of these fix transport only — the code-delivery analysis
above is unchanged.

## End-to-end: how the WebTransport web client would work

Composes the tethered-device shape with transport option B.

**The static app.** webapp.stonechat.app serves a static, open-source,
reproducibly built bundle: UI + libsodium WASM. No accounts, no
database, no server logic — a dumb file server. The code-delivery
caveat applies to this origin; that is exactly why nothing durable
lives in the browser.

**Linking.** The browser generates a fresh ephemeral keypair and shows
a QR of its public key. The phone scans it and: (1) tells the relay to
create a **web device** — own queue, own device token, an expiry;
(2) builds a **link grant** sealed to the browser's ephemeral key:
relay IP, device token, current + next cert SHA-256 hashes, expiry,
contact snapshot (names/keys, no history); (3) drops the grant at a
rendezvous the browser can reach — the hub is the natural dead-drop
(real CA cert; the grant is opaque to it). The browser polls, decrypts,
and now knows how to reach the mailbox. The QR solves the bootstrap
chicken-and-egg: the browser can't connect before knowing the cert
hash, and the hash arrives inside the grant.

**Connecting.** `new WebTransport("https://<relay-ip>:port/wt",
{serverCertificateHashes: [current, next]})` — direct browser→mailbox,
bare IP, self-signed cert, the existing trust model. Authenticates the
stream with the device token, drains its per-device queue. Rotation is
invisible (hash array spans the rollover; fingerprints re-fetched on
reconnect).

**Sending/receiving.** The web device is a *real* device in the
MULTIDEVICE.md sense, not a mirror: it runs X3DH against peers'
per-device bundles, keeps its own ratchet sessions in memory, and posts
sealed envelopes to peers' relays over WebTransport (cert hash from the
peer's signed directory entry), one copy per peer × device. Incoming
mail arrives because senders encrypt a copy for the web device's queue.
Consequence: **the phone does not need to be online** for the web
client to work — it is needed only at link time and for revocation.

**What the browser never has.** The identity key (phone only — the web
device's keys are its own, authorized by an identity-signed grant),
history (nothing before link time), anything after expiry/revocation
(revoke deletes queue + token at the relay; contacts drop the device on
next bundle refresh). Maximum yield of any attack on the web app:
messages flowing during that session's lifetime.

**User's-eye view.** Visit webapp.stonechat.app → QR, no login. Phone:
Settings → Linked devices → Link a web session → scan → one consent
card ("sends and receives as you; expires after 7 days unused, 30 days
max; no history; end it anytime") — the only prompt the user ever
sees. Chats
appear with contacts intact but conversations empty, filling from link
time forward ("web sessions don't carry history — your history lives
on your phone"). Works with the phone dead in a bag. Phone shows a
persistent indicator ("Web session active · MacBook · last used
today · expires Aug 25") with an End-session button — revocation kills the tab within
seconds; doing nothing lets the session lapse at expiry, and the next
visit shows the QR again. Relinking is ten seconds, and that friction
is the feature: a forgotten library-computer login can't outlive the
timer. Don't confuse the two timers: cert rotation (≤14 d) renews
itself silently because approving it means nothing; the session expiry
deliberately does NOT auto-renew on its own, because it is the
mechanism that bounds a web-app compromise — unconditional auto-renewal
would collapse "bounded, revocable, visible" back into "permanent."

**Expiry policy (decided): sliding window with a hard cap.**

- **Idle timeout** (default 7 d): each day of active use pushes expiry
  out again, so a daily-driver laptop never nags; any browser left
  unused dies within 7 d of last activity. "Active use" = the web
  device authenticating to its own queue, which the relay observes
  directly — the browser cannot self-extend without actually being
  used.
- **Hard cap** (default 30 d): the session ends at the cap regardless
  of activity, requiring a fresh QR. This bounds a
  compromised-but-active session, which sliding expiry alone would
  keep alive indefinitely.
- **Configurable per device** from the phone's linked-devices screen:
  idle timeout (1–14 d), hard cap (1–90 d), and a **strict mode**
  (hard expiry only, no sliding — for the hardcore/untrusted-ish
  machines). Defaults 7/30; the phone is the only place these can be
  changed — the web client can read its own expiry but never set it.
- Enforcement lives on the **relay** (it deletes the device queue +
  token at expiry), not in the web client; a malicious page can't
  ignore it. Revocation from the phone overrides everything, always. Two rough edges the UX owns honestly: no notifications when the
tab is closed (web is live-only; the phone still gets everything), and
a link-time warning — "only link browsers on computers you trust" —
because no protocol fixes a keylogger on the machine you type on.

## If/when we do it

1. Browser-reachable relay transport: either CA certs + per-relay
   hostnames, or — to stay CA-free and domain-free — option A/B above.
   Costs engineering, not confidentiality.
2. Implement multi-device (MULTIDEVICE.md) — needed for desktop anyway.
3. Web client as a tethered, ephemeral device per above.
4. Static, open-source, reproducibly built webapp on a central origin;
   CORS opened on the relay. Accept the residual risk knowingly: the
   origin can attack a live session, but only a live session.
5. Optionally, later: a Code-Verify-style extension for attestation.

Recommended ordering: 1–2, then ship **Flutter desktop** (same
multi-device prerequisite, none of the web compromises), and treat the
tethered web client as a later, deliberately-scoped addition — not the
flagship second client.

## Further reading

- [MDN: Subresource Integrity](https://developer.mozilla.org/en-US/docs/Web/Security/Defenses/Subresource_Integrity)
  — the `integrity` mechanism discussed in the code-delivery section:
  protects against compromised CDNs, explicitly not against the
  first-party origin.
- [Signal community: "Web app for Signal?"](https://community.signalusers.org/t/web-app-for-signal/1272/7)
  — long-running thread on why Signal has no web client. Post #7 adds an
  angle this doc doesn't dwell on: even with delivery solved, users will
  run a web client on *untrusted machines* (shared/work computers), so
  the UX must communicate "only where you trust the sysadmin" — an
  argument for the tethered model's expiry + revocation defaults.
