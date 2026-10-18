# stonechat-agent

A headless Stonechat **device**, not a bot with its own account.

It links exactly the way a second phone or a browser tab does — the owner
authorises it from their primary — and then speaks the protocol through
`stonechat-core`, the same crate the Flutter app calls over FFI. What makes it
an *agent* is only that nobody is sitting at it: no screen, no camera, no user,
usually a server rather than a pocket.

What it says is deliberately dull: one of ten canned sentences. The point is
to be a device the phone can live with — one that links, stays certified,
knows who the owner's contacts are, receives, decrypts, ratchets, answers,
and tells the phone what it said. `src/replies.rs` is where anything cleverer
goes.

## Read this before you deploy one

**An agent shares its owner's identity.** Three consequences, none of them
obvious from the outside:

1. **It is not a contact.** You cannot add it and chat with it. To everyone
   else it *is* you; there is no separate SC- ID and no thread. If what you
   want is someone to talk to for testing, you want `scripts/echo_bot.py`,
   which is a separate identity, not this.
2. **A reply it sends is a message from you.** One of your contacts messages
   you, this program answers in your name, on your identity, to your contact
   — and the answer shows up on your phone as something you said.
3. **It sees what is addressed to you.** Every envelope for this device
   decrypts here. That is what makes an agent useful and it is also the whole
   of its exposure: a server holding this state file is a server that reads your
   mail until the device is revoked.

## Why this is safe to put on a server at all

Because since device certificates (2026-08-03) **the identity secret does not
travel**. This device holds its own signing and seal keys plus a short public
statement, signed by the primary, that they are its owner's. It cannot mint or
renew a certificate (its own included), sign its mailbox's TLS fingerprint,
recover or export the identity, or manage or destroy the mailbox — there is no
hub account token in a link grant.

So a stolen agent is bounded by exactly one certificate, which the owner can
revoke immediately from the phone — and since the device manifest
(2026-10-14), a revocation is something every contact can check for
themselves, not only a queue deleted on the mailbox. Before certificates this
idea would have required copying an identity root onto a rented VM, which is
indefensible.

## Build

```bash
cd agent_client
cargo build --release        # → target/release/stonechat-agent
```

One static-ish binary, no Python, no repo checkout at runtime. It links
`stonechat-core` as a crate rather than through the C ABI — that ABI exists for
Dart, Swift and wasm hosts, and a Rust host has no reason to marshal through
it.

## Link

On the server, with `$STONECHAT_HUB` set (default `https://hub.stonechat.app`):

```bash
stonechat-agent link          # --no-qr for the line only
```

It prints a scannable QR (when a terminal is watching) and, underneath it, the
102-character code as plain text:

```
  stonechat-link:AkP8x21haE9q26tKlECJfxJS6jjFSOn7amrm3Q3HTfRSD2eiBB0M3rz…
```

On the phone that holds the identity, open **Linked devices** and either
**Link a device** to scan the terminal, or **Paste a code instead** for the
line. Then choose **Agent**.

Both are printed because both fail in different places: a camera cannot help
you through a multiplexer that eats escape codes or a window too small to hold
the code, and a clipboard cannot help you when the phone is the only thing in
reach. The QR is rendered as half blocks (one cell is two modules tall, which
cancels the terminal's ~2:1 cell ratio) with colours forced black-on-white, so
polarity does not depend on your theme.

The direction is what makes any of this work. In the link flow the *new* device
displays and the *existing* one reads, so a machine with no screen is fine —
and since 2026-08-04 the code carries a 32-byte commitment instead of the keys
themselves, which is why it fits a terminal at all. The old form carried a
1216-byte X-Wing key and ran to ~2360 characters.

`link` exits once it has collected the grant, made its three checks, and
published prekeys. One command leaves a device that can actually be reached.

**It knows nobody yet.** The next time the phone connects to the mailbox and
finds the new device listed with prekeys, it sends it the contact list
(`sync_history`). Until that has happened, every message is from a stranger
and gets no answer. Opening the app once after linking is enough.

## Run

```bash
stonechat-agent run               # holds the socket, answers contacts
stonechat-agent run --show-text   # also logs message text (see below)
stonechat-agent status            # what this agent is, when its certificate lapses
stonechat-agent forget            # deletes local state — does NOT revoke
```

`forget` is named that way because it does not unlink anything: the device row
and its certificate live on the mailbox and in the directory, and only the
primary can revoke them. Revoke on the phone.

**The log carries no message text** unless you ask for it with `--show-text`
(or `STONECHAT_AGENT_SHOW_TEXT=1`). A container's stdout is kept by the host,
and the owner's mail does not belong in it; by default a message is logged
as who sent it and how long it was.

## What it does

As a device of its owner's identity it behaves the way the phone expects a
linked device to:

- **Answers accepted contacts only.** It learns who those are from the phone
  — the `sync_history` export after linking, then `sync_contact` and
  `sync_block` for every change — and never decides for itself. A stranger's
  message is decrypted (which keeps the ratchet current) and otherwise
  ignored: no reply, no receipt, nothing that says an agent is running. A
  blocked sender is ignored too. A contact the phone removes loses their
  sessions here as well, as the protocol says.
- **Mirrors what it said.** Every reply goes to the owner's other devices as
  `sync_sent`, so the phone's transcript shows the answer where it belongs.
  A contact's message gets a `delivered` receipt, like from any device.
- **Stays certified.** The phone renews a linked device's certificate over
  `sync_cert` while the device is still listed; the agent adopts one that
  verifies, names its own slot and keys, and is later than the one held,
  then republishes its prekeys under it.
- **Checks the sending device on every envelope**, not only when a session
  begins: its certificate must be unexpired (an expired one is refetched
  from the sender's mailbox, and the envelope dropped if nothing newer is
  published), and when the sender has published a device manifest the
  device must be on it with that certificate's key. It encrypts only to
  devices a peer's manifest lists, and states its own identity's manifest
  version on everything it sends.
- **Checks what arrives where it enters**: the inner envelope's id must be
  a UUID and equal the id on the wire, it must be addressed to this identity
  and this device, both device numbers must be present, and a directory
  answer is checked against the ID that was asked for.
- **Leaves an envelope queued** rather than acking it when handling failed
  because the hub or a mailbox could not be reached, and drops it — acked —
  when the envelope itself is the problem. A transient failure is retried
  across a few connections, then given up on, so one dead sender cannot hold
  the queue behind it.
- **Republishes its prekeys on every connect** with the full remaining
  stock, rotating the signed prekeys weekly (keeping the previous pair for
  handshakes in flight), so a fresh or recreated mailbox converges on what it
  holds.

## Deploying

As a container. `Dockerfile` builds the static binary into an otherwise empty
image (it builds from the repo root, because it links `../core`), and
`docker-compose.yml` runs it. Link interactively first — `link` needs someone
holding the phone — then start it:

```bash
cd agent_client
docker compose run --rm agent link     # QR + code; exits once linked
docker compose up -d
docker compose logs -f                 # the log is the whole interface
docker compose run --rm agent status   # when the certificate lapses
```

It runs as an unprivileged user with a read-only filesystem, no capabilities
and **no inbound ports** — it dials the hub and its own mailbox — so it adds
nothing to the host's exposure. The state file lives in the `state` named
volume: `docker compose down` keeps it; `down -v` deletes it, which is `forget`
and, like `forget`, revokes nothing.

If the phone revokes the device, `run` exits with a sentence saying so rather
than reconnecting forever; the same if another connection takes the device
over, which means two copies are running against one state file.

Where: a machine you control. **Not the hub server** — the hub holds the directory
and provisioning credentials and its whole security story is one port with no
extra tenants. And not a server that hosts
other people's mailboxes: whatever holds this state file reads your mail.

## What it holds, and how well

| | |
|---|---|
| `~/.stonechat/agent.json` (or `$STONECHAT_AGENT_STATE`; `/state/agent.json` in the container) | device keys, certificate, device token, ratchet sessions, cached peer certificates, the owner's contacts and blocks, device manifests |
| mode | `0600` from the first byte, written atomically via temp-and-rename |

A phone keeps this in a keystore; here it is a file. That is a real downgrade
and worth stating rather than implying away. What bounds it is scope — no
identity secret is in there — and revocation, which is immediate.

The atomic write is not tidiness. The double ratchet advances on every
message, and a half-written state file is a device that has lost track of
which message keys it has already used.

## Certificates: 14 days, renewed by the phone

An agent's certificate lasts **14 days** (`app/lib/core/device_keys.dart`,
`agentCertLifetime`), like any linked device's. Only the primary can renew
it, and it does: on every connect to the mailbox the phone re-signs the
certificate of any listed device with less than seven days left and sends it
over `sync_cert`. So an agent stays certified for as long as the phone opens
the app at least once a week and the device is still listed.

When it lapses anyway — the phone was off for a fortnight, or the device was
revoked — peers *refuse to encrypt to this device*. Correct behaviour, and a
silent one: the agent simply stops receiving. `run` warns on startup and on
every reconnect once it is inside three days (the phone would have renewed by
then, so the warning means "open the app"), and `status` prints the date. If
the device is gone from Linked devices, re-linking is the only renewal:
`forget`, then `link` again.

## Known gaps

Real absences, not oversights.

- **No media, no groups, no calls.** `media` from a contact is answered like
  text, but the attachment is never fetched. Group, call, typing, reaction,
  edit and pin envelopes are decrypted (which keeps the ratchet current) and
  otherwise ignored.
- **No history.** It keeps no messages, so `sync_sent`, `sync_read` and
  `sync_clear` from the phone have nothing to apply to. It starts with the
  contacts in the phone's export and learns only what arrives after.
- **No contact handling.** A `contact_request` is logged and left alone, and
  a `contact_accept` is applied only once the phone says so over
  `sync_contact`. Accepting adds a contact to the identity on every device,
  and that is the phone's decision.
- **No push config.** It holds its socket, so it never needs the gateway.
- **No read receipts, no typing.** Nobody is reading or typing.

## Testing

```bash
cd agent_client && cargo test             # unit tests
cd agent_client && cargo build --release
cd ../relay && cargo build --release
../scripts/build_core.sh host             # the Python side's KEM
hub/.venv/bin/python agent_client/tests/e2e_agent.py
```

A live run against a live hub and two live mailboxes, no Docker. The primary is
simulated with `scripts/e2e.py`'s `Phone` — the reference implementation the
Dart client must interoperate with — so what it proves is that this Rust agent
and the Python reference agree on the wire: offer, commitment, grant, the three
checks, PQXDH against a certified device key, a ratchet that advances
identically on both sides, and then the device behaviour around it — a
stranger gets no answer, a contact learned over `sync_history` does, the
answer is mirrored to the primary as `sync_sent` under the same message id, a
renewed certificate arrives over `sync_cert` and is republished, a device the
sender's manifest does not list is dropped, and a contact the phone removes
is a stranger again.
