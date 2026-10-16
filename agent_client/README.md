# stonechat-agent

A headless Stonechat **device**, not a bot with its own account.

It links exactly the way a second phone or a browser tab does — the owner
authorises it from their primary — and then speaks the protocol through
`stonechat-core`, the same crate the Flutter app calls over FFI. What makes it
an *agent* is only that nobody is sitting at it: no screen, no camera, no user,
usually a server rather than a pocket.

The first version answers messages with one of ten canned sentences. That is
deliberately dull; the point of v1 is to prove the device is real — that it
links, receives, decrypts, ratchets, and answers on the same session — not to
be interesting. `src/replies.rs` is where anything cleverer goes.

## Read this before you deploy one

**An agent shares its owner's identity.** Three consequences, none of them
obvious from the outside:

1. **It is not a contact.** You cannot add it and chat with it. To everyone
   else it *is* you; there is no separate SC- ID and no thread. If what you
   want is someone to talk to for testing, you want `scripts/echo_bot.py`,
   which is a separate identity, not this.
2. **A reply it sends is a message from you.** Somebody messages you, this
   program answers in your name, on your identity, to your contact.
3. **It sees what is addressed to you.** Every envelope for this device
   decrypts here. That is what makes an agent useful and it is also the whole
   of its exposure: a box holding this state file is a box that reads your
   mail until the certificate is revoked.

## Why this is safe to put on a server at all

Because since device certificates (2026-08-03) **the identity secret does not
travel**. This device holds its own signing and seal keys plus a short public
statement, signed by the primary, that they are its owner's. It cannot mint or
renew a certificate (its own included), sign its mailbox's TLS fingerprint,
recover or export the identity, or manage or destroy the mailbox — there is no
hub account token in a link grant.

So a stolen agent is bounded by exactly one certificate, which the owner can
revoke immediately from the phone. Before certificates this idea would have
required copying an identity root onto a rented VM, which is indefensible.

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

On the box, with `$STONECHAT_HUB` set (default `https://hub.stonechat.app`):

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

## Run

```bash
stonechat-agent run       # holds the socket, answers messages
stonechat-agent status    # what this agent is, when its certificate lapses
stonechat-agent forget    # deletes local state — does NOT revoke
```

`forget` is named that way because it does not unlink anything: the device row
and its certificate live on the mailbox and in the directory, and only the
primary can revoke them. Revoke on the phone.

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

Where: a machine you control. **Not the hub box** — the hub holds the directory
and provisioning credentials and its whole security story is one port with no
extra tenants. And not a box that hosts
other people's mailboxes: whatever holds this state file reads your mail.

## What it holds, and how well

| | |
|---|---|
| `~/.stonechat/agent.json` (or `$STONECHAT_AGENT_STATE`; `/state/agent.json` in the container) | device keys, certificate, device token, ratchet sessions, cached peer certificates |
| mode | `0600`, written atomically via temp-and-rename |

A phone keeps this in a keystore; here it is a file. That is a real downgrade
and worth stating rather than implying away. What bounds it is scope — no
identity secret is in there — and revocation, which is immediate.

The atomic write is not tidiness. The double ratchet advances on every
message, and a half-written state file is a device that has lost track of
which message keys it has already used.

## Certificate expiry is the thing that will bite you

An agent gets **180 days** (`app/lib/core/device_keys.dart`, `agentCertLifetime`).
Only the primary can renew, and there is no way to do it from the box. When it
lapses, peers *refuse to encrypt to this device* — correct behaviour, and a
silent one: the agent simply stops receiving.

`run` warns on startup and on every reconnect once it is inside seven days, and
`status` prints the date. Re-linking is the renewal: `forget`, revoke on the
phone, `link` again.

## Known gaps

Real absences, not oversights — v1 is scoped to "links and answers".

- **No `sync_sent`.** The agent does not mirror its replies to the owner's
  other devices, so what it said will not appear on the phone. The phone's
  transcript of that conversation has holes in it.
- **No contact handling.** A `contact_request` is logged and left alone.
  Accepting one adds a contact to the identity on every device, and a program
  guessing at that on its owner's behalf eventually guesses wrong.
- **No media, no groups, no calls, no receipts.** Those envelope types are
  decrypted (which keeps the ratchet current) and otherwise ignored.
- **No history.** It starts empty and learns only what arrives.
- **No push config.** It holds its socket, so it never needs the gateway.

## Testing

```bash
cd agent_client && cargo build --release
cd ../relay && cargo build --release
../scripts/build_core.sh host      # the Python side's KEM
python3 agent_client/tests/e2e_agent.py
```

A live run against a live hub and two live mailboxes, no Docker. The primary is
simulated with `scripts/e2e.py`'s `Phone` — the reference implementation the
Dart client must interoperate with — so what it proves is that this Rust agent
and the Python reference agree on the wire: offer, commitment, grant, the three
checks, PQXDH against a certified device key, and a ratchet that advances
identically on both sides through two messages.
