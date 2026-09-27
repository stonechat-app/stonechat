# Stonechat Protocol (v1)

The shared contract between the three components:

- **app/** — Flutter client. Holds keys and message history. The only place plaintext exists.
- **relay/** — the mailbox program. One instance per user, on a VM the user owns. Stores only sealed envelopes, deletes them on delivery. Also serves its owner's public prekeys.
- **hub/** — provisioner + directory. Maps Stonechat IDs to public identity keys and current mailbox addresses. Never sees message content.

Sessions are **forward-secret and post-quantum hybrid**: PQXDH key agreement
(X3DH + ML-KEM-768, docs/POST_QUANTUM.md) bootstrapped from prekeys served
by the recipient's own mailbox, then a double ratchet deriving a fresh key
for every message. Compromising a device's keys today does not decrypt
ciphertext recorded yesterday — the keys that produced it no longer exist —
and recording traffic today does not let a future quantum computer decrypt
it. On the wire, every envelope is additionally **sealed to the recipient**
with a hybrid KEM ("Envelope" below), so a mailbox never learns who wrote
to its owner.
Mailboxes reject envelopes whose `v` they do not speak (see "Versioning").

## Identity

On account creation the app generates an **Ed25519 signing keypair**. The
private key never leaves the device. The public key is registered with the
hub; it authenticates prekeys and (converted to X25519 by the standard
birational map — what libsodium calls
`crypto_sign_ed25519_*_to_curve25519`) participates in PQXDH.

Every client-side primitive named in this document lives in the
`stonechat-core` Rust crate (`core/`), which the Flutter app reaches over
dart:ffi and the iOS notification extension links directly — one
implementation, so no two processes can derive a value differently. The
constructions are libsodium's by name and byte layout; the code is
RustCrypto/dalek. `crypto_*` names below therefore describe the
construction, not a dependency.

The identity has a **post-quantum half** (docs/POST_QUANTUM.md): an
**X-Wing** encapsulation keypair (draft-connolly-cfrg-xwing-kem; X25519 +
ML-KEM-768 as one hybrid KEM) that seals every envelope on the wire. Its
32-byte secret seed is *derived*, not stored:

```
pq_seed = crypto_generichash(identity_sk, key="stonechat-v1-pqidseed", outlen=32)
pq_pk   = XWing-expand(pq_seed).public    # 1216 bytes
```

(`identity_sk` is the full 64-byte secret key, seed ‖ pubkey — hashing only
the 32-byte seed yields a different identity and opens nothing.)
Deriving means identity export, recovery and backups restore the PQ half for
free, and holding the Ed25519 key is already total identity compromise, so
the derivation adds no new custody risk. At registration the client
publishes `pq_pk` with `pq_sig = crypto_sign_detached("stonechat-v1-pqpk" ||
pq_pk, identity_sk)`; both ride in the directory record, and resolvers MUST
verify `pq_sig` against the (commitment-checked) identity key before sealing
anything to `pq_pk`.

### Stonechat ID

The user-facing identifier is a *commitment* to the Ed25519 public key, so the
directory cannot swap keys without detection:

```
hash      = crypto_generichash(pubkey, outlen=20)        # BLAKE2b-160, unkeyed
checksum  = crypto_generichash(hash,   outlen=16)[0:2]   # first 2 bytes
payload   = hash || checksum                             # 22 bytes
id        = "SC-" + base32(payload)                      # RFC 4648, upper, no padding
```

22 bytes → 36 base32 chars, displayed in 9 groups of 4:

```
SC-K3M9-QF2X-V8D4-HTPR-26LN-AQ7B-ZZC4-J5WE-M2KA
```

Whenever a client obtains an identity key — from the directory, from an
envelope's `x3dh.ik`, or from a group member list — it MUST recompute the hash
and verify it matches the claimed Stonechat ID (and verify the checksum when
parsing user input). A directory that lies is detected client-side.

### No handles — invite-only by ID

There is no friendly handle namespace. A user is reached only by their full
SC- ID, shared out-of-band: a QR code, or a universal-link invite
(`https://stonechat.app/add#<SC- ID>`) the app opens. This is deliberate. A
short, human-memorable handle is necessarily low-entropy, and an unauthenticated
directory over a low-entropy namespace is enumerable — walk it and you harvest
every user's pubkey and mailbox address. A SC- ID is a 160-bit commitment, so
directory lookup by ID is not walkable: you can only resolve someone whose ID
they gave you. Discovery is the cost; enumeration-resistance is the reward.

### Cross-hub resolution (experimental, off by default)

Builds compiled with `--dart-define=STONECHAT_CROSS_HUB=true` can reach peers
whose directory entry lives on a **different hub**. Nothing changes on the
wire between phones and mailboxes — messages always went sender's phone →
recipient's mailbox directly. This only extends *resolution*:

- An invite may tag the ID with its home hub: `#SC-…@hub.example.com` in the
  link fragment (bare authority ⇒ https; other schemes verbatim). Untagged
  invites keep today's meaning — resolve on the scanner's own hub.
- The client stores a home hub per contact and sends that hub's
  `/v1/directory/{id}` instead of its own. `contact_request` / `contact_accept`
  payloads gain an optional `hub` field (additive; old clients ignore it) so
  the recipient of a cross-hub request can resolve the sender back.
- **Trust is unchanged.** A directory answer is self-authenticating — pubkey
  must hash to the ID, mailbox fingerprint must carry the owner's signature —
  so a foreign (or malicious) hub is trusted for availability only, exactly
  like one's own. The `hub` value itself is routing data: wrong ⇒ lookup
  fails, nothing else.
- Cost, and why the flag exists: resolving a foreign ID sends your IP and the
  ID you're interested in to a hub you didn't choose. Store builds ship with
  the flag off. Group members on foreign hubs resolve only while they are also
  contacts (the membership payload carries no hub yet).

**This is not federation, and we should not call it that.** Federation, as the
word is used by XMPP and Matrix, means a *server-to-server protocol*: servers
authenticate to one another, replicate state between themselves, and share an
addressable namespace so that `user@server-a` is routable from `server-b`.
Stonechat has none of those three:

- **No server-to-server traffic at all.** Hubs never speak to each other. The
  only thing that changed is which URL the *client* puts its
  `GET /v1/directory/{id}` to — a foreign hub cannot tell it is being used
  this way, and has no peer relationship to accept or refuse.
- **No shared namespace.** Handles are ~26 bits and uniquified per directory
  ("Handle"), so the same `zn-…` handle legitimately exists on many hubs.
  Nothing is globally addressable; the only cross-hub name is the SC- ID,
  which is a hash commitment, not an allocation from a namespace.
- **No replicated state.** A hub stores exactly its own users' records.
  Nothing propagates, so there is no cross-server metadata spill — the failure
  mode Matrix pays for, where joining a room hands your membership and profile
  to every homeserver in it.

The consequence is that the trust story is *better* than a federated one, not
equivalent: because a directory answer is self-authenticating, a foreign hub
is trusted for availability only. In XMPP and Matrix the remote server is
trusted for considerably more. Calling this "federation" would concede a
weakness we do not have — see `docs/TODO.md` "cross-hub contact discovery",
which names the shape **hub hint** for the same reason.

## Prekeys

Forward-secret sessions must start while the recipient is offline, so every
user parks **public** key-agreement material on their own mailbox (private
halves never leave the phone):

- **Signed prekey (SPK)** — an X25519 keypair, rotated periodically (clients
  rotate after ~7 days; old private halves are kept ~30 days for in-flight
  messages). The public half is signed with the identity key:
  `sig = crypto_sign_detached("stonechat-v1-spk" || spk_pub, identity_sk)`.
- **One-time prekeys (OPK)** — a pool of X25519 keypairs. The mailbox hands
  each public half out at most once (deleted on fetch); clients top the pool
  up (target ~32) and delete each private half after the session that used it.
- **KEM signed prekey (KSPK)** — an **ML-KEM-768** keypair (FIPS 203), the
  post-quantum half of PQXDH (docs/POST_QUANTUM.md). Same rotation cadence
  as the SPK; signed with
  `sig = crypto_sign_detached("stonechat-v1-kspk" || kspk_pub, identity_sk)`.
  Client-side the secret is a 64-byte seed.
- **KEM one-time prekeys (KOPK)** — a pool of ML-KEM-768 keypairs, one-time
  exactly like OPKs (target ~32, mailbox cap 64 — they are 1184-byte keys).

The owner upload (`POST /prekeys`, owner token) carries the SPK + KSPK plus
the client's **full remaining OPK/KOPK stock**, and the mailbox **replaces**
its store with it. The client is the source of truth for which private
halves it still holds: merge semantics would keep one-time keys from a
previous install alive in the mailbox forever, handing senders bundles the
owner can no longer decrypt.

`GET /prekeys/bundle` on the recipient's mailbox returns (404 until both
signed halves are published — PQXDH has no classical-only fallback):

```json
{
  "spk":  {"id": 7,  "pub": "<base64>", "sig": "<base64>"},
  "opk":  {"id": 41, "pub": "<base64>"},    // or null when the pool is dry
  "kspk": {"id": 8,  "pub": "<base64>", "sig": "<base64>"},
  "kopk": {"id": 51, "pub": "<base64>"}     // or null when the pool is dry
}
```

The sender verifies both `sig`s against the recipient's **directory**
identity key (commitment-checked) — a compromised mailbox cannot substitute
prekeys, only refuse to serve them or drain the one-time pools. A dry pool
degrades gracefully: no `opk` → 3-DH; no `kopk` → encapsulate to the KSPK.
Still forward-secret going forward, minus one-time replay protection for
the very first message.

## Transport (pinned TLS)

All mailbox traffic runs over **HTTPS/WSS with a pinned, self-signed
certificate** — no certificate authorities, no domain names, no Certificate
Transparency entries enumerating users. The trust chain is the same one used
everywhere else in the protocol: it terminates at the Stonechat ID.

- On first boot the mailbox generates a TLS keypair and a long-lived
  self-signed certificate (persisted beside its DB; the key lives as long as
  the mailbox). The certificate authenticates the *pipe* only — message
  security never depends on it; that is the ratchet's job.
- Its fingerprint is `fp = crypto_generichash(cert_der, outlen=32)` (BLAKE2b
  over the DER-encoded certificate), reported as base64 in `/health`.
- The **owner** vouches for it:
  `tls_sig = crypto_sign_detached("stonechat-v1-tls" || fp, identity_sk)`, published
  to the hub, which serves both fields in the directory record:

```json
"mailbox": {"address": "https://203.0.113.7:8080", "status": "running",
           "tls_fp": "<base64>", "tls_sig": "<base64>"}
```

- Clients MUST NOT use system CA validation for mailbox connections. Instead:
  verify `tls_sig` against the peer's (commitment-checked) identity key, then
  accept the TLS handshake iff the presented certificate hashes to `tls_fp`.
  A directory that lies about the fingerprint cannot forge the signature —
  the worst it can do is deny service.
- **Bootstrap** (the owner's own mailbox, before any signature exists): the
  hub observed `tls_fp` via `/health` while waiting for the mailbox
  to become healthy and returns it in the owner's mailbox record — the same
  channel that already delivers the owner token. The owner's app pins that
  fingerprint for its own connection, signs it, and publishes the signature.
  For self-hosted relays the app observes the certificate on first contact
  with the box the user themselves provisioned (trust-on-first-use), then
  signs and publishes identically.
- A recreated mailbox has a new TLS key: the owner's app re-signs on the next
  refresh, and peers re-fetch the fingerprint through the same directory
  re-resolve path that already handles address changes.

## Session crypto

All shared constants. `H(msg, key, n)` is `crypto_generichash(msg, key, outlen=n)`
(keyed BLAKE2b; key lengths 16–64 bytes).

### PQXDH (session establishment)

X3DH plus an ML-KEM-768 encapsulation, after Signal's PQXDH
(docs/POST_QUANTUM.md): the classical DHs authenticate, the KEM share makes
the root key — and therefore the whole ratchet chain derived from it —
resistant to harvest-now-decrypt-later. Both halves are always present;
neither is ever a substitute for the other.

Alice initiates to Bob. `IKx` denotes an identity key converted
Ed25519→X25519. Alice generates an ephemeral X25519 keypair `EK`, and
encapsulates to Bob's KOPK when the bundle had one, else to his KSPK:

```
DH1 = scalarmult(IKx_A_priv, SPK_B)
DH2 = scalarmult(EK_priv,    IKx_B)
DH3 = scalarmult(EK_priv,    SPK_B)
DH4 = scalarmult(EK_priv,    OPK_B)          # only if the bundle had an opk
KCT, KSS = ML-KEM-768.Encaps(KOPK_B or KSPK_B)
SK  = H(DH1 || DH2 || DH3 [|| DH4] || KSS, key = "stonechat-v1-pqxdh-kdf", 32)
```

DH1/DH2 bind both identity keys — decryption succeeding proves the peer holds
the identity key committed to by their Stonechat ID; that is what authenticates a
message. Until Alice's session is **confirmed** (she has decrypted
one message from Bob on it), every envelope she sends carries an `x3dh` block
(see Envelope) — including `kct` (the KEM ciphertext), `kem_id` and
`kem_one_time` — so Bob can establish the session no matter which message
arrives first; Bob verifies `x3dh.ik` commits to the envelope's `from`.

Bob, on receiving a prekey message, computes the same DHs from the other
side, decapsulates `kct` with the KEM prekey named by `kem_id`, and deletes
the OPK/KOPK privates after successful establishment — replayed initial
messages then fail cleanly.
If a valid prekey message arrives while Bob holds an *unconfirmed* session he
himself initiated (both sides added each other simultaneously), the session
initiated by the **lower Stonechat ID** (lexicographic) wins; the loser's initial
envelopes are dropped, which the normal pending-outbox retry absorbs.

### Double ratchet

Standard Signal double ratchet over the primitives above:

```
KDF_RK(rk, dh):  out = H(dh, key = rk, 64) → (rk', ck) = (out[0:32], out[32:64])
KDF_CK(ck):      mk  = H(0x01, key = ck, 32);  ck' = H(0x02, key = ck, 32)
```

- Initiator: `DHs` = fresh X25519 pair; `RK, CKs = KDF_RK(SK, scalarmult(DHs, SPK_B))`;
  Bob's `SPK` is his initial ratchet key.
- Responder: `RK = SK`, `DHs` = SPK pair; the first received header triggers
  the usual DH-ratchet step, after which he can send.
- Every message: `mk, ck' = KDF_CK(ck)`. Every observed new remote ratchet
  key: two `KDF_RK` steps (receive chain, then fresh send chain). Message keys
  are deleted on use; out-of-order messages use stored skipped keys
  (`MAX_SKIP = 256` per chain, ≤ 512 stored per session, oldest evicted).

### Message encryption

```
ciphertext = crypto_aead_xchacha20poly1305_ietf_encrypt(
    plaintext, ad, nonce = random 24 bytes, key = mk)
ad = "stonechat/v1|{from}|{to}|{type}|{ratchet.dh}|{ratchet.pn}|{ratchet.n}"
```

The associated data binds the routing fields and ratchet header — tampering
with any of them fails authentication. These fields are "cleartext" only to
the recipient: on the wire they live in the inner envelope, inside the
transport seal.

## Envelope

All traffic between users is an **envelope**. What a mailbox stores
and forwards is the **sealed** form — the recipient is the only cleartext
routing fact on the wire:

```json
{
  "v": 1,
  "id": "<uuid4, sender-generated>",
  "to": "<recipient Stonechat ID>",
  "sealed": "<base64>",
  "blob_id": "<uuid, optional — only on media envelopes>",
  "transient": true,
  "push": false
}
```

`transient` and `push` are optional **delivery hints** for the recipient's
mailbox (booleans; absent means normal delivery):

- `transient: true` — deliver only if the owner's WebSocket is connected
  right now; never queue, never trigger a push ping. Used for typing
  indicators, which are worthless late.
- `push: false` — queue and deliver normally, but never wake the owner's
  phone for it. Used for receipts: nobody's 2 a.m. read receipt should light
  up a screen.
- `ring: true` — queue and deliver normally, and wake the owner *loudly*:
  where the gateway supports it, this becomes a VoIP/high-priority push
  instead of the generic ping. Used for `call_offer` — an incoming call is
  the one envelope that must interrupt.

All are necessarily mailbox-visible, and all are honesty-only (a hostile
mailbox already controls delivery). None tells an observer anything that
envelope size and timing don't: receipts and typing envelopes are
recognizably small, and a call setup is recognizably a burst.

```
kem_ct, kem_ss = XWing.Encaps(pq_pk_recipient)      # directory pq_pk, sig-verified
key    = H(kem_ss, key = "stonechat-v1-hsealkdf", 32)
nonce  = random 24 bytes
sealed = kem_ct (1120) || nonce || crypto_aead_xchacha20poly1305_ietf_encrypt(
             inner_envelope_json, ad = "stonechat-v1-hseal", nonce, key)
```

The X-Wing seal is *anonymous* and *hybrid* — a fresh encapsulation per
envelope, no sender key anywhere in it, and X25519 + ML-KEM-768 in one KEM,
so a recorded envelope stays sealed against a future quantum attacker
(docs/POST_QUANTUM.md step 2 — the classical `crypto_box_seal` would have
retroactively leaked who-talked-to-whom). The wire form identifies no
sender, carries no type, and cannot be linked to a session across
envelopes: a mailbox never learns who writes to its owner (**sealed
sender**). It also has no legitimate use for that information — `/inbox`
only checks `to == owner`. `blob_id` is the one extra hint: the mailbox uses
it solely to garbage-collect the blob when the envelope is acked (it marks
the envelope as media, nothing more).

The **inner envelope**, visible only to the recipient after unsealing with
their identity key:

```json
{
  "v": 1,
  "id": "<same uuid as the sealed form>",
  "type": "msg" | "media" | "contact_request" | ...,
  "from": "<sender Stonechat ID>",
  "to": "<recipient Stonechat ID>",
  "sent_at": "<ISO-8601 UTC>",
  "ratchet": {"dh": "<base64 ratchet pubkey>", "pn": 0, "n": 3},
  "x3dh": {"ik": "<base64>", "ek": "<base64>", "spk_id": 7, "opk_id": 41,
           "kct": "<base64, 1088 bytes>", "kem_id": 51, "kem_one_time": true},
  "nonce": "<base64, 24 bytes>",
  "ciphertext": "<base64>",
  "blob_id": "<uuid, optional — only on type=media>"
}
```

`ratchet` is the double-ratchet header. `x3dh` appears only on a session's
initial envelopes (until confirmed); `opk_id` is omitted when the bundle was
dry.

A recipient silently drops anything that does not unseal to its identity
key, whose inner `to` is not itself, or for which no session can be
established (no matching session, no `x3dh` block, or prekey privates
already consumed) — the sender's pending-outbox retry re-encrypts fresh.

One caveat by construction: the seal rides on the recipient's *long-term*
X-Wing identity key, so this layer has no forward secrecy. Recorded
envelopes plus a future identity-key theft reveal historical sender/type
metadata — never message content, which stays behind the ratchet's
single-use keys. (A future *quantum* attacker without the key gets nothing:
that is what the hybrid seal buys.)

### Plaintext payloads (JSON, encrypted)

| type              | payload                                |
|-------------------|----------------------------------------|
| `msg`             | `{"text": "...", "expire_after_ms"?, "reply_to"?}` |
| `media`           | `{"blob_id", "key", "blob_nonce", "mime", "kind": "image"\|"audio"\|"video"\|"file"\|"sticker", "size", "duration_ms"?, "name"?, "expire_after_ms"?, "reply_to"?}` |
| `contact_request` | `{"display_name": "...", "avatar"?}`   |
| `contact_accept`  | `{"display_name": "...", "avatar"?}`   |
| `profile_update`  | `{"display_name"?, "avatar"?: {"data": "<base64>", "mime"} \| null}` — wire form SHOULD set `push: false` |
| `group_create` / `group_update` | `{"group_id", "name", "version", "admin", "members": [{"stonechat_id", "pubkey", "display_name"}], "expire_ms"?}` |
| `group_msg`       | `{"group_id", "text", "expire_after_ms"?, "reply_to"?}` |
| `group_media`     | `group_msg`'s fields minus `text`, plus `media`'s minus `blob_id`-on-the-envelope, plus `{"fetch_token", "blob_host", "blob_tls_fp"}` — see "Group media" |
| `group_leave`     | `{"group_id"}`                         |
| `receipt`         | `{"kind": "delivered"\|"read", "ids": ["<message id>", …]}` |
| `typing`          | `{"group_id"?, "state": "started"\|"stopped"}` — wire form MUST set `transient: true` |
| `msg_edit`        | `{"id": "<message id>", "text": "..."}` |
| `msg_delete`      | `{"id": "<message id>"}`               |
| `group_msg_edit`  | `{"group_id", "id", "text"}`           |
| `group_msg_delete`| `{"group_id", "id"}`                   |
| `reaction`        | `{"id": "<message id>", "emoji": "👍"}` — `""` clears |
| `group_reaction`  | `{"group_id", "id", "emoji"}`          |
| `timer_update`    | `{"expire_ms": <int ms, 0 = off>}`     |
| `group_timer_update` | `{"group_id", "expire_ms"}`         |
| `call_offer`      | `{"call_id", "media": "audio"\|"video", "sdp"}` — wire form SHOULD set `ring: true` |
| `call_answer`     | `{"call_id", "sdp"}`                   |
| `call_ice`        | `{"call_id", "candidates": [{"candidate", "sdp_mid", "sdp_mline_index"}, …]}` — wire form MUST set `transient: true` |
| `call_end`        | `{"call_id", "reason": "hangup"\|"decline"\|"busy"\|"timeout"}` |

Member `pubkey` entries are Ed25519 identity keys (same commitment check as
the directory).

### Receipts, typing, edit/delete

All four ride ordinary pairwise sessions — same encryption, same sealed
sender; a mailbox cannot tell a receipt from a message (beyond size). The
**message id** they reference is the original envelope's `id`, which group
fan-out already reuses across every member's copy, so one id names the same
message everywhere.

- **`receipt`** — sent by the recipient of `msg`/`media`/`group_msg`/
  `group_media` back to
  its author, batched (one envelope may cover many ids). `delivered` fires
  when the message is persisted; `read` when it is displayed (client
  setting; delivered is unconditional). Wire form SHOULD set `push: false`.
  Receivers apply a receipt only if the referenced message is outgoing and
  the receipt's sender is the DM peer (or, for groups, a current member —
  tracked per member; a group message counts delivered/read when *every*
  other member is). Statuses only move forward. Receipts are best-effort:
  no durable retry.
- **`typing`** — throttled to one `started` per ~8 s of continuous typing;
  receivers expire it after ~15 s without a refresh, on `stopped`, or when
  the sender's message arrives. Clients only send typing on already-
  established sessions (never fetch a prekey bundle for it) and MUST mark
  the wire envelope `transient` — a queued typing indicator is noise, and
  dropped ones merely become skipped message keys within `MAX_SKIP`.
- **`msg_edit` / `msg_delete`** — only valid from the original author, which
  the session already authenticates: receivers check the referenced message
  is incoming, in that conversation, and (groups) written by `from`. Senders
  offer edit/delete-for-everyone for 24 h; receivers allow 36 h to absorb
  clock skew and queue delay. Edits replace the text and mark it edited;
  deletes tombstone the message ("message deleted"). Both are cooperative,
  not cryptographic — like Signal, an unmodified client honors them, nothing
  forces a hostile one to. A message edited while still in the sender's
  pending outbox is simply rewritten before first delivery. Edits and
  deletes are best-effort (no durable retry); an unreachable member keeps
  the old content.
- **`reaction`** — one emoji per (message, reactor); a new reaction replaces
  the previous one, the empty string clears it. Either side of a DM (or any
  current group member) may react to any non-deleted message; receivers
  key the stored reaction by the session-authenticated sender, so nobody
  can react in someone else's name. Best-effort, like receipts.

### Replies (`reply_to`)

`msg`, `media`, `group_msg` and `group_media` payloads MAY carry a quote of an
earlier message in the same conversation:

```json
"reply_to": {"id": "<message id>", "sender": "<Stonechat ID>", "preview": "..."}
```

The block is a **display snapshot**, not a reference the receiver must
resolve: `preview` (sender-clipped to ~140 chars) and `sender` are rendered
as-is, so a quote of a message the receiver no longer holds (expired,
deleted, pre-history) still displays. When the receiver does hold `id`
locally, clients offer jump-to-original. Like reactions, the block is
cooperative display data — receivers cap the preview length and ignore
malformed blocks, and a lying sender can only misquote inside a
conversation the session already authenticates them into.

### Profiles (`profile_update`)

A user's profile — display name and photo — is client-held data pushed over
the ordinary pairwise sessions, never stored on the hub or any mailbox. The
photo therefore inherits E2EE and sealed sender, and only travels to people
the owner already trusts:

- **Audience** — accepted contacts only. Receivers drop `profile_update`
  from anyone else. `contact_request` / `contact_accept` MAY carry the
  sender's current profile (`avatar` in the same shape) so the first render
  is immediate; a requester's photo reaches the recipient with the request,
  the accepter's flows back with the accept.
- **`avatar` field** — absent means *unchanged*, `null` means *cleared*,
  otherwise `{"data": "<base64 image bytes>", "mime": "image/jpeg"|…}`.
  Senders scale the image down (≤ 256 px, ≤ ~24 KB raw) so the envelope
  stays under the mailbox's 64 KB wire cap after the two base64 layers;
  receivers enforce their own decoded-size cap and drop anything oversized
  or undecodable. Like `reply_to`, the image is cooperative display data.
- **Last-writer-wins** — receivers store the `sent_at` of the profile they
  hold and ignore an update that is not newer, so replayed or out-of-order
  envelopes cannot regress a profile (same rule as `timer_update`).
- **Fan-out** — on any profile change the owner sends one `profile_update`
  to every accepted contact. Best-effort (no durable retry): an unreachable
  contact keeps the old profile until the owner's next change reaches them.
  Wire form SHOULD set `push: false` — nobody's phone should wake for a
  photo swap.
- **Groups** — membership fan-outs carry no images. A member's photo is
  rendered only where the viewer knows them as an accepted contact;
  everyone else stays on the ID-derived fallback.

### Disappearing messages

A per-conversation timer: while it is active, every new message the
conversation's participants send carries `expire_after_ms`, and each
device deletes its copy `expire_after_ms` after the envelope's `sent_at`
— read or not. Changing or disabling the timer never touches messages
already sent; only messages sent under an active timer expire.

- **Setting the timer** — either DM party sends `timer_update`; any
  current group member fans `group_timer_update` to the other members
  (receivers drop it unless `from` is a current member). Clients offer
  0 (off), 1 hour, 24 hours and 7 days; receivers accept any
  non-negative integer for forward compatibility.
- **Last-writer-wins** — receivers store the change time of the timer
  they hold and ignore an update whose envelope `sent_at` is not newer,
  so replayed or out-of-order updates cannot regress the setting.
- **Per-message field is authoritative** — a receiver computes expiry
  from the message's own `expire_after_ms`, never from its local
  setting. Messages queued offline or racing a `timer_update` therefore
  expire exactly as the sender intended, regardless of arrival order.
- **Joiners** — `group_create`/`group_update` MAY carry `expire_ms`
  (the group's current timer). A client applies it only when learning
  of the group for the first time; established members ignore it, so a
  membership fan-out cannot clobber a newer member-set timer.
- Like `msg_edit`/`msg_delete`, this is **cooperative, not
  cryptographic**: an unmodified client deletes on schedule, nothing
  forces a hostile one to. Timer updates are best-effort (no durable
  retry); an unreachable member keeps the old timer until someone
  changes it again.

### Calls (1:1, WebRTC)

Calls are between **accepted contacts only**. The envelope layer is the
signaling channel: SDP and ICE ride ordinary ratchet-encrypted envelopes,
so signaling inherits E2EE and sealed sender, and — because the session
authenticates the sender and the SDP carries the DTLS certificate
fingerprints — the DTLS-SRTP media keys are authenticated end-to-end with
no additional cryptography. **Media never touches a mailbox**: it flows
peer-to-peer (or through a TURN relay, below).

Rules:

- `call_id` is a caller-generated uuid4; every envelope of the call carries
  it, and anything referencing an unknown/ended call is dropped.
- A receiver ignores a `call_offer` whose `sent_at` is older than 60 s and
  records a missed call instead. Both sides give up ringing after ~45 s
  (caller sends `call_end reason=timeout`).
- A second concurrent `call_offer` from anyone is answered with
  `call_end reason=busy`.
- **Glare** (both sides call each other simultaneously): the offer from the
  **lower Stonechat ID** (lexicographic) wins; the other side discards its own
  attempt and treats the winning offer as incoming — same tiebreak as
  simultaneous X3DH.
- `call_ice` envelopes are transient: late candidates are useless, and if
  the peer is not connected the call is failing anyway. Offers, answers and
  hangups are normal (queued) envelopes.
- IP privacy: exchanging ICE candidates reveals device addresses to the
  *peer* (an accepted contact). Callers who consider that sensitive route
  through TURN/VPN; a relay-only mode is planned, not present.

#### TURN (`/turn-credentials`)

NAT-hostile paths need a relay. Architecture-consistent home: **the user's
own mailbox VM** runs a coturn container beside `stonechat-relay`, sharing a
secret via `STONECHAT_TURN_SECRET`. The mailbox mints ephemeral credentials
(coturn's TURN REST API scheme — `username = expiry:stonechat`,
`password = base64(HMAC-SHA1(secret, username))`):

| Method | Path                | Auth      | Description |
|--------|---------------------|-----------|-------------|
| GET    | `/turn-credentials` | `?token=` | `{"urls": ["turn:<host>:3478?transport=udp", …], "username", "credential", "ttl"}`. 404 when the relay has no TURN (`STONECHAT_TURN_SECRET` unset). |

Each side fetches credentials from its **own** mailbox and contributes its
own relay candidates; either side's relay can carry the call. Clients fall
back to STUN-only when their mailbox serves no TURN.

### Media (photos, videos, voice notes, documents)

`kind` says how to render: `image`, `audio` (voice note), `video`,
`file` (arbitrary document; `name` carries its original filename —
receivers MUST strip any path components and take only the basename),
or `sticker` (a small transparent image — canonically 512×512 WebP —
rendered inline without frame chrome; receivers treat it exactly like
`image` otherwise). Sticker packs are a purely client-side concept:
nothing about packs exists on the wire.
Media never travels inside the envelope. The sender:

1. generates a one-off XChaCha20-Poly1305 key (32 bytes) + nonce (24),
2. encrypts the file with it (empty associated data) and `POST /blob`s the
   ciphertext to the *recipient's* mailbox → `blob_id`,
3. sends a normal `media` envelope whose (session-encrypted) payload
   carries the `blob_id`, the `key`/`blob_nonce` (base64), and display
   metadata.

The recipient downloads `GET /blob/{id}` from their own mailbox (owner token
required), decrypts with the key from the payload, persists locally, then acks
the envelope — which deletes both the envelope row and the blob. Only the
recipient ever holds the blob key, so the mailbox stores ciphertext it cannot
open, same as envelopes. Blob keys inherit forward secrecy from the envelope
layer that carries them.

Unknown senders: clients only render `msg` envelopes from accepted contacts.
Anything else from a stranger is shown as a pending contact request at most.

### Groups (client-side fan-out)

A group is **not a stored object anywhere**. Neither the hub nor any
mailbox stores a member list, a
group name, or can distinguish a group message from a DM — each group message
is N ordinary pairwise envelopes, one per member, encrypted with the member's
normal pairwise session (established on demand from their prekey bundle) and
sent to each member's own mailbox. Group traffic is therefore exactly as
forward-secret as DMs.

Rules:

- **The creator is the admin.** `group_create` and every `group_update` carry
  the *full* member list (including the admin and the recipient) and a
  `version` that increments on every change. Clients MUST ignore
  `group_create`/`group_update` envelopes whose `from` is not the group's
  admin (the session already authenticates the sender), and ignore versions ≤
  the one they hold. A client that receives a `group_msg` referencing a
  version-gap can request nothing yet — the next `group_update` heals it.
- **Member keys verify offline**: each member entry's `pubkey` must hash to
  its `stonechat_id` (same commitment check as the directory), so a malicious
  admin cannot silently substitute keys.
- `group_msg` / `group_media` are only rendered if `from` is a current member.
- `group_leave` is a courtesy announcement; removal becomes authoritative
  with the admin's next `group_update`.
- Practical cap ~25 members (fan-out is O(N) per message).

#### Group media

DM media parks the ciphertext on the *recipient's* mailbox (above). Doing that
per member would re-upload the same video N times, so group media inverts it:
**one blob, on the sender's own mailbox, N capability tokens' worth of reads.**
The sender:

1. generates one XChaCha20-Poly1305 key + nonce and encrypts the file once,
2. `POST /blob?shared=1` to **their own** mailbox → `{blob_id, fetch_token}`,
3. fans out a `group_media` envelope to each member, carrying `blob_id`, the
   `key`/`blob_nonce`, the `fetch_token`, and `blob_host`/`blob_tls_fp` —
   where to fetch it and which pinned certificate to expect.

Each member `GET /blob/{id}?token={fetch_token}` from the *sender's* mailbox
(pinned to `blob_tls_fp`), decrypts with the key from the payload, and persists
locally before acking. Upload cost is O(1) in members instead of O(N); the
envelope fan-out stays O(N), as for text.

Receivers MUST check `blob_host` against the sender's own mailbox address —
the directory entry for `from`, refreshed if the cached one disagrees — and
drop the media otherwise. `blob_host` is the only field in the protocol that
points a client at a host it did not choose, and a group member is not
automatically trusted to choose one. A sender who moved mailboxes between
sending and the fetch fails closed (media unavailable), which is the safe
direction for a rare case.

Unlike DM media the outer envelope carries **no** `blob_id`: the blob does not
live on the recipient's mailbox, so their ack must not try to GC it. The
sender instead deletes it (`DELETE /blob/{id}`) once every member has
`delivered`-receipted the message; the 14-day blob TTL is the backstop for
members who never come back.

What this costs, stated plainly: a member fetching group media contacts the
**sender's** mailbox directly, so that host sees the member's IP and the fact
that someone fetched — where DM media only ever has the sender contacting the
recipient's box. It learns no identity (the fetch carries only a per-blob
token) and no content (it stores ciphertext it cannot open, as always). The
key never touches the sender's mailbox: it rides the ratchet inside the
envelope, so the one host holding the ciphertext is the one host that cannot
decrypt it.

## Routing model (mailbox)

Each user's mailbox is their **inbox**. To send, Alice's app:

1. `GET {hub}/v1/directory/{bob_id}` → Bob's identity key + current mailbox address + TLS fingerprint
2. Verifies the key against the ID, and `tls_sig`/`pq_sig` against the key; if no session yet, `GET {bob_mailbox}/prekeys/bundle` (pinned TLS) and runs PQXDH
3. Encrypts on the session, seals the envelope to Bob's X-Wing identity key (`pq_pk`), `POST https://{bob_mailbox}/inbox` (pinned TLS)
4. If Bob has no mailbox or it's unreachable → queue locally, retry later.

Bob's app keeps a WebSocket to *his own* mailbox and acks envelopes as it
persists them locally; each ack deletes the envelope from the mailbox's SQLite.
On connect, the app also republishes its prekeys (`POST /prekeys` with the
full remaining stock — the mailbox replaces its store, so a fresh, recreated,
or stale-stocked mailbox all converge), and registers its push token
(`POST /push-config`) so the mailbox can wake it via the gateway while it's
offline.

## Mailbox API (`relay/`)

Configured via env: `STONECHAT_OWNER_ID`, `STONECHAT_OWNER_TOKEN`, `STONECHAT_PORT` (default
8080), `STONECHAT_TLS_DIR` (cert/key location, defaults beside the DB). All
endpoints are served exclusively over TLS (see Transport).

| Method | Path          | Auth      | Description |
|--------|---------------|-----------|-------------|
| GET    | `/health`     | none      | Liveness only: `{"status": "ok", "v": <wire version>, "tls_fp": "<base64>"}`. Deliberately identity-free (see below). |
| GET    | `/status`     | `?token=` | Owner-only mailbox state: `{"status": "ok", "v", "queued": n, "prekeys": {"spk": bool, "opks": n}}`. |
| GET    | `/owner`      | none      | `?stonechat_id=` → 200 `{"owner_matches": true}` iff the mailbox's owner equals the supplied ID, else 404 (400 if absent). Confirms a *known* ID; never reveals one. |
| POST   | `/inbox`      | none      | Body: sealed envelope. 403 unless `to == owner`; 400 unless `v` matches the mailbox's wire version and `sealed` well-formed. Queues; pushes immediately if owner connected. `transient: true` → deliver-if-connected-else-drop (no queue, no push ping); `push: false` → queue but never ping the gateway. |
| GET    | `/prekeys/bundle` | none  | Owner's current prekey bundle; consumes (deletes) the returned OPK. 404 until the owner has uploaded prekeys. |
| POST   | `/prekeys`    | `?token=` | Owner uploads `{"spk": {id, pub, sig}, "opks": [{id, pub}, …]}` — the full remaining stock. Replaces the SPK and the whole OPK store (cap 256). |
| POST   | `/blob`       | none      | Body: raw encrypted bytes (≤ 64 MB). → `{"blob_id"}`. With `?shared=1` also returns `{"fetch_token"}` — a per-blob read capability, for group media. |
| GET    | `/blob/{id}`  | `?token=` | Download a queued blob. Accepts the owner token, or *that blob's* `fetch_token`. |
| DELETE | `/blob/{id}`  | `?token=` | Owner-only; idempotent (`{"status": "ok"}` even if already gone). Reclaims a shared group blob once every member has fetched it. |
| POST   | `/push-config`| `?token=` | Owner registers `{"device_token", "platform": "ios"\|"android"}` for wake-up pings. |
| WS     | `/ws`         | `?token=` | Owner connection. The mailbox sends envelopes as JSON; client replies `{"ack": "<envelope id>"}` → row deleted (and its `blob_id`'s file, if any). |

`/inbox`, `/blob` and `/prekeys/bundle` are deliberately unauthenticated
(anyone may deliver mail or start a session), but the mailbox validates
envelope shape, enforces `to == owner`, caps envelope size (64 KB), queue
depth (10k), blob size (64 MB) and total blob storage (1 GB). Blobs older
than 14 days are garbage-collected. The prekey store holds only public keys;
the worst a reader can do is drain the OPK pool, which degrades to 3-DH.

A `fetch_token` is *derived*, never stored:
`blake2b-256(owner_token ‖ "|stonechat-blob-fetch|" ‖ blob_id)`, hex. So the
relay keeps no per-blob row, a token is valid exactly as long as its blob is,
and it opens that blob and nothing else — it is not the owner token and grants
no other endpoint. It is only ever returned to whoever uploaded the blob, and
only when they asked for it. Token comparison is constant-time.

`/health` carries no identity — only liveness, the wire version, and the
(already-public) TLS fingerprint — and `/owner` merely *confirms* a supplied
Stonechat ID, so neither lets a stranger scanning mailbox addresses learn or
enumerate a mailbox's owner. Owner-visible state (queue depth, prekey counts)
lives behind the owner token on `/status`.

## Push gateway (`push_gateway/`)

A separate stateless service — the only place APNs/FCM credentials live. When
an envelope arrives and the owner's WebSocket is down — or the device fails
to ack it within a short grace window (10 s; 2 s for `ring` envelopes),
since a suspended phone keeps its TCP connection open without reading it —
the mailbox POSTs `{"device_token", "platform"}` to
`{STONECHAT_PUSH_GATEWAY}/v1/ping`; the gateway sends a **content-free** generic
notification ("You have new messages") and the woken phone drains its own
mailbox over the normal encrypted path.

Separation is deliberate: the gateway sees device tokens + timing but no
identities; the hub knows identities but no tokens. Neither logs
enough to join the two. Mailboxes debounce pings (5 s) and the gateway
debounces per token (3 s) with a collapse id, so a burst of envelopes wakes
the phone once. Self-hosted mailboxes may set `STONECHAT_PUSH_GATEWAY` to any
compatible gateway, or leave it empty (pull-only delivery).

**Push keys.** When the gateway is deployed with `STONECHAT_PUSH_MINT_SECRET`,
`/v1/ping` requires an `X-Stonechat-Push-Key` header: an opaque credential
`pk_<random>:<hmac>` the hub mints per relay at provisioning (hmac =
HMAC-SHA256(secret, key_id); env `STONECHAT_PUSH_KEY` on the relay). Verification
is offline — the gateway checks the hmac against the shared secret, no
identity lookup — preserving the tokens+timing-only posture. Bad or missing
key → 403. Abuse is handled per credential: the key id (never an identity)
appears in gateway logs, and a revoked id in the gateway's blocklist file
(`STONECHAT_PUSH_BLOCKLIST`) cuts that one relay off. With the secret unset the
endpoint is open, as before (dev/e2e).

## Mailbox host (`mailbox_host/`) — the program that runs mailboxes

Every box that holds mailbox containers runs this, and it is the only thing with
Docker access to that box. A container per mailbox: own port, own token, own TLS
certificate, cgroup/pids caps.

Three ways to get one, one program:

* **Invite-hosted** ("host your circle"): a user runs `mailbox_host/main.py` on a
  box they own, hosting their own mailbox plus friends they invite. A guest's
  mailbox is registered in the directory as an ordinary self-hosted (`external`)
  relay, so no new hub concepts are needed.
* **Managed** (`STONECHAT_MAILBOX_HOST_MANAGED=1`): the box belongs to a hub
  operator, and the hub places mailboxes on it through this same API — the shared
  tier the Mailbox plan sells, provider `mailbox_host`. Invites are refused in
  this mode, so a box has exactly one authority; a mailbox the hub did not place
  would sit on a port it believes is free, unknown to its directory and reaper.
* **Dedicated VMs** the hub provisions (`gcp`/`aws`/`digitalocean`) come with the
  mailbox host pre-installed on port 8200 — the hub mints the admin token at
  provision time, bakes it into the VM's startup script, and returns it in
  `GET /v1/mailbox` (`mailbox_host` field) so the app connects with zero setup.

Where the hub holds an admin token (managed hosts and dedicated VMs) that adds
nothing to the trust model: it provisioned the box and already holds
`mailbox_token`, and message content is end-to-end encrypted regardless. An
invite host-owner's token never touches the hub.

The hub reaches a managed host over this HTTPS API, pinning the host's
certificate fingerprint and presenting the admin token. It holds no shell or
Docker access there — the retired `fleet` provider drove each host's daemon over
SSH as a member of the `docker` group, which is root on that box in all but name.

Served over pinned TLS (self-signed, same scheme as a mailbox). The **invite**
a host-owner shares is `stonechat-host:` + base64url(`{u: mailbox host URL, f: mailbox host TLS
fingerprint, t: token}`); the guest's app pins the mailbox host connection to `f`, so
the redeem can't be MITM'd.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET  | `/health` | none | Liveness + pinning only: `{status, v, tls_fp}`. Guest count and capacity are occupancy metadata, served admin-only via `/v1/guests`. |
| POST | `/v1/invite` | admin | `{uses, ttl_hours}` → `{invite}`. 403 in managed mode |
| GET  | `/v1/invites` | admin | sent invites with status: `{invites: [{invite, uses, uses_left, expires_at, created_at, redeemed_by: [owner_id]}]}` — the mailbox host records each redemption so the owner's app can show accepted/waiting/expired |
| POST | `/v1/redeem` | none | `{invite, owner_id}` → `{address, mailbox_token, tls_fp, wt_address}`; launches a `stonechat-relay` container for `owner_id`, single-use, capacity-capped. 403 in managed mode |
| POST | `/v1/guest` | admin | `{owner_id}` — provision directly (the host-owner's own mailbox, or a hub placing one). A hub also sends `owner_token` (the token it has already recorded for that mailbox, so the app's token is the one the relay accepts) and `push_key` (only the hub holds the mint secret) |
| GET  | `/v1/guests` | admin | `{guests, count, capacity, managed}` — occupancy, which is how a hub picks the emptiest host in a country |
| DELETE | `/v1/guest/{owner_id}` | admin | evict — destroy that guest's container. Idempotent: an unknown guest is `{"status": "gone"}`, so a hub destroying a mailbox it has already forgotten does not get an error it cannot act on |
| GET  | `/v1/relay` | admin | `{installed_build, image, managed, guests: [{owner_id, build}]}` — each `build` read from that relay's own `/status`, so a half-finished roll reads as one |
| POST | `/v1/relay` | admin | the relay binary as a raw body; becomes what new mailboxes are built from, wrapped in an image tagged by its build id. Refuses a non-ELF |
| POST | `/v1/relay/roll` | admin | `{only?, dry_run?, force?}` — swap the installed binary into running mailboxes, one at a time, verifying each reports the new build and rolling that one back if it does not |

After redeeming, the guest connects the returned mailbox exactly like a
self-hosted relay: `POST /v1/mailbox/external` (the hub verifies the
mailbox reports the guest as owner), then publishes its TLS signature. The
`mailbox_token` stays on the guest's device. **Trust:** the host-owner can see
that a guest hosts there and the guest's traffic metadata — never message
content (E2EE). Same as any relay operator; the guest just picked a friend.

## Hub API (`hub/`)

User auth: `Authorization: Bearer <account_token>` (issued at registration).

| Method | Path                      | Auth   | Description |
|--------|---------------------------|--------|-------------|
| POST   | `/v1/register`            | none   | `{"pubkey": "<base64 Ed25519>", "pq_pk": "<base64 X-Wing, 1216 bytes>", "pq_sig": "<base64>"}` → `{"stonechat_id", "account_token"}`. `pq_sig` is Ed25519 over `"stonechat-v1-pqpk" \|\| pq_pk`; the hub verifies it (and clients re-verify on every resolve — the directory stays untrusted). |
| POST   | `/v1/recover`             | none   | `{"pubkey", "timestamp", "signature"}` → `{"stonechat_id", "account_token"}` — identity restore. `signature` is Ed25519 over `"stonechat-v1-recover" \|\| str(timestamp)` (unix seconds, ±5 min). Rotates the account token: the recovering device becomes the account, any previous token dies. 404 if the key was never registered (client falls back to `/v1/register`). |
| GET    | `/v1/directory/{stonechat_id}` | none | Lookup by full SC- ID only (no handles; the 160-bit ID is not enumerable). → `{"stonechat_id", "pubkey", "pq_pk", "pq_sig", "mailbox": {"address", "status", "tls_fp", "tls_sig"} \| null}`. 400 on a non-ID string, 404 if unknown. |
| POST   | `/v1/mailbox`              | bearer | `{"country": "DE"}` (the app's form — the hub resolves it against the catalog and the caller's plan) **or** `{"provider": "gcp"\|"aws"\|"digitalocean"\|"local"\|"mailbox_host", "machine": {"machine_type", "region", "disk_gb"}}`. For `mailbox_host`, `region` is the ISO country code: placement is least-loaded *within* that country and fails rather than falling back to another. → 202, provisioning starts. One mailbox per user. On a gated hub, gated providers require a tier (see "Gate"): missing/insufficient → 402 `{"code": "access_required", "tier_required", "message"}`; gate unreachable → 503 `{"code": "gate_unavailable"}`. |
| POST   | `/v1/mailbox/external`     | bearer | `{"address"}` — list a self-provisioned relay. The hub confirms ownership via `GET {address}/owner?stonechat_id=<caller>` — the mailbox confirms the supplied ID rather than exposing its owner (ownership is proven, not claimed). The relay's token never reaches the hub. |
| POST   | `/v1/mailbox/tls`          | bearer | `{"tls_fp", "tls_sig"}` — owner publishes the signature over their mailbox's TLS fingerprint. The hub verifies the Ed25519 signature against the registered pubkey and that `tls_fp` matches the fingerprint it observed. |
| GET    | `/v1/mailbox`              | bearer | `{"status": "none"\|"provisioning"\|"running"\|"error", "address", "mailbox_token", "provider", "tls_fp", "error", "mailbox_host"}`. `mailbox_host` is `{"address", "admin_token"}` on running dedicated VMs (pre-installed mailbox host, see "Mailbox host"), else `null`. |
| DELETE | `/v1/mailbox`              | bearer | Destroys the VM and forgets it. |
| POST   | `/v1/account/delete`       | bearer | `{"timestamp", "signature"}` → `{"status": "deleted"}` — deletes the account. `signature` is Ed25519 by the identity key over `"stonechat-v1-delete" \|\| str(timestamp)` (unix seconds, ±5 min), so a token alone cannot erase an account and a linked device cannot at all. In order: on a gated hub, asks the gate to release the ID (it ends what it grants, and what the user pays for) — the gate's 409 refusal is passed through and nothing is deleted; then destroys the mailbox's machine and drops the account. Afterwards the directory answers 404, as for an ID it never saw; peers are not notified. The ID is a hash of the pubkey, so registering the same key again yields the same ID as a new, empty account. |
| GET    | `/v1/access`              | bearer | `{"gated", "tier", "status", "until", "notice"}`. `gated: false` → an open hub; nothing needs a tier and there is nothing to redeem. `tier` is `"mailbox"`, `"machine"` or null; `notice` is the gate's own text for the user, shown as-is. 503 if the gate is unreachable. |
| POST   | `/v1/access/claim`        | bearer | `{"code"}` → forwarded to the gate for the caller's ID → same shape as `GET /v1/access`. The gate's 404/409 refusals pass through unchanged (the hosted gate: 404 `invalid_code`, 409 `already_granted`). 404 `not_gated` on an open hub. |
| POST   | `/v1/report`              | signature | `{"reported_id", "reporter_pubkey", "timestamp", "category", "note", "evidence"\|null, "signature"}` → 202 `{"report_id"}`. See "Reporting". 400 malformed/self-report/unknown category, 401 bad signature, 404 `{"code": "not_our_account"}` if this hub does not host the reported ID. |

`mailbox_token` is the `STONECHAT_OWNER_TOKEN` the client uses for its own `/ws`.

### Reporting

A user reports another user to the hub **hosting the reported account** — the
only party that can destroy a mailbox or refuse a new one. Under cross-hub
resolution that is frequently not the reporter's own hub, where their account
token means nothing, so the report is authenticated by **signature**
instead: a Stonechat ID is
a commitment to an Ed25519 key ("Identity"), so any hub can verify a reporter
it has never met. Same posture as `/v1/directory` — open, and verified rather
than trusted.

The signature is Ed25519 over

```
"stonechat-v1-report" || reported_id || str(timestamp) || BLAKE2b-256(body)
```

where `reported_id` is in canonical `SC-…` form, `timestamp` is unix seconds
(±5 min, as `/v1/recover`), and the body digest is over

```
category || 0x1F || note || 0x1F || (evidence ?? "")
```

The body is committed to by digest rather than signed directly because it has
to survive a round trip through JSON, which preserves neither field order nor
whitespace. `0x1F` (unit separator) prevents a note that ends in what looks
like the next field from colliding with a different report.

`category` is one of `spam`, `harassment`, `impersonation`, `illegal_content`,
`csam`, `other`. `evidence` is **null by default**: a report carries no message
content unless the reporter explicitly attaches one, and when they do it is a
client-composed JSON document (`{"v":1,"messages":[{"sent_at","kind","text"}]}`)
that the hub stores verbatim and never parses. Only messages the *reported*
party sent are eligible, media is described rather than uploaded, and the
signature covers the attachment's exact bytes. Client side: `app/lib/core/
report.dart`. Hub side, including retention: `hub/app/report.py`.

### Gate

Tiers map to providers: **mailbox** → `mailbox_host` (container on a shared
host), **machine** → `gcp`/`aws`/`digitalocean`/`hetzner`/`vultr` (dedicated
VM). Machine outranks mailbox (a Machine holder may run on a shared host);
`local` and `external` are never gated.

Who holds which tier is not the hub's to decide. A hub started without
`STONECHAT_GATE_URL` is **open**: every provider it offers is free to use and
nothing is ever reaped. With it, the hub asks that service — the **gate** — and
keeps no copy of the answer. Payment, coupons, invite codes, an allowlist: all
of it lives behind this contract, every call carrying
`Authorization: Bearer <STONECHAT_GATE_TOKEN>`:

| Method | Path | Body → response |
|--------|------|-----------------|
| GET  | `/v1/access/{stonechat_id}` | → access object |
| POST | `/v1/access/{stonechat_id}/claim` | `{"code"}` → access object; 404/409 with a `{"detail": …}` body the hub passes to the client verbatim |
| POST | `/v1/access/{stonechat_id}/release` | the account is being deleted: end what it grants → 2xx; 409 `{"detail": …}` refuses the deletion |

Access object: `{"tier": "mailbox"|"machine"|null, "status", "until",
"revoked_at", "notice"}`. A tier the hub does not know reads as null.
`revoked_at` is when a tier the ID once held was lost (null if it never held
one); the hub's reaper destroys a gated mailbox once its owner's `revoked_at`
is older than `STONECHAT_REAP_RETENTION_DAYS`, and leaves owners with a null
one alone. The gate takes the Stonechat ID on trust — the hub has already
authenticated the user — so the token is the whole of its security.

Failure is asymmetric on purpose: a gate the hub cannot reach refuses gated
provisioning (503) and skips that reap pass; nothing already running is
touched. `scripts/stub_gate.py` is a working gate that grants tiers for codes
(and what `scripts/e2e.py` runs against).

The hosted service's gate sells tiers through Stripe Payment Links on
stonechat.app. The webhook mints an **activation code** — `STONECHAT-` + 8
chars from an unambiguous alphabet (`ABCDEFGHJKMNPQRSTVWXYZ23456789`), matched
case-insensitively, separators ignored — which the purchase page shows and the
app claims. Claiming is the only moment a payment touches a Stonechat ID: from
then on that gate can link the ID to a Stripe customer id (Stripe knows who
paid; the gate knows which ID they paid for). That is the entire, and
deliberate, privacy cost of paying — and it is borne by the gate, not the hub.

The hub stores **only**: pubkey, stonechat_id, hashed account token, current
mailbox record (provider, provider-side resource id, address, status). No
names, no emails, no payment data, no message data, no contact graph. It never
sees prekeys — those live on the user's mailbox.

## Versioning

The wire has a single integer version, currently **1**, surfaced three ways:
envelopes carry it as `v` (a mailbox rejects an envelope whose `v` it does not
speak), mailboxes report it in `/health` and `/status`, and clients send it to
the hub as an `X-Stonechat-Version` header. The hub answers any request whose header
is below its minimum supported version with **426 Upgrade Required**
(`{"code": "upgrade_required", "min_version": n, "message": …}`), which the app
turns into a "please update" wall; an absent header is treated as a legacy
(pre-versioning) client and allowed through.

Because a mailbox cannot read a sealed envelope, it **cannot translate between
envelope versions** — so the envelope `v` is evolved conservatively (new fields
are additive; old clients ignore what they do not recognize), while the hub and
mailbox HTTP APIs, which the mailbox terminates and can inspect, may gate by
version directly. First-party clients are the only ones that must stay in sync;
a third-party client that falls behind is told to upgrade, never silently
mishandled.

## Threat notes

- **Forward secrecy**: message keys are single-use and deleted; root/chain
  keys advance with every round trip (post-compromise healing on the next
  fresh DH). Recorded ciphertext + later key theft ≠ plaintext.
- **Sealed sender**: the wire envelope names only the recipient. A mailbox —
  including one hosted by a friend via the mailbox host — learns *that* its
  owner received mail, when, how big, and whether it was media (`blob_id`),
  but never from whom or of what type. The exception is the seal's own
  layer: it rides on the recipient's long-term identity key, so a recorded
  backlog plus a future identity-key theft reveals historical sender/type
  metadata (never content — the ratchet's keys are gone).
- **What a stolen phone still yields**: the message-history database and
  session states are SQLCipher-encrypted with a random key held in the
  platform keystore (Keychain/Keystore), so a lifted filesystem image or
  device backup yields ciphertext. Received/sent media files are currently
  plain files outside that database. A phone unlocked (or with keystore
  access) yields everything — that's the storage model; the optional app
  lock is a screen gate on top, not a second key.
- **What a compromised mailbox yields**: undelivered sealed ciphertext,
  queue timing and sizes, the owner's *public* prekeys, and the ability to
  serve stale or no prekeys (denial, detectable) — never sender identities,
  never key substitution (SPK signature + identity commitment), never
  plaintext.
- **Session loss** (app data wiped but identity restored — possible via the
  app's encrypted identity export and `POST /v1/recover`; ratchet sessions
  are never part of the export): peer messages drop until a new session
  forms; there is deliberately no session escrow anywhere.
- **Transport**: pinned TLS removes cleartext exposure of the owner token
  and of envelopes to on-path observers, and makes mailbox MITM require that
  mailbox's TLS private key. What it cannot hide: **IP addresses are
  routing metadata**. The destination IP names the recipient (one mailbox is
  one user), and delivery is direct, so the sender's device IP is visible to
  the recipient's mailbox. The protocol does not try to hide network origin
  — senders who consider their IP sensitive route the app through a VPN or
  Tor. Inherent to per-user mailboxes.

---

## License

This specification is licensed under
[Creative Commons Attribution 4.0 International](licenses/CC-BY-4.0.txt)
(CC-BY-4.0), not under the AGPL-3.0 that covers the code in this repository.

That is deliberate. An independent implementation of this protocol is a
*good* outcome for Stonechat: every client that speaks it reaches the same
directory and the same users, and a protocol nobody else can implement is a
protocol nobody can check. Build one, and attribute the spec.

Implementing this document grants no right to use the Stonechat name or
marks — see the trademark note in the repository README.
