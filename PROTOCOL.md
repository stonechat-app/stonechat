# Stonechat Protocol (v1)

The shared contract between the components:

- **Clients** — the Flutter app (`app/`), the browser client (`webclient/`)
  and the headless agent (`agent_client/`). They hold keys and message
  history, and are the only place plaintext exists. All three run the same
  protocol implementation, `stonechat-core` (`core/`).
- **relay/** — the mailbox program, one instance per user. Stores only
  sealed envelopes, one queue per device, and deletes each envelope when the
  device it was for acks it. Also serves its owner's public prekeys and
  device certificates.
- **hub/** — provisioner + directory. Maps Stonechat IDs to public identity
  keys and current mailbox addresses, and is the dead drop for linking a
  device. Never sees message content.
- **push_gateway/** — turns "this device has mail" into a content-free
  APNs/FCM wake-up.
- **mailbox_host/** — the program that runs mailbox containers on a box.

Sessions are **forward-secret and post-quantum hybrid**: PQXDH key agreement
(X3DH + ML-KEM-768, docs/POST_QUANTUM.md) bootstrapped from prekeys served
by the recipient's own mailbox, then a double ratchet deriving a fresh key
for every message, with a fresh ML-KEM secret mixed into it every so often
("Post-quantum ratchet"). Recorded traffic is opened neither by a future quantum
computer nor by later theft of a device's keys, within the limits in
"Threat notes". Every envelope is additionally **sealed to the recipient
device** with a hybrid KEM ("Envelope"), so it names no sender on the wire.

An identity may have **several devices**, each with its own keys, its own
queue on the mailbox, and its own ratchet with every peer device
("Devices"). Which devices currently speak for an identity is a signed,
numbered statement by the identity itself ("Device manifest"), not a
relay's word.

The wire version is 1 ("Versioning").

## Conventions

- **base64** is standard base64 with padding (RFC 4648 §4) unless a field
  says base64url.
- `H(msg, key, n)` is keyed BLAKE2b with an `n`-byte output — libsodium's
  `crypto_generichash(msg, key, outlen=n)`. Without a key it is plain
  BLAKE2b.
- `Sign(context, msg, sk)` is Ed25519 over the byte string `context || msg`.
  Verification is strict (`verify_strict`: no malleable or small-order
  signatures).
- Every client-side primitive named here lives in the `stonechat-core` Rust
  crate — reached by the Flutter app over dart:ffi, the iOS notification
  extension over the C ABI, the agent as a Rust crate and the browser as
  wasm — so no two processes can derive a value differently. The
  constructions are libsodium's by name and byte layout; the code is
  RustCrypto/dalek, so `crypto_*` names describe the construction, not a
  dependency. The core draws no entropy of its own: every caller passes it
  CSPRNG bytes.

Domain-separation strings, all ASCII, no terminator:

| String | Used for |
|---|---|
| `stonechat-v1-pqxdh-kdf` | key of the PQXDH shared-secret hash |
| `stonechat-v1-hsealkdf` | key of the envelope-seal key derivation |
| `stonechat-v1-hseal` | associated data of the envelope seal |
| `stonechat/v1` | first field of the message associated data |
| `stonechat-v1-spk` | signature over a signed prekey (device key) |
| `stonechat-v1-kspk` | signature over a KEM signed prekey (device key) |
| `stonechat-v1-devcert` | signature over a device certificate (identity key) |
| `stonechat-v1-tls` | signature over a mailbox's TLS fingerprint (identity key) |
| `stonechat-v1-wtcerts` | signature over a WebTransport certificate schedule (identity key) |
| `stonechat-v1-pqpk` | signature over the identity's X-Wing key (identity key) |
| `stonechat-v1-pqidseed` | key of the hash deriving that X-Wing key's seed |
| `stonechat-v1-recover` | account-token recovery at the hub (identity key) |
| `stonechat-v1-delete` | account deletion at the hub (identity key) |
| `stonechat-v1-report` | abuse report (identity key) |
| `stonechat-link-offer` | prefix of the link-offer commitment hash |
| `stonechat-device-token\|` | prefix of the relay's stored device-token hash |
| `\|stonechat-bundle\|` | derivation of the bundle token |
| `\|stonechat-blob-fetch\|` | derivation of a blob fetch token |

## Identity

On account creation the client generates an **Ed25519 signing keypair** —
the **identity key** — and registers the public half with the hub. The
private half never leaves the device that generated it (the *primary*
device), except in a passphrase-encrypted export the user makes explicitly
("Local containers").

The identity key is a **root**, not a messaging key. It signs:

- one certificate per device ("Device certificates");
- the mailbox's TLS fingerprint and WebTransport certificate schedule
  ("Transport");
- the identity's X-Wing key (below);
- requests to the hub that must prove possession of the identity: recovery,
  account deletion, abuse reports.

It takes no part in key agreement, signs no prekeys, and opens no envelopes.
Those are done with **device keys**.

### The identity's X-Wing key (`pq_pk`)

Every identity has an X-Wing encapsulation key (X25519 + ML-KEM-768 as one
hybrid KEM), whose 32-byte seed is *derived*, not stored:

```
pq_seed = H(identity_sk, key="stonechat-v1-pqidseed", 32)
pq_pk   = XWing-expand(pq_seed).public    # 1216 bytes
pq_sig  = Sign("stonechat-v1-pqpk", pq_pk, identity_sk)
```

(`identity_sk` is the full 64-byte secret key, seed ‖ pubkey — hashing only
the 32-byte seed yields a different key.)

`pq_pk` and `pq_sig` are **required at registration** and served in every
directory record. The hub checks the length of `pq_pk` (1216 bytes) and the
signature, and refuses the registration otherwise. A client MAY verify
`pq_sig` against the (commitment-checked) identity key when it resolves a
record: the Flutter app does, and treats a record without a valid `pq_pk` as
unusable; the browser client and the agent ignore both fields.

**Nothing is sealed to `pq_pk`.** No client encapsulates to it or attempts
to open anything with its private half. Envelopes are sealed to the
recipient *device's* certified X-Wing key ("Envelope").

### Stonechat ID

The user-facing identifier is a *commitment* to the Ed25519 identity public
key, so the directory cannot swap keys without detection:

```
hash      = H(pubkey, outlen=20)                 # BLAKE2b-160, unkeyed
checksum  = H(hash,   outlen=16)[0:2]            # first 2 bytes
payload   = hash || checksum                     # 22 bytes
id        = "SC-" + base32(payload)              # RFC 4648, upper, no padding
```

22 bytes → 36 base32 chars, displayed in 9 groups of 4:

```
SC-K3M9-QF2X-V8D4-HTPR-26LN-AQ7B-ZZC4-J5WE-M2KA
```

The grouped, upper-case form is canonical and is what appears in envelopes,
certificates and signed material. Parsing user input ignores case,
whitespace and hyphens and verifies the checksum.

Whenever a client obtains an identity key — from the directory, a link
grant, or a group member list — it MUST recompute the hash and verify it
matches the Stonechat ID **it was looking for** ("Directory resolution").
Device keys do *not* hash to a Stonechat ID; a certificate ties them to one.

### No handles — invite-only by ID

There is no handle namespace. A user is reached only by their full SC- ID,
shared out-of-band: a QR code, or a universal-link invite
(`https://stonechat.app/add#<SC- ID>`) the app opens. The ID rides in the
URL *fragment*, which a browser never sends to the server.

This is deliberate: an unauthenticated directory over a low-entropy handle
namespace is enumerable — walk it and you harvest every user's pubkey and
mailbox address. A SC- ID is a 160-bit commitment, so the directory is not
walkable: you can only resolve someone whose ID they gave you.

### Cross-hub resolution (experimental, off by default)

Builds compiled with `--dart-define=STONECHAT_CROSS_HUB=true` can reach peers
whose directory entry lives on a **different hub**. Nothing changes on the
wire between clients and mailboxes; only *resolution* is extended:

- An invite may tag the ID with its home hub: `#SC-…@hub.example.com` in the
  link fragment (bare authority ⇒ https; a value containing `://` is taken
  verbatim). Untagged invites resolve on the scanner's own hub.
- The client stores a home hub per contact and sends that hub's
  `/v1/directory/{id}` instead of its own. `contact_request` /
  `contact_accept` payloads carry an optional `hub` field so the recipient
  of a cross-hub request can resolve the sender back. Receivers accept it
  only when it starts with `http://` or `https://`.
- **Trust is unchanged.** A directory answer is checked against the ID that
  was asked for, and a mailbox fingerprint must carry the owner's signature
  — so a foreign (or malicious) hub is trusted for exactly what one's own
  is ("Directory resolution", "Threat notes"). The `hub` value is routing
  data: wrong ⇒ lookup fails, nothing else.
- **Cost, and why the flag exists:** resolving a foreign ID sends your IP
  and the ID you're interested in to a hub you didn't choose. Store builds
  ship with the flag off.
- Group members on foreign hubs resolve only while they are also contacts
  (the membership payload carries no hub).

**This is not federation**:

- **No server-to-server traffic.** Hubs never speak to each other. Only the
  URL the *client* puts its `GET /v1/directory/{id}` to changes; a foreign
  hub cannot tell it is being used this way, and has no peer relationship
  to accept or refuse.
- **No shared namespace.** The only name is the SC- ID, a hash commitment
  to a key, not an entry a hub hands out. The same ID may be registered on
  several hubs; each holds its own record for it.
- **No replicated state.** A hub stores exactly its own users' records;
  nothing propagates.

## Devices

### Device model

A mailbox has one or more **devices**, numbered by the relay. Everything a
mailbox holds per user it holds **per device**: the envelope queue, the
prekey pool, the push registration, the live socket.

- **Device 1 is the primary**: whoever holds the mailbox's owner token
  (`STONECHAT_OWNER_TOKEN`). It is created when the relay first boots and
  its row is re-seeded from that variable on every boot. It holds the
  identity secret, so only it can certify devices.
- Further devices are **minted** by the primary (`POST /devices`). Ids are
  assigned by the relay, increase monotonically and are **never reused**, so
  an envelope still in flight to a revoked device can never land in a newer
  device's queue.
- Each device has a **kind**: `primary`, `linked` (another of the owner's
  apps), `web` (a browser session) or `agent` (a headless program). `primary`
  cannot be minted. The kind is advisory — the relay and the protocol treat
  all devices alike; it lets a device list say what each entry is and the
  certifying device pick a lifetime.
- A device MAY have an **expiry** (`expires_at`, RFC 3339), fixed when it is
  minted from `expires_in_s` (an integer from 1 to 31 536 000 seconds).
  Absent means "until revoked". Nothing a device does extends it. From the
  deadline on, the device's token authenticates as nobody and the device is
  left out of every listing; an hourly sweep then revokes it properly
  (queue, prekeys, push registration, `devices_v` bump).

### Device keys

Each device generates two keypairs on first run and keeps them for its
lifetime. Only seeds are stored; public halves are derived. Neither key
ever leaves the device — not in a link grant, not anywhere.

| Key | Type | Used for |
|---|---|---|
| signing key (`sig_pub`) | Ed25519, 32-byte seed | signs this device's signed prekeys; converted to X25519, it is this device's long-term key in PQXDH |
| seal key (`seal_pub`) | X-Wing, 32-byte seed, 1216-byte public key | envelopes to this device are sealed to it |

### Device certificates

A device certificate is the identity key's statement that a pair of device
keys belongs to a Stonechat ID, as a given device, until a given time. As
JSON:

```json
{
  "stonechat_id": "SC-K3M9-…",
  "device_id": 2,
  "sig_pub": "<base64, 32 bytes>",
  "seal_pub": "<base64, 1216 bytes>",
  "not_after": 1790000000,
  "sig": "<base64, 64 bytes>"
}
```

`not_after` is Unix seconds. The JSON is only a carrier. What is signed is a
fixed, length-prefixed byte string — never the JSON, whose key order and
number formatting differ between serializers:

```
field(x)      = u32_be(len(x)) || x
signing_bytes = field(utf8(stonechat_id))
             || field(u32_be(device_id))
             || field(sig_pub)                    # 32 bytes
             || field(seal_pub)                   # 1216 bytes
             || field(u64_be(not_after))
sig           = Sign("stonechat-v1-devcert", signing_bytes, identity_sk)
```

**Verification.** A certificate is *valid* for identity key `IK` at time
`now` iff, in this order:

1. `sig` verifies over `"stonechat-v1-devcert" || signing_bytes` under `IK`
   (else: bad signature);
2. `IK` is the key `stonechat_id` commits to — `derive_id(IK) ==
   stonechat_id` (else: wrong identity). Without this, a directory that
   answers with another user's key gets that user's certificates accepted
   under the wrong name;
3. `now < not_after` (else: expired — `not_after` is exclusive).

That makes the name in the certificate *true*, not the *right* one. The
client MUST additionally check:

4. `stonechat_id` is the peer it meant to reach (or, on receive, the
   envelope's `from`);
5. `device_id` is the device slot the certificate arrived in — the device it
   was listed under, fetched for, or the envelope's `from_device`. Otherwise
   a mailbox that shuffled certificates between its devices would redirect
   mail.

A certificate that fails any check is not a partial credential: the client
skips that device rather than falling back to any other key.

**Lifetimes.** The certifying (primary) device chooses `not_after`. The
Flutter app uses, by kind:

| Kind | Certificate lifetime | Renewed by the primary when less than |
|---|---|---|
| `primary` | 365 days | 3 days (re-signs its own) |
| `linked` | 14 days | 7 days left |
| `agent` | 14 days | 7 days left |
| `web` (and any unknown kind) | 7 days | 3.5 days left |

Lifetimes are short because a certificate is what a revoked device keeps.
The device manifest ("Device manifest") tells a contact who fetches it
that a device is gone; the certificate's expiry is the bound for a contact
who does not.

- A device row given an expiry (`expires_in_s`) gets a certificate of the
  same lifetime, so a device that stops authenticating does not go on being
  a valid encryption target.
- The primary re-signs its own certificate when it has less than 3 days
  left, or when the one it holds names a different identity.
- **Renewal.** On every connect to its mailbox the primary lists the
  identity's devices and, for each device other than itself whose
  certificate has less than half its lifetime left — or has already run
  out — signs a new certificate over the same keys for the same slot and
  sends it to that device as a `sync_cert` self-sync envelope ("Self-sync").
  The device verifies it (against the identity key it holds; names its own
  ID, slot and both keys; later than the one it has), adopts it and
  republishes its prekeys with it. A linked device thus stays certified for
  as long as its primary connects at least once per half-lifetime and it is
  still on the relay. A device that was revoked is not listed and gets
  nothing. A linked device that does not handle `sync_cert` (the browser
  client and the agent do not yet) is linked again when its certificate
  runs out.
- Senders re-fetch a peer's certificates when the one they hold has less
  than 3 days left, which is after the primary would have renewed it. A
  sender MUST NOT encrypt to a device whose certificate has expired,
  whatever the mailbox lists.
- Receivers keep the certificate they verified for a sending device and
  check it on every envelope, not only when the session began ("What a
  recipient checks"). A certificate that has expired is refetched from the
  sender's mailbox; one that cannot be replaced drops the envelope.

**Where certificates travel.** A device uploads its certificate to its
mailbox with its prekeys (`POST /prekeys`, `cert`); the mailbox stores it as
an opaque object of at most 8 KiB and serves it back verbatim in prekey
bundles and device listings. The mailbox cannot verify a certificate and
does not try — the sender's device does. A certificate also rides in the
`x3dh` block of every initial envelope, so the recipient can check the
sender's device key without fetching anything.

### Device tokens, the bundle token and `devices_v`

A **device token** is the device's login to its own mailbox: possession of
the token *is* being that device. Device 1's token is the mailbox's owner
token. A minted device's token is chosen by the primary (at least 32
characters; the app uses 32 random bytes, base64url without padding) and
handed to the new device inside the link grant. The relay stores only
`hex(BLAKE2b-256("stonechat-device-token|" || token))`. Tokens are presented
as the `token` query parameter.

The **bundle token** is a capability that lets a peer list a mailbox's
devices and fetch a named device's prekey bundle — and nothing else:

```
bundle_token = hex(BLAKE2b-256(owner_token || "|stonechat-bundle|"))
```

- It grants `GET /prekeys/devices` and `GET /prekeys/bundle?device=N`. It is
  not a device token and opens no other route.
- Only the relay and device 1 can compute it. The relay hands it to every
  authenticated device in `GET /status`, and the primary puts it in the
  link grant.
- It travels in the **inner envelope** (`bundle_token`), on every envelope a
  device sends. Its audience is therefore everyone who has received
  something from this identity — contacts, fellow group members, and anyone
  who was sent a contact request.
- It exists because the *unauthenticated* bundle request serves device 1
  only, at the cost of one one-time prekey per request. If listing were
  open, one anonymous request could burn a prekey on every device.
- It does not change when the device set changes and cannot be revoked
  without changing the owner token.

**`devices_v`** is a per-mailbox integer, starting at 1, incremented whenever
a device is minted or revoked (including expiry). It never decreases. The
relay reports it in `/status`, `/devices`, `/prekeys/devices`, in every
`/inbox` response, and in the body of a `410`. A sender that sees a larger
value than the one it holds drops its cached device list for that peer and
re-reads it on the next send.

### Device manifest

A certificate says a device *was* the identity's, until a date. The
**device manifest** is the identity's statement of which devices speak for
it *now*: the primary signs the current set, numbered so a newer manifest
supersedes an older, and publishes it to the hub, which serves it in the
directory record (`devices`). A peer that holds it encrypts only to devices
on it and accepts envelopes only from devices on it — so revoking a device
is a new manifest without the device, which a contact can check, rather
than only a queue deleted on a relay the contact has to trust.

```json
{
  "stonechat_id": "SC-…",
  "version": 7,
  "issued_at": 1790000000,
  "devices": [
    {"device_id": 1, "sig_pub": "<base64, 32 bytes>"},
    {"device_id": 3, "sig_pub": "<base64, 32 bytes>"}
  ],
  "sig": "<base64, 64 bytes>"
}
```

Each entry pairs a device slot with the signing key its certificate
carries, so a relay that moved a certificate between slots, or kept one
from before a slot was re-keyed, is caught by the pair not matching.
`issued_at` is informational: nothing expires a manifest. What is signed is
a length-prefixed byte string, as for certificates:

```
signing_bytes = field(utf8(stonechat_id))
             || field(u64_be(version))
             || field(i64_be(issued_at))
             || field(u32_be(count))
             || for each device: field(u32_be(device_id)) || field(sig_pub)
sig           = Sign("stonechat-v1-devices", signing_bytes, identity_sk)
```

A manifest is **valid** for identity key `IK` iff `sig` verifies under
`IK`, `IK` is the key `stonechat_id` commits to, it lists between 1 and 64
devices, and no slot is listed twice. A client MUST additionally check it
names the identity it asked about.

**Publishing.** Only the primary can sign. It publishes with
`POST /v1/devices` ("Hub API"); the hub verifies the signature and refuses a
version at or below the one on record (`409`, naming the current version).
The primary publishes:

- when it links a device, listing the new device by the key in its offer,
  before the device has published anything itself;
- when it revokes a device;
- on every connect to its mailbox, if the devices the relay lists (by the
  certificates they published) are not the set the manifest on record
  lists — which also covers a device the relay expired.

The next version is one past both the version the primary knows and the
version on record, so a primary restored from an identity export, which
knows nothing, still publishes a manifest that supersedes.

**Holding one.** A client keeps the newest verified manifest it has seen
per identity — its own included — and never replaces it with an older one,
whatever the directory serves. Every inner envelope states the sender's
current version as `manifest_v` ("Envelope"). A client fetches an
identity's manifest (by resolving the ID, "Directory resolution"):

- the first time it deals with the identity, as part of resolving it;
- when an envelope states a `manifest_v` above the version it holds;
- when the sender's mailbox lists a device the held manifest does not;
- once per run when it holds none, so an identity that published after
  first contact is caught up with.

There is deliberately no periodic refresh. A contact who is never prompted
to refetch keeps accepting a revoked device until that device's certificate
expires, which the lifetimes above keep short.

**What a holder enforces.** For an identity with a manifest:

- on receive, the envelope's `from_device` MUST be listed with the
  `sig_pub` of the certificate the receiver holds for it, else the envelope
  is dropped (after refetching the manifest if the envelope's `manifest_v`
  is newer than the one held);
- on send, only listed devices are encrypted to, and a listed device whose
  held certificate carries another key is skipped.

For an identity that has published no manifest, certificates alone decide.
A client's own devices are judged the same way: a revoked device of one's
own cannot write self-sync to the others once they hold the manifest that
drops it.

**What it does not do.** The manifest carries no expiry and the directory
can serve a stale one: a hub can hold a contact at an old version until
something prompts a refetch, and even then only answer with what it has.
The certificate lifetime bounds that. A manifest also says nothing about a
device's *queue*: a hostile relay can go on accepting deposits for a
revoked device and serving its certificate; a sender holding the manifest
does not encrypt to it, and one that does not stops when the certificate
expires.

### Linking a device

Linking gives a new device a certificate and the addressing it needs,
without moving any secret key. The transfer channel is the hub, used as a
dead drop; **the trust anchor is the user**, who carries a code between two
screens they are looking at.

**1. The new device makes an offer.** It uses its own long-lived device keys
(not throwaways) and generates a 32-byte random **lookup secret**:

```
commitment  = BLAKE2b-256("stonechat-link-offer" || seal_pub || sig_pub)
parking_key = hex(BLAKE2b-256(lookup))
```

It parks the public keys on the hub under the commitment:

```
POST {hub}/v1/link/offer
{"key": "<hex commitment>", "offer": {"seal": "<base64 seal_pub>", "sig": "<base64 sig_pub>"}}
```

and displays the code (QR or text):

```
"stonechat-link:" + base64url_nopad( 0x02 || lookup (32) || commitment (32) )
```

65 bytes. `0x02` is the format marker; a scanner rejects any other length or
marker. The keys themselves (1248 bytes) do not fit a QR a phone will read,
so the code carries a commitment and the network carries the keys.

The two values are separate on purpose: the commitment ties the fetched keys
to what the user saw; the lookup secret is what the grant is filed under.
Deriving the parking key from the public keys would let anyone who can see
the hub's offer table collect — and thereby destroy — the grant.

**2. The primary authorises it.** It parses the code, fetches
`GET {hub}/v1/link/offer/{commitment}`, and MUST recompute the commitment
from the keys it was served and refuse on a mismatch. (The hub checks the
same thing on upload; its word does not count.) The user is asked what kind
of device this is. Then the primary:

- generates a device token and mints the device on its own mailbox
  (`POST /devices`), obtaining the `device_id`;
- signs a device certificate over the offered `sig_pub` / `seal_pub` for
  that `device_id`;
- builds the **grant** and seals it to the offered `seal_pub` with the same
  construction that seals envelopes ("Envelope");
- parks it: `POST {hub}/v1/link` `{"key": "<parking_key>", "sealed":
  "<base64>"}`;
- publishes a device manifest that lists the new device by the offered
  `sig_pub` ("Device manifest"), so contacts accept it as soon as it speaks.

The grant, as JSON inside the seal:

```json
{
  "identity_pub": "<base64 Ed25519 identity PUBLIC key>",
  "cert": { …device certificate… },
  "stonechat_id": "SC-…",
  "display_name": "…",
  "hub_url": "https://…",
  "relay_address": "https://203.0.113.7:8080",
  "relay_tls_fp": "<base64>",
  "device_id": 2,
  "device_token": "…",
  "bundle_token": "<hex, optional>"
}
```

The only secret in it is `device_token`. Not in it, each omission a bound on
what a linked device can do: the identity secret (so it cannot mint or renew
certificates, sign a TLS fingerprint, recover or delete the account), the
hub account token (so it cannot provision or destroy the mailbox), and
message history.

**3. The new device collects.** It polls `GET {hub}/v1/link/{parking_key}`
(404 until the grant is parked), unseals with its own seal seed, and before
adopting anything MUST check:

1. `identity_pub` hashes to `stonechat_id` — so a grant cannot install a
   different identity under the name the user is looking at;
2. `cert` is valid against `identity_pub` (signature, commitment, expiry) and
   names `stonechat_id` and `device_id`;
3. `cert.sig_pub` and `cert.seal_pub` are **this device's own** public keys.
   A valid certificate for some other device's keys would be published with
   this device's prekeys and leave it unable to open a single envelope.

It then stores the identity public key, the certificate, the device id and
token, pins `relay_tls_fp` for its own mailbox connection, and publishes its
prekeys and certificate.

**The dead drop.** Both hub tables are unauthenticated — a device being
linked has no account — and bounded instead:

| | Offers (`/v1/link/offer`) | Grants (`/v1/link`) |
|---|---|---|
| Key | 64 lowercase hex chars, and MUST equal the commitment to the body's keys (hub recomputes) | 64 lowercase hex chars |
| Body | `seal` 1216 bytes, `sig` 32 bytes | `sealed`, non-empty, ≤ 65 536 characters |
| Read | repeatable (the scanner may retry) | **returns and deletes** — single use |
| Lifetime | 600 s | 600 s |
| Pending at once, hub-wide | 8 (then 503) | 8 (then 503) |
| Rate limit | 30 requests/minute per client address, shared by all four link routes | same |

Re-posting an existing key replaces its body and restarts its clock.

The hub learns from a link that two addresses took part in one, and when.
It sees the new device's public keys and an opaque grant.

### Revocation and expiry

`DELETE /devices/{id}` removes a device: its row, queue, prekeys and push
registration go, its live socket is closed with code 4001, `devices_v` is
incremented, and any later envelope addressed to it is refused with `410`.
The primary may revoke any other device; a linked device may revoke only
itself ("sign out"); device 1 cannot be revoked by anyone.

Revocation is enforced three ways: by **the relay**, which stops queueing
for the device; by the **device manifest** the primary publishes without
it, which a contact who fetches it checks on every envelope and every send;
and by **certificate expiry**, which bounds a contact who never fetches it
("Device manifest", "Device certificates"). The revoked device keeps its
keys and its certificate; what it loses is anyone's reason to accept them.

## Prekeys

Forward-secret sessions must start while the recipient is offline, so every
**device** parks **public** key-agreement material on its mailbox (private
halves never leave the device). Pools are per device; one device restocking
never touches a sibling's pool.

| Prekey | Type | Signed | Notes |
|---|---|---|---|
| **Signed prekey (SPK)** | X25519 | `sig = Sign("stonechat-v1-spk", spk_pub, device_sig_sk)` | signed by the **device** signing key |
| **One-time prekeys (OPK)** | pool of X25519 | **unsigned** | the mailbox hands each public half out at most once (deleted on fetch) |
| **KEM signed prekey (KSPK)** | **ML-KEM-768** (FIPS 203) | `sig = Sign("stonechat-v1-kspk", kspk_pub, device_sig_sk)` | the post-quantum half of PQXDH. Client-side the secret is a 64-byte seed; the public key is 1184 bytes |
| **KEM one-time prekeys (KOPK)** | pool of ML-KEM-768 | **unsigned** | one-time exactly like OPKs |

A mailbox can substitute a one-time prekey of either kind ("Known open
gaps").

Prekey ids are integers chosen by the device, unique within a kind on that
device. (`kem_one_time` in the handshake says which KEM pool a `kem_id`
names, so the two KEM kinds may overlap.)

Client policy (Flutter app):

- SPK and KSPK are replaced once they are more than 7 days old, checked
  whenever prekeys are published (on every mailbox connect);
- the device keeps the private halves of the **two most recent** keys of
  each kind and deletes older ones;
- one-time pools are topped up to 32 of each kind;
- a one-time private half is deleted after the session that used it
  decrypts its first message.

The browser client keeps 20 of each and does not rotate its signed prekeys.

The upload (`POST /prekeys`, the device's token) carries the SPK + KSPK plus
the device's **full remaining OPK/KOPK stock**, and optionally its
certificate; the mailbox **replaces** that device's store with it:

```json
{
  "spk":   {"id": 7,  "pub": "<base64>", "sig": "<base64>"},
  "opks":  [{"id": 41, "pub": "<base64>"}, …],
  "kspk":  {"id": 8,  "pub": "<base64>", "sig": "<base64>"},
  "kopks": [{"id": 51, "pub": "<base64>"}, …],
  "cert":  { …device certificate… }
}
```

The device is the source of truth for which private halves it still holds:
merge semantics would keep one-time keys from a previous install alive in
the mailbox forever, handing senders bundles the owner can no longer
decrypt. `opks` and `kopks` may be omitted (empty pools); `cert` omitted
leaves the stored certificate in place.

`GET /prekeys/bundle` returns one device's bundle (404 until both signed
halves are published — PQXDH has no classical-only fallback):

```json
{
  "cert": { …device certificate… },           // or null if none was uploaded
  "spk":  {"id": 7,  "pub": "<base64>", "sig": "<base64>"},
  "opk":  {"id": 41, "pub": "<base64>"},      // or null when the pool is dry
  "kspk": {"id": 8,  "pub": "<base64>", "sig": "<base64>"},
  "kopk": {"id": 51, "pub": "<base64>"}       // or null when the pool is dry
}
```

Without parameters it serves **device 1**, to anyone. With `?device=N` it
serves device N and requires `?token=` to be the bundle token (or any of the
mailbox's device tokens). Either way it consumes the returned one-time
prekeys, lowest id first.

`GET /prekeys/devices?token=<bundle token>` lists every device that has
published signed prekeys, consuming nothing:

```json
{
  "devices_v": 3,
  "devices": [
    {"device_id": 1, "spk": {…}, "kspk": {…}, "cert": {…}},
    {"device_id": 2, "spk": {…}, "kspk": {…}, "cert": {…}}
  ]
}
```

**What the sender verifies**, in this order, before it uses a bundle:

1. the bundle's `cert` is a valid device certificate against the
   recipient's identity key, naming the recipient's ID and the device asked
   for ("Device certificates"). No certificate ⇒ no session;
2. `spk.sig` and `kspk.sig` verify under the certificate's `sig_pub`.

A mailbox therefore cannot substitute a signed prekey or a device key; it
can refuse to serve, serve an old signed prekey, drain the one-time pools,
or substitute a one-time prekey ("Threat notes"). A dry pool degrades
gracefully: no `opk` → 3-DH; no `kopk` → encapsulate to the KSPK.

## Transport (pinned TLS)

All mailbox traffic from native clients runs over **HTTPS/WSS with a pinned,
self-signed certificate** — no certificate authorities, no domain names, no
Certificate Transparency entries enumerating users. The trust chain
terminates at the Stonechat ID.

- On first boot the mailbox generates an ECDSA P-256 keypair and a
  long-lived self-signed certificate (persisted beside its DB; the key lives
  as long as the mailbox). The certificate authenticates the *pipe* only —
  message security never depends on it; that is the ratchet's job.
- Its fingerprint is `fp = BLAKE2b-256(cert_der)` over the DER-encoded
  certificate, reported as base64 in `/health`.
- The **owner** vouches for it:
  `tls_sig = Sign("stonechat-v1-tls", fp, identity_sk)` — over the 32 raw
  fingerprint bytes — published to the hub (`POST /v1/mailbox/tls`), which
  serves both fields in the directory record. Only the primary can do this;
  it needs the identity key.

**What a client MUST do on every mailbox connection:**

1. **Refuse any address whose scheme is not `https`.** A relay serves
   nothing else, so such an address did not come from one.
2. Verify `tls_sig` against the owner's (commitment-checked) identity key. A
   fingerprint without a valid signature is the directory's opinion; the
   mailbox is treated as unreachable, never as unpinned.
3. **Check the fingerprint itself, on the connection that will carry the
   request**, after the handshake and before a single byte of the request —
   and the token in its URL — is written: hash the leaf certificate the peer
   actually presented and compare with `tls_fp`. The platform's certificate
   validation is not consulted and its verdict is not used: no trusted
   roots, no hostname check. In particular a certificate a public CA vouches
   for MUST NOT be accepted on that ground; only the fingerprint decides.
4. Not send the request through a proxy.

Observing the certificate on one connection and sending the request on
another checks nothing: whoever sits on the path passes the first through
and answers the second. The same rule binds the hub when it talks to a
mailbox host ("Mailbox host").

Where the fingerprint comes from:

| Case | Source |
|---|---|
| **Bootstrap**: the owner's own mailbox, before any signature exists | The hub observed `tls_fp` via `/health` while waiting for the mailbox to become healthy and returns it in the owner's mailbox record — the channel that also delivers the owner token. The owner's app pins it for its own connection, signs it, and publishes the signature. |
| Self-hosted relay | The app observes the certificate on first contact with the box the user themselves provisioned (trust-on-first-use), then signs and publishes identically. |
| Linked device | Its link grant. |
| Recreated mailbox (new TLS key) | The hub clears the old signature, the owner's app re-signs on the next refresh, and peers re-fetch the fingerprint through the directory re-resolve path that handles address changes. |

### Browser transport (WebTransport)

A browser cannot do any of the above: `fetch` and `WebSocket` refuse a
self-signed certificate and expose no API to accept one. WebTransport's
`serverCertificateHashes` is the one exception. It is the same trust model —
pin the certificate, ignore CAs — under conditions the browsers set:

- the pin is **SHA-256 of the DER** (not BLAKE2b);
- the key must be ECDSA P-256;
- the certificate must carry a subjectAltName naming the address dialled;
- the certificate may be valid for **at most 14 days**.

So the relay runs a second listener (QUIC/UDP, default port 8443, separate
from the TLS listener) with its own short-lived certificates:

- It keeps a **schedule** of 12 certificates. Each is valid for 13 days and
  takes over 1 day before its predecessor expires; the first starts one day
  in the past. At any moment it serves the newest certificate already inside
  its window, and rotates in place without dropping live sessions.
- `GET /wt/certs` (no auth) publishes every unexpired certificate, including
  those not yet live, ascending by `not_before`:

  ```json
  {
    "certs": [
      {"sha256": "<base64 SHA-256 of the DER>", "not_before": 1790000000, "not_after": 1791123200},
      …
    ],
    "refresh_after": 1803000000
  }
  ```

  `refresh_after` is the largest `not_after` in the list. 404 when the
  browser transport is disabled.
- That endpoint *states*; it cannot *vouch*, being the thing under
  authentication. The **owner signs the list**:

  ```
  field(x)      = u32_be(len(x)) || x
  signing_bytes = u32_be(count)
               || for each cert, in list order:
                    field(utf8(sha256))            # the base64 text, as published
                 || field(i64_be(not_before))
                 || field(i64_be(not_after))
  wt_sig        = Sign("stonechat-v1-wtcerts", signing_bytes, identity_sk)
  ```

  The leading count stops a truncated list verifying as a prefix of the
  signed one — dropping the *future* certificates is how an attacker would
  strand a client on one they hold. Reordering changes the bytes.
  `refresh_after` is not signed.
- The owner publishes `{certs, wt_sig}` with `POST /v1/mailbox/wt`; the
  directory serves `wt_certs` and `wt_sig` together, or both null. It also
  serves `wt_address` (`host:port`), which is **unsigned**: rewriting it
  sends a client to a server whose certificate is not in the signed
  schedule, so the connection fails — denial, not compromise.

**What a browser client MUST do**, in order:

1. check the directory record against the ID it asked for;
2. verify `wt_sig` over the list exactly as served, against that identity
   key;
3. only then pass every entry with `not_after` in the future to
   `serverCertificateHashes` (all of them, since it cannot know which one
   the relay is serving);
4. validate `wt_address` as `host:port` — a host name, IPv4 literal or
   bracketed IPv6 literal, port 1–65535 — before building a URL from it.

**Framing.** The WebTransport session carries the relay's whole HTTP surface.
The session itself is **unauthenticated** — most of a relay's surface is
open by design — and the relay does not interpret the session URL's path or
query. Each request is one bidirectional stream:

```
request:   {"method":"POST","path":"/inbox","len":1234}\n<1234 bytes>
response:  {"status":200,"headers":{…},"len":56}\n<56 bytes>
```

One JSON header line (at most 8 KiB, newline-terminated), then exactly `len`
body bytes. `method` defaults to `GET` and `len` to 0. `path` includes the
query string, which is where a route's token goes, as over HTTPS. The
request is handed to the same router the TLS listener serves, so every
route, status code, body limit and rate limit is identical. A body that
stalls for 30 s is abandoned; a declared `len` above 64 MiB + 1024 is
answered `413`.

`/ws` is the upgrade: the relay answers `{"status":101}\n` (or
`{"status":403,"headers":{},"len":0}\n` for a bad token) and the stream then
carries the owner socket as newline-delimited JSON — envelopes down,
`{"ack": "<id>"}` up. A close is a final line
`{"close": <code>, "reason": "<text>"}` with the same codes the WebSocket
uses.

## Directory resolution

`GET {hub}/v1/directory/{stonechat_id}` returns:

```json
{
  "stonechat_id": "SC-…",
  "pubkey": "<base64 Ed25519 identity key>",
  "pq_pk": "<base64, 1216 bytes>",
  "pq_sig": "<base64>",
  "devices": { …device manifest, "Device manifest"… } | null,
  "mailbox": {
    "address": "https://203.0.113.7:8080",
    "status": "running",
    "tls_fp": "<base64>",
    "tls_sig": "<base64> | null",
    "wt_address": "203.0.113.7:8443 | null",
    "wt_certs": [ {"sha256", "not_before", "not_after"}, … ] ,
    "wt_sig": "<base64> | null"
  }
}
```

`mailbox` is `null` unless the identity has a mailbox whose status is
`running`. `wt_certs` is `null` when no schedule has been signed. `devices`
is `null` until the owner publishes a manifest.

The directory is untrusted. A client that resolves an ID:

1. MUST check the answer **against the ID it asked for** — both that the
   returned `stonechat_id` equals it and that `pubkey` hashes to it. Checking
   the key against the ID *in the answer* proves nothing: a directory that
   returns somebody else's complete record is internally consistent.
2. MUST verify `tls_sig` before using `address` ("Transport"), and `wt_sig`
   before pinning anything from `wt_certs`; and MUST verify `devices`, when
   present, as "Device manifest" says, refusing the record if it does not
   verify — a directory serving a manifest the owner did not sign is not
   serving the owner's record.
3. For a peer it **already knows**, uses the identity key it already holds —
   provided that key still hashes to the peer's ID — for everything that
   needs one: verifying device certificates on send and on receive. An ID
   commits to exactly one key, so asking again could only tell the hub who
   is writing to whom and make receiving depend on the hub being up. The
   directory is asked for a key only the first time a client deals with an
   ID; after that, only for where the mailbox is.

The identity key is never learned from an envelope. The `ik` in an `x3dh`
block is a *device* key and does not hash to anything.

## Session crypto

All shared constants. `H(msg, key, n)` is keyed BLAKE2b (key lengths 16–64
bytes).

### PQXDH (session establishment)

X3DH plus an ML-KEM-768 encapsulation, after Signal's PQXDH
(docs/POST_QUANTUM.md): the classical DHs authenticate, the KEM share makes
the root key — and therefore the whole ratchet chain derived from it —
resistant to harvest-now-decrypt-later. Both halves are always present;
neither is ever a substitute for the other.

**Sessions are device-to-device.** A session is between one device of the
sender and one device of the recipient, and the long-term keys in the
handshake are the two devices' **signing keys**, converted Ed25519→X25519 by
the standard birational map (what libsodium calls
`crypto_sign_ed25519_*_to_curve25519`). The identity keys take no part.

Alice's device `A` initiates to Bob's device `B`. `DKx` denotes a device
signing key converted to X25519. `A` generates an ephemeral X25519 keypair
`EK`, and encapsulates to `B`'s KOPK when the bundle had one, else to its
KSPK:

```
DH1 = scalarmult(DKx_A_priv, SPK_B)
DH2 = scalarmult(EK_priv,    DKx_B)
DH3 = scalarmult(EK_priv,    SPK_B)
DH4 = scalarmult(EK_priv,    OPK_B)          # only if the bundle had an opk
KCT, KSS = ML-KEM-768.Encaps(KOPK_B or KSPK_B)
SK  = H(DH1 || DH2 || DH3 [|| DH4] || KSS, key = "stonechat-v1-pqxdh-kdf", 32)
```

`DKx_B` comes from the `sig_pub` of `B`'s verified certificate. DH1/DH2 bind
both device keys, and the certificates bind each device key to its
identity — so decryption succeeding proves the peer device holds a key the
peer's identity vouched for. That is what authenticates a message.

Until `A`'s session is **confirmed** (it has decrypted one message from `B`
on it), every envelope it sends carries an `x3dh` block, so `B` can
establish the session whichever message arrives first:

```json
"x3dh": {
  "ik": "<base64 — A's DEVICE signing key (sig_pub), Ed25519>",
  "cert": { …A's device certificate… },
  "ek": "<base64 X25519>",
  "spk_id": 7,
  "opk_id": 41,
  "kct": "<base64, 1088 bytes>",
  "kem_id": 51,
  "kem_one_time": true
}
```

`opk_id` is omitted when the bundle had no OPK. `kem_id` names the KOPK
(`kem_one_time: true`) or the KSPK (`false`) that was encapsulated to.

`B`, on receiving an envelope with an `x3dh` block for which it has no
working session, MUST, before computing anything:

1. take the sender's **identity key** from what it already holds for
   `from`, or from the directory ("Directory resolution") — never from the
   envelope;
2. verify `x3dh.cert` against that identity key, and that it names `from`
   and `from_device`;
3. check that `x3dh.ik` **equals the certificate's `sig_pub`**. Without this
   the certificate would be decoration: a valid certificate for one key
   beside a handshake made with another.

It then computes the same DHs from the other side (using its own device
signing key and the SPK named by `spk_id`), decapsulates `kct` with the KEM
prekey named by `kem_id`, and decrypts the message. Only after that first
decryption succeeds does it store the session and delete the one-time
private halves that were used — replayed initial messages that used a
one-time prekey then fail cleanly. **A responder session whose first
decryption fails MUST be discarded**; nothing about it has been
authenticated.

Two collisions:

- **Simultaneous initiation.** If a valid initial envelope arrives while `B`
  holds an *unconfirmed* session it initiated itself to that same device,
  the session initiated by the **lower Stonechat ID** (byte-wise comparison
  of the canonical ID strings) wins; the loser's initial envelopes are
  dropped, which the normal pending-outbox retry absorbs.
- **Replacement.** If `B` holds a session that fails to decrypt the envelope
  and the envelope carries a valid `x3dh` block, the new session
  **replaces** the old one. This is how a peer who reinstalled gets
  through, and also the opening "Threat notes" describes under replay.

### Double ratchet

Standard Signal double ratchet over the primitives above:

```
KDF_RK(rk, dh):  out = H(dh, key = rk, 64) → (rk', ck) = (out[0:32], out[32:64])
KDF_CK(ck):      mk  = H(0x01, key = ck, 32);  ck' = H(0x02, key = ck, 32)
```

- Initiator: `DHs` = fresh X25519 pair; `RK, CKs = KDF_RK(SK, scalarmult(DHs, SPK_B))`;
  `B`'s `SPK` is its initial ratchet key.
- Responder: `RK = SK`, `DHs` = SPK pair; the first received header triggers
  the usual DH-ratchet step, after which it can send.
- Every message: `mk, ck' = KDF_CK(ck)`. Every observed new remote ratchet
  key: two `KDF_RK` steps (receive chain, then fresh send chain).
- Out-of-order messages use stored skipped keys: a gap of more than
  `MAX_SKIP = 256` on one chain is refused; at most 512 skipped keys are
  stored per session, oldest evicted first. A skipped key is deleted when it
  is used, and otherwise stays until it is evicted or the session is
  replaced.
- A failed decryption leaves the session state untouched.

### Post-quantum ratchet

The DH ratchet heals a compromised session with X25519 alone. On top of it,
a session periodically runs an ML-KEM-768 exchange and folds the result
into the root key, so that healing also holds against an attacker who can
break X25519 (docs/POST_QUANTUM.md). It is sparse: most messages carry
nothing for it.

The roles are fixed by the handshake. The session's **initiator** generates
KEM keys and mixes; the **responder** encapsulates. The material travels in
an optional `pq` object in the ratchet header:

```json
"ratchet": {
  "dh": "…", "pn": 0, "n": 3,
  "pq": {
    "mix": 4,
    "ek": {"id": 5, "pub": "<base64, 1184 bytes>"},
    "ct": {"id": 5, "ct": "<base64, 1088 bytes>"}
  }
}
```

Every field of `pq` is optional, and `pq` is absent when it would be empty.
Key ids count up from 1 within a session.

1. **Advertise.** When the initiator performs a DH-ratchet step (it has
   received a new remote ratchet key and starts a new sending chain), and at
   least `PQ_INTERVAL = 50` messages have been sent or received on the
   session since the last mix (or since PQXDH), and it has no key
   outstanding, it generates an ML-KEM-768 keypair with the next id and
   sends the public half as `ek`.
2. **Encapsulate.** The responder, on an authenticated message carrying an
   `ek` whose id is greater than the last id mixed and than the id it is
   already answering, encapsulates to it and sends the ciphertext as `ct`
   with the same id. It keeps the shared secret.
3. **Decapsulate.** The initiator, on an authenticated message carrying a
   `ct` for the id it is advertising, decapsulates, **deletes the KEM
   private key**, and holds the shared secret for its next sending chain.
4. **Mix.** At its next DH-ratchet step the initiator folds the secret into
   the root key immediately before deriving the new sending chain, and puts
   the id in `mix` on **every** message of that chain:

   ```
   KDF_PQ(rk, ss):  rk' = H("stonechat-v1-pqratchet" || ss, key = rk, 32)

   initiator, new sending chain:   rk = KDF_PQ(rk, ss);  rk, CKs = KDF_RK(rk, dh)
   responder, receiving that chain: rk = KDF_PQ(rk, ss);  rk, CKr = KDF_RK(rk, dh)
   ```

   The responder, on a header with a new ratchet key and a `mix`, MUST hold
   the secret for that id — otherwise the message does not decrypt — and
   discards it once mixed. `mix` on a later message of the same chain needs
   no action. Both sides then count the interval from zero.

`ek` and `ct` are large, so they are not sent on every message: each is
attached to the first `PQ_ATTACH = 3` messages sent after it becomes
pending, and again to the first three of every later sending chain, until it
is answered (`ek` by a `ct`, `ct` by a `mix`). A key or ciphertext that is
lost entirely is therefore offered again a round trip later. Repeats, stale
ids and malformed keys are ignored; they never fail a message that
otherwise decrypts.

The exchange takes two and a half round trips and only advances when the
conversation alternates, like the DH ratchet itself. The interval is counted
in messages because the session layer has no clock.

### Message encryption

```
ciphertext = crypto_aead_xchacha20poly1305_ietf_encrypt(
    plaintext, ad, nonce = random 24 bytes, key = mk)

ad = "stonechat/v1|{from}|{from_device}|{to}|{device}|{type}|{ratchet.dh}|{ratchet.pn}|{ratchet.n}"
     [ "|pq|{mix}|{ek.id}|{ek.pub}|{ct.id}|{ct.ct}" ]      # only when the header has a pq object
```

The associated data is that string in UTF-8: nine fields joined by `|`.
`from` and `to` are canonical Stonechat IDs; `from_device`, `device`, `pn`
and `n` are decimal integers without padding; `type` is the envelope type;
`ratchet.dh` is the base64 text exactly as it appears in the header. There
is one form, used on every message whether or not either side has more than
one device.

When the header carries a `pq` object, six more fields follow: the literal
`pq`, then `mix`, `ek.id`, `ek.pub`, `ct.id` and `ct.ct` — numbers in
decimal, base64 exactly as in the header, and an absent field as the empty
string. This is what authenticates the KEM material: a `pq` object that is
stripped, added or altered changes the associated data and the message does
not decrypt.

Binding both device numbers ties a ciphertext to one ratchet: an envelope
relabelled as coming from, or going to, another device fails to decrypt.
These fields are "cleartext" only to the recipient: on the wire they live in
the inner envelope, inside the transport seal.

## Envelope

All traffic between users is an **envelope**. What a mailbox stores and
forwards is the **sealed** (outer) form:

```json
{
  "v": 1,
  "id": "<uuid, sender-generated>",
  "to": "<recipient Stonechat ID>",
  "device": 2,
  "sealed": "<base64>",
  "blob_id": "<uuid, optional — only on DM media envelopes>",
  "transient": true,
  "push": false,
  "ring": true
}
```

`v`, `id`, `to`, `device` and `sealed` are **required**. `device` is the
recipient device whose queue this copy belongs in. It has no default: the
associated data binds the same number, and an implicit value would make
sender and receiver agree on what "absent" meant. It reveals nothing new,
being meaningful only to the recipient's own mailbox, which is the device
registry.

`transient`, `push` and `ring` are optional **delivery hints** for the
recipient's mailbox (booleans; absent means normal delivery):

| Hint | Meaning | Used for |
|---|---|---|
| `transient: true` | Deliver only if the addressed device is connected right now; never queue, never trigger a push ping. | typing indicators and call ICE candidates, which are worthless late |
| `push: false` | Queue and deliver normally, but never wake the device for it. | receipts, profile updates and self-sync |
| `ring: true` | Queue and deliver normally, and mark the wake-up as a call. It shortens the mailbox's wait before it pings (2 s instead of 10 s) and is debounced on its own 2 s window; the flag is forwarded to the push gateway ("Push gateway"). | `call_offer` |

All are necessarily mailbox-visible, and all are honesty-only (a hostile
mailbox already controls delivery). None tells an observer anything that
envelope size and timing don't.

**The seal.** The inner envelope is sealed to the recipient **device's**
X-Wing key — the `seal_pub` of its verified certificate:

```
kem_ct, kem_ss = XWing.Encaps(seal_pub_of_recipient_device)   # 64 bytes of randomness
key    = H(kem_ss, key = "stonechat-v1-hsealkdf", 32)
nonce  = random 24 bytes
sealed = kem_ct (1120) || nonce (24) || crypto_aead_xchacha20poly1305_ietf_encrypt(
             pad(inner_envelope_json), ad = "stonechat-v1-hseal", nonce, key)
```

**Padding.** What is sealed is padded to a size bucket, so that a mailbox
cannot tell a receipt from a message from a roster by length:

```
pad(m)  = m || 0x80 || 0x00 … 0x00          up to bucket(len(m))
bucket(n) = the smallest of 2048, 4096, 8192, 16384, 32768 that is ≥ n + 1,
            else n + 1 rounded up to a multiple of 1024
```

The `0x80` marker is always present, so the padded form is always longer
than the content. A recipient strips the trailing zeros and the marker, and
MUST drop a seal whose content does not end that way or is not exactly the
bucket its content pads to. Everything short — receipts, typing, text, a
group message — is one size on the wire (2048 bytes of content, 3208 sealed);
what the remaining buckets still tell apart is in "Threat notes". Blobs are
not padded.

X-Wing is draft-connolly-cfrg-xwing-kem, revision 06. The seal is
*anonymous* and *hybrid* — a fresh encapsulation per envelope, no sender key
anywhere in it, and X25519 + ML-KEM-768 in one KEM, so a recorded envelope
stays sealed against a future quantum attacker. The wire form identifies no
sender, carries no type, and cannot be linked to a session across envelopes.
The seal has no forward secrecy of its own ("Threat notes").

`/inbox` only checks `to == owner` and that `device` exists. `blob_id` is
the one extra hint: the mailbox uses it solely to garbage-collect the blob
when the last envelope naming it is acked.

The **inner envelope**, visible only to the recipient device after unsealing
with its own seal seed:

```json
{
  "v": 1,
  "id": "<same uuid as the sealed form>",
  "type": "msg" | "media" | "contact_request" | ...,
  "from": "<sender Stonechat ID>",
  "from_device": 1,
  "to": "<recipient Stonechat ID>",
  "device": 2,
  "sent_at": "<ISO-8601 UTC>",
  "ratchet": {"dh": "<base64 ratchet pubkey>", "pn": 0, "n": 3, "pq": { …optional, see "Post-quantum ratchet"… }},
  "x3dh": { …see "PQXDH"… },
  "nonce": "<base64, 24 bytes>",
  "ciphertext": "<base64>",
  "blob_id": "<uuid, optional — only on type=media>",
  "bundle_token": "<hex, optional — the SENDER's mailbox's bundle token>",
  "manifest_v": 7
}
```

`manifest_v` is the version of the sender's device manifest as the sender
knows it ("Device manifest"); absent or 0 when it knows of none. Inside
the seal and the ratchet, so only the recipient reads it; not
authenticated beyond that, since the worst a false value does is cause or
skip one directory lookup.

`from_device` and `device` are required. `ratchet` is the double-ratchet
header. `x3dh` appears only on a session's initial envelopes (until
confirmed).

**Ids are UUIDs.** `id` and `blob_id` are UUIDs in the canonical
36-character form (`8-4-4-4-12` hex digits). A receiver MUST reject an inner
envelope whose `id` — or `blob_id`, when present — is anything else: the id
names the media file on disk and the blob id is put in a URL, so neither is
taken on trust. Blob ids are minted by the mailbox that stores the blob and
are lower-case.

**What a recipient checks**, dropping the envelope silently on any failure:

1. the outer `to` is itself;
2. `sealed` opens with its own seal seed, and what it holds is padded as
   above;
3. the inner envelope parses, with `id` (and `blob_id`) a UUID;
4. the inner `to` is itself;
5. the inner `id` **equals the outer `id`**. One id names a message
   everywhere — it is what gets acked, stored and receipted — and an inner
   id that disagrees is a sender trying to be filed under a name the mailbox
   never saw;
6. the message decrypts on the session keyed by `(from, from_device)`, or a
   session can be established from its `x3dh` block ("PQXDH");
7. the sending device still speaks for the sender: the certificate the
   receiver holds for `(from, from_device)` is unexpired (else refetched
   from the sender's mailbox, and the envelope dropped if none is current),
   and, when the sender has a device manifest, the device is listed on it
   with that certificate's key ("Device manifest"). Checked on every
   envelope, not only when a session begins: a device may have been
   revoked since.

A dropped envelope is still acked: it can never succeed, and leaving it
queued would replay it on every connect. The sender's pending-outbox retry
re-encrypts fresh. An envelope whose processing fails *transiently* (a blob
that cannot be fetched right now) is left un-acked and redelivered on the
next connect.

### Per-device fan-out

One logical message to a peer with *k* devices is *k* envelopes: each
encrypted on its own ratchet, with its own associated data, sealed to its
own device's key, addressed to its own queue. They all carry the **same
`id`**; the mailbox keys its queue by `(id, device)`.

To send to a peer, a client:

1. determines the peer's devices. With the peer's bundle token it reads
   `GET /prekeys/devices`; without one it can reach **device 1 only** —
   which is what a stranger sending a first contact request gets. Listing
   is an optimisation, never a precondition: if it fails the client still
   sends to device 1;
2. for each device, obtains and verifies its certificate, establishes a
   session if there is none, encrypts, seals and posts;
3. treats the message as delivered to that peer only when every listed
   device has accepted its copy, and retries the ones still owed. A device
   answered with `410` is gone: the client forgets its session and owes it
   nothing.

A recipient's devices share one mailbox, so a client SHOULD send all of a
peer's copies over one connection.

A peer's bundle token is learned from the `bundle_token` of any envelope
they send, whoever they are — contact, fellow group member, or neither.

### Self-sync

A user's own devices are peers like any other: ordinary pairwise sessions
between sibling devices, bootstrapped from the user's own mailbox with the
bundle token, sealed to the sibling's certified key. Self-sync envelopes are
`from` and `to` the same Stonechat ID, and set `push: false`.

A receiver applies a `sync_*` envelope **only when `from` is its own
Stonechat ID**. The session already proves the sender holds a device key
that identity certified; this check stops a *peer* from writing the user's
history.

| type | payload | effect on the receiving sibling |
|---|---|---|
| `sync_sent` | `{"peer" \| "group_id", "type", "payload", "id", "sent_at"}` | stores an outgoing message. `type`/`payload` are the type and payload that were sent to the peer; `id` is the message id; `sent_at` is **milliseconds** since the epoch (unlike the envelope's ISO `sent_at`) |
| `sync_read` | `{"peer" \| "group_id", "ids": ["<message id>", …]}` | marks those incoming messages read, without sending a receipt |
| `sync_clear` | `{"peer" \| "group_id"}` | deletes that conversation's history; the conversation itself stays |
| `sync_cert` | `{"cert"}` | from the primary to one linked device: a renewed certificate over that device's keys ("Device certificates"). Adopted only if it verifies against the identity key, names this device's ID, slot and keys, and is later than the one held |
| `sync_block` | `{"peer", "blocked_at": <ms> \| null}` | blocks (`blocked_at` set) or unblocks (`null`) that Stonechat ID |

Exactly one of `peer` (a DM, the peer's ID) or `group_id` names the
conversation.

Incoming messages need no sync — every device gets its own copy from the
sender. Outgoing **media** cannot be mirrored verbatim, because DM media
parks its ciphertext on the *recipient's* mailbox, where a sibling holds no
token. The sending device therefore uploads a second, separately encrypted
copy to the user's **own** mailbox as a shared blob and sends `sync_sent`
with `payload` rewritten to point at it (`blob_id`, `key`, `blob_nonce`,
`fetch_token`, `blob_host`, `blob_tls_fp` — the group-media fields).

The admin of a group also sends `group_create` / `group_update` to its own
sibling devices, which are not members and would otherwise never learn the
roster; a device that finds itself behind asks its siblings with a
`group_sync` ("Keeping the roster in step"). All self-sync is best-effort:
no durable retry.

### Plaintext payloads (JSON, encrypted)

| type              | payload                                |
|-------------------|----------------------------------------|
| `msg`             | `{"text": "...", "expire_after_ms"?, "reply_to"?}` |
| `media`           | `{"blob_id", "key", "blob_nonce", "mime", "kind": "image"\|"audio"\|"video"\|"file"\|"sticker", "size", "duration_ms"?, "name"?, "expire_after_ms"?, "reply_to"?}` |
| `contact_request` | `{"display_name": "...", "avatar"?, "hub"?}` |
| `contact_accept`  | `{"display_name": "...", "avatar"?, "hub"?}` |
| `profile_update`  | `{"display_name"?, "avatar"?: {"data": "<base64>", "mime"} \| null}` — wire form SHOULD set `push: false` |
| `group_create` / `group_update` | `{"group_id", "name", "version", "admin", "members": [{"stonechat_id", "pubkey", "display_name"}], "expire_ms"?}` |
| `group_sync`      | `{"group_id", "version"}` — "send me the roster"; `version` is the one the asker holds (0 for none). Wire form MUST set `push: false` |
| `group_msg`       | `{"group_id", "text", "roster"?, "salt"?, "seen"?, "expire_after_ms"?, "reply_to"?}` — `roster`, `salt` and `seen` are described under "Groups" |
| `group_media`     | `group_msg`'s fields minus `text`, plus `media`'s, plus `{"fetch_token", "blob_host", "blob_tls_fp"}` — see "Group media" |
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
| `sync_sent`, `sync_read`, `sync_clear`, `sync_block` | see "Self-sync" |

Member `pubkey` entries are Ed25519 **identity** keys (same commitment check
as the directory). A client that does not implement a type decrypts it — to
keep the ratchet current — and drops it.

Unknown senders: clients only render `msg` envelopes from accepted contacts.
Anything else from a stranger is shown as a pending contact request at most.

### Receipts, typing, edit/delete

All ride ordinary pairwise sessions — same encryption, same sealed
envelope; a mailbox cannot tell a receipt from a message (beyond size). The
**message id** they reference is the original envelope's `id`, which
per-device and group fan-out reuse across every copy.

- **`receipt`** — sent by the recipient of `msg`/`media`/`group_msg`/
  `group_media` back to its author, batched (one envelope may cover many
  ids). `delivered` fires when the message is persisted; `read` when it is
  displayed (client setting; delivered is unconditional). Wire form SHOULD
  set `push: false`. Receivers apply a receipt only if the referenced
  message is outgoing and the receipt's sender is the DM peer (or, for
  groups, a current member — tracked per member; a group message counts
  delivered/read when *every* other member is). Statuses only move forward.
  Best-effort: no durable retry.
- **`typing`** — throttled to one `started` per ~8 s of continuous typing;
  receivers expire it after ~15 s without a refresh, on `stopped`, or when
  the sender's message arrives, and ignore one whose `sent_at` is more than
  60 s from their own clock. Clients only send typing on already-established
  sessions (never fetch a prekey bundle for it) and MUST mark the wire
  envelope `transient` — a queued typing indicator is noise, and dropped
  ones merely become skipped message keys within `MAX_SKIP`.
- **`msg_edit` / `msg_delete`** — only valid from the original author, which
  the session already authenticates: receivers check the referenced message
  is incoming, in that conversation, and (groups) written by `from`. Senders
  offer edit/delete-for-everyone for 24 h; receivers allow 36 h to absorb
  clock skew and queue delay. Edits replace the text and mark it edited;
  deletes tombstone the message ("message deleted"). Both are cooperative,
  not cryptographic: an unmodified client honors them, nothing forces a
  hostile one to. A DM edited while still in the sender's pending outbox is
  rewritten before first delivery. Best-effort (no durable retry); an
  unreachable member keeps the old content.
- **`reaction`** — one emoji per (message, reactor); a new reaction replaces
  the previous one, the empty string clears it. Either side of a DM (or any
  current group member) may react to any non-deleted message; receivers
  key the stored reaction by the session-authenticated sender, so nobody
  can react in someone else's name, and ignore an `emoji` longer than 32
  UTF-16 units. Best-effort, like receipts.

### Replies (`reply_to`)

`msg`, `media`, `group_msg` and `group_media` payloads MAY carry a quote of an
earlier message in the same conversation:

```json
"reply_to": {"id": "<message id>", "sender": "<Stonechat ID>", "preview": "..."}
```

The block is a **display snapshot**, not a reference the receiver must
resolve: `preview` (sender-clipped to 140 chars) and `sender` are rendered
as-is, so a quote of a message the receiver no longer holds (expired,
deleted, pre-history) still displays. When the receiver does hold `id`
locally, clients offer jump-to-original. The block is cooperative display
data, like reactions: receivers cap the preview length and ignore malformed
blocks, and a lying sender can only misquote inside a conversation the
session already authenticates them into.

### Profiles (`profile_update`)

A user's profile — display name and photo — is client-held data pushed over
the ordinary pairwise sessions, never stored on the hub or any mailbox. The
photo therefore inherits E2EE, and only travels to people the owner already
trusts:

- **Audience** — accepted contacts only. Receivers drop `profile_update`
  from anyone else. `contact_request` / `contact_accept` MAY carry the
  sender's current profile (`avatar` in the same shape) so the first render
  is immediate; a requester's photo reaches the recipient with the request,
  the accepter's flows back with the accept.
- **`avatar` field** — absent means *unchanged*, `null` means *cleared*,
  otherwise `{"data": "<base64 image bytes>", "mime": "image/jpeg"|…}`.
  Senders scale the image down (≤ 256 px, ≤ 24 KiB raw) so the envelope
  stays under the mailbox's 64 KiB envelope cap after the base64 layers;
  receivers accept up to twice that decoded size and drop anything larger
  or undecodable. Like `reply_to`, the image is cooperative display data.
- **Last-writer-wins** — receivers store the `sent_at` of the profile they
  hold and ignore an update that is not newer, so replayed or out-of-order
  envelopes cannot regress a profile (same rule as `timer_update`).
- **Fan-out** — on any profile change the owner sends one `profile_update`
  to every accepted contact. Best-effort (no durable retry): an unreachable
  contact keeps the old profile until the owner's next change reaches them.
  Wire form SHOULD set `push: false`.
- **Groups** — membership fan-outs carry no images. A member's photo is
  rendered only where the viewer knows them as an accepted contact;
  everyone else stays on the ID-derived fallback.

### Disappearing messages

A per-conversation timer: while it is active, every new message the
conversation's participants send carries `expire_after_ms`, and each
device deletes its copy `expire_after_ms` after the envelope's `sent_at`
— read or not. Changing or disabling the timer never touches messages
already sent.

- **Setting the timer** — either DM party sends `timer_update`; any
  current group member fans `group_timer_update` to the other members
  (receivers drop it unless `from` is a current member). Clients offer
  0 (off), 1 hour, 24 hours and 7 days; receivers accept any
  non-negative integer.
- **Last-writer-wins** — receivers store the change time of the timer
  they hold and ignore an update whose envelope `sent_at` is not newer,
  so replayed or out-of-order updates cannot regress the setting.
- **Per-message field is authoritative** — a receiver computes expiry
  from the message's own `expire_after_ms`, never from its local
  setting, so messages queued offline or racing a `timer_update` expire
  as the sender intended, regardless of arrival order.
- **Joiners** — `group_create`/`group_update` MAY carry `expire_ms`
  (the group's current timer). A client applies it only when learning
  of the group for the first time; established members ignore it, so a
  membership fan-out cannot clobber a newer member-set timer.
- Like `msg_edit`/`msg_delete`, this is **cooperative, not
  cryptographic**. Timer updates are best-effort (no durable retry); an
  unreachable member keeps the old timer until someone changes it again.

### Calls (1:1, WebRTC)

Calls are between **accepted contacts only**. The envelope layer is the
signaling channel: SDP and ICE ride ordinary ratchet-encrypted envelopes,
so signaling inherits E2EE. Because the session authenticates the sender
and the SDP carries the DTLS certificate fingerprints, the DTLS-SRTP media
keys are authenticated end-to-end with no additional cryptography. **Media
never touches a mailbox's queue**: it flows peer-to-peer (or through a TURN
relay, below).

- `call_id` is a caller-generated uuid4; every envelope of the call carries
  it, and anything referencing an unknown/ended call is dropped.
- A receiver ignores a `call_offer` whose `sent_at` is older than 60 s and
  records a missed call instead. Both sides give up ringing after 45 s
  (caller sends `call_end reason=timeout`).
- A second concurrent `call_offer` from anyone is answered with
  `call_end reason=busy`.
- **Glare** (both sides call each other simultaneously): the offer from the
  **lower Stonechat ID** wins; the other side discards its own attempt and
  treats the winning offer as incoming — same tiebreak as simultaneous
  PQXDH.
- `call_ice` envelopes are transient: late candidates are useless, and if
  the peer is not connected the call is failing anyway. Offers, answers and
  hangups are normal (queued) envelopes.
- IP privacy: exchanging ICE candidates reveals device addresses to the
  *peer* (an accepted contact). Callers who consider that sensitive route
  through TURN/VPN; a relay-only mode is planned, not present.

#### TURN (`/turn-credentials`)

NAT-hostile paths need a relay: **the user's own mailbox box** runs a coturn
beside `stonechat-relay`, sharing a secret via `STONECHAT_TURN_SECRET`. The
mailbox mints ephemeral credentials (coturn's TURN REST API scheme —
`username = "<expiry>:stonechat"` with `expiry` = now + 21 600 s in Unix
seconds, `credential = base64(HMAC-SHA1(secret, username))`):

| Method | Path                | Auth      | Description |
|--------|---------------------|-----------|-------------|
| GET    | `/turn-credentials` | any device token | `{"urls": ["turn:<host>:<port>?transport=udp"], "username", "credential", "ttl": 21600}`. `<host>` is the host the client addressed the request to; `<port>` is `STONECHAT_TURN_PORT` (default 3478). 404 when the relay has no TURN (`STONECHAT_TURN_SECRET` unset). |

Each side fetches credentials from its **own** mailbox and contributes its
own relay candidates; either side's relay can carry the call. Clients fall
back to STUN-only when their mailbox serves no TURN.

### Media (photos, videos, voice notes, documents)

`kind` says how to render:

| `kind` | Rendering |
|---|---|
| `image` | an image; also how an unknown `kind` renders |
| `audio` | voice note |
| `video` | video |
| `file` | arbitrary document; `name` carries its original filename — receivers MUST strip any path components and take only the basename |
| `sticker` | a small transparent image — canonically 512×512 WebP — rendered inline without frame chrome; receivers treat it exactly like `image` otherwise |

Sticker packs are a purely client-side concept: nothing about packs exists
on the wire.

Media never travels inside the envelope. The sender:

1. generates a one-off XChaCha20-Poly1305 key (32 bytes) + nonce (24),
2. encrypts the file with it (empty associated data) and `POST /blob`s the
   ciphertext **once** to the *recipient's* mailbox → `blob_id`,
3. sends a `media` envelope to each of the recipient's devices. The
   (session-encrypted) payload carries the `blob_id`, the `key`/`blob_nonce`
   (base64), and display metadata; the outer envelope carries the same
   `blob_id`.

A recipient device downloads `GET /blob/{id}` from its own mailbox with its
device token, decrypts with the key from the payload, persists locally, then
acks the envelope. The mailbox deletes the blob when **no queued envelope on
any device** still names it — so the first device to ack does not pull the
file out from under its siblings. Only the recipient's devices ever hold the
blob key, so the mailbox stores ciphertext it cannot open. Blob keys inherit
forward secrecy from the envelope layer that carries them.

A receiver never overwrites the media of a message it already holds: the
message id is the file's name, so writing again would let anyone who
learned an id replace somebody else's media.

### Groups (client-side fan-out)

A group is **not a stored object anywhere**. Neither the hub nor any
mailbox stores a member list or a group name, or can distinguish a group
message from a DM — each group message is ordinary pairwise envelopes, one
per member device, encrypted with that device's normal pairwise session
(established on demand from its prekey bundle) and sent to each member's
own mailbox. Group traffic is therefore exactly as forward-secret as DMs.

- **The creator is the admin.** `group_create` and every `group_update` carry
  the *full* member list (including the admin and the recipient) and a
  `version` that increases on every change. The two types are applied
  identically.
- **Which roster a client accepts.** A client MUST ignore a roster:
  - whose `group_id` is not a UUID ("Envelope" — the id becomes a
    conversation key beside contacts' Stonechat IDs, and a "group" named
    after a contact would capture what is typed to them);
  - with more than **100** members, with a member listed twice, or whose
    `admin` is not among its members;
  - with a member entry whose `pubkey` does not hash to its `stonechat_id`
    (same commitment check as the directory), so a malicious admin cannot
    silently substitute keys. One bad entry rejects the whole roster;
  - **for a group it does not hold:** whose `from` is not the payload's
    `admin`, or whose `from` is not one of its **accepted contacts** (or
    its own identity, mirroring a group between its devices). Fellow
    members may be strangers; the person who adds you may not;
  - **for a group it holds:** whose `from` is not the admin **it has on
    record**, or whose `version` is ≤ the one it holds. Checking `from`
    against the payload's own `admin` instead would let any member take a
    group over by naming themselves.
- **Handing over the admin role.** A roster from the admin on record that
  names a *different* member as `admin` is a handover: the client records the
  new admin, and from then on listens only to them. The former admin stays a
  member. A member who never held the group cannot learn of it from the
  handover roster (it is not from the admin it names); it learns of it from
  the new admin's next roster.
- A roster that no longer lists the recipient is its removal.
- `group_msg` / `group_media` are only rendered if `from` is a current member
  of a group the client holds a roster for.
- `group_leave` is a courtesy announcement; removal becomes authoritative
  with the admin's next `group_update`.
- The app builds groups of up to 25 members (fan-out is O(members × devices)
  per message); the 100 above is only what a receiver tolerates.

#### Keeping the roster in step

A member who misses a roster change keeps writing to people who were removed
and drops messages from people who were added, so rosters are not
best-effort.

- **Delivery.** The admin owes each roster to everyone it was addressed to —
  the members and anyone it just removed — until **every device** of each has
  accepted it, retrying with the same backoff and seven-day limit as a
  message. A retry sends the roster as it stands *then*, so someone removed
  in the meantime receives the roster that no longer lists them.
- **`roster` in every message.** `group_msg` and `group_media` carry the
  sender's view:

  ```json
  "roster": {"v": 7, "h": "<base64 roster hash>", "admin": "<Stonechat ID>"}
  ```

  ```
  h = BLAKE2b-256("stonechat-v1-roster|{group_id}|{version}|{admin}|{ids}")
  ```

  where `ids` is the roster's Stonechat IDs sorted and joined with `,`. The
  hash is over the roster **as the admin issued it**: applying a
  `group_leave` locally does not change it. `h` is omitted by a client that
  does not hold one (a group restored from a backup).
- **What a receiver does with it**, for a message from a current member:
  - `v` above its own: it is behind. It still renders the message, and sends
    the admin on record a `group_sync`.
  - `v` below its own: the sender is behind. If the receiver is the admin, it
    sends that member the current roster.
  - same `v`, different `h`: the admin issued two rosters under one version.
    The client tells the user that member lists differ.
  - no `roster`: nothing is concluded.
- **Messages that arrive ahead of their roster.** A message from someone not
  in the roster held, whose `roster.v` is above the version held — or for a
  group not held at all, whose `roster.admin` is an accepted contact — is
  **kept rather than dropped**: the client parks it (at most 200 in total,
  for at most seven days), sends that admin a `group_sync`, and processes it
  when the roster arrives. Anything else from a non-member is dropped.
- **`group_sync`.** Whoever receives one holds the group and is the admin on
  the asker's record. If the asker is in the roster it holds, and that roster
  is newer than the `version` asked about, it answers with the current roster
  as a `group_update`. A former admin answers too: for a member that missed
  the handover, it is the only sender whose roster will be accepted, and the
  roster it sends is the handover. Requests and answers are rate-limited by
  the clients (one request per group and version per ten minutes; one answer
  per member per minute).
- **An admin behind its own group.** An admin that sees a member's `v` above
  its own version (it was restored from an older backup, or another of its
  devices issued the roster) numbers its next roster past the highest `v` it
  has seen, so that members accept it, and asks its own devices for the
  roster with a `group_sync`.

#### Transcript consistency

Fan-out means a sender chooses what each member receives. Nothing can stop a
member from sending two members different text under one message id, but the
others can notice.

- Every `group_msg` and `group_media` carries a random 16-byte `salt`
  (base64). A receiver records, for each message it stores:

  ```
  content hash = BLAKE2b-256("stonechat-v1-gmsg|{group_id}|{from}|{id}|{salt}|{body}")
  body         = "text|{text}"                          for group_msg
                 "media|{blob_id}|{key}|{blob_nonce}"   for group_media
  ```

  The hash is of the message as it first arrived; edits do not change it.
- Every `group_msg` and `group_media` also carries `seen`: up to **4**
  `{"id", "h"}` pairs — the other members' messages that reached the sender
  since it last wrote to the group, newest first, with the content hashes it
  recorded.
- A receiver that holds a message named in `seen`, from a third member, with
  a **different** hash, tells the user: the two of them were sent different
  versions. It cannot tell whether the author sent two versions or the
  reporting member misreports; it reports the disagreement, not a culprit.
- The salt exists so that a member who was never sent a message cannot test
  guesses of its text against a hash that reaches them in `seen`.

A message that one member was simply never sent is **not** detected: `seen`
entries for ids the receiver does not hold are ignored, because delivery is
asynchronous and a missing message is usually only late.

#### Group media

DM media parks the ciphertext on the *recipient's* mailbox ("Media"). Doing
that per member would re-upload the same file N times, so group media
inverts it: **one blob, on the sender's own mailbox, N capability tokens'
worth of reads** — upload cost O(1) in members instead of O(N). The sender:

1. generates one XChaCha20-Poly1305 key + nonce and encrypts the file once,
2. `POST /blob?shared=1` to **their own** mailbox → `{blob_id, fetch_token}`,
3. fans out a `group_media` envelope to each member device, carrying
   `blob_id`, the `key`/`blob_nonce`, the `fetch_token`, and
   `blob_host`/`blob_tls_fp` — where to fetch it and which pinned
   certificate to expect.

Each member `GET /blob/{id}?token={fetch_token}` from the *sender's* mailbox,
decrypts with the key from the payload, and persists locally before acking.

Receivers MUST check `blob_host` against the sender's own mailbox address —
the directory entry for `from`, refreshed if the cached one disagrees — and
drop the media otherwise. `blob_host` is the only field in the protocol that
points a client at a host it did not choose, and a group member is not
automatically trusted to choose one. (A client MAY ignore `blob_host`
altogether and dial the sender's mailbox as the directory gives it, which is
what the browser client does.) A sender who moved mailboxes between sending
and the fetch fails closed (media unavailable).

Unlike DM media the outer envelope carries **no** `blob_id`: the blob does not
live on the recipient's mailbox, so their ack must not try to GC it. The
sender instead deletes it (`DELETE /blob/{id}`) once every member has
`delivered`-receipted the message; the 14-day blob TTL is the backstop for
members who never come back.

What this costs: a member fetching group media contacts the **sender's**
mailbox directly, so that host sees the member's IP and the fact that
someone fetched — where DM media only ever has the sender contacting the
recipient's box. It learns no identity from the request (the fetch carries
only a per-blob token) and no content: the key never touches the sender's
mailbox, it rides the ratchet inside the envelope.

## Routing model (mailbox)

Each user's mailbox is their **inbox**. To send to Bob, Alice's device:

1. resolves Bob — `GET {hub}/v1/directory/{bob_id}` → identity key (if
   Alice does not hold it yet), current mailbox address and TLS fingerprint
   — and verifies the answer ("Directory resolution");
2. lists Bob's devices and verifies their certificates; for each device
   with no session yet, `GET {bob_mailbox}/prekeys/bundle` and runs PQXDH;
3. encrypts on each session, seals each envelope to that device's certified
   X-Wing key, and `POST https://{bob_mailbox}/inbox` (pinned TLS);
4. if Bob has no mailbox or it's unreachable, queues locally and retries
   (the app backs off from 30 s to 30 min and gives up after 7 days).

Each of Bob's devices keeps a socket to *his* mailbox, authenticated with its
own device token, and acks envelopes as it persists them locally; each ack
deletes that device's copy from the mailbox's SQLite. On connect, a device
also republishes its prekeys and certificate (`POST /prekeys` with the full
remaining stock, so a fresh, recreated, or stale-stocked mailbox all
converge), and registers its push token (`POST /push-config`) so the mailbox
can wake it via the gateway while it's offline.

## Mailbox API (`relay/`)

Configured via env:

| Variable | Meaning |
|---|---|
| `STONECHAT_OWNER_ID`, `STONECHAT_OWNER_TOKEN` | the owner, and device 1's token |
| `STONECHAT_PORT` | TLS listener (default 8080) |
| `STONECHAT_WT_PORT` | browser transport (default 8443, UDP; `0` disables it) |
| `STONECHAT_WT_ADVERTISE` | the names the browser transport's certificates must carry |
| `STONECHAT_DB`, `STONECHAT_BLOBS`, `STONECHAT_TLS_DIR` | storage locations |
| `STONECHAT_TURN_SECRET` / `STONECHAT_TURN_PORT` | see "TURN" |
| `STONECHAT_PUSH_GATEWAY` / `STONECHAT_PUSH_KEY` | see "Push gateway" |
| `STONECHAT_MAX_QUEUE_BYTES` | see "Depositing" |
| `STONECHAT_LIMIT_INBOX` / `_BLOB` / `_BUNDLE` | see "Limits" |

All endpoints are served exclusively over TLS, and identically over the
browser transport (see "Transport").

Tokens are passed as the `token` query parameter. "Device" below means *any
valid, unexpired device token*; "primary" means device 1's.

| Method | Path          | Auth      | Description |
|--------|---------------|-----------|-------------|
| GET    | `/health`     | none      | Liveness only: `{"status": "ok", "v": <wire version>, "tls_fp": "<base64>"}`. Deliberately identity-free (see below). |
| GET    | `/status`     | device | The calling device's view: `{"status": "ok", "v", "queued": n, "prekeys": {"spk": bool, "opks": n, "kspk": bool, "kopks": n}, "device_id", "devices_v", "bundle_token", "build"}`. `queued` and `prekeys` are that device's own. `build` is the first 16 hex chars of BLAKE2b-256 of the running executable. |
| GET    | `/owner`      | none      | `?stonechat_id=` → 200 `{"owner_matches": true}` iff the mailbox's owner equals the supplied ID, else 404 (400 if absent). Confirms a *known* ID; never reveals one. |
| POST   | `/inbox`      | none      | Body: sealed envelope. See "Depositing" below. |
| GET    | `/prekeys/bundle` | none, or bundle token with `?device=` | One device's prekey bundle; consumes the returned one-time prekeys. Without `device`: device 1. 404 until that device has uploaded both signed prekeys; 400 on a non-integer `device`. |
| GET    | `/prekeys/devices` | bundle token (or device) | Every device's signed prekeys and certificate, plus `devices_v`. Consumes nothing. |
| POST   | `/prekeys`    | device | The calling device uploads `{spk, opks, kspk, kopks, cert?}` — its full remaining stock ("Prekeys"). Replaces that device's store. At most 256 `opks` and 64 `kopks`, else 400. Body ≤ 256 KiB and `cert` ≤ 8 KiB serialized, else 413. → `{"status": "ok", "prekeys": {…}}`. |
| GET    | `/devices`    | device | `{"devices_v", "devices": [{"device_id", "kind", "cert", "created_at", "expires_at", "last_seen"}]}`. Here `cert` is the stored certificate **as a JSON string** (or null), not an object. |
| POST   | `/devices`    | primary | `{"device_token": "<≥ 32 chars>", "kind"?: "linked"\|"web"\|"agent", "expires_in_s"?: 1…31536000}` → `{"device_id", "kind", "expires_at", "devices_v"}`. `kind` defaults to `linked`. 400 on a short token, unknown kind or out-of-range lifetime; 409 if the token is already a device's. |
| DELETE | `/devices/{id}` | see matrix | Revoke. → `{"status": "ok", "devices_v"}`. 400 non-integer id, 404 no such device. |
| POST   | `/blob`       | none      | Body: raw encrypted bytes (≤ 64 MiB), streamed to disk. → `{"blob_id"}`. With `?shared=1` (or `true`) also returns `{"fetch_token"}` — a per-blob read capability. 400 empty or interrupted, 413 too large, 507 storage full. |
| GET    | `/blob/{id}`  | device, or that blob's fetch token | Download a blob (`application/octet-stream`, with `Content-Length`). 400 malformed id, 404 no such blob. |
| DELETE | `/blob/{id}`  | see matrix | Idempotent (`{"status": "ok"}` even if already gone). |
| POST   | `/push-config`| device | The calling device registers `{"device_token", "platform": "ios"\|"android"}` for wake-up pings. Here `device_token` is the APNs/FCM token, not the mailbox device token. |
| GET    | `/turn-credentials` | device | See "TURN". |
| GET    | `/wt/certs`   | none      | The browser transport's certificate schedule ("Browser transport"). 404 when disabled. |
| WS     | `/ws`         | device | The owner socket for the calling device. See below. A bad or missing token is refused at the handshake with 403. |

Errors are JSON `{"detail": "<message>"}`. A missing or invalid token is
`401 {"detail": "owner only"}` on every authenticated route, whichever
credential was expected — a caller holding none learns nothing about what
exists.

`/health` carries no identity — only liveness, the wire version, and the
(already-public) TLS fingerprint — and `/owner` merely *confirms* a supplied
Stonechat ID, so neither lets a stranger scanning mailbox addresses learn or
enumerate a mailbox's owner.

### Who may do what

A device token is a login to that device's own things. It is not authority
over the mailbox; only device 1 manages it.

| | primary (device 1) | linked device | no valid token |
|---|---|---|---|
| `GET /status`, `POST /prekeys`, `POST /push-config`, `GET /ws` | own | own | 401 (`/ws`: 403 handshake) |
| `GET /devices`, `GET /turn-credentials` | yes | yes | 401 |
| `POST /devices` | yes | **403** | 401 |
| `DELETE /devices/{id}`, a linked device | yes | itself only, else **403** | 401 |
| `DELETE /devices/1` | **403** | **403** | 401 |
| `GET /blob/{id}` | yes | yes | that blob's fetch token, else 401 |
| `DELETE /blob/{id}` | yes | unless a sibling still has it queued (**403**) | 401 |
| `GET /prekeys/devices`, `GET /prekeys/bundle?device=` | yes | yes | the bundle token, else 401 |
| `POST /inbox`, `POST /blob`, `GET /prekeys/bundle`, `GET /health`, `GET /owner`, `GET /wt/certs` | open | open | open |

The reasons are the threat model:

- A linked device that could add devices could, if stolen, mint itself a
  successor with no expiry to outlive its own revocation.
- One that could revoke its siblings would make one stolen laptop enough to
  evict every other device.
- The primary cannot be revoked over the API by anyone, itself included:
  its row is the owner token, and removing it would lock the owner out.
  `DELETE /devices/1` is refused before the device is looked up, so a
  linked device learns nothing about which ids exist.
- The blob-delete rule exists because the only blob whose loss costs
  anybody anything is one a sibling has yet to fetch.

### Depositing (`POST /inbox`)

Checks, in order:

| Check | Failure |
|---|---|
| body ≤ 64 KiB | 413 `envelope too large` |
| body is JSON | 400 `not json` |
| an object with `v`, `id`, `to`, `sealed` | 400 `missing fields` |
| `v` is the integer 1 | 400 `unsupported protocol version (need v1)` |
| `id` a non-empty string | 400 `bad id` |
| `sealed` a non-empty string | 400 `bad sealed body` |
| `blob_id`, if present and not null: 36 characters from `[a-f0-9-]` | 400 `bad blob_id` |
| `transient`, `push`, `ring`, if present: booleans | 400 `bad <hint> flag` |
| `to` equals the mailbox's owner | 403 `not this mailbox's owner` |
| `device` is an integer | 400 `bad device` |
| `device` is a current device | **410** `{"detail": "no such device", "devices_v": n}` |

The mailbox checks the *shape* of `id`, not that it is a UUID; that is the
recipient's check. A `410` is permanent for that copy: the device was
revoked, expired, or never existed.

Then:

- **Transient** envelopes are handed to the addressed device's live socket
  if it has one and room for it (each connection holds at most 32 waiting
  transient frames). → `{"status": "delivered" | "dropped", "devices_v"}`.
  Never stored, never pushed for.
- **Duplicate.** If that device's queue already holds an envelope with this
  `id`, the deposit is answered exactly as the first was —
  `{"status": "queued", "devices_v"}` — and is otherwise a no-op: nothing is
  stored, delivered or pushed for again. Deduplication covers only what is
  still queued; once an envelope is acked its id is forgotten.
- **Full.** A device's queue is capped at 10 000 envelopes **and** at
  `STONECHAT_MAX_QUEUE_BYTES` (default 67 108 864, 64 MiB) of envelope
  bodies. Either cap → `503 mailbox full`. The caps are per device: one
  device that stops draining does not stop its siblings receiving.
- Otherwise the envelope is stored, the addressed device's connection is
  woken, and → `{"status": "queued", "devices_v"}`.

### The owner socket (`/ws`)

One live socket per **device**. A second connection for the same device
replaces the first, which is closed with code **4000** (`replaced by newer
connection`) — whichever transport either arrived on. A revoked or expired
device's socket is closed with **4001** (`device revoked`).

On connect the mailbox drains that device's queue, oldest first, and then
delivers new envelopes as they arrive. Each frame is one sealed envelope as
JSON text. The client replies `{"ack": "<envelope id>"}`, which deletes that
device's row — and the blob it names, once no device's queue names it.

Guarantees and limits:

- **Order.** Queued envelopes are sent in deposit order, each at most once
  per connection. The queue is read in pages of 16 through a cursor that
  only advances and whose sequence numbers are never reused, so an envelope
  deposited mid-drain is simply on a later page and none is skipped.
- **Redelivery.** An envelope that is not acked stays queued and is sent
  again on the next connection. Clients MUST therefore tolerate receiving
  the same envelope twice, and ack only after they have persisted it.
- **Transient frames** may interleave with queued ones and are dropped when
  the connection's 32-frame buffer is full.
- **Write timeout.** A peer that does not accept a frame within 30 s is
  disconnected; the next envelope then wakes it through the push gateway
  instead.
- A socket write succeeding is not delivery; only an ack counts ("Push
  gateway").

### Limits

`/inbox`, `/blob` and `/prekeys/bundle` are deliberately unauthenticated
(anyone may deliver mail or start a session). What a stranger can make a
mailbox hold is bounded:

| Bound | Value |
|---|---|
| envelope size | 64 KiB |
| queue depth and bytes, per device | see "Depositing" |
| blob size | 64 MiB |
| total blob storage | 1 GiB |
| blob age | garbage-collected when older than 14 days |

The prekey store holds only public keys; the worst an anonymous reader can
do is drain device 1's one-time pools, which degrades to 3-DH and the signed
KEM prekey.

How fast is limited too, by token bucket, per source address and in total:

| Route | Per address (rate/s, burst) | All addresses (rate/s, burst) |
|---|---|---|
| `POST /inbox` | 20, 200 | 100, 1000 |
| `POST /blob` | 1, 60 | 4, 240 |
| `GET /prekeys/bundle` | 0.5, 30 | 5, 300 |

A request needs a token from both buckets; one refused by its own address's
bucket does not spend from the shared one. Over the limit →
**`429 {"detail": "too many requests"}`** with `Retry-After: 1`, before the
body is read. An IPv6 sender is its /64; an IPv4-mapped address is its IPv4
address. Over WebTransport the address is the QUIC session's. Each limiter
remembers at most 4096 addresses and forgets the one idle longest. The
figures are defaults (`STONECHAT_LIMIT_*`, `off` disables one); no other
route is rate-limited.

### Derived tokens

A blob's `fetch_token` is *derived*, never stored:
`hex(BLAKE2b-256(owner_token ‖ "|stonechat-blob-fetch|" ‖ blob_id))`. So the
relay keeps no per-blob row, a token is valid exactly as long as its blob
is, and it opens that blob and nothing else. It is only ever returned to
whoever uploaded the blob, and only when they asked for it. The bundle token
is derived the same way ("Device tokens, the bundle token and
`devices_v`"). Comparison of derived tokens is constant-time.

## Push gateway (`push_gateway/`)

A separate stateless service — the only place APNs/FCM credentials live. When
an envelope is queued for a device whose socket is down — or the device
fails to ack it within a grace window (10 s; 2 s for `ring` envelopes),
since a suspended phone keeps its TCP connection open without reading it —
the mailbox POSTs

```json
{"device_token": "<APNs/FCM token>", "platform": "ios" | "android", "ring": false}
```

to `{STONECHAT_PUSH_GATEWAY}/v1/ping`; the gateway sends a **content-free**
generic notification ("You have new messages") and the woken device drains
its own queue over the normal encrypted path. Only the device the envelope
was addressed to is woken. Envelopes with `push: false` and transient
envelopes never cause a ping.

Mailboxes debounce pings per device and per kind (5 s for ordinary pings,
2 s for `ring`) and the gateway debounces per token (3 s, answering
`{"sent": false, "reason": "debounced"}`) with a collapse id, so a burst of
envelopes wakes the device once. The gateway ignores `ring`: it does not
escalate the notification. Self-hosted mailboxes may set
`STONECHAT_PUSH_GATEWAY` to any compatible gateway, or leave it empty
(pull-only delivery).

**What the gateway sees.** Device push tokens, the platform, the timing of
each wake-up — and the **network address the ping came from, which is the
mailbox's**. A mailbox is one user, so that address identifies the user to
anyone who can also read the directory; on a shared mailbox host it
identifies the host. The gateway is sent no Stonechat ID and the hub is
sent no push token, and neither service logs the other's half — but that
separation is a property of what each is *given* and a **policy** about
what each records, not something the protocol enforces. An operator running
both, and logging source addresses at the gateway, could join them.

**Push keys.** When the gateway is deployed with `STONECHAT_PUSH_MINT_SECRET`,
`/v1/ping` requires an `X-Stonechat-Push-Key` header: an opaque credential
`pk_<16 hex chars>:<hex hmac>` minted per relay at provisioning (hmac =
HMAC-SHA256(secret, key_id); env `STONECHAT_PUSH_KEY` on the relay).
Verification is offline — the gateway checks the hmac against the shared
secret, no identity lookup. Bad or missing key → 403. Abuse is handled per
credential: the key id appears in gateway logs when a push fails, and a
revoked id in the gateway's blocklist file (`STONECHAT_PUSH_BLOCKLIST`) cuts
that one relay off. With the secret unset the endpoint is open (dev/e2e).

## Mailbox host (`mailbox_host/`) — the program that runs mailboxes

Every box that holds mailbox containers runs this, and it is the only thing with
Docker access to that box. A container per mailbox: own port, own token, own TLS
certificate, cgroup/pids caps. A mailbox's TCP port and its browser
transport's UDP port are the same number on the host.

Three ways to get one, one program:

* **Invite-hosted** ("host your circle"): a user runs `mailbox_host/main.py` on a
  box they own, hosting their own mailbox plus friends they invite. A guest's
  mailbox is registered in the directory as an ordinary self-hosted (`external`)
  relay.
* **Managed** (`STONECHAT_MAILBOX_HOST_MANAGED=1`): the box belongs to a hub
  operator, and the hub places mailboxes on it through this same API — the shared
  tier, provider `mailbox_host`. Invites are refused in this mode, so a box
  has exactly one authority.
* **Dedicated VMs** the hub provisions come with the mailbox host
  pre-installed on port 8200 — the hub mints the admin token at provision
  time, bakes it into the VM's startup script, and returns it in
  `GET /v1/mailbox` (`mailbox_host` field) so the app connects with zero
  setup.

Served over pinned TLS (self-signed, same fingerprint scheme as a mailbox).
The hub reaches a managed host over this API, checking the host's
certificate fingerprint on the connection that carries the admin token,
before the token is written to it, and refusing any address that is not
`https`. It holds no shell or Docker access there.

**The admin token** is `Authorization: Bearer <token>`. The host refuses to
start with one shorter than 16 characters — the variable being *set* says
nothing about it being filled in, and an empty token is one every request
presents.

**What the admin token is worth.** Authority over the *placement* of
mailboxes on that host. Its holder can:

- create mailboxes, choosing the owner ID and — when it supplies one — the
  owner token the mailbox will accept;
- list every guest: owner Stonechat ID, container name, port, creation
  time;
- destroy any guest's container, and with it that mailbox's queue, prekeys,
  device list and TLS key;
- read which relay build each mailbox runs, and trigger a roll of running
  mailboxes onto the release the host is already pinned to;
- in invite mode, mint and list invites.

It can also install a relay binary (`POST /v1/relay`), which the host
then runs in every mailbox it rolls. Nothing on the wire yet lets the host
tell an operator's release from anyone else's: whoever holds the token can
ship code to that box. Release signing is a known open gap ("Threat notes").
No route returns an existing mailbox's owner token; the host process reads it
from the container's own configuration to query the relay, and keeps it to
itself.

For mailboxes the hub *provisions*, the hub is the party that chose the
owner token and it stores that token; "Threat notes" says what a hub can do
with it. An invite host-owner's admin token never touches the hub.

**Relay releases.** `POST /v1/relay` takes the relay binary as a raw body
(≤ 64 MiB, must be an ELF). The host stores it under its build id, hashes it
again immediately before every roll and refuses to roll a file that no longer
matches, and launches new mailboxes from it. The upload carries no signature:
the admin token alone authorises it (see "What the admin token is worth"). A
host pinned to a container image instead takes the binary out of that image,
and needs no upload.

Upgrading a relay is a binary swap inside the running container, never a
container recreate: a mailbox's data lives in the container's writable layer
with no volume behind it, so a new container would be a new, empty mailbox.

**Invites.** The invite a host-owner shares is

```
"stonechat-host:" + base64url_nopad( JSON {"u": host URL, "f": host TLS fingerprint, "t": redeem token} )
```

The guest's app pins the connection to `f`, so the redeem call cannot be
intercepted or redirected. **The invite itself is a secret**: `t` is the
redeem token, and whoever sees the invite before it is used up can redeem it
for a mailbox of their own on that host. It must be shared privately.
Invites are single-use by default (`uses` 1–100) and expire (`ttl_hours`
1–720, default 72).

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET  | `/health` | none | Liveness + pinning only: `{status, v, tls_fp}`. Guest count and capacity are occupancy metadata, served admin-only via `/v1/guests`. |
| POST | `/v1/invite` | admin | `{uses, ttl_hours}` → `{invite, uses, ttl_hours}`. 403 in managed mode |
| GET  | `/v1/invites` | admin | `{invites: [{invite, uses, uses_left, expires_at, created_at, redeemed_by: [owner_id]}]}`. 403 in managed mode |
| POST | `/v1/redeem` | the invite | `{invite: "<redeem token>", owner_id}` → `{address, mailbox_token, tls_fp, wt_address}`; launches a `stonechat-relay` container for `owner_id`. 403 invalid/expired/spent invite or managed mode, 409 if that ID already has a mailbox here, 507 host full |
| POST | `/v1/guest` | admin | `{owner_id, owner_token?, push_key?, push_gateway?}` → same shape as redeem. Provision directly: the host-owner's own mailbox, or a hub placing one. A hub sends the `owner_token` it has already recorded for that mailbox, and the `push_key` and `push_gateway` only it knows. 409 already hosted, 507 full |
| GET  | `/v1/guests` | admin | `{guests: [{owner_id, container_id, port, created_at}], count, capacity, managed}` — occupancy, which is how a hub picks the emptiest host in a country |
| DELETE | `/v1/guest/{owner_id}` | admin | evict — destroy that guest's container. Idempotent: an unknown guest is `{"status": "gone"}` |
| GET  | `/v1/relay` | admin | `{installed_build, image, managed, guests: [{owner_id, build}]}` — each `build` read from that relay's own `/status` |
| POST | `/v1/relay` | admin | the relay binary (≤ 64 MiB) → `{build, bytes, image}`. 400 not an ELF; 413 too large |
| POST | `/v1/relay/roll` | admin | `{only?, dry_run?, force?}` → `{build, rolled: [...], stopped}` — swap the pinned binary into running mailboxes, one at a time, verifying each reports the new build and rolling that one back if it does not; stops at the first failure |

After redeeming, the guest connects the returned mailbox exactly like a
self-hosted relay: `POST /v1/mailbox/external` (the hub verifies the
mailbox reports the guest as owner), then publishes its TLS signature. The
`mailbox_token` stays on the guest's device — but it was generated by the
host, so it is not a secret from the host-owner. **Trust:** the host-owner
has root on the box. They can see that a guest hosts there, the guest's
traffic metadata, and everything "What a compromised mailbox yields" lists —
never message content (E2EE). Same as any relay operator.

## Hub API (`hub/`)

User auth: `Authorization: Bearer <account_token>` (issued at registration).
Only the primary device holds an account token; a linked device has none.

| Method | Path                      | Auth   | Description |
|--------|---------------------------|--------|-------------|
| GET    | `/health`                 | none   | `{"status": "ok", "providers": [...]}` |
| POST   | `/v1/register`            | none   | `{"pubkey": "<base64 Ed25519>", "pq_pk": "<base64 X-Wing, 1216 bytes>", "pq_sig": "<base64>"}` → 201 `{"stonechat_id", "account_token"}`. The hub verifies `pq_sig`. The client MUST compare the returned ID with the one its key derives. 400 malformed key or bad `pq_sig`, 409 key already registered. 10 per minute per client address. |
| POST   | `/v1/recover`             | signature | `{"pubkey", "timestamp", "signature"}` → `{"stonechat_id", "account_token"}` — identity restore. `signature` is `Sign("stonechat-v1-recover", str(timestamp), identity_sk)` (unix seconds as decimal text, ±300 s). Rotates the account token: the recovering device becomes the account, any previous token dies. 400 stale timestamp, 401 bad signature, 404 if the key was never registered (client falls back to `/v1/register`). 10 per minute per address. |
| GET    | `/v1/directory/{stonechat_id}` | none | Lookup by full SC- ID only. See "Directory resolution" for the response. 400 on a non-ID string, 404 if unknown. 120 per minute per address. |
| GET    | `/v1/countries`           | none   | `{"countries": [{"code", "name", "city", "flag", "jurisdiction", "caveat", "plans": ["machine", "mailbox"]}]}` — where a mailbox can be placed. `code` is what `POST /v1/mailbox` is sent. Clients MUST show `caveat` wherever they show `jurisdiction`. |
| POST   | `/v1/mailbox`             | bearer | `{"country": "DE"}` (the app's form — the hub resolves it against the catalog and the caller's tier; on an open hub, where nobody holds one, it picks a shared mailbox host when one declares that country, else a dedicated VM) **or** `{"provider", "machine": {"machine_type", "region", "disk_gb"}}` — exactly one of the two forms. For `mailbox_host`, `region` is the ISO country code: placement is least-loaded *within* that country and fails rather than falling back to another. → 202 `{"status": "provisioning"}`. One mailbox per user (409). 400 `{"code": "country_unavailable"}`; 400 `{"code": "provider_unavailable"}` for a provider the hub does not run (`STONECHAT_PROVIDERS`) and `{"code": "machine_unavailable"}` for an explicit machine shape the catalog never boots — the provider+machine form cannot choose a VM size; 403 `{"code": "account_suspended"}` for a banned account. On a gated hub, gated providers require a tier (see "Gate"): missing/insufficient → 402 `{"code": "access_required", "tier_required", "message"}`; gate unreachable → 503 `{"code": "gate_unavailable"}`. |
| POST   | `/v1/mailbox/external`    | bearer | `{"address": "https://host[:port]", "wt_address"?: "host:port"}` → 201 `{"status": "running", "address", "tls_fp"}` — list a self-provisioned relay. The hub confirms ownership via `GET {address}/owner?stonechat_id=<caller>` — the mailbox confirms the supplied ID rather than exposing its owner. The relay's token never reaches the hub. 403 for a banned account. |
| POST   | `/v1/mailbox/tls`         | bearer | `{"tls_fp", "tls_sig"}` — the owner publishes the signature over their mailbox's TLS fingerprint. The hub verifies the signature against the registered identity key and that `tls_fp` matches the fingerprint it observed. 404 no running mailbox. |
| POST   | `/v1/devices`             | bearer | the signed device manifest, as "Device manifest" shows it. The hub verifies the signature against the registered identity key, that the manifest names the caller, lists 1–64 devices with 32-byte keys and no slot twice, and that `version` is above the one on record — else **409** `{"code": "stale_version", "current": n}`. Stored and served verbatim as the directory record's `devices`. |
| POST   | `/v1/mailbox/wt`          | bearer | `{"certs": [{"sha256", "not_before", "not_after"}, …], "wt_sig"}` (at most 64 entries) — the owner publishes the signature over the browser transport's certificate schedule. The hub verifies the signature and stores list and signature together. It does **not** check the list against the relay. 404 no running mailbox. |
| GET    | `/v1/mailbox`             | bearer | `{"status": "none"}` or `{"status": "provisioning"\|"running"\|"error", "provider", "machine", "address", "mailbox_token", "tls_fp", "error", "mailbox_host"}`. `mailbox_token` is the mailbox's owner token — device 1's token; null for an external mailbox. `mailbox_host` is `{"address", "admin_token"}` on running dedicated VMs, else `null`. |
| DELETE | `/v1/mailbox`             | bearer | Destroys the machine and forgets it. → `{"status": "deleted"}`. 404 no mailbox, 502 if the provider could not destroy it (nothing is forgotten). |
| POST   | `/v1/account/delete`      | bearer **and** signature | `{"timestamp", "signature"}` → `{"status": "deleted"}`. `signature` is `Sign("stonechat-v1-delete", str(timestamp), identity_sk)` (±300 s), so a token alone cannot erase an account and a linked device cannot at all. In order: on a gated hub, asks the gate to release the ID — the gate's 409 refusal is passed through and nothing is deleted; then destroys the mailbox's machine and drops the account. Afterwards the directory answers 404, as for an ID it never saw; peers are not notified. Registering the same key again yields the same ID as a new, empty account. |
| GET    | `/v1/access`              | bearer | `{"gated", "tier", "status", "until", "notice"}`. `gated: false` → an open hub; nothing needs a tier and there is nothing to redeem. `tier` is `"mailbox"`, `"machine"` or null; `notice` is the gate's own text for the user, shown as-is. 503 if the gate is unreachable. |
| POST   | `/v1/access/claim`        | bearer | `{"code"}` → forwarded to the gate for the caller's ID → same shape as `GET /v1/access`. The gate's 404/409 refusals pass through unchanged. 404 `not_gated` on an open hub. |
| POST   | `/v1/link/offer`, GET `/v1/link/offer/{key}`, POST `/v1/link`, GET `/v1/link/{key}` | none | The link dead drop. See "Linking a device". 400 malformed key or body, 404 nothing parked, 503 too many pending. |
| POST   | `/v1/report`              | signature | `{"reported_id", "reporter_pubkey", "timestamp", "category", "note", "evidence"\|null, "signature"}` → 202 `{"status": "received", "report_id"}`. See "Reporting". |
| GET    | `/v1/relay-binary`        | bearer = a mailbox token | The static relay binary that dedicated-VM startup scripts fetch. The token gates egress cost only; integrity comes from the SHA-256 pinned in the script. 404 until the operator configures one. |
| —      | `/v1/admin/*`             | `X-Admin-Token` | Operator routes. See "Operator routes". |

Every rate-limited route answers `429` over its limit. Limits are counted
per client address, in memory.

**Providers.**

| Provider | What it is |
|---|---|
| `gcp`, `aws`, `digitalocean`, `hetzner`, `vultr` | a dedicated VM, each booted from the same startup script, which downloads the relay binary and verifies its pinned SHA-256 |
| `mailbox_host` | a container on a shared host |
| `local` | a container on the hub operator's own Docker, for development |
| `external` | not a provider a client can ask for; it is what a self-provisioned mailbox's record says |

### Reporting

A user reports another user to the hub **hosting the reported account** — the
only party that can destroy a mailbox or refuse a new one. Under cross-hub
resolution that is frequently not the reporter's own hub, where their account
token means nothing, so the report is authenticated by **signature**
instead: a Stonechat ID is a commitment to an Ed25519 key ("Identity"), so
any hub can verify a reporter it has never met. Only a device holding the
identity key — the primary — can file one.

The signature is Ed25519 by the reporter's identity key over

```
"stonechat-v1-report" || reported_id || str(timestamp) || BLAKE2b-256(body)
```

where `reported_id` is in canonical `SC-…` form, `timestamp` is unix seconds
(±300 s, as `/v1/recover`), and the body digest is over

```
category || 0x1F || note || 0x1F || (evidence ?? "")
```

The body is committed to by digest rather than signed directly because it has
to survive a round trip through JSON, which preserves neither field order nor
whitespace. `0x1F` (unit separator) prevents a note that ends in what looks
like the next field from colliding with a different report.

| Field | Rule |
|---|---|
| `category` | one of `spam`, `harassment`, `impersonation`, `illegal_content`, `csam`, `other` |
| `note` | at most 2000 characters |
| `evidence` | **null by default**: a report carries no message content unless the reporter explicitly attaches one. When present, a client-composed JSON document (`{"v":1,"messages":[{"sent_at","kind","text"}]}`, at most 65 536 characters) that the hub stores verbatim and never parses. Only messages the *reported* party sent are eligible, media is described rather than uploaded, and the signature covers the attachment's exact bytes |

Responses: 400 malformed / self-report / unknown category / stale timestamp,
401 bad signature, 404 `{"code": "not_our_account"}` if this hub does not
host the reported ID, 429 over 20 reports per hour per address or 10 per
hour per reporter.

A report is an edge in a contact graph — *this ID complained about that
one* — that the hub otherwise never holds. Rows are deleted after
`STONECHAT_REPORT_RETENTION_DAYS` (default 180), and resolving a report
drops its evidence at once.

### Operator routes

All under `/v1/admin`, authenticated by the `X-Admin-Token` header, and
disabled entirely (403) unless the hub is started with
`STONECHAT_ADMIN_TOKEN`. They are the abuse desk's verbs, not part of the
client protocol:

| Method | Path | Does |
|---|---|---|
| GET | `/v1/admin/whois?host=` | address → the account(s) whose mailbox is there, with ban state and count of prior destroys |
| POST | `/v1/admin/mailboxes/{stonechat_id}/destroy` | `{"reason"}` — destroy that account's machine, recording a tombstone first. The account and its access are untouched |
| POST | `/v1/admin/users/{stonechat_id}/ban` | `{"reason"}` — refuse the account further mailboxes (`POST /v1/mailbox` and `/v1/mailbox/external`). Destroys nothing |
| POST | `/v1/admin/users/{stonechat_id}/unban` | lift it |
| GET | `/v1/admin/reports?status=&limit=` | the report queue; evidence shown as a byte count |
| GET | `/v1/admin/reports/{id}` | one report in full, evidence included |
| POST | `/v1/admin/reports/{id}/resolve` | `{"status": "actioned"\|"dismissed", "resolution"}` — close it and drop its evidence |

A ban is narrow on purpose: a banned identity still resolves in the
directory and can still recover its account. None of these routes returns a
mailbox token.

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
is older than `STONECHAT_REAP_RETENTION_DAYS` (default 14), and leaves owners
with a null one alone. The gate takes the Stonechat ID on trust — the hub has
already authenticated the user — so the token is the whole of its security.

Failure is asymmetric on purpose: a gate the hub cannot reach refuses gated
provisioning (503) and skips that reap pass; nothing already running is
touched. Mailbox lifecycle is gate-driven, never activity-driven: the hub
does not learn when a mailbox is used. `scripts/stub_gate.py` is a working
gate that grants tiers for codes (and what `scripts/e2e.py` runs against).

The hosted service's gate sells tiers through Stripe Payment Links on
stonechat.app. The webhook mints an **activation code** — `STONECHAT-` + 8
chars from an unambiguous alphabet (`ABCDEFGHJKMNPQRSTVWXYZ23456789`), matched
case-insensitively, separators ignored — which the purchase page shows and the
app claims. Claiming is the only moment a payment touches a Stonechat ID: from
then on that gate can link the ID to a Stripe customer id (Stripe knows who
paid; the gate knows which ID they paid for). That is the entire privacy cost
of paying, and it is borne by the gate, not the hub.

### What the hub stores

| Scope | Stored |
|---|---|
| Per **account** | the Stonechat ID; the identity public key; `pq_pk` and `pq_sig`; the signed device manifest, if published; a SHA-256 hash of the account token; when the account was created; and, if an operator banned it, when and why |
| Per **mailbox** (at most one per account) | provider; status; the machine spec that was asked for; the provider-side resource id and whatever else the provider needs to destroy it; the address; the **mailbox's owner token**, in the clear, for mailboxes the hub provisioned (never for external ones); the mailbox host's admin token, for dedicated VMs; the TLS fingerprint it observed and the owner's signature over it; the browser transport's address, certificate schedule and the owner's signature over that; the last provisioning error; when it was created |
| **Link offers and grants** in flight | public keys, and ciphertext the hub cannot open; 600 s at most |
| **Tombstones** of machines an operator destroyed for abuse | ID, provider, resource, address, reason, dates; kept indefinitely |
| **Abuse reports** | reported ID, reporter ID, category, note, optional evidence, status; kept for the retention window |

It stores no names, no emails, no payment data, no message data, no device
lists, no prekeys and no push tokens. It stores no contact graph — with the
one named exception of abuse reports. What it can *observe* without storing
is a separate matter: see "Threat notes".

## Local containers

Two artifacts never travel on the wire but are part of what a second
implementation must read: the identity export and the encrypted backup. Both
are the same passphrase container:

```
offset size  field
0      1     format version (2)
1      1     kdf id (1 = Argon2id, version 0x13)
2      4     m_cost, KiB, little-endian
6      4     t_cost, little-endian
10     1     salt length (16)
11     16    salt
27     24    nonce
51     —     XChaCha20-Poly1305(payload), ad = the 51-byte header
```

The key is Argon2id(passphrase, salt) with parallelism 1 and a 32-byte
output, using the parameters **in the container** (written with 262 144 KiB
and 3 passes). The header is the AEAD's associated data, so tampering with
the parameters is a decryption failure rather than a silent downgrade. A
reader refuses `m_cost` outside 8 192–1 048 576 KiB or `t_cost` outside
1–10.

- **Identity export:** the string `SCID2.` + base64url(container), whose
  payload is `{"v":1,"sk":"<base64 64-byte identity secret key>","name":…}`.
  This is the one way the identity secret leaves the primary, and only on
  the user's explicit action.
- **Backup file** (`.stonechatbackup`): the 8 bytes `SC-BAK-2`, then a
  container. It holds text history and contacts; never sessions, prekeys,
  device keys or media.

## Versioning

The wire has a single integer version, currently **1**, surfaced three ways:

- envelopes carry it as `v`; a mailbox rejects an envelope whose `v` it does
  not speak;
- mailboxes and mailbox hosts report it in `/health` (mailboxes also in
  `/status`);
- the hub reads it from an `X-Stonechat-Version` request header. It answers
  any request whose header is below its minimum supported version
  (currently 1) with **426 Upgrade Required**
  (`{"code": "upgrade_required", "min_version": n, "message": …}`); a
  request without the header is served. The header is optional, and the
  clients in this repository do not send it.

Because a mailbox cannot read a sealed envelope, it **cannot translate between
envelope versions**. A client that receives a payload type it does not know
decrypts it and drops it; a client that receives a payload field it does not
know ignores it.

## Threat notes

What the design gives, and where it stops.

- **Forward secrecy.** Message keys are single-use and deleted on use;
  root and chain keys advance with every round trip, and a fresh DH heals a
  compromised chain. Recorded ciphertext plus *later* key theft does not
  yield plaintext — with two caveats. First, an **initial message** is
  protected by the recipient's signed prekeys (and one-time prekeys, when
  the pools had any): a device keeps the private halves of its two most
  recent signed prekeys of each kind, so until they are rotated out — at
  least a week, longer for a device that is rarely online — theft of that
  device's prekey secrets and signing key opens recorded initial messages
  that used no one-time prekey. Second, **skipped message keys** (for
  messages that never arrived) are kept until used or evicted, so a message
  withheld by the network stays decryptable by whoever later steals the
  session state.
- **Post-compromise security is hybrid but sparse; signatures are
  classical.** A KEM secret is mixed into the root key at session
  establishment and again by the post-quantum ratchet, at most once per 50
  messages and only while the conversation alternates. Between two mixes the
  ratchet heals with X25519 alone: a quantum attacker who holds a device's
  state can follow its ratchet forward until the next exchange completes
  with a key generated after the theft — and indefinitely on a session
  where only one side ever writes, which the DH ratchet does not heal
  either. The exchange is authenticated only by the session's own keys, so
  it does not stop an attacker who holds the state *and* is actively in the
  path. Everything that authenticates — identity, device certificates,
  prekey signatures, TLS and WebTransport pins — is Ed25519: an attacker
  with a quantum computer at the time of an attack can forge signatures.
  None of this harms what was recorded before.
- **Sealed sender, and what it does not hide.** The wire envelope names
  only the recipient and the recipient device. A mailbox does not learn the
  sender's *identity* from an envelope. It does see the **sender's network
  address** on every deposit, and delivery is direct — so a mailbox
  operator learns which addresses write to its owner, when, and how much. On
  a hosted tier one operator may run the mailboxes at **both** ends of a
  conversation, and can then correlate a deposit leaving one customer's
  address pattern with an arrival at another's. Senders who consider their
  address sensitive route through a VPN or Tor; the protocol does not hide
  network origin. The seal also has no forward secrecy of its own: it rides
  on the recipient device's long-lived key, so a recorded backlog plus a
  later theft of that key reveals historical sender and type (never
  content).
- **What padding hides, and what it does not.** Sealed envelopes come in
  size buckets ("Envelope"), and everything short is the smallest one: a
  mailbox cannot tell a receipt from a typing notice from a text, or a
  direct message from a group one, by length. Larger things still stand
  out by bucket: a session's first envelopes (they carry the handshake), a
  message carrying post-quantum ratchet material, a roster, a call offer, a
  profile photo. **Blobs are not padded**, so a media file's size is that of
  its content. And **timing is untouched**: a group message is a burst of
  deposits from one address to each member's mailbox, a receipt follows a
  message, and the fan-out shows how many devices a recipient has. An
  operator who runs several members' mailboxes can infer a group from the
  bursts alone.
- **What a group member can do.** Group traffic is pairwise, so a member
  decides what each other member receives. Sending two members different
  content under one message id is **detected, not prevented**, and only
  once a third member who received it writes to the group ("Transcript
  consistency"); leaving a member out of a message is not detected. An
  admin can remove anyone, and can hand the role to any member without
  their agreement. An admin that issues two different rosters under one
  version is detected by the roster hash, again only when the affected
  members hear from each other. A removed member stops receiving from each
  remaining member as that member learns of the removal — promptly when
  their mailbox is reachable, and never, for a member whose every device
  stays unreachable for the seven days a roster is owed.
- **What the directory can and cannot do.** A hub cannot substitute an
  identity key: the answer is checked against the ID that was asked for. It
  cannot forge a TLS or WebTransport signature. It can **deny service**
  (answer 404, or no mailbox). It can **serve an old record**: `tls_sig` and
  `wt_sig` carry no timestamp or expiry, so a fingerprint the owner once
  signed verifies forever, and a hub can point senders at a previous
  mailbox of the same owner — for as long as someone holds that mailbox's
  TLS key. That does not expose content (envelopes are sealed to device keys
  from certificates), but it delivers metadata and one-time prekey requests
  to whoever that is. It can **serve an old device manifest**, or none,
  holding a contact at a version that still lists a revoked device until
  that device's certificate expires ("Device manifest"); it cannot forge
  one. And it **observes lookups**: who (by network address,
  and by account when the lookup is followed by authenticated calls) asks
  for which ID, at first contact and whenever a mailbox address is
  refreshed. It stores no contact graph; it is in a position to watch one
  form.
- **What a hub that provisioned a mailbox can do.** It chose and stores
  that mailbox's owner token, so it can authenticate to the mailbox as
  device 1: drain and acknowledge (that is, delete) queued envelopes,
  replace the published prekeys, register a push token, mint or revoke
  devices. It cannot read an envelope (sealed to device keys it does not
  hold), cannot make senders accept prekeys (it cannot sign them) and cannot
  make them encrypt to a device it minted (it cannot certify one). What it
  can do is disrupt, and observe everything a compromised mailbox yields.
  A self-hosted (`external`) mailbox's token never reaches the hub.
- **What a compromised mailbox yields.** Undelivered sealed ciphertext,
  with queue timing and sizes; **acknowledged envelopes that are still
  recoverable** from the database file's free pages, since deletion is an
  ordinary SQLite delete with no secure erase; the **device list** — how
  many devices, their kinds, when each was created and last connected, and
  their certificates; each device's **push token**; the owner's public
  prekeys; hashes of the device tokens, and the owner token itself from the
  process environment; the TLS private key; and the **private keys of the
  WebTransport certificates for the coming months**, which are generated
  ahead of time, so a one-time theft lets an attacker impersonate the
  browser transport until the schedule runs out or is regenerated. It
  yields the senders' network addresses as they arrive. It can serve stale
  or no prekeys, substitute unsigned one-time prekeys, and **replay a stored
  initial envelope** (below). It never yields plaintext, sender identities
  from envelopes, or the ability to substitute a signed prekey or a device
  key.
- **What a stolen phone still yields.** The message-history database and
  session states are SQLCipher-encrypted with a random key held in the
  platform keystore (Keychain/Keystore), so a lifted filesystem image or
  device backup yields ciphertext **for the database**. **Received and sent
  media files are stored unencrypted**, as plain files outside that
  database. A phone unlocked (or with keystore access) yields everything —
  that's the storage model; the optional app lock is a screen gate on top,
  not a second key.
- **Session loss** (app data wiped but identity restored — possible via the
  identity export and `POST /v1/recover`; ratchet sessions are never part of
  the export): peer messages drop until a new session forms; there is
  deliberately no session escrow anywhere.
- **Transport.** Pinned TLS removes cleartext exposure of tokens and of
  envelopes to on-path observers, and makes mailbox MITM require that
  mailbox's TLS private key. What it cannot hide: **IP addresses are
  routing metadata**. The destination address names the recipient (one
  mailbox is one user, or one host's users), and the source address is the
  sender's device. Tokens travel in URLs, which is where a server-side log
  would record them if one were kept.

### Known open gaps

Accepted for now, not fixed.

1. **Revocation reaches a contact only when something prompts a refetch.**
   The device manifest is checked by every contact who holds it, but a
   contact is prompted to refetch it by an envelope stating a newer
   version, by the sender's mailbox listing an unknown device, or once per
   run when it holds none — never by time. A revoked device claims the old
   version, so a contact who hears from nothing but the revoked device
   keeps accepting it until its certificate expires: up to 14 days for a
   linked device, 7 for a browser. A hub can likewise hold a contact at an
   old manifest until then. There is no periodic refresh by design.
2. **One-time prekeys are unsigned, the KEM one-time prekey included.** A
   mailbox can hand a sender one-time prekeys of its own making. The
   recipient holds no matching private half, so it cannot complete that
   handshake and what was sent on it is lost — denial, which a mailbox can
   cause anyway. What is lost besides is the one-time keys' contribution:
   a substituted OPK removes DH4's, and with a substituted KOPK the KEM
   share of that handshake is a secret the mailbox knows, leaving the
   classical DHs as its only secret inputs. The handshake and its
   ciphertext still travel inside the hybrid seal, which the mailbox cannot
   open.
3. **Signed prekeys and signed pins carry no timestamp or expiry.** A
   mailbox can keep serving an old signed prekey the device has since
   rotated away (the device then cannot decrypt, and the sender's message is
   lost until it retries on a fresh bundle); a hub can keep serving an old
   signed TLS fingerprint or WebTransport schedule. Device certificates do
   expire; nothing else signed does.
4. **A replayed initial envelope can replace a session.** When an initial
   envelope used no one-time prekey of either kind (the pools were dry),
   whoever holds a copy of the sealed envelope — in practice the mailbox,
   or someone who has read its database — can deposit it again after it was
   acknowledged (the mailbox forgets an id once it is acked). The recipient's current
   session fails to decrypt it, the `x3dh` block is valid, and the session
   it re-creates **replaces** the live one. The old message is processed
   again and the peer's subsequent messages fail until a new handshake.
   Nothing is disclosed; a conversation is disrupted.
5. **Signatures are classical, and post-compromise security is
   post-quantum only once per interval** (above).
6. **Blobs are unpadded and timing is visible** (above).
7. **No identity rotation.** A Stonechat ID is a hash of one key. There is
   no way to move an identity to a new key, and no way to revoke a
   compromised one: the remedy for a stolen identity key is a new identity
   and telling one's contacts.
8. **Media files are stored unencrypted on the device** (above).
9. **Relay releases are unsigned.** A mailbox host installs whatever binary
   its admin token's holder uploads, and the hub holds that token for every
   host it manages. A compromised hub, or a stolen token, can ship code to
   every mailbox on those hosts. The published image and release binary are
   likewise protected only by where they are downloaded from.

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
