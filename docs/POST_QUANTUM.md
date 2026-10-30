# Post-quantum cryptography in Stonechat

This document describes what Stonechat's post-quantum protection actually
consists of today: which parts of the protocol use a post-quantum KEM, which
parts are still classical, and where the code lives. The wire format is
specified in PROTOCOL.md ("Identity", "Prekeys", "PQXDH", "Post-quantum
ratchet", "Envelope"); this document explains why it looks the way it does.

## Summary

| Layer | Construction | Quantum status |
|---|---|---|
| Session establishment | **PQXDH**: X3DH + ML-KEM-768 (FIPS 203) | Hybrid, resists harvest-now-decrypt-later |
| Message keys | Double ratchet (X25519 + BLAKE2b) rooted in the PQXDH key | Inherits PQ secrecy from the root |
| Envelope seal (sealed sender) | **X-Wing** (X25519 + ML-KEM-768) to the recipient **device's** certified key | Hybrid, resists harvest-now-decrypt-later |
| Symmetric crypto | XChaCha20-Poly1305, BLAKE2b, Argon2id | Already PQ-adequate (256-bit keys) |
| Signatures | Ed25519 (identity, prekeys, device certs, TLS pins) | **Classical**, forgeable by a future quantum computer |
| Ratchet healing (PCS) | X25519 DH ratchet on every turn, plus an ML-KEM-768 secret mixed into the root at most once per 50 messages | Hybrid, but **sparse**: classical between two KEM exchanges |
| Transport | rustls with the `ring` provider; WebTransport | **Classical** key exchange |

Group messages are ordinary pairwise sessions, one per member device
(PROTOCOL.md "Groups"), so everything in this table applies to them
unchanged: there is no separate group key to protect.

Post-quantum protection is not an optional mode. Every session is hybrid, and
so is every sealed envelope. There's no classical fallback, no negotiation and
no version to downgrade to. A mailbox won't serve a prekey bundle until both
the X25519 and the ML-KEM signed prekeys exist. Every KEM use is hybrid,
never ML-KEM alone, so if ML-KEM is broken the protocol is exactly as strong
as classical X3DH/X25519.

## Threat model

- **Harvest now, decrypt later.** An adversary records traffic today and
  decrypts it once a cryptographically relevant quantum computer exists. This
  attacks X25519 retroactively, so it is what the implementation defends
  against: key agreement and the envelope seal are hybrid.
- **Following a stolen session.** An adversary who steals a device's session
  state, and can break X25519, could otherwise read that session for as long
  as it lives: the DH ratchet's fresh keys would not shut them out. The
  post-quantum ratchet bounds this for a *passive* adversary.
- **Forgery.** Breaking Ed25519 would allow someone to impersonate an
  identity. That requires a quantum computer at the time of the attack and
  does no retroactive harm, so signatures are still classical (see "Not yet
  post-quantum").

## What is implemented

### 1. PQXDH session establishment

Signal's PQXDH shape: X3DH with an ML-KEM-768 encapsulation mixed into the
root key.

- Every **device** publishes to its mailbox, alongside the classical SPK/OPKs:
  - a **KEM signed prekey (KSPK)**: ML-KEM-768, signed with the **device's**
    signing key — the one its device certificate names — under the context
    `stonechat-v1-kspk`, and rotated on the same schedule as the SPK;
  - a pool of **KEM one-time prekeys (KOPK)**: the client targets about 32,
    and the mailbox caps the pool at 64 (`MAX_KOPKS` in `relay/src/main.rs`).
    **KOPKs are unsigned**, like classical one-time prekeys. A mailbox can
    therefore substitute one: the recipient then cannot complete the
    handshake, and the KEM share of that handshake is a secret the mailbox
    knows (PROTOCOL.md "Known open gaps").
- The initiator encapsulates to the KOPK when the bundle has one, and to the
  KSPK otherwise:

  ```
  KCT, KSS = ML-KEM-768.Encaps(KOPK_B or KSPK_B)
  SK = BLAKE2b(DH1 || DH2 || DH3 [|| DH4] || KSS, key="stonechat-v1-pqxdh-kdf", 32)
  ```

- The 1088-byte `kct`, along with `kem_id` and `kem_one_time`, travels in the
  inner envelope's `x3dh` block until the session is confirmed. The responder
  decapsulates with the seed named by `kem_id` and then deletes the one-time
  private key.
- The classical DH terms provide authentication; the KEM term provides
  quantum-resistant secrecy. Every message key descends from `SK` through the
  double ratchet, so an attacker who later breaks every X25519 ratchet step
  still doesn't have the root. **For message content, harvest-now-decrypt-later
  is defeated from the first message.**

Media is covered as well. Blobs are encrypted with one-off XChaCha20 keys, and
those keys travel inside ratchet-encrypted payloads.

Code: `core/src/session.rs` (`SessionState::initiate` / `respond`),
`core/src/primitives.rs` (`x3dh_shared_key`, KDF constants).

### 2. X-Wing envelope seal (hybrid sealed sender)

The outer envelope a mailbox stores contains only `to` and an opaque `sealed`
blob. A classical `crypto_box_seal` would let a future quantum attacker open
every recorded envelope and learn **who wrote to whom**. It wouldn't expose
the content, because PQXDH protects that. The seal is therefore X-Wing
(draft-connolly-cfrg-xwing-kem, **revision 06** — the revision the `x-wing`
0.1.0 crate implements and tests against):

```
kem_ct, kem_ss = XWing.Encaps(recipient_seal_pk)
key    = BLAKE2b(kem_ss, key="stonechat-v1-hsealkdf", 32)
sealed = kem_ct (1120 B) || nonce (24 B) || XChaCha20-Poly1305(inner, ad="stonechat-v1-hseal")
```

There is **one** seal target: the recipient **device's own X-Wing key**
(`seal_pub`, 1216 B). Every device — the primary included — generates its own
X-Wing keypair and holds a device certificate signed by the identity key
(`core/src/devcert.rs`) that names it. Senders verify the certificate against
the identity key the recipient's Stonechat ID commits to, and seal to the key
it carries. A device without a valid certificate is not encrypted to; there
is no other key to fall back on.

**The identity has no KEM key.** An identity-level X-Wing key (`pq_pk`)
derived from the identity secret was published at registration and served in
every directory record until 2026-10-18. It predated device certificates,
which moved the seal target to the device; after that nothing was
encapsulated to it and nothing opened with its private half, so it was
removed. Its one side effect, proving at registration that the caller held
the identity secret, is now a plain signature over the current time
(PROTOCOL.md "Registration").

By construction, the seal has **no forward secrecy**, because it is made to a
long-lived key. Recorded envelopes plus a later theft of that device's seal
key reveal historical sender/type metadata, but never content.

Code: `core/src/envelope.rs` (`seal_to` / `unseal`), `core/src/devcert.rs`.

### 3. Post-quantum ratchet (hybrid healing)

PQXDH makes the root key quantum-resistant, which protects content against a
recording adversary. It does nothing for a session whose state has been
stolen: from then on the only fresh secrets entering the ratchet are X25519
outputs. The post-quantum ratchet adds ML-KEM-768 secrets to the same root.

```
initiator                                responder
---------                                ---------
ek = ML-KEM keygen     --- ek(id) --->
                       <--- ct(id) ---   ct, ss = Encaps(ek)
ss = Decaps(ct); delete the private key
new sending chain:     --- mix(id) -->   same step, before the chain key
  rk = BLAKE2b("stonechat-v1-pqratchet" || ss, key = rk, 32)
```

Why it looks like this:

- **Tied to the DH ratchet, not beside it.** The secret is folded into the
  root key at the one moment both sides already agree on — the start of a
  sending chain — and the chain says so in every header (`mix`). There is no
  second ratchet to keep in step and no new failure mode for reordered
  messages: a chain either decrypts with the secret or does not decrypt.
- **Sparse.** A key is 1184 bytes and a ciphertext 1088, against a few
  hundred for a message. An exchange starts only after 50 messages have
  passed on the session since the last, and its key and ciphertext ride on
  the first three messages of a sending chain rather than on all of them,
  re-offered on the next chain until answered. Signal's SPQR spreads the
  same bytes over many messages with erasure codes; this sends them whole,
  rarely. It costs bandwidth in bursts and saves a great deal of machinery.
- **Counted in messages, not time.** `stonechat-core` takes no clock, so the
  interval is a message count. A session that is quiet for a month does not
  rekey until it speaks again — and has had nothing to protect meanwhile.
- **Fixed roles.** The session's initiator always generates the key and the
  responder always encapsulates. Both contribute fresh randomness either
  way, and one direction is one state machine instead of two that can cross.
- **Authenticated by the session.** `ek`, `ct` and `mix` are bound into the
  message's associated data, so they cannot be stripped or swapped by anyone
  who cannot already forge a message on that session.
- **Its own randomness.** The KEM key and the encapsulation are drawn from
  bytes the host supplies separately from the DH ratchet's. The ratchet
  key's public half goes on the wire, and anything derivable from its
  private half would fall with X25519.

What it gives: once an exchange completes with a key generated *after* a
compromise, an adversary who only listens — quantum computer or not — no
longer holds the root key. What it does not give is in "Not yet
post-quantum" below.

Code: `core/src/session.rs` (`PqState`, `absorb_pq`, `dh_ratchet`),
`core/src/primitives.rs` (`kdf_pq`). `scripts/e2e.py` carries an independent
implementation, and the two are checked against each other.

### Where the code lives

- **`pqcore/`**: the only KEM implementation. It is a thin wrapper around
  RustCrypto's `ml-kem` (0.3) and `x-wing` (0.1), exposed as Rust and as a C
  ABI (`stonechat_mlkem_*`, `stonechat_xwing_*`). Secret keys are carried as
  seeds (64 B for ML-KEM, 32 B for X-Wing), and key expansion stays inside the
  crate. It draws no entropy of its own: callers pass CSPRNG bytes, which
  keeps every operation deterministic and testable.
- **`core/` (`stonechat-core`)**: links `pqcore` and contains the whole
  protocol (PQXDH, ratchet, X-Wing seal, device certificates). One artifact
  exports both ABIs. It is consumed by:
  - the Flutter app over dart:ffi (`app/lib/core/core_ffi.dart`,
    `app/lib/core/pqcore.dart`). The app has no cryptography of its own;
  - the iOS Notification Service Extension over the C ABI;
  - `agent_client/` as a Rust crate (`agent_client/src/prekeys.rs` generates
    ML-KEM prekeys);
  - `webclient/` as wasm (`webclient/src/core.ts`).
- **`scripts/pqcore.py`** loads the same library over ctypes, so the Python
  reference client (`scripts/e2e.py`) and `echo_bot.py` exercise byte-identical
  KEM code.
- **`relay/`** links neither crate. It stores and serves KEM prekeys as opaque
  strings, refuses to serve a bundle until both signed halves exist, and has
  a dedicated 256 KB cap on prekey uploads (`MAX_PREKEY_UPLOAD_BYTES`). This
  behavior is pinned by the conformance corpus (`relay/tests/conformance.py`).
- **`hub/`** links neither crate and stores no KEM material: the directory
  record is the Ed25519 identity key and what its owner signed.

### Sizes on the wire

| Item | Bytes |
|---|---|
| ML-KEM-768 public key (KSPK/KOPK) | 1184 |
| ML-KEM-768 ciphertext (`kct`, initial messages only) | 1088 |
| X-Wing public key (device `seal_pub`) | 1216 |
| X-Wing ciphertext (every sealed envelope) | 1120 |
| ML-KEM-768 public key (ratchet `ek`, up to 3 messages per sending chain while unanswered) | 1184 |
| ML-KEM-768 ciphertext (ratchet `ct`, likewise) | 1088 |

Sealed envelopes are padded to size buckets (PROTOCOL.md "Envelope"), the
smallest holding 2048 bytes. An ordinary message fits it; one carrying
handshake or ratchet KEM material lands in the next bucket up, which is how
a mailbox could tell that such a message passed, though not which session
it belongs to.

## Not yet post-quantum

These gaps are known and intentional for now, listed from most to least
likely to be addressed next.

1. **Ratchet healing between exchanges.** The post-quantum ratchet runs at
   most once per 50 messages and takes two and a half round trips. Between
   two exchanges the ratchet heals with X25519 alone, so a quantum attacker
   who holds a device's state can follow it until the next exchange
   completes. A session on which only one side writes never exchanges at
   all (nor does its DH ratchet turn). And the exchange is authenticated by
   the session's own keys, so it shuts out a listener, not an attacker who
   holds the state and can also alter traffic. A shorter interval, a
   time-based trigger supplied by the host, or SPQR-style chunking to run
   it continuously would each narrow the first of these.
2. **Transport.** The relay's TLS uses rustls' `ring` provider
   (`relay/src/main.rs`), which doesn't offer X25519MLKEM768, and neither does
   WebTransport. This only exposes metadata (the owner token, sealed
   envelopes), because content is already protected by the layers above.
   Switching to a provider with hybrid key exchange would be cheap
   defense-in-depth.
3. **Signatures.** Ed25519 still signs everything that is signed: device
   certificates (identity key), signed prekeys (device key), TLS/WebTransport
   pins and recovery (identity key). Moving to hybrid
   Ed25519 + ML-DSA-44 would add roughly 1.3 KB per public key and 2.4 KB per
   signature, and would require a cross-signed migration of the directory.
   There's no retroactive risk, so this can wait until a quantum computer is
   realistically close.

## Why it was built pre-launch

Adding PQ after launch would have meant re-handshaking every existing
session, defending against downgrades in a mixed fleet (a stripped KEM prekey
becomes an attack), backfilling KEM keys into the directory, and loading two
formats for every crypto structure. Traffic sent before the switch would also
have stayed harvestable forever. Building it before there were any users
meant none of that was needed, and no classical-only traffic was ever sent.

## Further reading

- [Signal: PQXDH specification](https://signal.org/docs/specifications/pqxdh/)
- [X-Wing: draft-connolly-cfrg-xwing-kem](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/)
- [Signal: SPQR / sparse post-quantum ratchet](https://signal.org/blog/spqr/)
- [Apple: iMessage PQ3](https://security.apple.com/blog/imessage-pq3/)
