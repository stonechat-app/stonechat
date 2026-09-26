# Post-quantum (design + rollout)

Status: **steps 1–2 implemented (pre-launch, 2026-07).** With no users
yet, hybrid PQ key agreement is not "v2 of the protocol" — it simply IS
the protocol. No negotiation, no fallback, no downgrade surface, no
migration. PROTOCOL.md "Identity", "Prekeys", "PQXDH" and "Envelope"
are the wire spec; this document keeps the rationale and the later
steps (3–4).

## Threat model → work order

The quantum threat splits in two, and the split dictates priorities:

- **Harvest-now-decrypt-later (HNDL):** an adversary records
  ciphertext today and decrypts when a CRQC exists. Threatens every
  X25519 key agreement *retroactively*. Urgent — it attacks messages
  sent this year.
- **Forgery:** breaking Ed25519 to impersonate identities. Only works
  once the CRQC exists; no retroactive harm. Can wait years.

So: key agreement first, signatures later — the same order Signal
shipped (PQXDH 2023, ratchet/signatures later).

## Already post-quantum — no work needed

XChaCha20-Poly1305, BLAKE2b KDFs, Argon2id,
SQLCipher at rest. Grover halves effective strength; 256-bit keys have
margin. Backups, identity export, media encryption: untouched.

## The ladder

1. **Hybrid PQXDH** (now). ML-KEM-768 (FIPS 203) joins X3DH: bundle
   gains a signed last-resort KEM prekey + one-time KEM prekeys;
   initiator encapsulates; `SK = BLAKE2b(DH1‖DH2‖DH3[‖DH4]‖KEM_ss,
   key="stonechat-v1-pqxdh-kdf")`. Initial message carries the ~1.1 KB KEM
   ciphertext. Always hybrid, never KEM-only — if ML-KEM falls we are
   exactly as secure as today. Key property: once the root key is
   PQ-secure, the whole ratchet chain inherits HNDL resistance — a
   recorder who later breaks every X25519 ratchet step still lacks the
   root. Hybrid PQXDH alone defeats HNDL for all message content.
   Follow Signal's public PQXDH spec; do not invent.
2. **Hybrid sealed sender** (now). `crypto_box_seal` is pure X25519 to
   the directory-published identity key — a quantum attacker opens
   every *recorded outer envelope* and learns who talked to whom (the
   sender identity is inside the seal), even though the inner ratchet
   ciphertext stays safe after step 1. Fix: seal with **X-Wing**
   (draft-connolly-cfrg-xwing: X25519 + ML-KEM-768 as one audited
   hybrid KEM) to a KEM identity encryption key published in the
   directory, signed by the Ed25519 identity. ~1.1 KB per envelope.
3. **PQ ratchet** (later). Steps 1–2 leave quantum PCS: if device
   state leaks, classical DH ratchet healing is quantum-breakable.
   Adopt Signal's SPQR when its spec settles, or PQ3-style periodic
   hybrid rekey as a stopgap. Incremental, versioned, on top of 1.
4. **PQ signatures** (last, pre-CRQC). Dual-sign with ML-DSA-44
   alongside Ed25519 (identity, prekey sigs, fingerprint signing,
   recovery). ~1.3 KB pubkeys, ~2.4 KB sigs, directory growth,
   cross-signed migration. Years of runway; requirement today is only
   that every persisted/signed structure carries a version byte so
   this lands additively.

Nearly free, independent: **PQ TLS** on the relay — rustls ships
X25519MLKEM768; browsers already speak it (composes with the relay's
browser transport). Defense-in-depth for metadata.

## Why now (the post-ship counterfactual)

Doing 1–2 after shipping with a live fleet would add four work items,
recorded here so the cost of *ever* being in that position is on the
record:

1. **Session re-handshake sweep.** PQ security flows from the X3DH
   root; every pre-upgrade ratchet session stays quantum-vulnerable
   forever until explicitly re-handshaked. Requires dual-session
   receive windows, ordering care, idle-contact refresh policy.
2. **Downgrade pinning.** Mixed fleet ⇒ classical fallback ⇒ "peer
   has no KEM prekeys" becomes an attack (stripping, stale-but-signed
   bundles from a malicious relay). Needs signed bundle version fields
   + "once v2, never v1 again" pinning + X-Stonechat-Version/426 sunset.
3. **Directory backfill.** Fleet-wide lazy generation + publication of
   KEM identity keys; hub serves both schemas during transition.
4. **Dual-format windows.** Every serialized crypto structure must
   load old and new formats.

Plus the uncorrectable one: everything sent before the upgrade is
harvested-forever — mailboxes delete on ack so little rests at the
relay, but a passive traffic recorder keeps it. The corpus of
forever-decryptable traffic grows with every month of delay. Pre-launch
it is zero.

## Implementation map (steps 1–2, as built)

**`pqcore/` Rust crate → one KEM implementation everywhere.** (Since
2026-07-30 the same argument was carried to its conclusion: `stonechat-core`
holds *all* client cryptography and libsodium is gone from the app.) libsodium
has no ML-KEM, so a small Rust core (RustCrypto `ml-kem` + `x-wing`,
C ABI) is the one architectural addition. Every client loads the same
library: Flutter over dart:ffi (`app/lib/core/pqcore.dart`), the Python
protocol clients over ctypes (`scripts/pqcore.py` — e2e.py and
echo_bot.py exercise byte-identical code), and a future web client via
the same crate compiled to wasm. Secrets are seeds (64 B ML-KEM, 32 B
X-Wing); the core draws no entropy — callers pass CSPRNG bytes.
`scripts/build_pqcore.sh` builds host/android/ios artifacts; the
iOS/Android build wiring is the remaining ship blocker.

- `app/lib/core/crypto.dart` — PQXDH KDF (`stonechat-v1-pqxdh-kdf`);
  sealed sender is the X-Wing seal (encaps → BLAKE2b KDF →
  XChaCha20-Poly1305). **The X-Wing identity is derived from the
  Ed25519 secret** (`stonechat-v1-pqidseed` KDF) rather than stored:
  export/recovery/backups restore it for free, and Ed25519 custody
  already equals total identity compromise.
- `app/lib/core/session.dart` — initiator encapsulates to the KOPK
  (else KSPK); `kct`/`kem_id`/`kem_one_time` ride the x3dh block;
  responder decapsulates. **Double ratchet unchanged** (step 3).
- `db.dart` / `chat_state.dart` — `prekeys` kinds `kspk`/`kopk`
  (seeds in the encrypted table, same rotation cadence as spk/opk);
  contacts and group members carry a sig-verified `pq_pk`.
- `relay/` — `/prekeys` and `/prekeys/bundle`
  carry the KEM twins (opaque strings; dedicated 256 KB upload cap);
  no bundle until both signed halves exist. Parity corpus updated
  (relay/tests/conformance.py).
- `hub/` — `pq_pk`+`pq_sig` at registration (signature verified) and
  in every directory record. SC-ID derivation stays Ed25519-only.
- `PROTOCOL.md` (repo root) — Identity/Prekeys/PQXDH/Envelope sections are
  the exact wire spec; scripts/e2e.py doubles as the reference
  implementation, KEMs included.

## Further reading

- [Signal: PQXDH specification](https://signal.org/docs/specifications/pqxdh/)
- [X-Wing: draft-connolly-cfrg-xwing-kem](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/)
- [Signal: SPQR / sparse post-quantum ratchet](https://signal.org/blog/spqr/)
- [Apple: iMessage PQ3](https://security.apple.com/blog/imessage-pq3/)
