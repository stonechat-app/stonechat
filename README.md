# Stonechat

Privacy-first messaging app where **every user runs their own relay**.

- No central message store. Your "relay" is a mailbox of your own — a container
  on a box that hosts a handful of people, a whole VM if you want one, or
  something you run yourself at home — whose only job is to hold **end-to-end
  encrypted envelopes** until your phone picks them up, then delete them.
- No phone number, no email. Your identity is an Ed25519 keypair generated on
  device; your **Stonechat ID** (`SC-XXXX-…`) is a hash commitment to the public key.
  Share it by QR or text — it reveals nothing about you.
- **Forward secrecy, post-quantum hybrid**: PQXDH (X3DH + ML-KEM-768) +
  double ratchet (Signal-style), with prekeys served by your own relay
  instead of a central server. Every message gets a fresh key; stealing keys
  today can't decrypt traffic recorded yesterday, and recording traffic
  today doesn't let a future quantum computer decrypt it
  (docs/POST_QUANTUM.md).
- **Pinned TLS, no CAs**: relays self-sign their certificates; clients pin a
  fingerprint the owner signs with their identity key and publishes in the
  directory. Trust chains to the Stonechat ID, not to any authority — same as
  everything else in the protocol.
- Message history lives on your phone only. Uninstall the app and it's gone. Well, you can do an encrypted backup if you want, but you need to take care of that backup.

See [PROTOCOL.md](PROTOCOL.md) for the full wire protocol and threat notes.

## Components

| Directory       | What it is                                                                                                                                                                                                                                                                                                                   |
| --------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `app/`          | Flutter app (iOS/Android). Keys, history, encryption — all client-side.                                                                                                                                                                                                                                                      |
| `relay/`        | The mailbox. Rust + SQLite; a static binary that runs on the user's VM. Stores ciphertext only, deletes on ack.                                                                                                                                                                                                              |
| `hub/`          | Provisioner + directory. Boots/destroys relays via a pluggable provider layer and maps Stonechat IDs to pubkeys + current relay address. Never sees message content.                                                                                                                                                         |
| `push_gateway/` | Push gateway for mobile push notifications. Stateless. The only holder of APNs/FCM credentials. Mailboxes ping it when the owner is offline; it sends a content-free wake-up. Sees device tokens + timing, never identities.                                                                                                 |
| `mailbox_host/` | Mailbox host, hosts multiple mailboxes. Runs on a user-owned VM; mints invites and provisions invited friends' mailboxes as containers on that box. If you want to host mailboxes, for friends or family, in your own machine, you should use this. Still connects to the main Stonechat directory (where all the users are) |
| `agent_client/` | Agent client. A headless **device** on a user's identity — links like a phone or a browser tab, holds no identity secret, runs unattended on a server.                                                                                                                                                                       |

## Quick start (all local, no cloud account)

## Self-hosting

### Mailbox

### Host your circle (one box, invited friends)

### Running your own hub (a private network)

## Notes

- **The hub is a centralized directory.** It stores routing metadata
  (ID → pubkey → relay IP), never content. Self-hosted relays reduce its
  knowledge further (it never sees their tokens); running your own hub is possible but puts you on a separate directory island.
- **Push needs credentials to go live.** The full path is wired end to end —
  app fetches a device token → registers it with its own mailbox → mailbox
  pings the gateway → content-free wake-up. It stays dormant until you supply
  APNs/FCM credentials and a Firebase config in the build (see
  [docs/SELF-HOST.md](docs/SELF-HOST.md#push-gateway-optional)); without them the app falls back to
  live-socket / on-resume delivery.
- **Metadata: the destination IP is unavoidable.** Transport is pinned TLS
  (relays self-sign; clients pin an owner-signed fingerprint through the
  directory — no CAs), so on-path observers no longer read envelope metadata
  or the owner token. But one mailbox = one user, so _which IP you connect to_
  still reveals _that_ you contacted that person. Inherent to per-user mailboxes;
  hiding it (padding, onion routing) is a separate, larger project.
- **Groups are minimal**: ~25 members

---

## License

**Stonechat is licensed under the GNU Affero General Public License v3.0**
([LICENSE](LICENSE)) — all of it: the clients, the protocol core, the relay,
the hub, the push gateway.

AGPL §13 is the part that matters: anyone who runs a modified version as a
network service must offer its users the source of their modifications. You
may compete with Stonechat and you may charge for it; you may not do it with a
secret fork, and you may not sell a closed-source Stonechat to companies. Same
license as Signal and SimpleX, for the same reason — a messenger that asks for
your trust has no business being unreadable.

Two carve-outs: **[PROTOCOL.md](PROTOCOL.md) is CC-BY-4.0**, because
independent implementations reach the same directory and the same users; and
the **name, logo and bird mark are trademarks of GazelleLabs LLC**, not
covered by the AGPL. Say your project is based on or compatible with
Stonechat; don't name it Stonechat, and use your own icon.

Full detail, including what the AGPL asks of you if you self-host or fork:
**[LICENSING.md](LICENSING.md)**.

## Contributing

Contributions are welcome to the server and the clients alike. Sign your
commits off (`git commit -s`) to certify you have the right to submit the
code; you keep your copyright. Read [CONTRIBUTING.md](CONTRIBUTING.md) first,
especially the invariants: breaking one is expensive and quiet.

Security issues go to security@stonechat.app, not the issue tracker. See
[docs/SECURITY.md](docs/SECURITY.md).
