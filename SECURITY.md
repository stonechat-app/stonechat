# Security policy

## Reporting a vulnerability

Email **security@stonechat.app**. Please don't open a public issue for anything
that affects the confidentiality or integrity of users' messages, keys, or
identities.

Include whatever you have: what you did, what happened, and what you expected.
A proof of concept helps but is not required to make a report worth sending.

You should get a human reply within **72 hours**. If you don't, resend — a
silent mailbox is a bug in this policy, not a decision about your report.

We won't take legal action against good-faith research: testing against your
own identity and your own mailbox, stopping at the point where you'd reach
someone else's data, and giving us a reasonable window before publishing.
Please don't test against other people's mailboxes, and don't run anything that
degrades service for real users.

There is no bug bounty. We'll credit you in the fix's release notes unless you
ask us not to.

## What is in scope

Everything in this repository, and the hosted hub, directory, and push gateway
that the official app talks to.

Findings we're especially interested in:

- Anything that lets a party other than the intended recipient read message
  content, or that breaks forward secrecy or post-compromise security.
- Anything that lets the hub, a relay operator, or a network attacker link a
  Stonechat ID to a person, a device, or another Stonechat ID beyond what the
  design already concedes (see "Known and accepted" below).
- Certificate-pinning bypasses — anything that makes a client accept a relay
  it shouldn't, or that lets a device certificate do something the design says
  it can't (mint or renew certificates, sign a TLS fingerprint, export the
  identity, manage the mailbox).
- Provisioning and isolation failures: one user's mailbox reaching another's,
  or a mailbox reaching the hub.

## Known and accepted

These are design decisions, not bugs. A report that rediscovers one of them is
still welcome — a fresh argument that the tradeoff is wrong is useful — but it
won't be treated as a vulnerability.

- **The hub sees metadata.** It maps Stonechat IDs to public keys and current
  relay addresses, so it knows an ID exists and where its mailbox is. It never
  sees message content.
- **The push gateway sees device tokens and timing.** That is what a wake-up
  requires. It never sees identities or content.
- **A relay operator sees envelope timing and size** for the one user it
  serves, and ciphertext it cannot read.
- **History lives on the device only.** Losing the device loses the history.
  That is the design, not a data-loss bug.
- **The protocol has not had an external cryptographic review.** It follows the
  PQXDH and double-ratchet specifications closely, but "follows the spec" is a
  claim about intent, and until someone qualified has looked, it stays a claim.
  Treat the crypto as unreviewed and report anything that looks wrong.

## Supported versions

Pre-launch: only the current `main` and the most recent published build get
fixes. There are no maintained release branches yet.
