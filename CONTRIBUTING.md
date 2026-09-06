# Contributing to Stonechat

Thanks for looking. A few things are worth knowing before you spend time on a
change.

## The one hard requirement: sign off your commits

Every commit must carry a `Signed-off-by` line:

```
Signed-off-by: Your Name <your.email@example.com>
```

`git commit -s` adds it for you. `git rebase --signoff` fixes a branch you
already wrote.

That line is the [Developer Certificate of Origin](https://developercertificate.org/)
(DCO) 1.1, reproduced at the bottom of this file. Signing off means you have
the right to submit the code under this repository's license. It is not a
copyright assignment and it is not a CLA — you keep your copyright.

We require it so that Stonechat's licensing stays changeable by consent rather
than by archaeology. Pull requests without sign-off can't be merged; this is
checked, not just asked for.

## Before you open a pull request

**Talk to us first for anything structural.** Bug fixes and small improvements
can go straight to a PR. Anything that changes the protocol, the storage
schema, or a component boundary should start as an issue — Stonechat has a
small number of load-bearing invariants (below) and a change that violates one
will be rejected no matter how good the code is.

**Security issues do not go in the issue tracker.** See `SECURITY.md`.

## The invariants

These are the rules that span files. They exist because breaking one is
expensive and quiet.

- **There is exactly one protocol implementation: `core/`.** Clients are thin
  wrappers over its C ABI (Dart FFI, wasm) or link the crate directly. A client
  must not grow cryptography of its own. If a client needs new protocol
  behaviour, it goes in `core/` and gets exposed through the ABI.
- **`core/` is state-in / state-out.** No network, no filesystem, no clock, and
  **caller-supplied randomness** — every operation needing entropy takes
  explicit CSPRNG bytes. This is what makes it corpus-testable and
  wasm-buildable. Keep dependencies' `getrandom` features off.
- **The relay never depends on protocol code.** It links `pqcore` alone. It
  routes ciphertext and knows nothing about sessions.
- **The relay's behavioural contract is the recorded corpus in `relay/tests/`,
  not the source.** A change to relay HTTP/WS behaviour must either keep the
  goldens green or be re-recorded deliberately (`conformance.py --record`) with
  an explanation of what changed and why.
- **Trust chains to the Stonechat ID, not to any CA.** Relays self-sign;
  clients pin a fingerprint the owner signed with their identity key. Don't
  introduce a code path that trusts the system trust store.
- **Mailboxes never run on the hub machine.** The hub holds the directory and
  provisioning credentials; mailboxes hold users' mail on a wide open port
  range. Keeping them apart is why a compromised mailbox host can't reach the
  directory.

## Running the tests

The core library has to exist before most things will run:

```bash
./scripts/build_core.sh host      # dylib/so for flutter test + python tooling
```

Then, per component:

```bash
cd core   && cargo test           # vectors, protocol, golden transcript, ABI
cd relay  && cargo test           # unit + parity vectors
cd app    && flutter analyze && \
  STONECHAT_CORE_LIB=$PWD/../core/target/release/libstonechat_core.dylib flutter test
cd webclient && npm ci && npm run check
```

Relay conformance needs a **fresh** relay — the corpus is stateful and
order-dependent, so point it at a binary started with an empty data directory:

```bash
STONECHAT_OWNER_ID=SC-TEST-OWNER STONECHAT_OWNER_TOKEN=tok-secret \
  ./target/release/stonechat-relay &
python3 relay/tests/conformance.py https://127.0.0.1:<port>
```

The full-stack check (`scripts/e2e.py`) needs Docker and a running hub; the
README's Testing section has the invocation.

## Building the app

`app/android/app/google-services.json` and
`app/ios/Runner/GoogleService-Info.plist` are **not** in the repo — they name a
specific Firebase project, and a fork should point at its own. Copy the
`.example` file sitting next to each one and fill in your own project's values.
Both builds require the real filename: the Gradle `google-services` plugin
reads the JSON, and the Xcode Runner target bundles the plist as a resource.

Push notifications are the only thing that needs them. Everything else —
messaging, linking, the relay, the hub — runs without a Firebase project at
all.

## Style

Match the file you're editing. There is no separate style guide; `cargo fmt`,
`dart format` and the existing comment density are the standard. Comments here
tend to explain *why* a thing is the way it is, especially where the reason is
non-obvious or was learned the hard way — that convention is deliberate, and
worth keeping.

## Developer Certificate of Origin 1.1

```
By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I have the right
    to submit it under the open source license indicated in the file; or

(b) The contribution is based upon previous work that, to the best of my
    knowledge, is covered under an appropriate open source license and I have
    the right under that license to submit that work with modifications,
    whether created in whole or in part by me, under the same open source
    license (unless I am permitted to submit under a different license), as
    indicated in the file; or

(c) The contribution was provided directly to me by some other person who
    certified (a), (b) or (c) and I have not modified it.

(d) I understand and agree that this project and the contribution are public
    and that a record of the contribution (including all personal information I
    submit with it, including my sign-off) is maintained indefinitely and may
    be redistributed consistent with this project or the open source license(s)
    involved.
```
