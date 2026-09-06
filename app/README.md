# app — the Stonechat phone client

Flutter, iOS and Android. Every key, every message, every piece of history
lives on the device; this app is the only thing in the system that can read a
message.

## What it is not

**It is not a protocol implementation.** `core/` is — one Rust crate holding
the entire session protocol (PQXDH + double ratchet + X-Wing seal), reached
here over FFI. `lib/core/session.dart` is a thin wrapper over
`lib/core/core_ffi.dart`; there is no cryptography written in Dart and no
libsodium in `pubspec.yaml`. If you need new protocol behaviour, it goes in
`core/` and comes out through the C ABI — never reimplemented here.

That constraint is what lets the same protocol run in the browser
(`webclient/`, the same crate as wasm) and in a headless agent
(`agent_client/`, the same crate linked directly) without three subtly
different implementations drifting apart.

## Layout

| Path | What lives there |
|---|---|
| `lib/core/` | The boundary to everything outside the UI. `core_ffi.dart` is the FFI surface onto `core/`; `pqcore.dart` the KEM half; `api.dart` the transport to hub and relay; `crypto.dart`, `session.dart`, `device_keys.dart`, `linking.dart` the identity and session plumbing. |
| `lib/state/` | Orchestration. `chat_state.dart` is the center of the app — fan-out, the outbox, the certificate cache. |
| `lib/ui/` | Screens and widgets. `theme.dart` is the visual identity; `webclient/src/theme.css` is lifted from it value-for-value, so the two move together. |
| `lib/models.dart` | The data shapes shared across all three. |
| `test/` | Unit and widget tests, plus the parity tests that check this client against the same corpora the Rust and TypeScript clients are checked against. |

## Running it

You need the core library built first — `flutter test` and the app both load
it:

```bash
../scripts/build_core.sh host       # dylib/so, for tests and desktop tooling
../scripts/build_core.sh ios        # device + simulator staticlibs into ios/Core/
../scripts/build_core.sh android    # jniLibs per ABI

flutter run
```

Then, in the app: **Forge identity** → the relay screen → **LOCAL** →
**Ignite**. That asks a locally running hub to build the relay image from
`relay/` and start it as a container. Run a second simulator, forge a second
identity, exchange Stonechat IDs, and you have a conversation. The repo README's
Quick start has the hub side.

Testing from a real phone on your LAN: start the hub with
`STONECHAT_LOCAL_HOST=<your-machine-LAN-IP>` and point the app's hub field
(onboarding → advanced) at `http://<your-machine-LAN-IP>:8000`.

## Firebase config

`android/app/google-services.json` and `ios/Runner/GoogleService-Info.plist`
are **not** in the repo — they name a specific Firebase project, and a fork
should use its own. Copy the `.example` next to each one and fill in your
project's values. Both builds need the real filename: the Gradle
`google-services` plugin reads the JSON, and the Xcode Runner target bundles
the plist as a resource.

Only push notifications need them. Messaging, linking, the relay and the hub
all work without a Firebase project.

## Tests

```bash
flutter analyze
STONECHAT_CORE_LIB=$PWD/../core/target/release/libstonechat_core.dylib flutter test

flutter test test/golden_transcript_test.dart   # one file
flutter test --plain-name "handshake"           # one test
```

`golden_transcript_test.dart` and `core_parity_test.dart` are the ones that
matter most: they replay recorded transcripts through this client, so a change
in `core/` that alters the wire format fails here loudly instead of in the
field.
