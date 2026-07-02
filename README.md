# Zeon Chat

Privacy-first messaging where **every user runs their own server**.

- No central message store. Your "relay" is a tiny VM you spin up (GCP, AWS, or
  a local Docker container for dev) whose only job is to hold **end-to-end
  encrypted envelopes** until your phone picks them up — then they're deleted.
- Message history lives on your phone only. Uninstall the app and it's gone.
- No phone number, no email. Your identity is an X25519 keypair generated on
  device; your **Zeon ID** (`ZC-XXXX-…`) is a hash commitment to the public key.
  Share it by QR or text — it reveals nothing about you.

See [PROTOCOL.md](PROTOCOL.md) for the full wire protocol and threat notes.

## Components

| Directory | What it is |
|---|---|
| `app/` | Flutter app (iOS/Android). Keys, history, encryption — all client-side. |
| `server/` | Routing server ("relay"). Single-file FastAPI + SQLite mailbox that runs on the user's VM. Stores ciphertext only, deletes on ack. |
| `control-plane/` | Provisioner + directory. Boots/destroys relays via a pluggable provider layer and maps Zeon IDs → pubkeys + current relay address. Never sees message content. |

## Quick start (all local, no cloud account)

Requirements: Python 3.11+, Docker, Flutter.

```bash
# 1. control plane
cd control-plane
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/uvicorn app.main:app --port 8000

# 2. app (simulator)
cd ../app
flutter run
```

In the app: **Forge identity** → open the relay screen → pick **LOCAL** →
**Ignite**. The control plane builds the relay Docker image from `server/` and
runs it as a container. Run a second simulator, forge a second identity,
exchange Zeon IDs, and chat.

Testing from a real phone: start the control plane with
`ZEON_LOCAL_HOST=<your-mac-LAN-IP>` and point the app's "control plane" field
(onboarding → advanced) at `http://<your-mac-LAN-IP>:8000`.

## Cloud providers

The provider layer (`control-plane/app/providers/`) is deliberately thin:
every provider boots the **same** startup script that embeds `server/main.py`,
so an adapter is only "create VM, pass script, return IP".

| Provider | Setup |
|---|---|
| `gcp` | `pip install google-cloud-compute`, set `ZEON_GCP_PROJECT`, auth via ADC (`gcloud auth application-default login`). `region` = zone, e.g. `us-central1-a`; `machine_type` e.g. `e2-micro` (free tier). |
| `aws` | `pip install boto3`, standard AWS credential chain. `region` e.g. `us-east-1`; `machine_type` e.g. `t3.micro`. |
| `local` | Docker only. For development. |

Adding one: subclass `CloudProvider` (two methods: `provision`, `destroy`) and
register it in `providers/__init__.py`.

## Testing

```bash
# end-to-end: register → provision (docker) → handshake → message → ack → destroy
cd control-plane && .venv/bin/pip install pynacl websockets
.venv/bin/uvicorn app.main:app --port 8477 &
.venv/bin/python ../scripts/e2e.py

# app unit tests + static analysis
cd app && flutter test && flutter analyze
```

## Honest limitations (v1)

- **The control plane is a centralized directory.** It stores routing metadata
  (ID → pubkey → relay IP), never content. Long term: self-hostable, or
  bring-your-own-cloud-credentials.
- **No push notifications yet.** Messages arrive while the app is open (live
  WebSocket) or on app resume. Content-free FCM/APNs wake-ups are the planned
  fix.
- **Transport is plain HTTP.** Payloads are E2E-encrypted regardless, but
  metadata protection wants TLS + server key pinning next.
- **No forward secrecy.** Static X25519 `crypto_box` per message; a Signal-style
  ratchet is a natural upgrade.
- Group chats: deliberately out of scope for now.
