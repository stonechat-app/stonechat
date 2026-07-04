# Deploying Zeon for a first live test

This gets **one VM** running the whole backend — control plane + directory, and
mailboxes as Docker containers on the same box (the `local` provider) — enough
for you and a friend to chat over real iPhones. It is deliberately the simplest
topology, not the production one; see "Beyond a friends test" at the end.

Everything here assumes a fresh **Debian or Ubuntu** VM. Per
[BUSINESS.md](../BUSINESS.md), **DigitalOcean or Hetzner** are the right hosts
(≈$4–5/mo, bundled IPv4, and — unlike AWS — you can reach your own public IP
from inside the box, which the health checks rely on).

## 1. Get a VM

- Smallest droplet / cloud instance is plenty (1 vCPU, 1 GB).
- Note its **public IPv4** — phones connect to this. Call it `PUBLIC_IP` below.
- SSH in as root (or a sudo user).

## 2. Put the repo on the box

```bash
# on the VM
git clone <your-repo-url> zeonchat && cd zeonchat
# (private repo → use a deploy key or a PAT)
```

## 3. Run the setup script

```bash
sudo ZEON_PUBLIC_IP=<PUBLIC_IP> deploy/setup.sh
```

It installs Docker + Python, builds the control-plane venv, prebuilds the relay
image, writes a **systemd** service (`zeon-control-plane`), opens the host
firewall with `ufw`, and health-checks itself. Re-run it any time after a
`git pull` — it rebuilds and restarts idempotently.

Knobs (all optional env vars):

| Var | Default | Meaning |
|---|---|---|
| `ZEON_PUBLIC_IP` | — (required) | Address phones + health checks use; baked into every mailbox's advertised URL |
| `ZEON_CP_PORT` | `8000` | Control-plane listen port |
| `MAILBOX_PORT_RANGE` | `32768:60999` | Host ports Docker publishes mailboxes on (the kernel ephemeral range) |

## 4. Open the CLOUD firewall too

`ufw` guards the OS, but cloud providers have a **separate** network firewall
you must also open. Add inbound TCP rules for:

- **`8000`** (or your `ZEON_CP_PORT`) — the control plane
- **`32768–60999`** — the mailbox containers (Docker's published-port range)

On DigitalOcean/Hetzner that's the "Cloud Firewall" UI; on AWS/GCP it's the
security group / VPC firewall. Without this, the app reaches nothing.

> Why such a wide mailbox range: the `local` provider lets Docker pick a random
> host port per mailbox, from the kernel's ephemeral range. For a handful of
> users this is fine. To pin it down later, constrain the range or add a fixed
> port base to the provider (see "Beyond a friends test").

## 5. Build the app and send it to your friend

You need the **Apple Developer Program** ($99/yr) — enroll first, approval can
take a day or two. Then, on your Mac:

```bash
cd app
flutter build ipa --dart-define=ZEON_CP=http://<PUBLIC_IP>:8000
```

Baking `ZEON_CP` in means neither of you has to type the server address.
Upload the archive (Xcode → Organizer, or `xcrun altool`) to **TestFlight**,
then add your friend as an **internal tester** in App Store Connect — internal
testing needs no Apple review, so this is same-day.

(No Mac/Apple account yet? For a quick local proof you can instead run the app
from `flutter run` on a simulator or a USB-tethered iPhone with the same
`--dart-define`, and skip TestFlight.)

## 6. The actual test

Both of you, in the app:

1. **Forge identity** (generates your Ed25519 key on-device).
2. Open the relay screen → provider **This computer** (the `local` provider) →
   **Ignite**. The control plane spins up your mailbox container and the app
   pins its TLS certificate.
3. Exchange **handles** (the `zn-word-word-word` on your ID screen) — type or QR.
4. Send a message, a photo, a voice note.
5. The finale: hit **Turn off** and watch the mailbox container get destroyed —
   "delete the only server my messages ever touched."

Keep the app **foregrounded**: there are no push notifications yet, so delivery
happens over the live WebSocket while the app is open or on resume.

## Operating it

```bash
systemctl status zeon-control-plane          # is it up?
journalctl -u zeon-control-plane -f          # live logs
docker ps                                    # running mailboxes
systemctl restart zeon-control-plane         # after config changes

# update to the latest code:
cd ~/zeonchat && git pull && sudo ZEON_PUBLIC_IP=<PUBLIC_IP> deploy/setup.sh
```

State that survives restarts: the control-plane DB at
`/var/lib/zeon/control_plane.db` and each mailbox's SQLite + TLS key inside its
container volume. Destroying a mailbox from the app (or `docker rm -f`) is
final — its undelivered ciphertext is gone, by design.

## Enable push (optional)

Without this, messages arrive only while the app is foregrounded or on resume —
fine for a quick test. To get real background wake-ups, stand up the push
gateway. It's the only component that holds APNs/FCM credentials, and it never
learns identities (the relay pings it with just a device token). The app→relay→
gateway wiring is already built; you only need credentials + the service.

**1. Apple push key.** In your Apple Developer account: Certificates, IDs &
Profiles → Keys → create an **APNs Auth Key** (`.p8`). Note the Key ID and your
Team ID. Enable the **Push Notifications** capability on your app id.

**2. App build.** In Xcode add the Push Notifications capability to the Runner
target (creates `Runner.entitlements` with `aps-environment`), drop in the
Firebase config the app uses to obtain the token (`GoogleService-Info.plist`
for iOS, `google-services.json` for Android), and rebuild the IPA. Without these
the app just runs push-disabled — no crash.

> The app fetches the raw APNs token on iOS and sends it to your mailbox; our
> gateway pushes APNs-direct. Firebase here is only the token-acquisition /
> notification-lifecycle plumbing.

**3. Run the gateway** on the same VM:

```bash
cd ~/zeonchat/gateway
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
sudo mkdir -p /etc/zeon && sudo cp /path/to/AuthKey_XXXX.p8 /etc/zeon/apns.p8
sudo cp deploy/zeon-push-gateway.service /etc/systemd/system/
sudo nano /etc/systemd/system/zeon-push-gateway.service   # fill in key id / team id / topic
sudo systemctl daemon-reload && sudo systemctl enable --now zeon-push-gateway
curl -s localhost:8100/health     # -> {"apns": true, ...}
```

Do **not** open port 8100 in the firewall — only the mailbox containers reach
it, over the Docker bridge.

**4. Point the control plane at it** and recreate mailboxes so they inherit the
setting (mailbox containers reach the host at the Docker bridge address, not
`127.0.0.1`):

```bash
cd ~/zeonchat
sudo ZEON_PUBLIC_IP=<PUBLIC_IP> ZEON_PUSH_GATEWAY=http://172.17.0.1:8100 deploy/setup.sh
```

Existing mailboxes keep their old (empty) gateway setting until recreated —
have each user **Turn off → Ignite** once, or destroy/re-provision. New Ignites
get it automatically. Verify with a message to a user whose app is fully closed.

## Host friends on your box ("host your circle")

Want your VM to also host a few friends' mailboxes? Run the **host agent**
(`agent/README.md`) alongside the control plane — it mints invites and spins up
a container per invited friend on the same box, each end-to-end encrypted and
unreadable to you. Open port 8200 (agent) plus the mailbox range, and share
invites from the app ("Host friends on my server"). Friends redeem with
"Join a friend's host."

## What this setup skips (fine for two people)

- **The reconciler, billing, abuse handling** — the "before charging money"
  list in BUSINESS.md. Not needed for a test.
- **A domain + HTTPS on the control plane** — the app talks to it over plain
  HTTP here. (Mailbox traffic is already pinned TLS regardless.) For anything
  public, put the control plane behind a domain with Caddy/Let's Encrypt and
  build with `--dart-define=ZEON_CP=https://…`.

## Beyond a friends test

When you outgrow one box, the moves — all already scaffolded in the codebase —
are: switch the managed tier to the `fleet` provider (container-per-user across
shared hosts, `ZEON_FLEET_HOSTS`) or real per-user VMs (`DigitalOceanProvider`/
`HetznerProvider` adapters), pin the mailbox port range, add the reconciler and
push gateway, and front the control plane with TLS. See BUSINESS.md's "Before
charging money" checklist.
