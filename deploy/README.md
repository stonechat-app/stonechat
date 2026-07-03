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

## What this setup skips (fine for two people)

- **Push notifications** — the gateway exists but needs APNs credentials wired
  in; without it, foreground/resume delivery only.
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
