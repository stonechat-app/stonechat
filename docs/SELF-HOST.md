# Self-hosting Stonechat

Every piece of Stonechat's server side is open source and can run on a machine
you control. This guide covers what there is to run, and how to run each piece.
The component READMEs go deeper; this is the path through them.

## What you can self-host

| What                                 | What it gives you                                                             | Stays on the main network?       |
| ------------------------------------ | ----------------------------------------------------------------------------- | -------------------------------- |
| **A mailbox** (`relay/`)             | Your own mail lives on your own machine. One mailbox, one user: you.          | Yes                              |
| **A mailbox host** (`mailbox_host/`) | One box that runs your mailbox plus your invited friends' mailboxes.          | Yes                              |
| **A hub** (`hub/`)                   | Your own directory: a private Stonechat network with its own users.           | **No**, it is a separate network |
| **A push gateway** (`push_gateway/`) | Background wake-ups for phones running _your own build_ of the app. Optional. | n/a                              |

What each piece does:

- **Mailbox (relay).** Holds end-to-end encrypted envelopes until your devices
  collect them, then deletes them. It never sees message content, and its TLS
  certificate is self-signed and pinned by your contacts through a fingerprint
  you sign with your identity key. No certificate authority is involved.
- **Mailbox host.** The program that starts and stops mailbox containers on a
  box. The hosted service's shared boxes run the same program.
- **Hub.** The directory: it maps Stonechat IDs to public keys and mailbox
  addresses, and can provision mailboxes. It stores routing metadata, never
  content.
- **Push gateway.** Sends content-free "you have new messages" push notifications
  through APNs/FCM when a mailbox's owner is offline.

**Hubs do not federate.** Self-hosting a mailbox or a mailbox host keeps you on
the main directory: you can still message everyone on Stonechat. Running your
own hub creates a separate island: its users can reach each other, but not
anyone registered with `hub.stonechat.app`, and vice versa. You can create `stonechat.myorganization.app` and communicate among you freely and securitly.

The official apps from the App Store and Google Play work with every option
here. The only exception is push through your own gateway, which needs your own
app build (see [Push gateway](#push-gateway-optional)).

---

## Self-hosting a mailbox

Run a single mailbox, just for you, on any machine you control: a small VM or
an always-on Linux box at home.

### What you need

- A Linux machine.
- A **public IP or DNS name**. The address is published in the directory, and
  your contacts dial it directly.
- Inbound **8080/tcp** (the mailbox) and **8443/udp** (the browser transport)
  open in your cloud firewall, or forwarded on your router.
- The Stonechat app, with an identity already created. Copy your Stonechat ID
  (`SC-…`) from it.

> **Static or ephemeral IP.** An ephemeral IP works, but cloud providers can
> hand you a new one when the VM is stopped and started (a reboot keeps it). If
> the IP changes, contacts keep dialing the old one until you connect the
> mailbox again from the app, and you must recreate the container with the new
> `STONECHAT_WT_ADVERTISE`. A static (reserved) IP, or a DNS name you keep
> pointed at the box, avoids both. Dynamic DNS works if your home IP rotates.
> Your contacts' certificate pin is not tied to the address, so it survives
> either way.

### Run it

The published image is `ghcr.io/stonechat-app/relay`: the static relay binary
on `scratch`, nothing else. Pin it by digest rather than a floating tag, so you
always know which build you run:

```bash
curl -fsSL https://get.docker.com | sudo sh   # skip if Docker is already installed

docker buildx imagetools inspect ghcr.io/stonechat-app/relay:0.1.0   # → Digest: sha256:…

export STONECHAT_OWNER_ID=SC-XXXX-...   # replace with your Stonechat ID, copied from the app

export STONECHAT_MAILBOX_TOKEN=$(openssl rand -hex 24)
echo "$STONECHAT_MAILBOX_TOKEN"   # save it; you'll paste it into the app

export STONECHAT_PUBLIC_ADDR=$(curl -s ifconfig.me)   # or your DNS name
echo "$STONECHAT_PUBLIC_ADDR"

docker run -d --name stonechat-mailbox --restart unless-stopped \
  -p 8080:8080 -p 8443:8443/udp \
  -v stonechat-mailbox:/data \
  -e STONECHAT_OWNER_ID="$STONECHAT_OWNER_ID" \
  -e STONECHAT_OWNER_TOKEN="$STONECHAT_MAILBOX_TOKEN" \
  -e STONECHAT_WT_ADVERTISE="$STONECHAT_PUBLIC_ADDR" \
  ghcr.io/stonechat-app/relay@sha256:<digest>

curl -sk https://127.0.0.1:8080/health
```

What each piece is for:

- **`-v stonechat-mailbox:/data`.** Everything the mailbox keeps lives under
  `/data`: queued mail, media blobs, and the TLS key your contacts pin. A named
  volume survives recreating the container. Without it, an upgrade hands you an
  empty mailbox with a new certificate.
- **`STONECHAT_OWNER_ID`.** The mailbox only serves this identity. The directory
  checks it before listing your address, so nobody can register your mailbox as
  theirs.
- **`STONECHAT_OWNER_TOKEN`.** The secret your devices use to collect mail. It
  ends up on your phone and nowhere else; the hub never sees it.
- **`STONECHAT_WT_ADVERTISE`.** The name browsers dial. The browser transport's
  certificates must carry it. Without it phones work fine but no browser can
  connect, and the error looks like a pin mismatch when it is not
  (`relay/README.md` "The browser transport").
- **Port 8443/udp.** The app assumes the browser transport is on 8443 of the same
  host, so publish it on that port.

Not using Docker? The release also ships the binary itself
(`stonechat-relay-x86_64-linux-musl`, statically linked, no dependencies). Run
it with the same environment variables, plus `STONECHAT_DB`,
`STONECHAT_BLOBS` and `STONECHAT_TLS_DIR` pointing somewhere persistent. The
full environment list is in `relay/README.md`.

### Connect it

In the app: **Mailbox** → **Self-host** → **Address** `https://<your host>:8080`
and **Mailbox token** → **Connect my mailbox**.

The app pins the mailbox's certificate, checks the token opens it, and lists
the address in the directory. From then on your contacts deliver straight to
your box.

### Keep it running

- **Upgrade:** pull the new digest, `docker rm -f stonechat-mailbox`, and run
  the same command with the new digest. The volume carries your mail and TLS
  key across, so contacts' pins keep working.
- **Back up** the `stonechat-mailbox` volume if you care about undelivered mail
  surviving a disk loss. Your message history is not in it: history lives only
  on your devices.
- **If your address changes**, connect the mailbox again from the app so the
  directory lists the new one.
- **Disconnecting** (**Mailbox** → **Disconnect mailbox**) only removes your
  address from the directory; the phone forgets the address and token. The
  mailbox keeps running, and mail already queued on it stays there. Contacts'
  new messages wait on their phones until you connect again. To reconnect, use
  **Self-host** with the same address and token (`sudo docker inspect
  stonechat-mailbox` shows the token if you lost it); the volume keeps the TLS
  key, so the certificate is unchanged. To shut it down for good, also run
  `sudo docker rm -f stonechat-mailbox`.
- **Push:** without a gateway, messages arrive whenever the app is open or
  resumes, but there are no background wake-ups. The official app can only be
  woken by Stonechat's own gateway, and that gateway only accepts mailboxes the
  hosted hub provisions. A mailbox you run yourself gets no push with the
  official app.

---

## Self-hosting a mailbox host

A mailbox host runs mailboxes for **you and friends you invite**, on one box you
own. Each guest gets their own mailbox container, with its own port, token and
TLS certificate. Everyone stays on the main Stonechat directory.

The full walkthrough is [`mailbox_host/README.md`](../mailbox_host/README.md)
"Host your own Stonechat, step by step". The short version follows.

### Trust model: tell your guests

Messages stay end-to-end encrypted: even as root on the box, you cannot read
your friends' chats. You _can_ see that a friend has a mailbox on your box, and
its traffic metadata: when, how much, and from which IPs. Only host people who
are fine with that. They are choosing you as their operator instead of a
company.

### 1. Prepare the box

- A Linux VM (1 vCPU / 1 GB is plenty) or an always-on home box, with a
  **static public IP**. The IP is baked into every mailbox address on the host.
- Open inbound **8200/tcp** (the mailbox host itself) and **42000–42024, TCP
  and UDP** (guest mailboxes: `STONECHAT_MAILBOX_HOST_PORT_BASE` through base +
  capacity − 1). Each guest uses the same port number for both. The UDP half is
  the browser transport.

> **Browsers and mailboxes on a mailbox host.** Phones work fully. Browser access to
> mailboxes on a mailbox host is not wired up in the app yet: a friend who joins
> by invite registers no browser address, and a mailbox you connect through
> **Self-host** is registered as if its browser transport were on port 8443,
> not on its own port. Open the UDP range anyway, so nothing changes on the box
> once the app catches up.

### 2. Install and start it

```bash
curl -fsSL https://get.docker.com | sudo sh
sudo git clone https://github.com/stonechat-app/stonechat.git /opt/stonechat
cd /opt/stonechat/mailbox_host

sudo cp .env.example .env
openssl rand -hex 24     # your ADMIN TOKEN; save it
sudo nano .env           # STONECHAT_MAILBOX_HOST_ADMIN_TOKEN, STONECHAT_MAILBOX_HOST_ADVERTISE_HOST

sudo docker compose up -d --build
curl -sk https://127.0.0.1:8200/health   # → {"status":"ok","v":1,"tls_fp":"…"}
```

The mailbox host mounts the Docker socket and starts each guest as a sibling
container. Its state (`mailbox_host.db` and its TLS keypair) lives in
`/var/lib/stonechat`. **Back that directory up.** Every invite you send carries
the certificate's fingerprint, and the app pins it.

Pin the relay image the same way as for a single mailbox, by setting
`STONECHAT_MAILBOX_HOST_IMAGE=ghcr.io/stonechat-app/relay@sha256:…` in `.env`.

### 3. Create your own mailbox on it

```bash
curl -sk -X POST https://127.0.0.1:8200/v1/guest \
  -H "Authorization: Bearer <admin token>" \
  -H 'content-type: application/json' \
  -d '{"owner_id": "SC-…"}'
# → {"address": "https://<ip>:42000", "mailbox_token": "…", "tls_fp": "…"}
```

In the app: **Mailbox** → **Self-host** → paste `address` and `mailbox_token` →
**Connect my mailbox**.

### 4. Invite friends

In the app, the Mailbox screen now shows **Invites**. Enter
`https://<ip>:8200` and the admin token → **Connect** → **New invite**.
Invites are single-use and valid for 3 days. Send one over any channel. It
carries no secret, and the friend's app pins your host's certificate, so it
cannot be intercepted.

Each friend: install the app → create an identity → **Mailbox** → **A friend's
machine** → paste the invite → **Join with invite**.

### Upgrading

`git pull && sudo docker compose up -d --build` updates the mailbox host.
Running mailboxes are untouched.

Upgrading the _relay_ inside running mailboxes is a binary swap, never a
container recreate: a guest's mail lives in its container, so a fresh container
would be an empty mailbox. Point `STONECHAT_MAILBOX_HOST_IMAGE` at the new
digest, restart, then call `POST /v1/relay/roll`. The roll swaps one mailbox at
a time and rolls back any that does not come up on the new build.

If the box dies, nobody loses history: it lives on their phones, and each guest
can re-home their mailbox anywhere.

---

## Self-hosting a full hub

A hub of your own is a **private Stonechat network**: your directory, your
users, your rules. Users of your hub message each other; they cannot reach users
of `hub.stonechat.app`. The two directories share nothing.

### The pieces

```
  phones ──► your hub (directory)          required
     │
     └────► mailboxes                      required: bring-your-own, or on your mailbox hosts
                │
                └──► push gateway          optional: only with your own app build
```

- **The hub**: `hub/docker-compose.yml`. Holds `hub.db`, the directory.
- **Mailboxes**: either users run their own (as in "Self-hosting a mailbox"
  above) and register them with your hub, or you run mailbox hosts that your
  hub fills. Mailboxes **never run on the hub's machine**: the hub holds the
  directory, the mailbox boxes hold mail.
- **Push gateway**: optional, see below.

### 1. Run the hub

On a box with a domain name pointing at it:

```bash
sudo git clone https://github.com/stonechat-app/stonechat.git /opt/stonechat
cd /opt/stonechat/hub
cp .env.example .env
$EDITOR .env
```

The values that matter:

| Env                     | Set it to                                                                            |
| ----------------------- | ------------------------------------------------------------------------------------ |
| `STONECHAT_HUB_DOMAIN`  | Your hub's domain, e.g. `hub.example.com`. Its DNS A record must already point here. |
| `STONECHAT_BIND`        | `127.0.0.1`: Caddy fronts the hub, so the hub port need not be public.               |
| `COMPOSE_PROFILES`      | `tls`, so every `docker compose` command includes Caddy.                             |
| `STONECHAT_ADMIN_TOKEN` | `openssl rand -hex 32`. Enables the abuse-report admin routes.                       |
| `STONECHAT_STATE_DIR`   | Where `hub.db` lives on the host (default `/var/lib/stonechat`).                     |

Then:

```bash
docker compose up -d --build
curl -s https://hub.example.com/health
```

Open **80 and 443** (TCP, plus 443/udp) to the internet. Port 80 is not
optional: it is how Caddy proves the domain to Let's Encrypt, and closing it
breaks renewal 60 days later. Phones need a real certificate for the hub, so run
the `tls` profile for anything beyond local testing.

A self-hosted hub runs with billing off: no plans, no payment, every feature
open. Back it up with `sqlite3 hub.db ".backup out.db"` (it is in WAL mode, so
a plain `cp` of a running hub is not safe).

### 2. Point the app at it

Users choose the hub when they **create their identity**. On the first screen:
**Advanced** → **Service address (self-hosters only)** →
`https://hub.example.com` → then create the account as usual. An identity lives
on the hub it was created on.

### 3. Give your users mailboxes

Pick one or both:

**Bring-your-own (simplest).** Leave `STONECHAT_MAILBOX_HOSTS` empty. Each user
runs a mailbox as in "Self-hosting a mailbox" above, or joins a friend's
invite-mode mailbox host, and connects it from the app. Your hub only lists
addresses; no machine of yours holds anyone's mail.

**Your hub hands out mailboxes.** Run one or more mailbox hosts **in managed
mode** on other boxes, and add them to the hub's pool. On each mailbox host,
add to its `.env` and restart:

```bash
STONECHAT_MAILBOX_HOST_MANAGED=1
STONECHAT_MAILBOX_HOST_CAPACITY=200
STONECHAT_MAILBOX_HOST_IMAGE=ghcr.io/stonechat-app/relay@sha256:<digest>   # managed mode refuses a floating tag
```

Read its fingerprint with `curl -sk https://127.0.0.1:8200/health`, then list it
in the hub's `.env` and restart the hub:

```bash
STONECHAT_MAILBOX_HOSTS=de1=https://10.0.0.5:8200|DE|<that host's admin token>|<its tls_fp>
```

The four fields are all required:

- **Address:** where the hub reaches the mailbox host.
- **ISO country code:** where the mailboxes land, and what the app offers in the
  country picker.
- **Admin token:** that mailbox host's admin token.
- **TLS fingerprint:** the mailbox host self-signs, so this pin is the only
  thing stopping someone on the path from collecting the admin token.

A managed mailbox host refuses invites: the hub is its only authority. Keep its
public IP static, and allow `8200/tcp` from the hub only. Details:
`mailbox_host/README.md` "Hosting for a hub".

Check the hub sees the pool:

```bash
curl -s https://hub.example.com/v1/countries
```

### Push gateway (optional)

Without a push gateway everything works. Messages simply arrive when the app is
open or comes back to the foreground, instead of waking a closed app.

**It only helps if you ship your own build of the app.** Apple and Google only
accept a push signed with the credentials of the app it targets: APNs checks
your key's team against the bundle id, and FCM checks the Firebase project the
app was built with. Phones running the official Stonechat app can only be woken
by Stonechat's own gateway. If your users run your signed build (your bundle id,
your own Firebase project), this is what wakes them. The repo ships no Firebase
config: copy `app/ios/Runner/GoogleService-Info.plist.example` and
`app/android/app/google-services.json.example` to the real names and fill them
in from your Firebase project. Both real files are gitignored.

How it fits:

- The hub never calls the gateway, and the gateway never calls the hub.
  **Mailboxes** call it, when their owner's device is offline.
- It is stateless and holds only the APNs/FCM credentials. It sees device
  tokens and timing, never identities or content.
- It can run on the hub box, on a mailbox host, or on its own machine, as long
  as mailboxes can reach it.

Run it:

```bash
sudo mkdir -p /etc/stonechat
sudo cp AuthKey_XXXX.p8 /etc/stonechat/apns.p8
sudo cp firebase-service-account.json /etc/stonechat/fcm.json   # Android

cd /opt/stonechat/push_gateway
cp .env.example .env
$EDITOR .env      # APNs key id, team id, topic (your bundle id); FCM path;
                  # STONECHAT_PUSH_MINT_SECRET; STONECHAT_PUSH_BIND = this box's private IP
docker compose up -d --build
curl -s http://<private IP>:8100/health   # → {"apns": true, ...}
```

Then tell the mailboxes where it is, with the same mint secret on both sides:

- **Mailboxes your hub provisions:** set `STONECHAT_PUSH_GATEWAY=http://<gateway
private IP>:8100` and `STONECHAT_PUSH_MINT_SECRET` in the hub's `.env`. The hub
  mints a push key into every mailbox it places. Mailboxes keep the value they
  were created with, so set it before the first one.
- **Mailboxes users run themselves:** set `STONECHAT_PUSH_GATEWAY` in the
  mailbox's own environment. With a mint secret on the gateway, the mailbox
  also needs `STONECHAT_PUSH_KEY`, which nobody mints for it. Mint one where the
  secret is:

  ```bash
  key_id=pk_$(openssl rand -hex 8)
  tag=$(printf %s "$key_id" | openssl dgst -sha256 -hmac "$STONECHAT_PUSH_MINT_SECRET" | awk '{print $NF}')
  echo "$key_id:$tag"     # → STONECHAT_PUSH_KEY
  ```

  These mailboxes usually run outside your private network, so they need the
  gateway's public URL (see below).

Keep the gateway **off the public internet**. Publish it on a private address
and allow port 8100 from the mailbox hosts only, in the cloud firewall. `ufw`
cannot enforce this, because Docker's published ports bypass it. A mailbox that
can only reach it over the internet needs a public URL, and then the mint secret
is what stops it being an open push relay.

If a mailbox cannot reach the gateway, nothing breaks: the relay logs
`gateway ping failed` and push never arrives. Full reference:
[`push_gateway/README.md`](../push_gateway/README.md).

---

## Licensing

Everything here is AGPL-3.0. If you run a **modified** version as a network
service, you must offer its users the source of your modifications. Running it
unmodified asks nothing of you. The Stonechat name and logo are trademarks: a
hub you run for others should not call itself Stonechat. See
[LICENSING.md](../LICENSING.md).
