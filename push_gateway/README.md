# Push gateway

Optional. Without it, messages arrive whenever the app is open or resumes —
there are just no background wake-ups.

The gateway is the only component holding APNs/FCM credentials. Mailboxes
`POST /v1/ping` to it when their owner's device is offline, and it sends a
content-free "you have new messages" notification (PROTOCOL.md "Push
gateway"). It sees device tokens and timing, never identities.

## Before you run this

**It only helps if you ship your own build of the app.** Apple and Google
accept a push only when it is signed with credentials of the app it targets:
APNs checks the key's team against the bundle id (`STONECHAT_APNS_TOPIC`), FCM
checks the Firebase project the app was built with. Phones running the
official Stonechat app from the App Store or Play Store can only be woken by
Stonechat's own gateway, so a gateway you deploy cannot reach them.

If your users run your own signed build — your bundle id, your Firebase
config — this is the service that wakes them.

## How it connects to the rest

The hub never calls the gateway and the gateway never calls the hub.
**Mailboxes** make the calls, and each needs two values:

- `STONECHAT_PUSH_GATEWAY` — this service's address. A mailbox you run
  yourself sets it directly. A hub that provisions mailboxes copies its own
  value into each one; they keep the value they were created with, so set it
  before the first ignite, or re-ignite afterwards.
- `STONECHAT_PUSH_MINT_SECRET` — when set here, the gateway refuses pings
  without a push key minted from the same secret. Provisioning hubs mint one
  into each mailbox.

Because only mailboxes talk to it, the gateway can run on the hub box, on a
machine host, or on its own machine.

## Run it

```bash
# credentials, on the box that runs the gateway
sudo mkdir -p /etc/stonechat
sudo cp /path/to/AuthKey_XXXX.p8 /etc/stonechat/apns.p8
sudo cp /path/to/firebase-service-account.json /etc/stonechat/fcm.json   # Android

cd push_gateway
cp .env.example .env
$EDITOR .env          # APNs ids + topic, FCM path, mint secret, STONECHAT_PUSH_BIND
docker compose up -d --build
docker compose ps     # "healthy"
curl -s http://<STONECHAT_PUSH_BIND>:8100/health   # -> {"apns": true, ...}
```

Then point mailboxes at it: `STONECHAT_PUSH_GATEWAY=http://<GATEWAY_PRIVATE_IP>:8100`
in each self-run mailbox's environment, or in the `.env` of a hub that
provisions them, together with the same `STONECHAT_PUSH_MINT_SECRET`.

## Network

Reachable **from mailboxes, never from the internet**. Publish it on the box's
private address (`STONECHAT_PUSH_BIND`) and allow port 8100 from the machine
hosts' internal addresses only, in the cloud firewall — `ufw` cannot do this,
because Docker's published-port rules bypass it.

Mailboxes on dedicated VMs in another cloud cannot reach a private address at
all. Those need a public URL, with the mint secret set so the gateway is not
an open relay.

If a mailbox cannot reach the gateway, pings fail quietly: the relay logs
`gateway ping failed`, nothing else breaks, and push never arrives. Check from
a machine host with `curl http://<GATEWAY_PRIVATE_IP>:8100/health`.

## Operating it

- **Verify:** send a message to a user whose app is fully closed.
- **Cut off one abusive mailbox:** find its `pk_…` id in
  `docker compose logs push_gateway` and add it to
  `/etc/stonechat/push-blocklist`. No restart needed.
- **Update:** `git pull && docker compose up -d --build`. The gateway is
  stateless, so there is nothing to back up beyond `/etc/stonechat`.
