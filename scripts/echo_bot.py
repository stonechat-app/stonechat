"""Echo bot: a headless Stonechat identity for testing the app against production.

Registers a real identity on the hub, ignites a shared-tier mailbox, then sits on
its websocket forever: auto-accepts contact requests and replies to every
message with a random canned sentence. Add its SC- ID from the phone's
"Add contact" screen and you have someone to chat with.

Usage (first run provisions; later runs reuse the saved identity):

    STONECHAT_TEST_CODE=STONECHAT-XXXX-XXXX python3 scripts/echo_bot.py

    python3 scripts/echo_bot.py --add SC-...   # bot sends YOU the request
    python3 scripts/echo_bot.py --say SC-... "text"  # one message, then exit
                                               # (background the app first —
                                               # this is the notification test)
    python3 scripts/echo_bot.py --destroy      # tear down mailbox + state

Env: STONECHAT_HUB (default https://hub.stonechat.app), STONECHAT_TEST_CODE (required on
first run — the shared tier is plan-gated), STONECHAT_BOT_NAME (default: a random
"<word> (echo bot)", chosen once and kept with the identity),
STONECHAT_BOT_STATE (default ~/.stonechat_echo_bot.pkl).

Identity, prekeys, and ratchet sessions persist in the state file, so the bot
survives restarts without breaking established chats. Deps: httpx, pynacl,
websockets (the e2e/hub venv has all three).
"""

import asyncio
import base64
import json
import os
import pathlib
import pickle
import random
import sys
import time
import uuid

os.environ.setdefault("STONECHAT_HUB", "https://hub.stonechat.app")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import httpx
import websockets
from nacl.signing import SigningKey, VerifyKey

import e2e
from e2e import MX, WS_SSL, Phone
from app.identity import stonechat_id_from_pubkey  # noqa: E402 (path set by e2e)

HUB = e2e.HUB

# A different name per run, so several bots in a contact list are tellable
# apart — and so a fresh one is obviously fresh rather than looking like the
# last one come back. STONECHAT_BOT_NAME still overrides.
#
# The name is chosen once and then persisted with the identity: it is part of
# who this bot is to everyone who has added it, and rerolling it on restart
# would rename a contact under the user.
_WORDS = [
    "amber", "basalt", "cedar", "delta", "ember", "flint", "granite", "harbor",
    "indigo", "juniper", "kelp", "lumen", "marble", "nimbus", "onyx", "pebble",
    "quartz", "ridge", "slate", "tundra", "umber", "vellum", "willow", "yarrow",
]


def random_bot_name() -> str:
    return f"{random.choice(_WORDS)} (echo bot)"


BOT_NAME = os.environ.get("STONECHAT_BOT_NAME") or random_bot_name()
STATE_PATH = pathlib.Path(
    os.environ.get("STONECHAT_BOT_STATE", pathlib.Path.home() / ".stonechat_echo_bot.pkl"))

SENTENCES = [
    "Interesting — tell me more.",
    "Ha! I was just thinking the same thing.",
    "Message received loud and clear over here.",
    "That's a bold claim. I respect it.",
    "The ratchet turned, the sentence arrived. All is well.",
    "Sure, but have you considered the opposite?",
    "I'd reply something smarter, but I only know ten sentences.",
    "Encrypted, delivered, acknowledged. What a time to be alive.",
    "Noted. Filing that under 'important'.",
    "Say that again and I'll say this again.",
]


class Peer:
    """Duck-typed stand-in for e2e.Phone on the remote side: exactly the
    attributes Phone.make_envelope/wrap/deliver_to read from `to`.

    `cert` is the peer device's certificate, and it is load-bearing: since
    device certificates, envelopes are sealed to the key a *certificate* names,
    not to the one identity key in the directory. Without it wrap() has nothing
    to encrypt to. It is cached in the bot's state because fetching it means
    pulling the peer's bundle, which consumes one of their one-time prekeys."""

    def __init__(self, stonechat_id: str, pubkey_b64: str, address: str,
                 cert: dict | None = None):
        self.stonechat_id = stonechat_id
        self.pubkey_b64 = pubkey_b64
        self.address = address
        self.mailbox = {"address": address}
        self.cert = cert
        # Only read if `cert` is missing, which for a remote peer means we
        # have no business sending at all — so it fails loudly rather than
        # sealing to something arbitrary.
        self.dev_seal_pk = None


def hub(method: str, path: str, **kw) -> dict:
    """A hub call that fails with a sentence rather than a KeyError.

    The bot used to call .json() straight off the response, so a 401 body —
    `{"detail": "..."}` — surfaced three lines later as `KeyError: 'status'`
    and pointed nowhere. 401 in particular has one overwhelmingly likely
    cause worth naming.
    """
    r = httpx.request(method, f"{HUB}{path}", timeout=30, **kw)
    if r.status_code == 401:
        sys.exit(
            f"the hub no longer knows this identity ({r.status_code}).\n"
            f"Its directory was probably reset. Delete {STATE_PATH} and re-run "
            "to register a fresh one."
        )
    if r.status_code >= 400:
        sys.exit(f"{method} {path} failed ({r.status_code}): {r.text[:300]}")
    return r.json()


def peer_cert(bot: Phone, peer: Peer, device: int) -> dict:
    """One of the peer's device certificates, cached.

    Every envelope is sealed to the key a certificate names, so this is needed
    on *every* send — but fetching it means pulling their prekey bundle, which
    consumes one of their one-time prekeys. Hence the cache. Verified against
    the identity key their SC- ID commits to before it is trusted or stored.
    """
    key = (peer.stonechat_id, device)
    cached = bot.peer_certs.get(key)
    if cached:
        return cached
    params = {}
    if device != e2e.PRIMARY_DEVICE:
        # Only device 1's bundle is open. Anything else needs their bundle
        # token, which rides every envelope they have sent us.
        token = bot.bundle_tokens.get(peer.stonechat_id)
        if not token:
            raise RuntimeError(f"no bundle token for {peer.stonechat_id}")
        params = {"device": device, "token": token}
    bundle = MX.get(f"{peer.mailbox['address']}/prekeys/bundle",
                    params=params, timeout=15)
    bundle.raise_for_status()
    cert = bundle.json().get("cert")
    if not cert:
        raise RuntimeError(
            f"{peer.stonechat_id} device {device} publishes no certificate — "
            "nothing to encrypt to")
    e2e.verify_devcert(cert, base64.b64decode(peer.pubkey_b64), device=device)
    bot.peer_certs[key] = cert
    return cert


def peer_devices(bot: Phone, peer: Peer) -> list[int]:
    """Which of a peer's devices to encrypt for.

    Not optional, and not a nicety: a browser session is device 2 or later, so
    a reply that only ever went to device 1 would reach their phone and never
    the tab that sent the message. Which devices exist comes from their bundle
    token; without one we can reach only their primary, which is exactly what
    a stranger's first message gets.
    """
    token = bot.bundle_tokens.get(peer.stonechat_id)
    if not token:
        return [e2e.PRIMARY_DEVICE]
    try:
        listed = MX.get(f"{peer.mailbox['address']}/prekeys/devices",
                        params={"token": token}, timeout=15)
        listed.raise_for_status()
        ids = sorted(d["device_id"] for d in listed.json()["devices"])
        return ids or [e2e.PRIMARY_DEVICE]
    except Exception:
        # A listing we cannot fetch is not a reason to send nothing.
        return [e2e.PRIMARY_DEVICE]


def resolve(stonechat_id: str) -> Peer:
    entry = httpx.get(f"{HUB}/v1/directory/{stonechat_id}", timeout=10)
    entry.raise_for_status()
    entry = entry.json()
    assert stonechat_id_from_pubkey(base64.b64decode(entry["pubkey"])) == entry["stonechat_id"], \
        "directory pubkey does not commit to the Stonechat ID"
    # The identity's X-Wing key is still published and still signature-checked
    # — a directory serving an unsigned one is serving junk — but **nothing
    # seals to it any more**. Envelopes go to a device's certified seal key;
    # see peer_cert() below.
    VerifyKey(base64.b64decode(entry["pubkey"])).verify(
        e2e.PQPK_SIG_CONTEXT + base64.b64decode(entry["pq_pk"]),
        base64.b64decode(entry["pq_sig"]))
    if not entry["mailbox"]:
        raise RuntimeError(f"{stonechat_id} has no running relay — can't deliver")
    return Peer(entry["stonechat_id"], entry["pubkey"],
                entry["mailbox"]["address"])


# -- state ---------------------------------------------------------------------

def save(bot: Phone) -> None:
    STATE_PATH.write_bytes(pickle.dumps({
        "seed": bytes(bot.identity),
        "name": bot.name,
        "stonechat_id": bot.stonechat_id,
        "token": bot.token,
        "mailbox": bot.mailbox,
        "sessions": bot.sessions,
        "spk": bot.spk,
        "opks": bot.opks,
        "kspk": bot.kspk,
        "kopks": bot.kopks,
        "next_prekey_id": bot._next_prekey_id,
        # This device's own keys and the certificate over them. Regenerating
        # these on restart would publish prekeys signed by a key no peer has
        # heard of, and leave every cached certificate pointing at a seal key
        # this process no longer holds — every established chat would break,
        # silently, which is the one thing the state file exists to prevent.
        "dev_sig_seed": bytes(bot.dev_sig),
        "dev_seal_seed": bot.dev_seal_seed,
        "cert": bot.cert,
        # Peer certificates: needed on every send, and each fetch costs one of
        # their one-time prekeys.
        "peer_certs": bot.peer_certs,
        # Their bundle tokens, so fan-out survives a restart.
        "bundle_tokens": bot.bundle_tokens,
    }))


def load() -> Phone | None:
    if not STATE_PATH.exists():
        return None
    s = pickle.loads(STATE_PATH.read_bytes())
    bot = Phone(s.get("name", BOT_NAME))
    bot.identity = SigningKey(s["seed"])
    bot.pubkey_b64 = e2e.b64(bytes(bot.identity.verify_key))
    # Restore the device keys *before* derive_pq, which only mints them when
    # they are absent. Getting this order wrong is how a restart quietly
    # becomes a different device.
    if "dev_sig_seed" in s:
        bot.dev_sig = SigningKey(s["dev_sig_seed"])
        bot.dev_seal_seed = s["dev_seal_seed"]
    bot.derive_pq()
    bot.cert = s.get("cert")
    bot.peer_certs = s.get("peer_certs", {})
    bot.bundle_tokens = s.get("bundle_tokens", {})
    bot.stonechat_id, bot.token, bot.mailbox = s["stonechat_id"], s["token"], s["mailbox"]
    bot.sessions, bot.spk, bot.opks = s["sessions"], s["spk"], s["opks"]
    bot.kspk, bot.kopks = s.get("kspk"), s.get("kopks", {})
    bot._next_prekey_id = s["next_prekey_id"]
    if "dev_sig_seed" not in s:
        # State from before device certificates. The keys it holds are for a
        # device the relay has never heard of, so the sessions in it are dead.
        sys.exit(
            f"{STATE_PATH} predates device certificates — its sessions cannot "
            "be resumed. Delete it and re-run to register fresh."
        )
    return bot


# -- provisioning --------------------------------------------------------------

def redeem(bot: Phone) -> None:
    code = os.environ.get("STONECHAT_TEST_CODE") or sys.exit(
        "the shared tier is plan-gated — set STONECHAT_TEST_CODE (the current tester "
        "live in the hub's systemd drop-in, STONECHAT_TEST_CODES)")
    r = httpx.post(f"{HUB}/v1/billing/redeem", headers=bot.auth,
                   json={"code": code}, timeout=30)
    if r.status_code == 404:
        sys.exit(f"hub does not recognize code {code!r} — that's the "
                 "placeholder or a revoked code; use the current one from "
                 "the hub's drop-in")
    if r.status_code >= 400:
        sys.exit(f"redeeming {code!r} failed ({r.status_code}): {r.text[:300]}")
    print("entitlement:", r.json()["plan"], r.json()["status"])


def ensure_provisioned(bot: Phone) -> None:
    """Idempotent: registers/ignites whatever is still missing, so a failed
    first run (bad code, network blip) resumes instead of orphaning IDs."""
    srv = hub("GET", "/v1/mailbox", headers=bot.auth)
    if srv["status"] == "error":
        sys.exit(f"relay is in error state: {srv.get('error')} — run "
                 "--destroy and start over")
    if srv["status"] == "none":
        body = {
            "provider": "machine_host",
            "machine": {"machine_type": "container",
                        "region": e2e.shared_country(HUB), "disk_gb": 10},
        }
        r = httpx.post(f"{HUB}/v1/mailbox", headers=bot.auth, json=body, timeout=30)
        if r.status_code == 402:
            redeem(bot)
            r = httpx.post(f"{HUB}/v1/mailbox", headers=bot.auth, json=body,
                           timeout=30)
        if r.status_code != 202:
            sys.exit(f"could not ignite a mailbox ({r.status_code}): "
                     f"{r.text[:300]}")
        print("igniting shared-tier mailbox…")
    if srv["status"] == "running":
        bot.mailbox = srv
    else:
        bot.wait_running()
    if bot.spk is None:  # first run (or crashed before prekeys landed)
        bot.publish_tls_sig()
        # Mints this device's certificate if it has none, and publishes it
        # alongside the prekeys it signed — one without the other leaves a
        # sender unable to check either.
        bot.upload_prekeys(opk_count=32)
    # Vouch for the browser transport's certificate schedule, on every start
    # rather than only the first: the relay may have been replaced since, and
    # the schedule rotates on its own. An unvouched schedule is served by the
    # directory as *no* schedule — deliberately, since a client must not pin
    # something nobody signed — so a browser simply refuses to connect, with
    # "that mailbox publishes no signed browser-transport certificates".
    #
    # Best-effort: a relay with no browser transport returns None and native
    # clients are unaffected either way.
    try:
        if bot.publish_wt_certs() is not None:
            print("vouched for the browser transport's certificates")
    except Exception as exc:
        print(f"could not vouch for the browser transport: {exc!r}")
    save(bot)


def top_up_opks(bot: Phone) -> None:
    st = MX.get(f"{bot.mailbox['address']}/status",
                params={"token": bot.mailbox["mailbox_token"]}).json()
    if st["prekeys"]["opks"] < 8:
        bot.upload_prekeys(opk_count=16)
        save(bot)
        print("topped up one-time prekeys")


# -- the bot -------------------------------------------------------------------

def send(bot: Phone, peer: Peer, type_: str, payload: dict) -> None:
    """Seal and deliver one envelope **per device** the peer has.

    The recipient device's certified key is needed on every message, not just
    the first — an established session never re-fetches a bundle. But a bundle
    fetch consumes one of their one-time prekeys, so the order matters: use the
    cache, and otherwise let the handshake's own fetch supply it rather than
    paying for a second one.

    One dead device does not stop its siblings: the ones that took a copy will
    show the message.
    """
    envelope_id = str(uuid.uuid4())
    token = bot.bundle_tokens.get(peer.stonechat_id)
    delivered, last_error = 0, None
    for device in peer_devices(bot, peer):
        key = (peer.stonechat_id, device)
        try:
            peer.cert = bot.peer_certs.get(key)
            if peer.cert is None and key in bot.sessions:
                # A session with no cached certificate: nothing is about to
                # fetch a bundle on our behalf, so do it once.
                peer.cert = peer_cert(bot, peer, device)
            bot.deliver_to(peer, bot.seal(
                peer, type_, payload, envelope_id=envelope_id,
                device=device, bundle_token=token))
            # seal() establishes the session when there is none, and records
            # the certificate it verified on the way.
            if peer.cert is not None:
                bot.peer_certs[key] = peer.cert
            delivered += 1
        except Exception as exc:
            last_error = exc
            print(f"  ! device {device} of {peer.stonechat_id[:12]}…: {exc!r}")
    if delivered == 0 and last_error is not None:
        raise last_error
    save(bot)


async def handle(bot: Phone, outer: dict) -> None:
    inner = bot.unseal(outer)
    sender, type_ = inner["from"], inner["type"]
    # Their bundle token rides every envelope. It is what lets a reply reach
    # all of their devices instead of only their primary — without it a
    # browser session never sees an answer to the message it just sent.
    if inner.get("bundle_token"):
        bot.bundle_tokens[sender] = inner["bundle_token"]
    payload = bot.open_envelope(inner, None)

    if type_ == "contact_request":
        name = payload.get("display_name") or sender[:12]
        print(f"contact request from {name} ({sender}) — accepting")
        peer = resolve(sender)
        send(bot, peer, "contact_accept", {"display_name": bot.name})
        await asyncio.sleep(1.0)
        send(bot, peer, "msg",
             {"text": f"Hi {name}! I'm {bot.name}. Say anything and "
                      "I'll answer with one of my ten sentences."})
    elif type_ == "contact_accept":
        print(f"{sender} accepted our request")
    elif type_ in ("msg", "media"):
        got = payload.get("text", f"<{type_}>")
        print(f"{sender[:12]}…: {got!r}")
        peer = resolve(sender)
        await asyncio.sleep(random.uniform(0.6, 1.8))  # feels less robotic
        send(bot, peer, "msg", {"text": random.choice(SENTENCES)})
    else:
        # typing, receipts, reactions, profile updates, calls… decrypting
        # above already kept the ratchet current; nothing to answer.
        print(f"ignoring {type_} from {sender[:12]}…")


async def run(bot: Phone) -> None:
    url = (bot.mailbox["address"].replace("http", "ws", 1)
           + f"/ws?token={bot.mailbox['mailbox_token']}")
    while True:
        try:
            async with websockets.connect(url, ssl=WS_SSL, ping_interval=20) as ws:
                print("connected — waiting for messages (Ctrl-C to stop)")
                top_up_opks(bot)
                async for raw in ws:
                    outer = json.loads(raw)
                    try:
                        await handle(bot, outer)
                    except Exception as exc:  # never wedge the queue
                        print(f"  ! could not handle {outer.get('id')}: {exc!r}")
                    await ws.send(json.dumps({"ack": outer["id"]}))
                    save(bot)
        except (OSError, websockets.WebSocketException) as exc:
            print(f"websocket dropped ({exc!r}) — reconnecting in 3s")
            await asyncio.sleep(3)


def main() -> None:
    if "--destroy" in sys.argv:
        bot = load() or sys.exit("no state file — nothing to destroy")
        httpx.delete(f"{HUB}/v1/mailbox",
                     headers=bot.auth, timeout=30).raise_for_status()
        STATE_PATH.unlink()
        print("mailbox destroyed, state removed")
        return

    bot = load()
    if bot is None:
        bot = Phone(BOT_NAME)
        bot.peer_certs = {}
        bot.bundle_tokens = {}
        print("registering fresh identity on", HUB)
        bot.register()
        save(bot)
    ensure_provisioned(bot)

    print(f"\n  {bot.name}: {bot.stonechat_id}")
    print("  add this ID as a contact on your phone\n")

    if "--say" in sys.argv:
        # Fire one message and exit — made for testing the phone's
        # notification path: background the app there first, then run this;
        # the relay queues it, pings the gateway, and the push should show
        # the decrypted preview.
        i = sys.argv.index("--say")
        target, text = sys.argv[i + 1], sys.argv[i + 2]
        peer = resolve(target)
        send(bot, peer, "msg", {"text": text})
        print(f"sent to {target}: {text!r}")
        return

    if "--add" in sys.argv:
        target = sys.argv[sys.argv.index("--add") + 1]
        peer = resolve(target)
        send(bot, peer, "contact_request", {"display_name": bot.name})
        print(f"sent contact request to {target} — accept it on the phone")

    try:
        asyncio.run(run(bot))
    except KeyboardInterrupt:
        print("\nbye — mailbox stays up; re-run to resume, --destroy to remove")


if __name__ == "__main__":
    main()
