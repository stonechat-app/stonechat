"""Echo bot: a headless Stonechat identity for testing the app against production.

Registers a real identity on the hub, ignites a fleet mailbox, then sits on
its websocket forever: auto-accepts contact requests and replies to every
message with a random canned sentence. Add its SC- ID from the phone's
"Add contact" screen and you have someone to chat with.

Usage (first run provisions; later runs reuse the saved identity):

    STONECHAT_TEST_CODE=STONECHAT-XXXX-XXXX python3 scripts/echo_bot.py

    python3 scripts/echo_bot.py --add SC-...   # bot sends YOU the request
    python3 scripts/echo_bot.py --destroy      # tear down mailbox + state

Env: STONECHAT_HUB (default https://hub.stonechat.app), STONECHAT_TEST_CODE (required on
first run — fleet is plan-gated), STONECHAT_BOT_NAME (default "Echo Bot"),
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

os.environ.setdefault("STONECHAT_HUB", "https://hub.stonechat.app")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import httpx
import websockets
from nacl.signing import SigningKey, VerifyKey

import e2e
from e2e import MX, WS_SSL, Phone
from app.identity import stonechat_id_from_pubkey  # noqa: E402 (path set by e2e)

HUB = e2e.HUB
BOT_NAME = os.environ.get("STONECHAT_BOT_NAME", "Echo Bot")
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
    attributes Phone.make_envelope/wrap/deliver_to read from `to`."""

    def __init__(self, stonechat_id: str, pubkey_b64: str, pq_pk: bytes, address: str):
        self.stonechat_id = stonechat_id
        self.pubkey_b64 = pubkey_b64
        self.pq_pk = pq_pk
        self.server = {"address": address}


def resolve(stonechat_id: str) -> Peer:
    entry = httpx.get(f"{HUB}/v1/directory/{stonechat_id}", timeout=10)
    entry.raise_for_status()
    entry = entry.json()
    assert stonechat_id_from_pubkey(base64.b64decode(entry["pubkey"])) == entry["stonechat_id"], \
        "directory pubkey does not commit to the Stonechat ID"
    # The X-Wing key seals every envelope to this peer — only trust it
    # signed by the (commitment-checked) identity key.
    VerifyKey(base64.b64decode(entry["pubkey"])).verify(
        e2e.PQPK_SIG_CONTEXT + base64.b64decode(entry["pq_pk"]),
        base64.b64decode(entry["pq_sig"]))
    if not entry["server"]:
        raise RuntimeError(f"{stonechat_id} has no running relay — can't deliver")
    return Peer(entry["stonechat_id"], entry["pubkey"],
                base64.b64decode(entry["pq_pk"]), entry["server"]["address"])


# -- state ---------------------------------------------------------------------

def save(bot: Phone) -> None:
    STATE_PATH.write_bytes(pickle.dumps({
        "seed": bytes(bot.identity),
        "stonechat_id": bot.stonechat_id,
        "token": bot.token,
        "server": bot.server,
        "sessions": bot.sessions,
        "spk": bot.spk,
        "opks": bot.opks,
        "kspk": bot.kspk,
        "kopks": bot.kopks,
        "next_prekey_id": bot._next_prekey_id,
    }))


def load() -> Phone | None:
    if not STATE_PATH.exists():
        return None
    s = pickle.loads(STATE_PATH.read_bytes())
    bot = Phone(BOT_NAME)
    bot.identity = SigningKey(s["seed"])
    bot.pubkey_b64 = e2e.b64(bytes(bot.identity.verify_key))
    bot.derive_pq()  # the X-Wing identity is derived from the Ed25519 key
    bot.stonechat_id, bot.token, bot.server = s["stonechat_id"], s["token"], s["server"]
    bot.sessions, bot.spk, bot.opks = s["sessions"], s["spk"], s["opks"]
    bot.kspk, bot.kopks = s.get("kspk"), s.get("kopks", {})
    bot._next_prekey_id = s["next_prekey_id"]
    return bot


# -- provisioning --------------------------------------------------------------

def redeem(bot: Phone) -> None:
    code = os.environ.get("STONECHAT_TEST_CODE") or sys.exit(
        "fleet is plan-gated — set STONECHAT_TEST_CODE (the current tester codes "
        "live in the hub's systemd drop-in, STONECHAT_TEST_CODES)")
    r = httpx.post(f"{HUB}/v1/billing/redeem", headers=bot.auth,
                   json={"code": code})
    if r.status_code == 404:
        sys.exit(f"hub does not recognize code {code!r} — that's the "
                 "placeholder or a revoked code; use the current one from "
                 "the hub's drop-in")
    r.raise_for_status()
    print("entitlement:", r.json()["plan"], r.json()["status"])


def ensure_provisioned(bot: Phone) -> None:
    """Idempotent: registers/ignites whatever is still missing, so a failed
    first run (bad code, network blip) resumes instead of orphaning IDs."""
    srv = httpx.get(f"{HUB}/v1/server", headers=bot.auth).json()
    if srv["status"] == "error":
        sys.exit(f"relay is in error state: {srv.get('error')} — run "
                 "--destroy and start over")
    if srv["status"] == "none":
        r = httpx.post(f"{HUB}/v1/server", headers=bot.auth, json={
            "provider": "fleet",
            "machine": {"machine_type": "container", "region": "fleet1",
                        "disk_gb": 10},
        })
        if r.status_code == 402:
            redeem(bot)
            r = httpx.post(f"{HUB}/v1/server", headers=bot.auth, json={
                "provider": "fleet",
                "machine": {"machine_type": "container", "region": "fleet1",
                            "disk_gb": 10},
            })
        assert r.status_code == 202, (r.status_code, r.text)
        print("igniting fleet mailbox…")
    if srv["status"] == "running":
        bot.server = srv
    else:
        bot.wait_running()
    if bot.spk is None:  # first run (or crashed before prekeys landed)
        bot.publish_tls_sig()
        bot.upload_prekeys(opk_count=32)
    save(bot)


def top_up_opks(bot: Phone) -> None:
    st = MX.get(f"{bot.server['address']}/status",
                params={"token": bot.server["server_token"]}).json()
    if st["prekeys"]["opks"] < 8:
        bot.upload_prekeys(opk_count=16)
        save(bot)
        print("topped up one-time prekeys")


# -- the bot -------------------------------------------------------------------

def send(bot: Phone, peer: Peer, type_: str, payload: dict) -> None:
    bot.deliver_to(peer, bot.seal(peer, type_, payload))
    save(bot)


async def handle(bot: Phone, outer: dict) -> None:
    inner = bot.unseal(outer)
    sender, type_ = inner["from"], inner["type"]
    payload = bot.open_envelope(inner, None)

    if type_ == "contact_request":
        name = payload.get("display_name") or sender[:12]
        print(f"contact request from {name} ({sender}) — accepting")
        peer = resolve(sender)
        send(bot, peer, "contact_accept", {"display_name": BOT_NAME})
        await asyncio.sleep(1.0)
        send(bot, peer, "msg",
             {"text": f"Hi {name}! I'm {BOT_NAME}. Say anything and "
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
    url = (bot.server["address"].replace("http", "ws", 1)
           + f"/ws?token={bot.server['server_token']}")
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
        httpx.delete(f"{HUB}/v1/server",
                     headers=bot.auth, timeout=30).raise_for_status()
        STATE_PATH.unlink()
        print("mailbox destroyed, state removed")
        return

    bot = load()
    if bot is None:
        bot = Phone(BOT_NAME)
        print("registering fresh identity on", HUB)
        bot.register()
        save(bot)
    ensure_provisioned(bot)

    print(f"\n  {BOT_NAME}: {bot.stonechat_id}")
    print("  add this ID as a contact on your phone\n")

    if "--add" in sys.argv:
        target = sys.argv[sys.argv.index("--add") + 1]
        peer = resolve(target)
        send(bot, peer, "contact_request", {"display_name": BOT_NAME})
        print(f"sent contact request to {target} — accept it on the phone")

    try:
        asyncio.run(run(bot))
    except KeyboardInterrupt:
        print("\nbye — mailbox stays up; re-run to resume, --destroy to remove")


if __name__ == "__main__":
    main()
