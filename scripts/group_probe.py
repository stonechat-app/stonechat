"""Group probe: a misbehaving group member, for testing what the app does about one.

The app never breaks the group rules itself, so the checks that catch a
member who does (PROTOCOL.md "Groups", "Keeping the roster in step",
"Transcript consistency") cannot be exercised from the app alone. This is a
headless identity, like the echo bot, that breaks them on request — one
command per case, each saying what the phone should then show.

It is its own identity with its own mailbox and state file, built on the
echo bot's plumbing (scripts/echo_bot.py) and the protocol client in
scripts/e2e.py.

Usage (first run provisions, exactly as the echo bot does):

    STONECHAT_TEST_CODE=STONECHAT-XXXX-XXXX python3 scripts/group_probe.py listen

    group_probe.py listen                      # accept contact requests, record groups
    group_probe.py befriend SC-YOU             # send YOU a contact request, then listen

  Rosters the app must refuse (nothing should appear on the phone):

    group_probe.py stranger-invite SC-YOU      # run BEFORE befriending
    group_probe.py oversize SC-YOU             # a roster of 101; needs befriending
    group_probe.py contact-id SC-YOU SC-FRIEND # a "group" named after a contact

  Rosters that differ between members (the probe is the admin):

    group_probe.py split-roster SC-YOU SC-B SC-HIDDEN
    group_probe.py withhold-update SC-YOU SC-B SC-NEW

  Messages that differ between members (the probe is a member — add it to a
  group from the phone while it listens, and note the group id it prints):

    group_probe.py split-message GROUP_ID --to SC-YOU "text for you" "text for the rest"
    group_probe.py false-witness GROUP_ID

    group_probe.py groups                      # what it is in, and the ids
    group_probe.py --destroy                   # tear down mailbox + state

Every command drains what was queued while the probe was offline, acts, and
then keeps listening until Ctrl-C — so never run two at once: they would
share one identity's ratchets.

Env: as echo_bot.py, with STONECHAT_BOT_STATE defaulting to
~/.stonechat_group_probe.pkl and STONECHAT_BOT_NAME to "mallory (probe)".
"""

import argparse
import asyncio
import json
import os
import pathlib
import sys
import uuid

os.environ.setdefault(
    "STONECHAT_BOT_STATE", str(pathlib.Path.home() / ".stonechat_group_probe.pkl"))
os.environ.setdefault("STONECHAT_BOT_NAME", "mallory (probe)")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import websockets  # noqa: E402
from nacl.signing import SigningKey  # noqa: E402

import e2e  # noqa: E402
import echo_bot  # noqa: E402
from e2e import WS_SSL, Phone  # noqa: E402
from echo_bot import resolve, save, send  # noqa: E402
from app.identity import stonechat_id_from_pubkey  # noqa: E402 (path set by e2e)

# What a receiver tolerates (PROTOCOL.md "Groups").
ROSTER_MAX = echo_bot.GROUP_ROSTER_MAX


# -- rosters -------------------------------------------------------------------

def entry(stonechat_id: str, pubkey_b64: str, name: str) -> dict:
    return {"stonechat_id": stonechat_id, "pubkey": pubkey_b64, "display_name": name}


def own_entry(bot: Phone) -> dict:
    return entry(bot.stonechat_id, bot.pubkey_b64, bot.name)


def entry_for(stonechat_id: str) -> dict:
    """A real member: the key comes from the directory, which is what makes
    the roster pass the receiver's key check."""
    peer = resolve(stonechat_id)
    return entry(peer.stonechat_id, peer.pubkey_b64, peer.stonechat_id[3:12])


def roster(group_id: str, name: str, version: int, admin: str,
           members: list[dict]) -> dict:
    return {"group_id": group_id, "name": name, "version": version,
            "admin": admin, "members": members}


def remember(bot: Phone, payload: dict) -> None:
    """Hold a roster we issued, so `listen` can answer a group_sync for it
    and the message commands can speak in the group."""
    ids = {m["stonechat_id"]: m["display_name"] for m in payload["members"]}
    bot.groups[payload["group_id"]] = {
        "name": payload["name"], "admin": payload["admin"],
        "version": payload["version"], "members": ids,
        "hash": e2e.roster_hash(payload["group_id"], payload["version"],
                                payload["admin"], ids),
        # Kept verbatim: what a member who asks is sent.
        "roster": payload,
    }
    save(bot)


def deliver(bot: Phone, stonechat_id: str, type_: str, payload: dict,
            envelope_id: str | None = None) -> bool:
    try:
        send(bot, resolve(stonechat_id), type_, payload, envelope_id=envelope_id)
        return True
    except Exception as exc:
        print(f"  ! could not reach {stonechat_id[:16]}…: {exc!r}")
        return False


def group_message(bot: Phone, group_id: str, text: str, **extra) -> dict:
    """A group_msg as the app sends it: our roster view and a salt included."""
    group = bot.groups[group_id]
    return {
        "group_id": group_id, "text": text,
        "roster": {"v": group["version"], "admin": group["admin"],
                   **({"h": group["hash"]} if group.get("hash") else {})},
        "salt": e2e.b64(os.urandom(16)),
        **extra,
    }


def others(bot: Phone, group_id: str) -> list[str]:
    return [m for m in bot.groups[group_id]["members"] if m != bot.stonechat_id]


# -- the cases -----------------------------------------------------------------

def stranger_invite(bot: Phone, args) -> None:
    payload = roster(str(uuid.uuid4()), "from a stranger", 1, bot.stonechat_id,
                     [own_entry(bot), entry_for(args.target)])
    if deliver(bot, args.target, "group_create", payload):
        print("sent a group invitation from a non-contact.\n"
              "  EXPECT: no group appears on the phone. (If the probe is "
              "already a contact there, it will appear — that is the control.)")


def oversize(bot: Phone, args) -> None:
    # Real keys for every filler member, so the size is the only thing wrong.
    fillers = []
    for i in range(ROSTER_MAX - 1):  # + us + the target = ROSTER_MAX + 1
        key = bytes(SigningKey.generate().verify_key)
        fillers.append(entry(stonechat_id_from_pubkey(key), e2e.b64(key), f"filler {i}"))
    payload = roster(str(uuid.uuid4()), "too many people", 1, bot.stonechat_id,
                     [own_entry(bot), entry_for(args.target), *fillers])
    if deliver(bot, args.target, "group_create", payload):
        print(f"sent a roster of {len(payload['members'])} members.\n"
              "  EXPECT: no group appears on the phone.")


def contact_id(bot: Phone, args) -> None:
    payload = roster(args.victim, "not a group id", 1, bot.stonechat_id,
                     [own_entry(bot), entry_for(args.target)])
    if deliver(bot, args.target, "group_create", payload):
        print(f"sent a roster whose group id is the contact {args.victim[:16]}….\n"
              "  EXPECT: no group appears, and the chat with that contact is "
              "unchanged — what is typed there still goes only to them.")


def split_roster(bot: Phone, args) -> None:
    group_id = str(uuid.uuid4())
    me, a, b, hidden = (own_entry(bot), entry_for(args.target),
                        entry_for(args.other), entry_for(args.hidden))
    narrow = roster(group_id, "split roster", 1, bot.stonechat_id, [me, a, b])
    wide = roster(group_id, "split roster", 1, bot.stonechat_id, [me, a, b, hidden])
    deliver(bot, args.target, "group_create", narrow)
    deliver(bot, args.other, "group_create", wide)
    deliver(bot, args.hidden, "group_create", wide)
    remember(bot, wide)
    print(f"group {group_id}: version 1 issued twice.\n"
          f"  {args.target[:16]}… was told 3 members; the other two were told 4.\n"
          "  EXPECT: when one of the other two writes in the group (an echo "
          "bot greets it on joining), the phone shows a notice that member "
          "lists differ. The hidden member's own messages are dropped there: "
          "the phone has no roster that lists them.")


def withhold_update(bot: Phone, args) -> None:
    group_id = str(uuid.uuid4())
    me, a, b, new = (own_entry(bot), entry_for(args.target),
                     entry_for(args.other), entry_for(args.new))
    v1 = roster(group_id, "withheld update", 1, bot.stonechat_id, [me, a, b])
    v2 = roster(group_id, "withheld update", 2, bot.stonechat_id, [me, a, b, new])
    deliver(bot, args.target, "group_create", v1)
    deliver(bot, args.other, "group_create", v1)
    deliver(bot, args.other, "group_update", v2)
    deliver(bot, args.new, "group_create", v2)
    remember(bot, v2)
    print(f"group {group_id}: version 2 adds {args.new[:16]}…, and "
          f"{args.target[:16]}… was not told.\n"
          "  EXPECT: when the new member writes (an echo bot greets the group "
          "on joining), the phone holds that message back, asks this probe "
          "for the roster — a line below says so — and then shows the new "
          "member as added, followed by the message it held.\n"
          "  Keep this running: the probe has to answer.")


def split_message(bot: Phone, args) -> None:
    if args.group not in bot.groups:
        sys.exit(f"not in group {args.group} — run `groups` to list them")
    members = others(bot, args.group)
    if args.to not in members:
        sys.exit(f"{args.to} is not in that group")
    message_id = str(uuid.uuid4())
    for member in members:
        text = args.text_one if member == args.to else args.text_two
        deliver(bot, member, "group_msg",
                group_message(bot, args.group, text), envelope_id=message_id)
    print(f"sent message {message_id} with two different texts.\n"
          "  EXPECT: nothing yet. When a member who got the other text next "
          "writes in the group FROM THE APP, the phone shows a notice that "
          "they received a different version of a message from this probe.\n"
          "  The echo bots do not report what they received, so this one "
          "needs a second app install in the group; `false-witness` covers "
          "the same check with a bot.")


def false_witness(bot: Phone, args) -> None:
    group = bot.groups.get(args.group) or sys.exit(
        f"not in group {args.group} — run `groups` to list them")
    last = group.get("last")
    if last is None:
        sys.exit("no message from another member seen in that group yet — "
                 "have someone other than the phone write there while the "
                 "probe listens, then run this again")
    payload = group_message(
        bot, args.group, "I read that differently.",
        # A hash that cannot be the right one for that message.
        seen=[{"id": last["id"], "h": e2e.b64(os.urandom(32))}])
    message_id = str(uuid.uuid4())
    for member in others(bot, args.group):
        deliver(bot, member, "group_msg", payload, envelope_id=message_id)
    print(f"vouched for message {last['id']} from {last['from'][:16]}… with "
          "a wrong hash.\n"
          "  EXPECT: the phone shows a notice that this probe received a "
          "different version of a message from that member — provided the "
          "phone holds the message and it carried a salt (the app's and the "
          "echo bots' do).")


# -- listening -----------------------------------------------------------------

async def handle(bot: Phone, outer: dict) -> None:
    inner = bot.unseal(outer)
    payload = bot.open_envelope(inner, None, wire=outer)
    sender, type_ = inner["from"], inner["type"]
    if inner.get("bundle_token"):
        bot.bundle_tokens[sender] = inner["bundle_token"]

    if type_ == "contact_request":
        print(f"contact request from {payload.get('display_name') or sender} "
              f"({sender}) — accepting")
        send(bot, resolve(sender), "contact_accept", {"display_name": bot.name})
    elif type_ == "contact_accept":
        print(f"{sender} accepted our request")
    elif type_ in ("group_create", "group_update"):
        # Someone else's group: believed as sent. The probe is the one who
        # lies here, not the one being lied to.
        if payload.get("admin") != bot.stonechat_id:
            ids = {m["stonechat_id"]: m.get("display_name", "")
                   for m in payload.get("members", [])}
            if bot.stonechat_id in ids:
                version = payload.get("version", 0)
                bot.groups[payload["group_id"]] = {
                    "name": payload.get("name", ""), "admin": payload["admin"],
                    "version": version, "members": ids,
                    "hash": e2e.roster_hash(payload["group_id"], version,
                                            payload["admin"], ids),
                    "last": (bot.groups.get(payload["group_id"]) or {}).get("last"),
                }
                print(f"in group {payload.get('name')!r}: {payload['group_id']} "
                      f"(version {version}, {len(ids)} members)")
            else:
                bot.groups.pop(payload["group_id"], None)
                print(f"removed from group {payload.get('name')!r}")
    elif type_ == "group_sync":
        group = bot.groups.get(payload.get("group_id"))
        held = payload.get("version", 0)
        if group and group.get("roster") and sender in group["members"] \
                and held < group["version"]:
            print(f"{sender[:16]}… holds version {held} and asked for the "
                  f"roster — sending version {group['version']}")
            send(bot, resolve(sender), "group_update", group["roster"])
        else:
            print(f"group_sync from {sender[:16]}… — nothing to send")
    elif type_ in ("group_msg", "group_media"):
        group = bot.groups.get(payload.get("group_id"))
        if group is not None:
            group["last"] = {"id": inner["id"], "from": sender}
            print(f"[{group['name']}] {sender[:16]}…: "
                  f"{payload.get('text', '<media>')!r}  roster={payload.get('roster')}")
    elif type_ == "msg":
        print(f"{sender[:16]}…: {payload.get('text')!r}")
    else:
        print(f"ignoring {type_} from {sender[:16]}…")


async def run(bot: Phone, action) -> None:
    """Drain the queue, run `action` once it has gone quiet, keep listening."""
    url = (bot.mailbox["address"].replace("http", "ws", 1)
           + f"/ws?token={bot.mailbox['mailbox_token']}")
    acted = action is None
    while True:
        try:
            async with websockets.connect(url, ssl=WS_SSL, ping_interval=20) as ws:
                echo_bot.top_up_opks(bot)
                while True:
                    try:
                        raw = await asyncio.wait_for(ws.recv(), None if acted else 2.0)
                    except asyncio.TimeoutError:
                        acted = True
                        action()
                        print("\nlistening (Ctrl-C to stop)")
                        continue
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


# -- entry point ---------------------------------------------------------------

def parse(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="A misbehaving group member, for testing the app's group checks.")
    parser.add_argument("--destroy", action="store_true",
                        help="tear down the probe's mailbox and state")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("listen")
    sub.add_parser("groups")
    for name in ("befriend", "stranger-invite", "oversize"):
        sub.add_parser(name).add_argument("target")
    p = sub.add_parser("contact-id")
    p.add_argument("target")
    p.add_argument("victim", help="a contact of the target's, whose ID becomes the group id")
    p = sub.add_parser("split-roster")
    p.add_argument("target")
    p.add_argument("other")
    p.add_argument("hidden")
    p = sub.add_parser("withhold-update")
    p.add_argument("target")
    p.add_argument("other")
    p.add_argument("new")
    p = sub.add_parser("split-message")
    p.add_argument("group")
    p.add_argument("--to", required=True, help="who gets the first text")
    p.add_argument("text_one")
    p.add_argument("text_two")
    sub.add_parser("false-witness").add_argument("group")
    return parser.parse_args(argv)


ACTIONS = {
    "stranger-invite": stranger_invite,
    "oversize": oversize,
    "contact-id": contact_id,
    "split-roster": split_roster,
    "withhold-update": withhold_update,
    "split-message": split_message,
    "false-witness": false_witness,
}


def main() -> None:
    args = parse(sys.argv[1:])
    if args.destroy:
        sys.argv = [sys.argv[0], "--destroy"]
        return echo_bot.main()

    bot = echo_bot.load()
    if bot is None:
        bot = Phone(echo_bot.BOT_NAME)
        bot.peer_certs, bot.bundle_tokens, bot.groups = {}, {}, {}
        print("registering fresh identity on", e2e.HUB)
        bot.register()
        save(bot)
    echo_bot.ensure_provisioned(bot)
    print(f"\n  {bot.name}: {bot.stonechat_id}\n")

    if args.command == "groups":
        for group_id, group in bot.groups.items():
            role = "admin" if group["admin"] == bot.stonechat_id else "member"
            print(f"  {group_id}  {group['name']!r}  v{group['version']}  "
                  f"{len(group['members'])} members  ({role})")
        return

    action = None
    if args.command == "befriend":
        def action():
            if deliver(bot, args.target, "contact_request", {"display_name": bot.name}):
                print(f"sent a contact request to {args.target} — accept it on the phone")
    elif args.command in ACTIONS:
        def action():
            ACTIONS[args.command](bot, args)
    try:
        asyncio.run(run(bot, action))
    except KeyboardInterrupt:
        print("\nbye — mailbox stays up; --destroy to remove")


if __name__ == "__main__":
    main()
