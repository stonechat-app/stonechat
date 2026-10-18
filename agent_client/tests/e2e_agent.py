"""End-to-end proof that the agent client is a real device on a real identity.

Not a unit test of the Rust: a live run of the whole thing against a live hub
and two live mailboxes. The primary is simulated with `scripts/e2e.py`'s
`Phone` — the reference implementation the Dart client must interoperate with
— so what this really proves is that the Rust agent and the Python reference
agree on the wire, which is the only agreement that matters.

What it exercises, in order:

  1. `stonechat-agent link` parks an offer and prints a code;
  2. the primary fetches the offer, checks the commitment itself, mints an
     **agent** device, signs a 14-day certificate over the agent's own keys,
     seals a grant to those keys, parks it on the hub, and publishes a device
     manifest listing the new device;
  3. the agent collects it, makes its three checks, and publishes prekeys
     signed by a key its certificate names;
  4. a stranger runs PQXDH against *that device* and sends a message — and
     gets **no answer**, because the agent answers accepted contacts only;
  5. the primary sends `sync_history` (its contact list, as a shared blob on
     its own mailbox); the stranger is now a contact; the next message gets a
     canned sentence back, a delivered receipt, and the primary receives a
     `sync_sent` mirror of the answer;
  6. the primary renews the agent's certificate over `sync_cert`; the agent
     adopts it and republishes it with its prekeys;
  7. the contact publishes a device manifest that does not list the device
     he writes from; the agent drops his message. A manifest that does list
     it, and the agent answers again;
  8. the primary removes the contact over `sync_contact`; no more answers.

Step 5 is the point. A reply that decrypts means the ratchet advanced
identically on both sides, in two independent implementations, through a
handshake neither of them hardcoded — and the rest is the agent behaving as a
device the phone can live with.

No Docker: mailboxes run as plain binaries and are listed with the hub through
`/v1/mailbox/external` (the self-hosting path), which keeps this runnable on a
laptop.

    hub/.venv/bin/python agent_client/tests/e2e_agent.py

Requires the hub venv (hub/.venv), release builds of relay/ and agent_client/,
and `scripts/build_core.sh host` for the Python side's KEM.
"""

import asyncio
import base64
import gzip
import hashlib
import json
import os
import pathlib
import re
import secrets
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

HUB_PORT = 8479
HUB = f"http://127.0.0.1:{HUB_PORT}"
os.environ["STONECHAT_HUB"] = HUB
os.environ["STONECHAT_ADMIN_TOKEN"] = "test-admin"

import httpx  # noqa: E402
import pqcore  # noqa: E402
import e2e  # noqa: E402
from e2e import MX, Phone, b64, unb64  # noqa: E402
from nacl.utils import random as nacl_random  # noqa: E402

AGENT_BIN = ROOT / "agent_client" / "target" / "release" / "stonechat-agent"
RELAY_BIN = ROOT / "relay" / "target" / "release" / "stonechat-relay"
SENTENCES_RS = ROOT / "agent_client" / "src" / "replies.rs"

# The app's `agentCertLifetime`: what the phone actually signs for an agent.
AGENT_CERT_DAYS = 14

procs: list[subprocess.Popen] = []
tmpdirs: list[tempfile.TemporaryDirectory] = []


# -- plumbing -----------------------------------------------------------------

def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for(check, what: str, timeout=30):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            if check():
                return
        except Exception as exc:
            last = exc
        time.sleep(0.3)
    raise SystemExit(f"timed out waiting for {what} ({last!r})")


def cleanup():
    for p in procs:
        try:
            p.send_signal(signal.SIGTERM)
        except Exception:
            pass
    for p in procs:
        try:
            p.wait(timeout=5)
        except Exception:
            p.kill()


def start_hub():
    d = tempfile.TemporaryDirectory()
    tmpdirs.append(d)
    env = {
        **os.environ,
        "STONECHAT_DB": str(pathlib.Path(d.name) / "hub.db"),
        "STONECHAT_TEST_CODES": "STONECHAT-TEST-TEST",
    }
    # `python -m uvicorn`, not the console script: the venv's shebangs point at
    # a path that no longer exists (they were written on the control-plane box).
    procs.append(subprocess.Popen(
        [str(ROOT / "hub" / ".venv" / "bin" / "python"), "-m", "uvicorn",
         "app.main:app", "--port", str(HUB_PORT), "--log-level", "warning"],
        cwd=ROOT / "hub", env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    wait_for(lambda: httpx.get(f"{HUB}/health", timeout=2).status_code == 200,
             "the hub")


def start_relay(owner_id: str, owner_token: str) -> str:
    """A mailbox as a plain process. Returns its https:// address."""
    port = free_port()
    d = tempfile.TemporaryDirectory()
    tmpdirs.append(d)
    env = {
        **os.environ,
        "STONECHAT_OWNER_ID": owner_id,
        "STONECHAT_OWNER_TOKEN": owner_token,
        "STONECHAT_PORT": str(port),
        "STONECHAT_DB": str(pathlib.Path(d.name) / "mailbox.db"),
        "STONECHAT_BLOBS": str(pathlib.Path(d.name) / "blobs"),
        "STONECHAT_TLS_DIR": d.name,
        "STONECHAT_TURN_PORT": "0",
    }
    procs.append(subprocess.Popen(
        [str(RELAY_BIN)], env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    address = f"https://127.0.0.1:{port}"
    wait_for(lambda: MX.get(f"{address}/health", timeout=2).status_code == 200,
             f"a mailbox on {port}")
    return address


def give_mailbox(phone: Phone) -> str:
    """Register, stand a mailbox up, list it, publish prekeys. Returns its
    owner token (which is also device 1's device token)."""
    phone.register()
    token = secrets.token_hex(24)
    address = start_relay(phone.stonechat_id, token)
    httpx.post(f"{HUB}/v1/mailbox/external", headers=phone.auth,
               json={"address": address}, timeout=20).raise_for_status()
    phone.mailbox = {"address": address, "mailbox_token": token, "status": "running"}
    phone.publish_tls_sig()
    phone.upload_prekeys(opk_count=8)
    return token


def bundle_token(owner_token: str) -> str:
    """Mirrors the relay's derived list-devices capability."""
    return hashlib.blake2b(
        owner_token.encode() + b"|stonechat-bundle|", digest_size=32).hexdigest()


def agent_env(state: pathlib.Path) -> dict:
    return {**os.environ, "STONECHAT_AGENT_STATE": str(state)}


def peer_view(phone: Phone) -> SimpleNamespace:
    """`identity` as a *recipient*, for `Phone.seal(to=…)`.

    `_initiate_session` caches the recipient device's certificate on the
    `to` object. Sealing to the agent through the owner's own `Phone` would
    overwrite the owner's certificate with the agent's — and the owner's next
    handshake would then carry the wrong certificate. A view keeps the two
    apart, and lets the owner's Phone send to its own identity's other
    device, which is what self-sync is."""
    return SimpleNamespace(stonechat_id=phone.stonechat_id, pubkey_b64=phone.pubkey_b64,
                           mailbox=phone.mailbox, cert=None)


class AgentLog:
    """The agent's stdout, as it arrives, for waiting on specific lines."""

    def __init__(self, proc: subprocess.Popen):
        self.lines: list[str] = []
        self.lock = threading.Lock()
        threading.Thread(target=self._pump, args=(proc.stdout,), daemon=True).start()
        threading.Thread(target=self._pump, args=(proc.stderr,), daemon=True).start()

    def _pump(self, stream):
        for line in stream:
            with self.lock:
                self.lines.append(line.rstrip())
            print(f"       agent | {line.rstrip()}")

    def wait(self, needle: str, timeout=30, after=0) -> int:
        """Index of the first line after `after` containing `needle`."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self.lock:
                for i in range(after, len(self.lines)):
                    if needle in self.lines[i]:
                        return i
            time.sleep(0.1)
        raise SystemExit(f"the agent never logged {needle!r}")

    def text(self) -> str:
        with self.lock:
            return "\n".join(self.lines)

    def mark(self) -> int:
        with self.lock:
            return len(self.lines)


# -- the primary's side of linking --------------------------------------------

def authorise(alice: Phone, alice_token: str, code: str, kind: str) -> tuple[int, bytes]:
    """Exactly what the phone does when it scans (or pastes) a code. Returns
    the minted device id and the signing key the offer carried."""
    body = code.removeprefix("stonechat-link:")
    raw = base64.urlsafe_b64decode(body + "=" * ((4 - len(body) % 4) % 4))
    assert len(raw) == 65, f"a v2 offer is 65 bytes, got {len(raw)}"
    assert raw[0] == 2, f"expected offer version 2, got {raw[0]}"
    lookup, commitment = raw[1:33], raw[33:65]

    # Fetch the keys the commitment names and check them here. The hub checks
    # too — which is exactly why we do not take its word for it.
    offer = httpx.get(f"{HUB}/v1/link/offer/{commitment.hex()}", timeout=10)
    offer.raise_for_status()
    offer = offer.json()["offer"]
    seal, sig = unb64(offer["seal"]), unb64(offer["sig"])
    assert len(seal) == pqcore.XWING_PK, "offer seal key is the wrong size"
    recomputed = hashlib.blake2b(
        b"stonechat-link-offer" + seal + sig, digest_size=32).digest()
    assert recomputed == commitment, "offer keys do not match the commitment"

    # Mint the device. This is where the `agent` kind is exercised: a relay
    # that does not know it answers 400.
    dev_token = base64.urlsafe_b64encode(nacl_random(32)).decode().rstrip("=")
    minted = MX.post(f"{alice.mailbox['address']}/devices",
                     params={"token": alice_token},
                     json={"device_token": dev_token, "kind": kind})
    assert minted.status_code == 200, \
        f"minting a {kind!r} device failed: {minted.status_code} {minted.text[:200]}"
    minted = minted.json()
    assert minted["kind"] == kind, f"relay recorded kind {minted['kind']!r}"
    device_id = minted["device_id"]

    # Certify the agent's own keys with the identity root — the one thing only
    # the primary can do, and the only authority the agent will ever hold. For
    # the lifetime the phone really gives an agent, renewed over sync_cert.
    cert = alice.sign_cert_for(sig, seal, device=device_id,
                               not_after=int(time.time()) + AGENT_CERT_DAYS * 86400)
    tls_fp = httpx.get(f"{HUB}/v1/mailbox", headers=alice.auth).json()["tls_fp"]
    grant = json.dumps({
        "identity_pub": alice.pubkey_b64,
        "cert": cert,
        "stonechat_id": alice.stonechat_id,
        "display_name": alice.name,
        "hub_url": HUB,
        "relay_address": alice.mailbox["address"],
        "relay_tls_fp": tls_fp,
        "device_id": device_id,
        "device_token": dev_token,
        "bundle_token": bundle_token(alice_token),
    }).encode()

    # Sealed with the protocol's own hybrid seal — padded, like an envelope —
    # to the key just certified, so only the device the certificate names can
    # open it.
    kct, ss = pqcore.xwing_encaps(seal)
    key = e2e.H(ss, e2e.HSEAL_KDF_KEY, 32)
    nonce = nacl_random(24)
    sealed = kct + nonce + e2e.crypto_aead_xchacha20poly1305_ietf_encrypt(
        e2e.pad(grant), e2e.HSEAL_AD, nonce, key)
    parking_key = hashlib.blake2b(lookup, digest_size=32).hexdigest()
    httpx.post(f"{HUB}/v1/link",
               json={"key": parking_key, "sealed": b64(sealed)}).raise_for_status()
    return device_id, sig


def park_history(alice: Phone, contacts: list[dict]) -> dict:
    """The primary's export as `sync_history` carries it: the backup payload,
    gzip-compressed, encrypted like a media blob, parked on the primary's OWN
    mailbox as a shared blob. Returns the sync_history payload."""
    export = {
        "format": "stonechat-backup", "version": 1,
        "created_at": int(time.time() * 1000),
        "contacts": contacts, "blocked": [],
        "groups": [], "group_members": [], "messages": [], "reactions": [],
    }
    key, nonce = nacl_random(32), nacl_random(24)
    sealed = e2e.crypto_aead_xchacha20poly1305_ietf_encrypt(
        gzip.compress(json.dumps(export).encode()), b"", nonce, key)
    r = MX.post(f"{alice.mailbox['address']}/blob", params={"shared": "1"},
                content=sealed, timeout=30)
    r.raise_for_status()
    tls_fp = httpx.get(f"{HUB}/v1/mailbox", headers=alice.auth).json()["tls_fp"]
    return {
        "blob_id": r.json()["blob_id"], "key": b64(key), "blob_nonce": b64(nonce),
        "fetch_token": r.json()["fetch_token"],
        "blob_host": alice.mailbox["address"], "blob_tls_fp": tls_fp,
    }


# -- the contact's side ----------------------------------------------------------

async def talk_to_agent(bob: Phone, alice_view, device: int, alice_bundle_token: str,
                        text: str, expect_reply: bool = True) -> dict:
    """Send one message to the agent's device. With `expect_reply`, wait for
    its answer (acking whatever else arrives — the receipt comes first) and
    return the envelopes seen by type.

    The socket is opened *before* sending: the reply can land in under a
    second, and a receiver that connects afterwards races it.
    """
    import ssl
    import websockets

    ws_url = (bob.mailbox["address"].replace("https", "wss", 1)
              + f"/ws?token={bob.mailbox['mailbox_token']}")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    seen: dict[str, dict] = {}
    async with websockets.connect(ws_url, ssl=ctx) as ws:
        envelope = bob.seal(alice_view, "msg", {"text": text},
                            device=device, bundle_token=alice_bundle_token)
        bob.deliver_to(alice_view, envelope)
        seen["sent_id"] = envelope["id"]
        if not expect_reply:
            return seen
        deadline = time.time() + 60
        while "msg" not in seen and time.time() < deadline:
            raw = await asyncio.wait_for(ws.recv(), timeout=60)
            outer = json.loads(raw)
            inner = bob.unseal(outer)
            payload = bob.open_envelope(inner, None, wire=outer)
            await ws.send(json.dumps({"ack": outer["id"]}))
            seen[inner["type"]] = {"inner": inner, "payload": payload}
    assert "msg" in seen, "the agent never answered"
    return seen


def canned_sentences() -> list[str]:
    """Read them out of the Rust rather than duplicating them here: a copy
    would drift, and the assertion would stop meaning anything."""
    src = SENTENCES_RS.read_text()
    block = src.split("SENTENCES: &[&str] = &[", 1)[1].split("];", 1)[0]
    return re.findall(r'"((?:[^"\\]|\\.)*)"', block)


def agent_listed_cert(alice: Phone, alice_token: str, device_id: int) -> dict:
    """The certificate the agent's mailbox serves for it — what peers see."""
    listed = MX.get(f"{alice.mailbox['address']}/prekeys/devices",
                    params={"token": bundle_token(alice_token)}).json()["devices"]
    return next(d["cert"] for d in listed if d["device_id"] == device_id)


# -- the run ------------------------------------------------------------------

def main():
    for binary, how in [(AGENT_BIN, "cd agent_client && cargo build --release"),
                        (RELAY_BIN, "cd relay && cargo build --release")]:
        if not binary.exists():
            raise SystemExit(f"missing {binary}\n  build it: {how}")

    print("0) hub + two mailboxes (no Docker; plain binaries, listed as external)")
    start_hub()
    alice = Phone("alice (agent owner)")
    alice_token = give_mailbox(alice)
    bob = Phone("bob")
    give_mailbox(bob)
    alice_view = peer_view(alice)
    print(f"  ok   alice {alice.stonechat_id}")
    print(f"  ok   bob   {bob.stonechat_id}")

    state = pathlib.Path(tempfile.mkdtemp()) / "agent.json"
    tmpdirs.append(state.parent)

    print("\n1) stonechat-agent link — parks an offer, prints a code, polls")
    linking = subprocess.Popen(
        [str(AGENT_BIN), "link", "--hub", HUB], env=agent_env(state),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
    procs.append(linking)

    code = None
    deadline = time.time() + 30
    while time.time() < deadline and code is None:
        line = linking.stdout.readline()
        if not line:
            break
        m = re.search(r"(stonechat-link:[A-Za-z0-9_-]+)", line)
        if m:
            code = m.group(1)
    if code is None:
        linking.kill()
        raise SystemExit("the agent never printed a link code:\n"
                         + linking.stderr.read())
    print(f"  ok   {code}")
    # Exactly 102: scheme + base64url of (version ‖ lookup32 ‖ commitment32),
    # unpadded. Pinned rather than bounded because the number is the whole
    # point of the 2026-08-04 commitment change — it is what makes the code
    # pasteable over SSH and small enough to render as a QR in a terminal.
    assert len(code) == 102, f"expected a 102-char code, got {len(code)}"

    print("\n2) the primary authorises it as an `agent` device and lists it in its manifest")
    device_id, agent_sig_pub = authorise(alice, alice_token, code, kind="agent")
    manifest = alice.publish_devices({1: bytes(alice.dev_sig.verify_key),
                                      device_id: agent_sig_pub})
    print(f"  ok   minted + certified device {device_id}; manifest version {manifest['version']}")

    linking.wait(timeout=60)
    if linking.returncode != 0:
        raise SystemExit(f"link failed ({linking.returncode}):\n"
                         f"{linking.stdout.read()}\n{linking.stderr.read()}")
    print("  ok   agent collected the grant, made its checks, published prekeys")

    # It must have refused to keep an identity secret it was never given, and
    # the state file must not be world-readable.
    saved = json.loads(state.read_text())
    assert "identity_seed" not in json.dumps(saved), \
        "no identity secret may appear in agent state"
    assert saved["device_id"] == device_id
    assert oct(state.stat().st_mode)[-3:] == "600", "state file must be 0600"
    assert saved["contacts"] == {}, "a freshly linked agent knows nobody"
    print("  ok   state holds no identity secret, mode 0600, no contacts yet")

    print("\n3) linking twice is refused")
    again = subprocess.run([str(AGENT_BIN), "link", "--hub", HUB],
                           env=agent_env(state), capture_output=True, text=True,
                           timeout=30)
    assert again.returncode != 0, "a second link should refuse, not re-link"
    assert "already linked" in again.stderr, again.stderr
    print("  ok   refused with a sentence")

    print("\n4) stonechat-agent run")
    running = subprocess.Popen(
        [str(AGENT_BIN), "run"], env=agent_env(state),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
    procs.append(running)
    log = AgentLog(running)
    log.wait("connected", timeout=30)
    print("  ok   holding its receive socket")

    print("\n5) a stranger starts a session with that device and says hello — no answer")
    mark = log.mark()
    asyncio.run(talk_to_agent(bob, alice_view, device_id, bundle_token(alice_token),
                              "hello from the e2e test", expect_reply=False))
    log.wait("not an accepted contact, not answering", after=mark)
    time.sleep(1.0)
    assert bob.queue_depth() == 0, "a stranger must get nothing back, not even a receipt"
    assert "hello from the e2e test" not in log.text(), \
        "message text must stay out of the log without --show-text"
    print("  ok   decrypted (the ratchet is current), answered nobody, logged no text")

    print("\n6) the primary sends its contact list over sync_history; bob is a contact now")
    history = park_history(alice, [{
        "stonechat_id": bob.stonechat_id, "pubkey": bob.pubkey_b64,
        "status": "accepted", "display_name": "Bob",
    }])
    mark = log.mark()
    alice.deliver_to(alice_view, alice.seal(
        alice_view, "sync_history", history,
        device=device_id, bundle_token=bundle_token(alice_token)))
    log.wait("bootstrapped from our primary: 1 contacts", after=mark)
    print("  ok   fetched from its own mailbox, opened, merged")

    print("\n7) the contact says hello again — answered, receipted, mirrored to the phone")
    seen = asyncio.run(talk_to_agent(bob, alice_view, device_id, bundle_token(alice_token),
                                     "hello again, now as a contact"))
    answer = seen["msg"]["payload"]["text"]
    print(f"  agent replied: {answer!r}")
    assert answer in canned_sentences(), \
        f"reply {answer!r} is not one of the canned sentences"
    assert seen["msg"]["inner"]["manifest_v"] == manifest["version"], \
        "the agent's envelopes must state its identity's manifest version"
    assert "receipt" in seen, "a message from a contact gets a delivered receipt"
    assert seen["receipt"]["payload"] == {"kind": "delivered", "ids": [seen["sent_id"]]}, \
        seen["receipt"]["payload"]
    print("  ok   PQXDH + ratchet round trip between Rust and the reference, with a receipt")

    mirrored = {}

    def take_sync_sent(envelope):
        inner = alice.unseal(envelope)
        mirrored["inner"] = inner
        mirrored["payload"] = alice.open_envelope(inner, None, wire=envelope)

    asyncio.run(alice.receive_one(timeout=30, process=take_sync_sent))
    assert mirrored["inner"]["type"] == "sync_sent", \
        f"the phone should receive a sync_sent, got {mirrored['inner']['type']}"
    assert mirrored["inner"]["from_device"] == device_id
    assert mirrored["payload"]["peer"] == bob.stonechat_id
    assert mirrored["payload"]["payload"]["text"] == answer
    assert mirrored["payload"]["id"] == seen["msg"]["inner"]["id"], \
        "the mirror names the same message id the contact received"
    print("  ok   the phone received a sync_sent naming the same message")

    print("\n8) a second message reuses the established session")
    seen2 = asyncio.run(talk_to_agent(bob, alice_view, device_id, bundle_token(alice_token),
                                      "and again"))
    assert seen2["msg"]["payload"]["text"] in canned_sentences()
    assert "x3dh" not in seen2["msg"]["inner"], "a confirmed session carries no handshake"
    asyncio.run(alice.receive_one(timeout=30))  # the mirror of that one
    print("  ok   the ratchet kept turning")

    print("\n9) the primary renews the certificate over sync_cert")
    held = agent_listed_cert(alice, alice_token, device_id)
    renewed = alice.sign_cert_for(agent_sig_pub, unb64(held["seal_pub"]), device=device_id,
                                  not_after=held["not_after"] + 3600)
    mark = log.mark()
    alice.deliver_to(alice_view, alice.seal(
        alice_view, "sync_cert", {"cert": renewed},
        device=device_id, bundle_token=bundle_token(alice_token)))
    log.wait("certificate renewed by the phone", after=mark)
    wait_for(lambda: agent_listed_cert(alice, alice_token, device_id)["not_after"]
             == renewed["not_after"], "the renewed certificate to be republished")
    assert json.loads(state.read_text())["cert"]["not_after"] == renewed["not_after"]
    # One for somebody else's keys must not be adopted.
    forged = alice.sign_cert_for(bytes(bob.dev_sig.verify_key), bob.dev_seal_pk,
                                 device=device_id, not_after=renewed["not_after"] + 3600)
    mark = log.mark()
    alice.deliver_to(alice_view, alice.seal(
        alice_view, "sync_cert", {"cert": forged},
        device=device_id, bundle_token=bundle_token(alice_token)))
    log.wait("names other keys", after=mark)
    assert agent_listed_cert(alice, alice_token, device_id)["not_after"] == renewed["not_after"]
    print("  ok   adopted and republished; a certificate over other keys refused")

    print("\n10) the contact's device manifest decides whether his device is heard")
    # A manifest that lists device 1 under some other key: as if Bob had
    # re-keyed and the relay kept serving the old certificate.
    bob.publish_devices({1: nacl_random(32)})
    mark = log.mark()
    asyncio.run(talk_to_agent(bob, alice_view, device_id, bundle_token(alice_token),
                              "from a device the manifest does not list", expect_reply=False))
    log.wait("is not in their device manifest", after=mark)
    time.sleep(1.0)
    assert bob.queue_depth() == 0, "an unlisted device must get nothing back"
    # And the manifest that does list it, under the key his certificate carries.
    bob.publish_devices({1: bytes(bob.dev_sig.verify_key)})
    seen3 = asyncio.run(talk_to_agent(bob, alice_view, device_id, bundle_token(alice_token),
                                      "listed again"))
    assert seen3["msg"]["payload"]["text"] in canned_sentences()
    asyncio.run(alice.receive_one(timeout=30))
    print("  ok   dropped while unlisted, answered once listed")

    print("\n11) the primary removes the contact over sync_contact — no more answers")
    mark = log.mark()
    alice.deliver_to(alice_view, alice.seal(
        alice_view, "sync_contact", {"peer": bob.stonechat_id, "pubkey": bob.pubkey_b64,
                                     "status": "removed"},
        device=device_id, bundle_token=bundle_token(alice_token)))
    log.wait("removed from contacts", after=mark)
    # Removing a contact removes its sessions too (PROTOCOL.md "Self-sync"),
    # so a message on the old session no longer decrypts…
    mark = log.mark()
    asyncio.run(talk_to_agent(bob, alice_view, device_id, bundle_token(alice_token),
                              "anyone there?", expect_reply=False))
    log.wait("no session with", after=mark)
    # …and a fresh handshake gets through to a device that now treats him as
    # the stranger he is again.
    del bob.sessions[(alice.stonechat_id, device_id)]
    mark = log.mark()
    asyncio.run(talk_to_agent(bob, alice_view, device_id, bundle_token(alice_token),
                              "anyone there at all?", expect_reply=False))
    log.wait("not an accepted contact, not answering", after=mark)
    time.sleep(1.0)
    assert bob.queue_depth() == 0
    print("  ok   silence")

    print("\n12) stonechat-agent status")
    status = subprocess.run([str(AGENT_BIN), "status"], env=agent_env(state),
                            capture_output=True, text=True, timeout=30)
    assert status.returncode == 0, status.stderr
    assert f"version {manifest['version']}" in status.stdout, status.stdout
    assert "0 accepted" in status.stdout, status.stdout
    print("  ok   reports the manifest version and the contact count")

    print("\nPASS")


if __name__ == "__main__":
    try:
        main()
    finally:
        cleanup()
