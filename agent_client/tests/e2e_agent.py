"""End-to-end proof that the agent client is a real device on a real identity.

Not a unit test of the Rust: a live run of the whole thing against a live hub
and two live mailboxes. The primary is simulated with `scripts/e2e.py`'s
`Phone` — the reference implementation the Dart client must interoperate with
— so what this really proves is that the Rust agent and the Python reference
agree on the wire, which is the only agreement that matters.

What it exercises, in order:

  1. `stonechat-agent link` parks an offer and prints a code;
  2. the primary fetches the offer, checks the commitment itself, mints an
     **agent** device, signs a certificate over the agent's own keys, seals a
     grant to those keys and parks it on the hub;
  3. the agent collects it, makes its three checks, and publishes prekeys
     signed by a key its certificate names;
  4. a stranger runs PQXDH against *that device* and sends a message;
  5. the agent decrypts it and answers with one of its canned sentences, which
     the stranger decrypts on the session it initiated.

Step 5 is the point. A reply that decrypts means the ratchet advanced
identically on both sides, in two independent implementations, through a
handshake neither of them hardcoded.

No Docker: mailboxes run as plain binaries and are listed with the hub through
`/v1/server/external` (the self-hosting path), which keeps this runnable on a
laptop.

    python3 agent_client/tests/e2e_agent.py

Requires the hub venv (hub/.venv), release builds of relay/ and agent_client/,
and `scripts/build_core.sh host` for the Python side's KEM.
"""

import asyncio
import base64
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
import time

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
    httpx.post(f"{HUB}/v1/server/external", headers=phone.auth,
               json={"address": address}, timeout=20).raise_for_status()
    phone.server = {"address": address, "server_token": token, "status": "running"}
    phone.publish_tls_sig()
    phone.upload_prekeys(opk_count=8)
    return token


def bundle_token(owner_token: str) -> str:
    """Mirrors the relay's derived list-devices capability."""
    return hashlib.blake2b(
        owner_token.encode() + b"|stonechat-bundle|", digest_size=32).hexdigest()


def agent_env(state: pathlib.Path) -> dict:
    return {**os.environ, "STONECHAT_AGENT_STATE": str(state)}


# -- the primary's side of linking --------------------------------------------

def authorise(alice: Phone, alice_token: str, code: str, kind: str) -> int:
    """Exactly what the phone does when it scans (or pastes) a code."""
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

    # Mint the device. This is where the new `agent` kind is exercised: a relay
    # that does not know it answers 400.
    dev_token = base64.urlsafe_b64encode(nacl_random(32)).decode().rstrip("=")
    minted = MX.post(f"{alice.server['address']}/devices",
                     params={"token": alice_token},
                     json={"device_token": dev_token, "kind": kind})
    assert minted.status_code == 200, \
        f"minting a {kind!r} device failed: {minted.status_code} {minted.text[:200]}"
    minted = minted.json()
    assert minted["kind"] == kind, f"relay recorded kind {minted['kind']!r}"
    device_id = minted["device_id"]

    # Certify the agent's own keys with the identity root — the one thing only
    # the primary can do, and the only authority the agent will ever hold.
    cert = alice.sign_cert_for(sig, seal, device=device_id,
                               not_after=int(time.time()) + 180 * 86400)
    tls_fp = httpx.get(f"{HUB}/v1/server", headers=alice.auth).json()["tls_fp"]
    grant = json.dumps({
        "identity_pub": alice.pubkey_b64,
        "cert": cert,
        "stonechat_id": alice.stonechat_id,
        "display_name": alice.name,
        "hub_url": HUB,
        "relay_address": alice.server["address"],
        "relay_tls_fp": tls_fp,
        "device_id": device_id,
        "device_token": dev_token,
        "bundle_token": bundle_token(alice_token),
    }).encode()

    # Sealed with the protocol's own hybrid seal, to the key just certified —
    # so only the device the certificate names can open it.
    kct, ss = pqcore.xwing_encaps(seal)
    key = e2e.H(ss, e2e.HSEAL_KDF_KEY, 32)
    nonce = nacl_random(24)
    sealed = kct + nonce + e2e.crypto_aead_xchacha20poly1305_ietf_encrypt(
        grant, e2e.HSEAL_AD, nonce, key)
    parking_key = hashlib.blake2b(lookup, digest_size=32).hexdigest()
    httpx.post(f"{HUB}/v1/link",
               json={"key": parking_key, "sealed": b64(sealed)}).raise_for_status()
    return device_id


# -- the stranger's side ------------------------------------------------------

async def talk_to_agent(bob: Phone, alice: Phone, device: int,
                        alice_bundle_token: str, text: str) -> str:
    """Send one message to the agent's device and wait for its answer.

    The socket is opened *before* sending: the reply can land in under a
    second, and a receiver that connects afterwards races it.
    """
    import ssl
    import websockets

    ws_url = (bob.server["address"].replace("https", "wss", 1)
              + f"/ws?token={bob.server['server_token']}")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    async with websockets.connect(ws_url, ssl=ctx) as ws:
        envelope = bob.seal(alice, "msg", {"text": text},
                            device=device, bundle_token=alice_bundle_token)
        bob.deliver_to(alice, envelope)
        raw = await asyncio.wait_for(ws.recv(), timeout=60)
        outer = json.loads(raw)
        payload = bob.open_envelope(outer, None)
        await ws.send(json.dumps({"ack": outer["id"]}))
        return payload.get("text", "")


def canned_sentences() -> list[str]:
    """Read them out of the Rust rather than duplicating them here: a copy
    would drift, and the assertion would stop meaning anything."""
    src = SENTENCES_RS.read_text()
    block = src.split("SENTENCES: &[&str] = &[", 1)[1].split("];", 1)[0]
    return re.findall(r'"((?:[^"\\]|\\.)*)"', block)


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

    print("\n2) the primary authorises it as an `agent` device")
    device_id = authorise(alice, alice_token, code, kind="agent")
    print(f"  ok   minted + certified device {device_id}")

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
    print("  ok   state holds no identity secret, mode 0600")

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
    deadline = time.time() + 30
    connected = False
    while time.time() < deadline:
        line = running.stdout.readline()
        if not line:
            break
        print(f"       agent | {line.rstrip()}")
        if "connected" in line:
            connected = True
            break
    if not connected:
        running.kill()
        raise SystemExit("the agent never reported a connection:\n"
                         + running.stderr.read())
    print("  ok   holding its receive socket")

    print("\n5) a stranger starts a session with that device and says hello")
    answer = asyncio.run(talk_to_agent(
        bob, alice, device_id, bundle_token(alice_token),
        "hello from the e2e test"))
    print(f"  agent replied: {answer!r}")
    assert answer in canned_sentences(), \
        f"reply {answer!r} is not one of the canned sentences"
    print("  ok   PQXDH + ratchet round trip between Rust and the reference")

    print("\n6) a second message reuses the established session")
    answer2 = asyncio.run(talk_to_agent(
        bob, alice, device_id, bundle_token(alice_token), "and again"))
    assert answer2 in canned_sentences(), f"second reply {answer2!r} is not canned"
    print(f"  agent replied: {answer2!r}")
    print("  ok   the ratchet kept turning")

    print("\nPASS")


if __name__ == "__main__":
    try:
        main()
    finally:
        cleanup()
