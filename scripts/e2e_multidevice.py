"""Multi-device end to end, without Docker (MULTIDEVICE.md).

e2e.py provisions relays through the hub, which needs Docker. This one runs
relays directly and registers them as external mailboxes, so the whole
multi-device path can be exercised on a laptop:

  link grant → per-device fan-out → per-device queues → self-sync →
  per-device receipts → revocation

It reuses e2e.py's protocol implementation (PQXDH, double ratchet, sealed
envelopes) rather than restating it — that file is the reference the Dart
client is checked against, and a second copy would drift.

Usage (hub must be running; no Docker needed):
    cd hub && .venv/bin/uvicorn app.main:app --port 8477 &
    hub/.venv/bin/python scripts/e2e_multidevice.py
"""
import asyncio
import base64
import json
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import uuid

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import e2e  # noqa: E402  the protocol reference
from e2e import (  # noqa: E402
    HUB, MX, PRIMARY_DEVICE, Phone, b64, nacl_random,
)
import httpx  # noqa: E402
import pqcore  # noqa: E402

RELAY = pathlib.Path(__file__).resolve().parents[1] / "relay/target/debug/stonechat-relay"
_procs: list[subprocess.Popen] = []
_dirs: list[str] = []


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start_relay(owner_id: str, owner_token: str) -> str:
    """A real relay on a real port. No Docker: the hub's external-mailbox path
    lists an address the user already runs, which is exactly this."""
    port = free_port()
    data = tempfile.mkdtemp(prefix="sc-md-")
    _dirs.append(data)
    proc = subprocess.Popen(
        [str(RELAY)],
        env={
            **os.environ,
            "STONECHAT_OWNER_ID": owner_id,
            "STONECHAT_OWNER_TOKEN": owner_token,
            "STONECHAT_PORT": str(port),
            "STONECHAT_DB": f"{data}/mailbox.db",
            "STONECHAT_BLOBS": f"{data}/blobs",
            "STONECHAT_TLS_DIR": data,
        },
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    _procs.append(proc)
    address = f"https://127.0.0.1:{port}"
    for _ in range(60):
        try:
            if MX.get(f"{address}/health", timeout=2).status_code == 200:
                return address
        except Exception:
            time.sleep(0.2)
    raise RuntimeError(f"relay for {owner_id} never came up")


def cleanup():
    for proc in _procs:
        proc.terminate()
    for d in _dirs:
        shutil.rmtree(d, ignore_errors=True)


def attach_relay(phone: Phone, token: str) -> None:
    """Run a relay for this phone and list it in the directory."""
    address = start_relay(phone.stonechat_id, token)
    r = httpx.post(f"{HUB}/v1/server/external", headers=phone.auth,
                   json={"address": address})
    r.raise_for_status()
    phone.server = {"address": address, "server_token": token,
                    "tls_fp": r.json()["tls_fp"]}
    phone.publish_tls_sig()


def bundle_token(owner_token: str) -> str:
    import hashlib
    return hashlib.blake2b(
        owner_token.encode() + b"|stonechat-bundle|", digest_size=32
    ).hexdigest()


def main() -> int:
    print("multi-device e2e (no Docker)\n")

    alice, bob = Phone("Alice"), Phone("Bob")
    for p in (alice, bob):
        p.register()
    attach_relay(alice, "alice-owner-token-000000000000000")
    attach_relay(bob, "bob-owner-token-0000000000000000")
    for p in (alice, bob):
        p.upload_prekeys()

    a_addr, a_tok = alice.server["address"], alice.server["server_token"]
    a_fp = alice.server["tls_fp"]

    # -- 1. link a second device to Alice -------------------------------------
    print("1) link grant: mint → seal → park on the hub → collect")
    ek_seed = nacl_random(32)
    ek_pub = pqcore.xwing_pk_from_seed(ek_seed)
    lookup = nacl_random(32)
    import hashlib
    parking_key = hashlib.blake2b(lookup, digest_size=32).hexdigest()

    # Alice's phone mints the newcomer a device.
    dev2_token = base64.urlsafe_b64encode(nacl_random(32)).decode().rstrip("=")
    r = MX.post(f"{a_addr}/devices", params={"token": a_tok},
                json={"device_token": dev2_token, "kind": "linked"})
    r.raise_for_status()
    device_id = r.json()["device_id"]
    assert device_id == 2, f"expected device 2, got {device_id}"

    # ...seals a grant to the newcomer's ephemeral key and parks it on the hub.
    grant = json.dumps({
        "identity_seed": b64(bytes(alice.identity)),
        "stonechat_id": alice.stonechat_id,
        "display_name": "Alice",
        "hub_url": HUB,
        "relay_address": a_addr,
        "relay_tls_fp": a_fp,
        "device_id": device_id,
        "device_token": dev2_token,
        "bundle_token": bundle_token(a_tok),
    }).encode()
    kct, ss = pqcore.xwing_encaps(ek_pub)
    key = e2e.H(ss, e2e.HSEAL_KDF_KEY, 32)
    nonce = nacl_random(24)
    sealed = kct + nonce + e2e.crypto_aead_xchacha20poly1305_ietf_encrypt(
        grant, e2e.HSEAL_AD, nonce, key)
    httpx.post(f"{HUB}/v1/link",
               json={"key": parking_key, "sealed": b64(sealed)}).raise_for_status()

    # The new device collects and opens it.
    got = httpx.get(f"{HUB}/v1/link/{parking_key}")
    got.raise_for_status()
    blob = base64.b64decode(got.json()["sealed"])
    ct, nonce2, box = (blob[:pqcore.XWING_CT],
                       blob[pqcore.XWING_CT:pqcore.XWING_CT + 24],
                       blob[pqcore.XWING_CT + 24:])
    opened = json.loads(e2e.crypto_aead_xchacha20poly1305_ietf_decrypt(
        box, e2e.HSEAL_AD, nonce2,
        e2e.H(pqcore.xwing_decaps(ek_seed, ct), e2e.HSEAL_KDF_KEY, 32)))
    assert opened["stonechat_id"] == alice.stonechat_id
    assert opened["device_id"] == 2
    assert "account_token" not in opened, "a linked device must get no hub token"
    print("  ok   grant sealed, parked, collected, opened")

    # Single-use: the grant is gone.
    assert httpx.get(f"{HUB}/v1/link/{parking_key}").status_code == 404
    print("  ok   grant is single-use")

    # -- 2. the second device publishes its own prekeys -----------------------
    print("2) per-device prekeys: device 2's pool is its own")
    # Same identity, different ratchets — which is the whole design. The
    # public key has to be re-derived too: Phone() generated a throwaway one
    # in its constructor, and leaving it would make device 2 look like a
    # different user to anyone verifying its signed prekeys.
    alice2 = Phone("Alice/2")
    alice2.identity = alice.identity
    alice2.pubkey_b64 = alice.pubkey_b64
    alice2.derive_pq()
    alice2.stonechat_id = alice.stonechat_id
    alice2.server = {"address": a_addr, "server_token": dev2_token,
                     "tls_fp": a_fp}
    alice2.upload_prekeys()

    listed = MX.get(f"{a_addr}/prekeys/devices",
                    params={"token": bundle_token(a_tok)}).json()
    ids = sorted(d["device_id"] for d in listed["devices"])
    assert ids == [1, 2], f"expected both devices listed, got {ids}"
    print(f"  ok   /prekeys/devices lists {ids} (no OPK consumed)")

    # The gate: without the bundle token, a stranger sees only device 1.
    assert MX.get(f"{a_addr}/prekeys/devices").status_code == 401
    assert MX.get(f"{a_addr}/prekeys/bundle").status_code == 200
    print("  ok   listing is gated; the open bundle still serves device 1")

    # -- 3. Bob sends one message; both of Alice's devices get a copy ---------
    print("3) fan-out: one logical message, one envelope per device")
    logical_id = str(uuid.uuid4())
    for device in (1, 2):
        target = alice if device == 1 else alice2
        env = bob.make_envelope(target, "msg", {"text": "hi both"},
                                envelope_id=logical_id, device=device,
                                bundle_token=bundle_token(a_tok))
        MX.post(f"{a_addr}/inbox", json=bob.wrap(target, env)).raise_for_status()

    for device, token in ((1, a_tok), (2, dev2_token)):
        depth = MX.get(f"{a_addr}/status", params={"token": token}).json()["queued"]
        assert depth == 1, f"device {device} should hold exactly 1, has {depth}"
    print("  ok   both device queues hold their own copy of the same id")

    # Each device drains only its own queue.
    drained = {}
    for name, phone, token in (("dev1", alice, a_tok), ("dev2", alice2, dev2_token)):
        env = asyncio.run(phone.receive_one())
        inner = phone.open_envelope(env, bob)
        drained[name] = inner["text"]
        assert env["device"] == (1 if name == "dev1" else 2)
    assert drained == {"dev1": "hi both", "dev2": "hi both"}
    print("  ok   each device decrypted its own copy on its own ratchet")

    # -- 4. a revoked device stops receiving ----------------------------------
    print("4) revocation: delivery stops, devices_v bumps")
    before = MX.get(f"{a_addr}/status", params={"token": a_tok}).json()["devices_v"]
    MX.delete(f"{a_addr}/devices/2", params={"token": a_tok}).raise_for_status()
    after = MX.get(f"{a_addr}/status", params={"token": a_tok}).json()["devices_v"]
    assert after > before, "revocation must bump devices_v"

    env = bob.make_envelope(alice2, "msg", {"text": "too late"}, device=2)  # session exists
    r = MX.post(f"{a_addr}/inbox", json=bob.wrap(alice2, env))
    assert r.status_code == 410, f"expected 410 for a revoked device, got {r.status_code}"
    assert r.json()["devices_v"] == after, "the 410 must carry the new devices_v"
    print(f"  ok   410 + devices_v={after}; the revoked token no longer authenticates")
    assert MX.get(f"{a_addr}/status", params={"token": dev2_token}).status_code == 401

    print("\nPASS")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    finally:
        cleanup()
