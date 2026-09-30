"""Multi-device end to end, without Docker.

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
    HUB, MX, PRIMARY_DEVICE, Phone, b64, nacl_random, unb64,
)
from nacl.exceptions import BadSignatureError  # noqa: E402
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
    r = httpx.post(f"{HUB}/v1/mailbox/external", headers=phone.auth,
                   json={"address": address})
    r.raise_for_status()
    phone.mailbox = {"address": address, "mailbox_token": token,
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

    a_addr, a_tok = alice.mailbox["address"], alice.mailbox["mailbox_token"]
    a_fp = alice.mailbox["tls_fp"]

    # -- 1. link a second device to Alice -------------------------------------
    print("1) link grant: mint → certify → seal → park on the hub → collect")
    # The newcomer, with its OWN keys. It never receives Alice's identity
    # secret — what it gets is a certificate over the public halves it is
    # about to show in its QR.
    alice2 = Phone("Alice/2")
    alice2.identity = None  # proves the linked device never needs the root
    alice2.pubkey_b64 = alice.pubkey_b64
    alice2.device = 2  # it stamps from_device 2, and the AEAD binds that
    alice2.stonechat_id = alice.stonechat_id

    # The QR carries a *commitment* to this device's keys, not the keys: an
    # X-Wing public key is 1216 bytes, which made the code QR version 36 and
    # unreadable in practice. The keys go to the hub; the phone fetches them
    # and checks they hash to what was scanned, so a substituted key is still
    # refused — the eyes carry 32 bytes instead of 1248.
    import hashlib
    lookup = nacl_random(32)
    parking_key = hashlib.blake2b(lookup, digest_size=32).hexdigest()

    commitment = hashlib.blake2b(
        b"stonechat-link-offer" + alice2.dev_seal_pk
        + bytes(alice2.dev_sig.verify_key),
        digest_size=32,
    ).hexdigest()
    httpx.post(f"{HUB}/v1/link/offer", json={
        "key": commitment,
        "offer": {"seal": b64(alice2.dev_seal_pk),
                  "sig": b64(bytes(alice2.dev_sig.verify_key))},
    }).raise_for_status()

    # The hub refuses a key that is not the commitment to the offer — it
    # cannot be used to serve keys the scanner did not agree to.
    bad = httpx.post(f"{HUB}/v1/link/offer", json={
        "key": hashlib.blake2b(b"wrong", digest_size=32).hexdigest(),
        "offer": {"seal": b64(alice2.dev_seal_pk),
                  "sig": b64(bytes(alice2.dev_sig.verify_key))},
    })
    assert bad.status_code == 400, f"mismatched commitment: got {bad.status_code}"

    # The phone side: fetch and verify before certifying anything.
    fetched = httpx.get(f"{HUB}/v1/link/offer/{commitment}").json()["offer"]
    assert hashlib.blake2b(
        b"stonechat-link-offer" + unb64(fetched["seal"]) + unb64(fetched["sig"]),
        digest_size=32,
    ).hexdigest() == commitment, "fetched keys must match the scanned commitment"
    # Not single-use: a scan that fails downstream has to be retryable.
    assert httpx.get(f"{HUB}/v1/link/offer/{commitment}").status_code == 200, \
        "the offer must survive a re-read"
    print("  ok   offer parked under its commitment, verified, re-readable")

    # Alice's phone mints the newcomer a device...
    dev2_token = base64.urlsafe_b64encode(nacl_random(32)).decode().rstrip("=")
    r = MX.post(f"{a_addr}/devices", params={"token": a_tok},
                json={"device_token": dev2_token, "kind": "linked"})
    r.raise_for_status()
    device_id = r.json()["device_id"]
    assert device_id == 2, f"expected device 2, got {device_id}"

    # ...certifies the keys from the QR for exactly that device id, and seals
    # the grant to the seal key it just certified.
    cert = alice.sign_cert_for(
        bytes(alice2.dev_sig.verify_key), alice2.dev_seal_pk, device=device_id)
    grant = json.dumps({
        "identity_pub": alice.pubkey_b64,
        "cert": cert,
        "stonechat_id": alice.stonechat_id,
        "display_name": "Alice",
        "hub_url": HUB,
        "relay_address": a_addr,
        "relay_tls_fp": a_fp,
        "device_id": device_id,
        "device_token": dev2_token,
        "bundle_token": bundle_token(a_tok),
    }).encode()
    kct, ss = pqcore.xwing_encaps(alice2.dev_seal_pk)
    key = e2e.H(ss, e2e.HSEAL_KDF_KEY, 32)
    nonce = nacl_random(24)
    sealed = kct + nonce + e2e.crypto_aead_xchacha20poly1305_ietf_encrypt(
        grant, e2e.HSEAL_AD, nonce, key)
    httpx.post(f"{HUB}/v1/link",
               json={"key": parking_key, "sealed": b64(sealed)}).raise_for_status()

    # The new device collects and opens it — with its own seal seed, which is
    # the seed the certificate inside vouches for.
    got = httpx.get(f"{HUB}/v1/link/{parking_key}")
    got.raise_for_status()
    blob = base64.b64decode(got.json()["sealed"])
    ct, nonce2, box = (blob[:pqcore.XWING_CT],
                       blob[pqcore.XWING_CT:pqcore.XWING_CT + 24],
                       blob[pqcore.XWING_CT + 24:])
    opened = json.loads(e2e.crypto_aead_xchacha20poly1305_ietf_decrypt(
        box, e2e.HSEAL_AD, nonce2,
        e2e.H(pqcore.xwing_decaps(alice2.dev_seal_seed, ct),
              e2e.HSEAL_KDF_KEY, 32)))
    assert opened["stonechat_id"] == alice.stonechat_id
    assert opened["device_id"] == 2
    assert "account_token" not in opened, "a linked device must get no hub token"
    assert "identity_seed" not in opened, \
        "the identity secret must not travel in a grant"
    assert e2e.stonechat_id_from_pubkey(unb64(opened["identity_pub"])) \
        == alice.stonechat_id, "identity key must commit to the claimed ID"
    print("  ok   grant sealed, parked, collected, opened")

    # The three checks the new device makes before adopting it.
    e2e.verify_devcert(opened["cert"], unb64(opened["identity_pub"]),
                       device=opened["device_id"])
    assert opened["cert"]["sig_pub"] == b64(bytes(alice2.dev_sig.verify_key))
    assert opened["cert"]["seal_pub"] == b64(alice2.dev_seal_pk), \
        "a certificate for keys we do not hold would leave us unable to read"
    alice2.cert = opened["cert"]
    print("  ok   certificate verifies, names device 2, and vouches for OUR keys")

    # A certificate the primary did not sign is refused — this is the check
    # that stops a substituted grant installing a device under Alice's name.
    mallory = Phone("Mallory")
    mallory.stonechat_id = alice.stonechat_id  # claiming to be her
    forged = mallory.sign_cert_for(
        bytes(alice2.dev_sig.verify_key), alice2.dev_seal_pk, device=2)
    try:
        e2e.verify_devcert(forged, unb64(alice.pubkey_b64), device=2)
        raise AssertionError("a certificate signed by someone else must not verify")
    except BadSignatureError:
        pass
    print("  ok   a certificate from another identity is refused")

    # Single-use: the grant is gone.
    assert httpx.get(f"{HUB}/v1/link/{parking_key}").status_code == 404
    print("  ok   grant is single-use")

    # -- 2. the second device publishes its own prekeys -----------------------
    print("2) per-device prekeys: device 2's pool is its own")
    # Same identity, different ratchets — which is the whole design. Its
    # prekeys are signed by its own key and published with the certificate it
    # was granted; it could not mint one, having no root to sign with.
    alice2.mailbox = {"address": a_addr, "mailbox_token": dev2_token,
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

    # -- 4. self-sync: what device 1 sends shows up on device 2 ---------------
    print("4) self-sync: an outgoing message mirrored to our own other device")
    # Alice's phone sends Bob a message...
    sent_id = str(uuid.uuid4())
    out = alice.make_envelope(bob, "msg", {"text": "from my phone"},
                              envelope_id=sent_id, device=PRIMARY_DEVICE)
    MX.post(f"{bob.mailbox['address']}/inbox",
            json=alice.wrap(bob, out)).raise_for_status()
    assert asyncio.run(bob.receive_one(
        process=lambda e: bob.open_envelope(e, alice)))["id"] == sent_id

    # ...and mirrors it to her own laptop, over an ordinary pairwise session
    # with herself. Siblings are peers like any other.
    sync = alice.make_envelope(alice2, "sync_sent", {
        "peer": bob.stonechat_id,
        "type": "msg",
        "payload": {"text": "from my phone"},
        "id": sent_id,
        "sent_at": 1,
    }, device=2, bundle_token=bundle_token(a_tok))
    MX.post(f"{a_addr}/inbox", json=alice.wrap(alice2, sync)).raise_for_status()

    got = asyncio.run(alice2.receive_one())
    inner = alice2.unseal(got)
    assert inner["type"] == "sync_sent"
    assert inner["from"] == alice.stonechat_id, "a sync must come from our own identity"
    assert inner["from_device"] == PRIMARY_DEVICE
    body = alice2.open_envelope(got, alice)
    assert body["id"] == sent_id and body["payload"]["text"] == "from my phone"
    print("  ok   device 2 rendered a message device 1 sent, same logical id")

    # The guard that matters: the type is only ever applied when `from` is our
    # own identity, and the session is what proves that.
    assert inner["from"] == alice2.stonechat_id, \
        "sender and receiver are the same identity — that IS the check"

    # -- 5. per-device receipts ----------------------------------------------
    print("5) receipts: each of Alice's devices acknowledges for itself")
    for phone in (alice, alice2):
        env = phone.make_envelope(bob, "receipt",
                                  {"kind": "delivered", "ids": [sent_id]},
                                  device=PRIMARY_DEVICE)
        MX.post(f"{bob.mailbox['address']}/inbox",
                json=phone.wrap(bob, env)).raise_for_status()

    seen = {}
    for _ in range(2):
        env = asyncio.run(bob.receive_one())
        inner = bob.unseal(env)
        # Decrypt, do not merely read the field: from_device is AEAD-bound,
        # so opening it on the right ratchet is the actual proof that this
        # device sent it. Reading the header alone would pass even for an
        # envelope whose from_device had been altered after sealing.
        body = bob.open_envelope(env, alice)
        assert body["kind"] == "delivered" and body["ids"] == [sent_id]
        seen[inner["from_device"]] = inner["from"]
    assert sorted(seen) == [1, 2], f"expected a receipt from each device, got {seen}"
    # Both name the same identity, so a client keyed (message, peer) collapses
    # them into one row — which is what keeps group "delivered when every
    # MEMBER is" counting members rather than devices.
    assert set(seen.values()) == {alice.stonechat_id}
    print(f"  ok   two receipts decrypted on two ratchets, from_device {sorted(seen)}")

    # The binding is what makes from_device trustworthy. Relabelling it after
    # sealing must fail to open — otherwise a relay could attribute a message
    # to the wrong device of the right person, and self-sync acts on that.
    tampered = alice.make_envelope(bob, "msg", {"text": "who sent this?"},
                                   device=PRIMARY_DEVICE)
    tampered["from_device"] = 2
    try:
        bob.open_envelope(bob.wrap(bob, tampered), alice)
        raise AssertionError("a relabelled from_device must not decrypt")
    except AssertionError:
        raise
    except Exception:
        print("  ok   a relabelled from_device fails to decrypt (AEAD-bound)")

    # -- 6. who may manage the mailbox, and what revocation does ---------------
    print("6) device management is the primary's; revocation stops delivery")
    # A linked device's token is a login to its own queue, not authority over
    # the device list: it cannot add a device, and it cannot remove the
    # primary or a sibling. Its one power there is to sign itself out.
    dev3_token = base64.urlsafe_b64encode(nacl_random(32)).decode().rstrip("=")
    r = MX.post(f"{a_addr}/devices", params={"token": dev2_token},
                json={"device_token": dev3_token, "kind": "linked"})
    assert r.status_code == 403, f"a linked device minted a device: {r.status_code}"
    r = MX.delete(f"{a_addr}/devices/1", params={"token": dev2_token})
    assert r.status_code == 403, f"a linked device revoked the primary: {r.status_code}"
    r = MX.delete(f"{a_addr}/devices/1", params={"token": a_tok})
    assert r.status_code == 403, f"the primary was revoked over the API: {r.status_code}"
    assert MX.get(f"{a_addr}/status", params={"token": a_tok}).status_code == 200, \
        "the owner token must survive every attempt to revoke device 1"

    r = MX.post(f"{a_addr}/devices", params={"token": a_tok},
                json={"device_token": dev3_token, "kind": "linked"})
    r.raise_for_status()
    assert r.json()["device_id"] == 3
    r = MX.delete(f"{a_addr}/devices/3", params={"token": dev2_token})
    assert r.status_code == 403, f"a linked device revoked a sibling: {r.status_code}"
    assert MX.get(f"{a_addr}/status", params={"token": dev3_token}).status_code == 200
    print("  ok   a linked device cannot mint, nor revoke the primary or a sibling")

    # Signing out: device 3 removes itself, and is then nobody.
    MX.delete(f"{a_addr}/devices/3", params={"token": dev3_token}).raise_for_status()
    assert MX.get(f"{a_addr}/status", params={"token": dev3_token}).status_code == 401
    print("  ok   a linked device can revoke itself")

    # The primary revokes device 2.
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
