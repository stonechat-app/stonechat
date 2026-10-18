"""End-to-end test of the Stonechat stack (protocol v1), no Flutter needed.

Simulates phones with PyNaCl (same libsodium primitives the app uses) plus
the pqcore Rust library over ctypes (the same C ABI the app loads over FFI —
build once with scripts/build_core.sh host):
register → provision local-Docker relays → pin TLS + publish prekeys → PQXDH
contact handshake → double-ratchet messages inside hybrid-sealed envelopes →
ack → forward-secrecy + sealed-sender proofs → destroy.

The PQXDH + double-ratchet + sealed-envelope implementation below mirrors
PROTOCOL.md "Session crypto" and "Envelope" constant-for-constant; it doubles
as the reference implementation the Dart client must interoperate with.

Transport: relays serve pinned TLS (PROTOCOL.md "Transport"). Mailbox
requests here use verify=False because relay certs are self-signed BY DESIGN
— the real check is the pin, which the test asserts explicitly:
live certificate fingerprint == directory fingerprint, signed by the owner.
"""

import asyncio
import base64
import copy
import hashlib
import json
import pathlib
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from datetime import datetime, timezone
from urllib.parse import urlsplit

import httpx
import websockets
from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_decrypt,
    crypto_aead_xchacha20poly1305_ietf_encrypt,
    crypto_scalarmult,
)
from nacl.public import PrivateKey, SealedBox
from nacl.signing import SigningKey, VerifyKey
from nacl.utils import random as nacl_random

import os
HUB = os.environ.get("STONECHAT_HUB", "http://127.0.0.1:8477")
# must match the STONECHAT_ADMIN_TOKEN the hub was started with
ADMIN_TOKEN = os.environ.get("STONECHAT_ADMIN_TOKEN", "test-admin")
# The gate the hub asks about tiers (hub/app/gate.py). This script runs a stub
# one in-process (scripts/stub_gate.py); the hub must be started pointing at
# it: STONECHAT_GATE_URL=http://127.0.0.1:<GATE_PORT> and STONECHAT_GATE_TOKEN
# set to GATE_TOKEN below.
GATE_PORT = int(os.environ.get("STONECHAT_TEST_GATE_PORT", "8478"))
GATE_TOKEN = os.environ.get("STONECHAT_TEST_GATE_TOKEN", "e2e-gate")
GATE_CODE = "E2E-MAILBOX"

# The shared tier under test is a real mailbox host, started by this script (see
# MailboxHostUnderTest). The hub must already be pointed at it, which means these
# three values have to agree with the hub's STONECHAT_MAILBOX_HOSTS entry (this
# URL and admin token, `insecure` as the fingerprint). `insecure` skips the
# certificate pin, which is exactly what laptop dev is for: the host mints a
# fresh self-signed cert in a temp directory on every run, so there is no
# stable fingerprint to pin.
MAILBOX_HOST_PORT = int(os.environ.get("STONECHAT_TEST_MAILBOX_HOST_PORT", "8201"))
MAILBOX_HOST_TOKEN = os.environ.get(
    "STONECHAT_TEST_MAILBOX_HOST_TOKEN", "e2e-mailbox-host-admin")
MAILBOX_HOST_URL = f"https://127.0.0.1:{MAILBOX_HOST_PORT}"

# Mailbox client: no CA validation (self-signed by design); see module docstring.
MX = httpx.Client(verify=False, timeout=10)
WS_SSL = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
WS_SSL.check_hostname = False
WS_SSL.verify_mode = ssl.CERT_NONE

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1] / "hub"))
from app.identity import stonechat_id_from_pubkey  # noqa: E402
from app.providers.local import image_tag  # noqa: E402

MAILBOX_HOST_MAIN = (
    __import__("pathlib").Path(__file__).resolve().parents[1] / "mailbox_host" / "main.py"
)

TLS_SIG_CONTEXT = b"stonechat-v1-tls"
WTCERTS_SIG_CONTEXT = b"stonechat-v1-wtcerts"


def shared_country(hub_url: str) -> str:
    """A country the hub can actually place a Mailbox-plan container in.

    Mailbox hosts place by country, so `region` is not a placeholder — it must
    name a country STONECHAT_MAILBOX_HOSTS configures a host for. Read it from
    the catalog instead of hardcoding, so this follows whatever the hub under
    test is configured with.
    """
    for c in httpx.get(f"{hub_url}/v1/countries").json()["countries"]:
        if "mailbox" in c["plans"]:
            return c["code"]
    raise SystemExit(
        "no country offers the mailbox plan — give STONECHAT_MAILBOX_HOSTS a host "
        f'with a country, e.g. "local={MAILBOX_HOST_URL}|DE|{MAILBOX_HOST_TOKEN}|insecure"'
    )


def wtcerts_signing_bytes(certs: list[dict]) -> bytes:
    """Mirrors core/src/wtcerts.rs — length-prefixed and ordered, not JSON.

    The leading count is what stops a truncated list verifying as a prefix of
    the signed one, and truncating away the *future* certificates is exactly
    how an attacker strands a client on one they already hold."""
    out = bytearray(len(certs).to_bytes(4, "big"))
    for cert in certs:
        for field in (
            cert["sha256"].encode(),
            int(cert["not_before"]).to_bytes(8, "big", signed=True),
            int(cert["not_after"]).to_bytes(8, "big", signed=True),
        ):
            out += len(field).to_bytes(4, "big") + field
    return bytes(out)


def live_cert_fp(address: str) -> str:
    """What a pinning client computes during the handshake:
    BLAKE2b-256 of the DER certificate the relay actually presents."""
    host, port = address.removeprefix("https://").rsplit(":", 1)
    pem = ssl.get_server_certificate((host, int(port)))
    der = ssl.PEM_cert_to_DER_cert(pem)
    return base64.b64encode(hashlib.blake2b(der, digest_size=32).digest()).decode()


class Rejected(Exception):
    """Something a client must refuse, and drop for good: no retry makes a
    malformed envelope well-formed, or a lying directory honest."""


_WIRE_ID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE)


def is_wire_id(value) -> bool:
    """A UUID in its canonical form (PROTOCOL.md "Envelope"). Envelope and blob
    ids end up in file names and URLs on the receiving side, so anything else
    is refused where it enters rather than escaped where it is used."""
    return isinstance(value, str) and _WIRE_ID.fullmatch(value) is not None


def check_directory_entry(asked_for: str, entry: dict) -> dict:
    """PROTOCOL.md "Directory resolution": what a client checks before it
    believes a directory's answer. Returns the entry, or raises Rejected.

    Against the ID that was ASKED FOR, never the one in the answer: somebody
    else's complete record is internally consistent — its key does hash to its
    ID — and the only thing wrong with it is that it is not what was asked for.
    """
    try:
        identity = base64.b64decode(entry["pubkey"], validate=True)
        if entry["stonechat_id"] != asked_for \
                or stonechat_id_from_pubkey(identity) != asked_for:
            raise Rejected(f"directory answered for {asked_for} with a record "
                           "that does not commit to it")
        verify = VerifyKey(identity)
        mailbox = entry.get("mailbox")
        # A mailbox nobody vouched for is one to stay away from, not one to
        # connect to unpinned. An owner who has not signed yet (just
        # provisioned) reads as "no mailbox", which is what it is to a sender.
        if mailbox and mailbox.get("tls_sig"):
            verify.verify(TLS_SIG_CONTEXT + base64.b64decode(mailbox["tls_fp"]),
                          base64.b64decode(mailbox["tls_sig"]))
            if not str(mailbox.get("address", "")).startswith("https://"):
                raise Rejected("mailbox address is not https")
        elif mailbox:
            entry = {**entry, "mailbox": None}
        # The signed device manifest, when the owner has published one
        # (PROTOCOL.md "Device manifest"). Present and not verifying is a
        # directory serving something the owner never signed: refuse the
        # record, not just the manifest.
        if entry.get("devices") is not None:
            verify_devices_manifest(entry["devices"], identity, asked_for)
    except Rejected:
        raise
    except Exception as e:
        raise Rejected(f"directory record for {asked_for} does not verify: {e!r}")
    return entry


def resolve_directory(stonechat_id: str) -> dict:
    r = httpx.get(f"{HUB}/v1/directory/{stonechat_id}", timeout=10)
    r.raise_for_status()
    return check_directory_entry(stonechat_id, r.json())


def assert_pinned(phone: "Phone") -> None:
    """The full client-side transport check: directory fp is vouched for by
    the owner's identity key AND matches the certificate actually served."""
    srv = resolve_directory(phone.stonechat_id)["mailbox"]
    assert srv, "the owner has signed no fingerprint for this mailbox"
    assert srv["tls_fp"] == live_cert_fp(srv["address"]), \
        "served certificate must match the owner-signed fingerprint"


# -- session crypto (PROTOCOL.md) ----------------------------------------------

import pqcore  # noqa: E402  (scripts/pqcore.py — ctypes over the Rust core)

X3DH_KDF_KEY = b"stonechat-v1-pqxdh-kdf"
SPK_SIG_CONTEXT = b"stonechat-v1-spk"
KSPK_SIG_CONTEXT = b"stonechat-v1-kspk"
REGISTER_SIG_CONTEXT = b"stonechat-v1-register"
HSEAL_KDF_KEY = b"stonechat-v1-hsealkdf"
HSEAL_AD = b"stonechat-v1-hseal"
MAX_SKIP = 256
# Post-quantum ratchet (PROTOCOL.md "Post-quantum ratchet"), as in
# core/src/session.rs.
PQ_RATCHET_KDF_INFO = b"stonechat-v1-pqratchet"
PQ_INTERVAL = 50
PQ_ATTACH = 3
# Seal padding buckets (PROTOCOL.md "Envelope").
PAD_MIN, PAD_DOUBLING_MAX, PAD_STEP = 2048, 32768, 1024


def H(msg: bytes, key: bytes, n: int) -> bytes:
    return hashlib.blake2b(msg, key=key, digest_size=n).digest()


def kdf_rk(rk: bytes, dh: bytes) -> tuple[bytes, bytes]:
    out = H(dh, rk, 64)
    return out[:32], out[32:]


def kdf_ck(ck: bytes) -> tuple[bytes, bytes]:
    return H(b"\x01", ck, 32), H(b"\x02", ck, 32)  # (mk, ck')


def kdf_pq(rk: bytes, kem_ss: bytes) -> bytes:
    return H(PQ_RATCHET_KDF_INFO + kem_ss, rk, 32)


def padded_len(n: int) -> int:
    need = n + 1
    if need > PAD_DOUBLING_MAX:
        return -(-need // PAD_STEP) * PAD_STEP
    bucket = PAD_MIN
    while bucket < need:
        bucket *= 2
    return bucket


def pad(message: bytes) -> bytes:
    return (message + b"\x80").ljust(padded_len(len(message)), b"\x00")


def unpad(padded: bytes) -> bytes:
    """Raises unless the bytes are padded exactly as pad() pads."""
    body = padded.rstrip(b"\x00")
    if not body.endswith(b"\x80") or padded_len(len(body) - 1) != len(padded):
        raise Rejected("sealed content is not padded to its bucket")
    return body[:-1]


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def roster_hash(group_id: str, version: int, admin: str, member_ids) -> str:
    """What a roster commits to (PROTOCOL.md "Keeping the roster in step"):
    unkeyed BLAKE2b-256, base64."""
    ids = ",".join(sorted(member_ids))
    return b64(hashlib.blake2b(
        f"stonechat-v1-roster|{group_id}|{version}|{admin}|{ids}".encode(),
        digest_size=32).digest())


def group_message_hash(group_id: str, sender: str, message_id: str,
                       salt: str, payload: dict) -> str | None:
    """What one member received as a group message (PROTOCOL.md "Transcript
    consistency"). None for a payload that is neither text nor media."""
    if isinstance(payload.get("text"), str):
        body = f"text|{payload['text']}"
    elif all(isinstance(payload.get(k), str) for k in ("blob_id", "key", "blob_nonce")):
        body = f"media|{payload['blob_id']}|{payload['key']}|{payload['blob_nonce']}"
    else:
        return None
    return b64(hashlib.blake2b(
        f"stonechat-v1-gmsg|{group_id}|{sender}|{message_id}|{salt}|{body}".encode(),
        digest_size=32).digest())


def unb64(s: str) -> bytes:
    return base64.b64decode(s)


PRIMARY_DEVICE = 1
DEVCERT_SIG_CONTEXT = b"stonechat-v1-devcert"
DEVICES_SIG_CONTEXT = b"stonechat-v1-devices"
MAX_MANIFEST_DEVICES = 64


def devices_signing_bytes(manifest: dict) -> bytes:
    """Mirror of Manifest::signing_bytes in core/src/devices.rs (and the
    hub's copy): length-prefixed and ordered, with the device count, so a
    truncated list does not verify as a prefix of the signed one."""
    def field(b: bytes) -> bytes:
        return len(b).to_bytes(4, "big") + b
    out = (field(manifest["stonechat_id"].encode())
           + field(int(manifest["version"]).to_bytes(8, "big"))
           + field(int(manifest["issued_at"]).to_bytes(8, "big", signed=True))
           + field(len(manifest["devices"]).to_bytes(4, "big")))
    for d in manifest["devices"]:
        out += field(int(d["device_id"]).to_bytes(4, "big"))
        out += field(unb64(d["sig_pub"]))
    return out


def sign_devices_manifest(identity: SigningKey, stonechat_id: str, version: int,
                          devices: dict[int, bytes]) -> dict:
    """The identity's statement of which devices speak for it, numbered."""
    manifest = {
        "stonechat_id": stonechat_id,
        "version": version,
        "issued_at": int(time.time()),
        "devices": [{"device_id": i, "sig_pub": b64(k)} for i, k in sorted(devices.items())],
    }
    manifest["sig"] = b64(identity.sign(
        DEVICES_SIG_CONTEXT + devices_signing_bytes(manifest)).signature)
    return manifest


def verify_devices_manifest(manifest: dict, identity_pub: bytes,
                            stonechat_id: str) -> dict:
    """Raises Rejected unless `manifest` is that identity's genuine,
    well-formed manifest for `stonechat_id`."""
    try:
        if manifest["stonechat_id"] != stonechat_id:
            raise Rejected("device manifest names another identity")
        if stonechat_id_from_pubkey(identity_pub) != stonechat_id:
            raise Rejected("device manifest checked against a key its ID does not commit to")
        ids = [d["device_id"] for d in manifest["devices"]]
        if not ids or len(ids) > MAX_MANIFEST_DEVICES or len(set(ids)) != len(ids):
            raise Rejected("device manifest lists no device, too many, or one twice")
        VerifyKey(identity_pub).verify(
            DEVICES_SIG_CONTEXT + devices_signing_bytes(manifest), unb64(manifest["sig"]))
    except Rejected:
        raise
    except Exception as e:
        raise Rejected(f"device manifest does not verify: {e!r}")
    return manifest


def device_listed(manifest: dict | None, device_id: int, sig_pub: bytes) -> bool:
    """Whether a verified manifest names `device_id` with exactly this key. No
    manifest (an identity that never published one) lists every device."""
    if manifest is None:
        return True
    return any(d["device_id"] == device_id and unb64(d["sig_pub"]) == sig_pub
               for d in manifest["devices"])


def devcert_signing_bytes(cert: dict) -> bytes:
    """Mirror of DeviceCert::signing_bytes in core/src/devcert.rs.

    Length-prefixed and ordered, deliberately NOT JSON: a signature over
    re-serialized JSON is a signature over whatever the other side's
    serializer emitted, and two implementations ordering keys differently
    would reject each other's certificates while looking like forgery."""
    def field(b: bytes) -> bytes:
        return len(b).to_bytes(4, "big") + b
    return (
        field(cert["stonechat_id"].encode())
        + field(cert["device_id"].to_bytes(4, "big"))
        + field(unb64(cert["sig_pub"]))
        + field(unb64(cert["seal_pub"]))
        + field(cert["not_after"].to_bytes(8, "big"))
    )


def verify_devcert(cert: dict, identity_pub: bytes, now: int | None = None,
                   device: int | None = None) -> None:
    """Raises unless the certificate is signed by that identity, unexpired,
    and — when `device` is given — actually for the device it arrived as.
    This is the check that lets a device exist without the identity secret."""
    VerifyKey(identity_pub).verify(
        DEVCERT_SIG_CONTEXT + devcert_signing_bytes(cert), unb64(cert["sig"]))
    assert stonechat_id_from_pubkey(identity_pub) == cert["stonechat_id"], \
        "certificate is signed by a key its Stonechat ID does not commit to"
    assert cert["not_after"] > (now or int(time.time())), "certificate expired"
    if device is not None:
        assert cert["device_id"] == device, \
            "certificate names a different device than the slot it came in"


def ad_for(envelope: dict) -> bytes:
    """Both device numbers are bound — one
    form, always, so a relabelled envelope simply fails to decrypt."""
    r = envelope["ratchet"]
    ad = (
        f"stonechat/v1|{envelope['from']}|{envelope['from_device']}"
        f"|{envelope['to']}|{envelope['device']}|{envelope['type']}"
        f"|{r['dh']}|{r['pn']}|{r['n']}"
    )
    pq = r.get("pq")
    if pq is not None:
        # The KEM material is authenticated by being part of the AD.
        def num(v):
            return "" if v is None else str(v)
        ek, ct = pq.get("ek") or {}, pq.get("ct") or {}
        ad += (f"|pq|{num(pq.get('mix'))}|{num(ek.get('id'))}|{ek.get('pub', '')}"
               f"|{num(ct.get('id'))}|{ct.get('ct', '')}")
    return ad.encode()


def _pq(state: dict) -> dict:
    """The session's post-quantum ratchet state, created on first use (a
    session pickled before it existed has none)."""
    return state.setdefault("pq", {
        "count": 0, "issued": 0, "mixed": 0, "attach": 0, "mix": None,
        "local": None, "inbound": None, "outbound": None})


def _pq_header(state: dict) -> dict | None:
    pq = _pq(state)
    out = {}
    if pq["mix"] is not None:
        out["mix"] = pq["mix"]
    if pq["attach"] > 0:
        if pq["local"]:
            out["ek"] = {"id": pq["local"]["id"],
                         "pub": b64(pqcore.mlkem_pk_from_seed(pq["local"]["seed"]))}
        if pq["outbound"]:
            out["ct"] = {"id": pq["outbound"]["id"], "ct": b64(pq["outbound"]["ct"])}
        if "ek" in out or "ct" in out:
            pq["attach"] -= 1
    return out or None


def _pq_absorb(state: dict, header: dict) -> None:
    """Take in an authenticated header's KEM material: the responder
    encapsulates to a new key, the initiator decapsulates the answer."""
    block, pq = header.get("pq"), _pq(state)
    if not block:
        return
    ek, ct = block.get("ek"), block.get("ct")
    if ek and not state.get("initiated") and ek["id"] > pq["mixed"] \
            and (pq["outbound"] is None or pq["outbound"]["id"] < ek["id"]):
        try:
            kct, ss = pqcore.mlkem_encaps(unb64(ek["pub"]))
        except ValueError:
            pass
        else:
            pq["outbound"] = {"id": ek["id"], "ct": kct, "ss": ss}
            pq["attach"] = PQ_ATTACH
    if ct and state.get("initiated") and pq["local"] and pq["local"]["id"] == ct["id"]:
        raw = unb64(ct["ct"])
        if len(raw) == pqcore.MLKEM_CT:
            pq["inbound"] = {"id": ct["id"],
                             "ss": pqcore.mlkem_decaps(pq["local"]["seed"], raw)}
            pq["local"] = None


def session_encrypt(state: dict, plaintext: bytes, meta: dict) -> dict:
    """meta = {from,from_device,to,device,type}. Returns the ratchet/nonce/
    ciphertext fields. The AD is built by the same rule as ad_for() — one
    form, both device numbers bound."""
    mk, state["cks"] = kdf_ck(state["cks"])
    header = {"dh": b64(state["dhs_pub"]), "pn": state["pn"], "n": state["ns"]}
    pq = _pq_header(state)
    if pq:
        header["pq"] = pq
    state["ns"] += 1
    _pq(state)["count"] += 1
    nonce = nacl_random(24)
    ad = ad_for({**meta, "ratchet": header})
    ct = crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, ad, nonce, mk)
    return {"ratchet": header, "nonce": b64(nonce), "ciphertext": b64(ct)}


def _skip_keys(state: dict, until: int) -> None:
    if state["nr"] + MAX_SKIP < until:
        raise ValueError("gap too large")
    if state["ckr"] is None:
        if state["nr"] < until:
            raise ValueError("no receive chain")
        return
    dh_b64 = b64(state["dhr"])
    while state["nr"] < until:
        mk, state["ckr"] = kdf_ck(state["ckr"])
        state["skipped"][(dh_b64, state["nr"])] = mk
        state["nr"] += 1


def _dh_ratchet(state: dict, header_dh: bytes, peer_mixed: dict | None = None) -> None:
    """A KEM secret is mixed into the root immediately before the chain its
    initiator-side owner sends on: `peer_mixed` (our encapsulation, which the
    header said was mixed) before the receive chain, our own `inbound` before
    the send chain."""
    pq = _pq(state)
    state["pn"], state["ns"], state["nr"] = state["ns"], 0, 0
    state["dhr"] = header_dh
    if peer_mixed:
        state["rk"] = kdf_pq(state["rk"], peer_mixed["ss"])
        pq["mixed"], pq["count"] = peer_mixed["id"], 0
    state["rk"], state["ckr"] = kdf_rk(
        state["rk"], crypto_scalarmult(state["dhs_priv"], header_dh))
    fresh = PrivateKey.generate()
    state["dhs_priv"], state["dhs_pub"] = bytes(fresh), bytes(fresh.public_key)
    pq["mix"] = None
    if pq["inbound"]:
        inbound, pq["inbound"] = pq["inbound"], None
        state["rk"] = kdf_pq(state["rk"], inbound["ss"])
        pq["mix"] = pq["mixed"] = inbound["id"]
        pq["count"] = 0
    state["rk"], state["cks"] = kdf_rk(
        state["rk"], crypto_scalarmult(state["dhs_priv"], header_dh))
    pq["attach"] = PQ_ATTACH
    if state.get("initiated") and pq["local"] is None and pq["count"] >= PQ_INTERVAL:
        pq["issued"] += 1
        pq["local"] = {"id": pq["issued"], "seed": pqcore.mlkem_keygen()[0]}


def session_decrypt(state: dict, envelope: dict) -> bytes:
    """Mutates state on success; raises on failure (caller uses a copy)."""
    header = envelope["ratchet"]
    ad = ad_for(envelope)
    nonce, ct = unb64(envelope["nonce"]), unb64(envelope["ciphertext"])
    skipped_mk = state["skipped"].pop((header["dh"], header["n"]), None)
    if skipped_mk is not None:
        plain = crypto_aead_xchacha20poly1305_ietf_decrypt(ct, ad, nonce, skipped_mk)
    else:
        header_dh = unb64(header["dh"])
        if state["dhr"] is None or header_dh != state["dhr"]:
            _skip_keys(state, header["pn"])
            mix_id = (header.get("pq") or {}).get("mix")
            mixed = None
            if mix_id is not None:
                mixed, _pq(state)["outbound"] = _pq(state)["outbound"], None
                if mixed is None or mixed["id"] != mix_id:
                    raise ValueError("chain mixes a KEM secret we do not hold")
            _dh_ratchet(state, header_dh, mixed)
        _skip_keys(state, header["n"])
        mk, state["ckr"] = kdf_ck(state["ckr"])
        state["nr"] += 1
        plain = crypto_aead_xchacha20poly1305_ietf_decrypt(ct, ad, nonce, mk)
    state["confirmed"] = True
    state["pending_x3dh"] = None
    _pq(state)["count"] += 1
    _pq_absorb(state, header)
    return plain


# -- a simulated phone -----------------------------------------------------------


# Every mailbox this run ignites, so a failed assertion cannot leak a
# container. The local and mailbox-host providers run `docker run --restart
# unless-stopped`, so a leaked mailbox is not merely a stray container: it
# comes back on every Docker restart and holds its published ports forever.
_PROVISIONED: list["Phone"] = []


def _container_name(stonechat_id):
    """The container the local provider names for this owner.

    Mirrors hub/app/providers/local.py — the sweep needs it because the
    fallback path runs when the hub is the thing that died. Mailbox-host guests
    are named differently and are swept by label; see sweep_mailboxes().
    """
    return f"stonechat-{stonechat_id[3:11].lower().replace('-', '')}"


def sweep_mailboxes():
    """Destroy every mailbox still standing. Best effort, never raises.

    Asks the hub first (the real teardown path, so tombstones and directory
    delisting happen as they would in production), then removes the container
    directly in case the hub is down or already forgot it.
    """
    for phone in list(_PROVISIONED):
        try:
            httpx.delete(f"{HUB}/v1/mailbox", headers=phone.auth, timeout=30)
        except Exception:
            pass  # hub unreachable — the docker fallback below still applies
        subprocess.run(["docker", "rm", "-f", _container_name(phone.stonechat_id)],
                       capture_output=True)
        _PROVISIONED.remove(phone)
    # Mailbox-host guests are named differently (mailbox_host/main.py) and are
    # not always in _PROVISIONED — a redeem or a direct provision leaves no hub
    # row at all — so sweep them by their label instead of by owner.
    hosted = subprocess.run(
        ["docker", "ps", "-aq", "--filter", "label=stonechat.hosted=1"],
        capture_output=True, text=True).stdout.split()
    if hosted:
        subprocess.run(["docker", "rm", "-f", *hosted], capture_output=True)
    MailboxHostUnderTest.stop()


class MailboxHostUnderTest:
    """The shared tier, run for real: mailbox_host/main.py in managed mode.

    Started by this script rather than assumed to be running, because the shared
    tier *is* this program now (hub/app/providers/mailbox_host.py drives it), and
    standing in a fake for it would test the fake. It gets a temp state directory
    — fresh TLS keypair and DB every run — and a guest port range of its own.

    The hub under test must already list it in STONECHAT_MAILBOX_HOSTS; only the
    hub's own env can do that, so the values here are fixed rather than
    negotiated.
    """

    proc: subprocess.Popen | None = None
    state: str | None = None

    @classmethod
    def start(cls) -> None:
        if cls.proc is not None:
            return
        cls.state = tempfile.mkdtemp(prefix="stonechat-e2e-mailbox-host-")
        env = {
            **os.environ,
            "STONECHAT_MAILBOX_HOST_ADMIN_TOKEN": MAILBOX_HOST_TOKEN,
            "STONECHAT_MAILBOX_HOST_ADVERTISE_HOST": "127.0.0.1",
            "STONECHAT_MAILBOX_HOST_MANAGED": "1",
            "STONECHAT_MAILBOX_HOST_PORT": str(MAILBOX_HOST_PORT),
            "STONECHAT_MAILBOX_HOST_DB": f"{cls.state}/mailbox_host.db",
            "STONECHAT_MAILBOX_HOST_TLS_DIR": cls.state,
            "STONECHAT_MAILBOX_HOST_RELAY_DIR": cls.state,
            # Clear of the ephemeral ports the local provider picks.
            "STONECHAT_MAILBOX_HOST_PORT_BASE": "42200",
            "STONECHAT_MAILBOX_HOST_CAPACITY": "4",
            # Managed mode refuses a floating tag (it cannot say which relay its
            # customers run), so name the image the local provider already built
            # from this checkout.
            "STONECHAT_MAILBOX_HOST_IMAGE": image_tag(),
        }
        cls.proc = subprocess.Popen(
            [sys.executable, str(MAILBOX_HOST_MAIN)], env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if cls.proc.poll() is not None:
                err = (cls.proc.stderr.read() or b"").decode()[-800:]
                raise SystemExit(f"mailbox host exited at startup:\n{err}")
            try:
                if MX.get(f"{MAILBOX_HOST_URL}/health").status_code == 200:
                    print(f"  mailbox host up on {MAILBOX_HOST_URL} (managed mode)")
                    return
            except httpx.HTTPError:
                pass
            time.sleep(0.5)
        raise SystemExit(f"mailbox host never answered on {MAILBOX_HOST_URL}")

    @classmethod
    def admin(cls, method: str, path: str, **kw):
        return MX.request(
            method, f"{MAILBOX_HOST_URL}{path}",
            headers={"Authorization": f"Bearer {MAILBOX_HOST_TOKEN}"}, **kw,
        )

    @classmethod
    def stop(cls) -> None:
        if cls.proc is None:
            return
        cls.proc.terminate()
        try:
            cls.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            cls.proc.kill()
        cls.proc = None
        shutil.rmtree(cls.state or "", ignore_errors=True)


class Phone:
    def __init__(self, name):
        self.name = name
        self.identity = SigningKey.generate()  # Ed25519
        self.pubkey_b64 = b64(bytes(self.identity.verify_key))
        self.stonechat_id = None
        self.token = None
        self.mailbox = None
        # (peer stonechat_id, device) -> ratchet state. Keyed by device
        # because a double ratchet is mutable state that advances on every
        # message: two of a peer's devices cannot share one.
        # Everything defaults to device 1, so single-device
        # flows read exactly as before.
        # Which device of its owner this Phone is. make_envelope stamps it
        # into from_device and the AEAD binds it, so a Phone cannot claim to
        # be a device it is not.
        self.device = PRIMARY_DEVICE
        self.sessions = {}
        self.spk = None  # {"id", "priv", "pub"}
        self.opks = {}  # id -> priv bytes
        self.kspk = None  # {"id", "seed", "pub"} — ML-KEM-768 signed prekey
        self.kopks = {}  # id -> 64-byte seed
        self._next_prekey_id = 1
        self.derive_pq()

    def derive_pq(self):
        """This device's OWN keys. Envelopes are sealed to dev_seal_pk and
        this device's prekeys are signed by dev_sig — neither is the
        identity, which only signs the certificate tying them to this SC-
        ID. Re-call after replacing self.identity (echo_bot restore path)."""
        if not hasattr(self, "dev_sig"):
            self.dev_sig = SigningKey.generate()
            self.dev_seal_seed = nacl_random(32)
        self.dev_seal_pk = pqcore.xwing_pk_from_seed(self.dev_seal_seed)
        self.cert = None
        # The version of our device manifest, stated in every envelope we
        # send; 0 until one is published.
        if not hasattr(self, "manifest_version"):
            self.manifest_version = 0

    # -- hub -----------------------------------------------------------

    def sign_cert_for(self, sig_pub: bytes, seal_pub: bytes,
                      device=PRIMARY_DEVICE, not_after=None):
        """The identity root vouching for a device's keys.

        Only a device holding the root can do this, which is the whole bound
        on a linked device: it receives a certificate over the public keys it
        showed in its QR, and can neither extend it nor mint another."""
        cert = {
            "stonechat_id": self.stonechat_id,
            "device_id": device,
            "sig_pub": b64(sig_pub),
            "seal_pub": b64(seal_pub),
            "not_after": not_after or int(time.time()) + 365 * 24 * 3600,
        }
        cert["sig"] = b64(self.identity.sign(
            DEVCERT_SIG_CONTEXT + devcert_signing_bytes(cert)).signature)
        return cert

    def sign_own_cert(self, device=PRIMARY_DEVICE, not_after=None):
        """The primary certifying itself — the one device that can."""
        self.cert = self.sign_cert_for(
            bytes(self.dev_sig.verify_key), self.dev_seal_pk,
            device=device, not_after=not_after)
        return self.cert

    def publish_devices(self, devices: dict[int, bytes] | None = None) -> dict:
        """Sign and publish the manifest of our devices (PROTOCOL.md "Device
        manifest"): by default just this one, as a single-device identity has.
        Numbered past whatever the directory already holds, as a primary
        restored from an export must."""
        devices = devices or {self.device: bytes(self.dev_sig.verify_key)}
        current = resolve_directory(self.stonechat_id).get("devices")
        version = max(self.manifest_version, current["version"] if current else 0) + 1
        manifest = sign_devices_manifest(self.identity, self.stonechat_id, version, devices)
        r = httpx.post(f"{HUB}/v1/devices", headers=self.auth, json=manifest, timeout=10)
        r.raise_for_status()
        self.manifest_version = version
        return manifest

    def register(self):
        # Proof of possession, as /v1/recover: a signature over the context
        # and the current unix time, so a key one merely knows cannot be
        # registered and its account token held.
        now = int(time.time())
        sig = self.identity.sign(REGISTER_SIG_CONTEXT + str(now).encode()).signature
        r = httpx.post(f"{HUB}/v1/register", json={
            "pubkey": self.pubkey_b64,
            "timestamp": now,
            "signature": b64(sig),
        })
        r.raise_for_status()
        data = r.json()
        self.stonechat_id, self.token = data["stonechat_id"], data["account_token"]
        expected = stonechat_id_from_pubkey(bytes(self.identity.verify_key))
        assert self.stonechat_id == expected, "mailbox-derived ID != client-derived ID"
        assert "handle" not in data, "handles were removed; register must not return one"
        print(f"  {self.name}: {self.stonechat_id}")

    @property
    def auth(self):
        return {"Authorization": f"Bearer {self.token}"}

    def file_report(self, reported_id, category="harassment", note="e2e",
                    evidence=None, hub=None):
        """Report another user (PROTOCOL.md "Reporting"). Mirrors what the
        Flutter client's CryptoService.signReport builds — no account token is
        sent, because a report is judged by the hub hosting the *reported*
        account, which with cross-hub resolution is not necessarily ours."""
        timestamp = int(time.time())
        digest = hashlib.blake2b(
            category.encode() + b"\x1f" + note.encode() + b"\x1f"
            + (evidence or "").encode(), digest_size=32).digest()
        material = (b"stonechat-v1-report" + reported_id.encode()
                    + str(timestamp).encode() + digest)
        return httpx.post(f"{hub or HUB}/v1/report", json={
            "reported_id": reported_id,
            "reporter_pubkey": self.pubkey_b64,
            "timestamp": timestamp,
            "category": category,
            "note": note,
            "evidence": evidence,
            "signature": b64(self.identity.sign(material).signature),
        })

    def provision(self, country=None, body=None):
        """Ignite this phone's mailbox.

        With `country`, sends the app's own request shape and lets the hub
        resolve it against the catalog and this account's plan — that is the
        path a real device takes, so smoke_prod exercises it rather than a
        test-only one. With `body`, sends that request verbatim (the
        shared-tier case). Without either, the local Docker provider the e2e run wants.

        Every success is recorded for sweep_mailboxes(), so a later assertion
        failure cannot leave the container running.
        """
        body = body or (
            {"country": country}
            if country
            else {
                "provider": "local",
                "machine": {"machine_type": "container", "region": "localhost"},
            }
        )
        r = httpx.post(f"{HUB}/v1/mailbox", headers=self.auth, json=body)
        r.raise_for_status()
        if self not in _PROVISIONED:
            _PROVISIONED.append(self)

    def wait_running(self, timeout=300):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            r = httpx.get(f"{HUB}/v1/mailbox", headers=self.auth)
            r.raise_for_status()
            s = r.json()
            if s["status"] == "running":
                self.mailbox = s
                print(f"  {self.name} relay: {s['address']}")
                return
            if s["status"] == "error":
                raise RuntimeError(f"provisioning failed: {s['error']}")
            time.sleep(2)
        raise TimeoutError("relay never became running")

    # -- prekeys -------------------------------------------------------------------

    def upload_prekeys(self, opk_count=8):
        if self.spk is None:
            kp = PrivateKey.generate()
            self.spk = {"id": self._next_prekey_id, "priv": bytes(kp),
                        "pub": bytes(kp.public_key)}
            self._next_prekey_id += 1
        if self.kspk is None:
            seed, pub = pqcore.mlkem_keygen()
            self.kspk = {"id": self._next_prekey_id, "seed": seed, "pub": pub}
            self._next_prekey_id += 1
        new_opks = []
        for _ in range(opk_count):
            kp = PrivateKey.generate()
            self.opks[self._next_prekey_id] = bytes(kp)
            new_opks.append({"id": self._next_prekey_id, "pub": b64(bytes(kp.public_key))})
            self._next_prekey_id += 1
        new_kopks = []
        for _ in range(opk_count):
            seed, pub = pqcore.mlkem_keygen()
            self.kopks[self._next_prekey_id] = seed
            new_kopks.append({"id": self._next_prekey_id, "pub": b64(pub)})
            self._next_prekey_id += 1
        # Signed by the DEVICE key. Senders check these against the key this
        # device's certificate names, not against the identity.
        sig = self.dev_sig.sign(SPK_SIG_CONTEXT + self.spk["pub"]).signature
        ksig = self.dev_sig.sign(KSPK_SIG_CONTEXT + self.kspk["pub"]).signature
        r = MX.post(
            f"{self.mailbox['address']}/prekeys",
            params={"token": self.mailbox["mailbox_token"]},
            json={"spk": {"id": self.spk["id"], "pub": b64(self.spk["pub"]),
                          "sig": b64(sig)},
                  "opks": new_opks,
                  "kspk": {"id": self.kspk["id"], "pub": b64(self.kspk["pub"]),
                           "sig": b64(ksig)},
                  "kopks": new_kopks,
                  # The certificate goes up with the prekeys: it names the key
                  # that signed them, so one without the other leaves a peer
                  # unable to check either.
                  "cert": self.cert or self.sign_own_cert()},
        )
        r.raise_for_status()

    def publish_wt_certs(self):
        """The owner vouching for the mailbox's browser-transport schedule.

        The relay states which short-lived WebTransport certificates it will
        present; only the owner can say the list is theirs. Without this the
        directory serves nothing and a browser cannot pin — which is the safe
        failure, not a broken one."""
        r = MX.get(f"{self.mailbox['address']}/wt/certs")
        if r.status_code == 404:
            return None  # browser transport disabled on this relay
        r.raise_for_status()
        certs = r.json()["certs"]
        sig = self.identity.sign(
            WTCERTS_SIG_CONTEXT + wtcerts_signing_bytes(certs)).signature
        httpx.post(f"{HUB}/v1/mailbox/wt", headers=self.auth,
                   json={"certs": certs, "wt_sig": b64(sig)}).raise_for_status()
        return certs

    def publish_tls_sig(self):
        """The owner's half of pinned TLS: confirm the fingerprint the control
        plane observed matches the live certificate, sign it, publish."""
        record = httpx.get(f"{HUB}/v1/mailbox", headers=self.auth).json()
        fp = record["tls_fp"]
        assert fp == live_cert_fp(self.mailbox["address"]), \
            "hub fp must match the certificate the relay serves"
        sig = self.identity.sign(TLS_SIG_CONTEXT + unb64(fp)).signature
        httpx.post(f"{HUB}/v1/mailbox/tls", headers=self.auth,
                   json={"tls_fp": fp, "tls_sig": b64(sig)}).raise_for_status()

    # -- sessions --------------------------------------------------------------------

    def _initiate_session(self, to: "Phone", device: int = PRIMARY_DEVICE,
                          bundle_token: str | None = None):
        """Fetch the peer's bundle from their mailbox, verify, run PQXDH.

        A sibling device needs *that device's* prekeys: the unauthenticated
        bundle is device 1's by design, so anything else goes through
        ?device= with the peer's bundle token."""
        if device == PRIMARY_DEVICE:
            r = MX.get(f"{to.mailbox['address']}/prekeys/bundle")
        else:
            assert bundle_token, "a sibling device needs the peer's bundle token"
            r = MX.get(f"{to.mailbox['address']}/prekeys/bundle",
                       params={"device": device, "token": bundle_token})
        r.raise_for_status()
        bundle = r.json()
        # Two steps, and the order is the whole point: the certificate is
        # checked against the peer's IDENTITY key (which their SC- ID commits
        # to), and the prekeys are then checked against the DEVICE key that
        # certificate names.
        cert = bundle.get("cert")
        assert cert, "no certificate for that device — nothing to encrypt to"
        verify_devcert(cert, unb64(to.pubkey_b64), device=device)
        # Record it on the peer: wrap() needs the certified seal key on every
        # send, not just the first, and a remote peer (echo_bot's Peer) has no
        # other way to learn it. Verified immediately above, so what is cached
        # is never unchecked.
        to.cert = cert
        device_ed = VerifyKey(unb64(cert["sig_pub"]))
        # And PQXDH runs between those same two device keys — the third and
        # last place the identity secret used to be load-bearing. Nothing an
        # ordinary send touches needs the identity secret now; it is a root
        # that signs certificates and nothing else.
        spk_pub = unb64(bundle["spk"]["pub"])
        device_ed.verify(SPK_SIG_CONTEXT + spk_pub, unb64(bundle["spk"]["sig"]))
        kspk_pub = unb64(bundle["kspk"]["pub"])
        device_ed.verify(KSPK_SIG_CONTEXT + kspk_pub, unb64(bundle["kspk"]["sig"]))

        ikx_priv = bytes(self.dev_sig.to_curve25519_private_key())
        peer_ikx = bytes(device_ed.to_curve25519_public_key())
        ek = PrivateKey.generate()
        dhs = [
            crypto_scalarmult(ikx_priv, spk_pub),
            crypto_scalarmult(bytes(ek), peer_ikx),
            crypto_scalarmult(bytes(ek), spk_pub),
        ]
        opk = bundle.get("opk")
        if opk:
            dhs.append(crypto_scalarmult(bytes(ek), unb64(opk["pub"])))
        # KEM half of PQXDH: one-time prekey when available, else the signed
        # last-resort key (same degradation story as the missing opk).
        kopk = bundle.get("kopk")
        kem_pub = unb64(kopk["pub"]) if kopk else kspk_pub
        kct, kem_ss = pqcore.mlkem_encaps(kem_pub)
        sk = H(b"".join(dhs) + kem_ss, X3DH_KDF_KEY, 32)

        ratchet = PrivateKey.generate()
        rk, cks = kdf_rk(sk, crypto_scalarmult(bytes(ratchet), spk_pub))
        self.sessions[(to.stonechat_id, device)] = {
            "rk": rk, "dhs_priv": bytes(ratchet), "dhs_pub": bytes(ratchet.public_key),
            "dhr": spk_pub, "cks": cks, "ckr": None,
            "ns": 0, "nr": 0, "pn": 0, "skipped": {}, "confirmed": False,
            "initiated": True,
            "pending_x3dh": {
                # Our DEVICE key, plus the certificate that vouches for it —
                # the responder cannot check a device key against an SC- ID,
                # so the proof has to travel with the handshake.
                "ik": b64(bytes(self.dev_sig.verify_key)),
                "cert": self.cert or self.sign_own_cert(self.device),
                "ek": b64(bytes(ek.public_key)),
                "spk_id": bundle["spk"]["id"],
                **({"opk_id": opk["id"]} if opk else {}),
                "kct": b64(kct),
                "kem_id": kopk["id"] if kopk else bundle["kspk"]["id"],
                "kem_one_time": bool(kopk),
            },
        }

    def _respond_session(self, envelope: dict):
        """Responder PQXDH from an initial envelope's x3dh block."""
        block = envelope["x3dh"]
        # Two checks in place of the old "does this key hash to the sender's
        # ID": the certificate against the identity key their ID does commit
        # to, then the handshake key against what the certificate vouches for.
        # Skipping the second would make the certificate decoration.
        cert = block.get("cert")
        assert cert, "initial envelope must carry the sender's device certificate"
        sender_identity = unb64(resolve_directory(envelope["from"])["pubkey"])
        verify_devcert(cert, sender_identity,
                       device=envelope.get("from_device", PRIMARY_DEVICE))
        assert cert["sig_pub"] == block["ik"], \
            "x3dh key is not the one its certificate vouches for"
        sender_ed = VerifyKey(unb64(block["ik"]))
        assert block["spk_id"] == self.spk["id"]
        ek_pub = unb64(block["ek"])
        sender_ikx = bytes(sender_ed.to_curve25519_public_key())
        my_ikx = bytes(self.dev_sig.to_curve25519_private_key())
        dhs = [
            crypto_scalarmult(self.spk["priv"], sender_ikx),
            crypto_scalarmult(my_ikx, ek_pub),
            crypto_scalarmult(self.spk["priv"], ek_pub),
        ]
        opk_id = block.get("opk_id")
        if opk_id is not None:
            dhs.append(crypto_scalarmult(self.opks[opk_id], ek_pub))
        if block["kem_one_time"]:
            kem_seed = self.kopks[block["kem_id"]]
        else:
            assert block["kem_id"] == self.kspk["id"]
            kem_seed = self.kspk["seed"]
        kem_ss = pqcore.mlkem_decaps(kem_seed, unb64(block["kct"]))
        sk = H(b"".join(dhs) + kem_ss, X3DH_KDF_KEY, 32)
        state = {
            "rk": sk, "dhs_priv": self.spk["priv"], "dhs_pub": self.spk["pub"],
            "dhr": None, "cks": None, "ckr": None,
            "ns": 0, "nr": 0, "pn": 0, "skipped": {}, "confirmed": True,
            "initiated": False,
            "pending_x3dh": None,
        }
        kopk_id = block["kem_id"] if block["kem_one_time"] else None
        return state, opk_id, kopk_id

    def make_envelope(self, to: "Phone", type_: str, payload: dict,
                      envelope_id=None, blob_id=None,
                      device=PRIMARY_DEVICE, bundle_token=None) -> dict:
        """The inner envelope: session-encrypted payload + routing fields.
        Only the recipient ever sees this — it travels inside wrap().

        One copy per recipient device, each on its own ratchet: a logical
        message to a peer with k devices is k of these."""
        if (to.stonechat_id, device) not in self.sessions:
            self._initiate_session(to, device, bundle_token)
        state = self.sessions[(to.stonechat_id, device)]
        meta = {
            "from": self.stonechat_id,
            "from_device": self.device,
            "to": to.stonechat_id,
            "device": device,
            "type": type_,
        }
        sealed = session_encrypt(state, json.dumps(payload).encode(), meta)
        envelope = {
            "v": 1,
            "id": envelope_id or str(uuid.uuid4()),
            "type": type_,
            "from": self.stonechat_id,
            "from_device": self.device,
            "to": to.stonechat_id,
            "device": device,
            "sent_at": datetime.now(timezone.utc).isoformat(),
            **({"manifest_v": self.manifest_version} if self.manifest_version else {}),
            **sealed,
        }
        if state["pending_x3dh"]:
            envelope["x3dh"] = state["pending_x3dh"]
        if blob_id:
            envelope["blob_id"] = blob_id
        return envelope

    def wrap(self, to: "Phone", inner: dict) -> dict:
        """The wire form (PROTOCOL.md "Envelope"): an anonymous hybrid seal
        (X-Wing) to the recipient DEVICE's certified seal key — not to the
        one identity key in the directory, which nothing seals to since
        device certificates. The mailbox sees only the recipient.
        Wire: kem_ct || nonce || aead_ct, over the inner envelope padded
        to its size bucket."""
        seal_pk = unb64(to.cert["seal_pub"]) if to.cert else to.dev_seal_pk
        kct, ss = pqcore.xwing_encaps(seal_pk)
        key = H(ss, HSEAL_KDF_KEY, 32)
        nonce = nacl_random(24)
        box = crypto_aead_xchacha20poly1305_ietf_encrypt(
            pad(json.dumps(inner).encode()), HSEAL_AD, nonce, key)
        outer = {
            "v": 1,
            "id": inner["id"],
            "to": inner["to"],
            # Routing: which of the recipient's queues this belongs in.
            "device": inner["device"],
            "sealed": b64(kct + nonce + box),
        }
        if "blob_id" in inner:
            outer["blob_id"] = inner["blob_id"]
        return outer

    def seal(self, to: "Phone", type_: str, payload: dict,
             envelope_id=None, blob_id=None,
             device=PRIMARY_DEVICE, bundle_token=None) -> dict:
        return self.wrap(to, self.make_envelope(
            to, type_, payload, envelope_id=envelope_id, blob_id=blob_id,
            device=device, bundle_token=bundle_token))

    def unseal(self, outer: dict) -> dict:
        """Recover the inner envelope from a sealed wire envelope."""
        sealed = unb64(outer["sealed"])
        kct, nonce, box = (sealed[:pqcore.XWING_CT],
                           sealed[pqcore.XWING_CT:pqcore.XWING_CT + 24],
                           sealed[pqcore.XWING_CT + 24:])
        # Opened with THIS DEVICE's seal seed. It used to be the identity's,
        # which is why every device needed the identity secret to read.
        key = H(pqcore.xwing_decaps(self.dev_seal_seed, kct), HSEAL_KDF_KEY, 32)
        return json.loads(unpad(
            crypto_aead_xchacha20poly1305_ietf_decrypt(box, HSEAL_AD, nonce, key)))

    def check_envelope(self, inner: dict, wire: dict | None) -> None:
        """What a recipient checks before an envelope touches a session
        (PROTOCOL.md "Envelope"). All of it is about the unsealed form, which
        anyone holding this device's PUBLIC seal key can produce — so none of
        it is authenticated yet, and none of it may be acted on."""
        if not is_wire_id(inner.get("id")):
            raise Rejected("envelope id is not a UUID")
        if inner.get("blob_id") is not None and not is_wire_id(inner["blob_id"]):
            raise Rejected("envelope blob_id is not a UUID")
        if wire is not None and inner["id"] != wire.get("id"):
            # One id names a message everywhere: it is what gets acked, stored
            # and receipted. The mailbox only ever saw the outer one.
            raise Rejected("inner id differs from the id on the wire")
        if inner.get("to") != self.stonechat_id:
            raise Rejected("envelope is addressed to somebody else")
        for field in ("from_device", "device"):
            if type(inner.get(field)) is not int:
                raise Rejected(f"envelope {field} is missing or not an integer")
        if not isinstance(inner.get("from"), str) or not isinstance(inner.get("type"), str):
            raise Rejected("envelope from/type is missing")

    def open_envelope(self, envelope: dict, sender: "Phone",
                      wire: dict | None = None) -> dict:
        """Decrypt an envelope, sealed or already unsealed. `wire` is the
        sealed form it arrived in, for a caller that unsealed it itself.
        Raises Rejected for anything a client must drop."""
        if "sealed" in envelope:
            wire = envelope
            envelope = self.unseal(envelope)
        self.check_envelope(envelope, wire)
        # Which of the sender's ratchets wrote this. AEAD-bound, so a
        # relabelled envelope simply fails to decrypt.
        key = (envelope["from"], envelope["from_device"])
        state = self.sessions.get(key)
        if state is not None:
            try:
                trial = copy.deepcopy(state)
                plain = session_decrypt(trial, envelope)
                self.sessions[key] = trial
                return json.loads(plain)
            except Exception:
                if "x3dh" not in envelope:
                    raise
        fresh, opk_id, kopk_id = self._respond_session(envelope)
        plain = session_decrypt(fresh, envelope)
        if opk_id is not None:
            del self.opks[opk_id]  # one-time means one time
        if kopk_id is not None:
            del self.kopks[kopk_id]  # one-time means one time
        self.sessions[key] = fresh
        return json.loads(plain)

    # -- transport --------------------------------------------------------------------

    def deliver_to(self, to: "Phone", envelope: dict):
        r = MX.post(f"{to.mailbox['address']}/inbox", json=envelope)
        r.raise_for_status()

    async def receive_one(self, timeout=15, process=None) -> dict:
        """Receive one envelope, run `process(envelope)` BEFORE acking (the
        app does the same: persist/download first, ack last), then ack."""
        url = self.mailbox["address"].replace("http", "ws") + f"/ws?token={self.mailbox['mailbox_token']}"
        async with websockets.connect(url, ssl=WS_SSL) as ws:
            raw = await asyncio.wait_for(ws.recv(), timeout)
            envelope = json.loads(raw)
            if process:
                process(envelope)
            await ws.send(json.dumps({"ack": envelope["id"]}))
            await asyncio.sleep(0.3)  # let the ack land before closing
            return envelope

    def queue_depth(self):
        return MX.get(f"{self.mailbox['address']}/status",
                      params={"token": self.mailbox["mailbox_token"]}).json()["queued"]

    def destroy(self):
        r = httpx.delete(f"{HUB}/v1/mailbox", headers=self.auth, timeout=30)
        r.raise_for_status()
        if self in _PROVISIONED:
            _PROVISIONED.remove(self)


def main():
    from stub_gate import StubGate  # scripts/, next to this file

    gate = StubGate(GATE_TOKEN, {GATE_CODE: "mailbox"}).serve(GATE_PORT)
    threading.Thread(target=gate.serve_forever, daemon=True).start()

    alice, bob = Phone("alice"), Phone("bob")

    print("1) register")
    alice.register()
    bob.register()

    print("2) directory lookup + commitment check")
    entry = resolve_directory(bob.stonechat_id)
    assert entry["pubkey"] == bob.pubkey_b64
    # A directory that lies. The hub under test is honest, so the lie is made
    # here: each of these is an answer a hostile hub could give to "who is
    # Bob?", and each must be refused.
    alices = httpx.get(f"{HUB}/v1/directory/{alice.stonechat_id}").json()
    for lie, why in [
        (alices, "somebody else's record, complete and self-consistent"),
        ({**entry, "pubkey": alices["pubkey"]}, "Bob's ID over another key"),
        ({**alices, "stonechat_id": bob.stonechat_id}, "another record relabelled"),
        ({**entry, "mailbox": {"address": "https://203.0.113.9:8080",
                               "tls_fp": b64(nacl_random(32)),
                               "tls_sig": b64(nacl_random(64))}},
         "a mailbox the owner did not vouch for"),
    ]:
        try:
            check_directory_entry(bob.stonechat_id, lie)
        except Rejected:
            continue
        raise AssertionError(f"a lying directory was believed: {why}")
    print("  ok   four lying answers refused")
    assert stonechat_id_from_pubkey(base64.b64decode(entry["pubkey"])) == bob.stonechat_id
    # The record is the identity key and what the owner signed, nothing an
    # identity-level KEM key would add: envelopes go to device keys.
    assert "pq_pk" not in entry and "pq_sig" not in entry
    assert entry["mailbox"] is None

    print("2a2) registration rejects a key its holder did not sign for")
    mallory, eve = Phone("mallory"), Phone("eve")
    now = int(time.time())
    sig_by_other_key = mallory.identity.sign(
        REGISTER_SIG_CONTEXT + str(now).encode()).signature
    r = httpx.post(f"{HUB}/v1/register", json={
        "pubkey": eve.pubkey_b64,
        "timestamp": now,
        "signature": b64(sig_by_other_key),
    })
    assert r.status_code == 401, f"forged registration: expected 401, got {r.status_code}"
    stale = now - 600
    r = httpx.post(f"{HUB}/v1/register", json={
        "pubkey": eve.pubkey_b64,
        "timestamp": stale,
        "signature": b64(eve.identity.sign(
            REGISTER_SIG_CONTEXT + str(stale).encode()).signature),
    })
    assert r.status_code == 400, f"stale registration: expected 400, got {r.status_code}"
    lower = bob.stonechat_id.lower().replace("-", "")
    assert httpx.get(f"{HUB}/v1/directory/{lower}").status_code == 200, "sloppy input should normalize"
    assert "handle" not in entry, "directory must not return a handle"

    print("2b) lookup is ID-only — no enumerable handle namespace")
    assert httpx.get(f"{HUB}/v1/directory/zn-palm-dog-cherry").status_code == 400, \
        "handle-form lookups must be rejected, not resolved"

    print("3) provision relays (local docker)")
    alice.provision()
    bob.provision()
    alice.wait_running()
    bob.wait_running()

    print("3a) pinned TLS: owners vouch for their relays' certificates")
    # before publication the directory has the fingerprint but no signature —
    # pinning clients treat that as "no mailbox"
    entry = httpx.get(f"{HUB}/v1/directory/{bob.stonechat_id}").json()
    assert entry["mailbox"]["tls_sig"] is None
    alice.publish_tls_sig()
    bob.publish_tls_sig()
    assert_pinned(alice)
    assert_pinned(bob)

    # a signature that doesn't verify against the identity key is rejected
    wrong = alice.identity.sign(TLS_SIG_CONTEXT + b"\x00" * 32).signature
    fp = httpx.get(f"{HUB}/v1/mailbox", headers=alice.auth).json()["tls_fp"]
    r = httpx.post(f"{HUB}/v1/mailbox/tls", headers=alice.auth,
                   json={"tls_fp": fp, "tls_sig": b64(wrong)})
    assert r.status_code == 400, f"forged sig: expected 400, got {r.status_code}"
    # and so is a signature over a fingerprint that isn't this mailbox's
    other_fp = b64(b"\x11" * 32)
    sig = alice.identity.sign(TLS_SIG_CONTEXT + unb64(other_fp)).signature
    r = httpx.post(f"{HUB}/v1/mailbox/tls", headers=alice.auth,
                   json={"tls_fp": other_fp, "tls_sig": b64(sig)})
    assert r.status_code == 400, f"wrong fp: expected 400, got {r.status_code}"

    print("3a1) browser transport: the owner vouches for the cert schedule")
    # A relay's /wt/certs states which short-lived WebTransport certificates it
    # will present; it cannot vouch for them, being the thing under
    # authentication. Until the owner signs, the directory serves nothing —
    # a browser that pinned an unsigned list has pinned whatever the network
    # said (relay/src/wtcert.rs).
    entry = httpx.get(f"{HUB}/v1/directory/{alice.stonechat_id}").json()
    assert entry["mailbox"]["wt_certs"] is None, "unsigned schedule must not be served"
    certs = alice.publish_wt_certs()
    if certs is None:
        print("  --   relay has no browser transport; skipping")
    else:
        assert len(certs) >= 2, "the schedule should run ahead of the live cert"
        entry = httpx.get(f"{HUB}/v1/directory/{alice.stonechat_id}").json()
        served = entry["mailbox"]["wt_certs"]
        assert served == certs, "the directory must serve exactly what was signed"
        VerifyKey(unb64(alice.pubkey_b64)).verify(
            WTCERTS_SIG_CONTEXT + wtcerts_signing_bytes(served),
            unb64(entry["mailbox"]["wt_sig"]))
        # Every certificate is inside the browser's 14-day cap, and the
        # schedule reaches months ahead so rotation needs no network.
        for c in served:
            assert c["not_after"] - c["not_before"] <= 14 * 86400, "over the browser cap"
        horizon = (max(c["not_after"] for c in served) - int(time.time())) / 86400
        assert horizon > 90, f"only {horizon:.0f} days of pins published"
        print(f"  ok   {len(certs)} pins signed, {horizon:.0f} days ahead, all ≤14d")

        # And somewhere to send them. Not derivable from the mailbox address:
        # container providers map a *random* host port for each, so a mailbox
        # at 1.2.3.4:49173 says nothing about where its QUIC listener landed.
        wt_address = entry["mailbox"]["wt_address"]
        assert wt_address, "a provisioned mailbox must publish its browser transport"
        wt_host, wt_port = wt_address.rsplit(":", 1)
        assert 0 < int(wt_port) <= 65535, wt_address
        assert wt_address != alice.mailbox["address"].removeprefix("https://"), \
            "the browser transport is a separate port, not the mailbox's"
        # It really is listening: QUIC is UDP, and an unbound port answers
        # nothing at all.
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.settimeout(1)
        try:
            probe.sendto(b"\x00", (wt_host, int(wt_port)))
        finally:
            probe.close()
        print(f"  ok   browser transport published at {wt_address}")

        # Tampering is caught by the hub as well as by clients. Truncation is
        # the one worth naming: dropping the future certificates would strand
        # a client on the current one, which is the one an attacker holding it
        # wants them stuck with.
        for name, mutated in (
            ("truncated", certs[:-1]),
            ("reordered", list(reversed(certs))),
            ("tampered", [{**certs[0], "sha256": b64(b"\x11" * 32)}] + certs[1:]),
        ):
            r = httpx.post(f"{HUB}/v1/mailbox/wt", headers=alice.auth,
                           json={"certs": mutated,
                                 "wt_sig": b64(alice.identity.sign(
                                     WTCERTS_SIG_CONTEXT
                                     + wtcerts_signing_bytes(certs)).signature)})
            assert r.status_code == 400, f"{name}: expected 400, got {r.status_code}"
        # And a schedule signed by somebody else.
        r = httpx.post(f"{HUB}/v1/mailbox/wt", headers=alice.auth,
                       json={"certs": certs,
                             "wt_sig": b64(bob.identity.sign(
                                 WTCERTS_SIG_CONTEXT
                                 + wtcerts_signing_bytes(certs)).signature)})
        assert r.status_code == 400, f"foreign sig: expected 400, got {r.status_code}"
        print("  ok   truncated / reordered / tampered / foreign signatures refused")

    print("3a2) publish prekeys — mailboxes serve public halves only")
    alice.upload_prekeys()
    bob.upload_prekeys()
    health = MX.get(f"{bob.mailbox['address']}/status",
                    params={"token": bob.mailbox["mailbox_token"]}).json()
    assert health["prekeys"]["spk"] is True
    assert health["prekeys"]["kspk"] is True
    opks_before = health["prekeys"]["opks"]
    assert opks_before == 8
    assert health["prekeys"]["kopks"] == 8

    print("3b) mailbox-host provider: plan-gated, container-per-user on a shared host")
    MailboxHostUnderTest.start()
    # Managed hosts answer to the hub alone. An invite door left open there would
    # put mailboxes on ports the hub believes are free.
    r = MailboxHostUnderTest.admin("POST", "/v1/invite", json={"uses": 1})
    assert r.status_code == 403, f"managed host must refuse invites, got {r.status_code}"

    carol = Phone("carol")
    carol.register()
    shared_req = {"provider": "mailbox_host",
                  "machine": {"machine_type": "container",
                              "region": shared_country(HUB)}}

    # gated providers 402 until the gate grants the tier (PROTOCOL.md "Gate")
    access = httpx.get(f"{HUB}/v1/access", headers=carol.auth).json()
    assert access["gated"] is True, (
        f"hub is not gated — start it with STONECHAT_GATE_URL="
        f"http://127.0.0.1:{GATE_PORT} STONECHAT_GATE_TOKEN={GATE_TOKEN}")
    assert access["tier"] is None
    r = httpx.post(f"{HUB}/v1/mailbox", headers=carol.auth, json=shared_req)
    assert r.status_code == 402, f"no tier: expected 402, got {r.status_code}"
    assert r.json()["detail"]["code"] == "access_required"
    assert r.json()["detail"]["tier_required"] == "mailbox"

    # a claim is forwarded to the gate, and its refusals come back verbatim
    r = httpx.post(f"{HUB}/v1/access/claim", headers=carol.auth,
                   json={"code": "NOT-A-CODE"})
    assert r.status_code == 404, f"bad code: expected 404, got {r.status_code}"
    assert r.json()["detail"]["code"] == "invalid_code"
    r = httpx.post(f"{HUB}/v1/access/claim", headers=carol.auth,
                   json={"code": GATE_CODE})
    assert r.status_code == 200, f"claim failed ({r.status_code}): {r.text}"
    access = httpx.get(f"{HUB}/v1/access", headers=carol.auth).json()
    assert access["tier"] == "mailbox" and access["status"] == "active"
    r = httpx.post(f"{HUB}/v1/access/claim", headers=carol.auth,
                   json={"code": GATE_CODE})
    assert r.status_code == 409, f"re-claim: expected 409, got {r.status_code}"

    carol.provision(body=shared_req)
    carol.wait_running()
    assert MX.get(f"{carol.mailbox['address']}/owner",
                  params={"stonechat_id": carol.stonechat_id}).status_code == 200, \
        "mailbox must confirm its own owner"
    assert MX.get(f"{carol.mailbox['address']}/owner",
                  params={"stonechat_id": "SC-NOT-THE-OWNER"}).status_code == 404, \
        "mailbox must not confirm a stranger's ID (no address→identity leak)"

    # The hub's token is the mailbox's token: the host must have used the one it
    # was handed, not minted its own, or the app holds a token nobody accepts.
    assert MX.get(f"{carol.mailbox['address']}/status",
                  params={"token": carol.mailbox["mailbox_token"]}).status_code == 200, \
        "the mailbox must accept the token the hub stored for it"

    hosted = MailboxHostUnderTest.admin("GET", "/v1/guests").json()
    assert [g["owner_id"] for g in hosted["guests"]] == [carol.stonechat_id], hosted
    assert hosted["managed"] is True and hosted["capacity"] == 4

    # A relay release: upload, then roll. The binary here is the one the mailbox
    # is ALREADY running, pulled back out of its own container — a laptop has no
    # musl artifact, and the assertion that matters does not need one. It is that
    # the build id the host computes from the bytes equals the build the relay
    # reports for itself on /status, which is the whole basis of the roll's
    # verify-rather-than-assume check (mailbox_host/main.py _roll_guest).
    container = subprocess.run(
        ["docker", "ps", "--filter", "label=stonechat.hosted=1", "--format", "{{.Names}}"],
        capture_output=True, text=True, check=True).stdout.split()[0]
    with tempfile.TemporaryDirectory() as td:
        local = f"{td}/stonechat-relay"
        subprocess.run(["docker", "cp", f"{container}:/stonechat-relay", local],
                       capture_output=True, check=True)
        payload = pathlib.Path(local).read_bytes()
    want_build = hashlib.blake2b(payload, digest_size=32).hexdigest()[:16]
    r = MailboxHostUnderTest.admin("POST", "/v1/relay", content=payload, timeout=180)
    r.raise_for_status()
    assert r.json()["build"] == want_build, r.json()
    state = MailboxHostUnderTest.admin("GET", "/v1/relay").json()
    assert state["installed_build"] == want_build, state
    assert state["guests"] == [{"owner_id": carol.stonechat_id, "build": want_build}], \
        f"the relay's own /status build must match the uploaded artifact: {state}"
    # Rolling onto the build it already runs is a no-op the host recognises,
    # which exercises the probe without bouncing the mailbox.
    rolled = MailboxHostUnderTest.admin(
        "POST", "/v1/relay/roll", json={"dry_run": False}, timeout=180).json()
    assert rolled["stopped"] is False and rolled["build"] == want_build, rolled
    assert all(item["ok"] for item in rolled["rolled"]), rolled
    # A managed host with no relay installed refuses to guess; one WITH a pinned
    # binary launches new guests from it. Only the second half is asserted here —
    # the first would need a second host.
    assert MailboxHostUnderTest.admin("GET", "/v1/relay").json()["image"] == \
        f"stonechat-relay:{want_build}"

    carol.destroy()
    assert httpx.get(f"{HUB}/v1/mailbox", headers=carol.auth).json()["status"] == "none"
    # Destroying through the hub must actually evict on the host, or the next
    # placement reads a stale occupancy and the container lingers holding a port.
    assert MailboxHostUnderTest.admin("GET", "/v1/guests").json()["guests"] == [], \
        "the hub's destroy must evict the guest on the mailbox host"

    print("3c) external relay: bring-your-own mailbox, token stays client-side")
    dave = Phone("dave")
    dave.register()
    dave_token = "dave-keeps-this-token-himself"
    cid = subprocess.run(
        ["docker", "run", "-d", "-p", "0:8080",
         "-e", f"STONECHAT_OWNER_ID={dave.stonechat_id}",
         "-e", f"STONECHAT_OWNER_TOKEN={dave_token}",
         # The tag the local provider builds. Named through image_tag() rather
         # than spelled out, so it follows STONECHAT_RELAY_BINARY the way every
         # provider does — a hardcoded tag here went stale once already.
         image_tag()],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    try:
        port = subprocess.run(
            ["docker", "port", cid, "8080"], capture_output=True, text=True, check=True
        ).stdout.strip().splitlines()[0].rsplit(":", 1)[1]
        dave_address = f"https://127.0.0.1:{port}"
        for _ in range(30):  # wait for the container to come up
            try:
                if MX.get(f"{dave_address}/health", timeout=2).status_code == 200:
                    break
            except httpx.HTTPError:
                time.sleep(0.5)

        # impersonation rejected: eve cannot claim dave's relay
        eve = Phone("eve")
        eve.register()
        r = httpx.post(f"{HUB}/v1/mailbox/external", headers=eve.auth,
                       json={"address": dave_address})
        assert r.status_code == 400, f"expected 400, got {r.status_code}"

        # dave registers his own relay; only the address reaches the directory
        r = httpx.post(f"{HUB}/v1/mailbox/external", headers=dave.auth,
                       json={"address": dave_address})
        r.raise_for_status()
        record = httpx.get(f"{HUB}/v1/mailbox", headers=dave.auth).json()
        assert record["provider"] == "external" and record["mailbox_token"] is None
        entry = httpx.get(f"{HUB}/v1/directory/{dave.stonechat_id}").json()
        assert entry["mailbox"]["address"] == dave_address
        dave.mailbox = {"address": dave_address, "mailbox_token": dave_token,
                       "status": "running"}

        # and he's a full participant: TLS vouched, prekeys up, alice
        # delivers, dave receives
        dave.publish_tls_sig()
        assert_pinned(dave)
        dave.upload_prekeys()
        alice.deliver_to(dave, alice.seal(dave, "msg", {"text": "hi dave"}))
        got = asyncio.run(dave.receive_one())
        assert dave.open_envelope(got, alice) == {"text": "hi dave"}

        # disconnect = directory delisting only (no provider destroy)
        httpx.delete(f"{HUB}/v1/mailbox", headers=dave.auth).raise_for_status()
        entry = httpx.get(f"{HUB}/v1/directory/{dave.stonechat_id}").json()
        assert entry["mailbox"] is None
        assert MX.get(f"{dave_address}/health").status_code == 200, \
            "dave's own mailbox must keep running after disconnect"
    finally:
        subprocess.run(["docker", "rm", "-f", cid], capture_output=True)

    print("3d) invite-hosted mailbox: host a friend on your own box")
    mh_dir = pathlib.Path(__file__).resolve().parents[1] / "mailbox_host"
    mh_admin = "e2e-mailbox-host-admin"
    mh_port = "8290"
    mh_data = tempfile.mkdtemp()
    mh_url = f"https://127.0.0.1:{mh_port}"
    mh_proc = subprocess.Popen(
        [sys.executable, str(mh_dir / "main.py")],
        env={**os.environ,
             "STONECHAT_MAILBOX_HOST_ADMIN_TOKEN": mh_admin,
             "STONECHAT_MAILBOX_HOST_ADVERTISE_HOST": "127.0.0.1",
             "STONECHAT_MAILBOX_HOST_PORT": mh_port,
             "STONECHAT_MAILBOX_HOST_DB": os.path.join(mh_data, "mailbox_host.db"),
             "STONECHAT_MAILBOX_HOST_TLS_DIR": mh_data,
             # The image the local provider built from this checkout. Without
             # this the host falls back to pulling ghcr.io/stonechat-app/relay,
             # so the test depends on a published artifact and fails with a
             # `docker pull` denial on any machine that cannot fetch it.
             "STONECHAT_MAILBOX_HOST_IMAGE": image_tag()},
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    admin_hdr = {"Authorization": f"Bearer {mh_admin}"}
    try:
        for _ in range(30):
            try:
                if MX.get(f"{mh_url}/health", timeout=2).status_code == 200:
                    break
            except httpx.HTTPError:
                time.sleep(0.5)

        # admin auth is enforced on invite minting
        assert MX.post(f"{mh_url}/v1/invite", json={"uses": 1}).status_code == 401

        # host-owner mints a single-use invite
        r = MX.post(f"{mh_url}/v1/invite", headers=admin_hdr,
                    json={"uses": 1, "ttl_hours": 24})
        r.raise_for_status()
        blob = r.json()["invite"]
        assert blob.startswith("stonechat-host:")
        invite = json.loads(base64.urlsafe_b64decode(blob.split(":", 1)[1] + "=="))
        assert invite["f"] == live_cert_fp(mh_url), \
            "invite must pin the mailbox host's real certificate"

        # a bad token is rejected
        assert MX.post(f"{mh_url}/v1/redeem",
                       json={"invite": "not-a-real-invite-token",
                             "owner_id": "SC-" + "A" * 36}
                       ).status_code == 403

        # frank redeems it -> a mailbox on the host-owner's box
        frank = Phone("frank")
        frank.register()
        r = MX.post(f"{mh_url}/v1/redeem",
                    json={"invite": invite["t"], "owner_id": frank.stonechat_id})
        r.raise_for_status()
        hosted = r.json()
        assert hosted["tls_fp"] == live_cert_fp(hosted["address"]), \
            "redeem fingerprint must match the guest mailbox's live cert"

        # frank connects it exactly like a self-hosted relay: the hub
        # proves ownership via /owner, the token never leaves frank's device
        frank.mailbox = {"address": hosted["address"],
                        "mailbox_token": hosted["mailbox_token"], "status": "running"}
        httpx.post(f"{HUB}/v1/mailbox/external", headers=frank.auth,
                   json={"address": hosted["address"]}).raise_for_status()
        frank.publish_tls_sig()
        assert_pinned(frank)
        frank.upload_prekeys()

        # full participant: alice messages frank on his friend-hosted mailbox
        alice.deliver_to(frank, alice.seal(frank, "msg", {"text": "hi frank"}))
        got = asyncio.run(frank.receive_one())
        assert frank.open_envelope(got, alice) == {"text": "hi frank"}

        # single-use: a second redeem of the same invite fails
        grace = Phone("grace")
        grace.register()
        assert MX.post(f"{mh_url}/v1/redeem",
                       json={"invite": invite["t"], "owner_id": grace.stonechat_id}
                       ).status_code == 403, "single-use invite must not redeem twice"

        # the host-owner sees sent-invite status: who accepted, uses left
        assert MX.get(f"{mh_url}/v1/invites").status_code == 401
        r = MX.get(f"{mh_url}/v1/invites", headers=admin_hdr)
        r.raise_for_status()
        mine = [i for i in r.json()["invites"] if i["invite"] == blob]
        assert mine and mine[0]["uses"] == 1 and mine[0]["uses_left"] == 0 \
            and mine[0]["redeemed_by"] == [frank.stonechat_id], \
            "invite status must record frank's redemption"

        # host-owner evicts frank -> his container is destroyed
        MX.delete(f"{mh_url}/v1/guest/{frank.stonechat_id}",
                  headers=admin_hdr).raise_for_status()
        httpx.delete(f"{HUB}/v1/mailbox", headers=frank.auth)  # tidy the directory
    finally:
        mh_proc.terminate()
        try:
            mh_proc.wait(timeout=5)
        except Exception:
            mh_proc.kill()
        leftover = subprocess.run(
            ["docker", "ps", "-aq", "--filter", "label=stonechat.hosted=1"],
            capture_output=True, text=True).stdout.split()
        if leftover:
            subprocess.run(["docker", "rm", "-f", *leftover], capture_output=True)

    print("4) one-mailbox-per-user enforced")
    r = httpx.post(
        f"{HUB}/v1/mailbox", headers=alice.auth,
        json={"provider": "local", "machine": {"machine_type": "x", "region": "y"}},
    )
    assert r.status_code == 409, f"expected 409, got {r.status_code}"

    print("5) contact handshake = X3DH prekey message, sealed sender on the wire")
    request_inner = alice.make_envelope(bob, "contact_request", {"display_name": "Alice"})
    assert "x3dh" in request_inner, "initial envelope must carry the x3dh block"
    assert "opk_id" in request_inner["x3dh"], "bundle had one-time prekeys"
    alice.deliver_to(bob, alice.wrap(bob, request_inner))
    req = asyncio.run(bob.receive_one())
    # Sealed sender: what the mailbox stored and forwarded names only the
    # recipient and which of their devices — no from, no from_device, no
    # type, no identity key, no ratchet header. `device` is meaningful only
    # to the recipient's own mailbox, which IS their device registry, so it
    # tells an observer nothing it did not already serve.
    assert set(req) <= {"v", "id", "to", "device", "sealed", "blob_id"}, \
        f"wire envelope leaks fields beyond the recipient: {sorted(req)}"
    assert "from_device" not in req, "the sending device must stay sealed"
    assert bob.unseal(req)["type"] == "contact_request"
    assert bob.open_envelope(req, alice) == {"display_name": "Alice"}
    used_opk = request_inner["x3dh"]["opk_id"]
    assert used_opk not in bob.opks, "one-time prekey private must be consumed"

    bob.deliver_to(alice, bob.seal(alice, "contact_accept", {"display_name": "Bob"}))
    acc = asyncio.run(alice.receive_one())
    assert alice.open_envelope(acc, bob) == {"display_name": "Bob"}
    assert alice.sessions[(bob.stonechat_id, PRIMARY_DEVICE)]["confirmed"], \
        "round trip confirms the session"

    print("5b) group wire format: create + message, key commitments verify")
    group_id = str(uuid.uuid4())
    membership = {
        "group_id": group_id, "name": "e2e crew", "version": 1,
        "admin": alice.stonechat_id,
        "members": [
            {"stonechat_id": p.stonechat_id, "pubkey": p.pubkey_b64, "display_name": p.name}
            for p in (alice, bob)
        ],
    }
    alice.deliver_to(bob, alice.seal(bob, "group_create", membership))
    created = asyncio.run(bob.receive_one())
    got_membership = bob.open_envelope(created, alice)
    assert bob.unseal(created)["from"] == got_membership["admin"], \
        "admin must be the sender"
    for m in got_membership["members"]:
        derived = stonechat_id_from_pubkey(base64.b64decode(m["pubkey"]))
        assert derived == m["stonechat_id"], "member key commitment must verify"

    alice.deliver_to(bob, alice.seal(bob, "group_msg",
                                     {"group_id": group_id, "text": "hi crew"}))
    gm = asyncio.run(bob.receive_one())
    assert bob.open_envelope(gm, alice) == {"group_id": group_id, "text": "hi crew"}

    print("6) message + delete-on-ack")
    first_inner = alice.make_envelope(bob, "msg", {"text": "hello from my own relay"})
    alice.deliver_to(bob, alice.wrap(bob, first_inner))
    msg = asyncio.run(bob.receive_one())
    assert bob.open_envelope(msg, alice) == {"text": "hello from my own relay"}
    time.sleep(0.5)
    assert bob.queue_depth() == 0, "envelope should be deleted after ack"

    print("6a) forward secrecy: the ratchet turns and old keys die")
    # a reply turns the DH ratchet…
    bob.deliver_to(alice, bob.seal(alice, "msg", {"text": "roger"}))
    asyncio.run(alice.receive_one(process=lambda e: alice.open_envelope(e, bob)))
    later_inner = alice.make_envelope(bob, "msg", {"text": "post-ratchet"})
    assert later_inner["ratchet"]["dh"] != first_inner["ratchet"]["dh"], \
        "sender ratchet key must rotate after a round trip"
    alice.deliver_to(bob, alice.wrap(bob, later_inner))
    asyncio.run(bob.receive_one(process=lambda e: bob.open_envelope(e, alice)))
    # …and bob's CURRENT session state cannot decrypt the recorded envelope 6:
    # the message key that sealed it was deleted on use — compromise-now does
    # not decrypt recorded-then.
    compromised = copy.deepcopy(bob.sessions[(alice.stonechat_id, PRIMARY_DEVICE)])
    try:
        session_decrypt(compromised, first_inner)
        raise AssertionError("old ciphertext decrypted from current state — no FS!")
    except AssertionError:
        raise
    except Exception:
        pass  # expected: key material for that message no longer exists

    print("6a2) envelopes that fail the recipient's checks never reach a session")
    # Each is sealed correctly to Bob — anyone holding his public seal key can
    # do that — and each must be dropped BEFORE decryption is attempted, so a
    # hostile envelope cannot move his ratchet or name a file on his device.
    before = copy.deepcopy(bob.sessions)
    hostile_id = "../../databases/stonechat.db"
    good = alice.make_envelope(bob, "msg", {"text": "checks"})
    cases = [
        ("an id that is not a UUID",
         alice.wrap(bob, {**good, "id": hostile_id})),
        ("an inner id that differs from the wire id",
         {**alice.wrap(bob, good), "id": str(uuid.uuid4())}),
        ("a blob_id that is not a UUID",
         alice.wrap(bob, {**good, "blob_id": "../prekeys/bundle?x="})),
        ("an envelope addressed to somebody else",
         {**alice.wrap(bob, {**good, "to": alice.stonechat_id}),
          "to": bob.stonechat_id}),
        ("a missing from_device",
         alice.wrap(bob, {k: v for k, v in good.items() if k != "from_device"})),
    ]
    for what, wire in cases:
        try:
            bob.open_envelope(wire, alice)
        except Rejected:
            assert bob.sessions == before, f"{what}: the session moved"
            continue
        except Exception as e:
            raise AssertionError(f"{what}: reached the session ({e!r})")
        raise AssertionError(f"{what}: accepted")
    # …and the envelope they were all built from is still good.
    assert bob.open_envelope(alice.wrap(bob, good), alice) == {"text": "checks"}
    print(f"  ok   {len(cases)} hostile envelopes dropped, the honest one opened")

    print("6b) unsealed / wrong-version envelopes are rejected outright")
    cleartext_env = {
        "v": 1, "id": str(uuid.uuid4()), "type": "msg",
        "from": alice.stonechat_id, "to": bob.stonechat_id,
        "sent_at": datetime.now(timezone.utc).isoformat(),
        "nonce": b64(nacl_random(24)), "ciphertext": b64(nacl_random(64)),
    }
    r = MX.post(f"{bob.mailbox['address']}/inbox", json=cleartext_env)
    assert r.status_code == 400, f"expected 400 for unsealed envelope, got {r.status_code}"
    wrong_version = {"v": 2, "id": str(uuid.uuid4()), "to": bob.stonechat_id,
                     "sealed": b64(nacl_random(64))}
    r = MX.post(f"{bob.mailbox['address']}/inbox", json=wrong_version)
    assert r.status_code == 400, f"expected 400 for wrong version, got {r.status_code}"

    print("6c) one-time prekeys are consumed mailbox-side")
    ids = set()
    for _ in range(2):
        b = MX.get(f"{bob.mailbox['address']}/prekeys/bundle").json()
        assert b["opk"] is not None
        ids.add(b["opk"]["id"])
    assert len(ids) == 2, "each bundle fetch must consume a distinct OPK"

    print("6d) media blob: upload → envelope → download → decrypt → ack-deletes")
    photo = nacl_random(200_000)  # stand-in for an encrypted JPEG
    blob_key, blob_nonce = nacl_random(32), nacl_random(24)
    # Media blobs use XChaCha20-Poly1305, like every other AEAD in the
    # protocol since the stonechat-core cutover (crypto.dart sealBlob →
    # core stonechat_blob_seal); libsodium's secretbox is gone.
    sealed_blob = crypto_aead_xchacha20poly1305_ietf_encrypt(
        photo, b"", blob_nonce, blob_key)
    r = MX.post(f"{bob.mailbox['address']}/blob", content=sealed_blob, timeout=30)
    r.raise_for_status()
    blob_id = r.json()["blob_id"]

    media_env = alice.seal(bob, "media", {
        "blob_id": blob_id,
        "key": base64.b64encode(blob_key).decode(),
        "blob_nonce": base64.b64encode(blob_nonce).decode(),
        "mime": "image/jpeg", "kind": "image", "size": len(photo),
    }, blob_id=blob_id)
    alice.deliver_to(bob, media_env)

    recovered_holder = {}

    def fetch_and_decrypt(envelope):
        payload = bob.open_envelope(envelope, alice)
        dl = MX.get(
            f"{bob.mailbox['address']}/blob/{payload['blob_id']}",
            params={"token": bob.mailbox["mailbox_token"]}, timeout=30,
        )
        dl.raise_for_status()
        recovered_holder["data"] = crypto_aead_xchacha20poly1305_ietf_decrypt(
            dl.content, b"",
            base64.b64decode(payload["blob_nonce"]),
            base64.b64decode(payload["key"]),
        )

    asyncio.run(bob.receive_one(process=fetch_and_decrypt))
    assert recovered_holder["data"] == photo, "media round-trip corrupted"
    # unauthenticated download must fail; after ack the blob must be gone
    assert MX.get(f"{bob.mailbox['address']}/blob/{blob_id}").status_code == 401
    time.sleep(0.5)
    gone = MX.get(f"{bob.mailbox['address']}/blob/{blob_id}",
                  params={"token": bob.mailbox["mailbox_token"]})
    assert gone.status_code == 404, "blob should be deleted after ack"

    print("6e) group media: one shared blob on the sender's box, fetched by token")
    # Group media inverts the DM path (PROTOCOL.md "Group media"): Alice
    # uploads ONE ciphertext to her OWN mailbox and hands every member a
    # per-blob capability, instead of parking a copy on each of their boxes.
    clip = nacl_random(150_000)
    g_key, g_nonce = nacl_random(32), nacl_random(24)
    g_sealed = crypto_aead_xchacha20poly1305_ietf_encrypt(clip, b"", g_nonce, g_key)
    r = MX.post(f"{alice.mailbox['address']}/blob", params={"shared": "1"},
                content=g_sealed, timeout=30)
    r.raise_for_status()
    g_blob_id, g_token = r.json()["blob_id"], r.json()["fetch_token"]
    assert g_token and g_token != alice.mailbox["mailbox_token"], \
        "the fetch token must not be (or reveal) the owner token"

    gmedia = alice.seal(bob, "group_media", {
        "group_id": group_id,
        "blob_id": g_blob_id,
        "key": base64.b64encode(g_key).decode(),
        "blob_nonce": base64.b64encode(g_nonce).decode(),
        "fetch_token": g_token,
        "blob_host": alice.mailbox["address"],
        "blob_tls_fp": alice.mailbox["tls_fp"],
        "mime": "video/mp4", "kind": "video", "size": len(clip),
    })
    # No blob_id on the outer envelope: the blob lives on Alice's mailbox, so
    # Bob's ack must not try to garbage-collect it from his.
    assert "blob_id" not in gmedia, "group media must not hint blob_id to a member's mailbox"
    alice.deliver_to(bob, gmedia)

    shared_holder = {}

    def fetch_shared(envelope):
        payload = bob.open_envelope(envelope, alice)
        assert payload["blob_tls_fp"] == live_cert_fp(payload["blob_host"]), \
            "the quoted fingerprint must be the one the sender's box presents"
        dl = MX.get(f"{payload['blob_host']}/blob/{payload['blob_id']}",
                    params={"token": payload["fetch_token"]}, timeout=30)
        dl.raise_for_status()
        shared_holder["data"] = crypto_aead_xchacha20poly1305_ietf_decrypt(
            dl.content, b"",
            base64.b64decode(payload["blob_nonce"]),
            base64.b64decode(payload["key"]),
        )

    asyncio.run(bob.receive_one(process=fetch_shared))
    assert shared_holder["data"] == clip, "group media round-trip corrupted"

    # The capability is scoped: it opens that one blob, and it is not an
    # owner token for anything else on Alice's mailbox.
    assert MX.get(f"{alice.mailbox['address']}/blob/{g_blob_id}").status_code == 401
    assert MX.get(f"{alice.mailbox['address']}/status",
                  params={"token": g_token}).status_code == 401

    # A member's ack must NOT collect the sender's blob — she still owes it to
    # every member who hasn't fetched yet.
    time.sleep(0.5)
    assert MX.get(f"{alice.mailbox['address']}/blob/{g_blob_id}",
                  params={"token": g_token}).status_code == 200, \
        "a member's ack must not GC the sender's shared blob"

    # She reclaims it herself once everyone has it.
    assert MX.delete(f"{alice.mailbox['address']}/blob/{g_blob_id}",
                     params={"token": alice.mailbox["mailbox_token"]}).status_code == 200
    assert MX.get(f"{alice.mailbox['address']}/blob/{g_blob_id}",
                  params={"token": g_token}).status_code == 404, \
        "the capability must not outlive the blob"

    print("6f) device manifest: published, served, verified; revocation by omission")
    # Alice publishes the list of devices that speak for her: just her phone.
    published = alice.publish_devices()
    served = resolve_directory(alice.stonechat_id)["devices"]
    assert served == published, "the directory serves the manifest exactly as published"
    assert device_listed(served, PRIMARY_DEVICE, bytes(alice.dev_sig.verify_key))
    # A version that does not move forward is refused, and the hub says
    # which version stands.
    stale = sign_devices_manifest(alice.identity, alice.stonechat_id, published["version"],
                                  {PRIMARY_DEVICE: bytes(alice.dev_sig.verify_key)})
    r = httpx.post(f"{HUB}/v1/devices", headers=alice.auth, json=stale)
    assert r.status_code == 409 and r.json()["detail"]["current"] == published["version"]
    # What a lying directory could serve: a device added after signing, a
    # device dropped, another identity's manifest under Alice's name.
    laptop_key = bytes(SigningKey.generate().verify_key)
    for name, forged in {
        "added device": {**served, "devices": served["devices"]
                         + [{"device_id": 2, "sig_pub": b64(laptop_key)}]},
        "dropped device": {**served, "devices": []},
        "bob's signature": sign_devices_manifest(bob.identity, alice.stonechat_id, 99,
                                                 {1: bytes(alice.dev_sig.verify_key)}),
    }.items():
        try:
            check_directory_entry(alice.stonechat_id,
                                  {**resolve_directory(alice.stonechat_id), "devices": forged})
        except Rejected:
            pass
        else:
            raise AssertionError(f"a manifest with {name} was accepted")
    # Alice links a laptop (version 2), then revokes it (version 3): to a
    # contact, the laptop is a device she vouched for and then stopped
    # vouching for, whatever her relay says.
    alice.publish_devices({PRIMARY_DEVICE: bytes(alice.dev_sig.verify_key), 2: laptop_key})
    assert device_listed(resolve_directory(alice.stonechat_id)["devices"], 2, laptop_key)
    alice.publish_devices()
    after = resolve_directory(alice.stonechat_id)["devices"]
    assert after["version"] == 3 and not device_listed(after, 2, laptop_key), \
        "a revoked device is one the manifest no longer lists"
    assert not device_listed(after, PRIMARY_DEVICE, laptop_key), \
        "a slot is listed with its key, not with any key"
    # And every envelope Alice sends now says which manifest she holds.
    stated = alice.make_envelope(bob, "msg", {"text": "v"})
    assert stated["manifest_v"] == 3, "envelopes state the sender's manifest version"
    assert bob.open_envelope(stated, alice) == {"text": "v"}

    print("7) wrong recipient rejected by mailbox")
    r = MX.post(
        f"{bob.mailbox['address']}/inbox",
        json=alice.seal(alice, "msg", {"text": "misrouted"}),
    )
    assert r.status_code == 403, f"expected 403, got {r.status_code}"

    print("8) offline queueing (no ws connected)")
    alice.deliver_to(bob, alice.seal(bob, "msg", {"text": "while you were out"}))
    assert bob.queue_depth() == 1
    queued = asyncio.run(bob.receive_one())  # drains on connect
    assert bob.open_envelope(queued, alice)["text"] == "while you were out"
    time.sleep(0.5)
    assert bob.queue_depth() == 0

    push_gateway = os.environ.get("STONECHAT_TEST_PUSH_GATEWAY")
    if push_gateway:
        print("8b) offline owner triggers a content-free gateway ping")
        r = MX.post(
            f"{bob.mailbox['address']}/push-config",
            params={"token": bob.mailbox["mailbox_token"]},
            json={"device_token": "e2e-test-token-bob", "platform": "ios"},
        )
        r.raise_for_status()
        alice.deliver_to(bob, alice.seal(bob, "msg", {"text": "wake up"}))
        deadline = time.monotonic() + 10
        seen = False
        while time.monotonic() < deadline and not seen:
            pings = httpx.get(f"{push_gateway}/v1/debug/pings").json()
            seen = any(p["device_token"] == "e2e-test-token-bob" for p in pings)
            time.sleep(0.5)
        assert seen, "gateway never received the wake-up ping"
        asyncio.run(bob.receive_one(
            process=lambda e: bob.open_envelope(e, alice)))  # drain before teardown

    print("8b) abuse actions: whois → destroy → ban")
    # The abuse-desk reply templates promise "we can destroy any individual
    # customer's machine immediately". This is that promise, exercised against
    # a real container — an abuse report carries an IP and nothing else, so the
    # whole chain starts from one.
    admin_hdr = {"X-Admin-Token": ADMIN_TOKEN}
    mallory = Phone("mallory")
    mallory.register()
    mallory.provision()
    mallory.wait_running()
    host = urlsplit(mallory.mailbox["address"]).hostname

    # admin surface is closed without the token — no anonymous mailbox enumeration
    assert httpx.get(f"{HUB}/v1/admin/whois", params={"host": host}).status_code == 403
    assert httpx.get(f"{HUB}/v1/admin/whois", params={"host": host},
                     headers={"X-Admin-Token": "wrong"}).status_code == 403

    r = httpx.get(f"{HUB}/v1/admin/whois", params={"host": host}, headers=admin_hdr)
    r.raise_for_status()
    hit = next(s for s in r.json()["mailboxes"] if s["stonechat_id"] == mallory.stonechat_id)
    assert hit["provider"] == "local" and hit["prior_destroys"] == 0
    assert hit["banned_at"] is None
    assert "mailbox_token" not in r.text and "mailbox_host_token" not in r.text, \
        "triage output must not hand back credentials"

    # exact host match, not a substring: 27.0.0.1 must not resolve to 127.0.0.1's
    # owner, or a malformed report destroys the wrong customer's mailbox
    r = httpx.get(f"{HUB}/v1/admin/whois", params={"host": host[1:]}, headers=admin_hdr)
    assert r.json()["mailboxes"] == [], "substring matched — wrong customer at risk"

    # ban shuts BOTH provisioning doors; the external one is the cheap bypass
    r = httpx.post(f"{HUB}/v1/admin/users/{mallory.stonechat_id}/ban",
                   headers=admin_hdr, json={"reason": "e2e: phishing report"})
    r.raise_for_status()
    r = httpx.post(f"{HUB}/v1/mailbox", headers=mallory.auth,
                   json={"provider": "local",
                         "machine": {"machine_type": "x", "region": "y"}})
    assert r.status_code == 403, f"banned /v1/mailbox: expected 403, got {r.status_code}"
    assert r.json()["detail"]["code"] == "account_suspended"
    r = httpx.post(f"{HUB}/v1/mailbox/external", headers=mallory.auth,
                   json={"address": "https://198.51.100.9:8443"})
    assert r.status_code == 403, \
        f"banned /v1/mailbox/external: expected 403, got {r.status_code}"

    # ...but a ban is narrow: it refuses infrastructure, it does not erase the
    # account. Making "banned" and "never existed" the same state would be a
    # censorship lever the hub shouldn't have.
    assert httpx.get(f"{HUB}/v1/mailbox", headers=mallory.auth).status_code == 200
    assert httpx.get(f"{HUB}/v1/directory/{mallory.stonechat_id}").status_code == 200

    r = httpx.post(f"{HUB}/v1/admin/mailboxes/{mallory.stonechat_id}/destroy",
                   headers=admin_hdr, json={"reason": "e2e: provider case 12345"})
    r.raise_for_status()
    assert httpx.get(f"{HUB}/v1/mailbox", headers=mallory.auth).json()["status"] == "none"
    assert httpx.get(f"{HUB}/v1/directory/{mallory.stonechat_id}").json()["mailbox"] is None
    try:
        MX.get(f"{mallory.mailbox['address']}/health", timeout=3)
        raise AssertionError("mailbox still answering after destroy")
    except httpx.HTTPError:
        pass  # container is gone, not merely delisted
    r = httpx.post(f"{HUB}/v1/admin/mailboxes/{mallory.stonechat_id}/destroy",
                   headers=admin_hdr, json={"reason": "e2e: repeat"})
    assert r.status_code == 404, f"second destroy: expected 404, got {r.status_code}"

    # unban reopens the door, and the tombstone outlives the machine — that
    # history is what tells a first offence from a pattern on the next report
    httpx.post(f"{HUB}/v1/admin/users/{mallory.stonechat_id}/unban",
               headers=admin_hdr).raise_for_status()
    mallory.provision()
    mallory.wait_running()
    r = httpx.get(f"{HUB}/v1/admin/whois",
                  params={"host": urlsplit(mallory.mailbox["address"]).hostname},
                  headers=admin_hdr)
    hit = next(s for s in r.json()["mailboxes"] if s["stonechat_id"] == mallory.stonechat_id)
    assert hit["prior_destroys"] == 1, "tombstone did not survive the destroy"
    assert hit["banned_at"] is None
    mallory.destroy()

    r = httpx.post(f"{HUB}/v1/admin/users/SC-NOBODY/ban",
                   headers=admin_hdr, json={"reason": "e2e: unknown"})
    assert r.status_code == 404, f"unknown ID ban: expected 404, got {r.status_code}"

    print("8c) user reports: signed filing → triage queue → resolve")
    # App Store Guideline 1.2 in one flow. The property under test is that a
    # report authenticates by *signature*, so it works across a hub
    # boundary where the reporter has no account — and that message plaintext
    # only ever appears when the reporter attached it.
    r = alice.file_report(mallory.stonechat_id, note="e2e: unsolicited messages")
    assert r.status_code == 202, f"report: expected 202, got {r.status_code} {r.text}"
    ref = r.json()["report_id"]

    # a tampered body must not verify under the original signature
    timestamp = int(time.time())
    digest = hashlib.blake2b(b"harassment\x1fe2e\x1f", digest_size=32).digest()
    good = alice.identity.sign(
        b"stonechat-v1-report" + mallory.stonechat_id.encode()
        + str(timestamp).encode() + digest).signature
    r = httpx.post(f"{HUB}/v1/report", json={
        "reported_id": mallory.stonechat_id, "reporter_pubkey": alice.pubkey_b64,
        "timestamp": timestamp, "category": "harassment",
        "note": "something the reporter never wrote", "evidence": None,
        "signature": b64(good)})
    assert r.status_code == 401, f"tampered note: expected 401, got {r.status_code}"

    # reporting yourself, and reporting into a hub that does not host you
    assert alice.file_report(alice.stonechat_id).status_code == 400
    stranger = stonechat_id_from_pubkey(bytes(SigningKey.generate().verify_key))
    r = alice.file_report(stranger)
    assert r.status_code == 404 and r.json()["detail"]["code"] == "not_our_account", \
        "a report about an account we don't host must say so, not vanish"

    # a second, independent reporter — distinct reporters is the triage signal
    evidence = json.dumps({"v": 1, "messages": [
        {"sent_at": 1, "kind": "text", "text": "e2e attached message"}]})
    r = bob.file_report(mallory.stonechat_id, category="spam",
                        note="e2e: with transcript", evidence=evidence)
    assert r.status_code == 202, r.text

    # the queue is closed without the admin token
    assert httpx.get(f"{HUB}/v1/admin/reports").status_code == 403
    r = httpx.get(f"{HUB}/v1/admin/reports", headers=admin_hdr)
    r.raise_for_status()
    all_open = r.json()["reports"]
    # Scoped to *this run's* subject. The hub DB persists across runs, and a
    # count over the whole queue made the second run of the day fail with
    # "expected 2, got 3" — a fixture problem that reads exactly like a bug in
    # the thing under test.
    queue = [row for row in all_open if row["reported_id"] == mallory.stonechat_id]
    assert len(queue) == 2, f"expected 2 open reports for mallory, got {len(queue)}"
    assert all("evidence" not in row for row in all_open), \
        "the list view must not spill attached plaintext"

    r = httpx.get(f"{HUB}/v1/admin/reports/{ref}", headers=admin_hdr)
    r.raise_for_status()
    detail = r.json()
    assert detail["report"]["evidence"] is None, \
        "an unattached report must carry no message content"
    assert detail["reported"]["distinct_reporters"] == 2, detail["reported"]
    assert detail["reported"]["prior_destroys"] == 1, \
        "triage must see the abuse history alongside the report"

    # resolving records the decision and drops the evidence with it
    with_evidence = next(row for row in queue if row["evidence_bytes"] > 0)
    r = httpx.post(f"{HUB}/v1/admin/reports/{with_evidence['id']}/resolve",
                   headers=admin_hdr,
                   json={"status": "actioned", "resolution": "e2e: destroyed"})
    r.raise_for_status()
    r = httpx.get(f"{HUB}/v1/admin/reports/{with_evidence['id']}", headers=admin_hdr)
    assert r.json()["report"]["evidence"] is None, \
        "attached plaintext must not outlive the decision it informed"
    assert r.json()["report"]["status"] == "actioned"
    # Again scoped to this run's subject: one of mallory's two is resolved.
    still_open = [
        row
        for row in httpx.get(f"{HUB}/v1/admin/reports", headers=admin_hdr).json()["reports"]
        if row["reported_id"] == mallory.stonechat_id
    ]
    assert len(still_open) == 1, f"expected 1 still open, got {len(still_open)}"

    print("9) destroy relays")
    alice.destroy()
    bob.destroy()
    assert httpx.get(f"{HUB}/v1/mailbox", headers=alice.auth).json()["status"] == "none"
    entry = httpx.get(f"{HUB}/v1/directory/{bob.stonechat_id}").json()
    assert entry["mailbox"] is None

    print("10) delete an account")
    def deletion(phone, context=b"stonechat-v1-delete"):
        timestamp = int(time.time())
        sig = phone.identity.sign(context + str(timestamp).encode()).signature
        return httpx.post(f"{HUB}/v1/account/delete", headers=phone.auth,
                          json={"timestamp": timestamp, "signature": b64(sig)})
    # the token alone is not enough, and a signature for another purpose
    # must not stand in for this one
    assert deletion(bob, b"stonechat-v1-recover").status_code == 401
    assert httpx.get(f"{HUB}/v1/directory/{bob.stonechat_id}").status_code == 200
    r = deletion(bob)
    assert r.status_code == 200, r.text
    assert httpx.get(f"{HUB}/v1/directory/{bob.stonechat_id}").status_code == 404, \
        "a deleted account must leave the directory"
    assert httpx.get(f"{HUB}/v1/mailbox", headers=bob.auth).status_code == 401, \
        "a deleted account's token must stop working"

    print("\nALL E2E CHECKS PASSED")


if __name__ == "__main__":
    try:
        main()
    finally:
        sweep_mailboxes()
