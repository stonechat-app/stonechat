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
import socket
import ssl
import subprocess
import sys
import tempfile
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
# must match the STONECHAT_ADMIN_TOKEN / STONECHAT_TEST_CODE the hub was started with (README)
ADMIN_TOKEN = os.environ.get("STONECHAT_ADMIN_TOKEN", "test-admin")
TEST_CODE = os.environ.get("STONECHAT_TEST_CODE", "STONECHAT-TEST-TEST")

# Mailbox client: no CA validation (self-signed by design); see module docstring.
MX = httpx.Client(verify=False, timeout=10)
WS_SSL = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
WS_SSL.check_hostname = False
WS_SSL.verify_mode = ssl.CERT_NONE

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1] / "hub"))
from app.identity import stonechat_id_from_pubkey  # noqa: E402

TLS_SIG_CONTEXT = b"stonechat-v1-tls"
WTCERTS_SIG_CONTEXT = b"stonechat-v1-wtcerts"


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


def assert_pinned(phone: "Phone") -> None:
    """The full client-side transport check: directory fp is vouched for by
    the owner's identity key AND matches the certificate actually served."""
    entry = httpx.get(f"{HUB}/v1/directory/{phone.stonechat_id}").json()
    srv = entry["server"]
    VerifyKey(base64.b64decode(entry["pubkey"])).verify(
        TLS_SIG_CONTEXT + base64.b64decode(srv["tls_fp"]),
        base64.b64decode(srv["tls_sig"]),
    )
    assert srv["tls_fp"] == live_cert_fp(srv["address"]), \
        "served certificate must match the owner-signed fingerprint"


# -- session crypto (PROTOCOL.md) ----------------------------------------------

import pqcore  # noqa: E402  (scripts/pqcore.py — ctypes over the Rust core)

X3DH_KDF_KEY = b"stonechat-v1-pqxdh-kdf"
SPK_SIG_CONTEXT = b"stonechat-v1-spk"
KSPK_SIG_CONTEXT = b"stonechat-v1-kspk"
PQPK_SIG_CONTEXT = b"stonechat-v1-pqpk"
PQID_SEED_KEY = b"stonechat-v1-pqidseed"
HSEAL_KDF_KEY = b"stonechat-v1-hsealkdf"
HSEAL_AD = b"stonechat-v1-hseal"
MAX_SKIP = 256


def H(msg: bytes, key: bytes, n: int) -> bytes:
    return hashlib.blake2b(msg, key=key, digest_size=n).digest()


def kdf_rk(rk: bytes, dh: bytes) -> tuple[bytes, bytes]:
    out = H(dh, rk, 64)
    return out[:32], out[32:]


def kdf_ck(ck: bytes) -> tuple[bytes, bytes]:
    return H(b"\x01", ck, 32), H(b"\x02", ck, 32)  # (mk, ck')


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def unb64(s: str) -> bytes:
    return base64.b64decode(s)


PRIMARY_DEVICE = 1
DEVCERT_SIG_CONTEXT = b"stonechat-v1-devcert"


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
    assert cert["not_after"] > (now or int(time.time())), "certificate expired"
    if device is not None:
        assert cert["device_id"] == device, \
            "certificate names a different device than the slot it came in"


def ad_for(envelope: dict) -> bytes:
    """Both device numbers are bound (MULTIDEVICE.md "Associated data") — one
    form, always, so a relabelled envelope simply fails to decrypt."""
    r = envelope["ratchet"]
    return (
        f"stonechat/v1|{envelope['from']}|{envelope['from_device']}"
        f"|{envelope['to']}|{envelope['device']}|{envelope['type']}"
        f"|{r['dh']}|{r['pn']}|{r['n']}"
    ).encode()


def session_encrypt(state: dict, plaintext: bytes, meta: dict) -> dict:
    """meta = {from,from_device,to,device,type}. Returns the ratchet/nonce/
    ciphertext fields. The AD is built by the same rule as ad_for() — one
    form, both device numbers bound."""
    mk, state["cks"] = kdf_ck(state["cks"])
    header = {"dh": b64(state["dhs_pub"]), "pn": state["pn"], "n": state["ns"]}
    state["ns"] += 1
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


def _dh_ratchet(state: dict, header_dh: bytes) -> None:
    state["pn"], state["ns"], state["nr"] = state["ns"], 0, 0
    state["dhr"] = header_dh
    state["rk"], state["ckr"] = kdf_rk(
        state["rk"], crypto_scalarmult(state["dhs_priv"], header_dh))
    fresh = PrivateKey.generate()
    state["dhs_priv"], state["dhs_pub"] = bytes(fresh), bytes(fresh.public_key)
    state["rk"], state["cks"] = kdf_rk(
        state["rk"], crypto_scalarmult(state["dhs_priv"], header_dh))


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
            _dh_ratchet(state, header_dh)
        _skip_keys(state, header["n"])
        mk, state["ckr"] = kdf_ck(state["ckr"])
        state["nr"] += 1
        plain = crypto_aead_xchacha20poly1305_ietf_decrypt(ct, ad, nonce, mk)
    state["confirmed"] = True
    state["pending_x3dh"] = None
    return plain


# -- a simulated phone -----------------------------------------------------------


class Phone:
    def __init__(self, name):
        self.name = name
        self.identity = SigningKey.generate()  # Ed25519
        self.pubkey_b64 = b64(bytes(self.identity.verify_key))
        self.stonechat_id = None
        self.token = None
        self.server = None
        # (peer stonechat_id, device) -> ratchet state. Keyed by device
        # because a double ratchet is mutable state that advances on every
        # message: two of a peer's devices cannot share one
        # (MULTIDEVICE.md). Everything defaults to device 1, so single-device
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
        """The X-Wing identity is derived from the Ed25519 secret exactly as
        the app does (crypto.dart): seed = H(sk64, key="stonechat-v1-pqidseed").
        Re-call after replacing self.identity (echo_bot restore path)."""
        sk64 = bytes(self.identity) + bytes(self.identity.verify_key)
        self.pq_seed = H(sk64, PQID_SEED_KEY, 32)
        self.pq_pk = pqcore.xwing_pk_from_seed(self.pq_seed)
        self.pq_pk_b64 = b64(self.pq_pk)
        # This device's OWN keys (MULTIDEVICE_IMPLEMENTATION.md "How device
        # certificates work"). Envelopes are sealed to dev_seal_pk and this
        # device's prekeys are signed by dev_sig — neither is the identity,
        # which now only signs the certificate tying them to this SC- ID.
        if not hasattr(self, "dev_sig"):
            self.dev_sig = SigningKey.generate()
            self.dev_seal_seed = nacl_random(32)
        self.dev_seal_pk = pqcore.xwing_pk_from_seed(self.dev_seal_seed)
        self.cert = None

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

    def register(self):
        pq_sig = self.identity.sign(PQPK_SIG_CONTEXT + self.pq_pk).signature
        r = httpx.post(f"{HUB}/v1/register", json={
            "pubkey": self.pubkey_b64,
            "pq_pk": self.pq_pk_b64,
            "pq_sig": b64(pq_sig),
        })
        r.raise_for_status()
        data = r.json()
        self.stonechat_id, self.token = data["stonechat_id"], data["account_token"]
        expected = stonechat_id_from_pubkey(bytes(self.identity.verify_key))
        assert self.stonechat_id == expected, "server-derived ID != client-derived ID"
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

    def provision(self):
        r = httpx.post(
            f"{HUB}/v1/server",
            headers=self.auth,
            json={
                "provider": "local",
                "machine": {"machine_type": "container", "region": "localhost"},
            },
        )
        r.raise_for_status()

    def wait_running(self, timeout=300):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            r = httpx.get(f"{HUB}/v1/server", headers=self.auth)
            r.raise_for_status()
            s = r.json()
            if s["status"] == "running":
                self.server = s
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
            f"{self.server['address']}/prekeys",
            params={"token": self.server["server_token"]},
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
        r = MX.get(f"{self.server['address']}/wt/certs")
        if r.status_code == 404:
            return None  # browser transport disabled on this relay
        r.raise_for_status()
        certs = r.json()["certs"]
        sig = self.identity.sign(
            WTCERTS_SIG_CONTEXT + wtcerts_signing_bytes(certs)).signature
        httpx.post(f"{HUB}/v1/server/wt", headers=self.auth,
                   json={"certs": certs, "wt_sig": b64(sig)}).raise_for_status()
        return certs

    def publish_tls_sig(self):
        """The owner's half of pinned TLS: confirm the fingerprint the control
        plane observed matches the live certificate, sign it, publish."""
        record = httpx.get(f"{HUB}/v1/server", headers=self.auth).json()
        fp = record["tls_fp"]
        assert fp == live_cert_fp(self.server["address"]), \
            "hub fp must match the certificate the relay serves"
        sig = self.identity.sign(TLS_SIG_CONTEXT + unb64(fp)).signature
        httpx.post(f"{HUB}/v1/server/tls", headers=self.auth,
                   json={"tls_fp": fp, "tls_sig": b64(sig)}).raise_for_status()

    # -- sessions --------------------------------------------------------------------

    def _initiate_session(self, to: "Phone", device: int = PRIMARY_DEVICE,
                          bundle_token: str | None = None):
        """Fetch the peer's bundle from their mailbox, verify, run PQXDH.

        A sibling device needs *that device's* prekeys: the unauthenticated
        bundle is device 1's by design, so anything else goes through
        ?device= with the peer's bundle token."""
        if device == PRIMARY_DEVICE:
            r = MX.get(f"{to.server['address']}/prekeys/bundle")
        else:
            assert bundle_token, "a sibling device needs the peer's bundle token"
            r = MX.get(f"{to.server['address']}/prekeys/bundle",
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
        sender_entry = httpx.get(f"{HUB}/v1/directory/{envelope['from']}").json()
        sender_identity = unb64(sender_entry["pubkey"])
        assert stonechat_id_from_pubkey(sender_identity) == envelope["from"], \
            "directory key must commit to the sender's Stonechat ID"
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
        Wire: kem_ct || nonce || aead_ct."""
        seal_pk = unb64(to.cert["seal_pub"]) if to.cert else to.dev_seal_pk
        kct, ss = pqcore.xwing_encaps(seal_pk)
        key = H(ss, HSEAL_KDF_KEY, 32)
        nonce = nacl_random(24)
        box = crypto_aead_xchacha20poly1305_ietf_encrypt(
            json.dumps(inner).encode(), HSEAL_AD, nonce, key)
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
             envelope_id=None, blob_id=None) -> dict:
        return self.wrap(to, self.make_envelope(
            to, type_, payload, envelope_id=envelope_id, blob_id=blob_id))

    def unseal(self, outer: dict) -> dict:
        """Recover the inner envelope from a sealed wire envelope."""
        sealed = unb64(outer["sealed"])
        kct, nonce, box = (sealed[:pqcore.XWING_CT],
                           sealed[pqcore.XWING_CT:pqcore.XWING_CT + 24],
                           sealed[pqcore.XWING_CT + 24:])
        # Opened with THIS DEVICE's seal seed. It used to be the identity's,
        # which is why every device needed the identity secret to read.
        key = H(pqcore.xwing_decaps(self.dev_seal_seed, kct), HSEAL_KDF_KEY, 32)
        return json.loads(
            crypto_aead_xchacha20poly1305_ietf_decrypt(box, HSEAL_AD, nonce, key))

    def open_envelope(self, envelope: dict, sender: "Phone") -> dict:
        if "sealed" in envelope:
            envelope = self.unseal(envelope)
        # Which of the sender's ratchets wrote this. AEAD-bound, so a
        # relabelled envelope simply fails to decrypt.
        key = (envelope["from"], envelope.get("from_device", PRIMARY_DEVICE))
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
        r = MX.post(f"{to.server['address']}/inbox", json=envelope)
        r.raise_for_status()

    async def receive_one(self, timeout=15, process=None) -> dict:
        """Receive one envelope, run `process(envelope)` BEFORE acking (the
        app does the same: persist/download first, ack last), then ack."""
        url = self.server["address"].replace("http", "ws") + f"/ws?token={self.server['server_token']}"
        async with websockets.connect(url, ssl=WS_SSL) as ws:
            raw = await asyncio.wait_for(ws.recv(), timeout)
            envelope = json.loads(raw)
            if process:
                process(envelope)
            await ws.send(json.dumps({"ack": envelope["id"]}))
            await asyncio.sleep(0.3)  # let the ack land before closing
            return envelope

    def queue_depth(self):
        return MX.get(f"{self.server['address']}/status",
                      params={"token": self.server["server_token"]}).json()["queued"]

    def destroy(self):
        r = httpx.delete(f"{HUB}/v1/server", headers=self.auth, timeout=30)
        r.raise_for_status()


def main():
    alice, bob = Phone("alice"), Phone("bob")

    print("1) register")
    alice.register()
    bob.register()

    print("2) directory lookup + commitment check")
    entry = httpx.get(f"{HUB}/v1/directory/{bob.stonechat_id}").json()
    assert entry["pubkey"] == bob.pubkey_b64
    assert stonechat_id_from_pubkey(base64.b64decode(entry["pubkey"])) == bob.stonechat_id
    # The X-Wing identity key rides in the directory under an Ed25519
    # signature — resolvers verify it before sealing anything to it.
    assert entry["pq_pk"] == bob.pq_pk_b64
    VerifyKey(unb64(entry["pubkey"])).verify(
        PQPK_SIG_CONTEXT + unb64(entry["pq_pk"]), unb64(entry["pq_sig"]))
    assert entry["server"] is None

    print("2a2) registration rejects a pq_pk the identity key didn't sign")
    mallory = Phone("mallory")
    sig_by_other_key = mallory.identity.sign(
        PQPK_SIG_CONTEXT + b"\x00" * 1216).signature
    r = httpx.post(f"{HUB}/v1/register", json={
        "pubkey": Phone("eve").pubkey_b64,
        "pq_pk": b64(b"\x00" * 1216),
        "pq_sig": b64(sig_by_other_key),
    })
    assert r.status_code == 400, f"forged pq_sig: expected 400, got {r.status_code}"
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
    # pinning clients treat that as "no server"
    entry = httpx.get(f"{HUB}/v1/directory/{bob.stonechat_id}").json()
    assert entry["server"]["tls_sig"] is None
    alice.publish_tls_sig()
    bob.publish_tls_sig()
    assert_pinned(alice)
    assert_pinned(bob)

    # a signature that doesn't verify against the identity key is rejected
    wrong = alice.identity.sign(TLS_SIG_CONTEXT + b"\x00" * 32).signature
    fp = httpx.get(f"{HUB}/v1/server", headers=alice.auth).json()["tls_fp"]
    r = httpx.post(f"{HUB}/v1/server/tls", headers=alice.auth,
                   json={"tls_fp": fp, "tls_sig": b64(wrong)})
    assert r.status_code == 400, f"forged sig: expected 400, got {r.status_code}"
    # and so is a signature over a fingerprint that isn't this mailbox's
    other_fp = b64(b"\x11" * 32)
    sig = alice.identity.sign(TLS_SIG_CONTEXT + unb64(other_fp)).signature
    r = httpx.post(f"{HUB}/v1/server/tls", headers=alice.auth,
                   json={"tls_fp": other_fp, "tls_sig": b64(sig)})
    assert r.status_code == 400, f"wrong fp: expected 400, got {r.status_code}"

    print("3a1) browser transport: the owner vouches for the cert schedule")
    # A relay's /wt/certs states which short-lived WebTransport certificates it
    # will present; it cannot vouch for them, being the thing under
    # authentication. Until the owner signs, the directory serves nothing —
    # a browser that pinned an unsigned list has pinned whatever the network
    # said (WEB_CLIENT.md "the code-delivery problem", relay/src/wtcert.rs).
    entry = httpx.get(f"{HUB}/v1/directory/{alice.stonechat_id}").json()
    assert entry["server"]["wt_certs"] is None, "unsigned schedule must not be served"
    certs = alice.publish_wt_certs()
    if certs is None:
        print("  --   relay has no browser transport; skipping")
    else:
        assert len(certs) >= 2, "the schedule should run ahead of the live cert"
        entry = httpx.get(f"{HUB}/v1/directory/{alice.stonechat_id}").json()
        served = entry["server"]["wt_certs"]
        assert served == certs, "the directory must serve exactly what was signed"
        VerifyKey(unb64(alice.pubkey_b64)).verify(
            WTCERTS_SIG_CONTEXT + wtcerts_signing_bytes(served),
            unb64(entry["server"]["wt_sig"]))
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
        wt_address = entry["server"]["wt_address"]
        assert wt_address, "a provisioned mailbox must publish its browser transport"
        wt_host, wt_port = wt_address.rsplit(":", 1)
        assert 0 < int(wt_port) <= 65535, wt_address
        assert wt_address != alice.server["address"].removeprefix("https://"), \
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
            r = httpx.post(f"{HUB}/v1/server/wt", headers=alice.auth,
                           json={"certs": mutated,
                                 "wt_sig": b64(alice.identity.sign(
                                     WTCERTS_SIG_CONTEXT
                                     + wtcerts_signing_bytes(certs)).signature)})
            assert r.status_code == 400, f"{name}: expected 400, got {r.status_code}"
        # And a schedule signed by somebody else.
        r = httpx.post(f"{HUB}/v1/server/wt", headers=alice.auth,
                       json={"certs": certs,
                             "wt_sig": b64(bob.identity.sign(
                                 WTCERTS_SIG_CONTEXT
                                 + wtcerts_signing_bytes(certs)).signature)})
        assert r.status_code == 400, f"foreign sig: expected 400, got {r.status_code}"
        print("  ok   truncated / reordered / tampered / foreign signatures refused")

    print("3a2) publish prekeys — mailboxes serve public halves only")
    alice.upload_prekeys()
    bob.upload_prekeys()
    health = MX.get(f"{bob.server['address']}/status",
                    params={"token": bob.server["server_token"]}).json()
    assert health["prekeys"]["spk"] is True
    assert health["prekeys"]["kspk"] is True
    opks_before = health["prekeys"]["opks"]
    assert opks_before == 8
    assert health["prekeys"]["kopks"] == 8

    print("3b) fleet provider: plan-gated, container-per-user on a shared host")
    carol = Phone("carol")
    carol.register()
    fleet_req = {"provider": "fleet",
                 "machine": {"machine_type": "container", "region": "fleet"}}

    # paid providers 402 without an entitlement (PROTOCOL.md "Billing")
    r = httpx.post(f"{HUB}/v1/server", headers=carol.auth, json=fleet_req)
    assert r.status_code == 402, f"unpaid fleet: expected 402, got {r.status_code}"
    assert r.json()["detail"]["code"] == "subscription_required"
    assert r.json()["detail"]["plan_required"] == "private"

    # comp grant → redeem → entitlement live (same path a paid code takes)
    r = httpx.post(f"{HUB}/v1/billing/comp",
                   headers={"X-Admin-Token": ADMIN_TOKEN},
                   json={"plan": "private", "note": "e2e"})
    assert r.status_code == 201, (
        f"comp grant failed ({r.status_code}) — start the hub with "
        f"STONECHAT_ADMIN_TOKEN={ADMIN_TOKEN}")
    code = r.json()["code"]
    httpx.post(f"{HUB}/v1/billing/redeem", headers=carol.auth,
               json={"code": code}).raise_for_status()
    ent = httpx.get(f"{HUB}/v1/billing/entitlement", headers=carol.auth).json()
    assert ent["plan"] == "private" and ent["status"] == "active"
    # a code is single-use
    r = httpx.post(f"{HUB}/v1/billing/redeem", headers=carol.auth,
                   json={"code": code})
    assert r.status_code == 409, f"re-redeem: expected 409, got {r.status_code}"

    # ...except STONECHAT_TEST_CODE, which works for any number of fresh identities
    # (the TestFlight reset-and-reactivate loop, PROTOCOL.md "Billing")
    for name in ("tess1", "tess2"):
        tess = Phone(name)
        tess.register()
        r = httpx.post(f"{HUB}/v1/billing/redeem", headers=tess.auth,
                       json={"code": TEST_CODE})
        assert r.status_code == 200, (
            f"test code redeem failed ({r.status_code}) — start the hub with "
            f"STONECHAT_TEST_CODE={TEST_CODE}")
        ent = httpx.get(f"{HUB}/v1/billing/entitlement",
                        headers=tess.auth).json()
        assert ent["plan"] == "private" and ent["source"] == "test"

    r = httpx.post(f"{HUB}/v1/server", headers=carol.auth, json=fleet_req)
    r.raise_for_status()
    carol.wait_running()
    assert MX.get(f"{carol.server['address']}/owner",
                  params={"stonechat_id": carol.stonechat_id}).status_code == 200, \
        "mailbox must confirm its own owner"
    assert MX.get(f"{carol.server['address']}/owner",
                  params={"stonechat_id": "SC-NOT-THE-OWNER"}).status_code == 404, \
        "mailbox must not confirm a stranger's ID (no address→identity leak)"
    carol.destroy()
    assert httpx.get(f"{HUB}/v1/server", headers=carol.auth).json()["status"] == "none"

    print("3c) external relay: bring-your-own server, token stays client-side")
    dave = Phone("dave")
    dave.register()
    dave_token = "dave-keeps-this-token-himself"
    cid = subprocess.run(
        ["docker", "run", "-d", "-p", "0:8080",
         "-e", f"STONECHAT_OWNER_ID={dave.stonechat_id}",
         "-e", f"STONECHAT_OWNER_TOKEN={dave_token}",
         "stonechat-server:dev"],
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
        r = httpx.post(f"{HUB}/v1/server/external", headers=eve.auth,
                       json={"address": dave_address})
        assert r.status_code == 400, f"expected 400, got {r.status_code}"

        # dave registers his own relay; only the address reaches the directory
        r = httpx.post(f"{HUB}/v1/server/external", headers=dave.auth,
                       json={"address": dave_address})
        r.raise_for_status()
        record = httpx.get(f"{HUB}/v1/server", headers=dave.auth).json()
        assert record["provider"] == "external" and record["server_token"] is None
        entry = httpx.get(f"{HUB}/v1/directory/{dave.stonechat_id}").json()
        assert entry["server"]["address"] == dave_address
        dave.server = {"address": dave_address, "server_token": dave_token,
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
        httpx.delete(f"{HUB}/v1/server", headers=dave.auth).raise_for_status()
        entry = httpx.get(f"{HUB}/v1/directory/{dave.stonechat_id}").json()
        assert entry["server"] is None
        assert MX.get(f"{dave_address}/health").status_code == 200, \
            "dave's own server must keep running after disconnect"
    finally:
        subprocess.run(["docker", "rm", "-f", cid], capture_output=True)

    print("3d) invite-hosted mailbox: host a friend on your own box")
    agent_dir = pathlib.Path(__file__).resolve().parents[1] / "host_agent"
    agent_admin = "e2e-agent-admin"
    agent_port = "8290"
    agent_data = tempfile.mkdtemp()
    agent_url = f"https://127.0.0.1:{agent_port}"
    agent_proc = subprocess.Popen(
        [sys.executable, str(agent_dir / "main.py")],
        env={**os.environ,
             "STONECHAT_HOST_AGENT_ADMIN_TOKEN": agent_admin,
             "STONECHAT_HOST_AGENT_ADVERTISE_HOST": "127.0.0.1",
             "STONECHAT_HOST_AGENT_PORT": agent_port,
             "STONECHAT_HOST_AGENT_DB": os.path.join(agent_data, "agent.db"),
             "STONECHAT_HOST_AGENT_TLS_DIR": agent_data},
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    admin_hdr = {"Authorization": f"Bearer {agent_admin}"}
    try:
        for _ in range(30):
            try:
                if MX.get(f"{agent_url}/health", timeout=2).status_code == 200:
                    break
            except httpx.HTTPError:
                time.sleep(0.5)

        # admin auth is enforced on invite minting
        assert MX.post(f"{agent_url}/v1/invite", json={"uses": 1}).status_code == 401

        # host-owner mints a single-use invite
        r = MX.post(f"{agent_url}/v1/invite", headers=admin_hdr,
                    json={"uses": 1, "ttl_hours": 24})
        r.raise_for_status()
        blob = r.json()["invite"]
        assert blob.startswith("stonechat-host:")
        invite = json.loads(base64.urlsafe_b64decode(blob.split(":", 1)[1] + "=="))
        assert invite["f"] == live_cert_fp(agent_url), \
            "invite must pin the host agent's real certificate"

        # a bad token is rejected
        assert MX.post(f"{agent_url}/v1/redeem",
                       json={"invite": "not-a-real-invite-token",
                             "owner_id": "SC-" + "A" * 36}
                       ).status_code == 403

        # frank redeems it -> a mailbox on the host-owner's box
        frank = Phone("frank")
        frank.register()
        r = MX.post(f"{agent_url}/v1/redeem",
                    json={"invite": invite["t"], "owner_id": frank.stonechat_id})
        r.raise_for_status()
        hosted = r.json()
        assert hosted["tls_fp"] == live_cert_fp(hosted["address"]), \
            "redeem fingerprint must match the guest mailbox's live cert"

        # frank connects it exactly like a self-hosted relay: the hub
        # proves ownership via /owner, the token never leaves frank's device
        frank.server = {"address": hosted["address"],
                        "server_token": hosted["server_token"], "status": "running"}
        httpx.post(f"{HUB}/v1/server/external", headers=frank.auth,
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
        assert MX.post(f"{agent_url}/v1/redeem",
                       json={"invite": invite["t"], "owner_id": grace.stonechat_id}
                       ).status_code == 403, "single-use invite must not redeem twice"

        # the host-owner sees sent-invite status: who accepted, uses left
        assert MX.get(f"{agent_url}/v1/invites").status_code == 401
        r = MX.get(f"{agent_url}/v1/invites", headers=admin_hdr)
        r.raise_for_status()
        mine = [i for i in r.json()["invites"] if i["invite"] == blob]
        assert mine and mine[0]["uses"] == 1 and mine[0]["uses_left"] == 0 \
            and mine[0]["redeemed_by"] == [frank.stonechat_id], \
            "invite status must record frank's redemption"

        # host-owner evicts frank -> his container is destroyed
        MX.delete(f"{agent_url}/v1/guest/{frank.stonechat_id}",
                  headers=admin_hdr).raise_for_status()
        httpx.delete(f"{HUB}/v1/server", headers=frank.auth)  # tidy the directory
    finally:
        agent_proc.terminate()
        try:
            agent_proc.wait(timeout=5)
        except Exception:
            agent_proc.kill()
        leftover = subprocess.run(
            ["docker", "ps", "-aq", "--filter", "label=stonechat.hosted=1"],
            capture_output=True, text=True).stdout.split()
        if leftover:
            subprocess.run(["docker", "rm", "-f", *leftover], capture_output=True)

    print("4) one-server-per-user enforced")
    r = httpx.post(
        f"{HUB}/v1/server", headers=alice.auth,
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

    print("6b) unsealed / wrong-version envelopes are rejected outright")
    cleartext_env = {
        "v": 1, "id": str(uuid.uuid4()), "type": "msg",
        "from": alice.stonechat_id, "to": bob.stonechat_id,
        "sent_at": datetime.now(timezone.utc).isoformat(),
        "nonce": b64(nacl_random(24)), "ciphertext": b64(nacl_random(64)),
    }
    r = MX.post(f"{bob.server['address']}/inbox", json=cleartext_env)
    assert r.status_code == 400, f"expected 400 for unsealed envelope, got {r.status_code}"
    wrong_version = {"v": 2, "id": str(uuid.uuid4()), "to": bob.stonechat_id,
                     "sealed": b64(nacl_random(64))}
    r = MX.post(f"{bob.server['address']}/inbox", json=wrong_version)
    assert r.status_code == 400, f"expected 400 for wrong version, got {r.status_code}"

    print("6c) one-time prekeys are consumed server-side")
    ids = set()
    for _ in range(2):
        b = MX.get(f"{bob.server['address']}/prekeys/bundle").json()
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
    r = MX.post(f"{bob.server['address']}/blob", content=sealed_blob, timeout=30)
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
            f"{bob.server['address']}/blob/{payload['blob_id']}",
            params={"token": bob.server["server_token"]}, timeout=30,
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
    assert MX.get(f"{bob.server['address']}/blob/{blob_id}").status_code == 401
    time.sleep(0.5)
    gone = MX.get(f"{bob.server['address']}/blob/{blob_id}",
                  params={"token": bob.server["server_token"]})
    assert gone.status_code == 404, "blob should be deleted after ack"

    print("6e) group media: one shared blob on the sender's box, fetched by token")
    # Group media inverts the DM path (PROTOCOL.md "Group media"): Alice
    # uploads ONE ciphertext to her OWN mailbox and hands every member a
    # per-blob capability, instead of parking a copy on each of their boxes.
    clip = nacl_random(150_000)
    g_key, g_nonce = nacl_random(32), nacl_random(24)
    g_sealed = crypto_aead_xchacha20poly1305_ietf_encrypt(clip, b"", g_nonce, g_key)
    r = MX.post(f"{alice.server['address']}/blob", params={"shared": "1"},
                content=g_sealed, timeout=30)
    r.raise_for_status()
    g_blob_id, g_token = r.json()["blob_id"], r.json()["fetch_token"]
    assert g_token and g_token != alice.server["server_token"], \
        "the fetch token must not be (or reveal) the owner token"

    gmedia = alice.seal(bob, "group_media", {
        "group_id": group_id,
        "blob_id": g_blob_id,
        "key": base64.b64encode(g_key).decode(),
        "blob_nonce": base64.b64encode(g_nonce).decode(),
        "fetch_token": g_token,
        "blob_host": alice.server["address"],
        "blob_tls_fp": alice.server["tls_fp"],
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
    assert MX.get(f"{alice.server['address']}/blob/{g_blob_id}").status_code == 401
    assert MX.get(f"{alice.server['address']}/status",
                  params={"token": g_token}).status_code == 401

    # A member's ack must NOT collect the sender's blob — she still owes it to
    # every member who hasn't fetched yet.
    time.sleep(0.5)
    assert MX.get(f"{alice.server['address']}/blob/{g_blob_id}",
                  params={"token": g_token}).status_code == 200, \
        "a member's ack must not GC the sender's shared blob"

    # She reclaims it herself once everyone has it.
    assert MX.delete(f"{alice.server['address']}/blob/{g_blob_id}",
                     params={"token": alice.server["server_token"]}).status_code == 200
    assert MX.get(f"{alice.server['address']}/blob/{g_blob_id}",
                  params={"token": g_token}).status_code == 404, \
        "the capability must not outlive the blob"

    print("7) wrong recipient rejected by mailbox")
    r = MX.post(
        f"{bob.server['address']}/inbox",
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
            f"{bob.server['address']}/push-config",
            params={"token": bob.server["server_token"]},
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

    print("8b) abuse actions: whois → destroy → ban (notes/docs/abuse_reply_template.md, internal)")
    # The abuse-desk reply templates promise "we can destroy any individual
    # customer's machine immediately". This is that promise, exercised against
    # a real container — an abuse report carries an IP and nothing else, so the
    # whole chain starts from one.
    admin_hdr = {"X-Admin-Token": ADMIN_TOKEN}
    mallory = Phone("mallory")
    mallory.register()
    mallory.provision()
    mallory.wait_running()
    host = urlsplit(mallory.server["address"]).hostname

    # admin surface is closed without the token — no anonymous fleet enumeration
    assert httpx.get(f"{HUB}/v1/admin/whois", params={"host": host}).status_code == 403
    assert httpx.get(f"{HUB}/v1/admin/whois", params={"host": host},
                     headers={"X-Admin-Token": "wrong"}).status_code == 403

    r = httpx.get(f"{HUB}/v1/admin/whois", params={"host": host}, headers=admin_hdr)
    r.raise_for_status()
    hit = next(s for s in r.json()["servers"] if s["stonechat_id"] == mallory.stonechat_id)
    assert hit["provider"] == "local" and hit["prior_destroys"] == 0
    assert hit["banned_at"] is None
    assert "server_token" not in r.text and "host_agent_token" not in r.text, \
        "triage output must not hand back credentials"

    # exact host match, not a substring: 27.0.0.1 must not resolve to 127.0.0.1's
    # owner, or a malformed report destroys the wrong customer's mailbox
    r = httpx.get(f"{HUB}/v1/admin/whois", params={"host": host[1:]}, headers=admin_hdr)
    assert r.json()["servers"] == [], "substring matched — wrong customer at risk"

    # ban shuts BOTH provisioning doors; the external one is the cheap bypass
    r = httpx.post(f"{HUB}/v1/admin/users/{mallory.stonechat_id}/ban",
                   headers=admin_hdr, json={"reason": "e2e: phishing report"})
    r.raise_for_status()
    r = httpx.post(f"{HUB}/v1/server", headers=mallory.auth,
                   json={"provider": "local",
                         "machine": {"machine_type": "x", "region": "y"}})
    assert r.status_code == 403, f"banned /v1/server: expected 403, got {r.status_code}"
    assert r.json()["detail"]["code"] == "account_suspended"
    r = httpx.post(f"{HUB}/v1/server/external", headers=mallory.auth,
                   json={"address": "https://198.51.100.9:8443"})
    assert r.status_code == 403, \
        f"banned /v1/server/external: expected 403, got {r.status_code}"

    # ...but a ban is narrow: it refuses infrastructure, it does not erase the
    # account. Making "banned" and "never existed" the same state would be a
    # censorship lever the hub shouldn't have.
    assert httpx.get(f"{HUB}/v1/server", headers=mallory.auth).status_code == 200
    assert httpx.get(f"{HUB}/v1/directory/{mallory.stonechat_id}").status_code == 200

    r = httpx.post(f"{HUB}/v1/admin/servers/{mallory.stonechat_id}/destroy",
                   headers=admin_hdr, json={"reason": "e2e: provider case 12345"})
    r.raise_for_status()
    assert httpx.get(f"{HUB}/v1/server", headers=mallory.auth).json()["status"] == "none"
    assert httpx.get(f"{HUB}/v1/directory/{mallory.stonechat_id}").json()["server"] is None
    try:
        MX.get(f"{mallory.server['address']}/health", timeout=3)
        raise AssertionError("mailbox still answering after destroy")
    except httpx.HTTPError:
        pass  # container is gone, not merely delisted
    r = httpx.post(f"{HUB}/v1/admin/servers/{mallory.stonechat_id}/destroy",
                   headers=admin_hdr, json={"reason": "e2e: repeat"})
    assert r.status_code == 404, f"second destroy: expected 404, got {r.status_code}"

    # unban reopens the door, and the tombstone outlives the machine — that
    # history is what tells a first offence from a pattern on the next report
    httpx.post(f"{HUB}/v1/admin/users/{mallory.stonechat_id}/unban",
               headers=admin_hdr).raise_for_status()
    mallory.provision()
    mallory.wait_running()
    r = httpx.get(f"{HUB}/v1/admin/whois",
                  params={"host": urlsplit(mallory.server["address"]).hostname},
                  headers=admin_hdr)
    hit = next(s for s in r.json()["servers"] if s["stonechat_id"] == mallory.stonechat_id)
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
    assert httpx.get(f"{HUB}/v1/server", headers=alice.auth).json()["status"] == "none"
    entry = httpx.get(f"{HUB}/v1/directory/{bob.stonechat_id}").json()
    assert entry["server"] is None

    print("\nALL E2E CHECKS PASSED")


if __name__ == "__main__":
    main()
