"""Production smoke test for the deployed hub + its mailbox hosts.

Registers a throwaway identity, claims access with the tester code, ignites a
shared-tier mailbox in a country the hub actually offers (which also proves the
hub can reach that mailbox host, pass its certificate pin and place a guest on
it), verifies the mailbox end to end, destroys it.

**Drives e2e.Phone rather than its own protocol client.** This script used to
carry a second, private implementation of registration and delivery, and it
rotted twice without anyone noticing: it kept sending pubkey-only
registrations long after the X-Wing cutover made them a 422, and device-less
envelopes after multidevice made `device` mandatory. Both were found by
running it, not by reading it. e2e.Phone is exercised by the e2e suite on
every change, so borrowing it means this script tracks the protocol for free.

Usage (the code never lives in the repo — it's GATE_TEST_CODES in the gate's env):

    STONECHAT_TEST_CODE=STONECHAT-XXXX-XXXX hub/.venv/bin/python scripts/smoke_prod.py

Env: STONECHAT_HUB (default https://hub.stonechat.app), STONECHAT_TEST_CODE
(required). Needs httpx + pynacl (both in the hub venv) and the core library
for the X-Wing identity key — `scripts/build_core.sh host` if pqcore cannot
find one.
"""
import os
import sys

# e2e reads STONECHAT_HUB at import time, so this has to land before the
# import below: the point of this script is that it targets production by
# default, where e2e defaults to a local dev hub.
os.environ.setdefault("STONECHAT_HUB", "https://hub.stonechat.app")

import httpx  # noqa: E402
import e2e  # noqa: E402  (scripts/e2e.py — the protocol client)
from e2e import MX, PRIMARY_DEVICE, Phone  # noqa: E402

HUB = e2e.HUB
TEST_CODE = os.environ.get("STONECHAT_TEST_CODE") or sys.exit(
    "set STONECHAT_TEST_CODE (a tester code from the gate's GATE_TEST_CODES)")


def shared_country() -> str:
    """A country the hub can actually place a Mailbox-plan container in.

    Read from the catalog rather than hardcoded, because the catalog is
    derived from the configured mailbox hosts — so this follows whatever the hub
    under test is wired to, and asserts that derivation on the way past.
    """
    for c in httpx.get(f"{HUB}/v1/countries").json()["countries"]:
        if "mailbox" in c["plans"]:
            return c["code"]
    raise SystemExit(
        "no country offers the mailbox plan — the hub's STONECHAT_MAILBOX_HOSTS "
        "lists no host with a country"
    )


print(f"hub: {HUB}")
phone = Phone("smoke")
phone.register()
print("registered:", phone.stonechat_id)

r = httpx.post(f"{HUB}/v1/access/claim", json={"code": TEST_CODE},
               headers=phone.auth)
r.raise_for_status()
tier = r.json()["tier"]
print("access:", tier, r.json()["status"])
assert tier == "mailbox", f"expected the mailbox tier, got {tier!r}"

country = shared_country()
print(f"igniting in {country} (the app's country form — the hub resolves it)")
phone.provision(country=country)
phone.wait_running()

srv = phone.mailbox
addr, tls_fp = srv["address"], srv["tls_fp"]
# The hub resolved country -> provider+region. Placement itself is asserted by
# the address: a mailbox host only ever advertises its own public IP.
assert srv["provider"] == "mailbox_host", srv["provider"]
assert srv["machine"]["region"] == country, srv["machine"]
print(f"placed: provider={srv['provider']} region={srv['machine']['region']}")

# The mailbox cert is self-signed by design (clients pin the fingerprint; this
# script trusts the hub's TLS instead, which just vouched for fp). MX is e2e's
# client, already configured not to verify.
h = MX.get(f"{addr}/health").json()
assert h == {"status": "ok", "v": 1, "tls_fp": tls_fp}, h
print("health ok — fingerprint served by mailbox matches hub record")

# What a real device does right after ignite: sign the fingerprint with the
# identity key, then publish prekeys. The certificate rides up with the
# prekeys, and registering the device is what makes /inbox accept an envelope
# addressed to it at all.
phone.publish_tls_sig()
phone.upload_prekeys()
print("published tls_sig + prekeys (device certificate registered)")

env = {"v": 1, "id": "smoke-1", "to": phone.stonechat_id,
       "device": PRIMARY_DEVICE, "sealed": "c21va2U="}
r = MX.post(f"{addr}/inbox", json=env)
queued = r.json()
# Field-wise, not exact-equality: the relay legitimately grows this response
# (multidevice added devices_v), and an exact match turns every such addition
# into a smoke-test failure. Check what this test is actually about.
assert queued["status"] == "queued", r.text
# devices_v rides along so a sender can notice the device list moved. Seeing
# it at all confirms the certificate upload above registered this device.
assert queued.get("devices_v", 0) >= 1, queued
assert phone.queue_depth() == 1, phone.queue_depth()
r = MX.post(f"{addr}/inbox", json={**env, "v": 2})
assert r.status_code == 400, "wrong version must be rejected"
print("inbox round trip ok: queued=1, v2 rejected")

phone.destroy()
print("destroyed")
print("\nSMOKE PASSED")
