"""Production smoke test for the deployed hub + fleet.

Registers a throwaway identity, redeems the tester activation code, ignites a
fleet mailbox (first ignite after an image eviction also proves the relay
image builds on the fleet host), verifies the mailbox end to end, destroys it.

Usage (the code never lives in the repo — it's in the hub's systemd drop-in):

    STONECHAT_TEST_CODE=STONECHAT-XXXX-XXXX hub/.venv/bin/python scripts/smoke_prod.py

Env: STONECHAT_HUB (default https://hub.stonechat.app), STONECHAT_TEST_CODE (required).
Needs httpx + pynacl (both in the hub venv).
"""
import base64
import json
import os
import ssl
import sys
import time

import httpx
from nacl.signing import SigningKey

HUB = os.environ.get("STONECHAT_HUB", "https://hub.stonechat.app")
TEST_CODE = os.environ.get("STONECHAT_TEST_CODE") or sys.exit(
    "set STONECHAT_TEST_CODE (the tester activation code from the hub's drop-in)")
H = {"X-Stonechat-Version": "1"}

sk = SigningKey.generate()
pub = base64.b64encode(sk.verify_key.encode()).decode()

r = httpx.post(f"{HUB}/v1/register", json={"pubkey": pub}, headers=H)
r.raise_for_status()
me = r.json()
auth = {**H, "Authorization": f"Bearer {me['account_token']}"}
print("registered:", me["stonechat_id"])
assert "handle" not in me, "hub still returns handles — old code deployed?"

r = httpx.post(f"{HUB}/v1/billing/redeem", json={"code": TEST_CODE}, headers=auth)
r.raise_for_status()
print("entitlement:", r.json()["plan"], r.json()["status"])

r = httpx.post(f"{HUB}/v1/mailbox", headers=auth, json={
    "provider": "fleet",
    "machine": {"machine_type": "container", "region": "fleet1", "disk_gb": 10},
})
assert r.status_code == 202, (r.status_code, r.text)
print("provisioning started…")

t0 = time.time()
srv = None
while time.time() - t0 < 300:
    srv = httpx.get(f"{HUB}/v1/mailbox", headers=auth).json()
    if srv["status"] in ("running", "error"):
        break
    time.sleep(3)
print(f"status={srv['status']} after {time.time()-t0:.0f}s")
if srv["status"] != "running":
    print("PROVISION FAILED:", json.dumps(srv, indent=2))
    sys.exit(1)
addr, tls_fp = srv["address"], srv["tls_fp"]
print("mailbox:", addr, "fp:", tls_fp[:16] + "…")

# The mailbox cert is self-signed by design (clients pin the fingerprint;
# this script trusts the hub's TLS instead, which just vouched for fp).
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
mx = httpx.Client(verify=ctx, timeout=10)

h = mx.get(f"{addr}/health").json()
assert h == {"status": "ok", "v": 1, "tls_fp": tls_fp}, h
print("health ok — fingerprint served by mailbox matches hub record")

env = {"v": 1, "id": "smoke-1", "to": me["stonechat_id"], "sealed": "c21va2U="}
r = mx.post(f"{addr}/inbox", json=env)
assert r.json() == {"status": "queued"}, r.text
st = mx.get(f"{addr}/status", params={"token": srv["mailbox_token"]}).json()
assert st["queued"] == 1, st
r = mx.post(f"{addr}/inbox", json={**env, "v": 2})
assert r.status_code == 400, "wrong version must be rejected"
print("inbox round trip ok: queued=1, v2 rejected")

r = httpx.delete(f"{HUB}/v1/mailbox", headers=auth)
print("destroyed:", r.status_code)
print("\nSMOKE PASSED")
