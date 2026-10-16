"""Conformance corpus for the relay's HTTP surface: replay a fixed request
sequence and diff status codes + JSON bodies against the golden expectations
in fixtures/golden.json.

The corpus began life as a live diff between the Python relay and this Rust
port; the Python relay is gone (cutover 2026-07), so the
recorded behavior IS the contract now. The corpus is stateful and
order-dependent — always run it against a FRESH relay (empty DB/blob dir)
started with OWNER_ID=SC-TEST-OWNER, OWNER_TOKEN=tok-secret.

Usage:
    python conformance.py <base_url>            # check against golden.json
    python conformance.py <base_url> --record   # regenerate golden.json
"""
import hashlib
import json
import pathlib
import ssl
import sys
import time
import urllib.request

OWNER = "SC-TEST-OWNER"
TOKEN = "tok-secret"
GOLDEN = pathlib.Path(__file__).resolve().parent / "fixtures" / "golden.json"

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


def req(base, method, path, body=None):
    r = urllib.request.Request(base + path, method=method,
                               data=body if body is None or isinstance(body, bytes)
                               else json.dumps(body).encode())
    try:
        with urllib.request.urlopen(r, context=CTX, timeout=10) as resp:
            return resp.status, _body(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, _body(e.read())


def _body(raw):
    """JSON where the relay speaks JSON; a short marker otherwise — a blob
    download returns opaque ciphertext, not an object."""
    try:
        return json.loads(raw or b"null")
    except json.JSONDecodeError:
        return {"_nonjson": raw.decode(errors="replace")[:100]}


# `device` is required on every envelope: the AEAD binds it, so there is no
# implicit value for sender and receiver to disagree about.
ENV_OK = {"v": 1, "id": "e-0001", "to": OWNER, "sealed": "aGVsbG8=", "device": 1}

# A second device's token, and the derived bundle token that gates the device
# list. Derived here rather
# than hardcoded so the corpus pins the derivation, not just a constant.
DEV2 = "dev2-token-0123456789abcdef0123456789"
DEV3 = "dev3-token-0123456789abcdef0123456789"
DEV4 = "dev4-token-0123456789abcdef0123456789"
DEV5 = "dev5-token-0123456789abcdef0123456789"
DEV6 = "dev6-token-0123456789abcdef0123456789"
DEV7 = "dev7-token-0123456789abcdef0123456789"
BUNDLE = hashlib.blake2b(
    TOKEN.encode() + b"|stonechat-bundle|", digest_size=32
).hexdigest()


def norm_devices(b):
    """created_at/expires_at/last_seen are wall-clock; keep their presence and
    their null-ness, not their values. expires_at null vs set IS the contract
    (a bounded device from an unbounded one), so it is preserved as a flag."""
    if "devices" not in b:
        return b
    return {**b, "devices": [
        {
            **d,
            "created_at": "X",
            "expires_at": "X" if d.get("expires_at") else None,
            "last_seen": "X" if d.get("last_seen") else None,
        }
        for d in b["devices"]
    ]}

# (label, method, path, body, normalizer)
CORPUS = [
    ("health", "GET", "/health", None, lambda b: {**b, "tls_fp": "X"}),
    ("status-noauth", "GET", "/status", None, None),
    ("status", "GET", f"/status?token={TOKEN}", None, None),
    ("owner-missing", "GET", "/owner", None, None),
    ("owner-wrong", "GET", "/owner?stonechat_id=SC-NOPE", None, None),
    ("owner-right", "GET", f"/owner?stonechat_id={OWNER}", None, None),
    ("bundle-empty", "GET", "/prekeys/bundle", None, None),
    ("prekeys-noauth", "POST", "/prekeys", {"spk": {"id": 1, "pub": "p", "sig": "s"}}, None),
    ("prekeys-badshape", "POST", f"/prekeys?token={TOKEN}", {"spk": {"id": "x"}}, None),
    # both signed halves are required (PQXDH — docs/POST_QUANTUM.md)
    ("prekeys-missing-kspk", "POST", f"/prekeys?token={TOKEN}",
     {"spk": {"id": 1, "pub": "p", "sig": "s"}}, None),
    ("prekeys-toomany-opks", "POST", f"/prekeys?token={TOKEN}",
     {"spk": {"id": 1, "pub": "p", "sig": "s"},
      "kspk": {"id": 2, "pub": "kp", "sig": "ks"},
      "opks": [{"id": i, "pub": "p"} for i in range(257)]}, None),
    ("prekeys-toomany-kopks", "POST", f"/prekeys?token={TOKEN}",
     {"spk": {"id": 1, "pub": "p", "sig": "s"},
      "kspk": {"id": 2, "pub": "kp", "sig": "ks"},
      "kopks": [{"id": i, "pub": "p"} for i in range(65)]}, None),
    ("prekeys-ok", "POST", f"/prekeys?token={TOKEN}",
     {"spk": {"id": 7, "pub": "spk-pub", "sig": "spk-sig"},
      "opks": [{"id": 41, "pub": "opk-41"}, {"id": 42, "pub": "opk-42"}],
      "kspk": {"id": 8, "pub": "kspk-pub", "sig": "kspk-sig"},
      "kopks": [{"id": 51, "pub": "kopk-51"}, {"id": 52, "pub": "kopk-52"}]}, None),
    ("bundle-consumes-lowest", "GET", "/prekeys/bundle", None, None),
    ("bundle-second", "GET", "/prekeys/bundle", None, None),
    ("bundle-dry", "GET", "/prekeys/bundle", None, None),
    ("inbox-notjson", "POST", "/inbox", b"not json{", None),
    ("inbox-missing", "POST", "/inbox", {"v": 1, "id": "x"}, None),
    ("inbox-badver", "POST", "/inbox", {**ENV_OK, "v": 2}, None),
    ("inbox-badver-str", "POST", "/inbox", {**ENV_OK, "v": "1"}, None),
    ("inbox-empty-id", "POST", "/inbox", {**ENV_OK, "id": ""}, None),
    ("inbox-int-id", "POST", "/inbox", {**ENV_OK, "id": 9}, None),
    ("inbox-bad-sealed", "POST", "/inbox", {**ENV_OK, "sealed": ""}, None),
    ("inbox-bad-blobid", "POST", "/inbox", {**ENV_OK, "blob_id": "../x"}, None),
    ("inbox-bad-hint", "POST", "/inbox", {**ENV_OK, "transient": "yes"}, None),
    ("inbox-no-device", "POST", "/inbox",
     {k: v for k, v in ENV_OK.items() if k != "device"}, None),
    ("inbox-wrong-owner", "POST", "/inbox", {**ENV_OK, "to": "SC-SOMEONE-ELSE"}, None),
    ("inbox-ok", "POST", "/inbox", ENV_OK, None),
    ("inbox-dup", "POST", "/inbox", ENV_OK, None),
    ("inbox-push-false", "POST", "/inbox", {**ENV_OK, "id": "e-0002", "push": False}, None),
    ("inbox-transient-offline", "POST", "/inbox", {**ENV_OK, "id": "e-0003", "transient": True}, None),
    ("status-after", "GET", f"/status?token={TOKEN}", None, None),
    ("push-config-noauth", "POST", "/push-config", {"device_token": "t", "platform": "ios"}, None),
    ("push-config-badplat", "POST", f"/push-config?token={TOKEN}",
     {"device_token": "t", "platform": "windows"}, None),
    ("push-config-missing", "POST", f"/push-config?token={TOKEN}", {"platform": "ios"}, None),
    ("push-config-ok", "POST", f"/push-config?token={TOKEN}",
     {"device_token": "t", "platform": "ios"}, None),
    ("turn-noauth", "GET", "/turn-credentials", None, None),
    ("turn-notoken-404", "GET", f"/turn-credentials?token={TOKEN}", None, None),
    ("blob-empty", "POST", "/blob", b"", None),
    ("blob-ok", "POST", "/blob", b"\x00\x01\x02encrypted-bytes", lambda b: {"blob_id": "X"}),
    ("blob-get-noauth", "GET", "/blob/123e4567-e89b-42d3-a456-426614174000", None, None),
    ("blob-get-badid", "GET", f"/blob/notanid?token={TOKEN}", None, None),
    ("blob-get-missing", "GET", f"/blob/123e4567-e89b-42d3-a456-426614174000?token={TOKEN}", None, None),
    # Group media (PROTOCOL.md "Groups"): one shared blob on the sender's own
    # mailbox, read by fellow members with a per-blob capability token.
    ("blob-shared-ok", "POST", "/blob?shared=1", b"group-photo-ciphertext",
     lambda b: {"blob_id": "X", "fetch_token": "X" if b.get("fetch_token") else None}),
    # ...the token the upload just handed out actually opens that blob...
    ("blob-shared-get", "GET",
     lambda r: f"/blob/{r['blob-shared-ok']['blob_id']}?token={r['blob-shared-ok']['fetch_token']}",
     None, None),
    # ...and opens nothing else: the token is bound to its own blob id.
    ("blob-shared-token-wrong-blob", "GET",
     lambda r: f"/blob/{r['blob-ok']['blob_id']}?token={r['blob-shared-ok']['fetch_token']}",
     None, None),
    ("blob-shared-token-not-owner", "GET",
     lambda r: f"/status?token={r['blob-shared-ok']['fetch_token']}", None, None),
    # A plain (non-shared) upload hands out no token at all.
    ("blob-plain-has-no-token", "GET",
     lambda r: f"/blob/{r['blob-ok']['blob_id']}?token=deadbeef", None, None),
    ("blob-delete-noauth", "DELETE", "/blob/123e4567-e89b-42d3-a456-426614174000", None, None),
    ("blob-delete-badid", "DELETE", f"/blob/notanid?token={TOKEN}", None, None),
    ("blob-delete-missing", "DELETE",
     f"/blob/123e4567-e89b-42d3-a456-426614174000?token={TOKEN}", None, None),
    ("blob-delete-ok", "DELETE",
     lambda r: f"/blob/{r['blob-shared-ok']['blob_id']}?token={TOKEN}", None, None),
    # Deleted means gone — the capability token outlives nothing.
    ("blob-shared-get-after-delete", "GET",
     lambda r: f"/blob/{r['blob-shared-ok']['blob_id']}?token={r['blob-shared-ok']['fetch_token']}",
     None, None),
    # -- devices ---------------------------------------------------------------
    # Device 1's token IS the owner token, which is what lets every
    # expectation above stay byte-identical through this change.
    ("devices-noauth", "GET", "/devices", None, None),
    ("devices-list", "GET", f"/devices?token={TOKEN}", None, norm_devices),
    ("devices-mint-noauth", "POST", "/devices", {"device_token": DEV2}, None),
    ("devices-mint-short", "POST", f"/devices?token={TOKEN}",
     {"device_token": "too-short"}, None),
    ("devices-mint-ok", "POST", f"/devices?token={TOKEN}", {"device_token": DEV2}, None),
    ("devices-mint-dup-token", "POST", f"/devices?token={TOKEN}",
     {"device_token": DEV2}, None),
    ("devices-list-after", "GET", f"/devices?token={TOKEN}", None, norm_devices),
    # The new device's token authenticates as itself, with its own queue.
    ("status-device2", "GET", f"/status?token={DEV2}", None, None),
    # ...and its prekey pool is its own: device 1's stock is untouched.
    ("prekeys-device2", "POST", f"/prekeys?token={DEV2}",
     {"spk": {"id": 70, "pub": "d2-spk", "sig": "d2-sig"},
      "opks": [{"id": 71, "pub": "d2-opk"}],
      "kspk": {"id": 80, "pub": "d2-kspk", "sig": "d2-ksig"},
      "kopks": [{"id": 81, "pub": "d2-kopk"}],
      # A device publishes its certificate with its prekeys — same
      # operation, same auth, and useless apart. Opaque to the relay.
      "cert": {"device_id": 2, "seal_pub": "d2-seal"}}, None),
    ("prekeys-bad-cert", "POST", f"/prekeys?token={DEV2}",
     {"spk": {"id": 70, "pub": "p", "sig": "s"},
      "kspk": {"id": 80, "pub": "k", "sig": "ks"}, "cert": "a string"}, None),
    ("status-device1-unaffected", "GET", f"/status?token={TOKEN}", None, None),
    # -- bundle split ---------------------------------------------------------
    # Listing is gated and free; the open bundle keeps device 1's exact shape.
    ("prekey-devices-noauth", "GET", "/prekeys/devices", None, None),
    ("prekey-devices-wrongtoken", "GET", "/prekeys/devices?token=nope", None, None),
    ("prekey-devices-bundletoken", "GET", f"/prekeys/devices?token={BUNDLE}", None, None),
    ("bundle-device-needs-token", "GET", "/prekeys/bundle?device=2", None, None),
    ("bundle-device2", "GET", f"/prekeys/bundle?device=2&token={BUNDLE}", None, None),
    ("bundle-device-bad", "GET", f"/prekeys/bundle?device=x&token={BUNDLE}", None, None),
    # -- per-device routing ---------------------------------------------------
    ("inbox-device2", "POST", "/inbox", {**ENV_OK, "id": "e-d2-1", "device": 2}, None),
    ("inbox-device-unknown", "POST", "/inbox", {**ENV_OK, "id": "e-d9", "device": 99}, None),
    ("inbox-device-bad-type", "POST", "/inbox", {**ENV_OK, "id": "e-dx", "device": "2"}, None),
    # Same envelope id to two devices is two rows, not a duplicate.
    ("inbox-same-id-device1", "POST", "/inbox", {**ENV_OK, "id": "e-d2-1", "device": 1}, None),
    ("status-device2-queued", "GET", f"/status?token={DEV2}", None, None),
    # -- revocation -----------------------------------------------------------
    ("revoke-noauth", "DELETE", "/devices/2", None, None),
    ("revoke-missing", "DELETE", f"/devices/99?token={TOKEN}", None, None),
    ("revoke-bad-id", "DELETE", f"/devices/xx?token={TOKEN}", None, None),
    ("revoke-ok", "DELETE", f"/devices/2?token={TOKEN}", None, None),
    # Revoked means gone: its token stops authenticating, its queue is dropped,
    # and posting to it is a permanent 410 carrying the new devices_v.
    ("status-revoked-token", "GET", f"/status?token={DEV2}", None, None),
    ("inbox-revoked-device", "POST", "/inbox", {**ENV_OK, "id": "e-d2-2", "device": 2}, None),
    ("devices-list-after-revoke", "GET", f"/devices?token={TOKEN}", None, norm_devices),
    # -- device lifetime (a browser session must end by itself)
    ("devices-mint-bad-kind", "POST", f"/devices?token={TOKEN}",
     {"device_token": DEV3, "kind": "primary"}, None),
    ("devices-mint-bad-expiry", "POST", f"/devices?token={TOKEN}",
     {"device_token": DEV3, "kind": "web", "expires_in_s": 0}, None),
    ("devices-mint-web", "POST", f"/devices?token={TOKEN}",
     {"device_token": DEV3, "kind": "web", "expires_in_s": 3600},
     lambda b: {**b, "expires_at": "X" if b.get("expires_at") else None}),
    ("devices-list-kinds", "GET", f"/devices?token={TOKEN}", None, norm_devices),
    # An already-expired device authenticates as nobody, before any sweep runs.
    ("devices-mint-expiring", "POST", f"/devices?token={TOKEN}",
     {"device_token": DEV4, "kind": "web", "expires_in_s": 1},
     lambda b: {**b, "expires_at": "X" if b.get("expires_at") else None}),
    ("status-expiring-device", "GET", f"/status?token={DEV4}", None, None),
    ("sleep-past-expiry", "SLEEP", "1.5", None, None),
    ("status-expired-device", "GET", f"/status?token={DEV4}", None, None),
    ("inbox-expired-device", "POST", "/inbox", {**ENV_OK, "id": "e-exp", "device": 4}, None),
    ("devices-list-hides-expired", "GET", f"/devices?token={TOKEN}", None, norm_devices),
    # -- headless agents (agent_client/) ---------------------------------------
    # A third kind, minted through the same path as any other. Appended rather
    # than filed next to the web cases on purpose: inserting a device mint
    # earlier would renumber every device id after it and rewrite most of this
    # file's expectations for no reason.
    ("devices-mint-agent", "POST", f"/devices?token={TOKEN}",
     {"device_token": DEV5, "kind": "agent"}, None),
    # Unbounded by default: an agent runs unattended, so its lifetime is the
    # certificate's (set by the authorising device), not a device-row expiry.
    ("devices-list-with-agent", "GET", f"/devices?token={TOKEN}", None, norm_devices),
    # A fresh token, because "already in use" is checked before the kind is
    # parsed — reusing DEV5 here would record a 409 and prove nothing about
    # the whitelist.
    ("devices-mint-still-rejects-junk-kind", "POST", f"/devices?token={TOKEN}",
     {"device_token": DEV6, "kind": "agentt"}, None),
    # -- who may manage the mailbox --------------------------------------------
    # Every device call above is the primary's, which is why none of them
    # moved when this was added. A linked device's token is authentication for
    # its own queue, prekeys and socket; it is not authority over the device
    # list. 403, not 401: the token is good, the device is the wrong one.
    ("policy-mint-linked", "POST", f"/devices?token={TOKEN}",
     {"device_token": DEV6, "kind": "linked"}, None),
    ("policy-linked-cannot-mint", "POST", f"/devices?token={DEV6}",
     {"device_token": DEV7, "kind": "linked"}, None),
    ("policy-linked-cannot-revoke-primary", "DELETE", f"/devices/1?token={DEV6}", None, None),
    ("policy-primary-cannot-revoke-itself", "DELETE", f"/devices/1?token={TOKEN}", None, None),
    ("policy-linked-cannot-revoke-sibling", "DELETE", f"/devices/5?token={DEV6}", None, None),
    # Same answer for an id that does not exist: not a way to enumerate.
    ("policy-linked-cannot-probe", "DELETE", f"/devices/99?token={DEV6}", None, None),
    ("policy-devices-untouched", "GET", f"/devices?token={DEV6}", None, norm_devices),
    ("policy-linked-revokes-itself", "DELETE", f"/devices/6?token={DEV6}", None, None),
    ("policy-revoked-itself-token", "GET", f"/status?token={DEV6}", None, None),
    ("policy-primary-still-works", "GET", f"/status?token={TOKEN}", None, None),
]


def stamp_build(body):
    """The relay reports which binary is running on /status (added 2026-08-05).
    Its *presence* is contract; its value is a fingerprint that changes with
    every compile, so recording the value would make this corpus fail on the
    next build. Applied globally rather than per-entry so a future authenticated
    endpoint that grows the field cannot forget to normalize it."""
    if isinstance(body, dict) and "build" in body:
        return {**body, "build": "X"}
    return body


def run(base):
    out, raw = {}, {}
    for label, method, path, body, norm in CORPUS:
        # A callable path reads earlier *un-normalized* responses: the blob id
        # and fetch token are random per run, so the capability round trip can
        # only be expressed by chaining, while the golden records the shape.
        if method == "SLEEP":
            time.sleep(float(path))
            out[label] = [0, {"slept": path}]
            continue
        status, resp = req(base, method, path(raw) if callable(path) else path, body)
        raw[label] = resp if isinstance(resp, dict) else {}
        out[label] = [status, stamp_build(norm(resp) if norm else resp)]
    return out


def main():
    base = sys.argv[1]
    got = run(base)
    if "--record" in sys.argv:
        GOLDEN.write_text(json.dumps(got, indent=2) + "\n")
        print(f"recorded {len(got)} expectations → {GOLDEN}")
        return
    golden = json.loads(GOLDEN.read_text())
    failures = 0
    for label in golden:
        want, have = golden[label], got.get(label)
        if want == have:
            print(f"  ok    {label}: {want[0]}")
        else:
            failures += 1
            print(f"  DIFF  {label}:\n    want: {want}\n    have: {have}")
    print(f"\n{'FAIL' if failures else 'PASS'}: "
          f"{len(golden) - failures}/{len(golden)} identical")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
