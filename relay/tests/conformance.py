"""Conformance corpus for the relay's HTTP surface: replay a fixed request
sequence and diff status codes + JSON bodies against the golden expectations
in fixtures/golden.json.

The corpus began life as a live diff between the Python relay and this Rust
port; the Python relay is gone (cutover 2026-07, notes/docs/RUST_PORT.md), so the
recorded behavior IS the contract now. The corpus is stateful and
order-dependent — always run it against a FRESH relay (empty DB/blob dir)
started with OWNER_ID=SC-TEST-OWNER, OWNER_TOKEN=tok-secret.

Usage:
    python conformance.py <base_url>            # check against golden.json
    python conformance.py <base_url> --record   # regenerate golden.json
"""
import json
import pathlib
import ssl
import sys
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


ENV_OK = {"v": 1, "id": "e-0001", "to": OWNER, "sealed": "aGVsbG8="}

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
    # both signed halves are required (PQXDH — notes/docs/POST_QUANTUM.md)
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
]


def run(base):
    out, raw = {}, {}
    for label, method, path, body, norm in CORPUS:
        # A callable path reads earlier *un-normalized* responses: the blob id
        # and fetch token are random per run, so the capability round trip can
        # only be expressed by chaining, while the golden records the shape.
        status, resp = req(base, method, path(raw) if callable(path) else path, body)
        raw[label] = resp if isinstance(resp, dict) else {}
        out[label] = [status, norm(resp) if norm else resp]
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
