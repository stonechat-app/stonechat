"""Conformance diff: replay an identical request corpus against the Python
relay and the Rust relay, diff status codes + JSON bodies.

Usage: python conformance.py <python_base_url> <rust_base_url>
Both servers must run with OWNER_ID=ZC-TEST-OWNER, OWNER_TOKEN=tok-secret.
"""
import json
import ssl
import sys
import urllib.request

OWNER = "ZC-TEST-OWNER"
TOKEN = "tok-secret"

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


def req(base, method, path, body=None):
    r = urllib.request.Request(base + path, method=method,
                               data=body if body is None or isinstance(body, bytes)
                               else json.dumps(body).encode())
    try:
        with urllib.request.urlopen(r, context=CTX, timeout=10) as resp:
            return resp.status, json.loads(resp.read() or b"null")
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except json.JSONDecodeError:
            return e.code, {"_nonjson": raw.decode(errors="replace")[:100]}


ENV_OK = {"v": 1, "id": "e-0001", "to": OWNER, "sealed": "aGVsbG8="}

# (label, method, path, body, normalizer)
CORPUS = [
    ("health", "GET", "/health", None, lambda b: {**b, "tls_fp": "X"}),
    ("status-noauth", "GET", "/status", None, None),
    ("status", "GET", f"/status?token={TOKEN}", None, None),
    ("owner-missing", "GET", "/owner", None, None),
    ("owner-wrong", "GET", "/owner?zeon_id=ZC-NOPE", None, None),
    ("owner-right", "GET", f"/owner?zeon_id={OWNER}", None, None),
    ("bundle-empty", "GET", "/prekeys/bundle", None, None),
    ("prekeys-noauth", "POST", "/prekeys", {"spk": {"id": 1, "pub": "p", "sig": "s"}}, None),
    ("prekeys-badshape", "POST", f"/prekeys?token={TOKEN}", {"spk": {"id": "x"}}, None),
    ("prekeys-toomany-opks", "POST", f"/prekeys?token={TOKEN}",
     {"spk": {"id": 1, "pub": "p", "sig": "s"},
      "opks": [{"id": i, "pub": "p"} for i in range(257)]}, None),
    ("prekeys-ok", "POST", f"/prekeys?token={TOKEN}",
     {"spk": {"id": 7, "pub": "spk-pub", "sig": "spk-sig"},
      "opks": [{"id": 41, "pub": "opk-41"}, {"id": 42, "pub": "opk-42"}]}, None),
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
    ("inbox-wrong-owner", "POST", "/inbox", {**ENV_OK, "to": "ZC-SOMEONE-ELSE"}, None),
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
]


def main(py_base, rs_base):
    failures = 0
    for label, method, path, body, norm in CORPUS:
        py = req(py_base, method, path, body)
        rs = req(rs_base, method, path, body)
        if norm:
            py = (py[0], norm(py[1]))
            rs = (rs[0], norm(rs[1]))
        if py == rs:
            print(f"  ok    {label}: {py[0]}")
        else:
            failures += 1
            print(f"  DIFF  {label}:\n    py: {py}\n    rs: {rs}")
    print(f"\n{'FAIL' if failures else 'PASS'}: {len(CORPUS) - failures}/{len(CORPUS)} identical")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
