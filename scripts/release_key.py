"""The relay release key: make one, and sign a relay binary with it.

A mailbox host installs a relay binary uploaded to it (`POST /v1/relay`) only if
it is signed by a key the host was configured to trust
(`STONECHAT_RELAY_RELEASE_KEYS`, mailbox_host/main.py "Relay releases"). That
key is the answer to "who may run code in every mailbox on this box", and it is
deliberately not the admin token: the hub holds the admin token, and a release
key the hub held would be stolen with it.

So the private half lives with whoever cuts releases, off the servers:

    hub/.venv/bin/python scripts/release_key.py generate ~/.stonechat/release.key
    # → prints the PUBLIC key; put it in STONECHAT_RELAY_RELEASE_KEYS on each host

    hub/.venv/bin/python scripts/release_key.py sign --key ~/.stonechat/release.key \\
        --binary stonechat-relay > stonechat-relay.sig

`scripts/roll_relay.py --release-key …` signs as it uploads, so `sign` is only
needed to make the signature on one machine and ship from another.

What is signed is `"stonechat-v1-relay-release" || BLAKE2b-256(binary)` with
Ed25519. The key file is the 32-byte seed, base64, mode 0600.
"""

import argparse
import base64
import hashlib
import os
import sys
from pathlib import Path

from nacl.signing import SigningKey

RELEASE_SIG_CONTEXT = b"stonechat-v1-relay-release"


def release_message(binary: bytes) -> bytes:
    return RELEASE_SIG_CONTEXT + hashlib.blake2b(binary, digest_size=32).digest()


def load_key(path: Path) -> SigningKey:
    try:
        seed = base64.b64decode(path.read_text().strip(), validate=True)
    except Exception:
        seed = b""
    if len(seed) != 32:
        raise SystemExit(f"{path} is not a release key (expected a base64 "
                         "32-byte seed, as `generate` writes)")
    return SigningKey(seed)


def public_b64(key: SigningKey) -> str:
    return base64.b64encode(bytes(key.verify_key)).decode()


def sign(key: SigningKey, binary: bytes) -> str:
    """The signature a mailbox host expects, base64."""
    return base64.b64encode(key.sign(release_message(binary)).signature).decode()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    gen = sub.add_parser("generate", help="make a key; prints the public half")
    gen.add_argument("path", type=Path)
    pub = sub.add_parser("public", help="print the public half of a key")
    pub.add_argument("path", type=Path)
    sg = sub.add_parser("sign", help="sign a relay binary; prints the signature")
    sg.add_argument("--key", required=True, type=Path)
    sg.add_argument("--binary", required=True, type=Path)
    args = ap.parse_args()

    if args.cmd == "generate":
        path: Path = args.path
        path.parent.mkdir(parents=True, exist_ok=True)
        key = SigningKey.generate()
        # O_EXCL: never overwrite a key — every host that trusts the old one
        # would refuse the next release. 0600 from the first byte, not after.
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            print(f"{path} already exists; refusing to overwrite a release key",
                  file=sys.stderr)
            return 2
        with os.fdopen(fd, "w") as f:
            f.write(base64.b64encode(bytes(key)).decode() + "\n")
        print(public_b64(key))
        print(f"private key written to {path} — keep it off the servers.\n"
              "The line above is the PUBLIC key, for "
              "STONECHAT_RELAY_RELEASE_KEYS.", file=sys.stderr)
        return 0
    if args.cmd == "public":
        print(public_b64(load_key(args.path)))
        return 0
    print(sign(load_key(args.key), args.binary.read_bytes()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
