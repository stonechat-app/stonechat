"""Ship a relay release to every mailbox host, and swap it into running mailboxes.

A mailbox keeps everything it has — the message queue, the prekeys, the TLS key,
the WebTransport certificate schedule — in the container's own writable layer,
deliberately: destroy the container and the data is gone with it, no volume left
behind on the host. That privacy property has a cost, which is that `docker run`
with a new image is not available as an upgrade path. It would hand every user a
new mailbox and drop the old one on the floor.

So a release is a **swap**: copy the new binary over the entrypoint, restart the
container. The writable layer survives a restart, the process does not, and the
mailbox comes back up on the new code with its queue intact. The published ports
survive too — they are pinned at create time — so the address the hub handed out
stays correct.

This script is now a thin driver. The swap itself happens *on* each mailbox host
(mailbox_host/main.py, `POST /v1/relay/roll`), because that is where Docker
access lives: the hub holds an admin token for a small HTTPS API, not a key
into the `docker` group on every mailbox host the way the retired fleet provider
did. What the host does per mailbox:

* **Verifies** rather than assuming. Each relay reports the hash of the binary
  it is running on `/status`; the host reads it before and after and fails if it
  did not become the expected value. A copy that silently landed in the wrong
  place would otherwise look exactly like a success.
* Goes **one mailbox at a time and stops at the first failure**, leaving the rest
  of that host serving the old binary.
* **Rolls that one back** — the outgoing binary is kept until the new one is
  confirmed healthy.

Uploading also sets what **new** mailboxes are built from, which is the step that
used to be a separate "remember to restart the hub" footnote: the host stores the
binary, wraps it in a `FROM scratch` image tagged by content, and launches every
later guest from it.

Usage::

    hub/.venv/bin/python scripts/roll_relay.py --binary relay/target/release/stonechat-relay
    hub/.venv/bin/python scripts/roll_relay.py --binary <path> --dry-run
    hub/.venv/bin/python scripts/roll_relay.py --binary <path> --host de1 --only SC-…

A host pinned to a published image does not need this script to upgrade: point
it at the new digest, restart it, and `POST /v1/relay/roll` takes the binary out
of that image. This is for shipping a binary you built yourself.

Needs STONECHAT_MAILBOX_HOSTS set the same way the hub has it. The binary must be
the musl static build the image ships (`FROM scratch` has no loader) — the same
artifact `relay/README.md` "Producing the production artifact" builds. Rolling a
dynamically-linked host build produces a container that cannot exec, which the
health check catches on the first mailbox only, before it spreads.
"""

import argparse
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "hub"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.providers.base import ProviderError  # noqa: E402
from app.providers.mailbox_host import MailboxHost, _parse_hosts  # noqa: E402
from app.providers.pinned import pinned_request  # noqa: E402

# Uploading a few MB and then rolling every mailbox on the host, one at a time,
# each with its own health wait. Generous: the failure this must not produce is a
# client-side timeout in the middle of a roll, which leaves the operator not
# knowing how far it got.
UPLOAD_TIMEOUT = 120
ROLL_TIMEOUT = 900


def build_id(path: Path) -> str:
    """The same hash the relay computes for itself at boot: BLAKE2b-256 of the
    executable, first 16 hex characters. Computing it here from the file we are
    about to ship is what makes the host's post-swap check meaningful."""
    return hashlib.blake2b(path.read_bytes(), digest_size=32).hexdigest()[:16]


def call(host: MailboxHost, method: str, path: str, *, timeout: float,
         json_body: dict | None = None, content: bytes | None = None) -> dict:
    """One authenticated request to a mailbox host, on a pinned connection.

    The pin is the whole trust anchor — these hosts self-sign — and it is
    checked on the connection that carries the admin token and the binary,
    before either is written to it (hub/app/providers/pinned.py).
    """
    headers = {"Authorization": f"Bearer {host.admin_token}"}
    if content is not None:
        headers["Content-Type"] = "application/octet-stream"
    try:
        resp = pinned_request(host.url, host.tls_fp, method, path, headers=headers,
                              json_body=json_body, content=content, timeout=timeout)
    except ProviderError as e:
        raise ProviderError(f"{host.name}: {e}") from e
    if resp.status_code >= 400:
        raise ProviderError(f"{host.name}: HTTP {resp.status_code} {resp.text[:300]}")
    return resp.json()


def show(result: dict) -> None:
    """One line per mailbox, in the vocabulary the host answered in."""
    owner = result.get("owner_id", "?")
    label = f"  {owner[:24]:<24}"
    if result.get("ok"):
        detail = result.get("detail")
        moved = f"{result.get('from') or '?'} -> {result.get('to')}"
        print(f"{label} {moved}  {detail or 'ok'}")
    else:
        print(f"{label} FAILED: {result.get('detail')}")
        if result.get("rolled_back_to"):
            print(f"{label} rolled back to {result['rolled_back_to']}")


def roll_host(host: MailboxHost, binary: Path, want: str, args) -> bool:
    """Returns True when this host ended up wholly on `want`."""
    if args.dry_run:
        state = call(host, "GET", "/v1/relay", timeout=UPLOAD_TIMEOUT)
        guests = state.get("guests", [])
        if args.only:
            guests = [g for g in guests if g.get("owner_id") == args.only]
        print(f"{host.name} ({host.url}) — installed {state.get('installed_build')}, "
              f"{len(guests)} mailbox(es)")
        for guest in guests:
            current = guest.get("build")
            verdict = "already on it" if current == want else (
                "DOWN" if current is None else f"{current} -> {want}")
            print(f"  {guest.get('owner_id', '?')[:24]:<24} {verdict}  (dry run)")
        return True

    installed = call(host, "POST", "/v1/relay", timeout=UPLOAD_TIMEOUT,
                     content=binary.read_bytes())
    if installed.get("build") != want:
        # The host hashed the bytes it received; a mismatch means they are not
        # the bytes we sent, and rolling that would ship an unknown binary.
        raise ProviderError(
            f"{host.name}: uploaded {want} but the host computed "
            f"{installed.get('build')}"
        )
    print(f"{host.name} ({host.url}) — installed {want} "
          f"({installed.get('bytes', 0):,} bytes); new mailboxes use it from now on")

    body = {"dry_run": False, "force": args.force}
    if args.only:
        body["only"] = args.only
    rolled = call(host, "POST", "/v1/relay/roll", timeout=ROLL_TIMEOUT, json_body=body)
    for result in rolled.get("rolled", []):
        show(result)
    if rolled.get("stopped"):
        print(f"{host.name}: stopped — the rest of this host is still on the old "
              "binary", file=sys.stderr)
        return False
    return True


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--binary", required=True, type=Path,
                    help="the new relay binary (musl static)")
    ap.add_argument("--host", help="roll just this mailbox host (pool name)")
    ap.add_argument("--only", help="roll just this mailbox (Stonechat ID)")
    ap.add_argument("--dry-run", action="store_true",
                    help="say what would change, change nothing (uploads nothing)")
    ap.add_argument(
        "--force", action="store_true",
        help="roll a mailbox that is already down (its rollback target will be "
             "unverified)",
    )
    args = ap.parse_args()

    if not args.binary.is_file():
        print(f"no such binary: {args.binary}", file=sys.stderr)
        return 2

    want = build_id(args.binary)
    print(f"new build: {want}  ({args.binary}, {args.binary.stat().st_size:,} bytes)\n")

    try:
        hosts = _parse_hosts()
    except ProviderError as e:
        print(f"cannot read the host pool: {e}", file=sys.stderr)
        print("set STONECHAT_MAILBOX_HOSTS the same way the hub has it",
              file=sys.stderr)
        return 2
    if args.host:
        hosts = [h for h in hosts if h.name == args.host]
        if not hosts:
            print(f"no mailbox host named {args.host!r}", file=sys.stderr)
            return 2

    for host in hosts:
        try:
            if not roll_host(host, args.binary, want, args):
                return 1
        except ProviderError as e:
            # Stop at the first host that misbehaves rather than marching on: the
            # remaining hosts are still serving, and whatever is wrong here is
            # likely wrong there too.
            print(f"\n{e}", file=sys.stderr)
            print("stopped; later hosts untouched.", file=sys.stderr)
            return 1
        print()

    print(f"all hosts on {want}" + (" (dry run)" if args.dry_run else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
