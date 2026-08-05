"""Upgrade the relay binary inside running mailboxes, without recreating them.

A mailbox keeps everything it has — the message queue, the prekeys, the TLS
key, the WebTransport certificate schedule — in the container's own writable
layer, deliberately: destroy the container and the data is gone with it, no
volume left behind on the host. That privacy property has a cost, which is
that `docker run` with a new image is not available as an upgrade path. It
would hand every user a new mailbox and drop the old one on the floor.

So a release is a **swap**: copy the new binary over the entrypoint, restart
the container. The writable layer survives a restart, the process does not, and
the mailbox comes back up on the new code with its queue intact. The published
ports survive too — they are pinned at create time (see providers/bootstrap.py
`pick_ports`), so the address the hub handed out stays correct.

What this script is careful about:

* It **verifies**, rather than assuming. Each relay reports the hash of the
  binary it is running on `/status`; the script reads that before and after and
  fails if it did not change to the expected value. A copy that silently landed
  in the wrong place would otherwise look exactly like a success.
* It goes **one container at a time and stops on the first failure**, leaving
  the rest of the fleet on the old binary. A bad build should cost one mailbox
  of downtime, not all of them.
* It **rolls that one back** — the previous binary is kept inside the container
  at /stonechat-relay.prev until the new one is confirmed healthy.

Usage::

    hub/.venv/bin/python scripts/roll_relay.py --binary relay/target/release/stonechat-relay
    hub/.venv/bin/python scripts/roll_relay.py --binary <path> --only stonechat-abc1234
    hub/.venv/bin/python scripts/roll_relay.py --binary <path> --dry-run

The binary must be the musl static build the image ships (`FROM scratch` has no
loader) — the same artifact `relay/README.md` "Producing the production
artifact" builds, and the same one `STONECHAT_RELAY_BINARY` points at. Rolling
a dynamically-linked host build produces a container that cannot exec, which
the health check catches — on the first mailbox only, before it spreads.
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "hub"))

from app.providers.fleet import _parse_hosts  # noqa: E402

# Where the entrypoint lives inside the image, and where the outgoing binary is
# parked so a failed rollout has something to go back to.
TARGET = "/stonechat-relay"
BACKUP = "/stonechat-relay.prev"

# How long to wait for a restarted relay to answer. A cold relay opens its
# database and loads (or mints) its certificate schedule first; on a loaded
# fleet host that is seconds, not milliseconds.
HEALTH_TIMEOUT = 30


def build_id(path: Path) -> str:
    """The same hash the relay computes for itself at boot: BLAKE2b-256 of the
    executable, first 16 hex characters. Computing it here from the file we are
    about to ship is what makes the post-upgrade check meaningful."""
    return hashlib.blake2b(path.read_bytes(), digest_size=32).hexdigest()[:16]


class Host:
    """One Docker endpoint, plus the containers on it."""

    def __init__(self, fleet_host):
        self.name = fleet_host.name
        self.endpoint = fleet_host.endpoint
        self.advertise = fleet_host.advertise

    def docker(self, *args: str, check: bool = True) -> str:
        cmd = ["docker"] + (["-H", self.endpoint] if self.endpoint else []) + list(args)
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if check and proc.returncode != 0:
            raise RuntimeError(f"{self.name}: docker {args[0]} failed: {proc.stderr.strip()[:400]}")
        return proc.stdout.strip()

    def mailboxes(self) -> list[str]:
        # The fleet label specifically. LocalDockerProvider containers carry a
        # different one and are deliberately not rollout targets: that provider
        # is laptop dev, where rebuilding the image is the upgrade.
        out = self.docker(
            "ps", "--filter", "label=stonechat.fleet=1", "--format", "{{.Names}}"
        )
        return [n for n in out.split() if n]

    def probe_target(self, container: str) -> tuple[str, str] | None:
        """Where to reach this mailbox: (published port, owner token).

        `HostConfig.PortBindings` first: it is the pinned configuration, and it
        is there whether the container is up or down. `NetworkSettings.Ports`
        describes the *running* container and goes empty the moment it stops —
        exactly the state a failed upgrade leaves behind.

        But mailboxes created before ports were pinned were run with `-p 0:`,
        and their PortBindings literally says `"0"` — the real port was chosen
        by the kernel and only ever appears in NetworkSettings. On the day this
        script first runs, that is the entire fleet, so falling back is not an
        edge case; without it the first rollout refuses every mailbox it finds.

        Both templates use `range` rather than `index …  0`, which errors out on
        a nil map instead of yielding nothing.
        """
        env = self.docker(
            "inspect", "-f", "{{range .Config.Env}}{{println .}}{{end}}",
            container, check=False,
        )
        owner = next(
            (l.split("=", 1)[1] for l in env.splitlines()
             if l.startswith("STONECHAT_OWNER_TOKEN=")),
            "",
        )
        if not owner:
            return None
        for source in (".HostConfig.PortBindings", ".NetworkSettings.Ports"):
            port = self.docker(
                "inspect", "-f",
                '{{range $p := index %s "8080/tcp"}}{{$p.HostPort}}{{end}}' % source,
                container, check=False,
            )
            if port and port != "0":
                return port, owner
        return None

    def running_build(self, container: str) -> str | None:
        """Ask the relay which binary it is running, through its own API.

        Deliberately not `docker exec` (the image is FROM scratch — there is no
        shell to exec) and not a hash of the file on disk (that would tell us
        the file changed, not that the *process* picked it up). The relay
        answering at all is also the health check.

        Three outcomes, and the difference between the last two matters:

        * ``None``  — it did not answer. Down, or not up yet.
        * ``""``    — it answered, but reports no build. That is a relay from
          before this field existed, which is what the whole production fleet
          is running on the day this ships. Healthy, just unidentifiable — and
          conflating it with ``None`` would make the first rollout's rollback
          look like a dead mailbox.
        * a hash    — it answered and said which binary it is.

        Never raises. Container stopped, port gone, socket refused, garbage
        body: all of it means "did not answer", and an exception instead would
        abort the rollout *before* it could roll the mailbox back.
        """
        target = self.probe_target(container)
        if target is None:
            return None
        port, owner = target
        url = f"https://{self.advertise}:{port}/status?token={owner}"
        try:
            proc = subprocess.run(
                ["curl", "-sk", "--max-time", "5", url],
                capture_output=True, text=True,
            )
        except OSError:
            return None
        if proc.returncode != 0 or not proc.stdout.strip():
            return None
        try:
            return str(json.loads(proc.stdout).get("build") or "")
        except json.JSONDecodeError:
            return None

    def wait_healthy(self, container: str) -> str | None:
        """Block until it answers, and say what it answered. `None` on timeout
        — i.e. it never came back at all."""
        deadline = time.time() + HEALTH_TIMEOUT
        while time.time() < deadline:
            got = self.running_build(container)
            if got is not None:
                return got
            time.sleep(1)
        return None


def roll_one(
    host: Host, container: str, binary: Path, want: str, dry: bool, force: bool
) -> bool:
    before = host.running_build(container)
    label = f"  {container:<28}"
    if before and before == want:
        print(f"{label} already on {want}, skipped")
        return True
    if dry:
        print(f"{label} {before if before is not None else 'DOWN'} -> {want}  (dry run)")
        return True

    # Refuse a mailbox that is already down. The rollback target is whatever is
    # sitting at the entrypoint right now, so rolling one of these would park an
    # unverified binary as the thing we fall back to — and the health check
    # afterwards could not tell a bad new build from the failure that was
    # already there. Something is wrong with this mailbox that a release is not
    # the fix for.
    if before is None and not force:
        print(f"{label} DOWN before the roll — skipping the fleet, use --force to override")
        return False

    # Pull the outgoing binary out to the local disk and KEEP it there for the
    # duration of the roll. It is the rollback source.
    #
    # It has to live outside the container, because `docker cp` always has one
    # foot on the local filesystem — container-to-container is not a form it
    # supports. A rollback written as `cp <container>:<backup> <container>:<target>`
    # does nothing at all, and does it quietly.
    #
    # The in-container copy at BACKUP is written too, but it is for a human
    # arriving later, not for this script.
    tmp = Path(os.environ.get("TMPDIR", "/tmp")) / f".stonechat-prev-{container}"
    have_backup = False
    try:
        host.docker("cp", f"{container}:{TARGET}", str(tmp))
        have_backup = tmp.is_file()
        host.docker("cp", str(tmp), f"{container}:{BACKUP}", check=False)

        # From here on the container has been touched, so every path out goes
        # through the rollback below — including a docker command that itself
        # fails. Raising past this point would leave a mailbox on a binary
        # nobody verified.
        try:
            host.docker("cp", str(binary), f"{container}:{TARGET}")
            host.docker("restart", container)
            after = host.wait_healthy(container)
            why = None if after == want else (
                "did not come back" if after is None else f"reports {after}"
            )
        except RuntimeError as e:
            after, why = None, str(e)

        if why is None:
            print(f"{label} {before or '?'} -> {after}  ok")
            return True

        # Roll back. The mailbox was healthy on the old binary a moment ago, so
        # the fastest way out is to put it back and let a human look at the
        # build.
        print(f"{label} FAILED: {why} — rolling back")
        if not have_backup:
            print(f"{label} NO BACKUP TO ROLL BACK TO — mailbox is down, needs a human")
            return False
        host.docker("cp", str(tmp), f"{container}:{TARGET}", check=False)
        host.docker("restart", container, check=False)
    finally:
        tmp.unlink(missing_ok=True)
    recovered = host.wait_healthy(container)
    if recovered is None:
        print(f"{label} ROLLBACK ALSO FAILED — mailbox is down, needs a human")
    elif before is not None and recovered != before:
        # The backup was not what this mailbox was running when we arrived, so
        # something clobbered it — in practice a previous --force roll. It is
        # serving again, which is the urgent part, but not on the binary it had.
        print(
            f"{label} back up, but on {recovered or 'an unidentified binary'}, "
            f"not the {before or 'unidentified one'} it started on — check it"
        )
    else:
        print(f"{label} rolled back to {recovered or 'its previous binary'}")
    return False


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--binary", required=True, type=Path, help="the new relay binary (musl static)")
    ap.add_argument("--only", help="roll just this container name")
    ap.add_argument("--dry-run", action="store_true", help="say what would change, change nothing")
    ap.add_argument(
        "--force", action="store_true",
        help="roll a mailbox that is already down (its rollback target will be unverified)",
    )
    args = ap.parse_args()

    if not args.binary.is_file():
        print(f"no such binary: {args.binary}", file=sys.stderr)
        return 2

    want = build_id(args.binary)
    print(f"new build: {want}  ({args.binary}, {args.binary.stat().st_size:,} bytes)\n")

    try:
        hosts = [Host(h) for h in _parse_hosts()]
    except Exception as e:
        print(f"cannot read the fleet: {e}", file=sys.stderr)
        print("set STONECHAT_FLEET_HOSTS the same way the hub has it", file=sys.stderr)
        return 2

    total = 0
    for host in hosts:
        names = host.mailboxes()
        if args.only:
            names = [n for n in names if n == args.only]
        if not names:
            continue
        print(f"{host.name} ({host.advertise}) — {len(names)} mailbox(es)")
        for name in names:
            total += 1
            if not roll_one(host, name, args.binary, want, args.dry_run, args.force):
                print(
                    f"\nstopped after {total} mailbox(es). "
                    "The rest are untouched and still on the old binary.",
                    file=sys.stderr,
                )
                return 1
        print()

    if total == 0:
        print("no mailboxes matched — nothing to do")
        return 0
    print(f"{total} mailbox(es) now on {want}" + (" (dry run)" if args.dry_run else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
