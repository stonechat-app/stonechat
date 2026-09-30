"""User-to-user abuse reports.

`admin.py` gave an operator the verbs to act on abuse — whois, destroy, ban —
but every one of them assumed the complaint arrived by mail, from a provider
or a law-enforcement contact. Nothing carried a
complaint from the one party who always knows first: the person being
harassed. This module is that path, and it is also what App Store review
Guideline 1.2 requires of an app carrying user-generated content.

Three things make it unlike the rest of the hub's surface.

**It is unauthenticated, but not anonymous.** A Stonechat ID is a BLAKE2b
commitment to an Ed25519 public key (identity.py), so a report signed by the
reporter's identity key is verifiable by *any* hub, including one the reporter
has no account on. That matters: a report has to be judged by the hub that can
act on it, which is the hub hosting the *reported* account, and with cross-hub
resolution that is often not the reporter's own. Bearer tokens cannot cross
that boundary; a signature can. Same trust posture as /v1/directory — open to
anyone holding a full ID, verified rather than trusted.

**The content is opt-in and opaque.** The privacy policy's claim is that
message content never reaches us at any layer. A report keeps that true by
default: it carries an ID, a category and the reporter's own words, and
nothing else. `evidence` is populated only when the reporter explicitly
attaches a transcript, is composed entirely on their device, and is stored
verbatim without ever being parsed here. The hub does not choose what goes in
it and cannot ask for more.

**Its rows expire.** See the `reports` table comment in db.py: a report is an
edge in a contact graph the hub otherwise never holds, so retention is bounded
(STONECHAT_REPORT_RETENTION_DAYS, swept by the reaper in main.py) and resolving a
report drops its evidence immediately.

What this module deliberately does not do is decide anything. It writes a row
and returns a reference number. A human reads it through /v1/admin/reports and
reaches for destroy or ban — the same two verbs, now with an input.
"""

import base64
import hashlib
import logging
import os
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from .deps import store
from .identity import PUBKEY_LEN, normalize_stonechat_id, stonechat_id_from_pubkey
from .ratelimit import RateLimiter

log = logging.getLogger("stonechat.hub.report")

router = APIRouter(tags=["report"])

RETENTION_DAYS = int(os.environ.get("STONECHAT_REPORT_RETENTION_DAYS", "180"))

# Fixed vocabulary rather than free text, so triage can sort a queue and so
# the urgent categories are recognisable without reading every note first.
# `note` is where nuance goes.
CATEGORIES = {
    "spam",
    "harassment",      # includes threats and targeted abuse
    "impersonation",
    "csam",            # legal duty to act, and to preserve
    "illegal_content",
    "other",
}

# A report is a human act: composing one takes a person minutes. Both walls
# exist to break scripts — a brigade pointing many identities at one account,
# or one identity spraying reports across many. Per-reporter is the tighter of
# the two because minting identities is free (admin.py's ban docstring makes
# the same point) so the IP wall is what actually bites a determined flooder.
#
# The IP wall is overridable for the same reason STONECHAT_REGISTER_LIMIT is:
# scripts/e2e.py files several reports from one address per run, and a rerun
# within the hour trips a limit meant for humans. Default is the production
# value; the env var is a test-rig knob.
_report_ip_limiter = RateLimiter(
    limit=int(os.environ.get("STONECHAT_REPORT_LIMIT", "20")), window_s=3600.0
)
_report_id_limiter = RateLimiter(
    limit=int(os.environ.get("STONECHAT_REPORT_LIMIT", "10")), window_s=3600.0
)


class ReportIn(BaseModel):
    reported_id: str = Field(max_length=64)
    reporter_pubkey: str = Field(max_length=64)  # base64 Ed25519 identity key
    timestamp: int                               # unix seconds, signed
    category: str = Field(max_length=32)
    note: str = Field(default="", max_length=2000)
    # Opaque, client-composed, never parsed here. Capped so one report cannot
    # be used to park a megabyte of anything in the hub's database.
    evidence: str | None = Field(default=None, max_length=65536)
    signature: str = Field(max_length=128)


def _signed_material(reported_id: str, timestamp: int, category: str,
                     note: str, evidence: str | None) -> bytes:
    """The exact bytes the reporter signs (PROTOCOL.md "Reporting").

    The body is committed to by hash rather than re-serialised, because the
    signature has to survive a round trip through JSON: field order and
    whitespace are not preserved, but a digest over the values is. 0x1F (unit
    separator) between fields so a note ending in what looks like the next
    field cannot forge a different report with the same digest.
    """
    digest = hashlib.blake2b(
        category.encode() + b"\x1f" + note.encode() + b"\x1f"
        + (evidence or "").encode(),
        digest_size=32,
    ).digest()
    return (b"stonechat-v1-report" + reported_id.encode()
            + str(timestamp).encode() + digest)


@router.post("/v1/report", status_code=202)
def report(body: ReportIn, request: Request):
    """File an abuse report against an account hosted by this hub.

    Returns a reference the reporter can quote to abuse@ — the only receipt
    they get, since the hub has no way to contact them back and should not
    acquire one.

    404 on an account this hub does not host is deliberate and not a new leak:
    /v1/directory already answers the same existence question to anyone
    holding a full ID. It is also the useful answer, because it tells a
    cross-hub client to send the report to the peer's own hub instead of
    silently dropping it into ours.
    """
    _report_ip_limiter.check(request.client.host if request.client else "unknown")

    try:
        reported_id = normalize_stonechat_id(body.reported_id)
    except ValueError as e:
        raise HTTPException(400, str(e))

    if body.category not in CATEGORIES:
        raise HTTPException(400, f"unknown category (expected one of {sorted(CATEGORIES)})")

    try:
        pubkey = base64.b64decode(body.reporter_pubkey, validate=True)
    except Exception:
        raise HTTPException(400, "reporter_pubkey is not valid base64")
    if len(pubkey) != PUBKEY_LEN:
        raise HTTPException(400, f"reporter_pubkey must be {PUBKEY_LEN} bytes")

    # Same ±5-minute window as /v1/recover: bounds replay to the TLS channel
    # the report was heard on.
    now = int(datetime.now(timezone.utc).timestamp())
    if abs(now - body.timestamp) > 300:
        raise HTTPException(400, "signature timestamp out of range — check the device clock")

    try:
        from nacl.signing import VerifyKey

        VerifyKey(pubkey).verify(
            _signed_material(reported_id, body.timestamp, body.category,
                             body.note, body.evidence),
            base64.b64decode(body.signature),
        )
    except Exception:
        raise HTTPException(401, "bad signature")

    reporter_id = stonechat_id_from_pubkey(pubkey)
    _report_id_limiter.check(reporter_id)

    if reporter_id == reported_id:
        raise HTTPException(400, "cannot report yourself")
    if not store.user_by_id(reported_id):
        raise HTTPException(404, {
            "code": "not_our_account",
            "message": "This hub does not host that account. Report it to the "
                       "hub that does, or write to abuse@stonechat.app.",
        })

    report_id = store.create_report(
        reported_id, reporter_id, body.category, body.note, body.evidence)

    # Loud on purpose: this is the line that has to page someone. Neither ID
    # is logged in full — the log is a signal that a report landed, and the
    # report itself is in the database.
    log.warning("abuse report %s: %s reported by %s (%s%s)", report_id[:8],
                reported_id[:12], reporter_id[:12], body.category,
                ", with evidence" if body.evidence else "")
    return {"status": "received", "report_id": report_id}
