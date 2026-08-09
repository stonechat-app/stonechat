"""Operator-only abuse actions.

Every managed mailbox lives in GazelleLabs' provider accounts, so a report
about one customer's machine is a threat to every customer's machine
(notes/docs/ABUSE.md, internal). These routes are what turn "we can act on a credible report"
from a claim in an abuse-desk reply into something doable at 3am:

    whois   — an abuse report carries an IP; this turns it into a Stonechat ID
    destroy — the machine is gone, the record of it is kept
    ban     — this account gets no more machines from us
    reports — the queue of complaints raised by users against other users
              (filed at POST /v1/report, report.py), and the verb to close one

`destroy` and `ban` are deliberately separate verbs. Destroying is cheap:
mailboxes hold no history (it lives on the phone) and the client re-resolves
through the directory on the first delivery failure, so a wrongly-destroyed
mailbox costs its owner a re-provision and the undelivered queue, not their
account. That makes it safe to do fast, on the balance of probabilities,
which is the posture an abuse desk needs. Banning says someone is not a
customer any more — a slower, colder decision that should not ride along with
an urgent one.

Runbook and the reply templates these routes back up: notes/docs/abuse_reply_template.md.

Disabled entirely unless STONECHAT_ADMIN_TOKEN is set.
"""

import logging

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from .deps import Admin, store
from .providers import ProviderError, get_provider

log = logging.getLogger("stonechat.hub.admin")

router = APIRouter(prefix="/v1/admin", tags=["admin"])


class ReasonIn(BaseModel):
    reason: str = Field(min_length=3, max_length=500)


def _public(mailbox: dict) -> dict:
    """Never hand back mailbox_token / host_agent_token — this is a report, not
    a credential dump, and abuse triage never needs them."""
    return {
        "stonechat_id": mailbox["stonechat_id"],
        "provider": mailbox["provider"],
        "status": mailbox["status"],
        "resource_id": mailbox["resource_id"],
        "address": mailbox["address"],
        "meta": mailbox["meta"],
        "created_at": mailbox["created_at"],
    }


@router.get("/whois")
def whois(host: str, _: Admin):
    """IP (or hostname) → the account behind it, plus its ban and abuse
    history. Step 1 of every abuse report.

    An empty `mailboxes` result usually means the IP is not ours *any more*:
    recycled provider IPs arrive carrying someone else's history (ABUSE.md §9),
    and that is an answer worth sending quickly rather than investigating."""
    mailboxes = store.mailboxes_by_host(host)
    out = []
    for mailbox in mailboxes:
        user = store.user_by_id(mailbox["stonechat_id"]) or {}
        out.append({
            **_public(mailbox),
            "banned_at": user.get("banned_at"),
            "ban_reason": user.get("ban_reason"),
            "prior_destroys": len(store.tombstones_for(mailbox["stonechat_id"])),
        })
    return {"host": host, "mailboxes": out}


@router.post("/mailboxes/{stonechat_id}/destroy")
def destroy(stonechat_id: str, body: ReasonIn, _: Admin):
    """Destroy one customer's machine. Does not touch their account, their
    subscription or their identity — only the machine.

    Ordering is load-bearing: the tombstone is written first, so a provider
    call that fails halfway leaves us with a record of what existed rather
    than an orphaned VM nobody can name. Subscription rows are deliberately
    left alone — deleting them would make the machine invisible to
    `reapable_mailboxes`, which skips owners with no subscription, and an
    un-reapable VM bills forever."""
    mailbox = store.mailbox_for(stonechat_id)
    if not mailbox:
        raise HTTPException(404, "no mailbox for that Stonechat ID")

    store.record_tombstone(mailbox, body.reason)

    if mailbox["resource_id"]:
        try:
            get_provider(mailbox["provider"]).destroy(
                mailbox["resource_id"], mailbox["meta"])
        except ProviderError as e:
            # The tombstone survives — the machine is still out there and
            # someone has to go and kill it by hand.
            log.error("abuse destroy failed for %s: %s", stonechat_id[:12], e)
            raise HTTPException(502, f"failed to destroy: {e}")

    store.delete_mailbox(stonechat_id)
    log.warning("abuse destroy: %s (%s) — %s",
                stonechat_id[:12], mailbox["provider"], body.reason)
    return {"status": "destroyed", "stonechat_id": stonechat_id,
            "provider": mailbox["provider"], "address": mailbox["address"]}


@router.post("/users/{stonechat_id}/ban")
def ban(stonechat_id: str, body: ReasonIn, _: Admin):
    """Refuse this account further infrastructure. Blocks POST /v1/mailbox and
    POST /v1/mailbox/external — the second one matters most, because without it
    a banned user re-enters the directory in one call by pointing it at a
    relay they run themselves.

    Does not destroy anything: ban then destroy, or the machine keeps running
    while its owner is banned from replacing it.

    Worth being honest about the ceiling. A Stonechat ID is a hash of a freshly
    generated keypair, so anyone can mint a new identity in seconds and this
    is a speed bump, not a wall. It bites where re-entry has a cost: once
    provisioning is entitlement-gated, coming back means a new payment
    method."""
    if not store.set_ban(stonechat_id, body.reason):
        raise HTTPException(404, "unknown Stonechat ID")
    log.warning("banned %s — %s", stonechat_id[:12], body.reason)
    return {"status": "banned", "stonechat_id": stonechat_id}


@router.post("/users/{stonechat_id}/unban")
def unban(stonechat_id: str, _: Admin):
    if not store.set_ban(stonechat_id, None):
        raise HTTPException(404, "unknown Stonechat ID")
    log.warning("unbanned %s", stonechat_id[:12])
    return {"status": "active", "stonechat_id": stonechat_id}


# -- reports from users ---------------------------------------------------------
#
# The queue that feeds the three verbs above. Reports arrive signed and
# unauthenticated at POST /v1/report (report.py); everything here is the
# operator side of that pipe. Reading a report is a separate call from listing
# them because only the detail view returns attached message plaintext, and
# that should take a deliberate act.


class ResolveIn(BaseModel):
    status: str = Field(pattern="^(actioned|dismissed)$")
    resolution: str = Field(min_length=3, max_length=500)


@router.get("/reports")
def list_reports(_: Admin, status: str = "open", limit: int = 100):
    """The triage queue, newest first. `status=all` includes closed reports.

    Evidence is summarised as a byte count here, never inlined — see
    Store.list_reports."""
    return {"reports": store.list_reports(
        None if status == "all" else status, min(limit, 500))}


@router.get("/reports/{report_id}")
def get_report(report_id: str, _: Admin):
    """One report in full, including any attached plaintext, plus the context
    that decides what to do with it: whether this account has been reported
    before and by how many *distinct* people, whether it is already banned,
    and how many machines it has had destroyed."""
    report = store.report_by_id(report_id)
    if not report:
        raise HTTPException(404, "unknown report")
    user = store.user_by_id(report["reported_id"]) or {}
    mailbox = store.mailbox_for(report["reported_id"])
    return {
        "report": report,
        "reported": {
            "stonechat_id": report["reported_id"],
            "banned_at": user.get("banned_at"),
            "ban_reason": user.get("ban_reason"),
            "prior_destroys": len(store.tombstones_for(report["reported_id"])),
            "mailbox": _public(mailbox) if mailbox else None,
            **store.report_counts(report["reported_id"]),
        },
    }


@router.post("/reports/{report_id}/resolve")
def resolve_report(report_id: str, body: ResolveIn, _: Admin):
    """Close a report once a human has decided. Records the outcome and drops
    the attached plaintext (Store.resolve_report).

    Purely a bookkeeping call: acting on a report means calling destroy and/or
    ban, which are separate on purpose — see the module docstring. Resolving
    without having called either is a legitimate outcome and what `dismissed`
    is for."""
    if not store.resolve_report(report_id, body.status, body.resolution):
        raise HTTPException(404, "unknown report")
    log.warning("report %s %s — %s", report_id[:8], body.status, body.resolution)
    return {"status": body.status, "report_id": report_id}
