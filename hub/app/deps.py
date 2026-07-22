"""Shared FastAPI dependencies: the store singleton and bearer-token auth.

Lives outside main.py so routers (billing, admin) can import them without a
circular import.
"""

import os
import secrets
from typing import Annotated

from fastapi import Depends, Header, HTTPException

from .db import Store

store = Store(os.environ.get("ZEON_HUB_DB", "hub.db"))


def current_user(authorization: Annotated[str | None, Header()] = None) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "missing bearer token")
    user = store.user_by_token(authorization.removeprefix("Bearer ").strip())
    if not user:
        raise HTTPException(401, "invalid token")
    return user


User = Annotated[dict, Depends(current_user)]


def unbanned_user(user: User) -> dict:
    """A ban is narrow on purpose: it blocks *acquiring infrastructure*, not
    the account. Reading your own record, publishing a TLS signature and
    recovering the identity all still work — the ban is a refusal to keep
    hosting someone, not an attempt to erase them. See docs/ABUSE.md."""
    if user.get("banned_at"):
        raise HTTPException(403, {
            "code": "account_suspended",
            "message": "This account may no longer provision mailboxes. "
                       "Contact abuse@zeonchat.com if you believe this is an error.",
        })
    return user


UnbannedUser = Annotated[dict, Depends(unbanned_user)]


def require_admin(x_admin_token: Annotated[str | None, Header()] = None) -> None:
    """Operator-only routes. Disabled entirely unless ZEON_ADMIN_TOKEN is set,
    so a hub that never configures one has no admin surface to attack."""
    admin_token = os.environ.get("ZEON_ADMIN_TOKEN")
    if not admin_token or not x_admin_token or not secrets.compare_digest(
            admin_token, x_admin_token):
        raise HTTPException(403, "admin token required")


Admin = Annotated[None, Depends(require_admin)]
