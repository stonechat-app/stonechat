"""Shared FastAPI dependencies: the store singleton and bearer-token auth.

Lives outside main.py so routers (billing) can import them without a
circular import.
"""

import os
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
