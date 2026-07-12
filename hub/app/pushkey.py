"""Push-key minting (PROTOCOL.md "Push gateway").

Each relay gets an opaque credential `pk_<random>:<hmac>` at provisioning,
where the hmac is HMAC-SHA256(ZEON_PUSH_MINT_SECRET, key_id). The gateway
holds the same secret and verifies offline — no identity lookup, so the
gateway/hub separation (tokens+timing vs identities) survives. Revoking one
relay = its key id in the gateway's blocklist file.

The key id is random and stored nowhere by default: the hub *could* log the
id→owner mapping at mint time if abuse forensics ever require it, but today
it deliberately doesn't.
"""

import hashlib
import hmac
import os
import secrets


def mint_push_key() -> str:
    """A fresh relay credential, or "" when ZEON_PUSH_MINT_SECRET is unset
    (push-key auth disabled; the gateway then accepts bare pings)."""
    secret = os.environ.get("ZEON_PUSH_MINT_SECRET", "")
    if not secret:
        return ""
    key_id = "pk_" + secrets.token_hex(8)
    tag = hmac.new(secret.encode(), key_id.encode(), hashlib.sha256).hexdigest()
    return f"{key_id}:{tag}"
