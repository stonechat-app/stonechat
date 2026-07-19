"""Zeon ID derivation and validation (see PROTOCOL.md).

The ID is a BLAKE2b commitment to the user's Ed25519 identity public key, so
this directory can never swap a key undetected — clients recompute the hash.
hashlib.blake2b(digest_size=n) is bit-identical to libsodium's
crypto_generichash(outlen=n), which is what the Flutter client uses.
"""

import base64
import hashlib

HASH_LEN = 20
CHECKSUM_LEN = 2
PUBKEY_LEN = 32  # Ed25519


def zeon_id_from_pubkey(pubkey: bytes) -> str:
    """Derive the canonical Zeon ID for an Ed25519 identity public key.

    The ID is a client-verifiable commitment to pubkey (see PROTOCOL.md
    "Zeon ID"): BLAKE2b-160 of the key, plus a 2-byte checksum over that hash,
    base32-encoded in nine groups of four after the ``ZC-`` prefix. Clients
    recompute this whenever they receive a pubkey so a directory cannot swap
    keys undetected.

    Args:
        pubkey: Raw 32-byte Ed25519 public key.

    Returns:
        Canonical ID, e.g. ``ZC-K3M9-QF2X-V8D4-HTPR-26LN-AQ7B-ZZC4-J5WE-M2KA``.

    Raises:
        ValueError: If *pubkey* is not exactly 32 bytes.
    """
    if len(pubkey) != PUBKEY_LEN:
        raise ValueError(f"pubkey must be {PUBKEY_LEN} bytes, got {len(pubkey)}")
    h = hashlib.blake2b(pubkey, digest_size=HASH_LEN).digest()
    checksum = hashlib.blake2b(h, digest_size=16).digest()[:CHECKSUM_LEN]
    b32 = base64.b32encode(h + checksum).decode().rstrip("=")
    return "ZC-" + "-".join(b32[i : i + 4] for i in range(0, len(b32), 4))


def normalize_zeon_id(raw: str) -> str:
    """Parse user/wire input into canonical form. Raises ValueError if invalid."""
    compact = raw.strip().upper().replace("-", "").replace(" ", "")
    if not compact.startswith("ZC"):
        raise ValueError("Zeon IDs start with ZC-")
    b32 = compact[2:]
    if len(b32) != 36:
        raise ValueError("wrong length for a Zeon ID")
    try:
        payload = base64.b32decode(b32 + "=" * 4)  # 36 chars -> pad to 40
    except Exception:
        raise ValueError("not valid base32")
    h, checksum = payload[:HASH_LEN], payload[HASH_LEN:]
    expected = hashlib.blake2b(h, digest_size=16).digest()[:CHECKSUM_LEN]
    if checksum != expected:
        raise ValueError("checksum mismatch — mistyped ID?")
    return "ZC-" + "-".join(b32[i : i + 4] for i in range(0, len(b32), 4))
