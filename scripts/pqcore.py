"""ctypes bindings to the pqcore KEM ABI — the same C ABI the Flutter app
loads over dart:ffi, so the Python protocol clients (e2e.py, echo_bot.py)
exercise byte-identical KEM code instead of a second implementation. Since
the stonechat-core cutover the symbols ship inside libstonechat_core (repo
/core, which links pqcore). Build it once with `scripts/build_core.sh
host`; point STONECHAT_CORE_LIB at the library to override discovery.

ML-KEM-768 secrets are 64-byte seeds, X-Wing secrets 32-byte seeds
(notes/docs/POST_QUANTUM.md, internal). Randomness is drawn here (secrets module) and passed
in explicitly — the Rust core never touches an RNG.
"""

import ctypes
import os
import pathlib
import secrets

MLKEM_SEED = 64
MLKEM_PK = 1184
MLKEM_CT = 1088
MLKEM_ENCAPS_RANDOM = 32
XWING_SEED = 32
XWING_PK = 1216
XWING_CT = 1120
XWING_ENCAPS_RANDOM = 64
SS = 32


def _find_lib() -> str:
    env = os.environ.get("STONECHAT_CORE_LIB") or os.environ.get("STONECHAT_PQCORE_LIB")
    if env:
        return env
    root = pathlib.Path(__file__).resolve().parents[1]
    candidates = [
        root / "core" / "target" / "release" / "libstonechat_core.dylib",
        root / "core" / "target" / "release" / "libstonechat_core.so",
        # pre-cutover artifacts, still fine for the KEM symbols
        root / "pqcore" / "target" / "release" / "libpqcore.dylib",
        root / "pqcore" / "target" / "release" / "libpqcore.so",
    ]
    for path in candidates:
        if path.exists():
            return str(path)
    raise RuntimeError(
        "core library not found — run scripts/build_core.sh host "
        "(or set STONECHAT_CORE_LIB)"
    )


_lib = ctypes.CDLL(_find_lib())


def _call(fn, *args) -> None:
    rc = fn(*args)
    if rc != 0:
        raise ValueError(f"pqcore {fn.__name__} failed ({rc})")


def mlkem_keygen() -> tuple[bytes, bytes]:
    """(seed, pk) — the seed is the stored secret half."""
    seed = secrets.token_bytes(MLKEM_SEED)
    return seed, mlkem_pk_from_seed(seed)


def mlkem_pk_from_seed(seed: bytes) -> bytes:
    out = ctypes.create_string_buffer(MLKEM_PK)
    _call(_lib.stonechat_mlkem_pk_from_seed, seed, out)
    return out.raw


def mlkem_encaps(pk: bytes) -> tuple[bytes, bytes]:
    """(ct, ss). Raises ValueError on a malformed public key."""
    ct = ctypes.create_string_buffer(MLKEM_CT)
    ss = ctypes.create_string_buffer(SS)
    _call(_lib.stonechat_mlkem_encaps, pk, secrets.token_bytes(MLKEM_ENCAPS_RANDOM), ct, ss)
    return ct.raw, ss.raw


def mlkem_decaps(seed: bytes, ct: bytes) -> bytes:
    ss = ctypes.create_string_buffer(SS)
    _call(_lib.stonechat_mlkem_decaps, seed, ct, ss)
    return ss.raw


def xwing_pk_from_seed(seed: bytes) -> bytes:
    out = ctypes.create_string_buffer(XWING_PK)
    _call(_lib.stonechat_xwing_pk_from_seed, seed, out)
    return out.raw


def xwing_encaps(pk: bytes) -> tuple[bytes, bytes]:
    """(ct, ss). Raises ValueError on a malformed public key."""
    ct = ctypes.create_string_buffer(XWING_CT)
    ss = ctypes.create_string_buffer(SS)
    _call(_lib.stonechat_xwing_encaps, pk, secrets.token_bytes(XWING_ENCAPS_RANDOM), ct, ss)
    return ct.raw, ss.raw


def xwing_decaps(seed: bytes, ct: bytes) -> bytes:
    ss = ctypes.create_string_buffer(SS)
    _call(_lib.stonechat_xwing_decaps, seed, ct, ss)
    return ss.raw


if __name__ == "__main__":
    seed, pk = mlkem_keygen()
    ct, ss1 = mlkem_encaps(pk)
    assert mlkem_decaps(seed, ct) == ss1
    xseed = secrets.token_bytes(XWING_SEED)
    xpk = xwing_pk_from_seed(xseed)
    xct, xss = xwing_encaps(xpk)
    assert xwing_decaps(xseed, xct) == xss
    print("pqcore ok:", _find_lib())
