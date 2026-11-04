"""Password-based key derivation (Argon2id)."""
from __future__ import annotations

import hashlib
import unicodedata
from dataclasses import dataclass

from argon2.low_level import Type, hash_secret_raw

from .errors import CorruptFileError


@dataclass(frozen=True)
class KdfParams:
    time_cost: int
    memory_kib: int
    parallelism: int


PROFILES = {
    # ~0.5-1 s and 256 MiB RAM on a typical laptop.
    "standard": KdfParams(time_cost=3, memory_kib=256 * 1024, parallelism=4),
    # For long-term secrets: 1 GiB of RAM per guess.
    "paranoid": KdfParams(time_cost=4, memory_kib=1024 * 1024, parallelism=4),
    # For low-memory devices.
    "light": KdfParams(time_cost=4, memory_kib=64 * 1024, parallelism=2),
    # Only for the test-suite: deliberately weak.
    "insecure-test": KdfParams(time_cost=1, memory_kib=8 * 1024, parallelism=1),
}

# Upper bounds accepted when *reading* a file, so a malicious header can't
# make us allocate absurd amounts of memory / CPU.
MAX_MEMORY_KIB = 4 * 1024 * 1024
MAX_TIME_COST = 64
MAX_PARALLELISM = 64
SALT_LEN = 16


def validate(params: KdfParams) -> None:
    if not (1 <= params.time_cost <= MAX_TIME_COST
            and 8 * params.parallelism <= params.memory_kib <= MAX_MEMORY_KIB
            and 1 <= params.parallelism <= MAX_PARALLELISM):
        raise CorruptFileError("unreasonable key-derivation parameters in header")


def secret_bytes(password: str | None, keyfile: bytes | None) -> bytes:
    """Combine password and optional keyfile contents into the KDF secret."""
    pw = unicodedata.normalize("NFC", password or "").encode("utf-8")
    if keyfile is None:
        return pw
    return pw + b"\x00crunchlock-keyfile\x00" + hashlib.sha256(keyfile).digest()


def derive(secret: bytes, salt: bytes, params: KdfParams) -> bytes:
    validate(params)
    return hash_secret_raw(
        secret=secret,
        salt=salt,
        time_cost=params.time_cost,
        memory_cost=params.memory_kib,
        parallelism=params.parallelism,
        hash_len=32,
        type=Type.ID,
    )
