"""The ``.clk`` container header and key slots.

Layout (all integers big-endian)::

    prefix  : "CRLK" | version u8 | flags u8 | chunk_size u32 | nonce_prefix 7B
    slots   : slot_count u8 | slot*
    slot 1  : (password)  type=1 | time u32 | mem_kib u32 | par u8 | keyfile u8
                          | salt 16B | nonce 12B | wrapped_key 48B
    slot 2  : (X25519)    type=2 | ephemeral_pub 32B | nonce 12B | wrapped_key 48B

The whole serialized header is used as associated data for every encrypted
chunk, so any change to it makes decryption fail.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import BinaryIO

from .errors import CorruptFileError, CrunchlockError
from .kdf import KdfParams

MAGIC = b"CRLK"
VERSION = 1
NONCE_PREFIX_LEN = 7
WRAPPED_LEN = 32 + 16
SLOT_NONCE_LEN = 12
MAX_SLOTS = 64
MIN_CHUNK = 1024
MAX_CHUNK = 64 * 1024 * 1024

SLOT_PASSWORD = 1
SLOT_X25519 = 2

_PREFIX = struct.Struct(">4sBBI7s")
_PW = struct.Struct(">IIBB16s")


@dataclass
class PasswordSlot:
    params: KdfParams
    uses_keyfile: bool
    salt: bytes
    nonce: bytes = b""
    wrapped: bytes = b""

    def public_part(self) -> bytes:
        return bytes([SLOT_PASSWORD]) + _PW.pack(
            self.params.time_cost, self.params.memory_kib, self.params.parallelism,
            1 if self.uses_keyfile else 0, self.salt)

    def pack(self) -> bytes:
        return self.public_part() + self.nonce + self.wrapped


@dataclass
class X25519Slot:
    ephemeral_pub: bytes
    nonce: bytes = b""
    wrapped: bytes = b""

    def public_part(self) -> bytes:
        return bytes([SLOT_X25519]) + self.ephemeral_pub

    def pack(self) -> bytes:
        return self.public_part() + self.nonce + self.wrapped


Slot = PasswordSlot | X25519Slot


@dataclass
class Header:
    chunk_size: int
    nonce_prefix: bytes
    slots: list = field(default_factory=list)
    flags: int = 0
    version: int = VERSION

    def prefix(self) -> bytes:
        return _PREFIX.pack(MAGIC, self.version, self.flags, self.chunk_size, self.nonce_prefix)

    def pack(self) -> bytes:
        if not self.slots:
            raise CrunchlockError("at least one password or recipient is required")
        if len(self.slots) > MAX_SLOTS:
            raise CrunchlockError(f"at most {MAX_SLOTS} recipients/passwords per file")
        return self.prefix() + bytes([len(self.slots)]) + b"".join(s.pack() for s in self.slots)


def _read_exact(f: BinaryIO, n: int) -> bytes:
    data = f.read(n)
    if len(data) != n:
        raise CorruptFileError("file is truncated (incomplete header)")
    return data


def read_header(f: BinaryIO) -> tuple[Header, bytes]:
    """Parse a header from *f*. Returns the header and its exact raw bytes."""
    raw = _read_exact(f, _PREFIX.size)
    magic, version, flags, chunk_size, nonce_prefix = _PREFIX.unpack(raw)
    if magic != MAGIC:
        raise CorruptFileError("not a crunchlock file (bad magic)")
    if version != VERSION:
        raise CrunchlockError(f"unsupported file version {version}; please upgrade crunchlock")
    if flags != 0:
        raise CrunchlockError("file uses features this version doesn't understand")
    if not MIN_CHUNK <= chunk_size <= MAX_CHUNK:
        raise CorruptFileError("invalid chunk size in header")
    count_b = _read_exact(f, 1)
    raw += count_b
    count = count_b[0]
    if not 1 <= count <= MAX_SLOTS:
        raise CorruptFileError("invalid key slot count")
    slots = []
    for _ in range(count):
        t = _read_exact(f, 1)
        raw += t
        if t[0] == SLOT_PASSWORD:
            body = _read_exact(f, _PW.size + SLOT_NONCE_LEN + WRAPPED_LEN)
            raw += body
            tc, mem, par, kf, salt = _PW.unpack(body[:_PW.size])
            rest = body[_PW.size:]
            slots.append(PasswordSlot(KdfParams(tc, mem, par), bool(kf), salt,
                                      rest[:SLOT_NONCE_LEN], rest[SLOT_NONCE_LEN:]))
        elif t[0] == SLOT_X25519:
            body = _read_exact(f, 32 + SLOT_NONCE_LEN + WRAPPED_LEN)
            raw += body
            slots.append(X25519Slot(body[:32], body[32:44], body[44:]))
        else:
            raise CorruptFileError(f"unknown key slot type {t[0]}")
    return Header(chunk_size, nonce_prefix, slots, flags, version), raw
